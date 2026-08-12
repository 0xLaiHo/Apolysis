// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::{
    read_frame, write_frame, AuthoritativeSnapshotSource, DirtyWaitOutcome, KubernetesListPort,
    KubernetesSnapshot, KubernetesSourceError, KubernetesSourceErrorKind, SourceEpoch,
    SourceRequest, SourceResponse, KUBERNETES_SOURCE_SCHEMA_V1,
};

const MAX_REQUEST_FRAME_BYTES: usize = 4 * 1024;
const DEFAULT_COLLECTOR_UID: u32 = 0;
const MAX_STALE_SOCKET_ARTIFACTS: usize = 128;
const PENDING_SOCKET_PREFIX: &str = ".apolysis-source-pending-";
const STALE_SOCKET_PREFIX: &str = ".apolysis-source-stale-";

pub trait SnapshotProvider: Send + Sync {
    fn source_epoch(&self) -> &SourceEpoch;

    fn capture(
        &self,
    ) -> impl Future<Output = Result<KubernetesSnapshot, KubernetesSourceError>> + Send;
}

impl<P> SnapshotProvider for AuthoritativeSnapshotSource<P>
where
    P: KubernetesListPort,
{
    fn source_epoch(&self) -> &SourceEpoch {
        self.source_epoch()
    }

    async fn capture(&self) -> Result<KubernetesSnapshot, KubernetesSourceError> {
        self.capture().await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceServerConfig {
    socket_path: PathBuf,
    expected_collector_uid: u32,
    request_timeout: Duration,
    dirty_wait_timeout: Duration,
    max_connections: usize,
    max_frame_bytes: usize,
}

impl SourceServerConfig {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_collector_uid: DEFAULT_COLLECTOR_UID,
            request_timeout: Duration::from_secs(5),
            dirty_wait_timeout: Duration::from_secs(1),
            max_connections: 16,
            max_frame_bytes: crate::DEFAULT_MAX_IPC_FRAME_BYTES,
        }
    }

    pub fn with_expected_collector_uid(mut self, expected_collector_uid: u32) -> Self {
        self.expected_collector_uid = expected_collector_uid;
        self
    }

    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    pub fn with_dirty_wait_timeout(mut self, dirty_wait_timeout: Duration) -> Self {
        self.dirty_wait_timeout = dirty_wait_timeout;
        self
    }

    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    fn validate(&self) -> Result<(), KubernetesSourceError> {
        if self.socket_path.as_os_str().is_empty()
            || !self.socket_path.is_absolute()
            || self.request_timeout.is_zero()
            || self.dirty_wait_timeout.is_zero()
            || self.dirty_wait_timeout >= self.request_timeout
            || self.max_connections == 0
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > crate::DEFAULT_MAX_IPC_FRAME_BYTES
        {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Malformed,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceServerSummary {
    pub accepted_connections: u64,
    pub rejected_connections: u64,
}

struct DirtyState {
    sequence: u64,
    relist_required: bool,
}

pub struct DirtyTracker {
    source_epoch: SourceEpoch,
    state: Mutex<DirtyState>,
    notify: Notify,
}

impl DirtyTracker {
    pub fn new(source_epoch: SourceEpoch) -> Self {
        Self {
            source_epoch,
            state: Mutex::new(DirtyState {
                sequence: 1,
                relist_required: true,
            }),
            notify: Notify::new(),
        }
    }

    pub fn source_epoch(&self) -> &SourceEpoch {
        &self.source_epoch
    }

    pub async fn mark_dirty(&self, relist_required: bool) -> Result<u64, KubernetesSourceError> {
        let mut state = self.state.lock().await;
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| KubernetesSourceError::new(KubernetesSourceErrorKind::Oversized))?;
        state.relist_required |= relist_required;
        let sequence = state.sequence;
        drop(state);
        self.notify.notify_waiters();
        Ok(sequence)
    }

    async fn snapshot_completed(&self) {
        self.state.lock().await.relist_required = false;
    }

    async fn wait(
        &self,
        source_epoch: Option<SourceEpoch>,
        after_sequence: u64,
        maximum_wait: Duration,
    ) -> DirtyWaitOutcome {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.state.lock().await;
                if source_epoch.as_ref() != Some(&self.source_epoch) {
                    return DirtyWaitOutcome::Dirty {
                        source_epoch: self.source_epoch.clone(),
                        dirty_sequence: state.sequence,
                        relist_required: true,
                    };
                }
                if state.sequence > after_sequence {
                    return DirtyWaitOutcome::Dirty {
                        source_epoch: self.source_epoch.clone(),
                        dirty_sequence: state.sequence,
                        relist_required: state.relist_required,
                    };
                }
            }
            if tokio::time::timeout(maximum_wait, notified.as_mut())
                .await
                .is_err()
            {
                let state = self.state.lock().await;
                return if state.sequence > after_sequence {
                    DirtyWaitOutcome::Dirty {
                        source_epoch: self.source_epoch.clone(),
                        dirty_sequence: state.sequence,
                        relist_required: state.relist_required,
                    }
                } else {
                    DirtyWaitOutcome::Idle {
                        source_epoch: self.source_epoch.clone(),
                        dirty_sequence: state.sequence,
                    }
                };
            }
        }
    }
}

pub async fn run_source_server<P, S>(
    config: SourceServerConfig,
    provider: Arc<P>,
    dirty: Arc<DirtyTracker>,
    shutdown: S,
) -> Result<SourceServerSummary, KubernetesSourceError>
where
    P: SnapshotProvider + 'static,
    S: Future<Output = ()> + Send,
{
    config.validate()?;
    if provider.source_epoch() != dirty.source_epoch() {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        ));
    }
    let (listener, socket_identity) = bind_new_restricted_socket(&config.socket_path)?;
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    let mut summary = SourceServerSummary::default();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(_) => {
                        cleanup_owned_socket(&config.socket_path, socket_identity)?;
                        return Err(KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable));
                    }
                };
                let authorized = stream
                    .peer_cred()
                    .map(|credential| credential.uid() == config.expected_collector_uid)
                    .unwrap_or(false);
                if !authorized {
                    summary.rejected_connections = summary.rejected_connections.saturating_add(1);
                    continue;
                }
                let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        summary.rejected_connections = summary.rejected_connections.saturating_add(1);
                        continue;
                    }
                };
                summary.accepted_connections = summary.accepted_connections.saturating_add(1);
                let provider = Arc::clone(&provider);
                let dirty = Arc::clone(&dirty);
                let request_timeout = config.request_timeout;
                let dirty_wait_timeout = config.dirty_wait_timeout;
                let max_frame_bytes = config.max_frame_bytes;
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        request_timeout,
                        handle_connection(
                            stream,
                            provider,
                            dirty,
                            dirty_wait_timeout,
                            max_frame_bytes,
                        ),
                    )
                    .await;
                });
            }
        }
        while tasks.try_join_next().is_some() {}
    }

    drop(listener);
    while tasks.join_next().await.is_some() {}
    cleanup_owned_socket(&config.socket_path, socket_identity)?;
    Ok(summary)
}

async fn handle_connection<P>(
    mut stream: UnixStream,
    provider: Arc<P>,
    dirty: Arc<DirtyTracker>,
    dirty_wait_timeout: Duration,
    max_frame_bytes: usize,
) -> Result<(), KubernetesSourceError>
where
    P: SnapshotProvider,
{
    let request = read_frame(&mut stream, MAX_REQUEST_FRAME_BYTES).await?;
    let request: SourceRequest = serde_json::from_slice(&request)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    let response = match request {
        SourceRequest::Capture { schema_version }
            if schema_version == KUBERNETES_SOURCE_SCHEMA_V1 =>
        {
            match provider.capture().await {
                Ok(snapshot) => {
                    dirty.snapshot_completed().await;
                    SourceResponse::Snapshot {
                        schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                        snapshot,
                    }
                }
                Err(error) => error_response(error.kind()),
            }
        }
        SourceRequest::WaitDirty {
            schema_version,
            source_epoch,
            after_dirty_sequence,
        } if schema_version == KUBERNETES_SOURCE_SCHEMA_V1 => {
            match dirty
                .wait(source_epoch, after_dirty_sequence, dirty_wait_timeout)
                .await
            {
                DirtyWaitOutcome::Dirty {
                    source_epoch,
                    dirty_sequence,
                    relist_required,
                } => SourceResponse::Dirty {
                    schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                    source_epoch,
                    dirty_sequence,
                    relist_required,
                },
                DirtyWaitOutcome::Idle {
                    source_epoch,
                    dirty_sequence,
                } => SourceResponse::Idle {
                    schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                    source_epoch,
                    dirty_sequence,
                },
            }
        }
        _ => error_response(KubernetesSourceErrorKind::Protocol),
    };
    let mut body = serde_json::to_vec(&response)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    if body.len() > max_frame_bytes {
        body = serde_json::to_vec(&error_response(KubernetesSourceErrorKind::Oversized))
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    }
    write_frame(&mut stream, &body, max_frame_bytes).await
}

fn error_response(error: KubernetesSourceErrorKind) -> SourceResponse {
    SourceResponse::Error {
        schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
        error,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
}

fn bind_new_restricted_socket(
    path: &Path,
) -> Result<(UnixListener, SocketIdentity), KubernetesSourceError> {
    let parent = path
        .parent()
        .ok_or_else(|| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    prepare_socket_parent(parent)?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    if !parent_metadata.file_type().is_dir()
        || canonical_parent != parent
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.gid() != unsafe { libc::getegid() }
        || parent_metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unauthorized,
        ));
    }
    recover_stale_socket_artifacts(parent)?;
    recover_stale_owned_socket(path)?;

    // Build and verify the socket at an unpredictable source-private name, then
    // publish it with one no-replace rename. The final path is therefore never
    // observable with an ambient-umask mode or a partially checked identity.
    let pending_path = parent.join(format!("{PENDING_SOCKET_PREFIX}{}", Uuid::new_v4()));
    let listener = UnixListener::bind(&pending_path)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    let metadata = std::fs::symlink_metadata(&pending_path)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    let socket_identity = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
    };
    if std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o660)).is_err() {
        drop(listener);
        cleanup_bound_socket(&pending_path, socket_identity, None)?;
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unavailable,
        ));
    }
    let metadata = match std::fs::symlink_metadata(&pending_path) {
        Ok(metadata) => metadata,
        Err(_) => {
            drop(listener);
            cleanup_bound_socket(&pending_path, socket_identity, None)?;
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unavailable,
            ));
        }
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != socket_identity.device
        || metadata.ino() != socket_identity.inode
        || metadata.permissions().mode() & 0o777 != 0o660
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != unsafe { libc::getegid() }
    {
        drop(listener);
        cleanup_bound_socket(&pending_path, socket_identity, None)?;
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unauthorized,
        ));
    }
    if let Err(error) = rename_noreplace(&pending_path, path) {
        drop(listener);
        cleanup_bound_socket(&pending_path, socket_identity, None)?;
        return Err(error);
    }
    let published = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            drop(listener);
            cleanup_owned_socket(path, socket_identity)?;
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unavailable,
            ));
        }
    };
    if !is_owned_socket(&published, socket_identity) {
        drop(listener);
        cleanup_owned_socket(path, socket_identity)?;
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        ));
    }
    Ok((listener, socket_identity))
}

fn recover_stale_owned_socket(path: &Path) -> Result<(), KubernetesSourceError> {
    recover_stale_socket(path, is_owned_socket, false)
}

fn recover_stale_socket_artifacts(parent: &Path) -> Result<(), KubernetesSourceError> {
    let entries = std::fs::read_dir(parent)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    let mut artifact_count = 0_usize;
    for entry in entries {
        let entry = entry
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let suffix = if let Some(suffix) = file_name.strip_prefix(PENDING_SOCKET_PREFIX) {
            suffix
        } else if let Some(suffix) = file_name.strip_prefix(STALE_SOCKET_PREFIX) {
            suffix
        } else {
            continue;
        };
        artifact_count = artifact_count.saturating_add(1);
        if artifact_count > MAX_STALE_SOCKET_ARTIFACTS {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Oversized,
            ));
        }
        let uuid = Uuid::parse_str(suffix)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unauthorized))?;
        if uuid.to_string() != suffix {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unauthorized,
            ));
        }
        recover_stale_socket(&entry.path(), is_owned_pending_socket, true)?;
    }
    Ok(())
}

fn recover_stale_socket(
    path: &Path,
    is_owned: fn(&std::fs::Metadata, SocketIdentity) -> bool,
    normalize_permissions: bool,
) -> Result<(), KubernetesSourceError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unavailable,
            ));
        }
    };
    let expected = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
    };
    if !is_owned(&metadata, expected) {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unauthorized,
        ));
    }
    if normalize_permissions && metadata.permissions().mode() & 0o777 != 0o660 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
        let normalized = std::fs::symlink_metadata(path)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Inconsistent))?;
        if !is_owned(&normalized, expected) || normalized.permissions().mode() & 0o777 != 0o660 {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Inconsistent,
            ));
        }
    }

    match probe_socket_nonblocking(path) {
        Ok(()) => {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unauthorized,
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unavailable,
            ));
        }
    }

    let current = std::fs::symlink_metadata(path)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Inconsistent))?;
    if !is_owned(&current, expected) {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    let quarantine = parent.join(format!("{STALE_SOCKET_PREFIX}{}", Uuid::new_v4()));
    rename_noreplace(path, &quarantine)?;
    let quarantined = std::fs::symlink_metadata(&quarantine)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Inconsistent))?;
    if !is_owned(&quarantined, expected) {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        ));
    }
    std::fs::remove_file(&quarantine)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    match std::fs::symlink_metadata(&quarantine) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        )),
    }
}

fn probe_socket_nonblocking(path: &Path) -> std::io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let bytes = path.as_bytes_with_nul();
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    if bytes.len() > address.sun_path.len() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }

    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let address_length = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len())
        .try_into()
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let result = unsafe {
        libc::connect(
            descriptor.as_raw_fd(),
            std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
            address_length,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(code)
            if code == libc::EINPROGRESS || code == libc::EAGAIN || code == libc::EALREADY
    ) {
        return Err(error);
    }

    let mut poll_descriptor = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let ready = unsafe { libc::poll(std::ptr::from_mut(&mut poll_descriptor), 1, 50) };
    if ready == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
    }
    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut socket_error = 0_i32;
    let mut socket_error_length = std::mem::size_of::<i32>() as libc::socklen_t;
    let inspected = unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            std::ptr::from_mut(&mut socket_error).cast(),
            std::ptr::from_mut(&mut socket_error_length),
        )
    };
    if inspected != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if socket_error == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(socket_error))
    }
}

fn is_owned_socket(metadata: &std::fs::Metadata, expected: SocketIdentity) -> bool {
    metadata.file_type().is_socket()
        && metadata.dev() == expected.device
        && metadata.ino() == expected.inode
        && metadata.uid() == expected.uid
        && metadata.gid() == expected.gid
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.gid() == unsafe { libc::getegid() }
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o777 == 0o660
}

fn is_owned_pending_socket(metadata: &std::fs::Metadata, expected: SocketIdentity) -> bool {
    metadata.file_type().is_socket()
        && metadata.dev() == expected.device
        && metadata.ino() == expected.inode
        && metadata.uid() == expected.uid
        && metadata.gid() == expected.gid
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.gid() == unsafe { libc::getegid() }
        && metadata.nlink() == 1
}

fn rename_noreplace(source: &Path, destination: &Path) -> Result<(), KubernetesSourceError> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        ))
    }
}

fn prepare_socket_parent(parent: &Path) -> Result<(), KubernetesSourceError> {
    match std::fs::symlink_metadata(parent) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unavailable,
            ));
        }
    }
    let grandparent = parent
        .parent()
        .ok_or_else(|| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
    let grandparent_metadata = std::fs::symlink_metadata(grandparent)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    let canonical_grandparent = std::fs::canonicalize(grandparent)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    if !grandparent_metadata.file_type().is_dir() || canonical_grandparent != grandparent {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Unauthorized,
        ));
    }
    // The grandparent is the Kubernetes emptyDir mount. Requesting mode 0700
    // makes the create safe under every ambient umask (umask can only remove
    // permissions); chmod below then installs the exact contract. Never mutate
    // the process-wide umask in this multi-threaded source process.
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(parent)
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))
}

fn cleanup_owned_socket(
    path: &Path,
    expected: SocketIdentity,
) -> Result<(), KubernetesSourceError> {
    cleanup_bound_socket(path, expected, Some(0o660))
}

fn cleanup_bound_socket(
    path: &Path,
    expected: SocketIdentity,
    required_mode: Option<u32>,
) -> Result<(), KubernetesSourceError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unavailable,
            ));
        }
    };
    if metadata.file_type().is_socket()
        && metadata.dev() == expected.device
        && metadata.ino() == expected.inode
        && metadata.uid() == expected.uid
        && metadata.gid() == expected.gid
        && metadata.nlink() == 1
        && required_mode.is_none_or(|mode| metadata.permissions().mode() & 0o777 == mode)
    {
        std::fs::remove_file(path)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
        return match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Inconsistent,
            )),
        };
    }
    Err(KubernetesSourceError::new(
        KubernetesSourceErrorKind::Inconsistent,
    ))
}

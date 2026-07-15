// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{self, OpenOptions},
    future::pending,
    io::{Cursor, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use apolysis_contracts::{RunId, SourceKind};
use apolysis_gateway::{GatewayClock, SystemClock};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository,
};

use crate::server::{decode_replay_key, read_secret_text, ACTIVE_REPLAY_KEY_ID};
use crate::{http::GatewayRouteOperation, GatewayServerError};

const MARKER_CONTENTS: &[u8] = b"committed\n";
const PRE_OPERATION_MARKER_CONTENTS: &[u8] = b"ready\n";
const RELEASE_CONTENTS: &[u8] = b"release\n";
const PRE_OPERATION_RELEASE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_CERTIFICATE_PEM_BYTES: u64 = 1024 * 1024;
const MAX_DATABASE_URL_BYTES: u64 = 4096;
const MAX_PROOF_BYTES: u64 = 512;
const MAX_REPLAY_KEY_BYTES: u64 = 256;

/// Seed one pending join grant through the production repository validation
/// path for the local multiprocess qualification gate.
///
/// This helper is available only with the `qualification` feature. It reads
/// all secret-bearing inputs from bounded private files and retains no remote
/// request surface.
#[allow(clippy::too_many_arguments)]
pub async fn register_qualification_join_grant(
    database_url_file: &Path,
    replay_key_file: &Path,
    issuer_certificate_file: &Path,
    joining_certificate_file: &Path,
    run_id: &str,
    proof_file: &Path,
    expires_at_unix_ms: u64,
) -> Result<(), GatewayServerError> {
    let database_url = read_secret_text(database_url_file, MAX_DATABASE_URL_BYTES)?;
    if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
        return Err(GatewayServerError::configuration(
            "Gateway database URL uses an unsupported scheme",
        ));
    }
    let replay_key_text = read_secret_text(replay_key_file, MAX_REPLAY_KEY_BYTES)?;
    let replay_key = decode_replay_key(&replay_key_text)?;
    let proof = read_secret_text(proof_file, MAX_PROOF_BYTES)?;
    let run_id = RunId::try_from(run_id).map_err(|_| {
        GatewayServerError::configuration("Gateway qualification join grant run is invalid")
    })?;
    let issuer_leaf = read_leaf_der(issuer_certificate_file)?;
    let joining_leaf = read_leaf_der(joining_certificate_file)?;
    let now_unix_ms = SystemClock.now_unix_ms();
    let authority = crate::AuthorityStore::connect(&database_url).await?;
    let issuer = authority
        .resolve_mtls(&issuer_leaf, "open_run", now_unix_ms)
        .await?;
    let joining_source = authority
        .resolve_mtls(&joining_leaf, "open_run", now_unix_ms)
        .await?;
    let replay_protector = Arc::new(
        Aes256GcmReplayProtector::new(
            ACTIVE_REPLAY_KEY_ID,
            [(ACTIVE_REPLAY_KEY_ID.to_string(), replay_key)],
        )
        .map_err(GatewayServerError::gateway)?,
    );
    let repository = PostgresGatewayRepository::connect(
        &database_url,
        replay_protector,
        PostgresGatewayConfig::default(),
    )
    .await
    .map_err(GatewayServerError::gateway)?;
    repository
        .register_join_grant(
            &issuer,
            &joining_source,
            run_id,
            SourceKind::SemanticHook,
            &proof,
            expires_at_unix_ms,
        )
        .await
        .map_err(GatewayServerError::gateway)
}

fn read_leaf_der(path: &Path) -> Result<Vec<u8>, GatewayServerError> {
    let pem = crate::file_input::read_bounded_file(path, MAX_CERTIFICATE_PEM_BYTES, false)?;
    let mut reader = Cursor::new(pem.as_slice());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayServerError::configuration("Client certificate PEM is invalid"))?;
    let leaf = certificates.first().ok_or_else(|| {
        GatewayServerError::configuration("Client certificate PEM contains no certificate")
    })?;
    Ok(leaf.as_ref().to_vec())
}

impl GatewayRouteOperation {
    pub fn parse(value: &str) -> Result<Self, GatewayServerError> {
        match value {
            "open_run" => Ok(Self::OpenRun),
            "bind_runtime" => Ok(Self::BindRuntime),
            "ingest" => Ok(Self::Ingest),
            "finish_run" => Ok(Self::FinishRun),
            _ => Err(GatewayServerError::configuration(
                "Gateway qualification operation is unsupported",
            )),
        }
    }
}

pub(crate) struct QualificationBarrier {
    operation: GatewayRouteOperation,
    marker: PathBuf,
    release: Option<PathBuf>,
}

impl QualificationBarrier {
    pub(crate) fn new(
        operation: GatewayRouteOperation,
        marker: PathBuf,
    ) -> Result<Self, GatewayServerError> {
        if !marker.is_absolute() {
            return Err(GatewayServerError::configuration(
                "Gateway qualification marker path must be absolute",
            ));
        }
        Ok(Self {
            operation,
            marker,
            release: None,
        })
    }

    pub(crate) fn pre_operation(
        operation: GatewayRouteOperation,
        marker: PathBuf,
        release: PathBuf,
    ) -> Result<Self, GatewayServerError> {
        if !marker.is_absolute() {
            return Err(GatewayServerError::configuration(
                "Gateway qualification marker path must be absolute",
            ));
        }
        if !release.is_absolute() {
            return Err(GatewayServerError::configuration(
                "Gateway qualification release path must be absolute",
            ));
        }
        if marker == release || marker.parent() != release.parent() {
            return Err(GatewayServerError::configuration(
                "Gateway qualification release must be a distinct sibling of the marker",
            ));
        }
        match fs::symlink_metadata(&release) {
            Ok(_) => {
                return Err(GatewayServerError::configuration(
                    "Gateway qualification release must not exist before the barrier",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(GatewayServerError::io_at(
                    "qualification-release-metadata",
                    error,
                ));
            }
        }
        Ok(Self {
            operation,
            marker,
            release: Some(release),
        })
    }

    pub(crate) fn marker(&self) -> &Path {
        &self.marker
    }

    pub(crate) fn release(&self) -> Option<&Path> {
        self.release.as_deref()
    }

    pub(crate) async fn before_operation(
        &self,
        operation: GatewayRouteOperation,
    ) -> Result<(), GatewayServerError> {
        if operation != self.operation {
            return Ok(());
        }
        let Some(release) = &self.release else {
            return Ok(());
        };

        write_private_marker(&self.marker, PRE_OPERATION_MARKER_CONTENTS)?;
        wait_for_private_release(release, PRE_OPERATION_RELEASE_TIMEOUT).await
    }

    pub(crate) async fn reach(
        &self,
        operation: GatewayRouteOperation,
    ) -> Result<(), GatewayServerError> {
        if operation != self.operation {
            return Ok(());
        }
        if self.release.is_some() {
            return Ok(());
        }

        write_private_marker(&self.marker, MARKER_CONTENTS)?;
        pending::<()>().await;
        Ok(())
    }
}

async fn wait_for_private_release(
    path: &Path,
    timeout: Duration,
) -> Result<(), GatewayServerError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(GatewayServerError::configuration(
                "Gateway qualification release timed out",
            ));
        }
        let mut release_options = OpenOptions::new();
        release_options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut release = match release_options.open(path) {
            Ok(release) => release,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            Err(error) => {
                return Err(GatewayServerError::io_at(
                    "qualification-release-open",
                    error,
                ));
            }
        };
        let metadata = release
            .metadata()
            .map_err(|error| GatewayServerError::io_at("qualification-release-metadata", error))?;
        // SAFETY: geteuid has no preconditions and does not retain pointers.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != effective_uid
        {
            return Err(GatewayServerError::configuration(
                "Gateway qualification release is not a private regular file",
            ));
        }
        let mut contents = [0_u8; RELEASE_CONTENTS.len()];
        release
            .read_exact(&mut contents)
            .map_err(|error| GatewayServerError::io_at("qualification-release-read", error))?;
        let mut extra = [0_u8; 1];
        let extra_bytes = release
            .read(&mut extra)
            .map_err(|error| GatewayServerError::io_at("qualification-release-read", error))?;
        if contents != RELEASE_CONTENTS || extra_bytes != 0 {
            return Err(GatewayServerError::configuration(
                "Gateway qualification release content is invalid",
            ));
        }
        return Ok(());
    }
}

fn write_private_marker(path: &Path, contents: &[u8]) -> Result<(), GatewayServerError> {
    let parent = path.parent().ok_or_else(|| {
        GatewayServerError::configuration("Gateway qualification marker parent is invalid")
    })?;
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK);
    let parent_directory = parent_options
        .open(parent)
        .map_err(|error| GatewayServerError::io_at("qualification-parent-open", error))?;
    let parent_metadata = parent_directory
        .metadata()
        .map_err(|error| GatewayServerError::io_at("qualification-parent-metadata", error))?;
    // SAFETY: geteuid has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if !parent_metadata.is_dir()
        || parent_metadata.mode() & 0o077 != 0
        || parent_metadata.uid() != effective_uid
    {
        return Err(GatewayServerError::configuration(
            "Gateway qualification marker parent must be private",
        ));
    }

    let mut marker_options = OpenOptions::new();
    marker_options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut marker = marker_options
        .open(path)
        .map_err(|error| GatewayServerError::io_at("qualification-marker-open", error))?;
    let marker_metadata = marker
        .metadata()
        .map_err(|error| GatewayServerError::io_at("qualification-marker-metadata", error))?;
    if !marker_metadata.is_file()
        || marker_metadata.mode() & 0o777 != 0o600
        || marker_metadata.nlink() != 1
        || marker_metadata.uid() != effective_uid
    {
        return Err(GatewayServerError::configuration(
            "Gateway qualification marker is not a private regular file",
        ));
    }

    marker
        .write_all(contents)
        .map_err(|error| GatewayServerError::io_at("qualification-marker-write", error))?;
    marker
        .sync_all()
        .map_err(|error| GatewayServerError::io_at("qualification-marker-sync", error))?;
    parent_directory
        .sync_all()
        .map_err(|error| GatewayServerError::io_at("qualification-parent-sync", error))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn private() -> Self {
            let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "apolysis-gateway-qualification-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create qualification test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("make qualification test directory private");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn wait_for_marker(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("qualification marker was not created within the test bound");
    }

    #[test]
    fn parses_only_frozen_lifecycle_operations() {
        assert_eq!(
            GatewayRouteOperation::parse("open_run").unwrap(),
            GatewayRouteOperation::OpenRun
        );
        assert_eq!(
            GatewayRouteOperation::parse("finish_run").unwrap(),
            GatewayRouteOperation::FinishRun
        );
        assert!(GatewayRouteOperation::parse("query").is_err());
    }

    #[tokio::test]
    async fn writes_one_private_static_marker_before_holding() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let barrier = QualificationBarrier::new(GatewayRouteOperation::OpenRun, marker.clone())
            .expect("valid qualification barrier");
        let worker =
            tokio::spawn(async move { barrier.reach(GatewayRouteOperation::OpenRun).await });

        wait_for_marker(&marker).await;

        assert_eq!(fs::read(&marker).unwrap(), MARKER_CONTENTS);
        let metadata = fs::symlink_metadata(&marker).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(!worker.is_finished());
        worker.abort();
    }

    #[tokio::test]
    async fn pre_operation_barrier_waits_for_a_private_static_release() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let release = directory.path().join("release");
        let barrier = QualificationBarrier::pre_operation(
            GatewayRouteOperation::OpenRun,
            marker.clone(),
            release.clone(),
        )
        .expect("valid pre-operation barrier");
        let worker = tokio::spawn(async move {
            barrier
                .before_operation(GatewayRouteOperation::OpenRun)
                .await
        });

        wait_for_marker(&marker).await;
        assert_eq!(fs::read(&marker).unwrap(), PRE_OPERATION_MARKER_CONTENTS);
        assert!(!worker.is_finished());

        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(&release)
            .and_then(|mut file| file.write_all(b"release\n"))
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .expect("pre-operation barrier observes release")
            .expect("pre-operation barrier worker completes")
            .expect("valid private release");
    }

    #[test]
    fn pre_operation_barrier_rejects_a_stale_release() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let release = directory.path().join("release");
        fs::write(&release, RELEASE_CONTENTS).unwrap();

        assert!(QualificationBarrier::pre_operation(
            GatewayRouteOperation::OpenRun,
            marker,
            release,
        )
        .is_err());
    }

    #[tokio::test]
    async fn pre_operation_barrier_rejects_a_symlinked_release() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let release = directory.path().join("release");
        let target = directory.path().join("target");
        let barrier = QualificationBarrier::pre_operation(
            GatewayRouteOperation::OpenRun,
            marker.clone(),
            release.clone(),
        )
        .unwrap();
        let worker = tokio::spawn(async move {
            barrier
                .before_operation(GatewayRouteOperation::OpenRun)
                .await
        });
        wait_for_marker(&marker).await;
        fs::write(&target, RELEASE_CONTENTS).unwrap();
        symlink(&target, &release).unwrap();

        assert!(worker.await.unwrap().is_err());
        assert_eq!(fs::read(&target).unwrap(), RELEASE_CONTENTS);
    }

    #[tokio::test]
    async fn pre_operation_barrier_rejects_broad_or_changed_release_files() {
        for (mode, contents) in [(0o644, RELEASE_CONTENTS), (0o600, b"changed\n")] {
            let directory = TestDirectory::private();
            let marker = directory.path().join("reached");
            let release = directory.path().join("release");
            let barrier = QualificationBarrier::pre_operation(
                GatewayRouteOperation::OpenRun,
                marker.clone(),
                release.clone(),
            )
            .unwrap();
            let worker = tokio::spawn(async move {
                barrier
                    .before_operation(GatewayRouteOperation::OpenRun)
                    .await
            });
            wait_for_marker(&marker).await;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(mode);
            options
                .open(&release)
                .and_then(|mut file| file.write_all(contents))
                .unwrap();

            assert!(worker.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn missing_pre_operation_release_times_out_closed() {
        let directory = TestDirectory::private();
        let release = directory.path().join("release");

        assert!(
            wait_for_private_release(&release, Duration::from_millis(20))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_a_symlinked_marker_without_overwriting_its_target() {
        let directory = TestDirectory::private();
        let target = directory.path().join("target");
        let marker = directory.path().join("reached");
        fs::write(&target, b"unchanged\n").unwrap();
        symlink(&target, &marker).unwrap();
        let barrier = QualificationBarrier::new(GatewayRouteOperation::OpenRun, marker).unwrap();

        assert!(barrier.reach(GatewayRouteOperation::OpenRun).await.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged\n");
    }

    #[tokio::test]
    async fn non_target_operations_do_not_create_a_marker() {
        let directory = TestDirectory::private();
        let marker = directory.path().join("reached");
        let barrier =
            QualificationBarrier::new(GatewayRouteOperation::OpenRun, marker.clone()).unwrap();

        barrier.reach(GatewayRouteOperation::Ingest).await.unwrap();

        assert!(!marker.exists());
    }
}

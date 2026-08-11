// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

use apolysis_core::{kubernetes_reference_v1, KubernetesReferenceKind};
use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

mod capture;
mod kube_adapter;
mod runtime;
mod server;

pub use apolysis_core::KubernetesContainerKind as ContainerKind;
pub use capture::{
    AuthoritativeSnapshotSource, CaptureLimits, KubernetesApiContainer, KubernetesApiPod,
    KubernetesListPort, KubernetesPodPage, KubernetesWatchPort, ListPageRequest, SourceProfile,
    WatchPollOutcome, WatchRequest, OBSERVATION_MARKER_SELECTOR,
};
pub use kube_adapter::KubeListAdapter;
pub use runtime::{run_production_source, ProductionSourceConfig};
pub use server::{
    run_source_server, DirtyTracker, SnapshotProvider, SourceServerConfig, SourceServerSummary,
};

pub const KUBERNETES_SOURCE_SCHEMA_V1: u16 = 1;
pub const DEFAULT_MAX_IPC_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const SOURCE_CONTAINER_UID: u32 = 65_532;
pub const SOURCE_CONTAINER_GID: u32 = 65_532;
pub const MAX_SNAPSHOT_PODS: usize = 4_096;
pub const MAX_SNAPSHOT_CONTAINERS_PER_POD: usize = 32;

/// A source-process generation identifier.
///
/// ```compile_fail
/// use apolysis_kubernetes_source::{KubernetesClusterId, SourceEpoch};
/// let cluster = KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
/// let _: SourceEpoch = cluster;
/// ```
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceEpoch(String);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KubernetesClusterId(String);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KubernetesPodUid(String);

impl SourceEpoch {
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

fn parse_canonical_uuid(value: &str) -> Result<String, IdentifierError> {
    let parsed = Uuid::parse_str(value).map_err(|_| IdentifierError::InvalidUuid)?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(IdentifierError::InvalidUuid);
    }
    Ok(value.to_owned())
}

macro_rules! impl_canonical_uuid {
    ($name:ident) => {
        impl $name {
            pub fn parse(value: &str) -> Result<Self, IdentifierError> {
                parse_canonical_uuid(value).map(Self)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(&value).map_err(de::Error::custom)
            }
        }
    };
}

impl_canonical_uuid!(SourceEpoch);
impl_canonical_uuid!(KubernetesClusterId);
impl_canonical_uuid!(KubernetesPodUid);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueRef(String);

impl OpaqueRef {
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(IdentifierError::InvalidOpaqueRef);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OpaqueRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RuntimeContainerId(String);

impl RuntimeContainerId {
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        let Some(identifier) = value.strip_prefix("containerd://") else {
            return Err(IdentifierError::UnsupportedRuntimeContainerId);
        };
        if identifier.len() != 64
            || !identifier
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(IdentifierError::UnsupportedRuntimeContainerId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RuntimeContainerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesSnapshot {
    pub schema_version: u16,
    pub source_epoch: SourceEpoch,
    pub snapshot_sequence: u64,
    pub cluster_id: KubernetesClusterId,
    pub namespace_ref: OpaqueRef,
    pub node_ref: OpaqueRef,
    pub pods: Vec<KubernetesPodSnapshot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KubernetesSnapshotWire {
    schema_version: u16,
    source_epoch: SourceEpoch,
    snapshot_sequence: u64,
    cluster_id: KubernetesClusterId,
    namespace_ref: OpaqueRef,
    node_ref: OpaqueRef,
    pods: Vec<KubernetesPodSnapshot>,
}

impl<'de> Deserialize<'de> for KubernetesSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KubernetesSnapshotWire::deserialize(deserializer)?;
        if wire.schema_version != KUBERNETES_SOURCE_SCHEMA_V1 {
            return Err(de::Error::custom("unsupported kubernetes source schema"));
        }
        if wire.snapshot_sequence == 0 {
            return Err(de::Error::custom("invalid kubernetes snapshot sequence"));
        }
        if wire.pods.len() > MAX_SNAPSHOT_PODS
            || wire.pods.iter().any(|pod| {
                pod.containers.len() > MAX_SNAPSHOT_CONTAINERS_PER_POD
                    || pod.containers.iter().any(|container| {
                        container.running && container.runtime_container_id.is_none()
                    })
                    || !pod.containers.windows(2).all(|pair| {
                        (&pair[0].kind, &pair[0].container_ref)
                            < (&pair[1].kind, &pair[1].container_ref)
                    })
            })
            || !wire
                .pods
                .windows(2)
                .all(|pair| pair[0].pod_uid < pair[1].pod_uid)
        {
            return Err(de::Error::custom("invalid kubernetes snapshot contents"));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            source_epoch: wire.source_epoch,
            snapshot_sequence: wire.snapshot_sequence,
            cluster_id: wire.cluster_id,
            namespace_ref: wire.namespace_ref,
            node_ref: wire.node_ref,
            pods: wire.pods,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesPodSnapshot {
    pub pod_uid: KubernetesPodUid,
    pub pod_revision_ref: OpaqueRef,
    pub deleting: bool,
    pub runtime_class_ref: Option<OpaqueRef>,
    pub containers: Vec<KubernetesContainerSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesContainerSnapshot {
    pub kind: ContainerKind,
    pub container_ref: OpaqueRef,
    pub runtime_container_id: Option<RuntimeContainerId>,
    pub running: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceRequest {
    Capture {
        schema_version: u16,
    },
    WaitDirty {
        schema_version: u16,
        source_epoch: Option<SourceEpoch>,
        after_dirty_sequence: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceResponse {
    Snapshot {
        schema_version: u16,
        snapshot: KubernetesSnapshot,
    },
    Dirty {
        schema_version: u16,
        source_epoch: SourceEpoch,
        dirty_sequence: u64,
        relist_required: bool,
    },
    Idle {
        schema_version: u16,
        source_epoch: SourceEpoch,
        dirty_sequence: u64,
    },
    Error {
        schema_version: u16,
        error: KubernetesSourceErrorKind,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesSourceErrorKind {
    Unavailable,
    Timeout,
    Unauthorized,
    Forbidden,
    Malformed,
    Oversized,
    Inconsistent,
    Protocol,
}

impl KubernetesSourceErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Malformed => "malformed",
            Self::Oversized => "oversized",
            Self::Inconsistent => "inconsistent",
            Self::Protocol => "protocol",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KubernetesSourceError {
    kind: KubernetesSourceErrorKind,
}

impl KubernetesSourceError {
    pub const fn new(kind: KubernetesSourceErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> KubernetesSourceErrorKind {
        self.kind
    }
}

impl fmt::Display for KubernetesSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "kubernetes_source_error kind={}",
            self.kind.as_str()
        )
    }
}

impl std::error::Error for KubernetesSourceError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesSourceClientConfig {
    socket_path: PathBuf,
    expected_source_uid: u32,
    expected_source_gid: u32,
    io_timeout: Duration,
    max_frame_bytes: usize,
}

impl KubernetesSourceClientConfig {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_source_uid: SOURCE_CONTAINER_UID,
            expected_source_gid: SOURCE_CONTAINER_GID,
            io_timeout: Duration::from_secs(5),
            max_frame_bytes: DEFAULT_MAX_IPC_FRAME_BYTES,
        }
    }

    pub fn with_expected_source_uid(mut self, expected_source_uid: u32) -> Self {
        self.expected_source_uid = expected_source_uid;
        self
    }

    pub fn with_expected_source_gid(mut self, expected_source_gid: u32) -> Self {
        self.expected_source_gid = expected_source_gid;
        self
    }

    pub fn with_io_timeout(mut self, io_timeout: Duration) -> Self {
        self.io_timeout = io_timeout;
        self
    }

    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }
}

#[derive(Clone, Debug)]
pub struct KubernetesSourceClient {
    config: KubernetesSourceClientConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceSocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirtyWaitOutcome {
    Dirty {
        source_epoch: SourceEpoch,
        dirty_sequence: u64,
        relist_required: bool,
    },
    Idle {
        source_epoch: SourceEpoch,
        dirty_sequence: u64,
    },
}

impl KubernetesSourceClient {
    pub fn new(config: KubernetesSourceClientConfig) -> Result<Self, KubernetesSourceError> {
        if config.socket_path.as_os_str().is_empty()
            || config.io_timeout.is_zero()
            || config.max_frame_bytes == 0
            || config.max_frame_bytes > DEFAULT_MAX_IPC_FRAME_BYTES
        {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Malformed,
            ));
        }
        Ok(Self { config })
    }

    pub async fn capture(&self) -> Result<KubernetesSnapshot, KubernetesSourceError> {
        let response = self
            .exchange(SourceRequest::Capture {
                schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
            })
            .await?;
        match response {
            SourceResponse::Snapshot {
                schema_version,
                snapshot,
            } if schema_version == KUBERNETES_SOURCE_SCHEMA_V1
                && snapshot.schema_version == KUBERNETES_SOURCE_SCHEMA_V1 =>
            {
                Ok(snapshot)
            }
            SourceResponse::Error {
                schema_version,
                error,
            } if schema_version == KUBERNETES_SOURCE_SCHEMA_V1 => {
                Err(KubernetesSourceError::new(error))
            }
            _ => Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Protocol,
            )),
        }
    }

    pub async fn wait_dirty(
        &self,
        source_epoch: Option<SourceEpoch>,
        after_dirty_sequence: u64,
    ) -> Result<DirtyWaitOutcome, KubernetesSourceError> {
        let response = self
            .exchange(SourceRequest::WaitDirty {
                schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                source_epoch: source_epoch.clone(),
                after_dirty_sequence,
            })
            .await?;
        match response {
            SourceResponse::Dirty {
                schema_version,
                source_epoch: response_epoch,
                dirty_sequence,
                relist_required,
            } if schema_version == KUBERNETES_SOURCE_SCHEMA_V1
                && dirty_sequence > 0
                && (source_epoch.as_ref() != Some(&response_epoch)
                    || dirty_sequence > after_dirty_sequence)
                && (source_epoch.as_ref() == Some(&response_epoch) || relist_required) =>
            {
                Ok(DirtyWaitOutcome::Dirty {
                    source_epoch: response_epoch,
                    dirty_sequence,
                    relist_required,
                })
            }
            SourceResponse::Idle {
                schema_version,
                source_epoch: response_epoch,
                dirty_sequence,
            } if schema_version == KUBERNETES_SOURCE_SCHEMA_V1
                && source_epoch
                    .as_ref()
                    .is_none_or(|expected| expected == &response_epoch)
                && dirty_sequence == after_dirty_sequence =>
            {
                Ok(DirtyWaitOutcome::Idle {
                    source_epoch: response_epoch,
                    dirty_sequence,
                })
            }
            SourceResponse::Error {
                schema_version,
                error,
            } if schema_version == KUBERNETES_SOURCE_SCHEMA_V1 => {
                Err(KubernetesSourceError::new(error))
            }
            _ => Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Protocol,
            )),
        }
    }

    async fn exchange(
        &self,
        request: SourceRequest,
    ) -> Result<SourceResponse, KubernetesSourceError> {
        let expected_socket = self.validate_socket()?;
        let exchange = async {
            let mut stream = UnixStream::connect(&self.config.socket_path)
                .await
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
            let peer = stream
                .peer_cred()
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unauthorized))?;
            if peer.uid() != self.config.expected_source_uid
                || peer.gid() != self.config.expected_source_gid
            {
                return Err(KubernetesSourceError::new(
                    KubernetesSourceErrorKind::Unauthorized,
                ));
            }
            self.validate_socket_identity(expected_socket)?;

            let body = serde_json::to_vec(&request)
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
            write_frame(&mut stream, &body, self.config.max_frame_bytes).await?;
            let response = read_frame(&mut stream, self.config.max_frame_bytes).await?;
            serde_json::from_slice(&response)
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))
        };
        tokio::time::timeout(self.config.io_timeout, exchange)
            .await
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Timeout))?
    }

    fn validate_socket(&self) -> Result<SourceSocketIdentity, KubernetesSourceError> {
        let metadata = std::fs::symlink_metadata(&self.config.socket_path)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != self.config.expected_source_uid
            || metadata.gid() != self.config.expected_source_gid
            || metadata.permissions().mode() & 0o777 != 0o660
        {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unauthorized,
            ));
        }
        Ok(SourceSocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.permissions().mode() & 0o777,
        })
    }

    fn validate_socket_identity(
        &self,
        expected: SourceSocketIdentity,
    ) -> Result<(), KubernetesSourceError> {
        if self.validate_socket()? != expected {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Unauthorized,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod socket_identity_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn connected_socket_identity_rejects_a_replaced_path() {
        let directory = tempfile::tempdir().expect("temporary socket directory");
        let path = directory.path().join("source.sock");
        let moved = directory.path().join("source-original.sock");
        let original = UnixListener::bind(&path).expect("bind original socket");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("restrict original socket");
        let client = KubernetesSourceClient::new(
            KubernetesSourceClientConfig::new(&path)
                .with_expected_source_uid(unsafe { libc::geteuid() })
                .with_expected_source_gid(unsafe { libc::getegid() }),
        )
        .expect("valid client");
        let expected = client.validate_socket().expect("original socket identity");

        std::fs::rename(&path, &moved).expect("move original socket");
        let replacement = UnixListener::bind(&path).expect("bind replacement socket");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .expect("restrict replacement socket");

        assert_eq!(
            client
                .validate_socket_identity(expected)
                .expect_err("replacement socket identity")
                .kind(),
            KubernetesSourceErrorKind::Unauthorized
        );
        drop(replacement);
        drop(original);
    }
}

async fn read_frame(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<Vec<u8>, KubernetesSourceError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Oversized,
        ));
    }
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    Ok(body)
}

async fn write_frame(
    stream: &mut UnixStream,
    body: &[u8],
    maximum: usize,
) -> Result<(), KubernetesSourceError> {
    if body.is_empty() || body.len() > maximum || body.len() > u32::MAX as usize {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Oversized,
        ));
    }
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
    stream
        .write_all(body)
        .await
        .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    InvalidDnsLabel,
    InvalidDnsSubdomain,
    InvalidOpaqueRef,
    InvalidResourceVersion,
    InvalidUuid,
    UnsupportedRuntimeContainerId,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDnsLabel => "invalid DNS label",
            Self::InvalidDnsSubdomain => "invalid DNS subdomain",
            Self::InvalidOpaqueRef => "invalid opaque reference",
            Self::InvalidResourceVersion => "invalid Kubernetes resource version",
            Self::InvalidUuid => "invalid canonical UUID",
            Self::UnsupportedRuntimeContainerId => "unsupported runtime container identifier",
        })
    }
}

impl std::error::Error for IdentifierError {}

pub fn kubernetes_namespace_ref(value: &str) -> Result<OpaqueRef, IdentifierError> {
    reference(KubernetesReferenceKind::Namespace, value)
}

pub fn kubernetes_node_ref(value: &str) -> Result<OpaqueRef, IdentifierError> {
    reference(KubernetesReferenceKind::Node, value)
}

pub fn kubernetes_container_ref(value: &str) -> Result<OpaqueRef, IdentifierError> {
    reference(KubernetesReferenceKind::Container, value)
}

pub fn kubernetes_runtime_class_ref(value: &str) -> Result<OpaqueRef, IdentifierError> {
    reference(KubernetesReferenceKind::RuntimeClass, value)
}

pub fn kubernetes_pod_revision_ref(value: &str) -> Result<OpaqueRef, IdentifierError> {
    const MAX_RESOURCE_VERSION_BYTES: usize = 256;
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_RESOURCE_VERSION_BYTES
        || bytes.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(IdentifierError::InvalidResourceVersion);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"apolysis:kubernetes-pod-revision:v1");
    hasher.update([0]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    OpaqueRef::parse(&output)
}

fn reference(kind: KubernetesReferenceKind, value: &str) -> Result<OpaqueRef, IdentifierError> {
    let reference = kubernetes_reference_v1(kind, value).map_err(|_| match kind {
        KubernetesReferenceKind::Namespace | KubernetesReferenceKind::Container => {
            IdentifierError::InvalidDnsLabel
        }
        KubernetesReferenceKind::Node | KubernetesReferenceKind::RuntimeClass => {
            IdentifierError::InvalidDnsSubdomain
        }
    })?;
    OpaqueRef::parse(&reference)
}

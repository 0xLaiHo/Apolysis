// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use tokio::sync::Mutex;

use crate::{
    kubernetes_container_ref, kubernetes_namespace_ref, kubernetes_node_ref,
    kubernetes_pod_revision_ref, kubernetes_runtime_class_ref, ContainerKind, KubernetesClusterId,
    KubernetesContainerSnapshot, KubernetesPodSnapshot, KubernetesPodUid, KubernetesSnapshot,
    KubernetesSourceError, KubernetesSourceErrorKind, RuntimeContainerId, SourceEpoch,
    KUBERNETES_SOURCE_SCHEMA_V1,
};

pub const OBSERVATION_MARKER_SELECTOR: &str = "apolysis.dev/observe=true";

const MAX_PAGE_SIZE: u32 = 500;
const MAX_PAGES_HARD: usize = 16;
const MAX_PODS_HARD: usize = 4_096;
const MAX_CONTAINERS_PER_POD_HARD: usize = 32;
const MAX_RESPONSE_BYTES_HARD: usize = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES_HARD: usize = 8 * 1024 * 1024;
const MAX_RESOURCE_VERSION_BYTES: usize = 256;
const MAX_CONTINUE_TOKEN_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    pub page_size: u32,
    pub max_pages: usize,
    pub max_pods: usize,
    pub max_containers_per_pod: usize,
    pub max_response_bytes: usize,
    pub max_snapshot_bytes: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            page_size: 256,
            max_pages: 16,
            max_pods: 4_096,
            max_containers_per_pod: 32,
            max_response_bytes: 8 * 1024 * 1024,
            max_snapshot_bytes: 8 * 1024 * 1024,
        }
    }
}

impl CaptureLimits {
    fn validate(self) -> Result<Self, KubernetesSourceError> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES_HARD
            || self.max_pods == 0
            || self.max_pods > MAX_PODS_HARD
            || self.max_containers_per_pod == 0
            || self.max_containers_per_pod > MAX_CONTAINERS_PER_POD_HARD
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES_HARD
            || self.max_snapshot_bytes == 0
            || self.max_snapshot_bytes > MAX_SNAPSHOT_BYTES_HARD
        {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Malformed,
            ));
        }
        Ok(self)
    }
}

pub struct SourceProfile {
    cluster_id: KubernetesClusterId,
    namespace: String,
    node_name: String,
    namespace_ref: crate::OpaqueRef,
    node_ref: crate::OpaqueRef,
    limits: CaptureLimits,
}

impl SourceProfile {
    pub fn new(
        cluster_id: KubernetesClusterId,
        namespace: impl Into<String>,
        node_name: impl Into<String>,
        limits: CaptureLimits,
    ) -> Result<Self, KubernetesSourceError> {
        let namespace = namespace.into();
        let node_name = node_name.into();
        let namespace_ref = kubernetes_namespace_ref(&namespace)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
        let node_ref = kubernetes_node_ref(&node_name)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
        Ok(Self {
            cluster_id,
            namespace,
            node_name,
            namespace_ref,
            node_ref,
            limits: limits.validate()?,
        })
    }
}

pub struct ListPageRequest {
    namespace: String,
    node_name: String,
    marker_selector: &'static str,
    continue_token: Option<String>,
    page_size: u32,
}

pub struct WatchRequest {
    namespace: String,
    node_name: String,
    marker_selector: &'static str,
    resource_version: String,
}

impl WatchRequest {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    pub const fn marker_selector(&self) -> &'static str {
        self.marker_selector
    }

    pub fn resource_version(&self) -> &str {
        &self.resource_version
    }
}

impl ListPageRequest {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    pub const fn marker_selector(&self) -> &'static str {
        self.marker_selector
    }

    pub fn continue_token(&self) -> Option<&str> {
        self.continue_token.as_deref()
    }

    pub const fn page_size(&self) -> u32 {
        self.page_size
    }
}

pub struct KubernetesPodPage {
    pub resource_version: String,
    pub continue_token: Option<String>,
    pub encoded_bytes: usize,
    pub pods: Vec<KubernetesApiPod>,
}

pub struct KubernetesApiPod {
    pub namespace: String,
    pub node_name: String,
    pub marked_for_observation: bool,
    pub pod_uid: String,
    pub resource_version: String,
    pub deleting: bool,
    pub runtime_class_name: Option<String>,
    pub containers: Vec<KubernetesApiContainer>,
}

pub struct KubernetesApiContainer {
    pub kind: ContainerKind,
    pub name: String,
    pub runtime_container_id: Option<String>,
    pub running: bool,
}

pub trait KubernetesListPort: Send + Sync {
    fn list_page(
        &self,
        request: ListPageRequest,
    ) -> impl std::future::Future<Output = Result<KubernetesPodPage, KubernetesSourceErrorKind>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchPollOutcome {
    Dirty,
    Idle,
    RelistRequired,
}

pub trait KubernetesWatchPort: Send + Sync {
    fn watch_once(
        &self,
        request: WatchRequest,
    ) -> impl std::future::Future<Output = Result<WatchPollOutcome, KubernetesSourceErrorKind>> + Send;
}

struct CaptureState {
    snapshot_sequence: u64,
    resource_version: Option<String>,
}

pub struct AuthoritativeSnapshotSource<P> {
    profile: SourceProfile,
    port: P,
    source_epoch: SourceEpoch,
    state: Mutex<CaptureState>,
}

impl<P> AuthoritativeSnapshotSource<P>
where
    P: KubernetesListPort,
{
    pub fn new(profile: SourceProfile, port: P) -> Self {
        Self {
            profile,
            port,
            source_epoch: SourceEpoch::random(),
            state: Mutex::new(CaptureState {
                snapshot_sequence: 0,
                resource_version: None,
            }),
        }
    }

    pub fn source_epoch(&self) -> &SourceEpoch {
        &self.source_epoch
    }

    pub async fn capture(&self) -> Result<KubernetesSnapshot, KubernetesSourceError> {
        let mut state = self.state.lock().await;
        let mut continue_token = None;
        let mut seen_continue_tokens = BTreeSet::new();
        let mut resource_version = None;
        let mut response_bytes = 0_usize;
        let mut pods = BTreeMap::new();

        for page_index in 0..self.profile.limits.max_pages {
            let page = self
                .port
                .list_page(ListPageRequest {
                    namespace: self.profile.namespace.clone(),
                    node_name: self.profile.node_name.clone(),
                    marker_selector: OBSERVATION_MARKER_SELECTOR,
                    continue_token: continue_token.clone(),
                    page_size: self.profile.limits.page_size,
                })
                .await
                .map_err(KubernetesSourceError::new)?;

            validate_resource_version(&page.resource_version)?;
            if resource_version
                .as_ref()
                .is_some_and(|expected| expected != &page.resource_version)
            {
                return Err(KubernetesSourceError::new(
                    KubernetesSourceErrorKind::Inconsistent,
                ));
            }
            resource_version.get_or_insert(page.resource_version);
            response_bytes = response_bytes
                .checked_add(page.encoded_bytes)
                .ok_or_else(|| KubernetesSourceError::new(KubernetesSourceErrorKind::Oversized))?;
            if page.encoded_bytes == 0 || response_bytes > self.profile.limits.max_response_bytes {
                return Err(KubernetesSourceError::new(
                    KubernetesSourceErrorKind::Oversized,
                ));
            }
            if pods.len().saturating_add(page.pods.len()) > self.profile.limits.max_pods {
                return Err(KubernetesSourceError::new(
                    KubernetesSourceErrorKind::Oversized,
                ));
            }

            for raw in page.pods {
                let pod = self.normalize_pod(raw)?;
                if pods.insert(pod.pod_uid.clone(), pod).is_some() {
                    return Err(KubernetesSourceError::new(
                        KubernetesSourceErrorKind::Inconsistent,
                    ));
                }
            }

            match page.continue_token {
                None => {
                    let sequence = state.snapshot_sequence.checked_add(1).ok_or_else(|| {
                        KubernetesSourceError::new(KubernetesSourceErrorKind::Oversized)
                    })?;
                    let snapshot = KubernetesSnapshot {
                        schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
                        source_epoch: self.source_epoch.clone(),
                        snapshot_sequence: sequence,
                        cluster_id: self.profile.cluster_id.clone(),
                        namespace_ref: self.profile.namespace_ref.clone(),
                        node_ref: self.profile.node_ref.clone(),
                        pods: pods.into_values().collect(),
                    };
                    let snapshot_bytes = serde_json::to_vec(&snapshot)
                        .map_err(|_| {
                            KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed)
                        })?
                        .len();
                    if snapshot_bytes > self.profile.limits.max_snapshot_bytes {
                        return Err(KubernetesSourceError::new(
                            KubernetesSourceErrorKind::Oversized,
                        ));
                    }
                    state.snapshot_sequence = sequence;
                    state.resource_version = resource_version;
                    return Ok(snapshot);
                }
                Some(token) => {
                    validate_continue_token(&token)?;
                    if !seen_continue_tokens.insert(token.clone()) {
                        return Err(KubernetesSourceError::new(
                            KubernetesSourceErrorKind::Inconsistent,
                        ));
                    }
                    if page_index + 1 == self.profile.limits.max_pages {
                        return Err(KubernetesSourceError::new(
                            KubernetesSourceErrorKind::Oversized,
                        ));
                    }
                    continue_token = Some(token);
                }
            }
        }

        Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Inconsistent,
        ))
    }

    fn normalize_pod(
        &self,
        raw: KubernetesApiPod,
    ) -> Result<KubernetesPodSnapshot, KubernetesSourceError> {
        if raw.namespace != self.profile.namespace
            || raw.node_name != self.profile.node_name
            || !raw.marked_for_observation
            || raw.containers.len() > self.profile.limits.max_containers_per_pod
        {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Inconsistent,
            ));
        }
        let pod_uid = KubernetesPodUid::parse(&raw.pod_uid)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
        let pod_revision_ref = kubernetes_pod_revision_ref(&raw.resource_version)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
        let runtime_class_ref = raw
            .runtime_class_name
            .as_deref()
            .map(kubernetes_runtime_class_ref)
            .transpose()
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
        let mut containers = Vec::with_capacity(raw.containers.len());
        let mut slots = BTreeSet::new();
        for raw_container in raw.containers {
            let container_ref = kubernetes_container_ref(&raw_container.name)
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
            if !slots.insert((raw_container.kind, container_ref.clone())) {
                return Err(KubernetesSourceError::new(
                    KubernetesSourceErrorKind::Inconsistent,
                ));
            }
            let runtime_container_id = raw_container
                .runtime_container_id
                .as_deref()
                .map(RuntimeContainerId::parse)
                .transpose()
                .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Malformed))?;
            if raw_container.running && runtime_container_id.is_none() {
                return Err(KubernetesSourceError::new(
                    KubernetesSourceErrorKind::Malformed,
                ));
            }
            containers.push(KubernetesContainerSnapshot {
                kind: raw_container.kind,
                container_ref,
                runtime_container_id,
                running: raw_container.running,
            });
        }
        containers.sort_by(|left, right| {
            (&left.kind, &left.container_ref).cmp(&(&right.kind, &right.container_ref))
        });
        Ok(KubernetesPodSnapshot {
            pod_uid,
            pod_revision_ref,
            deleting: raw.deleting,
            runtime_class_ref,
            containers,
        })
    }
}

impl<P> AuthoritativeSnapshotSource<P>
where
    P: KubernetesListPort + KubernetesWatchPort,
{
    pub async fn poll_watch(&self) -> Result<WatchPollOutcome, KubernetesSourceError> {
        let resource_version = self.state.lock().await.resource_version.clone();
        let Some(resource_version) = resource_version else {
            return Ok(WatchPollOutcome::RelistRequired);
        };
        self.port
            .watch_once(WatchRequest {
                namespace: self.profile.namespace.clone(),
                node_name: self.profile.node_name.clone(),
                marker_selector: OBSERVATION_MARKER_SELECTOR,
                resource_version,
            })
            .await
            .map_err(KubernetesSourceError::new)
    }
}

fn validate_resource_version(value: &str) -> Result<(), KubernetesSourceError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_VERSION_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Malformed,
        ));
    }
    Ok(())
}

fn validate_continue_token(value: &str) -> Result<(), KubernetesSourceError> {
    if value.is_empty()
        || value.len() > MAX_CONTINUE_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(KubernetesSourceError::new(
            KubernetesSourceErrorKind::Malformed,
        ));
    }
    Ok(())
}

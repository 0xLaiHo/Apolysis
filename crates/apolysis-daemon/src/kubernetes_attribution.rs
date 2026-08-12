// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use apolysis_accountability::{AdapterKind, ComponentState};
use apolysis_core::{kubernetes_reference_v1, KubernetesContainerKind, KubernetesReferenceKind};
use apolysis_kubernetes::{
    KubernetesContainerCandidate, KubernetesPodCandidate,
    KubernetesPodSnapshot as QualifiedPodSnapshot, KubernetesSnapshotIdentity,
    KubernetesSourceUnavailableReason,
};
use apolysis_kubernetes_source::{
    ContainerKind, DirtyWaitOutcome, KubernetesSnapshot, KubernetesSourceClient,
    KubernetesSourceClientConfig, KubernetesSourceErrorKind,
};
use tokio::sync::oneshot;

use crate::{
    adapter_backoff_delay, AdapterBackoffPolicy, ContainerdCriRuntimeAdapter, CriRuntimeClient,
    DaemonConfig, DaemonState, RuntimeAdapterSummary, RuntimeInventoryAdapter,
};

type SourceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, KubernetesSourceErrorKind>> + Send + 'a>>;

trait KubernetesSourcePort: Send + Sync + 'static {
    fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot>;

    fn wait_dirty(
        &self,
        source_epoch: Option<String>,
        after_dirty_sequence: u64,
    ) -> SourceFuture<'_, SourceDirtyOutcome>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceDirtyOutcome {
    Dirty {
        source_epoch: String,
        dirty_sequence: u64,
    },
    Idle {
        source_epoch: String,
        dirty_sequence: u64,
    },
}

impl KubernetesSourcePort for KubernetesSourceClient {
    fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot> {
        Box::pin(async move { self.capture().await.map_err(|error| error.kind()) })
    }

    fn wait_dirty(
        &self,
        source_epoch: Option<String>,
        after_dirty_sequence: u64,
    ) -> SourceFuture<'_, SourceDirtyOutcome> {
        Box::pin(async move {
            let source_epoch = source_epoch
                .as_deref()
                .map(apolysis_kubernetes_source::SourceEpoch::parse)
                .transpose()
                .map_err(|_| KubernetesSourceErrorKind::Protocol)?;
            match self
                .wait_dirty(source_epoch, after_dirty_sequence)
                .await
                .map_err(|error| error.kind())?
            {
                DirtyWaitOutcome::Dirty {
                    source_epoch,
                    dirty_sequence,
                    ..
                } => Ok(SourceDirtyOutcome::Dirty {
                    source_epoch: source_epoch.as_str().to_string(),
                    dirty_sequence,
                }),
                DirtyWaitOutcome::Idle {
                    source_epoch,
                    dirty_sequence,
                } => Ok(SourceDirtyOutcome::Idle {
                    source_epoch: source_epoch.as_str().to_string(),
                    dirty_sequence,
                }),
            }
        })
    }
}

#[derive(Clone, Debug)]
struct KubernetesNodeProfile {
    cluster_id: String,
    namespace: String,
    namespace_ref: String,
    node_ref: String,
    runtime_adapter: AdapterKind,
    scan_interval: Duration,
    runtime_scan_timeout: Duration,
}

impl KubernetesNodeProfile {
    fn from_config(config: &DaemonConfig) -> Result<Option<Self>, String> {
        let Some(source_socket) = config.kubernetes_source_socket.as_ref() else {
            return Ok(None);
        };
        let cluster_id = config
            .kubernetes_cluster_id
            .as_deref()
            .ok_or_else(|| "Kubernetes node profile is incomplete".to_string())?;
        apolysis_kubernetes_source::KubernetesClusterId::parse(cluster_id)
            .map_err(|_| "Kubernetes node profile cluster ID is invalid".to_string())?;
        let namespace = config
            .kubernetes_namespace
            .as_deref()
            .ok_or_else(|| "Kubernetes node profile is incomplete".to_string())?;
        let node_name = config
            .kubernetes_node_name
            .as_deref()
            .ok_or_else(|| "Kubernetes node profile is incomplete".to_string())?;
        let namespace_ref = kubernetes_reference_v1(KubernetesReferenceKind::Namespace, namespace)
            .map_err(|_| "Kubernetes node profile namespace is invalid".to_string())?;
        let node_ref = kubernetes_reference_v1(KubernetesReferenceKind::Node, node_name)
            .map_err(|_| "Kubernetes node profile node name is invalid".to_string())?;
        if !source_socket.is_absolute() {
            return Err("Kubernetes source socket must be absolute".to_string());
        }
        let runtime_adapter = match (
            config.containerd_socket.is_some(),
            config.k3s_containerd_socket.is_some(),
        ) {
            (true, false) => AdapterKind::Containerd,
            (false, true) => AdapterKind::K3sContainerd,
            _ => {
                return Err(
                    "Kubernetes node profile requires exactly one containerd runtime socket"
                        .to_string(),
                )
            }
        };
        Ok(Some(Self {
            cluster_id: cluster_id.to_string(),
            namespace: namespace.to_string(),
            namespace_ref,
            node_ref,
            runtime_adapter,
            scan_interval: config.runtime_adapter_scan_interval,
            runtime_scan_timeout: config.request_timeout,
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KubernetesNodeAttributionSummary {
    pub runtime: RuntimeAdapterSummary,
    pub qualified_cycles: u64,
    pub source_errors: u64,
}

pub struct KubernetesNodeAttributionTask {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<KubernetesNodeAttributionSummary>,
}

impl KubernetesNodeAttributionTask {
    pub fn start(config: &DaemonConfig, state: Arc<DaemonState>) -> Result<Option<Self>, String> {
        let Some(profile) = KubernetesNodeProfile::from_config(config)? else {
            return Ok(None);
        };
        let source_socket = config
            .kubernetes_source_socket
            .as_ref()
            .ok_or_else(|| "Kubernetes node profile is incomplete".to_string())?;
        let source = KubernetesSourceClient::new(
            KubernetesSourceClientConfig::new(source_socket)
                .with_io_timeout(config.request_timeout),
        )
        .map_err(|error| error.to_string())?;
        let runtime_socket = match profile.runtime_adapter {
            AdapterKind::Containerd => config.containerd_socket.clone(),
            AdapterKind::K3sContainerd => config.k3s_containerd_socket.clone(),
            _ => None,
        }
        .ok_or_else(|| "Kubernetes runtime socket is missing".to_string())?;
        let runtime_client = if profile.runtime_adapter == AdapterKind::K3sContainerd {
            CriRuntimeClient::new(runtime_socket).with_image_endpoint(None)
        } else {
            CriRuntimeClient::new(runtime_socket)
        };
        let runtime = ContainerdCriRuntimeAdapter::new(
            profile.runtime_adapter,
            runtime_client,
            config.proc_root.clone(),
            config.cgroup_root.clone(),
            config.runtime_adapter_scan_interval,
            config.runtime_adapter_seen_capacity,
        )?
        .with_kubernetes_sandbox_metadata(profile.namespace.clone())?;
        Ok(Some(Self::start_with_ports(
            profile, source, runtime, state,
        )))
    }

    fn start_with_ports<S, R>(
        profile: KubernetesNodeProfile,
        source: S,
        runtime: R,
        state: Arc<DaemonState>,
    ) -> Self
    where
        S: KubernetesSourcePort,
        R: RuntimeInventoryAdapter,
    {
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(run_kubernetes_node_attribution(
            profile, source, runtime, state, receiver,
        ));
        Self {
            shutdown: Some(shutdown),
            task,
        }
    }

    pub async fn shutdown(
        mut self,
        deadline: Duration,
    ) -> Result<KubernetesNodeAttributionSummary, String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        match tokio::time::timeout(deadline, &mut self.task).await {
            Ok(Ok(summary)) => Ok(summary),
            Ok(Err(error)) => Err(format!("Kubernetes attribution task failed: {error}")),
            Err(_) => {
                self.task.abort();
                Err("Kubernetes attribution task shutdown deadline exceeded".to_string())
            }
        }
    }
}

async fn run_kubernetes_node_attribution<S, R>(
    profile: KubernetesNodeProfile,
    source: S,
    runtime: R,
    state: Arc<DaemonState>,
    mut shutdown: oneshot::Receiver<()>,
) -> KubernetesNodeAttributionSummary
where
    S: KubernetesSourcePort,
    R: RuntimeInventoryAdapter,
{
    let adapter = runtime.kind();
    let mut summary = KubernetesNodeAttributionSummary {
        runtime: RuntimeAdapterSummary {
            adapter,
            discovered: 0,
            missing_intent: 0,
            backend_errors: 0,
            backend_recoveries: 0,
            ingest_errors: 0,
        },
        qualified_cycles: 0,
        source_errors: 0,
    };
    state
        .set_adapter(AdapterKind::Kubernetes, ComponentState::Unavailable)
        .await;
    let mut consecutive_errors = 0_u64;
    let mut dirty_epoch: Option<String> = None;
    let mut dirty_sequence = 0_u64;

    loop {
        let before = match select_capture(&source, &mut shutdown).await {
            CaptureOutcome::Shutdown => break,
            CaptureOutcome::Snapshot(snapshot) => snapshot,
            CaptureOutcome::Error(kind) => {
                record_source_error(&state, &profile, kind, &mut summary).await;
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        AdapterKind::Kubernetes,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
                continue;
            }
        };
        let before = match qualified_snapshot(&profile, before) {
            Ok(snapshot) => snapshot,
            Err(()) => {
                record_source_error(
                    &state,
                    &profile,
                    KubernetesSourceErrorKind::Inconsistent,
                    &mut summary,
                )
                .await;
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        AdapterKind::Kubernetes,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
                continue;
            }
        };
        let source_epoch = Some(before.identity.source_epoch.clone());
        if dirty_epoch.as_ref() != source_epoch.as_ref() {
            dirty_epoch = source_epoch.clone();
            dirty_sequence = 0;
        }

        let inventory = tokio::select! {
            _ = &mut shutdown => break,
            inventory = tokio::time::timeout(
                profile.runtime_scan_timeout,
                runtime.scan_inventory(),
            ) => match inventory {
                Ok(inventory) => inventory,
                Err(_) => Err(crate::RuntimeInventoryScanError::socket_unavailable(
                    "runtime inventory scan deadline exceeded",
                )),
            },
        };
        let inventory = match inventory {
            Ok(inventory) => inventory,
            Err(error) => {
                summary.runtime.backend_errors = summary.runtime.backend_errors.saturating_add(1);
                if state
                    .kubernetes_runtime_source_unavailable(
                        &profile.cluster_id,
                        adapter,
                        error.reason(),
                    )
                    .await
                    .is_err()
                {
                    summary.runtime.ingest_errors = summary.runtime.ingest_errors.saturating_add(1);
                }
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        adapter,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
                continue;
            }
        };
        let after = match select_capture(&source, &mut shutdown).await {
            CaptureOutcome::Shutdown => break,
            CaptureOutcome::Snapshot(snapshot) => snapshot,
            CaptureOutcome::Error(kind) => {
                record_source_error(&state, &profile, kind, &mut summary).await;
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        AdapterKind::Kubernetes,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
                continue;
            }
        };
        let after = match qualified_snapshot(&profile, after) {
            Ok(snapshot) => snapshot,
            Err(()) => {
                record_source_error(
                    &state,
                    &profile,
                    KubernetesSourceErrorKind::Inconsistent,
                    &mut summary,
                )
                .await;
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        AdapterKind::Kubernetes,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
                continue;
            }
        };
        match state
            .apply_kubernetes_qualification_cycle_classified(before, inventory, after)
            .await
        {
            Ok(cycle) => {
                summary.qualified_cycles = summary.qualified_cycles.saturating_add(1);
                summary.runtime.discovered = summary
                    .runtime
                    .discovered
                    .saturating_add(cycle.observed as u64);
                if consecutive_errors > 0 {
                    summary.runtime.backend_recoveries =
                        summary.runtime.backend_recoveries.saturating_add(1);
                }
                consecutive_errors = 0;
            }
            Err(error) => {
                summary.runtime.ingest_errors = summary.runtime.ingest_errors.saturating_add(1);
                if error.requires_runtime_suspension() {
                    let _ = state
                        .kubernetes_runtime_source_unavailable(
                            &profile.cluster_id,
                            adapter,
                            crate::RuntimeSourceGapReason::InventoryInvalid,
                        )
                        .await;
                } else {
                    let _ = state
                        .kubernetes_source_unavailable(
                            &profile.cluster_id,
                            KubernetesSourceUnavailableReason::SnapshotInvalid,
                        )
                        .await;
                }
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        AdapterKind::Kubernetes,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
                continue;
            }
        }

        let dirty = tokio::select! {
            _ = &mut shutdown => break,
            dirty = source.wait_dirty(source_epoch.clone(), dirty_sequence) => dirty,
        };
        match dirty {
            Ok(SourceDirtyOutcome::Dirty {
                source_epoch: epoch,
                dirty_sequence: sequence,
            }) => {
                dirty_epoch = Some(epoch);
                dirty_sequence = sequence;
            }
            Ok(SourceDirtyOutcome::Idle {
                source_epoch: epoch,
                dirty_sequence: sequence,
            }) => {
                dirty_epoch = Some(epoch);
                dirty_sequence = sequence;
                if wait_or_shutdown(&mut shutdown, profile.scan_interval).await {
                    break;
                }
            }
            Err(kind) => {
                record_source_error(&state, &profile, kind, &mut summary).await;
                consecutive_errors = consecutive_errors.saturating_add(1);
                if wait_or_shutdown(
                    &mut shutdown,
                    adapter_backoff_delay(
                        AdapterBackoffPolicy::default(),
                        AdapterKind::Kubernetes,
                        consecutive_errors,
                    ),
                )
                .await
                {
                    break;
                }
            }
        }
    }
    summary
}

enum CaptureOutcome {
    Shutdown,
    Snapshot(KubernetesSnapshot),
    Error(KubernetesSourceErrorKind),
}

async fn select_capture<S: KubernetesSourcePort>(
    source: &S,
    shutdown: &mut oneshot::Receiver<()>,
) -> CaptureOutcome {
    tokio::select! {
        _ = shutdown => CaptureOutcome::Shutdown,
        result = source.capture() => match result {
            Ok(snapshot) => CaptureOutcome::Snapshot(snapshot),
            Err(kind) => CaptureOutcome::Error(kind),
        }
    }
}

async fn record_source_error(
    state: &DaemonState,
    profile: &KubernetesNodeProfile,
    kind: KubernetesSourceErrorKind,
    summary: &mut KubernetesNodeAttributionSummary,
) {
    summary.source_errors = summary.source_errors.saturating_add(1);
    let reason = match kind {
        KubernetesSourceErrorKind::Unavailable | KubernetesSourceErrorKind::Timeout => {
            KubernetesSourceUnavailableReason::ApiUnavailable
        }
        KubernetesSourceErrorKind::Unauthorized
        | KubernetesSourceErrorKind::Forbidden
        | KubernetesSourceErrorKind::Malformed
        | KubernetesSourceErrorKind::Oversized
        | KubernetesSourceErrorKind::Inconsistent
        | KubernetesSourceErrorKind::Protocol => KubernetesSourceUnavailableReason::SnapshotInvalid,
    };
    if state
        .kubernetes_source_unavailable(&profile.cluster_id, reason)
        .await
        .is_err()
    {
        summary.runtime.ingest_errors = summary.runtime.ingest_errors.saturating_add(1);
    }
}

fn qualified_snapshot(
    profile: &KubernetesNodeProfile,
    snapshot: KubernetesSnapshot,
) -> Result<QualifiedPodSnapshot, ()> {
    if snapshot.cluster_id.as_str() != profile.cluster_id
        || snapshot.namespace_ref.as_str() != profile.namespace_ref
        || snapshot.node_ref.as_str() != profile.node_ref
    {
        return Err(());
    }
    let pods = snapshot
        .pods
        .into_iter()
        .map(|pod| {
            let containers = pod
                .containers
                .into_iter()
                .map(|container| {
                    let kind = match container.kind {
                        ContainerKind::Application => KubernetesContainerKind::Application,
                        ContainerKind::Init => KubernetesContainerKind::Init,
                        ContainerKind::Ephemeral => KubernetesContainerKind::Ephemeral,
                    };
                    let runtime_container_id = container
                        .runtime_container_id
                        .map(|runtime_id| {
                            runtime_id
                                .as_str()
                                .strip_prefix("containerd://")
                                .ok_or(())
                                .map(str::to_string)
                        })
                        .transpose()?;
                    Ok(KubernetesContainerCandidate {
                        kind,
                        container_ref: container.container_ref.as_str().to_string(),
                        runtime_container_id,
                        running: container.running,
                    })
                })
                .collect::<Result<Vec<_>, ()>>()?;
            Ok(KubernetesPodCandidate {
                pod_uid: pod.pod_uid.as_str().to_string(),
                pod_revision_ref: pod.pod_revision_ref.as_str().to_string(),
                marked_for_observation: true,
                deleting: pod.deleting,
                runtime_class_ref: pod
                    .runtime_class_ref
                    .map(|reference| reference.as_str().to_string()),
                containers,
            })
        })
        .collect::<Result<Vec<_>, ()>>()?;
    Ok(QualifiedPodSnapshot {
        sequence: snapshot.snapshot_sequence,
        identity: KubernetesSnapshotIdentity {
            source_epoch: snapshot.source_epoch.as_str().to_string(),
            cluster_id: snapshot.cluster_id.as_str().to_string(),
            namespace_ref: snapshot.namespace_ref.as_str().to_string(),
            node_ref: snapshot.node_ref.as_str().to_string(),
        },
        pods,
    })
}

async fn wait_or_shutdown(shutdown: &mut oneshot::Receiver<()>, delay: Duration) -> bool {
    tokio::select! {
        _ = shutdown => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use apolysis_accountability::{ActionClass, RetentionTier, SessionIntent};
    use apolysis_core::{KubernetesWorkloadClaimV1, KUBERNETES_ATTRIBUTION_SCHEMA_VERSION};
    use apolysis_kubernetes_source::{
        kubernetes_container_ref, kubernetes_namespace_ref, kubernetes_node_ref,
        KubernetesClusterId, KubernetesContainerSnapshot, KubernetesPodSnapshot, OpaqueRef,
        RuntimeContainerId, SourceEpoch, KUBERNETES_SOURCE_SCHEMA_V1,
    };

    use super::*;
    use crate::{CgroupIdentity, RuntimeInventory, RuntimeWorkloadIdentity};

    const AGENT_RUN_ID: &str = "agent-run-kubernetes-task";
    const CLUSTER_ID: &str = "11111111-1111-1111-1111-111111111111";
    const POD_UID: &str = "22222222-2222-2222-2222-222222222222";
    const CONTAINER_ID: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    type DirtyWaitRequest = (Option<String>, u64);
    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn task_qualifies_a_complete_cycle_and_shuts_down_cleanly() {
        let config = task_test_config("complete-cycle");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        state
            .register(
                SessionIntent {
                    schema_version: 1,
                    tenant_id: "tenant-a".to_string(),
                    retention_tier: RetentionTier::Standard,
                    session_id: AGENT_RUN_ID.to_string(),
                    expires_at_unix_ms: 4_102_444_800_000,
                    declared_actions: vec![ActionClass::Test],
                    allowed_resources: Vec::new(),
                    workload_selectors: Vec::new(),
                    kubernetes_claims: vec![KubernetesWorkloadClaimV1 {
                        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
                        claim_revision: 1,
                        cluster_id: CLUSTER_ID.to_string(),
                        namespace_ref: namespace_ref.as_str().to_string(),
                        pod_uid: POD_UID.to_string(),
                        container_kind: KubernetesContainerKind::Application,
                        container_ref: kubernetes_container_ref("agent")
                            .expect("container ref")
                            .as_str()
                            .to_string(),
                    }],
                },
                1_700_000_000_000,
            )
            .await
            .expect("register claim");
        let source = FakeSource::new(vec![snapshot(1), snapshot(2)]);
        let runtime = FakeRuntime(runtime_inventory());
        let profile = KubernetesNodeProfile {
            cluster_id: CLUSTER_ID.to_string(),
            namespace: "agents".to_string(),
            namespace_ref: namespace_ref.as_str().to_string(),
            node_ref: node_ref.as_str().to_string(),
            runtime_adapter: AdapterKind::Containerd,
            scan_interval: Duration::from_secs(60),
            runtime_scan_timeout: Duration::from_secs(1),
        };
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile,
            source,
            runtime,
            Arc::clone(&state),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (_, runtime, kubernetes) = state
                    .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
                    .await;
                if runtime.len() == 1 && kubernetes.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("task qualification deadline");
        let summary = task
            .shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");
        assert_eq!(summary.qualified_cycles, 1);
        assert_eq!(summary.source_errors, 0);

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn task_runtime_outage_records_kubernetes_before_runtime_suspension() {
        let config = task_test_config("runtime-outage");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let source = DirtySource::new(vec![snapshot(1), snapshot(2), snapshot(3)]);
        let runtime = SequencedRuntime::new(vec![
            Ok(runtime_inventory()),
            Err(crate::RuntimeInventoryScanError::socket_unavailable(
                "test runtime outage",
            )),
        ]);
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            runtime,
            Arc::clone(&state),
        );

        let timeline_path = config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl");
        let timeline = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let timeline = std::fs::read_to_string(&timeline_path).unwrap_or_default();
                if timeline.contains("runtime_binding_suspended") {
                    break timeline;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runtime outage deadline");
        let summary = task
            .shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");
        assert_eq!(summary.runtime.backend_errors, 1);
        let kubernetes_gap = timeline
            .find("reason=kubernetes_runtime_unavailable")
            .expect("typed Kubernetes runtime gap");
        let kubernetes_suspended = timeline
            .find("kubernetes_attribution_suspended")
            .expect("Kubernetes suspension");
        let runtime_gap = timeline
            .find("source=containerd,reason=socket_unavailable")
            .expect("typed runtime source gap");
        let runtime_suspended = timeline
            .find("runtime_binding_suspended")
            .expect("runtime suspension");
        assert!(
            kubernetes_gap < kubernetes_suspended
                && kubernetes_suspended < runtime_gap
                && runtime_gap < runtime_suspended
        );

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn task_missing_claimed_runtime_binding_suspends_kubernetes_and_runtime() {
        let config = task_test_config("missing-claimed-runtime");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let source = DirtySource::new(vec![snapshot(1), snapshot(2), snapshot(3), snapshot(4)]);
        let runtime = SequencedRuntime::new(vec![
            Ok(runtime_inventory()),
            Ok(RuntimeInventory::new(AdapterKind::Containerd, Vec::new())),
        ]);
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            runtime,
            Arc::clone(&state),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let timeline = std::fs::read_to_string(
                    config
                        .state_dir
                        .join("sessions")
                        .join(AGENT_RUN_ID)
                        .join("timeline.jsonl"),
                )
                .unwrap_or_default();
                if timeline.contains("runtime_binding_suspended") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("missing claimed runtime must suspend D1");
        let (_, runtime, kubernetes) = state
            .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
            .await;
        assert!(runtime.is_empty());
        assert!(kubernetes.is_empty());

        task.shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");
        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn task_pod_snapshot_churn_suspends_only_kubernetes_attribution() {
        let config = task_test_config("pod-snapshot-churn");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let mut changed_after = snapshot(4);
        changed_after.pods[0].pod_revision_ref =
            OpaqueRef::parse(&"8".repeat(64)).expect("changed Pod revision ref");
        let source = DirtySource::new(vec![snapshot(1), snapshot(2), snapshot(3), changed_after]);
        let runtime = SequencedRuntime::new(vec![Ok(runtime_inventory()), Ok(runtime_inventory())]);
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            runtime,
            Arc::clone(&state),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (_, runtime, kubernetes) = state
                    .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
                    .await;
                if runtime.len() == 1 && kubernetes.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("source-only churn must retain healthy D1");
        let timeline = std::fs::read_to_string(
            config
                .state_dir
                .join("sessions")
                .join(AGENT_RUN_ID)
                .join("timeline.jsonl"),
        )
        .expect("Agent Run timeline");
        assert!(timeline.contains("kubernetes_attribution_suspended"));
        assert!(!timeline.contains("runtime_binding_suspended"));

        task.shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");
        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn task_initial_runtime_outage_records_the_registered_claim_gap() {
        let config = task_test_config("initial-runtime-outage");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let source = FakeSource::new(vec![snapshot(1)]);
        let runtime = SequencedRuntime::new(vec![Err(
            crate::RuntimeInventoryScanError::socket_unavailable("test runtime outage"),
        )]);
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            runtime,
            Arc::clone(&state),
        );

        let timeline_path = config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if std::fs::read_to_string(&timeline_path)
                    .unwrap_or_default()
                    .contains("reason=kubernetes_runtime_unavailable")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial runtime gap deadline");
        task.shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn task_runtime_inventory_has_a_whole_scan_deadline() {
        let config = task_test_config("runtime-scan-deadline");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let mut node_profile = profile(namespace_ref.as_str(), node_ref.as_str());
        node_profile.runtime_scan_timeout = Duration::from_millis(10);
        let task = KubernetesNodeAttributionTask::start_with_ports(
            node_profile,
            FakeSource::new(vec![snapshot(1)]),
            PendingRuntime,
            Arc::clone(&state),
        );

        let timeline_path = config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl");
        tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if std::fs::read_to_string(&timeline_path)
                    .unwrap_or_default()
                    .contains("reason=kubernetes_runtime_unavailable")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("whole runtime scan deadline");
        let summary = task
            .shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");
        assert_eq!(summary.runtime.backend_errors, 1);

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn persistent_invalid_after_snapshot_is_backed_off_and_can_shutdown() {
        let config = task_test_config("invalid-after-backoff");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let capture_count = Arc::new(AtomicU64::new(0));
        let source = AlternatingInvalidAfterSource {
            capture_count: Arc::clone(&capture_count),
        };
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            FakeRuntime(runtime_inventory()),
            Arc::clone(&state),
        );

        tokio::time::sleep(Duration::from_millis(75)).await;
        assert_eq!(
            capture_count.load(Ordering::Acquire),
            2,
            "a persistent invalid after-snapshot must not busy-loop"
        );
        let summary = task
            .shutdown(Duration::from_millis(250))
            .await
            .expect("backoff must remain shutdown-responsive");
        assert_eq!(summary.source_errors, 1);

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn wait_dirty_failure_suspends_kubernetes_before_another_capture() {
        let config = task_test_config("wait-dirty-outage");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let source = WaitDirtyErrorSource {
            snapshots: Mutex::new(vec![snapshot(1), snapshot(2)].into()),
        };
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            FakeRuntime(runtime_inventory()),
            Arc::clone(&state),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (_, runtime, kubernetes) = state
                    .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
                    .await;
                if runtime.len() == 1 && kubernetes.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("wait-dirty outage must suspend Kubernetes attribution");

        let summary = task
            .shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");
        assert_eq!(summary.source_errors, 1);

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn task_resets_the_dirty_cursor_when_the_source_epoch_changes() {
        let config = task_test_config("source-epoch-cursor");
        let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
        register_claim(&state).await;
        let namespace_ref = kubernetes_namespace_ref("agents").expect("namespace ref");
        let node_ref = kubernetes_node_ref("worker-a").expect("node ref");
        let first_epoch = "33333333-3333-3333-3333-333333333333";
        let second_epoch = "55555555-5555-5555-5555-555555555555";
        let waits = Arc::new(Mutex::new(Vec::new()));
        let source = EpochRestartSource {
            snapshots: Mutex::new(
                vec![
                    snapshot_with_epoch(1, first_epoch),
                    snapshot_with_epoch(2, first_epoch),
                    snapshot_with_epoch(1, second_epoch),
                    snapshot_with_epoch(2, second_epoch),
                ]
                .into(),
            ),
            waits: Arc::clone(&waits),
        };
        let task = KubernetesNodeAttributionTask::start_with_ports(
            profile(namespace_ref.as_str(), node_ref.as_str()),
            source,
            FakeRuntime(runtime_inventory()),
            Arc::clone(&state),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if waits.lock().expect("wait requests").len() == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("two dirty waits");
        task.shutdown(Duration::from_secs(1))
            .await
            .expect("clean task shutdown");

        assert_eq!(
            *waits.lock().expect("wait requests"),
            vec![
                (Some(first_epoch.to_string()), 0),
                (Some(second_epoch.to_string()), 0),
            ]
        );

        drop(state);
        std::fs::remove_dir_all(config.state_dir).expect("clean test state");
    }

    struct FakeSource {
        snapshots: Mutex<VecDeque<KubernetesSnapshot>>,
    }

    impl FakeSource {
        fn new(snapshots: Vec<KubernetesSnapshot>) -> Self {
            Self {
                snapshots: Mutex::new(snapshots.into()),
            }
        }
    }

    impl KubernetesSourcePort for FakeSource {
        fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot> {
            Box::pin(async move {
                self.snapshots
                    .lock()
                    .map_err(|_| KubernetesSourceErrorKind::Unavailable)?
                    .pop_front()
                    .ok_or(KubernetesSourceErrorKind::Unavailable)
            })
        }

        fn wait_dirty(
            &self,
            _source_epoch: Option<String>,
            _after_dirty_sequence: u64,
        ) -> SourceFuture<'_, SourceDirtyOutcome> {
            Box::pin(std::future::pending())
        }
    }

    struct DirtySource {
        snapshots: Mutex<VecDeque<KubernetesSnapshot>>,
    }

    impl DirtySource {
        fn new(snapshots: Vec<KubernetesSnapshot>) -> Self {
            Self {
                snapshots: Mutex::new(snapshots.into()),
            }
        }
    }

    impl KubernetesSourcePort for DirtySource {
        fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot> {
            Box::pin(async move {
                self.snapshots
                    .lock()
                    .map_err(|_| KubernetesSourceErrorKind::Unavailable)?
                    .pop_front()
                    .ok_or(KubernetesSourceErrorKind::Unavailable)
            })
        }

        fn wait_dirty(
            &self,
            source_epoch: Option<String>,
            after_dirty_sequence: u64,
        ) -> SourceFuture<'_, SourceDirtyOutcome> {
            Box::pin(async move {
                Ok(SourceDirtyOutcome::Dirty {
                    source_epoch: source_epoch
                        .unwrap_or_else(|| "33333333-3333-3333-3333-333333333333".to_string()),
                    dirty_sequence: after_dirty_sequence.saturating_add(1),
                })
            })
        }
    }

    struct AlternatingInvalidAfterSource {
        capture_count: Arc<AtomicU64>,
    }

    impl KubernetesSourcePort for AlternatingInvalidAfterSource {
        fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot> {
            Box::pin(async move {
                let capture = self.capture_count.fetch_add(1, Ordering::AcqRel) + 1;
                let mut captured = snapshot(capture);
                if capture.is_multiple_of(2) {
                    captured.node_ref = kubernetes_node_ref("worker-b")
                        .map_err(|_| KubernetesSourceErrorKind::Protocol)?;
                }
                Ok(captured)
            })
        }

        fn wait_dirty(
            &self,
            _source_epoch: Option<String>,
            _after_dirty_sequence: u64,
        ) -> SourceFuture<'_, SourceDirtyOutcome> {
            Box::pin(std::future::pending())
        }
    }

    struct WaitDirtyErrorSource {
        snapshots: Mutex<VecDeque<KubernetesSnapshot>>,
    }

    impl KubernetesSourcePort for WaitDirtyErrorSource {
        fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot> {
            Box::pin(async move {
                let next = self
                    .snapshots
                    .lock()
                    .map_err(|_| KubernetesSourceErrorKind::Unavailable)?
                    .pop_front();
                match next {
                    Some(snapshot) => Ok(snapshot),
                    None => std::future::pending().await,
                }
            })
        }

        fn wait_dirty(
            &self,
            _source_epoch: Option<String>,
            _after_dirty_sequence: u64,
        ) -> SourceFuture<'_, SourceDirtyOutcome> {
            Box::pin(async { Err(KubernetesSourceErrorKind::Unavailable) })
        }
    }

    struct EpochRestartSource {
        snapshots: Mutex<VecDeque<KubernetesSnapshot>>,
        waits: Arc<Mutex<Vec<DirtyWaitRequest>>>,
    }

    impl KubernetesSourcePort for EpochRestartSource {
        fn capture(&self) -> SourceFuture<'_, KubernetesSnapshot> {
            Box::pin(async move {
                self.snapshots
                    .lock()
                    .map_err(|_| KubernetesSourceErrorKind::Unavailable)?
                    .pop_front()
                    .ok_or(KubernetesSourceErrorKind::Unavailable)
            })
        }

        fn wait_dirty(
            &self,
            source_epoch: Option<String>,
            after_dirty_sequence: u64,
        ) -> SourceFuture<'_, SourceDirtyOutcome> {
            Box::pin(async move {
                let wait_number = {
                    let mut waits = self
                        .waits
                        .lock()
                        .map_err(|_| KubernetesSourceErrorKind::Unavailable)?;
                    waits.push((source_epoch.clone(), after_dirty_sequence));
                    waits.len()
                };
                if wait_number == 1 {
                    Ok(SourceDirtyOutcome::Dirty {
                        source_epoch: source_epoch.ok_or(KubernetesSourceErrorKind::Protocol)?,
                        dirty_sequence: 10,
                    })
                } else {
                    std::future::pending().await
                }
            })
        }
    }

    struct FakeRuntime(RuntimeInventory);

    impl RuntimeInventoryAdapter for FakeRuntime {
        fn kind(&self) -> AdapterKind {
            AdapterKind::Containerd
        }

        fn scan_interval(&self) -> Duration {
            Duration::from_secs(60)
        }

        fn scan_inventory(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<RuntimeInventory, crate::RuntimeInventoryScanError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    struct PendingRuntime;

    impl RuntimeInventoryAdapter for PendingRuntime {
        fn kind(&self) -> AdapterKind {
            AdapterKind::Containerd
        }

        fn scan_interval(&self) -> Duration {
            Duration::from_secs(60)
        }

        fn scan_inventory(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<RuntimeInventory, crate::RuntimeInventoryScanError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(std::future::pending())
        }
    }

    struct SequencedRuntime(
        Mutex<VecDeque<Result<RuntimeInventory, crate::RuntimeInventoryScanError>>>,
    );

    impl SequencedRuntime {
        fn new(scans: Vec<Result<RuntimeInventory, crate::RuntimeInventoryScanError>>) -> Self {
            Self(Mutex::new(scans.into()))
        }
    }

    impl RuntimeInventoryAdapter for SequencedRuntime {
        fn kind(&self) -> AdapterKind {
            AdapterKind::Containerd
        }

        fn scan_interval(&self) -> Duration {
            Duration::from_secs(60)
        }

        fn scan_inventory(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<RuntimeInventory, crate::RuntimeInventoryScanError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                self.0
                    .lock()
                    .map_err(|_| {
                        crate::RuntimeInventoryScanError::socket_unavailable("test runtime lock")
                    })?
                    .pop_front()
                    .unwrap_or_else(|| {
                        Err(crate::RuntimeInventoryScanError::socket_unavailable(
                            "test runtime sequence exhausted",
                        ))
                    })
            })
        }
    }

    fn snapshot(sequence: u64) -> KubernetesSnapshot {
        snapshot_with_epoch(sequence, "33333333-3333-3333-3333-333333333333")
    }

    fn snapshot_with_epoch(sequence: u64, source_epoch: &str) -> KubernetesSnapshot {
        KubernetesSnapshot {
            schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
            source_epoch: SourceEpoch::parse(source_epoch).expect("source epoch"),
            snapshot_sequence: sequence,
            cluster_id: KubernetesClusterId::parse(CLUSTER_ID).expect("cluster ID"),
            namespace_ref: kubernetes_namespace_ref("agents").expect("namespace ref"),
            node_ref: kubernetes_node_ref("worker-a").expect("node ref"),
            pods: vec![KubernetesPodSnapshot {
                pod_uid: apolysis_kubernetes_source::KubernetesPodUid::parse(POD_UID)
                    .expect("Pod UID"),
                pod_revision_ref: OpaqueRef::parse(&"9".repeat(64)).expect("Pod revision ref"),
                deleting: false,
                runtime_class_ref: Some(OpaqueRef::parse(&"c".repeat(64)).expect("runtime class")),
                containers: vec![KubernetesContainerSnapshot {
                    kind: ContainerKind::Application,
                    container_ref: kubernetes_container_ref("agent").expect("container ref"),
                    runtime_container_id: Some(
                        RuntimeContainerId::parse(&format!("containerd://{CONTAINER_ID}"))
                            .expect("runtime container ID"),
                    ),
                    running: true,
                }],
            }],
        }
    }

    fn runtime_inventory() -> RuntimeInventory {
        RuntimeInventory::new(
            AdapterKind::Containerd,
            vec![crate::RuntimeBinding {
                agent_run_id: AGENT_RUN_ID.to_string(),
                identity: RuntimeWorkloadIdentity {
                    adapter: AdapterKind::Containerd,
                    workload_id: format!("containerd/{CONTAINER_ID}"),
                    start_marker: "42".to_string(),
                    host_boot_id: "44444444-4444-4444-4444-444444444444".to_string(),
                    init_process_start_time_ticks: 103,
                    cgroup: CgroupIdentity {
                        device: 7,
                        inode: 107,
                    },
                },
                runtime_handler: Some("runc".to_string()),
            }],
        )
    }

    fn task_test_config(name: &str) -> DaemonConfig {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-kubernetes-task-{name}-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        }
    }

    fn profile(namespace_ref: &str, node_ref: &str) -> KubernetesNodeProfile {
        KubernetesNodeProfile {
            cluster_id: CLUSTER_ID.to_string(),
            namespace: "agents".to_string(),
            namespace_ref: namespace_ref.to_string(),
            node_ref: node_ref.to_string(),
            runtime_adapter: AdapterKind::Containerd,
            scan_interval: Duration::from_secs(60),
            runtime_scan_timeout: Duration::from_secs(1),
        }
    }

    async fn register_claim(state: &DaemonState) {
        state
            .register(
                SessionIntent {
                    schema_version: 1,
                    tenant_id: "tenant-a".to_string(),
                    retention_tier: RetentionTier::Standard,
                    session_id: AGENT_RUN_ID.to_string(),
                    expires_at_unix_ms: 4_102_444_800_000,
                    declared_actions: vec![ActionClass::Test],
                    allowed_resources: Vec::new(),
                    workload_selectors: Vec::new(),
                    kubernetes_claims: vec![KubernetesWorkloadClaimV1 {
                        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
                        claim_revision: 1,
                        cluster_id: CLUSTER_ID.to_string(),
                        namespace_ref: kubernetes_namespace_ref("agents")
                            .expect("namespace ref")
                            .as_str()
                            .to_string(),
                        pod_uid: POD_UID.to_string(),
                        container_kind: KubernetesContainerKind::Application,
                        container_ref: kubernetes_container_ref("agent")
                            .expect("container ref")
                            .as_str()
                            .to_string(),
                    }],
                },
                1_700_000_000_000,
            )
            .await
            .expect("register claim");
    }
}

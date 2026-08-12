// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use apolysis_accountability::{
    AccountabilityAnalyzer, AdapterKind, AssociationOutcome, ComponentState, EffectKind,
    EvidenceBoundary, HealthSnapshot, ObservedEffect, QueueStats, RegisterOutcome, RegistryError,
    ResourceKind, RetentionPurgeReport, RetentionTier, RuntimeIdentity, SessionIntent,
    SessionRegistry, SessionState,
};
use apolysis_core::{
    CollectorCapabilityManifest, CollectorFailureReason, CollectorLifecycleCounters,
    CollectorLifecycleRecord, KubernetesAttributionRecordType, KubernetesAttributionWireV1,
    ObservationGap, ObservationGapKind, RuntimeBindingRecordType, RuntimeBindingRuntimeHandler,
    RuntimeBindingWireV1, RUNTIME_BINDING_SCHEMA_VERSION,
};
use apolysis_kubernetes::{
    KubernetesAttributionCoordinator, KubernetesAttributionEffect, KubernetesAttributionGapKind,
    KubernetesAttributionPlan, KubernetesAttributionSummary, KubernetesPodSnapshot,
    KubernetesQualificationCycle, KubernetesQualificationError, KubernetesRuntimeInventory,
    KubernetesSourceUnavailableReason,
};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::{
    retention::{
        recover_retention_transactions, stage_agent_run_retention_targets,
        validate_agent_run_retention_target, RetentionError,
    },
    scope::PreparedAgentRunClose,
    DaemonConfig, DaemonRecord, EventPipeline, RecordDeliveryMode, RecordWriteOutcome,
    RuntimeBinding, RuntimeBindingCoordinator, RuntimeBindingEffect, RuntimeBindingGapKind,
    RuntimeBindingReconcile, RuntimeInventory, RuntimeWorkload, RuntimeWorkloadIdentity,
    ScopeController, WriterSummary,
};

// The on-disk directory name predates the Agent Run domain terminology.
const LEGACY_AGENT_RUN_STORAGE_DIR: &str = "sessions";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSourceGapReason {
    SocketUnavailable,
    InventoryInvalid,
}

impl RuntimeSourceGapReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SocketUnavailable => "socket_unavailable",
            Self::InventoryInvalid => "inventory_invalid",
        }
    }
}

pub(crate) struct KubernetesQualificationCycleError {
    message: String,
    runtime_source_invalid: bool,
}

impl KubernetesQualificationCycleError {
    fn qualification(error: KubernetesQualificationError) -> Self {
        Self {
            runtime_source_invalid: error.requires_runtime_suspension(),
            message: error.to_string(),
        }
    }

    fn runtime(message: String) -> Self {
        Self {
            message,
            runtime_source_invalid: true,
        }
    }

    pub(crate) const fn requires_runtime_suspension(&self) -> bool {
        self.runtime_source_invalid
    }
}

impl std::fmt::Display for KubernetesQualificationCycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl From<String> for KubernetesQualificationCycleError {
    fn from(message: String) -> Self {
        Self {
            message,
            runtime_source_invalid: false,
        }
    }
}

pub struct DaemonState {
    registry: RwLock<SessionRegistry>,
    runtime_bindings: Mutex<ManagedRuntimeBindings>,
    health: RwLock<HealthSnapshot>,
    stores: Mutex<AgentRunStores>,
    collector_capability_agent_runs: Mutex<BTreeSet<String>>,
    paused_agent_runs: RwLock<BTreeMap<String, String>>,
    agent_runs_dir: PathBuf,
    storage_writable: AtomicBool,
    scope: Option<ScopeController>,
    pipeline: EventPipeline,
    collector_checkpoint_interval: Duration,
}

struct ManagedRuntimeBindings {
    committed: RuntimeBindingCoordinator,
    kubernetes: KubernetesAttributionCoordinator,
    kubernetes_claim_revisions: BTreeMap<String, u64>,
    pending: Option<PendingRuntimeBindingApplication>,
    pending_kubernetes: Option<PendingKubernetesApplication>,
    pending_close: Option<PendingAgentRunCloseApplication>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AuthorizedRuntimeBindingKey {
    agent_run_id: String,
    adapter: String,
    workload_id: String,
    start_marker: String,
    host_boot_id: String,
    init_process_start_time_ticks: u64,
    cgroup_device: u64,
    cgroup_id: u64,
    runtime_handler: Option<String>,
}

#[derive(Clone)]
struct PendingKubernetesApplication {
    runtime_candidate: RuntimeBindingCoordinator,
    kubernetes_candidate: KubernetesAttributionCoordinator,
    runtime_reconciliation: RuntimeBindingReconcile,
    kubernetes_summary: KubernetesAttributionSummary,
    batches: Vec<(String, Vec<Value>)>,
    next_batch: usize,
}

#[derive(Clone)]
struct PendingAgentRunCloseApplication {
    agent_run_id: String,
    runtime_candidate: RuntimeBindingCoordinator,
    kubernetes_candidate: KubernetesAttributionCoordinator,
    registry_candidate: SessionRegistry,
    prepared_scope: Option<PreparedAgentRunClose>,
}

#[derive(Clone)]
struct PendingRuntimeBindingApplication {
    candidate: RuntimeBindingCoordinator,
    reconciliation: RuntimeBindingReconcile,
    gap_batches: Vec<RuntimeBindingGapBatch>,
    next_gap_batch: usize,
    next_effect_batch: usize,
}

#[derive(Clone)]
struct RuntimeBindingGapBatch {
    agent_run_id: String,
    payloads: Vec<Value>,
    effects: Vec<RuntimeBindingEffect>,
}

struct RuntimeBindingEffectApplicationError {
    message: String,
    next_effect_batch: usize,
}

impl RuntimeBindingEffectApplicationError {
    fn new(message: String, next_effect_batch: usize) -> Self {
        Self {
            message,
            next_effect_batch,
        }
    }
}

struct ManagedAgentRunStore {
    store: HashChainStore,
    identity: AgentRunStorageIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AgentRunStorageIdentity {
    agent_run_device: u64,
    agent_run_inode: u64,
}

#[derive(Default)]
struct AgentRunStores {
    active: BTreeMap<String, ManagedAgentRunStore>,
    write_blocked: BTreeSet<String>,
}

impl DaemonState {
    pub fn new(config: &DaemonConfig) -> Result<Self, String> {
        Self::new_with_scope(config, None)
    }

    pub fn new_with_scope(
        config: &DaemonConfig,
        scope: Option<ScopeController>,
    ) -> Result<Self, String> {
        let agent_runs_dir = config.state_dir.join(LEGACY_AGENT_RUN_STORAGE_DIR);
        std::fs::create_dir_all(&agent_runs_dir)
            .map_err(|error| format!("failed to create daemon state directory: {error}"))?;
        recover_retention_transactions(&agent_runs_dir)
            .map_err(|error| format!("failed to recover retention state: {error}"))?;
        let mut registry = SessionRegistry::new(config.max_sessions, config.max_pending);
        let mut recovered_runtime_bindings = Vec::new();
        let mut recovered_kubernetes_attributions = Vec::new();
        let mut kubernetes_claim_revisions = BTreeMap::new();
        let mut collector_capability_agent_runs = BTreeSet::new();
        let mut stores = BTreeMap::new();
        let now_unix_ms = current_unix_ms()?;
        let mut recovered_integrity_issue = false;
        for entry in std::fs::read_dir(&agent_runs_dir)
            .map_err(|error| format!("failed to scan daemon Agent Run state: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("failed to inspect daemon Agent Run state: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("failed to inspect Agent Run state type: {error}"))?
                .is_dir()
            {
                continue;
            }
            let agent_run_id = entry.file_name().to_string_lossy().to_string();
            let timeline = entry.path().join("timeline.jsonl");
            match std::fs::symlink_metadata(&timeline) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                Ok(_) => {
                    recovered_integrity_issue = true;
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "failed to inspect daemon Agent Run timeline: {error}"
                    ));
                }
            }
            let mut recovery = HashChainStore::create_or_recover(&timeline)
                .map_err(|error| format!("failed to recover Agent Run {agent_run_id}: {error}"))?;
            if recovery.quarantined_path.is_some() {
                append_integrity_finding(
                    &mut recovery.store,
                    &agent_run_id,
                    recovery.records.len(),
                )?;
                recovered_integrity_issue = true;
            }
            append_incomplete_collector_lifecycles(
                &mut recovery.store,
                &agent_run_id,
                &recovery.records,
            )?;
            let capability_records = recovery
                .records
                .iter()
                .filter(|record| {
                    record.payload.get("record_type").and_then(Value::as_str)
                        == Some("collector_capability_manifest")
                })
                .collect::<Vec<_>>();
            if capability_records.len() > 1 {
                return Err(format!(
                    "failed to restore Agent Run {agent_run_id}: duplicate Collector Capability manifest"
                ));
            }
            if let Some(capability) = capability_records.first() {
                if capability
                    .payload
                    .get("agent_run_id")
                    .and_then(Value::as_str)
                    != Some(agent_run_id.as_str())
                {
                    return Err(format!(
                        "failed to restore Agent Run {agent_run_id}: Collector Capability identity mismatch"
                    ));
                }
                collector_capability_agent_runs.insert(agent_run_id.clone());
            }
            let recovered =
                replay_persisted_agent_run(&recovery.records, &agent_run_id, now_unix_ms)?;
            recovered_runtime_bindings.extend(recovered.runtime_bindings);
            recovered_kubernetes_attributions.extend(recovered.kubernetes_attributions);
            if let Some(registration) = recovered.registration {
                if registration.status == RecoveredAgentRunStatus::Active {
                    if let Some(revision) = registration
                        .intent
                        .kubernetes_claims
                        .first()
                        .map(|claim| claim.claim_revision)
                    {
                        kubernetes_claim_revisions.insert(agent_run_id.clone(), revision);
                    }
                }
                if registration.intent.session_id != agent_run_id {
                    return Err(format!(
                        "failed to restore Agent Run {agent_run_id}: durable Agent Run identity mismatch"
                    ));
                }
                match registration.status {
                    RecoveredAgentRunStatus::Active => {
                        registry
                            .register(registration.intent, now_unix_ms)
                            .map_err(|error| {
                                format!("failed to restore Agent Run {agent_run_id}: {error}")
                            })?;
                        for cgroup_id in registration.cgroup_ids {
                            registry
                                .discover_cgroup(&agent_run_id, cgroup_id)
                                .map_err(|error| {
                                    format!(
                                        "failed to restore cgroup {cgroup_id} for Agent Run {agent_run_id}: {error}"
                                    )
                                })?;
                        }
                    }
                    RecoveredAgentRunStatus::Closed => {
                        registry
                            .restore_closed_agent_run(registration.intent)
                            .map_err(|error| {
                                format!(
                                    "failed to restore closed Agent Run {agent_run_id}: {error}"
                                )
                            })?;
                    }
                }
            }
            let identity = capture_agent_run_storage_identity(&entry.path(), &recovery.store)
                .map_err(|_| "unsafe daemon Agent Run storage identity".to_string())?;
            stores.insert(
                agent_run_id,
                ManagedAgentRunStore {
                    store: recovery.store,
                    identity,
                },
            );
        }
        let pipeline = EventPipeline::new(config.queue_capacity);
        let mut health = HealthSnapshot::new(QueueStats::new(config.queue_capacity));
        health.set_storage(if recovered_integrity_issue {
            ComponentState::Degraded
        } else {
            ComponentState::Ready
        });
        health.set_ebpf(ComponentState::Unavailable);
        let runtime_bindings =
            RuntimeBindingCoordinator::recover_dormant(recovered_runtime_bindings)
                .map_err(|error| format!("failed to restore runtime binding state: {error}"))?;
        let kubernetes_attributions =
            KubernetesAttributionCoordinator::recover_dormant(recovered_kubernetes_attributions)
                .map_err(|error| {
                    format!("failed to restore Kubernetes attribution state: {error}")
                })?;
        Ok(Self {
            registry: RwLock::new(registry),
            runtime_bindings: Mutex::new(ManagedRuntimeBindings {
                committed: runtime_bindings,
                kubernetes: kubernetes_attributions,
                kubernetes_claim_revisions,
                pending: None,
                pending_kubernetes: None,
                pending_close: None,
            }),
            health: RwLock::new(health),
            stores: Mutex::new(AgentRunStores {
                active: stores,
                write_blocked: BTreeSet::new(),
            }),
            collector_capability_agent_runs: Mutex::new(collector_capability_agent_runs),
            paused_agent_runs: RwLock::new(BTreeMap::new()),
            agent_runs_dir,
            storage_writable: AtomicBool::new(true),
            scope,
            pipeline,
            collector_checkpoint_interval: config.collector_checkpoint_interval,
        })
    }

    pub async fn register(
        &self,
        intent: SessionIntent,
        now_unix_ms: u64,
    ) -> Result<RegisterOutcome, String> {
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        self.resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        self.resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        let mut registry = self.registry.write().await;
        let previous_intent = registry
            .get(&intent.session_id)
            .map(|state| state.intent.clone());
        let claims_changed = previous_intent
            .as_ref()
            .is_some_and(|previous| previous.kubernetes_claims != intent.kubernetes_claims);
        let mut kubernetes_candidate = runtime_bindings.kubernetes.clone();
        let kubernetes_retirement = if claims_changed {
            runtime_bindings
                .kubernetes_claim_revisions
                .get(&intent.session_id)
                .copied()
                .map(|claim_revision| {
                    kubernetes_candidate
                        .retire_agent_run(&intent.session_id, claim_revision)
                        .map_err(|error| error.to_string())
                })
                .transpose()?
        } else {
            None
        };
        let mut runtime_candidate = runtime_bindings.committed.clone();
        let runtime_retirement = if claims_changed
            && previous_intent
                .as_ref()
                .is_some_and(|previous| !previous.kubernetes_claims.is_empty())
        {
            // A K1 claim is the admission authority for the node-local CRI
            // domains. Revocation must therefore retire those D1 bindings even
            // while Kubernetes metadata is suspended and no active K1 wire is
            // available. Docker remains an independent runtime authority.
            runtime_candidate.retire_agent_run_adapters(
                &intent.session_id,
                &[AdapterKind::Containerd, AdapterKind::K3sContainerd],
            )
        } else {
            RuntimeBindingReconcile::default()
        };
        let revoked_cgroups = runtime_retirement
            .effects
            .iter()
            .filter_map(|effect| match effect {
                RuntimeBindingEffect::Retire { binding }
                | RuntimeBindingEffect::RetireDormant { binding } => {
                    Some(binding.identity.cgroup.inode)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let refresh_bindings = if registry.is_scope_admitted(&intent.session_id) {
            Vec::new()
        } else {
            runtime_bindings
                .committed
                .bindings_for_agent_run(&intent.session_id)
                .into_iter()
                .filter(|binding| !revoked_cgroups.contains(&binding.identity.cgroup.inode))
                .collect()
        };
        let mut candidate = registry.clone();
        let outcome = candidate
            .register(intent.clone(), now_unix_ms)
            .map_err(registry_error)?;
        for cgroup_id in &revoked_cgroups {
            candidate
                .retire_cgroup(&intent.session_id, *cgroup_id)
                .map_err(registry_error)?;
        }
        let kubernetes_plans = kubernetes_retirement
            .as_ref()
            .map(|plan| vec![(intent.session_id.clone(), plan.clone())])
            .unwrap_or_default();
        let mut payloads = combined_attribution_batches(
            &runtime_retirement.effects,
            &kubernetes_plans,
            None,
            None,
        )?
        .into_iter()
        .next()
        .map(|(_, payloads)| payloads)
        .unwrap_or_default();
        payloads.push(json!({"record_type":"intent_registered","intent":intent}));
        let mut refreshed = Vec::new();
        if let Some(scope) = &self.scope {
            for binding in &refresh_bindings {
                if let Err(error) = scope
                    .refresh_runtime_agent_run(
                        &binding.agent_run_id,
                        Some(&intent),
                        binding.identity.cgroup.inode,
                        &binding.identity.workload_id,
                    )
                    .await
                {
                    rollback_runtime_scope_contexts(scope, previous_intent.as_ref(), &refreshed)
                        .await
                        .map_err(|rollback| {
                            format!("{error}; scope context rollback failed: {rollback}")
                        })?;
                    return Err(error);
                }
                refreshed.push(binding.clone());
            }
        }
        let mut applied_runtime_effects = Vec::new();
        if !runtime_retirement.effects.is_empty() {
            if let Some(scope) = &self.scope {
                let previous = previous_intent.as_ref().ok_or_else(|| {
                    "Kubernetes claim retirement lost its prior intent".to_string()
                })?;
                for effect in &runtime_retirement.effects {
                    let RuntimeBindingEffect::Retire { binding } = effect else {
                        continue;
                    };
                    if let Err(error) = scope
                        .untrack_runtime_agent_run(
                            &binding.agent_run_id,
                            Some(previous),
                            binding.identity.cgroup.inode,
                            &binding.identity.workload_id,
                        )
                        .await
                    {
                        let rollback = rollback_register_scope_changes(
                            scope,
                            &registry,
                            &candidate,
                            &applied_runtime_effects,
                            previous_intent.as_ref(),
                            &refreshed,
                        )
                        .await;
                        return match rollback {
                            Ok(()) => Err(error),
                            Err(rollback) => {
                                Err(format!("{error}; scope rollback failed: {rollback}"))
                            }
                        };
                    }
                    applied_runtime_effects.push(effect.clone());
                }
            }
        }
        if let Err(error) = self.persist_batch(&intent.session_id, payloads).await {
            if let Some(scope) = &self.scope {
                if let Err(rollback) = rollback_register_scope_changes(
                    scope,
                    &registry,
                    &candidate,
                    &applied_runtime_effects,
                    previous_intent.as_ref(),
                    &refreshed,
                )
                .await
                {
                    return Err(format!("{error}; scope rollback failed: {rollback}"));
                }
            }
            return Err(error);
        }
        *registry = candidate;
        runtime_bindings.committed = runtime_candidate;
        runtime_bindings.kubernetes = kubernetes_candidate;
        match intent
            .kubernetes_claims
            .first()
            .map(|claim| claim.claim_revision)
        {
            Some(revision) => {
                runtime_bindings
                    .kubernetes_claim_revisions
                    .insert(intent.session_id.clone(), revision);
            }
            None => {
                runtime_bindings
                    .kubernetes_claim_revisions
                    .remove(&intent.session_id);
            }
        }
        Ok(outcome)
    }

    pub async fn renew(
        &self,
        session_id: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), String> {
        let runtime_bindings = self.runtime_bindings.lock().await;
        if runtime_bindings
            .pending_close
            .as_ref()
            .is_some_and(|pending| pending.agent_run_id == session_id)
        {
            return Err("Agent Run close finalization is pending".to_string());
        }
        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        candidate
            .renew(session_id, expires_at_unix_ms, now_unix_ms)
            .map_err(registry_error)?;
        self.persist(
            session_id,
            json!({
                "record_type":"intent_renewed",
                "session_id":session_id,
                "expires_at_unix_ms":expires_at_unix_ms
            }),
        )
        .await?;
        *registry = candidate;
        drop(runtime_bindings);
        Ok(())
    }

    pub async fn close(&self, session_id: &str) -> Result<(), String> {
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        if runtime_bindings.pending_close.is_some() {
            let completed = self
                .finish_pending_agent_run_close(&mut runtime_bindings)
                .await?;
            if completed == session_id {
                return Ok(());
            }
            return Err(format!(
                "Agent Run close for {completed} completed before requested close for {session_id}; retry the requested close"
            ));
        }
        self.resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        self.resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        let runtime_scope_context: BTreeMap<_, _> = runtime_bindings
            .committed
            .bindings_for_agent_run(session_id)
            .into_iter()
            .map(|binding| (binding.identity.cgroup.inode, binding))
            .collect();
        let runtime_retire_effects = runtime_scope_context
            .values()
            .cloned()
            .map(|binding| RuntimeBindingEffect::Retire { binding })
            .collect::<Vec<_>>();
        let mut runtime_candidate = runtime_bindings.committed.clone();
        runtime_candidate.retire_agent_run(session_id);
        let mut kubernetes_candidate = runtime_bindings.kubernetes.clone();
        let kubernetes_retirement = if let Some(claim_revision) = runtime_bindings
            .kubernetes_claim_revisions
            .get(session_id)
            .copied()
        {
            Some(
                kubernetes_candidate
                    .retire_agent_run(session_id, claim_revision)
                    .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        let kubernetes_plans = kubernetes_retirement
            .into_iter()
            .map(|plan| (session_id.to_string(), plan))
            .collect::<Vec<_>>();
        let mut terminal_payloads =
            combined_attribution_batches(&runtime_retire_effects, &kubernetes_plans, None, None)?
                .into_iter()
                .next()
                .map(|(_, payloads)| payloads)
                .unwrap_or_default();
        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        let closed = candidate.close(session_id).map_err(registry_error)?;
        let mut removed = Vec::new();
        if let Some(scope) = &self.scope {
            for cgroup_id in &closed.cgroup_ids {
                let result = if let Some(binding) = runtime_scope_context.get(cgroup_id) {
                    scope
                        .untrack_runtime_agent_run(
                            session_id,
                            Some(&closed.intent),
                            *cgroup_id,
                            &binding.identity.workload_id,
                        )
                        .await
                } else {
                    scope
                        .untrack_agent_run(session_id, Some(&closed.intent), *cgroup_id)
                        .await
                };
                if let Err(error) = result {
                    for removed_id in removed {
                        let _ = restore_closed_scope(
                            scope,
                            session_id,
                            &closed.intent,
                            removed_id,
                            runtime_scope_context.get(&removed_id),
                        )
                        .await;
                    }
                    return Err(error);
                }
                removed.push(*cgroup_id);
            }
        }
        let prepared_scope = if let Some(scope) = &self.scope {
            match scope.prepare_agent_run_close(session_id).await {
                Ok(prepared) => Some(prepared),
                Err(error) => {
                    for cgroup_id in &removed {
                        if let Err(rollback) = restore_closed_scope(
                            scope,
                            session_id,
                            &closed.intent,
                            *cgroup_id,
                            runtime_scope_context.get(cgroup_id),
                        )
                        .await
                        {
                            return Err(format!("{error}; scope rollback failed: {rollback}"));
                        }
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        if let Some(stopped) = prepared_scope
            .as_ref()
            .and_then(PreparedAgentRunClose::stopped)
        {
            match collector_agent_run_close_payload(stopped, session_id) {
                Ok(payload) => terminal_payloads.push(payload),
                Err(error) => {
                    let mut rollback_errors = Vec::new();
                    if let (Some(scope), Some(prepared)) = (&self.scope, &prepared_scope) {
                        if let Err(rollback) = scope.cancel_agent_run_close(prepared).await {
                            rollback_errors.push(format!("close cancel failed: {rollback}"));
                        }
                    }
                    if let Some(scope) = &self.scope {
                        for cgroup_id in removed {
                            if let Err(rollback) = restore_closed_scope(
                                scope,
                                session_id,
                                &closed.intent,
                                cgroup_id,
                                runtime_scope_context.get(&cgroup_id),
                            )
                            .await
                            {
                                rollback_errors.push(format!("scope restore failed: {rollback}"));
                            }
                        }
                    }
                    return if rollback_errors.is_empty() {
                        Err(error)
                    } else {
                        Err(format!("{error}; {}", rollback_errors.join("; ")))
                    };
                }
            }
        }
        terminal_payloads.push(json!({"record_type":"session_closed","session_id":session_id}));
        if let Err(error) = self.persist_batch(session_id, terminal_payloads).await {
            let mut rollback_errors = Vec::new();
            if let (Some(scope), Some(prepared)) = (&self.scope, &prepared_scope) {
                if let Err(rollback) = scope.cancel_agent_run_close(prepared).await {
                    rollback_errors.push(format!("close cancel failed: {rollback}"));
                }
            }
            if let Some(scope) = &self.scope {
                for cgroup_id in removed {
                    if let Err(rollback) = restore_closed_scope(
                        scope,
                        session_id,
                        &closed.intent,
                        cgroup_id,
                        runtime_scope_context.get(&cgroup_id),
                    )
                    .await
                    {
                        rollback_errors.push(format!("scope restore failed: {rollback}"));
                    }
                }
            }
            return if rollback_errors.is_empty() {
                Err(error)
            } else {
                Err(format!("{error}; {}", rollback_errors.join("; ")))
            };
        }

        runtime_bindings.pending_close = Some(PendingAgentRunCloseApplication {
            agent_run_id: session_id.to_string(),
            runtime_candidate,
            kubernetes_candidate,
            registry_candidate: candidate,
            prepared_scope: prepared_scope.clone(),
        });
        if let (Some(scope), Some(prepared)) = (&self.scope, &prepared_scope) {
            if let Err(error) = scope.finalize_agent_run_close(prepared).await {
                return Err(format!(
                    "Agent Run close was durably committed but scope finalization is pending: {error}"
                ));
            }
        }
        let completed = runtime_bindings
            .pending_close
            .take()
            .ok_or_else(|| "Agent Run close lost pending state".to_string())?;
        *registry = completed.registry_candidate;
        runtime_bindings.committed = completed.runtime_candidate;
        runtime_bindings.kubernetes = completed.kubernetes_candidate;
        runtime_bindings
            .kubernetes_claim_revisions
            .remove(session_id);
        Ok(())
    }

    pub async fn query(&self, session_id: &str) -> Option<SessionState> {
        self.registry.read().await.get(session_id).cloned()
    }

    pub async fn query_for_tenant(
        &self,
        session_id: &str,
        tenant_id: &str,
    ) -> Option<SessionState> {
        self.registry
            .read()
            .await
            .get_for_tenant(session_id, tenant_id)
            .cloned()
    }

    pub async fn query_with_runtime_bindings_for_tenant(
        &self,
        session_id: &str,
        tenant_id: &str,
    ) -> (Option<SessionState>, Vec<RuntimeBinding>) {
        let (session, runtime_bindings, _) = self
            .query_with_workload_context_for_tenant(session_id, tenant_id)
            .await;
        (session, runtime_bindings)
    }

    pub async fn query_with_workload_context_for_tenant(
        &self,
        session_id: &str,
        tenant_id: &str,
    ) -> (
        Option<SessionState>,
        Vec<RuntimeBinding>,
        Vec<KubernetesAttributionWireV1>,
    ) {
        // Keep the established runtime-bindings -> registry lock order used by
        // register/close. Runtime and Kubernetes attribution share this lock so
        // the authorization decision and both returned sets form one snapshot.
        let runtime_bindings = self.runtime_bindings.lock().await;
        let registry = self.registry.read().await;
        let session = registry.get_for_tenant(session_id, tenant_id).cloned();
        let close_pending = runtime_bindings
            .pending_close
            .as_ref()
            .is_some_and(|pending| pending.agent_run_id == session_id);
        let bindings = if session.is_some() && !close_pending {
            runtime_bindings
                .committed
                .bindings_for_agent_run(session_id)
        } else {
            Vec::new()
        };
        let attributions = (!close_pending)
            .then_some(session.as_ref())
            .flatten()
            .map(|session| {
                let Some(claim_revision) = session
                    .intent
                    .kubernetes_claims
                    .first()
                    .map(|claim| claim.claim_revision)
                else {
                    return Vec::new();
                };
                runtime_bindings
                    .kubernetes
                    .attributions_for_agent_run_at_revision(session_id, claim_revision)
                    .into_iter()
                    .filter(|attribution| {
                        session.intent.kubernetes_claims.iter().any(|claim| {
                            claim.cluster_id == attribution.cluster_id
                                && claim.namespace_ref == attribution.namespace_ref
                                && claim.pod_uid == attribution.pod_uid
                                && claim.container_kind == attribution.container_kind
                                && claim.container_ref == attribution.container_ref
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        (session, bindings, attributions)
    }

    pub async fn list_for_tenant(
        &self,
        tenant_id: &str,
        retention_tier: Option<RetentionTier>,
    ) -> Vec<SessionState> {
        self.registry
            .read()
            .await
            .list_for_tenant(tenant_id, retention_tier)
    }

    pub async fn preview_retention_at(
        &self,
        tenant_id: &str,
        now_unix_ms: u64,
    ) -> RetentionPurgeReport {
        self.registry
            .read()
            .await
            .retention_purge_report_for_tenant(tenant_id, now_unix_ms, true)
    }

    pub async fn apply_retention(&self) -> Result<RetentionPurgeReport, RetentionError> {
        let now_unix_ms = current_unix_ms().map_err(|_| RetentionError::ClockUnavailable)?;
        self.apply_retention_at(now_unix_ms).await
    }

    async fn apply_retention_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<RetentionPurgeReport, RetentionError> {
        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        let report = candidate.apply_retention(now_unix_ms);
        let purged_agent_run_ids = report.purged_session_ids.clone();
        if !purged_agent_run_ids.is_empty() {
            let mut stores = self.stores.lock().await;
            let mut targets = Vec::with_capacity(purged_agent_run_ids.len());
            for agent_run_id in &purged_agent_run_ids {
                let target =
                    validate_agent_run_retention_target(&self.agent_runs_dir, agent_run_id)?;
                let expected_timeline = target.agent_run_path().join("timeline.jsonl");
                let Some(managed) = stores.active.get(agent_run_id) else {
                    return Err(RetentionError::UnsafeTarget);
                };
                let opened_timeline = managed
                    .store
                    .file_identity()
                    .map_err(|_| RetentionError::UnsafeTarget)?;
                if managed.store.path() != expected_timeline
                    || managed.identity.agent_run_device != target.directory_device()
                    || managed.identity.agent_run_inode != target.directory_inode()
                    || opened_timeline.device != target.timeline_device()
                    || opened_timeline.inode != target.timeline_inode()
                {
                    return Err(RetentionError::UnsafeTarget);
                }
                targets.push(target);
            }
            for agent_run_id in &purged_agent_run_ids {
                stores.write_blocked.insert(agent_run_id.clone());
            }
            let mut transaction =
                match stage_agent_run_retention_targets(&self.agent_runs_dir, &targets) {
                    Ok(transaction) => transaction,
                    Err(error) => {
                        if error != RetentionError::StageRollbackFailed {
                            for agent_run_id in &purged_agent_run_ids {
                                stores.write_blocked.remove(agent_run_id);
                            }
                        }
                        drop(stores);
                        if error == RetentionError::StageRollbackFailed {
                            self.health
                                .write()
                                .await
                                .set_storage(ComponentState::Degraded);
                        }
                        return Err(error);
                    }
                };
            if transaction.commit().is_err() {
                let rollback = transaction.rollback();
                if rollback.is_ok() {
                    for agent_run_id in &purged_agent_run_ids {
                        stores.write_blocked.remove(agent_run_id);
                    }
                }
                drop(stores);
                if rollback.is_err() {
                    self.health
                        .write()
                        .await
                        .set_storage(ComponentState::Degraded);
                    return Err(RetentionError::StageRollbackFailed);
                }
                return Err(RetentionError::StageFailed);
            }
            for agent_run_id in &purged_agent_run_ids {
                stores.active.remove(agent_run_id);
            }
            drop(stores);

            *registry = candidate;
            {
                let mut paused = self.paused_agent_runs.write().await;
                for agent_run_id in &purged_agent_run_ids {
                    paused.remove(agent_run_id);
                }
            }

            if let Err(error) = transaction.cleanup() {
                self.health
                    .write()
                    .await
                    .set_storage(ComponentState::Degraded);
                return Err(error);
            }
            return Ok(report);
        }
        *registry = candidate;
        Ok(report)
    }

    pub async fn session_for_cgroup(&self, cgroup_id: u64) -> Option<String> {
        self.registry
            .read()
            .await
            .session_for_cgroup(cgroup_id)
            .map(str::to_string)
    }

    pub async fn tracked_cgroups(&self) -> Vec<u64> {
        self.registry.read().await.tracked_cgroups()
    }

    pub async fn workspace_root_for_session(&self, session_id: &str) -> PathBuf {
        self.registry
            .read()
            .await
            .get(session_id)
            .and_then(|state| {
                state
                    .intent
                    .allowed_resources
                    .iter()
                    .find(|selector| selector.kind == ResourceKind::Workspace)
            })
            .map(|selector| PathBuf::from(&selector.value))
            .unwrap_or_else(|| PathBuf::from("/__apolysis_no_workspace__"))
    }

    pub async fn intent_for_session(&self, session_id: &str) -> Option<SessionIntent> {
        self.registry
            .read()
            .await
            .get(session_id)
            .map(|state| state.intent.clone())
    }

    pub async fn discover_cgroup(
        &self,
        session_id: &str,
        cgroup_id: u64,
    ) -> Result<AssociationOutcome, String> {
        let runtime_bindings = self.runtime_bindings.lock().await;
        if runtime_bindings
            .pending_close
            .as_ref()
            .is_some_and(|pending| pending.agent_run_id == session_id)
        {
            return Err("Agent Run close finalization is pending".to_string());
        }
        let mut registry = self.registry.write().await;
        if registry.session_for_cgroup(cgroup_id) == Some(session_id) {
            return Ok(if registry.get(session_id).is_some() {
                AssociationOutcome::Attached
            } else {
                AssociationOutcome::MissingIntent
            });
        }

        let mut candidate = registry.clone();
        let outcome = candidate
            .discover_cgroup(session_id, cgroup_id)
            .map_err(registry_error)?;
        let scope_intent = candidate.get(session_id).map(|state| state.intent.clone());
        if let Some(scope) = &self.scope {
            scope
                .track_agent_run(session_id, scope_intent.as_ref(), cgroup_id)
                .await?;
        }

        let outcome_name = match outcome {
            AssociationOutcome::Attached => "attached",
            AssociationOutcome::MissingIntent => "missing_intent",
        };
        if let Err(error) = self
            .persist(
                session_id,
                json!({
                    "record_type":"cgroup_discovered",
                    "session_id":session_id,
                    "cgroup_id":cgroup_id,
                    "outcome":outcome_name
                }),
            )
            .await
        {
            if let Some(scope) = &self.scope {
                if let Err(rollback) = scope
                    .untrack_agent_run(session_id, scope_intent.as_ref(), cgroup_id)
                    .await
                {
                    return Err(format!("{error}; scope rollback failed: {rollback}"));
                }
            }
            return Err(error);
        }

        *registry = candidate;
        drop(runtime_bindings);
        Ok(outcome)
    }

    pub async fn health(&self) -> HealthSnapshot {
        let mut health = self.health.read().await.clone();
        if let Ok(stats) = self.pipeline.stats() {
            health.queue = stats;
        }
        health
    }

    pub fn pipeline(&self) -> EventPipeline {
        self.pipeline.clone()
    }

    pub fn collector_checkpoint_interval(&self) -> Duration {
        self.collector_checkpoint_interval
    }

    pub async fn set_ebpf(&self, state: ComponentState) {
        self.health.write().await.set_ebpf(state);
    }

    pub async fn set_adapter(&self, adapter: AdapterKind, state: ComponentState) {
        self.health.write().await.set_adapter(adapter, state);
    }

    pub async fn apply_kubernetes_qualification_cycle(
        &self,
        before: KubernetesPodSnapshot,
        inventory: RuntimeInventory,
        after: KubernetesPodSnapshot,
    ) -> Result<KubernetesAttributionSummary, String> {
        self.apply_kubernetes_qualification_cycle_classified(before, inventory, after)
            .await
            .map_err(|error| error.to_string())
    }

    pub(crate) async fn apply_kubernetes_qualification_cycle_classified(
        &self,
        before: KubernetesPodSnapshot,
        inventory: RuntimeInventory,
        after: KubernetesPodSnapshot,
    ) -> Result<KubernetesAttributionSummary, KubernetesQualificationCycleError> {
        let adapter = inventory.adapter;
        if !matches!(
            adapter,
            AdapterKind::Containerd | AdapterKind::K3sContainerd
        ) {
            return Err(KubernetesQualificationCycleError::runtime(
                "Kubernetes qualification requires a complete containerd runtime inventory"
                    .to_string(),
            ));
        }
        let complete_runtime_inventory = KubernetesRuntimeInventory {
            adapter: adapter_name(adapter).to_string(),
            bindings: inventory
                .bindings
                .iter()
                .map(|binding| runtime_binding_wire(RuntimeBindingRecordType::Observed, binding))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        self.resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        let resumed_summary = self
            .resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        let mut kubernetes_candidate = runtime_bindings.kubernetes.clone();
        let claim_sets = {
            let registry = self.registry.read().await;
            runtime_bindings
                .kubernetes_claim_revisions
                .keys()
                .cloned()
                .filter_map(|agent_run_id| {
                    if !registry.is_scope_admitted(&agent_run_id) {
                        return None;
                    }
                    let intent = &registry.get(&agent_run_id)?.intent;
                    let claims = intent
                        .kubernetes_claims
                        .iter()
                        .filter(|claim| {
                            claim.cluster_id == before.identity.cluster_id
                                && claim.namespace_ref == before.identity.namespace_ref
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    let claim_revision = claims.first().map(|claim| claim.claim_revision)?;
                    Some((agent_run_id, claim_revision, claims))
                })
                .collect::<Vec<_>>()
        };
        let mut plans = Vec::with_capacity(claim_sets.len());
        let mut summary = resumed_summary;
        let mut authorized_runtime_bindings = BTreeSet::new();
        for (agent_run_id, claim_revision, claims) in claim_sets {
            let plan = kubernetes_candidate
                .reconcile(KubernetesQualificationCycle {
                    agent_run_id: agent_run_id.clone(),
                    claim_revision,
                    claims,
                    before: before.clone(),
                    runtime: complete_runtime_inventory.clone(),
                    after: after.clone(),
                })
                .map_err(KubernetesQualificationCycleError::qualification)?;
            merge_kubernetes_summary(&mut summary, plan.summary);
            authorized_runtime_bindings.extend(
                kubernetes_candidate
                    .attributions_for_agent_run_at_revision(&agent_run_id, claim_revision)
                    .into_iter()
                    .map(|attribution| {
                        authorized_runtime_binding_key_from_wire(&attribution.runtime_binding)
                    }),
            );
            plans.push((agent_run_id, plan));
        }

        // Kubernetes source metadata discovers candidates, but only an exact,
        // freshly qualified typed claim can authorize a D1 binding in the K1
        // runtime domain. Filtering before D1 reconciliation prevents a Pod
        // annotation from attaching another Agent Run's scope while retaining
        // complete-inventory retirement semantics for revoked claims.
        let admitted_inventory = RuntimeInventory::new(
            adapter,
            inventory
                .bindings
                .into_iter()
                .filter(|binding| {
                    authorized_runtime_bindings.contains(&authorized_runtime_binding_key(binding))
                })
                .collect(),
        );
        let mut runtime_candidate = runtime_bindings.committed.clone();
        let mut runtime_reconciliation = runtime_candidate
            .reconcile(admitted_inventory)
            .map_err(|error| KubernetesQualificationCycleError::runtime(error.to_string()))?;
        let missing_intent_bindings = {
            let registry = self.registry.read().await;
            runtime_reconciliation
                .effects
                .iter()
                .filter_map(|effect| match effect {
                    RuntimeBindingEffect::Attach { binding }
                        if !registry.is_scope_admitted(&binding.agent_run_id) =>
                    {
                        Some((binding.agent_run_id.clone(), binding.identity.cgroup.inode))
                    }
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
        };
        runtime_reconciliation.summary.attached = runtime_reconciliation
            .summary
            .attached
            .saturating_sub(missing_intent_bindings.len());
        runtime_reconciliation.summary.missing_intent = missing_intent_bindings.len();

        let batches = combined_attribution_batches(
            &runtime_reconciliation.effects,
            &plans,
            None,
            Some(&missing_intent_bindings),
        )?;
        runtime_bindings.pending_kubernetes = Some(PendingKubernetesApplication {
            runtime_candidate,
            kubernetes_candidate,
            runtime_reconciliation,
            kubernetes_summary: summary,
            batches,
            next_batch: 0,
        });
        let summary = self
            .finish_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        drop(runtime_bindings);
        self.set_adapter(adapter, ComponentState::Ready).await;
        self.set_adapter(AdapterKind::Kubernetes, ComponentState::Ready)
            .await;
        Ok(summary)
    }

    pub async fn kubernetes_source_unavailable(
        &self,
        cluster_id: &str,
        reason: KubernetesSourceUnavailableReason,
    ) -> Result<KubernetesAttributionSummary, String> {
        if reason == KubernetesSourceUnavailableReason::RuntimeUnavailable {
            return Err(
                "runtime unavailability must be applied with the exact runtime source".to_string(),
            );
        }
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        self.resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        let mut summary = self
            .resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        let mut kubernetes_candidate = runtime_bindings.kubernetes.clone();
        let registered_claims = {
            let registry = self.registry.read().await;
            runtime_bindings
                .kubernetes_claim_revisions
                .iter()
                .filter_map(|(agent_run_id, claim_revision)| {
                    let intent = &registry.get(agent_run_id)?.intent;
                    intent
                        .kubernetes_claims
                        .iter()
                        .any(|claim| claim.cluster_id == cluster_id)
                        .then_some((agent_run_id.clone(), *claim_revision))
                })
                .collect::<Vec<_>>()
        };
        let mut plans = Vec::new();
        for (agent_run_id, claim_revision) in registered_claims {
            let plan = kubernetes_candidate
                .source_unavailable(&agent_run_id, claim_revision, cluster_id, reason)
                .map_err(|error| error.to_string())?;
            merge_kubernetes_summary(&mut summary, plan.summary);
            plans.push((agent_run_id, plan));
        }
        let runtime_candidate = runtime_bindings.committed.clone();
        let runtime_reconciliation = RuntimeBindingReconcile::default();
        let batches = combined_attribution_batches(&[], &plans, None, None)?;
        runtime_bindings.pending_kubernetes = Some(PendingKubernetesApplication {
            runtime_candidate,
            kubernetes_candidate,
            runtime_reconciliation,
            kubernetes_summary: summary,
            batches,
            next_batch: 0,
        });
        let summary = self
            .finish_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        drop(runtime_bindings);
        self.set_adapter(AdapterKind::Kubernetes, ComponentState::Degraded)
            .await;
        Ok(summary)
    }

    pub async fn reconcile_runtime_inventory(
        &self,
        inventory: RuntimeInventory,
    ) -> Result<RuntimeBindingReconcile, String> {
        let adapter = inventory.adapter;
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        let resumed = self
            .resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        self.resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        let mut candidate = runtime_bindings.committed.clone();
        let mut reconciliation = candidate
            .reconcile(inventory)
            .map_err(|error| error.to_string())?;
        let missing_intent_attaches = {
            let registry = self.registry.read().await;
            reconciliation
                .effects
                .iter()
                .filter(|effect| {
                    matches!(
                        effect,
                        RuntimeBindingEffect::Attach { binding }
                            if !registry.is_scope_admitted(&binding.agent_run_id)
                    )
                })
                .count()
        };
        reconciliation.summary.attached = reconciliation
            .summary
            .attached
            .saturating_sub(missing_intent_attaches);
        reconciliation.summary.missing_intent = missing_intent_attaches;
        let applied = self
            .stage_runtime_binding_application(
                &mut runtime_bindings,
                candidate,
                reconciliation,
                None,
            )
            .await?;
        self.set_adapter(adapter, ComponentState::Ready).await;
        Ok(merge_runtime_binding_reconciliations(resumed, applied))
    }

    pub async fn kubernetes_runtime_source_unavailable(
        &self,
        cluster_id: &str,
        adapter: AdapterKind,
        reason: RuntimeSourceGapReason,
    ) -> Result<RuntimeBindingReconcile, String> {
        if !matches!(
            adapter,
            AdapterKind::Containerd | AdapterKind::K3sContainerd
        ) {
            return Err(
                "Kubernetes qualification requires a containerd runtime source".to_string(),
            );
        }
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        let resumed = self
            .resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        self.resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;

        let mut runtime_candidate = runtime_bindings.committed.clone();
        let reconciliation = runtime_candidate
            .source_unavailable(adapter)
            .map_err(|error| error.to_string())?;
        let registered_claims = {
            let registry = self.registry.read().await;
            runtime_bindings
                .kubernetes_claim_revisions
                .iter()
                .filter_map(|(agent_run_id, claim_revision)| {
                    let intent = &registry.get(agent_run_id)?.intent;
                    intent
                        .kubernetes_claims
                        .iter()
                        .any(|claim| claim.cluster_id == cluster_id)
                        .then_some((agent_run_id.clone(), *claim_revision))
                })
                .collect::<Vec<_>>()
        };
        let mut kubernetes_candidate = runtime_bindings.kubernetes.clone();
        let mut kubernetes_summary = KubernetesAttributionSummary::default();
        let mut plans = Vec::with_capacity(registered_claims.len());
        for (agent_run_id, claim_revision) in registered_claims {
            let plan = kubernetes_candidate
                .source_unavailable(
                    &agent_run_id,
                    claim_revision,
                    cluster_id,
                    KubernetesSourceUnavailableReason::RuntimeUnavailable,
                )
                .map_err(|error| error.to_string())?;
            merge_kubernetes_summary(&mut kubernetes_summary, plan.summary);
            plans.push((agent_run_id, plan));
        }

        let batches =
            combined_attribution_batches(&reconciliation.effects, &plans, Some(reason), None)?;
        runtime_bindings.pending_kubernetes = Some(PendingKubernetesApplication {
            runtime_candidate,
            kubernetes_candidate,
            runtime_reconciliation: reconciliation.clone(),
            kubernetes_summary,
            batches,
            next_batch: 0,
        });
        self.finish_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        drop(runtime_bindings);
        self.set_adapter(adapter, ComponentState::Degraded).await;
        self.set_adapter(AdapterKind::Kubernetes, ComponentState::Degraded)
            .await;
        Ok(merge_runtime_binding_reconciliations(
            resumed,
            reconciliation,
        ))
    }

    pub async fn runtime_source_unavailable(
        &self,
        adapter: AdapterKind,
        reason: RuntimeSourceGapReason,
    ) -> Result<RuntimeBindingReconcile, String> {
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        let resumed = self
            .resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        self.resume_pending_kubernetes_application(&mut runtime_bindings)
            .await?;
        let mut candidate = runtime_bindings.committed.clone();
        let reconciliation = candidate
            .source_unavailable(adapter)
            .map_err(|error| error.to_string())?;
        let affected_agent_runs = reconciliation
            .effects
            .iter()
            .filter_map(runtime_binding_effect_agent_run_id)
            .collect::<BTreeSet<_>>();
        let mut kubernetes_candidate = runtime_bindings.kubernetes.clone();
        let mut kubernetes_summary = KubernetesAttributionSummary::default();
        let mut plans = Vec::new();
        for agent_run_id in affected_agent_runs {
            let Some(claim_revision) = runtime_bindings
                .kubernetes_claim_revisions
                .get(agent_run_id)
                .copied()
            else {
                continue;
            };
            let cluster_id = kubernetes_candidate
                .attributions_for_agent_run(agent_run_id)
                .first()
                .map(|attribution| attribution.cluster_id.clone())
                .ok_or_else(|| {
                    "runtime outage attribution has no Kubernetes cluster identity".to_string()
                })?;
            let plan = kubernetes_candidate
                .source_unavailable(
                    agent_run_id,
                    claim_revision,
                    &cluster_id,
                    KubernetesSourceUnavailableReason::RuntimeUnavailable,
                )
                .map_err(|error| error.to_string())?;
            merge_kubernetes_summary(&mut kubernetes_summary, plan.summary);
            plans.push((agent_run_id.to_string(), plan));
        }
        if !plans.is_empty() {
            let batches =
                combined_attribution_batches(&reconciliation.effects, &plans, Some(reason), None)?;
            runtime_bindings.pending_kubernetes = Some(PendingKubernetesApplication {
                runtime_candidate: candidate,
                kubernetes_candidate,
                runtime_reconciliation: reconciliation.clone(),
                kubernetes_summary,
                batches,
                next_batch: 0,
            });
            self.finish_pending_kubernetes_application(&mut runtime_bindings)
                .await?;
            self.set_adapter(adapter, ComponentState::Degraded).await;
            self.set_adapter(AdapterKind::Kubernetes, ComponentState::Degraded)
                .await;
            return Ok(merge_runtime_binding_reconciliations(
                resumed,
                reconciliation,
            ));
        }
        let applied = self
            .stage_runtime_binding_application(
                &mut runtime_bindings,
                candidate,
                reconciliation,
                Some(reason),
            )
            .await?;
        self.set_adapter(adapter, ComponentState::Degraded).await;
        Ok(merge_runtime_binding_reconciliations(resumed, applied))
    }

    pub async fn runtime_bindings_for_agent_run(&self, agent_run_id: &str) -> Vec<RuntimeBinding> {
        let runtime_bindings = self.runtime_bindings.lock().await;
        if runtime_bindings
            .pending_close
            .as_ref()
            .is_some_and(|pending| pending.agent_run_id == agent_run_id)
        {
            Vec::new()
        } else {
            runtime_bindings
                .committed
                .bindings_for_agent_run(agent_run_id)
        }
    }

    pub(crate) async fn runtime_container_id_for_cgroup(
        &self,
        agent_run_id: &str,
        cgroup_id: u64,
    ) -> Option<String> {
        self.runtime_bindings
            .lock()
            .await
            .committed
            .bindings_for_agent_run(agent_run_id)
            .into_iter()
            .find(|binding| binding.identity.cgroup.inode == cgroup_id)
            .map(|binding| binding.identity.workload_id)
    }

    async fn resume_pending_runtime_binding_application(
        &self,
        runtime_bindings: &mut ManagedRuntimeBindings,
    ) -> Result<RuntimeBindingReconcile, String> {
        if runtime_bindings.pending_close.is_some() {
            return Err("Agent Run close finalization is pending".to_string());
        }
        if runtime_bindings.pending.is_none() {
            return Ok(RuntimeBindingReconcile::default());
        }
        self.finish_pending_runtime_binding_application(runtime_bindings)
            .await
    }

    async fn resume_pending_kubernetes_application(
        &self,
        runtime_bindings: &mut ManagedRuntimeBindings,
    ) -> Result<KubernetesAttributionSummary, String> {
        if runtime_bindings.pending_kubernetes.is_none() {
            return Ok(KubernetesAttributionSummary::default());
        }
        self.finish_pending_kubernetes_application(runtime_bindings)
            .await
    }

    async fn finish_pending_agent_run_close(
        &self,
        runtime_bindings: &mut ManagedRuntimeBindings,
    ) -> Result<String, String> {
        let pending = runtime_bindings
            .pending_close
            .as_ref()
            .cloned()
            .ok_or_else(|| "Agent Run close is not pending".to_string())?;
        if let (Some(scope), Some(prepared)) = (&self.scope, &pending.prepared_scope) {
            scope
                .finalize_agent_run_close(prepared)
                .await
                .map_err(|error| {
                    format!(
                        "Agent Run close is durable but scope finalization remains pending: {error}"
                    )
                })?;
        }
        let mut registry = self.registry.write().await;
        *registry = pending.registry_candidate;
        runtime_bindings.committed = pending.runtime_candidate;
        runtime_bindings.kubernetes = pending.kubernetes_candidate;
        runtime_bindings
            .kubernetes_claim_revisions
            .remove(&pending.agent_run_id);
        runtime_bindings.pending_close = None;
        Ok(pending.agent_run_id)
    }

    async fn finish_pending_kubernetes_application(
        &self,
        runtime_bindings: &mut ManagedRuntimeBindings,
    ) -> Result<KubernetesAttributionSummary, String> {
        loop {
            let batch = runtime_bindings
                .pending_kubernetes
                .as_ref()
                .and_then(|pending| pending.batches.get(pending.next_batch).cloned());
            let Some((agent_run_id, payloads)) = batch else {
                break;
            };
            self.persist_batch(&agent_run_id, payloads).await?;
            let pending = runtime_bindings
                .pending_kubernetes
                .as_mut()
                .ok_or_else(|| "Kubernetes application lost pending state".to_string())?;
            pending.next_batch = pending.next_batch.saturating_add(1);
        }
        let effects = runtime_bindings
            .pending_kubernetes
            .as_ref()
            .ok_or_else(|| "Kubernetes application is not pending".to_string())?
            .runtime_reconciliation
            .effects
            .clone();
        self.apply_runtime_binding_state_and_scope(&effects).await?;
        let completed = runtime_bindings
            .pending_kubernetes
            .take()
            .ok_or_else(|| "Kubernetes application lost completed state".to_string())?;
        runtime_bindings.committed = completed.runtime_candidate;
        runtime_bindings.kubernetes = completed.kubernetes_candidate;
        Ok(completed.kubernetes_summary)
    }

    async fn stage_runtime_binding_application(
        &self,
        runtime_bindings: &mut ManagedRuntimeBindings,
        candidate: RuntimeBindingCoordinator,
        reconciliation: RuntimeBindingReconcile,
        source_reason: Option<RuntimeSourceGapReason>,
    ) -> Result<RuntimeBindingReconcile, String> {
        let pending_reconciliation = runtime_binding_reconcile_without_gaps(&reconciliation);
        let gap_batches = runtime_binding_gap_batches(&reconciliation.effects, source_reason)?;
        if pending_reconciliation.effects.is_empty() && gap_batches.is_empty() {
            runtime_bindings.committed = candidate;
            return Ok(reconciliation);
        }
        runtime_bindings.pending = Some(PendingRuntimeBindingApplication {
            candidate,
            reconciliation: pending_reconciliation,
            gap_batches,
            next_gap_batch: 0,
            next_effect_batch: 0,
        });
        self.finish_pending_runtime_binding_application(runtime_bindings)
            .await?;
        Ok(reconciliation)
    }

    async fn finish_pending_runtime_binding_application(
        &self,
        runtime_bindings: &mut ManagedRuntimeBindings,
    ) -> Result<RuntimeBindingReconcile, String> {
        let mut applied_gap_effects = Vec::new();
        loop {
            let batch = runtime_bindings
                .pending
                .as_ref()
                .and_then(|pending| pending.gap_batches.get(pending.next_gap_batch).cloned());
            let Some(batch) = batch else {
                break;
            };
            self.persist_batch(&batch.agent_run_id, batch.payloads)
                .await?;
            let pending = runtime_bindings
                .pending
                .as_mut()
                .ok_or_else(|| "runtime binding application lost pending state".to_string())?;
            pending.next_gap_batch = pending.next_gap_batch.saturating_add(1);
            applied_gap_effects.extend(batch.effects);
        }
        let pending = runtime_bindings
            .pending
            .as_ref()
            .cloned()
            .ok_or_else(|| "runtime binding application is not pending".to_string())?;
        match self
            .apply_runtime_binding_effects(
                &pending.reconciliation.effects,
                pending.next_effect_batch,
            )
            .await
        {
            Ok(next_effect_batch) => {
                let pending = runtime_bindings
                    .pending
                    .as_mut()
                    .ok_or_else(|| "runtime binding application lost pending state".to_string())?;
                pending.next_effect_batch = next_effect_batch;
            }
            Err(error) => {
                let pending = runtime_bindings
                    .pending
                    .as_mut()
                    .ok_or_else(|| "runtime binding application lost pending state".to_string())?;
                pending.next_effect_batch = error.next_effect_batch;
                return Err(error.message);
            }
        }
        let completed = runtime_bindings
            .pending
            .take()
            .ok_or_else(|| "runtime binding application lost completed state".to_string())?;
        runtime_bindings.committed = completed.candidate;
        applied_gap_effects.extend(completed.reconciliation.effects);
        let mut reconciliation = runtime_binding_reconcile_for_effects(
            applied_gap_effects,
            completed.reconciliation.summary.active,
        );
        reconciliation.summary.attached = completed.reconciliation.summary.attached;
        Ok(reconciliation)
    }

    async fn apply_runtime_binding_effects(
        &self,
        effects: &[RuntimeBindingEffect],
        next_effect_batch: usize,
    ) -> Result<usize, RuntimeBindingEffectApplicationError> {
        if effects.is_empty() {
            return Ok(0);
        }

        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        let mut missing_intent_bindings = BTreeSet::new();
        for effect in effects {
            match effect {
                RuntimeBindingEffect::Suspend { binding }
                | RuntimeBindingEffect::Retire { binding }
                | RuntimeBindingEffect::RetireDormant { binding } => {
                    candidate
                        .retire_cgroup(&binding.agent_run_id, binding.identity.cgroup.inode)
                        .map_err(|error| {
                            RuntimeBindingEffectApplicationError::new(
                                registry_error(error),
                                next_effect_batch,
                            )
                        })?;
                }
                RuntimeBindingEffect::Attach { binding } => {
                    let outcome = candidate
                        .discover_cgroup(&binding.agent_run_id, binding.identity.cgroup.inode)
                        .map_err(|error| {
                            RuntimeBindingEffectApplicationError::new(
                                registry_error(error),
                                next_effect_batch,
                            )
                        })?;
                    if outcome == AssociationOutcome::MissingIntent {
                        missing_intent_bindings
                            .insert((binding.agent_run_id.clone(), binding.identity.cgroup.inode));
                    }
                }
                RuntimeBindingEffect::PersistGap { .. } => {}
            }
        }

        let mut applied_scope_effects = Vec::new();
        if let Some(scope) = &self.scope {
            for effect in effects {
                let result = match effect {
                    RuntimeBindingEffect::Suspend { binding }
                    | RuntimeBindingEffect::Retire { binding } => {
                        let intent = registry
                            .get(&binding.agent_run_id)
                            .map(|state| state.intent.clone());
                        scope
                            .untrack_runtime_agent_run(
                                &binding.agent_run_id,
                                intent.as_ref(),
                                binding.identity.cgroup.inode,
                                &binding.identity.workload_id,
                            )
                            .await
                    }
                    RuntimeBindingEffect::Attach { binding } => {
                        let intent = candidate
                            .get(&binding.agent_run_id)
                            .map(|state| state.intent.clone());
                        scope
                            .track_runtime_agent_run(
                                &binding.agent_run_id,
                                intent.as_ref(),
                                binding.identity.cgroup.inode,
                                &binding.identity.workload_id,
                            )
                            .await
                    }
                    RuntimeBindingEffect::RetireDormant { .. } => continue,
                    RuntimeBindingEffect::PersistGap { .. } => continue,
                };
                if let Err(error) = result {
                    let rollback = rollback_runtime_scope_effects(
                        scope,
                        &registry,
                        &candidate,
                        &applied_scope_effects,
                    )
                    .await;
                    return Err(RuntimeBindingEffectApplicationError::new(
                        match rollback {
                            Ok(()) => error,
                            Err(rollback) => {
                                format!("{error}; runtime scope rollback failed: {rollback}")
                            }
                        },
                        next_effect_batch,
                    ));
                }
                applied_scope_effects.push(effect.clone());
            }
        }

        let mut effect_batches = BTreeMap::<String, Vec<Value>>::new();
        for effect in effects {
            let (record_type, binding) = match effect {
                RuntimeBindingEffect::Suspend { binding } => {
                    (RuntimeBindingRecordType::Suspended, binding)
                }
                RuntimeBindingEffect::Retire { binding }
                | RuntimeBindingEffect::RetireDormant { binding } => {
                    (RuntimeBindingRecordType::Retired, binding)
                }
                RuntimeBindingEffect::Attach { binding } => {
                    (RuntimeBindingRecordType::Observed, binding)
                }
                RuntimeBindingEffect::PersistGap { .. } => continue,
            };
            let payloads = effect_batches
                .entry(binding.agent_run_id.clone())
                .or_default();
            payloads.push(
                runtime_binding_payload(record_type, binding).map_err(|error| {
                    RuntimeBindingEffectApplicationError::new(error, next_effect_batch)
                })?,
            );
            if matches!(effect, RuntimeBindingEffect::Attach { .. })
                && missing_intent_bindings
                    .contains(&(binding.agent_run_id.clone(), binding.identity.cgroup.inode))
            {
                payloads.extend(runtime_binding_missing_intent_payloads(binding).map_err(
                    |error| RuntimeBindingEffectApplicationError::new(error, next_effect_batch),
                )?);
            }
        }
        let effect_batch_count = effect_batches.len();
        if next_effect_batch > effect_batch_count {
            return Err(RuntimeBindingEffectApplicationError::new(
                "runtime binding effect progress exceeds the pending batch count".to_string(),
                next_effect_batch,
            ));
        }
        for (batch_index, (agent_run_id, payloads)) in effect_batches
            .into_iter()
            .enumerate()
            .skip(next_effect_batch)
        {
            if let Err(error) = self.persist_batch(&agent_run_id, payloads).await {
                if let Some(scope) = &self.scope {
                    if let Err(rollback) = rollback_runtime_scope_effects(
                        scope,
                        &registry,
                        &candidate,
                        &applied_scope_effects,
                    )
                    .await
                    {
                        return Err(RuntimeBindingEffectApplicationError::new(
                            format!("{error}; runtime scope rollback failed: {rollback}"),
                            batch_index,
                        ));
                    }
                }
                return Err(RuntimeBindingEffectApplicationError::new(
                    error,
                    batch_index,
                ));
            }
        }

        *registry = candidate;
        Ok(effect_batch_count)
    }

    async fn apply_runtime_binding_state_and_scope(
        &self,
        effects: &[RuntimeBindingEffect],
    ) -> Result<(), String> {
        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        for effect in effects {
            match effect {
                RuntimeBindingEffect::Suspend { binding }
                | RuntimeBindingEffect::Retire { binding }
                | RuntimeBindingEffect::RetireDormant { binding } => {
                    candidate
                        .retire_cgroup(&binding.agent_run_id, binding.identity.cgroup.inode)
                        .map_err(registry_error)?;
                }
                RuntimeBindingEffect::Attach { binding } => {
                    candidate
                        .discover_cgroup(&binding.agent_run_id, binding.identity.cgroup.inode)
                        .map_err(registry_error)?;
                }
                RuntimeBindingEffect::PersistGap { .. } => {}
            }
        }

        let mut applied_scope_effects = Vec::new();
        if let Some(scope) = &self.scope {
            for effect in effects {
                let result = match effect {
                    RuntimeBindingEffect::Suspend { binding }
                    | RuntimeBindingEffect::Retire { binding } => {
                        let intent = registry
                            .get(&binding.agent_run_id)
                            .map(|state| state.intent.clone());
                        scope
                            .untrack_runtime_agent_run(
                                &binding.agent_run_id,
                                intent.as_ref(),
                                binding.identity.cgroup.inode,
                                &binding.identity.workload_id,
                            )
                            .await
                    }
                    RuntimeBindingEffect::Attach { binding } => {
                        let intent = candidate
                            .get(&binding.agent_run_id)
                            .map(|state| state.intent.clone());
                        scope
                            .track_runtime_agent_run(
                                &binding.agent_run_id,
                                intent.as_ref(),
                                binding.identity.cgroup.inode,
                                &binding.identity.workload_id,
                            )
                            .await
                    }
                    RuntimeBindingEffect::RetireDormant { .. }
                    | RuntimeBindingEffect::PersistGap { .. } => continue,
                };
                if let Err(error) = result {
                    let rollback = rollback_runtime_scope_effects(
                        scope,
                        &registry,
                        &candidate,
                        &applied_scope_effects,
                    )
                    .await;
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback) => {
                            format!("{error}; runtime scope rollback failed: {rollback}")
                        }
                    });
                }
                applied_scope_effects.push(effect.clone());
            }
        }
        *registry = candidate;
        Ok(())
    }

    pub async fn persist_collector_lifecycle(
        &self,
        record: CollectorLifecycleRecord,
    ) -> Result<(), String> {
        let agent_run_id = record.agent_run_id().to_string();
        let payload = serde_json::from_str(&record.to_json_line())
            .map_err(|error| format!("failed to encode collector lifecycle: {error}"))?;
        self.persist(&agent_run_id, payload).await
    }

    pub async fn persist_collector_start_boundary(
        &self,
        capability: CollectorCapabilityManifest,
        started: CollectorLifecycleRecord,
    ) -> Result<(), String> {
        let agent_run_id = started.agent_run_id().to_string();
        if capability.agent_run_id != agent_run_id {
            return Err(
                "collector capability and lifecycle Agent Run identities differ".to_string(),
            );
        }
        let capability_payload = serde_json::from_str(&capability.to_json_line())
            .map_err(|error| format!("failed to encode collector capability: {error}"))?;
        let started_payload: Value = serde_json::from_str(&started.to_json_line())
            .map_err(|error| format!("failed to encode collector lifecycle: {error}"))?;
        if started_payload.get("state").and_then(Value::as_str) != Some("started") {
            return Err("collector start boundary requires a started lifecycle record".to_string());
        }

        let mut declared = self.collector_capability_agent_runs.lock().await;
        let first_start = !declared.contains(&agent_run_id);
        let mut payloads = Vec::with_capacity(if first_start { 2 } else { 1 });
        if first_start {
            payloads.push(capability_payload);
        }
        payloads.push(started_payload);
        self.persist_batch(&agent_run_id, payloads).await?;
        if first_start {
            declared.insert(agent_run_id);
        }
        Ok(())
    }

    pub async fn persist_collector_failure_for_tracked_runs(
        &self,
        collector_instance_id: &str,
        reason: CollectorFailureReason,
    ) -> Result<usize, String> {
        let agent_run_ids: BTreeSet<String> = {
            let registry = self.registry.read().await;
            registry
                .tracked_cgroups()
                .into_iter()
                .filter_map(|cgroup_id| registry.session_for_cgroup(cgroup_id).map(str::to_string))
                .collect()
        };
        for agent_run_id in &agent_run_ids {
            self.persist_collector_lifecycle(CollectorLifecycleRecord::failed(
                agent_run_id,
                collector_instance_id,
                reason,
                CollectorLifecycleCounters::default(),
            ))
            .await?;
        }
        Ok(agent_run_ids.len())
    }

    pub async fn ingest_runtime_workload(
        &self,
        workload: RuntimeWorkload,
    ) -> Result<AssociationOutcome, String> {
        let outcome = self
            .discover_cgroup(&workload.session_id, workload.cgroup_id)
            .await?;
        let outcome_name = match outcome {
            AssociationOutcome::Attached => "attached",
            AssociationOutcome::MissingIntent => "missing_intent",
        };
        self.persist(
            &workload.session_id,
            json!({
                "record_type":"runtime_workload_discovered",
                "adapter":workload.adapter,
                "session_id":workload.session_id,
                "workload_id":workload.workload_id,
                "cgroup_id":workload.cgroup_id,
                "image":workload.image,
                "runtime_handler":workload.runtime_handler,
                "outcome":outcome_name
            }),
        )
        .await?;
        if outcome == AssociationOutcome::MissingIntent {
            self.persist_missing_intent_finding(&workload).await?;
        }
        self.set_adapter(workload.adapter, ComponentState::Ready)
            .await;
        Ok(outcome)
    }

    pub async fn accountability_finding_payloads(
        &self,
        effect: &ObservedEffect,
    ) -> Result<Vec<Value>, String> {
        let intent = {
            let registry = self.registry.read().await;
            registry
                .get(&effect.session_id)
                .map(|state| state.intent.clone())
        };
        let mut payloads = Vec::new();
        for finding in AccountabilityAnalyzer::evaluate(intent.as_ref(), effect) {
            payloads.push(finding_payload(finding)?);
        }
        Ok(payloads)
    }

    pub async fn run_writer(
        self: std::sync::Arc<Self>,
        shutdown: oneshot::Receiver<()>,
    ) -> Result<WriterSummary, String> {
        let pipeline = self.pipeline();
        pipeline
            .run_writer(shutdown, move |record, delivery_mode| {
                let state = std::sync::Arc::clone(&self);
                async move { state.persist_record(record, delivery_mode).await }
            })
            .await
    }

    pub(crate) async fn persist_record(
        self: &std::sync::Arc<Self>,
        record: DaemonRecord,
        delivery_mode: RecordDeliveryMode,
    ) -> Result<RecordWriteOutcome, String> {
        if !self.storage_writable.load(Ordering::Acquire) {
            return Err(
                "Agent Run storage is unavailable; restart after repairing storage".to_string(),
            );
        }
        if self
            .paused_agent_runs
            .read()
            .await
            .contains_key(&record.session_id)
        {
            return Ok(RecordWriteOutcome::Failed);
        }
        match self.persist_inner(&record.session_id, record.payload).await {
            Ok(()) => Ok(RecordWriteOutcome::Written),
            Err(error) => {
                let first_failure = self.pause_session(&record.session_id, &error).await;
                if delivery_mode == RecordDeliveryMode::Queued && first_failure {
                    let state = std::sync::Arc::clone(self);
                    let session_id = record.session_id.clone();
                    tokio::spawn(async move {
                        state.degrade_session_and_fail_scopes(&session_id).await;
                    });
                }
                Ok(RecordWriteOutcome::Failed)
            }
        }
    }

    pub(crate) async fn session_is_paused(&self, session_id: &str) -> bool {
        self.paused_agent_runs.read().await.contains_key(session_id)
    }

    async fn persist(&self, session_id: &str, payload: Value) -> Result<(), String> {
        if !self.storage_writable.load(Ordering::Acquire) {
            return Err(
                "Agent Run storage is unavailable; restart after repairing storage".to_string(),
            );
        }
        let result = self.persist_inner(session_id, payload).await;
        if result.is_err() {
            self.storage_writable.store(false, Ordering::Release);
            self.health
                .write()
                .await
                .set_storage(ComponentState::Unavailable);
        }
        result
    }

    async fn persist_batch(&self, session_id: &str, payloads: Vec<Value>) -> Result<(), String> {
        if !self.storage_writable.load(Ordering::Acquire) {
            return Err(
                "Agent Run storage is unavailable; restart after repairing storage".to_string(),
            );
        }
        let result = self.persist_batch_inner(session_id, payloads).await;
        if result.is_err() {
            self.storage_writable.store(false, Ordering::Release);
            self.health
                .write()
                .await
                .set_storage(ComponentState::Unavailable);
        }
        result
    }

    async fn persist_missing_intent_finding(
        &self,
        workload: &RuntimeWorkload,
    ) -> Result<(), String> {
        let effect = ObservedEffect {
            session_id: workload.session_id.clone(),
            evidence_ref: format!("runtime_workload:{}", workload.workload_id),
            kind: EffectKind::Exec,
            actor: workload.workload_id.clone(),
            resource: workload.workload_id.clone(),
            runtime: RuntimeIdentity {
                runtime: adapter_name(workload.adapter).to_string(),
                container_id: container_identity(workload),
                pod_uid: None,
                cgroup_id: Some(workload.cgroup_id),
            },
            evidence_boundary: EvidenceBoundary::HostBoundary,
        };
        for payload in self.accountability_finding_payloads(&effect).await? {
            self.persist(&workload.session_id, payload).await?;
        }
        Ok(())
    }

    async fn pause_session(&self, session_id: &str, reason: &str) -> bool {
        let first_failure = self
            .paused_agent_runs
            .write()
            .await
            .insert(session_id.to_string(), reason.to_string())
            .is_none();
        self.health
            .write()
            .await
            .set_storage(ComponentState::Degraded);
        first_failure
    }

    async fn degrade_session_and_fail_scopes(&self, session_id: &str) {
        let degraded = {
            let mut registry = self.registry.write().await;
            registry
                .degrade(session_id)
                .map(|state| (state.intent, state.cgroup_ids))
        };
        if let (Some(scope), Ok((intent, cgroup_ids))) = (&self.scope, degraded) {
            for cgroup_id in cgroup_ids {
                if scope
                    .fail_agent_run(
                        session_id,
                        Some(&intent),
                        cgroup_id,
                        CollectorFailureReason::StorageFailure,
                    )
                    .await
                    .is_err()
                {
                    self.health
                        .write()
                        .await
                        .set_ebpf(ComponentState::Unavailable);
                    break;
                }
            }
        }
    }

    async fn persist_inner(&self, session_id: &str, payload: Value) -> Result<(), String> {
        let mut stores = self.stores.lock().await;
        let store = managed_store_for_write(&mut stores, &self.agent_runs_dir, session_id)?;
        let payload = serde_json::to_string(&payload)
            .map_err(|error| format!("failed to serialize Agent Run record: {error}"))?;
        store
            .store
            .append_json(1, &payload)
            .map_err(|error| format!("failed to append Agent Run timeline: {error}"))?;
        store
            .store
            .flush()
            .map_err(|error| format!("failed to flush Agent Run timeline: {error}"))
    }

    async fn persist_batch_inner(
        &self,
        session_id: &str,
        payloads: Vec<Value>,
    ) -> Result<(), String> {
        let mut stores = self.stores.lock().await;
        let store = managed_store_for_write(&mut stores, &self.agent_runs_dir, session_id)?;
        let payloads = payloads
            .into_iter()
            .map(|payload| {
                serde_json::to_string(&payload)
                    .map_err(|error| format!("failed to serialize Agent Run record: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        store
            .store
            .append_json_batch_and_flush(1, &payloads)
            .map(|_| ())
            .map_err(|error| format!("failed to append Agent Run timeline batch: {error}"))
    }
}

fn managed_store_for_write<'a>(
    stores: &'a mut AgentRunStores,
    agent_runs_dir: &Path,
    session_id: &str,
) -> Result<&'a mut ManagedAgentRunStore, String> {
    if stores.write_blocked.contains(session_id) {
        return Err("Agent Run storage write is blocked".to_string());
    }
    if !stores.active.contains_key(session_id) {
        let timeline = agent_runs_dir.join(session_id).join("timeline.jsonl");
        refuse_unsafe_storage_path_before_open(agent_runs_dir, session_id, &timeline)
            .map_err(|_| "unsafe Agent Run storage target".to_string())?;
        let recovery = HashChainStore::create_or_recover(&timeline)
            .map_err(|error| format!("failed to recover Agent Run timeline: {error}"))?;
        let agent_run_dir = agent_runs_dir.join(session_id);
        let identity = capture_agent_run_storage_identity(&agent_run_dir, &recovery.store)
            .map_err(|_| "unsafe Agent Run storage identity".to_string())?;
        stores.active.insert(
            session_id.to_string(),
            ManagedAgentRunStore {
                store: recovery.store,
                identity,
            },
        );
    }
    stores
        .active
        .get_mut(session_id)
        .ok_or_else(|| "Agent Run store was not initialized".to_string())
}

fn capture_agent_run_storage_identity(
    agent_run_dir: &Path,
    store: &HashChainStore,
) -> Result<AgentRunStorageIdentity, RetentionError> {
    let agent_run_metadata =
        std::fs::symlink_metadata(agent_run_dir).map_err(|_| RetentionError::UnsafeTarget)?;
    let timeline_metadata =
        std::fs::symlink_metadata(store.path()).map_err(|_| RetentionError::UnsafeTarget)?;
    let opened_timeline = store
        .file_identity()
        .map_err(|_| RetentionError::UnsafeTarget)?;
    if !agent_run_metadata.file_type().is_dir()
        || !timeline_metadata.file_type().is_file()
        || timeline_metadata.nlink() != 1
        || timeline_metadata.dev() != opened_timeline.device
        || timeline_metadata.ino() != opened_timeline.inode
    {
        return Err(RetentionError::UnsafeTarget);
    }
    Ok(AgentRunStorageIdentity {
        agent_run_device: agent_run_metadata.dev(),
        agent_run_inode: agent_run_metadata.ino(),
    })
}

fn refuse_unsafe_storage_path_before_open(
    agent_runs_dir: &Path,
    agent_run_id: &str,
    timeline: &Path,
) -> Result<(), RetentionError> {
    let agent_run_path = Path::new(agent_run_id);
    let mut components = agent_run_path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(RetentionError::UnsafeTarget);
    }
    let agent_runs_metadata =
        std::fs::symlink_metadata(agent_runs_dir).map_err(|_| RetentionError::UnsafeTarget)?;
    if !agent_runs_metadata.file_type().is_dir() {
        return Err(RetentionError::UnsafeTarget);
    }
    let agent_run_dir = agent_runs_dir.join(agent_run_path);
    let agent_run_metadata = match std::fs::symlink_metadata(&agent_run_dir) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(_) => return Err(RetentionError::UnsafeTarget),
    };
    if let Some(metadata) = agent_run_metadata.as_ref() {
        if !metadata.file_type().is_dir()
            || metadata.dev() != agent_runs_metadata.dev()
            || metadata.uid() != agent_runs_metadata.uid()
        {
            return Err(RetentionError::UnsafeTarget);
        }
    }
    match std::fs::symlink_metadata(timeline) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.nlink() == 1
                && agent_run_metadata
                    .as_ref()
                    .is_some_and(|agent_run| metadata.dev() == agent_run.dev()) =>
        {
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        _ => Err(RetentionError::UnsafeTarget),
    }
}

fn append_incomplete_collector_lifecycles(
    store: &mut HashChainStore,
    agent_run_id: &str,
    records: &[apolysis_store::ChainRecord],
) -> Result<(), String> {
    let mut instances = BTreeMap::new();
    let mut order = Vec::new();
    let mut recovered_gaps = BTreeSet::new();
    for record in records {
        let record_type = record.payload.get("record_type").and_then(Value::as_str);
        if record_type == Some("observation_gap")
            && record.payload.get("operation").and_then(Value::as_str)
                == Some("collector_lifecycle")
            && record.payload.get("kind").and_then(Value::as_str) == Some("collector_restart")
        {
            if let Some(instance_id) = record
                .payload
                .get("detail")
                .and_then(Value::as_str)
                .and_then(recovered_instance_id)
            {
                recovered_gaps.insert(instance_id.to_string());
            }
        }
        if record_type != Some("collector_lifecycle") {
            continue;
        }
        let Some(instance_id) = record
            .payload
            .get("collector_instance_id")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(state) = record.payload.get("state").and_then(Value::as_str) else {
            continue;
        };
        match state {
            "started" | "checkpoint" => {
                if !instances.contains_key(instance_id) {
                    order.push(instance_id.to_string());
                }
                instances.insert(
                    instance_id.to_string(),
                    (false, lifecycle_counters(&record.payload)),
                );
            }
            "stopped" | "failed" => {
                instances.insert(
                    instance_id.to_string(),
                    (true, lifecycle_counters(&record.payload)),
                );
            }
            _ => {}
        }
    }

    let incomplete: Vec<(String, CollectorLifecycleCounters)> = order
        .into_iter()
        .filter_map(|instance_id| match instances.get(&instance_id) {
            Some((false, counters)) => Some((instance_id, *counters)),
            _ => None,
        })
        .collect();
    if incomplete.is_empty() {
        return Ok(());
    }

    for (instance_id, counters) in incomplete {
        if !recovered_gaps.contains(&instance_id) {
            let gap = ObservationGap::new(
                agent_run_id,
                "collector_lifecycle",
                ObservationGapKind::CollectorRestart,
                1,
                format!(
                    "collector_instance:{instance_id},previous lifecycle has no durable terminal record"
                ),
            );
            append_json_line(
                store,
                &gap.to_json_line(),
                "collector restart Observation Gap",
            )?;
        }
        let terminal = CollectorLifecycleRecord::failed(
            agent_run_id,
            instance_id,
            CollectorFailureReason::CollectorRestart,
            counters,
        );
        append_json_line(
            store,
            &terminal.to_json_line(),
            "recovered collector terminal record",
        )?;
    }
    store
        .flush()
        .map_err(|error| format!("failed to flush recovered collector lifecycle: {error}"))
}

fn recovered_instance_id(detail: &str) -> Option<&str> {
    detail
        .strip_prefix("collector_instance:")
        .and_then(|detail| detail.split_once(',').map(|(instance_id, _)| instance_id))
        .filter(|instance_id| !instance_id.is_empty())
}

fn lifecycle_counters(payload: &Value) -> CollectorLifecycleCounters {
    let counters = &payload["counters"];
    let counter = |name| counters.get(name).and_then(Value::as_u64).unwrap_or(0);
    CollectorLifecycleCounters {
        global_reserve_failures: counter("global_reserve_failures"),
        global_map_pressure: counter("global_map_pressure"),
        global_abi_mismatches: counter("global_abi_mismatches"),
        global_decode_failures: counter("global_decode_failures"),
        global_truncations: counter("global_truncations"),
        scope_missing_entries: counter("scope_missing_entries"),
        scope_missing_exits: counter("scope_missing_exits"),
        scope_pending: counter("scope_pending"),
    }
}

fn append_json_line(store: &mut HashChainStore, line: &str, subject: &str) -> Result<(), String> {
    store
        .append_json(1, line)
        .map(|_| ())
        .map_err(|error| format!("failed to append {subject}: {error}"))
}

fn registry_error(error: RegistryError) -> String {
    error.to_string()
}

fn append_integrity_finding(
    store: &mut HashChainStore,
    session_id: &str,
    valid_records: usize,
) -> Result<(), String> {
    let payload = json!({
        "record_type":"integrity_finding",
        "session_id":session_id,
        "reason":"hash_chain_tail_quarantined",
        "artifact":"agent_run_timeline",
        "valid_records":valid_records
    });
    let payload = serde_json::to_string(&payload)
        .map_err(|error| format!("failed to serialize integrity finding: {error}"))?;
    store
        .append_json(1, &payload)
        .map_err(|error| format!("failed to append integrity finding: {error}"))?;
    store
        .flush()
        .map_err(|error| format!("failed to flush integrity finding: {error}"))
}

fn finding_payload(
    finding: apolysis_accountability::AccountabilityFinding,
) -> Result<Value, String> {
    finding
        .to_record_value()
        .map_err(|error| format!("failed to serialize accountability finding: {error}"))
}

fn collector_agent_run_close_payload(
    record: &CollectorLifecycleRecord,
    agent_run_id: &str,
) -> Result<Value, String> {
    if record.agent_run_id() != agent_run_id {
        return Err("collector terminal and closed Agent Run identities differ".to_string());
    }
    let payload: Value = serde_json::from_str(&record.to_json_line())
        .map_err(|error| format!("failed to encode collector lifecycle: {error}"))?;
    if payload.get("state").and_then(Value::as_str) != Some("stopped")
        || payload.get("stop_reason").and_then(Value::as_str) != Some("agent_run_closed")
    {
        return Err("collector close boundary requires an agent_run_closed terminal".to_string());
    }
    Ok(payload)
}

fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Docker => "docker",
        AdapterKind::Containerd => "containerd",
        AdapterKind::K3sContainerd => "k3s_containerd",
        AdapterKind::Kubernetes => "kubernetes",
    }
}

#[derive(Default)]
struct CombinedAttributionPayloads {
    kubernetes_gaps: Vec<Value>,
    kubernetes_ends: Vec<Value>,
    runtime_gaps: Vec<Value>,
    runtime_ends: Vec<Value>,
    runtime_observations: Vec<Value>,
    kubernetes_observations: Vec<Value>,
    kubernetes_gap_kinds: BTreeSet<&'static str>,
}

fn combined_attribution_batches(
    runtime_effects: &[RuntimeBindingEffect],
    kubernetes_plans: &[(String, KubernetesAttributionPlan)],
    runtime_source_reason: Option<RuntimeSourceGapReason>,
    missing_intent_bindings: Option<&BTreeSet<(String, u64)>>,
) -> Result<Vec<(String, Vec<Value>)>, String> {
    let mut batches = BTreeMap::<String, CombinedAttributionPayloads>::new();
    let attached_runtime_bindings = runtime_effects
        .iter()
        .filter_map(|effect| match effect {
            RuntimeBindingEffect::Attach { binding } => Some(runtime_binding_wire(
                RuntimeBindingRecordType::Observed,
                binding,
            )),
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    for effect in runtime_effects {
        match effect {
            RuntimeBindingEffect::PersistGap { binding, .. } => {
                let gap = runtime_binding_gap_batches(
                    std::slice::from_ref(effect),
                    runtime_source_reason,
                )?
                .into_iter()
                .next()
                .ok_or_else(|| "runtime gap did not produce a durable payload".to_string())?;
                batches
                    .entry(binding.agent_run_id.clone())
                    .or_default()
                    .runtime_gaps
                    .extend(gap.payloads);
            }
            RuntimeBindingEffect::Suspend { binding }
            | RuntimeBindingEffect::Retire { binding }
            | RuntimeBindingEffect::RetireDormant { binding } => {
                let record_type = if matches!(effect, RuntimeBindingEffect::Suspend { .. }) {
                    RuntimeBindingRecordType::Suspended
                } else {
                    RuntimeBindingRecordType::Retired
                };
                batches
                    .entry(binding.agent_run_id.clone())
                    .or_default()
                    .runtime_ends
                    .push(runtime_binding_payload(record_type, binding)?);
            }
            RuntimeBindingEffect::Attach { binding } => {
                let observations = &mut batches
                    .entry(binding.agent_run_id.clone())
                    .or_default()
                    .runtime_observations;
                observations.push(runtime_binding_payload(
                    RuntimeBindingRecordType::Observed,
                    binding,
                )?);
                if missing_intent_bindings.is_some_and(|missing| {
                    missing.contains(&(binding.agent_run_id.clone(), binding.identity.cgroup.inode))
                }) {
                    observations.extend(runtime_binding_missing_intent_payloads(binding)?);
                }
            }
        }
    }

    for (agent_run_id, plan) in kubernetes_plans {
        let batch = batches.entry(agent_run_id.clone()).or_default();
        for effect in &plan.effects {
            match effect {
                KubernetesAttributionEffect::EnsureRuntimeObserved { .. } => {}
                KubernetesAttributionEffect::PersistGap {
                    cluster_id, kind, ..
                } => {
                    push_kubernetes_gap(batch, agent_run_id, cluster_id, *kind)?;
                }
                KubernetesAttributionEffect::SuspendAttribution { attribution }
                | KubernetesAttributionEffect::RetireAttribution { attribution }
                | KubernetesAttributionEffect::RetireDormantAttribution { attribution } => {
                    batch
                        .kubernetes_ends
                        .push(serde_json::to_value(attribution).map_err(|error| {
                            format!(
                                "failed to encode Kubernetes attribution lifecycle record: {error}"
                            )
                        })?);
                }
                KubernetesAttributionEffect::ObserveAttribution {
                    attribution,
                    late_attach_if_runtime_preexisting,
                } => {
                    if *late_attach_if_runtime_preexisting
                        && !attached_runtime_bindings
                            .iter()
                            .any(|binding| binding.has_same_identity(&attribution.runtime_binding))
                    {
                        push_kubernetes_gap(
                            batch,
                            agent_run_id,
                            &attribution.cluster_id,
                            KubernetesAttributionGapKind::LateAttach,
                        )?;
                    }
                    batch
                        .kubernetes_observations
                        .push(serde_json::to_value(attribution).map_err(|error| {
                            format!(
                                "failed to encode Kubernetes attribution lifecycle record: {error}"
                            )
                        })?);
                }
            }
        }
    }

    Ok(batches
        .into_iter()
        .filter_map(|(agent_run_id, batch)| {
            let payloads = if runtime_source_reason.is_some() {
                batch
                    .kubernetes_gaps
                    .into_iter()
                    .chain(batch.kubernetes_ends)
                    .chain(batch.runtime_gaps)
                    .chain(batch.runtime_ends)
                    .chain(batch.runtime_observations)
                    .chain(batch.kubernetes_observations)
                    .collect::<Vec<_>>()
            } else {
                batch
                    .kubernetes_gaps
                    .into_iter()
                    .chain(batch.runtime_gaps)
                    .chain(batch.kubernetes_ends)
                    .chain(batch.runtime_ends)
                    .chain(batch.runtime_observations)
                    .chain(batch.kubernetes_observations)
                    .collect::<Vec<_>>()
            };
            (!payloads.is_empty()).then_some((agent_run_id, payloads))
        })
        .collect())
}

fn push_kubernetes_gap(
    batch: &mut CombinedAttributionPayloads,
    agent_run_id: &str,
    cluster_id: &str,
    kind: KubernetesAttributionGapKind,
) -> Result<(), String> {
    if !batch.kubernetes_gap_kinds.insert(kind.as_str()) {
        return Ok(());
    }
    batch.kubernetes_gaps.push(json!({
        "record_type": "observation_gap",
        "schema_version": 1,
        "timestamp_unix_ms": current_unix_ms()?,
        "agent_run_id": agent_run_id,
        "operation": "kubernetes_metadata",
        "kind": "kubernetes_metadata_unavailable",
        "count": 1,
        "detail": format!("cluster={cluster_id},reason={}", kind.as_str()),
    }));
    Ok(())
}

fn runtime_binding_effect_agent_run_id(effect: &RuntimeBindingEffect) -> Option<&str> {
    match effect {
        RuntimeBindingEffect::PersistGap { binding, .. }
        | RuntimeBindingEffect::Suspend { binding }
        | RuntimeBindingEffect::Retire { binding }
        | RuntimeBindingEffect::RetireDormant { binding }
        | RuntimeBindingEffect::Attach { binding } => Some(&binding.agent_run_id),
    }
}

fn merge_kubernetes_summary(
    aggregate: &mut KubernetesAttributionSummary,
    summary: KubernetesAttributionSummary,
) {
    aggregate.gaps = aggregate.gaps.saturating_add(summary.gaps);
    aggregate.suspended = aggregate.suspended.saturating_add(summary.suspended);
    aggregate.retired = aggregate.retired.saturating_add(summary.retired);
    aggregate.observed = aggregate.observed.saturating_add(summary.observed);
    aggregate.unchanged = aggregate.unchanged.saturating_add(summary.unchanged);
    aggregate.active = aggregate.active.saturating_add(summary.active);
}

fn runtime_binding_reconcile_without_gaps(
    reconciliation: &RuntimeBindingReconcile,
) -> RuntimeBindingReconcile {
    let effects = reconciliation
        .effects
        .iter()
        .filter(|effect| !matches!(effect, RuntimeBindingEffect::PersistGap { .. }))
        .cloned()
        .collect::<Vec<_>>();
    let mut pending = runtime_binding_reconcile_for_effects(effects, reconciliation.summary.active);
    pending.summary.attached = reconciliation.summary.attached;
    pending
}

fn runtime_binding_gap_batches(
    effects: &[RuntimeBindingEffect],
    source_reason: Option<RuntimeSourceGapReason>,
) -> Result<Vec<RuntimeBindingGapBatch>, String> {
    let mut batches = BTreeMap::<String, (Vec<Value>, Vec<RuntimeBindingEffect>)>::new();
    for effect in effects {
        let RuntimeBindingEffect::PersistGap { binding, kind } = effect else {
            continue;
        };
        let reason = match kind {
            RuntimeBindingGapKind::IdentityTransition => "identity_transition",
            RuntimeBindingGapKind::DaemonRestart => "daemon_restart",
            RuntimeBindingGapKind::RuntimeSourceUnavailable => source_reason
                .unwrap_or(RuntimeSourceGapReason::SocketUnavailable)
                .as_str(),
        };
        let gap = ObservationGap::new(
            &binding.agent_run_id,
            "runtime_metadata",
            ObservationGapKind::RuntimeMetadataUnavailable,
            1,
            format!(
                "source={},reason={reason}",
                adapter_name(binding.identity.adapter)
            ),
        );
        let payload = serde_json::from_str(&gap.to_json_line()).map_err(|error| {
            format!("failed to encode runtime metadata Observation Gap: {error}")
        })?;
        let batch = batches.entry(binding.agent_run_id.clone()).or_default();
        batch.0.push(payload);
        batch.1.push(effect.clone());
    }
    Ok(batches
        .into_iter()
        .map(
            |(agent_run_id, (payloads, effects))| RuntimeBindingGapBatch {
                agent_run_id,
                payloads,
                effects,
            },
        )
        .collect())
}

fn runtime_binding_reconcile_for_effects(
    effects: Vec<RuntimeBindingEffect>,
    active: usize,
) -> RuntimeBindingReconcile {
    RuntimeBindingReconcile::from_effects(effects, active)
}

fn merge_runtime_binding_reconciliations(
    mut first: RuntimeBindingReconcile,
    second: RuntimeBindingReconcile,
) -> RuntimeBindingReconcile {
    first.effects.extend(second.effects);
    first.summary.gaps = first.summary.gaps.saturating_add(second.summary.gaps);
    first.summary.suspended = first
        .summary
        .suspended
        .saturating_add(second.summary.suspended);
    first.summary.retired = first.summary.retired.saturating_add(second.summary.retired);
    first.summary.attached = first
        .summary
        .attached
        .saturating_add(second.summary.attached);
    first.summary.unchanged = first
        .summary
        .unchanged
        .saturating_add(second.summary.unchanged);
    first.summary.missing_intent = first
        .summary
        .missing_intent
        .saturating_add(second.summary.missing_intent);
    first.summary.active = second.summary.active;
    first
}

fn runtime_binding_payload(
    record_type: RuntimeBindingRecordType,
    binding: &RuntimeBinding,
) -> Result<Value, String> {
    let wire = runtime_binding_wire(record_type, binding)?;
    serde_json::to_value(wire)
        .map_err(|error| format!("failed to encode runtime binding lifecycle record: {error}"))
}

fn runtime_binding_wire(
    record_type: RuntimeBindingRecordType,
    binding: &RuntimeBinding,
) -> Result<RuntimeBindingWireV1, String> {
    let wire = RuntimeBindingWireV1 {
        record_type,
        schema_version: RUNTIME_BINDING_SCHEMA_VERSION,
        agent_run_id: binding.agent_run_id.clone(),
        adapter: adapter_name(binding.identity.adapter).to_string(),
        workload_id: binding.identity.workload_id.clone(),
        start_marker: binding.identity.start_marker.clone(),
        host_boot_id: binding.identity.host_boot_id.clone(),
        init_process_start_time_ticks: binding.identity.init_process_start_time_ticks,
        cgroup_device: binding.identity.cgroup.device,
        cgroup_id: binding.identity.cgroup.inode,
        runtime_handler: RuntimeBindingRuntimeHandler(binding.runtime_handler.clone()),
    };
    wire.validate().map_err(|error| error.to_string())?;
    Ok(wire)
}

fn authorized_runtime_binding_key(binding: &RuntimeBinding) -> AuthorizedRuntimeBindingKey {
    AuthorizedRuntimeBindingKey {
        agent_run_id: binding.agent_run_id.clone(),
        adapter: adapter_name(binding.identity.adapter).to_string(),
        workload_id: binding.identity.workload_id.clone(),
        start_marker: binding.identity.start_marker.clone(),
        host_boot_id: binding.identity.host_boot_id.clone(),
        init_process_start_time_ticks: binding.identity.init_process_start_time_ticks,
        cgroup_device: binding.identity.cgroup.device,
        cgroup_id: binding.identity.cgroup.inode,
        runtime_handler: binding.runtime_handler.clone(),
    }
}

fn authorized_runtime_binding_key_from_wire(
    binding: &RuntimeBindingWireV1,
) -> AuthorizedRuntimeBindingKey {
    AuthorizedRuntimeBindingKey {
        agent_run_id: binding.agent_run_id.clone(),
        adapter: binding.adapter.clone(),
        workload_id: binding.workload_id.clone(),
        start_marker: binding.start_marker.clone(),
        host_boot_id: binding.host_boot_id.clone(),
        init_process_start_time_ticks: binding.init_process_start_time_ticks,
        cgroup_device: binding.cgroup_device,
        cgroup_id: binding.cgroup_id,
        runtime_handler: binding.runtime_handler.0.clone(),
    }
}

fn runtime_binding_missing_intent_payloads(binding: &RuntimeBinding) -> Result<Vec<Value>, String> {
    let effect = ObservedEffect {
        session_id: binding.agent_run_id.clone(),
        evidence_ref: format!("runtime_binding:{}", binding.identity.workload_id),
        kind: EffectKind::Exec,
        actor: binding.identity.workload_id.clone(),
        resource: binding.identity.workload_id.clone(),
        runtime: RuntimeIdentity {
            runtime: adapter_name(binding.identity.adapter).to_string(),
            container_id: Some(binding.identity.workload_id.clone()),
            pod_uid: None,
            cgroup_id: Some(binding.identity.cgroup.inode),
        },
        evidence_boundary: EvidenceBoundary::HostBoundary,
    };
    AccountabilityAnalyzer::evaluate(None, &effect)
        .into_iter()
        .map(finding_payload)
        .collect()
}

async fn restore_closed_scope(
    scope: &ScopeController,
    agent_run_id: &str,
    intent: &SessionIntent,
    cgroup_id: u64,
    runtime_binding: Option<&RuntimeBinding>,
) -> Result<(), String> {
    if let Some(binding) = runtime_binding {
        scope
            .track_runtime_agent_run(
                agent_run_id,
                Some(intent),
                cgroup_id,
                &binding.identity.workload_id,
            )
            .await
    } else {
        scope
            .track_agent_run(agent_run_id, Some(intent), cgroup_id)
            .await
    }
}

async fn rollback_runtime_scope_contexts(
    scope: &ScopeController,
    previous_intent: Option<&SessionIntent>,
    bindings: &[RuntimeBinding],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for binding in bindings.iter().rev() {
        if let Err(error) = scope
            .refresh_runtime_agent_run(
                &binding.agent_run_id,
                previous_intent,
                binding.identity.cgroup.inode,
                &binding.identity.workload_id,
            )
            .await
        {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(())
}

async fn rollback_register_scope_changes(
    scope: &ScopeController,
    registry: &SessionRegistry,
    candidate: &SessionRegistry,
    runtime_effects: &[RuntimeBindingEffect],
    previous_intent: Option<&SessionIntent>,
    refreshed: &[RuntimeBinding],
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) =
        rollback_runtime_scope_effects(scope, registry, candidate, runtime_effects).await
    {
        errors.push(error);
    }
    if let Err(error) = rollback_runtime_scope_contexts(scope, previous_intent, refreshed).await {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn rollback_runtime_scope_effects(
    scope: &ScopeController,
    registry: &SessionRegistry,
    candidate: &SessionRegistry,
    effects: &[RuntimeBindingEffect],
) -> Result<(), String> {
    let mut errors = Vec::new();
    for effect in effects.iter().rev() {
        let result = match effect {
            RuntimeBindingEffect::Attach { binding } => {
                let intent = candidate
                    .get(&binding.agent_run_id)
                    .map(|state| state.intent.clone());
                scope
                    .untrack_runtime_agent_run(
                        &binding.agent_run_id,
                        intent.as_ref(),
                        binding.identity.cgroup.inode,
                        &binding.identity.workload_id,
                    )
                    .await
            }
            RuntimeBindingEffect::Suspend { binding }
            | RuntimeBindingEffect::Retire { binding } => {
                let intent = registry
                    .get(&binding.agent_run_id)
                    .map(|state| state.intent.clone());
                scope
                    .track_runtime_agent_run(
                        &binding.agent_run_id,
                        intent.as_ref(),
                        binding.identity.cgroup.inode,
                        &binding.identity.workload_id,
                    )
                    .await
            }
            RuntimeBindingEffect::RetireDormant { .. }
            | RuntimeBindingEffect::PersistGap { .. } => Ok(()),
        };
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn container_identity(workload: &RuntimeWorkload) -> Option<String> {
    match workload.adapter {
        AdapterKind::Docker | AdapterKind::Containerd | AdapterKind::K3sContainerd => {
            Some(workload.workload_id.clone())
        }
        AdapterKind::Kubernetes => None,
    }
}

struct RecoveredAgentRun {
    registration: Option<RecoveredAgentRunRegistration>,
    runtime_bindings: Vec<RuntimeBinding>,
    kubernetes_attributions: Vec<KubernetesAttributionWireV1>,
}

struct RecoveredAgentRunRegistration {
    intent: SessionIntent,
    cgroup_ids: Vec<u64>,
    status: RecoveredAgentRunStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveredAgentRunStatus {
    Active,
    Closed,
}

fn replay_persisted_agent_run(
    records: &[apolysis_store::ChainRecord],
    expected_agent_run_id: &str,
    now_unix_ms: u64,
) -> Result<RecoveredAgentRun, String> {
    let mut intent: Option<SessionIntent> = None;
    let mut cgroup_ids = Vec::new();
    let mut runtime_managed_cgroups = BTreeSet::new();
    let mut runtime_bindings = BTreeMap::new();
    let mut kubernetes_attributions = BTreeMap::new();
    let mut closed = false;
    for record in records {
        match record.payload.get("record_type").and_then(Value::as_str) {
            Some("intent_registered") => {
                if closed {
                    cgroup_ids.clear();
                    runtime_bindings.clear();
                    kubernetes_attributions.clear();
                    runtime_managed_cgroups.clear();
                }
                let value = record
                    .payload
                    .get("intent")
                    .cloned()
                    .ok_or_else(|| "intent_registered record is missing intent".to_string())?;
                intent = Some(
                    serde_json::from_value(value)
                        .map_err(|error| format!("failed to replay registered intent: {error}"))?,
                );
                closed = false;
            }
            Some("intent_renewed") => {
                if let (Some(intent), Some(expiry)) = (
                    intent.as_mut(),
                    record
                        .payload
                        .get("expires_at_unix_ms")
                        .and_then(Value::as_u64),
                ) {
                    intent.expires_at_unix_ms = expiry;
                }
            }
            Some("cgroup_discovered") => {
                if let Some(cgroup_id) = record.payload.get("cgroup_id").and_then(Value::as_u64) {
                    if !cgroup_ids.contains(&cgroup_id) {
                        cgroup_ids.push(cgroup_id);
                    }
                }
            }
            Some("runtime_workload_discovered") => {
                if let Some(cgroup_id) = record.payload.get("cgroup_id").and_then(Value::as_u64) {
                    runtime_managed_cgroups.insert(cgroup_id);
                }
            }
            Some("runtime_binding_observed") => {
                let binding = runtime_binding_from_payload(&record.payload, expected_agent_run_id)?;
                runtime_managed_cgroups.insert(binding.identity.cgroup.inode);
                let key = runtime_binding_replay_key(&binding);
                if runtime_bindings.contains_key(&key) {
                    return Err(
                        "runtime binding observed while already active in durable lifecycle"
                            .to_string(),
                    );
                }
                runtime_bindings.insert(key, binding);
            }
            Some("runtime_binding_retired") | Some("runtime_binding_suspended") => {
                let binding = runtime_binding_from_payload(&record.payload, expected_agent_run_id)?;
                runtime_managed_cgroups.insert(binding.identity.cgroup.inode);
                let key = runtime_binding_replay_key(&binding);
                let Some(active) = runtime_bindings.get(&key) else {
                    return Err(
                        "runtime binding lifecycle ended while inactive in durable lifecycle"
                            .to_string(),
                    );
                };
                if active != &binding {
                    return Err(
                        "runtime binding retirement identity mismatch in durable lifecycle"
                            .to_string(),
                    );
                }
                runtime_bindings.remove(&key);
            }
            Some("kubernetes_attribution_observed") => {
                let attribution = kubernetes_attribution_from_payload(
                    &record.payload,
                    expected_agent_run_id,
                    KubernetesAttributionRecordType::Observed,
                )?;
                let key = kubernetes_attribution_replay_key(&attribution);
                if kubernetes_attributions.contains_key(&key) {
                    return Err(
                        "Kubernetes attribution observed while already active in durable lifecycle"
                            .to_string(),
                    );
                }
                kubernetes_attributions.insert(key, attribution);
            }
            Some("kubernetes_attribution_retired") | Some("kubernetes_attribution_suspended") => {
                let expected_record_type =
                    if record.payload.get("record_type").and_then(Value::as_str)
                        == Some("kubernetes_attribution_suspended")
                    {
                        KubernetesAttributionRecordType::Suspended
                    } else {
                        KubernetesAttributionRecordType::Retired
                    };
                let attribution = kubernetes_attribution_from_payload(
                    &record.payload,
                    expected_agent_run_id,
                    expected_record_type,
                )?;
                let key = kubernetes_attribution_replay_key(&attribution);
                let Some(active) = kubernetes_attributions.get(&key) else {
                    return Err(
                        "Kubernetes attribution lifecycle ended while inactive in durable lifecycle"
                            .to_string(),
                    );
                };
                if !active.has_same_identity(&attribution) {
                    return Err(
                        "Kubernetes attribution retirement identity mismatch in durable lifecycle"
                            .to_string(),
                    );
                }
                kubernetes_attributions.remove(&key);
            }
            Some("session_closed") => {
                closed = true;
                cgroup_ids.clear();
                runtime_bindings.clear();
                kubernetes_attributions.clear();
            }
            Some(record_type) if record_type.starts_with("runtime_binding_") => {
                return Err("unsupported runtime binding lifecycle record type".to_string());
            }
            Some(record_type) if record_type.starts_with("kubernetes_attribution_") => {
                return Err("unsupported Kubernetes attribution lifecycle record type".to_string());
            }
            _ => {}
        }
    }
    cgroup_ids.retain(|cgroup_id| !runtime_managed_cgroups.contains(cgroup_id));
    cgroup_ids.sort_unstable();
    let runtime_bindings = runtime_bindings.into_values().collect::<Vec<_>>();
    let kubernetes_attributions = kubernetes_attributions.into_values().collect::<Vec<_>>();
    let Some(intent) = intent else {
        return Ok(RecoveredAgentRun {
            registration: None,
            runtime_bindings,
            kubernetes_attributions,
        });
    };
    if !closed && intent.expires_at_unix_ms <= now_unix_ms {
        return Ok(RecoveredAgentRun {
            registration: None,
            runtime_bindings,
            kubernetes_attributions,
        });
    }
    let status = if closed {
        RecoveredAgentRunStatus::Closed
    } else {
        RecoveredAgentRunStatus::Active
    };
    Ok(RecoveredAgentRun {
        registration: Some(RecoveredAgentRunRegistration {
            intent,
            cgroup_ids,
            status,
        }),
        runtime_bindings,
        kubernetes_attributions,
    })
}

fn kubernetes_attribution_replay_key(
    attribution: &KubernetesAttributionWireV1,
) -> (
    String,
    String,
    apolysis_core::KubernetesContainerKind,
    String,
) {
    (
        attribution.cluster_id.clone(),
        attribution.pod_uid.clone(),
        attribution.container_kind,
        attribution.container_ref.clone(),
    )
}

fn kubernetes_attribution_from_payload(
    payload: &Value,
    expected_agent_run_id: &str,
    expected_record_type: KubernetesAttributionRecordType,
) -> Result<KubernetesAttributionWireV1, String> {
    let attribution: KubernetesAttributionWireV1 = serde_json::from_value(payload.clone())
        .map_err(|_| {
            "Kubernetes attribution lifecycle record does not match the exact schema".to_string()
        })?;
    attribution.validate().map_err(|error| error.to_string())?;
    if attribution.record_type != expected_record_type {
        return Err("Kubernetes attribution lifecycle record type mismatch".to_string());
    }
    if attribution.agent_run_id != expected_agent_run_id {
        return Err("Kubernetes attribution Agent Run identity mismatch".to_string());
    }
    Ok(attribution)
}

fn runtime_binding_replay_key(binding: &RuntimeBinding) -> (AdapterKind, String) {
    (
        binding.identity.adapter,
        binding.identity.workload_id.clone(),
    )
}

fn runtime_binding_from_payload(
    payload: &Value,
    expected_agent_run_id: &str,
) -> Result<RuntimeBinding, String> {
    let record: RuntimeBindingWireV1 = serde_json::from_value(payload.clone()).map_err(|_| {
        "runtime binding lifecycle record does not match the exact schema".to_string()
    })?;
    if record.schema_version != RUNTIME_BINDING_SCHEMA_VERSION {
        return Err("runtime binding schema_version must be 1".to_string());
    }
    record.validate().map_err(|error| error.to_string())?;
    let adapter = match record.adapter.as_str() {
        "docker" => AdapterKind::Docker,
        "containerd" => AdapterKind::Containerd,
        "k3s_containerd" => AdapterKind::K3sContainerd,
        _ => return Err("runtime binding adapter is unsupported".to_string()),
    };
    let binding = RuntimeBinding {
        agent_run_id: record.agent_run_id,
        identity: RuntimeWorkloadIdentity {
            adapter,
            workload_id: record.workload_id,
            start_marker: record.start_marker,
            host_boot_id: record.host_boot_id,
            init_process_start_time_ticks: record.init_process_start_time_ticks,
            cgroup: crate::CgroupIdentity {
                device: record.cgroup_device,
                inode: record.cgroup_id,
            },
        },
        runtime_handler: record.runtime_handler.0,
    };
    if binding.agent_run_id != expected_agent_run_id {
        return Err("runtime binding Agent Run identity mismatch".to_string());
    }
    binding.validate().map_err(|error| error.to_string())?;
    Ok(binding)
}

fn current_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "current Unix timestamp exceeds u64".to_string())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use apolysis_accountability::{ActionClass, QueuePriority, DEFAULT_TENANT_ID};
    use serde_json::json;

    use super::*;
    use crate::{scope_channel, DaemonRecord, ScopeOperation};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn queued_write_failure_releases_the_writer_before_scope_cleanup() {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-writer-scope-failure-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let (scope, mut requests) = scope_channel(1);
        let scope_filler = scope.clone();
        let state = Arc::new(
            DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
        );
        let agent_run_id = "agent-run-writer-scope-failure";
        {
            let mut registry = state.registry.write().await;
            registry
                .register(test_intent(agent_run_id), 1_700_000_000_000)
                .expect("register test Agent Run");
            registry
                .discover_cgroup(agent_run_id, 71)
                .expect("associate test cgroup");
        }
        std::fs::create_dir_all(
            config
                .state_dir
                .join("sessions")
                .join(agent_run_id)
                .join("timeline.jsonl"),
        )
        .expect("block timeline path with a directory");

        let filler = tokio::spawn(async move { scope_filler.track(99).await });
        tokio::task::yield_now().await;

        let pipeline = state.pipeline();
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let writer = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.run_writer(shutdown_receiver).await })
        };
        let registry_guard = state.registry.write().await;
        pipeline
            .submit(DaemonRecord::new(
                agent_run_id,
                QueuePriority::Ordinary,
                json!({"record_type":"forced_write_failure"}),
            ))
            .expect("admit failing record");

        tokio::time::timeout(std::time::Duration::from_secs(1), pipeline.fence())
            .await
            .expect("writer fence completes while the registry is locked")
            .expect("writer fence");
        drop(registry_guard);
        let filler_request =
            tokio::time::timeout(std::time::Duration::from_secs(1), requests.recv())
                .await
                .expect("pre-existing scope request")
                .expect("scope request channel");
        assert_eq!(filler_request.operation(), ScopeOperation::Track);
        filler_request.complete(Ok(()));
        filler.await.unwrap().expect("complete queue filler");
        let request = tokio::time::timeout(std::time::Duration::from_secs(1), requests.recv())
            .await
            .expect("scope cleanup signal waits for channel capacity")
            .expect("scope cleanup request");
        assert_eq!(request.operation(), ScopeOperation::Untrack);
        assert_eq!(
            request.failure_reason(),
            Some(CollectorFailureReason::StorageFailure)
        );
        request.complete(Err("test scope worker stopped".to_string()));
        shutdown.send(()).expect("request writer shutdown");
        assert_eq!(writer.await.unwrap().expect("writer drain").failed, 1);
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn runtime_gap_batches_resume_after_a_later_agent_run_write_failure() {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-runtime-gap-batch-retry-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let state = DaemonState::new(&config).expect("daemon state");
        let agent_run_a = "agent-run-gap-batch-a";
        let agent_run_b = "agent-run-gap-batch-b";
        state
            .register(test_intent(agent_run_a), 1_700_000_000_000)
            .await
            .expect("register first Agent Run");
        state
            .register(test_intent(agent_run_b), 1_700_000_000_000)
            .await
            .expect("register second Agent Run");
        state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![
                    test_runtime_binding(agent_run_a, "container-gap-a", 701),
                    test_runtime_binding(agent_run_b, "container-gap-b", 702),
                ],
            ))
            .await
            .expect("attach both runtime bindings");

        let timeline_b = config
            .state_dir
            .join("sessions")
            .join(agent_run_b)
            .join("timeline.jsonl");
        let displaced_b = timeline_b.with_extension("displaced");
        std::fs::rename(&timeline_b, &displaced_b).expect("displace second timeline");
        std::fs::write(&timeline_b, b"").expect("replace second timeline path");

        let first_error = state
            .runtime_source_unavailable(
                AdapterKind::Docker,
                RuntimeSourceGapReason::SocketUnavailable,
            )
            .await
            .expect_err("second Agent Run gap batch must fail");
        assert!(
            first_error.contains("timeline path changed"),
            "{first_error}"
        );
        let timeline_a = config
            .state_dir
            .join("sessions")
            .join(agent_run_a)
            .join("timeline.jsonl");
        assert_eq!(
            std::fs::read_to_string(&timeline_a)
                .expect("read first timeline")
                .matches("runtime_metadata_unavailable")
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(&displaced_b)
                .expect("read displaced second timeline")
                .matches("runtime_metadata_unavailable")
                .count(),
            0
        );

        std::fs::remove_file(&timeline_b).expect("remove replacement timeline");
        std::fs::rename(&displaced_b, &timeline_b).expect("restore second timeline identity");
        state.storage_writable.store(true, Ordering::Release);
        let resumed = state
            .runtime_source_unavailable(
                AdapterKind::Docker,
                RuntimeSourceGapReason::SocketUnavailable,
            )
            .await
            .expect("resume pending Agent Run gap and suspends");
        assert_eq!(resumed.summary.gaps, 1);
        assert_eq!(resumed.summary.suspended, 2);
        assert!(state
            .runtime_bindings_for_agent_run(agent_run_a)
            .await
            .is_empty());
        assert!(state
            .runtime_bindings_for_agent_run(agent_run_b)
            .await
            .is_empty());
        assert_eq!(
            std::fs::read_to_string(&timeline_a)
                .expect("reread first timeline")
                .matches("runtime_metadata_unavailable")
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(&timeline_b)
                .expect("read restored second timeline")
                .matches("runtime_metadata_unavailable")
                .count(),
            1
        );

        drop(state);
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn runtime_effect_batches_resume_without_rewriting_an_earlier_agent_run() {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-runtime-effect-batch-retry-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let state = DaemonState::new(&config).expect("daemon state");
        let agent_run_a = "agent-run-effect-batch-a";
        let agent_run_b = "agent-run-effect-batch-b";
        state
            .register(test_intent(agent_run_a), 1_700_000_000_000)
            .await
            .expect("register first Agent Run");
        state
            .register(test_intent(agent_run_b), 1_700_000_000_000)
            .await
            .expect("register second Agent Run");
        state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![
                    test_runtime_binding(agent_run_a, "container-effect-a", 711),
                    test_runtime_binding(agent_run_b, "container-effect-b", 712),
                ],
            ))
            .await
            .expect("attach both runtime bindings");

        let timeline_b = config
            .state_dir
            .join("sessions")
            .join(agent_run_b)
            .join("timeline.jsonl");
        let displaced_b = timeline_b.with_extension("displaced");
        std::fs::rename(&timeline_b, &displaced_b).expect("displace second timeline");
        std::fs::write(&timeline_b, b"").expect("replace second timeline path");

        let first_error = state
            .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, Vec::new()))
            .await
            .expect_err("second Agent Run lifecycle batch must fail");
        assert!(
            first_error.contains("timeline path changed"),
            "{first_error}"
        );
        let timeline_a = config
            .state_dir
            .join("sessions")
            .join(agent_run_a)
            .join("timeline.jsonl");
        assert_eq!(
            std::fs::read_to_string(&timeline_a)
                .expect("read first timeline")
                .matches("runtime_binding_retired")
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(&displaced_b)
                .expect("read displaced second timeline")
                .matches("runtime_binding_retired")
                .count(),
            0
        );

        std::fs::remove_file(&timeline_b).expect("remove replacement timeline");
        std::fs::rename(&displaced_b, &timeline_b).expect("restore second timeline identity");
        state.storage_writable.store(true, Ordering::Release);
        let resumed = state
            .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, Vec::new()))
            .await
            .expect("resume pending lifecycle batches");
        assert_eq!(resumed.summary.retired, 2);
        assert_eq!(
            std::fs::read_to_string(&timeline_a)
                .expect("reread first timeline")
                .matches("runtime_binding_retired")
                .count(),
            1,
            "the already durable first Agent Run batch must not be appended twice"
        );
        assert_eq!(
            std::fs::read_to_string(&timeline_b)
                .expect("read restored second timeline")
                .matches("runtime_binding_retired")
                .count(),
            1
        );

        drop(state);
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn kubernetes_cycle_resumes_after_a_later_agent_run_write_failure() {
        use apolysis_core::{
            KubernetesContainerKind, KubernetesWorkloadClaimV1,
            KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        };
        use apolysis_kubernetes::{
            KubernetesContainerCandidate, KubernetesPodCandidate, KubernetesSnapshotIdentity,
        };

        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-kubernetes-batch-retry-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let state = DaemonState::new(&config).expect("daemon state");
        let agent_run_a = "agent-run-kubernetes-batch-a";
        let agent_run_b = "agent-run-kubernetes-batch-b";
        let pod_uid_a = "11111111-1111-1111-1111-111111111111";
        let pod_uid_b = "22222222-2222-2222-2222-222222222222";
        let cluster_id = "33333333-3333-3333-3333-333333333333";
        let namespace_ref = "a".repeat(64);
        let node_ref = "b".repeat(64);
        let container_ref_a = "c".repeat(64);
        let container_ref_b = "d".repeat(64);
        let container_id_a = "e".repeat(64);
        let container_id_b = "f".repeat(64);
        for (agent_run_id, pod_uid, container_ref) in [
            (agent_run_a, pod_uid_a, container_ref_a.clone()),
            (agent_run_b, pod_uid_b, container_ref_b.clone()),
        ] {
            let mut intent = test_intent(agent_run_id);
            intent.kubernetes_claims = vec![KubernetesWorkloadClaimV1 {
                schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
                claim_revision: 1,
                cluster_id: cluster_id.to_string(),
                namespace_ref: namespace_ref.clone(),
                pod_uid: pod_uid.to_string(),
                container_kind: KubernetesContainerKind::Application,
                container_ref,
            }];
            state
                .register(intent, 1_700_000_000_000)
                .await
                .expect("register Kubernetes Agent Run");
        }
        let snapshot = |sequence| KubernetesPodSnapshot {
            sequence,
            identity: KubernetesSnapshotIdentity {
                source_epoch: "44444444-4444-4444-4444-444444444444".to_string(),
                cluster_id: cluster_id.to_string(),
                namespace_ref: namespace_ref.clone(),
                node_ref: node_ref.clone(),
            },
            pods: vec![
                KubernetesPodCandidate {
                    pod_uid: pod_uid_a.to_string(),
                    pod_revision_ref: "1".repeat(64),
                    marked_for_observation: true,
                    deleting: false,
                    runtime_class_ref: None,
                    containers: vec![KubernetesContainerCandidate {
                        kind: KubernetesContainerKind::Application,
                        container_ref: container_ref_a.clone(),
                        runtime_container_id: Some(container_id_a.clone()),
                        running: true,
                    }],
                },
                KubernetesPodCandidate {
                    pod_uid: pod_uid_b.to_string(),
                    pod_revision_ref: "2".repeat(64),
                    marked_for_observation: true,
                    deleting: false,
                    runtime_class_ref: None,
                    containers: vec![KubernetesContainerCandidate {
                        kind: KubernetesContainerKind::Application,
                        container_ref: container_ref_b.clone(),
                        runtime_container_id: Some(container_id_b.clone()),
                        running: true,
                    }],
                },
            ],
        };
        let runtime_inventory = || {
            RuntimeInventory::new(
                AdapterKind::Containerd,
                vec![
                    test_containerd_binding(agent_run_a, &container_id_a, 801),
                    test_containerd_binding(agent_run_b, &container_id_b, 802),
                ],
            )
        };

        let timeline_b = config
            .state_dir
            .join("sessions")
            .join(agent_run_b)
            .join("timeline.jsonl");
        let displaced_b = timeline_b.with_extension("displaced");
        std::fs::rename(&timeline_b, &displaced_b).expect("displace second timeline");
        std::fs::write(&timeline_b, b"").expect("replace second timeline path");

        let error = state
            .apply_kubernetes_qualification_cycle(snapshot(1), runtime_inventory(), snapshot(2))
            .await
            .expect_err("second Agent Run durable batch must fail");
        assert!(error.contains("timeline path changed"), "{error}");
        let (_, runtime, kubernetes) = state
            .query_with_workload_context_for_tenant(agent_run_a, DEFAULT_TENANT_ID)
            .await;
        assert!(runtime.is_empty());
        assert!(kubernetes.is_empty());

        std::fs::remove_file(&timeline_b).expect("remove replacement timeline");
        std::fs::rename(&displaced_b, &timeline_b).expect("restore second timeline identity");
        state.storage_writable.store(true, Ordering::Release);
        state
            .apply_kubernetes_qualification_cycle(snapshot(3), runtime_inventory(), snapshot(4))
            .await
            .expect("resume pending Kubernetes cycle");

        let timeline_a = config
            .state_dir
            .join("sessions")
            .join(agent_run_a)
            .join("timeline.jsonl");
        let timeline_a = std::fs::read_to_string(timeline_a).expect("first Agent Run timeline");
        assert_eq!(
            timeline_record_type_count(&timeline_a, "runtime_binding_observed"),
            1
        );
        assert_eq!(
            timeline_record_type_count(&timeline_a, "kubernetes_attribution_observed"),
            1
        );
        let (_, runtime, kubernetes) = state
            .query_with_workload_context_for_tenant(agent_run_b, DEFAULT_TENANT_ID)
            .await;
        assert_eq!(runtime.len(), 1);
        assert_eq!(kubernetes.len(), 1);

        drop(state);
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn close_persists_kubernetes_runtime_collector_and_session_terminals_in_one_order() {
        use apolysis_core::{
            CollectorLifecycleCounters, CollectorNormalStopReason, KubernetesContainerKind,
            KubernetesWorkloadClaimV1, KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        };
        use apolysis_kubernetes::{
            KubernetesContainerCandidate, KubernetesPodCandidate, KubernetesSnapshotIdentity,
        };

        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-kubernetes-close-order-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let (scope, mut requests) = scope_channel(8);
        let state = Arc::new(
            DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
        );
        let agent_run_id = "agent-run-kubernetes-close-order";
        let cluster_id = "11111111-1111-1111-1111-111111111111";
        let pod_uid = "22222222-2222-2222-2222-222222222222";
        let container_id = "e".repeat(64);
        let container_ref = "d".repeat(64);
        let namespace_ref = "a".repeat(64);
        let worker_agent_run_id = agent_run_id.to_string();
        let scope_worker = tokio::spawn(async move {
            while let Some(request) = requests.recv().await {
                match request.operation() {
                    ScopeOperation::CloseAgentRun => {
                        request.complete_agent_run_close(Ok(PreparedAgentRunClose::new(
                            worker_agent_run_id.clone(),
                            NonZeroU64::new(1).expect("nonzero close token"),
                            Some(CollectorLifecycleRecord::stopped(
                                worker_agent_run_id.clone(),
                                "collector-close-order",
                                CollectorNormalStopReason::AgentRunClosed,
                                CollectorLifecycleCounters::default(),
                            )),
                        )));
                    }
                    ScopeOperation::Track
                    | ScopeOperation::RefreshContext
                    | ScopeOperation::Untrack
                    | ScopeOperation::FinalizeAgentRunClose
                    | ScopeOperation::CancelAgentRunClose => request.complete(Ok(())),
                }
            }
        });
        let mut intent = test_intent(agent_run_id);
        intent.kubernetes_claims = vec![KubernetesWorkloadClaimV1 {
            schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
            claim_revision: 1,
            cluster_id: cluster_id.to_string(),
            namespace_ref: namespace_ref.clone(),
            pod_uid: pod_uid.to_string(),
            container_kind: KubernetesContainerKind::Application,
            container_ref: container_ref.clone(),
        }];
        state
            .register(intent, 1_700_000_000_000)
            .await
            .expect("register K1 claim");
        let snapshot = |sequence| KubernetesPodSnapshot {
            sequence,
            identity: KubernetesSnapshotIdentity {
                source_epoch: "33333333-3333-3333-3333-333333333333".to_string(),
                cluster_id: cluster_id.to_string(),
                namespace_ref: namespace_ref.clone(),
                node_ref: "b".repeat(64),
            },
            pods: vec![KubernetesPodCandidate {
                pod_uid: pod_uid.to_string(),
                pod_revision_ref: "c".repeat(64),
                marked_for_observation: true,
                deleting: false,
                runtime_class_ref: None,
                containers: vec![KubernetesContainerCandidate {
                    kind: KubernetesContainerKind::Application,
                    container_ref: container_ref.clone(),
                    runtime_container_id: Some(container_id.clone()),
                    running: true,
                }],
            }],
        };
        state
            .apply_kubernetes_qualification_cycle(
                snapshot(1),
                RuntimeInventory::new(
                    AdapterKind::Containerd,
                    vec![test_containerd_binding(agent_run_id, &container_id, 901)],
                ),
                snapshot(2),
            )
            .await
            .expect("qualify K1 link");

        state.close(agent_run_id).await.expect("close Agent Run");
        let timeline = std::fs::read_to_string(
            config
                .state_dir
                .join("sessions")
                .join(agent_run_id)
                .join("timeline.jsonl"),
        )
        .expect("Agent Run timeline");
        let kubernetes_retired = timeline
            .find("kubernetes_attribution_retired")
            .expect("K1 retirement");
        let runtime_retired = timeline
            .find("runtime_binding_retired")
            .expect("D1 retirement");
        let collector_stopped = timeline
            .find(r#""stop_reason":"agent_run_closed""#)
            .expect("collector terminal");
        let session_closed = timeline.find("session_closed").expect("session terminal");
        assert!(
            kubernetes_retired < runtime_retired
                && runtime_retired < collector_stopped
                && collector_stopped < session_closed
        );

        drop(state);
        scope_worker.abort();
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn failed_close_batch_cancels_scope_and_retry_writes_one_terminal_boundary() {
        use std::sync::Mutex as StdMutex;

        use apolysis_core::{CollectorLifecycleCounters, CollectorNormalStopReason};

        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-close-cancel-retry-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let (scope, mut requests) = scope_channel(8);
        let operations = Arc::new(StdMutex::new(Vec::new()));
        let worker_operations = Arc::clone(&operations);
        let state =
            DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope");
        let agent_run_id = "agent-run-close-cancel-retry";
        let worker_agent_run_id = agent_run_id.to_string();
        let scope_worker = tokio::spawn(async move {
            let mut token = 1_u64;
            while let Some(request) = requests.recv().await {
                let operation = request.operation();
                worker_operations.lock().unwrap().push(operation);
                if operation == ScopeOperation::CloseAgentRun {
                    request.complete_agent_run_close(Ok(PreparedAgentRunClose::new(
                        worker_agent_run_id.clone(),
                        NonZeroU64::new(token).expect("nonzero close token"),
                        Some(CollectorLifecycleRecord::stopped(
                            worker_agent_run_id.clone(),
                            "collector-cancel-retry",
                            CollectorNormalStopReason::AgentRunClosed,
                            CollectorLifecycleCounters::default(),
                        )),
                    )));
                    token = token.saturating_add(1);
                } else {
                    request.complete(Ok(()));
                }
            }
        });
        state
            .register(test_intent(agent_run_id), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
        state
            .discover_cgroup(agent_run_id, 921)
            .await
            .expect("track scope");
        let timeline_path = config
            .state_dir
            .join("sessions")
            .join(agent_run_id)
            .join("timeline.jsonl");
        let displaced = timeline_path.with_extension("displaced");
        std::fs::rename(&timeline_path, &displaced).expect("displace timeline");
        std::fs::write(&timeline_path, b"").expect("replace timeline path");

        state
            .close(agent_run_id)
            .await
            .expect_err("terminal batch must fail");
        assert_eq!(
            state
                .query(agent_run_id)
                .await
                .expect("old state remains")
                .cgroup_ids,
            vec![921]
        );
        assert_eq!(
            *operations.lock().unwrap(),
            vec![
                ScopeOperation::Track,
                ScopeOperation::Untrack,
                ScopeOperation::CloseAgentRun,
                ScopeOperation::CancelAgentRunClose,
                ScopeOperation::Track,
            ]
        );

        std::fs::remove_file(&timeline_path).expect("remove replacement timeline");
        std::fs::rename(&displaced, &timeline_path).expect("restore timeline identity");
        state.storage_writable.store(true, Ordering::Release);
        state.close(agent_run_id).await.expect("retry close");
        let timeline = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
        assert_eq!(timeline.matches("agent_run_closed").count(), 1);
        assert_eq!(timeline.matches("session_closed").count(), 1);

        drop(state);
        scope_worker.abort();
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn invalid_close_terminal_reports_every_scope_rollback_failure() {
        use apolysis_core::{CollectorLifecycleCounters, CollectorNormalStopReason};

        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-close-invalid-terminal-rollback-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let (scope, mut requests) = scope_channel(8);
        let state =
            DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope");
        let agent_run_id = "agent-run-close-invalid-terminal";
        let scope_worker = tokio::spawn(async move {
            let mut track_count = 0_u8;
            while let Some(request) = requests.recv().await {
                match request.operation() {
                    ScopeOperation::Track => {
                        track_count = track_count.saturating_add(1);
                        if track_count == 1 {
                            request.complete(Ok(()));
                        } else {
                            request.complete(Err("forced scope restore failure".to_string()));
                        }
                    }
                    ScopeOperation::CloseAgentRun => {
                        request.complete_agent_run_close(Ok(PreparedAgentRunClose::new(
                            "different-agent-run",
                            NonZeroU64::new(1).expect("nonzero close token"),
                            Some(CollectorLifecycleRecord::stopped(
                                "different-agent-run",
                                "collector-invalid-terminal",
                                CollectorNormalStopReason::AgentRunClosed,
                                CollectorLifecycleCounters::default(),
                            )),
                        )));
                    }
                    ScopeOperation::CancelAgentRunClose => {
                        request.complete(Err("forced close cancel failure".to_string()));
                    }
                    ScopeOperation::RefreshContext
                    | ScopeOperation::Untrack
                    | ScopeOperation::FinalizeAgentRunClose => request.complete(Ok(())),
                }
            }
        });
        state
            .register(test_intent(agent_run_id), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
        state
            .discover_cgroup(agent_run_id, 923)
            .await
            .expect("track scope");

        let error = state
            .close(agent_run_id)
            .await
            .expect_err("invalid collector terminal must fail close");
        assert!(
            error.contains("collector terminal and closed Agent Run identities differ"),
            "{error}"
        );
        assert!(
            error.contains("close cancel failed: forced close cancel failure"),
            "{error}"
        );
        assert!(
            error.contains("scope restore failed: forced scope restore failure"),
            "{error}"
        );
        assert_eq!(
            state
                .query(agent_run_id)
                .await
                .expect("registry remains uncommitted")
                .cgroup_ids,
            vec![923]
        );

        drop(state);
        scope_worker.abort();
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    #[tokio::test]
    async fn finalize_failure_keeps_a_durable_close_pending_without_rewriting_its_batch() {
        use std::sync::Mutex as StdMutex;

        use apolysis_core::{CollectorLifecycleCounters, CollectorNormalStopReason};

        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let config = DaemonConfig {
            state_dir: std::env::temp_dir().join(format!(
                "apolysis-close-finalize-retry-{}-{id}",
                std::process::id()
            )),
            ..DaemonConfig::default()
        };
        let (scope, mut requests) = scope_channel(8);
        let operations = Arc::new(StdMutex::new(Vec::new()));
        let worker_operations = Arc::clone(&operations);
        let state =
            DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope");
        let agent_run_id = "agent-run-close-finalize-retry";
        let worker_agent_run_id = agent_run_id.to_string();
        let scope_worker = tokio::spawn(async move {
            let mut reject_finalize = true;
            while let Some(request) = requests.recv().await {
                let operation = request.operation();
                worker_operations.lock().unwrap().push(operation);
                match operation {
                    ScopeOperation::CloseAgentRun => {
                        request.complete_agent_run_close(Ok(PreparedAgentRunClose::new(
                            worker_agent_run_id.clone(),
                            NonZeroU64::new(1).expect("nonzero close token"),
                            Some(CollectorLifecycleRecord::stopped(
                                worker_agent_run_id.clone(),
                                "collector-finalize-retry",
                                CollectorNormalStopReason::AgentRunClosed,
                                CollectorLifecycleCounters::default(),
                            )),
                        )));
                    }
                    ScopeOperation::FinalizeAgentRunClose if reject_finalize => {
                        reject_finalize = false;
                        request.complete(Err("forced finalize failure".to_string()));
                    }
                    ScopeOperation::Track
                    | ScopeOperation::RefreshContext
                    | ScopeOperation::Untrack
                    | ScopeOperation::FinalizeAgentRunClose
                    | ScopeOperation::CancelAgentRunClose => request.complete(Ok(())),
                }
            }
        });
        state
            .register(test_intent(agent_run_id), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
        state
            .discover_cgroup(agent_run_id, 922)
            .await
            .expect("track scope");
        let timeline_path = config
            .state_dir
            .join("sessions")
            .join(agent_run_id)
            .join("timeline.jsonl");

        let error = state
            .close(agent_run_id)
            .await
            .expect_err("first finalization must fail closed");
        assert!(error.contains("finalization is pending"), "{error}");
        assert_eq!(
            state
                .query(agent_run_id)
                .await
                .expect("uncommitted state remains")
                .cgroup_ids,
            vec![922]
        );
        let first = std::fs::read_to_string(&timeline_path).expect("durable pending close");
        assert_eq!(first.matches("session_closed").count(), 1);

        state
            .close(agent_run_id)
            .await
            .expect("retry only finalizes the durable close");
        let retried = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
        assert_eq!(retried.matches("agent_run_closed").count(), 1);
        assert_eq!(retried.matches("session_closed").count(), 1);
        assert_eq!(
            *operations.lock().unwrap(),
            vec![
                ScopeOperation::Track,
                ScopeOperation::Untrack,
                ScopeOperation::CloseAgentRun,
                ScopeOperation::FinalizeAgentRunClose,
                ScopeOperation::FinalizeAgentRunClose,
            ]
        );

        drop(state);
        scope_worker.abort();
        std::fs::remove_dir_all(&config.state_dir).expect("clean test state");
    }

    fn test_intent(agent_run_id: &str) -> SessionIntent {
        SessionIntent {
            schema_version: 1,
            tenant_id: DEFAULT_TENANT_ID.to_string(),
            retention_tier: RetentionTier::Standard,
            session_id: agent_run_id.to_string(),
            expires_at_unix_ms: 4_102_444_800_000,
            declared_actions: vec![ActionClass::Test],
            allowed_resources: Vec::new(),
            workload_selectors: Vec::new(),
            kubernetes_claims: Vec::new(),
        }
    }

    fn test_runtime_binding(
        agent_run_id: &str,
        workload_id: &str,
        cgroup_inode: u64,
    ) -> RuntimeBinding {
        let token = workload_id.bytes().fold(1_u64, |token, byte| {
            token.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
        });
        let token = if token == 0 { 1 } else { token };
        RuntimeBinding {
            agent_run_id: agent_run_id.to_string(),
            identity: RuntimeWorkloadIdentity {
                adapter: AdapterKind::Docker,
                workload_id: format!("{token:016x}").repeat(4),
                start_marker: format!("2026-08-11T01:02:03.{:09}Z", token % 1_000_000_000),
                host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
                init_process_start_time_ticks: cgroup_inode,
                cgroup: crate::CgroupIdentity {
                    device: 7,
                    inode: cgroup_inode,
                },
            },
            runtime_handler: Some("runc".to_string()),
        }
    }

    fn test_containerd_binding(
        agent_run_id: &str,
        container_id: &str,
        cgroup_inode: u64,
    ) -> RuntimeBinding {
        RuntimeBinding {
            agent_run_id: agent_run_id.to_string(),
            identity: RuntimeWorkloadIdentity {
                adapter: AdapterKind::Containerd,
                workload_id: format!("containerd/{container_id}"),
                start_marker: "42".to_string(),
                host_boot_id: "55555555-5555-5555-5555-555555555555".to_string(),
                init_process_start_time_ticks: cgroup_inode,
                cgroup: crate::CgroupIdentity {
                    device: 7,
                    inode: cgroup_inode,
                },
            },
            runtime_handler: Some("runc".to_string()),
        }
    }

    fn timeline_record_type_count(timeline: &str, record_type: &str) -> usize {
        timeline
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|record| {
                record
                    .get("payload")
                    .and_then(|payload| payload.get("record_type"))
                    .and_then(Value::as_str)
                    == Some(record_type)
            })
            .count()
    }
}

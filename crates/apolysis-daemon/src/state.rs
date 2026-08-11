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
    CollectorLifecycleRecord, ObservationGap, ObservationGapKind, RuntimeBindingRecordType,
    RuntimeBindingRuntimeHandler, RuntimeBindingWireV1, RUNTIME_BINDING_SCHEMA_VERSION,
};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::{
    retention::{
        recover_retention_transactions, stage_agent_run_retention_targets,
        validate_agent_run_retention_target, RetentionError,
    },
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
    pending: Option<PendingRuntimeBindingApplication>,
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
            if let Some(registration) = recovered.registration {
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
        Ok(Self {
            registry: RwLock::new(registry),
            runtime_bindings: Mutex::new(ManagedRuntimeBindings {
                committed: runtime_bindings,
                pending: None,
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
        let runtime_bindings = self.runtime_bindings.lock().await;
        let mut registry = self.registry.write().await;
        let previous_intent = registry
            .get(&intent.session_id)
            .map(|state| state.intent.clone());
        let refresh_bindings = if registry.is_scope_admitted(&intent.session_id) {
            Vec::new()
        } else {
            runtime_bindings
                .committed
                .bindings_for_agent_run(&intent.session_id)
        };
        let mut candidate = registry.clone();
        let outcome = candidate
            .register(intent.clone(), now_unix_ms)
            .map_err(registry_error)?;
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
        if let Err(error) = self
            .persist(
                &intent.session_id,
                json!({"record_type":"intent_registered","intent":intent}),
            )
            .await
        {
            if let Some(scope) = &self.scope {
                rollback_runtime_scope_contexts(scope, previous_intent.as_ref(), &refreshed)
                    .await
                    .map_err(|rollback| {
                        format!("{error}; scope context rollback failed: {rollback}")
                    })?;
            }
            return Err(error);
        }
        *registry = candidate;
        Ok(outcome)
    }

    pub async fn renew(
        &self,
        session_id: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), String> {
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
        Ok(())
    }

    pub async fn close(&self, session_id: &str) -> Result<(), String> {
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        self.resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        let runtime_scope_context: BTreeMap<_, _> = runtime_bindings
            .committed
            .bindings_for_agent_run(session_id)
            .into_iter()
            .map(|binding| (binding.identity.cgroup.inode, binding))
            .collect();
        let mut runtime_candidate = runtime_bindings.committed.clone();
        runtime_candidate.retire_agent_run(session_id);
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
        let close_persisted = if let Some(scope) = &self.scope {
            match scope.close_agent_run(session_id).await {
                Ok(persisted) => persisted,
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
            false
        };
        if !close_persisted {
            if let Err(error) = self
                .persist(
                    session_id,
                    json!({"record_type":"session_closed","session_id":session_id}),
                )
                .await
            {
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
                            return Err(format!("{error}; scope rollback failed: {rollback}"));
                        }
                    }
                }
                return Err(error);
            }
        }
        *registry = candidate;
        runtime_bindings.committed = runtime_candidate;
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
        // Keep the established runtime-bindings -> registry lock order used by
        // register/close so the authorization decision and returned binding
        // set form one consistent snapshot.
        let runtime_bindings = self.runtime_bindings.lock().await;
        let registry = self.registry.read().await;
        let session = registry.get_for_tenant(session_id, tenant_id).cloned();
        let bindings = if session.is_some() {
            runtime_bindings
                .committed
                .bindings_for_agent_run(session_id)
        } else {
            Vec::new()
        };
        (session, bindings)
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

    pub async fn reconcile_runtime_inventory(
        &self,
        inventory: RuntimeInventory,
    ) -> Result<RuntimeBindingReconcile, String> {
        let adapter = inventory.adapter;
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        let resumed = self
            .resume_pending_runtime_binding_application(&mut runtime_bindings)
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

    pub async fn runtime_source_unavailable(
        &self,
        adapter: AdapterKind,
        reason: RuntimeSourceGapReason,
    ) -> Result<RuntimeBindingReconcile, String> {
        let mut runtime_bindings = self.runtime_bindings.lock().await;
        let resumed = self
            .resume_pending_runtime_binding_application(&mut runtime_bindings)
            .await?;
        let mut candidate = runtime_bindings.committed.clone();
        let reconciliation = candidate
            .source_unavailable(adapter)
            .map_err(|error| error.to_string())?;
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
        self.runtime_bindings
            .lock()
            .await
            .committed
            .bindings_for_agent_run(agent_run_id)
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
        if runtime_bindings.pending.is_none() {
            return Ok(RuntimeBindingReconcile::default());
        }
        self.finish_pending_runtime_binding_application(runtime_bindings)
            .await
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

    pub(crate) async fn persist_collector_agent_run_close_boundary(
        &self,
        agent_run_id: &str,
        stopped: Option<CollectorLifecycleRecord>,
    ) -> Result<(), String> {
        let mut payloads = Vec::with_capacity(if stopped.is_some() { 2 } else { 1 });
        if let Some(stopped) = stopped {
            if stopped.agent_run_id() != agent_run_id {
                return Err("collector terminal and closed Agent Run identities differ".to_string());
            }
            let stopped_payload: Value = serde_json::from_str(&stopped.to_json_line())
                .map_err(|error| format!("failed to encode collector lifecycle: {error}"))?;
            if stopped_payload.get("state").and_then(Value::as_str) != Some("stopped")
                || stopped_payload.get("stop_reason").and_then(Value::as_str)
                    != Some("agent_run_closed")
            {
                return Err(
                    "collector close boundary requires an agent_run_closed terminal".to_string(),
                );
            }
            payloads.push(stopped_payload);
        }
        payloads.push(json!({"record_type":"session_closed","session_id":agent_run_id}));
        self.persist_batch(agent_run_id, payloads).await
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

fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Docker => "docker",
        AdapterKind::Containerd => "containerd",
        AdapterKind::K3sContainerd => "k3s_containerd",
        AdapterKind::Kubernetes => "kubernetes",
    }
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
    serde_json::to_value(wire)
        .map_err(|error| format!("failed to encode runtime binding lifecycle record: {error}"))
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
    for binding in bindings.iter().rev() {
        scope
            .refresh_runtime_agent_run(
                &binding.agent_run_id,
                previous_intent,
                binding.identity.cgroup.inode,
                &binding.identity.workload_id,
            )
            .await?;
    }
    Ok(())
}

async fn rollback_runtime_scope_effects(
    scope: &ScopeController,
    registry: &SessionRegistry,
    candidate: &SessionRegistry,
    effects: &[RuntimeBindingEffect],
) -> Result<(), String> {
    for effect in effects.iter().rev() {
        match effect {
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
                    .await?;
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
                    .await?;
            }
            RuntimeBindingEffect::RetireDormant { .. } => {}
            RuntimeBindingEffect::PersistGap { .. } => {}
        }
    }
    Ok(())
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
    let mut closed = false;
    for record in records {
        match record.payload.get("record_type").and_then(Value::as_str) {
            Some("intent_registered") => {
                if closed {
                    cgroup_ids.clear();
                    runtime_bindings.clear();
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
            Some("session_closed") => {
                closed = true;
                cgroup_ids.clear();
                runtime_bindings.clear();
            }
            Some(record_type) if record_type.starts_with("runtime_binding_") => {
                return Err("unsupported runtime binding lifecycle record type".to_string());
            }
            _ => {}
        }
    }
    cgroup_ids.retain(|cgroup_id| !runtime_managed_cgroups.contains(cgroup_id));
    cgroup_ids.sort_unstable();
    let runtime_bindings = runtime_bindings.into_values().collect::<Vec<_>>();
    let Some(intent) = intent else {
        return Ok(RecoveredAgentRun {
            registration: None,
            runtime_bindings,
        });
    };
    if !closed && intent.expires_at_unix_ms <= now_unix_ms {
        return Ok(RecoveredAgentRun {
            registration: None,
            runtime_bindings,
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
    })
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
}

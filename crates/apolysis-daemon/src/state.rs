// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
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
    CollectorFailureReason, CollectorLifecycleCounters, CollectorLifecycleRecord, ObservationGap,
    ObservationGapKind,
};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::{
    DaemonConfig, DaemonRecord, EventPipeline, RecordDeliveryMode, RecordWriteOutcome,
    RuntimeWorkload, ScopeController, WriterSummary,
};

pub struct DaemonState {
    registry: RwLock<SessionRegistry>,
    health: RwLock<HealthSnapshot>,
    stores: Mutex<BTreeMap<String, HashChainStore>>,
    paused_sessions: RwLock<BTreeMap<String, String>>,
    sessions_dir: PathBuf,
    storage_writable: AtomicBool,
    scope: Option<ScopeController>,
    pipeline: EventPipeline,
    collector_checkpoint_interval: Duration,
}

impl DaemonState {
    pub fn new(config: &DaemonConfig) -> Result<Self, String> {
        Self::new_with_scope(config, None)
    }

    pub fn new_with_scope(
        config: &DaemonConfig,
        scope: Option<ScopeController>,
    ) -> Result<Self, String> {
        let sessions_dir = config.state_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir)
            .map_err(|error| format!("failed to create daemon state directory: {error}"))?;
        let mut registry = SessionRegistry::new(config.max_sessions, config.max_pending);
        let mut stores = BTreeMap::new();
        let now_unix_ms = current_unix_ms()?;
        let mut recovered_integrity_issue = false;
        for entry in std::fs::read_dir(&sessions_dir)
            .map_err(|error| format!("failed to scan daemon session state: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("failed to inspect daemon session state: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("failed to inspect session state type: {error}"))?
                .is_dir()
            {
                continue;
            }
            let session_id = entry.file_name().to_string_lossy().to_string();
            let timeline = entry.path().join("timeline.jsonl");
            if !timeline.is_file() {
                continue;
            }
            let mut recovery = HashChainStore::create_or_recover(&timeline)
                .map_err(|error| format!("failed to recover session {session_id}: {error}"))?;
            if let Some(quarantine_path) = recovery.quarantined_path.as_deref() {
                append_integrity_finding(
                    &mut recovery.store,
                    &session_id,
                    &timeline,
                    quarantine_path,
                    recovery.records.len(),
                )?;
                recovered_integrity_issue = true;
            }
            append_incomplete_collector_lifecycles(
                &mut recovery.store,
                &session_id,
                &recovery.records,
            )?;
            if let Some(recovered) = replay_active_session(&recovery.records, now_unix_ms)? {
                registry
                    .register(recovered.intent, now_unix_ms)
                    .map_err(|error| format!("failed to restore session {session_id}: {error}"))?;
                for cgroup_id in recovered.cgroup_ids {
                    registry
                        .discover_cgroup(&session_id, cgroup_id)
                        .map_err(|error| {
                            format!(
                                "failed to restore cgroup {cgroup_id} for session {session_id}: {error}"
                            )
                        })?;
                }
            }
            stores.insert(session_id, recovery.store);
        }
        let pipeline = EventPipeline::new(config.queue_capacity);
        let mut health = HealthSnapshot::new(QueueStats::new(config.queue_capacity));
        health.set_storage(if recovered_integrity_issue {
            ComponentState::Degraded
        } else {
            ComponentState::Ready
        });
        health.set_ebpf(ComponentState::Unavailable);
        Ok(Self {
            registry: RwLock::new(registry),
            health: RwLock::new(health),
            stores: Mutex::new(stores),
            paused_sessions: RwLock::new(BTreeMap::new()),
            sessions_dir,
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
        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        let outcome = candidate
            .register(intent.clone(), now_unix_ms)
            .map_err(registry_error)?;
        self.persist(
            &intent.session_id,
            json!({"record_type":"intent_registered","intent":intent}),
        )
        .await?;
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
        let mut registry = self.registry.write().await;
        let mut candidate = registry.clone();
        let closed = candidate.close(session_id).map_err(registry_error)?;
        let mut removed = Vec::new();
        if let Some(scope) = &self.scope {
            for cgroup_id in &closed.cgroup_ids {
                if let Err(error) = scope
                    .untrack_agent_run(session_id, Some(&closed.intent), *cgroup_id)
                    .await
                {
                    for removed_id in removed {
                        let _ = scope
                            .track_agent_run(session_id, Some(&closed.intent), removed_id)
                            .await;
                    }
                    return Err(error);
                }
                removed.push(*cgroup_id);
            }
        }
        if let Err(error) = self
            .persist(
                session_id,
                json!({"record_type":"session_closed","session_id":session_id}),
            )
            .await
        {
            if let Some(scope) = &self.scope {
                for cgroup_id in removed {
                    if let Err(rollback) = scope
                        .track_agent_run(session_id, Some(&closed.intent), cgroup_id)
                        .await
                    {
                        return Err(format!("{error}; scope rollback failed: {rollback}"));
                    }
                }
            }
            return Err(error);
        }
        *registry = candidate;
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

    pub async fn apply_retention(
        &self,
        tenant_id: &str,
        now_unix_ms: u64,
        dry_run: bool,
    ) -> Result<RetentionPurgeReport, String> {
        let mut registry = self.registry.write().await;
        if dry_run {
            return Ok(registry.retention_purge_report_for_tenant(tenant_id, now_unix_ms, true));
        }

        let mut candidate = registry.clone();
        let report = candidate.apply_retention_for_tenant(tenant_id, now_unix_ms);
        let purged_session_ids = report.purged_session_ids.clone();
        if !purged_session_ids.is_empty() {
            {
                let mut stores = self.stores.lock().await;
                for session_id in &purged_session_ids {
                    stores.remove(session_id);
                }
            }
            for session_id in &purged_session_ids {
                let session_dir = self.sessions_dir.join(session_id);
                match std::fs::remove_dir_all(&session_dir) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!(
                            "failed to remove retained session state {}: {error}",
                            session_dir.display()
                        ));
                    }
                }
            }
            {
                let mut paused = self.paused_sessions.write().await;
                for session_id in &purged_session_ids {
                    paused.remove(session_id);
                }
            }
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

    pub async fn persist_collector_lifecycle(
        &self,
        record: CollectorLifecycleRecord,
    ) -> Result<(), String> {
        let agent_run_id = record.agent_run_id().to_string();
        let payload = serde_json::from_str(&record.to_json_line())
            .map_err(|error| format!("failed to encode collector lifecycle: {error}"))?;
        self.persist(&agent_run_id, payload).await
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
                "session storage is unavailable; restart after repairing storage".to_string(),
            );
        }
        if self
            .paused_sessions
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
        self.paused_sessions.read().await.contains_key(session_id)
    }

    async fn persist(&self, session_id: &str, payload: Value) -> Result<(), String> {
        if !self.storage_writable.load(Ordering::Acquire) {
            return Err(
                "session storage is unavailable; restart after repairing storage".to_string(),
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
            .paused_sessions
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
                let _ = scope
                    .fail_agent_run(
                        session_id,
                        Some(&intent),
                        cgroup_id,
                        CollectorFailureReason::StorageFailure,
                    )
                    .await;
            }
        }
    }

    async fn persist_inner(&self, session_id: &str, payload: Value) -> Result<(), String> {
        let mut stores = self.stores.lock().await;
        if !stores.contains_key(session_id) {
            let timeline = self.sessions_dir.join(session_id).join("timeline.jsonl");
            let recovery = HashChainStore::create_or_recover(timeline)
                .map_err(|error| format!("failed to recover session timeline: {error}"))?;
            stores.insert(session_id.to_string(), recovery.store);
        }
        let store = stores
            .get_mut(session_id)
            .ok_or_else(|| "session store was not initialized".to_string())?;
        let payload = serde_json::to_string(&payload)
            .map_err(|error| format!("failed to serialize session record: {error}"))?;
        store
            .append_json(1, &payload)
            .map_err(|error| format!("failed to append session timeline: {error}"))?;
        store
            .flush()
            .map_err(|error| format!("failed to flush session timeline: {error}"))
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
    timeline_path: &Path,
    quarantine_path: &Path,
    valid_records: usize,
) -> Result<(), String> {
    let payload = json!({
        "record_type":"integrity_finding",
        "session_id":session_id,
        "reason":"hash_chain_tail_quarantined",
        "timeline_path":timeline_path.to_string_lossy(),
        "quarantine_path":quarantine_path.to_string_lossy(),
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

fn container_identity(workload: &RuntimeWorkload) -> Option<String> {
    match workload.adapter {
        AdapterKind::Docker | AdapterKind::Containerd | AdapterKind::K3sContainerd => {
            Some(workload.workload_id.clone())
        }
        AdapterKind::Kubernetes => None,
    }
}

struct RecoveredSession {
    intent: SessionIntent,
    cgroup_ids: Vec<u64>,
}

fn replay_active_session(
    records: &[apolysis_store::ChainRecord],
    now_unix_ms: u64,
) -> Result<Option<RecoveredSession>, String> {
    let mut intent: Option<SessionIntent> = None;
    let mut cgroup_ids = Vec::new();
    let mut closed = false;
    for record in records {
        match record.payload.get("record_type").and_then(Value::as_str) {
            Some("intent_registered") => {
                if closed {
                    cgroup_ids.clear();
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
            Some("session_closed") => {
                closed = true;
                cgroup_ids.clear();
            }
            _ => {}
        }
    }
    cgroup_ids.sort_unstable();
    Ok(intent
        .filter(|intent| !closed && intent.expires_at_unix_ms > now_unix_ms)
        .map(|intent| RecoveredSession { intent, cgroup_ids }))
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
        let request = tokio::time::timeout(std::time::Duration::from_secs(1), requests.recv())
            .await
            .expect("scope cleanup signal must not deadlock the writer")
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
}

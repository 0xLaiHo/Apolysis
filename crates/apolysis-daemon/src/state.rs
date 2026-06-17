// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use apolysis_accountability::{
    AccountabilityAnalyzer, AdapterKind, AssociationOutcome, ComponentState, EffectKind,
    EvidenceBoundary, HealthSnapshot, ObservedEffect, QueueStats, RegisterOutcome, RegistryError,
    ResourceKind, RuntimeIdentity, SessionIntent, SessionRegistry, SessionState,
};
use apolysis_feedback::FeedbackWriter;
use apolysis_policy::Policy;
use apolysis_store::HashChainStore;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex, RwLock};

use crate::{
    DaemonConfig, DaemonRecord, EventPipeline, RecordWriteOutcome, RuntimeWorkload,
    ScopeController, WriterSummary,
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
    redaction_policies: RwLock<BTreeMap<String, Option<Policy>>>,
    feedback: Option<FeedbackWriter>,
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
        let mut redaction_policies = BTreeMap::new();
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
            if let Some(recovered) = replay_active_session(&recovery.records, now_unix_ms)? {
                let redaction_policy = load_redaction_policy(&recovered.intent.policy_ref);
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
                redaction_policies.insert(session_id.clone(), redaction_policy);
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
            redaction_policies: RwLock::new(redaction_policies),
            feedback: config.feedback_dir.clone().map(FeedbackWriter::new),
        })
    }

    pub async fn register(
        &self,
        intent: SessionIntent,
        now_unix_ms: u64,
    ) -> Result<RegisterOutcome, String> {
        let redaction_policy = load_redaction_policy(&intent.policy_ref);
        let session_id = intent.session_id.clone();
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
        self.redaction_policies
            .write()
            .await
            .insert(session_id, redaction_policy);
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
                if let Err(error) = scope.untrack(*cgroup_id).await {
                    for removed_id in removed {
                        let _ = scope.track(removed_id).await;
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
                    if let Err(rollback) = scope.track(cgroup_id).await {
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

    pub async fn credential_path_requires_redaction(&self, session_id: &str, path: &str) -> bool {
        self.redaction_policies
            .read()
            .await
            .get(session_id)
            .and_then(Option::as_ref)
            .map(|policy| policy.denies_credential_path(path))
            .unwrap_or(true)
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
        if let Some(scope) = &self.scope {
            scope.track(cgroup_id).await?;
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
                if let Err(rollback) = scope.untrack(cgroup_id).await {
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

    pub async fn set_ebpf(&self, state: ComponentState) {
        self.health.write().await.set_ebpf(state);
    }

    pub async fn set_adapter(&self, adapter: AdapterKind, state: ComponentState) {
        self.health.write().await.set_adapter(adapter, state);
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
            if let Some(feedback) = &self.feedback {
                feedback.write_last_accountability_finding(&finding)?;
            }
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
            .run_writer(shutdown, move |record| {
                let state = std::sync::Arc::clone(&self);
                async move { state.persist_record(record).await }
            })
            .await
    }

    pub(crate) async fn persist_record(
        &self,
        record: DaemonRecord,
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
                self.mark_session_degraded(&record.session_id, &error).await;
                Ok(RecordWriteOutcome::Failed)
            }
        }
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

    async fn mark_session_degraded(&self, session_id: &str, reason: &str) {
        self.paused_sessions
            .write()
            .await
            .insert(session_id.to_string(), reason.to_string());
        let cgroup_ids = {
            let mut registry = self.registry.write().await;
            registry
                .degrade(session_id)
                .map(|state| state.cgroup_ids)
                .unwrap_or_default()
        };
        if let Some(scope) = &self.scope {
            for cgroup_id in cgroup_ids {
                let _ = scope.untrack(cgroup_id).await;
            }
        }
        self.health
            .write()
            .await
            .set_storage(ComponentState::Degraded);
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
    let mut payload = serde_json::to_value(finding)
        .map_err(|error| format!("failed to serialize accountability finding: {error}"))?;
    let object = payload
        .as_object_mut()
        .ok_or_else(|| "accountability finding did not serialize as an object".to_string())?;
    object.insert(
        "record_type".to_string(),
        Value::String("accountability_finding".to_string()),
    );
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

fn load_redaction_policy(path: &str) -> Option<Policy> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|input| Policy::parse(&input).ok())
}

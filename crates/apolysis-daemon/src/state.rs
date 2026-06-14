// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use apolysis_accountability::{
    ComponentState, HealthSnapshot, QueueStats, RegisterOutcome, RegistryError, SessionIntent,
    SessionRegistry, SessionState,
};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};

use crate::DaemonConfig;

pub struct DaemonState {
    registry: RwLock<SessionRegistry>,
    health: RwLock<HealthSnapshot>,
    stores: Mutex<BTreeMap<String, HashChainStore>>,
    sessions_dir: PathBuf,
    storage_writable: AtomicBool,
}

impl DaemonState {
    pub fn new(config: &DaemonConfig) -> Result<Self, String> {
        let sessions_dir = config.state_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir)
            .map_err(|error| format!("failed to create daemon state directory: {error}"))?;
        let mut registry = SessionRegistry::new(config.max_sessions, config.max_pending);
        let mut stores = BTreeMap::new();
        let now_unix_ms = current_unix_ms()?;
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
            let recovery = HashChainStore::create_or_recover(&timeline)
                .map_err(|error| format!("failed to recover session {session_id}: {error}"))?;
            if let Some(intent) = replay_active_intent(&recovery.records, now_unix_ms)? {
                registry
                    .register(intent, now_unix_ms)
                    .map_err(|error| format!("failed to restore session {session_id}: {error}"))?;
            }
            stores.insert(session_id, recovery.store);
        }
        let mut health = HealthSnapshot::new(QueueStats::new(0));
        health.set_storage(ComponentState::Ready);
        health.set_ebpf(ComponentState::Unavailable);
        Ok(Self {
            registry: RwLock::new(registry),
            health: RwLock::new(health),
            stores: Mutex::new(stores),
            sessions_dir,
            storage_writable: AtomicBool::new(true),
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
        candidate.close(session_id).map_err(registry_error)?;
        self.persist(
            session_id,
            json!({"record_type":"session_closed","session_id":session_id}),
        )
        .await?;
        *registry = candidate;
        Ok(())
    }

    pub async fn query(&self, session_id: &str) -> Option<SessionState> {
        self.registry.read().await.get(session_id).cloned()
    }

    pub async fn health(&self) -> HealthSnapshot {
        self.health.read().await.clone()
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

fn replay_active_intent(
    records: &[apolysis_store::ChainRecord],
    now_unix_ms: u64,
) -> Result<Option<SessionIntent>, String> {
    let mut intent: Option<SessionIntent> = None;
    let mut closed = false;
    for record in records {
        match record.payload.get("record_type").and_then(Value::as_str) {
            Some("intent_registered") => {
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
            Some("session_closed") => closed = true,
            _ => {}
        }
    }
    Ok(intent.filter(|intent| !closed && intent.expires_at_unix_ms > now_unix_ms))
}

fn current_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "current Unix timestamp exceeds u64".to_string())
}

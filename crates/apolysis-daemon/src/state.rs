// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::PathBuf;

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
}

impl DaemonState {
    pub fn new(config: &DaemonConfig) -> Result<Self, String> {
        let sessions_dir = config.state_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir)
            .map_err(|error| format!("failed to create daemon state directory: {error}"))?;
        let mut health = HealthSnapshot::new(QueueStats::new(0));
        health.set_storage(ComponentState::Ready);
        health.set_ebpf(ComponentState::Unavailable);
        Ok(Self {
            registry: RwLock::new(SessionRegistry::new(
                config.max_sessions,
                config.max_pending,
            )),
            health: RwLock::new(health),
            stores: Mutex::new(BTreeMap::new()),
            sessions_dir,
        })
    }

    pub async fn register(
        &self,
        intent: SessionIntent,
        now_unix_ms: u64,
    ) -> Result<RegisterOutcome, String> {
        let outcome = self
            .registry
            .write()
            .await
            .register(intent.clone(), now_unix_ms)
            .map_err(registry_error)?;
        self.persist(
            &intent.session_id,
            json!({"record_type":"intent_registered","intent":intent}),
        )
        .await?;
        Ok(outcome)
    }

    pub async fn renew(
        &self,
        session_id: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<(), String> {
        self.registry
            .write()
            .await
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
        .await
    }

    pub async fn close(&self, session_id: &str) -> Result<(), String> {
        self.registry
            .write()
            .await
            .close(session_id)
            .map_err(registry_error)?;
        self.persist(
            session_id,
            json!({"record_type":"session_closed","session_id":session_id}),
        )
        .await
    }

    pub async fn query(&self, session_id: &str) -> Option<SessionState> {
        self.registry.read().await.get(session_id).cloned()
    }

    pub async fn health(&self) -> HealthSnapshot {
        self.health.read().await.clone()
    }

    async fn persist(&self, session_id: &str, payload: Value) -> Result<(), String> {
        let mut stores = self.stores.lock().await;
        if !stores.contains_key(session_id) {
            let timeline = self
                .sessions_dir
                .join(session_id)
                .join("timeline.jsonl");
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

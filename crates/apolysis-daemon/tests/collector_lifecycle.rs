// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_accountability::{ActionClass, RetentionTier, SessionIntent, DEFAULT_TENANT_ID};
use apolysis_core::CollectorLifecycleRecord;
use apolysis_daemon::{DaemonConfig, DaemonState};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn daemon_recovery_reports_and_closes_an_unfinished_collector_instance() {
    let config = config("unfinished");
    let agent_run_id = "agent-run-restarted";
    let timeline = timeline_path(&config, agent_run_id);
    let mut recovery = HashChainStore::create_or_recover(&timeline).expect("create timeline");
    recovery
        .store
        .append_json(
            1,
            &serde_json::to_string(&json!({
                "record_type": "intent_registered",
                "intent": intent(agent_run_id),
            }))
            .expect("serialize intent"),
        )
        .expect("append intent");
    recovery
        .store
        .append_json(
            1,
            &CollectorLifecycleRecord::started(agent_run_id, "collector-instance-before-crash")
                .with_timestamp(1_780_328_100_007)
                .to_json_line(),
        )
        .expect("append lifecycle start");
    recovery.store.flush().expect("flush timeline");
    drop(recovery);

    let state = DaemonState::new(&config).expect("recover daemon state");
    drop(state);

    let payloads = timeline_payloads(&timeline);
    assert!(payloads.iter().any(|payload| {
        payload["record_type"] == "observation_gap"
            && payload["agent_run_id"] == agent_run_id
            && payload["operation"] == "collector_lifecycle"
            && payload["kind"] == "collector_restart"
            && payload["count"] == 1
    }));
    assert!(payloads.iter().any(|payload| {
        payload["record_type"] == "collector_lifecycle"
            && payload["agent_run_id"] == agent_run_id
            && payload["collector_instance_id"] == "collector-instance-before-crash"
            && payload["state"] == "failed"
            && payload["health"] == "failed"
            && payload["stop_reason"] == "collector_restart"
    }));

    cleanup(&config);
}

fn timeline_payloads(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("read timeline")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse chain record"))
        .map(|record| record["payload"].clone())
        .collect()
}

fn intent(agent_run_id: &str) -> SessionIntent {
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

fn config(name: &str) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-collector-lifecycle-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        ..DaemonConfig::default()
    }
}

fn timeline_path(config: &DaemonConfig, agent_run_id: &str) -> std::path::PathBuf {
    config
        .state_dir
        .join("sessions")
        .join(agent_run_id)
        .join("timeline.jsonl")
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}

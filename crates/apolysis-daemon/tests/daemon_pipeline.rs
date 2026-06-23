// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use apolysis_accountability::{
    ActionClass, ComponentState, QueuePriority, ResourceKind, ResourceSelector, SessionIntent,
};
use apolysis_daemon::{ingest_observer_batch, DaemonConfig, DaemonRecord, DaemonState};
use apolysis_observer::abi::{
    KernelEventKind, KernelEventRecord, ACTION_LEN, COMM_LEN, PAYLOAD_LEN, RESOURCE_LEN,
};
use apolysis_observer::{DaemonKernelEvent, DaemonObserverBatch};
use serde_json::json;
use tokio::sync::oneshot;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn daemon_writer_drains_observer_records_into_the_hash_chain() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let pipeline = state.pipeline();
    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(receiver).await })
    };

    pipeline
        .submit(DaemonRecord::new(
            "pipeline-session",
            QueuePriority::Ordinary,
            json!({
                "record_type":"observed_kernel_event",
                "session_id":"pipeline-session",
                "cgroup_id":77
            }),
        ))
        .expect("record accepted");
    shutdown.send(()).unwrap();
    let summary = writer.await.unwrap().expect("writer drain");

    assert_eq!(summary.written, 1);
    let health = state.health().await;
    assert_eq!(health.queue.capacity, config.queue_capacity);
    assert_eq!(health.queue.depth, 0);
    assert_eq!(health.queue.accepted, 1);
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/pipeline-session/timeline.jsonl"),
    )
    .expect("session timeline");
    assert!(timeline.contains(r#""record_type":"observed_kernel_event""#));
    assert!(timeline.contains(r#""cgroup_id":77"#));

    cleanup(&config);
}

#[tokio::test]
async fn timeline_write_failure_degrades_storage_and_writer_continues_other_sessions() {
    let config = config();
    let blocked_timeline = config.state_dir.join("sessions/bad-session/timeline.jsonl");
    std::fs::create_dir_all(&blocked_timeline).expect("block bad timeline path");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let pipeline = state.pipeline();
    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(receiver).await })
    };

    pipeline
        .submit(DaemonRecord::new(
            "bad-session",
            QueuePriority::Ordinary,
            json!({"record_type":"observed_kernel_event","session_id":"bad-session"}),
        ))
        .expect("bad record accepted");
    pipeline
        .submit(DaemonRecord::new(
            "healthy-session",
            QueuePriority::Ordinary,
            json!({"record_type":"observed_kernel_event","session_id":"healthy-session"}),
        ))
        .expect("healthy record accepted");

    shutdown.send(()).unwrap();
    let summary = writer.await.unwrap().expect("writer drain");

    assert_eq!(summary.failed, 1);
    assert_eq!(summary.written, 1);
    assert_eq!(state.health().await.storage(), ComponentState::Degraded);
    let healthy_timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/healthy-session/timeline.jsonl"),
    )
    .expect("healthy session timeline");
    assert!(healthy_timeline.contains(r#""session_id":"healthy-session""#));

    cleanup(&config);
}

#[tokio::test]
async fn observer_batch_submits_only_records_with_session_ownership() {
    let config = config();
    let policy_path = config.state_dir.parent().unwrap().join("policy.yaml");
    std::fs::create_dir_all(policy_path.parent().unwrap()).unwrap();
    std::fs::write(
        &policy_path,
        "version: 1\ncredentials:\n  deny_read:\n    - .env\n",
    )
    .unwrap();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(
            intent("observed-session", policy_path.to_str().unwrap()),
            1_700_000_000_000,
        )
        .await
        .expect("register intent");
    state
        .discover_cgroup("observed-session", 77)
        .await
        .expect("discover cgroup");
    let pipeline = state.pipeline();
    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(receiver).await })
    };

    let summary = ingest_observer_batch(
        &state,
        &pipeline,
        DaemonObserverBatch {
            events: vec![
                kernel_event(77),
                kernel_file_event(77, "/host/private/credential"),
                kernel_file_event(77, "/workspace/src/main.rs"),
                kernel_file_event(77, "/workspace/.env"),
                kernel_event(99),
            ],
            decode_failures: 2,
            truncations: 1,
        },
    )
    .await;

    assert_eq!(summary.submitted, 10);
    assert_eq!(summary.unscoped, 1);
    assert_eq!(summary.decode_failures, 2);
    assert_eq!(summary.truncations, 1);
    shutdown.send(()).unwrap();
    writer.await.unwrap().expect("writer drain");

    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/observed-session/timeline.jsonl"),
    )
    .expect("session timeline");
    assert!(timeline.contains(r#""record_type":"raw_kernel_event""#));
    assert!(timeline.contains(r#""cgroup_id":"77""#));
    assert!(!timeline.contains(r#""cgroup_id":"99""#));
    assert!(timeline.contains("path_token:"));
    assert!(!timeline.contains("/host/private/credential"));
    assert!(timeline.contains("/workspace/src/main.rs"));
    assert!(!timeline.contains("/workspace/.env"));

    cleanup(&config);
}

#[tokio::test]
async fn observer_batch_appends_accountability_findings_for_registered_intent() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(
            intent("accountability-session", "policy.yaml"),
            1_700_000_000_000,
        )
        .await
        .expect("register intent");
    state
        .discover_cgroup("accountability-session", 77)
        .await
        .expect("discover cgroup");
    let pipeline = state.pipeline();
    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(receiver).await })
    };

    let summary = ingest_observer_batch(
        &state,
        &pipeline,
        DaemonObserverBatch {
            events: vec![kernel_network_event(77, "1.1.1.1:443")],
            decode_failures: 0,
            truncations: 0,
        },
    )
    .await;

    assert_eq!(summary.submitted, 3);
    shutdown.send(()).unwrap();
    writer.await.unwrap().expect("writer drain");

    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/accountability-session/timeline.jsonl"),
    )
    .expect("session timeline");
    assert!(timeline.contains(r#""record_type":"raw_kernel_event""#));
    assert!(timeline.contains(r#""record_type":"accountability_finding""#));
    assert!(timeline.contains(r#""kind":"undeclared_action""#));
    assert!(timeline.contains(r#""kind":"unknown_egress""#));
    assert!(timeline.contains(r#""decision":"review""#));

    cleanup(&config);
}

#[tokio::test]
async fn observer_batch_updates_accountability_feedback_output() {
    let mut config = config();
    let feedback_dir = config.state_dir.parent().unwrap().join("feedback");
    config.feedback_dir = Some(feedback_dir.clone());
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("feedback-session", "policy.yaml"), 1_700_000_000_000)
        .await
        .expect("register intent");
    state
        .discover_cgroup("feedback-session", 77)
        .await
        .expect("discover cgroup");
    let pipeline = state.pipeline();
    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(receiver).await })
    };

    ingest_observer_batch(
        &state,
        &pipeline,
        DaemonObserverBatch {
            events: vec![kernel_network_event(77, "1.1.1.1:443")],
            decode_failures: 0,
            truncations: 0,
        },
    )
    .await;
    shutdown.send(()).unwrap();
    writer.await.unwrap().expect("writer drain");

    let json = std::fs::read_to_string(feedback_dir.join("last-accountability-finding.json"))
        .expect("accountability feedback JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid feedback JSON");
    assert_eq!(value["session_id"], "feedback-session");
    assert!(matches!(
        value["kind"].as_str(),
        Some("undeclared_action" | "unknown_egress")
    ));

    cleanup(&config);
}

fn kernel_event(cgroup_id: u64) -> DaemonKernelEvent {
    let mut comm = [0_u8; COMM_LEN];
    comm[..4].copy_from_slice(b"test");
    DaemonKernelEvent {
        timestamp_unix_ms: 1_700_000_000_100,
        record: KernelEventRecord {
            timestamp_ns: 1,
            cgroup_id,
            pid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            event_kind: KernelEventKind::Exec as u32,
            flags: 0,
            comm,
            resource: [0; RESOURCE_LEN],
            action: [0; ACTION_LEN],
            payload: [0; PAYLOAD_LEN],
        },
    }
}

fn kernel_network_event(cgroup_id: u64, endpoint: &str) -> DaemonKernelEvent {
    let mut event = kernel_event(cgroup_id);
    event.record.event_kind = KernelEventKind::Connect as u32;
    event.record.action[..7].copy_from_slice(b"connect");
    event.record.resource[..endpoint.len()].copy_from_slice(endpoint.as_bytes());
    event
}

fn kernel_file_event(cgroup_id: u64, path: &str) -> DaemonKernelEvent {
    let mut event = kernel_event(cgroup_id);
    event.record.event_kind = KernelEventKind::Open as u32;
    event.record.action[..4].copy_from_slice(b"open");
    event.record.resource[..path.len()].copy_from_slice(path.as_bytes());
    event
}

fn intent(session_id: &str, policy_ref: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: apolysis_accountability::DEFAULT_TENANT_ID.to_string(),
        retention_tier: apolysis_accountability::RetentionTier::Standard,
        session_id: session_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: vec![ResourceSelector {
            kind: ResourceKind::Workspace,
            value: "/workspace".to_string(),
        }],
        policy_ref: policy_ref.to_string(),
        workload_selectors: Vec::new(),
    }
}

fn config() -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-daemon-pipeline-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        queue_capacity: 8,
        ..DaemonConfig::default()
    }
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}

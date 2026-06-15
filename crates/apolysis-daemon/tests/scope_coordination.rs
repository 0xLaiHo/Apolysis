// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};
use std::time::Duration;

use apolysis_accountability::{ActionClass, SessionIntent};
use apolysis_daemon::{scope_channel, DaemonConfig, DaemonState, ScopeOperation, ScopeRequest};

#[tokio::test]
async fn observer_rejection_does_not_publish_cgroup_ownership() {
    let config = config("observer-rejection");
    let (scope, receiver) = scope_channel(4);
    let worker = spawn_scope_worker(receiver, Arc::new(Mutex::new(Vec::new())), true);
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    state
        .register(intent("scope-rejected"), now_ms())
        .await
        .expect("register intent");

    let error = state
        .discover_cgroup("scope-rejected", 41)
        .await
        .expect_err("observer rejection must fail correlation");

    assert!(error.contains("observer rejected cgroup"));
    assert_eq!(state.session_for_cgroup(41).await, None);

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn persistence_failure_rolls_back_observer_scope() {
    let config = config("storage-rollback");
    let blocked_timeline = config
        .state_dir
        .join("sessions/pending-session/timeline.jsonl");
    std::fs::create_dir_all(&blocked_timeline).unwrap();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, receiver) = scope_channel(4);
    let worker = spawn_scope_worker(receiver, Arc::clone(&operations), false);
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");

    state
        .discover_cgroup("pending-session", 51)
        .await
        .expect_err("blocked timeline must fail correlation");

    assert_eq!(state.session_for_cgroup(51).await, None);
    assert_eq!(
        *operations.lock().unwrap(),
        vec![ScopeOperation::Track, ScopeOperation::Untrack]
    );

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn closing_a_session_removes_its_observer_scope() {
    let config = config("close-untracks");
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, receiver) = scope_channel(4);
    let worker = spawn_scope_worker(receiver, Arc::clone(&operations), false);
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    state
        .register(intent("close-session"), now_ms())
        .await
        .expect("register intent");
    state
        .discover_cgroup("close-session", 61)
        .await
        .expect("discover cgroup");

    state.close("close-session").await.expect("close session");

    assert_eq!(state.session_for_cgroup(61).await, None);
    assert_eq!(
        *operations.lock().unwrap(),
        vec![ScopeOperation::Track, ScopeOperation::Untrack]
    );

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn restart_restores_persisted_cgroup_ownership() {
    let config = config("restart-scope");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("restart-session"), now_ms())
        .await
        .expect("register intent");
    state
        .discover_cgroup("restart-session", 71)
        .await
        .expect("discover cgroup");
    drop(state);

    let restarted = DaemonState::new(&config).expect("restarted daemon state");

    assert_eq!(
        restarted.session_for_cgroup(71).await.as_deref(),
        Some("restart-session")
    );
    assert_eq!(restarted.tracked_cgroups().await, vec![71]);
    cleanup(&config);
}

fn spawn_scope_worker(
    mut receiver: tokio::sync::mpsc::Receiver<ScopeRequest>,
    operations: Arc<Mutex<Vec<ScopeOperation>>>,
    reject_track: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            operations.lock().unwrap().push(request.operation());
            let result = if reject_track && request.operation() == ScopeOperation::Track {
                Err("observer rejected cgroup".to_string())
            } else {
                Ok(())
            };
            request.complete(result);
        }
    })
}

fn intent(session_id: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        session_id: session_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: Vec::new(),
        policy_ref: "policy.yaml".to_string(),
        workload_selectors: Vec::new(),
    }
}

fn config(name: &str) -> DaemonConfig {
    let root = std::env::temp_dir().join(format!("apolysis-scope-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        max_sessions: 32,
        max_pending: 32,
        max_connections: 16,
        request_timeout: Duration::from_millis(100),
        ..DaemonConfig::default()
    }
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}

fn now_ms() -> u64 {
    1_700_000_000_000
}

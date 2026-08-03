// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::{ActionClass, ComponentState, SessionIntent};
use apolysis_daemon::{
    run_observer_runtime, scope_channel, DaemonConfig, DaemonState, ObserverRuntimeBackend,
    ScopeOperation,
};
use apolysis_observer::{DaemonObserverBatch, DaemonObserverCounters, NetworkConnectCounters};
use tokio::sync::oneshot;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn observer_runtime_processes_scope_commands_and_reports_final_counters() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let operations = Arc::new(Mutex::new(Vec::new()));
    let backend = FakeBackend {
        operations: Arc::clone(&operations),
        fail_counters: false,
        fail_track: None,
        batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (scope, receiver) = scope_channel(4);
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, vec![31, 32], receiver, state, shutdown_receiver).await
        })
    };

    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(state.health().await.ebpf(), ComponentState::Ready);
    scope.track(41).await.expect("track cgroup");
    scope.untrack(41).await.expect("untrack cgroup");
    shutdown.send(()).unwrap();
    let summary = runtime.await.unwrap().expect("clean observer shutdown");

    assert_eq!(
        *operations.lock().unwrap(),
        vec![
            (ScopeOperation::Track, 31),
            (ScopeOperation::Track, 32),
            (ScopeOperation::Track, 41),
            (ScopeOperation::Untrack, 41)
        ]
    );
    assert_eq!(summary.counters.reserve_failures, 3);
    assert_eq!(summary.counters.map_pressure, 2);
    cleanup(&config);
}

#[tokio::test]
async fn observer_shutdown_persists_connect_gaps_to_the_owning_agent_run() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-a"), 1_700_000_000_000)
        .await
        .expect("register Agent Run A");
    state
        .register(intent("agent-run-b"), 1_700_000_000_000)
        .await
        .expect("register Agent Run B");
    state
        .discover_cgroup("agent-run-a", 31)
        .await
        .expect("associate cgroup 31");
    state
        .discover_cgroup("agent-run-b", 32)
        .await
        .expect("associate cgroup 32");

    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        batch: None,
        scoped_counters: BTreeMap::from([
            (
                31,
                NetworkConnectCounters {
                    missing_entries: 2,
                    ..NetworkConnectCounters::default()
                },
            ),
            (
                32,
                NetworkConnectCounters {
                    missing_exits: 1,
                    pending: 2,
                    ..NetworkConnectCounters::default()
                },
            ),
        ]),
    };
    let (_scope, receiver) = scope_channel(2);
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, vec![31, 32], receiver, state, shutdown_receiver).await
        })
    };

    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    shutdown.send(()).expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");

    let timeline_a = timeline(&config, "agent-run-a");
    assert!(timeline_a.contains(r#""record_type":"observation_gap""#));
    assert!(timeline_a.contains(r#""agent_run_id":"agent-run-a""#));
    assert!(timeline_a.contains(r#""kind":"missing_entry""#));
    assert!(timeline_a.contains(r#""count":2"#));
    assert!(!timeline_a.contains("agent-run-b"));
    assert!(!timeline_a.contains(r#""kind":"missing_exit""#));

    let timeline_b = timeline(&config, "agent-run-b");
    assert!(timeline_b.contains(r#""record_type":"observation_gap""#));
    assert!(timeline_b.contains(r#""agent_run_id":"agent-run-b""#));
    assert!(timeline_b.contains(r#""kind":"missing_exit""#));
    assert!(timeline_b.contains(r#""count":3"#));
    assert!(!timeline_b.contains("agent-run-a"));
    assert!(!timeline_b.contains(r#""kind":"missing_entry""#));

    cleanup(&config);
}

#[tokio::test]
async fn counter_read_failure_marks_ebpf_unavailable() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: true,
        fail_track: None,
        batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (_scope, receiver) = scope_channel(1);
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, shutdown_receiver).await
        })
    };

    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    shutdown.send(()).unwrap();
    let error = runtime.await.unwrap().expect_err("counter read must fail");

    assert!(error.contains("counter read failed"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    cleanup(&config);
}

#[tokio::test]
async fn restored_scope_failure_keeps_ebpf_unavailable() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: Some(31),
        batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (_scope, receiver) = scope_channel(1);
    let (_shutdown, shutdown_receiver) = oneshot::channel();

    let error = run_observer_runtime(
        backend,
        vec![31],
        receiver,
        Arc::clone(&state),
        shutdown_receiver,
    )
    .await
    .expect_err("scope restore must fail");

    assert!(error.contains("failed to restore observer scope"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    cleanup(&config);
}

#[tokio::test]
async fn abi_mismatch_stops_the_observer_and_marks_ebpf_unavailable() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        batch: Some(DaemonObserverBatch {
            abi_mismatches: 1,
            ..DaemonObserverBatch::default()
        }),
        scoped_counters: BTreeMap::new(),
    };
    let (_scope, receiver) = scope_channel(1);
    let (_shutdown, shutdown_receiver) = oneshot::channel();

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        run_observer_runtime(
            backend,
            Vec::new(),
            receiver,
            Arc::clone(&state),
            shutdown_receiver,
        ),
    )
    .await
    .expect("ABI mismatch must stop the observer");
    let error = result.expect_err("ABI mismatch must fail loud");

    assert!(error.contains("kernel/userspace ABI mismatch"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    cleanup(&config);
}

struct FakeBackend {
    operations: Arc<Mutex<Vec<(ScopeOperation, u64)>>>,
    fail_counters: bool,
    fail_track: Option<u64>,
    batch: Option<DaemonObserverBatch>,
    scoped_counters: BTreeMap<u64, NetworkConnectCounters>,
}

impl ObserverRuntimeBackend for FakeBackend {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Track, cgroup_id));
        if self.fail_track == Some(cgroup_id) {
            return Err("track failed".to_string());
        }
        Ok(())
    }

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<NetworkConnectCounters, String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Untrack, cgroup_id));
        Ok(self.scoped_counters.remove(&cgroup_id).unwrap_or_default())
    }

    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>> {
        match self.batch.take() {
            Some(batch) => Box::pin(async move { Ok(batch) }),
            None => Box::pin(pending()),
        }
    }

    fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        if self.fail_counters {
            return Err("counter read failed".to_string());
        }
        Ok(DaemonObserverCounters {
            reserve_failures: 3,
            map_pressure: 2,
            ..DaemonObserverCounters::default()
        })
    }
}

fn intent(agent_run_id: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: apolysis_accountability::DEFAULT_TENANT_ID.to_string(),
        retention_tier: apolysis_accountability::RetentionTier::Standard,
        session_id: agent_run_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: Vec::new(),
        workload_selectors: Vec::new(),
    }
}

fn timeline(config: &DaemonConfig, agent_run_id: &str) -> String {
    std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(agent_run_id)
            .join("timeline.jsonl"),
    )
    .expect("read Agent Run timeline")
}

fn config() -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-observer-runtime-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        ..DaemonConfig::default()
    }
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}

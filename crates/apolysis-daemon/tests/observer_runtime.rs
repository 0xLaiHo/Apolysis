// SPDX-License-Identifier: Apache-2.0

use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::ComponentState;
use apolysis_daemon::{
    run_observer_runtime, scope_channel, DaemonConfig, DaemonState, ObserverRuntimeBackend,
    ScopeOperation,
};
use apolysis_observer::{DaemonObserverBatch, DaemonObserverCounters};
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
async fn counter_read_failure_marks_ebpf_unavailable() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: true,
        fail_track: None,
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

struct FakeBackend {
    operations: Arc<Mutex<Vec<(ScopeOperation, u64)>>>,
    fail_counters: bool,
    fail_track: Option<u64>,
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

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Untrack, cgroup_id));
        Ok(())
    }

    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>> {
        Box::pin(pending())
    }

    fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        if self.fail_counters {
            return Err("counter read failed".to_string());
        }
        Ok(DaemonObserverCounters {
            reserve_failures: 3,
            map_pressure: 2,
        })
    }
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

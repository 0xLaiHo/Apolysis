// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::{
    ActionClass, ComponentState, QueuePriority, ResourceKind, ResourceSelector, SessionIntent,
};
use apolysis_daemon::{
    run_observer_runtime, scope_channel, DaemonConfig, DaemonRecord, DaemonState,
    ObserverRuntimeBackend, ScopeOperation,
};
use apolysis_observer::abi::{
    KernelEventKind, KernelEventRecord, ACTION_LEN, COMM_LEN, FLAG_RETURN_VALUE,
    KERNEL_ABI_VERSION, KERNEL_EVENT_RECORD_LEN, PAYLOAD_LEN, RESOURCE_LEN,
};
use apolysis_observer::{
    DaemonKernelEvent, DaemonObserverBatch, DaemonObserverCounters, FileOperationCounters,
    NetworkConnectCounters, OperationPairCounters, ScopeGeneration, ScopeObservationGapCounters,
};
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
        fail_untrack: None,
        batch: None,
        drain_batch: None,
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
            (ScopeOperation::Untrack, 41),
            (ScopeOperation::Untrack, 31),
            (ScopeOperation::Untrack, 32)
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
        fail_untrack: None,
        batch: None,
        drain_batch: None,
        scoped_counters: BTreeMap::from([
            (
                31,
                ScopeObservationGapCounters {
                    network_connect: NetworkConnectCounters {
                        missing_entries: 2,
                        ..NetworkConnectCounters::default()
                    },
                    ..ScopeObservationGapCounters::default()
                },
            ),
            (
                32,
                ScopeObservationGapCounters {
                    network_connect: NetworkConnectCounters {
                        missing_exits: 1,
                        pending: 2,
                        ..NetworkConnectCounters::default()
                    },
                    ..ScopeObservationGapCounters::default()
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
async fn observer_shutdown_persists_file_gaps_to_the_owning_agent_runs() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-file-a"), 1_700_000_000_000)
        .await
        .expect("register Agent Run A");
    state
        .register(intent("agent-run-file-b"), 1_700_000_000_000)
        .await
        .expect("register Agent Run B");
    state
        .discover_cgroup("agent-run-file-a", 71)
        .await
        .expect("associate cgroup 71");
    state
        .discover_cgroup("agent-run-file-b", 72)
        .await
        .expect("associate cgroup 72");

    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: Some(file_outcome_batch(71)),
        scoped_counters: BTreeMap::from([
            (
                71,
                ScopeObservationGapCounters {
                    file_operations: FileOperationCounters {
                        open: OperationPairCounters {
                            missing_entries: 2,
                            ..OperationPairCounters::default()
                        },
                        ..FileOperationCounters::default()
                    },
                    ..ScopeObservationGapCounters::default()
                },
            ),
            (
                72,
                ScopeObservationGapCounters {
                    file_operations: FileOperationCounters {
                        rename: OperationPairCounters {
                            missing_exits: 1,
                            pending: 2,
                            ..OperationPairCounters::default()
                        },
                        ..FileOperationCounters::default()
                    },
                    ..ScopeObservationGapCounters::default()
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
            run_observer_runtime(backend, vec![71, 72], receiver, state, shutdown_receiver).await
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

    let timeline_a = timeline(&config, "agent-run-file-a");
    assert!(timeline_a.contains(r#""operation":"file_open""#));
    assert!(timeline_a.contains(r#""event_name":"openat""#));
    assert!(timeline_a.contains(r#""outcome":"succeeded""#));
    assert!(timeline_a.contains(r#""kind":"missing_entry""#));
    assert!(timeline_a.contains(r#""count":2"#));
    assert!(!timeline_a.contains("file_rename"));
    assert!(!timeline_a.contains("agent-run-file-b"));

    let timeline_b = timeline(&config, "agent-run-file-b");
    assert!(timeline_b.contains(r#""operation":"file_rename""#));
    assert!(timeline_b.contains(r#""kind":"missing_exit""#));
    assert!(timeline_b.contains(r#""count":3"#));
    assert!(!timeline_b.contains("file_open"));
    assert!(!timeline_b.contains("agent-run-file-a"));

    cleanup(&config);
}

#[tokio::test]
async fn dropped_observation_gap_makes_scope_drain_fail_loud() {
    let mut config = config();
    config.queue_capacity = 1;
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-gap-drop"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-gap-drop", 51)
        .await
        .expect("associate cgroup");
    state
        .pipeline()
        .submit(DaemonRecord::new(
            "agent-run-gap-drop",
            QueuePriority::Integrity,
            serde_json::json!({"record_type":"integrity_test"}),
        ))
        .expect("fill protected queue");

    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: None,
        scoped_counters: BTreeMap::from([(
            51,
            ScopeObservationGapCounters {
                network_connect: NetworkConnectCounters {
                    missing_entries: 1,
                    ..NetworkConnectCounters::default()
                },
                ..ScopeObservationGapCounters::default()
            },
        )]),
    };
    let (_scope, receiver) = scope_channel(1);
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, vec![51], receiver, state, shutdown_receiver).await
        })
    };
    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    shutdown.send(()).unwrap();

    let error = runtime
        .await
        .unwrap()
        .expect_err("dropped Observation Gap must fail scope drain");
    assert!(error.contains("Observation Gap"));
    assert!(error.contains("dropped"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    cleanup(&config);
}

#[tokio::test]
async fn dropped_file_outcome_stops_the_observer_runtime() {
    let mut config = config();
    config.queue_capacity = 1;
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-outcome-drop"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-outcome-drop", 52)
        .await
        .expect("associate cgroup");
    state
        .pipeline()
        .submit(DaemonRecord::new(
            "agent-run-outcome-drop",
            QueuePriority::Integrity,
            serde_json::json!({"record_type":"integrity_test"}),
        ))
        .expect("fill protected queue");

    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: Some(file_outcome_batch(52)),
        drain_batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (_scope, receiver) = scope_channel(1);
    let (_shutdown, shutdown_receiver) = oneshot::channel();

    let error = run_observer_runtime(
        backend,
        vec![52],
        receiver,
        Arc::clone(&state),
        shutdown_receiver,
    )
    .await
    .expect_err("dropped file outcome must fail loud");

    assert!(error.contains("dropped"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    cleanup(&config);
}

#[tokio::test]
async fn normalization_failure_stops_queued_observer_ingest() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-normalize"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-normalize", 53)
        .await
        .expect("associate cgroup");
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: Some(invalid_normalization_batch(53)),
        drain_batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (_scope, receiver) = scope_channel(1);
    let (_shutdown, shutdown_receiver) = oneshot::channel();

    let error = run_observer_runtime(
        backend,
        vec![53],
        receiver,
        Arc::clone(&state),
        shutdown_receiver,
    )
    .await
    .expect_err("normalization failure must fail queued ingest");

    assert!(error.contains("failed to normalize observer record"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    cleanup(&config);
}

#[tokio::test]
async fn normalization_failure_during_scope_drain_rejects_clean_close() {
    let config = config();
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: Some(invalid_normalization_batch(54)),
        scoped_counters: BTreeMap::new(),
    };
    let (scope, receiver) = scope_channel(2);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let (_observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };
    state
        .register(intent("agent-run-drain-normalize"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-drain-normalize", 54)
        .await
        .expect("associate cgroup");

    let close_error = state
        .close("agent-run-drain-normalize")
        .await
        .expect_err("normalization failure must reject clean close");
    let runtime_error = runtime
        .await
        .unwrap()
        .expect_err("normalization failure must stop observer runtime");

    assert!(close_error.contains("failed to normalize observer record"));
    assert!(runtime_error.contains("failed to normalize observer record"));
    assert!(state.query("agent-run-drain-normalize").await.is_some());
    cleanup(&config);
}

#[tokio::test]
async fn closing_an_agent_run_persists_its_scoped_gap_without_deadlock() {
    let config = config();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let backend = FakeBackend {
        operations: Arc::clone(&operations),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: Some(file_and_process_drain_batch(41, "/sensitive/private.txt")),
        scoped_counters: BTreeMap::from([(
            41,
            ScopeObservationGapCounters {
                file_operations: FileOperationCounters {
                    open: OperationPairCounters {
                        missing_entries: 1,
                        ..OperationPairCounters::default()
                    },
                    ..FileOperationCounters::default()
                },
                ..ScopeObservationGapCounters::default()
            },
        )]),
    };
    let (scope, receiver) = scope_channel(2);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let (observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };

    state
        .register(
            intent_with_workspace("agent-run-close", "/sensitive"),
            1_700_000_000_000,
        )
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-close", 41)
        .await
        .expect("associate cgroup");
    state
        .register(intent("agent-run-close"), 1_700_000_000_001)
        .await
        .expect("replace Agent Run intent without workspace allowlist");
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state.close("agent-run-close"),
    )
    .await
    .expect("Agent Run close must not deadlock")
    .expect("close Agent Run");
    let timeline_after_close = timeline(&config, "agent-run-close");
    let gap_index = timeline_after_close
        .find(r#""record_type":"observation_gap""#)
        .expect("gap is durable before close returns");
    let outcome_index = timeline_after_close
        .find(r#""event_name":"openat""#)
        .expect("completed file outcome is durable before close returns");
    let process_index = timeline_after_close
        .find(r#""event_name":"sched_process_exec""#)
        .expect("process event submitted before drain is durable before close returns");
    let close_index = timeline_after_close
        .find(r#""record_type":"session_closed""#)
        .expect("terminal record is durable before close returns");
    assert!(outcome_index < close_index);
    assert!(process_index < close_index);
    assert!(gap_index < close_index);
    assert!(!timeline_after_close.contains("/sensitive/private.txt"));
    assert!(timeline_after_close.contains("path_token:"));

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");

    assert_eq!(
        *operations.lock().unwrap(),
        vec![(ScopeOperation::Track, 41), (ScopeOperation::Untrack, 41)]
    );
    let timeline = timeline(&config, "agent-run-close");
    assert!(timeline.contains(r#""record_type":"observation_gap""#));
    assert!(timeline.contains(r#""agent_run_id":"agent-run-close""#));
    assert!(timeline.contains(r#""operation":"file_open""#));
    assert!(timeline.contains(r#""kind":"missing_entry""#));
    assert!(timeline.contains(r#""count":1"#));

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
        fail_untrack: None,
        batch: None,
        drain_batch: None,
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
async fn scoped_counter_read_failure_stops_runtime_and_keeps_agent_run_open() {
    let config = config();
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: Some(61),
        batch: None,
        drain_batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (scope, receiver) = scope_channel(2);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let (_observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };
    state
        .register(intent("agent-run-read-failure"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-read-failure", 61)
        .await
        .expect("associate cgroup");

    let close_error = state
        .close("agent-run-read-failure")
        .await
        .expect_err("counter read failure must reject clean close");
    let runtime_error = runtime
        .await
        .unwrap()
        .expect_err("counter read failure must stop observer runtime");

    assert!(close_error.contains("scoped counter read failed"));
    assert!(runtime_error.contains("scoped counter read failed"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    assert!(state.query("agent-run-read-failure").await.is_some());
    assert!(!timeline(&config, "agent-run-read-failure").contains("session_closed"));
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
        fail_untrack: None,
        batch: None,
        drain_batch: None,
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
async fn reused_cgroup_rejects_records_from_the_drained_scope_generation() {
    let config = config();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let mut stale = file_outcome_batch_for_path(41, "reused-stale.txt");
    stale.events[0].record.scope_generation = 1;
    let backend = ReuseBackend {
        operations: Arc::clone(&operations),
        stale_batch: Some(stale),
    };
    let (scope, receiver) = scope_channel(4);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let (_observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };

    state
        .register(intent("agent-run-generation-a"), 1_700_000_000_000)
        .await
        .expect("register first Agent Run");
    state
        .discover_cgroup("agent-run-generation-a", 41)
        .await
        .expect("track first cgroup generation");
    state
        .close("agent-run-generation-a")
        .await
        .expect("drain first cgroup generation");
    state
        .register(intent("agent-run-generation-b"), 1_700_000_000_001)
        .await
        .expect("register second Agent Run");
    state
        .discover_cgroup("agent-run-generation-b", 41)
        .await
        .expect("reuse numeric cgroup with a new generation");

    let error = tokio::time::timeout(std::time::Duration::from_secs(1), runtime)
        .await
        .expect("stale generation must stop the observer")
        .expect("observer task")
        .expect_err("stale generation must fail loud");

    assert!(error.contains("stale or unknown scope generations"));
    assert_eq!(
        *operations.lock().unwrap(),
        vec![
            (ScopeOperation::Track, 41),
            (ScopeOperation::Untrack, 41),
            (ScopeOperation::Track, 41),
        ]
    );
    assert!(!timeline(&config, "agent-run-generation-b").contains("reused-stale.txt"));
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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
        fail_untrack: None,
        batch: Some(DaemonObserverBatch {
            abi_mismatches: 1,
            ..DaemonObserverBatch::default()
        }),
        drain_batch: None,
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
    fail_untrack: Option<u64>,
    batch: Option<DaemonObserverBatch>,
    drain_batch: Option<DaemonObserverBatch>,
    scoped_counters: BTreeMap<u64, ScopeObservationGapCounters>,
}

struct ReuseBackend {
    operations: Arc<Mutex<Vec<(ScopeOperation, u64)>>>,
    stale_batch: Option<DaemonObserverBatch>,
}

impl ObserverRuntimeBackend for ReuseBackend {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeGeneration, String> {
        let mut operations = self.operations.lock().unwrap();
        let generation = operations
            .iter()
            .filter(|(operation, _)| *operation == ScopeOperation::Track)
            .count() as u64
            + 1;
        operations.push((ScopeOperation::Track, cgroup_id));
        ScopeGeneration::new(generation)
    }

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Untrack, cgroup_id));
        Ok(ScopeObservationGapCounters::default())
    }

    fn drain_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        Ok(DaemonObserverBatch::default())
    }

    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>> {
        let tracked_twice = self
            .operations
            .lock()
            .unwrap()
            .iter()
            .filter(|(operation, _)| *operation == ScopeOperation::Track)
            .count()
            >= 2;
        if tracked_twice {
            if let Some(batch) = self.stale_batch.take() {
                return Box::pin(async move { Ok(batch) });
            }
        }
        Box::pin(pending())
    }

    fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        Ok(DaemonObserverCounters::default())
    }
}

impl ObserverRuntimeBackend for FakeBackend {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeGeneration, String> {
        let mut operations = self.operations.lock().unwrap();
        let generation = operations
            .iter()
            .filter(|(operation, _)| *operation == ScopeOperation::Track)
            .count() as u64
            + 1;
        operations.push((ScopeOperation::Track, cgroup_id));
        if self.fail_track == Some(cgroup_id) {
            return Err("track failed".to_string());
        }
        ScopeGeneration::new(generation)
    }

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Untrack, cgroup_id));
        if self.fail_untrack == Some(cgroup_id) {
            return Err("scoped counter read failed".to_string());
        }
        Ok(self.scoped_counters.remove(&cgroup_id).unwrap_or_default())
    }

    fn drain_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        Ok(self.drain_batch.take().unwrap_or_default())
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

fn intent_with_workspace(agent_run_id: &str, workspace: &str) -> SessionIntent {
    let mut intent = intent(agent_run_id);
    intent.allowed_resources = vec![ResourceSelector {
        kind: ResourceKind::Workspace,
        value: workspace.to_string(),
    }];
    intent
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

fn file_outcome_batch(cgroup_id: u64) -> DaemonObserverBatch {
    file_outcome_batch_for_path(cgroup_id, "artifact.txt")
}

fn file_outcome_batch_for_path(cgroup_id: u64, path: &str) -> DaemonObserverBatch {
    let mut comm = [0_u8; COMM_LEN];
    comm[..4].copy_from_slice(b"test");
    let mut resource = [0_u8; RESOURCE_LEN];
    resource[..path.len()].copy_from_slice(path.as_bytes());
    let mut action = [0_u8; ACTION_LEN];
    action[..4].copy_from_slice(b"read");
    DaemonObserverBatch {
        events: vec![DaemonKernelEvent {
            timestamp_unix_ms: 1_780_000_000_000,
            host_boot_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
            record: KernelEventRecord {
                abi_version: KERNEL_ABI_VERSION,
                record_size: KERNEL_EVENT_RECORD_LEN as u32,
                timestamp_ns: 1,
                cgroup_id,
                pid: 4242,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                event_kind: KernelEventKind::Open as u32,
                flags: FLAG_RETURN_VALUE,
                return_value: 3,
                scope_generation: 1,
                process_generation: 4_242,
                process_start_time_ns: 42_000,
                parent_process_generation: 1,
                exec_generation: 1,
                parent_exec_generation: 1,
                comm,
                resource,
                action,
                payload: [0; PAYLOAD_LEN],
            },
        }],
        ..DaemonObserverBatch::default()
    }
}

fn invalid_normalization_batch(cgroup_id: u64) -> DaemonObserverBatch {
    let mut batch = file_outcome_batch(cgroup_id);
    batch.events[0].record.event_kind = u32::MAX;
    batch
}

fn file_and_process_drain_batch(cgroup_id: u64, path: &str) -> DaemonObserverBatch {
    let mut batch = file_outcome_batch_for_path(cgroup_id, path);
    let mut process = batch.events[0].clone();
    process.record.event_kind = KernelEventKind::Exec as u32;
    process.record.flags = 0;
    process.record.return_value = 0;
    process.record.resource = [0; RESOURCE_LEN];
    process.record.resource[..13].copy_from_slice(b"/usr/bin/test");
    process.record.action = [0; ACTION_LEN];
    process.record.action[..4].copy_from_slice(b"exec");
    batch.events.push(process);
    batch
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

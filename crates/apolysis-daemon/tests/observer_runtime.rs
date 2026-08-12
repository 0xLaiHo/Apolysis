// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::future::{pending, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::{
    project_agent_run, validate_agent_observation_record_v1, ActionClass, AdapterKind,
    AgentRunRecordBatch, ComponentState, QueuePriority, ResourceKind, ResourceSelector,
    SessionIntent,
};
use apolysis_core::CollectorCapabilityManifest;
use apolysis_daemon::{
    ingest_observer_batch, run_observer_runtime, scope_channel, CgroupIdentity, DaemonConfig,
    DaemonRecord, DaemonState, ObserverRuntimeBackend, RuntimeBinding, RuntimeInventory,
    RuntimeSourceGapReason, RuntimeWorkloadIdentity, ScopeOperation,
};
use apolysis_observer::abi::{
    KernelEventKind, KernelEventRecord, ACTION_LEN, COMM_LEN, FLAG_RETURN_VALUE,
    KERNEL_ABI_VERSION, KERNEL_EVENT_RECORD_LEN, PAYLOAD_LEN, RESOURCE_LEN,
};
use apolysis_observer::{
    audit_observer_capability_manifest, AyaLoaderPlan, DaemonKernelEvent, DaemonObserverBatch,
    DaemonObserverCounters, FileOperationCounters, LiveScope, NetworkConnectCounters,
    OperationPairCounters, ScopeGeneration, ScopeObservationGapCounters,
};
use apolysis_store::ChainRecord;
use tokio::sync::oneshot;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn runtime_inventory_enriches_kernel_observation_with_verified_container_identity() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-container"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![RuntimeBinding {
                agent_run_id: "agent-run-container".to_string(),
                identity: RuntimeWorkloadIdentity {
                    adapter: AdapterKind::Docker,
                    workload_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                    start_marker: "2026-08-11T01:02:03Z".to_string(),
                    host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
                    init_process_start_time_ticks: 42,
                    cgroup: CgroupIdentity {
                        device: 7,
                        inode: 707,
                    },
                },
                runtime_handler: Some("runc".to_string()),
            }],
        ))
        .await
        .expect("reconcile complete runtime inventory");
    let pipeline = state.pipeline();
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };

    let summary = ingest_observer_batch(&state, &pipeline, file_outcome_batch(707))
        .await
        .expect("ingest container-scoped kernel observation");
    assert!(summary.submitted >= 1);
    pipeline.fence().await.expect("flush observation");
    writer_shutdown.send(()).expect("stop writer");
    writer.await.unwrap().expect("drain writer");

    let timeline = timeline(&config, "agent-run-container");
    assert!(timeline.contains(
        r#""container_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#
    ));
    assert!(timeline.contains(r#""cgroup_id":"707""#));
    cleanup(&config);
}

#[tokio::test]
async fn runtime_untrack_drain_keeps_verified_container_identity() {
    let config = config();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let backend = FakeBackend {
        operations: Arc::clone(&operations),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: Some(file_outcome_batch(708)),
        scoped_counters: BTreeMap::new(),
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
        .register(intent("agent-run-container-drain"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![RuntimeBinding {
                agent_run_id: "agent-run-container-drain".to_string(),
                identity: RuntimeWorkloadIdentity {
                    adapter: AdapterKind::Docker,
                    workload_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                    start_marker: "2026-08-11T01:02:03Z".to_string(),
                    host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
                    init_process_start_time_ticks: 42,
                    cgroup: CgroupIdentity {
                        device: 7,
                        inode: 708,
                    },
                },
                runtime_handler: Some("runc".to_string()),
            }],
        ))
        .await
        .expect("track runtime binding");

    state
        .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, Vec::new()))
        .await
        .expect("retire runtime binding after draining its scope");

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("drain writer");
    assert_eq!(
        *operations.lock().unwrap(),
        vec![(ScopeOperation::Track, 708), (ScopeOperation::Untrack, 708)]
    );
    let timeline = timeline(&config, "agent-run-container-drain");
    assert!(timeline.contains(
        r#""container_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#
    ));

    cleanup(&config);
}

#[tokio::test]
async fn pending_runtime_registration_refreshes_intent_without_retracking_or_restarting() {
    let config = config();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(4);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let pending = RuntimeBinding {
        agent_run_id: "agent-run-refresh-context".to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Docker,
            workload_id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            start_marker: "2026-08-11T01:02:03Z".to_string(),
            host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
            init_process_start_time_ticks: 42,
            cgroup: CgroupIdentity {
                device: 7,
                inode: 709,
            },
        },
        runtime_handler: Some("runc".to_string()),
    };
    let pending_reconcile = {
        let state = Arc::clone(&state);
        let pending = pending.clone();
        tokio::spawn(async move {
            state
                .reconcile_runtime_inventory(RuntimeInventory::new(
                    AdapterKind::Docker,
                    vec![pending],
                ))
                .await
        })
    };
    let request = receiver.recv().await.expect("pending Track request");
    assert_eq!(request.operation(), ScopeOperation::Track);
    assert!(request.agent_intent().is_none());
    request.complete(Ok(()));
    pending_reconcile
        .await
        .expect("pending reconcile task")
        .expect("pending reconcile");

    let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(1);
    let backend = ChannelBackend {
        operations: Arc::clone(&operations),
        batches: batch_receiver,
    };
    let pipeline = state.pipeline();
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let (observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, vec![709], receiver, state, observer_receiver).await
        })
    };
    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(state.health().await.ebpf(), ComponentState::Ready);

    state
        .register(intent("agent-run-refresh-context"), 1_700_000_000_000)
        .await
        .expect("register pending runtime Agent Run");
    assert_eq!(
        *operations.lock().unwrap(),
        vec![(ScopeOperation::Track, 709)],
        "context refresh must not call the eBPF backend"
    );
    batch_sender
        .send(file_outcome_batch(709))
        .await
        .expect("release post-refresh event");
    for _ in 0..100 {
        pipeline.fence().await.expect("flush current observations");
        if timeline(&config, "agent-run-refresh-context").contains("artifact.txt") {
            break;
        }
        tokio::task::yield_now().await;
    }
    let durable = timeline(&config, "agent-run-refresh-context");
    assert!(durable.contains("artifact.txt"));
    assert_eq!(durable.matches(r#""kind":"missing_intent""#).count(), 1);
    assert_eq!(durable.matches(r#""state":"started""#).count(), 1);

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("drain writer");
    cleanup(&config);
}

#[tokio::test]
async fn dynamically_tracked_agent_run_declares_capability_before_start_and_routes_events() {
    let config = config();
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(1);
    let backend = ChannelBackend {
        operations: Arc::clone(&operations),
        batches: batch_receiver,
    };
    let (scope, receiver) = scope_channel(2);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let pipeline = state.pipeline();
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
    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(state.health().await.ebpf(), ComponentState::Ready);

    state
        .register(
            intent_with_workspace("agent-run-dynamic-boundary", "/workspace"),
            1_700_000_000_000,
        )
        .await
        .expect("register dynamic Agent Run");
    state
        .discover_cgroup("agent-run-dynamic-boundary", 710)
        .await
        .expect("dynamically track Agent Run cgroup");
    batch_sender
        .send(file_outcome_batch_for_path(710, "/workspace/dynamic.txt"))
        .await
        .expect("release first dynamically scoped event");
    for _ in 0..100 {
        pipeline.fence().await.expect("flush dynamic observation");
        if timeline(&config, "agent-run-dynamic-boundary").contains("/workspace/dynamic.txt") {
            break;
        }
        tokio::task::yield_now().await;
    }

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("drain writer");
    let durable = timeline(&config, "agent-run-dynamic-boundary");
    cleanup(&config);

    assert_eq!(
        *operations.lock().unwrap(),
        vec![(ScopeOperation::Track, 710), (ScopeOperation::Untrack, 710)]
    );
    let capability = durable
        .find(r#""record_type":"collector_capability_manifest""#)
        .expect("dynamic Collector Capability manifest");
    let started = durable
        .find(r#""state":"started""#)
        .expect("dynamic collector start");
    let event = durable
        .find("/workspace/dynamic.txt")
        .expect("first dynamically scoped event");
    assert!(capability < started);
    assert!(started < event);
    assert_eq!(
        durable
            .matches(r#""record_type":"collector_capability_manifest""#)
            .count(),
        1
    );
}

#[tokio::test]
async fn runtime_source_recovery_keeps_one_collector_lifecycle_until_daemon_shutdown() {
    let config = config();
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
    let agent_run_id = "agent-run-runtime-recovery";
    state
        .register(intent(agent_run_id), 1_700_000_000_000)
        .await
        .expect("register runtime Agent Run");
    let binding = runtime_binding(agent_run_id, 711);
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![binding.clone()],
        ))
        .await
        .expect("attach runtime scope");
    state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("suspend runtime scope during source outage");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, vec![binding]))
        .await
        .expect("reattach runtime scope after source recovery");

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("drain writer");

    let durable = timeline(&config, agent_run_id);
    assert_eq!(
        durable
            .matches(r#""record_type":"collector_capability_manifest""#)
            .count(),
        1
    );
    assert_eq!(durable.matches(r#""state":"started""#).count(), 1);
    assert_eq!(
        durable
            .matches(r#""stop_reason":"agent_run_closed""#)
            .count(),
        0
    );
    assert_eq!(
        durable
            .matches(r#""stop_reason":"daemon_shutdown""#)
            .count(),
        1
    );
    assert_eq!(
        *operations.lock().unwrap(),
        vec![
            (ScopeOperation::Track, 711),
            (ScopeOperation::Untrack, 711),
            (ScopeOperation::Track, 711),
            (ScopeOperation::Untrack, 711),
        ]
    );
    let projected = project_agent_run([AgentRunRecordBatch::verified_hash_chain(
        timeline_payloads(&durable),
    )])
    .expect("source recovery timeline must have a valid collector lifecycle");
    validate_agent_observation_record_v1(&projected)
        .expect("source recovery Agent Observation Record must remain valid");
    cleanup(&config);
}

#[tokio::test]
async fn daemon_shutdown_terminates_a_started_run_with_no_current_scope() {
    let config = config();
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
    let agent_run_id = "agent-run-zero-scope-shutdown";
    state
        .register(intent(agent_run_id), 1_700_000_000_000)
        .await
        .expect("register runtime Agent Run");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![runtime_binding(agent_run_id, 712)],
        ))
        .await
        .expect("attach runtime scope");
    state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("drain final recoverable scope");

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("drain writer");

    assert_eq!(
        *operations.lock().unwrap(),
        vec![(ScopeOperation::Track, 712), (ScopeOperation::Untrack, 712)]
    );
    let durable = timeline(&config, agent_run_id);
    assert_eq!(durable.matches(r#""state":"started""#).count(), 1);
    assert_eq!(
        durable
            .matches(r#""stop_reason":"agent_run_closed""#)
            .count(),
        0
    );
    assert_eq!(
        durable
            .matches(r#""stop_reason":"daemon_shutdown""#)
            .count(),
        1
    );
    let projected = project_agent_run([AgentRunRecordBatch::verified_hash_chain(
        timeline_payloads(&durable),
    )])
    .expect("zero-scope shutdown timeline must have a valid collector lifecycle");
    validate_agent_observation_record_v1(&projected)
        .expect("zero-scope shutdown Agent Observation Record must remain valid");
    cleanup(&config);
}

#[tokio::test]
async fn explicit_close_terminates_a_started_run_after_recoverable_scope_drain() {
    let config = config();
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
    let agent_run_id = "agent-run-zero-scope-close";
    state
        .register(intent(agent_run_id), 1_700_000_000_000)
        .await
        .expect("register runtime Agent Run");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![runtime_binding(agent_run_id, 713)],
        ))
        .await
        .expect("attach runtime scope");
    state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("drain final recoverable scope");
    state
        .close(agent_run_id)
        .await
        .expect("explicitly close zero-scope Agent Run");

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("drain writer");

    assert_eq!(
        *operations.lock().unwrap(),
        vec![(ScopeOperation::Track, 713), (ScopeOperation::Untrack, 713)]
    );
    let durable = timeline(&config, agent_run_id);
    assert_eq!(durable.matches(r#""state":"started""#).count(), 1);
    assert_eq!(
        durable
            .matches(r#""stop_reason":"agent_run_closed""#)
            .count(),
        1
    );
    assert_eq!(
        durable.matches(r#""record_type":"session_closed""#).count(),
        1
    );
    assert_eq!(
        durable
            .matches(r#""stop_reason":"daemon_shutdown""#)
            .count(),
        0
    );
    let projected = project_agent_run([AgentRunRecordBatch::verified_hash_chain(
        timeline_payloads(&durable),
    )])
    .expect("zero-scope close timeline must have a valid collector lifecycle");
    validate_agent_observation_record_v1(&projected)
        .expect("zero-scope closed Agent Observation Record must remain valid");
    cleanup(&config);
}

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
    let gap_a = timeline_a
        .find(r#""record_type":"observation_gap""#)
        .unwrap();
    let stopped_a = timeline_a.find(r#""state":"stopped""#).unwrap();
    assert!(timeline_a.contains(r#""stop_reason":"daemon_shutdown""#));
    assert!(gap_a < stopped_a);

    let timeline_b = timeline(&config, "agent-run-b");
    assert!(timeline_b.contains(r#""record_type":"observation_gap""#));
    assert!(timeline_b.contains(r#""agent_run_id":"agent-run-b""#));
    assert!(timeline_b.contains(r#""kind":"missing_exit""#));
    assert!(timeline_b.contains(r#""count":3"#));
    assert!(!timeline_b.contains("agent-run-a"));
    assert!(!timeline_b.contains(r#""kind":"missing_entry""#));
    let gap_b = timeline_b
        .find(r#""record_type":"observation_gap""#)
        .unwrap();
    let stopped_b = timeline_b.find(r#""state":"stopped""#).unwrap();
    assert!(timeline_b.contains(r#""stop_reason":"daemon_shutdown""#));
    assert!(gap_b < stopped_b);

    cleanup(&config);
}

#[tokio::test]
async fn observer_runtime_persists_periodic_global_and_scope_loss_checkpoints() {
    let mut config = config();
    config.collector_checkpoint_interval = std::time::Duration::from_millis(1);
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: None,
        scoped_counters: BTreeMap::from([(
            31,
            ScopeObservationGapCounters {
                network_connect: NetworkConnectCounters {
                    missing_entries: 13,
                    missing_exits: 17,
                    pending: 19,
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
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, shutdown_receiver).await
        })
    };

    state
        .register(intent("agent-run-checkpoint"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-checkpoint", 31)
        .await
        .expect("associate cgroup");
    let mut observed = String::new();
    for _ in 0..100 {
        observed = timeline(&config, "agent-run-checkpoint");
        if observed.contains(r#""state":"checkpoint""#) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }

    assert!(observed.contains(r#""state":"checkpoint""#));
    assert!(observed.contains(r#""health":"degraded""#));
    assert!(observed.contains(r#""global_reserve_failures":3"#));
    assert!(observed.contains(r#""global_map_pressure":2"#));
    assert!(observed.contains(r#""scope_missing_entries":13"#));
    assert!(observed.contains(r#""scope_missing_exits":17"#));
    assert!(observed.contains(r#""scope_pending":19"#));

    shutdown.send(()).expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("clean writer shutdown");
    cleanup(&config);
}

#[tokio::test]
async fn failed_terminal_preserves_the_last_cumulative_checkpoint() {
    let mut config = config();
    config.collector_checkpoint_interval = std::time::Duration::from_millis(1);
    let release_failure = Arc::new(tokio::sync::Notify::new());
    let backend = CheckpointFailureBackend {
        release_failure: Arc::clone(&release_failure),
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
    let (_observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };
    state
        .register(intent("agent-run-checkpoint-failure"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-checkpoint-failure", 91)
        .await
        .expect("associate cgroup");
    for _ in 0..100 {
        if timeline(&config, "agent-run-checkpoint-failure").contains(r#""state":"checkpoint""#) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    release_failure.notify_one();
    runtime
        .await
        .unwrap()
        .expect_err("released ABI failure must stop observer");

    let timeline = timeline(&config, "agent-run-checkpoint-failure");
    let failed = timeline
        .lines()
        .find(|line| line.contains(r#""state":"failed""#))
        .expect("failed lifecycle terminal");
    assert!(failed.contains(r#""global_reserve_failures":3"#));
    assert!(failed.contains(r#""global_map_pressure":2"#));
    assert!(failed.contains(r#""scope_missing_entries":13"#));

    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
    cleanup(&config);
}

#[tokio::test]
async fn empty_checkpoint_drain_waits_for_previously_admitted_evidence() {
    let mut config = config();
    config.collector_checkpoint_interval = std::time::Duration::from_millis(1);
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (scope, receiver) = scope_channel(2);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let (observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };
    state
        .register(intent("agent-run-checkpoint-fence"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-checkpoint-fence", 92)
        .await
        .expect("associate cgroup");
    state
        .pipeline()
        .submit(DaemonRecord::new(
            "agent-run-checkpoint-fence",
            QueuePriority::Ordinary,
            serde_json::json!({"record_type":"admitted_before_checkpoint"}),
        ))
        .expect("admit evidence");

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(!timeline(&config, "agent-run-checkpoint-fence").contains(r#""state":"checkpoint""#));

    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    for _ in 0..100 {
        if timeline(&config, "agent-run-checkpoint-fence").contains(r#""state":"checkpoint""#) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");

    let timeline = timeline(&config, "agent-run-checkpoint-fence");
    let evidence = timeline.find("admitted_before_checkpoint").unwrap();
    let checkpoint = timeline.find(r#""state":"checkpoint""#).unwrap();
    assert!(evidence < checkpoint);
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
    assert!(!timeline_a.lines().any(|line| {
        line.contains(r#""record_type":"observation_gap""#)
            && line.contains(r#""operation":"file_rename""#)
    }));
    assert!(!timeline_a.contains("agent-run-file-b"));

    let timeline_b = timeline(&config, "agent-run-file-b");
    assert!(timeline_b.contains(r#""operation":"file_rename""#));
    assert!(timeline_b.contains(r#""kind":"missing_exit""#));
    assert!(timeline_b.contains(r#""count":3"#));
    assert!(!timeline_b.lines().any(|line| {
        line.contains(r#""record_type":"observation_gap""#)
            && line.contains(r#""operation":"file_open""#)
    }));
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

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(!runtime.is_finished());
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };

    let error = runtime
        .await
        .unwrap()
        .expect_err("dropped Observation Gap must fail scope drain");
    assert!(error.contains("Observation Gap"));
    assert!(error.contains("dropped"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    assert!(timeline(&config, "agent-run-gap-drop").contains(r#""state":"failed""#));
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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

    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, vec![52], receiver, state, shutdown_receiver).await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(!runtime.is_finished());
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let error = runtime
        .await
        .unwrap()
        .expect_err("dropped file outcome must fail loud");

    assert!(error.contains("dropped"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    assert!(timeline(&config, "agent-run-outcome-drop").contains(r#""state":"failed""#));
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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
        batch: Some(partially_invalid_normalization_batch(53)),
        drain_batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (_scope, receiver) = scope_channel(1);
    let (_shutdown, shutdown_receiver) = oneshot::channel();

    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, vec![53], receiver, state, shutdown_receiver).await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        !runtime.is_finished(),
        "failed terminal overtook admitted evidence without writer confirmation"
    );
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let error = runtime
        .await
        .unwrap()
        .expect_err("normalization failure must fail queued ingest");

    assert!(error.contains("failed to normalize observer record"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    let timeline = timeline(&config, "agent-run-normalize");
    assert!(timeline.contains(r#""state":"failed""#));
    assert!(timeline.contains(r#""health":"failed""#));
    assert!(timeline.contains(r#""stop_reason":"decode_failure""#));
    let event = timeline
        .find(r#""record_type":"raw_kernel_event""#)
        .unwrap();
    let terminal = timeline.find(r#""state":"failed""#).unwrap();
    assert!(event < terminal);
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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
    let timeline_after_track = timeline(&config, "agent-run-close");
    assert!(timeline_after_track.contains(r#""record_type":"collector_lifecycle""#));
    assert!(timeline_after_track.contains(r#""state":"started""#));
    assert!(timeline_after_track.contains(r#""health":"healthy""#));
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
    let lifecycle_terminal_index = timeline_after_close
        .find(r#""state":"stopped""#)
        .expect("collector terminal is durable before close returns");
    assert_eq!(
        timeline_after_close
            .matches(r#""stop_reason":"agent_run_closed""#)
            .count(),
        1
    );
    assert_eq!(
        timeline_after_close
            .matches(r#""record_type":"session_closed""#)
            .count(),
        1
    );
    assert!(outcome_index < lifecycle_terminal_index);
    assert!(process_index < lifecycle_terminal_index);
    assert!(gap_index < lifecycle_terminal_index);
    assert!(lifecycle_terminal_index < close_index);
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
    let projected = project_agent_run([AgentRunRecordBatch::verified_hash_chain(
        timeline_payloads(&timeline),
    )])
    .expect("closed Agent Run timeline must have a valid collector lifecycle");
    validate_agent_observation_record_v1(&projected)
        .expect("closed Agent Observation Record must remain valid");
    assert!(timeline.contains(r#""operation":"file_open""#));
    assert!(timeline.contains(r#""kind":"missing_entry""#));
    assert!(timeline.contains(r#""count":1"#));

    cleanup(&config);
}

#[tokio::test]
async fn collector_terminal_waits_for_previously_admitted_evidence_when_drain_is_empty() {
    let config = config();
    let backend = FakeBackend {
        operations: Arc::new(Mutex::new(Vec::new())),
        fail_counters: false,
        fail_track: None,
        fail_untrack: None,
        batch: None,
        drain_batch: None,
        scoped_counters: BTreeMap::new(),
    };
    let (scope, receiver) = scope_channel(2);
    let state = Arc::new(
        DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state with scope"),
    );
    let (observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(backend, Vec::new(), receiver, state, observer_receiver).await
        })
    };
    state
        .register(intent("agent-run-terminal-fence"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-terminal-fence", 81)
        .await
        .expect("associate cgroup");
    assert_eq!(
        state
            .pipeline()
            .submit(DaemonRecord::new(
                "agent-run-terminal-fence",
                QueuePriority::Ordinary,
                serde_json::json!({"record_type":"admitted_before_terminal"}),
            ))
            .expect("admit evidence"),
        apolysis_accountability::PushOutcome::Accepted
    );

    let close = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.close("agent-run-terminal-fence").await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        !close.is_finished(),
        "close completed before admitted evidence had a writer confirmation"
    );

    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), close)
        .await
        .expect("terminal fence completes after writer starts")
        .expect("close task")
        .expect("clean close");

    observer_shutdown
        .send(())
        .expect("request observer shutdown");
    runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");

    let timeline = timeline(&config, "agent-run-terminal-fence");
    let evidence = timeline.find("admitted_before_terminal").unwrap();
    let terminal = timeline.find(r#""state":"stopped""#).unwrap();
    assert!(evidence < terminal);
    cleanup(&config);
}

#[tokio::test]
async fn counter_read_failure_marks_ebpf_unavailable() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-counter-failure"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-counter-failure", 31)
        .await
        .expect("associate cgroup");
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
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
            run_observer_runtime(backend, vec![31], receiver, state, shutdown_receiver).await
        })
    };

    for _ in 0..100 {
        if state.health().await.ebpf() == ComponentState::Ready {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        timeline(&config, "agent-run-counter-failure").contains(r#""state":"started""#),
        "eBPF readiness must not precede a durable collector start"
    );
    shutdown.send(()).unwrap();
    let error = runtime.await.unwrap().expect_err("counter read must fail");

    assert!(error.contains("counter read failed"));
    assert_eq!(state.health().await.ebpf(), ComponentState::Unavailable);
    let timeline = timeline(&config, "agent-run-counter-failure");
    assert!(timeline.contains(r#""state":"failed""#));
    assert!(timeline.contains(r#""health":"failed""#));
    assert!(timeline.contains(r#""stop_reason":"counter_read_failure""#));
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
    cleanup(&config);
}

#[tokio::test]
async fn restored_scope_failure_keeps_ebpf_unavailable() {
    let config = config();
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-restore-failure"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-restore-failure", 31)
        .await
        .expect("associate cgroup");
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
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
    let timeline = timeline(&config, "agent-run-restore-failure");
    assert!(timeline.contains(r#""state":"failed""#));
    assert!(timeline.contains(r#""stop_reason":"observer_failure""#));
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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
    state
        .register(intent("agent-run-abi-mismatch"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    state
        .discover_cgroup("agent-run-abi-mismatch", 31)
        .await
        .expect("associate cgroup");
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
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
            vec![31],
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
    let timeline = timeline(&config, "agent-run-abi-mismatch");
    assert!(timeline.contains(r#""state":"started""#));
    assert!(timeline.contains(r#""state":"failed""#));
    assert!(timeline.contains(r#""health":"failed""#));
    assert!(timeline.contains(r#""stop_reason":"abi_mismatch""#));
    assert!(timeline.contains(r#""global_abi_mismatches":1"#));
    writer_shutdown.send(()).expect("request writer shutdown");
    writer.await.unwrap().expect("writer drain");
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

struct ChannelBackend {
    operations: Arc<Mutex<Vec<(ScopeOperation, u64)>>>,
    batches: tokio::sync::mpsc::Receiver<DaemonObserverBatch>,
}

struct ReuseBackend {
    operations: Arc<Mutex<Vec<(ScopeOperation, u64)>>>,
    stale_batch: Option<DaemonObserverBatch>,
}

struct CheckpointFailureBackend {
    release_failure: Arc<tokio::sync::Notify>,
}

impl ObserverRuntimeBackend for CheckpointFailureBackend {
    fn capability_manifest(
        &self,
        agent_run_id: &str,
        cgroup_id: u64,
    ) -> CollectorCapabilityManifest {
        test_capability_manifest(agent_run_id, cgroup_id)
    }

    fn track_cgroup(&mut self, _cgroup_id: u64) -> Result<ScopeGeneration, String> {
        ScopeGeneration::new(1)
    }

    fn untrack_cgroup(&mut self, _cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        Ok(ScopeObservationGapCounters::default())
    }

    fn scope_counters(&mut self, _cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        Ok(ScopeObservationGapCounters {
            network_connect: NetworkConnectCounters {
                missing_entries: 13,
                ..NetworkConnectCounters::default()
            },
            ..ScopeObservationGapCounters::default()
        })
    }

    fn drain_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        Ok(DaemonObserverBatch::default())
    }

    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>> {
        let release_failure = Arc::clone(&self.release_failure);
        Box::pin(async move {
            release_failure.notified().await;
            Ok(DaemonObserverBatch {
                abi_mismatches: 1,
                ..DaemonObserverBatch::default()
            })
        })
    }

    fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        Ok(DaemonObserverCounters {
            reserve_failures: 3,
            map_pressure: 2,
            ..DaemonObserverCounters::default()
        })
    }
}

impl ObserverRuntimeBackend for ChannelBackend {
    fn capability_manifest(
        &self,
        agent_run_id: &str,
        cgroup_id: u64,
    ) -> CollectorCapabilityManifest {
        test_capability_manifest(agent_run_id, cgroup_id)
    }

    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeGeneration, String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Track, cgroup_id));
        ScopeGeneration::new(1)
    }

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        self.operations
            .lock()
            .unwrap()
            .push((ScopeOperation::Untrack, cgroup_id));
        Ok(ScopeObservationGapCounters::default())
    }

    fn scope_counters(&mut self, _cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        Ok(ScopeObservationGapCounters::default())
    }

    fn drain_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        Ok(DaemonObserverBatch::default())
    }

    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>> {
        Box::pin(async move {
            self.batches
                .recv()
                .await
                .ok_or_else(|| "test batch channel closed".to_string())
        })
    }

    fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        Ok(DaemonObserverCounters::default())
    }
}

impl ObserverRuntimeBackend for ReuseBackend {
    fn capability_manifest(
        &self,
        agent_run_id: &str,
        cgroup_id: u64,
    ) -> CollectorCapabilityManifest {
        test_capability_manifest(agent_run_id, cgroup_id)
    }

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

    fn scope_counters(&mut self, _cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
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
    fn capability_manifest(
        &self,
        agent_run_id: &str,
        cgroup_id: u64,
    ) -> CollectorCapabilityManifest {
        test_capability_manifest(agent_run_id, cgroup_id)
    }

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

    fn scope_counters(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        if self.fail_untrack == Some(cgroup_id) {
            return Err("scoped counter read failed".to_string());
        }
        Ok(self
            .scoped_counters
            .get(&cgroup_id)
            .copied()
            .unwrap_or_default())
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

fn test_capability_manifest(agent_run_id: &str, cgroup_id: u64) -> CollectorCapabilityManifest {
    audit_observer_capability_manifest(
        agent_run_id,
        &LiveScope::Cgroup(cgroup_id),
        &AyaLoaderPlan::audit_observer_default("test-observer.o"),
    )
}

fn runtime_binding(agent_run_id: &str, cgroup_id: u64) -> RuntimeBinding {
    RuntimeBinding {
        agent_run_id: agent_run_id.to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Docker,
            workload_id: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
            start_marker: "2026-08-11T01:02:03Z".to_string(),
            host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
            init_process_start_time_ticks: 42,
            cgroup: CgroupIdentity {
                device: 7,
                inode: cgroup_id,
            },
        },
        runtime_handler: Some("runc".to_string()),
    }
}

fn timeline_payloads(timeline: &str) -> Vec<serde_json::Value> {
    timeline
        .lines()
        .map(|line| {
            serde_json::from_str::<ChainRecord>(line)
                .expect("decode durable hash-chain record")
                .payload
        })
        .collect()
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
        kubernetes_claims: Vec::new(),
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

fn partially_invalid_normalization_batch(cgroup_id: u64) -> DaemonObserverBatch {
    let mut batch = file_outcome_batch(cgroup_id);
    let mut invalid = batch.events[0].clone();
    invalid.record.event_kind = u32::MAX;
    batch.events.push(invalid);
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

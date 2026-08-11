// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::{
    ActionClass, AdapterKind, ComponentState, RetentionTier, SessionIntent, DEFAULT_TENANT_ID,
};
use apolysis_daemon::{
    scope_channel, CgroupIdentity, DaemonConfig, DaemonState, RuntimeBinding, RuntimeInventory,
    RuntimeSourceGapReason, RuntimeWorkloadIdentity, ScopeOperation,
};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const BOOT_ID: &str = "82b46386-b87a-4d86-93f6-232bb04c37fb";

#[tokio::test]
async fn complete_runtime_inventory_is_idempotent_and_rebinds_changed_identity() {
    let config = config("reconcile");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("agent-run-runtime"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let first = binding("agent-run-runtime", "container-a", "start-a", 41, 101);

    let first_result = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![first.clone()],
        ))
        .await
        .expect("reconcile first complete inventory");
    assert_eq!(first_result.summary.attached, 1);
    assert_eq!(
        state.session_for_cgroup(101).await.as_deref(),
        Some("agent-run-runtime")
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-runtime")
            .await,
        vec![first]
    );

    let repeated = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![binding(
                "agent-run-runtime",
                "container-a",
                "start-a",
                41,
                101,
            )],
        ))
        .await
        .expect("reconcile identical complete inventory");
    assert_eq!(repeated.summary.unchanged, 1);
    assert_eq!(
        timeline(&config, "agent-run-runtime")
            .matches("runtime_binding_observed")
            .count(),
        1
    );

    let replacement = binding("agent-run-runtime", "container-a", "start-b", 84, 202);
    let transition = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![replacement.clone()],
        ))
        .await
        .expect("reconcile changed stable identity proof");
    assert_eq!(transition.summary.gaps, 1);
    assert_eq!(transition.summary.retired, 1);
    assert_eq!(transition.summary.attached, 1);
    assert_eq!(state.session_for_cgroup(101).await, None);
    assert_eq!(
        state.session_for_cgroup(202).await.as_deref(),
        Some("agent-run-runtime")
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-runtime")
            .await,
        vec![replacement]
    );
    let timeline = timeline(&config, "agent-run-runtime");
    assert!(timeline.contains("reason=identity_transition"));
    assert!(timeline.contains("runtime_binding_retired"));

    cleanup(&config);
}

#[tokio::test]
async fn tenant_query_returns_the_agent_run_and_runtime_bindings_from_one_snapshot() {
    let config = config("tenant-binding-query");
    let state = DaemonState::new(&config).expect("daemon state");
    let agent_run_id = "agent-run-tenant-binding";
    let mut tenant_a_intent = intent(agent_run_id);
    tenant_a_intent.tenant_id = "tenant-a".to_string();
    state
        .register(tenant_a_intent, 1_700_000_000_000)
        .await
        .expect("register tenant-a Agent Run");
    let runtime_binding = binding(agent_run_id, "container-tenant", "start-a", 41, 107);
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![runtime_binding.clone()],
        ))
        .await
        .expect("observe tenant-a runtime binding");

    let (tenant_a_session, tenant_a_bindings) = state
        .query_with_runtime_bindings_for_tenant(agent_run_id, "tenant-a")
        .await;
    assert_eq!(
        tenant_a_session
            .expect("tenant-a owns the Agent Run")
            .intent
            .tenant_id,
        "tenant-a"
    );
    assert_eq!(tenant_a_bindings, vec![runtime_binding.clone()]);

    let (cross_tenant_session, cross_tenant_bindings) = state
        .query_with_runtime_bindings_for_tenant(agent_run_id, "tenant-b")
        .await;
    assert!(cross_tenant_session.is_none());
    assert!(cross_tenant_bindings.is_empty());

    let mut tenant_b_intent = intent(agent_run_id);
    tenant_b_intent.tenant_id = "tenant-b".to_string();
    state
        .register(tenant_b_intent, 1_700_000_000_000)
        .await
        .expect("replace ownership with tenant-b");

    let (stale_tenant_session, stale_tenant_bindings) = state
        .query_with_runtime_bindings_for_tenant(agent_run_id, "tenant-a")
        .await;
    assert!(stale_tenant_session.is_none());
    assert!(stale_tenant_bindings.is_empty());
    let (tenant_b_session, tenant_b_bindings) = state
        .query_with_runtime_bindings_for_tenant(agent_run_id, "tenant-b")
        .await;
    assert_eq!(
        tenant_b_session
            .expect("tenant-b owns the Agent Run")
            .intent
            .tenant_id,
        "tenant-b"
    );
    assert_eq!(tenant_b_bindings, vec![runtime_binding]);

    cleanup(&config);
}

#[tokio::test]
async fn unsafe_runtime_identity_is_rejected_before_storage_or_scope_mutation() {
    let config = config("unsafe-runtime-identity");
    let state = DaemonState::new(&config).expect("daemon state");
    let mut unsafe_agent_run = binding(
        "agent-run-placeholder",
        "container-unsafe",
        "start-unsafe",
        41,
        109,
    );
    unsafe_agent_run.agent_run_id = "../private-run".to_string();
    let mut unsafe_workload = binding(
        "agent-run-placeholder",
        "container-unsafe",
        "start-unsafe",
        41,
        109,
    );
    unsafe_workload.identity.workload_id =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let mut unsafe_marker = binding(
        "agent-run-placeholder",
        "container-unsafe",
        "start-unsafe",
        41,
        109,
    );
    unsafe_marker.identity.start_marker = "private-alternate-marker".to_string();

    for (unsafe_binding, expected_field) in [
        (unsafe_agent_run, "agent_run_id"),
        (unsafe_workload, "workload_id"),
        (unsafe_marker, "start_marker"),
    ] {
        let error = state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![unsafe_binding],
            ))
            .await
            .expect_err("unsafe runtime identity must fail before persistence");
        assert!(
            error.contains(&format!("field={expected_field}")),
            "{error}"
        );
    }

    assert_eq!(state.health().await.storage(), ComponentState::Ready);
    assert!(!config.state_dir.join("private-run").exists());
    state
        .register(intent("agent-run-still-writable"), 1_700_000_000_000)
        .await
        .expect("unrelated Agent Run storage remains writable");
    assert!(timeline(&config, "agent-run-still-writable").contains("intent_registered"));

    cleanup(&config);
}

#[tokio::test]
async fn complete_inventory_keeps_valid_bindings_when_an_agent_run_is_not_registered_yet() {
    let config = config("missing-intent");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("agent-run-known"), 1_700_000_000_000)
        .await
        .expect("register known Agent Run");
    let known = binding("agent-run-known", "container-known", "start-a", 41, 111);
    let pending = binding("agent-run-pending", "container-pending", "start-b", 42, 222);

    let first = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![known.clone(), pending.clone()],
        ))
        .await
        .expect("complete inventory with one missing intent");

    assert_eq!(first.summary.attached, 1);
    assert_eq!(first.summary.missing_intent, 1);
    assert_eq!(
        state.session_for_cgroup(111).await.as_deref(),
        Some("agent-run-known")
    );
    assert_eq!(
        state.session_for_cgroup(222).await.as_deref(),
        Some("agent-run-pending")
    );

    state
        .register(intent("agent-run-pending"), 1_700_000_000_000)
        .await
        .expect("register pending Agent Run");
    let second = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![known, pending],
        ))
        .await
        .expect("fresh complete inventory after registration");
    assert_eq!(second.summary.unchanged, 2);
    assert_eq!(second.summary.attached, 0);
    assert_eq!(second.summary.missing_intent, 0);
    assert_eq!(
        state.session_for_cgroup(222).await.as_deref(),
        Some("agent-run-pending")
    );

    cleanup(&config);
}

#[tokio::test]
async fn missing_intent_binding_is_observed_once_and_a_later_absence_retires_pending_scope() {
    let config = config("missing-intent-lifecycle");
    let state = DaemonState::new(&config).expect("daemon state");
    let pending = binding(
        "agent-run-pending-lifecycle",
        "container-pending-lifecycle",
        "start-pending",
        42,
        223,
    );

    let first = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![pending.clone()],
        ))
        .await
        .expect("observe complete inventory before intent registration");
    assert_eq!(first.summary.attached, 0);
    assert_eq!(first.summary.missing_intent, 1);
    assert_eq!(
        state.session_for_cgroup(223).await.as_deref(),
        Some("agent-run-pending-lifecycle")
    );

    let repeated = state
        .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, vec![pending]))
        .await
        .expect("identical pending inventory is a no-op");
    assert_eq!(repeated.summary.unchanged, 1);
    assert_eq!(repeated.summary.missing_intent, 0);
    let pending_timeline = timeline(&config, "agent-run-pending-lifecycle");
    assert_eq!(
        pending_timeline.matches("runtime_binding_observed").count(),
        1
    );
    assert_eq!(
        pending_timeline.matches("accountability_finding").count(),
        1
    );
    assert_eq!(
        pending_timeline
            .matches(r#""kind":"missing_intent""#)
            .count(),
        1
    );
    let observed_ordinal = pending_timeline
        .find(r#""record_type":"runtime_binding_observed""#)
        .expect("durable observed runtime binding");
    let finding_ordinal = pending_timeline
        .find(r#""record_type":"accountability_finding""#)
        .expect("durable missing-intent Finding");
    assert!(observed_ordinal < finding_ordinal);
    assert!(pending_timeline.contains(&format!(
        r#""evidence_ref":"runtime_binding:{}""#,
        test_container_id("container-pending-lifecycle")
    )));

    let absent = state
        .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, Vec::new()))
        .await
        .expect("successful absence retires pending runtime binding");
    assert_eq!(absent.summary.retired, 1);
    assert_eq!(absent.summary.missing_intent, 0);
    assert_eq!(state.session_for_cgroup(223).await, None);
    assert!(state
        .runtime_bindings_for_agent_run("agent-run-pending-lifecycle")
        .await
        .is_empty());

    cleanup(&config);
}

#[tokio::test]
async fn missing_intent_binding_restarts_dormant_then_requalifies_pending_until_registration() {
    let config = config("missing-intent-restart");
    let pending = binding(
        "agent-run-pending-restart",
        "container-pending-restart",
        "start-pending",
        42,
        225,
    );
    {
        let state = DaemonState::new(&config).expect("daemon state");
        let first = state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![pending.clone()],
            ))
            .await
            .expect("persist missing-intent binding");
        assert_eq!(first.summary.missing_intent, 1);
    }

    let restarted = DaemonState::new(&config).expect("restart daemon state");
    assert!(restarted
        .runtime_bindings_for_agent_run("agent-run-pending-restart")
        .await
        .is_empty());
    let recovered = restarted
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![pending.clone()],
        ))
        .await
        .expect("fresh inventory requalifies missing-intent dormant binding");
    assert_eq!(recovered.summary.gaps, 1);
    assert_eq!(recovered.summary.retired, 1);
    assert_eq!(recovered.summary.attached, 0);
    assert_eq!(recovered.summary.missing_intent, 1);
    assert!(restarted.query("agent-run-pending-restart").await.is_none());
    assert_eq!(
        restarted.session_for_cgroup(225).await.as_deref(),
        Some("agent-run-pending-restart")
    );

    restarted
        .register(intent("agent-run-pending-restart"), 1_700_000_000_000)
        .await
        .expect("register intent and promote recovered pending binding");
    assert_eq!(
        restarted
            .query("agent-run-pending-restart")
            .await
            .expect("registered Agent Run")
            .cgroup_ids,
        vec![225]
    );
    assert_eq!(
        restarted
            .runtime_bindings_for_agent_run("agent-run-pending-restart")
            .await,
        vec![pending]
    );
    let durable = timeline(&config, "agent-run-pending-restart");
    assert_eq!(durable.matches("reason=daemon_restart").count(), 1);
    assert_eq!(durable.matches("runtime_binding_retired").count(), 1);
    assert_eq!(durable.matches("runtime_binding_observed").count(), 2);

    cleanup(&config);
}

#[tokio::test]
async fn registering_intent_promotes_a_pending_runtime_binding_without_rediscovery() {
    let config = config("missing-intent-register");
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(4);
    let worker_operations = Arc::clone(&operations);
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            worker_operations.lock().unwrap().push((
                request.operation(),
                request.runtime_container_id().map(str::to_string),
                request
                    .agent_intent()
                    .map(|intent| intent.session_id.clone()),
            ));
            request.complete(Ok(()));
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    let pending = binding(
        "agent-run-pending-register",
        "container-pending-register",
        "start-pending",
        42,
        224,
    );
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![pending.clone()],
        ))
        .await
        .expect("scope pending binding before intent registration");

    state
        .register(intent("agent-run-pending-register"), 1_700_000_000_000)
        .await
        .expect("register intent and promote pending cgroup");

    assert!(state.query("agent-run-pending-register").await.is_some());
    assert_eq!(
        state.session_for_cgroup(224).await.as_deref(),
        Some("agent-run-pending-register")
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-pending-register")
            .await,
        vec![pending]
    );
    assert_eq!(
        *operations.lock().unwrap(),
        vec![
            (
                ScopeOperation::Track,
                Some(test_container_id("container-pending-register")),
                None,
            ),
            (
                ScopeOperation::RefreshContext,
                Some(test_container_id("container-pending-register")),
                Some("agent-run-pending-register".to_string()),
            ),
        ]
    );

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn failed_pending_runtime_context_refresh_keeps_registry_and_timeline_pending() {
    let config = config("missing-intent-refresh-failure");
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(4);
    let worker_operations = Arc::clone(&operations);
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            worker_operations.lock().unwrap().push(request.operation());
            let result = if request.operation() == ScopeOperation::RefreshContext {
                Err("injected context refresh failure".to_string())
            } else {
                Ok(())
            };
            request.complete(result);
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    let pending = binding(
        "agent-run-refresh-failure",
        "container-refresh-failure",
        "start-pending",
        42,
        226,
    );
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![pending.clone()],
        ))
        .await
        .expect("track pending binding");

    let error = state
        .register(intent("agent-run-refresh-failure"), 1_700_000_000_000)
        .await
        .expect_err("failed refresh must reject registration");

    assert!(error.contains("injected context refresh failure"));
    assert!(state.query("agent-run-refresh-failure").await.is_none());
    assert_eq!(
        state.session_for_cgroup(226).await.as_deref(),
        Some("agent-run-refresh-failure")
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-refresh-failure")
            .await,
        vec![pending]
    );
    assert!(!timeline(&config, "agent-run-refresh-failure").contains("intent_registered"));
    assert_eq!(
        *operations.lock().unwrap(),
        vec![ScopeOperation::Track, ScopeOperation::RefreshContext]
    );

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn failed_intent_persistence_rolls_pending_runtime_context_back_to_no_intent() {
    let config = config("missing-intent-persist-rollback");
    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(4);
    let worker_operations = Arc::clone(&operations);
    let worker_config = config.clone();
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            let operation = request.operation();
            let intent = request
                .agent_intent()
                .map(|intent| intent.session_id.clone());
            worker_operations.lock().unwrap().push((operation, intent));
            if operation == ScopeOperation::RefreshContext && request.agent_intent().is_some() {
                replace_timeline_path(&worker_config, "agent-run-persist-rollback");
            }
            request.complete(Ok(()));
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    let pending = binding(
        "agent-run-persist-rollback",
        "container-persist-rollback",
        "start-pending",
        42,
        227,
    );
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![pending.clone()],
        ))
        .await
        .expect("track pending binding");

    let error = state
        .register(intent("agent-run-persist-rollback"), 1_700_000_000_000)
        .await
        .expect_err("replaced timeline must reject intent persistence");

    assert!(error.contains("timeline path changed"), "{error}");
    assert!(state.query("agent-run-persist-rollback").await.is_none());
    assert_eq!(
        state.session_for_cgroup(227).await.as_deref(),
        Some("agent-run-persist-rollback")
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-persist-rollback")
            .await,
        vec![pending]
    );
    assert_eq!(
        *operations.lock().unwrap(),
        vec![
            (ScopeOperation::Track, None),
            (
                ScopeOperation::RefreshContext,
                Some("agent-run-persist-rollback".to_string()),
            ),
            (ScopeOperation::RefreshContext, None),
        ]
    );
    let displaced = config
        .state_dir
        .join("sessions/agent-run-persist-rollback/timeline.displaced");
    assert!(!std::fs::read_to_string(displaced)
        .expect("read displaced pending timeline")
        .contains("intent_registered"));

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn runtime_source_outage_writes_one_gap_suspends_scope_and_recovers_fresh() {
    let config = config("outage");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("agent-run-outage"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let current = binding("agent-run-outage", "container-outage", "start-a", 41, 303);
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("attach runtime binding");

    let first = state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("open runtime source outage");
    assert_eq!(first.summary.gaps, 1);
    assert_eq!(first.summary.suspended, 1);
    assert_eq!(state.session_for_cgroup(303).await, None);
    assert!(state
        .runtime_bindings_for_agent_run("agent-run-outage")
        .await
        .is_empty());

    let repeated = state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("repeat same outage");
    assert!(repeated.effects.is_empty());
    let outage_timeline = timeline(&config, "agent-run-outage");
    assert_eq!(
        outage_timeline
            .matches("runtime_metadata_unavailable")
            .count(),
        1
    );
    assert!(outage_timeline.contains("source=docker,reason=socket_unavailable"));

    let recovered = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("fresh complete inventory recovers runtime source");
    assert_eq!(recovered.summary.attached, 1);
    assert_eq!(
        state.session_for_cgroup(303).await.as_deref(),
        Some("agent-run-outage")
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-outage")
            .await,
        vec![current]
    );

    cleanup(&config);
}

#[tokio::test]
async fn runtime_source_outage_retries_pending_suspend_without_duplicate_gap() {
    let config = config("outage-scope-retry");
    let untrack_attempts = Arc::new(AtomicU64::new(0));
    let (scope, mut receiver) = scope_channel(4);
    let worker_attempts = Arc::clone(&untrack_attempts);
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            let result = if request.operation() == ScopeOperation::Untrack
                && worker_attempts.fetch_add(1, Ordering::Relaxed) == 0
            {
                Err("injected first untrack failure".to_string())
            } else {
                Ok(())
            };
            request.complete(result);
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    state
        .register(intent("agent-run-outage-retry"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let current = binding(
        "agent-run-outage-retry",
        "container-outage-retry",
        "start-a",
        41,
        304,
    );
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("attach runtime binding");

    let first_error = state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect_err("first scope suspend must fail");
    assert!(first_error.contains("injected first untrack failure"));
    assert_eq!(
        timeline(&config, "agent-run-outage-retry")
            .matches("runtime_metadata_unavailable")
            .count(),
        1
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-outage-retry")
            .await,
        vec![current]
    );

    let resumed = state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("retry must finish the pending suspend");
    assert_eq!(resumed.summary.gaps, 0);
    assert_eq!(resumed.summary.suspended, 1);
    assert_eq!(
        timeline(&config, "agent-run-outage-retry")
            .matches("runtime_metadata_unavailable")
            .count(),
        1
    );
    assert!(state
        .runtime_bindings_for_agent_run("agent-run-outage-retry")
        .await
        .is_empty());
    assert_eq!(untrack_attempts.load(Ordering::Relaxed), 2);

    let repeated = state
        .runtime_source_unavailable(
            AdapterKind::Docker,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("completed outage remains idempotent");
    assert!(repeated.effects.is_empty());

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn daemon_restart_keeps_runtime_binding_dormant_until_fresh_inventory() {
    let config = config("restart");
    let current = binding("agent-run-restart", "container-restart", "start-a", 41, 404);
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("agent-run-restart"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
        state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .await
            .expect("persist runtime binding");
    }

    let restarted = DaemonState::new(&config).expect("restart daemon state");
    assert_eq!(restarted.session_for_cgroup(404).await, None);
    assert!(restarted.tracked_cgroups().await.is_empty());
    assert!(restarted
        .runtime_bindings_for_agent_run("agent-run-restart")
        .await
        .is_empty());

    let recovered = restarted
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("revalidate dormant runtime binding");
    assert_eq!(recovered.summary.gaps, 1);
    assert_eq!(recovered.summary.attached, 1);
    assert_eq!(
        restarted.session_for_cgroup(404).await.as_deref(),
        Some("agent-run-restart")
    );
    let timeline = timeline(&config, "agent-run-restart");
    assert_eq!(timeline.matches("reason=daemon_restart").count(), 1);

    cleanup(&config);
}

#[tokio::test]
async fn daemon_restart_retires_dormant_evidence_without_untracking_an_unrestored_scope() {
    let config = config("restart-scope");
    let current = binding(
        "agent-run-restart-scope",
        "container-restart-scope",
        "start-a",
        41,
        405,
    );
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("agent-run-restart-scope"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
        state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .await
            .expect("persist runtime binding");
    }

    let operations = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(4);
    let worker_operations = Arc::clone(&operations);
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            worker_operations.lock().unwrap().push(request.operation());
            let result = if request.operation() == ScopeOperation::Untrack {
                Err("dormant scope was never restored".to_string())
            } else {
                Ok(())
            };
            request.complete(result);
        }
    });
    let restarted = DaemonState::new_with_scope(&config, Some(scope)).expect("restarted state");

    let recovered = restarted
        .reconcile_runtime_inventory(RuntimeInventory::new(AdapterKind::Docker, vec![current]))
        .await
        .expect("fresh inventory must not untrack a dormant scope");

    assert_eq!(recovered.summary.gaps, 1);
    assert_eq!(recovered.summary.retired, 1);
    assert_eq!(recovered.summary.attached, 1);
    assert_eq!(*operations.lock().unwrap(), vec![ScopeOperation::Track]);
    let timeline = timeline(&config, "agent-run-restart-scope");
    let restart_gap = timeline
        .find("reason=daemon_restart")
        .expect("restart gap must be durable");
    let retired = timeline
        .find("runtime_binding_retired")
        .expect("dormant binding retirement must be durable");
    let observed = timeline
        .rfind("runtime_binding_observed")
        .expect("fresh binding attach must be durable");
    assert!(restart_gap < retired);
    assert!(retired < observed);

    drop(restarted);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn daemon_restart_retries_pending_attach_without_duplicate_gap_or_dormant_untrack() {
    let config = config("restart-scope-retry");
    let current = binding(
        "agent-run-restart-retry",
        "container-restart-retry",
        "start-a",
        41,
        406,
    );
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("agent-run-restart-retry"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
        state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .await
            .expect("persist runtime binding");
    }

    let operations = Arc::new(Mutex::new(Vec::new()));
    let track_attempts = Arc::new(AtomicU64::new(0));
    let (scope, mut receiver) = scope_channel(4);
    let worker_operations = Arc::clone(&operations);
    let worker_attempts = Arc::clone(&track_attempts);
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            worker_operations.lock().unwrap().push(request.operation());
            let result = if request.operation() == ScopeOperation::Track
                && worker_attempts.fetch_add(1, Ordering::Relaxed) == 0
            {
                Err("injected first restart attach failure".to_string())
            } else {
                Ok(())
            };
            request.complete(result);
        }
    });
    let restarted = DaemonState::new_with_scope(&config, Some(scope)).expect("restarted state");

    let first_error = restarted
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect_err("first fresh attach must fail");
    assert!(first_error.contains("injected first restart attach failure"));
    assert_eq!(
        timeline(&config, "agent-run-restart-retry")
            .matches("reason=daemon_restart")
            .count(),
        1
    );
    assert!(restarted
        .runtime_bindings_for_agent_run("agent-run-restart-retry")
        .await
        .is_empty());

    let resumed = restarted
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("second fresh inventory finishes pending restart attach");
    assert_eq!(resumed.summary.gaps, 0);
    assert_eq!(resumed.summary.retired, 1);
    assert_eq!(resumed.summary.attached, 1);
    assert_eq!(
        restarted
            .runtime_bindings_for_agent_run("agent-run-restart-retry")
            .await,
        vec![current]
    );
    assert_eq!(
        *operations.lock().unwrap(),
        vec![ScopeOperation::Track, ScopeOperation::Track]
    );
    let timeline = timeline(&config, "agent-run-restart-retry");
    assert_eq!(timeline.matches("reason=daemon_restart").count(), 1);
    assert_eq!(timeline.matches("runtime_binding_retired").count(), 1);

    drop(restarted);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn daemon_replay_rejects_an_unknown_runtime_binding_schema() {
    let config = config("replay-schema");
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("agent-run-schema"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
    }
    let mut payload = runtime_binding_payload("agent-run-schema");
    payload["schema_version"] = json!(2);
    append_runtime_binding(&config, "agent-run-schema", payload);

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("unknown runtime binding schema must fail replay"),
        Err(error) => error,
    };

    assert!(
        error.contains("runtime binding schema_version must be 1"),
        "{error}"
    );
    cleanup(&config);
}

#[tokio::test]
async fn daemon_replay_rejects_runtime_identity_outside_the_adapter_domain() {
    let workload_config = config("replay-workload-domain");
    let mut invalid_workload = runtime_binding_payload("agent-run-workload-domain");
    invalid_workload["workload_id"] =
        json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    append_runtime_binding(
        &workload_config,
        "agent-run-workload-domain",
        invalid_workload,
    );
    let workload_error = match DaemonState::new(&workload_config) {
        Ok(_) => panic!("noncanonical workload ID must fail replay"),
        Err(error) => error,
    };
    assert!(
        workload_error.contains("field=workload_id"),
        "{workload_error}"
    );
    cleanup(&workload_config);

    let marker_config = config("replay-marker-domain");
    let mut invalid_marker = runtime_binding_payload("agent-run-marker-domain");
    invalid_marker["start_marker"] = json!("private-alternate-marker");
    append_runtime_binding(&marker_config, "agent-run-marker-domain", invalid_marker);
    let marker_error = match DaemonState::new(&marker_config) {
        Ok(_) => panic!("noncanonical start marker must fail replay"),
        Err(error) => error,
    };
    assert!(
        marker_error.contains("field=start_marker"),
        "{marker_error}"
    );
    cleanup(&marker_config);
}

#[tokio::test]
async fn daemon_replay_rejects_a_runtime_binding_from_another_agent_run() {
    let config = config("replay-agent-run");
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("agent-run-owner"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
    }
    append_runtime_binding(
        &config,
        "agent-run-owner",
        runtime_binding_payload("agent-run-foreign"),
    );

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("foreign runtime binding must fail replay"),
        Err(error) => error,
    };

    assert!(
        error.contains("runtime binding Agent Run identity mismatch"),
        "{error}"
    );
    cleanup(&config);
}

#[tokio::test]
async fn daemon_replay_rejects_unknown_runtime_binding_fields_without_echoing_values() {
    let config = config("replay-extra-field");
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("agent-run-extra-field"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
    }
    let private_value = "/private/tenant/namespace/should-not-escape";
    let mut payload = runtime_binding_payload("agent-run-extra-field");
    payload["private_namespace"] = json!(private_value);
    append_runtime_binding(&config, "agent-run-extra-field", payload);

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("unknown runtime binding field must fail replay"),
        Err(error) => error,
    };

    assert!(
        error.contains("runtime binding lifecycle record"),
        "{error}"
    );
    assert!(!error.contains(private_value), "{error}");
    cleanup(&config);
}

#[tokio::test]
async fn daemon_replay_requires_runtime_handler_even_when_its_value_is_nullable() {
    let missing_config = config("replay-missing-handler");
    {
        let state = DaemonState::new(&missing_config).expect("daemon state");
        state
            .register(intent("agent-run-missing-handler"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
    }
    let mut missing = runtime_binding_payload("agent-run-missing-handler");
    missing
        .as_object_mut()
        .expect("runtime binding object")
        .remove("runtime_handler");
    append_runtime_binding(&missing_config, "agent-run-missing-handler", missing);
    let missing_error = match DaemonState::new(&missing_config) {
        Ok(_) => panic!("missing runtime_handler must fail replay"),
        Err(error) => error,
    };
    assert!(
        missing_error.contains("runtime binding lifecycle record"),
        "{missing_error}"
    );
    cleanup(&missing_config);

    let nullable_config = config("replay-null-handler");
    {
        let state = DaemonState::new(&nullable_config).expect("daemon state");
        state
            .register(intent("agent-run-null-handler"), 1_700_000_000_000)
            .await
            .expect("register Agent Run");
    }
    let mut nullable = runtime_binding_payload("agent-run-null-handler");
    nullable["runtime_handler"] = Value::Null;
    append_runtime_binding(&nullable_config, "agent-run-null-handler", nullable);
    let reopened = DaemonState::new(&nullable_config)
        .expect("explicitly null runtime_handler remains a valid lifecycle record");
    assert!(reopened
        .runtime_bindings_for_agent_run("agent-run-null-handler")
        .await
        .is_empty());
    drop(reopened);
    cleanup(&nullable_config);
}

#[tokio::test]
async fn daemon_replay_rejects_removed_or_illegal_runtime_binding_record_types() {
    let config = config("replay-record-type");
    let mut payload = runtime_binding_payload("agent-run-record-type");
    payload["record_type"] = json!("runtime_binding_transition");
    append_runtime_binding(&config, "agent-run-record-type", payload);

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("removed runtime binding record type must fail replay"),
        Err(error) => error,
    };

    assert!(
        error.contains("unsupported runtime binding lifecycle record type"),
        "{error}"
    );
    cleanup(&config);
}

#[tokio::test]
async fn daemon_replay_rejects_runtime_binding_lifecycle_sequence_tampering() {
    let duplicate_config = config("replay-duplicate-observed");
    let original = runtime_binding_payload("agent-run-duplicate-observed");
    append_runtime_binding(
        &duplicate_config,
        "agent-run-duplicate-observed",
        original.clone(),
    );
    let mut replacement = original;
    replacement["start_marker"] = json!("2026-08-11T01:02:04.000000000Z");
    append_runtime_binding(
        &duplicate_config,
        "agent-run-duplicate-observed",
        replacement,
    );
    let duplicate_error = match DaemonState::new(&duplicate_config) {
        Ok(_) => panic!("replacement without prior retirement must fail replay"),
        Err(error) => error,
    };
    assert!(
        duplicate_error.contains("runtime binding observed while already active"),
        "{duplicate_error}"
    );
    cleanup(&duplicate_config);

    let retire_config = config("replay-mismatched-retire");
    let observed = runtime_binding_payload("agent-run-mismatched-retire");
    append_runtime_binding(
        &retire_config,
        "agent-run-mismatched-retire",
        observed.clone(),
    );
    let mut mismatched_retire = observed;
    mismatched_retire["record_type"] = json!("runtime_binding_retired");
    mismatched_retire["cgroup_id"] = json!(506);
    append_runtime_binding(
        &retire_config,
        "agent-run-mismatched-retire",
        mismatched_retire,
    );
    let retire_error = match DaemonState::new(&retire_config) {
        Ok(_) => panic!("retirement of a different identity must fail replay"),
        Err(error) => error,
    };
    assert!(
        retire_error.contains("runtime binding retirement identity mismatch"),
        "{retire_error}"
    );
    cleanup(&retire_config);

    let absent_config = config("replay-absent-suspend");
    let mut absent_suspend = runtime_binding_payload("agent-run-absent-suspend");
    absent_suspend["record_type"] = json!("runtime_binding_suspended");
    append_runtime_binding(&absent_config, "agent-run-absent-suspend", absent_suspend);
    let absent_error = match DaemonState::new(&absent_config) {
        Ok(_) => panic!("suspending an absent binding must fail replay"),
        Err(error) => error,
    };
    assert!(
        absent_error.contains("runtime binding lifecycle ended while inactive"),
        "{absent_error}"
    );
    cleanup(&absent_config);
}

#[tokio::test]
async fn expired_intent_restart_preserves_runtime_binding_as_dormant_pending_attribution() {
    let config = config("expired-intent-runtime-restart");
    let agent_run_id = "agent-run-expired-runtime";
    let current = binding(
        agent_run_id,
        "container-expired-runtime",
        "start-expired",
        42,
        228,
    );
    {
        let state = DaemonState::new(&config).expect("daemon state");
        let mut expiring = intent(agent_run_id);
        expiring.expires_at_unix_ms = 1_700_000_000_001;
        state
            .register(expiring, 1_700_000_000_000)
            .await
            .expect("register briefly valid intent");
        state
            .reconcile_runtime_inventory(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![current.clone()],
            ))
            .await
            .expect("persist runtime binding before expiry");
    }

    let restarted = DaemonState::new(&config).expect("restart after intent expiry");
    assert!(restarted.query(agent_run_id).await.is_none());
    assert!(restarted
        .runtime_bindings_for_agent_run(agent_run_id)
        .await
        .is_empty());
    let recovered = restarted
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("fresh inventory requalifies expired-intent dormant binding");
    assert_eq!(recovered.summary.gaps, 1);
    assert_eq!(recovered.summary.retired, 1);
    assert_eq!(recovered.summary.attached, 0);
    assert_eq!(recovered.summary.missing_intent, 1);
    assert_eq!(
        restarted.session_for_cgroup(228).await.as_deref(),
        Some(agent_run_id)
    );
    restarted
        .register(intent(agent_run_id), 1_700_000_000_000)
        .await
        .expect("fresh intent promotes preserved runtime attribution");
    assert_eq!(
        restarted.runtime_bindings_for_agent_run(agent_run_id).await,
        vec![current]
    );
    assert_eq!(
        timeline(&config, agent_run_id)
            .matches("reason=daemon_restart")
            .count(),
        1
    );

    cleanup(&config);
}

#[tokio::test]
async fn failed_close_restores_runtime_scope_with_its_container_identity() {
    let config = config("close-rollback-runtime");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(8);
    let worker_observed = Arc::clone(&observed);
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            worker_observed.lock().unwrap().push((
                request.operation(),
                request.runtime_container_id().map(str::to_string),
            ));
            request.complete(Ok(()));
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    state
        .register(intent("agent-run-close"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let current = binding("agent-run-close", "container-close", "start-close", 42, 606);
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("attach runtime binding");

    replace_timeline_path(&config, "agent-run-close");
    let error = state
        .close("agent-run-close")
        .await
        .expect_err("replaced timeline must fail close persistence");

    assert!(error.contains("timeline path changed"), "{error}");
    assert_eq!(
        *observed.lock().unwrap(),
        vec![
            (
                ScopeOperation::Track,
                Some(test_container_id("container-close")),
            ),
            (
                ScopeOperation::Untrack,
                Some(test_container_id("container-close")),
            ),
            (ScopeOperation::CloseAgentRun, None),
            (
                ScopeOperation::Track,
                Some(test_container_id("container-close")),
            ),
        ]
    );
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-close")
            .await,
        vec![current]
    );

    drop(state);
    worker.abort();
    cleanup(&config);
}

#[tokio::test]
async fn failed_runtime_lifecycle_persistence_restores_the_entire_previous_scope() {
    let config = config("runtime-persistence-rollback");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (scope, mut receiver) = scope_channel(8);
    let worker_observed = Arc::clone(&observed);
    let worker_config = config.clone();
    let worker = tokio::spawn(async move {
        while let Some(request) = receiver.recv().await {
            let operation = request.operation();
            let cgroup_id = request.cgroup_id();
            let container_id = request.runtime_container_id().map(str::to_string);
            worker_observed
                .lock()
                .unwrap()
                .push((operation, container_id.clone()));
            if operation == ScopeOperation::Track && cgroup_id == 611 {
                replace_timeline_path(&worker_config, "agent-run-runtime-rollback");
            }
            request.complete(Ok(()));
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    state
        .register(intent("agent-run-runtime-rollback"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let current = binding(
        "agent-run-runtime-rollback",
        "container-rollback",
        "start-old",
        42,
        610,
    );
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("attach original runtime binding");
    let replacement = binding(
        "agent-run-runtime-rollback",
        "container-rollback",
        "start-new",
        84,
        611,
    );

    let error = state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![replacement],
        ))
        .await
        .expect_err("replaced timeline must fail lifecycle persistence");

    assert!(error.contains("timeline path changed"), "{error}");
    assert_eq!(
        *observed.lock().unwrap(),
        vec![
            (
                ScopeOperation::Track,
                Some(test_container_id("container-rollback"))
            ),
            (
                ScopeOperation::Untrack,
                Some(test_container_id("container-rollback"))
            ),
            (
                ScopeOperation::Track,
                Some(test_container_id("container-rollback"))
            ),
            (
                ScopeOperation::Untrack,
                Some(test_container_id("container-rollback"))
            ),
            (
                ScopeOperation::Track,
                Some(test_container_id("container-rollback"))
            ),
        ]
    );
    assert_eq!(
        state.session_for_cgroup(610).await.as_deref(),
        Some("agent-run-runtime-rollback")
    );
    assert_eq!(state.session_for_cgroup(611).await, None);
    assert_eq!(
        state
            .runtime_bindings_for_agent_run("agent-run-runtime-rollback")
            .await,
        vec![current.clone()]
    );
    let timeline_path = config
        .state_dir
        .join("sessions/agent-run-runtime-rollback/timeline.jsonl");
    let displaced_path = config
        .state_dir
        .join("sessions/agent-run-runtime-rollback/timeline.displaced");
    let displaced = std::fs::read_to_string(&displaced_path).expect("read displaced timeline");
    assert!(displaced.contains("reason=identity_transition"));
    assert!(!displaced.contains("runtime_binding_retired"));
    assert_eq!(displaced.matches("runtime_binding_observed").count(), 1);

    drop(state);
    worker.abort();
    std::fs::remove_file(&timeline_path).expect("remove injected replacement timeline");
    std::fs::rename(&displaced_path, &timeline_path).expect("restore original timeline identity");
    let reopened = DaemonState::new(&config).expect("reopen rolled back Agent Run timeline");
    assert!(reopened
        .runtime_bindings_for_agent_run("agent-run-runtime-rollback")
        .await
        .is_empty());
    let recovered = reopened
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Docker,
            vec![current.clone()],
        ))
        .await
        .expect("fresh inventory requalifies the old dormant binding");
    assert_eq!(recovered.summary.gaps, 1);
    assert_eq!(recovered.summary.attached, 1);
    assert_eq!(
        reopened
            .runtime_bindings_for_agent_run("agent-run-runtime-rollback")
            .await,
        vec![current]
    );

    cleanup(&config);
}

fn binding(
    agent_run_id: &str,
    workload_id: &str,
    start_marker: &str,
    init_process_start_time_ticks: u64,
    cgroup_inode: u64,
) -> RuntimeBinding {
    RuntimeBinding {
        agent_run_id: agent_run_id.to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Docker,
            workload_id: test_container_id(workload_id),
            start_marker: test_docker_start_marker(start_marker),
            host_boot_id: BOOT_ID.to_string(),
            init_process_start_time_ticks,
            cgroup: CgroupIdentity {
                device: 7,
                inode: cgroup_inode,
            },
        },
        runtime_handler: Some("runc".to_string()),
    }
}

fn test_container_id(label: &str) -> String {
    format!("{:016x}", fixture_token(label)).repeat(4)
}

fn test_docker_start_marker(label: &str) -> String {
    format!(
        "2026-08-11T01:02:03.{:09}Z",
        fixture_token(label) % 1_000_000_000
    )
}

fn fixture_token(value: &str) -> u64 {
    value.bytes().fold(1_u64, |token, byte| {
        token.wrapping_mul(16_777_619).wrapping_add(u64::from(byte))
    }) | 1
}

fn runtime_binding_payload(agent_run_id: &str) -> Value {
    json!({
        "record_type": "runtime_binding_observed",
        "schema_version": 1,
        "agent_run_id": agent_run_id,
        "adapter": "docker",
        "workload_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "start_marker": "2026-08-11T01:02:03.000000000Z",
        "host_boot_id": BOOT_ID,
        "init_process_start_time_ticks": 42,
        "cgroup_device": 7,
        "cgroup_id": 505,
        "runtime_handler": "runc",
    })
}

fn append_runtime_binding(config: &DaemonConfig, agent_run_id: &str, payload: Value) {
    let path = config
        .state_dir
        .join("sessions")
        .join(agent_run_id)
        .join("timeline.jsonl");
    let mut recovery = HashChainStore::create_or_recover(path).expect("recover timeline");
    assert!(recovery.quarantined_path.is_none());
    recovery
        .store
        .append_json(1, &payload.to_string())
        .expect("append runtime binding");
    recovery.store.flush().expect("flush runtime binding");
}

fn replace_timeline_path(config: &DaemonConfig, agent_run_id: &str) {
    let path = config
        .state_dir
        .join("sessions")
        .join(agent_run_id)
        .join("timeline.jsonl");
    std::fs::rename(&path, path.with_extension("displaced")).expect("displace timeline");
    std::fs::write(&path, b"").expect("replace timeline path");
}

fn intent(agent_run_id: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        retention_tier: RetentionTier::Standard,
        session_id: agent_run_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Execute],
        allowed_resources: Vec::new(),
        workload_selectors: Vec::new(),
    }
}

fn config(name: &str) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-runtime-binding-state-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        ..DaemonConfig::default()
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

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.state_dir.parent() {
        match std::fs::remove_dir_all(root) {
            Ok(()) => assert!(!root.exists(), "runtime binding test root must be absent"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove runtime binding test root: {error}"),
        }
    }
}

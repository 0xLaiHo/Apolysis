// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::{ActionClass, AdapterKind, RetentionTier, SessionIntent};
use apolysis_core::{
    KubernetesContainerKind, KubernetesWorkloadClaimV1, KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
};
use apolysis_daemon::{
    scope_channel, CgroupIdentity, DaemonConfig, DaemonState, RuntimeBinding, RuntimeInventory,
    RuntimeSourceGapReason, RuntimeWorkloadIdentity, ScopeOperation,
};
use apolysis_kubernetes::{
    KubernetesContainerCandidate, KubernetesPodCandidate, KubernetesPodSnapshot,
    KubernetesSnapshotIdentity, KubernetesSourceUnavailableReason,
};

const AGENT_RUN_ID: &str = "agent-run-kubernetes-state";
const CLUSTER_ID: &str = "11111111-1111-1111-1111-111111111111";
const POD_UID: &str = "22222222-2222-2222-2222-222222222222";
const SOURCE_EPOCH: &str = "33333333-3333-3333-3333-333333333333";
const HOST_BOOT_ID: &str = "44444444-4444-4444-4444-444444444444";
const CONTAINER_ID: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const SECOND_CONTAINER_ID: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn complete_cycle_publishes_runtime_and_kubernetes_context_atomically() {
    let config = test_config("complete-cycle");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");

    let before = stable_snapshot(1);
    let after = stable_snapshot(2);
    state
        .apply_kubernetes_qualification_cycle(
            before,
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            after,
        )
        .await
        .expect("stable complete cycle");

    let (session, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(session.is_some());
    assert_eq!(runtime_bindings.len(), 1);
    assert_eq!(kubernetes_attributions.len(), 1);
    assert_eq!(kubernetes_attributions[0].pod_uid, POD_UID);
    assert_eq!(
        kubernetes_attributions[0].runtime_binding.workload_id,
        format!("containerd/{CONTAINER_ID}")
    );

    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    let runtime_offset = timeline
        .find("runtime_binding_observed")
        .expect("durable exact runtime binding");
    let kubernetes_offset = timeline
        .find("kubernetes_attribution_observed")
        .expect("durable Kubernetes attribution");
    assert!(runtime_offset < kubernetes_offset);
    assert!(!timeline.contains("kubernetes_late_attach"));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn typed_claims_exclude_a_same_namespace_pod_that_spoofs_a_registered_agent_run() {
    let config = test_config("claim-admission");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");

    state
        .apply_kubernetes_qualification_cycle(
            snapshot_with_unclaimed_pod(1),
            RuntimeInventory::new(
                AdapterKind::Containerd,
                vec![runtime_binding(), second_runtime_binding()],
            ),
            snapshot_with_unclaimed_pod(2),
        )
        .await
        .expect("complete cycle filters an unclaimed Pod");

    let (_, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert_eq!(runtime_bindings, vec![runtime_binding()]);
    assert_eq!(kubernetes_attributions.len(), 1);
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert!(!timeline.contains(SECOND_CONTAINER_ID));
    assert!(!timeline.contains(r#""kind":"missing_intent""#));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn tenant_mismatch_returns_no_workload_context() {
    let config = test_config("tenant-gate");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    let before = stable_snapshot(1);
    let after = stable_snapshot(2);
    state
        .apply_kubernetes_qualification_cycle(
            before,
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            after,
        )
        .await
        .expect("stable complete cycle");

    let (session, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-b")
        .await;
    assert!(session.is_none());
    assert!(runtime_bindings.is_empty());
    assert!(kubernetes_attributions.is_empty());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn complete_cycle_ignores_registered_claims_outside_its_cluster_namespace_domain() {
    let config = test_config("claim-domain-filter");
    let state = DaemonState::new(&config).expect("daemon state");
    let mut outside = intent("tenant-a");
    outside.kubernetes_claims[0].cluster_id = "55555555-5555-5555-5555-555555555555".to_string();
    outside.kubernetes_claims[0].namespace_ref = "9".repeat(64);
    state
        .register(outside, 1_700_000_000_000)
        .await
        .expect("register claim outside this source profile");

    let summary = state
        .apply_kubernetes_qualification_cycle(
            empty_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, Vec::new()),
            empty_snapshot(2),
        )
        .await
        .expect("ignore unrelated registered claim");
    assert_eq!(summary, Default::default());
    let (_, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime.is_empty());
    assert!(kubernetes.is_empty());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn combined_cycle_does_not_create_agent_run_state_from_unclaimed_runtime_metadata() {
    let config = test_config("combined-unclaimed-runtime");
    let state = DaemonState::new(&config).expect("daemon state");

    let summary = state
        .apply_kubernetes_qualification_cycle(
            empty_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            empty_snapshot(2),
        )
        .await
        .expect("combined cycle ignores an unclaimed D1 binding");
    assert_eq!(summary, Default::default());
    let timeline = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    assert!(matches!(
        std::fs::symlink_metadata(timeline),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn api_outage_suspends_only_kubernetes_context() {
    let config = test_config("api-outage");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("stable complete cycle");

    state
        .kubernetes_source_unavailable(
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .await
        .expect("persist Kubernetes API outage");

    let (_, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert_eq!(runtime_bindings.len(), 1);
    assert!(kubernetes_attributions.is_empty());
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    let gap = timeline
        .find("kubernetes_metadata_unavailable")
        .expect("typed Kubernetes metadata gap");
    let suspended = timeline
        .find("kubernetes_attribution_suspended")
        .expect("suspended Kubernetes attribution");
    assert!(gap < suspended);

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn claim_revocation_during_api_outage_immediately_retires_the_authorized_runtime() {
    let config = test_config("api-outage-claim-revocation");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("stable complete cycle");
    state
        .kubernetes_source_unavailable(
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .await
        .expect("suspend Kubernetes attribution");

    let mut revoked = intent("tenant-a");
    revoked.kubernetes_claims.clear();
    state
        .register(revoked, 1_700_000_000_001)
        .await
        .expect("revoke Kubernetes authorization during the outage");

    let (_, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime.is_empty());
    assert!(kubernetes.is_empty());
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert_eq!(timeline.matches("runtime_binding_retired").count(), 1);

    drop(state);
    let restarted = DaemonState::new(&config).expect("restart after claim revocation");
    let (_, runtime, kubernetes) = restarted
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime.is_empty());
    assert!(kubernetes.is_empty());

    drop(restarted);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn api_outage_recovery_does_not_misclassify_the_existing_runtime_as_late_attach() {
    let config = test_config("api-outage-recovery");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("initial complete cycle");
    state
        .kubernetes_source_unavailable(
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .await
        .expect("suspend Kubernetes attribution");
    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let before_len = std::fs::read_to_string(&timeline_path)
        .expect("timeline before recovery")
        .len();

    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(3),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(4),
        )
        .await
        .expect("recover from API outage");
    let timeline = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
    let recovery = &timeline[before_len..];
    assert!(recovery.contains("kubernetes_attribution_observed"));
    assert!(!recovery.contains("kubernetes_late_attach"));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn source_epoch_restart_requalifies_without_misclassifying_a_late_attach() {
    let config = test_config("source-epoch-restart");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("initial source epoch");
    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let before_len = std::fs::read_to_string(&timeline_path)
        .expect("timeline before source restart")
        .len();
    let restarted_epoch = "66666666-6666-6666-6666-666666666666";

    state
        .apply_kubernetes_qualification_cycle(
            snapshot_with_epoch(1, restarted_epoch),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            snapshot_with_epoch(2, restarted_epoch),
        )
        .await
        .expect("fresh source epoch");
    let timeline = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
    let restart = &timeline[before_len..];
    let gap = restart
        .find("reason=kubernetes_daemon_restart")
        .expect("source restart gap");
    let retired = restart
        .find("kubernetes_attribution_retired")
        .expect("old source attribution retired");
    let observed = restart
        .find("kubernetes_attribution_observed")
        .expect("fresh source attribution observed");
    assert!(gap < retired && retired < observed);
    assert!(!restart.contains("kubernetes_late_attach"));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn runtime_outage_suspends_kubernetes_before_its_exact_runtime_dependency() {
    let config = test_config("runtime-outage");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("stable complete cycle");

    state
        .kubernetes_runtime_source_unavailable(
            CLUSTER_ID,
            AdapterKind::Containerd,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("persist coupled runtime outage");

    let (_, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime_bindings.is_empty());
    assert!(kubernetes_attributions.is_empty());
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    let kubernetes_gap = timeline
        .find("reason=kubernetes_runtime_unavailable")
        .expect("typed Kubernetes runtime gap");
    let kubernetes_suspended = timeline
        .find("kubernetes_attribution_suspended")
        .expect("suspended Kubernetes attribution");
    let runtime_gap = timeline
        .find("source=containerd,reason=socket_unavailable")
        .expect("typed runtime source gap");
    let runtime_suspended = timeline
        .rfind("runtime_binding_suspended")
        .expect("suspended exact runtime binding");
    assert!(
        kubernetes_gap < kubernetes_suspended
            && kubernetes_suspended < runtime_gap
            && runtime_gap < runtime_suspended
    );

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn runtime_outage_before_first_binding_still_records_a_claim_gap() {
    let config = test_config("initial-runtime-outage");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");

    state
        .kubernetes_runtime_source_unavailable(
            CLUSTER_ID,
            AdapterKind::Containerd,
            RuntimeSourceGapReason::SocketUnavailable,
        )
        .await
        .expect("persist initial coupled runtime outage");
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert!(timeline.contains("kubernetes_metadata_unavailable"));
    assert!(timeline.contains("reason=kubernetes_runtime_unavailable"));
    assert!(!timeline.contains("runtime_binding_suspended"));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn restart_keeps_kubernetes_context_dormant_until_a_fresh_complete_cycle() {
    let config = test_config("restart-dormant");
    {
        let state = DaemonState::new(&config).expect("daemon state");
        state
            .register(intent("tenant-a"), 1_700_000_000_000)
            .await
            .expect("register exact Kubernetes claim");
        state
            .apply_kubernetes_qualification_cycle(
                stable_snapshot(1),
                RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
                stable_snapshot(2),
            )
            .await
            .expect("initial stable complete cycle");
    }

    let restarted = DaemonState::new(&config).expect("restart from durable state");
    let (_, runtime_bindings, kubernetes_attributions) = restarted
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime_bindings.is_empty());
    assert!(kubernetes_attributions.is_empty());

    restarted
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(3),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(4),
        )
        .await
        .expect("fresh complete cycle requalifies dormant context");
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    let gap = timeline
        .find("kubernetes_daemon_restart")
        .expect("restart creates a typed Kubernetes gap");
    let retired = timeline
        .find("kubernetes_attribution_retired")
        .expect("dormant attribution is explicitly retired");
    let observed = timeline
        .rfind("kubernetes_attribution_observed")
        .expect("fresh attribution is observed");
    assert!(gap < retired && retired < observed);

    drop(restarted);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn closing_an_agent_run_removes_its_kubernetes_context() {
    let config = test_config("close");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("stable complete cycle");

    state.close(AGENT_RUN_ID).await.expect("close Agent Run");
    let (session, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(session.is_some());
    assert!(runtime_bindings.is_empty());
    assert!(kubernetes_attributions.is_empty());
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    let kubernetes_retired = timeline
        .find("kubernetes_attribution_retired")
        .expect("durable Kubernetes retirement");
    let runtime_retired = timeline
        .find("runtime_binding_retired")
        .expect("durable runtime retirement");
    let session_closed = timeline.find("session_closed").expect("durable close");
    assert!(kubernetes_retired < runtime_retired && runtime_retired < session_closed);

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn complete_empty_cycle_retires_absent_runtime_and_kubernetes_context() {
    let config = test_config("complete-empty");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("stable complete cycle");

    state
        .apply_kubernetes_qualification_cycle(
            empty_snapshot(3),
            RuntimeInventory::new(AdapterKind::Containerd, Vec::new()),
            empty_snapshot(4),
        )
        .await
        .expect("authoritative empty cycle");
    let (_, runtime_bindings, kubernetes_attributions) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime_bindings.is_empty());
    assert!(kubernetes_attributions.is_empty());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn api_outage_before_first_binding_still_records_a_claim_gap() {
    let config = test_config("initial-api-outage");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");

    let summary = state
        .kubernetes_source_unavailable(
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .await
        .expect("persist initial Kubernetes API outage");
    assert_eq!(summary.gaps, 1);
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert!(timeline.contains("kubernetes_metadata_unavailable"));
    assert!(timeline.contains("reason=kubernetes_api_unavailable"));

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn attribution_added_to_an_existing_runtime_binding_records_late_attach() {
    let config = test_config("late-attach");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register exact Kubernetes claim");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Containerd,
            vec![runtime_binding()],
        ))
        .await
        .expect("establish exact runtime binding first");

    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("late Kubernetes attribution");
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    let gap = timeline
        .find("kubernetes_late_attach")
        .expect("typed late-attach gap");
    let observed = timeline
        .find("kubernetes_attribution_observed")
        .expect("Kubernetes attribution");
    assert!(gap < observed);

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn identity_transition_and_late_attach_each_record_their_distinct_gap() {
    let config = test_config("mixed-transition-late-attach");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent_with_two_claims("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register both exact Kubernetes claims");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("qualify first claim");
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Containerd,
            vec![runtime_binding(), second_runtime_binding()],
        ))
        .await
        .expect("establish second exact runtime dependency");
    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let before_len = std::fs::read_to_string(&timeline_path)
        .expect("timeline before mixed cycle")
        .len();

    state
        .apply_kubernetes_qualification_cycle(
            two_container_snapshot(3),
            RuntimeInventory::new(
                AdapterKind::Containerd,
                vec![transitioned_runtime_binding(), second_runtime_binding()],
            ),
            two_container_snapshot(4),
        )
        .await
        .expect("mixed identity-transition and late-attach cycle");
    let timeline = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
    let cycle = &timeline[before_len..];
    let identity_gap = cycle
        .find("reason=kubernetes_identity_transition")
        .expect("Kubernetes identity-transition gap");
    let late_attach_gap = cycle
        .find("reason=kubernetes_late_attach")
        .expect("Kubernetes late-attach gap");
    let runtime_gap = cycle
        .find("reason=identity_transition")
        .expect("runtime identity-transition gap");
    let kubernetes_end = cycle
        .find("kubernetes_attribution_retired")
        .expect("old Kubernetes link retired");
    let runtime_end = cycle
        .find("runtime_binding_retired")
        .expect("old runtime binding retired");
    let runtime_observed = runtime_end
        + cycle[runtime_end..]
            .find("runtime_binding_observed")
            .expect("new runtime binding observed");
    let kubernetes_observed = cycle
        .find("kubernetes_attribution_observed")
        .expect("new Kubernetes link observed");
    assert!(identity_gap < kubernetes_end);
    assert!(late_attach_gap < kubernetes_end);
    assert!(runtime_gap < kubernetes_end);
    assert!(
        kubernetes_end < runtime_end
            && runtime_end < runtime_observed
            && runtime_observed < kubernetes_observed
    );

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn claim_revision_change_hides_stale_attribution_until_fresh_qualification() {
    let config = test_config("claim-revision");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register revision one");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("qualify revision one");

    let mut revision_two = intent("tenant-a");
    revision_two.kubernetes_claims[0].claim_revision = 2;
    state
        .register(revision_two, 1_700_000_000_001)
        .await
        .expect("replace with revision two");
    let (_, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime.is_empty());
    assert!(kubernetes.is_empty());

    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(3),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(4),
        )
        .await
        .expect("freshly qualify revision two");
    let (_, _, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert_eq!(kubernetes.len(), 1);

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn removing_all_claims_durably_retires_the_previous_kubernetes_link() {
    let config = test_config("remove-claims");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("qualify claim");
    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let before_len = std::fs::read_to_string(&timeline_path)
        .expect("timeline before claim removal")
        .len();
    let mut removed = intent("tenant-a");
    removed.kubernetes_claims.clear();

    state
        .register(removed.clone(), 1_700_000_000_001)
        .await
        .expect("remove Kubernetes authorization");
    let timeline = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
    let refresh = &timeline[before_len..];
    let retired = refresh
        .find("kubernetes_attribution_retired")
        .expect("durable K1 retirement");
    let runtime_retired = refresh
        .find("runtime_binding_retired")
        .expect("durable D1 retirement");
    let registered = refresh
        .find("intent_registered")
        .expect("replacement intent");
    assert!(retired < runtime_retired && runtime_retired < registered);
    let (_, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime.is_empty());
    assert!(kubernetes.is_empty());

    drop(state);
    let restarted = DaemonState::new(&config).expect("restart from retired K1 state");
    let (_, _, kubernetes) = restarted
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(kubernetes.is_empty());
    drop(restarted);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn replacing_the_claim_domain_durably_retires_the_previous_link() {
    let config = test_config("replace-claim-domain");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("qualify claim");
    let mut replacement = intent("tenant-a");
    replacement.kubernetes_claims[0].claim_revision = 2;
    replacement.kubernetes_claims[0].cluster_id =
        "55555555-5555-5555-5555-555555555555".to_string();
    replacement.kubernetes_claims[0].namespace_ref = "9".repeat(64);

    state
        .register(replacement, 1_700_000_000_001)
        .await
        .expect("replace Kubernetes claim domain");
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert_eq!(
        timeline.matches("kubernetes_attribution_retired").count(),
        1
    );
    let (_, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert!(runtime.is_empty());
    assert!(kubernetes.is_empty());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn failed_claim_removal_keeps_the_old_state_and_retry_does_not_duplicate_retirement() {
    let config = test_config("claim-removal-retry");
    let state = DaemonState::new(&config).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("qualify claim");
    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let displaced = timeline_path.with_extension("displaced");
    std::fs::rename(&timeline_path, &displaced).expect("displace timeline");
    std::fs::write(&timeline_path, b"").expect("replace timeline path");
    let mut removed = intent("tenant-a");
    removed.kubernetes_claims.clear();

    state
        .register(removed.clone(), 1_700_000_000_001)
        .await
        .expect_err("claim replacement batch must fail");
    let (session, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert_eq!(
        session.expect("old session").intent.kubernetes_claims.len(),
        1
    );
    assert_eq!(runtime.len(), 1);
    assert_eq!(kubernetes.len(), 1);

    std::fs::remove_file(&timeline_path).expect("remove replacement timeline");
    std::fs::rename(&displaced, &timeline_path).expect("restore timeline identity");
    drop(state);
    let restarted = DaemonState::new(&config).expect("restart after failed replacement");
    restarted
        .register(removed, 1_700_000_000_002)
        .await
        .expect("retry claim replacement");
    let timeline = std::fs::read_to_string(&timeline_path).expect("Agent Run timeline");
    assert_eq!(
        timeline.matches("kubernetes_attribution_retired").count(),
        1
    );

    drop(restarted);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn failed_claim_revocation_restores_the_runtime_scope_before_returning() {
    let config = test_config("claim-revocation-scope-rollback");
    let operations = Arc::new(Mutex::new(Vec::new()));
    let worker_operations = Arc::clone(&operations);
    let (scope, mut requests) = scope_channel(8);
    let worker = tokio::spawn(async move {
        while let Some(request) = requests.recv().await {
            worker_operations
                .lock()
                .expect("scope operations lock")
                .push(request.operation());
            request.complete(Ok(()));
        }
    });
    let state = DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state");
    state
        .register(intent("tenant-a"), 1_700_000_000_000)
        .await
        .expect("register claim");
    state
        .apply_kubernetes_qualification_cycle(
            stable_snapshot(1),
            RuntimeInventory::new(AdapterKind::Containerd, vec![runtime_binding()]),
            stable_snapshot(2),
        )
        .await
        .expect("qualify claim");
    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let displaced = timeline_path.with_extension("displaced");
    std::fs::rename(&timeline_path, &displaced).expect("displace timeline");
    std::fs::write(&timeline_path, b"").expect("replace timeline path");
    let mut removed = intent("tenant-a");
    removed.kubernetes_claims.clear();

    state
        .register(removed, 1_700_000_000_001)
        .await
        .expect_err("claim revocation batch must fail");
    assert_eq!(
        *operations.lock().expect("scope operations lock"),
        vec![
            ScopeOperation::Track,
            ScopeOperation::Untrack,
            ScopeOperation::Track,
        ]
    );
    let (_, runtime, kubernetes) = state
        .query_with_workload_context_for_tenant(AGENT_RUN_ID, "tenant-a")
        .await;
    assert_eq!(runtime.len(), 1);
    assert_eq!(kubernetes.len(), 1);

    std::fs::remove_file(&timeline_path).expect("remove replacement timeline");
    std::fs::rename(&displaced, &timeline_path).expect("restore timeline identity");
    drop(state);
    worker.abort();
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

fn intent(tenant_id: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: tenant_id.to_string(),
        retention_tier: RetentionTier::Standard,
        session_id: AGENT_RUN_ID.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: Vec::new(),
        workload_selectors: Vec::new(),
        kubernetes_claims: vec![KubernetesWorkloadClaimV1 {
            schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
            claim_revision: 1,
            cluster_id: CLUSTER_ID.to_string(),
            namespace_ref: "a".repeat(64),
            pod_uid: POD_UID.to_string(),
            container_kind: KubernetesContainerKind::Application,
            container_ref: "d".repeat(64),
        }],
    }
}

fn intent_with_two_claims(tenant_id: &str) -> SessionIntent {
    let mut intent = intent(tenant_id);
    intent.kubernetes_claims.push(KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 1,
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: POD_UID.to_string(),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "f".repeat(64),
    });
    intent
}

fn stable_snapshot(sequence: u64) -> KubernetesPodSnapshot {
    KubernetesPodSnapshot {
        sequence,
        identity: KubernetesSnapshotIdentity {
            source_epoch: SOURCE_EPOCH.to_string(),
            cluster_id: CLUSTER_ID.to_string(),
            namespace_ref: "a".repeat(64),
            node_ref: "b".repeat(64),
        },
        pods: vec![KubernetesPodCandidate {
            pod_uid: POD_UID.to_string(),
            pod_revision_ref: "9".repeat(64),
            marked_for_observation: true,
            deleting: false,
            runtime_class_ref: Some("c".repeat(64)),
            containers: vec![KubernetesContainerCandidate {
                kind: KubernetesContainerKind::Application,
                container_ref: "d".repeat(64),
                runtime_container_id: Some(CONTAINER_ID.to_string()),
                running: true,
            }],
        }],
    }
}

fn snapshot_with_epoch(sequence: u64, source_epoch: &str) -> KubernetesPodSnapshot {
    let mut snapshot = stable_snapshot(sequence);
    snapshot.identity.source_epoch = source_epoch.to_string();
    snapshot
}

fn empty_snapshot(sequence: u64) -> KubernetesPodSnapshot {
    let mut snapshot = stable_snapshot(sequence);
    snapshot.pods.clear();
    snapshot
}

fn two_container_snapshot(sequence: u64) -> KubernetesPodSnapshot {
    let mut snapshot = stable_snapshot(sequence);
    snapshot.pods[0]
        .containers
        .push(KubernetesContainerCandidate {
            kind: KubernetesContainerKind::Application,
            container_ref: "f".repeat(64),
            runtime_container_id: Some(SECOND_CONTAINER_ID.to_string()),
            running: true,
        });
    snapshot
}

fn snapshot_with_unclaimed_pod(sequence: u64) -> KubernetesPodSnapshot {
    let mut snapshot = stable_snapshot(sequence);
    snapshot.pods.push(KubernetesPodCandidate {
        pod_uid: "77777777-7777-7777-7777-777777777777".to_string(),
        pod_revision_ref: "8".repeat(64),
        marked_for_observation: true,
        deleting: false,
        runtime_class_ref: Some("c".repeat(64)),
        containers: vec![KubernetesContainerCandidate {
            kind: KubernetesContainerKind::Application,
            container_ref: "f".repeat(64),
            runtime_container_id: Some(SECOND_CONTAINER_ID.to_string()),
            running: true,
        }],
    });
    snapshot
}

fn runtime_binding() -> RuntimeBinding {
    RuntimeBinding {
        agent_run_id: AGENT_RUN_ID.to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Containerd,
            workload_id: format!("containerd/{CONTAINER_ID}"),
            start_marker: "42".to_string(),
            host_boot_id: HOST_BOOT_ID.to_string(),
            init_process_start_time_ticks: 103,
            cgroup: CgroupIdentity {
                device: 7,
                inode: 107,
            },
        },
        runtime_handler: Some("runc".to_string()),
    }
}

fn second_runtime_binding() -> RuntimeBinding {
    RuntimeBinding {
        agent_run_id: AGENT_RUN_ID.to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Containerd,
            workload_id: format!("containerd/{SECOND_CONTAINER_ID}"),
            start_marker: "84".to_string(),
            host_boot_id: HOST_BOOT_ID.to_string(),
            init_process_start_time_ticks: 204,
            cgroup: CgroupIdentity {
                device: 7,
                inode: 207,
            },
        },
        runtime_handler: Some("runc".to_string()),
    }
}

fn transitioned_runtime_binding() -> RuntimeBinding {
    let mut binding = runtime_binding();
    binding.identity.start_marker = "43".to_string();
    binding.identity.init_process_start_time_ticks = 104;
    binding.identity.cgroup.inode = 108;
    binding
}

fn test_config(name: &str) -> DaemonConfig {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    DaemonConfig {
        state_dir: std::env::temp_dir().join(format!(
            "apolysis-kubernetes-{name}-{}-{id}",
            std::process::id()
        )),
        ..DaemonConfig::default()
    }
}

// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{
    KubernetesAttributionOptionalRef, KubernetesAttributionRecordType, KubernetesAttributionWireV1,
    KubernetesContainerKind, KubernetesWorkloadClaimV1, RuntimeBindingRecordType,
    RuntimeBindingRuntimeHandler, RuntimeBindingWireV1, KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
    RUNTIME_BINDING_SCHEMA_VERSION,
};
use apolysis_kubernetes::{
    KubernetesAttributionCoordinator, KubernetesAttributionEffect, KubernetesContainerCandidate,
    KubernetesPodCandidate, KubernetesPodSnapshot, KubernetesQualificationCycle,
    KubernetesQualificationError, KubernetesRuntimeInventory, KubernetesSnapshotIdentity,
    KubernetesSourceUnavailableReason,
};

const AGENT_RUN_ID: &str = "agent-run-1";
const CLUSTER_ID: &str = "11111111-1111-1111-1111-111111111111";
const POD_UID: &str = "22222222-2222-2222-2222-222222222222";
const SOURCE_EPOCH: &str = "33333333-3333-3333-3333-333333333333";
const HOST_BOOT_ID: &str = "44444444-4444-4444-4444-444444444444";

#[test]
fn stable_complete_cycle_orders_base_runtime_before_kubernetes_attribution() {
    let runtime = runtime_binding('e', 107);
    let claim = workload_claim();
    let mut coordinator = KubernetesAttributionCoordinator::new();

    let plan = coordinator
        .reconcile(KubernetesQualificationCycle {
            agent_run_id: AGENT_RUN_ID.to_string(),
            claim_revision: 1,
            claims: vec![claim],
            before: stable_snapshot('e', 10),
            runtime: KubernetesRuntimeInventory {
                adapter: "containerd".to_string(),
                bindings: vec![runtime.clone()],
            },
            after: stable_snapshot('e', 11),
        })
        .expect("stable complete cycle qualifies");

    let expected = KubernetesAttributionWireV1 {
        record_type: KubernetesAttributionRecordType::Observed,
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        agent_run_id: AGENT_RUN_ID.to_string(),
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: POD_UID.to_string(),
        node_ref: "b".repeat(64),
        runtime_class_ref: KubernetesAttributionOptionalRef(Some("c".repeat(64))),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "d".repeat(64),
        runtime_binding: runtime.clone(),
    };
    assert_eq!(
        plan.effects,
        vec![
            KubernetesAttributionEffect::EnsureRuntimeObserved { binding: runtime },
            KubernetesAttributionEffect::ObserveAttribution {
                attribution: expected.clone(),
                late_attach_if_runtime_preexisting: true,
            },
        ]
    );
    assert_eq!(plan.claim_revision, 1);
    assert_eq!(
        coordinator.attributions_for_agent_run(AGENT_RUN_ID),
        vec![expected]
    );
}

#[test]
fn repeated_stable_complete_cycle_is_a_no_op() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime.clone(), 20, 21))
        .expect("first cycle qualifies");

    let plan = coordinator
        .reconcile(stable_cycle(runtime, 22, 23))
        .expect("later complete cycle qualifies");

    assert!(plan.effects.is_empty());
    assert_eq!(plan.summary.unchanged, 1);
    assert_eq!(plan.summary.active, 1);
}

#[test]
fn attribution_relevant_a_b_churn_fails_closed_without_changing_active_state() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime.clone(), 30, 31))
        .expect("baseline qualifies");
    let expected = coordinator.attributions_for_agent_run(AGENT_RUN_ID);
    let mut churn = stable_cycle(runtime, 32, 33);
    churn.after.pods[0].containers[0].runtime_container_id = Some("f".repeat(64));

    let error = coordinator
        .reconcile(churn)
        .expect_err("container replacement between A and B must fail closed");

    assert_eq!(
        error.gap_kind(),
        Some(apolysis_kubernetes::KubernetesAttributionGapKind::SnapshotInvalid)
    );
    assert!(!error.requires_runtime_suspension());
    assert_eq!(
        coordinator.attributions_for_agent_run(AGENT_RUN_ID),
        expected
    );
}

#[test]
fn qualification_errors_distinguish_runtime_proof_loss_from_source_only_churn() {
    use apolysis_kubernetes::KubernetesQualificationError;

    assert!(KubernetesQualificationError::RuntimeBindingMissing.requires_runtime_suspension());
    assert!(KubernetesQualificationError::RuntimeBindingConflict.requires_runtime_suspension());
    assert!(KubernetesQualificationError::InvalidField {
        field: "runtime",
        reason: "must contain valid exact runtime bindings",
    }
    .requires_runtime_suspension());
    assert!(!KubernetesQualificationError::SnapshotChanged.requires_runtime_suspension());
    assert!(!KubernetesQualificationError::InvalidField {
        field: "pod_uid",
        reason: "must be canonical",
    }
    .requires_runtime_suspension());
}

#[test]
fn snapshot_container_order_does_not_create_false_attribution_churn() {
    let mut cycle = stable_cycle(runtime_binding('e', 107), 34, 35);
    cycle.claims.push(KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 1,
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: POD_UID.to_string(),
        container_kind: KubernetesContainerKind::Init,
        container_ref: "f".repeat(64),
    });
    let second = KubernetesContainerCandidate {
        kind: KubernetesContainerKind::Init,
        container_ref: "f".repeat(64),
        runtime_container_id: Some("9".repeat(64)),
        running: true,
    };
    cycle.before.pods[0].containers.push(second.clone());
    cycle.after.pods[0].containers.insert(0, second);
    cycle.runtime.bindings.push(runtime_binding('9', 109));
    let mut coordinator = KubernetesAttributionCoordinator::new();

    let plan = coordinator
        .reconcile(cycle)
        .expect("container list order is not attribution-relevant");

    assert_eq!(plan.summary.observed, 2);
    assert_eq!(plan.summary.active, 2);
}

#[test]
fn duplicate_pod_identity_is_rejected_before_any_state_change() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 40, 41);
    let duplicate = cycle.before.pods[0].clone();
    cycle.before.pods.push(duplicate.clone());
    cycle.after.pods.push(duplicate);
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(apolysis_kubernetes::KubernetesQualificationError::DuplicatePod)
    );
    assert!(coordinator
        .attributions_for_agent_run(AGENT_RUN_ID)
        .is_empty());
}

#[test]
fn one_runtime_binding_cannot_be_claimed_by_two_kubernetes_slots() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 50, 51);
    let mut second_pod = cycle.before.pods[0].clone();
    second_pod.pod_uid = "55555555-5555-5555-5555-555555555555".to_string();
    second_pod.containers[0].container_ref = "f".repeat(64);
    cycle.before.pods.push(second_pod.clone());
    cycle.after.pods.push(second_pod);
    cycle.claims.push(KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 1,
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: "55555555-5555-5555-5555-555555555555".to_string(),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "f".repeat(64),
    });
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(apolysis_kubernetes::KubernetesQualificationError::RuntimeBindingConflict)
    );
}

#[test]
fn container_restart_is_an_ordered_attribution_identity_transition() {
    let old_runtime = runtime_binding('e', 107);
    let new_runtime = runtime_binding('f', 109);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(old_runtime, 60, 61))
        .expect("old container qualifies");
    let old = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();

    let plan = coordinator
        .reconcile(KubernetesQualificationCycle {
            agent_run_id: AGENT_RUN_ID.to_string(),
            claim_revision: 1,
            claims: vec![workload_claim()],
            before: stable_snapshot('f', 62),
            runtime: KubernetesRuntimeInventory {
                adapter: "containerd".to_string(),
                bindings: vec![new_runtime.clone()],
            },
            after: stable_snapshot('f', 63),
        })
        .expect("replacement container qualifies");
    let new = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();

    assert_eq!(
        plan.effects,
        vec![
            KubernetesAttributionEffect::PersistGap {
                agent_run_id: AGENT_RUN_ID.to_string(),
                cluster_id: CLUSTER_ID.to_string(),
                kind: apolysis_kubernetes::KubernetesAttributionGapKind::IdentityTransition,
            },
            KubernetesAttributionEffect::RetireAttribution {
                attribution: old.with_record_type(KubernetesAttributionRecordType::Retired),
            },
            KubernetesAttributionEffect::EnsureRuntimeObserved {
                binding: new_runtime,
            },
            KubernetesAttributionEffect::ObserveAttribution {
                attribution: new.clone(),
                late_attach_if_runtime_preexisting: false,
            },
        ]
    );
    assert_eq!(plan.summary.gaps, 1);
    assert_eq!(plan.summary.retired, 1);
    assert_eq!(plan.summary.observed, 1);
    assert_eq!(
        new.runtime_binding.workload_id,
        format!("containerd/{}", "f".repeat(64))
    );
}

#[test]
fn metadata_source_epoch_change_forces_a_restart_boundary_and_fresh_observation() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime.clone(), 64, 65))
        .expect("baseline source epoch qualifies");
    let old = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();
    let mut restarted = stable_cycle(runtime.clone(), 1, 2);
    restarted.before.identity.source_epoch = "55555555-5555-5555-5555-555555555555".to_string();
    restarted.after.identity.source_epoch = restarted.before.identity.source_epoch.clone();

    let plan = coordinator
        .reconcile(restarted)
        .expect("fresh complete snapshot after source restart");
    let fresh = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();

    assert_eq!(
        plan.effects,
        vec![
            KubernetesAttributionEffect::PersistGap {
                agent_run_id: AGENT_RUN_ID.to_string(),
                cluster_id: CLUSTER_ID.to_string(),
                kind: apolysis_kubernetes::KubernetesAttributionGapKind::DaemonRestart,
            },
            KubernetesAttributionEffect::RetireAttribution {
                attribution: old.with_record_type(KubernetesAttributionRecordType::Retired),
            },
            KubernetesAttributionEffect::EnsureRuntimeObserved { binding: runtime },
            KubernetesAttributionEffect::ObserveAttribution {
                attribution: fresh,
                late_attach_if_runtime_preexisting: false,
            },
        ]
    );
}

#[test]
fn same_source_epoch_replayed_sequence_fails_closed_without_changing_active_state() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime.clone(), 66, 67))
        .expect("baseline sequence qualifies");
    let before = coordinator.attributions_for_agent_run(AGENT_RUN_ID);

    let error = coordinator
        .reconcile(stable_cycle(runtime, 67, 68))
        .expect_err("a sequence may not replay the previous terminal snapshot");

    assert_eq!(error, KubernetesQualificationError::SnapshotChanged);
    assert_eq!(coordinator.attributions_for_agent_run(AGENT_RUN_ID), before);
}

#[test]
fn api_unavailability_gaps_then_suspends_only_kubernetes_attribution() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 70, 71))
        .expect("baseline qualifies");
    let active = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();

    let plan = coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("canonical outage produces a plan");

    assert_eq!(
        plan.effects,
        vec![
            KubernetesAttributionEffect::PersistGap {
                agent_run_id: AGENT_RUN_ID.to_string(),
                cluster_id: CLUSTER_ID.to_string(),
                kind: apolysis_kubernetes::KubernetesAttributionGapKind::ApiUnavailable,
            },
            KubernetesAttributionEffect::SuspendAttribution {
                attribution: active.with_record_type(KubernetesAttributionRecordType::Suspended),
            },
        ]
    );
    assert_eq!(plan.summary.gaps, 1);
    assert_eq!(plan.summary.suspended, 1);
    assert!(coordinator
        .attributions_for_agent_run(AGENT_RUN_ID)
        .is_empty());
    let repeated = coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("repeated outage is idempotent");
    assert!(repeated.effects.is_empty());
}

#[test]
fn outage_recovery_reobserves_without_a_second_late_attach_boundary() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime.clone(), 74, 75))
        .expect("baseline qualifies");
    coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("source outage suspends attribution");

    let recovery = coordinator
        .reconcile(stable_cycle(runtime, 76, 77))
        .expect("fresh complete recovery");

    assert!(recovery.effects.iter().any(|effect| matches!(
        effect,
        KubernetesAttributionEffect::ObserveAttribution {
            late_attach_if_runtime_preexisting: false,
            ..
        }
    )));
}

#[test]
fn first_seen_during_a_zero_active_outage_stays_a_late_attach_candidate() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("initial zero-active outage is durable");

    let recovery = coordinator
        .reconcile(stable_cycle(runtime, 78, 79))
        .expect("first visible candidate qualifies");

    assert!(recovery.effects.iter().any(|effect| matches!(
        effect,
        KubernetesAttributionEffect::ObserveAttribution {
            late_attach_if_runtime_preexisting: true,
            ..
        }
    )));
}

#[test]
fn recovered_attribution_stays_dormant_until_a_fresh_complete_cycle() {
    let runtime = runtime_binding('e', 107);
    let mut baseline = KubernetesAttributionCoordinator::new();
    baseline
        .reconcile(stable_cycle(runtime.clone(), 80, 81))
        .expect("baseline qualifies");
    let recovered = baseline.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();
    let mut coordinator =
        KubernetesAttributionCoordinator::recover_dormant(vec![recovered.clone()])
            .expect("valid durable attribution recovers dormant");

    assert!(coordinator
        .attributions_for_agent_run(AGENT_RUN_ID)
        .is_empty());
    let plan = coordinator
        .reconcile(stable_cycle(runtime.clone(), 82, 83))
        .expect("fresh cycle requalifies dormant attribution");

    assert_eq!(
        plan.effects,
        vec![
            KubernetesAttributionEffect::PersistGap {
                agent_run_id: AGENT_RUN_ID.to_string(),
                cluster_id: CLUSTER_ID.to_string(),
                kind: apolysis_kubernetes::KubernetesAttributionGapKind::DaemonRestart,
            },
            KubernetesAttributionEffect::RetireDormantAttribution {
                attribution: recovered.with_record_type(KubernetesAttributionRecordType::Retired),
            },
            KubernetesAttributionEffect::EnsureRuntimeObserved { binding: runtime },
            KubernetesAttributionEffect::ObserveAttribution {
                attribution: coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone(),
                late_attach_if_runtime_preexisting: false,
            },
        ]
    );
}

#[test]
fn snapshot_identity_is_validated_before_an_empty_or_complete_set_can_be_authoritative() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 90, 91);
    cycle.before.identity.source_epoch = "33333333-3333-3333-3333-33333333333A".to_string();
    cycle.after.identity.source_epoch = cycle.before.identity.source_epoch.clone();
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InvalidField {
                field: "source_epoch",
                reason: "must be a canonical lowercase non-zero UUID",
            }
        )
    );
}

#[test]
fn cycle_bounds_are_enforced_before_duplicate_or_join_work() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 100, 101);
    cycle.claims =
        vec![workload_claim(); apolysis_kubernetes::MAX_KUBERNETES_REGISTERED_CLAIMS + 1];
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InventoryTooLarge {
                inventory: "claims",
                actual: apolysis_kubernetes::MAX_KUBERNETES_REGISTERED_CLAIMS + 1,
                maximum: apolysis_kubernetes::MAX_KUBERNETES_REGISTERED_CLAIMS,
            }
        )
    );
}

#[test]
fn kubernetes_qualification_rejects_non_cri_runtime_profiles() {
    let mut docker = runtime_binding('e', 107);
    docker.adapter = "docker".to_string();
    docker.workload_id = "e".repeat(64);
    docker.start_marker = "2026-08-12T01:02:03.000000000Z".to_string();
    let mut cycle = stable_cycle(docker, 110, 111);
    cycle.runtime.adapter = "docker".to_string();
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InvalidField {
                field: "runtime.adapter",
                reason: "must be containerd or k3s_containerd",
            }
        )
    );
}

#[test]
fn another_agent_run_cannot_steal_an_active_physical_kubernetes_slot() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 120, 121))
        .expect("first run qualifies");
    let existing = coordinator.attributions_for_agent_run(AGENT_RUN_ID);
    let mut conflicting_runtime = runtime_binding('e', 107);
    conflicting_runtime.agent_run_id = "agent-run-2".to_string();
    let mut conflict = stable_cycle(conflicting_runtime, 122, 123);
    conflict.agent_run_id = "agent-run-2".to_string();
    let error = coordinator
        .reconcile(conflict)
        .expect_err("active physical slot ownership is not transferable");

    assert_eq!(
        error,
        apolysis_kubernetes::KubernetesQualificationError::RuntimeBindingConflict
    );
    assert_eq!(
        coordinator.attributions_for_agent_run(AGENT_RUN_ID),
        existing
    );
    assert!(coordinator
        .attributions_for_agent_run("agent-run-2")
        .is_empty());
}

#[test]
fn retiring_an_agent_run_clears_only_its_active_attributions_idempotently() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 130, 131))
        .expect("baseline qualifies");
    let active = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();

    let plan = coordinator
        .retire_agent_run(AGENT_RUN_ID, 1)
        .expect("canonical close produces a plan");

    assert_eq!(
        plan.effects,
        vec![KubernetesAttributionEffect::RetireAttribution {
            attribution: active.with_record_type(KubernetesAttributionRecordType::Retired),
        }]
    );
    assert!(coordinator
        .attributions_for_agent_run(AGENT_RUN_ID)
        .is_empty());
    assert!(coordinator
        .retire_agent_run(AGENT_RUN_ID, 1)
        .expect("repeated close is idempotent")
        .effects
        .is_empty());
}

#[test]
fn invalid_outage_or_retire_request_does_not_change_active_state() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 132, 133))
        .expect("baseline qualifies");
    let active = coordinator.attributions_for_agent_run(AGENT_RUN_ID);

    assert_eq!(
        coordinator.source_unavailable(
            AGENT_RUN_ID,
            1,
            "22222222-2222-2222-2222-22222222222A",
            KubernetesSourceUnavailableReason::ApiUnavailable,
        ),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InvalidField {
                field: "cluster_id",
                reason: "must be a canonical lowercase non-zero UUID",
            }
        )
    );
    assert_eq!(coordinator.attributions_for_agent_run(AGENT_RUN_ID), active);
    assert_eq!(
        coordinator
            .attributions_for_agent_run_at_revision(AGENT_RUN_ID, 1)
            .len(),
        1
    );

    assert_eq!(
        coordinator.retire_agent_run(AGENT_RUN_ID, 0),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InvalidField {
                field: "claim_revision",
                reason: "must be non-zero",
            }
        )
    );
    assert_eq!(coordinator.attributions_for_agent_run(AGENT_RUN_ID), active);
    assert_eq!(
        coordinator
            .attributions_for_agent_run_at_revision(AGENT_RUN_ID, 1)
            .len(),
        1
    );
}

#[test]
fn dormant_recovery_rejects_the_whole_batch_when_one_record_is_invalid() {
    let runtime = runtime_binding('e', 107);
    let mut baseline = KubernetesAttributionCoordinator::new();
    baseline
        .reconcile(stable_cycle(runtime, 134, 135))
        .expect("baseline qualifies");
    let valid = baseline.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();
    let mut invalid = valid.clone();
    invalid.namespace_ref = "raw-namespace".to_string();

    let error = KubernetesAttributionCoordinator::recover_dormant(vec![valid, invalid])
        .expect_err("a partial dormant coordinator must never be returned");
    assert_eq!(
        error,
        apolysis_kubernetes::KubernetesQualificationError::InvalidField {
            field: "recovered_attributions",
            reason: "must contain valid observed Kubernetes attributions",
        }
    );
}

#[test]
fn pod_and_container_candidate_fields_are_validated_before_joining() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 140, 141);
    cycle.before.pods[0].pod_uid = "22222222-2222-2222-2222-22222222222A".to_string();
    cycle.after.pods[0].pod_uid = cycle.before.pods[0].pod_uid.clone();
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InvalidField {
                field: "pod_uid",
                reason: "must be a canonical lowercase non-zero UUID",
            }
        )
    );
}

#[test]
fn coordinator_lists_runs_that_need_source_outage_or_recovery_handling() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 150, 151))
        .expect("baseline qualifies");
    assert_eq!(coordinator.agent_run_ids(), vec![AGENT_RUN_ID.to_string()]);

    coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("outage suspends active attribution");
    assert_eq!(coordinator.agent_run_ids(), vec![AGENT_RUN_ID.to_string()]);
}

#[test]
fn multi_container_source_outage_writes_one_run_gap_before_all_suspends() {
    let mut cycle = stable_cycle(runtime_binding('e', 107), 160, 161);
    let second_claim = KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 1,
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: POD_UID.to_string(),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "f".repeat(64),
    };
    let second_container = KubernetesContainerCandidate {
        kind: KubernetesContainerKind::Application,
        container_ref: "f".repeat(64),
        runtime_container_id: Some("9".repeat(64)),
        running: true,
    };
    cycle.claims.push(second_claim);
    cycle.before.pods[0]
        .containers
        .push(second_container.clone());
    cycle.after.pods[0].containers.push(second_container);
    cycle.runtime.bindings.push(runtime_binding('9', 109));
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator.reconcile(cycle).expect("two slots qualify");

    let plan = coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("outage plans both suspends");

    assert_eq!(plan.summary.gaps, 1);
    assert_eq!(plan.summary.suspended, 2);
    assert_eq!(plan.effects.len(), 3);
    assert!(matches!(
        plan.effects.first(),
        Some(KubernetesAttributionEffect::PersistGap {
            agent_run_id,
            cluster_id,
            kind: apolysis_kubernetes::KubernetesAttributionGapKind::ApiUnavailable,
        }) if agent_run_id == AGENT_RUN_ID && cluster_id == CLUSTER_ID
    ));
    assert!(plan.effects[1..].iter().all(|effect| matches!(
        effect,
        KubernetesAttributionEffect::SuspendAttribution { .. }
    )));
}

#[test]
fn complete_runtime_inventory_rejects_cgroup_conflicts_even_when_one_binding_is_unclaimed() {
    let mut cycle = stable_cycle(runtime_binding('e', 107), 170, 171);
    cycle.runtime.bindings.push(runtime_binding('f', 107));
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(apolysis_kubernetes::KubernetesQualificationError::RuntimeBindingConflict)
    );
}

#[test]
fn first_source_outage_is_durable_even_before_any_attribution_is_active() {
    let mut coordinator = KubernetesAttributionCoordinator::new();

    let plan = coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("registered source outage produces a plan");

    assert_eq!(
        plan.effects,
        vec![KubernetesAttributionEffect::PersistGap {
            agent_run_id: AGENT_RUN_ID.to_string(),
            cluster_id: CLUSTER_ID.to_string(),
            kind: apolysis_kubernetes::KubernetesAttributionGapKind::ApiUnavailable,
        }]
    );
    assert_eq!(plan.summary.gaps, 1);
    assert_eq!(plan.summary.suspended, 0);
    let repeated = coordinator
        .source_unavailable(
            AGENT_RUN_ID,
            1,
            CLUSTER_ID,
            KubernetesSourceUnavailableReason::ApiUnavailable,
        )
        .expect("same outage is idempotent");
    assert!(repeated.effects.is_empty());
}

#[test]
fn stable_terminated_container_is_authoritative_absence_not_an_invalid_snapshot() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 180, 181))
        .expect("running container qualifies");
    let active = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();
    let mut before = stable_snapshot('e', 182);
    before.pods[0].containers[0].running = false;
    before.pods[0].containers[0].runtime_container_id = None;
    let mut after = before.clone();
    after.sequence = 183;
    let terminated = KubernetesQualificationCycle {
        agent_run_id: AGENT_RUN_ID.to_string(),
        claim_revision: 1,
        claims: vec![workload_claim()],
        before,
        runtime: KubernetesRuntimeInventory {
            adapter: "containerd".to_string(),
            bindings: Vec::new(),
        },
        after,
    };

    let plan = coordinator
        .reconcile(terminated.clone())
        .expect("complete terminated snapshot retires the old link");

    assert_eq!(
        plan.effects,
        vec![KubernetesAttributionEffect::RetireAttribution {
            attribution: active.with_record_type(KubernetesAttributionRecordType::Retired),
        }]
    );
    let pending = KubernetesAttributionCoordinator::new()
        .reconcile(terminated)
        .expect("fresh terminated claim is a pending no-op");
    assert!(pending.effects.is_empty());
}

#[test]
fn duplicate_claim_slot_is_rejected_before_runtime_joining() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 190, 191);
    cycle.claims.push(workload_claim());
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(apolysis_kubernetes::KubernetesQualificationError::DuplicateClaim)
    );
}

#[test]
fn stable_absent_pod_retires_an_active_link_and_is_a_fresh_pending_no_op() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime, 200, 201))
        .expect("running pod qualifies");
    let active = coordinator.attributions_for_agent_run(AGENT_RUN_ID)[0].clone();
    let empty_snapshot = |sequence| KubernetesPodSnapshot {
        sequence,
        identity: KubernetesSnapshotIdentity {
            source_epoch: SOURCE_EPOCH.to_string(),
            cluster_id: CLUSTER_ID.to_string(),
            namespace_ref: "a".repeat(64),
            node_ref: "b".repeat(64),
        },
        pods: Vec::new(),
    };
    let absent = KubernetesQualificationCycle {
        agent_run_id: AGENT_RUN_ID.to_string(),
        claim_revision: 1,
        claims: vec![workload_claim()],
        before: empty_snapshot(202),
        runtime: KubernetesRuntimeInventory {
            adapter: "containerd".to_string(),
            bindings: Vec::new(),
        },
        after: empty_snapshot(203),
    };

    let plan = coordinator
        .reconcile(absent.clone())
        .expect("complete absent Pod set retires the old link");

    assert_eq!(
        plan.effects,
        vec![KubernetesAttributionEffect::RetireAttribution {
            attribution: active.with_record_type(KubernetesAttributionRecordType::Retired),
        }]
    );
    assert!(KubernetesAttributionCoordinator::new()
        .reconcile(absent)
        .expect("not-yet-created claimed Pod is pending")
        .effects
        .is_empty());
}

#[test]
fn multi_container_transition_writes_one_gap_then_all_retires_then_observations() {
    let mut initial = stable_cycle(runtime_binding('e', 107), 210, 211);
    initial.claims.push(KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 1,
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: POD_UID.to_string(),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "f".repeat(64),
    });
    let second = KubernetesContainerCandidate {
        kind: KubernetesContainerKind::Application,
        container_ref: "f".repeat(64),
        runtime_container_id: Some("9".repeat(64)),
        running: true,
    };
    initial.before.pods[0].containers.push(second.clone());
    initial.after.pods[0].containers.push(second);
    initial.runtime.bindings.push(runtime_binding('9', 109));
    let mut replacement = initial.clone();
    replacement.before.sequence = 212;
    replacement.after.sequence = 213;
    replacement.before.pods[0].containers[0].runtime_container_id = Some("8".repeat(64));
    replacement.after.pods[0].containers[0].runtime_container_id = Some("8".repeat(64));
    replacement.before.pods[0].containers[1].runtime_container_id = Some("7".repeat(64));
    replacement.after.pods[0].containers[1].runtime_container_id = Some("7".repeat(64));
    replacement.runtime.bindings = vec![runtime_binding('8', 111), runtime_binding('7', 113)];
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator.reconcile(initial).expect("two slots qualify");

    let plan = coordinator
        .reconcile(replacement)
        .expect("both replacement containers qualify");

    assert_eq!(plan.summary.gaps, 1);
    assert_eq!(plan.summary.retired, 2);
    assert_eq!(plan.summary.observed, 2);
    assert_eq!(plan.effects.len(), 7);
    assert!(matches!(
        plan.effects[0],
        KubernetesAttributionEffect::PersistGap {
            kind: apolysis_kubernetes::KubernetesAttributionGapKind::IdentityTransition,
            ..
        }
    ));
    assert!(plan.effects[1..3].iter().all(|effect| matches!(
        effect,
        KubernetesAttributionEffect::RetireAttribution { .. }
    )));
    assert!(plan.effects[3..].chunks_exact(2).all(|pair| matches!(
        (&pair[0], &pair[1]),
        (
            KubernetesAttributionEffect::EnsureRuntimeObserved { .. },
            KubernetesAttributionEffect::ObserveAttribution { .. }
        )
    )));
}

#[test]
fn attribution_query_requires_the_last_freshly_qualified_claim_revision() {
    let runtime = runtime_binding('e', 107);
    let mut coordinator = KubernetesAttributionCoordinator::new();
    coordinator
        .reconcile(stable_cycle(runtime.clone(), 220, 221))
        .expect("revision one qualifies");

    assert_eq!(
        coordinator
            .attributions_for_agent_run_at_revision(AGENT_RUN_ID, 1)
            .len(),
        1
    );
    assert!(coordinator
        .attributions_for_agent_run_at_revision(AGENT_RUN_ID, 2)
        .is_empty());

    let mut revision_two = stable_cycle(runtime, 222, 223);
    revision_two.claim_revision = 2;
    revision_two.claims[0].claim_revision = 2;
    let plan = coordinator
        .reconcile(revision_two)
        .expect("same slot gets a fresh revision-two qualification");

    assert!(plan.effects.is_empty());
    assert!(coordinator
        .attributions_for_agent_run_at_revision(AGENT_RUN_ID, 1)
        .is_empty());
    assert_eq!(
        coordinator
            .attributions_for_agent_run_at_revision(AGENT_RUN_ID, 2)
            .len(),
        1
    );
}

#[test]
fn per_source_cycle_rejects_claims_from_another_cluster_or_namespace() {
    let runtime = runtime_binding('e', 107);
    let mut cycle = stable_cycle(runtime, 230, 231);
    cycle.claims[0].namespace_ref = "f".repeat(64);
    let mut coordinator = KubernetesAttributionCoordinator::new();

    assert_eq!(
        coordinator.reconcile(cycle),
        Err(
            apolysis_kubernetes::KubernetesQualificationError::InvalidField {
                field: "claims",
                reason: "must belong to the cycle cluster and namespace",
            }
        )
    );
}

fn workload_claim() -> KubernetesWorkloadClaimV1 {
    KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 1,
        cluster_id: CLUSTER_ID.to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: POD_UID.to_string(),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "d".repeat(64),
    }
}

fn stable_cycle(
    runtime: RuntimeBindingWireV1,
    before_sequence: u64,
    after_sequence: u64,
) -> KubernetesQualificationCycle {
    KubernetesQualificationCycle {
        agent_run_id: AGENT_RUN_ID.to_string(),
        claim_revision: 1,
        claims: vec![workload_claim()],
        before: stable_snapshot('e', before_sequence),
        runtime: KubernetesRuntimeInventory {
            adapter: "containerd".to_string(),
            bindings: vec![runtime],
        },
        after: stable_snapshot('e', after_sequence),
    }
}

#[test]
fn pod_revision_churn_rejects_an_otherwise_identical_complete_cycle() {
    let mut cycle = stable_cycle(runtime_binding('e', 71), 1, 2);
    cycle.after.pods[0].pod_revision_ref = "f".repeat(64);

    let error = KubernetesAttributionCoordinator::new()
        .reconcile(cycle)
        .expect_err("Pod object revision changed between the two authoritative lists");

    assert_eq!(error, KubernetesQualificationError::SnapshotChanged);
}

fn stable_snapshot(container_id_digit: char, sequence: u64) -> KubernetesPodSnapshot {
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
                runtime_container_id: Some(container_id_digit.to_string().repeat(64)),
                running: true,
            }],
        }],
    }
}

fn runtime_binding(container_id_digit: char, cgroup_id: u64) -> RuntimeBindingWireV1 {
    RuntimeBindingWireV1 {
        record_type: RuntimeBindingRecordType::Observed,
        schema_version: RUNTIME_BINDING_SCHEMA_VERSION,
        agent_run_id: AGENT_RUN_ID.to_string(),
        adapter: "containerd".to_string(),
        workload_id: format!("containerd/{}", container_id_digit.to_string().repeat(64)),
        start_marker: "42".to_string(),
        host_boot_id: HOST_BOOT_ID.to_string(),
        init_process_start_time_ticks: 103,
        cgroup_device: 7,
        cgroup_id,
        runtime_handler: RuntimeBindingRuntimeHandler(Some("runc".to_string())),
    }
}

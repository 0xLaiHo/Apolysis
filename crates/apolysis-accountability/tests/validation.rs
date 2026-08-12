// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    project_agent_run, validate_agent_observation_record_v1, AgentObservationRecord,
    AgentObservationRecordValidationError, AgentRunRecordBatch, CollectorHealthProjection,
    EvidenceState, ProjectionError, ProjectionIssue, ProjectionIssueCode, ReviewState,
};
use apolysis_core::audit_observer_capability_contract_v1;
use serde_json::{json, Value};

#[test]
fn validator_rejects_summary_grouping_mismatches() {
    for mutate in [
        |record: &mut AgentObservationRecord| {
            record
                .summary
                .event_type_counts
                .insert("network_connect".to_string(), 2);
        },
        |record: &mut AgentObservationRecord| {
            record
                .summary
                .outcome_counts
                .insert("succeeded".to_string(), 2);
        },
        |record: &mut AgentObservationRecord| {
            record
                .summary
                .relation_counts
                .insert("exact".to_string(), 2);
        },
        |record: &mut AgentObservationRecord| {
            record
                .summary
                .finding_kind_counts
                .insert("unknown_egress".to_string(), 1);
        },
        |record: &mut AgentObservationRecord| {
            record
                .summary
                .gap_kind_counts
                .insert("missing_exit".to_string(), 1);
        },
        |record: &mut AgentObservationRecord| {
            record.summary.known_missing_observation_count = 1;
        },
        |record: &mut AgentObservationRecord| {
            record.summary.unknown_history_boundary_count = 1;
        },
    ] {
        let mut record = complete_record();
        mutate(&mut record);
        assert!(validate_agent_observation_record_v1(&record).is_err());
    }
}

#[test]
fn validator_rejects_summary_count_mismatches() {
    for mutate in [
        |record: &mut AgentObservationRecord| record.summary.runtime_observation_count = 2,
        |record: &mut AgentObservationRecord| record.summary.runtime_identity_count = 2,
        |record: &mut AgentObservationRecord| record.summary.finding_count = 1,
        |record: &mut AgentObservationRecord| record.summary.observation_gap_record_count = 1,
    ] {
        let mut record = complete_record();
        mutate(&mut record);
        assert!(validate_agent_observation_record_v1(&record).is_err());
    }
}

#[test]
fn validator_rejects_invalid_projected_source_ordinals() {
    for mutate in [
        |record: &mut AgentObservationRecord| record.runtime_observations[0].source_ordinal = 0,
        |record: &mut AgentObservationRecord| record.runtime_observations[0].source_ordinal = 2,
        |record: &mut AgentObservationRecord| {
            record.collector_lifecycle[0].source_ordinal = 5;
        },
    ] {
        let mut record = complete_record();
        mutate(&mut record);
        assert!(validate_agent_observation_record_v1(&record).is_err());
    }
}

#[test]
fn validator_rejects_inconsistent_exact_runtime_identity_links() {
    let mut missing_link = complete_record();
    missing_link.runtime_observations[0].runtime_identity_id = None;
    assert!(validate_agent_observation_record_v1(&missing_link).is_err());

    let mut dangling_link = complete_record();
    dangling_link.runtime_observations[0].runtime_identity_id = Some("identity-404".to_string());
    assert!(validate_agent_observation_record_v1(&dangling_link).is_err());

    let mut incorrect_aggregate = complete_record();
    incorrect_aggregate.runtime_identities[0].observation_count = 2;
    assert!(validate_agent_observation_record_v1(&incorrect_aggregate).is_err());

    let mut non_exact_link = complete_record();
    non_exact_link.runtime_observations[0].relation_status = "inferred".to_string();
    non_exact_link.summary.relation_counts.clear();
    non_exact_link
        .summary
        .relation_counts
        .insert("inferred".to_string(), 1);
    assert!(validate_agent_observation_record_v1(&non_exact_link).is_err());
}

#[test]
fn validator_accepts_explicit_unresolved_findings_and_rejects_hidden_dangling_refs() {
    let resolved = record_with_finding("event-1");
    assert!(validate_agent_observation_record_v1(&resolved).is_ok());

    let dangling = record_with_finding("missing-event");
    assert!(validate_agent_observation_record_v1(&dangling).is_ok());

    let mut hidden_dangling = dangling;
    hidden_dangling.issues.clear();
    assert!(validate_agent_observation_record_v1(&hidden_dangling).is_err());
}

#[test]
fn validator_rebuilds_runtime_binding_support_and_accepts_old_records_without_the_additive_field() {
    let resolved = record_with_runtime_binding_finding();
    assert!(validate_agent_observation_record_v1(&resolved).is_ok());

    let mut mismatched_runtime = resolved.clone();
    mismatched_runtime.findings[0].runtime.cgroup_id = Some(910);
    assert_eq!(
        validate_agent_observation_record_v1(&mismatched_runtime),
        Err(AgentObservationRecordValidationError::InvalidFindingReference)
    );

    let mut late_support = resolved.clone();
    late_support.runtime_bindings[0].source_ordinal = 99;
    assert_eq!(
        validate_agent_observation_record_v1(&late_support),
        Err(AgentObservationRecordValidationError::InvalidFindingReference)
    );

    let mut terminal_only = serde_json::to_value(resolved).expect("serialize projected record");
    terminal_only["runtime_bindings"][0]["record_type"] = json!("runtime_binding_retired");
    let terminal_only: AgentObservationRecord =
        serde_json::from_value(terminal_only).expect("deserialize terminal-only record");
    assert_eq!(
        validate_agent_observation_record_v1(&terminal_only),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );

    let mut old_value = serde_json::to_value(complete_record()).expect("serialize old record");
    old_value
        .as_object_mut()
        .expect("record object")
        .remove("runtime_bindings");
    let old_record: AgentObservationRecord =
        serde_json::from_value(old_value).expect("deserialize pre-field AOR v1");
    assert!(old_record.runtime_bindings.is_empty());
    assert!(validate_agent_observation_record_v1(&old_record).is_ok());
}

#[test]
fn validator_rejects_runtime_retirement_before_kubernetes_attribution_retirement() {
    let agent_run_id = "run-kubernetes-frozen-order";
    let observed = containerd_runtime_binding(agent_run_id, "runtime_binding_observed");
    let retired = containerd_runtime_binding(agent_run_id, "runtime_binding_retired");
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        observed.clone(),
        kubernetes_attribution(
            agent_run_id,
            "kubernetes_attribution_observed",
            observed.clone(),
        ),
        kubernetes_attribution(agent_run_id, "kubernetes_attribution_retired", observed),
        retired,
    ])])
    .expect("project legal Kubernetes retirement order");
    let mut value = serde_json::to_value(record).expect("serialize Kubernetes AOR");
    value["runtime_bindings"][1]["source_ordinal"] = json!(4);
    value["kubernetes_attributions"][1]["source_ordinal"] = json!(5);
    let reordered: AgentObservationRecord =
        serde_json::from_value(value).expect("deserialize reordered Kubernetes AOR");

    assert_eq!(
        validate_agent_observation_record_v1(&reordered),
        Err(AgentObservationRecordValidationError::InvalidKubernetesAttribution)
    );
}

#[test]
fn validator_rejects_runtime_binding_suspension_without_a_source_gap() {
    let mut record = runtime_suspension_record("docker");
    record.observation_gaps.clear();
    record
        .issues
        .retain(|issue| issue.code != ProjectionIssueCode::ObservationGap);
    record.summary.observation_gap_record_count = 0;
    record.summary.gap_kind_counts.clear();

    assert_eq!(
        validate_agent_observation_record_v1(&record),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );
}

#[test]
fn validator_rejects_runtime_binding_suspension_with_a_different_source_gap() {
    let record = runtime_suspension_record("docker");
    let mut value = serde_json::to_value(record).expect("serialize runtime suspension AOR");
    value["observation_gaps"][0]["runtime_source"] = json!("containerd");
    let wrong_source =
        serde_json::from_value(value).expect("deserialize source-qualified runtime gap");

    assert_eq!(
        validate_agent_observation_record_v1(&wrong_source),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );
}

#[test]
fn validator_rejects_reusing_one_runtime_source_gap_for_two_suspensions() {
    let record = runtime_suspension_record("docker");
    let mut value = serde_json::to_value(record).expect("serialize runtime suspension AOR");
    let mut observed = value["runtime_bindings"][0].clone();
    observed["source_ordinal"] = json!(5);
    observed["workload_id"] =
        json!("1111111111111111111111111111111111111111111111111111111111111111");
    observed["start_marker"] = json!("2026-08-11T01:02:04.000000000Z");
    observed["init_process_start_time_ticks"] = json!(124);
    observed["cgroup_id"] = json!(910);
    let mut suspended = observed.clone();
    suspended["source_ordinal"] = json!(6);
    suspended["record_type"] = json!("runtime_binding_suspended");
    value["runtime_bindings"]
        .as_array_mut()
        .expect("runtime binding array")
        .extend([observed, suspended]);
    let reused_credit = serde_json::from_value(value).expect("deserialize repeated suspension AOR");

    assert_eq!(
        validate_agent_observation_record_v1(&reused_credit),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );
}

#[test]
fn validator_does_not_treat_daemon_restart_as_a_suspension_credit() {
    let agent_run_id = "run-runtime-restart-validation";
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        runtime_binding(agent_run_id, "docker", "runtime_binding_observed"),
        runtime_metadata_gap(agent_run_id, "docker", "daemon_restart", 1),
        runtime_binding(agent_run_id, "docker", "runtime_binding_retired"),
    ])])
    .expect("project legal daemon-restart retirement fixture");
    let mut value = serde_json::to_value(record).expect("serialize daemon-restart AOR");
    value["runtime_bindings"][1]["record_type"] = json!("runtime_binding_suspended");
    let invalid_suspension =
        serde_json::from_value(value).expect("deserialize daemon-restart suspension AOR");

    assert_eq!(
        validate_agent_observation_record_v1(&invalid_suspension),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );
}

#[test]
fn validator_accepts_one_prior_same_source_gap_for_one_suspension() {
    let record = runtime_suspension_record("docker");

    assert_eq!(
        record.observation_gaps[0].runtime_source.as_deref(),
        Some("docker")
    );
    assert_eq!(
        record.observation_gaps[0].runtime_reason.as_deref(),
        Some("socket_unavailable")
    );
    assert!(validate_agent_observation_record_v1(&record).is_ok());
}

#[test]
fn validator_rejects_a_runtime_source_gap_after_the_suspension() {
    let mut record = runtime_suspension_record("docker");
    record.observation_gaps[0].source_ordinal = 5;
    record
        .issues
        .iter_mut()
        .find(|issue| issue.code == ProjectionIssueCode::ObservationGap)
        .expect("runtime-gap issue")
        .source_ordinal = Some(5);

    assert_eq!(
        validate_agent_observation_record_v1(&record),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );
}

#[test]
fn validator_rejects_a_runtime_source_gap_with_a_non_unit_count() {
    let mut record = runtime_suspension_record("docker");
    record.observation_gaps[0].count = 2;
    record
        .issues
        .iter_mut()
        .find(|issue| issue.code == ProjectionIssueCode::ObservationGap)
        .expect("runtime-gap issue")
        .count = 2;

    assert!(validate_agent_observation_record_v1(&record).is_err());
}

#[test]
fn validator_reads_legacy_runtime_gaps_but_never_uses_missing_metadata_as_credit() {
    let suspension = runtime_suspension_record("docker");
    let mut suspension_value =
        serde_json::to_value(suspension).expect("serialize runtime suspension AOR");
    let suspension_gap = suspension_value["observation_gaps"][0]
        .as_object_mut()
        .expect("runtime gap object");
    suspension_gap.remove("runtime_source");
    suspension_gap.remove("runtime_reason");
    let legacy_suspension =
        serde_json::from_value(suspension_value).expect("read legacy runtime suspension AOR");
    assert_eq!(
        validate_agent_observation_record_v1(&legacy_suspension),
        Err(AgentObservationRecordValidationError::InvalidRuntimeBinding)
    );

    let retirement = runtime_retirement_record("daemon_restart");
    let mut retirement_value =
        serde_json::to_value(retirement).expect("serialize runtime retirement AOR");
    let retirement_gap = retirement_value["observation_gaps"][0]
        .as_object_mut()
        .expect("runtime gap object");
    retirement_gap.remove("runtime_source");
    retirement_gap.remove("runtime_reason");
    let legacy_retirement =
        serde_json::from_value(retirement_value).expect("read legacy runtime retirement AOR");
    assert!(validate_agent_observation_record_v1(&legacy_retirement).is_ok());
}

#[test]
fn validator_rejects_partial_unknown_or_private_runtime_gap_metadata() {
    let valid = runtime_retirement_record("daemon_restart");
    for mutate in [
        |value: &mut Value| {
            value["observation_gaps"][0]
                .as_object_mut()
                .expect("runtime gap object")
                .remove("runtime_source");
        },
        |value: &mut Value| {
            value["observation_gaps"][0]
                .as_object_mut()
                .expect("runtime gap object")
                .remove("runtime_reason");
        },
        |value: &mut Value| {
            value["observation_gaps"][0]["runtime_source"] = json!("unknown_runtime");
        },
        |value: &mut Value| {
            value["observation_gaps"][0]["runtime_reason"] = json!("backend_timeout");
        },
        |value: &mut Value| {
            value["observation_gaps"][0]["runtime_source"] = json!("/run/private.sock");
        },
        |value: &mut Value| {
            value["observation_gaps"][0]["runtime_reason"] =
                json!("socket_unavailable:/run/private.sock");
        },
    ] {
        let mut value = serde_json::to_value(valid.clone()).expect("serialize runtime gap AOR");
        mutate(&mut value);
        let record: AgentObservationRecord =
            serde_json::from_value(value).expect("deserialize malformed runtime gap metadata");
        assert_eq!(
            validate_agent_observation_record_v1(&record),
            Err(AgentObservationRecordValidationError::InvalidObservationGap)
        );
    }
}

#[test]
fn validator_rejects_runtime_gap_metadata_on_an_unrelated_gap() {
    let mut value = serde_json::to_value(gap_record()).expect("serialize observation-gap AOR");
    value["observation_gaps"][0]["runtime_source"] = json!("docker");
    value["observation_gaps"][0]["runtime_reason"] = json!("socket_unavailable");
    let record = serde_json::from_value(value).expect("deserialize unrelated gap metadata");

    assert_eq!(
        validate_agent_observation_record_v1(&record),
        Err(AgentObservationRecordValidationError::InvalidObservationGap)
    );
}

#[test]
fn validator_preserves_legal_restart_transition_and_inventory_sequences() {
    let agent_run_id = "run-runtime-sequence-validation";
    let observed = runtime_binding(agent_run_id, "docker", "runtime_binding_observed");
    let retired = runtime_binding(agent_run_id, "docker", "runtime_binding_retired");

    let daemon_restart = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        observed.clone(),
        runtime_metadata_gap(agent_run_id, "docker", "daemon_restart", 1),
        retired.clone(),
        observed.clone(),
    ])])
    .expect("project legal daemon-restart sequence");

    let mut replacement = observed.clone();
    replacement["start_marker"] = json!("2026-08-11T01:02:04.000000000Z");
    replacement["init_process_start_time_ticks"] = json!(124);
    replacement["cgroup_id"] = json!(910);
    let identity_transition = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        observed.clone(),
        runtime_metadata_gap(agent_run_id, "docker", "identity_transition", 1),
        retired.clone(),
        replacement,
    ])])
    .expect("project legal identity-transition sequence");

    let complete_inventory = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        observed.clone(),
        retired,
        observed,
    ])])
    .expect("project legal complete-inventory retire and reobserve sequence");

    for record in [daemon_restart, identity_transition, complete_inventory] {
        assert!(validate_agent_observation_record_v1(&record).is_ok());
    }
}

#[test]
fn validator_accepts_legitimate_three_axis_states_and_diagnostic_ambiguity() {
    for record in [
        complete_record(),
        active_record(),
        record_with_finding("missing-event"),
        mixed_record(),
        failed_record(),
        diagnostic_record("decode_failure"),
        diagnostic_record("attach_failure"),
    ] {
        assert!(validate_agent_observation_record_v1(&record).is_ok());
    }
}

#[test]
fn projector_rejects_collector_instance_transition_without_restart_gap() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-restart-validation", 1_000),
        lifecycle_for_instance(
            "run-restart-validation",
            "collector-1",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-restart-validation", 1_002),
        lifecycle_for_instance(
            "run-restart-validation",
            "collector-1",
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        lifecycle_for_instance(
            "run-restart-validation",
            "collector-2",
            1_004,
            "started",
            "healthy",
            Value::Null,
        ),
        lifecycle_for_instance(
            "run-restart-validation",
            "collector-2",
            1_005,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect_err("an unreported collector restart must fail closed");

    assert!(matches!(error, ProjectionError::InvalidLifecycle { .. }));
}

#[test]
fn validator_rejects_collector_instance_transition_without_restart_gap() {
    let mut record = complete_record();
    let mut restarted = record.collector_lifecycle[0].clone();
    restarted.source_ordinal = 5;
    restarted.timestamp_unix_ms = 1_004;
    restarted.collector_instance_id = "collector-2".to_string();
    let mut terminal = record.collector_lifecycle[1].clone();
    terminal.source_ordinal = 6;
    terminal.timestamp_unix_ms = 1_005;
    terminal.collector_instance_id = "collector-2".to_string();
    record.collector_lifecycle.extend([restarted, terminal]);
    record.summary.evidence_state = EvidenceState::Incomplete;
    record.summary.review_state = ReviewState::Indeterminate;

    assert_eq!(
        validate_agent_observation_record_v1(&record),
        Err(AgentObservationRecordValidationError::InvalidCollectorLifecycle)
    );
}

#[test]
fn explicit_restart_gap_covers_collector_instance_transition() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-explicit-restart-validation", 1_000),
        lifecycle_for_instance(
            "run-explicit-restart-validation",
            "collector-1",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-explicit-restart-validation", 1_002),
        collector_restart_gap(
            "run-explicit-restart-validation",
            1_003,
            "collector_lifecycle",
            1,
        ),
        lifecycle_for_instance(
            "run-explicit-restart-validation",
            "collector-1",
            1_004,
            "failed",
            "failed",
            json!("collector_restart"),
        ),
        lifecycle_for_instance(
            "run-explicit-restart-validation",
            "collector-2",
            1_005,
            "started",
            "healthy",
            Value::Null,
        ),
        lifecycle_for_instance(
            "run-explicit-restart-validation",
            "collector-2",
            1_006,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("an explicitly reported collector restart remains queryable");

    assert_eq!(record.summary.evidence_state, EvidenceState::Failed);
    assert_eq!(record.observation_gaps.len(), 1);
    assert!(validate_agent_observation_record_v1(&record).is_ok());
}

#[test]
fn validator_rejects_three_axis_overclaims_and_crossed_conclusions() {
    let mut wrong_evidence = complete_record();
    wrong_evidence.summary.evidence_state = EvidenceState::Incomplete;
    assert!(validate_agent_observation_record_v1(&wrong_evidence).is_err());

    let mut wrong_health = complete_record();
    wrong_health.summary.collector_health = CollectorHealthProjection::Unknown;
    assert!(validate_agent_observation_record_v1(&wrong_health).is_err());

    let mut wrong_review = complete_record();
    wrong_review.summary.review_state = ReviewState::Indeterminate;
    assert!(validate_agent_observation_record_v1(&wrong_review).is_err());

    let mut active_as_complete = active_record();
    active_as_complete.summary.evidence_state = EvidenceState::Complete;
    assert!(validate_agent_observation_record_v1(&active_as_complete).is_err());

    let mut mixed_as_complete = mixed_record();
    mixed_as_complete.summary.evidence_state = EvidenceState::Complete;
    assert!(validate_agent_observation_record_v1(&mixed_as_complete).is_err());

    let mut unresolved_as_complete = record_with_finding("missing-event");
    unresolved_as_complete.summary.evidence_state = EvidenceState::Complete;
    assert!(validate_agent_observation_record_v1(&unresolved_as_complete).is_err());

    let mut failed_as_complete = failed_record();
    failed_as_complete.summary.evidence_state = EvidenceState::Complete;
    assert!(validate_agent_observation_record_v1(&failed_as_complete).is_err());
}

#[test]
fn validator_requires_the_explicit_mixed_integrity_issue_only_for_mixed_sources() {
    let mut hidden_mixed = mixed_record();
    hidden_mixed.issues.clear();
    assert!(validate_agent_observation_record_v1(&hidden_mixed).is_err());

    let mut fictitious_mixed = complete_record();
    fictitious_mixed.issues.push(ProjectionIssue {
        code: ProjectionIssueCode::SourceIntegrityFinding,
        source_ordinal: None,
        count: 1,
    });
    assert!(validate_agent_observation_record_v1(&fictitious_mixed).is_err());
}

#[test]
fn validator_requires_derived_missing_record_issues() {
    let mut hidden_missing_capability = complete_record();
    hidden_missing_capability.capability_manifests.clear();
    hidden_missing_capability.summary.evidence_state = EvidenceState::Incomplete;
    hidden_missing_capability.summary.review_state = ReviewState::Indeterminate;
    assert!(validate_agent_observation_record_v1(&hidden_missing_capability).is_err());

    let mut hidden_active_limits = active_record();
    hidden_active_limits.issues.clear();
    assert!(validate_agent_observation_record_v1(&hidden_active_limits).is_err());
}

#[test]
fn validator_accepts_explicit_capability_limits_and_rejects_hidden_contract_drift() {
    let mut partial_capability = capability("run-partial-validation", 1_000);
    partial_capability["capabilities"] = json!([{
        "operation": "network_connect",
        "event_sources": ["syscalls/sys_enter_connect", "syscalls/sys_exit_connect"],
        "outcomes": ["succeeded", "failed", "denied", "pending"]
    }]);
    let partial = project_agent_run([AgentRunRecordBatch::plain(vec![
        partial_capability,
        lifecycle(
            "run-partial-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-partial-validation", 1_002),
        lifecycle(
            "run-partial-validation",
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("partial capability remains queryable");
    assert!(validate_agent_observation_record_v1(&partial).is_ok());

    let mut hidden_partial = partial;
    hidden_partial.issues.clear();
    assert!(validate_agent_observation_record_v1(&hidden_partial).is_err());

    let mut silent_contract_drift = complete_record();
    silent_contract_drift.capability_manifests[0]
        .capabilities
        .pop();
    assert!(validate_agent_observation_record_v1(&silent_contract_drift).is_err());
}

#[test]
fn validator_requires_explicit_observation_limits_and_valid_operation_results() {
    let mut missing_outcome = network_observation("run-outcome-validation", 1_002);
    missing_outcome["outcome"] = Value::Null;
    missing_outcome["return_value"] = Value::Null;
    let limited = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-outcome-validation", 1_000),
        lifecycle(
            "run-outcome-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        missing_outcome,
        lifecycle(
            "run-outcome-validation",
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("missing outcome remains queryable");
    assert!(validate_agent_observation_record_v1(&limited).is_ok());

    let mut hidden_limit = limited;
    hidden_limit.issues.clear();
    hidden_limit.summary.evidence_state = EvidenceState::Complete;
    hidden_limit.summary.review_state = ReviewState::NoFindingsReported;
    assert!(validate_agent_observation_record_v1(&hidden_limit).is_err());

    let mut invalid_result = complete_record();
    invalid_result.runtime_observations[0].return_value = Some(-1);
    invalid_result.runtime_observations[0].errno = Some(1);
    assert!(validate_agent_observation_record_v1(&invalid_result).is_err());
}

#[test]
fn validator_rejects_source_order_that_moves_facts_outside_collection() {
    let mut observation_after_terminal = complete_record();
    observation_after_terminal.runtime_observations[0].source_ordinal = 5;
    observation_after_terminal.runtime_identities[0].first_source_ordinal = 5;
    observation_after_terminal.runtime_identities[0].last_source_ordinal = 5;
    assert!(validate_agent_observation_record_v1(&observation_after_terminal).is_err());

    let mut capability_after_lifecycle = complete_record();
    capability_after_lifecycle.capability_manifests[0].source_ordinal = 5;
    assert!(validate_agent_observation_record_v1(&capability_after_lifecycle).is_err());
}

#[test]
fn validator_requires_gap_and_collector_loss_issue_anchors() {
    let gap = gap_record();
    assert!(validate_agent_observation_record_v1(&gap).is_ok());
    let mut hidden_gap = gap;
    hidden_gap
        .issues
        .retain(|issue| issue.code != ProjectionIssueCode::ObservationGap);
    assert!(validate_agent_observation_record_v1(&hidden_gap).is_err());

    let loss = loss_record();
    assert!(validate_agent_observation_record_v1(&loss).is_ok());
    let mut hidden_loss = loss;
    hidden_loss
        .issues
        .retain(|issue| issue.code != ProjectionIssueCode::CollectorLoss);
    assert!(validate_agent_observation_record_v1(&hidden_loss).is_err());
}

#[test]
fn projector_rejects_invalid_collector_restart_gap_shape() {
    for gap in [
        collector_restart_gap("run-restart-gap-shape", 1_003, "network_connect", 1),
        collector_restart_gap("run-restart-gap-shape", 1_003, "collector_lifecycle", 2),
    ] {
        let error = project_agent_run([AgentRunRecordBatch::plain(vec![
            capability("run-restart-gap-shape", 1_000),
            lifecycle(
                "run-restart-gap-shape",
                1_001,
                "started",
                "healthy",
                Value::Null,
            ),
            network_observation("run-restart-gap-shape", 1_002),
            gap,
            lifecycle(
                "run-restart-gap-shape",
                1_004,
                "failed",
                "failed",
                json!("collector_restart"),
            ),
        ])])
        .expect_err("an invalid collector-restart gap must fail closed");

        assert_eq!(
            error,
            ProjectionError::MalformedRecord {
                ordinal: 4,
                field: "collector_restart"
            }
        );
    }
}

#[test]
fn validator_rejects_invalid_collector_restart_gap_shape() {
    let record = restart_gap_record();
    assert!(validate_agent_observation_record_v1(&record).is_ok());

    let mut wrong_operation = record.clone();
    wrong_operation.observation_gaps[0].operation = "network_connect".to_string();
    assert_eq!(
        validate_agent_observation_record_v1(&wrong_operation),
        Err(AgentObservationRecordValidationError::InvalidObservationGap)
    );

    let mut wrong_count = record;
    wrong_count.observation_gaps[0].count = 2;
    wrong_count
        .issues
        .iter_mut()
        .find(|issue| issue.code == ProjectionIssueCode::ObservationGap)
        .expect("restart-gap issue")
        .count = 2;
    assert_eq!(
        validate_agent_observation_record_v1(&wrong_count),
        Err(AgentObservationRecordValidationError::InvalidObservationGap)
    );
}

fn complete_record() -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-validation", 1_000),
        lifecycle("run-validation", 1_001, "started", "healthy", Value::Null),
        network_observation("run-validation", 1_002),
        lifecycle(
            "run-validation",
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("complete Agent Observation Record fixture")
}

fn record_with_finding(evidence_ref: &str) -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-finding-validation", 1_000),
        lifecycle(
            "run-finding-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-finding-validation", 1_002),
        lifecycle(
            "run-finding-validation",
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        json!({
            "record_type": "accountability_finding",
            "schema_version": 1,
            "session_id": "run-finding-validation",
            "kind": "unknown_egress",
            "decision": "review",
            "reason": "network endpoint is outside the declared egress set",
            "evidence_ref": evidence_ref,
            "runtime": {
                "runtime": "native",
                "container_id": null,
                "pod_uid": null,
                "cgroup_id": null
            },
            "evidence_boundary": "host_boundary"
        }),
    ])])
    .expect("Agent Observation Record with Finding fixture")
}

fn record_with_runtime_binding_finding() -> AgentObservationRecord {
    let agent_run_id = "run-runtime-binding-validation";
    let workload_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        lifecycle(agent_run_id, 1_001, "started", "healthy", Value::Null),
        network_observation(agent_run_id, 1_002),
        json!({
            "record_type": "runtime_binding_observed",
            "schema_version": 1,
            "agent_run_id": agent_run_id,
            "adapter": "docker",
            "workload_id": workload_id,
            "start_marker": "2026-08-11T01:02:03.000000000Z",
            "host_boot_id": "82b46386-b87a-4d86-93f6-232bb04c37fb",
            "init_process_start_time_ticks": 123,
            "cgroup_device": 7,
            "cgroup_id": 909,
            "runtime_handler": "runc",
        }),
        json!({
            "record_type": "accountability_finding",
            "schema_version": 1,
            "session_id": agent_run_id,
            "kind": "missing_intent",
            "decision": "review",
            "reason": "observed side effect has no matching declared intent",
            "evidence_ref": format!("runtime_binding:{workload_id}"),
            "runtime": {
                "runtime": "docker",
                "container_id": workload_id,
                "pod_uid": null,
                "cgroup_id": 909,
            },
            "evidence_boundary": "host_boundary",
        }),
        lifecycle(
            agent_run_id,
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("project runtime binding Finding support")
}

fn runtime_suspension_record(gap_source: &str) -> AgentObservationRecord {
    let agent_run_id = "run-runtime-suspension-validation";
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        runtime_binding(agent_run_id, "docker", "runtime_binding_observed"),
        runtime_metadata_gap(agent_run_id, gap_source, "socket_unavailable", 1),
        runtime_binding(agent_run_id, "docker", "runtime_binding_suspended"),
    ])])
    .expect("project source-qualified runtime suspension fixture")
}

fn runtime_retirement_record(reason: &str) -> AgentObservationRecord {
    let agent_run_id = "run-runtime-retirement-validation";
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability(agent_run_id, 1_000),
        runtime_binding(agent_run_id, "docker", "runtime_binding_observed"),
        runtime_metadata_gap(agent_run_id, "docker", reason, 1),
        runtime_binding(agent_run_id, "docker", "runtime_binding_retired"),
    ])])
    .expect("project source-qualified runtime retirement fixture")
}

fn runtime_binding(agent_run_id: &str, adapter: &str, record_type: &str) -> Value {
    json!({
        "record_type": record_type,
        "schema_version": 1,
        "agent_run_id": agent_run_id,
        "adapter": adapter,
        "workload_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "start_marker": "2026-08-11T01:02:03.000000000Z",
        "host_boot_id": "82b46386-b87a-4d86-93f6-232bb04c37fb",
        "init_process_start_time_ticks": 123,
        "cgroup_device": 7,
        "cgroup_id": 909,
        "runtime_handler": "runc",
    })
}

fn containerd_runtime_binding(agent_run_id: &str, record_type: &str) -> Value {
    json!({
        "record_type": record_type,
        "schema_version": 1,
        "agent_run_id": agent_run_id,
        "adapter": "containerd",
        "workload_id": format!("containerd/{}", "e".repeat(64)),
        "start_marker": "1786410123123456789",
        "host_boot_id": "82b46386-b87a-4d86-93f6-232bb04c37fb",
        "init_process_start_time_ticks": 123,
        "cgroup_device": 7,
        "cgroup_id": 909,
        "runtime_handler": "runc",
    })
}

fn kubernetes_attribution(agent_run_id: &str, record_type: &str, runtime_binding: Value) -> Value {
    json!({
        "record_type": record_type,
        "schema_version": 1,
        "agent_run_id": agent_run_id,
        "cluster_id": "11111111-1111-1111-1111-111111111111",
        "namespace_ref": "a".repeat(64),
        "pod_uid": "22222222-2222-2222-2222-222222222222",
        "node_ref": "b".repeat(64),
        "runtime_class_ref": null,
        "container_kind": "application",
        "container_ref": "d".repeat(64),
        "runtime_binding": runtime_binding,
    })
}

fn runtime_metadata_gap(agent_run_id: &str, source: &str, reason: &str, count: u64) -> Value {
    json!({
        "record_type": "observation_gap",
        "schema_version": 1,
        "timestamp_unix_ms": 1_001,
        "agent_run_id": agent_run_id,
        "operation": "runtime_metadata",
        "kind": "runtime_metadata_unavailable",
        "count": count,
        "detail": format!("source={source},reason={reason}"),
    })
}

fn active_record() -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-active-validation", 1_000),
        lifecycle(
            "run-active-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
    ])])
    .expect("active Agent Observation Record fixture")
}

fn mixed_record() -> AgentObservationRecord {
    project_agent_run([
        AgentRunRecordBatch::verified_hash_chain(vec![
            capability("run-mixed-validation", 1_000),
            lifecycle(
                "run-mixed-validation",
                1_001,
                "started",
                "healthy",
                Value::Null,
            ),
            network_observation("run-mixed-validation", 1_002),
        ]),
        AgentRunRecordBatch::plain(vec![lifecycle(
            "run-mixed-validation",
            1_003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        )]),
    ])
    .expect("mixed-integrity Agent Observation Record fixture")
}

fn failed_record() -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-failed-validation", 1_000),
        lifecycle(
            "run-failed-validation",
            1_001,
            "failed",
            "failed",
            json!("attach_failure"),
        ),
    ])])
    .expect("failed Agent Observation Record fixture")
}

fn diagnostic_record(kind: &str) -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-diagnostic-validation", 1_000),
        lifecycle(
            "run-diagnostic-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-diagnostic-validation", 1_002),
        json!({
            "record_type": "observer_diagnostic",
            "timestamp_unix_ms": 1_003,
            "session_id": "run-diagnostic-validation",
            "kind": kind,
            "count": 1,
            "detail": "bounded-test-diagnostic"
        }),
        lifecycle(
            "run-diagnostic-validation",
            1_004,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("diagnostic Agent Observation Record fixture")
}

fn gap_record() -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-gap-validation", 1_000),
        lifecycle(
            "run-gap-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-gap-validation", 1_002),
        json!({
            "record_type": "observation_gap",
            "schema_version": 1,
            "timestamp_unix_ms": 1_003,
            "agent_run_id": "run-gap-validation",
            "operation": "network_connect",
            "kind": "missing_exit",
            "count": 2,
            "detail": "source text is canonicalized"
        }),
        lifecycle(
            "run-gap-validation",
            1_004,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("gapped Agent Observation Record fixture")
}

fn loss_record() -> AgentObservationRecord {
    let mut terminal = lifecycle(
        "run-loss-validation",
        1_003,
        "stopped",
        "degraded",
        json!("agent_exited"),
    );
    terminal["counters"]["global_reserve_failures"] = json!(3);
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-loss-validation", 1_000),
        lifecycle(
            "run-loss-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-loss-validation", 1_002),
        terminal,
    ])])
    .expect("lossy Agent Observation Record fixture")
}

fn restart_gap_record() -> AgentObservationRecord {
    project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-restart-gap-validation", 1_000),
        lifecycle(
            "run-restart-gap-validation",
            1_001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-restart-gap-validation", 1_002),
        collector_restart_gap(
            "run-restart-gap-validation",
            1_003,
            "collector_lifecycle",
            1,
        ),
        lifecycle(
            "run-restart-gap-validation",
            1_004,
            "failed",
            "failed",
            json!("collector_restart"),
        ),
    ])])
    .expect("explicit collector restart remains queryable")
}

fn capability(agent_run_id: &str, timestamp_unix_ms: u64) -> Value {
    let capabilities = audit_observer_capability_contract_v1()
        .iter()
        .map(|capability| {
            json!({
                "operation": capability.operation,
                "event_sources": capability.event_sources,
                "outcomes": capability
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.as_str())
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    json!({
        "record_type": "collector_capability_manifest",
        "schema_version": 1,
        "timestamp_unix_ms": timestamp_unix_ms,
        "agent_run_id": agent_run_id,
        "collector": "apolysis_observer",
        "collector_version": "0.1.0",
        "kernel_abi_version": 3,
        "kernel_record_size": 656,
        "observation_scope": "process_tree",
        "privacy_profile": "content_off",
        "capabilities": capabilities
    })
}

fn lifecycle(
    agent_run_id: &str,
    timestamp_unix_ms: u64,
    state: &str,
    health: &str,
    stop_reason: Value,
) -> Value {
    lifecycle_for_instance(
        agent_run_id,
        "collector-1",
        timestamp_unix_ms,
        state,
        health,
        stop_reason,
    )
}

fn lifecycle_for_instance(
    agent_run_id: &str,
    collector_instance_id: &str,
    timestamp_unix_ms: u64,
    state: &str,
    health: &str,
    stop_reason: Value,
) -> Value {
    json!({
        "record_type": "collector_lifecycle",
        "schema_version": 1,
        "timestamp_unix_ms": timestamp_unix_ms,
        "agent_run_id": agent_run_id,
        "collector": "apolysis_observer",
        "collector_instance_id": collector_instance_id,
        "state": state,
        "health": health,
        "stop_reason": stop_reason,
        "counters": {
            "global_reserve_failures": 0,
            "global_map_pressure": 0,
            "global_abi_mismatches": 0,
            "global_decode_failures": 0,
            "global_truncations": 0,
            "scope_missing_entries": 0,
            "scope_missing_exits": 0,
            "scope_pending": 0
        }
    })
}

fn collector_restart_gap(
    agent_run_id: &str,
    timestamp_unix_ms: u64,
    operation: &str,
    count: u64,
) -> Value {
    json!({
        "record_type": "observation_gap",
        "schema_version": 1,
        "timestamp_unix_ms": timestamp_unix_ms,
        "agent_run_id": agent_run_id,
        "operation": operation,
        "kind": "collector_restart",
        "count": count,
        "detail": "collector_instance:opaque,previous lifecycle has no durable terminal record"
    })
}

fn network_observation(agent_run_id: &str, timestamp_unix_ms: u64) -> Value {
    json!({
        "record_type": "event",
        "timestamp_unix_ms": timestamp_unix_ms,
        "session_id": agent_run_id,
        "event_source": "kernel_tracepoint",
        "event_type": "network_connect",
        "raw_event_id": "event-1",
        "pid": 42,
        "ppid": 1,
        "actor": "agent",
        "resource": "socket_token:example:443",
        "action": "connect",
        "outcome": "succeeded",
        "return_value": 0,
        "errno": null,
        "container_id": null,
        "cgroup_id": null,
        "host_boot_id": "00000000-0000-0000-0000-000000000042",
        "scope_generation": 7,
        "process_generation": 11,
        "process_start_time_ns": 123456,
        "exec_generation": 2,
        "parent_process_generation": 3,
        "parent_exec_generation": 1,
        "relation_status": "exact",
        "relation_reason": "host_boot_scope_process_start_exec_generation",
        "process_command": null,
        "process_executable": "executable_ref:agent",
        "process_started_at_unix_ms": null
    })
}

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

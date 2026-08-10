// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{project_agent_run, AgentRunRecordBatch, ProjectionError};
use serde_json::{json, Value};

#[test]
fn complete_agent_run_projects_one_queryable_aggregate_and_summary() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-42", 1000),
        json!({
            "record_type": "collector_lifecycle",
            "schema_version": 1,
            "timestamp_unix_ms": 1001,
            "agent_run_id": "run-42",
            "collector": "apolysis_observer",
            "collector_instance_id": "collector-1",
            "state": "started",
            "health": "healthy",
            "stop_reason": null,
            "counters": zero_counters()
        }),
        json!({
            "record_type": "event",
            "timestamp_unix_ms": 1002,
            "session_id": "run-42",
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
        }),
        json!({
            "record_type": "collector_lifecycle",
            "schema_version": 1,
            "timestamp_unix_ms": 1003,
            "agent_run_id": "run-42",
            "collector": "apolysis_observer",
            "collector_instance_id": "collector-1",
            "state": "stopped",
            "health": "healthy",
            "stop_reason": "agent_exited",
            "counters": zero_counters()
        }),
    ])])
    .expect("complete Agent Run projection");

    let rendered = serde_json::to_string(&record).expect("serialize projection");
    let round_trip: apolysis_accountability::AgentObservationRecord =
        serde_json::from_str(&rendered).expect("deserialize projection");
    assert_eq!(round_trip, record);
    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(
        json!({
            "record_type": value["record_type"],
            "schema_version": value["schema_version"],
            "agent_run_id": value["agent_run_id"],
            "source_integrity": value["source_integrity"],
            "evidence_state": value["summary"]["evidence_state"],
            "collector_health": value["summary"]["collector_health"],
            "review_state": value["summary"]["review_state"],
            "observations": value["summary"]["runtime_observation_count"],
            "identities": value["summary"]["runtime_identity_count"],
            "event_type_counts": value["summary"]["event_type_counts"],
            "outcome_counts": value["summary"]["outcome_counts"],
            "relation_counts": value["summary"]["relation_counts"],
            "issues": value["issues"]
        }),
        json!({
            "record_type": "agent_observation_record",
            "schema_version": 1,
            "agent_run_id": "run-42",
            "source_integrity": "unverified_plain_jsonl",
            "evidence_state": "complete",
            "collector_health": "healthy",
            "review_state": "no_findings_reported",
            "observations": 1,
            "identities": 1,
            "event_type_counts": {"network_connect": 1},
            "outcome_counts": {"succeeded": 1},
            "relation_counts": {"exact": 1},
            "issues": []
        })
    );
}

#[test]
fn late_attach_is_unknown_history_boundary_not_a_missing_event_estimate() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        json!({
            "record_type": "observation_gap",
            "schema_version": 1,
            "timestamp_unix_ms": 999,
            "agent_run_id": "run-late",
            "operation": "collector_lifecycle",
            "kind": "late_attach",
            "count": 1,
            "detail": "collection_boundary:protected_existing_process_attach,history:unknown,provenance:external_registration,root_selection:registration_qualified"
        }),
        capability("run-late", 1000),
        lifecycle("run-late", 1001, "started", "healthy", Value::Null),
        network_observation("run-late", 1002),
        lifecycle(
            "run-late",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("late-attach projection remains queryable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(
        json!({
            "evidence_state": value["summary"]["evidence_state"],
            "gap_records": value["summary"]["observation_gap_record_count"],
            "known_missing": value["summary"]["known_missing_observation_count"],
            "unknown_history_boundaries": value["summary"]["unknown_history_boundary_count"],
            "gap_kind_counts": value["summary"]["gap_kind_counts"],
            "issues": value["issues"],
            "gaps": value["observation_gaps"].as_array().map(Vec::len)
        }),
        json!({
            "evidence_state": "incomplete",
            "gap_records": 1,
            "known_missing": 0,
            "unknown_history_boundaries": 1,
            "gap_kind_counts": {"late_attach": 1},
            "issues": [{
                "code": "observation_gap",
                "source_ordinal": 1,
                "count": 1
            }],
            "gaps": 1
        })
    );
}

#[test]
fn quiet_unfinished_run_is_active_and_review_indeterminate_not_clean() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-active", 1000),
        lifecycle("run-active", 1001, "started", "healthy", Value::Null),
    ])])
    .expect("unfinished Agent Run remains queryable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(
        json!({
            "evidence_state": value["summary"]["evidence_state"],
            "collector_health": value["summary"]["collector_health"],
            "review_state": value["summary"]["review_state"],
            "observations": value["summary"]["runtime_observation_count"],
            "issues": value["issues"]
        }),
        json!({
            "evidence_state": "active",
            "collector_health": "healthy",
            "review_state": "indeterminate",
            "observations": 0,
            "issues": [
                {
                    "code": "missing_lifecycle_terminal",
                    "source_ordinal": null,
                    "count": 1
                },
                {
                    "code": "no_runtime_observations",
                    "source_ordinal": null,
                    "count": 1
                }
            ]
        })
    );
}

#[test]
fn finding_requires_review_without_rewriting_observation_completeness() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-review", 1000),
        lifecycle("run-review", 1001, "started", "healthy", Value::Null),
        network_observation("run-review", 1002),
        lifecycle(
            "run-review",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        json!({
            "record_type": "accountability_finding",
            "schema_version": 1,
            "session_id": "run-review",
            "kind": "unknown_egress",
            "decision": "review",
            "reason": "network endpoint is outside the declared egress set",
            "evidence_ref": "event-1",
            "runtime": {
                "runtime": "native",
                "container_id": null,
                "pod_uid": null,
                "cgroup_id": null
            },
            "evidence_boundary": "host_boundary"
        }),
    ])])
    .expect("finding projection");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(
        json!({
            "evidence_state": value["summary"]["evidence_state"],
            "review_state": value["summary"]["review_state"],
            "finding_count": value["summary"]["finding_count"],
            "finding_kind_counts": value["summary"]["finding_kind_counts"],
            "projected_finding": value["findings"][0]
        }),
        json!({
            "evidence_state": "complete",
            "review_state": "requires_review",
            "finding_count": 1,
            "finding_kind_counts": {"unknown_egress": 1},
            "projected_finding": {
                "source_ordinal": 5,
                "schema_version": 1,
                "kind": "unknown_egress",
                "decision": "review",
                "reason": "network endpoint is outside the declared egress set",
                "evidence_ref": "event-1",
                "runtime": {
                    "runtime": "native",
                    "container_id": null,
                    "pod_uid": null,
                    "cgroup_id": null
                },
                "evidence_boundary": "host_boundary"
            }
        })
    );
}

#[test]
fn unknown_additive_record_is_bounded_and_makes_completeness_indeterminate() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-future", 1000),
        lifecycle("run-future", 1001, "started", "healthy", Value::Null),
        network_observation("run-future", 1002),
        json!({
            "record_type": "future_observer_record",
            "session_id": "run-future",
            "private_future_payload": "APOLYSIS_PROJECTION_SECRET"
        }),
        lifecycle(
            "run-future",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("unknown additive record remains queryable");

    let rendered = serde_json::to_string(&record).expect("serialize projection");
    let value: Value = serde_json::from_str(&rendered).expect("parse projection");
    assert_eq!(
        json!({
            "evidence_state": value["summary"]["evidence_state"],
            "review_state": value["summary"]["review_state"],
            "issues": value["issues"],
            "unknown_payload_persisted": rendered.contains("APOLYSIS_PROJECTION_SECRET")
        }),
        json!({
            "evidence_state": "indeterminate",
            "review_state": "indeterminate",
            "issues": [{
                "code": "unknown_record_type",
                "source_ordinal": 4,
                "count": 1
            }],
            "unknown_payload_persisted": false
        })
    );
}

#[test]
fn undeclared_outcome_is_queryable_but_forces_incomplete_evidence() {
    let mut denied = network_observation("run-unsupported", 1002);
    denied["outcome"] = json!("denied");
    denied["return_value"] = json!(-13);
    denied["errno"] = json!(13);
    let mut succeeded_only = capability("run-unsupported", 1000);
    succeeded_only["capabilities"][0]["outcomes"] = json!(["succeeded"]);

    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        succeeded_only,
        lifecycle("run-unsupported", 1001, "started", "healthy", Value::Null),
        denied,
        lifecycle(
            "run-unsupported",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("unsupported outcome remains visible");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(
        json!({
            "evidence_state": value["summary"]["evidence_state"],
            "observation_count": value["summary"]["runtime_observation_count"],
            "outcomes": value["summary"]["outcome_counts"],
            "issues": value["issues"]
        }),
        json!({
            "evidence_state": "incomplete",
            "observation_count": 1,
            "outcomes": {"denied": 1},
            "issues": [
                {
                    "code": "unsupported_capability",
                    "source_ordinal": 1,
                    "count": 1
                },
                {
                    "code": "unsupported_outcome",
                    "source_ordinal": 3,
                    "count": 1
                }
            ]
        })
    );
}

#[test]
fn observation_after_terminal_lifecycle_fails_closed_at_its_source_ordinal() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-order", 1000),
        lifecycle("run-order", 1001, "started", "healthy", Value::Null),
        lifecycle(
            "run-order",
            1002,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        network_observation("run-order", 1003),
    ])])
    .expect_err("post-terminal observation must fail closed");

    assert_eq!(error, ProjectionError::InvalidLifecycle { ordinal: 4 });
}

#[test]
fn late_attach_after_lifecycle_start_fails_closed_without_timestamp_reordering() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-boundary-order", 1000),
        lifecycle(
            "run-boundary-order",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        json!({
            "record_type": "observation_gap",
            "schema_version": 1,
            "timestamp_unix_ms": 999,
            "agent_run_id": "run-boundary-order",
            "operation": "collector_lifecycle",
            "kind": "late_attach",
            "count": 1,
            "detail": "collection_boundary:protected_existing_process_attach,history:unknown,provenance:proc_discovery,root_selection:inferred"
        }),
    ])])
    .expect_err("late-attach source order must be authoritative");

    assert_eq!(error, ProjectionError::InvalidLifecycle { ordinal: 3 });
}

#[test]
fn capability_after_lifecycle_start_cannot_retroactively_cover_the_run() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        lifecycle(
            "run-capability-order",
            1000,
            "started",
            "healthy",
            Value::Null,
        ),
        capability("run-capability-order", 1001),
    ])])
    .expect_err("late capability must not cover an earlier lifecycle window");

    assert_eq!(error, ProjectionError::InvalidLifecycle { ordinal: 2 });
}

#[test]
fn completed_run_without_capability_or_observations_is_not_reported_complete() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        lifecycle("run-empty", 1000, "started", "healthy", Value::Null),
        lifecycle(
            "run-empty",
            1001,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("empty completed Agent Run remains queryable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(value["summary"]["evidence_state"], "incomplete");
    assert_eq!(value["summary"]["review_state"], "indeterminate");
    assert_eq!(
        value["issues"],
        json!([
            {
                "code": "missing_capability",
                "source_ordinal": null,
                "count": 1
            },
            {
                "code": "no_runtime_observations",
                "source_ordinal": null,
                "count": 1
            }
        ])
    );
}

#[test]
fn missing_lifecycle_start_is_incomplete_instead_of_active() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![capability(
        "run-no-lifecycle",
        1000,
    )])])
    .expect("missing lifecycle remains queryable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(value["summary"]["evidence_state"], "incomplete");
    assert_eq!(value["summary"]["collector_health"], "unknown");
    assert_eq!(
        value["issues"],
        json!([
            {
                "code": "missing_lifecycle_start",
                "source_ordinal": null,
                "count": 1
            },
            {
                "code": "no_runtime_observations",
                "source_ordinal": null,
                "count": 1
            }
        ])
    );
}

#[test]
fn lifecycle_loss_is_visible_as_an_issue_and_incomplete_evidence() {
    let mut terminal = lifecycle(
        "run-loss",
        1003,
        "stopped",
        "degraded",
        json!("agent_exited"),
    );
    terminal["counters"]["global_reserve_failures"] = json!(3);
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-loss", 1000),
        lifecycle("run-loss", 1001, "started", "healthy", Value::Null),
        network_observation("run-loss", 1002),
        terminal,
    ])])
    .expect("lossy Agent Run remains queryable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(value["summary"]["evidence_state"], "incomplete");
    assert_eq!(value["summary"]["collector_health"], "degraded");
    assert_eq!(
        value["issues"],
        json!([{
            "code": "collector_loss",
            "source_ordinal": 4,
            "count": 1
        }])
    );
}

#[test]
fn mixed_source_integrity_is_queryable_but_never_complete() {
    let record = project_agent_run([
        AgentRunRecordBatch::verified_hash_chain(vec![
            capability("run-mixed-source", 1000),
            lifecycle("run-mixed-source", 1001, "started", "healthy", Value::Null),
            network_observation("run-mixed-source", 1002),
        ]),
        AgentRunRecordBatch::plain(vec![lifecycle(
            "run-mixed-source",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        )]),
    ])
    .expect("mixed integrity remains queryable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(value["source_integrity"], "mixed");
    assert_eq!(value["summary"]["evidence_state"], "indeterminate");
    assert_eq!(
        value["issues"],
        json!([{
            "code": "source_integrity_finding",
            "source_ordinal": null,
            "count": 1
        }])
    );
}

#[test]
fn integrity_finding_is_projected_without_persisting_private_paths() {
    let record = project_agent_run([AgentRunRecordBatch::verified_hash_chain(vec![
        capability("run-integrity", 1000),
        lifecycle("run-integrity", 1001, "started", "healthy", Value::Null),
        network_observation("run-integrity", 1002),
        lifecycle(
            "run-integrity",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        json!({
            "record_type": "integrity_finding",
            "session_id": "run-integrity",
            "reason": "hash_chain_tail_quarantined",
            "timeline_path": "/private/APOLYSIS_PROJECTION_SECRET/timeline.jsonl",
            "quarantine_path": "/private/APOLYSIS_PROJECTION_SECRET/quarantine"
        }),
    ])])
    .expect("integrity finding remains queryable");

    let rendered = serde_json::to_string(&record).expect("serialize projection");
    let value: Value = serde_json::from_str(&rendered).expect("parse projection");
    assert_eq!(value["summary"]["evidence_state"], "incomplete");
    assert_eq!(
        value["issues"],
        json!([{
            "code": "source_integrity_finding",
            "source_ordinal": 5,
            "count": 1
        }])
    );
    assert!(!rendered.contains("APOLYSIS_PROJECTION_SECRET"));
}

#[test]
fn duplicate_canonical_raw_event_id_fails_closed_before_double_counting() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-duplicate", 1000),
        lifecycle("run-duplicate", 1001, "started", "healthy", Value::Null),
        network_observation("run-duplicate", 1002),
        network_observation("run-duplicate", 1003),
    ])])
    .expect_err("duplicate canonical observation must fail closed");

    assert_eq!(
        error,
        ProjectionError::DuplicateRuntimeObservation { ordinal: 4 }
    );
}

#[test]
fn ordinary_gap_after_terminal_lifecycle_fails_closed() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-gap-order", 1000),
        lifecycle("run-gap-order", 1001, "started", "healthy", Value::Null),
        lifecycle(
            "run-gap-order",
            1002,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        json!({
            "record_type": "observation_gap",
            "schema_version": 1,
            "timestamp_unix_ms": 1003,
            "agent_run_id": "run-gap-order",
            "operation": "network_connect",
            "kind": "missing_exit",
            "count": 1,
            "detail": "pending_at_stop:1"
        }),
    ])])
    .expect_err("post-terminal gap must fail closed");

    assert_eq!(error, ProjectionError::InvalidLifecycle { ordinal: 4 });
}

#[test]
fn mixed_agent_runs_fail_closed_without_leaking_record_payloads() {
    let conflicting = network_observation("APOLYSIS_PROJECTION_SECRET", 1002);
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-expected", 1000),
        lifecycle("run-expected", 1001, "started", "healthy", Value::Null),
        conflicting,
    ])])
    .expect_err("mixed runs must fail closed");

    assert!(matches!(
        error,
        ProjectionError::MixedAgentRuns { ordinal: 3, .. }
    ));
    assert!(!error.to_string().contains("APOLYSIS_PROJECTION_SECRET"));
}

#[test]
fn active_pending_gauge_that_drains_before_terminal_does_not_become_loss() {
    let mut checkpoint = lifecycle(
        "run-pending-drained",
        1002,
        "checkpoint",
        "healthy",
        Value::Null,
    );
    checkpoint["counters"]["scope_pending"] = json!(2);
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-pending-drained", 1000),
        lifecycle(
            "run-pending-drained",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        checkpoint,
        network_observation("run-pending-drained", 1003),
        lifecycle(
            "run-pending-drained",
            1004,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("drained pending gauge projects successfully");

    assert_eq!(
        record.summary.evidence_state,
        apolysis_accountability::EvidenceState::Complete
    );
    assert_eq!(
        record.summary.collector_health,
        apolysis_accountability::CollectorHealthProjection::Healthy
    );
    assert!(record.issues.is_empty());
}

#[test]
fn pending_at_terminal_is_explicit_loss() {
    let mut terminal = lifecycle(
        "run-pending-terminal",
        1003,
        "stopped",
        "degraded",
        json!("agent_exited"),
    );
    terminal["counters"]["scope_pending"] = json!(2);
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-pending-terminal", 1000),
        lifecycle(
            "run-pending-terminal",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-pending-terminal", 1002),
        terminal,
    ])])
    .expect("terminal pending gauge remains queryable");

    assert_eq!(
        record.summary.evidence_state,
        apolysis_accountability::EvidenceState::Incomplete
    );
    assert_eq!(
        record.summary.collector_health,
        apolysis_accountability::CollectorHealthProjection::Degraded
    );
    assert_eq!(
        record.issues[0].code,
        apolysis_accountability::ProjectionIssueCode::CollectorLoss
    );
}

#[test]
fn invalid_lifecycle_health_and_stop_reason_fail_closed() {
    let invalid_health = project_agent_run([AgentRunRecordBatch::plain(vec![lifecycle(
        "run-invalid-health",
        1000,
        "started",
        "clean",
        Value::Null,
    )])])
    .expect_err("unknown health must fail closed");
    assert_eq!(
        invalid_health,
        ProjectionError::MalformedRecord {
            ordinal: 1,
            field: "collector_lifecycle"
        }
    );

    let invalid_reason = project_agent_run([AgentRunRecordBatch::plain(vec![lifecycle(
        "run-invalid-reason",
        1000,
        "started",
        "healthy",
        json!("agent_exited"),
    )])])
    .expect_err("non-terminal stop reason must fail closed");
    assert_eq!(
        invalid_reason,
        ProjectionError::MalformedRecord {
            ordinal: 1,
            field: "collector_lifecycle"
        }
    );
}

#[test]
fn nonzero_loss_diagnostic_cannot_yield_complete_evidence() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-diagnostic", 1000),
        lifecycle("run-diagnostic", 1001, "started", "healthy", Value::Null),
        network_observation("run-diagnostic", 1002),
        json!({
            "record_type": "observer_diagnostic",
            "timestamp_unix_ms": 1003,
            "session_id": "run-diagnostic",
            "kind": "decode_failure",
            "count": 2,
            "detail": "APOLYSIS_PROJECTION_SECRET"
        }),
        lifecycle(
            "run-diagnostic",
            1004,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("diagnostic remains queryable");

    let rendered = serde_json::to_string(&record).expect("serialize projection");
    assert_eq!(
        record.summary.evidence_state,
        apolysis_accountability::EvidenceState::Incomplete
    );
    assert_eq!(
        record.issues[0].code,
        apolysis_accountability::ProjectionIssueCode::CollectorDiagnostic
    );
    assert_eq!(record.issues[0].count, 2);
    assert!(!rendered.contains("APOLYSIS_PROJECTION_SECRET"));
}

#[test]
fn missing_outcome_and_unknown_relation_never_become_complete() {
    let mut missing_outcome = network_observation("run-missing-outcome", 1002);
    missing_outcome["outcome"] = Value::Null;
    missing_outcome["return_value"] = Value::Null;
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-missing-outcome", 1000),
        lifecycle(
            "run-missing-outcome",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        missing_outcome,
        lifecycle(
            "run-missing-outcome",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("missing outcome remains queryable");
    assert_eq!(
        record.summary.evidence_state,
        apolysis_accountability::EvidenceState::Incomplete
    );
    assert_eq!(
        record.issues[0].code,
        apolysis_accountability::ProjectionIssueCode::UnsupportedOutcome
    );

    let mut unknown_relation = network_observation("run-unknown-relation", 1002);
    unknown_relation["relation_status"] = json!("certain");
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-unknown-relation", 1000),
        lifecycle(
            "run-unknown-relation",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        unknown_relation,
    ])])
    .expect_err("unknown relation must fail closed");
    assert_eq!(
        error,
        ProjectionError::MalformedRecord {
            ordinal: 3,
            field: "relation_status"
        }
    );
}

#[test]
fn duplicate_capability_manifest_is_rejected() {
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-duplicate-capability", 1000),
        capability("run-duplicate-capability", 1001),
    ])])
    .expect_err("duplicate capability must fail closed");
    assert_eq!(
        error,
        ProjectionError::MalformedRecord {
            ordinal: 2,
            field: "collector_capability_manifest"
        }
    );
}

#[test]
fn projection_stops_consuming_unbounded_batch_iterators_at_its_limit() {
    let batches = (0..).map(|_| AgentRunRecordBatch::plain(Vec::new()));
    let error = project_agent_run(batches).expect_err("unbounded input must stop at the limit");
    assert_eq!(
        error,
        ProjectionError::InputLimitExceeded {
            limit: "batch count"
        }
    );
}

#[test]
fn finding_reason_is_canonicalized_and_invalid_decisions_fail_closed() {
    let finding = json!({
        "record_type": "accountability_finding",
        "schema_version": 1,
        "session_id": "run-finding-policy",
        "kind": "unknown_egress",
        "decision": "review",
        "reason": "APOLYSIS_PROJECTION_SECRET",
        "evidence_ref": "event-1",
        "runtime": {
            "runtime": "native",
            "container_id": null,
            "pod_uid": null,
            "cgroup_id": null
        },
        "evidence_boundary": "host_boundary"
    });
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-finding-policy", 1000),
        lifecycle(
            "run-finding-policy",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-finding-policy", 1002),
        lifecycle(
            "run-finding-policy",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        finding.clone(),
    ])])
    .expect("typed finding projects");
    let rendered = serde_json::to_string(&record).expect("serialize projection");
    assert!(!rendered.contains("APOLYSIS_PROJECTION_SECRET"));
    assert_eq!(
        record.findings[0].reason,
        "network endpoint is outside the declared egress set"
    );

    let mut invalid = finding;
    invalid["decision"] = json!("blocked");
    let error = project_agent_run([AgentRunRecordBatch::plain(vec![invalid])])
        .expect_err("enforcement-style decision must fail closed");
    assert_eq!(
        error,
        ProjectionError::MalformedRecord {
            ordinal: 1,
            field: "record payload"
        }
    );
}

#[test]
fn ordinary_gap_detail_is_canonicalized_without_private_source_text() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-gap-privacy", 1000),
        lifecycle("run-gap-privacy", 1001, "started", "healthy", Value::Null),
        json!({
            "record_type": "observation_gap",
            "schema_version": 1,
            "timestamp_unix_ms": 1002,
            "agent_run_id": "run-gap-privacy",
            "operation": "network_connect",
            "kind": "missing_exit",
            "count": 1,
            "detail": "APOLYSIS_PROJECTION_SECRET"
        }),
        lifecycle(
            "run-gap-privacy",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("bounded gap remains queryable");

    let rendered = serde_json::to_string(&record).expect("serialize projection");
    assert!(!rendered.contains("APOLYSIS_PROJECTION_SECRET"));
    assert_eq!(record.observation_gaps[0].detail, "bounded_loss_counter");
}

#[test]
fn partial_or_fictitious_capability_contracts_cannot_be_complete() {
    let mut partial = capability("run-partial-capability", 1000);
    partial["capabilities"] = json!([{
        "operation": "network_connect",
        "event_sources": ["syscalls/sys_enter_connect", "syscalls/sys_exit_connect"],
        "outcomes": ["succeeded", "failed", "denied", "pending"]
    }]);
    let partial_record = project_agent_run([AgentRunRecordBatch::plain(vec![
        partial,
        lifecycle(
            "run-partial-capability",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-partial-capability", 1002),
        lifecycle(
            "run-partial-capability",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("partial capability remains queryable");
    let partial_value = serde_json::to_value(partial_record).expect("serialize projection");
    assert_eq!(partial_value["summary"]["evidence_state"], "incomplete");
    assert_eq!(
        partial_value["issues"],
        json!([{
            "code": "unsupported_capability",
            "source_ordinal": 1,
            "count": 9
        }])
    );

    let mut fictitious = capability("run-fictitious-capability", 1000);
    fictitious["capabilities"][0]["event_sources"] =
        json!(["syscalls/sys_enter_openat", "syscalls/sys_exit_openat"]);
    let fictitious_record = project_agent_run([AgentRunRecordBatch::plain(vec![
        fictitious,
        lifecycle(
            "run-fictitious-capability",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-fictitious-capability", 1002),
        lifecycle(
            "run-fictitious-capability",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ])])
    .expect("incompatible capability remains queryable");
    let fictitious_value = serde_json::to_value(fictitious_record).expect("serialize projection");
    assert_eq!(fictitious_value["summary"]["evidence_state"], "incomplete");
    assert_eq!(
        fictitious_value["issues"],
        json!([{
            "code": "unsupported_capability",
            "source_ordinal": 1,
            "count": 1
        }])
    );
}

#[test]
fn unsupported_or_heuristic_relations_are_never_promoted_to_exact_identity() {
    let mut manual = network_observation("run-manual-exact", 1002);
    manual["event_source"] = json!("manual");
    let manual_error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-manual-exact", 1000),
        lifecycle("run-manual-exact", 1001, "started", "healthy", Value::Null),
        manual,
    ])])
    .expect_err("manual evidence must not become an exact identity");
    assert_eq!(
        manual_error,
        ProjectionError::ConflictingRuntimeIdentity { ordinal: 3 }
    );

    let mut heuristic = network_observation("run-heuristic-exact", 1002);
    heuristic["relation_reason"] = json!("pid_only_runtime_identity");
    let heuristic_error = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-heuristic-exact", 1000),
        lifecycle(
            "run-heuristic-exact",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        heuristic,
    ])])
    .expect_err("heuristic evidence must not become an exact identity");
    assert_eq!(
        heuristic_error,
        ProjectionError::ConflictingRuntimeIdentity { ordinal: 3 }
    );
}

#[test]
fn dangling_finding_evidence_is_explicit_and_prevents_complete_evidence() {
    let record = project_agent_run([AgentRunRecordBatch::plain(vec![
        capability("run-dangling-finding", 1000),
        lifecycle(
            "run-dangling-finding",
            1001,
            "started",
            "healthy",
            Value::Null,
        ),
        network_observation("run-dangling-finding", 1002),
        lifecycle(
            "run-dangling-finding",
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
        json!({
            "record_type": "accountability_finding",
            "schema_version": 1,
            "session_id": "run-dangling-finding",
            "kind": "unknown_egress",
            "decision": "review",
            "reason": "network endpoint is outside the declared egress set",
            "evidence_ref": "missing-event",
            "runtime": {
                "runtime": "native",
                "container_id": null,
                "pod_uid": null,
                "cgroup_id": null
            },
            "evidence_boundary": "host_boundary"
        }),
    ])])
    .expect("dangling finding remains reviewable");

    let value = serde_json::to_value(record).expect("serialize projection");
    assert_eq!(value["summary"]["evidence_state"], "incomplete");
    assert_eq!(value["summary"]["review_state"], "requires_review");
    assert_eq!(
        value["issues"],
        json!([{
            "code": "unresolved_finding_evidence",
            "source_ordinal": 5,
            "count": 1
        }])
    );
}

fn zero_counters() -> Value {
    json!({
        "global_reserve_failures": 0,
        "global_map_pressure": 0,
        "global_abi_mismatches": 0,
        "global_decode_failures": 0,
        "global_truncations": 0,
        "scope_missing_entries": 0,
        "scope_missing_exits": 0,
        "scope_pending": 0
    })
}

fn capability(agent_run_id: &str, timestamp_unix_ms: u64) -> Value {
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
        "capabilities": [
            {
                "operation": "network_connect",
                "event_sources": ["syscalls/sys_enter_connect", "syscalls/sys_exit_connect"],
                "outcomes": ["succeeded", "failed", "denied", "pending"]
            },
            {
                "operation": "process_fork",
                "event_sources": ["sched/sched_process_fork"],
                "outcomes": ["succeeded"]
            },
            {
                "operation": "process_exec",
                "event_sources": ["sched/sched_process_exec", "syscalls/sys_enter_execve", "syscalls/sys_enter_execveat"],
                "outcomes": ["succeeded"]
            },
            {
                "operation": "process_exit",
                "event_sources": ["sched/sched_process_exit"],
                "outcomes": ["unknown"]
            },
            {
                "operation": "file_open",
                "event_sources": ["syscalls/sys_enter_openat", "syscalls/sys_exit_openat", "syscalls/sys_enter_openat2", "syscalls/sys_exit_openat2"],
                "outcomes": ["succeeded", "failed", "denied"]
            },
            {
                "operation": "file_create",
                "event_sources": ["syscalls/sys_enter_openat", "syscalls/sys_exit_openat", "syscalls/sys_enter_openat2", "syscalls/sys_exit_openat2", "syscalls/sys_enter_creat", "syscalls/sys_exit_creat"],
                "outcomes": ["succeeded", "failed", "denied"]
            },
            {
                "operation": "file_truncate",
                "event_sources": ["syscalls/sys_enter_openat", "syscalls/sys_exit_openat", "syscalls/sys_enter_openat2", "syscalls/sys_exit_openat2", "syscalls/sys_enter_truncate", "syscalls/sys_exit_truncate"],
                "outcomes": ["succeeded", "failed", "denied"]
            },
            {
                "operation": "file_unlink",
                "event_sources": ["syscalls/sys_enter_unlinkat", "syscalls/sys_exit_unlinkat"],
                "outcomes": ["succeeded", "failed", "denied"]
            },
            {
                "operation": "file_rename",
                "event_sources": ["syscalls/sys_enter_renameat2", "syscalls/sys_exit_renameat2"],
                "outcomes": ["succeeded", "failed", "denied"]
            },
            {
                "operation": "credential_path_access",
                "event_sources": ["syscalls/sys_enter_openat", "syscalls/sys_exit_openat", "syscalls/sys_enter_openat2", "syscalls/sys_exit_openat2"],
                "outcomes": ["succeeded", "failed", "denied"]
            }
        ]
    })
}

fn lifecycle(
    agent_run_id: &str,
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
        "collector_instance_id": "collector-1",
        "state": state,
        "health": health,
        "stop_reason": stop_reason,
        "counters": zero_counters()
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

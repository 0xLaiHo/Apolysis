// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f3_block_enablement_policy, evaluate_f3_block_validation_gate,
    F3BlockEnablementRequest, F3BlockRollbackPlan, F3BlockValidationAction,
    F3BlockValidationReport, F3BlockValidationRuntime, F3BlockValidationSource,
};

#[test]
fn f3_block_enablement_policy_approves_matching_opt_in_request_with_rollback() {
    let validation = evaluate_f3_block_validation_gate(vec![live_seccomp_report()]);
    let report = evaluate_f3_block_enablement_policy(validation, vec![approved_request()]);

    assert!(report.passed, "{report:#?}");
    assert!(report.failures.is_empty(), "{report:#?}");
    assert_eq!(report.approved_enablements.len(), 1);
    assert_eq!(
        report.approved_enablements[0].request_id,
        "enable-seccomp-file-read"
    );
    assert_eq!(
        report.approved_enablements[0].evidence_id,
        "live-seccomp-local-file-read"
    );
    assert!(!report.approved_enablements[0].default_enabled);
}

#[test]
fn f3_block_enablement_policy_rejects_default_enablement_without_operator_or_rollback() {
    let validation = evaluate_f3_block_validation_gate(vec![live_seccomp_report()]);
    let mut request = approved_request();
    request.operator_approved = false;
    request.default_enabled = true;
    request.rollback = None;

    let report = evaluate_f3_block_enablement_policy(validation, vec![request]);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approved_enablements.is_empty(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("operator approval is required"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("production-facing block must remain opt-in"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("rollback plan is required"),
        "{failure_text}"
    );
}

#[test]
fn f3_block_enablement_policy_rejects_mismatched_or_unvalidated_evidence() {
    let validation = evaluate_f3_block_validation_gate(vec![live_seccomp_report()]);
    let mut mismatch = approved_request();
    mismatch.request_id = "mismatch-action".to_string();
    mismatch.action = F3BlockValidationAction::NetworkConnect;

    let mut missing = approved_request();
    missing.request_id = "missing-evidence".to_string();
    missing.evidence_id = "unknown-live-report".to_string();

    let report = evaluate_f3_block_enablement_policy(validation, vec![mismatch, missing]);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approved_enablements.is_empty(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("does not match validated runtime/action/backend"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("no matching validated block evidence"),
        "{failure_text}"
    );
}

fn approved_request() -> F3BlockEnablementRequest {
    F3BlockEnablementRequest {
        request_id: "enable-seccomp-file-read".to_string(),
        evidence_id: "live-seccomp-local-file-read".to_string(),
        backend: "seccomp_block".to_string(),
        runtime: F3BlockValidationRuntime::Local,
        action: F3BlockValidationAction::FileRead,
        operator_approved: true,
        default_enabled: false,
        rollback: Some(F3BlockRollbackPlan {
            plan_id: "rollback-seccomp-file-read".to_string(),
            disable_command: "unset APOLYSIS_F3_BLOCK_ENABLEMENT".to_string(),
            validation_command: "make test-f3-guardrails".to_string(),
        }),
    }
}

fn live_seccomp_report() -> F3BlockValidationReport {
    F3BlockValidationReport {
        evidence_id: "live-seccomp-local-file-read".to_string(),
        source: F3BlockValidationSource::LiveHost,
        runtime: F3BlockValidationRuntime::Local,
        action: F3BlockValidationAction::FileRead,
        backend: "seccomp_block".to_string(),
        host_bpf_lsm_available: false,
        seccomp_available: true,
        preoperation_prevention: true,
        decision_latency_ms: Some(1),
        side_effect_race_window_ms: Some(0),
    }
}

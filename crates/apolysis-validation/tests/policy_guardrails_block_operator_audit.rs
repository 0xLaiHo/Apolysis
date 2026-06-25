// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_policy_guardrails_block_enablement_policy,
    evaluate_policy_guardrails_block_validation_gate,
    policy_guardrails_block_operator_audit_records, PolicyGuardrailsBlockEnablementRequest,
    PolicyGuardrailsBlockOperatorAuditOperation, PolicyGuardrailsBlockRollbackPlan,
    PolicyGuardrailsBlockValidationAction, PolicyGuardrailsBlockValidationReport,
    PolicyGuardrailsBlockValidationRuntime, PolicyGuardrailsBlockValidationSource,
};

#[test]
fn policy_guardrails_block_operator_audit_records_approval_and_rollback_events() {
    let validation = evaluate_policy_guardrails_block_validation_gate(vec![live_seccomp_report()]);
    let enablement =
        evaluate_policy_guardrails_block_enablement_policy(validation, vec![approved_request()]);

    let approval = policy_guardrails_block_operator_audit_records(
        &enablement,
        PolicyGuardrailsBlockOperatorAuditOperation::Approve,
        "operator@example.com",
        1_780_328_000_123,
    )
    .expect("approval audit records");
    let rollback = policy_guardrails_block_operator_audit_records(
        &enablement,
        PolicyGuardrailsBlockOperatorAuditOperation::Rollback,
        "operator@example.com",
        1_780_328_000_456,
    )
    .expect("rollback audit records");

    assert_eq!(approval.len(), 1);
    assert_eq!(rollback.len(), 1);
    assert_eq!(
        approval[0].record_type,
        "policy_guardrails_block_operator_audit"
    );
    assert_eq!(
        approval[0].operation,
        PolicyGuardrailsBlockOperatorAuditOperation::Approve
    );
    assert_eq!(
        rollback[0].operation,
        PolicyGuardrailsBlockOperatorAuditOperation::Rollback
    );
    assert_eq!(approval[0].request_id, "enable-seccomp-file-read");
    assert_eq!(rollback[0].request_id, approval[0].request_id);
    assert_eq!(rollback[0].rollback_plan_id, approval[0].rollback_plan_id);
    assert_eq!(approval[0].operator, "operator@example.com");

    let line = approval[0].to_json_line().expect("serialize approval");
    assert!(line.contains(r#""record_type":"policy_guardrails_block_operator_audit""#));
    assert!(line.contains(r#""operation":"approve""#));
    assert!(line.contains(r#""backend":"seccomp_block""#));
    assert!(line.contains(r#""runtime":"local""#));
    assert!(line.contains(r#""action":"file_read""#));
    assert!(line.contains(r#""default_enabled":false"#));
}

#[test]
fn policy_guardrails_block_operator_audit_requires_passed_enablement_report_and_operator() {
    let mut failed = evaluate_policy_guardrails_block_enablement_policy(
        evaluate_policy_guardrails_block_validation_gate(vec![live_seccomp_report()]),
        vec![approved_request()],
    );
    failed.passed = false;

    let failed_error = policy_guardrails_block_operator_audit_records(
        &failed,
        PolicyGuardrailsBlockOperatorAuditOperation::Approve,
        "operator@example.com",
        1,
    )
    .expect_err("failed report must not produce audit records");
    let operator_error = policy_guardrails_block_operator_audit_records(
        &evaluate_policy_guardrails_block_enablement_policy(
            evaluate_policy_guardrails_block_validation_gate(vec![live_seccomp_report()]),
            vec![approved_request()],
        ),
        PolicyGuardrailsBlockOperatorAuditOperation::Approve,
        "",
        1,
    )
    .expect_err("operator is required");

    assert!(
        failed_error.contains("passed enablement policy report"),
        "{failed_error}"
    );
    assert!(
        operator_error.contains("operator is required"),
        "{operator_error}"
    );
}

fn approved_request() -> PolicyGuardrailsBlockEnablementRequest {
    PolicyGuardrailsBlockEnablementRequest {
        request_id: "enable-seccomp-file-read".to_string(),
        evidence_id: "live-seccomp-local-file-read".to_string(),
        backend: "seccomp_block".to_string(),
        runtime: PolicyGuardrailsBlockValidationRuntime::Local,
        action: PolicyGuardrailsBlockValidationAction::FileRead,
        operator_approved: true,
        default_enabled: false,
        rollback: Some(PolicyGuardrailsBlockRollbackPlan {
            plan_id: "rollback-seccomp-file-read".to_string(),
            disable_command: "unset APOLYSIS_POLICY_GUARDRAILS_BLOCK_ENABLEMENT".to_string(),
            validation_command: "make test-policy-guardrails".to_string(),
        }),
    }
}

fn live_seccomp_report() -> PolicyGuardrailsBlockValidationReport {
    PolicyGuardrailsBlockValidationReport {
        evidence_id: "live-seccomp-local-file-read".to_string(),
        source: PolicyGuardrailsBlockValidationSource::LiveHost,
        runtime: PolicyGuardrailsBlockValidationRuntime::Local,
        action: PolicyGuardrailsBlockValidationAction::FileRead,
        backend: "seccomp_block".to_string(),
        host_bpf_lsm_available: false,
        seccomp_available: true,
        preoperation_prevention: true,
        decision_latency_ms: Some(1),
        side_effect_race_window_ms: Some(0),
    }
}

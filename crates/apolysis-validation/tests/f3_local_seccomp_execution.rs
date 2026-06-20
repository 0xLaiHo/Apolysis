// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f3_local_seccomp_execution_gate, F3BlockApprovedEnablement,
    F3BlockEnablementPolicyReport, F3BlockValidationAction, F3BlockValidationRuntime,
    F3LocalSeccompExecutionRequest,
};

#[test]
fn f3_local_seccomp_execution_gate_allows_matching_approved_enablement() {
    let report =
        evaluate_f3_local_seccomp_execution_gate(&approved_policy(), approved_execution_request());

    assert!(report.passed, "{report:#?}");
    assert!(report.failures.is_empty(), "{report:#?}");
    assert_eq!(
        report.applied_enablement_id.as_deref(),
        Some("enable-seccomp-file-read")
    );
    assert_eq!(report.enforcement_backend.as_deref(), Some("seccomp_block"));
    assert_eq!(report.target_path, "/etc/passwd");
}

#[test]
fn f3_local_seccomp_execution_gate_fails_closed_without_passed_enablement() {
    let mut policy = approved_policy();
    policy.passed = false;
    policy.approved_enablements.clear();

    let report = evaluate_f3_local_seccomp_execution_gate(&policy, approved_execution_request());

    assert!(!report.passed, "{report:#?}");
    assert!(report.applied_enablement_id.is_none(), "{report:#?}");
    assert!(report.enforcement_backend.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("passed enablement policy report"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("no matching approved local seccomp file-read enablement"),
        "{failure_text}"
    );
}

#[test]
fn f3_local_seccomp_execution_gate_rejects_mismatched_request_scope() {
    let mut request = approved_execution_request();
    request.evidence_id = "other-evidence".to_string();
    request.backend = "bpf_lsm_block".to_string();
    request.runtime = F3BlockValidationRuntime::Kubernetes;
    request.action = F3BlockValidationAction::NetworkConnect;
    request.target_path = "  ".to_string();

    let report = evaluate_f3_local_seccomp_execution_gate(&approved_policy(), request);

    assert!(!report.passed, "{report:#?}");
    assert!(report.applied_enablement_id.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("local seccomp execution only supports backend seccomp_block"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("local seccomp execution only supports local runtime"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("local seccomp execution only supports file_read action"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("target path is required"),
        "{failure_text}"
    );
}

fn approved_policy() -> F3BlockEnablementPolicyReport {
    F3BlockEnablementPolicyReport {
        schema_version: 1,
        passed: true,
        approved_enablements: vec![F3BlockApprovedEnablement {
            request_id: "enable-seccomp-file-read".to_string(),
            evidence_id: "live-seccomp-local-file-read".to_string(),
            backend: "seccomp_block".to_string(),
            runtime: F3BlockValidationRuntime::Local,
            action: F3BlockValidationAction::FileRead,
            default_enabled: false,
            rollback_plan_id: "rollback-seccomp-file-read".to_string(),
        }],
        failures: Vec::new(),
    }
}

fn approved_execution_request() -> F3LocalSeccompExecutionRequest {
    F3LocalSeccompExecutionRequest {
        evidence_id: "live-seccomp-local-file-read".to_string(),
        backend: "seccomp_block".to_string(),
        runtime: F3BlockValidationRuntime::Local,
        action: F3BlockValidationAction::FileRead,
        target_path: "/etc/passwd".to_string(),
    }
}

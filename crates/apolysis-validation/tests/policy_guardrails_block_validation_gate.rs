// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_policy_guardrails_block_validation_gate, PolicyGuardrailsBlockValidationAction,
    PolicyGuardrailsBlockValidationReport, PolicyGuardrailsBlockValidationRuntime,
    PolicyGuardrailsBlockValidationSource,
};

#[test]
fn policy_guardrails_block_validation_gate_accepts_live_zero_race_window_report() {
    let gate = evaluate_policy_guardrails_block_validation_gate(vec![live_block_report()]);

    assert!(gate.passed, "{gate:#?}");
    assert!(gate.failures.is_empty(), "{gate:#?}");
    assert_eq!(gate.validated_blocks.len(), 1);
    assert_eq!(
        gate.validated_blocks[0].runtime,
        PolicyGuardrailsBlockValidationRuntime::Local
    );
    assert_eq!(
        gate.validated_blocks[0].action,
        PolicyGuardrailsBlockValidationAction::FileRead
    );
}

#[test]
fn policy_guardrails_block_validation_gate_accepts_live_seccomp_block_report() {
    let mut report = live_block_report();
    report.evidence_id = "live-seccomp-file-read".to_string();
    report.backend = "seccomp_block".to_string();
    report.host_bpf_lsm_available = false;
    report.seccomp_available = true;

    let gate = evaluate_policy_guardrails_block_validation_gate(vec![report]);

    assert!(gate.passed, "{gate:#?}");
    assert!(gate.failures.is_empty(), "{gate:#?}");
    assert_eq!(gate.validated_blocks.len(), 1);
}

#[test]
fn policy_guardrails_block_validation_gate_rejects_fixture_or_post_event_reports() {
    let mut fixture = live_block_report();
    fixture.evidence_id = "fixture-report".to_string();
    fixture.source = PolicyGuardrailsBlockValidationSource::Fixture;

    let mut raced = live_block_report();
    raced.evidence_id = "post-event-report".to_string();
    raced.preoperation_prevention = false;
    raced.side_effect_race_window_ms = Some(9);

    let gate = evaluate_policy_guardrails_block_validation_gate(vec![fixture, raced]);

    assert!(!gate.passed, "{gate:#?}");
    assert!(gate.validated_blocks.is_empty(), "{gate:#?}");
    let failure_text = serde_json::to_string(&gate.failures).expect("serialize failures");
    assert!(
        failure_text.contains("pre-operation block requires live-host validation evidence"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("block prototype evidence must prove pre-operation prevention"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("block prototype evidence must prove a zero side-effect race window"),
        "{failure_text}"
    );
}

#[test]
fn policy_guardrails_block_validation_gate_rejects_runtime_mismatch_or_missing_latency() {
    let mut runtime_mismatch = live_block_report();
    runtime_mismatch.evidence_id = "runtime-mismatch".to_string();
    runtime_mismatch.runtime = PolicyGuardrailsBlockValidationRuntime::Gvisor;

    let mut missing_latency = live_block_report();
    missing_latency.evidence_id = "missing-latency".to_string();
    missing_latency.decision_latency_ms = None;

    let gate =
        evaluate_policy_guardrails_block_validation_gate(vec![runtime_mismatch, missing_latency]);

    assert!(!gate.passed, "{gate:#?}");
    assert!(gate.validated_blocks.is_empty(), "{gate:#?}");
    let failure_text = serde_json::to_string(&gate.failures).expect("serialize failures");
    assert!(
        failure_text.contains("does not support host BPF-LSM block validation"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("block prototype evidence must include decision latency"),
        "{failure_text}"
    );
}

#[test]
fn policy_guardrails_block_validation_gate_rejects_seccomp_report_without_seccomp_availability() {
    let mut report = live_block_report();
    report.evidence_id = "seccomp-unavailable".to_string();
    report.backend = "seccomp_block".to_string();
    report.host_bpf_lsm_available = false;
    report.seccomp_available = false;

    let gate = evaluate_policy_guardrails_block_validation_gate(vec![report]);

    assert!(!gate.passed, "{gate:#?}");
    let failure_text = serde_json::to_string(&gate.failures).expect("serialize failures");
    assert!(
        failure_text.contains("seccomp must be available before enabling block prototype"),
        "{failure_text}"
    );
}

fn live_block_report() -> PolicyGuardrailsBlockValidationReport {
    PolicyGuardrailsBlockValidationReport {
        evidence_id: "live-local-file-read".to_string(),
        source: PolicyGuardrailsBlockValidationSource::LiveHost,
        runtime: PolicyGuardrailsBlockValidationRuntime::Local,
        action: PolicyGuardrailsBlockValidationAction::FileRead,
        backend: "bpf_lsm_block".to_string(),
        host_bpf_lsm_available: true,
        seccomp_available: false,
        preoperation_prevention: true,
        decision_latency_ms: Some(3),
        side_effect_race_window_ms: Some(0),
    }
}

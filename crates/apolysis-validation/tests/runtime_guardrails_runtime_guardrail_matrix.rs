// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_runtime_guardrails_runtime_guardrail_matrix, PolicyGuardrailsBlockValidationAction,
    PolicyGuardrailsBlockValidationReport, PolicyGuardrailsBlockValidationRuntime,
    PolicyGuardrailsBlockValidationSource, RuntimeGuardrailsGuardrailSupportStatus,
    RuntimeGuardrailsRuntimeGuardrailTarget,
};

#[test]
fn runtime_guardrails_matrix_promotes_only_narrow_live_local_block_prototypes() {
    let matrix = evaluate_runtime_guardrails_runtime_guardrail_matrix(vec![
        live_report("live-seccomp-local-file-read", "seccomp_block"),
        live_report("live-bpf-lsm-local-file-read", "bpf_lsm_block"),
    ]);

    assert!(!matrix.production_facing_kernel_blocking_supported);
    let local = runtime(&matrix, RuntimeGuardrailsRuntimeGuardrailTarget::Local);
    assert_eq!(
        local.seccomp_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::PrototypeValidated
    );
    assert_eq!(
        local.bpf_lsm_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::PrototypeValidated
    );
    assert_eq!(
        local.seccomp_block.evidence_ids,
        vec!["live-seccomp-local-file-read".to_string()]
    );
    assert_eq!(
        local.bpf_lsm_block.evidence_ids,
        vec!["live-bpf-lsm-local-file-read".to_string()]
    );

    let docker = runtime(&matrix, RuntimeGuardrailsRuntimeGuardrailTarget::Docker);
    assert_eq!(
        docker.seccomp_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::RequiresRuntimeEvidence
    );
    assert!(docker.seccomp_block.evidence_ids.is_empty());
}

#[test]
fn runtime_guardrails_matrix_does_not_promote_fixture_or_runtime_mismatched_evidence() {
    let mut fixture = live_report("fixture-file-read", "bpf_lsm_block");
    fixture.source = PolicyGuardrailsBlockValidationSource::Fixture;
    let mut runtime_mismatch = live_report("live-gvisor-file-read", "bpf_lsm_block");
    runtime_mismatch.runtime = PolicyGuardrailsBlockValidationRuntime::Gvisor;

    let matrix =
        evaluate_runtime_guardrails_runtime_guardrail_matrix(vec![fixture, runtime_mismatch]);

    let local = runtime(&matrix, RuntimeGuardrailsRuntimeGuardrailTarget::Local);
    assert_eq!(
        local.bpf_lsm_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::RequiresRuntimeEvidence
    );
    assert!(local.bpf_lsm_block.evidence_ids.is_empty());
}

#[test]
fn runtime_guardrails_matrix_keeps_strong_isolation_boundary_claims_explicit() {
    let matrix = evaluate_runtime_guardrails_runtime_guardrail_matrix(Vec::new());

    let gvisor = runtime(&matrix, RuntimeGuardrailsRuntimeGuardrailTarget::Gvisor);
    assert_eq!(
        gvisor.bpf_lsm_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::MetadataOnly
    );
    assert!(!gvisor.requires_guest_collector);
    assert!(gvisor
        .no_go_claims
        .iter()
        .any(|claim| claim.contains("guest syscall semantics")));

    let kata = runtime(&matrix, RuntimeGuardrailsRuntimeGuardrailTarget::Kata);
    assert_eq!(
        kata.seccomp_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::BoundaryOnly
    );
    assert!(kata.requires_guest_collector);

    let firecracker = runtime(
        &matrix,
        RuntimeGuardrailsRuntimeGuardrailTarget::Firecracker,
    );
    assert_eq!(
        firecracker.kill.status,
        RuntimeGuardrailsGuardrailSupportStatus::BoundaryOnly
    );
    assert!(firecracker.requires_guest_collector);
}

fn runtime(
    matrix: &apolysis_validation::RuntimeGuardrailsRuntimeGuardrailMatrixReport,
    target: RuntimeGuardrailsRuntimeGuardrailTarget,
) -> &apolysis_validation::RuntimeGuardrailsRuntimeGuardrailSupport {
    matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == target)
        .expect("runtime matrix entry")
}

fn live_report(evidence_id: &str, backend: &str) -> PolicyGuardrailsBlockValidationReport {
    PolicyGuardrailsBlockValidationReport {
        evidence_id: evidence_id.to_string(),
        source: PolicyGuardrailsBlockValidationSource::LiveHost,
        runtime: PolicyGuardrailsBlockValidationRuntime::Local,
        action: PolicyGuardrailsBlockValidationAction::FileRead,
        backend: backend.to_string(),
        host_bpf_lsm_available: backend == "bpf_lsm_block",
        seccomp_available: backend == "seccomp_block",
        preoperation_prevention: true,
        decision_latency_ms: Some(2),
        side_effect_race_window_ms: Some(0),
    }
}

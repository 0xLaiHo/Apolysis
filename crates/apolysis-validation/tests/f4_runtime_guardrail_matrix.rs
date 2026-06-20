// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f4_runtime_guardrail_matrix, F3BlockValidationAction, F3BlockValidationReport,
    F3BlockValidationRuntime, F3BlockValidationSource, F4GuardrailSupportStatus,
    F4RuntimeGuardrailTarget,
};

#[test]
fn f4_matrix_promotes_only_narrow_live_local_block_prototypes() {
    let matrix = evaluate_f4_runtime_guardrail_matrix(vec![
        live_report("live-seccomp-local-file-read", "seccomp_block"),
        live_report("live-bpf-lsm-local-file-read", "bpf_lsm_block"),
    ]);

    assert!(!matrix.production_facing_kernel_blocking_supported);
    let local = runtime(&matrix, F4RuntimeGuardrailTarget::Local);
    assert_eq!(
        local.seccomp_block.status,
        F4GuardrailSupportStatus::PrototypeValidated
    );
    assert_eq!(
        local.bpf_lsm_block.status,
        F4GuardrailSupportStatus::PrototypeValidated
    );
    assert_eq!(
        local.seccomp_block.evidence_ids,
        vec!["live-seccomp-local-file-read".to_string()]
    );
    assert_eq!(
        local.bpf_lsm_block.evidence_ids,
        vec!["live-bpf-lsm-local-file-read".to_string()]
    );

    let docker = runtime(&matrix, F4RuntimeGuardrailTarget::Docker);
    assert_eq!(
        docker.seccomp_block.status,
        F4GuardrailSupportStatus::RequiresRuntimeEvidence
    );
    assert!(docker.seccomp_block.evidence_ids.is_empty());
}

#[test]
fn f4_matrix_does_not_promote_fixture_or_runtime_mismatched_evidence() {
    let mut fixture = live_report("fixture-file-read", "bpf_lsm_block");
    fixture.source = F3BlockValidationSource::Fixture;
    let mut runtime_mismatch = live_report("live-gvisor-file-read", "bpf_lsm_block");
    runtime_mismatch.runtime = F3BlockValidationRuntime::Gvisor;

    let matrix = evaluate_f4_runtime_guardrail_matrix(vec![fixture, runtime_mismatch]);

    let local = runtime(&matrix, F4RuntimeGuardrailTarget::Local);
    assert_eq!(
        local.bpf_lsm_block.status,
        F4GuardrailSupportStatus::RequiresRuntimeEvidence
    );
    assert!(local.bpf_lsm_block.evidence_ids.is_empty());
}

#[test]
fn f4_matrix_keeps_strong_isolation_boundary_claims_explicit() {
    let matrix = evaluate_f4_runtime_guardrail_matrix(Vec::new());

    let gvisor = runtime(&matrix, F4RuntimeGuardrailTarget::Gvisor);
    assert_eq!(
        gvisor.bpf_lsm_block.status,
        F4GuardrailSupportStatus::MetadataOnly
    );
    assert!(!gvisor.requires_guest_collector);
    assert!(gvisor
        .no_go_claims
        .iter()
        .any(|claim| claim.contains("guest syscall semantics")));

    let kata = runtime(&matrix, F4RuntimeGuardrailTarget::Kata);
    assert_eq!(
        kata.seccomp_block.status,
        F4GuardrailSupportStatus::BoundaryOnly
    );
    assert!(kata.requires_guest_collector);

    let firecracker = runtime(&matrix, F4RuntimeGuardrailTarget::Firecracker);
    assert_eq!(
        firecracker.kill.status,
        F4GuardrailSupportStatus::BoundaryOnly
    );
    assert!(firecracker.requires_guest_collector);
}

fn runtime(
    matrix: &apolysis_validation::F4RuntimeGuardrailMatrixReport,
    target: F4RuntimeGuardrailTarget,
) -> &apolysis_validation::F4RuntimeGuardrailSupport {
    matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == target)
        .expect("runtime matrix entry")
}

fn live_report(evidence_id: &str, backend: &str) -> F3BlockValidationReport {
    F3BlockValidationReport {
        evidence_id: evidence_id.to_string(),
        source: F3BlockValidationSource::LiveHost,
        runtime: F3BlockValidationRuntime::Local,
        action: F3BlockValidationAction::FileRead,
        backend: backend.to_string(),
        host_bpf_lsm_available: backend == "bpf_lsm_block",
        seccomp_available: backend == "seccomp_block",
        preoperation_prevention: true,
        decision_latency_ms: Some(2),
        side_effect_race_window_ms: Some(0),
    }
}

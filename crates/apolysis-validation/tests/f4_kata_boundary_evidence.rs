// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f4_kata_boundary_evidence_gate,
    evaluate_f4_runtime_guardrail_matrix_with_kata_boundary, F4GuardrailSupportStatus,
    F4KataBoundaryEvidenceReport, F4RuntimeAdapterEvidenceGateReport,
    F4RuntimeAdapterEvidenceSource, F4RuntimeGuardrailTarget,
};

#[test]
fn f4_kata_boundary_gate_validates_vmm_and_shim_boundary_evidence() {
    let gate = evaluate_f4_kata_boundary_evidence_gate(vec![kata_boundary_evidence()]);

    assert!(gate.passed);
    assert_eq!(gate.validated_evidence.len(), 1);
    assert_eq!(
        gate.validated_evidence[0].evidence_id,
        "live-kata-qemu-shim-boundary"
    );
}

#[test]
fn f4_kata_boundary_gate_rejects_incomplete_or_guest_semantic_evidence() {
    let mut missing_vmm = kata_boundary_evidence();
    missing_vmm.evidence_id = "live-kata-missing-vmm".to_string();
    missing_vmm.vmm_observed = false;
    let mut overclaim = kata_boundary_evidence();
    overclaim.evidence_id = "live-kata-overclaim".to_string();
    overclaim.guest_semantics_claimed = true;
    let mut fixture = kata_boundary_evidence();
    fixture.evidence_id = "fixture-kata-boundary".to_string();
    fixture.source = F4RuntimeAdapterEvidenceSource::Fixture;

    let gate = evaluate_f4_kata_boundary_evidence_gate(vec![missing_vmm, overclaim, fixture]);

    assert!(!gate.passed);
    assert!(gate.validated_evidence.is_empty());
    let failures = gate
        .failures
        .iter()
        .map(|failure| failure.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(failures.contains("VMM"));
    assert!(failures.contains("must not claim guest semantics"));
    assert!(failures.contains("live-host"));
}

#[test]
fn f4_matrix_attaches_kata_boundary_evidence_without_enabling_block() {
    let gate = evaluate_f4_kata_boundary_evidence_gate(vec![kata_boundary_evidence()]);
    let matrix = evaluate_f4_runtime_guardrail_matrix_with_kata_boundary(
        Vec::new(),
        F4RuntimeAdapterEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
        gate,
    );

    let kata = matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == F4RuntimeGuardrailTarget::Kata)
        .expect("kata row");
    assert_eq!(
        kata.notify.evidence_ids,
        vec!["live-kata-qemu-shim-boundary"]
    );
    assert_eq!(
        kata.review.evidence_ids,
        vec!["live-kata-qemu-shim-boundary"]
    );
    assert_eq!(kata.kill.evidence_ids, vec!["live-kata-qemu-shim-boundary"]);
    assert_eq!(
        kata.seccomp_block.status,
        F4GuardrailSupportStatus::BoundaryOnly
    );
    assert_eq!(
        kata.seccomp_block.evidence_ids,
        vec!["live-kata-qemu-shim-boundary"]
    );
    assert!(kata.requires_guest_collector);
    assert!(!matrix.production_facing_kernel_blocking_supported);
}

fn kata_boundary_evidence() -> F4KataBoundaryEvidenceReport {
    F4KataBoundaryEvidenceReport {
        evidence_id: "live-kata-qemu-shim-boundary".to_string(),
        source: F4RuntimeAdapterEvidenceSource::LiveHost,
        runtime_adapter_evidence_id: "live-kubernetes-kata-cgroup".to_string(),
        session_id: "session-kata".to_string(),
        runtime_handler: Some("kata".to_string()),
        host_event_subjects: vec![
            "containerd-shim-kata-v2".to_string(),
            "qemu-system-x86".to_string(),
        ],
        shim_observed: true,
        vmm_observed: true,
        host_boundary_visibility: true,
        guest_collector_required: true,
        guest_semantics_claimed: false,
    }
}

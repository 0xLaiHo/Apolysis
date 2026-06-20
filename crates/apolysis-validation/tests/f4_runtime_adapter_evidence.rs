// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f4_runtime_adapter_evidence_gate,
    evaluate_f4_runtime_guardrail_matrix_with_adapter_evidence, F4GuardrailSupportStatus,
    F4RuntimeAdapterEvidenceReport, F4RuntimeAdapterEvidenceSource, F4RuntimeGuardrailTarget,
};

#[test]
fn f4_runtime_adapter_gate_validates_live_metadata_and_cgroup_correlation() {
    let gate = evaluate_f4_runtime_adapter_evidence_gate(vec![docker_evidence()]);

    assert!(gate.passed);
    assert_eq!(gate.validated_evidence.len(), 1);
    assert_eq!(
        gate.validated_evidence[0].evidence_id,
        "live-docker-runc-cgroup"
    );
    assert_eq!(
        gate.validated_evidence[0].runtime,
        F4RuntimeGuardrailTarget::Docker
    );
}

#[test]
fn f4_runtime_adapter_gate_rejects_fixture_or_guest_semantic_overclaim() {
    let mut fixture = docker_evidence();
    fixture.source = F4RuntimeAdapterEvidenceSource::Fixture;
    let mut gvisor_overclaim = docker_evidence();
    gvisor_overclaim.evidence_id = "live-gvisor-overclaim".to_string();
    gvisor_overclaim.runtime = F4RuntimeGuardrailTarget::Gvisor;
    gvisor_overclaim.guest_semantics_claimed = true;

    let gate = evaluate_f4_runtime_adapter_evidence_gate(vec![fixture, gvisor_overclaim]);

    assert!(!gate.passed);
    assert!(gate.validated_evidence.is_empty());
    assert!(gate
        .failures
        .iter()
        .any(|failure| failure.message.contains("live runtime adapter evidence")));
    assert!(gate
        .failures
        .iter()
        .any(|failure| failure.message.contains("must not claim guest semantics")));
}

#[test]
fn f4_matrix_attaches_validated_adapter_evidence_without_enabling_block() {
    let gate = evaluate_f4_runtime_adapter_evidence_gate(vec![docker_evidence()]);
    let matrix = evaluate_f4_runtime_guardrail_matrix_with_adapter_evidence(Vec::new(), gate);

    let docker = matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == F4RuntimeGuardrailTarget::Docker)
        .expect("docker matrix row");
    assert_eq!(docker.notify.status, F4GuardrailSupportStatus::Supported);
    assert_eq!(
        docker.notify.evidence_ids,
        vec!["live-docker-runc-cgroup".to_string()]
    );
    assert_eq!(
        docker.review.evidence_ids,
        vec!["live-docker-runc-cgroup".to_string()]
    );
    assert_eq!(
        docker.kill.evidence_ids,
        vec!["live-docker-runc-cgroup".to_string()]
    );
    assert_eq!(
        docker.seccomp_block.status,
        F4GuardrailSupportStatus::RequiresRuntimeEvidence
    );
    assert!(docker.seccomp_block.evidence_ids.is_empty());
    assert!(!matrix.production_facing_kernel_blocking_supported);
}

fn docker_evidence() -> F4RuntimeAdapterEvidenceReport {
    F4RuntimeAdapterEvidenceReport {
        evidence_id: "live-docker-runc-cgroup".to_string(),
        source: F4RuntimeAdapterEvidenceSource::LiveHost,
        runtime: F4RuntimeGuardrailTarget::Docker,
        adapter: "docker".to_string(),
        session_id: "session-docker".to_string(),
        workload_id: "container-123".to_string(),
        cgroup_id: 77,
        runtime_handler: Some("runc".to_string()),
        metadata_correlation: true,
        cgroup_correlation: true,
        host_boundary_visibility: true,
        guest_semantics_claimed: false,
    }
}

// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_runtime_guardrails_gvisor_metadata_evidence_gate,
    evaluate_runtime_guardrails_runtime_guardrail_matrix_with_gvisor_metadata,
    RuntimeGuardrailsGuardrailSupportStatus, RuntimeGuardrailsGvisorMetadataEvidenceReport,
    RuntimeGuardrailsRuntimeAdapterEvidenceGateReport,
    RuntimeGuardrailsRuntimeAdapterEvidenceSource, RuntimeGuardrailsRuntimeGuardrailTarget,
};

#[test]
fn runtime_guardrails_gvisor_metadata_gate_validates_runsc_sentry_gofer_boundary_evidence() {
    let gate = evaluate_runtime_guardrails_gvisor_metadata_evidence_gate(vec![gvisor_evidence()]);

    assert!(gate.passed);
    assert_eq!(gate.validated_evidence.len(), 1);
    assert_eq!(
        gate.validated_evidence[0].evidence_id,
        "live-gvisor-runsc-sentry-gofer"
    );
}

#[test]
fn runtime_guardrails_gvisor_metadata_gate_rejects_incomplete_or_guest_semantic_evidence() {
    let mut missing_gofer = gvisor_evidence();
    missing_gofer.evidence_id = "live-gvisor-missing-gofer".to_string();
    missing_gofer.gofer_observed = false;
    let mut overclaim = gvisor_evidence();
    overclaim.evidence_id = "live-gvisor-overclaim".to_string();
    overclaim.guest_semantics_claimed = true;
    let mut fixture = gvisor_evidence();
    fixture.evidence_id = "fixture-gvisor".to_string();
    fixture.source = RuntimeGuardrailsRuntimeAdapterEvidenceSource::Fixture;

    let gate = evaluate_runtime_guardrails_gvisor_metadata_evidence_gate(vec![
        missing_gofer,
        overclaim,
        fixture,
    ]);

    assert!(!gate.passed);
    assert!(gate.validated_evidence.is_empty());
    let failures = gate
        .failures
        .iter()
        .map(|failure| failure.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(failures.contains("runsc, sentry, and gofer"));
    assert!(failures.contains("must not claim guest semantics"));
    assert!(failures.contains("live-host"));
}

#[test]
fn runtime_guardrails_matrix_attaches_gvisor_metadata_evidence_without_enabling_block() {
    let gate = evaluate_runtime_guardrails_gvisor_metadata_evidence_gate(vec![gvisor_evidence()]);
    let matrix = evaluate_runtime_guardrails_runtime_guardrail_matrix_with_gvisor_metadata(
        Vec::new(),
        RuntimeGuardrailsRuntimeAdapterEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
        gate,
    );

    let gvisor = matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == RuntimeGuardrailsRuntimeGuardrailTarget::Gvisor)
        .expect("gvisor row");
    assert_eq!(
        gvisor.notify.evidence_ids,
        vec!["live-gvisor-runsc-sentry-gofer"]
    );
    assert_eq!(
        gvisor.review.evidence_ids,
        vec!["live-gvisor-runsc-sentry-gofer"]
    );
    assert_eq!(
        gvisor.bpf_lsm_block.status,
        RuntimeGuardrailsGuardrailSupportStatus::MetadataOnly
    );
    assert_eq!(
        gvisor.bpf_lsm_block.evidence_ids,
        vec!["live-gvisor-runsc-sentry-gofer"]
    );
    assert!(!matrix.production_facing_kernel_blocking_supported);
}

fn gvisor_evidence() -> RuntimeGuardrailsGvisorMetadataEvidenceReport {
    RuntimeGuardrailsGvisorMetadataEvidenceReport {
        evidence_id: "live-gvisor-runsc-sentry-gofer".to_string(),
        source: RuntimeGuardrailsRuntimeAdapterEvidenceSource::LiveHost,
        runtime_adapter_evidence_id: "live-containerd-gvisor-cgroup".to_string(),
        session_id: "session-gvisor".to_string(),
        runtime_handler: Some("io.containerd.runsc.v1".to_string()),
        host_event_subjects: vec![
            "gofer".to_string(),
            "runsc-sandbox".to_string(),
            "sentry".to_string(),
        ],
        runsc_observed: true,
        sentry_observed: true,
        gofer_observed: true,
        host_semantics_collapsed: true,
        guest_semantics_claimed: false,
    }
}

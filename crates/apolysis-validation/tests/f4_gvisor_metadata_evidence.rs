// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f4_gvisor_metadata_evidence_gate,
    evaluate_f4_runtime_guardrail_matrix_with_gvisor_metadata, F4GuardrailSupportStatus,
    F4GvisorMetadataEvidenceReport, F4RuntimeAdapterEvidenceGateReport,
    F4RuntimeAdapterEvidenceSource, F4RuntimeGuardrailTarget,
};

#[test]
fn f4_gvisor_metadata_gate_validates_runsc_sentry_gofer_boundary_evidence() {
    let gate = evaluate_f4_gvisor_metadata_evidence_gate(vec![gvisor_evidence()]);

    assert!(gate.passed);
    assert_eq!(gate.validated_evidence.len(), 1);
    assert_eq!(
        gate.validated_evidence[0].evidence_id,
        "live-gvisor-runsc-sentry-gofer"
    );
}

#[test]
fn f4_gvisor_metadata_gate_rejects_incomplete_or_guest_semantic_evidence() {
    let mut missing_gofer = gvisor_evidence();
    missing_gofer.evidence_id = "live-gvisor-missing-gofer".to_string();
    missing_gofer.gofer_observed = false;
    let mut overclaim = gvisor_evidence();
    overclaim.evidence_id = "live-gvisor-overclaim".to_string();
    overclaim.guest_semantics_claimed = true;
    let mut fixture = gvisor_evidence();
    fixture.evidence_id = "fixture-gvisor".to_string();
    fixture.source = F4RuntimeAdapterEvidenceSource::Fixture;

    let gate = evaluate_f4_gvisor_metadata_evidence_gate(vec![missing_gofer, overclaim, fixture]);

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
fn f4_matrix_attaches_gvisor_metadata_evidence_without_enabling_block() {
    let gate = evaluate_f4_gvisor_metadata_evidence_gate(vec![gvisor_evidence()]);
    let matrix = evaluate_f4_runtime_guardrail_matrix_with_gvisor_metadata(
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

    let gvisor = matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == F4RuntimeGuardrailTarget::Gvisor)
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
        F4GuardrailSupportStatus::MetadataOnly
    );
    assert_eq!(
        gvisor.bpf_lsm_block.evidence_ids,
        vec!["live-gvisor-runsc-sentry-gofer"]
    );
    assert!(!matrix.production_facing_kernel_blocking_supported);
}

fn gvisor_evidence() -> F4GvisorMetadataEvidenceReport {
    F4GvisorMetadataEvidenceReport {
        evidence_id: "live-gvisor-runsc-sentry-gofer".to_string(),
        source: F4RuntimeAdapterEvidenceSource::LiveHost,
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

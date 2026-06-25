// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::RuntimeGuardrailsRuntimeAdapterEvidenceSource;
use apolysis_visibility::{
    assess_visibility, runtime_guardrails_kata_boundary_evidence_from_assessment,
    RuntimeVisibilityProfile, VisibilityInput,
};

#[test]
fn kata_visibility_assessment_becomes_runtime_guardrails_boundary_evidence() {
    let assessment = assess_visibility(VisibilityInput::new(
        "session-kata",
        RuntimeVisibilityProfile::KubernetesKata,
        fixture("tests/fixtures/visibility/kubernetes-kata-host-events.txt"),
    ))
    .expect("kata assessment");

    let evidence = runtime_guardrails_kata_boundary_evidence_from_assessment(
        &assessment,
        "live-kata-qemu-shim-boundary",
        "live-kubernetes-kata-cgroup",
        Some("kata"),
        RuntimeGuardrailsRuntimeAdapterEvidenceSource::LiveHost,
    )
    .expect("kata boundary evidence");

    assert!(evidence.shim_observed);
    assert!(evidence.vmm_observed);
    assert!(evidence.host_boundary_visibility);
    assert!(evidence.guest_collector_required);
    assert!(!evidence.guest_semantics_claimed);
}

fn fixture(path: &str) -> String {
    std::fs::read_to_string(workspace_root().join(path)).expect("read fixture")
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

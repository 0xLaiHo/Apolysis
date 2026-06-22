// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::F4RuntimeAdapterEvidenceSource;
use apolysis_visibility::{
    assess_visibility, f4_kata_boundary_evidence_from_assessment, RuntimeVisibilityProfile,
    VisibilityInput,
};

#[test]
fn kata_visibility_assessment_becomes_f4_boundary_evidence() {
    let assessment = assess_visibility(VisibilityInput::new(
        "session-kata",
        RuntimeVisibilityProfile::KubernetesKata,
        fixture("tests/fixtures/visibility/kubernetes-kata-host-events.txt"),
    ))
    .expect("kata assessment");

    let evidence = f4_kata_boundary_evidence_from_assessment(
        &assessment,
        "live-kata-qemu-shim-boundary",
        "live-kubernetes-kata-cgroup",
        Some("kata"),
        F4RuntimeAdapterEvidenceSource::LiveHost,
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

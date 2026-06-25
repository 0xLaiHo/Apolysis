// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::RuntimeGuardrailsRuntimeAdapterEvidenceSource;
use apolysis_visibility::{
    assess_visibility, runtime_guardrails_gvisor_metadata_evidence_from_assessment,
    RuntimeVisibilityProfile, VisibilityInput,
};

#[test]
fn gvisor_visibility_assessment_becomes_runtime_guardrails_metadata_evidence() {
    let assessment = assess_visibility(VisibilityInput::new(
        "session-gvisor",
        RuntimeVisibilityProfile::DockerGvisor,
        fixture("tests/fixtures/visibility/docker-gvisor-host-events.txt"),
    ))
    .expect("gvisor assessment");

    let evidence = runtime_guardrails_gvisor_metadata_evidence_from_assessment(
        &assessment,
        "live-gvisor-runsc-sentry-gofer",
        "live-containerd-gvisor-cgroup",
        Some("io.containerd.runsc.v1"),
        RuntimeGuardrailsRuntimeAdapterEvidenceSource::LiveHost,
    )
    .expect("gvisor metadata evidence");

    assert!(evidence.runsc_observed);
    assert!(evidence.sentry_observed);
    assert!(evidence.gofer_observed);
    assert!(evidence.host_semantics_collapsed);
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

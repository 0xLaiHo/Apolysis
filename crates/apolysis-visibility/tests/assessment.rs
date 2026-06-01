// SPDX-License-Identifier: Apache-2.0

use apolysis_visibility::{
    assess_visibility, HostVisibilityScope, RuntimeVisibilityProfile, VisibilityInput,
};

#[test]
fn docker_default_keeps_guest_process_semantics_visible_on_host() {
    let events = fixture("tests/fixtures/visibility/docker-default-host-events.txt");
    let assessment = assess_visibility(VisibilityInput::new(
        "session-m7-docker",
        RuntimeVisibilityProfile::DockerDefault,
        events,
    ))
    .expect("assess docker visibility");

    assert_eq!(
        assessment.host_visibility_scope,
        HostVisibilityScope::GuestProcess
    );
    assert!(!assessment.host_semantics_collapsed);
    assert!(!assessment.guest_collector_required);
    assert!(!assessment.runtime_metadata_required);
}

#[test]
fn gvisor_collapses_host_events_to_runtime_boundary() {
    let events = fixture("tests/fixtures/visibility/docker-gvisor-host-events.txt");
    let assessment = assess_visibility(VisibilityInput::new(
        "session-m7-gvisor",
        RuntimeVisibilityProfile::DockerGvisor,
        events,
    ))
    .expect("assess gvisor visibility");

    assert_eq!(
        assessment.host_visibility_scope,
        HostVisibilityScope::RuntimeBoundary
    );
    assert!(assessment.host_semantics_collapsed);
    assert!(!assessment.guest_collector_required);
    assert!(assessment.runtime_metadata_required);
    assert!(assessment.notes.contains("runsc"));
}

#[test]
fn kubernetes_gvisor_needs_runtime_metadata_for_pod_correlation() {
    let assessment = assess_visibility(VisibilityInput::new(
        "session-m7-k8s-gvisor",
        RuntimeVisibilityProfile::KubernetesGvisor,
        fixture("tests/fixtures/visibility/kubernetes-gvisor-host-events.txt"),
    ))
    .expect("assess kubernetes gvisor visibility");

    assert_eq!(
        assessment.host_visibility_scope,
        HostVisibilityScope::RuntimeBoundary
    );
    assert!(assessment.host_semantics_collapsed);
    assert!(!assessment.guest_collector_required);
    assert!(assessment.runtime_metadata_required);
    assert!(assessment.notes.contains("Kubernetes pod"));
}

#[test]
fn kata_and_firecracker_require_guest_collectors_for_full_semantics() {
    let kata = assess_visibility(VisibilityInput::new(
        "session-m7-kata",
        RuntimeVisibilityProfile::KubernetesKata,
        fixture("tests/fixtures/visibility/kubernetes-kata-host-events.txt"),
    ))
    .expect("assess kata visibility");
    assert_eq!(
        kata.host_visibility_scope,
        HostVisibilityScope::BoundaryOnly
    );
    assert!(kata.host_semantics_collapsed);
    assert!(kata.guest_collector_required);
    assert!(kata.notes.contains("guest kernel"));

    let firecracker = assess_visibility(VisibilityInput::new(
        "session-m7-firecracker",
        RuntimeVisibilityProfile::FirecrackerPrototype,
        fixture("tests/fixtures/visibility/firecracker-boundary-events.txt"),
    ))
    .expect("assess firecracker visibility");
    assert_eq!(
        firecracker.host_visibility_scope,
        HostVisibilityScope::BoundaryOnly
    );
    assert!(firecracker.host_semantics_collapsed);
    assert!(firecracker.guest_collector_required);
    assert!(firecracker.notes.contains("vsock"));
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

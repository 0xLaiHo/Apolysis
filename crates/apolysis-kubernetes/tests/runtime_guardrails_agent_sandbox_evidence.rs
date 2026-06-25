// SPDX-License-Identifier: Apache-2.0

use apolysis_kubernetes::{
    runtime_guardrails_agent_sandbox_evidence_from_metadata, KubernetesMetadata,
};
use apolysis_validation::RuntimeGuardrailsRuntimeAdapterEvidenceSource;

#[test]
fn kubernetes_metadata_becomes_runtime_guardrails_agent_sandbox_evidence() {
    let metadata = KubernetesMetadata::parse(&fixture(
        "tests/fixtures/kubernetes/agent-sandbox-gvisor-pod.yaml",
    ))
    .expect("parse fixture metadata");

    let evidence = runtime_guardrails_agent_sandbox_evidence_from_metadata(
        &metadata,
        "session-k8s-gvisor",
        "live-kubernetes-agent-sandbox-gvisor",
        "live-kubernetes-gvisor-cgroup",
        RuntimeGuardrailsRuntimeAdapterEvidenceSource::LiveHost,
    )
    .expect("agent sandbox evidence");

    assert_eq!(evidence.pod_name, "codex-session-7");
    assert_eq!(evidence.namespace, "agents");
    assert_eq!(evidence.service_account.as_deref(), Some("agent-runner"));
    assert_eq!(evidence.runtime_class_name.as_deref(), Some("gvisor"));
    assert_eq!(evidence.sandbox_name.as_deref(), Some("codex-sandbox"));
    assert!(evidence.host_boundary_visibility);
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

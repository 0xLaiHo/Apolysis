// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f4_kubernetes_agent_sandbox_evidence_gate,
    evaluate_f4_runtime_guardrail_matrix_with_kubernetes_agent_sandbox, F4GuardrailSupportStatus,
    F4KubernetesAgentSandboxEvidenceReport, F4RuntimeAdapterEvidenceGateReport,
    F4RuntimeAdapterEvidenceSource, F4RuntimeGuardrailTarget,
};

#[test]
fn f4_kubernetes_agent_sandbox_gate_validates_pod_identity_and_sandbox_metadata() {
    let gate = evaluate_f4_kubernetes_agent_sandbox_evidence_gate(vec![agent_sandbox_evidence()]);

    assert!(gate.passed);
    assert_eq!(gate.validated_evidence.len(), 1);
    assert_eq!(
        gate.validated_evidence[0].evidence_id,
        "live-kubernetes-agent-sandbox-gvisor"
    );
}

#[test]
fn f4_kubernetes_agent_sandbox_gate_rejects_incomplete_or_guest_semantic_evidence() {
    let mut missing_service_account = agent_sandbox_evidence();
    missing_service_account.evidence_id = "live-kubernetes-missing-sa".to_string();
    missing_service_account.service_account = None;
    let mut overclaim = agent_sandbox_evidence();
    overclaim.evidence_id = "live-kubernetes-overclaim".to_string();
    overclaim.guest_semantics_claimed = true;
    let mut fixture = agent_sandbox_evidence();
    fixture.evidence_id = "fixture-kubernetes-agent-sandbox".to_string();
    fixture.source = F4RuntimeAdapterEvidenceSource::Fixture;

    let gate = evaluate_f4_kubernetes_agent_sandbox_evidence_gate(vec![
        missing_service_account,
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
    assert!(failures.contains("service account"));
    assert!(failures.contains("must not claim guest semantics"));
    assert!(failures.contains("live-host"));
}

#[test]
fn f4_matrix_attaches_kubernetes_agent_sandbox_evidence_without_enabling_block() {
    let gate = evaluate_f4_kubernetes_agent_sandbox_evidence_gate(vec![agent_sandbox_evidence()]);
    let matrix = evaluate_f4_runtime_guardrail_matrix_with_kubernetes_agent_sandbox(
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

    let kubernetes = matrix
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime == F4RuntimeGuardrailTarget::Kubernetes)
        .expect("kubernetes row");
    assert_eq!(
        kubernetes.notify.evidence_ids,
        vec!["live-kubernetes-agent-sandbox-gvisor"]
    );
    assert_eq!(
        kubernetes.review.evidence_ids,
        vec!["live-kubernetes-agent-sandbox-gvisor"]
    );
    assert_eq!(
        kubernetes.seccomp_block.status,
        F4GuardrailSupportStatus::RequiresRuntimeEvidence
    );
    assert!(kubernetes.seccomp_block.evidence_ids.is_empty());
    assert!(!matrix.production_facing_kernel_blocking_supported);
}

fn agent_sandbox_evidence() -> F4KubernetesAgentSandboxEvidenceReport {
    F4KubernetesAgentSandboxEvidenceReport {
        evidence_id: "live-kubernetes-agent-sandbox-gvisor".to_string(),
        source: F4RuntimeAdapterEvidenceSource::LiveHost,
        runtime_adapter_evidence_id: "live-kubernetes-gvisor-cgroup".to_string(),
        session_id: "session-k8s-gvisor".to_string(),
        pod_name: "agent-sandbox-pod".to_string(),
        namespace: "agents".to_string(),
        service_account: Some("agent-runner".to_string()),
        runtime_class_name: Some("gvisor".to_string()),
        sandbox_name: Some("agent-sandbox".to_string()),
        node_name: Some("node-a".to_string()),
        pod_uid: Some("pod-uid-123".to_string()),
        host_boundary_visibility: true,
        guest_semantics_claimed: false,
    }
}

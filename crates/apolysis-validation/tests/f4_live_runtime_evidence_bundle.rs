// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use apolysis_validation::{
    evaluate_f4_live_runtime_evidence_bundle, F4LiveRuntimeEvidenceBundleRequest,
    F4RuntimeGuardrailTarget, VisibilityReport, VisibilityTarget,
};

#[test]
fn f4_live_runtime_evidence_bundle_requires_matrix_artifacts_and_visibility_gate() {
    let root = test_root("f4-live-runtime-evidence-pass");
    create_matrix_artifacts(&root);
    let request = bundle_request(&root, matrix_evidence_source(&root));

    let report = evaluate_f4_live_runtime_evidence_bundle(request);

    assert!(report.passed, "{:#?}", report.failures);
    let matrix = report.matrix.expect("matrix report");
    assert!(!matrix.production_facing_kernel_blocking_supported);
    let kata = matrix
        .runtimes
        .iter()
        .find(|entry| entry.runtime == F4RuntimeGuardrailTarget::Kata)
        .expect("kata row");
    assert!(kata
        .notify
        .evidence_ids
        .contains(&"live-kata-qemu-shim-boundary".to_string()));
}

#[test]
fn f4_live_runtime_evidence_bundle_fails_closed_without_artifact_dir() {
    let root = test_root("f4-live-runtime-evidence-missing-artifacts");
    let request = bundle_request(&root, matrix_evidence_source(&root));

    let report = evaluate_f4_live_runtime_evidence_bundle(request);

    assert!(!report.passed);
    assert!(report.matrix.is_none());
    let failures = failure_text(&report.failures);
    assert!(failures.contains("artifact"));
    assert!(failures.contains("backup-manifest.json"));
}

#[test]
fn f4_live_runtime_evidence_bundle_rejects_visibility_source_mismatch() {
    let root = test_root("f4-live-runtime-evidence-source-mismatch");
    create_matrix_artifacts(&root);
    let request = bundle_request(
        &root,
        "scripts/test-f2-runtime-adapter-matrix.sh artifacts=/tmp/other",
    );

    let report = evaluate_f4_live_runtime_evidence_bundle(request);

    assert!(!report.passed);
    assert!(report.matrix.is_none());
    assert!(failure_text(&report.failures).contains("visibility evidence source"));
}

fn bundle_request(
    artifact_dir: &Path,
    evidence_source: impl Into<String>,
) -> F4LiveRuntimeEvidenceBundleRequest {
    F4LiveRuntimeEvidenceBundleRequest {
        artifact_dir: artifact_dir.to_path_buf(),
        visibility_reports: visibility_reports(evidence_source.into()),
        block_validation_reports: fixture_value("block_validation_reports"),
        runtime_adapter_evidence_reports: fixture_value("runtime_adapter_evidence_reports"),
        gvisor_metadata_evidence_reports: fixture_value("gvisor_metadata_evidence_reports"),
        kubernetes_agent_sandbox_evidence_reports: fixture_value(
            "kubernetes_agent_sandbox_evidence_reports",
        ),
        kata_boundary_evidence_reports: fixture_value("kata_boundary_evidence_reports"),
    }
}

fn visibility_reports(evidence_source: String) -> Vec<VisibilityReport> {
    required_targets()
        .into_iter()
        .map(|(target, scope)| VisibilityReport {
            target,
            live_validated: true,
            evidence_source: evidence_source.clone(),
            host_visibility_scope: scope.to_string(),
            guest_semantics_claimed: false,
        })
        .collect()
}

fn required_targets() -> Vec<(VisibilityTarget, &'static str)> {
    vec![
        (VisibilityTarget::Local, "guest_process"),
        (VisibilityTarget::DockerRunc, "guest_process"),
        (VisibilityTarget::DockerGvisor, "runtime_boundary"),
        (VisibilityTarget::ContainerdRunc, "guest_process"),
        (VisibilityTarget::ContainerdGvisor, "runtime_boundary"),
        (VisibilityTarget::ContainerdKata, "boundary_only"),
        (VisibilityTarget::K3sRunc, "guest_process"),
        (VisibilityTarget::K3sGvisor, "runtime_boundary"),
        (VisibilityTarget::K3sKata, "boundary_only"),
    ]
}

fn fixture_value<T: for<'de> serde::Deserialize<'de>>(key: &str) -> Vec<T> {
    let value: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            workspace_root().join("tests/fixtures/validation/f4-runtime-guardrail-request.json"),
        )
        .expect("read fixture"),
    )
    .expect("parse fixture");
    serde_json::from_value(value.get(key).cloned().expect("fixture key"))
        .expect("parse fixture key")
}

fn create_matrix_artifacts(root: &Path) {
    std::fs::create_dir_all(root).expect("create artifact dir");
    for file in [
        "backup-manifest.json",
        "service-state.json",
        "kubernetes-context.json",
        "restore-plan.json",
        "runtime-registration-report.json",
        "restore-execution-report.json",
    ] {
        std::fs::write(root.join(file), b"{}").expect("write artifact marker");
    }
}

fn matrix_evidence_source(root: &Path) -> String {
    format!(
        "scripts/test-f2-runtime-adapter-matrix.sh artifacts={}",
        root.display()
    )
}

fn failure_text(failures: &[apolysis_validation::F4LiveRuntimeEvidenceBundleFailure]) -> String {
    failures
        .iter()
        .map(|failure| failure.message.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn test_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{name}-{}", std::process::id()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

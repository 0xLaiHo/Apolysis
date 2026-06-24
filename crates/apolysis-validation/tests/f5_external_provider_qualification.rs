// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f5_external_provider_qualification_bundle, F5ExternalProviderQualificationBundle,
    F5ExternalProviderQualificationEntry, F5ExternalProviderQualificationRequirement,
    F5ExternalProviderQualificationSource,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn f5_external_provider_qualification_accepts_bundle_with_r2_and_dockerhub_evidence() {
    let report = evaluate_f5_external_provider_qualification_bundle(qualification_bundle());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("external provider approval");
    assert_eq!(
        approval.bundle_id,
        "f5-external-provider-qualification-20260624"
    );
    assert_eq!(approval.qualified_requirements.len(), 4);
    assert!(approval.providers.contains(&"aws_kms".to_string()));
    assert!(approval
        .providers
        .contains(&"cloudflare_r2_bucket_lock".to_string()));
    assert!(approval.providers.contains(&"docker_hub".to_string()));
    assert!(approval
        .providers
        .contains(&"gke_anthos_service_mesh".to_string()));
}

#[test]
fn f5_external_provider_qualification_accepts_vultr_vke_istio_provider_evidence() {
    let mut bundle = qualification_bundle();
    let managed_mesh = bundle
        .entries
        .iter_mut()
        .find(|entry| {
            entry.requirement == F5ExternalProviderQualificationRequirement::ManagedServiceMesh
        })
        .expect("managed mesh entry");
    managed_mesh.provider = "vultr_vke_istio".to_string();
    managed_mesh.provider_control_plane =
        "vke:vke-a88389c3-f720-412d-9579-c83d3c21eabb:istio".to_string();

    let report = evaluate_f5_external_provider_qualification_bundle(bundle);

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("external provider approval");
    assert!(approval.providers.contains(&"vultr_vke_istio".to_string()));
}

#[test]
fn f5_external_provider_qualification_rejects_local_or_incomplete_bundles() {
    let mut bundle = qualification_bundle();
    bundle.source = F5ExternalProviderQualificationSource::Fixture;
    bundle.operator_approved = false;
    bundle.generated_at_unix_ms = 0;
    bundle.entries = vec![F5ExternalProviderQualificationEntry {
        requirement: F5ExternalProviderQualificationRequirement::CloudKmsOrExternalHsmSigning,
        provider: "softhsm".to_string(),
        provider_control_plane: "local workstation".to_string(),
        evidence_ref: "target/f5-signing-execution/local.json".to_string(),
        evidence_sha256: String::new(),
        report_ref: String::new(),
        report_sha256: String::new(),
        live_provider: false,
        external_provider: false,
        observed_at_unix_ms: 0,
    }];

    let report = evaluate_f5_external_provider_qualification_bundle(bundle);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "external provider qualification bundle evidence is required",
        "operator approval is required",
        "bundle generation timestamp is required",
        "real cloud WORM/object-lock provider qualification is required",
        "real cloud registry promotion/retention qualification is required",
        "managed service-mesh provider qualification is required",
        "live provider evidence is required",
        "external provider evidence is required",
        "provider must be an accepted external provider for this requirement",
        "evidence artifact sha256 is required",
        "report artifact reference is required",
        "report artifact sha256 is required",
        "provider observation timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

#[test]
fn f5_external_provider_qualification_cli_verifies_retained_artifact_files() {
    let root = fresh_temp_dir("f5-external-provider-artifacts-pass");
    let bundle = qualification_bundle_with_retained_artifacts(&root, false);
    let bundle_path = root.join("bundle.json");
    fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&bundle).expect("serialize bundle"),
    )
    .expect("write bundle");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_apolysis-f5-external-provider-qualification"
    ))
    .arg("--bundle")
    .arg(&bundle_path)
    .arg("--bundle-root")
    .arg(&root)
    .output()
    .expect("run external provider qualification CLI");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse CLI report JSON");
    assert_eq!(report["passed"], true);
}

#[test]
fn f5_external_provider_qualification_cli_rejects_missing_or_mismatched_artifacts() {
    let root = fresh_temp_dir("f5-external-provider-artifacts-fail");
    let bundle = qualification_bundle_with_retained_artifacts(&root, true);
    let bundle_path = root.join("bundle.json");
    fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&bundle).expect("serialize bundle"),
    )
    .expect("write bundle");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_apolysis-f5-external-provider-qualification"
    ))
    .arg("--bundle")
    .arg(&bundle_path)
    .arg("--bundle-root")
    .arg(&root)
    .output()
    .expect("run external provider qualification CLI");

    assert!(!output.status.success(), "CLI unexpectedly passed");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse CLI report JSON");
    assert_eq!(report["passed"], false);
    let failure_text = serde_json::to_string(&report["failures"]).expect("serialize failures");
    assert!(
        failure_text.contains("retained evidence artifact sha256 does not match"),
        "{failure_text}"
    );
}

#[cfg(unix)]
#[test]
fn f5_external_provider_qualification_cli_rejects_artifacts_that_escape_bundle_root() {
    use std::os::unix::fs::symlink;

    let root = fresh_temp_dir("f5-external-provider-artifacts-escape");
    let outside = fresh_temp_dir("f5-external-provider-artifacts-outside");
    let mut bundle = qualification_bundle_with_retained_artifacts(&root, false);
    let escaped_bytes = b"{\"provider\":\"aws_kms\",\"kind\":\"escaped\"}\n";
    let escaped_target = outside.join("escaped-evidence.json");
    fs::write(&escaped_target, escaped_bytes).expect("write escaped target");
    let escaped_link = root.join(&bundle.entries[0].evidence_ref);
    fs::remove_file(&escaped_link).expect("remove original evidence artifact");
    symlink(&escaped_target, &escaped_link).expect("symlink escaped evidence artifact");
    bundle.entries[0].evidence_sha256 = format!("sha256:{}", sha256_hex(escaped_bytes));

    let bundle_path = root.join("bundle.json");
    fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&bundle).expect("serialize bundle"),
    )
    .expect("write bundle");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_apolysis-f5-external-provider-qualification"
    ))
    .arg("--bundle")
    .arg(&bundle_path)
    .arg("--bundle-root")
    .arg(&root)
    .output()
    .expect("run external provider qualification CLI");

    assert!(!output.status.success(), "CLI unexpectedly passed");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse CLI report JSON");
    assert_eq!(report["passed"], false);
    let failure_text = serde_json::to_string(&report["failures"]).expect("serialize failures");
    assert!(
        failure_text.contains("retained evidence artifact reference must stay under bundle root"),
        "{failure_text}"
    );
}

fn qualification_bundle() -> F5ExternalProviderQualificationBundle {
    F5ExternalProviderQualificationBundle {
        bundle_id: "f5-external-provider-qualification-20260624".to_string(),
        source: F5ExternalProviderQualificationSource::EvidenceBundle,
        operator_approved: true,
        generated_at_unix_ms: 1_782_259_200_000,
        entries: vec![
            qualification_entry(
                F5ExternalProviderQualificationRequirement::CloudKmsOrExternalHsmSigning,
                "aws_kms",
                "aws-kms:us-west-2:alias/apolysis-f5-release",
            ),
            qualification_entry(
                F5ExternalProviderQualificationRequirement::CloudWormObjectLockArchive,
                "cloudflare_r2_bucket_lock",
                "cloudflare-r2:e85b6fa3634dc882cfbd2188361fb37e:apolysis-f5-worm-1782254413912",
            ),
            qualification_entry(
                F5ExternalProviderQualificationRequirement::CloudRegistryPromotionRetention,
                "docker_hub",
                "docker-hub:devlaiho:apolysis-f5-registry",
            ),
            qualification_entry(
                F5ExternalProviderQualificationRequirement::ManagedServiceMesh,
                "gke_anthos_service_mesh",
                "gke:prod-us-central1:anthos-service-mesh",
            ),
        ],
    }
}

fn qualification_bundle_with_retained_artifacts(
    root: &Path,
    corrupt_first_evidence_digest: bool,
) -> F5ExternalProviderQualificationBundle {
    let mut bundle = qualification_bundle();
    for entry in &mut bundle.entries {
        let safe_provider = entry.provider.replace([':', '/'], "_");
        entry.evidence_ref = format!("evidence/{safe_provider}.json");
        entry.report_ref = format!("reports/{safe_provider}.json");
        let evidence_body = format!(
            "{{\"provider\":\"{}\",\"kind\":\"evidence\"}}\n",
            entry.provider
        );
        let report_body = format!("{{\"provider\":\"{}\",\"passed\":true}}\n", entry.provider);
        write_retained_artifact(root, &entry.evidence_ref, evidence_body.as_bytes());
        write_retained_artifact(root, &entry.report_ref, report_body.as_bytes());
        entry.evidence_sha256 = format!("sha256:{}", sha256_hex(evidence_body.as_bytes()));
        entry.report_sha256 = format!("sha256:{}", sha256_hex(report_body.as_bytes()));
    }
    if corrupt_first_evidence_digest {
        bundle.entries[0].evidence_sha256 =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    }
    bundle
}

fn qualification_entry(
    requirement: F5ExternalProviderQualificationRequirement,
    provider: &str,
    provider_control_plane: &str,
) -> F5ExternalProviderQualificationEntry {
    F5ExternalProviderQualificationEntry {
        requirement,
        provider: provider.to_string(),
        provider_control_plane: provider_control_plane.to_string(),
        evidence_ref: format!("evidence/{provider}.json"),
        evidence_sha256: format!("sha256:{}", "a".repeat(64)),
        report_ref: format!("reports/{provider}.json"),
        report_sha256: format!("sha256:{}", "b".repeat(64)),
        live_provider: true,
        external_provider: true,
        observed_at_unix_ms: 1_782_259_200_000,
    }
}

fn write_retained_artifact(root: &Path, relative_path: &str, bytes: &[u8]) {
    let path = root.join(relative_path);
    fs::create_dir_all(path.parent().expect("artifact parent")).expect("create artifact parent");
    fs::write(path, bytes).expect("write retained artifact");
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fresh_temp_dir(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "apolysis-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create temp dir");
    root
}

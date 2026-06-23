// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f5_external_provider_qualification_bundle, F5ExternalProviderQualificationBundle,
    F5ExternalProviderQualificationEntry, F5ExternalProviderQualificationRequirement,
    F5ExternalProviderQualificationSource,
};

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

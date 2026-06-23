// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f5_registry_promotion_execution_evidence, F5RegistryPromotionExecutionEvidence,
    F5RegistryPromotionExecutionProvider, F5RegistryPromotionExecutionSource,
};

const IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[test]
fn f5_registry_promotion_execution_accepts_live_digest_locked_registry_promotion() {
    let report =
        evaluate_f5_registry_promotion_execution_evidence(registry_promotion_execution_evidence());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("registry promotion approval");
    assert_eq!(
        approval.provider,
        F5RegistryPromotionExecutionProvider::OciDistributionRegistry
    );
    assert_eq!(approval.repository, "apolysisd");
    assert_eq!(approval.source_tag, "staging-20260624");
    assert_eq!(approval.target_tag, "prod-20260624");
    assert_eq!(approval.rollback_tag, "prod-previous");
    assert_eq!(approval.image_digest, IMAGE_DIGEST);
    assert_eq!(approval.retention_days, 180);
}

#[test]
fn f5_registry_promotion_execution_rejects_fixture_or_mutable_promotion() {
    let mut evidence = registry_promotion_execution_evidence();
    evidence.source = F5RegistryPromotionExecutionSource::Fixture;
    evidence.provider = F5RegistryPromotionExecutionProvider::LocalFilesystem;
    evidence.registry_uri = "file:///tmp/registry".to_string();
    evidence.repository.clear();
    evidence.source_tag.clear();
    evidence.target_tag = "latest".to_string();
    evidence.rollback_tag.clear();
    evidence.image_digest = "sha256:not-a-digest".to_string();
    evidence.promoted_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    evidence.production_tag_digest =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
    evidence.rollback_tag_digest.clear();
    evidence.manifest_media_type.clear();
    evidence.staging_manifest_verified = false;
    evidence.production_manifest_verified = false;
    evidence.rollback_manifest_verified = false;
    evidence.digest_promotion_performed = false;
    evidence.digest_pulls_verified = false;
    evidence.production_delete_without_retention_denied = false;
    evidence.retention_days = 14;
    evidence.retain_until_unix_ms = evidence.observed_at_unix_ms + 14 * DAY_MS;
    evidence.promotion_approved = false;
    evidence.api_tool.clear();
    evidence.observed_at_unix_ms = 0;

    let report = evaluate_f5_registry_promotion_execution_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live registry promotion execution evidence is required",
        "registry promotion execution requires an OCI registry provider",
        "registry URI must be provider-backed",
        "repository is required",
        "source tag is required",
        "target tag must be immutable and start with prod-",
        "rollback tag is required",
        "image digest must be a sha256 digest",
        "promoted digest must match image digest",
        "production tag digest must match image digest",
        "rollback tag digest is required",
        "manifest media type is required",
        "staging manifest must be verified through the registry API",
        "production manifest must be verified through the registry API",
        "rollback manifest must be verified through the registry API",
        "promotion must be performed by digest through the registry API",
        "digest pulls must be verified through the registry API",
        "production delete without retention bypass must be denied by the registry API",
        "minimum production retention is 90 days",
        "operator approval is required",
        "API tool evidence is required",
        "live observation timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn registry_promotion_execution_evidence() -> F5RegistryPromotionExecutionEvidence {
    let observed_at = 1_782_259_200_000;
    F5RegistryPromotionExecutionEvidence {
        evidence_id: "f5-registry-promotion-execution-20260624".to_string(),
        source: F5RegistryPromotionExecutionSource::LiveProvider,
        provider: F5RegistryPromotionExecutionProvider::OciDistributionRegistry,
        registry_uri: "http://127.0.0.1:5000".to_string(),
        repository: "apolysisd".to_string(),
        source_tag: "staging-20260624".to_string(),
        target_tag: "prod-20260624".to_string(),
        rollback_tag: "prod-previous".to_string(),
        image_digest: IMAGE_DIGEST.to_string(),
        promoted_digest: IMAGE_DIGEST.to_string(),
        production_tag_digest: IMAGE_DIGEST.to_string(),
        rollback_tag_digest: IMAGE_DIGEST.to_string(),
        manifest_media_type: "application/vnd.docker.distribution.manifest.v2+json".to_string(),
        staging_manifest_verified: true,
        production_manifest_verified: true,
        rollback_manifest_verified: true,
        digest_promotion_performed: true,
        digest_pulls_verified: true,
        production_delete_without_retention_denied: true,
        retention_days: 180,
        retain_until_unix_ms: observed_at + 180 * DAY_MS,
        promotion_approved: true,
        api_tool: "curl Docker Registry HTTP API V2".to_string(),
        observed_at_unix_ms: observed_at,
    }
}

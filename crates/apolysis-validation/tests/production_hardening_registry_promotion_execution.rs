// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_registry_promotion_execution_evidence,
    ProductionHardeningRegistryPromotionExecutionEvidence,
    ProductionHardeningRegistryPromotionExecutionProvider,
    ProductionHardeningRegistryPromotionExecutionSource,
};

const IMAGE_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[test]
fn production_hardening_registry_promotion_execution_accepts_live_digest_locked_registry_promotion()
{
    let report = evaluate_production_hardening_registry_promotion_execution_evidence(
        registry_promotion_execution_evidence(),
    );

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("registry promotion approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningRegistryPromotionExecutionProvider::OciDistributionRegistry
    );
    assert_eq!(approval.repository, "apolysisd");
    assert_eq!(approval.source_tag, "staging-20260624");
    assert_eq!(approval.target_tag, "prod-20260624");
    assert_eq!(approval.rollback_tag, "prod-previous");
    assert_eq!(approval.image_digest, IMAGE_DIGEST);
    assert_eq!(approval.retention_days, 180);
}

#[test]
fn production_hardening_registry_promotion_execution_accepts_live_docker_hub_immutable_tag_evidence(
) {
    let mut evidence = registry_promotion_execution_evidence();
    evidence.evidence_id =
        "production-hardening-docker-hub-registry-promotion-20260624".to_string();
    evidence.provider = ProductionHardeningRegistryPromotionExecutionProvider::DockerHub;
    evidence.registry_uri =
        "https://index.docker.io/v2/devlaiho/apolysis-production-hardening-registry".to_string();
    evidence.repository = "devlaiho/apolysis-production-hardening-registry".to_string();
    evidence.source_tag = "staging-production-hardening-20260624".to_string();
    evidence.target_tag = "prod-production-hardening-20260624".to_string();
    evidence.rollback_tag = "rollback-production-hardening-20260624".to_string();
    evidence.api_tool = "docker push plus Docker Hub immutable tags API".to_string();

    let report = evaluate_production_hardening_registry_promotion_execution_evidence(evidence);

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("Docker Hub registry approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningRegistryPromotionExecutionProvider::DockerHub
    );
    assert_eq!(
        approval.repository,
        "devlaiho/apolysis-production-hardening-registry"
    );
    assert_eq!(approval.target_tag, "prod-production-hardening-20260624");
}

#[test]
fn production_hardening_registry_promotion_execution_rejects_fixture_or_mutable_promotion() {
    let mut evidence = registry_promotion_execution_evidence();
    evidence.source = ProductionHardeningRegistryPromotionExecutionSource::Fixture;
    evidence.provider = ProductionHardeningRegistryPromotionExecutionProvider::LocalFilesystem;
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

    let report = evaluate_production_hardening_registry_promotion_execution_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live registry promotion execution evidence is required",
        "registry promotion execution requires a provider-backed OCI registry",
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

fn registry_promotion_execution_evidence() -> ProductionHardeningRegistryPromotionExecutionEvidence
{
    let observed_at = 1_782_259_200_000;
    ProductionHardeningRegistryPromotionExecutionEvidence {
        evidence_id: "production-hardening-registry-promotion-execution-20260624".to_string(),
        source: ProductionHardeningRegistryPromotionExecutionSource::LiveProvider,
        provider: ProductionHardeningRegistryPromotionExecutionProvider::OciDistributionRegistry,
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

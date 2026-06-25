// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_worm_archive_execution_evidence,
    ProductionHardeningWormArchiveExecutionEvidence, ProductionHardeningWormArchiveExecutionSource,
    ProductionHardeningWormProvider, ProductionHardeningWormRetentionMode,
};

const RELEASE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OBJECT_SHA: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[test]
fn production_hardening_worm_archive_execution_accepts_live_s3_object_lock_api_evidence() {
    let report = evaluate_production_hardening_worm_archive_execution_evidence(
        worm_api_execution_evidence(),
    );

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("WORM archive execution approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningWormProvider::S3ObjectLock
    );
    assert_eq!(approval.bucket_uri, "s3://apolysis-prod-release-archive");
    assert_eq!(
        approval.object_key,
        "releases/apolysis/production-hardening-release-manifest.json"
    );
    assert_eq!(
        approval.object_version_id,
        "production-hardening-version-0001"
    );
    assert_eq!(
        approval.retention_mode,
        ProductionHardeningWormRetentionMode::Compliance
    );
    assert_eq!(approval.retention_days, 365);
    assert_eq!(approval.object_sha256, OBJECT_SHA);
}

#[test]
fn production_hardening_worm_archive_execution_accepts_live_cloudflare_r2_bucket_lock_evidence() {
    let mut evidence = worm_api_execution_evidence();
    evidence.evidence_id = "production-hardening-cloudflare-r2-bucket-lock-20260624".to_string();
    evidence.provider = ProductionHardeningWormProvider::CloudflareR2BucketLock;
    evidence.endpoint_uri = "cloudflare-r2://e85b6fa3634dc882cfbd2188361fb37e".to_string();
    evidence.bucket_uri = "cloudflare-r2://apolysis-production-hardening-worm-20260624".to_string();
    evidence.object_key =
        "releases/apolysis/production_hardening.22/release-manifest.json".to_string();
    evidence.object_version_id = "cloudflare-r2-etag-0001".to_string();
    evidence.audit_log_ref = "cloudflare-r2://apolysis-production-hardening-worm-20260624/.audit/production_hardening.22".to_string();
    evidence.api_tool = "cloudflare-api r2 bucket locks".to_string();
    evidence.versioning_enabled = false;
    evidence.legal_hold_applied = false;

    let report = evaluate_production_hardening_worm_archive_execution_evidence(evidence);

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report
        .approval
        .expect("Cloudflare R2 WORM archive execution approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningWormProvider::CloudflareR2BucketLock
    );
    assert_eq!(
        approval.bucket_uri,
        "cloudflare-r2://apolysis-production-hardening-worm-20260624"
    );
    assert_eq!(
        approval.object_key,
        "releases/apolysis/production_hardening.22/release-manifest.json"
    );
}

#[test]
fn production_hardening_worm_archive_execution_rejects_fixture_or_mutable_api_evidence() {
    let mut evidence = worm_api_execution_evidence();
    evidence.source = ProductionHardeningWormArchiveExecutionSource::Fixture;
    evidence.provider = ProductionHardeningWormProvider::LocalFilesystem;
    evidence.endpoint_uri = "file:///tmp/apolysis-archive".to_string();
    evidence.bucket_uri = "/tmp/apolysis-archive".to_string();
    evidence.object_key = "../release-manifest.json".to_string();
    evidence.object_version_id.clear();
    evidence.object_sha256 = "not-a-sha".to_string();
    evidence.retention_mode = ProductionHardeningWormRetentionMode::Governance;
    evidence.retention_days = 30;
    evidence.retain_until_unix_ms = evidence.observed_at_unix_ms + 30 * DAY_MS;
    evidence.object_lock_enabled = false;
    evidence.versioning_enabled = false;
    evidence.put_object_succeeded = false;
    evidence.retention_applied = false;
    evidence.legal_hold_applied = false;
    evidence.head_object_verified = false;
    evidence.delete_without_bypass_denied = false;
    evidence.audit_log_ref.clear();
    evidence.operator_approved = false;
    evidence.api_tool.clear();
    evidence.observed_at_unix_ms = 0;

    let report = evaluate_production_hardening_worm_archive_execution_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live WORM archive API execution evidence is required",
        "WORM archive execution requires S3 Object Lock, GCS Bucket Lock, Azure Immutable Blob, or Cloudflare R2 Bucket Lock",
        "archive endpoint must be provider-backed object storage",
        "archive bucket URI must be provider-backed object storage",
        "object key must be a bounded relative object key",
        "object version id is required",
        "object sha256 must be 64 hex characters",
        "retention mode must be compliance",
        "minimum WORM retention is 180 days",
        "object lock must be enabled by the provider",
        "object versioning must be enabled by the provider",
        "archive object write must succeed through the provider API",
        "retention must be applied through the provider API",
        "legal hold must be applied through the provider API",
        "retained object metadata must be verified through the provider API",
        "delete without bypass must be denied by the provider API",
        "audit log reference is required",
        "operator approval is required",
        "API tool evidence is required",
        "live observation timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn worm_api_execution_evidence() -> ProductionHardeningWormArchiveExecutionEvidence {
    let observed_at = 1_782_259_200_000;
    ProductionHardeningWormArchiveExecutionEvidence {
        evidence_id: "production-hardening-worm-api-execution-20260624".to_string(),
        source: ProductionHardeningWormArchiveExecutionSource::LiveProvider,
        provider: ProductionHardeningWormProvider::S3ObjectLock,
        endpoint_uri: "s3://minio.apolysis.local".to_string(),
        bucket_uri: "s3://apolysis-prod-release-archive".to_string(),
        object_key: "releases/apolysis/production-hardening-release-manifest.json".to_string(),
        object_version_id: "production-hardening-version-0001".to_string(),
        release_manifest_sha256: RELEASE_SHA.to_string(),
        object_sha256: OBJECT_SHA.to_string(),
        observed_at_unix_ms: observed_at,
        retention_days: 365,
        retain_until_unix_ms: observed_at + 365 * DAY_MS,
        retention_mode: ProductionHardeningWormRetentionMode::Compliance,
        object_lock_enabled: true,
        versioning_enabled: true,
        put_object_succeeded: true,
        retention_applied: true,
        legal_hold_applied: true,
        head_object_verified: true,
        delete_without_bypass_denied: true,
        audit_log_ref:
            "s3://apolysis-prod-release-archive/.audit/production-hardening-worm-api-execution"
                .to_string(),
        operator_approved: true,
        api_tool: "mc RELEASE.2025-05-21T01-59-54Z".to_string(),
    }
}

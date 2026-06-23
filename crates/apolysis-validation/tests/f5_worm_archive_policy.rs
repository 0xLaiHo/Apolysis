// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f5_worm_archive_policy, F5WormArchivePolicy, F5WormProvider, F5WormRetentionMode,
};

const RELEASE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[test]
fn f5_worm_archive_policy_accepts_external_object_lock_compliance_archive() {
    let report = evaluate_f5_worm_archive_policy(s3_object_lock_policy());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("archive approval");
    assert_eq!(approval.provider, F5WormProvider::S3ObjectLock);
    assert_eq!(approval.bucket_uri, "s3://apolysis-prod-release-archive");
    assert_eq!(approval.retention_days, 365);
    assert_eq!(approval.release_manifest_sha256, RELEASE_SHA);
}

#[test]
fn f5_worm_archive_policy_rejects_mutable_or_underprotected_archive() {
    let mut policy = s3_object_lock_policy();
    policy.provider = F5WormProvider::LocalFilesystem;
    policy.bucket_uri = "/var/lib/apolysis/archive".to_string();
    policy.object_prefix = "tmp".to_string();
    policy.object_lock_enabled = false;
    policy.versioning_enabled = false;
    policy.retention_mode = F5WormRetentionMode::Governance;
    policy.retention_days = 30;
    policy.retain_until_unix_ms = policy.requested_at_unix_ms + 30 * DAY_MS;
    policy.legal_hold_supported = false;
    policy.delete_protection_enabled = false;
    policy.audit_log_ref.clear();
    policy.operator_approved = false;
    policy.allowed_writer_principals = vec!["*".to_string()];
    policy.allowed_reader_principals = vec!["system:anonymous".to_string()];
    policy.deny_delete_principals.clear();
    policy.replication_target_uri.clear();

    let report = evaluate_f5_worm_archive_policy(policy);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "external WORM archive requires S3 Object Lock, GCS Bucket Lock, or Azure Immutable Blob",
        "production archive URI must be provider-backed object storage",
        "object lock must be enabled",
        "object versioning must be enabled",
        "retention mode must be compliance",
        "minimum WORM retention is 180 days",
        "legal hold support is required",
        "delete protection must be enabled",
        "audit log reference is required",
        "operator approval is required",
        "wildcard writer principals are forbidden",
        "anonymous reader principals are forbidden",
        "delete-deny principals are required",
        "replication target URI is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn s3_object_lock_policy() -> F5WormArchivePolicy {
    let requested_at = 1_782_259_200_000;
    F5WormArchivePolicy {
        policy_id: "f5-prod-worm-archive".to_string(),
        provider: F5WormProvider::S3ObjectLock,
        bucket_uri: "s3://apolysis-prod-release-archive".to_string(),
        object_prefix: "releases/apolysis".to_string(),
        release_manifest_sha256: RELEASE_SHA.to_string(),
        requested_at_unix_ms: requested_at,
        retention_days: 365,
        retain_until_unix_ms: requested_at + 365 * DAY_MS,
        retention_mode: F5WormRetentionMode::Compliance,
        object_lock_enabled: true,
        versioning_enabled: true,
        legal_hold_supported: true,
        delete_protection_enabled: true,
        audit_log_ref: "cloudtrail://apolysis-prod-release-archive".to_string(),
        operator_approved: true,
        allowed_writer_principals: vec!["ci:release-archiver".to_string()],
        allowed_reader_principals: vec!["cluster:prod-apolysis-readers".to_string()],
        deny_delete_principals: vec!["*".to_string()],
        replication_target_uri: "s3://apolysis-prod-release-archive-dr".to_string(),
    }
}

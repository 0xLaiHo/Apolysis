// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f5_release_promotion_policy, F5ReleasePromotionChannel,
    F5ReleasePromotionPolicyEvidence, F5ReleasePromotionRequest,
};
use serde_json::{json, Value};

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SBOM_DIGEST: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const RELEASE_SHA: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REGISTRY_SHA: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

#[test]
fn f5_release_promotion_policy_approves_digest_locked_production_release() {
    let report = evaluate_f5_release_promotion_policy(promotion_request(), promotion_evidence());

    assert!(report.passed, "{:#?}", report.failures);
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    let approval = report.approval.expect("promotion approval");
    assert_eq!(approval.channel, F5ReleasePromotionChannel::Production);
    assert_eq!(approval.target_tag, "prod-2026-06-24");
    assert_eq!(approval.image_digest, DIGEST);
    assert_eq!(approval.retention_days, 180);
    assert_eq!(
        approval.allowed_pull_principals,
        vec!["cluster:prod-apolysis-readers"]
    );
}

#[test]
fn f5_release_promotion_policy_rejects_mutable_or_underprotected_release() {
    let mut request = promotion_request();
    request.target_tag = "latest".to_string();
    request.image_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    request.retention_days = 14;
    request.retain_until_unix_ms = request.requested_at_unix_ms + 14 * DAY_MS;
    request.promotion_approved = false;
    request.require_digest_pulls = false;
    request.allow_anonymous_pull = true;
    request.allowed_pull_principals = vec!["*".to_string()];
    request.allowed_push_principals = vec!["system:anonymous".to_string()];
    request.rollback_tag.clear();

    let mut evidence = promotion_evidence();
    evidence.release_manifest["signing"]["keyMode"] = json!("ephemeral-local-validation");
    evidence.archive_manifest["immutability"]["mutationProbe"] = json!("allowed");

    let report = evaluate_f5_release_promotion_policy(request, evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "external or KMS/HSM-backed signing is required",
        "target tag must be immutable",
        "image digest does not match registry attachment",
        "minimum production retention is 90 days",
        "operator approval is required",
        "digest-only pulls are required",
        "anonymous registry pull access is forbidden",
        "wildcard pull principals are forbidden",
        "anonymous push principals are forbidden",
        "rollback tag is required",
        "archive mutation probe must be denied",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn promotion_request() -> F5ReleasePromotionRequest {
    F5ReleasePromotionRequest {
        promotion_id: "promote-apolysisd-2026-06-24".to_string(),
        channel: F5ReleasePromotionChannel::Production,
        source_tag: "f5-registry-20260624".to_string(),
        target_tag: "prod-2026-06-24".to_string(),
        image_digest: DIGEST.to_string(),
        sbom_attachment_digest: SBOM_DIGEST.to_string(),
        release_manifest_sha256: RELEASE_SHA.to_string(),
        retention_days: 180,
        requested_at_unix_ms: 1_782_259_200_000,
        retain_until_unix_ms: 1_782_259_200_000 + 180 * DAY_MS,
        promotion_approved: true,
        require_digest_pulls: true,
        allow_anonymous_pull: false,
        allowed_pull_principals: vec!["cluster:prod-apolysis-readers".to_string()],
        allowed_push_principals: vec!["ci:release-promoter".to_string()],
        rollback_tag: "prod-previous".to_string(),
    }
}

fn promotion_evidence() -> F5ReleasePromotionPolicyEvidence {
    F5ReleasePromotionPolicyEvidence {
        release_manifest_sha256: RELEASE_SHA.to_string(),
        registry_attachment_sha256: REGISTRY_SHA.to_string(),
        release_manifest: release_manifest(),
        registry_attachment: registry_attachment(),
        archive_manifest: archive_manifest(),
    }
}

fn release_manifest() -> Value {
    json!({
        "schema": "apolysis.dev/f5-release-manifest/v1",
        "phase": "F5.6",
        "signing": {
            "keyMode": "external",
            "publicKey": "apolysis-f5-release.pub",
            "manifestBundle": "apolysis-f5-release-manifest.sigstore.json",
            "provenanceBundle": "apolysis-f5-provenance.sigstore.json"
        },
        "files": [
            {"path": "apolysis-f5-release-payload.tar.gz", "sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 1},
            {"path": "apolysis-f5-apolysisd-image.tar", "sha256": "4444444444444444444444444444444444444444444444444444444444444444", "size": 1},
            {"path": "apolysis-f5-sbom.cdx.json", "sha256": "5555555555555555555555555555555555555555555555555555555555555555", "size": 1},
            {"path": "apolysis-f5-provenance.intoto.json", "sha256": "6666666666666666666666666666666666666666666666666666666666666666", "size": 1}
        ]
    })
}

fn registry_attachment() -> Value {
    json!({
        "schema": "apolysis.dev/f5-registry-attachment/v1",
        "phase": "F5.8",
        "registry": {
            "implementation": "registry:2",
            "repository": "apolysisd",
            "tag": "f5-registry-20260624",
            "imageDigest": DIGEST,
            "sbomAttachmentTag": "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.sbom",
            "sbomAttachmentDigest": SBOM_DIGEST
        },
        "releaseArtifacts": {
            "manifest": {
                "path": "release-bundle/apolysis-f5-release-manifest.json",
                "sha256": RELEASE_SHA
            },
            "provenance": {
                "path": "release-bundle/apolysis-f5-provenance.intoto.json",
                "sha256": "6666666666666666666666666666666666666666666666666666666666666666"
            },
            "sbom": {
                "path": "release-bundle/apolysis-f5-sbom.cdx.json",
                "sha256": "5555555555555555555555555555555555555555555555555555555555555555"
            }
        },
        "registryObservedState": {
            "tagsAfterSbom": {
                "tags": [
                    "f5-registry-20260624",
                    "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.sbom"
                ]
            }
        }
    })
}

fn archive_manifest() -> Value {
    json!({
        "schema": "apolysis.dev/f5-immutable-archive-manifest/v1",
        "phase": "F5.8",
        "archive": {
            "mode": "content-addressed-read-only-local",
            "object": "objects/sha256-1111111111111111111111111111111111111111111111111111111111111111",
            "releaseManifestSha256": RELEASE_SHA,
            "registryAttachmentSha256": REGISTRY_SHA
        },
        "immutability": {
            "directoryMode": "0555",
            "fileMode": "0444",
            "mutationProbe": "denied"
        },
        "artifacts": [
            {"path": "apolysis-f5-release-manifest.json", "sha256": RELEASE_SHA, "size": 1, "mode": "0444"},
            {"path": "apolysis-f5-registry-attachment.json", "sha256": REGISTRY_SHA, "size": 1, "mode": "0444"},
            {"path": "apolysis-f5-apolysisd-image.tar", "sha256": "4444444444444444444444444444444444444444444444444444444444444444", "size": 1, "mode": "0444"}
        ]
    })
}

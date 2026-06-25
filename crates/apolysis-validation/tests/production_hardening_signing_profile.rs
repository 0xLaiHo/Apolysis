// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_signing_profile, ProductionHardeningSigningKeyProvider,
    ProductionHardeningSigningProfile, ProductionHardeningSigningReleaseChannel,
};

#[test]
fn production_hardening_signing_profile_accepts_kms_or_hsm_production_signers() {
    let kms = evaluate_production_hardening_signing_profile(kms_profile());
    assert!(kms.passed, "{:#?}", kms.failures);
    let approval = kms.approval.expect("kms approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningSigningKeyProvider::Kms
    );
    assert_eq!(
        approval.key_uri,
        "awskms://alias/apolysis-production-hardening-release"
    );
    assert_eq!(approval.max_rotation_period_days, 90);

    let mut hsm = kms_profile();
    hsm.profile_id = "production-hardening-hsm-release-signer".to_string();
    hsm.provider = ProductionHardeningSigningKeyProvider::Hsm;
    hsm.key_uri =
        "pkcs11:token=apolysis;object=production-hardening-release;type=private".to_string();
    let report = evaluate_production_hardening_signing_profile(hsm);
    assert!(report.passed, "{:#?}", report.failures);
}

#[test]
fn production_hardening_signing_profile_rejects_exportable_or_local_production_signers() {
    let mut profile = kms_profile();
    profile.provider = ProductionHardeningSigningKeyProvider::LocalFile;
    profile.key_uri = "/var/lib/apolysis/release.key".to_string();
    profile.non_exportable = false;
    profile.hardware_or_service_backed = false;
    profile.operator_approved = false;
    profile.public_key_ref.clear();
    profile.certificate_chain_ref.clear();
    profile.attestation_ref.clear();
    profile.rotation_period_days = 365;
    profile.allowed_release_channels = vec![ProductionHardeningSigningReleaseChannel::Staging];

    let report = evaluate_production_hardening_signing_profile(profile);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "production release signing requires KMS or HSM provider",
        "production signing key must be non-exportable",
        "production signing key must be hardware-backed or managed by a KMS service",
        "operator approval is required",
        "public key reference is required",
        "certificate chain or verification bundle reference is required",
        "attestation or key policy evidence is required",
        "rotation period must be 180 days or less",
        "production release channel must be allowed",
        "file paths are not valid production signing key URIs",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn kms_profile() -> ProductionHardeningSigningProfile {
    ProductionHardeningSigningProfile {
        profile_id: "production-hardening-kms-release-signer".to_string(),
        provider: ProductionHardeningSigningKeyProvider::Kms,
        key_uri: "awskms://alias/apolysis-production-hardening-release".to_string(),
        public_key_ref: "kms://alias/apolysis-production-hardening-release/public-key".to_string(),
        certificate_chain_ref: "kms://alias/apolysis-production-hardening-release/cert-chain"
            .to_string(),
        attestation_ref: "kms://alias/apolysis-production-hardening-release/key-policy".to_string(),
        non_exportable: true,
        hardware_or_service_backed: true,
        operator_approved: true,
        rotation_period_days: 90,
        allowed_release_channels: vec![
            ProductionHardeningSigningReleaseChannel::Staging,
            ProductionHardeningSigningReleaseChannel::Production,
        ],
    }
}

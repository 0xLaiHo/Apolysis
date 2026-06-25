// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_signing_execution_evidence,
    ProductionHardeningSigningExecutionAlgorithm, ProductionHardeningSigningExecutionEvidence,
    ProductionHardeningSigningExecutionProvider, ProductionHardeningSigningExecutionSource,
};

#[test]
fn production_hardening_signing_execution_evidence_accepts_live_pkcs11_hsm_signature() {
    let report =
        evaluate_production_hardening_signing_execution_evidence(pkcs11_execution_evidence());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("signing execution approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningSigningExecutionProvider::Pkcs11Hsm
    );
    assert_eq!(
        approval.algorithm,
        ProductionHardeningSigningExecutionAlgorithm::RsaPkcs1Sha256
    );
    assert_eq!(
        approval.key_uri,
        "pkcs11:token=apolysis-production-hardening-release;object=production-hardening-release;type=private"
    );
    assert_eq!(approval.release_manifest_sha256, "1".repeat(64));
    assert_eq!(approval.signature_sha256, "2".repeat(64));
}

#[test]
fn production_hardening_signing_execution_evidence_accepts_live_external_hsm_signature() {
    let mut evidence = pkcs11_execution_evidence();
    evidence.provider = ProductionHardeningSigningExecutionProvider::ExternalHsm;

    let report = evaluate_production_hardening_signing_execution_evidence(evidence);

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("signing execution approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningSigningExecutionProvider::ExternalHsm
    );
    assert_eq!(
        approval.key_uri,
        "pkcs11:token=apolysis-production-hardening-release;object=production-hardening-release;type=private"
    );
}

#[test]
fn production_hardening_signing_execution_evidence_rejects_fixture_or_exportable_signing() {
    let mut evidence = pkcs11_execution_evidence();
    evidence.source = ProductionHardeningSigningExecutionSource::Fixture;
    evidence.provider = ProductionHardeningSigningExecutionProvider::LocalFile;
    evidence.key_uri = "/tmp/apolysis-release.key".to_string();
    evidence.token_label.clear();
    evidence.key_label.clear();
    evidence.key_id.clear();
    evidence.release_manifest_sha256 = "not-a-sha".to_string();
    evidence.signature_sha256 = "also-not-a-sha".to_string();
    evidence.public_key_sha256.clear();
    evidence.signature_verified = false;
    evidence.private_key_non_extractable = false;
    evidence.private_key_sensitive = false;
    evidence.key_generated_in_provider = false;
    evidence.token_initialized = false;
    evidence.operator_approved = false;
    evidence.cleanup_confirmed = false;
    evidence.observed_at_unix_ms = 0;

    let report = evaluate_production_hardening_signing_execution_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live provider signing evidence is required",
        "signing execution requires PKCS#11 HSM, external HSM, or cloud KMS provider",
        "file paths are not valid production signing key URIs",
        "token label is required",
        "key label is required",
        "key id is required",
        "release manifest sha256 must be 64 hex characters",
        "signature sha256 must be 64 hex characters",
        "public key sha256 must be 64 hex characters",
        "signature verification evidence is required",
        "private key must be non-extractable",
        "private key must be sensitive",
        "key must be generated inside the signing provider",
        "token initialization evidence is required",
        "operator approval is required",
        "cleanup confirmation is required",
        "observed timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn pkcs11_execution_evidence() -> ProductionHardeningSigningExecutionEvidence {
    ProductionHardeningSigningExecutionEvidence {
        evidence_id: "production-hardening-pkcs11-signing-execution-20260624".to_string(),
        source: ProductionHardeningSigningExecutionSource::LiveProvider,
        provider: ProductionHardeningSigningExecutionProvider::Pkcs11Hsm,
        key_uri: "pkcs11:token=apolysis-production-hardening-release;object=production-hardening-release;type=private".to_string(),
        token_label: "apolysis-production-hardening-release".to_string(),
        key_label: "production-hardening-release".to_string(),
        key_id: "01".to_string(),
        algorithm: ProductionHardeningSigningExecutionAlgorithm::RsaPkcs1Sha256,
        release_manifest_sha256: "1".repeat(64),
        signature_sha256: "2".repeat(64),
        public_key_sha256: "3".repeat(64),
        signature_verified: true,
        private_key_non_extractable: true,
        private_key_sensitive: true,
        key_generated_in_provider: true,
        token_initialized: true,
        signer_tool: "pkcs11-tool 0.27.1".to_string(),
        verifier_tool: "OpenSSL 3.6.3".to_string(),
        operator_approved: true,
        cleanup_confirmed: true,
        observed_at_unix_ms: 1_782_259_200_000,
    }
}

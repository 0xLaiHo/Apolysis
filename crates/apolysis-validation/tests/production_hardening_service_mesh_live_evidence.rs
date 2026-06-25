// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_service_mesh_live_evidence,
    ProductionHardeningServiceMeshEvidenceSource, ProductionHardeningServiceMeshLiveEvidence,
    ProductionHardeningServiceMeshMtlsMode, ProductionHardeningServiceMeshProvider,
    ProductionHardeningServiceMeshTrafficSecurity,
};

#[test]
fn production_hardening_service_mesh_live_evidence_accepts_istio_strict_mtls_handshake() {
    let report = evaluate_production_hardening_service_mesh_live_evidence(live_istio_evidence());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("service mesh approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningServiceMeshProvider::Istio
    );
    assert_eq!(approval.namespace, "apolysis-system");
    assert_eq!(
        approval.authorized_principal,
        "cluster.local/ns/apolysis-monitoring/sa/prometheus"
    );
    assert_eq!(
        approval.server_principal,
        "cluster.local/ns/apolysis-system/sa/apolysis"
    );
}

#[test]
fn production_hardening_service_mesh_live_evidence_rejects_fixture_or_permissive_mesh() {
    let mut evidence = live_istio_evidence();
    evidence.source = ProductionHardeningServiceMeshEvidenceSource::Fixture;
    evidence.provider = ProductionHardeningServiceMeshProvider::None;
    evidence.mtls_mode = ProductionHardeningServiceMeshMtlsMode::Permissive;
    evidence.peer_authentication_admitted = false;
    evidence.authorization_policy_admitted = false;
    evidence.authorized_principal = "*".to_string();
    evidence.server_principal = "anonymous".to_string();
    evidence.authorized_handshake_succeeded = false;
    evidence.unauthorized_handshake_denied = false;
    evidence.plaintext_handshake_denied = false;
    evidence.observed_traffic_security = ProductionHardeningServiceMeshTrafficSecurity::Plaintext;
    evidence.cleanup_confirmed = false;
    evidence.observed_at_unix_ms = 0;

    let report = evaluate_production_hardening_service_mesh_live_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live cluster evidence is required",
        "Istio is required for this ProductionHardening service-mesh live gate",
        "strict mTLS mode is required",
        "PeerAuthentication admission evidence is required",
        "AuthorizationPolicy admission evidence is required",
        "authorized service-account principal is required",
        "server service-account principal is required",
        "authorized mTLS handshake must succeed",
        "unauthorized principal must be denied",
        "plaintext traffic must be denied",
        "traffic telemetry must report mutual TLS",
        "cleanup confirmation is required",
        "observed timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn live_istio_evidence() -> ProductionHardeningServiceMeshLiveEvidence {
    ProductionHardeningServiceMeshLiveEvidence {
        evidence_id: "production-hardening-istio-mtls-handshake-20260624".to_string(),
        source: ProductionHardeningServiceMeshEvidenceSource::LiveCluster,
        provider: ProductionHardeningServiceMeshProvider::Istio,
        cluster_name: "mactavish-k3s".to_string(),
        namespace: "apolysis-system".to_string(),
        workload_service_account: "apolysis".to_string(),
        metrics_service_name: "apolysis-metrics".to_string(),
        peer_authentication_name: "apolysis-mtls".to_string(),
        authorization_policy_name: "apolysis-metrics".to_string(),
        mtls_mode: ProductionHardeningServiceMeshMtlsMode::Strict,
        peer_authentication_admitted: true,
        authorization_policy_admitted: true,
        authorized_principal: "cluster.local/ns/apolysis-monitoring/sa/prometheus".to_string(),
        server_principal: "cluster.local/ns/apolysis-system/sa/apolysis".to_string(),
        authorized_handshake_succeeded: true,
        unauthorized_handshake_denied: true,
        plaintext_handshake_denied: true,
        observed_traffic_security: ProductionHardeningServiceMeshTrafficSecurity::MutualTls,
        cleanup_confirmed: true,
        observed_at_unix_ms: 1_782_259_200_000,
    }
}

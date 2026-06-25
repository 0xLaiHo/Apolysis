// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_operator_controller_evidence,
    ProductionHardeningOperatorControllerEvidence,
    ProductionHardeningOperatorControllerEvidenceSource,
    ProductionHardeningOperatorControllerProvider, ProductionHardeningOperatorControllerRbacScope,
};

#[test]
fn production_hardening_operator_controller_accepts_live_reconciliation_evidence() {
    let report =
        evaluate_production_hardening_operator_controller_evidence(operator_controller_evidence());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("operator controller approval");
    assert_eq!(approval.cluster_name, "mactavish-k3s");
    assert_eq!(approval.namespace, "apolysis-production-hardening-operator");
    assert_eq!(
        approval.provider,
        ProductionHardeningOperatorControllerProvider::KubernetesController
    );
    assert_eq!(approval.controller_ready_replicas, 2);
    assert_eq!(approval.managed_daemonset_name, "apolysisd-managed");
    assert_eq!(approval.managed_configmap_name, "apolysisd-managed-config");
}

#[test]
fn production_hardening_operator_controller_rejects_static_or_unbounded_controller_claims() {
    let mut evidence = operator_controller_evidence();
    evidence.source = ProductionHardeningOperatorControllerEvidenceSource::Fixture;
    evidence.provider = ProductionHardeningOperatorControllerProvider::StaticManifest;
    evidence.cluster_name.clear();
    evidence.namespace.clear();
    evidence.crd_name = "configs.example.com".to_string();
    evidence.custom_resource_name.clear();
    evidence.controller_deployment.clear();
    evidence.controller_service_account.clear();
    evidence.controller_desired_replicas = 1;
    evidence.controller_ready_replicas = 1;
    evidence.leader_election_lease.clear();
    evidence.lease_holder_identity.clear();
    evidence.rbac_scope = ProductionHardeningOperatorControllerRbacScope::ClusterAdmin;
    evidence.controller_cpu_request_millicores = 0;
    evidence.controller_cpu_limit_millicores = 500;
    evidence.controller_memory_request_mib = 0;
    evidence.controller_memory_limit_mib = 1024;
    evidence.crd_established = false;
    evidence.crd_served = false;
    evidence.custom_resource_admitted = false;
    evidence.reconciliation_observed = false;
    evidence.observed_generation = 0;
    evidence.reconciled_generation = 0;
    evidence.managed_daemonset_name.clear();
    evidence.managed_daemonset_ready = false;
    evidence.managed_configmap_name.clear();
    evidence.owner_references_verified = false;
    evidence.status_condition_ready = false;
    evidence.status_observed_generation_matches = false;
    evidence.rollback_or_delete_cleanup_verified = false;
    evidence.cleanup_confirmed = false;
    evidence.observed_at_unix_ms = 0;

    let report = evaluate_production_hardening_operator_controller_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live Kubernetes cluster evidence is required",
        "Kubernetes controller execution evidence is required",
        "cluster name is required",
        "namespace is required",
        "ApolysisProductionConfig CRD name is required",
        "custom resource name is required",
        "controller deployment name is required",
        "controller service account is required",
        "controller must run at least two desired replicas",
        "all controller replicas must be ready",
        "leader-election Lease evidence is required",
        "leader holder identity is required",
        "controller RBAC must be namespace-scoped",
        "controller CPU request must be between 1m and 100m",
        "controller CPU limit must be between request and 250m",
        "controller memory request must be between 1Mi and 128Mi",
        "controller memory limit must be between request and 256Mi",
        "CRD Established condition evidence is required",
        "CRD served version evidence is required",
        "custom resource admission evidence is required",
        "controller reconciliation evidence is required",
        "observed generation is required",
        "managed DaemonSet name is required",
        "managed DaemonSet readiness evidence is required",
        "managed ConfigMap name is required",
        "managed resource ownerReferences must point to the custom resource",
        "Ready status condition evidence is required",
        "status observedGeneration must match the reconciled generation",
        "delete or rollback cleanup evidence is required",
        "cleanup confirmation is required",
        "observed timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn operator_controller_evidence() -> ProductionHardeningOperatorControllerEvidence {
    ProductionHardeningOperatorControllerEvidence {
        evidence_id: "production-hardening-operator-controller-20260624".to_string(),
        source: ProductionHardeningOperatorControllerEvidenceSource::LiveCluster,
        provider: ProductionHardeningOperatorControllerProvider::KubernetesController,
        cluster_name: "mactavish-k3s".to_string(),
        namespace: "apolysis-production-hardening-operator".to_string(),
        crd_name: "apolysisproductionconfigs.apolysis.dev".to_string(),
        custom_resource_name: "platform-production".to_string(),
        controller_deployment: "apolysis-production-hardening-operator-controller".to_string(),
        controller_service_account: "apolysis-production-hardening-operator-controller".to_string(),
        controller_desired_replicas: 2,
        controller_ready_replicas: 2,
        leader_election_lease: "apolysis-production-hardening-operator-leader".to_string(),
        lease_holder_identity: "apolysis-production-hardening-operator-controller-7d6c5d9c8c-kj4p7"
            .to_string(),
        rbac_scope: ProductionHardeningOperatorControllerRbacScope::NamespaceScoped,
        controller_cpu_request_millicores: 20,
        controller_cpu_limit_millicores: 100,
        controller_memory_request_mib: 32,
        controller_memory_limit_mib: 128,
        crd_established: true,
        crd_served: true,
        custom_resource_admitted: true,
        reconciliation_observed: true,
        observed_generation: 1,
        reconciled_generation: 1,
        managed_daemonset_name: "apolysisd-managed".to_string(),
        managed_daemonset_ready: true,
        managed_configmap_name: "apolysisd-managed-config".to_string(),
        owner_references_verified: true,
        status_condition_ready: true,
        status_observed_generation_matches: true,
        rollback_or_delete_cleanup_verified: true,
        cleanup_confirmed: true,
        observed_at_unix_ms: 1_782_259_200_000,
    }
}

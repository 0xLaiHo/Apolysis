// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_production_hardening_chaos_performance_evidence, ProductionHardeningChaosAction,
    ProductionHardeningChaosPerformanceEvidence, ProductionHardeningChaosPerformanceProvider,
    ProductionHardeningChaosPerformanceSource,
};

#[test]
fn production_hardening_chaos_performance_accepts_live_k3s_scale_and_recovery_evidence() {
    let report =
        evaluate_production_hardening_chaos_performance_evidence(chaos_performance_evidence());

    assert!(report.passed, "{:#?}", report.failures);
    let approval = report.approval.expect("chaos performance approval");
    assert_eq!(
        approval.provider,
        ProductionHardeningChaosPerformanceProvider::K3s
    );
    assert_eq!(approval.cluster_name, "mactavish-k3s");
    assert_eq!(approval.workload_replicas_total, 30);
    assert_eq!(approval.pod_churn_deleted, 6);
    assert_eq!(approval.max_observed_memory_mib, 180);
}

#[test]
fn production_hardening_chaos_performance_rejects_fixture_or_under_scaled_unmeasured_runs() {
    let mut evidence = chaos_performance_evidence();
    evidence.source = ProductionHardeningChaosPerformanceSource::Fixture;
    evidence.provider = ProductionHardeningChaosPerformanceProvider::Fixture;
    evidence.cluster_name.clear();
    evidence.namespace.clear();
    evidence.workload_deployment_count = 1;
    evidence.workload_replicas_total = 10;
    evidence.workload_ready_replicas_before_chaos = 9;
    evidence.workload_ready_replicas_after_chaos = 8;
    evidence.pod_churn_deleted = 1;
    evidence.chaos_actions.clear();
    evidence.p95_startup_latency_ms = 180_001;
    evidence.p95_recovery_latency_ms = 180_001;
    evidence.metrics_server_available = false;
    evidence.resource_metrics_collected = false;
    evidence.max_observed_cpu_millicores = 1_001;
    evidence.max_observed_memory_mib = 1_025;
    evidence.total_cpu_request_millicores = 501;
    evidence.total_cpu_limit_millicores = 1_001;
    evidence.total_memory_request_mib = 513;
    evidence.total_memory_limit_mib = 1_025;
    evidence.scheduling_failure_count = 1;
    evidence.oom_kill_count = 1;
    evidence.restart_count = 1;
    evidence.cleanup_confirmed = false;
    evidence.observed_at_unix_ms = 0;

    let report = evaluate_production_hardening_chaos_performance_evidence(evidence);

    assert!(!report.passed, "{report:#?}");
    assert!(report.approval.is_none(), "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    for expected in [
        "live Kubernetes cluster evidence is required",
        "k3s or managed Kubernetes provider evidence is required",
        "cluster name is required",
        "namespace is required",
        "at least three workload deployments are required",
        "at least thirty workload replicas are required",
        "all replicas must be ready before chaos",
        "all replicas must recover after chaos",
        "pod-delete chaos must remove at least 20% of workload pods",
        "pod-delete chaos action evidence is required",
        "deployment self-healing action evidence is required",
        "startup p95 latency must be 180 seconds or less",
        "recovery p95 latency must be 180 seconds or less",
        "metrics-server availability evidence is required",
        "resource metrics collection evidence is required",
        "observed CPU must stay at or below 1000m",
        "observed memory must stay at or below 1024Mi",
        "aggregate CPU request must stay at or below 500m",
        "aggregate CPU limit must stay at or below 1000m",
        "aggregate memory request must stay at or below 512Mi",
        "aggregate memory limit must stay at or below 1024Mi",
        "scheduling failures are not allowed",
        "OOM kills are not allowed",
        "container restarts are not allowed during the run",
        "cleanup confirmation is required",
        "observed timestamp is required",
    ] {
        assert!(failure_text.contains(expected), "{failure_text}");
    }
}

fn chaos_performance_evidence() -> ProductionHardeningChaosPerformanceEvidence {
    ProductionHardeningChaosPerformanceEvidence {
        evidence_id: "production-hardening-chaos-performance-20260624".to_string(),
        source: ProductionHardeningChaosPerformanceSource::LiveCluster,
        provider: ProductionHardeningChaosPerformanceProvider::K3s,
        cluster_name: "mactavish-k3s".to_string(),
        namespace: "apolysis-production-hardening-chaos-performance".to_string(),
        workload_deployment_count: 3,
        workload_replicas_total: 30,
        workload_ready_replicas_before_chaos: 30,
        workload_ready_replicas_after_chaos: 30,
        pod_churn_deleted: 6,
        chaos_actions: vec![
            ProductionHardeningChaosAction::PodDelete,
            ProductionHardeningChaosAction::DeploymentSelfHealing,
            ProductionHardeningChaosAction::MetricsScrape,
        ],
        p95_startup_latency_ms: 45_000,
        p95_recovery_latency_ms: 30_000,
        metrics_server_available: true,
        resource_metrics_collected: true,
        max_observed_cpu_millicores: 180,
        max_observed_memory_mib: 180,
        total_cpu_request_millicores: 150,
        total_cpu_limit_millicores: 600,
        total_memory_request_mib: 240,
        total_memory_limit_mib: 960,
        scheduling_failure_count: 0,
        oom_kill_count: 0,
        restart_count: 0,
        cleanup_confirmed: true,
        observed_at_unix_ms: 1_782_259_200_000,
    }
}

// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    default_f2_performance_budgets, evaluate_performance_gate, PerformanceLoad, PerformanceSample,
};

#[test]
fn f2_performance_gate_accepts_the_required_load_profile() {
    let report = evaluate_performance_gate(
        default_f2_performance_budgets(),
        vec![
            PerformanceSample {
                load: PerformanceLoad::Idle,
                events_per_second: 0,
                milli_cpu: 10,
                rss_mib: 128,
                worker_pool_bounded: true,
                loss_accounted: true,
                queue_bounded: true,
                adapter_connected: true,
            },
            PerformanceSample {
                load: PerformanceLoad::Steady10000,
                events_per_second: 10_000,
                milli_cpu: 1000,
                rss_mib: 256,
                worker_pool_bounded: true,
                loss_accounted: true,
                queue_bounded: true,
                adapter_connected: true,
            },
            PerformanceSample {
                load: PerformanceLoad::Burst50000,
                events_per_second: 50_000,
                milli_cpu: 1400,
                rss_mib: 256,
                worker_pool_bounded: true,
                loss_accounted: true,
                queue_bounded: true,
                adapter_connected: true,
            },
        ],
    );

    assert!(report.passed, "{report:#?}");
    assert!(report.failures.is_empty(), "{report:#?}");

    let serialized = serde_json::to_string(&report).expect("serialize report");
    assert!(serialized.contains(r#""load":"steady_10000""#));
    assert!(serialized.contains(r#""load":"burst_50000""#));
}

#[test]
fn f2_performance_gate_reports_each_budget_violation() {
    let report = evaluate_performance_gate(
        default_f2_performance_budgets(),
        vec![
            PerformanceSample {
                load: PerformanceLoad::Idle,
                events_per_second: 0,
                milli_cpu: 11,
                rss_mib: 129,
                worker_pool_bounded: true,
                loss_accounted: true,
                queue_bounded: true,
                adapter_connected: false,
            },
            PerformanceSample {
                load: PerformanceLoad::Steady10000,
                events_per_second: 9_999,
                milli_cpu: 1001,
                rss_mib: 257,
                worker_pool_bounded: true,
                loss_accounted: true,
                queue_bounded: false,
                adapter_connected: true,
            },
            PerformanceSample {
                load: PerformanceLoad::Burst50000,
                events_per_second: 49_999,
                milli_cpu: 4000,
                rss_mib: 512,
                worker_pool_bounded: false,
                loss_accounted: false,
                queue_bounded: false,
                adapter_connected: true,
            },
        ],
    );

    assert!(!report.passed, "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("idle cpu budget exceeded"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("idle rss budget exceeded"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("idle adapters not connected"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("steady_10000 event rate below required load"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("steady_10000 queue was not bounded"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("burst_50000 worker pool was not bounded"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("burst_50000 loss was not accounted"),
        "{failure_text}"
    );
}

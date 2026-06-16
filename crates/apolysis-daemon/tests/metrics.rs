// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    AdapterKind, ComponentState, HealthSnapshot, QueuePriority, QueueStats,
};
use apolysis_daemon::render_prometheus_metrics;

#[test]
fn prometheus_metrics_use_low_cardinality_runtime_labels() {
    let mut health = HealthSnapshot::new(
        QueueStats::new(16)
            .with_depth(3)
            .with_accepted(42)
            .with_drop(QueuePriority::Ordinary),
    );
    health.set_ebpf(ComponentState::Ready);
    health.set_storage(ComponentState::Ready);
    health.set_adapter(AdapterKind::Docker, ComponentState::Ready);
    health.set_adapter(AdapterKind::Kubernetes, ComponentState::Degraded);

    let metrics = render_prometheus_metrics(&health);

    assert!(metrics.contains("apolysis_component_state{component=\"ebpf\"} 1"));
    assert!(metrics.contains("apolysis_component_state{component=\"storage\"} 1"));
    assert!(metrics.contains("apolysis_adapter_state{adapter=\"docker\"} 1"));
    assert!(metrics.contains("apolysis_adapter_state{adapter=\"kubernetes\"} 0.5"));
    assert!(metrics.contains("apolysis_queue_capacity 16"));
    assert!(metrics.contains("apolysis_queue_depth 3"));
    assert!(metrics.contains("apolysis_queue_accepted_total 42"));
    assert!(metrics.contains("apolysis_queue_dropped_total{priority=\"ordinary\"} 1"));
    assert!(!metrics.contains("session_id"));
    assert!(!metrics.contains("container_id"));
    assert!(!metrics.contains("workload_id"));
}

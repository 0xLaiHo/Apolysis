// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    AdapterKind, ComponentState, HealthSnapshot, QueuePriority, QueueStats,
};

#[test]
fn readiness_requires_ebpf_and_storage_but_not_every_adapter() {
    let mut health = HealthSnapshot::new(QueueStats::new(128));
    health.set_ebpf(ComponentState::Ready);
    health.set_storage(ComponentState::Ready);
    health.set_adapter(AdapterKind::Docker, ComponentState::Degraded);
    health.set_adapter(AdapterKind::Kubernetes, ComponentState::Unavailable);

    assert!(health.liveness());
    assert!(health.readiness());
    assert_eq!(
        health.adapter(AdapterKind::Docker),
        ComponentState::Degraded
    );
}

#[test]
fn unavailable_ebpf_or_storage_fails_readiness() {
    let mut health = HealthSnapshot::new(QueueStats::new(128));
    health.set_ebpf(ComponentState::Unavailable);
    health.set_storage(ComponentState::Ready);
    assert!(!health.readiness());

    health.set_ebpf(ComponentState::Ready);
    health.set_storage(ComponentState::Degraded);
    assert!(!health.readiness());
}

#[test]
fn stopped_event_loop_fails_liveness_and_readiness() {
    let mut health = HealthSnapshot::new(QueueStats::new(128));
    health.set_ebpf(ComponentState::Ready);
    health.set_storage(ComponentState::Ready);
    health.set_event_loop_running(false);

    assert!(!health.liveness());
    assert!(!health.readiness());
}

#[test]
fn queue_snapshot_exposes_bounded_counts_without_workload_labels() {
    let queue = QueueStats::new(2)
        .with_depth(2)
        .with_accepted(4)
        .with_drop(QueuePriority::Ordinary);
    let health = HealthSnapshot::new(queue);

    assert_eq!(health.queue.capacity, 2);
    assert_eq!(health.queue.depth, 2);
    assert_eq!(health.queue.accepted, 4);
    assert_eq!(health.queue.dropped(QueuePriority::Ordinary), 1);
    assert_eq!(
        HealthSnapshot::metric_label_keys(),
        &["component", "adapter", "priority"]
    );
}

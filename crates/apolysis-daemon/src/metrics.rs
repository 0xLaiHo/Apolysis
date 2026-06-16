// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{AdapterKind, ComponentState, HealthSnapshot, QueuePriority};

pub fn render_prometheus_metrics(health: &HealthSnapshot) -> String {
    let mut metrics = String::new();
    metrics.push_str(
        "# HELP apolysis_component_state Component state: ready=1 degraded=0.5 unavailable=0.\n",
    );
    metrics.push_str("# TYPE apolysis_component_state gauge\n");
    push_metric(
        &mut metrics,
        "apolysis_component_state",
        &[("component", "ebpf")],
        component_value(health.ebpf()),
    );
    push_metric(
        &mut metrics,
        "apolysis_component_state",
        &[("component", "storage")],
        component_value(health.storage()),
    );

    metrics.push_str("# HELP apolysis_adapter_state Runtime adapter state: ready=1 degraded=0.5 unavailable=0.\n");
    metrics.push_str("# TYPE apolysis_adapter_state gauge\n");
    for adapter in [
        AdapterKind::Docker,
        AdapterKind::Containerd,
        AdapterKind::K3sContainerd,
        AdapterKind::Kubernetes,
    ] {
        push_metric(
            &mut metrics,
            "apolysis_adapter_state",
            &[("adapter", adapter_name(adapter))],
            component_value(health.adapter(adapter)),
        );
    }

    metrics.push_str("# TYPE apolysis_queue_capacity gauge\n");
    push_metric(
        &mut metrics,
        "apolysis_queue_capacity",
        &[],
        health.queue.capacity.to_string(),
    );
    metrics.push_str("# TYPE apolysis_queue_depth gauge\n");
    push_metric(
        &mut metrics,
        "apolysis_queue_depth",
        &[],
        health.queue.depth.to_string(),
    );
    metrics.push_str("# TYPE apolysis_queue_accepted_total counter\n");
    push_metric(
        &mut metrics,
        "apolysis_queue_accepted_total",
        &[],
        health.queue.accepted.to_string(),
    );
    metrics.push_str("# TYPE apolysis_queue_dropped_total counter\n");
    for priority in [
        QueuePriority::Ordinary,
        QueuePriority::Lifecycle,
        QueuePriority::Diagnostic,
        QueuePriority::Finding,
        QueuePriority::Integrity,
    ] {
        push_metric(
            &mut metrics,
            "apolysis_queue_dropped_total",
            &[("priority", priority_name(priority))],
            health.queue.dropped(priority).to_string(),
        );
    }

    metrics
}

fn push_metric(metrics: &mut String, name: &str, labels: &[(&str, &str)], value: impl AsRef<str>) {
    metrics.push_str(name);
    if !labels.is_empty() {
        metrics.push('{');
        for (index, (key, value)) in labels.iter().enumerate() {
            if index > 0 {
                metrics.push(',');
            }
            metrics.push_str(key);
            metrics.push_str("=\"");
            metrics.push_str(value);
            metrics.push('"');
        }
        metrics.push('}');
    }
    metrics.push(' ');
    metrics.push_str(value.as_ref());
    metrics.push('\n');
}

fn component_value(state: ComponentState) -> &'static str {
    match state {
        ComponentState::Ready => "1",
        ComponentState::Degraded => "0.5",
        ComponentState::Unavailable => "0",
    }
}

fn adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Docker => "docker",
        AdapterKind::Containerd => "containerd",
        AdapterKind::K3sContainerd => "k3s_containerd",
        AdapterKind::Kubernetes => "kubernetes",
    }
}

fn priority_name(priority: QueuePriority) -> &'static str {
    match priority {
        QueuePriority::Ordinary => "ordinary",
        QueuePriority::Lifecycle => "lifecycle",
        QueuePriority::Diagnostic => "diagnostic",
        QueuePriority::Finding => "finding",
        QueuePriority::Integrity => "integrity",
    }
}

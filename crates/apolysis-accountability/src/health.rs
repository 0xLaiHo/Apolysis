// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::QueueStats;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Docker,
    Containerd,
    K3sContainerd,
    Kubernetes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthSnapshot {
    event_loop_running: bool,
    ebpf: ComponentState,
    storage: ComponentState,
    adapters: BTreeMap<AdapterKind, ComponentState>,
    pub queue: QueueStats,
}

impl HealthSnapshot {
    pub fn new(queue: QueueStats) -> Self {
        Self {
            event_loop_running: true,
            ebpf: ComponentState::Unavailable,
            storage: ComponentState::Unavailable,
            adapters: BTreeMap::new(),
            queue,
        }
    }

    pub fn set_event_loop_running(&mut self, running: bool) {
        self.event_loop_running = running;
    }

    pub fn set_ebpf(&mut self, state: ComponentState) {
        self.ebpf = state;
    }

    pub fn set_storage(&mut self, state: ComponentState) {
        self.storage = state;
    }

    pub fn set_adapter(&mut self, adapter: AdapterKind, state: ComponentState) {
        self.adapters.insert(adapter, state);
    }

    pub fn adapter(&self, adapter: AdapterKind) -> ComponentState {
        self.adapters
            .get(&adapter)
            .copied()
            .unwrap_or(ComponentState::Unavailable)
    }

    pub fn liveness(&self) -> bool {
        self.event_loop_running
    }

    pub fn readiness(&self) -> bool {
        self.liveness()
            && self.ebpf == ComponentState::Ready
            && self.storage == ComponentState::Ready
    }

    pub fn metric_label_keys() -> &'static [&'static str] {
        &["component", "adapter", "priority"]
    }
}

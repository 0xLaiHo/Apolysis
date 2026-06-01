// SPDX-License-Identifier: Apache-2.0

//! Visibility validation for strong-isolation runtime backends.
//!
//! M7 does not claim to run production gVisor, Kata, or Firecracker sessions.
//! It codifies what host-side eBPF can still prove from fixture observations and
//! when runtime metadata or a guest-side collector is required to recover full
//! agent side-effect semantics.

use std::collections::BTreeSet;

use apolysis_core::{json_string, JsonLine};
use apolysis_kubernetes::KubernetesMetadata;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeVisibilityProfile {
    DockerDefault,
    DockerGvisor,
    KubernetesGvisor,
    KubernetesKata,
    FirecrackerPrototype,
}

impl RuntimeVisibilityProfile {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "docker-default" => Ok(Self::DockerDefault),
            "docker-gvisor" => Ok(Self::DockerGvisor),
            "kubernetes-gvisor" => Ok(Self::KubernetesGvisor),
            "kubernetes-kata" => Ok(Self::KubernetesKata),
            "firecracker-prototype" => Ok(Self::FirecrackerPrototype),
            unknown => Err(format!("unknown visibility scenario: {unknown}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DockerDefault => "docker-default",
            Self::DockerGvisor => "docker-gvisor",
            Self::KubernetesGvisor => "kubernetes-gvisor",
            Self::KubernetesKata => "kubernetes-kata",
            Self::FirecrackerPrototype => "firecracker-prototype",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostVisibilityScope {
    GuestProcess,
    RuntimeBoundary,
    BoundaryOnly,
}

impl HostVisibilityScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GuestProcess => "guest_process",
            Self::RuntimeBoundary => "runtime_boundary",
            Self::BoundaryOnly => "boundary_only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibilityInput {
    pub session_id: String,
    pub runtime_profile: RuntimeVisibilityProfile,
    pub host_events: String,
    pub kubernetes_metadata: Option<KubernetesMetadata>,
}

impl VisibilityInput {
    pub fn new(
        session_id: impl Into<String>,
        runtime_profile: RuntimeVisibilityProfile,
        host_events: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            runtime_profile,
            host_events: host_events.into(),
            kubernetes_metadata: None,
        }
    }

    pub fn with_kubernetes_metadata(mut self, metadata: Option<KubernetesMetadata>) -> Self {
        self.kubernetes_metadata = metadata;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VisibilityAssessment {
    pub session_id: String,
    pub runtime_profile: RuntimeVisibilityProfile,
    pub host_visibility_scope: HostVisibilityScope,
    pub host_semantics_collapsed: bool,
    pub guest_collector_required: bool,
    pub runtime_metadata_required: bool,
    pub host_event_subjects: Vec<String>,
    pub pod_name: Option<String>,
    pub namespace: Option<String>,
    pub runtime_class_name: Option<String>,
    pub sandbox_name: Option<String>,
    pub notes: String,
}

impl JsonLine for VisibilityAssessment {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":\"visibility_assessment\",\"session_id\":{},\"runtime_profile\":{},\"host_visibility_scope\":{},\"host_semantics_collapsed\":{},\"guest_collector_required\":{},\"runtime_metadata_required\":{},\"host_event_subjects\":{},\"pod_name\":{},\"namespace\":{},\"runtime_class_name\":{},\"sandbox_name\":{},\"notes\":{}}}",
            json_string(&self.session_id),
            json_string(self.runtime_profile.as_str()),
            json_string(self.host_visibility_scope.as_str()),
            self.host_semantics_collapsed,
            self.guest_collector_required,
            self.runtime_metadata_required,
            json_string_array(&self.host_event_subjects),
            json_option(self.pod_name.as_deref()),
            json_option(self.namespace.as_deref()),
            json_option(self.runtime_class_name.as_deref()),
            json_option(self.sandbox_name.as_deref()),
            json_string(&self.notes),
        )
    }
}

pub fn assess_visibility(input: VisibilityInput) -> Result<VisibilityAssessment, String> {
    let host_event_subjects = collect_host_subjects(&input.host_events)?;
    let metadata = input.kubernetes_metadata.as_ref();
    let (
        host_visibility_scope,
        host_semantics_collapsed,
        guest_collector_required,
        runtime_metadata_required,
        notes,
    ) = classify_profile(&input.runtime_profile);

    Ok(VisibilityAssessment {
        session_id: input.session_id,
        runtime_profile: input.runtime_profile,
        host_visibility_scope,
        host_semantics_collapsed,
        guest_collector_required,
        runtime_metadata_required,
        host_event_subjects,
        pod_name: metadata.map(|value| value.pod_name.clone()),
        namespace: metadata.map(|value| value.namespace.clone()),
        runtime_class_name: metadata.and_then(|value| value.runtime_class_name.clone()),
        sandbox_name: metadata.and_then(|value| value.sandbox_name.clone()),
        notes: notes.to_string(),
    })
}

fn classify_profile(
    profile: &RuntimeVisibilityProfile,
) -> (HostVisibilityScope, bool, bool, bool, &'static str) {
    match profile {
        RuntimeVisibilityProfile::DockerDefault => (
            HostVisibilityScope::GuestProcess,
            false,
            false,
            false,
            "host eBPF can usually see container process, file, and network subjects directly; container metadata is still useful for session correlation",
        ),
        RuntimeVisibilityProfile::DockerGvisor => (
            HostVisibilityScope::RuntimeBoundary,
            true,
            false,
            true,
            "host eBPF commonly sees runsc, sentry, and gofer boundary activity; runtime metadata or gVisor-specific metadata is needed to map back to guest intent",
        ),
        RuntimeVisibilityProfile::KubernetesGvisor => (
            HostVisibilityScope::RuntimeBoundary,
            true,
            false,
            true,
            "host eBPF commonly sees runsc, sentry, and gofer boundary activity; Kubernetes pod and RuntimeClass metadata are required for correlation",
        ),
        RuntimeVisibilityProfile::KubernetesKata => (
            HostVisibilityScope::BoundaryOnly,
            true,
            true,
            true,
            "host eBPF sees the VMM, shim, virtio, and host boundary; a guest kernel collector is required for full process, file, and network semantics",
        ),
        RuntimeVisibilityProfile::FirecrackerPrototype => (
            HostVisibilityScope::BoundaryOnly,
            true,
            true,
            true,
            "host eBPF sees firecracker, block, tap, and vsock boundary events; a guest collector or vsock event channel is required for full agent side-effect semantics",
        ),
    }
}

fn collect_host_subjects(input: &str) -> Result<Vec<String>, String> {
    let mut subjects = BTreeSet::new();
    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some(value) = field_value(line, "comm") else {
            return Err(format!("host visibility event missing comm field: {line}"));
        };
        subjects.insert(value.to_string());
    }

    Ok(subjects.into_iter().collect())
}

fn field_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split('|').find_map(|part| {
        let (field, value) = part.split_once('=')?;
        (field.trim() == key).then(|| value.trim())
    })
}

fn json_string_array(values: &[String]) -> String {
    let body = values
        .iter()
        .map(|value| json_string(value))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn json_option(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

// SPDX-License-Identifier: Apache-2.0

//! Kubernetes and Agent Sandbox metadata extraction.
//!
//! M6 intentionally consumes Kubernetes metadata from manifests or captured pod
//! snapshots instead of talking to the cluster API.  This keeps local tests
//! deterministic while defining the timeline records that a future in-cluster
//! adapter or Agent Sandbox integration must emit.

use apolysis_core::{
    actions, actors, resources,
    scalars::{clean_scalar, parse_bool},
    CanonicalEvent, EventSource, EventType,
};
use apolysis_validation::{F4KubernetesAgentSandboxEvidenceReport, F4RuntimeAdapterEvidenceSource};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesMetadata {
    pub pod_name: String,
    pub namespace: String,
    pub pod_uid: Option<String>,
    pub service_account: Option<String>,
    pub runtime_class_name: Option<String>,
    pub node_name: Option<String>,
    pub sandbox_name: Option<String>,
    pub automount_service_account_token: Option<bool>,
}

impl KubernetesMetadata {
    /// Parse a Kubernetes pod manifest or captured pod snapshot.
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut parser = MetadataParser::default();

        for raw_line in input.lines() {
            parser.consume_line(raw_line)?;
        }

        Ok(Self {
            pod_name: parser
                .pod_name
                .ok_or_else(|| "kubernetes metadata missing pod name".to_string())?,
            namespace: parser
                .namespace
                .ok_or_else(|| "kubernetes metadata missing namespace".to_string())?,
            pod_uid: parser.pod_uid,
            service_account: parser.service_account,
            runtime_class_name: parser.runtime_class_name,
            node_name: parser.node_name,
            sandbox_name: parser.sandbox_name,
            automount_service_account_token: parser.automount_service_account_token,
        })
    }

    /// Classify the runtime isolation profile implied by `runtimeClassName`.
    pub fn runtime_isolation_profile(&self) -> RuntimeIsolationProfile {
        self.runtime_class_name
            .as_deref()
            .map(RuntimeIsolationProfile::from_runtime_class)
            .unwrap_or(RuntimeIsolationProfile::DefaultContainer)
    }

    /// Convert Kubernetes metadata into canonical runtime metadata events.
    pub fn to_timeline_events(&self, session_id: &str) -> Vec<CanonicalEvent> {
        let mut records = vec![
            metadata_event(
                session_id,
                resources::KUBERNETES_POD,
                format!("{}{}", actions::NAME_PREFIX, self.pod_name),
            ),
            metadata_event(
                session_id,
                resources::KUBERNETES_NAMESPACE,
                format!("{}{}", actions::NAMESPACE_PREFIX, self.namespace),
            ),
            metadata_event(
                session_id,
                resources::KUBERNETES_RUNTIME_PROFILE,
                format!(
                    "{}{}",
                    actions::ISOLATION_PREFIX,
                    self.runtime_isolation_profile().as_str()
                ),
            ),
        ];

        if let Some(value) = &self.pod_uid {
            records.push(metadata_event(
                session_id,
                resources::KUBERNETES_POD_UID,
                format!("{}{value}", actions::UID_PREFIX),
            ));
        }
        if let Some(value) = &self.service_account {
            records.push(metadata_event(
                session_id,
                resources::KUBERNETES_SERVICE_ACCOUNT,
                format!("{}{value}", actions::SERVICE_ACCOUNT_PREFIX),
            ));
        }
        if let Some(value) = &self.runtime_class_name {
            records.push(metadata_event(
                session_id,
                resources::KUBERNETES_RUNTIME_CLASS,
                format!("{}{value}", actions::RUNTIME_CLASS_PREFIX),
            ));
        }
        if let Some(value) = &self.node_name {
            records.push(metadata_event(
                session_id,
                resources::KUBERNETES_NODE,
                format!("{}{value}", actions::NODE_PREFIX),
            ));
        }
        if let Some(value) = &self.sandbox_name {
            records.push(metadata_event(
                session_id,
                resources::AGENT_SANDBOX,
                format!("{}{value}", actions::SANDBOX_PREFIX),
            ));
        }
        if let Some(value) = self.automount_service_account_token {
            records.push(metadata_event(
                session_id,
                resources::KUBERNETES_SERVICE_ACCOUNT_TOKEN,
                format!("{}{value}", actions::AUTOMOUNT_PREFIX),
            ));
        }

        records
    }
}

pub fn f4_agent_sandbox_evidence_from_metadata(
    metadata: &KubernetesMetadata,
    session_id: impl Into<String>,
    evidence_id: impl Into<String>,
    runtime_adapter_evidence_id: impl Into<String>,
    source: F4RuntimeAdapterEvidenceSource,
) -> Result<F4KubernetesAgentSandboxEvidenceReport, String> {
    let session_id = session_id.into();
    let evidence_id = evidence_id.into();
    let runtime_adapter_evidence_id = runtime_adapter_evidence_id.into();

    if session_id.trim().is_empty() {
        return Err("F4 Kubernetes Agent Sandbox evidence requires session id".to_string());
    }
    if evidence_id.trim().is_empty() {
        return Err("F4 Kubernetes Agent Sandbox evidence requires evidence id".to_string());
    }
    if runtime_adapter_evidence_id.trim().is_empty() {
        return Err(
            "F4 Kubernetes Agent Sandbox evidence requires runtime adapter evidence id".to_string(),
        );
    }
    if metadata.pod_name.trim().is_empty() {
        return Err("F4 Kubernetes Agent Sandbox evidence requires pod name".to_string());
    }
    if metadata.namespace.trim().is_empty() {
        return Err("F4 Kubernetes Agent Sandbox evidence requires namespace".to_string());
    }

    Ok(F4KubernetesAgentSandboxEvidenceReport {
        evidence_id,
        source,
        runtime_adapter_evidence_id,
        session_id,
        pod_name: metadata.pod_name.clone(),
        namespace: metadata.namespace.clone(),
        service_account: metadata.service_account.clone(),
        runtime_class_name: metadata.runtime_class_name.clone(),
        sandbox_name: metadata.sandbox_name.clone(),
        node_name: metadata.node_name.clone(),
        pod_uid: metadata.pod_uid.clone(),
        host_boundary_visibility: true,
        guest_semantics_claimed: false,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeIsolationProfile {
    DefaultContainer,
    Gvisor,
    Kata,
    Unknown(String),
}

impl RuntimeIsolationProfile {
    /// Infer an isolation profile from a Kubernetes RuntimeClass value.
    pub fn from_runtime_class(runtime_class: &str) -> Self {
        let normalized = runtime_class.to_ascii_lowercase();
        if normalized.contains("gvisor") || normalized == "runsc" {
            Self::Gvisor
        } else if normalized.contains("kata") {
            Self::Kata
        } else if normalized == "runc" || normalized == "default" {
            Self::DefaultContainer
        } else {
            Self::Unknown(runtime_class.to_string())
        }
    }

    /// Return the stable profile string emitted to timelines.
    pub fn as_str(&self) -> &str {
        match self {
            Self::DefaultContainer => "default-container",
            Self::Gvisor => "gvisor",
            Self::Kata => "kata",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Default)]
struct MetadataParser {
    section: String,
    list: String,
    pod_name: Option<String>,
    namespace: Option<String>,
    pod_uid: Option<String>,
    service_account: Option<String>,
    runtime_class_name: Option<String>,
    node_name: Option<String>,
    sandbox_name: Option<String>,
    automount_service_account_token: Option<bool>,
}

impl MetadataParser {
    fn consume_line(&mut self, raw_line: &str) -> Result<(), String> {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line == "---" {
            return Ok(());
        }

        if !raw_line.starts_with(' ') && line.ends_with(':') {
            self.section = line.trim_end_matches(':').to_string();
            self.list.clear();
            return Ok(());
        }

        if line.ends_with(':') {
            self.list = line.trim_end_matches(':').to_string();
            return Ok(());
        }

        let Some((key, value)) = line.split_once(':') else {
            return Ok(());
        };
        let key = key.trim();
        let value = clean_scalar(value);

        match (self.section.as_str(), self.list.as_str(), key) {
            ("metadata", "", "name") => self.pod_name = Some(value.to_string()),
            ("metadata", "", "namespace") => self.namespace = Some(value.to_string()),
            ("metadata", "", "uid") => self.pod_uid = Some(value.to_string()),
            ("metadata", "labels", "agent-sandbox.sigs.k8s.io/sandbox")
            | ("metadata", "labels", "apolysis.dev/agent-sandbox") => {
                self.sandbox_name = Some(value.to_string());
            }
            ("spec", "", "serviceAccountName") => self.service_account = Some(value.to_string()),
            ("spec", "", "runtimeClassName") => self.runtime_class_name = Some(value.to_string()),
            ("spec", "", "nodeName") => self.node_name = Some(value.to_string()),
            ("spec", "", "automountServiceAccountToken") => {
                self.automount_service_account_token = Some(
                    parse_bool(value, "kubernetes")
                        .map_err(|_| format!("invalid kubernetes boolean: {value}"))?,
                );
            }
            _ => {}
        }

        Ok(())
    }
}

fn metadata_event(
    session_id: &str,
    resource: impl Into<String>,
    action: impl Into<String>,
) -> CanonicalEvent {
    CanonicalEvent::new(
        session_id,
        EventSource::RuntimeMetadata,
        EventType::RuntimeMetadata,
        std::process::id(),
        0,
        actors::KUBERNETES,
        resource,
        action,
    )
}

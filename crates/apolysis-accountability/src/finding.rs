// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::{ActionClass, ResourceKind, SessionIntent};

pub const FINDING_SCHEMA_V1: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    Exec,
    FileRead,
    FileWrite,
    NetworkConnect,
    CredentialRead,
    ServiceAccountTokenRead,
}

impl EffectKind {
    fn action_class(&self) -> ActionClass {
        match self {
            Self::Exec => ActionClass::Execute,
            Self::FileRead | Self::ServiceAccountTokenRead => ActionClass::ReadFile,
            Self::FileWrite => ActionClass::WriteFile,
            Self::NetworkConnect => ActionClass::Network,
            Self::CredentialRead => ActionClass::Credential,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBoundary {
    HostBoundary,
    GuestSemantic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeIdentity {
    pub runtime: String,
    pub container_id: Option<String>,
    pub pod_uid: Option<String>,
    pub cgroup_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedEffect {
    pub session_id: String,
    pub evidence_ref: String,
    pub kind: EffectKind,
    pub actor: String,
    pub resource: String,
    pub runtime: RuntimeIdentity,
    pub evidence_boundary: EvidenceBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    MissingIntent,
    UndeclaredAction,
    CredentialRead,
    WorkspaceBoundary,
    UnknownEgress,
    DangerousCommand,
    ServiceAccountTokenRead,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingDecision {
    Notify,
    Review,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountabilityFinding {
    pub schema_version: u32,
    pub session_id: String,
    pub kind: FindingKind,
    pub decision: FindingDecision,
    pub reason: String,
    pub evidence_ref: String,
    pub runtime: RuntimeIdentity,
    pub evidence_boundary: EvidenceBoundary,
}

pub struct AccountabilityAnalyzer;

impl AccountabilityAnalyzer {
    pub fn evaluate(
        intent: Option<&SessionIntent>,
        effect: &ObservedEffect,
    ) -> Vec<AccountabilityFinding> {
        let Some(intent) = intent else {
            return vec![finding(
                effect,
                FindingKind::MissingIntent,
                FindingDecision::Review,
                "marked workload has no registered intent",
            )];
        };

        let mut findings = Vec::new();
        if !intent
            .declared_actions
            .contains(&effect.kind.action_class())
        {
            findings.push(finding(
                effect,
                FindingKind::UndeclaredAction,
                FindingDecision::Review,
                "observed action class was not declared by intent",
            ));
        }

        match effect.kind {
            EffectKind::CredentialRead => findings.push(finding(
                effect,
                FindingKind::CredentialRead,
                FindingDecision::Notify,
                "workload read a credential-classified resource",
            )),
            EffectKind::FileRead | EffectKind::FileWrite => {
                if has_path_policy(intent)
                    && !intent.allowed_resources.iter().any(|selector| {
                        matches!(selector.kind, ResourceKind::Workspace | ResourceKind::Path)
                            && path_matches(&selector.value, &effect.resource)
                    })
                {
                    findings.push(finding(
                        effect,
                        FindingKind::WorkspaceBoundary,
                        FindingDecision::Review,
                        "file access crossed the declared workspace boundary",
                    ));
                }
            }
            EffectKind::NetworkConnect => {
                if !intent.allowed_resources.iter().any(|selector| {
                    selector.kind == ResourceKind::Egress
                        && endpoint_matches(&selector.value, &effect.resource)
                }) {
                    findings.push(finding(
                        effect,
                        FindingKind::UnknownEgress,
                        FindingDecision::Review,
                        "network endpoint is outside the declared egress set",
                    ));
                }
            }
            EffectKind::Exec => {
                if is_dangerous_command(&effect.actor) {
                    findings.push(finding(
                        effect,
                        FindingKind::DangerousCommand,
                        FindingDecision::Review,
                        "command matches the dangerous-command baseline",
                    ));
                }
            }
            EffectKind::ServiceAccountTokenRead => findings.push(finding(
                effect,
                FindingKind::ServiceAccountTokenRead,
                FindingDecision::Review,
                "workload read a Kubernetes service account token",
            )),
        }
        findings
    }
}

fn finding(
    effect: &ObservedEffect,
    kind: FindingKind,
    decision: FindingDecision,
    reason: &str,
) -> AccountabilityFinding {
    AccountabilityFinding {
        schema_version: FINDING_SCHEMA_V1,
        session_id: effect.session_id.clone(),
        kind,
        decision,
        reason: reason.to_string(),
        evidence_ref: effect.evidence_ref.clone(),
        runtime: effect.runtime.clone(),
        evidence_boundary: effect.evidence_boundary.clone(),
    }
}

fn has_path_policy(intent: &SessionIntent) -> bool {
    intent
        .allowed_resources
        .iter()
        .any(|selector| matches!(selector.kind, ResourceKind::Workspace | ResourceKind::Path))
}

fn path_matches(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn endpoint_matches(pattern: &str, endpoint: &str) -> bool {
    if pattern == endpoint {
        return true;
    }
    pattern
        .strip_prefix("*.")
        .map(|suffix| endpoint.ends_with(suffix))
        .unwrap_or(false)
}

fn is_dangerous_command(command: &str) -> bool {
    ["rm -rf", "curl | sh", "wget | sh", "chmod 777", "dd if="]
        .iter()
        .any(|pattern| command.contains(pattern))
}

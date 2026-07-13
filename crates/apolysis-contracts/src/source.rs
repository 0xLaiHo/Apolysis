// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    id::{validate_contract_identifier, validate_reference},
    ContractError, EnvironmentKind, SchemaVersion, SourceId,
};

/// Evidence Source integration categories.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Agent or IDE lifecycle hook.
    SemanticHook,
    /// In-process SDK processor.
    SdkProcessor,
    /// MCP, A2A, or other protocol evidence tap.
    ProtocolTap,
    /// Provider API or audit adapter.
    ProviderAdapter,
    /// Customer-controlled execution boundary witness.
    RuntimeWitness,
    /// Independent outcome read-back integration.
    OutcomeVerifier,
}

/// Boundary a source can directly observe, independent from effective trust.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBoundary {
    /// Agent hook, wrapper, or IDE harness boundary.
    AgentHarness,
    /// In-process SDK or telemetry processor boundary.
    InProcessSdk,
    /// MCP, A2A, or comparable protocol boundary.
    ProtocolBoundary,
    /// Vendor or managed-provider control-plane boundary.
    ProviderControlPlane,
    /// Customer-controlled host, VM, container, or node boundary.
    CustomerControlledHost,
    /// Independent read-back boundary for an external outcome.
    IndependentOutcomeReadback,
}

/// Ordering guarantee declared by one source stream.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OrderingCapability {
    /// Sequence is strictly increasing within a source stream.
    StrictPerStream,
    /// The source may deliver reordered items and reports observed gaps.
    BestEffort,
}

/// Privacy-preserving payload representations a source can produce.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyCapability {
    /// Typed allowlisted metadata with no raw prompt, result, body, or argv.
    StructureOnly,
    /// Immutable object reference subject to separate capture and read policy.
    AuthorizedContentReference,
}

/// The trust boundary under which source statements are interpreted.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustProfile {
    /// A source declared a fact without an independent observer.
    Declared,
    /// A harness observed lifecycle or tool semantics.
    HarnessObserved,
    /// A customer-controlled host boundary observed execution.
    HostVerified,
    /// A vendor attests activity inside its own boundary.
    ProviderAttested,
    /// The execution boundary is not observable by a qualifying source.
    Opaque,
    /// Expected trust evidence is missing, lost, or otherwise incomplete.
    Incomplete,
}

/// A source capability declaration, not a per-run completeness claim.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceCapability {
    /// Agent/run lifecycle semantics.
    SemanticLifecycle,
    /// Agent delegation lifecycle.
    Delegation,
    /// Declared tool-call lifecycle.
    ToolCalls,
    /// MCP lifecycle and correlation identifiers.
    Mcp,
    /// A2A task lifecycle and identifiers.
    A2a,
    /// Process execution observations.
    Process,
    /// File operation observations.
    File,
    /// Network operation observations.
    Network,
    /// Workload/runtime binding observations.
    Workload,
    /// Agent, tool, or provider outcome claims.
    ClaimedOutcome,
    /// Independently checked outcome evidence.
    VerifiedOutcome,
    /// Source health, loss, or terminal-position evidence.
    SourceHealth,
}

/// Expected source lifecycle markers.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceLifecycleEvent {
    /// Source stream start declaration.
    Started,
    /// Optional source liveness declaration.
    Heartbeat,
    /// Source stream terminal declaration.
    Finished,
}

/// Versioned declaration of an Evidence Source's identity and limits.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct SourceManifest {
    schema_version: SchemaVersion,
    source_id: SourceId,
    source_kind: SourceKind,
    declared_boundary: EvidenceBoundary,
    adapter_name: String,
    adapter_version: String,
    environment: EnvironmentKind,
    #[schemars(length(min = 1))]
    capabilities: Vec<SourceCapability>,
    expected_lifecycle: Vec<SourceLifecycleEvent>,
    ordering: OrderingCapability,
    samples: bool,
    redaction_profile_ref: String,
    redacted_fields: Vec<String>,
    #[schemars(length(min = 1))]
    privacy_capabilities: Vec<PrivacyCapability>,
}

impl SourceManifest {
    /// Return the registered source identifier.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Return the declared source capabilities.
    pub fn capabilities(&self) -> &[SourceCapability] {
        &self.capabilities
    }

    /// Return the source-declared observation boundary.
    pub fn declared_boundary(&self) -> EvidenceBoundary {
        self.declared_boundary
    }

    /// Return payload representations the source is permitted to produce.
    pub fn privacy_capabilities(&self) -> &[PrivacyCapability] {
        &self.privacy_capabilities
    }

    /// Validate the source declaration without consulting runtime state.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.adapter_name, "adapter_name")?;
        validate_reference(&self.adapter_version, "adapter_version")?;
        validate_contract_identifier(&self.redaction_profile_ref, "redaction_profile_ref")?;
        let boundary_matches_source = matches!(
            (self.source_kind, self.declared_boundary),
            (SourceKind::SemanticHook, EvidenceBoundary::AgentHarness)
                | (SourceKind::SdkProcessor, EvidenceBoundary::InProcessSdk)
                | (SourceKind::ProtocolTap, EvidenceBoundary::ProtocolBoundary)
                | (
                    SourceKind::ProviderAdapter,
                    EvidenceBoundary::ProviderControlPlane
                )
                | (
                    SourceKind::RuntimeWitness,
                    EvidenceBoundary::CustomerControlledHost
                )
                | (
                    SourceKind::OutcomeVerifier,
                    EvidenceBoundary::IndependentOutcomeReadback
                )
        );
        if !boundary_matches_source {
            return Err(ContractError::InvalidField {
                field: "declared_boundary",
                reason: "must match the source integration boundary",
            });
        }
        if self.capabilities.is_empty() {
            return Err(ContractError::InvalidField {
                field: "capabilities",
                reason: "must declare at least one capability",
            });
        }
        reject_duplicates(&self.capabilities, "capabilities")?;
        reject_duplicates(&self.expected_lifecycle, "expected_lifecycle")?;
        if self.privacy_capabilities.is_empty()
            || !self
                .privacy_capabilities
                .contains(&PrivacyCapability::StructureOnly)
        {
            return Err(ContractError::InvalidField {
                field: "privacy_capabilities",
                reason: "must include structure_only",
            });
        }
        reject_duplicates(&self.privacy_capabilities, "privacy_capabilities")?;
        let mut redacted = BTreeSet::new();
        for field in &self.redacted_fields {
            validate_field_path(field)?;
            if !redacted.insert(field) {
                return Err(ContractError::DuplicateValue {
                    field: "redacted_fields",
                });
            }
        }
        if self.source_kind == SourceKind::OutcomeVerifier
            && !self
                .capabilities
                .contains(&SourceCapability::VerifiedOutcome)
        {
            return Err(ContractError::InvalidField {
                field: "capabilities",
                reason: "outcome_verifier must declare verified_outcome",
            });
        }
        Ok(())
    }
}

fn reject_duplicates<T: Ord>(values: &[T], field: &'static str) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ContractError::DuplicateValue { field });
        }
    }
    Ok(())
}

fn validate_field_path(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(ContractError::InvalidField {
            field: "redacted_fields",
            reason: "must contain safe dotted field paths",
        });
    }
    Ok(())
}

impl<'de> Deserialize<'de> for SourceManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            source_id: SourceId,
            source_kind: SourceKind,
            declared_boundary: EvidenceBoundary,
            adapter_name: String,
            adapter_version: String,
            environment: EnvironmentKind,
            capabilities: Vec<SourceCapability>,
            expected_lifecycle: Vec<SourceLifecycleEvent>,
            ordering: OrderingCapability,
            samples: bool,
            redaction_profile_ref: String,
            redacted_fields: Vec<String>,
            privacy_capabilities: Vec<PrivacyCapability>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            source_id: wire.source_id,
            source_kind: wire.source_kind,
            declared_boundary: wire.declared_boundary,
            adapter_name: wire.adapter_name,
            adapter_version: wire.adapter_version,
            environment: wire.environment,
            capabilities: wire.capabilities,
            expected_lifecycle: wire.expected_lifecycle,
            ordering: wire.ordering,
            samples: wire.samples,
            redaction_profile_ref: wire.redaction_profile_ref,
            redacted_fields: wire.redacted_fields,
            privacy_capabilities: wire.privacy_capabilities,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Server-accepted source registration facts.
///
/// A source may declare its capabilities and boundary in `SourceManifest`, but
/// only the accepting control plane assigns the effective trust profile and
/// organization scope represented here.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RegisteredSource {
    manifest: SourceManifest,
    effective_trust_profile: TrustProfile,
}

impl RegisteredSource {
    /// Return the source-supplied, validated manifest.
    pub fn manifest(&self) -> &SourceManifest {
        &self.manifest
    }

    /// Return the trust profile assigned by the accepting control plane.
    pub fn effective_trust_profile(&self) -> TrustProfile {
        self.effective_trust_profile
    }

    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        self.manifest.validate()
    }
}

impl<'de> Deserialize<'de> for RegisteredSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            manifest: SourceManifest,
            effective_trust_profile: TrustProfile,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            manifest: wire.manifest,
            effective_trust_profile: wire.effective_trust_profile,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

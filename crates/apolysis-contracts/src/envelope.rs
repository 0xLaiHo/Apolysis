// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    id::{validate_contract_identifier, validate_reference},
    ContractError, RunId, SchemaVersion, SourceId, TrustProfile, TypedEvidencePayload,
};

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Time basis supplied by an Evidence Source.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockBasis {
    /// Source wall clock.
    WallClock,
    /// A monotonic clock converted to wall time by the source.
    MonotonicConverted,
    /// A vendor or external provider clock.
    ProviderClock,
}

/// Source-observed time and its known uncertainty.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct ObservedTime {
    #[schemars(range(min = 1))]
    unix_ms: u64,
    clock_basis: ClockBasis,
    uncertainty_ms: Option<u64>,
}

impl ObservedTime {
    /// Return the source-declared clock basis.
    pub fn clock_basis(&self) -> ClockBasis {
        self.clock_basis
    }

    /// Return the reported Unix timestamp in milliseconds.
    pub fn unix_ms(&self) -> u64 {
        self.unix_ms
    }

    /// Return the known clock uncertainty; absence means unknown, not zero.
    pub fn uncertainty_ms(&self) -> Option<u64> {
        self.uncertainty_ms
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "observed_at.unix_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ObservedTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            unix_ms: u64,
            clock_basis: ClockBasis,
            uncertainty_ms: Option<u64>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            unix_ms: wire.unix_ms,
            clock_basis: wire.clock_basis,
            uncertainty_ms: wire.uncertainty_ms,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Explicit identifiers supplied for correlation; absence is never invented.
#[derive(schemars::JsonSchema, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationRefs {
    /// Distributed trace identity, when supplied.
    pub trace_ref: Option<String>,
    /// Distributed trace span identity, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_ref: Option<String>,
    /// Agent or delegate identity, when supplied.
    pub agent_ref: Option<String>,
    /// Agent turn identity, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_ref: Option<String>,
    /// Delegation identity, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
    /// Tool-call, MCP call, or A2A task identity, when supplied.
    pub tool_ref: Option<String>,
    /// MCP or A2A task identity, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_ref: Option<String>,
    /// Process, container, Pod, VM, runner, or provider workload identity.
    pub runtime_ref: Option<String>,
    /// Provider-native session, job, or audit identity, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
    /// Outcome artifact identity, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// Repository identity, when supplied by a hook, CI, or provider source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_ref: Option<String>,
}

impl CorrelationRefs {
    fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("correlation.trace_ref", self.trace_ref.as_deref()),
            ("correlation.span_ref", self.span_ref.as_deref()),
            ("correlation.agent_ref", self.agent_ref.as_deref()),
            ("correlation.turn_ref", self.turn_ref.as_deref()),
            ("correlation.delegation_ref", self.delegation_ref.as_deref()),
            ("correlation.tool_ref", self.tool_ref.as_deref()),
            ("correlation.task_ref", self.task_ref.as_deref()),
            ("correlation.runtime_ref", self.runtime_ref.as_deref()),
            ("correlation.provider_ref", self.provider_ref.as_deref()),
            ("correlation.artifact_ref", self.artifact_ref.as_deref()),
            ("correlation.repository_ref", self.repository_ref.as_deref()),
        ] {
            if let Some(value) = value {
                validate_contract_identifier(value, field)?;
            }
        }
        Ok(())
    }
}

/// Loss, redaction, and content indicators carried by a source contribution.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFlags {
    /// The source reports missing or dropped evidence relevant to this item.
    pub loss_detected: bool,
    /// At least one source field was redacted before transmission.
    pub redacted: bool,
    /// The body contains authorized content rather than structure only.
    pub contains_content: bool,
}

/// Immutable reference to separately authorized evidence content.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct EvidenceObjectRef {
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    object_id: String,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    sha256: String,
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    size_bytes: u64,
}

impl EvidenceObjectRef {
    /// Construct an immutable object reference after validating its opaque
    /// identity, digest, and I-JSON-safe positive size.
    pub fn new(
        object_id: impl Into<String>,
        sha256: impl Into<String>,
        size_bytes: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            object_id: object_id.into(),
            sha256: sha256.into(),
            size_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    /// Borrow the opaque object identity. Possession does not authorize access.
    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    /// Borrow the immutable object digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Return the declared object size.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.object_id, "object_ref.object_id")?;
        validate_sha256(&self.sha256, "object_ref.sha256")?;
        if self.size_bytes == 0 || self.size_bytes > MAX_IJSON_INTEGER {
            return Err(ContractError::InvalidField {
                field: "object_ref.size_bytes",
                reason: "must be a positive I-JSON-safe integer",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for EvidenceObjectRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            object_id: String,
            sha256: String,
            size_bytes: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            object_id: wire.object_id,
            sha256: wire.sha256,
            size_bytes: wire.size_bytes,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// A source-supplied evidence contribution before server acceptance.
///
/// Organization scope, effective trust, ingest order, and ingest time are not
/// accepted from the source; they are present only in `AcceptedSourceEnvelope`.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct SourceEnvelope {
    schema_version: SchemaVersion,
    run_id: RunId,
    source_id: SourceId,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    source_stream_id: String,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    source_event_id: String,
    #[schemars(range(min = 1))]
    source_sequence: u64,
    observed_at: ObservedTime,
    correlation: CorrelationRefs,
    flags: EvidenceFlags,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    payload_type: String,
    #[schemars(length(min = 1, max = 512))]
    payload_version: String,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    payload_digest: String,
    inline_payload: Option<TypedEvidencePayload>,
    object_ref: Option<EvidenceObjectRef>,
}

impl SourceEnvelope {
    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the source-local sequence, which begins at one per stream.
    pub fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    /// Return the source identifier asserted by this contribution.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Return the run identifier asserted by this contribution.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the source-local stream identity.
    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    /// Return the idempotent source event identity.
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    /// Return source-observed time and uncertainty.
    pub fn observed_at(&self) -> &ObservedTime {
        &self.observed_at
    }

    /// Return explicitly supplied correlation identifiers.
    pub fn correlation(&self) -> &CorrelationRefs {
        &self.correlation
    }

    /// Return source-declared loss, redaction, and content flags.
    pub fn flags(&self) -> EvidenceFlags {
        self.flags
    }

    /// Return the typed payload discriminator.
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    /// Return the source payload contract version.
    pub fn payload_version(&self) -> &str {
        &self.payload_version
    }

    /// Return a structure-only inline payload when one was accepted.
    pub fn inline_payload(&self) -> Option<&TypedEvidencePayload> {
        self.inline_payload.as_ref()
    }

    /// Borrow the source-supplied integrity digest for the selected payload.
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    /// Return an immutable authorized object reference when selected.
    pub fn object_ref(&self) -> Option<&EvidenceObjectRef> {
        self.object_ref.as_ref()
    }

    /// Validate source-controlled fields without assigning server facts.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.source_stream_id, "source_stream_id")?;
        validate_contract_identifier(&self.source_event_id, "source_event_id")?;
        if self.source_sequence == 0 {
            return Err(ContractError::InvalidField {
                field: "source_sequence",
                reason: "must begin at one",
            });
        }
        self.observed_at.validate()?;
        self.correlation.validate()?;
        validate_contract_identifier(&self.payload_type, "payload_type")?;
        validate_reference(&self.payload_version, "payload_version")?;
        validate_sha256(&self.payload_digest, "payload_digest")?;
        match (&self.inline_payload, &self.object_ref) {
            (Some(payload), None) => {
                if self.payload_version != "0.1" {
                    return Err(ContractError::InvalidField {
                        field: "payload_version",
                        reason: "typed inline payloads must use version 0.1",
                    });
                }
                if self.payload_type != payload.evidence_type() {
                    return Err(ContractError::InvalidField {
                        field: "payload_type",
                        reason: "must match the typed inline evidence discriminator",
                    });
                }
                if self.flags.contains_content {
                    return Err(ContractError::InvalidField {
                        field: "flags.contains_content",
                        reason: "typed inline payloads are structure-only",
                    });
                }
            }
            (None, Some(object_ref)) => {
                object_ref.validate()?;
                if !self.flags.contains_content {
                    return Err(ContractError::InvalidField {
                        field: "flags.contains_content",
                        reason: "object references identify explicitly authorized content",
                    });
                }
                if self.payload_digest != object_ref.sha256 {
                    return Err(ContractError::InvalidField {
                        field: "payload_digest",
                        reason: "must match the immutable object digest",
                    });
                }
            }
            _ => return Err(ContractError::PayloadRepresentation),
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for SourceEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            run_id: RunId,
            source_id: SourceId,
            source_stream_id: String,
            source_event_id: String,
            source_sequence: u64,
            observed_at: ObservedTime,
            correlation: CorrelationRefs,
            flags: EvidenceFlags,
            payload_type: String,
            payload_version: String,
            payload_digest: String,
            inline_payload: Option<TypedEvidencePayload>,
            object_ref: Option<EvidenceObjectRef>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            source_id: wire.source_id,
            source_stream_id: wire.source_stream_id,
            source_event_id: wire.source_event_id,
            source_sequence: wire.source_sequence,
            observed_at: wire.observed_at,
            correlation: wire.correlation,
            flags: wire.flags,
            payload_type: wire.payload_type,
            payload_version: wire.payload_version,
            payload_digest: wire.payload_digest,
            inline_payload: wire.inline_payload,
            object_ref: wire.object_ref,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Effective trust assigned to an unchanged source item after acceptance.
///
/// Organization, run, ingest position, and ingest time remain exclusively on
/// the enclosing `AgentExecutionRecordItem`.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct AcceptedSourceEnvelope {
    source_registration_id: String,
    source_stream_id: String,
    #[schemars(range(min = 1))]
    registration_policy_revision: u64,
    effective_trust_profile: TrustProfile,
    manifest_version: SchemaVersion,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    manifest_digest: String,
    envelope: SourceEnvelope,
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidField {
            field,
            reason: "must be a lowercase 64-character SHA-256 digest",
        });
    }
    Ok(())
}

impl AcceptedSourceEnvelope {
    /// Construct validated server acceptance facts around an unchanged envelope.
    pub fn new(
        source_registration_id: impl Into<String>,
        source_stream_id: impl Into<String>,
        registration_policy_revision: u64,
        effective_trust_profile: TrustProfile,
        manifest_version: SchemaVersion,
        manifest_digest: impl Into<String>,
        envelope: SourceEnvelope,
    ) -> Result<Self, ContractError> {
        let value = Self {
            source_registration_id: source_registration_id.into(),
            source_stream_id: source_stream_id.into(),
            registration_policy_revision,
            effective_trust_profile,
            manifest_version,
            manifest_digest: manifest_digest.into(),
            envelope,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the server-resolved registration that submitted this envelope.
    pub fn source_registration_id(&self) -> &str {
        &self.source_registration_id
    }

    /// Return the server-accepted stream scope for this envelope.
    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    /// Return the control-plane policy revision frozen for this stream.
    pub fn registration_policy_revision(&self) -> u64 {
        self.registration_policy_revision
    }

    /// Return the original validated source contribution.
    pub fn envelope(&self) -> &SourceEnvelope {
        &self.envelope
    }

    /// Return the server-assigned effective trust for this contribution.
    pub fn effective_trust_profile(&self) -> TrustProfile {
        self.effective_trust_profile
    }

    /// Return the manifest wire version used during acceptance.
    pub fn manifest_version(&self) -> SchemaVersion {
        self.manifest_version
    }

    /// Return the immutable manifest digest used during acceptance.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.source_registration_id, "source_registration_id")?;
        validate_contract_identifier(&self.source_stream_id, "source_stream_id")?;
        if self.registration_policy_revision == 0 {
            return Err(ContractError::InvalidField {
                field: "registration_policy_revision",
                reason: "must be greater than zero",
            });
        }
        validate_sha256(&self.manifest_digest, "manifest_digest")?;
        self.envelope.validate()?;
        if self.source_stream_id != self.envelope.source_stream_id() {
            return Err(ContractError::InvalidField {
                field: "source_stream_id",
                reason: "server stream scope must match the accepted envelope",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AcceptedSourceEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            source_registration_id: String,
            source_stream_id: String,
            registration_policy_revision: u64,
            effective_trust_profile: TrustProfile,
            manifest_version: SchemaVersion,
            manifest_digest: String,
            envelope: SourceEnvelope,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            source_registration_id: wire.source_registration_id,
            source_stream_id: wire.source_stream_id,
            registration_policy_revision: wire.registration_policy_revision,
            effective_trust_profile: wire.effective_trust_profile,
            manifest_version: wire.manifest_version,
            manifest_digest: wire.manifest_digest,
            envelope: wire.envelope,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

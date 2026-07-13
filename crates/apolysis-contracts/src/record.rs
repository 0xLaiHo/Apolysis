// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    AcceptedSourceEnvelope, ContractError, CoverageSummary, OrganizationId, RegisteredSource,
    RunDescriptor, RunId, RunStateTransition, SchemaVersion,
};

/// The typed fact retained in one append-oriented record item.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "fact_type", content = "fact", rename_all = "snake_case")]
pub enum AgentExecutionRecordFact {
    /// Immutable run opening identity and boundary.
    RunOpened(Box<RunDescriptor>),
    /// One legal lifecycle transition.
    RunStateChanged(RunStateTransition),
    /// Server-accepted source registration and effective trust.
    SourceRegistered(Box<RegisteredSource>),
    /// Source evidence after acceptance and effective-trust assignment.
    EvidenceAccepted(Box<AcceptedSourceEnvelope>),
    /// A rebuildable server-side coverage computation.
    CoverageComputed(Box<CoverageSummary>),
}

impl<'de> Deserialize<'de> for AgentExecutionRecordFact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(tag = "fact_type", content = "fact", rename_all = "snake_case")]
        enum Wire {
            RunOpened(Box<RunDescriptor>),
            RunStateChanged(RunStateTransition),
            SourceRegistered(Box<RegisteredSource>),
            EvidenceAccepted(Box<AcceptedSourceEnvelope>),
            CoverageComputed(Box<CoverageSummary>),
        }

        Ok(match Wire::deserialize(deserializer)? {
            Wire::RunOpened(value) => Self::RunOpened(value),
            Wire::RunStateChanged(value) => Self::RunStateChanged(value),
            Wire::SourceRegistered(value) => Self::SourceRegistered(value),
            Wire::EvidenceAccepted(value) => Self::EvidenceAccepted(value),
            Wire::CoverageComputed(value) => Self::CoverageComputed(value),
        })
    }
}

/// One bounded, independently consumable append item for an Agent Run.
///
/// This is the public storage/stream seam. It intentionally does not expose an
/// unbounded whole-run snapshot.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct AgentExecutionRecordItem {
    schema_version: SchemaVersion,
    organization_id: OrganizationId,
    run_id: RunId,
    #[schemars(range(min = 1))]
    ingest_sequence: u64,
    #[schemars(range(min = 1))]
    ingested_at_unix_ms: u64,
    fact: AgentExecutionRecordFact,
}

impl AgentExecutionRecordItem {
    /// Return the organization scope assigned at acceptance.
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Return the Agent Run scope assigned at acceptance.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the durable append position assigned by the accepting plane.
    pub fn ingest_sequence(&self) -> u64 {
        self.ingest_sequence
    }

    /// Return the typed fact without changing its trust level.
    pub fn fact(&self) -> &AgentExecutionRecordFact {
        &self.fact
    }

    /// Validate server facts and any source-asserted scope inside the fact.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.ingest_sequence == 0 {
            return Err(ContractError::InvalidField {
                field: "ingest_sequence",
                reason: "must begin at one",
            });
        }
        if self.ingested_at_unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "ingested_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        match &self.fact {
            AgentExecutionRecordFact::RunOpened(descriptor) => {
                if descriptor.organization_id() != &self.organization_id
                    || descriptor.run_id() != &self.run_id
                {
                    return Err(ContractError::InvalidField {
                        field: "fact.run_opened",
                        reason: "scope assertion must match accepted item scope",
                    });
                }
            }
            AgentExecutionRecordFact::RunStateChanged(transition) => transition.validate()?,
            AgentExecutionRecordFact::SourceRegistered(source) => source.validate()?,
            AgentExecutionRecordFact::EvidenceAccepted(accepted) => {
                if accepted.envelope().run_id() != &self.run_id {
                    return Err(ContractError::InvalidField {
                        field: "fact.evidence_accepted.envelope.run_id",
                        reason: "scope assertion must match accepted item scope",
                    });
                }
            }
            AgentExecutionRecordFact::CoverageComputed(summary) => summary.validate()?,
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AgentExecutionRecordItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            organization_id: OrganizationId,
            run_id: RunId,
            ingest_sequence: u64,
            ingested_at_unix_ms: u64,
            fact: AgentExecutionRecordFact,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            organization_id: wire.organization_id,
            run_id: wire.run_id,
            ingest_sequence: wire.ingest_sequence,
            ingested_at_unix_ms: wire.ingested_at_unix_ms,
            fact: wire.fact,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

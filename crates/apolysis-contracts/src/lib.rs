// SPDX-License-Identifier: Apache-2.0

//! Versioned Agent Execution Record contracts.
//!
//! This crate is deliberately independent from the legacy JSONL v1 types. It
//! owns validated wire types only; persistence, Gateway, projection, and Query
//! behavior belong to later layers.

mod coverage;
mod envelope;
mod error;
mod evidence;
mod gateway;
mod id;
mod query;
mod record;
mod run;
mod schema;
mod source;
mod version;

pub use coverage::{
    ComputedCoverage, CoverageReasonCode, CoverageSummary, ExecutionCoverageState,
    OutcomeComparisonState, OutcomeCoverageState, SemanticCoverageState,
};
pub use envelope::{
    AcceptedSourceEnvelope, ClockBasis, CorrelationRefs, EvidenceFlags, EvidenceObjectRef,
    ObservedTime, SourceEnvelope,
};
pub use error::ContractError;
pub use evidence::*;
pub use gateway::*;
pub use id::{OrganizationId, RunId, SourceId};
pub use query::*;
pub use record::{AgentExecutionRecordFact, AgentExecutionRecordItem};
pub use run::{
    AuthorityKind, AuthorityRef, EnvironmentKind, PrincipalKind, PrincipalRef, RunDescriptor,
    RunState, RunStateTransition,
};
pub use schema::contract_schemas;
pub use source::{
    EvidenceBoundary, OrderingCapability, PrivacyCapability, RegisteredSource, SourceCapability,
    SourceKind, SourceLifecycleEvent, SourceManifest, TrustProfile,
};
pub use version::SchemaVersion;

// SPDX-License-Identifier: Apache-2.0

//! Accountability contracts shared by the node daemon and runtime adapters.

mod finding;
mod health;
mod intent;
mod projection;
mod queue;
mod session;

pub use finding::{
    AccountabilityAnalyzer, AccountabilityFinding, EffectKind, EvidenceBoundary, FindingDecision,
    FindingKind, ObservedEffect, RuntimeIdentity, FINDING_SCHEMA_V1,
};
pub use health::{AdapterKind, ComponentState, HealthSnapshot};
pub use intent::{
    decode_intent_frame, ActionClass, IntentError, IntentRequest, ResourceKind, ResourceSelector,
    RetentionTier, RuntimeSelector, SessionIntent, WorkloadSelector, DEFAULT_TENANT_ID,
    INTENT_SCHEMA_V1, MAX_INTENT_FRAME_BYTES,
};
pub use projection::{
    project_agent_run, validate_agent_observation_record_v1, AgentObservationRecord,
    AgentObservationRecordValidationError, AgentObservationSummary, AgentRunRecordBatch,
    CollectorHealthProjection, CollectorLifecycleHealth, CollectorLifecycleState,
    CollectorStopReason, EvidenceState, ObservationRecordSourceIntegrity, ProjectedCapability,
    ProjectedCapabilityManifest, ProjectedCollectorLifecycle, ProjectedFinding,
    ProjectedLifecycleCounters, ProjectedObservationGap, ProjectedRuntimeIdentity,
    ProjectedRuntimeObservation, ProjectionError, ProjectionIssue, ProjectionIssueCode,
    ReviewState, AGENT_OBSERVATION_RECORD_SCHEMA_V1, MAX_AGENT_RUN_PROJECTION_BATCHES,
    MAX_AGENT_RUN_PROJECTION_RECORDS,
};
pub use queue::{BoundedPriorityQueue, PushOutcome, QueuePriority, QueueStats};
pub use session::{
    AssociationOutcome, RegisterOutcome, RegistryError, RetentionPurgeReport, SessionRegistry,
    SessionState, SessionStatus,
};

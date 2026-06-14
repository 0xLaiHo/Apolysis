// SPDX-License-Identifier: Apache-2.0

//! Accountability contracts shared by the node daemon and runtime adapters.

mod finding;
mod health;
mod intent;
mod queue;
mod session;

pub use finding::{
    AccountabilityAnalyzer, AccountabilityFinding, EffectKind, EvidenceBoundary, FindingDecision,
    FindingKind, ObservedEffect, RuntimeIdentity, FINDING_SCHEMA_V1,
};
pub use health::{AdapterKind, ComponentState, HealthSnapshot};
pub use intent::{
    decode_intent_frame, ActionClass, IntentError, IntentRequest, ResourceKind, ResourceSelector,
    RuntimeSelector, SessionIntent, WorkloadSelector, INTENT_SCHEMA_V1, MAX_INTENT_FRAME_BYTES,
};
pub use queue::{BoundedPriorityQueue, PushOutcome, QueuePriority, QueueStats};
pub use session::{
    AssociationOutcome, RegisterOutcome, RegistryError, SessionRegistry, SessionState,
    SessionStatus,
};

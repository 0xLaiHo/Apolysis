// SPDX-License-Identifier: Apache-2.0

//! Content-off typed evidence payloads for the v0.1 source boundary.

use std::num::NonZeroU64;

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{
    id::validate_contract_identifier, ContractError, OutcomeComparisonState, SourceCapability,
};

/// An opaque reference carried instead of prompts, responses, arguments, or bodies.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EvidenceRef(
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    String,
);

impl EvidenceRef {
    /// Borrow the opaque reference value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EvidenceRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        validate_contract_identifier(&value, "evidence_ref").map_err(de::Error::custom)?;
        Ok(Self(value))
    }
}

/// Bounded outcome vocabulary shared by attempted operations.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    /// The operation reached its requested terminal state.
    Succeeded,
    /// The operation ran but did not reach its requested terminal state.
    Failed,
    /// Policy or an enforcement point prevented the operation.
    Denied,
    /// The operation has not reached a terminal state.
    Pending,
    /// Available evidence does not establish the operation result.
    Unknown,
}

/// Agent lifecycle event names exposed by the structure-only contract.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleEvent {
    /// An agent identity was allocated.
    Spawned,
    /// The agent began work.
    Started,
    /// The agent was suspended.
    Suspended,
    /// A suspended agent resumed.
    Resumed,
    /// The agent reported completion.
    Completed,
    /// The agent reported a failure.
    Failed,
    /// The agent was cancelled.
    Cancelled,
}

/// A content-off agent lifecycle observation.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleBody {
    agent_ref: EvidenceRef,
    supervisor_agent_ref: Option<EvidenceRef>,
    event: AgentLifecycleEvent,
    outcome: OperationOutcome,
}

/// Delegation lifecycle event names.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationLifecycleEvent {
    /// Delegation was requested.
    Requested,
    /// The delegate accepted the work.
    Accepted,
    /// The delegate reported completion.
    Completed,
    /// The delegate reported failure.
    Failed,
    /// Delegated work was cancelled.
    Cancelled,
}

/// A content-off delegation relationship and lifecycle observation.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLifecycleBody {
    delegation_ref: EvidenceRef,
    delegator_agent_ref: EvidenceRef,
    delegate_agent_ref: EvidenceRef,
    task_ref: EvidenceRef,
    event: DelegationLifecycleEvent,
    outcome: OperationOutcome,
}

/// Allowlisted tool capability classes.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    /// Process creation or control.
    Process,
    /// File or filesystem access.
    File,
    /// Network access.
    Network,
    /// Browser or UI automation.
    Browser,
    /// Database access.
    Database,
    /// Messaging or collaboration system access.
    Messaging,
    /// Identity or credential boundary access.
    Identity,
    /// Workload or infrastructure control.
    Workload,
}

/// Tool interaction lifecycle events.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionEvent {
    /// The interaction was requested but not observed running.
    Requested,
    /// The interaction began.
    Started,
    /// The interaction reached a terminal observation.
    Completed,
}

/// A tool interaction without raw arguments or results.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInteractionBody {
    interaction_ref: EvidenceRef,
    agent_ref: EvidenceRef,
    tool_ref: EvidenceRef,
    capability: ToolCapability,
    event: InteractionEvent,
    request_ref: Option<EvidenceRef>,
    response_ref: Option<EvidenceRef>,
    outcome: OperationOutcome,
}

/// Agent protocol families supported in v0.1.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProtocol {
    /// Model Context Protocol.
    Mcp,
    /// Agent-to-Agent protocol.
    A2a,
}

/// Allowlisted protocol operations; they carry no request or response body.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolOperation {
    /// Invoke an MCP tool.
    ToolCall,
    /// Read an MCP resource.
    ResourceRead,
    /// Resolve an MCP prompt template by reference.
    PromptTemplate,
    /// Submit an A2A task.
    TaskSubmit,
    /// Observe or publish an A2A task update.
    TaskUpdate,
    /// Exchange an artifact reference without artifact content.
    ArtifactReference,
    /// Exchange a message reference without message content.
    MessageReference,
}

/// An MCP or A2A interaction represented only by identities and metadata.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct ProtocolInteractionBody {
    interaction_ref: EvidenceRef,
    agent_ref: EvidenceRef,
    protocol: AgentProtocol,
    peer_ref: EvidenceRef,
    operation: ProtocolOperation,
    request_ref: Option<EvidenceRef>,
    response_ref: Option<EvidenceRef>,
    outcome: OperationOutcome,
}

impl ProtocolInteractionBody {
    /// Return the protocol family whose capability must be registered.
    pub fn protocol(&self) -> AgentProtocol {
        self.protocol
    }

    fn validate(&self) -> Result<(), ContractError> {
        let valid = matches!(
            (self.protocol, self.operation),
            (
                AgentProtocol::Mcp,
                ProtocolOperation::ToolCall
                    | ProtocolOperation::ResourceRead
                    | ProtocolOperation::PromptTemplate
            ) | (
                AgentProtocol::A2a,
                ProtocolOperation::TaskSubmit
                    | ProtocolOperation::TaskUpdate
                    | ProtocolOperation::ArtifactReference
                    | ProtocolOperation::MessageReference
            )
        );
        if !valid {
            return Err(ContractError::InvalidField {
                field: "protocol.operation",
                reason: "protocol operation must belong to the declared protocol",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ProtocolInteractionBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            interaction_ref: EvidenceRef,
            agent_ref: EvidenceRef,
            protocol: AgentProtocol,
            peer_ref: EvidenceRef,
            operation: ProtocolOperation,
            request_ref: Option<EvidenceRef>,
            response_ref: Option<EvidenceRef>,
            outcome: OperationOutcome,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            interaction_ref: wire.interaction_ref,
            agent_ref: wire.agent_ref,
            protocol: wire.protocol,
            peer_ref: wire.peer_ref,
            operation: wire.operation,
            request_ref: wire.request_ref,
            response_ref: wire.response_ref,
            outcome: wire.outcome,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Policy evaluation decisions.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    /// Policy permits the subject operation.
    Allow,
    /// Policy denies the subject operation.
    Deny,
    /// A separate approval is required before actuation.
    RequireApproval,
    /// The policy does not apply to the subject.
    NotApplicable,
    /// The source cannot establish a decision.
    Unknown,
}

/// Stable, content-free policy reason classes.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasonCode {
    /// An explicit rule matched.
    MatchedRule,
    /// The policy default determined the decision.
    DefaultRule,
    /// A human approval determined the decision.
    HumanApproval,
    /// The subject request was structurally invalid.
    InvalidRequest,
    /// Evidence was insufficient to decide.
    InsufficientContext,
    /// The policy service was unavailable.
    PolicyUnavailable,
}

/// A policy decision kept separate from any enforcement report.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionBody {
    decision_ref: EvidenceRef,
    policy_ref: EvidenceRef,
    subject_ref: EvidenceRef,
    decision: PolicyDecisionKind,
    reason_code: PolicyReasonCode,
    basis_ref: Option<EvidenceRef>,
}

/// Allowlisted actions an enforcement point can report.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActuationAction {
    /// Permit the subject operation to continue.
    Allow,
    /// Prevent the subject operation.
    Block,
    /// Terminate an already-running subject.
    Terminate,
    /// Isolate the subject from a boundary.
    Isolate,
    /// Apply a narrower capability or resource limit.
    Restrict,
    /// Emit a notification without changing execution.
    Notify,
}

/// A report of actuation tied to the policy decision that requested it.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActuationReportBody {
    actuation_ref: EvidenceRef,
    decision_ref: EvidenceRef,
    actuator_ref: EvidenceRef,
    subject_ref: EvidenceRef,
    action: ActuationAction,
    outcome: OperationOutcome,
}

/// Runtime effect classes visible without retaining raw values.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEffectKind {
    /// Process lifecycle or control effect.
    Process,
    /// File or filesystem effect.
    File,
    /// Network effect.
    Network,
    /// Identity or credential boundary effect.
    Identity,
    /// Container, Pod, VM, or infrastructure effect.
    Workload,
}

/// A host or managed-runtime effect represented by opaque identities.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEffectBody {
    effect_ref: EvidenceRef,
    runtime_ref: EvidenceRef,
    effect_kind: RuntimeEffectKind,
    target_ref: Option<EvidenceRef>,
    outcome: OperationOutcome,
}

impl RuntimeEffectBody {
    /// Return the runtime capability required for this effect.
    pub fn effect_kind(&self) -> RuntimeEffectKind {
        self.effect_kind
    }
}

/// Allowlisted claim classes.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeClaimKind {
    /// The assigned task completed.
    TaskCompleted,
    /// A referenced test run passed.
    TestsPassed,
    /// A referenced artifact was created.
    ArtifactCreated,
    /// A referenced external state changed.
    StateChanged,
    /// A referenced deployment completed.
    DeploymentCompleted,
}

/// An agent or provider outcome claim without prose or result content.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeClaimBody {
    claim_ref: EvidenceRef,
    claimant_ref: EvidenceRef,
    subject_ref: EvidenceRef,
    claim_type: OutcomeClaimKind,
    basis_ref: Option<EvidenceRef>,
    outcome: OperationOutcome,
}

/// An independent comparison of an outcome claim with an opaque observation.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeVerificationBody {
    verification_ref: EvidenceRef,
    claim_ref: EvidenceRef,
    verifier_ref: EvidenceRef,
    observation_ref: EvidenceRef,
    comparison: OutcomeComparisonState,
    outcome: OperationOutcome,
}

/// Stable source diagnostic classes.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDiagnosticKind {
    /// The source started a stream.
    Started,
    /// The source reported liveness.
    Heartbeat,
    /// The source detected missing evidence.
    LossDetected,
    /// The source enabled sampling.
    SamplingEnabled,
    /// The source truncated evidence.
    EvidenceTruncated,
    /// The source failed.
    Failed,
    /// The source recovered after a failure.
    Recovered,
    /// The source ended a stream.
    Finished,
}

/// Source diagnostic severity.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational source state.
    Info,
    /// A gap or degraded source state.
    Warning,
    /// A source failure that prevents expected evidence.
    Error,
}

/// A source-health observation without logs or captured content.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDiagnosticBody {
    diagnostic_ref: EvidenceRef,
    source_ref: EvidenceRef,
    kind: SourceDiagnosticKind,
    severity: DiagnosticSeverity,
    related_event_ref: Option<EvidenceRef>,
    affected_count: Option<NonZeroU64>,
}

/// Every structure-only v0.1 payload body accepted by the typed evidence seam.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "evidence_type", content = "body", rename_all = "snake_case")]
pub enum TypedEvidencePayload {
    /// Agent lifecycle evidence.
    AgentLifecycle(AgentLifecycleBody),
    /// Delegation lifecycle evidence.
    DelegationLifecycle(DelegationLifecycleBody),
    /// Tool interaction evidence.
    ToolInteraction(ToolInteractionBody),
    /// MCP or A2A protocol interaction evidence.
    ProtocolInteraction(ProtocolInteractionBody),
    /// Policy decision evidence.
    PolicyDecision(PolicyDecisionBody),
    /// Policy actuation evidence.
    ActuationReport(ActuationReportBody),
    /// Runtime effect evidence.
    RuntimeEffect(RuntimeEffectBody),
    /// Claimed outcome evidence.
    OutcomeClaim(OutcomeClaimBody),
    /// Independently verified outcome evidence.
    OutcomeVerification(OutcomeVerificationBody),
    /// Source health and loss evidence.
    SourceDiagnostic(SourceDiagnosticBody),
}

impl TypedEvidencePayload {
    /// Return the stable v0.1 payload discriminator.
    pub fn evidence_type(&self) -> &'static str {
        match self {
            Self::AgentLifecycle(_) => "agent_lifecycle",
            Self::DelegationLifecycle(_) => "delegation_lifecycle",
            Self::ToolInteraction(_) => "tool_interaction",
            Self::ProtocolInteraction(_) => "protocol_interaction",
            Self::PolicyDecision(_) => "policy_decision",
            Self::ActuationReport(_) => "actuation_report",
            Self::RuntimeEffect(_) => "runtime_effect",
            Self::OutcomeClaim(_) => "outcome_claim",
            Self::OutcomeVerification(_) => "outcome_verification",
            Self::SourceDiagnostic(_) => "source_diagnostic",
        }
    }

    /// Return the operation outcome when the evidence type carries one.
    pub fn operation_outcome(&self) -> Option<OperationOutcome> {
        match self {
            Self::AgentLifecycle(body) => Some(body.outcome),
            Self::DelegationLifecycle(body) => Some(body.outcome),
            Self::ToolInteraction(body) => Some(body.outcome),
            Self::ProtocolInteraction(body) => Some(body.outcome),
            Self::ActuationReport(body) => Some(body.outcome),
            Self::RuntimeEffect(body) => Some(body.outcome),
            Self::OutcomeClaim(body) => Some(body.outcome),
            Self::OutcomeVerification(body) => Some(body.outcome),
            Self::PolicyDecision(_) | Self::SourceDiagnostic(_) => None,
        }
    }

    /// Return the source capability required to submit this payload.
    ///
    /// Every accepted v0.1 evidence body has an explicit capability. Keeping
    /// policy decision, actuation, and identity evidence distinct prevents a
    /// source from gaining those powers through an unrelated tool or file
    /// capability.
    pub fn required_source_capability(&self) -> SourceCapability {
        match self {
            Self::AgentLifecycle(_) => SourceCapability::SemanticLifecycle,
            Self::DelegationLifecycle(_) => SourceCapability::Delegation,
            Self::ToolInteraction(_) => SourceCapability::ToolCalls,
            Self::ProtocolInteraction(body) => match body.protocol() {
                AgentProtocol::Mcp => SourceCapability::Mcp,
                AgentProtocol::A2a => SourceCapability::A2a,
            },
            Self::PolicyDecision(_) => SourceCapability::PolicyDecisions,
            Self::ActuationReport(_) => SourceCapability::PolicyActuation,
            Self::RuntimeEffect(body) => match body.effect_kind() {
                RuntimeEffectKind::Process => SourceCapability::Process,
                RuntimeEffectKind::File => SourceCapability::File,
                RuntimeEffectKind::Network => SourceCapability::Network,
                RuntimeEffectKind::Identity => SourceCapability::Identity,
                RuntimeEffectKind::Workload => SourceCapability::Workload,
            },
            Self::OutcomeClaim(_) => SourceCapability::ClaimedOutcome,
            Self::OutcomeVerification(_) => SourceCapability::VerifiedOutcome,
            Self::SourceDiagnostic(_) => SourceCapability::SourceHealth,
        }
    }
}

impl<'de> Deserialize<'de> for TypedEvidencePayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum EvidenceType {
            AgentLifecycle,
            DelegationLifecycle,
            ToolInteraction,
            ProtocolInteraction,
            PolicyDecision,
            ActuationReport,
            RuntimeEffect,
            OutcomeClaim,
            OutcomeVerification,
            SourceDiagnostic,
        }

        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            evidence_type: EvidenceType,
            body: Value,
        }

        let wire = Wire::deserialize(deserializer)?;
        macro_rules! decode_body {
            ($body:ty, $variant:ident) => {
                serde_json::from_value::<$body>(wire.body)
                    .map(Self::$variant)
                    .map_err(de::Error::custom)
            };
        }

        match wire.evidence_type {
            EvidenceType::AgentLifecycle => decode_body!(AgentLifecycleBody, AgentLifecycle),
            EvidenceType::DelegationLifecycle => {
                decode_body!(DelegationLifecycleBody, DelegationLifecycle)
            }
            EvidenceType::ToolInteraction => decode_body!(ToolInteractionBody, ToolInteraction),
            EvidenceType::ProtocolInteraction => {
                decode_body!(ProtocolInteractionBody, ProtocolInteraction)
            }
            EvidenceType::PolicyDecision => decode_body!(PolicyDecisionBody, PolicyDecision),
            EvidenceType::ActuationReport => decode_body!(ActuationReportBody, ActuationReport),
            EvidenceType::RuntimeEffect => decode_body!(RuntimeEffectBody, RuntimeEffect),
            EvidenceType::OutcomeClaim => decode_body!(OutcomeClaimBody, OutcomeClaim),
            EvidenceType::OutcomeVerification => {
                decode_body!(OutcomeVerificationBody, OutcomeVerification)
            }
            EvidenceType::SourceDiagnostic => {
                decode_body!(SourceDiagnosticBody, SourceDiagnostic)
            }
        }
    }
}

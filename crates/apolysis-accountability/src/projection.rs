// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{EvidenceBoundary, FindingDecision, FindingKind, RuntimeIdentity};

pub const AGENT_OBSERVATION_RECORD_SCHEMA_V1: u32 = 1;
pub const MAX_AGENT_RUN_PROJECTION_BATCHES: usize = 1024;
pub const MAX_AGENT_RUN_PROJECTION_RECORDS: u64 = 1_000_000;
const MAX_PROJECTION_STRING_BYTES: usize = 4096;
const MAX_PROJECTION_COLLECTION_ITEMS: usize = 1024;
const MAX_PROJECTION_OBJECT_FIELDS: usize = 256;
const MAX_PROJECTION_VALUE_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationRecordSourceIntegrity {
    UnverifiedPlainJsonl,
    VerifiedHashChain,
    Mixed,
}

#[derive(Clone, Debug)]
pub struct AgentRunRecordBatch {
    integrity: ObservationRecordSourceIntegrity,
    records: Vec<Value>,
}

impl AgentRunRecordBatch {
    pub fn plain(records: Vec<Value>) -> Self {
        Self {
            integrity: ObservationRecordSourceIntegrity::UnverifiedPlainJsonl,
            records,
        }
    }

    pub fn verified_hash_chain(records: Vec<Value>) -> Self {
        Self {
            integrity: ObservationRecordSourceIntegrity::VerifiedHashChain,
            records,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Active,
    Incomplete,
    Failed,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorHealthProjection {
    Healthy,
    Degraded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    RequiresReview,
    NoFindingsReported,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentObservationRecord {
    pub record_type: String,
    pub schema_version: u32,
    pub agent_run_id: String,
    pub source_integrity: ObservationRecordSourceIntegrity,
    pub summary: AgentObservationSummary,
    pub capability_manifests: Vec<ProjectedCapabilityManifest>,
    pub runtime_identities: Vec<ProjectedRuntimeIdentity>,
    pub runtime_observations: Vec<ProjectedRuntimeObservation>,
    pub collector_lifecycle: Vec<ProjectedCollectorLifecycle>,
    pub findings: Vec<ProjectedFinding>,
    pub observation_gaps: Vec<ProjectedObservationGap>,
    pub issues: Vec<ProjectionIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentObservationSummary {
    pub evidence_state: EvidenceState,
    pub collector_health: CollectorHealthProjection,
    pub review_state: ReviewState,
    pub runtime_observation_count: u64,
    pub runtime_identity_count: u64,
    pub finding_count: u64,
    pub observation_gap_record_count: u64,
    pub known_missing_observation_count: u64,
    pub unknown_history_boundary_count: u64,
    pub event_type_counts: BTreeMap<String, u64>,
    pub outcome_counts: BTreeMap<String, u64>,
    pub relation_counts: BTreeMap<String, u64>,
    pub finding_kind_counts: BTreeMap<String, u64>,
    pub gap_kind_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedCapabilityManifest {
    pub source_ordinal: u64,
    pub schema_version: u32,
    pub timestamp_unix_ms: u128,
    pub collector: String,
    pub collector_version: String,
    pub kernel_abi_version: u32,
    pub kernel_record_size: u32,
    pub observation_scope: String,
    pub privacy_profile: String,
    pub capabilities: Vec<ProjectedCapability>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedCapability {
    pub operation: String,
    pub event_sources: Vec<String>,
    pub outcomes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedLifecycleCounters {
    pub global_reserve_failures: u64,
    pub global_map_pressure: u64,
    pub global_abi_mismatches: u64,
    pub global_decode_failures: u64,
    pub global_truncations: u64,
    pub scope_missing_entries: u64,
    pub scope_missing_exits: u64,
    pub scope_pending: u64,
}

impl ProjectedLifecycleCounters {
    fn has_persistent_loss(self) -> bool {
        self.global_reserve_failures > 0
            || self.global_map_pressure > 0
            || self.global_abi_mismatches > 0
            || self.global_decode_failures > 0
            || self.global_truncations > 0
            || self.scope_missing_entries > 0
            || self.scope_missing_exits > 0
    }

    fn has_terminal_loss(self) -> bool {
        self.has_persistent_loss() || self.scope_pending > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedCollectorLifecycle {
    pub source_ordinal: u64,
    pub schema_version: u32,
    pub timestamp_unix_ms: u128,
    pub collector: String,
    pub collector_instance_id: String,
    pub state: String,
    pub health: String,
    pub stop_reason: Option<String>,
    pub counters: ProjectedLifecycleCounters,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedRuntimeIdentity {
    pub identity_id: String,
    pub host_boot_id: String,
    pub scope_generation: u64,
    pub pid: u32,
    pub process_generation: u64,
    pub process_start_time_ns: u64,
    pub exec_generation: u32,
    pub first_source_ordinal: u64,
    pub last_source_ordinal: u64,
    pub observation_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedRuntimeObservation {
    pub source_ordinal: u64,
    pub timestamp_unix_ms: u128,
    pub event_source: String,
    pub event_type: String,
    pub raw_event_id: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub outcome: Option<String>,
    pub return_value: Option<i64>,
    pub errno: Option<i32>,
    pub container_id: Option<String>,
    pub cgroup_id: Option<String>,
    pub relation_status: String,
    pub relation_reason: String,
    pub process_executable: Option<String>,
    pub process_started_at_unix_ms: Option<u128>,
    pub runtime_identity_id: Option<String>,
    pub parent_process_generation: Option<u64>,
    pub parent_exec_generation: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedFinding {
    pub source_ordinal: u64,
    pub schema_version: u32,
    pub kind: FindingKind,
    pub decision: FindingDecision,
    pub reason: String,
    pub evidence_ref: String,
    pub runtime: RuntimeIdentity,
    pub evidence_boundary: EvidenceBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectedObservationGap {
    pub source_ordinal: u64,
    pub schema_version: u32,
    pub timestamp_unix_ms: u128,
    pub operation: String,
    pub kind: String,
    pub count: u64,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionIssueCode {
    MissingCapability,
    MissingLifecycleStart,
    MissingLifecycleTerminal,
    InvalidLifecycle,
    CollectorLoss,
    CollectorDiagnostic,
    ObservationGap,
    UnsupportedObservation,
    UnsupportedOutcome,
    UnknownRecordType,
    SourceIntegrityFinding,
    NoRuntimeObservations,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectionIssue {
    pub code: ProjectionIssueCode,
    pub source_ordinal: Option<u64>,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    EmptyRun,
    MalformedRecord { ordinal: u64, field: &'static str },
    MixedAgentRuns { ordinal: u64 },
    ContentPolicyViolation { ordinal: u64 },
    InvalidLifecycle { ordinal: u64 },
    UnsupportedObservation { ordinal: u64 },
    ConflictingRuntimeIdentity { ordinal: u64 },
    DuplicateRuntimeObservation { ordinal: u64 },
    InputLimitExceeded { limit: &'static str },
    ArithmeticOverflow,
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRun => write!(formatter, "Agent Run projection input is empty"),
            Self::MalformedRecord { ordinal, field } => {
                write!(formatter, "record {ordinal} has invalid field {field}")
            }
            Self::MixedAgentRuns { ordinal } => {
                write!(
                    formatter,
                    "record {ordinal} belongs to a different Agent Run"
                )
            }
            Self::ContentPolicyViolation { ordinal } => write!(
                formatter,
                "record {ordinal} violates the content-off projection policy"
            ),
            Self::InvalidLifecycle { ordinal } => {
                write!(
                    formatter,
                    "record {ordinal} has an invalid collector lifecycle transition"
                )
            }
            Self::UnsupportedObservation { ordinal } => write!(
                formatter,
                "record {ordinal} is outside the declared Collector Capability"
            ),
            Self::ConflictingRuntimeIdentity { ordinal } => write!(
                formatter,
                "record {ordinal} has a conflicting exact Runtime Identity"
            ),
            Self::DuplicateRuntimeObservation { ordinal } => write!(
                formatter,
                "record {ordinal} duplicates a canonical Runtime Observation"
            ),
            Self::InputLimitExceeded { limit } => {
                write!(formatter, "Agent Run projection exceeded the {limit} limit")
            }
            Self::ArithmeticOverflow => write!(formatter, "projection counter overflow"),
        }
    }
}

impl std::error::Error for ProjectionError {}

#[derive(Deserialize)]
struct CapabilityManifestWire {
    schema_version: u32,
    timestamp_unix_ms: u128,
    agent_run_id: String,
    collector: String,
    collector_version: String,
    kernel_abi_version: u32,
    kernel_record_size: u32,
    observation_scope: String,
    privacy_profile: String,
    capabilities: Vec<ProjectedCapability>,
}

#[derive(Deserialize)]
struct CollectorLifecycleWire {
    schema_version: u32,
    timestamp_unix_ms: u128,
    agent_run_id: String,
    collector: String,
    collector_instance_id: String,
    state: String,
    health: String,
    stop_reason: Option<String>,
    counters: ProjectedLifecycleCounters,
}

#[derive(Deserialize)]
struct RuntimeObservationWire {
    timestamp_unix_ms: u128,
    session_id: String,
    event_source: String,
    event_type: String,
    raw_event_id: Option<String>,
    pid: u32,
    ppid: u32,
    actor: String,
    resource: String,
    action: String,
    outcome: Option<String>,
    return_value: Option<i64>,
    errno: Option<i32>,
    container_id: Option<String>,
    cgroup_id: Option<String>,
    host_boot_id: Option<String>,
    scope_generation: Option<u64>,
    process_generation: Option<u64>,
    process_start_time_ns: Option<u64>,
    exec_generation: Option<u32>,
    parent_process_generation: Option<u64>,
    parent_exec_generation: Option<u32>,
    relation_status: String,
    relation_reason: String,
    process_command: Option<String>,
    process_executable: Option<String>,
    process_started_at_unix_ms: Option<u128>,
}

#[derive(Deserialize)]
struct ObservationGapWire {
    schema_version: u32,
    timestamp_unix_ms: u128,
    agent_run_id: String,
    operation: String,
    kind: String,
    count: u64,
    detail: String,
}

#[derive(Deserialize)]
struct FindingWire {
    schema_version: u32,
    session_id: String,
    kind: FindingKind,
    decision: FindingDecision,
    #[serde(rename = "reason")]
    _reason: String,
    evidence_ref: String,
    runtime: RuntimeIdentity,
    evidence_boundary: EvidenceBoundary,
}

#[derive(Deserialize)]
struct ObserverDiagnosticWire {
    session_id: String,
    kind: String,
    count: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ExactIdentityKey {
    collector_instance_id: String,
    host_boot_id: String,
    scope_generation: u64,
    pid: u32,
    process_generation: u64,
    process_start_time_ns: u64,
    exec_generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleProgress {
    Started,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LateAttachProgress {
    AwaitingCapability,
    AwaitingStart,
}

pub fn project_agent_run(
    batches: impl IntoIterator<Item = AgentRunRecordBatch>,
) -> Result<AgentObservationRecord, ProjectionError> {
    let mut source_integrity = None;
    let mut batch_count = 0_usize;
    let mut agent_run_id = None;
    let mut capability_manifests = Vec::new();
    let mut runtime_identities = Vec::new();
    let mut identity_index = HashMap::<ExactIdentityKey, usize>::new();
    let mut runtime_observations = Vec::new();
    let mut collector_lifecycle = Vec::new();
    let mut lifecycle_progress = BTreeMap::<String, LifecycleProgress>::new();
    let mut late_attach_progress = None;
    let mut findings = Vec::new();
    let mut observation_gaps = Vec::new();
    let mut issues = Vec::new();
    let mut event_type_counts = BTreeMap::new();
    let mut outcome_counts = BTreeMap::new();
    let mut relation_counts = BTreeMap::new();
    let mut gap_kind_counts = BTreeMap::new();
    let mut finding_kind_counts = BTreeMap::new();
    let mut raw_event_ids = BTreeSet::new();
    let mut known_missing_observation_count = 0_u64;
    let mut unknown_history_boundary_count = 0_u64;
    let mut has_unknown_records = false;
    let mut has_capability_issues = false;
    let mut has_integrity_finding = false;
    let mut has_diagnostic_issue = false;
    let mut has_failure_diagnostic = false;
    let mut ordinal = 0_u64;

    for batch in batches {
        batch_count = batch_count
            .checked_add(1)
            .ok_or(ProjectionError::InputLimitExceeded {
                limit: "batch count",
            })?;
        if batch_count > MAX_AGENT_RUN_PROJECTION_BATCHES {
            return Err(ProjectionError::InputLimitExceeded {
                limit: "batch count",
            });
        }
        source_integrity = Some(match source_integrity {
            None => batch.integrity,
            Some(current) if current == batch.integrity => current,
            Some(_) => ObservationRecordSourceIntegrity::Mixed,
        });
        for value in batch.records {
            if ordinal >= MAX_AGENT_RUN_PROJECTION_RECORDS {
                return Err(ProjectionError::InputLimitExceeded {
                    limit: "record count",
                });
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or(ProjectionError::ArithmeticOverflow)?;
            validate_value_bounds(&value, ordinal, 0)?;
            let record_type = value.get("record_type").and_then(Value::as_str).ok_or(
                ProjectionError::MalformedRecord {
                    ordinal,
                    field: "record_type",
                },
            )?;
            match late_attach_progress {
                Some(LateAttachProgress::AwaitingCapability)
                    if record_type != "collector_capability_manifest" =>
                {
                    return Err(ProjectionError::InvalidLifecycle { ordinal });
                }
                Some(LateAttachProgress::AwaitingStart) if record_type != "collector_lifecycle" => {
                    return Err(ProjectionError::InvalidLifecycle { ordinal });
                }
                _ => {}
            }
            if let Some(candidate) = generic_agent_run_id(&value, ordinal)? {
                bind_agent_run(&mut agent_run_id, &candidate, ordinal)?;
            }
            match record_type {
                "collector_capability_manifest" => {
                    let wire: CapabilityManifestWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.agent_run_id, ordinal)?;
                    if !capability_manifests.is_empty() {
                        return Err(ProjectionError::MalformedRecord {
                            ordinal,
                            field: "collector_capability_manifest",
                        });
                    }
                    if !lifecycle_progress.is_empty() {
                        return Err(ProjectionError::InvalidLifecycle { ordinal });
                    }
                    validate_capability_manifest(&wire, ordinal)?;
                    capability_manifests.push(ProjectedCapabilityManifest {
                        source_ordinal: ordinal,
                        schema_version: wire.schema_version,
                        timestamp_unix_ms: wire.timestamp_unix_ms,
                        collector: wire.collector,
                        collector_version: wire.collector_version,
                        kernel_abi_version: wire.kernel_abi_version,
                        kernel_record_size: wire.kernel_record_size,
                        observation_scope: wire.observation_scope,
                        privacy_profile: wire.privacy_profile,
                        capabilities: wire.capabilities,
                    });
                    if late_attach_progress == Some(LateAttachProgress::AwaitingCapability) {
                        late_attach_progress = Some(LateAttachProgress::AwaitingStart);
                    }
                }
                "collector_lifecycle" => {
                    let wire: CollectorLifecycleWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.agent_run_id, ordinal)?;
                    if wire.schema_version != 1 {
                        return Err(ProjectionError::MalformedRecord {
                            ordinal,
                            field: "schema_version",
                        });
                    }
                    validate_lifecycle(&wire, ordinal)?;
                    if late_attach_progress == Some(LateAttachProgress::AwaitingStart)
                        && wire.state != "started"
                    {
                        return Err(ProjectionError::InvalidLifecycle { ordinal });
                    }
                    advance_lifecycle(
                        &mut lifecycle_progress,
                        &wire.collector_instance_id,
                        &wire.state,
                        ordinal,
                    )?;
                    collector_lifecycle.push(ProjectedCollectorLifecycle {
                        source_ordinal: ordinal,
                        schema_version: wire.schema_version,
                        timestamp_unix_ms: wire.timestamp_unix_ms,
                        collector: wire.collector,
                        collector_instance_id: wire.collector_instance_id,
                        state: wire.state,
                        health: wire.health,
                        stop_reason: wire.stop_reason,
                        counters: wire.counters,
                    });
                    if late_attach_progress == Some(LateAttachProgress::AwaitingStart) {
                        late_attach_progress = None;
                    }
                }
                "event" => {
                    let wire: RuntimeObservationWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.session_id, ordinal)?;
                    if wire.process_command.is_some() {
                        return Err(ProjectionError::ContentPolicyViolation { ordinal });
                    }
                    if is_runtime_observation(&wire.event_type) {
                        validate_runtime_observation(&wire, ordinal)?;
                        let collector_instance_id =
                            active_collector_instance(&lifecycle_progress, ordinal)?;
                        if capability_manifests.is_empty() {
                            has_capability_issues = true;
                        } else if let Some(code) = capability_issue(&capability_manifests, &wire) {
                            has_capability_issues = true;
                            issues.push(ProjectionIssue {
                                code,
                                source_ordinal: Some(ordinal),
                                count: 1,
                            });
                        }
                        if let Some(raw_event_id) = wire.raw_event_id.as_deref() {
                            if raw_event_id.is_empty() {
                                return Err(ProjectionError::MalformedRecord {
                                    ordinal,
                                    field: "raw_event_id",
                                });
                            }
                            if !raw_event_ids.insert(raw_event_id.to_string()) {
                                return Err(ProjectionError::DuplicateRuntimeObservation {
                                    ordinal,
                                });
                            }
                        }
                        let runtime_identity_id = project_runtime_identity(
                            &wire,
                            collector_instance_id,
                            ordinal,
                            &mut runtime_identities,
                            &mut identity_index,
                        )?;
                        increment(&mut event_type_counts, &wire.event_type)?;
                        if let Some(outcome) = wire.outcome.as_deref() {
                            increment(&mut outcome_counts, outcome)?;
                        }
                        increment(&mut relation_counts, &wire.relation_status)?;
                        runtime_observations.push(ProjectedRuntimeObservation {
                            source_ordinal: ordinal,
                            timestamp_unix_ms: wire.timestamp_unix_ms,
                            event_source: wire.event_source,
                            event_type: wire.event_type,
                            raw_event_id: wire.raw_event_id,
                            pid: wire.pid,
                            ppid: wire.ppid,
                            actor: wire.actor,
                            resource: wire.resource,
                            action: wire.action,
                            outcome: wire.outcome,
                            return_value: wire.return_value,
                            errno: wire.errno,
                            container_id: wire.container_id,
                            cgroup_id: wire.cgroup_id,
                            relation_status: wire.relation_status,
                            relation_reason: wire.relation_reason,
                            process_executable: wire.process_executable,
                            process_started_at_unix_ms: wire.process_started_at_unix_ms,
                            runtime_identity_id,
                            parent_process_generation: wire.parent_process_generation,
                            parent_exec_generation: wire.parent_exec_generation,
                        });
                    }
                }
                "observation_gap" => {
                    let wire: ObservationGapWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.agent_run_id, ordinal)?;
                    if wire.schema_version != 1 || wire.count == 0 {
                        return Err(ProjectionError::MalformedRecord {
                            ordinal,
                            field: "observation_gap",
                        });
                    }
                    if wire.kind == "late_attach" {
                        if wire.operation != "collector_lifecycle" || wire.count != 1 {
                            return Err(ProjectionError::MalformedRecord {
                                ordinal,
                                field: "late_attach",
                            });
                        }
                        if !capability_manifests.is_empty()
                            || !lifecycle_progress.is_empty()
                            || unknown_history_boundary_count > 0
                        {
                            return Err(ProjectionError::InvalidLifecycle { ordinal });
                        }
                        unknown_history_boundary_count = unknown_history_boundary_count
                            .checked_add(1)
                            .ok_or(ProjectionError::ArithmeticOverflow)?;
                        late_attach_progress = Some(LateAttachProgress::AwaitingCapability);
                    } else {
                        if !lifecycle_progress
                            .values()
                            .any(|progress| *progress == LifecycleProgress::Started)
                        {
                            return Err(ProjectionError::InvalidLifecycle { ordinal });
                        }
                        if matches!(wire.kind.as_str(), "missing_entry" | "missing_exit") {
                            known_missing_observation_count = known_missing_observation_count
                                .checked_add(wire.count)
                                .ok_or(ProjectionError::ArithmeticOverflow)?;
                        }
                    }
                    let detail = normalized_gap_detail(&wire, ordinal)?;
                    increment(&mut gap_kind_counts, &wire.kind)?;
                    issues.push(ProjectionIssue {
                        code: ProjectionIssueCode::ObservationGap,
                        source_ordinal: Some(ordinal),
                        count: wire.count,
                    });
                    observation_gaps.push(ProjectedObservationGap {
                        source_ordinal: ordinal,
                        schema_version: wire.schema_version,
                        timestamp_unix_ms: wire.timestamp_unix_ms,
                        operation: wire.operation,
                        kind: wire.kind,
                        count: wire.count,
                        detail,
                    });
                }
                "accountability_finding" => {
                    let wire: FindingWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.session_id, ordinal)?;
                    if wire.schema_version != 1 {
                        return Err(ProjectionError::MalformedRecord {
                            ordinal,
                            field: "schema_version",
                        });
                    }
                    validate_finding(&wire, ordinal)?;
                    increment(&mut finding_kind_counts, finding_kind_name(&wire.kind))?;
                    let reason = canonical_finding_reason(&wire.kind).to_string();
                    findings.push(ProjectedFinding {
                        source_ordinal: ordinal,
                        schema_version: wire.schema_version,
                        kind: wire.kind,
                        decision: wire.decision,
                        reason,
                        evidence_ref: wire.evidence_ref,
                        runtime: wire.runtime,
                        evidence_boundary: wire.evidence_boundary,
                    });
                }
                "integrity_finding" => {
                    has_integrity_finding = true;
                    issues.push(ProjectionIssue {
                        code: ProjectionIssueCode::SourceIntegrityFinding,
                        source_ordinal: Some(ordinal),
                        count: 1,
                    });
                }
                "observer_diagnostic" => {
                    let wire: ObserverDiagnosticWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.session_id, ordinal)?;
                    match wire.kind.as_str() {
                        "summary" => {}
                        "ring_buffer_reserve_failure"
                        | "map_pressure"
                        | "abi_mismatch"
                        | "decode_failure"
                        | "truncation"
                        | "attach_failure"
                        | "verifier_failure" => {
                            if wire.count > 0 {
                                has_diagnostic_issue = true;
                                has_failure_diagnostic |= matches!(
                                    wire.kind.as_str(),
                                    "attach_failure" | "verifier_failure"
                                );
                                issues.push(ProjectionIssue {
                                    code: ProjectionIssueCode::CollectorDiagnostic,
                                    source_ordinal: Some(ordinal),
                                    count: wire.count,
                                });
                            }
                        }
                        _ => {
                            return Err(ProjectionError::MalformedRecord {
                                ordinal,
                                field: "observer_diagnostic",
                            });
                        }
                    }
                }
                record_type if is_known_auxiliary_record(record_type) => {}
                _ => {
                    has_unknown_records = true;
                    issues.push(ProjectionIssue {
                        code: ProjectionIssueCode::UnknownRecordType,
                        source_ordinal: Some(ordinal),
                        count: 1,
                    });
                }
            }
        }
    }

    if late_attach_progress.is_some() {
        return Err(ProjectionError::InvalidLifecycle { ordinal });
    }
    let source_integrity =
        source_integrity.unwrap_or(ObservationRecordSourceIntegrity::UnverifiedPlainJsonl);
    let agent_run_id = agent_run_id.ok_or(ProjectionError::EmptyRun)?;
    let collector_health = aggregate_collector_health(&collector_lifecycle);
    if source_integrity == ObservationRecordSourceIntegrity::Mixed {
        issues.push(ProjectionIssue {
            code: ProjectionIssueCode::SourceIntegrityFinding,
            source_ordinal: None,
            count: 1,
        });
    }
    if capability_manifests.is_empty() {
        has_capability_issues = true;
        issues.push(ProjectionIssue {
            code: ProjectionIssueCode::MissingCapability,
            source_ordinal: None,
            count: 1,
        });
    }
    let lifecycle_complete = !lifecycle_progress.is_empty()
        && lifecycle_progress
            .values()
            .all(|progress| *progress == LifecycleProgress::Terminal);
    let missing_terminal_count = lifecycle_progress
        .values()
        .filter(|progress| **progress == LifecycleProgress::Started)
        .count();
    if lifecycle_progress.is_empty() {
        issues.push(ProjectionIssue {
            code: ProjectionIssueCode::MissingLifecycleStart,
            source_ordinal: None,
            count: 1,
        });
    } else if missing_terminal_count > 0 {
        issues.push(ProjectionIssue {
            code: ProjectionIssueCode::MissingLifecycleTerminal,
            source_ordinal: None,
            count: to_u64(missing_terminal_count)?,
        });
    }
    if runtime_observations.is_empty() {
        issues.push(ProjectionIssue {
            code: ProjectionIssueCode::NoRuntimeObservations,
            source_ordinal: None,
            count: 1,
        });
    }
    let any_failed = has_failure_diagnostic
        || collector_lifecycle
            .iter()
            .any(|record| record.state == "failed");
    let any_loss = collector_lifecycle.iter().any(lifecycle_record_has_loss);
    if let Some(record) = collector_lifecycle
        .iter()
        .rev()
        .find(|record| lifecycle_record_has_loss(record))
    {
        issues.push(ProjectionIssue {
            code: ProjectionIssueCode::CollectorLoss,
            source_ordinal: Some(record.source_ordinal),
            count: 1,
        });
    }
    let lifecycle_active = lifecycle_progress
        .values()
        .any(|progress| *progress == LifecycleProgress::Started);
    let evidence_state = if any_failed {
        EvidenceState::Failed
    } else if lifecycle_active {
        EvidenceState::Active
    } else if !lifecycle_complete
        || any_loss
        || runtime_observations.is_empty()
        || !observation_gaps.is_empty()
        || has_capability_issues
        || has_integrity_finding
        || has_diagnostic_issue
    {
        EvidenceState::Incomplete
    } else if source_integrity == ObservationRecordSourceIntegrity::Mixed || has_unknown_records {
        EvidenceState::Indeterminate
    } else {
        EvidenceState::Complete
    };
    let runtime_observation_count = to_u64(runtime_observations.len())?;
    let runtime_identity_count = to_u64(runtime_identities.len())?;
    let review_state = if !findings.is_empty() {
        ReviewState::RequiresReview
    } else if evidence_state == EvidenceState::Complete && !runtime_observations.is_empty() {
        ReviewState::NoFindingsReported
    } else {
        ReviewState::Indeterminate
    };

    Ok(AgentObservationRecord {
        record_type: "agent_observation_record".to_string(),
        schema_version: AGENT_OBSERVATION_RECORD_SCHEMA_V1,
        agent_run_id,
        source_integrity,
        summary: AgentObservationSummary {
            evidence_state,
            collector_health,
            review_state,
            runtime_observation_count,
            runtime_identity_count,
            finding_count: to_u64(findings.len())?,
            observation_gap_record_count: to_u64(observation_gaps.len())?,
            known_missing_observation_count,
            unknown_history_boundary_count,
            event_type_counts,
            outcome_counts,
            relation_counts,
            finding_kind_counts,
            gap_kind_counts,
        },
        capability_manifests,
        runtime_identities,
        runtime_observations,
        collector_lifecycle,
        findings,
        observation_gaps,
        issues,
    })
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value, ordinal: u64) -> Result<T, ProjectionError> {
    serde_json::from_value(value).map_err(|_| ProjectionError::MalformedRecord {
        ordinal,
        field: "record payload",
    })
}

fn validate_value_bounds(value: &Value, ordinal: u64, depth: usize) -> Result<(), ProjectionError> {
    if depth > MAX_PROJECTION_VALUE_DEPTH {
        return Err(ProjectionError::InputLimitExceeded {
            limit: "record nesting depth",
        });
    }
    match value {
        Value::String(value) if value.len() > MAX_PROJECTION_STRING_BYTES => {
            Err(ProjectionError::InputLimitExceeded {
                limit: "string byte length",
            })
        }
        Value::Array(values) => {
            if values.len() > MAX_PROJECTION_COLLECTION_ITEMS {
                return Err(ProjectionError::InputLimitExceeded {
                    limit: "array item count",
                });
            }
            for value in values {
                validate_value_bounds(value, ordinal, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_PROJECTION_OBJECT_FIELDS {
                return Err(ProjectionError::InputLimitExceeded {
                    limit: "object field count",
                });
            }
            for (key, value) in values {
                if key.len() > MAX_PROJECTION_STRING_BYTES {
                    return Err(ProjectionError::InputLimitExceeded {
                        limit: "string byte length",
                    });
                }
                validate_value_bounds(value, ordinal, depth + 1)?;
            }
            Ok(())
        }
        _ => {
            let _ = ordinal;
            Ok(())
        }
    }
}

fn validate_capability_manifest(
    wire: &CapabilityManifestWire,
    ordinal: u64,
) -> Result<(), ProjectionError> {
    if wire.schema_version != 1 {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "schema_version",
        });
    }
    if wire.privacy_profile != "content_off" {
        return Err(ProjectionError::ContentPolicyViolation { ordinal });
    }
    if wire.collector != "apolysis_observer"
        || wire.collector_version.is_empty()
        || wire.kernel_abi_version != 3
        || wire.kernel_record_size != 656
        || !matches!(wire.observation_scope.as_str(), "process_tree" | "cgroup")
        || wire.capabilities.is_empty()
    {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "collector_capability_manifest",
        });
    }
    let mut operations = BTreeSet::new();
    for capability in &wire.capabilities {
        if !matches!(
            capability.operation.as_str(),
            "process_fork"
                | "process_exec"
                | "process_exit"
                | "file_open"
                | "file_create"
                | "file_truncate"
                | "file_unlink"
                | "file_rename"
                | "network_connect"
                | "credential_path_access"
        ) || !operations.insert(capability.operation.as_str())
            || capability.event_sources.is_empty()
            || capability.outcomes.is_empty()
            || capability
                .event_sources
                .iter()
                .any(|source| !is_bounded_vocabulary(source, 128))
        {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "collector_capability_manifest",
            });
        }
        let mut outcomes = BTreeSet::new();
        if capability.outcomes.iter().any(|outcome| {
            !matches!(
                outcome.as_str(),
                "attempted" | "succeeded" | "failed" | "denied" | "pending" | "unknown"
            ) || !outcomes.insert(outcome.as_str())
        }) {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "collector_capability_manifest",
            });
        }
    }
    Ok(())
}

fn validate_lifecycle(wire: &CollectorLifecycleWire, ordinal: u64) -> Result<(), ProjectionError> {
    if wire.collector != "apolysis_observer"
        || wire.collector_instance_id.is_empty()
        || !is_bounded_vocabulary(&wire.collector_instance_id, 128)
    {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "collector_lifecycle",
        });
    }
    let valid = match wire.state.as_str() {
        "started" => wire.health == "healthy" && wire.stop_reason.is_none(),
        "checkpoint" => {
            wire.stop_reason.is_none()
                && wire.health
                    == if wire.counters.has_persistent_loss() {
                        "degraded"
                    } else {
                        "healthy"
                    }
        }
        "stopped" => {
            matches!(
                wire.stop_reason.as_deref(),
                Some(
                    "agent_run_closed"
                        | "daemon_shutdown"
                        | "duration_elapsed"
                        | "agent_exited"
                        | "shutdown_signal"
                )
            ) && wire.health
                == if wire.counters.has_terminal_loss() {
                    "degraded"
                } else {
                    "healthy"
                }
        }
        "failed" => {
            wire.health == "failed"
                && matches!(
                    wire.stop_reason.as_deref(),
                    Some(
                        "attach_failure"
                            | "verifier_failure"
                            | "abi_mismatch"
                            | "decode_failure"
                            | "counter_read_failure"
                            | "storage_failure"
                            | "observer_failure"
                            | "collector_restart"
                            | "incomplete_terminal_flush"
                    )
                )
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "collector_lifecycle",
        })
    }
}

fn validate_runtime_observation(
    wire: &RuntimeObservationWire,
    ordinal: u64,
) -> Result<(), ProjectionError> {
    if !matches!(
        wire.relation_status.as_str(),
        "exact" | "inferred" | "ambiguous" | "unattributed"
    ) {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "relation_status",
        });
    }
    if !matches!(
        wire.event_source.as_str(),
        "manual" | "process_tree" | "kernel_tracepoint" | "uprobe" | "runtime_metadata"
    ) || !is_bounded_vocabulary(&wire.actor, 128)
        || !is_bounded_vocabulary(&wire.action, 128)
        || !is_bounded_text(&wire.resource, MAX_PROJECTION_STRING_BYTES)
        || !is_bounded_vocabulary(&wire.relation_reason, 256)
        || wire
            .process_executable
            .as_deref()
            .is_some_and(|value| !is_executable_reference(value))
    {
        return Err(ProjectionError::ContentPolicyViolation { ordinal });
    }
    if let Some(outcome) = wire.outcome.as_deref() {
        if !matches!(
            outcome,
            "attempted" | "succeeded" | "failed" | "denied" | "pending" | "unknown"
        ) {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "outcome",
            });
        }
        let result_is_valid = match outcome {
            "succeeded" => {
                wire.return_value.is_some_and(|value| value >= 0) && wire.errno.is_none()
            }
            "failed" | "denied" | "pending" => {
                matches!((wire.return_value, wire.errno), (Some(value), Some(errno)) if value < 0 && errno > 0 && value.checked_neg() == Some(i64::from(errno)))
            }
            "attempted" | "unknown" => true,
            _ => false,
        };
        if !result_is_valid {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "operation_result",
            });
        }
    } else if wire.return_value.is_some() || wire.errno.is_some() {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "operation_result",
        });
    }
    Ok(())
}

fn active_collector_instance(
    progress: &BTreeMap<String, LifecycleProgress>,
    ordinal: u64,
) -> Result<&str, ProjectionError> {
    let mut active = progress.iter().filter_map(|(instance, state)| {
        (*state == LifecycleProgress::Started).then_some(instance.as_str())
    });
    let instance = active
        .next()
        .ok_or(ProjectionError::InvalidLifecycle { ordinal })?;
    if active.next().is_some() {
        return Err(ProjectionError::InvalidLifecycle { ordinal });
    }
    Ok(instance)
}

fn normalized_gap_detail(
    wire: &ObservationGapWire,
    ordinal: u64,
) -> Result<String, ProjectionError> {
    match wire.kind.as_str() {
        "late_attach" => {
            let parts = wire.detail.split(',').collect::<Vec<_>>();
            if parts.len() != 4
                || parts[0] != "collection_boundary:protected_existing_process_attach"
                || parts[1] != "history:unknown"
                || !matches!(
                    parts[2],
                    "provenance:external_registration" | "provenance:proc_discovery"
                )
                || !matches!(
                    parts[3],
                    "root_selection:registration_qualified" | "root_selection:inferred"
                )
            {
                return Err(ProjectionError::MalformedRecord {
                    ordinal,
                    field: "late_attach",
                });
            }
            Ok(parts.join(","))
        }
        "missing_entry" | "missing_exit" => Ok("bounded_loss_counter".to_string()),
        "collector_restart" => Ok("unfinished_collector_instance".to_string()),
        _ => Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "observation_gap",
        }),
    }
}

fn validate_finding(wire: &FindingWire, ordinal: u64) -> Result<(), ProjectionError> {
    if !is_bounded_vocabulary(&wire.evidence_ref, 256)
        || !is_bounded_vocabulary(&wire.runtime.runtime, 64)
        || wire
            .runtime
            .container_id
            .as_deref()
            .is_some_and(|value| !is_bounded_vocabulary(value, 256))
        || wire
            .runtime
            .pod_uid
            .as_deref()
            .is_some_and(|value| !is_bounded_vocabulary(value, 256))
    {
        return Err(ProjectionError::ContentPolicyViolation { ordinal });
    }
    Ok(())
}

fn finding_kind_name(kind: &FindingKind) -> &'static str {
    match kind {
        FindingKind::MissingIntent => "missing_intent",
        FindingKind::UnobservedIntent => "unobserved_intent",
        FindingKind::UndeclaredAction => "undeclared_action",
        FindingKind::CredentialRead => "credential_read",
        FindingKind::WorkspaceBoundary => "workspace_boundary",
        FindingKind::UnknownEgress => "unknown_egress",
        FindingKind::DangerousCommand => "dangerous_command",
        FindingKind::ServiceAccountTokenRead => "service_account_token_read",
    }
}

fn canonical_finding_reason(kind: &FindingKind) -> &'static str {
    match kind {
        FindingKind::MissingIntent => "observed side effect has no matching declared intent",
        FindingKind::UnobservedIntent => "declared intent has no matching observed side effect",
        FindingKind::UndeclaredAction => "observed action class was not declared by intent",
        FindingKind::CredentialRead => "workload read a credential-classified resource",
        FindingKind::WorkspaceBoundary => "file access crossed the declared workspace boundary",
        FindingKind::UnknownEgress => "network endpoint is outside the declared egress set",
        FindingKind::DangerousCommand => "command matches the dangerous-command baseline",
        FindingKind::ServiceAccountTokenRead => "workload read a Kubernetes service account token",
    }
}

fn is_bounded_vocabulary(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
}

fn is_bounded_text(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn is_executable_reference(value: &str) -> bool {
    value
        .strip_prefix("executable_ref:")
        .is_some_and(|name| is_bounded_vocabulary(name, 64) && !name.contains('/'))
}

fn bind_agent_run(
    current: &mut Option<String>,
    candidate: &str,
    ordinal: u64,
) -> Result<(), ProjectionError> {
    if candidate.is_empty() {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "agent_run_id",
        });
    }
    match current {
        Some(expected) if expected != candidate => Err(ProjectionError::MixedAgentRuns { ordinal }),
        Some(_) => Ok(()),
        None => {
            *current = Some(candidate.to_string());
            Ok(())
        }
    }
}

fn generic_agent_run_id(value: &Value, ordinal: u64) -> Result<Option<String>, ProjectionError> {
    fn read<'a>(
        value: &'a Value,
        field: &'static str,
        ordinal: u64,
    ) -> Result<Option<&'a str>, ProjectionError> {
        match value.get(field) {
            Some(Value::String(candidate)) => Ok(Some(candidate)),
            Some(_) => Err(ProjectionError::MalformedRecord { ordinal, field }),
            None => Ok(None),
        }
    }

    let agent_run_id = read(value, "agent_run_id", ordinal)?;
    let session_id = read(value, "session_id", ordinal)?;
    match (agent_run_id, session_id) {
        (Some(agent_run_id), Some(session_id)) if agent_run_id != session_id => {
            Err(ProjectionError::MixedAgentRuns { ordinal })
        }
        (Some(agent_run_id), _) => Ok(Some(agent_run_id.to_string())),
        (_, Some(session_id)) => Ok(Some(session_id.to_string())),
        (None, None) => Ok(None),
    }
}

fn is_known_auxiliary_record(record_type: &str) -> bool {
    matches!(
        record_type,
        "raw_kernel_event"
            | "intent"
            | "intent_correlation"
            | "visibility_assessment"
            | "intent_registered"
            | "intent_renewed"
            | "session_closed"
            | "cgroup_discovered"
            | "runtime_workload_discovered"
    )
}

fn advance_lifecycle(
    progress: &mut BTreeMap<String, LifecycleProgress>,
    collector_instance_id: &str,
    state: &str,
    ordinal: u64,
) -> Result<(), ProjectionError> {
    match (progress.get(collector_instance_id).copied(), state) {
        (None, "started") => {
            if progress
                .values()
                .any(|state| *state == LifecycleProgress::Started)
            {
                return Err(ProjectionError::InvalidLifecycle { ordinal });
            }
            progress.insert(
                collector_instance_id.to_string(),
                LifecycleProgress::Started,
            );
            Ok(())
        }
        (None, "failed") => {
            progress.insert(
                collector_instance_id.to_string(),
                LifecycleProgress::Terminal,
            );
            Ok(())
        }
        (Some(LifecycleProgress::Started), "checkpoint") => Ok(()),
        (Some(LifecycleProgress::Started), "stopped" | "failed") => {
            progress.insert(
                collector_instance_id.to_string(),
                LifecycleProgress::Terminal,
            );
            Ok(())
        }
        _ => Err(ProjectionError::InvalidLifecycle { ordinal }),
    }
}

fn is_runtime_observation(event_type: &str) -> bool {
    !matches!(event_type, "session_started" | "runtime_metadata")
}

fn operation_for_event(event_type: &str) -> Option<&'static str> {
    match event_type {
        "exec" => Some("process_exec"),
        "process_exit" => Some("process_exit"),
        "file_open" => Some("file_open"),
        "file_create" => Some("file_create"),
        "file_truncate" => Some("file_truncate"),
        "file_unlink" => Some("file_unlink"),
        "file_rename" => Some("file_rename"),
        "network_connect" => Some("network_connect"),
        "credential_read" => Some("credential_path_access"),
        _ => None,
    }
}

fn capability_issue(
    manifests: &[ProjectedCapabilityManifest],
    observation: &RuntimeObservationWire,
) -> Option<ProjectionIssueCode> {
    if observation.event_source != "kernel_tracepoint" {
        return Some(ProjectionIssueCode::UnsupportedObservation);
    }
    let Some(operation) = operation_for_event(&observation.event_type) else {
        return Some(ProjectionIssueCode::UnsupportedObservation);
    };
    let Some(capability) = manifests
        .iter()
        .rev()
        .flat_map(|manifest| manifest.capabilities.iter())
        .find(|capability| capability.operation == operation)
    else {
        return Some(ProjectionIssueCode::UnsupportedObservation);
    };
    let Some(outcome) = observation.outcome.as_deref() else {
        return Some(ProjectionIssueCode::UnsupportedOutcome);
    };
    if !capability
        .outcomes
        .iter()
        .any(|declared| declared == outcome)
    {
        return Some(ProjectionIssueCode::UnsupportedOutcome);
    }
    None
}

fn project_runtime_identity(
    observation: &RuntimeObservationWire,
    collector_instance_id: &str,
    ordinal: u64,
    identities: &mut Vec<ProjectedRuntimeIdentity>,
    identity_index: &mut HashMap<ExactIdentityKey, usize>,
) -> Result<Option<String>, ProjectionError> {
    if observation.relation_status != "exact" {
        return Ok(None);
    }
    let key = ExactIdentityKey {
        collector_instance_id: collector_instance_id.to_string(),
        host_boot_id: observation
            .host_boot_id
            .clone()
            .ok_or(ProjectionError::ConflictingRuntimeIdentity { ordinal })?,
        scope_generation: observation
            .scope_generation
            .ok_or(ProjectionError::ConflictingRuntimeIdentity { ordinal })?,
        pid: observation.pid,
        process_generation: observation
            .process_generation
            .ok_or(ProjectionError::ConflictingRuntimeIdentity { ordinal })?,
        process_start_time_ns: observation
            .process_start_time_ns
            .ok_or(ProjectionError::ConflictingRuntimeIdentity { ordinal })?,
        exec_generation: observation
            .exec_generation
            .ok_or(ProjectionError::ConflictingRuntimeIdentity { ordinal })?,
    };
    if !is_uuid(&key.host_boot_id)
        || key.scope_generation == 0
        || key.process_generation == 0
        || key.process_start_time_ns == 0
    {
        return Err(ProjectionError::ConflictingRuntimeIdentity { ordinal });
    }
    if let Some(index) = identity_index.get(&key).copied() {
        let identity = identities
            .get_mut(index)
            .ok_or(ProjectionError::ArithmeticOverflow)?;
        identity.last_source_ordinal = ordinal;
        identity.observation_count = identity
            .observation_count
            .checked_add(1)
            .ok_or(ProjectionError::ArithmeticOverflow)?;
        return Ok(Some(identity.identity_id.clone()));
    }
    let next = identities
        .len()
        .checked_add(1)
        .ok_or(ProjectionError::ArithmeticOverflow)?;
    let identity_id = format!("identity-{next}");
    let index = identities.len();
    identities.push(ProjectedRuntimeIdentity {
        identity_id: identity_id.clone(),
        host_boot_id: key.host_boot_id.clone(),
        scope_generation: key.scope_generation,
        pid: key.pid,
        process_generation: key.process_generation,
        process_start_time_ns: key.process_start_time_ns,
        exec_generation: key.exec_generation,
        first_source_ordinal: ordinal,
        last_source_ordinal: ordinal,
        observation_count: 1,
    });
    identity_index.insert(key, index);
    Ok(Some(identity_id))
}

fn increment(counts: &mut BTreeMap<String, u64>, key: &str) -> Result<(), ProjectionError> {
    let value = counts.entry(key.to_string()).or_default();
    *value = value
        .checked_add(1)
        .ok_or(ProjectionError::ArithmeticOverflow)?;
    Ok(())
}

fn aggregate_collector_health(
    lifecycle: &[ProjectedCollectorLifecycle],
) -> CollectorHealthProjection {
    if lifecycle.iter().any(|record| record.health == "failed") {
        CollectorHealthProjection::Failed
    } else if lifecycle
        .iter()
        .any(|record| record.health == "degraded" || lifecycle_record_has_loss(record))
    {
        CollectorHealthProjection::Degraded
    } else if lifecycle.is_empty() {
        CollectorHealthProjection::Unknown
    } else {
        CollectorHealthProjection::Healthy
    }
}

fn lifecycle_record_has_loss(record: &ProjectedCollectorLifecycle) -> bool {
    record.counters.has_persistent_loss()
        || matches!(record.state.as_str(), "stopped" | "failed")
            && record.counters.scope_pending > 0
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn to_u64(value: usize) -> Result<u64, ProjectionError> {
    u64::try_from(value).map_err(|_| ProjectionError::ArithmeticOverflow)
}

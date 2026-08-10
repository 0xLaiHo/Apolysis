// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap};

use apolysis_core::{
    audit_observer_capability_contract_v1, AuditObserverCapabilityContract, OperationOutcome,
    AUDIT_OBSERVER_COLLECTOR, CGROUP_OBSERVATION_SCOPE, CONTENT_OFF_PRIVACY_PROFILE,
    PROCESS_TREE_OBSERVATION_SCOPE,
};
pub use apolysis_core::{
    CollectorHealthState as CollectorLifecycleHealth, CollectorLifecycleState, CollectorStopReason,
};
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
const EXACT_RUNTIME_RELATION_REASON: &str = "host_boot_scope_process_start_exec_generation";

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
    #[serde(
        serialize_with = "serialize_lifecycle_state",
        deserialize_with = "deserialize_lifecycle_state"
    )]
    pub state: CollectorLifecycleState,
    #[serde(
        serialize_with = "serialize_lifecycle_health",
        deserialize_with = "deserialize_lifecycle_health"
    )]
    pub health: CollectorLifecycleHealth,
    #[serde(
        serialize_with = "serialize_stop_reason",
        deserialize_with = "deserialize_stop_reason"
    )]
    pub stop_reason: Option<CollectorStopReason>,
    pub counters: ProjectedLifecycleCounters,
}

fn serialize_lifecycle_state<S>(
    value: &CollectorLifecycleState,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_lifecycle_state<'de, D>(deserializer: D) -> Result<CollectorLifecycleState, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    CollectorLifecycleState::parse_v1(&value)
        .ok_or_else(|| serde::de::Error::custom("invalid collector lifecycle state"))
}

fn serialize_lifecycle_health<S>(
    value: &CollectorLifecycleHealth,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_lifecycle_health<'de, D>(
    deserializer: D,
) -> Result<CollectorLifecycleHealth, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    CollectorLifecycleHealth::parse_v1(&value)
        .ok_or_else(|| serde::de::Error::custom("invalid collector lifecycle health"))
}

fn serialize_stop_reason<S>(
    value: &Option<CollectorStopReason>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(reason) => serializer.serialize_some(reason.as_str()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_stop_reason<'de, D>(deserializer: D) -> Result<Option<CollectorStopReason>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|value| {
            CollectorStopReason::parse_v1(&value)
                .ok_or_else(|| serde::de::Error::custom("invalid collector stop reason"))
        })
        .transpose()
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
    UnsupportedCapability,
    MissingLifecycleStart,
    MissingLifecycleTerminal,
    CollectorLoss,
    CollectorDiagnostic,
    ObservationGap,
    UnsupportedObservation,
    UnsupportedOutcome,
    UnknownRecordType,
    SourceIntegrityFinding,
    NoRuntimeObservations,
    UnresolvedFindingEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectionIssue {
    pub code: ProjectionIssueCode,
    pub source_ordinal: Option<u64>,
    pub count: u64,
}

/// Structural inconsistencies in a frozen Agent Observation Record v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AgentObservationRecordValidationError {
    UnsupportedRecordType,
    UnsupportedSchemaVersion,
    EmptyAgentRunId,
    SummaryCountMismatch,
    SummaryAggregationMismatch,
    InvalidSourceOrdinal,
    InvalidRuntimeIdentity,
    InvalidFindingReference,
    InvalidCollectorLifecycle,
    InconsistentEvidenceState,
    InconsistentCollectorHealth,
    InconsistentReviewState,
    InvalidProjectionIssue,
    InvalidCapabilityManifest,
    InvalidRuntimeObservation,
    InvalidSourceOrder,
    InvalidObservationGap,
}

impl std::fmt::Display for AgentObservationRecordValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Agent Observation Record is internally inconsistent")
    }
}

impl std::error::Error for AgentObservationRecordValidationError {}

/// Validate consistency properties retained by the frozen v1 projection.
pub fn validate_agent_observation_record_v1(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    if record.record_type != "agent_observation_record" {
        return Err(AgentObservationRecordValidationError::UnsupportedRecordType);
    }
    if record.schema_version != AGENT_OBSERVATION_RECORD_SCHEMA_V1 {
        return Err(AgentObservationRecordValidationError::UnsupportedSchemaVersion);
    }
    if record.agent_run_id.is_empty() {
        return Err(AgentObservationRecordValidationError::EmptyAgentRunId);
    }
    let summary = &record.summary;
    let counts_match = usize_matches_u64(
        record.runtime_observations.len(),
        summary.runtime_observation_count,
    ) && usize_matches_u64(
        record.runtime_identities.len(),
        summary.runtime_identity_count,
    ) && usize_matches_u64(record.findings.len(), summary.finding_count)
        && usize_matches_u64(
            record.observation_gaps.len(),
            summary.observation_gap_record_count,
        );
    if !counts_match {
        return Err(AgentObservationRecordValidationError::SummaryCountMismatch);
    }
    let event_type_counts = count_values(
        record
            .runtime_observations
            .iter()
            .map(|observation| observation.event_type.as_str()),
    )?;
    let outcome_counts = count_values(
        record
            .runtime_observations
            .iter()
            .filter_map(|observation| observation.outcome.as_deref()),
    )?;
    let relation_counts = count_values(
        record
            .runtime_observations
            .iter()
            .map(|observation| observation.relation_status.as_str()),
    )?;
    let finding_kind_counts = count_values(
        record
            .findings
            .iter()
            .map(|finding| finding_kind_name(&finding.kind)),
    )?;
    let gap_kind_counts =
        count_values(record.observation_gaps.iter().map(|gap| gap.kind.as_str()))?;
    let known_missing_observation_count = record
        .observation_gaps
        .iter()
        .filter(|gap| matches!(gap.kind.as_str(), "missing_entry" | "missing_exit"))
        .try_fold(0_u64, |total, gap| total.checked_add(gap.count))
        .ok_or(AgentObservationRecordValidationError::SummaryAggregationMismatch)?;
    let unknown_history_boundary_count = u64::try_from(
        record
            .observation_gaps
            .iter()
            .filter(|gap| gap.kind == "late_attach")
            .count(),
    )
    .map_err(|_| AgentObservationRecordValidationError::SummaryAggregationMismatch)?;
    let aggregations_match = summary.event_type_counts == event_type_counts
        && summary.outcome_counts == outcome_counts
        && summary.relation_counts == relation_counts
        && summary.finding_kind_counts == finding_kind_counts
        && summary.gap_kind_counts == gap_kind_counts
        && summary.known_missing_observation_count == known_missing_observation_count
        && summary.unknown_history_boundary_count == unknown_history_boundary_count;
    if !aggregations_match {
        return Err(AgentObservationRecordValidationError::SummaryAggregationMismatch);
    }
    let mut source_ordinals = BTreeSet::new();
    validate_source_ordinal_sequence(
        record
            .capability_manifests
            .iter()
            .map(|manifest| manifest.source_ordinal),
        &mut source_ordinals,
    )?;
    validate_source_ordinal_sequence(
        record
            .runtime_observations
            .iter()
            .map(|observation| observation.source_ordinal),
        &mut source_ordinals,
    )?;
    validate_source_ordinal_sequence(
        record
            .collector_lifecycle
            .iter()
            .map(|lifecycle| lifecycle.source_ordinal),
        &mut source_ordinals,
    )?;
    validate_source_ordinal_sequence(
        record.findings.iter().map(|finding| finding.source_ordinal),
        &mut source_ordinals,
    )?;
    validate_source_ordinal_sequence(
        record.observation_gaps.iter().map(|gap| gap.source_ordinal),
        &mut source_ordinals,
    )?;
    validate_projected_source_order(record)?;
    validate_runtime_identities(record)?;
    validate_issue_structure(record, &source_ordinals)?;
    validate_required_presence_issues(record)?;
    validate_projected_capabilities(record)?;
    validate_projected_observations(record)?;
    validate_gaps_and_loss(record)?;
    validate_finding_references(record)?;
    validate_summary_states(record)?;
    Ok(())
}

fn usize_matches_u64(actual: usize, expected: u64) -> bool {
    u64::try_from(actual).ok() == Some(expected)
}

fn count_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeMap<String, u64>, AgentObservationRecordValidationError> {
    let mut counts = BTreeMap::new();
    for value in values {
        let count = counts.entry(value.to_string()).or_insert(0_u64);
        *count = count
            .checked_add(1)
            .ok_or(AgentObservationRecordValidationError::SummaryAggregationMismatch)?;
    }
    Ok(counts)
}

fn validate_source_ordinal_sequence(
    ordinals: impl IntoIterator<Item = u64>,
    all_ordinals: &mut BTreeSet<u64>,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut previous = None;
    for ordinal in ordinals {
        if ordinal == 0
            || ordinal > MAX_AGENT_RUN_PROJECTION_RECORDS
            || previous.is_some_and(|previous| ordinal <= previous)
            || !all_ordinals.insert(ordinal)
        {
            return Err(AgentObservationRecordValidationError::InvalidSourceOrdinal);
        }
        previous = Some(ordinal);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ProjectedSourceFact<'a> {
    Capability,
    Lifecycle(&'a ProjectedCollectorLifecycle),
    Observation,
    Gap(&'a ProjectedObservationGap),
}

fn validate_projected_source_order(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut facts = BTreeMap::new();
    for manifest in &record.capability_manifests {
        facts.insert(manifest.source_ordinal, ProjectedSourceFact::Capability);
    }
    for lifecycle in &record.collector_lifecycle {
        facts.insert(
            lifecycle.source_ordinal,
            ProjectedSourceFact::Lifecycle(lifecycle),
        );
    }
    for observation in &record.runtime_observations {
        facts.insert(observation.source_ordinal, ProjectedSourceFact::Observation);
    }
    for gap in &record.observation_gaps {
        facts.insert(gap.source_ordinal, ProjectedSourceFact::Gap(gap));
    }

    let mut manifest_seen = false;
    let mut late_attach_seen = false;
    let mut lifecycle_progress = BTreeMap::new();
    for (ordinal, fact) in &facts {
        match fact {
            ProjectedSourceFact::Capability => {
                if manifest_seen || !lifecycle_progress.is_empty() {
                    return Err(AgentObservationRecordValidationError::InvalidSourceOrder);
                }
                manifest_seen = true;
            }
            ProjectedSourceFact::Lifecycle(lifecycle) => {
                advance_lifecycle(
                    &mut lifecycle_progress,
                    &lifecycle.collector_instance_id,
                    lifecycle.state,
                    *ordinal,
                )
                .map_err(|_| AgentObservationRecordValidationError::InvalidSourceOrder)?;
            }
            ProjectedSourceFact::Observation => {
                active_collector_instance(&lifecycle_progress, *ordinal)
                    .map_err(|_| AgentObservationRecordValidationError::InvalidSourceOrder)?;
            }
            ProjectedSourceFact::Gap(gap) if gap.kind == "late_attach" => {
                let capability_ordinal = ordinal
                    .checked_add(1)
                    .ok_or(AgentObservationRecordValidationError::InvalidSourceOrder)?;
                let start_ordinal = ordinal
                    .checked_add(2)
                    .ok_or(AgentObservationRecordValidationError::InvalidSourceOrder)?;
                let next_is_capability = matches!(
                    facts.get(&capability_ordinal),
                    Some(ProjectedSourceFact::Capability)
                );
                let next_is_start = matches!(
                    facts.get(&start_ordinal),
                    Some(ProjectedSourceFact::Lifecycle(lifecycle))
                        if lifecycle.state == CollectorLifecycleState::Started
                );
                if late_attach_seen
                    || manifest_seen
                    || !lifecycle_progress.is_empty()
                    || !next_is_capability
                    || !next_is_start
                {
                    return Err(AgentObservationRecordValidationError::InvalidSourceOrder);
                }
                late_attach_seen = true;
            }
            ProjectedSourceFact::Gap(_) => {
                active_collector_instance(&lifecycle_progress, *ordinal)
                    .map_err(|_| AgentObservationRecordValidationError::InvalidSourceOrder)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct RuntimeIdentityStats {
    observation_count: u64,
    first_source_ordinal: Option<u64>,
    last_source_ordinal: Option<u64>,
}

fn validate_runtime_identities(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut identity_indices = BTreeMap::new();
    for (index, identity) in record.runtime_identities.iter().enumerate() {
        let expected_id = format!("identity-{}", index + 1);
        if identity.identity_id != expected_id
            || !is_uuid(&identity.host_boot_id)
            || identity.scope_generation == 0
            || identity.pid == 0
            || identity.process_generation == 0
            || identity.process_start_time_ns == 0
            || identity.first_source_ordinal == 0
            || identity.last_source_ordinal < identity.first_source_ordinal
            || identity_indices
                .insert(identity.identity_id.as_str(), index)
                .is_some()
        {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
        }
    }

    let mut stats = vec![RuntimeIdentityStats::default(); record.runtime_identities.len()];
    let mut raw_event_ids = BTreeSet::new();
    for observation in &record.runtime_observations {
        if let Some(raw_event_id) = observation.raw_event_id.as_deref() {
            if raw_event_id.is_empty() || !raw_event_ids.insert(raw_event_id) {
                return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
            }
        }
        if !matches!(
            observation.relation_status.as_str(),
            "exact" | "inferred" | "ambiguous" | "unattributed"
        ) {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
        }
        if observation.relation_status != "exact" {
            if observation.runtime_identity_id.is_some() {
                return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
            }
            continue;
        }
        if observation.event_source != "kernel_tracepoint"
            || observation.relation_reason != EXACT_RUNTIME_RELATION_REASON
            || observation.raw_event_id.is_none()
        {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
        }
        let identity_id = observation
            .runtime_identity_id
            .as_deref()
            .ok_or(AgentObservationRecordValidationError::InvalidRuntimeIdentity)?;
        let index = identity_indices
            .get(identity_id)
            .copied()
            .ok_or(AgentObservationRecordValidationError::InvalidRuntimeIdentity)?;
        if record.runtime_identities[index].pid != observation.pid {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
        }
        let identity_stats = &mut stats[index];
        identity_stats.observation_count = identity_stats
            .observation_count
            .checked_add(1)
            .ok_or(AgentObservationRecordValidationError::InvalidRuntimeIdentity)?;
        identity_stats.first_source_ordinal = Some(
            identity_stats
                .first_source_ordinal
                .map_or(observation.source_ordinal, |first| {
                    first.min(observation.source_ordinal)
                }),
        );
        identity_stats.last_source_ordinal = Some(
            identity_stats
                .last_source_ordinal
                .map_or(observation.source_ordinal, |last| {
                    last.max(observation.source_ordinal)
                }),
        );
    }
    for (identity, stats) in record.runtime_identities.iter().zip(stats) {
        if stats.observation_count != identity.observation_count
            || stats.first_source_ordinal != Some(identity.first_source_ordinal)
            || stats.last_source_ordinal != Some(identity.last_source_ordinal)
        {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeIdentity);
        }
    }
    Ok(())
}

fn validate_issue_structure(
    record: &AgentObservationRecord,
    source_fact_ordinals: &BTreeSet<u64>,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut opaque_source_ordinals = BTreeSet::new();
    let mut mixed_integrity_issue_count = 0_usize;
    for issue in &record.issues {
        if issue.count == 0
            || issue
                .source_ordinal
                .is_some_and(|ordinal| ordinal == 0 || ordinal > MAX_AGENT_RUN_PROJECTION_RECORDS)
        {
            return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
        }
        match issue.code {
            ProjectionIssueCode::MissingCapability
            | ProjectionIssueCode::MissingLifecycleStart
            | ProjectionIssueCode::MissingLifecycleTerminal
            | ProjectionIssueCode::NoRuntimeObservations => {
                if issue.source_ordinal.is_some() {
                    return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
                }
            }
            ProjectionIssueCode::SourceIntegrityFinding if issue.source_ordinal.is_none() => {
                if issue.count != 1 {
                    return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
                }
                mixed_integrity_issue_count += 1;
            }
            ProjectionIssueCode::UnknownRecordType
            | ProjectionIssueCode::CollectorDiagnostic
            | ProjectionIssueCode::SourceIntegrityFinding => {
                let ordinal = issue
                    .source_ordinal
                    .ok_or(AgentObservationRecordValidationError::InvalidProjectionIssue)?;
                if matches!(
                    issue.code,
                    ProjectionIssueCode::UnknownRecordType
                        | ProjectionIssueCode::SourceIntegrityFinding
                ) && issue.count != 1
                {
                    return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
                }
                if source_fact_ordinals.contains(&ordinal)
                    || !opaque_source_ordinals.insert(ordinal)
                {
                    return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
                }
            }
            _ => {
                if issue.source_ordinal.is_none() {
                    return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
                }
            }
        }
    }
    let expects_mixed_integrity_issue =
        record.source_integrity == ObservationRecordSourceIntegrity::Mixed;
    if mixed_integrity_issue_count != usize::from(expects_mixed_integrity_issue) {
        return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
    }
    Ok(())
}

fn validate_required_presence_issues(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    if record.capability_manifests.len() > 1 {
        return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
    }
    validate_singleton_issue(
        record,
        ProjectionIssueCode::MissingCapability,
        record.capability_manifests.is_empty().then_some((None, 1)),
    )?;
    validate_singleton_issue(
        record,
        ProjectionIssueCode::NoRuntimeObservations,
        record.runtime_observations.is_empty().then_some((None, 1)),
    )?;

    let mut lifecycle_progress = BTreeMap::new();
    for lifecycle in &record.collector_lifecycle {
        advance_lifecycle(
            &mut lifecycle_progress,
            &lifecycle.collector_instance_id,
            lifecycle.state,
            lifecycle.source_ordinal,
        )
        .map_err(|_| AgentObservationRecordValidationError::InvalidCollectorLifecycle)?;
    }
    validate_singleton_issue(
        record,
        ProjectionIssueCode::MissingLifecycleStart,
        record.collector_lifecycle.is_empty().then_some((None, 1)),
    )?;
    let active_count = lifecycle_progress
        .values()
        .filter(|progress| **progress == LifecycleProgress::Started)
        .count();
    let expected_missing_terminal = if active_count == 0 {
        None
    } else {
        Some((
            None,
            u64::try_from(active_count)
                .map_err(|_| AgentObservationRecordValidationError::InvalidProjectionIssue)?,
        ))
    };
    validate_singleton_issue(
        record,
        ProjectionIssueCode::MissingLifecycleTerminal,
        expected_missing_terminal,
    )?;
    Ok(())
}

fn validate_projected_capabilities(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let expected_issue = match record.capability_manifests.as_slice() {
        [] => None,
        [manifest] => {
            let unsupported_count = projected_unsupported_capability_count(manifest)?;
            (unsupported_count > 0).then_some((Some(manifest.source_ordinal), unsupported_count))
        }
        _ => return Err(AgentObservationRecordValidationError::InvalidCapabilityManifest),
    };
    validate_singleton_issue(
        record,
        ProjectionIssueCode::UnsupportedCapability,
        expected_issue,
    )
}

fn projected_unsupported_capability_count(
    manifest: &ProjectedCapabilityManifest,
) -> Result<u64, AgentObservationRecordValidationError> {
    if manifest.schema_version != AGENT_OBSERVATION_RECORD_SCHEMA_V1
        || manifest.privacy_profile != CONTENT_OFF_PRIVACY_PROFILE
        || manifest.collector != AUDIT_OBSERVER_COLLECTOR
        || manifest.collector_version.is_empty()
        || manifest.kernel_abi_version != 3
        || manifest.kernel_record_size != 656
        || !matches!(
            manifest.observation_scope.as_str(),
            PROCESS_TREE_OBSERVATION_SCOPE | CGROUP_OBSERVATION_SCOPE
        )
        || manifest.capabilities.is_empty()
    {
        return Err(AgentObservationRecordValidationError::InvalidCapabilityManifest);
    }
    let mut operations = BTreeSet::new();
    for capability in &manifest.capabilities {
        if capability_contract(&capability.operation).is_none()
            || !operations.insert(capability.operation.as_str())
            || capability.event_sources.is_empty()
            || capability.outcomes.is_empty()
        {
            return Err(AgentObservationRecordValidationError::InvalidCapabilityManifest);
        }
        let mut event_sources = BTreeSet::new();
        if capability.event_sources.iter().any(|source| {
            !is_bounded_vocabulary(source, 128) || !event_sources.insert(source.as_str())
        }) {
            return Err(AgentObservationRecordValidationError::InvalidCapabilityManifest);
        }
        let mut outcomes = BTreeSet::new();
        if capability.outcomes.iter().any(|outcome| {
            OperationOutcome::parse_v1(outcome).is_none() || !outcomes.insert(outcome.as_str())
        }) {
            return Err(AgentObservationRecordValidationError::InvalidCapabilityManifest);
        }
    }
    let unsupported = audit_observer_capability_contract_v1()
        .iter()
        .filter(|contract| {
            let Some(capability) = manifest
                .capabilities
                .iter()
                .find(|capability| capability.operation == contract.operation)
            else {
                return true;
            };
            !same_vocabulary(&capability.event_sources, contract.event_sources)
                || !same_outcome_vocabulary(&capability.outcomes, contract.outcomes)
        })
        .count();
    u64::try_from(unsupported)
        .map_err(|_| AgentObservationRecordValidationError::InvalidCapabilityManifest)
}

fn validate_projected_observations(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut expected_unsupported_observations = Vec::new();
    let mut expected_unsupported_outcomes = Vec::new();
    for observation in &record.runtime_observations {
        if !matches!(
            observation.event_source.as_str(),
            "manual" | "process_tree" | "kernel_tracepoint" | "uprobe" | "runtime_metadata"
        ) || !is_bounded_vocabulary(&observation.actor, 128)
            || !is_bounded_vocabulary(&observation.action, 128)
            || !is_bounded_text(&observation.resource, MAX_PROJECTION_STRING_BYTES)
            || !is_bounded_vocabulary(&observation.relation_reason, 256)
            || observation
                .process_executable
                .as_deref()
                .is_some_and(|value| !is_executable_reference(value))
        {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeObservation);
        }
        let outcome = observation
            .outcome
            .as_deref()
            .map(|outcome| {
                OperationOutcome::parse_v1(outcome)
                    .ok_or(AgentObservationRecordValidationError::InvalidRuntimeObservation)
            })
            .transpose()?;
        if !operation_result_is_valid(outcome, observation.return_value, observation.errno) {
            return Err(AgentObservationRecordValidationError::InvalidRuntimeObservation);
        }

        let Some(manifest) = record.capability_manifests.first() else {
            continue;
        };
        let issue = if observation.event_source != "kernel_tracepoint" {
            Some(ProjectionIssueCode::UnsupportedObservation)
        } else if let Some(operation) = operation_for_event(&observation.event_type) {
            match manifest
                .capabilities
                .iter()
                .find(|capability| capability.operation == operation)
            {
                None => Some(ProjectionIssueCode::UnsupportedObservation),
                Some(capability) => match observation.outcome.as_deref() {
                    Some(outcome) if capability.outcomes.iter().any(|value| value == outcome) => {
                        None
                    }
                    _ => Some(ProjectionIssueCode::UnsupportedOutcome),
                },
            }
        } else {
            Some(ProjectionIssueCode::UnsupportedObservation)
        };
        match issue {
            Some(ProjectionIssueCode::UnsupportedObservation) => {
                expected_unsupported_observations.push((Some(observation.source_ordinal), 1));
            }
            Some(ProjectionIssueCode::UnsupportedOutcome) => {
                expected_unsupported_outcomes.push((Some(observation.source_ordinal), 1));
            }
            _ => {}
        }
    }
    validate_issue_sequence(
        record,
        ProjectionIssueCode::UnsupportedObservation,
        &expected_unsupported_observations,
    )?;
    validate_issue_sequence(
        record,
        ProjectionIssueCode::UnsupportedOutcome,
        &expected_unsupported_outcomes,
    )
}

fn validate_gaps_and_loss(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut expected_gap_issues = Vec::new();
    for gap in &record.observation_gaps {
        let valid = gap.schema_version == AGENT_OBSERVATION_RECORD_SCHEMA_V1
            && gap.count > 0
            && match gap.kind.as_str() {
                "late_attach" => {
                    gap.operation == "collector_lifecycle"
                        && gap.count == 1
                        && valid_late_attach_detail(&gap.detail)
                }
                "missing_entry" | "missing_exit" => gap.detail == "bounded_loss_counter",
                "collector_restart" => {
                    valid_collector_restart_gap_shape(&gap.operation, gap.count)
                        && gap.detail == "unfinished_collector_instance"
                }
                _ => false,
            };
        if !valid {
            return Err(AgentObservationRecordValidationError::InvalidObservationGap);
        }
        expected_gap_issues.push((Some(gap.source_ordinal), gap.count));
    }
    validate_issue_sequence(
        record,
        ProjectionIssueCode::ObservationGap,
        &expected_gap_issues,
    )?;
    let expected_loss_issue = record
        .collector_lifecycle
        .iter()
        .rev()
        .find(|lifecycle| lifecycle_record_has_loss(lifecycle))
        .map(|lifecycle| (Some(lifecycle.source_ordinal), 1));
    validate_singleton_issue(
        record,
        ProjectionIssueCode::CollectorLoss,
        expected_loss_issue,
    )
}

fn valid_late_attach_detail(detail: &str) -> bool {
    let parts = detail.split(',').collect::<Vec<_>>();
    parts.len() == 4
        && parts[0] == "collection_boundary:protected_existing_process_attach"
        && parts[1] == "history:unknown"
        && matches!(
            parts[2],
            "provenance:external_registration" | "provenance:proc_discovery"
        )
        && matches!(
            parts[3],
            "root_selection:registration_qualified" | "root_selection:inferred"
        )
}

fn validate_singleton_issue(
    record: &AgentObservationRecord,
    code: ProjectionIssueCode,
    expected: Option<(Option<u64>, u64)>,
) -> Result<(), AgentObservationRecordValidationError> {
    validate_issue_sequence(record, code, &expected.into_iter().collect::<Vec<_>>())
}

fn validate_issue_sequence(
    record: &AgentObservationRecord,
    code: ProjectionIssueCode,
    expected: &[(Option<u64>, u64)],
) -> Result<(), AgentObservationRecordValidationError> {
    let actual = record
        .issues
        .iter()
        .filter(|issue| issue.code == code)
        .map(|issue| (issue.source_ordinal, issue.count))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(AgentObservationRecordValidationError::InvalidProjectionIssue);
    }
    Ok(())
}

fn validate_finding_references(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let raw_event_ids = record
        .runtime_observations
        .iter()
        .filter_map(|observation| observation.raw_event_id.as_deref())
        .collect::<BTreeSet<_>>();
    let mut expected_unresolved = Vec::new();
    for finding in &record.findings {
        if finding.schema_version != AGENT_OBSERVATION_RECORD_SCHEMA_V1
            || finding.reason != canonical_finding_reason(&finding.kind)
            || !is_bounded_vocabulary(&finding.evidence_ref, 256)
            || !is_bounded_vocabulary(&finding.runtime.runtime, 64)
            || finding
                .runtime
                .container_id
                .as_deref()
                .is_some_and(|value| !is_bounded_vocabulary(value, 256))
            || finding
                .runtime
                .pod_uid
                .as_deref()
                .is_some_and(|value| !is_bounded_vocabulary(value, 256))
        {
            return Err(AgentObservationRecordValidationError::InvalidFindingReference);
        }
        if !raw_event_ids.contains(finding.evidence_ref.as_str()) {
            expected_unresolved.push((Some(finding.source_ordinal), 1_u64));
        }
    }
    let actual_unresolved = record
        .issues
        .iter()
        .filter(|issue| issue.code == ProjectionIssueCode::UnresolvedFindingEvidence)
        .map(|issue| (issue.source_ordinal, issue.count))
        .collect::<Vec<_>>();
    if actual_unresolved != expected_unresolved {
        return Err(AgentObservationRecordValidationError::InvalidFindingReference);
    }
    Ok(())
}

fn validate_summary_states(
    record: &AgentObservationRecord,
) -> Result<(), AgentObservationRecordValidationError> {
    let mut lifecycle_progress = BTreeMap::new();
    for lifecycle in &record.collector_lifecycle {
        if !valid_projected_lifecycle(lifecycle)
            || advance_lifecycle(
                &mut lifecycle_progress,
                &lifecycle.collector_instance_id,
                lifecycle.state,
                lifecycle.source_ordinal,
            )
            .is_err()
        {
            return Err(AgentObservationRecordValidationError::InvalidCollectorLifecycle);
        }
    }
    let collector_restart_gap_count = record
        .observation_gaps
        .iter()
        .filter(|gap| gap.kind == "collector_restart")
        .count();
    if !collector_restart_gaps_cover_instance_transitions(
        lifecycle_progress.len(),
        collector_restart_gap_count,
    ) {
        return Err(AgentObservationRecordValidationError::InvalidCollectorLifecycle);
    }

    if record.summary.collector_health != aggregate_collector_health(&record.collector_lifecycle) {
        return Err(AgentObservationRecordValidationError::InconsistentCollectorHealth);
    }

    let expected_review_state = if !record.findings.is_empty() {
        ReviewState::RequiresReview
    } else if record.summary.evidence_state == EvidenceState::Complete
        && !record.runtime_observations.is_empty()
    {
        ReviewState::NoFindingsReported
    } else {
        ReviewState::Indeterminate
    };
    if record.summary.review_state != expected_review_state {
        return Err(AgentObservationRecordValidationError::InconsistentReviewState);
    }

    let any_failed_lifecycle = record
        .collector_lifecycle
        .iter()
        .any(|lifecycle| lifecycle.state == CollectorLifecycleState::Failed);
    let lifecycle_active = lifecycle_progress
        .values()
        .any(|progress| *progress == LifecycleProgress::Started);
    let lifecycle_complete = has_single_terminal_collector_lifecycle(&lifecycle_progress);
    let has_diagnostic = record
        .issues
        .iter()
        .any(|issue| issue.code == ProjectionIssueCode::CollectorDiagnostic);
    let has_capability_issue = record.capability_manifests.len() != 1
        || record.issues.iter().any(|issue| {
            matches!(
                issue.code,
                ProjectionIssueCode::MissingCapability
                    | ProjectionIssueCode::UnsupportedCapability
                    | ProjectionIssueCode::UnsupportedObservation
                    | ProjectionIssueCode::UnsupportedOutcome
            )
        });
    let has_source_integrity_finding = record.issues.iter().any(|issue| {
        issue.code == ProjectionIssueCode::SourceIntegrityFinding && issue.source_ordinal.is_some()
    });
    let has_unresolved_finding = record
        .issues
        .iter()
        .any(|issue| issue.code == ProjectionIssueCode::UnresolvedFindingEvidence);
    let has_unknown_record = record
        .issues
        .iter()
        .any(|issue| issue.code == ProjectionIssueCode::UnknownRecordType);
    let has_loss = record
        .collector_lifecycle
        .iter()
        .any(lifecycle_record_has_loss);
    let hard_incomplete = !lifecycle_complete
        || has_loss
        || record.runtime_observations.is_empty()
        || !record.observation_gaps.is_empty()
        || has_capability_issue
        || has_source_integrity_finding
        || has_diagnostic
        || has_unresolved_finding;
    let evidence_state_is_valid = if any_failed_lifecycle {
        record.summary.evidence_state == EvidenceState::Failed
    } else if lifecycle_active {
        record.summary.evidence_state == EvidenceState::Active
            || has_diagnostic && record.summary.evidence_state == EvidenceState::Failed
    } else if hard_incomplete {
        record.summary.evidence_state == EvidenceState::Incomplete
            || has_diagnostic && record.summary.evidence_state == EvidenceState::Failed
    } else if record.source_integrity == ObservationRecordSourceIntegrity::Mixed
        || has_unknown_record
    {
        record.summary.evidence_state == EvidenceState::Indeterminate
    } else {
        record.summary.evidence_state == EvidenceState::Complete
    };
    if !evidence_state_is_valid {
        return Err(AgentObservationRecordValidationError::InconsistentEvidenceState);
    }
    Ok(())
}

fn valid_projected_lifecycle(record: &ProjectedCollectorLifecycle) -> bool {
    if record.schema_version != AGENT_OBSERVATION_RECORD_SCHEMA_V1
        || record.collector != AUDIT_OBSERVER_COLLECTOR
        || !is_bounded_vocabulary(&record.collector_instance_id, 128)
    {
        return false;
    }
    lifecycle_fields_are_consistent(
        record.state,
        record.health,
        record.stop_reason,
        record.counters,
    )
}

fn lifecycle_fields_are_consistent(
    state: CollectorLifecycleState,
    health: CollectorLifecycleHealth,
    stop_reason: Option<CollectorStopReason>,
    counters: ProjectedLifecycleCounters,
) -> bool {
    match state {
        CollectorLifecycleState::Started => {
            health == CollectorLifecycleHealth::Healthy
                && stop_reason.is_none()
                && counters == ProjectedLifecycleCounters::default()
        }
        CollectorLifecycleState::Checkpoint => {
            stop_reason.is_none()
                && health
                    == if counters.has_persistent_loss() {
                        CollectorLifecycleHealth::Degraded
                    } else {
                        CollectorLifecycleHealth::Healthy
                    }
        }
        CollectorLifecycleState::Stopped => {
            stop_reason.is_some_and(CollectorStopReason::is_normal)
                && health
                    == if counters.has_terminal_loss() {
                        CollectorLifecycleHealth::Degraded
                    } else {
                        CollectorLifecycleHealth::Healthy
                    }
        }
        CollectorLifecycleState::Failed => {
            health == CollectorLifecycleHealth::Failed
                && stop_reason.is_some_and(CollectorStopReason::is_failure)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    EmptyRun,
    MalformedRecord { ordinal: u64, field: &'static str },
    MixedAgentRuns { ordinal: u64 },
    ContentPolicyViolation { ordinal: u64 },
    InvalidLifecycle { ordinal: u64 },
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
    #[serde(rename = "session_id")]
    agent_run_id: String,
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
    #[serde(rename = "session_id")]
    agent_run_id: String,
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
    #[serde(rename = "session_id")]
    agent_run_id: String,
    kind: String,
    count: u64,
}

#[derive(Clone, Copy)]
struct ValidatedLifecycle {
    state: CollectorLifecycleState,
    health: CollectorLifecycleHealth,
    stop_reason: Option<CollectorStopReason>,
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
                    let unsupported_capability_count =
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
                    if unsupported_capability_count > 0 {
                        has_capability_issues = true;
                        issues.push(ProjectionIssue {
                            code: ProjectionIssueCode::UnsupportedCapability,
                            source_ordinal: Some(ordinal),
                            count: unsupported_capability_count,
                        });
                    }
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
                    let validated = validate_lifecycle(&wire, ordinal)?;
                    if late_attach_progress == Some(LateAttachProgress::AwaitingStart)
                        && validated.state != CollectorLifecycleState::Started
                    {
                        return Err(ProjectionError::InvalidLifecycle { ordinal });
                    }
                    advance_lifecycle(
                        &mut lifecycle_progress,
                        &wire.collector_instance_id,
                        validated.state,
                        ordinal,
                    )?;
                    collector_lifecycle.push(ProjectedCollectorLifecycle {
                        source_ordinal: ordinal,
                        schema_version: wire.schema_version,
                        timestamp_unix_ms: wire.timestamp_unix_ms,
                        collector: wire.collector,
                        collector_instance_id: wire.collector_instance_id,
                        state: validated.state,
                        health: validated.health,
                        stop_reason: validated.stop_reason,
                        counters: wire.counters,
                    });
                    if late_attach_progress == Some(LateAttachProgress::AwaitingStart) {
                        late_attach_progress = None;
                    }
                }
                "event" => {
                    let wire: RuntimeObservationWire = decode(value, ordinal)?;
                    bind_agent_run(&mut agent_run_id, &wire.agent_run_id, ordinal)?;
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
                    if wire.kind == "collector_restart"
                        && !valid_collector_restart_gap_shape(&wire.operation, wire.count)
                    {
                        return Err(ProjectionError::MalformedRecord {
                            ordinal,
                            field: "collector_restart",
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
                    bind_agent_run(&mut agent_run_id, &wire.agent_run_id, ordinal)?;
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
                    bind_agent_run(&mut agent_run_id, &wire.agent_run_id, ordinal)?;
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
    let collector_restart_gap_count = observation_gaps
        .iter()
        .filter(|gap| gap.kind == "collector_restart")
        .count();
    if !collector_restart_gaps_cover_instance_transitions(
        lifecycle_progress.len(),
        collector_restart_gap_count,
    ) {
        return Err(ProjectionError::InvalidLifecycle { ordinal });
    }
    let mut has_unresolved_finding_evidence = false;
    for finding in &findings {
        if !raw_event_ids.contains(finding.evidence_ref.as_str()) {
            has_unresolved_finding_evidence = true;
            issues.push(ProjectionIssue {
                code: ProjectionIssueCode::UnresolvedFindingEvidence,
                source_ordinal: Some(finding.source_ordinal),
                count: 1,
            });
        }
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
    let lifecycle_complete = has_single_terminal_collector_lifecycle(&lifecycle_progress);
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
            .any(|record| record.state == CollectorLifecycleState::Failed);
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
        || has_unresolved_finding_evidence
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
) -> Result<u64, ProjectionError> {
    if wire.schema_version != 1 {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "schema_version",
        });
    }
    if wire.privacy_profile != CONTENT_OFF_PRIVACY_PROFILE {
        return Err(ProjectionError::ContentPolicyViolation { ordinal });
    }
    if wire.collector != AUDIT_OBSERVER_COLLECTOR
        || wire.collector_version.is_empty()
        || wire.kernel_abi_version != 3
        || wire.kernel_record_size != 656
        || !matches!(
            wire.observation_scope.as_str(),
            PROCESS_TREE_OBSERVATION_SCOPE | CGROUP_OBSERVATION_SCOPE
        )
        || wire.capabilities.is_empty()
    {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "collector_capability_manifest",
        });
    }
    let mut operations = BTreeSet::new();
    for capability in &wire.capabilities {
        if capability_contract(&capability.operation).is_none()
            || !operations.insert(capability.operation.as_str())
            || capability.event_sources.is_empty()
            || capability.outcomes.is_empty()
        {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "collector_capability_manifest",
            });
        }
        let mut event_sources = BTreeSet::new();
        if capability.event_sources.iter().any(|source| {
            !is_bounded_vocabulary(source, 128) || !event_sources.insert(source.as_str())
        }) {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "collector_capability_manifest",
            });
        }
        let mut outcomes = BTreeSet::new();
        if capability.outcomes.iter().any(|outcome| {
            OperationOutcome::parse_v1(outcome).is_none() || !outcomes.insert(outcome.as_str())
        }) {
            return Err(ProjectionError::MalformedRecord {
                ordinal,
                field: "collector_capability_manifest",
            });
        }
    }
    let unsupported = audit_observer_capability_contract_v1()
        .iter()
        .filter(|contract| {
            let Some(capability) = wire
                .capabilities
                .iter()
                .find(|capability| capability.operation == contract.operation)
            else {
                return true;
            };
            !same_vocabulary(&capability.event_sources, contract.event_sources)
                || !same_outcome_vocabulary(&capability.outcomes, contract.outcomes)
        })
        .count();
    to_u64(unsupported)
}

fn capability_contract(operation: &str) -> Option<&'static AuditObserverCapabilityContract> {
    audit_observer_capability_contract_v1()
        .iter()
        .find(|contract| contract.operation == operation)
}

fn same_vocabulary(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && expected
            .iter()
            .all(|expected| actual.iter().any(|actual| actual == expected))
}

fn same_outcome_vocabulary(actual: &[String], expected: &[OperationOutcome]) -> bool {
    actual.len() == expected.len()
        && expected
            .iter()
            .all(|expected| actual.iter().any(|actual| actual == expected.as_str()))
}

fn invalid_lifecycle_record(ordinal: u64) -> ProjectionError {
    ProjectionError::MalformedRecord {
        ordinal,
        field: "collector_lifecycle",
    }
}

fn validate_lifecycle(
    wire: &CollectorLifecycleWire,
    ordinal: u64,
) -> Result<ValidatedLifecycle, ProjectionError> {
    if wire.collector != AUDIT_OBSERVER_COLLECTOR
        || wire.collector_instance_id.is_empty()
        || !is_bounded_vocabulary(&wire.collector_instance_id, 128)
    {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "collector_lifecycle",
        });
    }
    let Some(state) = CollectorLifecycleState::parse_v1(&wire.state) else {
        return Err(invalid_lifecycle_record(ordinal));
    };
    let Some(health) = CollectorLifecycleHealth::parse_v1(&wire.health) else {
        return Err(invalid_lifecycle_record(ordinal));
    };
    let stop_reason = match wire.stop_reason.as_deref() {
        Some(reason) => Some(
            CollectorStopReason::parse_v1(reason)
                .ok_or_else(|| invalid_lifecycle_record(ordinal))?,
        ),
        None => None,
    };
    if lifecycle_fields_are_consistent(state, health, stop_reason, wire.counters) {
        Ok(ValidatedLifecycle {
            state,
            health,
            stop_reason,
        })
    } else {
        Err(invalid_lifecycle_record(ordinal))
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
    if wire.relation_status == "exact"
        && (wire.event_source != "kernel_tracepoint"
            || wire.relation_reason != EXACT_RUNTIME_RELATION_REASON
            || wire.raw_event_id.as_deref().is_none_or(str::is_empty))
    {
        return Err(ProjectionError::ConflictingRuntimeIdentity { ordinal });
    }
    let outcome = wire
        .outcome
        .as_deref()
        .map(|outcome| {
            OperationOutcome::parse_v1(outcome).ok_or(ProjectionError::MalformedRecord {
                ordinal,
                field: "outcome",
            })
        })
        .transpose()?;
    if !operation_result_is_valid(outcome, wire.return_value, wire.errno) {
        return Err(ProjectionError::MalformedRecord {
            ordinal,
            field: "operation_result",
        });
    }
    Ok(())
}

fn operation_result_is_valid(
    outcome: Option<OperationOutcome>,
    return_value: Option<i64>,
    errno: Option<i32>,
) -> bool {
    match outcome {
        Some(OperationOutcome::Succeeded) => {
            return_value.is_some_and(|value| value >= 0) && errno.is_none()
        }
        Some(OperationOutcome::Failed | OperationOutcome::Denied | OperationOutcome::Pending) => {
            matches!(
                (return_value, errno),
                (Some(value), Some(errno))
                    if value < 0
                        && errno > 0
                        && value.checked_neg() == Some(i64::from(errno))
            )
        }
        Some(OperationOutcome::Attempted | OperationOutcome::Unknown) => true,
        None => return_value.is_none() && errno.is_none(),
    }
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

fn has_single_terminal_collector_lifecycle(progress: &BTreeMap<String, LifecycleProgress>) -> bool {
    progress.len() == 1
        && progress
            .values()
            .all(|state| *state == LifecycleProgress::Terminal)
}

fn collector_restart_gaps_cover_instance_transitions(
    lifecycle_instance_count: usize,
    collector_restart_gap_count: usize,
) -> bool {
    collector_restart_gap_count >= lifecycle_instance_count.saturating_sub(1)
}

fn valid_collector_restart_gap_shape(operation: &str, count: u64) -> bool {
    operation == "collector_lifecycle" && count == 1
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
    let legacy_session_id = read(value, "session_id", ordinal)?;
    match (agent_run_id, legacy_session_id) {
        (Some(agent_run_id), Some(legacy_session_id)) if agent_run_id != legacy_session_id => {
            Err(ProjectionError::MixedAgentRuns { ordinal })
        }
        (Some(agent_run_id), _) => Ok(Some(agent_run_id.to_string())),
        (_, Some(legacy_session_id)) => Ok(Some(legacy_session_id.to_string())),
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
    state: CollectorLifecycleState,
    ordinal: u64,
) -> Result<(), ProjectionError> {
    match (progress.get(collector_instance_id).copied(), state) {
        (None, CollectorLifecycleState::Started) => {
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
        (None, CollectorLifecycleState::Failed) => {
            progress.insert(
                collector_instance_id.to_string(),
                LifecycleProgress::Terminal,
            );
            Ok(())
        }
        (Some(LifecycleProgress::Started), CollectorLifecycleState::Checkpoint) => Ok(()),
        (
            Some(LifecycleProgress::Started),
            CollectorLifecycleState::Stopped | CollectorLifecycleState::Failed,
        ) => {
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
        || key.pid == 0
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
    if lifecycle
        .iter()
        .any(|record| record.health == CollectorLifecycleHealth::Failed)
    {
        CollectorHealthProjection::Failed
    } else if lifecycle.iter().any(|record| {
        record.health == CollectorLifecycleHealth::Degraded || lifecycle_record_has_loss(record)
    }) {
        CollectorHealthProjection::Degraded
    } else if lifecycle.is_empty() {
        CollectorHealthProjection::Unknown
    } else {
        CollectorHealthProjection::Healthy
    }
}

fn lifecycle_record_has_loss(record: &ProjectedCollectorLifecycle) -> bool {
    record.counters.has_persistent_loss()
        || matches!(
            record.state,
            CollectorLifecycleState::Stopped | CollectorLifecycleState::Failed
        ) && record.counters.scope_pending > 0
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

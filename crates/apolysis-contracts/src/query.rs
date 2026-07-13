// SPDX-License-Identifier: Apache-2.0

//! Organization-scoped, read-only Query API and Console v0 contracts.
//!
//! These types are bounded projections. They intentionally contain no write
//! operations, storage locators, credentials, server implementation, or UI
//! behavior.

use std::collections::BTreeSet;

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    id::validate_contract_identifier,
    AuthorityRef, ClockBasis, ContractErrorCode, CoverageReasonCode, CoverageSummary,
    EnvironmentKind, OrganizationId, OutcomeComparisonState, OutcomeCoverageState, PrincipalRef,
    RunId, RunState, SourceCapability, SourceId, SourceKind, TrustProfile,
};

/// Maximum number of projected rows in one Query API page.
pub const MAX_QUERY_PAGE_SIZE: u16 = 200;

/// Maximum time span represented by one timeline page.
pub const MAX_TIMELINE_WINDOW_MS: u64 = 86_400_000;

const MAX_CURSOR_BYTES: usize = 1_024;
const MAX_SAFE_REFERENCE_BYTES: usize = 512;

/// Console read-model version.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub enum QueryViewVersion {
    /// Minimum Console read model.
    #[serde(rename = "0")]
    V0,
}

/// Projection freshness rendered by a Query API client without recomputation.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionFreshness {
    /// The projection is current at the declared input watermark.
    Current,
    /// Projection lag exceeds the configured freshness objective.
    Stale,
    /// The view is being rebuilt and can change at the next revision.
    Rebuilding,
}

/// Version and freshness facts attached to every bounded read projection.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionMetadata {
    /// Read-model wire version.
    pub view_version: QueryViewVersion,
    /// Stable projector implementation version.
    #[schemars(length(min = 1, max = 128))]
    pub computation_version: String,
    /// Monotonic revision of this projected view.
    #[schemars(range(min = 1))]
    pub projection_revision: u64,
    /// Highest durable ingest sequence included in the view.
    pub input_watermark: u64,
    /// Server-recorded completion time for this revision.
    #[schemars(range(min = 1))]
    pub projected_at_unix_ms: u64,
    /// Server-computed freshness state.
    pub freshness: ProjectionFreshness,
    /// Measured projection lag; zero is a measured value, not an unknown value.
    pub lag_ms: u64,
}

/// Bounded Run Explorer response.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RunExplorerPage {
    /// Authorized run summaries in stable server order.
    #[schemars(length(max = 200))]
    pub items: Vec<RunListItem>,
    /// Requested and enforced page limit.
    #[schemars(range(min = 1, max = 200))]
    pub limit: u16,
    /// Opaque continuation token; its contents have no client semantics.
    pub next_cursor: Option<String>,
}

impl RunExplorerPage {
    fn validate(&self) -> Result<(), &'static str> {
        validate_page(self.items.len(), self.limit, self.next_cursor.as_deref())
    }
}

impl<'de> Deserialize<'de> for RunExplorerPage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            items: Vec<RunListItem>,
            limit: u16,
            next_cursor: Option<String>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let page = Self {
            items: wire.items,
            limit: wire.limit,
            next_cursor: wire.next_cursor,
        };
        page.validate().map_err(de::Error::custom)?;
        Ok(page)
    }
}

/// One row in the Run Explorer.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunListItem {
    /// Organization scope already authorized by the Query API.
    pub organization_id: OrganizationId,
    /// Canonical run identity.
    pub run_id: RunId,
    /// Environment profile used to interpret source capabilities.
    pub environment: EnvironmentKind,
    /// Current terminal or non-terminal lifecycle state.
    pub state: RunState,
    /// Content-free primary Agent reference, when known.
    pub primary_agent_ref: Option<String>,
    /// Earliest server-visible run time.
    pub started_at_unix_ms: u64,
    /// Terminal server-visible time, when sealed.
    pub finished_at_unix_ms: Option<u64>,
    /// Independent coverage dimensions.
    pub coverage: CoverageSummary,
    /// Number of Findings still in a non-resolved state.
    pub active_finding_count: u32,
    /// Number of sources currently degraded, gapped, stalled, or failed.
    pub degraded_source_count: u32,
    /// Projection revision and freshness for this run row.
    pub projection: ProjectionMetadata,
}

/// Compatibility name used by the Console v0 information architecture.
pub type ListItem = RunListItem;

/// Complete bounded overview for one authorized Agent Run.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunOverview {
    /// Read-model wire version.
    pub view_version: QueryViewVersion,
    /// Organization scope already authorized by the Query API.
    pub organization_id: OrganizationId,
    /// Canonical run identity.
    pub run_id: RunId,
    /// Authority boundary that permitted the run.
    pub authority: AuthorityRef,
    /// Authenticated principal acting inside the Authority.
    pub principal: PrincipalRef,
    /// Content-free objective reference.
    pub objective_ref: String,
    /// Content-free primary Agent reference, when known.
    pub primary_agent_ref: Option<String>,
    /// Environment profile used for coverage computation.
    pub environment: EnvironmentKind,
    /// Current lifecycle state.
    pub state: RunState,
    /// Server-visible start time.
    pub started_at_unix_ms: u64,
    /// Terminal server-visible time, when sealed.
    pub finished_at_unix_ms: Option<u64>,
    /// Three independent server-computed coverage dimensions.
    pub coverage: CoverageSummary,
    /// Claimed and verified outcome statements and their separate comparison.
    pub outcome: OutcomeComparison,
    /// Expected and joined source health, including source loss.
    pub source_health: Vec<SourceHealth>,
    /// Unresolved and historical coverage limitations.
    pub coverage_gaps: Vec<CoverageGap>,
    /// Current read-only Findings.
    pub findings: Vec<Finding>,
    /// Authorized metadata-only evidence references associated with the run.
    pub evidence_refs: Vec<EvidenceReference>,
    /// Projection version, watermark, and freshness.
    pub projection: ProjectionMetadata,
}

/// Health state computed for an expected or joined Evidence Source.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealthState {
    /// Expected lifecycle and sequence observations are current.
    Healthy,
    /// The source is useful but operating below its declared capability.
    Degraded,
    /// At least one source-sequence gap is open.
    Gapped,
    /// The source has not advanced within its liveness objective.
    Stalled,
    /// The source declared or was diagnosed as failed.
    Failed,
    /// The relevant source boundary cannot be observed.
    Opaque,
    /// This source capability is not required by the environment profile.
    NotApplicable,
}

/// Stable source-health reasons suitable for filters and accessible labels.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealthReasonCode {
    /// Source is operating at the declared capability.
    Current,
    /// Expected source did not join the run.
    ExpectedSourceMissing,
    /// A required lifecycle declaration is missing.
    LifecycleMissing,
    /// One or more source sequence positions are missing.
    SequenceGap,
    /// Source explicitly reported loss.
    LossReported,
    /// Source samples qualifying evidence.
    SamplingEnabled,
    /// Source applies required redaction.
    RedactionApplied,
    /// Source has not advanced within the liveness objective.
    Stale,
    /// Source failed.
    Failed,
    /// Environment boundary is opaque.
    OpaqueBoundary,
    /// No applicable requirement exists.
    NoApplicableRequirement,
}

/// Query projection for one expected or joined Evidence Source.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHealth {
    /// Registered source identity.
    pub source_id: SourceId,
    /// Source integration category.
    pub source_kind: SourceKind,
    /// Effective server-assigned trust profile.
    pub trust_profile: TrustProfile,
    /// Whether the run profile expected this source.
    pub expected: bool,
    /// Whether a source stream joined the run.
    pub joined: bool,
    /// Declared expected capabilities relevant to this run.
    pub expected_capabilities: Vec<SourceCapability>,
    /// Server-computed source health state.
    pub state: SourceHealthState,
    /// Stable reasons for the current state.
    pub reason_codes: Vec<SourceHealthReasonCode>,
    /// Current stream identity, when joined.
    pub source_stream_ref: Option<String>,
    /// Last durable source sequence, when any item was accepted.
    pub last_durable_sequence: Option<u64>,
    /// Declared terminal source sequence, when received.
    pub terminal_sequence: Option<u64>,
    /// Last durable ingest time, when any item was accepted.
    pub last_ingested_at_unix_ms: Option<u64>,
    /// Whether the source declares sampling.
    pub sampling: bool,
    /// Whether source-side or Gateway redaction affected the stream.
    pub redacted: bool,
    /// Typed gaps associated with the source.
    pub gaps: Vec<CoverageGap>,
}

/// Stable coverage-gap identity and its bounded sequence/time extent.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    /// Opaque gap identity.
    pub gap_ref: String,
    /// Coverage reason represented by this gap.
    pub reason_code: CoverageReasonCode,
    /// Whether this gap blocks the applicable complete state.
    pub required: bool,
    /// Source associated with the gap, if known.
    pub source_id: Option<SourceId>,
    /// Stream associated with the gap, if known.
    pub source_stream_ref: Option<String>,
    /// First missing source sequence, if the gap is sequence-based.
    pub missing_from_sequence: Option<u64>,
    /// Last currently missing source sequence, inclusive.
    pub missing_to_sequence: Option<u64>,
    /// First time the gap became visible to the projector.
    pub detected_at_unix_ms: u64,
    /// Time the gap closed, if later evidence reconciled it.
    pub resolved_at_unix_ms: Option<u64>,
}

/// One outcome value retained without treating a claim as verification.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeState {
    /// The source reports a successful operation or check.
    Succeeded,
    /// The source reports a failed operation or check.
    Failed,
    /// The operation was denied.
    Denied,
    /// The outcome has not reached a terminal state.
    Pending,
    /// Available evidence cannot establish an outcome.
    Unknown,
    /// No outcome applies to the represented item.
    NotApplicable,
}

/// A source-bound claimed or verified outcome statement.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeStatement {
    /// Outcome asserted by this source.
    pub state: OutcomeState,
    /// Source that supplied the claim or independent check.
    pub source_id: SourceId,
    /// Source-observed time for the statement.
    pub observed_at_unix_ms: u64,
    /// Opaque evidence references supporting the statement.
    pub evidence_refs: Vec<EvidenceReference>,
}

/// Claimed outcome, independent verification, coverage, and comparison.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct OutcomeComparison {
    /// Server-derived Outcome Coverage.
    pub coverage: OutcomeCoverageState,
    /// Comparison is separate from coverage and may be a mismatch when verified.
    pub comparison: Option<OutcomeComparisonState>,
    /// Source claim, when one was received.
    pub claimed: Option<OutcomeStatement>,
    /// Independent read-back, when one was received.
    pub verified: Option<OutcomeStatement>,
}

impl OutcomeComparison {
    fn validate(&self) -> Result<(), &'static str> {
        match (
            self.coverage,
            self.comparison,
            self.claimed.as_ref(),
            self.verified.as_ref(),
        ) {
            (
                OutcomeCoverageState::Verified,
                Some(OutcomeComparisonState::Match),
                Some(claimed),
                Some(verified),
            ) if claimed.state == verified.state => Ok(()),
            (
                OutcomeCoverageState::Verified,
                Some(OutcomeComparisonState::Mismatch),
                Some(claimed),
                Some(verified),
            ) if claimed.state != verified.state => Ok(()),
            (
                OutcomeCoverageState::Unconfirmed,
                Some(OutcomeComparisonState::Unresolved),
                Some(_),
                None,
            ) => Ok(()),
            (OutcomeCoverageState::Unknown, Some(OutcomeComparisonState::Unresolved), _, _) => {
                Ok(())
            }
            (OutcomeCoverageState::NotApplicable, None, None, None) => Ok(()),
            _ => Err("outcome coverage, comparison, claim, and verification disagree"),
        }
    }
}

impl<'de> Deserialize<'de> for OutcomeComparison {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            coverage: OutcomeCoverageState,
            comparison: Option<OutcomeComparisonState>,
            claimed: Option<OutcomeStatement>,
            verified: Option<OutcomeStatement>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            coverage: wire.coverage,
            comparison: wire.comparison,
            claimed: wire.claimed,
            verified: wire.verified,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Timeline layer. Display order is projection order, not causal order.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineLane {
    /// Agent, delegation, tool, MCP, or A2A semantics.
    Semantic,
    /// Host, process, file, network, or workload observations.
    Execution,
    /// Claimed or independently verified outcomes.
    Outcome,
    /// Loss, redaction, source failure, or other coverage limitation.
    CoverageGap,
}

/// Source-observed time with an explicit clock basis and uncertainty.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineObservedTime {
    /// Source-reported Unix timestamp.
    #[schemars(range(min = 1))]
    pub unix_ms: u64,
    /// Basis of the source timestamp.
    pub clock_basis: ClockBasis,
    /// Known uncertainty; `None` means unknown, never zero.
    pub uncertainty_ms: Option<u64>,
}

/// Source and effective trust retained on every timeline item.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineSource {
    /// Registered source identity.
    pub source_id: SourceId,
    /// Server-assigned effective trust profile.
    pub trust_profile: TrustProfile,
}

/// Qualifying basis for an exact identity relation.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactAttributionBasis {
    /// The same identity was explicitly propagated across both records.
    PropagatedIdentity,
    /// A provider supplied a native stable relationship identity.
    ProviderNativeIdentity,
}

/// One retained candidate for an ambiguous relation.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionCandidate {
    /// Candidate entity identity.
    pub entity_ref: String,
    /// Non-empty stable reasons for retaining this candidate.
    #[schemars(length(min = 1))]
    pub reason_codes: Vec<String>,
    /// Projector score in basis points, from 0 through 10,000.
    #[schemars(range(max = 10000))]
    pub confidence_bps: u16,
    /// Evidence supporting this candidate without upgrading it to exact.
    #[schemars(length(min = 1))]
    pub evidence_refs: Vec<EvidenceReference>,
}

/// Attribution retained exactly as computed; no variant asserts causality.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationAttribution {
    /// An explicit identity relation from a qualifying source.
    Exact {
        /// Related entity identity.
        entity_ref: String,
        /// Typed non-heuristic identity basis.
        basis: ExactAttributionBasis,
        /// Evidence carrying the propagated or provider-native identity.
        #[schemars(length(min = 1))]
        evidence_refs: Vec<EvidenceReference>,
    },
    /// A non-exact relation inferred by a versioned projector.
    Inferred {
        /// Best candidate identity.
        entity_ref: String,
        /// Non-empty stable inference reasons.
        #[schemars(length(min = 1))]
        reason_codes: Vec<String>,
        /// Projector score in basis points, from 0 through 10,000.
        #[schemars(range(max = 10000))]
        confidence_bps: u16,
        /// Evidence supporting the inference without upgrading it to exact.
        #[schemars(length(min = 1))]
        evidence_refs: Vec<EvidenceReference>,
    },
    /// Multiple candidates remain and are all retained.
    Ambiguous {
        /// Candidate identities; at least two are required.
        #[schemars(length(min = 2))]
        candidates: Vec<AttributionCandidate>,
        /// Non-empty stable reasons why no candidate is exact.
        #[schemars(length(min = 1))]
        reason_codes: Vec<String>,
    },
    /// No qualifying relation was established.
    Unattributed {
        /// Stable explanation for the missing relation.
        #[schemars(length(min = 1))]
        reason_codes: Vec<String>,
    },
}

impl RelationAttribution {
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Exact {
                entity_ref,
                evidence_refs,
                ..
            } => {
                validate_safe_reference(entity_ref)?;
                validate_evidence_refs(evidence_refs)
            }
            Self::Inferred {
                entity_ref,
                reason_codes,
                confidence_bps,
                evidence_refs,
            } => {
                validate_safe_reference(entity_ref)?;
                validate_reason_codes(reason_codes)?;
                validate_confidence(*confidence_bps)?;
                validate_evidence_refs(evidence_refs)
            }
            Self::Ambiguous {
                candidates,
                reason_codes,
            } => {
                if candidates.len() < 2 {
                    return Err("ambiguous attribution requires at least two candidates");
                }
                let mut unique = BTreeSet::new();
                for candidate in candidates {
                    validate_safe_reference(&candidate.entity_ref)?;
                    validate_reason_codes(&candidate.reason_codes)?;
                    validate_confidence(candidate.confidence_bps)?;
                    validate_evidence_refs(&candidate.evidence_refs)?;
                    if !unique.insert(&candidate.entity_ref) {
                        return Err("ambiguous attribution candidates must be unique");
                    }
                }
                validate_reason_codes(reason_codes)
            }
            Self::Unattributed { reason_codes } => validate_reason_codes(reason_codes),
        }
    }
}

/// Opaque evidence metadata. It deliberately has no URL, path, bucket, or credential field.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct EvidenceReference {
    /// Organization-scoped opaque reference.
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    pub evidence_ref: String,
    /// Stable content-free evidence category.
    pub category: EvidenceCategory,
    /// Source that contributed the referenced evidence.
    pub source_id: SourceId,
    /// Current separately authorized dereference state.
    pub access: EvidenceAccessState,
    /// Whether metadata or content was redacted.
    pub redacted: bool,
    /// Captured object size when disclosing it is authorized.
    pub size_bytes: Option<u64>,
}

impl EvidenceReference {
    fn validate(&self) -> Result<(), &'static str> {
        validate_opaque_reference(&self.evidence_ref)?;
        if self.access != EvidenceAccessState::DereferenceAuthorized && self.size_bytes.is_some() {
            return Err("evidence size is unavailable without dereference authorization");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for EvidenceReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            evidence_ref: String,
            category: EvidenceCategory,
            source_id: SourceId,
            access: EvidenceAccessState,
            redacted: bool,
            size_bytes: Option<u64>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            evidence_ref: wire.evidence_ref,
            category: wire.category,
            source_id: wire.source_id,
            access: wire.access,
            redacted: wire.redacted,
            size_bytes: wire.size_bytes,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Stable content-free evidence categories.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    /// Agent or tool semantic lifecycle evidence.
    Semantic,
    /// Host or runtime operation evidence.
    Execution,
    /// Agent/provider claimed outcome.
    ClaimedOutcome,
    /// Independent outcome read-back.
    VerifiedOutcome,
    /// Source health or Coverage Gap evidence.
    CoverageGap,
    /// Finding-specific supporting evidence.
    Finding,
}

/// Object access state computed independently from possession of a reference.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAccessState {
    /// Metadata is visible but no raw object was captured.
    MetadataOnly,
    /// The caller may request a fresh, separately authorized dereference.
    DereferenceAuthorized,
    /// The caller is not authorized to read the object.
    NotAuthorized,
    /// The object was deleted and cannot be read.
    Deleted,
    /// Authorization or storage state is unavailable and reads fail closed.
    Unavailable,
}

/// One bounded timeline item.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineItem {
    /// Stable projected event identity.
    pub event_ref: String,
    /// Timeline layer.
    pub lane: TimelineLane,
    /// Stable content-free event type.
    pub item_type: String,
    /// Source timestamp and uncertainty.
    pub observed_at: TimelineObservedTime,
    /// Server-assigned durable ingest time.
    #[schemars(range(min = 1))]
    pub ingested_at_unix_ms: u64,
    /// Server-assigned durable ingest order.
    #[schemars(range(min = 1))]
    pub ingest_sequence: u64,
    /// Source identity and effective trust.
    pub source: TimelineSource,
    /// Item-level operation/outcome state.
    pub outcome: OutcomeState,
    /// Exact, inferred, ambiguous, or unattributed relation.
    pub attribution: RelationAttribution,
    /// Opaque evidence metadata supporting this item.
    pub evidence_refs: Vec<EvidenceReference>,
}

impl TimelineItem {
    fn validate(&self) -> Result<(), &'static str> {
        validate_safe_reference(&self.event_ref)?;
        validate_safe_reference(&self.item_type)?;
        if self.observed_at.unix_ms == 0 || self.ingested_at_unix_ms == 0 {
            return Err("timeline timestamps must be greater than zero");
        }
        if self.ingest_sequence == 0 {
            return Err("timeline ingest_sequence must begin at one");
        }
        self.attribution.validate()?;
        for reference in &self.evidence_refs {
            reference.validate()?;
        }
        Ok(())
    }
}

/// Explicit bounded time window for one timeline page.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineWindow {
    /// Inclusive lower time bound.
    #[schemars(range(min = 1))]
    pub start_unix_ms: u64,
    /// Exclusive upper time bound.
    pub end_unix_ms: u64,
}

impl TimelineWindow {
    fn validate(self) -> Result<(), &'static str> {
        if self.start_unix_ms == 0 || self.end_unix_ms <= self.start_unix_ms {
            return Err("timeline window must have positive, increasing bounds");
        }
        if self.end_unix_ms - self.start_unix_ms > MAX_TIMELINE_WINDOW_MS {
            return Err("timeline window exceeds the maximum duration");
        }
        Ok(())
    }
}

/// Bounded timeline response in stable projection order.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct TimelinePage {
    /// Read-model wire version.
    pub view_version: QueryViewVersion,
    /// Run that scopes every item in the page.
    pub run_id: RunId,
    /// Explicit bounded query window.
    pub window: TimelineWindow,
    /// Items in projection order, which is not a causal order claim.
    #[schemars(length(max = 200))]
    pub items: Vec<TimelineItem>,
    /// Requested and enforced page limit.
    #[schemars(range(min = 1, max = 200))]
    pub limit: u16,
    /// Opaque continuation token.
    pub next_cursor: Option<String>,
    /// Projection version, watermark, and freshness.
    pub projection: ProjectionMetadata,
}

impl TimelinePage {
    fn validate(&self) -> Result<(), &'static str> {
        self.window.validate()?;
        validate_page(self.items.len(), self.limit, self.next_cursor.as_deref())?;
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TimelinePage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            view_version: QueryViewVersion,
            run_id: RunId,
            window: TimelineWindow,
            items: Vec<TimelineItem>,
            limit: u16,
            next_cursor: Option<String>,
            projection: ProjectionMetadata,
        }

        let wire = Wire::deserialize(deserializer)?;
        let page = Self {
            view_version: wire.view_version,
            run_id: wire.run_id,
            window: wire.window,
            items: wire.items,
            limit: wire.limit,
            next_cursor: wire.next_cursor,
            projection: wire.projection,
        };
        page.validate().map_err(de::Error::custom)?;
        Ok(page)
    }
}

/// Stable Finding categories rendered by Console v0.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// No intent was supplied for an observed action.
    MissingIntent,
    /// Declared intent was not matched to observed execution.
    UnobservedIntent,
    /// Observed action was not declared.
    UndeclaredAction,
    /// Credential-like resource access.
    CredentialRead,
    /// Workspace or managed-boundary escape.
    WorkspaceBoundary,
    /// Network destination outside declared egress.
    UnknownEgress,
    /// Command classified as dangerous by a versioned rule.
    DangerousCommand,
    /// Kubernetes service-account token access.
    ServiceAccountTokenRead,
}

/// Finding severity supplied by the versioned finding projector.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Informational evidence context.
    Informational,
    /// Low-severity concern.
    Low,
    /// Medium-severity concern.
    Medium,
    /// High-severity concern.
    High,
    /// Critical concern.
    Critical,
}

/// Current server-owned Finding workflow state, rendered read-only in v0.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    /// Finding has no later workflow disposition.
    Open,
    /// A later workflow acknowledged it.
    Acknowledged,
    /// A later workflow suppressed it under policy.
    Suppressed,
    /// A later workflow resolved it.
    Resolved,
}

/// Current Finding projection. Console v0 exposes no mutation actions.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Stable Finding identity.
    pub finding_ref: String,
    /// Stable Finding category.
    pub kind: FindingKind,
    /// Server-computed severity.
    pub severity: FindingSeverity,
    /// Current server-owned state.
    pub state: FindingState,
    /// Stable rule identity.
    pub rule_ref: String,
    /// Rule implementation version.
    pub rule_version: String,
    /// Content-free affected entity references.
    pub affected_entity_refs: Vec<String>,
    /// Coverage limitations relevant to interpretation.
    pub coverage_reason_codes: Vec<CoverageReasonCode>,
    /// Opaque supporting evidence metadata.
    pub evidence_refs: Vec<EvidenceReference>,
    /// First projected observation time.
    pub first_seen_at_unix_ms: u64,
    /// Last projected observation time.
    pub last_seen_at_unix_ms: u64,
}

/// Query APIs use the same closed error vocabulary as the Gateway.
pub type QueryErrorCode = ContractErrorCode;

/// Content-free Query API failure response.
#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryError {
    /// Read-model wire version.
    pub view_version: QueryViewVersion,
    /// Stable machine error class.
    pub code: QueryErrorCode,
    /// Whether retry can succeed without changing the request.
    pub retryable: bool,
    /// Server-supplied minimum retry delay, when retryable.
    pub retry_after_ms: Option<u64>,
    /// Opaque support correlation reference.
    pub request_ref: String,
}

fn validate_page(item_count: usize, limit: u16, cursor: Option<&str>) -> Result<(), &'static str> {
    if limit == 0 || limit > MAX_QUERY_PAGE_SIZE {
        return Err("query page limit is outside the supported range");
    }
    if item_count > usize::from(limit) {
        return Err("query page contains more items than its declared limit");
    }
    if let Some(cursor) = cursor {
        if cursor.is_empty()
            || cursor.len() > MAX_CURSOR_BYTES
            || cursor.chars().any(char::is_control)
        {
            return Err("query cursor is empty, oversized, or contains control characters");
        }
    }
    Ok(())
}

fn validate_safe_reference(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_SAFE_REFERENCE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err("query reference is empty, oversized, or contains control characters");
    }
    Ok(())
}

fn validate_opaque_reference(value: &str) -> Result<(), &'static str> {
    validate_contract_identifier(value, "query_reference")
        .map_err(|_| "opaque reference must use safe identifier syntax")
}

fn validate_reason_codes(values: &[String]) -> Result<(), &'static str> {
    if values.is_empty() {
        return Err("attribution reason_codes must not be empty");
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_safe_reference(value)?;
        if !unique.insert(value) {
            return Err("attribution reason_codes must be unique");
        }
    }
    Ok(())
}

fn validate_confidence(value: u16) -> Result<(), &'static str> {
    if value > 10_000 {
        return Err("attribution confidence_bps must be between 0 and 10000");
    }
    Ok(())
}

fn validate_evidence_refs(values: &[EvidenceReference]) -> Result<(), &'static str> {
    if values.is_empty() {
        return Err("attribution evidence_refs must not be empty");
    }
    for value in values {
        value.validate()?;
    }
    Ok(())
}

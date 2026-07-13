// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{id::validate_contract_identifier, ContractError, SchemaVersion, SourceId};

/// Server-derived Semantic Coverage states.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCoverageState {
    /// All required semantic lifecycle evidence was observed.
    Complete,
    /// Useful semantic evidence exists with a known required gap.
    Partial,
    /// The semantic boundary is intentionally opaque.
    Opaque,
    /// Expected semantic evidence is not usable or available.
    Unavailable,
}

/// Server-derived Execution Coverage states.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCoverageState {
    /// The controlled host boundary met its declared capability without a gap.
    HostVerified,
    /// Execution evidence exists with a known capability or loss gap.
    Partial,
    /// No qualifying source can observe the execution boundary.
    Opaque,
    /// The run profile requires no execution assertion.
    NotApplicable,
    /// A required execution source did not produce usable complete evidence.
    Incomplete,
}

/// Server-derived Outcome Coverage states.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeCoverageState {
    /// A required outcome was independently checked, whether matching or not.
    Verified,
    /// An outcome was claimed but not independently checked.
    Unconfirmed,
    /// A reliable claim/check relationship cannot be established.
    Unknown,
    /// The run profile requires no external outcome.
    NotApplicable,
}

/// Comparison between a claim and an independent outcome check.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeComparisonState {
    /// The independent check matches the claimed outcome.
    Match,
    /// The independent check disagrees with the claimed outcome.
    Mismatch,
    /// A definitive comparison is not currently available.
    Unresolved,
}

/// Stable reasons attached to a coverage computation.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReasonCode {
    /// All requirements for the dimension were met.
    RequirementsSatisfied,
    /// A required source or lifecycle item is absent.
    RequiredEvidenceMissing,
    /// A source reported dropped evidence.
    SourceLoss,
    /// The source samples rather than observing every qualifying item.
    SamplingEnabled,
    /// The source truncated evidence.
    EvidenceTruncated,
    /// A required source failed.
    SourceFailed,
    /// The environment does not expose the required capability.
    UnsupportedCapability,
    /// The relevant environment boundary is opaque.
    OpaqueBoundary,
    /// No independent outcome verifier contributed.
    VerifierMissing,
    /// An independent check disagrees with a claim.
    OutcomeMismatch,
    /// This dimension has no requirement for the run profile.
    NoApplicableRequirement,
    /// Available evidence does not support a stronger state.
    InsufficientEvidence,
}

/// One versioned, server-derived coverage dimension.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct ComputedCoverage<S> {
    state: S,
    computation_version: String,
    #[schemars(range(min = 1))]
    projection_revision: u64,
    input_watermark: u64,
    #[schemars(length(min = 1))]
    reason_codes: Vec<CoverageReasonCode>,
    evidence_refs: Vec<String>,
    contributing_source_refs: Vec<SourceId>,
    coverage_gap_refs: Vec<String>,
}

impl<S> ComputedCoverage<S> {
    /// Return the dimension state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Return the computation algorithm version.
    pub fn computation_version(&self) -> &str {
        &self.computation_version
    }

    /// Return the durable input watermark used by this computation.
    pub fn input_watermark(&self) -> u64 {
        self.input_watermark
    }

    /// Return sources that contributed to this coverage computation.
    pub fn contributing_source_refs(&self) -> &[SourceId] {
        &self.contributing_source_refs
    }

    /// Return explicit Coverage Gap identities that limit this dimension.
    pub fn coverage_gap_refs(&self) -> &[String] {
        &self.coverage_gap_refs
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.computation_version, "computation_version")?;
        if self.projection_revision == 0 {
            return Err(ContractError::InvalidField {
                field: "projection_revision",
                reason: "must begin at one",
            });
        }
        if self.reason_codes.is_empty() {
            return Err(ContractError::InvalidCoverage {
                reason: "reason_codes must not be empty",
            });
        }
        reject_duplicates(&self.reason_codes, "reason_codes")?;
        let mut evidence = BTreeSet::new();
        for reference in &self.evidence_refs {
            validate_contract_identifier(reference, "evidence_refs")?;
            if !evidence.insert(reference) {
                return Err(ContractError::DuplicateValue {
                    field: "evidence_refs",
                });
            }
        }
        reject_duplicates(&self.contributing_source_refs, "contributing_source_refs")?;
        let mut gaps = BTreeSet::new();
        for reference in &self.coverage_gap_refs {
            validate_contract_identifier(reference, "coverage_gap_refs")?;
            if !gaps.insert(reference) {
                return Err(ContractError::DuplicateValue {
                    field: "coverage_gap_refs",
                });
            }
        }
        Ok(())
    }
}

#[derive(schemars::JsonSchema, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputedCoverageWire<S> {
    state: S,
    computation_version: String,
    projection_revision: u64,
    input_watermark: u64,
    reason_codes: Vec<CoverageReasonCode>,
    evidence_refs: Vec<String>,
    contributing_source_refs: Vec<SourceId>,
    coverage_gap_refs: Vec<String>,
}

impl<'de, S> Deserialize<'de> for ComputedCoverage<S>
where
    S: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ComputedCoverageWire::<S>::deserialize(deserializer)?;
        let value = Self {
            state: wire.state,
            computation_version: wire.computation_version,
            projection_revision: wire.projection_revision,
            input_watermark: wire.input_watermark,
            reason_codes: wire.reason_codes,
            evidence_refs: wire.evidence_refs,
            contributing_source_refs: wire.contributing_source_refs,
            coverage_gap_refs: wire.coverage_gap_refs,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
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

/// The three independent coverage dimensions and outcome comparison.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct CoverageSummary {
    schema_version: SchemaVersion,
    semantic: ComputedCoverage<SemanticCoverageState>,
    execution: ComputedCoverage<ExecutionCoverageState>,
    outcome: ComputedCoverage<OutcomeCoverageState>,
    outcome_comparison: Option<OutcomeComparisonState>,
}

impl CoverageSummary {
    /// Return Semantic Coverage without collapsing dimensions.
    pub fn semantic(&self) -> &ComputedCoverage<SemanticCoverageState> {
        &self.semantic
    }

    /// Return Execution Coverage without collapsing dimensions.
    pub fn execution(&self) -> &ComputedCoverage<ExecutionCoverageState> {
        &self.execution
    }

    /// Return Outcome Coverage without collapsing it into comparison state.
    pub fn outcome(&self) -> &ComputedCoverage<OutcomeCoverageState> {
        &self.outcome
    }

    /// Return claim/read-back comparison independently from Outcome Coverage.
    pub fn outcome_comparison(&self) -> Option<OutcomeComparisonState> {
        self.outcome_comparison
    }

    /// Validate cross-dimension projection and outcome invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.semantic.validate()?;
        self.execution.validate()?;
        self.outcome.validate()?;

        let computation_versions = [
            self.semantic.computation_version.as_str(),
            self.execution.computation_version.as_str(),
            self.outcome.computation_version.as_str(),
        ];
        if computation_versions[1..]
            .iter()
            .any(|version| *version != computation_versions[0])
        {
            return Err(ContractError::InvalidCoverage {
                reason: "dimensions must use one computation_version",
            });
        }
        let revisions = [
            self.semantic.projection_revision,
            self.execution.projection_revision,
            self.outcome.projection_revision,
        ];
        if revisions[1..]
            .iter()
            .any(|revision| *revision != revisions[0])
        {
            return Err(ContractError::InvalidCoverage {
                reason: "dimensions must use one projection_revision",
            });
        }
        let watermarks = [
            self.semantic.input_watermark,
            self.execution.input_watermark,
            self.outcome.input_watermark,
        ];
        if watermarks[1..]
            .iter()
            .any(|watermark| *watermark != watermarks[0])
        {
            return Err(ContractError::InvalidCoverage {
                reason: "dimensions must use one input_watermark",
            });
        }

        match (self.outcome.state, self.outcome_comparison) {
            (OutcomeCoverageState::Verified, Some(OutcomeComparisonState::Match)) => {
                if self
                    .outcome
                    .reason_codes
                    .contains(&CoverageReasonCode::OutcomeMismatch)
                {
                    return Err(ContractError::InvalidCoverage {
                        reason: "matching outcome cannot carry outcome_mismatch",
                    });
                }
            }
            (OutcomeCoverageState::Verified, Some(OutcomeComparisonState::Mismatch)) => {
                if !self
                    .outcome
                    .reason_codes
                    .contains(&CoverageReasonCode::OutcomeMismatch)
                {
                    return Err(ContractError::InvalidCoverage {
                        reason: "mismatching outcome requires outcome_mismatch",
                    });
                }
            }
            (OutcomeCoverageState::NotApplicable, None) => {}
            (
                OutcomeCoverageState::Unconfirmed | OutcomeCoverageState::Unknown,
                Some(OutcomeComparisonState::Unresolved),
            ) => {}
            _ => {
                return Err(ContractError::InvalidCoverage {
                    reason: "outcome coverage and comparison state disagree",
                })
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CoverageSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            semantic: ComputedCoverage<SemanticCoverageState>,
            execution: ComputedCoverage<ExecutionCoverageState>,
            outcome: ComputedCoverage<OutcomeCoverageState>,
            outcome_comparison: Option<OutcomeComparisonState>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            semantic: wire.semantic,
            execution: wire.execution,
            outcome: wire.outcome,
            outcome_comparison: wire.outcome_comparison,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

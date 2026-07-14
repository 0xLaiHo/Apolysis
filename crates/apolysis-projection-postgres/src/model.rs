// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    AuthorityRef, EnvironmentKind, OrganizationId, PrincipalRef, RunId, RunState,
};

use crate::{ProjectionError, ProjectionErrorCode, ProjectionResult};

pub const MAX_PROJECTION_BATCH_SIZE: u16 = 200;
pub const MAX_LIFECYCLE_PAGE_SIZE: u16 = 200;

const MAX_TRANSACTION_RETRIES: u8 = 8;
const MAX_LOCK_TIMEOUT_MS: u64 = 30_000;
const MAX_STATEMENT_TIMEOUT_MS: u64 = 120_000;
const MAX_I_JSON_INTEGER: i64 = 9_007_199_254_740_991;

/// Stable, bounded implementation identifier recorded on every generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputationVersion(String);

impl ComputationVersion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ComputationVersion {
    type Error = ProjectionError;

    fn try_from(value: &str) -> ProjectionResult<Self> {
        let bytes = value.as_bytes();
        let valid = (1..=128).contains(&bytes.len())
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            });
        if !valid {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::InvalidArgument,
            ));
        }
        Ok(Self(value.to_string()))
    }
}

impl TryFrom<String> for ComputationVersion {
    type Error = ProjectionError;

    fn try_from(value: String) -> ProjectionResult<Self> {
        Self::try_from(value.as_str())
    }
}

/// Positive database identity for one organization-scoped rebuild generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GenerationId(i64);

impl GenerationId {
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for GenerationId {
    type Error = ProjectionError;

    fn try_from(value: i64) -> ProjectionResult<Self> {
        if !(1..=MAX_I_JSON_INTEGER).contains(&value) {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::InvalidArgument,
            ));
        }
        Ok(Self(value))
    }
}

/// Complete tenant-qualified generation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationKey {
    organization_id: OrganizationId,
    generation_id: GenerationId,
}

impl GenerationKey {
    pub fn new(organization_id: OrganizationId, generation_id: GenerationId) -> Self {
        Self {
            organization_id,
            generation_id,
        }
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationState {
    Building,
    Active,
    Retired,
}

/// Bounded poison state retained without advancing a checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFailureCode {
    MissingInput,
    OversizedInput,
    DigestMismatch,
    InvalidContract,
    MetadataMismatch,
    LifecycleConflict,
    OutboxState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionGeneration {
    pub(crate) key: GenerationKey,
    pub(crate) computation_version: ComputationVersion,
    pub(crate) state: GenerationState,
    pub(crate) rebuild_of: Option<GenerationId>,
    pub(crate) created_source_watermark: u64,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) activated_at_unix_ms: Option<u64>,
    pub(crate) retired_at_unix_ms: Option<u64>,
}

impl ProjectionGeneration {
    pub fn key(&self) -> &GenerationKey {
        &self.key
    }

    pub fn computation_version(&self) -> &ComputationVersion {
        &self.computation_version
    }

    pub const fn state(&self) -> GenerationState {
        self.state
    }

    pub const fn rebuild_of(&self) -> Option<GenerationId> {
        self.rebuild_of
    }

    pub const fn created_source_watermark(&self) -> u64 {
        self.created_source_watermark
    }

    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    pub const fn activated_at_unix_ms(&self) -> Option<u64> {
        self.activated_at_unix_ms
    }

    pub const fn retired_at_unix_ms(&self) -> Option<u64> {
        self.retired_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionCheckpoint {
    pub(crate) key: GenerationKey,
    pub(crate) input_watermark: u64,
    pub(crate) last_commit_revision: Option<u64>,
    pub(crate) updated_at_unix_ms: u64,
    pub(crate) failure: Option<(InputFailureCode, u64)>,
}

impl ProjectionCheckpoint {
    pub fn key(&self) -> &GenerationKey {
        &self.key
    }

    pub const fn input_watermark(&self) -> u64 {
        self.input_watermark
    }

    pub const fn last_commit_revision(&self) -> Option<u64> {
        self.last_commit_revision
    }

    pub const fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }

    pub const fn failure(&self) -> Option<(InputFailureCode, u64)> {
        self.failure
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionCommit {
    pub(crate) key: GenerationKey,
    pub(crate) revision: u64,
    pub(crate) from_input_watermark: u64,
    pub(crate) through_input_watermark: u64,
    pub(crate) record_count: u16,
    pub(crate) projected_at_unix_ms: u64,
    pub(crate) batch_digest: String,
}

impl ProjectionCommit {
    pub fn key(&self) -> &GenerationKey {
        &self.key
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn from_input_watermark(&self) -> u64 {
        self.from_input_watermark
    }

    pub const fn through_input_watermark(&self) -> u64 {
        self.through_input_watermark
    }

    pub const fn record_count(&self) -> u16 {
        self.record_count
    }

    pub const fn projected_at_unix_ms(&self) -> u64 {
        self.projected_at_unix_ms
    }

    pub fn batch_digest(&self) -> &str {
        &self.batch_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionBatchOutcome {
    Applied(ProjectionCommit),
    CaughtUp(ProjectionCheckpoint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cutover {
    pub(crate) previous_generation: GenerationId,
    pub(crate) active_generation: GenerationId,
    pub(crate) cutover_revision: u64,
    pub(crate) query_visible_watermark: u64,
}

impl Cutover {
    pub const fn previous_generation(&self) -> GenerationId {
        self.previous_generation
    }

    pub const fn active_generation(&self) -> GenerationId {
        self.active_generation
    }

    pub const fn cutover_revision(&self) -> u64 {
        self.cutover_revision
    }

    pub const fn query_visible_watermark(&self) -> u64 {
        self.query_visible_watermark
    }
}

/// Internal lifecycle/header read model; this is not the Console Run Explorer contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunLifecycleRead {
    pub(crate) generation_id: GenerationId,
    pub(crate) computation_version: ComputationVersion,
    pub(crate) organization_id: OrganizationId,
    pub(crate) run_id: RunId,
    pub(crate) authority: AuthorityRef,
    pub(crate) principal: PrincipalRef,
    pub(crate) objective_ref: String,
    pub(crate) environment: EnvironmentKind,
    pub(crate) privacy_profile_ref: String,
    pub(crate) retention_profile_ref: String,
    pub(crate) state: RunState,
    pub(crate) opened_at_unix_ms: u64,
    pub(crate) state_changed_at_unix_ms: u64,
    pub(crate) terminal_at_unix_ms: Option<u64>,
    pub(crate) lifecycle_revision: u64,
    pub(crate) opened_ingest_sequence: u64,
    pub(crate) last_lifecycle_ingest_sequence: u64,
}

impl RunLifecycleRead {
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    pub fn computation_version(&self) -> &ComputationVersion {
        &self.computation_version
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn authority(&self) -> &AuthorityRef {
        &self.authority
    }

    pub fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    pub fn objective_ref(&self) -> &str {
        &self.objective_ref
    }

    pub const fn environment(&self) -> EnvironmentKind {
        self.environment
    }

    pub fn privacy_profile_ref(&self) -> &str {
        &self.privacy_profile_ref
    }

    pub fn retention_profile_ref(&self) -> &str {
        &self.retention_profile_ref
    }

    pub const fn state(&self) -> RunState {
        self.state
    }

    pub const fn opened_at_unix_ms(&self) -> u64 {
        self.opened_at_unix_ms
    }

    pub const fn state_changed_at_unix_ms(&self) -> u64 {
        self.state_changed_at_unix_ms
    }

    pub const fn terminal_at_unix_ms(&self) -> Option<u64> {
        self.terminal_at_unix_ms
    }

    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    pub const fn opened_ingest_sequence(&self) -> u64 {
        self.opened_ingest_sequence
    }

    pub const fn last_lifecycle_ingest_sequence(&self) -> u64 {
        self.last_lifecycle_ingest_sequence
    }
}

/// Generation-bound internal keyset position. It is not a Query API token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCursor {
    pub(crate) organization_id: OrganizationId,
    pub(crate) generation_id: GenerationId,
    pub(crate) visible_input_watermark: u64,
    pub(crate) opened_at_unix_ms: u64,
    pub(crate) run_id: RunId,
}

impl LifecycleCursor {
    pub const fn generation_id(&self) -> GenerationId {
        self.generation_id
    }

    pub const fn visible_input_watermark(&self) -> u64 {
        self.visible_input_watermark
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecyclePage {
    pub(crate) items: Vec<RunLifecycleRead>,
    pub(crate) limit: u16,
    pub(crate) visible_input_watermark: u64,
    pub(crate) next_cursor: Option<LifecycleCursor>,
}

impl LifecyclePage {
    pub fn items(&self) -> &[RunLifecycleRead] {
        &self.items
    }

    pub const fn limit(&self) -> u16 {
        self.limit
    }

    pub const fn visible_input_watermark(&self) -> u64 {
        self.visible_input_watermark
    }

    pub fn next_cursor(&self) -> Option<&LifecycleCursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionStatus {
    pub(crate) generation: ProjectionGeneration,
    pub(crate) checkpoint: ProjectionCheckpoint,
    pub(crate) durable_input_watermark: u64,
    pub(crate) query_visible_watermark: u64,
    pub(crate) lag_ms: u64,
}

impl ProjectionStatus {
    pub fn generation(&self) -> &ProjectionGeneration {
        &self.generation
    }

    pub fn checkpoint(&self) -> &ProjectionCheckpoint {
        &self.checkpoint
    }

    pub const fn durable_input_watermark(&self) -> u64 {
        self.durable_input_watermark
    }

    pub const fn query_visible_watermark(&self) -> u64 {
        self.query_visible_watermark
    }

    pub const fn lag_ms(&self) -> u64 {
        self.lag_ms
    }

    pub const fn is_current(&self) -> bool {
        matches!(self.generation.state, GenerationState::Active)
            && self.checkpoint.failure.is_none()
            && self.checkpoint.input_watermark == self.query_visible_watermark
            && self.query_visible_watermark == self.durable_input_watermark
    }
}

/// Bounded operational controls for one projection repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionConfig {
    batch_size: u16,
    transaction_retry_limit: u8,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
}

impl ProjectionConfig {
    pub fn new(
        batch_size: u16,
        transaction_retry_limit: u8,
        lock_timeout_ms: u64,
        statement_timeout_ms: u64,
    ) -> ProjectionResult<Self> {
        if !(1..=MAX_PROJECTION_BATCH_SIZE).contains(&batch_size)
            || !(1..=MAX_TRANSACTION_RETRIES).contains(&transaction_retry_limit)
            || !(1..=MAX_LOCK_TIMEOUT_MS).contains(&lock_timeout_ms)
            || !(1..=MAX_STATEMENT_TIMEOUT_MS).contains(&statement_timeout_ms)
            || lock_timeout_ms > statement_timeout_ms
        {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::InvalidArgument,
            ));
        }
        Ok(Self {
            batch_size,
            transaction_retry_limit,
            lock_timeout_ms,
            statement_timeout_ms,
        })
    }

    pub const fn batch_size(&self) -> u16 {
        self.batch_size
    }

    pub const fn transaction_retry_limit(&self) -> u8 {
        self.transaction_retry_limit
    }

    pub const fn lock_timeout_ms(&self) -> u64 {
        self.lock_timeout_ms
    }

    pub const fn statement_timeout_ms(&self) -> u64 {
        self.statement_timeout_ms
    }
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            transaction_retry_limit: 4,
            lock_timeout_ms: 2_000,
            statement_timeout_ms: 15_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(
        state: GenerationState,
        checkpoint_watermark: u64,
        query_visible_watermark: u64,
        durable_input_watermark: u64,
    ) -> ProjectionStatus {
        let organization_id =
            OrganizationId::try_from("org_projection_status_unit").expect("organization fixture");
        let generation_id = GenerationId::try_from(1).expect("generation fixture");
        let key = GenerationKey::new(organization_id, generation_id);
        ProjectionStatus {
            generation: ProjectionGeneration {
                key: key.clone(),
                computation_version: ComputationVersion::try_from("run-lifecycle-unit-v1")
                    .expect("computation fixture"),
                state,
                rebuild_of: None,
                created_source_watermark: durable_input_watermark,
                created_at_unix_ms: 1,
                activated_at_unix_ms: (state != GenerationState::Building).then_some(1),
                retired_at_unix_ms: (state == GenerationState::Retired).then_some(2),
            },
            checkpoint: ProjectionCheckpoint {
                key,
                input_watermark: checkpoint_watermark,
                last_commit_revision: (checkpoint_watermark > 0).then_some(1),
                updated_at_unix_ms: 1,
                failure: None,
            },
            durable_input_watermark,
            query_visible_watermark,
            lag_ms: 0,
        }
    }

    #[test]
    fn current_status_requires_one_active_equal_watermark_snapshot() {
        assert!(status(GenerationState::Active, 3, 3, 3).is_current());
        assert!(!status(GenerationState::Building, 0, 0, 0).is_current());
        assert!(!status(GenerationState::Retired, 0, 0, 0).is_current());
        assert!(!status(GenerationState::Active, 2, 3, 3).is_current());
    }
}

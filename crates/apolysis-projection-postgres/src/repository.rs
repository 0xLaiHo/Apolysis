// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use apolysis_contracts::{
    AgentExecutionRecordFact, AuthorityKind, AuthorityRef, OrganizationId, PrincipalKind,
    PrincipalRef, RunId, RunState,
};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};

use crate::validation::{
    batch_digest, validate_stored_ledger_row, StoredLedgerRow, ValidatedLedgerRow,
    MAX_LEDGER_ITEM_BYTES,
};
use crate::{
    error::{classify_commit_failure, database_failure, invariant_failure, CommitFailure},
    migrate_projection_schema, ComputationVersion, Cutover, GenerationId, GenerationKey,
    GenerationState, InputFailureCode, LifecycleCursor, LifecyclePage, ProjectionBatchOutcome,
    ProjectionCheckpoint, ProjectionCommit, ProjectionConfig, ProjectionError, ProjectionErrorCode,
    ProjectionGeneration, ProjectionResult, ProjectionStatus, RunLifecycleRead,
    MAX_LIFECYCLE_PAGE_SIZE,
};

const MAX_I_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_POOL_CONNECTIONS: u32 = 8;

/// Deep PostgreSQL boundary for ordered lifecycle projection and generation cutover.
#[derive(Clone)]
pub struct PostgresRunProjection {
    pool: PgPool,
    config: ProjectionConfig,
}

impl PostgresRunProjection {
    /// Connect with a bounded pool and install or verify the projection schema.
    pub async fn connect_and_migrate(
        database_url: &str,
        config: ProjectionConfig,
    ) -> ProjectionResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(MAX_POOL_CONNECTIONS)
            .acquire_timeout(Duration::from_secs(15))
            .connect(database_url)
            .await
            .map_err(|error| database_failure("connect", &error))?;
        migrate_projection_schema(&pool).await?;
        Ok(Self { pool, config })
    }

    /// Bind an already configured runtime pool. Migration remains an explicit
    /// administrative operation so deployments can separate owner/runtime roles.
    pub fn from_pool(pool: PgPool, config: ProjectionConfig) -> Self {
        Self { pool, config }
    }

    /// Create the first active generation for an organization, or return the
    /// exact existing generation when retried with the same computation version.
    pub async fn initialize_current(
        &self,
        organization_id: &OrganizationId,
        computation_version: ComputationVersion,
        now_unix_ms: u64,
    ) -> ProjectionResult<ProjectionGeneration> {
        let now = sql_positive(now_unix_ms)?;
        let mut transaction = self.begin_scoped(organization_id).await?;
        let source_watermark =
            source_watermark_for_update(&mut transaction, organization_id).await?;

        let observed_head: Option<(i64, i64)> = sqlx::query_as(
            "SELECT active_generation_id, cutover_revision \
             FROM apolysis_projection.organization_heads WHERE organization_id=$1",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("initialize_current_observe_head", &error))?;

        if let Some(observed_head) = observed_head {
            let active_generation_id = GenerationId::try_from(observed_head.0)?;
            // Projectors acquire the generation/checkpoint pair before updating
            // the active head. Initialization follows that order so an exact
            // retry cannot own the other half of a generation-to-head cycle.
            let row = sqlx::query(
                "SELECT g.generation_id, g.computation_version, g.generation_state, \
                        g.rebuild_of_generation_id, g.created_source_watermark, \
                        g.created_at_unix_ms, g.activated_at_unix_ms, g.retired_at_unix_ms \
                 FROM apolysis_projection.generations AS g \
                 JOIN apolysis_projection.checkpoints AS c \
                   ON c.organization_id=g.organization_id \
                  AND c.generation_id=g.generation_id \
                 WHERE g.organization_id=$1 AND g.generation_id=$2 \
                 FOR UPDATE OF g,c",
            )
            .bind(organization_id.as_str())
            .bind(active_generation_id.get())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| database_failure("initialize_current_lock_generation", &error))?
            .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::GenerationConflict))?;
            let locked_head: (i64, i64) = sqlx::query_as(
                "SELECT active_generation_id, cutover_revision \
                 FROM apolysis_projection.organization_heads \
                 WHERE organization_id=$1 FOR UPDATE",
            )
            .bind(organization_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| database_failure("initialize_current_lock_head", &error))?
            .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
            if locked_head != observed_head {
                return Err(ProjectionError::permanent(
                    ProjectionErrorCode::GenerationConflict,
                ));
            }
            let generation = decode_generation(organization_id, &row)?;
            if generation.computation_version() != &computation_version {
                return Err(ProjectionError::permanent(
                    ProjectionErrorCode::GenerationConflict,
                ));
            }
            transaction
                .commit()
                .await
                .map_err(|error| database_failure("initialize_current_commit", &error))?;
            return Ok(generation);
        }

        let generation_id: i64 = sqlx::query_scalar(
            "INSERT INTO apolysis_projection.generations (\
                organization_id, computation_version, generation_state, \
                rebuild_of_generation_id, created_source_watermark, created_at_unix_ms, \
                activated_at_unix_ms\
             ) VALUES ($1,$2,'active',NULL,$3,$4,$4) RETURNING generation_id",
        )
        .bind(organization_id.as_str())
        .bind(computation_version.as_str())
        .bind(sql_nonnegative(source_watermark)?)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| database_failure("initialize_current_insert_generation", &error))?;
        let generation_id = GenerationId::try_from(generation_id)?;
        sqlx::query(
            "INSERT INTO apolysis_projection.checkpoints (\
                organization_id, generation_id, input_watermark, updated_at_unix_ms\
             ) VALUES ($1,$2,0,$3)",
        )
        .bind(organization_id.as_str())
        .bind(generation_id.get())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("initialize_current_insert_checkpoint", &error))?;
        sqlx::query(
            "INSERT INTO apolysis_projection.organization_heads (\
                organization_id, active_generation_id, cutover_revision, \
                query_visible_watermark, cutover_at_unix_ms\
             ) VALUES ($1,$2,1,0,$3)",
        )
        .bind(organization_id.as_str())
        .bind(generation_id.get())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("initialize_current_insert_head", &error))?;
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("initialize_current_commit", &error))?;
        Ok(ProjectionGeneration {
            key: GenerationKey::new(organization_id.clone(), generation_id),
            computation_version,
            state: GenerationState::Active,
            rebuild_of: None,
            created_source_watermark: source_watermark,
            created_at_unix_ms: now_unix_ms,
            activated_at_unix_ms: Some(now_unix_ms),
            retired_at_unix_ms: None,
        })
    }

    /// Start an organization-local from-zero rebuild while its active generation
    /// remains queryable.
    pub async fn start_rebuild(
        &self,
        organization_id: &OrganizationId,
        computation_version: ComputationVersion,
        now_unix_ms: u64,
    ) -> ProjectionResult<ProjectionGeneration> {
        let now = sql_positive(now_unix_ms)?;
        let mut transaction = self.begin_scoped(organization_id).await?;
        let source_watermark =
            source_watermark_for_share(&mut transaction, organization_id).await?;
        let observed_head: (i64, i64) = sqlx::query_as(
            "SELECT active_generation_id, cutover_revision \
             FROM apolysis_projection.organization_heads \
             WHERE organization_id=$1",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("start_rebuild_observe_head", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let active_generation_id = GenerationId::try_from(observed_head.0)?;

        // Active projectors lock this generation/checkpoint pair and then the
        // head. Rebuild creation takes the same order and revalidates the head
        // before using the active generation as its foreign-key parent.
        let active = sqlx::query(
            "SELECT g.generation_state \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_id=$2 \
             FOR UPDATE OF g,c",
        )
        .bind(organization_id.as_str())
        .bind(active_generation_id.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("start_rebuild_lock_active", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::GenerationConflict))?;
        if decode_generation_state(&row_string(&active, "generation_state")?)?
            != GenerationState::Active
        {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }
        let locked_head: (i64, i64) = sqlx::query_as(
            "SELECT active_generation_id, cutover_revision \
             FROM apolysis_projection.organization_heads \
             WHERE organization_id=$1 FOR UPDATE",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("start_rebuild_lock_head", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        if locked_head != observed_head {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }

        if let Some(row) = sqlx::query(
            "SELECT g.generation_id, g.computation_version, g.generation_state, \
                    g.rebuild_of_generation_id, g.created_source_watermark, \
                    g.created_at_unix_ms, g.activated_at_unix_ms, g.retired_at_unix_ms \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_state='building' \
             FOR UPDATE OF g,c",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("start_rebuild_load_existing", &error))?
        {
            let generation = decode_generation(organization_id, &row)?;
            if generation.computation_version() != &computation_version
                || generation.rebuild_of() != Some(active_generation_id)
            {
                return Err(ProjectionError::permanent(
                    ProjectionErrorCode::GenerationConflict,
                ));
            }
            transaction
                .commit()
                .await
                .map_err(|error| database_failure("start_rebuild_commit", &error))?;
            return Ok(generation);
        }

        let generation_id: i64 = sqlx::query_scalar(
            "INSERT INTO apolysis_projection.generations (\
                organization_id, computation_version, generation_state, \
                rebuild_of_generation_id, created_source_watermark, created_at_unix_ms\
             ) VALUES ($1,$2,'building',$3,$4,$5) RETURNING generation_id",
        )
        .bind(organization_id.as_str())
        .bind(computation_version.as_str())
        .bind(active_generation_id.get())
        .bind(sql_nonnegative(source_watermark)?)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| database_failure("start_rebuild_insert_generation", &error))?;
        let generation_id = GenerationId::try_from(generation_id)?;
        sqlx::query(
            "INSERT INTO apolysis_projection.checkpoints (\
                organization_id, generation_id, input_watermark, updated_at_unix_ms\
             ) VALUES ($1,$2,0,$3)",
        )
        .bind(organization_id.as_str())
        .bind(generation_id.get())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("start_rebuild_insert_checkpoint", &error))?;
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("start_rebuild_commit", &error))?;
        Ok(ProjectionGeneration {
            key: GenerationKey::new(organization_id.clone(), generation_id),
            computation_version,
            state: GenerationState::Building,
            rebuild_of: Some(active_generation_id),
            created_source_watermark: source_watermark,
            created_at_unix_ms: now_unix_ms,
            activated_at_unix_ms: None,
            retired_at_unix_ms: None,
        })
    }

    /// Apply at most one configured, strictly contiguous input batch.
    ///
    /// Workers serialize only on the organization-generation checkpoint. An
    /// active generation also publishes the matching outbox rows in the same
    /// transaction; a building generation ignores mutable delivery state and
    /// always rebuilds from the immutable ledger/outbox identity join.
    pub async fn project_next(
        &self,
        key: &GenerationKey,
        now_unix_ms: u64,
    ) -> ProjectionResult<ProjectionBatchOutcome> {
        sql_positive(now_unix_ms)?;
        let mut attempt = 1_u8;
        loop {
            match self.project_once(key, now_unix_ms).await {
                Ok(outcome) => return Ok(outcome),
                Err(ProjectAttemptFailure::Commit(error)) => return Err(error),
                Err(ProjectAttemptFailure::Input(failure)) => {
                    self.persist_input_failure(key, now_unix_ms, &failure)
                        .await?;
                    return Err(ProjectionError::permanent(failure.public_code));
                }
                Err(ProjectAttemptFailure::Error(error)) => {
                    if !error.is_retryable() || attempt >= self.config.transaction_retry_limit() {
                        return Err(error);
                    }
                    tracing::debug!(
                        target: "apolysis_projection_postgres",
                        attempt,
                        max_attempts = self.config.transaction_retry_limit(),
                        "Retrying a bounded projection transaction"
                    );
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt) * 10)).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Atomically activate one caught-up organization-local rebuild generation.
    pub async fn cut_over(
        &self,
        key: &GenerationKey,
        now_unix_ms: u64,
    ) -> ProjectionResult<Cutover> {
        let now = sql_positive(now_unix_ms)?;
        let mut transaction = self.begin_scoped(key.organization_id()).await?;

        // This row lock is the short organization-local cutover barrier. Gateway
        // sequence allocation for other organizations remains independent.
        let source_high =
            source_watermark_for_update(&mut transaction, key.organization_id()).await?;
        let candidate = sqlx::query(
            "SELECT g.generation_id, g.generation_state, g.rebuild_of_generation_id, \
                    c.input_watermark, c.last_error_code \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_id=$2 FOR UPDATE OF g,c",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_candidate", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let state = decode_generation_state(&row_string(&candidate, "generation_state")?)?;
        let rebuild_of = row_optional_i64(&candidate, "rebuild_of_generation_id")?
            .map(GenerationId::try_from)
            .transpose()?
            .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::GenerationConflict))?;
        let candidate_watermark = sql_u64(row_i64(&candidate, "input_watermark")?)?;
        if state != GenerationState::Building
            || row_optional_string(&candidate, "last_error_code")?.is_some()
            || candidate_watermark != source_high
        {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationNotReady,
            ));
        }

        let observed_head: (i64, i64) = sqlx::query_as(
            "SELECT active_generation_id, cutover_revision \
             FROM apolysis_projection.organization_heads \
             WHERE organization_id=$1",
        )
        .bind(key.organization_id().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_observe_head", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let previous_generation = GenerationId::try_from(observed_head.0)?;
        if previous_generation != rebuild_of {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }

        // Active projectors lock this generation/checkpoint pair before they
        // update the head. Taking the same order prevents a projector and a
        // cutover from owning one side of a generation↔head lock cycle.
        let previous = sqlx::query(
            "SELECT g.generation_state \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_id=$2 \
             FOR UPDATE OF g,c",
        )
        .bind(key.organization_id().as_str())
        .bind(previous_generation.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_lock_previous", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::GenerationConflict))?;
        if decode_generation_state(&row_string(&previous, "generation_state")?)?
            != GenerationState::Active
        {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }

        let locked_head: (i64, i64) = sqlx::query_as(
            "SELECT active_generation_id, cutover_revision \
             FROM apolysis_projection.organization_heads \
             WHERE organization_id=$1 FOR UPDATE",
        )
        .bind(key.organization_id().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_lock_head", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        if locked_head != observed_head {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }
        let next_cutover_revision = sql_u64(locked_head.1)?
            .checked_add(1)
            .ok_or_else(|| invariant_failure("cutover_revision_overflow"))?;

        let unavailable_outbox_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM apolysis_gateway.projection_outbox \
             WHERE organization_id=$1 AND ingest_sequence <= $2 \
               AND delivery_state NOT IN ('pending','published')",
        )
        .bind(key.organization_id().as_str())
        .bind(sql_nonnegative(source_high)?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_outbox_check", &error))?;
        if unavailable_outbox_count != 0 {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationNotReady,
            ));
        }
        sqlx::query(
            "UPDATE apolysis_gateway.projection_outbox \
             SET delivery_state='published', attempt_count=attempt_count+1, \
                 claimed_by=NULL, claimed_at_unix_ms=NULL, published_at_unix_ms=$3, \
                 last_error_code=NULL \
             WHERE organization_id=$1 AND ingest_sequence <= $2 \
               AND delivery_state='pending'",
        )
        .bind(key.organization_id().as_str())
        .bind(sql_nonnegative(source_high)?)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_publish_outbox", &error))?;

        let retired = sqlx::query(
            "UPDATE apolysis_projection.generations \
             SET generation_state='retired', retired_at_unix_ms=$3 \
             WHERE organization_id=$1 AND generation_id=$2 AND generation_state='active'",
        )
        .bind(key.organization_id().as_str())
        .bind(previous_generation.get())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_retire_previous", &error))?;
        if retired.rows_affected() != 1 {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }
        let activated = sqlx::query(
            "UPDATE apolysis_projection.generations \
             SET generation_state='active', activated_at_unix_ms=$3 \
             WHERE organization_id=$1 AND generation_id=$2 AND generation_state='building'",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_activate_candidate", &error))?;
        if activated.rows_affected() != 1 {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }
        let head_update = sqlx::query(
            "UPDATE apolysis_projection.organization_heads \
             SET active_generation_id=$2, cutover_revision=$3, \
                 query_visible_watermark=$4, cutover_at_unix_ms=$5 \
             WHERE organization_id=$1 AND active_generation_id=$6",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .bind(sql_positive(next_cutover_revision)?)
        .bind(sql_nonnegative(source_high)?)
        .bind(now)
        .bind(previous_generation.get())
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("cutover_update_head", &error))?;
        if head_update.rows_affected() != 1 {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            ));
        }
        if let Err(error) = transaction.commit().await {
            return Err(match classify_commit_failure("cutover_commit", &error) {
                CommitFailure::Definite(error) | CommitFailure::OutcomeUnknown(error) => error,
            });
        }
        Ok(Cutover {
            previous_generation,
            active_generation: key.generation_id(),
            cutover_revision: next_cutover_revision,
            query_visible_watermark: source_high,
        })
    }

    async fn project_once(
        &self,
        key: &GenerationKey,
        now_unix_ms: u64,
    ) -> Result<ProjectionBatchOutcome, ProjectAttemptFailure> {
        let mut transaction = self
            .begin_scoped(key.organization_id())
            .await
            .map_err(ProjectAttemptFailure::Error)?;
        let result = self
            .project_in_transaction(&mut transaction, key, now_unix_ms)
            .await;
        match result {
            Ok(outcome) => {
                if let Err(error) = transaction.commit().await {
                    return Err(match classify_commit_failure("project_commit", &error) {
                        CommitFailure::Definite(error) => ProjectAttemptFailure::Error(error),
                        CommitFailure::OutcomeUnknown(error) => {
                            ProjectAttemptFailure::Commit(error)
                        }
                    });
                }
                Ok(outcome)
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    let _ = database_failure("project_rollback", &rollback_error);
                }
                Err(error)
            }
        }
    }

    async fn project_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key: &GenerationKey,
        now_unix_ms: u64,
    ) -> Result<ProjectionBatchOutcome, ProjectAttemptFailure> {
        let state_row = sqlx::query(
            "SELECT g.generation_state, c.input_watermark, c.last_commit_revision, \
                    c.updated_at_unix_ms, c.last_error_code, c.failed_ingest_sequence \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_id=$2 FOR UPDATE OF g,c",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| project_database("project_load_checkpoint", error))?
        .ok_or_else(|| {
            ProjectAttemptFailure::Error(ProjectionError::permanent(ProjectionErrorCode::NotFound))
        })?;
        let state = decode_generation_state(
            &state_row
                .try_get::<String, _>("generation_state")
                .map_err(|error| project_database("project_decode_checkpoint", error))?,
        )
        .map_err(ProjectAttemptFailure::Error)?;
        if !matches!(state, GenerationState::Active | GenerationState::Building) {
            return Err(ProjectAttemptFailure::Error(ProjectionError::permanent(
                ProjectionErrorCode::GenerationConflict,
            )));
        }
        let checkpoint =
            decode_checkpoint(key, &state_row).map_err(ProjectAttemptFailure::Error)?;
        let source_high = source_watermark(transaction, key.organization_id())
            .await
            .map_err(ProjectAttemptFailure::Error)?;
        if checkpoint.input_watermark() > source_high {
            return Err(ProjectAttemptFailure::Error(invariant_failure(
                "project_checkpoint_ahead",
            )));
        }
        if checkpoint.input_watermark() == source_high {
            if checkpoint.failure().is_some() {
                return Err(ProjectAttemptFailure::Error(ProjectionError::permanent(
                    ProjectionErrorCode::LedgerIntegrity,
                )));
            }
            return Ok(ProjectionBatchOutcome::CaughtUp(checkpoint));
        }

        let expected_start = checkpoint.input_watermark().checked_add(1).ok_or_else(|| {
            ProjectAttemptFailure::Error(invariant_failure("project_sequence_overflow"))
        })?;
        let through = checkpoint
            .input_watermark()
            .checked_add(u64::from(self.config.batch_size()))
            .map(|value| value.min(source_high))
            .ok_or_else(|| {
                ProjectAttemptFailure::Error(invariant_failure("project_batch_overflow"))
            })?;
        let rows = sqlx::query(
            "SELECT record.organization_id, record.run_id, record.ingest_sequence, \
                    record.schema_version, record.ingested_at_unix_ms, record.fact_kind, \
                    CASE WHEN octet_length(record.fact_json::text) <= $4 \
                         THEN record.fact_json ELSE NULL END AS fact_json, \
                    octet_length(record.fact_json::text) AS fact_size, record.fact_digest, \
                    outbox.topic AS outbox_topic, outbox.delivery_state AS outbox_state \
             FROM apolysis_gateway.record_items AS record \
             JOIN apolysis_gateway.projection_outbox AS outbox \
               ON outbox.organization_id=record.organization_id \
              AND outbox.ingest_sequence=record.ingest_sequence \
             WHERE record.organization_id=$1 \
               AND record.ingest_sequence BETWEEN $2 AND $3 \
             ORDER BY record.ingest_sequence",
        )
        .bind(key.organization_id().as_str())
        .bind(sql_positive(expected_start).map_err(ProjectAttemptFailure::Error)?)
        .bind(sql_positive(through).map_err(ProjectAttemptFailure::Error)?)
        .bind(MAX_LEDGER_ITEM_BYTES)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| project_database("project_load_input", error))?;

        let expected_count = usize::try_from(through - checkpoint.input_watermark())
            .map_err(|_| ProjectAttemptFailure::Error(invariant_failure("project_count")))?;
        let mut validated = Vec::with_capacity(expected_count);
        let mut expected_sequence = expected_start;
        for row in rows {
            let stored = stored_ledger_row(&row).map_err(ProjectAttemptFailure::Error)?;
            let actual_sequence = u64::try_from(stored.ingest_sequence).map_err(|_| {
                input_failure(
                    InputFailureCode::MetadataMismatch,
                    expected_sequence,
                    checkpoint.input_watermark(),
                )
            })?;
            if actual_sequence != expected_sequence {
                return Err(input_failure(
                    InputFailureCode::MissingInput,
                    expected_sequence,
                    checkpoint.input_watermark(),
                ));
            }
            if state == GenerationState::Active && stored.outbox_state != "pending" {
                return Err(input_failure(
                    InputFailureCode::OutboxState,
                    expected_sequence,
                    checkpoint.input_watermark(),
                ));
            }
            let item = validate_stored_ledger_row(stored).map_err(|code| {
                input_failure(code, expected_sequence, checkpoint.input_watermark())
            })?;
            validated.push(item);
            expected_sequence += 1;
        }
        if validated.len() != expected_count {
            return Err(input_failure(
                InputFailureCode::MissingInput,
                expected_sequence,
                checkpoint.input_watermark(),
            ));
        }

        let commit_revision = checkpoint
            .last_commit_revision()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| {
                ProjectAttemptFailure::Error(invariant_failure("project_revision_overflow"))
            })?;
        for row in &validated {
            apply_lifecycle_fact(
                transaction,
                key,
                checkpoint.input_watermark(),
                commit_revision,
                through,
                row,
            )
            .await?;
        }
        let digest = batch_digest(
            key.organization_id().as_str(),
            checkpoint.input_watermark(),
            through,
            &validated,
        );
        sqlx::query(
            "INSERT INTO apolysis_projection.commits (\
                organization_id, generation_id, commit_revision, previous_commit_revision, \
                from_input_watermark, through_input_watermark, record_count, \
                projected_at_unix_ms, batch_digest\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .bind(sql_positive(commit_revision).map_err(ProjectAttemptFailure::Error)?)
        .bind(
            checkpoint
                .last_commit_revision()
                .map(sql_positive)
                .transpose()
                .map_err(ProjectAttemptFailure::Error)?,
        )
        .bind(sql_nonnegative(checkpoint.input_watermark()).map_err(ProjectAttemptFailure::Error)?)
        .bind(sql_positive(through).map_err(ProjectAttemptFailure::Error)?)
        .bind(
            i16::try_from(validated.len()).map_err(|_| {
                ProjectAttemptFailure::Error(invariant_failure("project_record_count"))
            })?,
        )
        .bind(sql_positive(now_unix_ms).map_err(ProjectAttemptFailure::Error)?)
        .bind(digest.as_slice())
        .execute(&mut **transaction)
        .await
        .map_err(|error| project_database("project_insert_commit", error))?;
        let checkpoint_update = sqlx::query(
            "UPDATE apolysis_projection.checkpoints \
             SET input_watermark=$3, last_commit_revision=$4, updated_at_unix_ms=$5, \
                 checkpoint_health='ready', last_error_code=NULL, failed_ingest_sequence=NULL \
             WHERE organization_id=$1 AND generation_id=$2 AND input_watermark=$6",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .bind(sql_positive(through).map_err(ProjectAttemptFailure::Error)?)
        .bind(sql_positive(commit_revision).map_err(ProjectAttemptFailure::Error)?)
        .bind(sql_positive(now_unix_ms).map_err(ProjectAttemptFailure::Error)?)
        .bind(sql_nonnegative(checkpoint.input_watermark()).map_err(ProjectAttemptFailure::Error)?)
        .execute(&mut **transaction)
        .await
        .map_err(|error| project_database("project_update_checkpoint", error))?;
        if checkpoint_update.rows_affected() != 1 {
            return Err(ProjectAttemptFailure::Error(invariant_failure(
                "project_checkpoint_compare_and_swap",
            )));
        }

        if state == GenerationState::Active {
            let published = sqlx::query(
                "UPDATE apolysis_gateway.projection_outbox \
                 SET delivery_state='published', attempt_count=attempt_count+1, \
                     claimed_by=NULL, claimed_at_unix_ms=NULL, published_at_unix_ms=$4, \
                     last_error_code=NULL \
                 WHERE organization_id=$1 AND ingest_sequence BETWEEN $2 AND $3 \
                   AND delivery_state='pending'",
            )
            .bind(key.organization_id().as_str())
            .bind(sql_positive(expected_start).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(through).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(now_unix_ms).map_err(ProjectAttemptFailure::Error)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| project_database("project_publish_outbox", error))?;
            if published.rows_affected() != validated.len() as u64 {
                return Err(input_failure(
                    InputFailureCode::OutboxState,
                    expected_start,
                    checkpoint.input_watermark(),
                ));
            }
            let visible = sqlx::query(
                "UPDATE apolysis_projection.organization_heads \
                 SET query_visible_watermark=$3 \
                 WHERE organization_id=$1 AND active_generation_id=$2",
            )
            .bind(key.organization_id().as_str())
            .bind(key.generation_id().get())
            .bind(sql_positive(through).map_err(ProjectAttemptFailure::Error)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| project_database("project_update_visible", error))?;
            if visible.rows_affected() != 1 {
                return Err(ProjectAttemptFailure::Error(ProjectionError::permanent(
                    ProjectionErrorCode::GenerationConflict,
                )));
            }
        }

        Ok(ProjectionBatchOutcome::Applied(ProjectionCommit {
            key: key.clone(),
            revision: commit_revision,
            from_input_watermark: checkpoint.input_watermark(),
            through_input_watermark: through,
            record_count: u16::try_from(validated.len()).map_err(|_| {
                ProjectAttemptFailure::Error(invariant_failure("project_record_count"))
            })?,
            projected_at_unix_ms: now_unix_ms,
            batch_digest: hex(&digest),
        }))
    }

    async fn persist_input_failure(
        &self,
        key: &GenerationKey,
        now_unix_ms: u64,
        failure: &InputFailure,
    ) -> ProjectionResult<()> {
        let mut transaction = self.begin_scoped(key.organization_id()).await?;
        sqlx::query(
            "UPDATE apolysis_projection.checkpoints AS checkpoint \
             SET checkpoint_health='blocked', last_error_code=$4, \
                 failed_ingest_sequence=$5, updated_at_unix_ms=$6 \
             FROM apolysis_projection.generations AS generation \
             WHERE checkpoint.organization_id=$1 AND checkpoint.generation_id=$2 \
               AND checkpoint.input_watermark=$3 \
               AND generation.organization_id=checkpoint.organization_id \
               AND generation.generation_id=checkpoint.generation_id \
               AND generation.generation_state IN ('active','building')",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .bind(sql_nonnegative(failure.checkpoint_watermark)?)
        .bind(input_failure_name(failure.code))
        .bind(sql_positive(failure.ingest_sequence)?)
        .bind(sql_positive(now_unix_ms)?)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("persist_input_failure", &error))?;
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("persist_input_failure_commit", &error))
    }

    /// Read one generation's progress and durable source watermark.
    pub async fn generation_status(
        &self,
        key: &GenerationKey,
        now_unix_ms: u64,
    ) -> ProjectionResult<ProjectionStatus> {
        sql_positive(now_unix_ms)?;
        let mut transaction = self.begin_scoped(key.organization_id()).await?;
        let row = sqlx::query(
            "SELECT g.generation_id, g.computation_version, g.generation_state, \
                    g.rebuild_of_generation_id, g.created_source_watermark, \
                    g.created_at_unix_ms, g.activated_at_unix_ms, g.retired_at_unix_ms, \
                    c.input_watermark, c.last_commit_revision, c.updated_at_unix_ms, \
                    c.last_error_code, c.failed_ingest_sequence \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_id=$2 \
             FOR SHARE OF g,c",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("generation_status_load", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let generation = decode_generation(key.organization_id(), &row)?;
        let checkpoint = decode_checkpoint(key, &row)?;
        let durable_input_watermark =
            source_watermark(&mut transaction, key.organization_id()).await?;
        let query_visible_watermark: Option<i64> = sqlx::query_scalar(
            "SELECT query_visible_watermark \
             FROM apolysis_projection.organization_heads \
             WHERE organization_id=$1 AND active_generation_id=$2",
        )
        .bind(key.organization_id().as_str())
        .bind(key.generation_id().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("generation_status_visible", &error))?;
        let query_visible_watermark = query_visible_watermark
            .map(sql_u64)
            .transpose()?
            .unwrap_or(0);
        let lag_ms = projection_lag_ms(
            &mut transaction,
            key.organization_id(),
            checkpoint.input_watermark(),
            durable_input_watermark,
            now_unix_ms,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("generation_status_commit", &error))?;
        Ok(ProjectionStatus {
            generation,
            checkpoint,
            durable_input_watermark,
            query_visible_watermark,
            lag_ms,
        })
    }

    /// Read the active generation status for one organization.
    pub async fn active_status(
        &self,
        organization_id: &OrganizationId,
        now_unix_ms: u64,
    ) -> ProjectionResult<ProjectionStatus> {
        sql_positive(now_unix_ms)?;
        let mut transaction = self.begin_scoped(organization_id).await?;
        // Lock the head before reading its generation. Project and cutover
        // transactions must update this row before commit, so their generation
        // changes cannot become visible while this status snapshot is built.
        let head: (i64, i64) = sqlx::query_as(
            "SELECT head.active_generation_id, head.query_visible_watermark \
             FROM apolysis_projection.organization_heads AS head \
             WHERE head.organization_id=$1 FOR SHARE OF head",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("active_status_head", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let generation_id = GenerationId::try_from(head.0)?;
        let row = sqlx::query(
            "SELECT g.generation_id, g.computation_version, g.generation_state, \
                    g.rebuild_of_generation_id, g.created_source_watermark, \
                    g.created_at_unix_ms, g.activated_at_unix_ms, g.retired_at_unix_ms, \
                    c.input_watermark, c.last_commit_revision, c.updated_at_unix_ms, \
                    c.last_error_code, c.failed_ingest_sequence \
             FROM apolysis_projection.generations AS g \
             JOIN apolysis_projection.checkpoints AS c \
               ON c.organization_id=g.organization_id AND c.generation_id=g.generation_id \
             WHERE g.organization_id=$1 AND g.generation_id=$2",
        )
        .bind(organization_id.as_str())
        .bind(generation_id.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("active_status_load", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let generation = decode_generation(organization_id, &row)?;
        let checkpoint = decode_checkpoint(generation.key(), &row)?;
        let durable_input_watermark = source_watermark(&mut transaction, organization_id).await?;
        let query_visible_watermark = sql_u64(head.1)?;
        let lag_ms = projection_lag_ms(
            &mut transaction,
            organization_id,
            checkpoint.input_watermark(),
            durable_input_watermark,
            now_unix_ms,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("active_status_commit", &error))?;
        Ok(ProjectionStatus {
            generation,
            checkpoint,
            durable_input_watermark,
            query_visible_watermark,
            lag_ms,
        })
    }

    /// Return one tenant-scoped lifecycle/header projection from the active generation.
    pub async fn load_active_lifecycle(
        &self,
        organization_id: &OrganizationId,
        run_id: &RunId,
    ) -> ProjectionResult<Option<RunLifecycleRead>> {
        let mut transaction = self.begin_scoped(organization_id).await?;
        let row = sqlx::query(&lifecycle_select_sql(
            "WHERE lifecycle.organization_id=$1 AND lifecycle.run_id=$2",
        ))
        .bind(organization_id.as_str())
        .bind(run_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("load_active_lifecycle", &error))?;
        let result = row
            .as_ref()
            .map(|row| decode_lifecycle(organization_id, row))
            .transpose()?;
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("load_active_lifecycle_commit", &error))?;
        Ok(result)
    }

    /// Traverse active run identities in a bounded immutable-key order.
    ///
    /// The cursor is an internal generation-bound keyset position, not an
    /// authenticated Query API token. Its watermark pins membership only; a
    /// future Query layer must version rows to promise an as-of field snapshot.
    pub async fn list_active_lifecycle(
        &self,
        organization_id: &OrganizationId,
        cursor: Option<&LifecycleCursor>,
        limit: u16,
    ) -> ProjectionResult<LifecyclePage> {
        if !(1..=MAX_LIFECYCLE_PAGE_SIZE).contains(&limit) {
            return Err(ProjectionError::permanent(
                ProjectionErrorCode::InvalidArgument,
            ));
        }
        let mut transaction = self.begin_scoped(organization_id).await?;
        let head: (i64, i64) = sqlx::query_as(
            "SELECT head.active_generation_id, head.query_visible_watermark \
             FROM apolysis_projection.organization_heads AS head \
             WHERE head.organization_id=$1 FOR SHARE OF head",
        )
        .bind(organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| database_failure("list_active_lifecycle_head", &error))?
        .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
        let generation_id = GenerationId::try_from(head.0)?;
        let current_visible = sql_u64(head.1)?;
        let (visible_input_watermark, cursor_time, cursor_run) = match cursor {
            Some(cursor) => {
                if &cursor.organization_id != organization_id {
                    return Err(ProjectionError::permanent(ProjectionErrorCode::NotFound));
                }
                if cursor.generation_id != generation_id {
                    return Err(ProjectionError::permanent(
                        ProjectionErrorCode::CursorExpired,
                    ));
                }
                if cursor.visible_input_watermark > current_visible {
                    return Err(ProjectionError::permanent(
                        ProjectionErrorCode::CursorExpired,
                    ));
                }
                (
                    cursor.visible_input_watermark,
                    Some(sql_positive(cursor.opened_at_unix_ms)?),
                    Some(cursor.run_id.as_str()),
                )
            }
            None => (current_visible, None, None),
        };
        let requested = i64::from(limit) + 1;
        let rows = sqlx::query(&lifecycle_select_sql(
            "WHERE lifecycle.organization_id=$1 \
               AND lifecycle.opened_ingest_sequence <= $2 \
               AND ($3::bigint IS NULL \
                    OR lifecycle.opened_at_unix_ms < $3 \
                    OR (lifecycle.opened_at_unix_ms = $3 AND lifecycle.run_id > $4)) \
             ORDER BY lifecycle.opened_at_unix_ms DESC, lifecycle.run_id ASC LIMIT $5",
        ))
        .bind(organization_id.as_str())
        .bind(sql_nonnegative(visible_input_watermark)?)
        .bind(cursor_time)
        .bind(cursor_run)
        .bind(requested)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| database_failure("list_active_lifecycle_rows", &error))?;
        let has_more = rows.len() > usize::from(limit);
        let mut items = rows
            .iter()
            .take(usize::from(limit))
            .map(|row| decode_lifecycle(organization_id, row))
            .collect::<ProjectionResult<Vec<_>>>()?;
        let next_cursor = if has_more {
            items.last().map(|item| LifecycleCursor {
                organization_id: organization_id.clone(),
                generation_id,
                visible_input_watermark,
                opened_at_unix_ms: item.opened_at_unix_ms(),
                run_id: item.run_id().clone(),
            })
        } else {
            None
        };
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("list_active_lifecycle_commit", &error))?;
        Ok(LifecyclePage {
            items: std::mem::take(&mut items),
            limit,
            visible_input_watermark,
            next_cursor,
        })
    }

    async fn begin_scoped<'a>(
        &'a self,
        organization_id: &OrganizationId,
    ) -> ProjectionResult<Transaction<'a, Postgres>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_failure("transaction_begin", &error))?;
        let lock_timeout = format!("{}ms", self.config.lock_timeout_ms());
        let statement_timeout = format!("{}ms", self.config.statement_timeout_ms());
        sqlx::query(
            "SELECT set_config('apolysis.organization_id',$1,true), \
                    set_config('lock_timeout',$2,true), \
                    set_config('statement_timeout',$3,true)",
        )
        .bind(organization_id.as_str())
        .bind(lock_timeout)
        .bind(statement_timeout)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("transaction_scope", &error))?;
        Ok(transaction)
    }
}

enum ProjectAttemptFailure {
    Commit(ProjectionError),
    Input(InputFailure),
    Error(ProjectionError),
}

struct InputFailure {
    code: InputFailureCode,
    ingest_sequence: u64,
    checkpoint_watermark: u64,
    public_code: ProjectionErrorCode,
}

fn input_failure(
    code: InputFailureCode,
    ingest_sequence: u64,
    checkpoint_watermark: u64,
) -> ProjectAttemptFailure {
    let public_code = match code {
        InputFailureCode::MissingInput => ProjectionErrorCode::LedgerDiscontinuity,
        InputFailureCode::LifecycleConflict => ProjectionErrorCode::LifecycleConflict,
        InputFailureCode::OversizedInput
        | InputFailureCode::DigestMismatch
        | InputFailureCode::InvalidContract
        | InputFailureCode::MetadataMismatch
        | InputFailureCode::OutboxState => ProjectionErrorCode::LedgerIntegrity,
    };
    ProjectAttemptFailure::Input(InputFailure {
        code,
        ingest_sequence,
        checkpoint_watermark,
        public_code,
    })
}

fn project_database(stage: &'static str, error: sqlx::Error) -> ProjectAttemptFailure {
    ProjectAttemptFailure::Error(database_failure(stage, &error))
}

fn stored_ledger_row(row: &sqlx::postgres::PgRow) -> ProjectionResult<StoredLedgerRow> {
    Ok(StoredLedgerRow {
        organization_id: row_string(row, "organization_id")?,
        run_id: row_string(row, "run_id")?,
        ingest_sequence: row_i64(row, "ingest_sequence")?,
        schema_version: row_string(row, "schema_version")?,
        ingested_at_unix_ms: row_i64(row, "ingested_at_unix_ms")?,
        fact_kind: row_string(row, "fact_kind")?,
        fact_json: row
            .try_get("fact_json")
            .map_err(|error| database_failure("ledger_row_decode", &error))?,
        fact_size: row
            .try_get("fact_size")
            .map_err(|error| database_failure("ledger_row_decode", &error))?,
        fact_digest: row
            .try_get("fact_digest")
            .map_err(|error| database_failure("ledger_row_decode", &error))?,
        outbox_topic: row_string(row, "outbox_topic")?,
        outbox_state: row_string(row, "outbox_state")?,
    })
}

async fn apply_lifecycle_fact(
    transaction: &mut Transaction<'_, Postgres>,
    key: &GenerationKey,
    checkpoint_watermark: u64,
    commit_revision: u64,
    commit_watermark: u64,
    row: &ValidatedLedgerRow,
) -> Result<(), ProjectAttemptFailure> {
    let item = &row.item;
    match item.fact() {
        AgentExecutionRecordFact::RunOpened(descriptor) => {
            if descriptor.state() != RunState::Opening {
                return Err(input_failure(
                    InputFailureCode::LifecycleConflict,
                    item.ingest_sequence(),
                    checkpoint_watermark,
                ));
            }
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM apolysis_projection.run_lifecycle \
                 WHERE organization_id=$1 AND generation_id=$2 AND run_id=$3)",
            )
            .bind(key.organization_id().as_str())
            .bind(key.generation_id().get())
            .bind(item.run_id().as_str())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| project_database("apply_run_opened_probe", error))?;
            if exists {
                return Err(input_failure(
                    InputFailureCode::LifecycleConflict,
                    item.ingest_sequence(),
                    checkpoint_watermark,
                ));
            }
            sqlx::query(
                "INSERT INTO apolysis_projection.run_lifecycle (\
                    organization_id, generation_id, run_id, authority_kind, authority_id, \
                    principal_kind, principal_id, objective_ref, environment, \
                    privacy_profile_ref, retention_profile_ref, run_state, opened_at_unix_ms, \
                    state_changed_at_unix_ms, terminal_at_unix_ms, lifecycle_revision, \
                    opened_ingest_sequence, last_lifecycle_ingest_sequence, \
                    last_modified_commit_revision, last_modified_commit_watermark\
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'opening',$12,$12,NULL,1,$13,$13,$14,$15)",
            )
            .bind(key.organization_id().as_str())
            .bind(key.generation_id().get())
            .bind(item.run_id().as_str())
            .bind(enum_name(&descriptor.authority().kind()).map_err(ProjectAttemptFailure::Error)?)
            .bind(descriptor.authority().id())
            .bind(enum_name(&descriptor.principal().kind()).map_err(ProjectAttemptFailure::Error)?)
            .bind(descriptor.principal().id())
            .bind(descriptor.objective_ref())
            .bind(enum_name(&descriptor.environment()).map_err(ProjectAttemptFailure::Error)?)
            .bind(descriptor.policy().privacy_profile_ref())
            .bind(descriptor.policy().retention_profile_ref())
            .bind(sql_positive(item.ingested_at_unix_ms()).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(item.ingest_sequence()).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(commit_revision).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(commit_watermark).map_err(ProjectAttemptFailure::Error)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| project_database("apply_run_opened_insert", error))?;
        }
        AgentExecutionRecordFact::RunStateChanged(transition) => {
            let current: Option<String> = sqlx::query_scalar(
                "SELECT run_state FROM apolysis_projection.run_lifecycle \
                 WHERE organization_id=$1 AND generation_id=$2 AND run_id=$3 FOR UPDATE",
            )
            .bind(key.organization_id().as_str())
            .bind(key.generation_id().get())
            .bind(item.run_id().as_str())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| project_database("apply_transition_load", error))?;
            let current = current
                .ok_or_else(|| {
                    input_failure(
                        InputFailureCode::LifecycleConflict,
                        item.ingest_sequence(),
                        checkpoint_watermark,
                    )
                })
                .and_then(|value| {
                    decode_enum::<RunState>(&value).map_err(ProjectAttemptFailure::Error)
                })?;
            if current != transition.from() {
                return Err(input_failure(
                    InputFailureCode::LifecycleConflict,
                    item.ingest_sequence(),
                    checkpoint_watermark,
                ));
            }
            let terminal_at =
                if matches!(transition.to(), RunState::Finished | RunState::Incomplete) {
                    Some(
                        sql_positive(transition.recorded_at_unix_ms())
                            .map_err(ProjectAttemptFailure::Error)?,
                    )
                } else {
                    None
                };
            let updated = sqlx::query(
                "UPDATE apolysis_projection.run_lifecycle \
                 SET run_state=$4, state_changed_at_unix_ms=$5, terminal_at_unix_ms=$6, \
                     lifecycle_revision=lifecycle_revision+1, \
                     last_lifecycle_ingest_sequence=$7, \
                     last_modified_commit_revision=$8, last_modified_commit_watermark=$9 \
                 WHERE organization_id=$1 AND generation_id=$2 AND run_id=$3 AND run_state=$10",
            )
            .bind(key.organization_id().as_str())
            .bind(key.generation_id().get())
            .bind(item.run_id().as_str())
            .bind(enum_name(&transition.to()).map_err(ProjectAttemptFailure::Error)?)
            .bind(
                sql_positive(transition.recorded_at_unix_ms())
                    .map_err(ProjectAttemptFailure::Error)?,
            )
            .bind(terminal_at)
            .bind(sql_positive(item.ingest_sequence()).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(commit_revision).map_err(ProjectAttemptFailure::Error)?)
            .bind(sql_positive(commit_watermark).map_err(ProjectAttemptFailure::Error)?)
            .bind(enum_name(&transition.from()).map_err(ProjectAttemptFailure::Error)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| project_database("apply_transition_update", error))?;
            if updated.rows_affected() != 1 {
                return Err(input_failure(
                    InputFailureCode::LifecycleConflict,
                    item.ingest_sequence(),
                    checkpoint_watermark,
                ));
            }
        }
        AgentExecutionRecordFact::RunFinalizationDeclared(_)
        | AgentExecutionRecordFact::SourceRegistered(_)
        | AgentExecutionRecordFact::RuntimeBound(_)
        | AgentExecutionRecordFact::EvidenceAccepted(_)
        | AgentExecutionRecordFact::CoverageComputed(_) => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM apolysis_projection.run_lifecycle \
                 WHERE organization_id=$1 AND generation_id=$2 AND run_id=$3)",
            )
            .bind(key.organization_id().as_str())
            .bind(key.generation_id().get())
            .bind(item.run_id().as_str())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| project_database("apply_non_lifecycle_probe", error))?;
            if !exists {
                return Err(input_failure(
                    InputFailureCode::LifecycleConflict,
                    item.ingest_sequence(),
                    checkpoint_watermark,
                ));
            }
        }
    }
    Ok(())
}

async fn source_watermark_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
) -> ProjectionResult<u64> {
    let next: i64 = sqlx::query_scalar(
        "SELECT next_ingest_sequence FROM apolysis_gateway.organization_sequences \
         WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(organization_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_failure("source_watermark_for_update", &error))?
    .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
    sql_u64(
        next.checked_sub(1)
            .ok_or_else(|| invariant_failure("source_watermark_underflow"))?,
    )
}

async fn source_watermark(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
) -> ProjectionResult<u64> {
    let next: i64 = sqlx::query_scalar(
        "SELECT next_ingest_sequence FROM apolysis_gateway.organization_sequences \
         WHERE organization_id=$1",
    )
    .bind(organization_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_failure("source_watermark", &error))?
    .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
    sql_u64(
        next.checked_sub(1)
            .ok_or_else(|| invariant_failure("source_watermark_underflow"))?,
    )
}

async fn source_watermark_for_share(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
) -> ProjectionResult<u64> {
    let next: i64 = sqlx::query_scalar(
        "SELECT next_ingest_sequence FROM apolysis_gateway.organization_sequences \
         WHERE organization_id=$1 FOR SHARE",
    )
    .bind(organization_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_failure("source_watermark_for_share", &error))?
    .ok_or_else(|| ProjectionError::permanent(ProjectionErrorCode::NotFound))?;
    sql_u64(
        next.checked_sub(1)
            .ok_or_else(|| invariant_failure("source_watermark_underflow"))?,
    )
}

async fn projection_lag_ms(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
    checkpoint: u64,
    durable: u64,
    now_unix_ms: u64,
) -> ProjectionResult<u64> {
    if checkpoint >= durable {
        return Ok(0);
    }
    let expected = checkpoint
        .checked_add(1)
        .ok_or_else(|| invariant_failure("projection_lag_sequence_overflow"))?;
    let ingested_at: Option<i64> = sqlx::query_scalar(
        "SELECT ingested_at_unix_ms FROM apolysis_gateway.record_items \
         WHERE organization_id=$1 AND ingest_sequence=$2",
    )
    .bind(organization_id.as_str())
    .bind(sql_positive(expected)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| database_failure("projection_lag_input", &error))?;
    Ok(ingested_at
        .map(sql_u64)
        .transpose()?
        .map(|time| now_unix_ms.saturating_sub(time))
        .unwrap_or(0))
}

fn decode_generation(
    organization_id: &OrganizationId,
    row: &sqlx::postgres::PgRow,
) -> ProjectionResult<ProjectionGeneration> {
    let generation_id = GenerationId::try_from(row_i64(row, "generation_id")?)?;
    let computation_version =
        ComputationVersion::try_from(row_string(row, "computation_version")?)?;
    let state = decode_generation_state(&row_string(row, "generation_state")?)?;
    let rebuild_of = row_optional_i64(row, "rebuild_of_generation_id")?
        .map(GenerationId::try_from)
        .transpose()?;
    Ok(ProjectionGeneration {
        key: GenerationKey::new(organization_id.clone(), generation_id),
        computation_version,
        state,
        rebuild_of,
        created_source_watermark: sql_u64(row_i64(row, "created_source_watermark")?)?,
        created_at_unix_ms: sql_u64(row_i64(row, "created_at_unix_ms")?)?,
        activated_at_unix_ms: row_optional_i64(row, "activated_at_unix_ms")?
            .map(sql_u64)
            .transpose()?,
        retired_at_unix_ms: row_optional_i64(row, "retired_at_unix_ms")?
            .map(sql_u64)
            .transpose()?,
    })
}

fn decode_checkpoint(
    key: &GenerationKey,
    row: &sqlx::postgres::PgRow,
) -> ProjectionResult<ProjectionCheckpoint> {
    let failure = match (
        row_optional_string(row, "last_error_code")?,
        row_optional_i64(row, "failed_ingest_sequence")?,
    ) {
        (None, None) => None,
        (Some(code), Some(sequence)) => Some((decode_input_failure(&code)?, sql_u64(sequence)?)),
        _ => return Err(invariant_failure("checkpoint_failure_decode")),
    };
    Ok(ProjectionCheckpoint {
        key: key.clone(),
        input_watermark: sql_u64(row_i64(row, "input_watermark")?)?,
        last_commit_revision: row_optional_i64(row, "last_commit_revision")?
            .map(sql_u64)
            .transpose()?,
        updated_at_unix_ms: sql_u64(row_i64(row, "updated_at_unix_ms")?)?,
        failure,
    })
}

fn lifecycle_select_sql(predicate: &str) -> String {
    format!(
        "SELECT lifecycle.generation_id, generation.computation_version, \
                lifecycle.run_id, lifecycle.authority_kind, lifecycle.authority_id, \
                lifecycle.principal_kind, lifecycle.principal_id, lifecycle.objective_ref, \
                lifecycle.environment, lifecycle.privacy_profile_ref, \
                lifecycle.retention_profile_ref, lifecycle.run_state, \
                lifecycle.opened_at_unix_ms, lifecycle.state_changed_at_unix_ms, \
                lifecycle.terminal_at_unix_ms, lifecycle.lifecycle_revision, \
                lifecycle.opened_ingest_sequence, lifecycle.last_lifecycle_ingest_sequence \
         FROM apolysis_projection.organization_heads AS head \
         JOIN apolysis_projection.generations AS generation \
           ON generation.organization_id=head.organization_id \
          AND generation.generation_id=head.active_generation_id \
         JOIN apolysis_projection.run_lifecycle AS lifecycle \
           ON lifecycle.organization_id=head.organization_id \
          AND lifecycle.generation_id=head.active_generation_id {predicate}"
    )
}

fn decode_lifecycle(
    organization_id: &OrganizationId,
    row: &sqlx::postgres::PgRow,
) -> ProjectionResult<RunLifecycleRead> {
    let authority_kind: AuthorityKind = decode_enum(&row_string(row, "authority_kind")?)?;
    let principal_kind: PrincipalKind = decode_enum(&row_string(row, "principal_kind")?)?;
    Ok(RunLifecycleRead {
        generation_id: GenerationId::try_from(row_i64(row, "generation_id")?)?,
        computation_version: ComputationVersion::try_from(row_string(row, "computation_version")?)?,
        organization_id: organization_id.clone(),
        run_id: RunId::try_from(row_string(row, "run_id")?.as_str())
            .map_err(|_| invariant_failure("lifecycle_run_id"))?,
        authority: AuthorityRef::new(authority_kind, row_string(row, "authority_id")?)
            .map_err(|_| invariant_failure("lifecycle_authority"))?,
        principal: PrincipalRef::new(principal_kind, row_string(row, "principal_id")?)
            .map_err(|_| invariant_failure("lifecycle_principal"))?,
        objective_ref: row_string(row, "objective_ref")?,
        environment: decode_enum(&row_string(row, "environment")?)?,
        privacy_profile_ref: row_string(row, "privacy_profile_ref")?,
        retention_profile_ref: row_string(row, "retention_profile_ref")?,
        state: decode_enum(&row_string(row, "run_state")?)?,
        opened_at_unix_ms: sql_u64(row_i64(row, "opened_at_unix_ms")?)?,
        state_changed_at_unix_ms: sql_u64(row_i64(row, "state_changed_at_unix_ms")?)?,
        terminal_at_unix_ms: row_optional_i64(row, "terminal_at_unix_ms")?
            .map(sql_u64)
            .transpose()?,
        lifecycle_revision: sql_u64(row_i64(row, "lifecycle_revision")?)?,
        opened_ingest_sequence: sql_u64(row_i64(row, "opened_ingest_sequence")?)?,
        last_lifecycle_ingest_sequence: sql_u64(row_i64(row, "last_lifecycle_ingest_sequence")?)?,
    })
}

fn decode_generation_state(value: &str) -> ProjectionResult<GenerationState> {
    match value {
        "building" => Ok(GenerationState::Building),
        "active" => Ok(GenerationState::Active),
        "retired" => Ok(GenerationState::Retired),
        _ => Err(invariant_failure("generation_state_decode")),
    }
}

fn decode_input_failure(value: &str) -> ProjectionResult<InputFailureCode> {
    match value {
        "missing_input" => Ok(InputFailureCode::MissingInput),
        "oversized_input" => Ok(InputFailureCode::OversizedInput),
        "digest_mismatch" => Ok(InputFailureCode::DigestMismatch),
        "invalid_contract" => Ok(InputFailureCode::InvalidContract),
        "metadata_mismatch" => Ok(InputFailureCode::MetadataMismatch),
        "lifecycle_conflict" => Ok(InputFailureCode::LifecycleConflict),
        "outbox_state" => Ok(InputFailureCode::OutboxState),
        _ => Err(invariant_failure("input_failure_decode")),
    }
}

fn decode_enum<T: DeserializeOwned>(value: &str) -> ProjectionResult<T> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| invariant_failure("enum_decode"))
}

fn enum_name<T: Serialize>(value: &T) -> ProjectionResult<String> {
    serde_json::to_value(value)
        .map_err(|_| invariant_failure("enum_encode"))?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| invariant_failure("enum_encode"))
}

fn input_failure_name(value: InputFailureCode) -> &'static str {
    match value {
        InputFailureCode::MissingInput => "missing_input",
        InputFailureCode::OversizedInput => "oversized_input",
        InputFailureCode::DigestMismatch => "digest_mismatch",
        InputFailureCode::InvalidContract => "invalid_contract",
        InputFailureCode::MetadataMismatch => "metadata_mismatch",
        InputFailureCode::LifecycleConflict => "lifecycle_conflict",
        InputFailureCode::OutboxState => "outbox_state",
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn row_i64(row: &sqlx::postgres::PgRow, column: &'static str) -> ProjectionResult<i64> {
    row.try_get(column)
        .map_err(|error| database_failure("row_decode", &error))
}

fn row_optional_i64(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> ProjectionResult<Option<i64>> {
    row.try_get(column)
        .map_err(|error| database_failure("row_decode", &error))
}

fn row_string(row: &sqlx::postgres::PgRow, column: &'static str) -> ProjectionResult<String> {
    row.try_get(column)
        .map_err(|error| database_failure("row_decode", &error))
}

fn row_optional_string(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> ProjectionResult<Option<String>> {
    row.try_get(column)
        .map_err(|error| database_failure("row_decode", &error))
}

fn sql_positive(value: u64) -> ProjectionResult<i64> {
    if value == 0 || value > MAX_I_JSON_INTEGER {
        return Err(ProjectionError::permanent(
            ProjectionErrorCode::InvalidArgument,
        ));
    }
    i64::try_from(value)
        .map_err(|_| ProjectionError::permanent(ProjectionErrorCode::InvalidArgument))
}

fn sql_nonnegative(value: u64) -> ProjectionResult<i64> {
    if value > MAX_I_JSON_INTEGER {
        return Err(ProjectionError::permanent(
            ProjectionErrorCode::InvalidArgument,
        ));
    }
    i64::try_from(value)
        .map_err(|_| ProjectionError::permanent(ProjectionErrorCode::InvalidArgument))
}

fn sql_u64(value: i64) -> ProjectionResult<u64> {
    u64::try_from(value).map_err(|_| invariant_failure("negative_database_integer"))
}

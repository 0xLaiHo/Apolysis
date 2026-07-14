// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use apolysis_contracts::{
    AgentExecutionRecordFact, AgentExecutionRecordItem, AuthenticatedSourceContext,
    BindRuntimeResponse, ContractErrorCode, FinishRunResponse, IngestAck, JoinProofKind,
    OpenRunOutcome, OpenRunResponse, RunId, RunState, RunStateTransition, SourceKind,
};
use apolysis_gateway::{
    AuditReason, GatewayFailure, GatewayIdGenerator, GatewayRepository, LedgerCommand,
    LedgerOperation, LedgerOutcome, RepositoryFuture,
};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool, Postgres, Row, Transaction};
use zeroize::Zeroizing;

use crate::{
    error::{
        database_failure, idempotency_conflict, not_found, policy_failure, report_database_retry,
        repository_failure,
    },
    model::{
        enum_name, hex_digest, join_proof_digest, json_decode, json_value, principal_kind_name,
        sha256_bytes, sql_i64, sql_u64, OperationIdentity, ReplayOutcome, MAX_SQL_INTEGER,
    },
    replay::{Aes256GcmReplayProtector, ReplayProtector, SealedReplay},
};

const DEFAULT_REPLAY_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const DEFAULT_MAX_TRANSACTION_RETRIES: u32 = 3;
const DEFAULT_LOCK_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 15_000;
const MAX_TRANSACTION_RETRIES: u32 = 10;
const MAX_DATABASE_TIMEOUT_MS: u64 = 5 * 60 * 1_000;
const AES_GCM_TAG_BYTES: usize = 16;

async fn qualify_served_connection(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    let has_origin_replication_role: bool =
        sqlx::query_scalar("SELECT current_setting('session_replication_role', false) = 'origin'")
            .fetch_one(connection)
            .await?;
    if !has_origin_replication_role {
        return Err(sqlx::Error::Protocol(
            "served PostgreSQL session failed qualification".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresGatewayConfig {
    replay_ttl_ms: u64,
    max_transaction_retries: u32,
    max_connections: u32,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
}

impl PostgresGatewayConfig {
    pub fn new(
        replay_ttl_ms: u64,
        max_transaction_retries: u32,
        max_connections: u32,
    ) -> Result<Self, GatewayFailure> {
        if replay_ttl_ms == 0
            || replay_ttl_ms > MAX_SQL_INTEGER
            || max_transaction_retries > MAX_TRANSACTION_RETRIES
            || max_connections == 0
            || max_connections > 256
        {
            return Err(repository_failure());
        }
        Ok(Self {
            replay_ttl_ms,
            max_transaction_retries,
            max_connections,
            lock_timeout_ms: DEFAULT_LOCK_TIMEOUT_MS,
            statement_timeout_ms: DEFAULT_STATEMENT_TIMEOUT_MS,
        })
    }

    pub fn with_database_timeouts(
        mut self,
        lock_timeout_ms: u64,
        statement_timeout_ms: u64,
    ) -> Result<Self, GatewayFailure> {
        if lock_timeout_ms == 0
            || statement_timeout_ms == 0
            || lock_timeout_ms > statement_timeout_ms
            || statement_timeout_ms > MAX_DATABASE_TIMEOUT_MS
        {
            return Err(repository_failure());
        }
        self.lock_timeout_ms = lock_timeout_ms;
        self.statement_timeout_ms = statement_timeout_ms;
        Ok(self)
    }

    pub fn replay_ttl_ms(&self) -> u64 {
        self.replay_ttl_ms
    }

    pub fn max_transaction_retries(&self) -> u32 {
        self.max_transaction_retries
    }

    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    pub fn lock_timeout_ms(&self) -> u64 {
        self.lock_timeout_ms
    }

    pub fn statement_timeout_ms(&self) -> u64 {
        self.statement_timeout_ms
    }
}

impl Default for PostgresGatewayConfig {
    fn default() -> Self {
        Self {
            replay_ttl_ms: DEFAULT_REPLAY_TTL_MS,
            max_transaction_retries: DEFAULT_MAX_TRANSACTION_RETRIES,
            max_connections: 16,
            lock_timeout_ms: DEFAULT_LOCK_TIMEOUT_MS,
            statement_timeout_ms: DEFAULT_STATEMENT_TIMEOUT_MS,
        }
    }
}

/// PostgreSQL-backed implementation of the Gateway atomic command seam.
#[derive(Clone)]
pub struct PostgresGatewayRepository {
    pub(crate) pool: PgPool,
    pub(crate) replay_protector: Arc<Aes256GcmReplayProtector>,
    pub(crate) config: PostgresGatewayConfig,
}

impl PostgresGatewayRepository {
    pub fn from_pool(
        pool: PgPool,
        replay_protector: Arc<Aes256GcmReplayProtector>,
        config: PostgresGatewayConfig,
    ) -> Self {
        Self {
            pool,
            replay_protector,
            config,
        }
    }

    /// Connect to an already-migrated Gateway database.
    ///
    /// Production runtimes must use this constructor so their database role
    /// does not need schema-owner or migration privileges. Every physical
    /// connection is qualified for normal trigger execution before pool use.
    pub async fn connect(
        database_url: &str,
        replay_protector: Arc<Aes256GcmReplayProtector>,
        config: PostgresGatewayConfig,
    ) -> Result<Self, GatewayFailure> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections())
            .acquire_timeout(Duration::from_secs(10))
            .after_connect(|connection, _metadata| {
                Box::pin(async move { qualify_served_connection(connection).await })
            })
            .connect(database_url)
            .await
            .map_err(|error| database_failure("connect", &error))?;
        Ok(Self::from_pool(pool, replay_protector, config))
    }

    pub async fn register_join_grant(
        &self,
        issuer: &AuthenticatedSourceContext,
        joining_source: &AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), GatewayFailure> {
        self.register_join_authorization(
            issuer,
            joining_source,
            run_id,
            source_kind,
            proof_ref,
            expires_at_unix_ms,
            JoinProofKind::Grant,
        )
        .await
    }

    pub async fn register_join_policy(
        &self,
        issuer: &AuthenticatedSourceContext,
        joining_source: &AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &str,
        expires_at_unix_ms: u64,
    ) -> Result<(), GatewayFailure> {
        self.register_join_authorization(
            issuer,
            joining_source,
            run_id,
            source_kind,
            proof_ref,
            expires_at_unix_ms,
            JoinProofKind::RegistrationPolicy,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn register_join_authorization(
        &self,
        issuer: &AuthenticatedSourceContext,
        joining_source: &AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &str,
        expires_at_unix_ms: u64,
        kind: JoinProofKind,
    ) -> Result<(), GatewayFailure> {
        if proof_ref.is_empty()
            || proof_ref.len() > 512
            || proof_ref.chars().any(char::is_control)
            || expires_at_unix_ms == 0
            || expires_at_unix_ms > MAX_SQL_INTEGER
            || expires_at_unix_ms <= issuer.authentication().authenticated_at_unix_ms()
            || issuer.organization_id() != joining_source.organization_id()
        {
            return Err(policy_failure(ContractErrorCode::Forbidden));
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_failure("register_join_begin", &error))?;
        self.configure_transaction_deadlines(&mut transaction)
            .await
            .map_err(|failure| failure.failure)?;
        let run = self
            .load_run_for_update(&mut transaction, issuer.organization_id().as_str(), &run_id)
            .await
            .map_err(|failure| failure.failure)?;
        if run.initiating_source_registration_id != issuer.source_registration_id()
            || run.initiating_principal_kind != principal_kind_name(issuer.principal().kind())?
            || run.initiating_principal_id != issuer.principal().id()
            || !joining_source
                .registration_policy()
                .allowed_source_kinds()
                .contains(&source_kind)
            || matches!(run.state, RunState::Finished | RunState::Incomplete)
        {
            return Err(policy_failure(ContractErrorCode::Forbidden));
        }
        let proof_digest = join_proof_digest(proof_ref);
        let kind_name = enum_name(&kind)?;
        let source_kind_name = enum_name(&source_kind)?;
        let joining_principal_kind = principal_kind_name(joining_source.principal().kind())?;
        let issuer_principal_kind = principal_kind_name(issuer.principal().kind())?;
        let expires_at = sql_i64(expires_at_unix_ms)?;
        let issued_at = sql_i64(issuer.authentication().authenticated_at_unix_ms())?;
        let policy_revision = sql_i64(joining_source.authentication().policy_revision())?;
        let inserted = sqlx::query(
            "INSERT INTO apolysis_gateway.join_authorizations (\
                organization_id, proof_digest, authorization_kind, run_id, source_id, \
                source_kind, environment, source_registration_id, principal_kind, principal_id, \
                registration_policy_revision, issued_by_source_registration_id, \
                issued_by_principal_kind, issued_by_principal_id, issued_at_unix_ms, expires_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) \
             ON CONFLICT (organization_id, proof_digest) DO NOTHING",
        )
        .bind(issuer.organization_id().as_str())
        .bind(&proof_digest)
        .bind(&kind_name)
        .bind(run_id.as_str())
        .bind(joining_source.registration_policy().source_id().as_str())
        .bind(&source_kind_name)
        .bind(enum_name(&run.environment)?)
        .bind(joining_source.source_registration_id())
        .bind(&joining_principal_kind)
        .bind(joining_source.principal().id())
        .bind(policy_revision)
        .bind(issuer.source_registration_id())
        .bind(&issuer_principal_kind)
        .bind(issuer.principal().id())
        .bind(issued_at)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("register_join_insert", &error))?;
        if inserted.rows_affected() == 0 {
            let existing = sqlx::query(
                "SELECT authorization_kind, authorization_state, run_id, source_id, source_kind, \
                        environment, source_registration_id, principal_kind, principal_id, \
                        registration_policy_revision, expires_at_unix_ms \
                 FROM apolysis_gateway.join_authorizations \
                 WHERE organization_id=$1 AND proof_digest=$2 FOR UPDATE",
            )
            .bind(issuer.organization_id().as_str())
            .bind(&proof_digest)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| database_failure("register_join_load", &error))?;
            let identical = existing
                .try_get::<String, _>("authorization_kind")
                .map_err(|error| database_failure("register_join_decode", &error))?
                == kind_name
                && existing
                    .try_get::<String, _>("authorization_state")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == "pending"
                && existing
                    .try_get::<String, _>("run_id")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == run_id.as_str()
                && existing
                    .try_get::<String, _>("source_id")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == joining_source.registration_policy().source_id().as_str()
                && existing
                    .try_get::<String, _>("source_kind")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == source_kind_name
                && existing
                    .try_get::<String, _>("environment")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == enum_name(&run.environment)?
                && existing
                    .try_get::<String, _>("source_registration_id")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == joining_source.source_registration_id()
                && existing
                    .try_get::<String, _>("principal_kind")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == joining_principal_kind
                && existing
                    .try_get::<String, _>("principal_id")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == joining_source.principal().id()
                && existing
                    .try_get::<i64, _>("registration_policy_revision")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == policy_revision
                && existing
                    .try_get::<i64, _>("expires_at_unix_ms")
                    .map_err(|error| database_failure("register_join_decode", &error))?
                    == expires_at;
            if !identical {
                return Err(idempotency_conflict());
            }
        }
        transaction
            .commit()
            .await
            .map_err(|error| database_failure("register_join_commit", &error))
    }

    async fn execute_command(
        &self,
        command: &LedgerCommand,
        ids: &dyn GatewayIdGenerator,
    ) -> Result<LedgerOutcome, GatewayFailure> {
        let mut attempt = 0_u32;
        loop {
            let mut transaction = match self.pool.begin().await {
                Ok(transaction) => transaction,
                Err(error)
                    if is_transaction_restartable_error(&error)
                        && attempt < self.config.max_transaction_retries() =>
                {
                    attempt += 1;
                    report_database_retry(
                        "command_begin",
                        &error,
                        attempt,
                        self.config.max_transaction_retries(),
                    );
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                Err(error) => return Err(database_failure("command_begin", &error)),
            };
            let decision = if let Err(failure) =
                self.configure_transaction_deadlines(&mut transaction).await
            {
                Err(failure)
            } else {
                match command.operation() {
                    LedgerOperation::OpenRun {
                        context,
                        request,
                        now_unix_ms,
                        lease_expires_at_unix_ms,
                    } => {
                        self.execute_open_run(
                            &mut transaction,
                            context,
                            request,
                            now_unix_ms,
                            lease_expires_at_unix_ms,
                            ids,
                        )
                        .await
                    }
                    LedgerOperation::Ingest {
                        context,
                        request,
                        now_unix_ms,
                    } => {
                        self.execute_ingest(&mut transaction, context, request, now_unix_ms)
                            .await
                    }
                    LedgerOperation::BindRuntime {
                        context,
                        request,
                        now_unix_ms,
                    } => {
                        self.execute_bind_runtime(&mut transaction, context, request, now_unix_ms)
                            .await
                    }
                    LedgerOperation::FinishRun {
                        context,
                        request,
                        now_unix_ms,
                        finalization_deadline_unix_ms,
                    } => {
                        self.execute_finish_run(
                            &mut transaction,
                            context,
                            request,
                            now_unix_ms,
                            finalization_deadline_unix_ms,
                        )
                        .await
                    }
                }
            };
            match decision {
                Ok(outcome) => match transaction.commit().await {
                    Ok(()) => return Ok(outcome),
                    Err(error)
                        if is_transaction_restartable_error(&error)
                            && attempt < self.config.max_transaction_retries() =>
                    {
                        attempt += 1;
                        report_database_retry(
                            "command_commit",
                            &error,
                            attempt,
                            self.config.max_transaction_retries(),
                        );
                        tokio::time::sleep(retry_delay(attempt)).await;
                    }
                    Err(error) => return Err(database_failure("command_commit", &error)),
                },
                Err(failure)
                    if failure.retry_transaction
                        && attempt < self.config.max_transaction_retries() =>
                {
                    if let Err(error) = transaction.rollback().await {
                        let _ = database_failure("command_retry_rollback", &error);
                    }
                    attempt += 1;
                    tracing::debug!(
                        target: "apolysis_gateway_postgres",
                        stage = "command_transaction",
                        attempt,
                        max_attempts = self.config.max_transaction_retries(),
                        "Retrying a PostgreSQL Gateway transaction"
                    );
                    tokio::time::sleep(retry_delay(attempt)).await;
                }
                Err(failure) if failure.commit_on_failure => {
                    transaction
                        .commit()
                        .await
                        .map_err(|error| database_failure("command_reconcile_commit", &error))?;
                    return Err(failure.failure);
                }
                Err(failure) => {
                    if let Err(error) = transaction.rollback().await {
                        let _ = database_failure("command_rollback", &error);
                    }
                    return Err(failure.failure);
                }
            }
        }
    }

    async fn configure_transaction_deadlines(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> TxResult<()> {
        let has_origin_replication_role: bool = sqlx::query_scalar(
            "SELECT current_setting('session_replication_role', false) = 'origin'",
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("qualify_served_session", error))?;
        if !has_origin_replication_role {
            return Err(TxFailure::rollback(repository_failure()));
        }
        let lock_timeout = format!("{}ms", self.config.lock_timeout_ms());
        let statement_timeout = format!("{}ms", self.config.statement_timeout_ms());
        sqlx::query(
            "SELECT set_config('lock_timeout',$1,true), \
                    set_config('statement_timeout',$2,true)",
        )
        .bind(lock_timeout)
        .bind(statement_timeout)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("configure_transaction_deadlines", error))?;
        Ok(())
    }

    pub(crate) async fn lock_and_replay_operation(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        identity: &OperationIdentity,
        request_digest: &str,
        now_unix_ms: u64,
    ) -> TxResult<Option<LedgerOutcome>> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 573274117))")
            .bind(identity.advisory_lock_key())
            .execute(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("operation_lock", error))?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_gateway_operation($1,$2,$3,$4,$5,$6)",
        )
        .bind(&identity.organization_id)
        .bind(&identity.source_registration_id)
        .bind(&identity.principal_kind)
        .bind(&identity.principal_id)
        .bind(identity.operation_kind)
        .bind(&identity.client_operation_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("operation_row_lock", error))?;
        let existing = sqlx::query(
            "SELECT operation.operation_id, operation.request_digest, operation.outcome_kind, \
                    replay.encryption_algorithm, replay.cipher_version, replay.encryption_key_ref, \
                    replay.nonce, replay.authentication_tag, replay.aad_digest, \
                    replay.outcome_ciphertext, replay.expires_at_unix_ms \
             FROM apolysis_gateway.gateway_operations AS operation \
             LEFT JOIN apolysis_gateway.operation_replays AS replay \
               ON replay.organization_id=operation.organization_id \
              AND replay.operation_id=operation.operation_id \
             WHERE operation.organization_id=$1 \
               AND operation.source_registration_id=$2 \
               AND operation.principal_kind=$3 \
               AND operation.principal_id=$4 \
               AND operation.operation_kind=$5 \
               AND operation.client_operation_id=$6",
        )
        .bind(&identity.organization_id)
        .bind(&identity.source_registration_id)
        .bind(&identity.principal_kind)
        .bind(&identity.principal_id)
        .bind(identity.operation_kind)
        .bind(&identity.client_operation_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("operation_replay_load", error))?;
        let Some(row) = existing else {
            return Ok(None);
        };
        if row
            .try_get::<Vec<u8>, _>("request_digest")
            .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?
            != hex_digest(request_digest).map_err(TxFailure::rollback)?
        {
            return Err(TxFailure::rollback(idempotency_conflict()));
        }
        let outcome_kind: String = row
            .try_get("outcome_kind")
            .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?;
        if outcome_kind != identity.operation_kind
            || row
                .try_get::<Option<String>, _>("encryption_algorithm")
                .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?
                .as_deref()
                != Some("aes-256-gcm")
        {
            return Err(TxFailure::rollback(idempotency_conflict()));
        }
        let expires_at: i64 = row
            .try_get::<Option<i64>, _>("expires_at_unix_ms")
            .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?
            .ok_or_else(|| TxFailure::rollback(idempotency_conflict()))?;
        if sql_i64(now_unix_ms).map_err(TxFailure::rollback)? >= expires_at {
            return Err(TxFailure::rollback(idempotency_conflict()));
        }
        let key_id = row
            .try_get::<Option<String>, _>("encryption_key_ref")
            .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?
            .ok_or_else(|| TxFailure::rollback(idempotency_conflict()))?;
        let cipher_version = row
            .try_get::<Option<i32>, _>("cipher_version")
            .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| TxFailure::rollback(idempotency_conflict()))?;
        let nonce = required_optional_bytes(&row, "nonce")?;
        let tag = required_optional_bytes(&row, "authentication_tag")?;
        let mut ciphertext = required_optional_bytes(&row, "outcome_ciphertext")?;
        ciphertext.extend_from_slice(&tag);
        let sealed = SealedReplay::new(key_id, cipher_version, nonce, ciphertext)
            .map_err(TxFailure::rollback)?;
        let associated_data = identity.associated_data(request_digest, expires_at);
        let expected_aad_digest = sha256_bytes(&associated_data);
        if required_optional_bytes(&row, "aad_digest")? != expected_aad_digest {
            return Err(TxFailure::rollback(idempotency_conflict()));
        }
        let plaintext = self
            .replay_protector
            .open(&associated_data, &sealed)
            .map_err(TxFailure::rollback)?;
        let replay: ReplayOutcome = serde_json::from_slice(&plaintext)
            .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let outcome = idempotent_outcome(replay.into()).map_err(TxFailure::rollback)?;
        Ok(Some(outcome))
    }

    pub(crate) async fn store_operation(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        identity: &OperationIdentity,
        request_digest: &str,
        run_id: &RunId,
        now_unix_ms: u64,
        outcome: &LedgerOutcome,
    ) -> TxResult<()> {
        let now = sql_i64(now_unix_ms).map_err(TxFailure::rollback)?;
        let replay_expires = now_unix_ms
            .checked_add(self.config.replay_ttl_ms())
            .filter(|value| *value <= MAX_SQL_INTEGER)
            .ok_or_else(|| TxFailure::rollback(repository_failure()))?;
        let replay_expires = sql_i64(replay_expires).map_err(TxFailure::rollback)?;
        let operation_id: i64 = sqlx::query_scalar(
            "INSERT INTO apolysis_gateway.gateway_operations (\
                organization_id, source_registration_id, principal_kind, principal_id, \
                operation_kind, client_operation_id, request_digest, run_id, outcome_kind, \
                committed_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING operation_id",
        )
        .bind(&identity.organization_id)
        .bind(&identity.source_registration_id)
        .bind(&identity.principal_kind)
        .bind(&identity.principal_id)
        .bind(identity.operation_kind)
        .bind(&identity.client_operation_id)
        .bind(hex_digest(request_digest).map_err(TxFailure::rollback)?)
        .bind(run_id.as_str())
        .bind(identity.operation_kind)
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("operation_insert", error))?;
        let associated_data = identity.associated_data(request_digest, replay_expires);
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&ReplayOutcome::from(outcome.clone()))
                .map_err(|_| TxFailure::rollback(repository_failure()))?,
        );
        let sealed = self
            .replay_protector
            .seal(&associated_data, &plaintext)
            .map_err(TxFailure::rollback)?;
        if sealed.ciphertext().len() <= AES_GCM_TAG_BYTES {
            return Err(TxFailure::rollback(repository_failure()));
        }
        let split = sealed.ciphertext().len() - AES_GCM_TAG_BYTES;
        let (ciphertext, authentication_tag) = sealed.ciphertext().split_at(split);
        sqlx::query(
            "INSERT INTO apolysis_gateway.operation_replays (\
                organization_id, operation_id, encryption_algorithm, cipher_version, \
                encryption_key_ref, wrapped_data_key, nonce, authentication_tag, aad_digest, \
                outcome_ciphertext, created_at_unix_ms, expires_at_unix_ms\
             ) VALUES ($1,$2,'aes-256-gcm',$3,$4,NULL,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&identity.organization_id)
        .bind(operation_id)
        .bind(i32::from(sealed.cipher_version()))
        .bind(sealed.key_id())
        .bind(sealed.nonce())
        .bind(authentication_tag)
        .bind(sha256_bytes(&associated_data))
        .bind(ciphertext)
        .bind(now)
        .bind(replay_expires)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("operation_replay_insert", error))?;
        Ok(())
    }

    pub(crate) async fn ensure_organization(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: &str,
        now_unix_ms: u64,
    ) -> TxResult<()> {
        sqlx::query(
            "INSERT INTO apolysis_gateway.organization_sequences (\
                organization_id, next_ingest_sequence, updated_at_unix_ms\
             ) VALUES ($1,1,$2) ON CONFLICT (organization_id) DO NOTHING",
        )
        .bind(organization_id)
        .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("organization_sequence_initialize", error))?;
        Ok(())
    }

    pub(crate) async fn append_fact(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        run_id: &RunId,
        ingested_at_unix_ms: u64,
        fact: AgentExecutionRecordFact,
    ) -> TxResult<u64> {
        self.append_facts(
            transaction,
            context,
            run_id,
            ingested_at_unix_ms,
            vec![fact],
        )
        .await?
        .pop()
        .ok_or_else(|| TxFailure::rollback(repository_failure()))
    }

    pub(crate) async fn append_facts(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        run_id: &RunId,
        ingested_at_unix_ms: u64,
        facts: Vec<AgentExecutionRecordFact>,
    ) -> TxResult<Vec<u64>> {
        if facts.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_organization(
            transaction,
            context.organization_id().as_str(),
            ingested_at_unix_ms,
        )
        .await?;
        let fact_count =
            u64::try_from(facts.len()).map_err(|_| TxFailure::rollback(repository_failure()))?;
        let fact_count_sql = sql_i64(fact_count).map_err(TxFailure::rollback)?;
        let first_sequence: i64 = sqlx::query_scalar(
            "UPDATE apolysis_gateway.organization_sequences \
             SET next_ingest_sequence=next_ingest_sequence+$2, updated_at_unix_ms=$3 \
             WHERE organization_id=$1 RETURNING next_ingest_sequence-$2",
        )
        .bind(context.organization_id().as_str())
        .bind(fact_count_sql)
        .bind(sql_i64(ingested_at_unix_ms).map_err(TxFailure::rollback)?)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("organization_sequence_reserve", error))?;
        let first_sequence = sql_u64(first_sequence).map_err(TxFailure::rollback)?;
        let ingested_at = sql_i64(ingested_at_unix_ms).map_err(TxFailure::rollback)?;
        let mut sequences = Vec::with_capacity(facts.len());
        for (offset, fact) in facts.into_iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| TxFailure::rollback(repository_failure()))?;
            let sequence = first_sequence
                .checked_add(offset)
                .ok_or_else(|| TxFailure::rollback(repository_failure()))?;
            let sequence_sql = sql_i64(sequence).map_err(TxFailure::rollback)?;
            let fact_kind = fact_kind(&fact);
            let item = AgentExecutionRecordItem::new(
                context.organization_id().clone(),
                run_id.clone(),
                sequence,
                ingested_at_unix_ms,
                fact,
            )
            .map_err(|_| TxFailure::rollback(repository_failure()))?;
            let canonical = serde_json_canonicalizer::to_vec(&item)
                .map_err(|_| TxFailure::rollback(repository_failure()))?;
            let item_json = json_value(&item).map_err(TxFailure::rollback)?;
            sqlx::query(
                "INSERT INTO apolysis_gateway.record_items (\
                    organization_id, run_id, ingest_sequence, ingested_at_unix_ms, fact_kind, \
                    fact_json, fact_digest, outbox_ingest_sequence\
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$3)",
            )
            .bind(context.organization_id().as_str())
            .bind(run_id.as_str())
            .bind(sequence_sql)
            .bind(ingested_at)
            .bind(fact_kind)
            .bind(item_json)
            .bind(sha256_bytes(&canonical))
            .execute(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("record_item_insert", error))?;
            sqlx::query(
                "INSERT INTO apolysis_gateway.projection_outbox (\
                    organization_id, ingest_sequence, available_at_unix_ms\
                 ) VALUES ($1,$2,$3)",
            )
            .bind(context.organization_id().as_str())
            .bind(sequence_sql)
            .bind(ingested_at)
            .execute(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("projection_outbox_insert", error))?;
            sequences.push(sequence);
        }
        Ok(sequences)
    }

    pub(crate) async fn load_run_for_update(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: &str,
        run_id: &RunId,
    ) -> TxResult<RunRow> {
        let row = sqlx::query(
            "SELECT state, environment, initiating_source_registration_id, \
                    initiating_principal_kind, initiating_principal_id, finalization_deadline_unix_ms \
             FROM apolysis_gateway.runs WHERE organization_id=$1 AND run_id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(run_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("load_run_for_update", error))?
        .ok_or_else(|| TxFailure::rollback(not_found()))?;
        Ok(RunRow {
            state: decode_enum_name(
                row.try_get("state")
                    .map_err(|error| TxFailure::from_sqlx_at("load_run_decode", error))?,
            )
            .map_err(TxFailure::rollback)?,
            environment: decode_enum_name(
                row.try_get("environment")
                    .map_err(|error| TxFailure::from_sqlx_at("load_run_decode", error))?,
            )
            .map_err(TxFailure::rollback)?,
            initiating_source_registration_id: row
                .try_get("initiating_source_registration_id")
                .map_err(|error| TxFailure::from_sqlx_at("load_run_decode", error))?,
            initiating_principal_kind: row
                .try_get("initiating_principal_kind")
                .map_err(|error| TxFailure::from_sqlx_at("load_run_decode", error))?,
            initiating_principal_id: row
                .try_get("initiating_principal_id")
                .map_err(|error| TxFailure::from_sqlx_at("load_run_decode", error))?,
            finalization_deadline_unix_ms: row
                .try_get::<Option<i64>, _>("finalization_deadline_unix_ms")
                .map_err(|error| TxFailure::from_sqlx_at("load_run_decode", error))?
                .map(sql_u64)
                .transpose()
                .map_err(TxFailure::rollback)?,
        })
    }

    pub(crate) async fn reconcile_expired_run(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        run_id: &RunId,
        run: &RunRow,
        now_unix_ms: u64,
    ) -> TxResult<bool> {
        let now = sql_i64(now_unix_ms).map_err(TxFailure::rollback)?;
        let unexpired_lease_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM apolysis_gateway.leases \
             WHERE organization_id=$1 AND run_id=$2 AND revoked_at_unix_ms IS NULL \
               AND expires_at_unix_ms>$3",
        )
        .bind(context.organization_id().as_str())
        .bind(run_id.as_str())
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("run_reconcile_lease_count", error))?;
        let deadline_elapsed = run.state == RunState::Finishing
            && run
                .finalization_deadline_unix_ms
                .is_some_and(|deadline| now_unix_ms >= deadline);
        let should_seal = match run.state {
            RunState::Active => unexpired_lease_count == 0,
            RunState::Finishing => deadline_elapsed || unexpired_lease_count == 0,
            RunState::Opening | RunState::Finished | RunState::Incomplete => false,
        };
        if !should_seal {
            return Ok(false);
        }
        self.append_fact(
            transaction,
            context,
            run_id,
            now_unix_ms,
            AgentExecutionRecordFact::RunStateChanged(
                RunStateTransition::new(run.state, RunState::Incomplete, now_unix_ms)
                    .map_err(|_| TxFailure::rollback(repository_failure()))?,
            ),
        )
        .await?;
        sqlx::query(
            "UPDATE apolysis_gateway.runs \
             SET state='incomplete', finalization_deadline_unix_ms=NULL, \
                 state_changed_at_unix_ms=$3, lock_version=lock_version+1 \
             WHERE organization_id=$1 AND run_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(run_id.as_str())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("run_reconcile_state_update", error))?;
        sqlx::query(
            "DELETE FROM apolysis_gateway.active_runtime_identities \
             WHERE organization_id=$1 AND run_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(run_id.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("run_reconcile_runtime_release", error))?;
        Ok(true)
    }
}

impl GatewayRepository for PostgresGatewayRepository {
    fn execute<'a>(
        &'a self,
        command: LedgerCommand,
        ids: &'a dyn GatewayIdGenerator,
    ) -> RepositoryFuture<'a, Result<LedgerOutcome, GatewayFailure>> {
        Box::pin(async move { self.execute_command(&command, ids).await })
    }
}

#[derive(Clone)]
pub(crate) struct RunRow {
    pub(crate) state: RunState,
    pub(crate) environment: apolysis_contracts::EnvironmentKind,
    pub(crate) initiating_source_registration_id: String,
    pub(crate) initiating_principal_kind: String,
    pub(crate) initiating_principal_id: String,
    pub(crate) finalization_deadline_unix_ms: Option<u64>,
}

pub(crate) struct TxFailure {
    pub(crate) failure: GatewayFailure,
    pub(crate) commit_on_failure: bool,
    pub(crate) retry_transaction: bool,
}

impl TxFailure {
    pub(crate) fn rollback(failure: GatewayFailure) -> Self {
        Self {
            failure,
            commit_on_failure: false,
            retry_transaction: false,
        }
    }

    pub(crate) fn commit(failure: GatewayFailure) -> Self {
        Self {
            failure,
            commit_on_failure: true,
            retry_transaction: false,
        }
    }

    pub(crate) fn from_sqlx_at(stage: &'static str, error: sqlx::Error) -> Self {
        let failure = database_failure(stage, &error);
        Self {
            failure,
            commit_on_failure: false,
            retry_transaction: is_transaction_restartable_error(&error),
        }
    }
}

pub(crate) type TxResult<T> = Result<T, TxFailure>;

fn retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(u64::from(attempt).saturating_mul(10).min(100))
}

fn is_transaction_restartable_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "40001" || code == "40P01")
}

fn decode_enum_name<T>(value: String) -> Result<T, GatewayFailure>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(Value::String(value)).map_err(|_| repository_failure())
}

fn required_optional_bytes(row: &sqlx::postgres::PgRow, column: &str) -> TxResult<Vec<u8>> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|error| TxFailure::from_sqlx_at("operation_replay_decode", error))?
        .ok_or_else(|| TxFailure::rollback(idempotency_conflict()))
}

fn fact_kind(fact: &AgentExecutionRecordFact) -> &'static str {
    match fact {
        AgentExecutionRecordFact::RunOpened(_) => "run_opened",
        AgentExecutionRecordFact::RunStateChanged(_) => "run_state_changed",
        AgentExecutionRecordFact::RunFinalizationDeclared(_) => "run_finalization_declared",
        AgentExecutionRecordFact::SourceRegistered(_) => "source_registered",
        AgentExecutionRecordFact::RuntimeBound(_) => "runtime_bound",
        AgentExecutionRecordFact::EvidenceAccepted(_) => "evidence_accepted",
        AgentExecutionRecordFact::CoverageComputed(_) => "coverage_computed",
    }
}

fn idempotent_outcome(outcome: LedgerOutcome) -> Result<LedgerOutcome, GatewayFailure> {
    match outcome {
        LedgerOutcome::OpenRun(original) => OpenRunResponse::new(
            original.run_id().clone(),
            original.source_id().clone(),
            original.source_stream_id(),
            OpenRunOutcome::IdempotentRetry,
            original.lease().clone(),
        )
        .map(LedgerOutcome::OpenRun)
        .map_err(|_| repository_failure()),
        LedgerOutcome::BindRuntime(original) => BindRuntimeResponse::new(
            original.run_id().clone(),
            original.binding_id(),
            original.accepted(),
            true,
        )
        .map(LedgerOutcome::BindRuntime)
        .map_err(|_| repository_failure()),
        LedgerOutcome::Ingest(original) => Ok(LedgerOutcome::Ingest(
            IngestAck::new(
                original.run_id().clone(),
                original.acknowledgements().to_vec(),
                original.durable_ingest_watermark(),
                original.source_watermark(),
                original.known_gaps().to_vec(),
            )
            .map_err(|_| repository_failure())?,
        )),
        LedgerOutcome::FinishRun(original) => FinishRunResponse::new(
            original.run_id().clone(),
            original.state(),
            original.finalization_deadline_unix_ms(),
            true,
        )
        .map(LedgerOutcome::FinishRun)
        .map_err(|_| repository_failure()),
    }
}

pub(crate) fn operation_identity(
    context: &AuthenticatedSourceContext,
    operation_kind: &'static str,
    client_operation_id: &str,
) -> Result<OperationIdentity, GatewayFailure> {
    Ok(OperationIdentity {
        organization_id: context.organization_id().to_string(),
        source_registration_id: context.source_registration_id().to_string(),
        principal_kind: principal_kind_name(context.principal().kind())?,
        principal_id: context.principal().id().to_string(),
        operation_kind,
        client_operation_id: client_operation_id.to_string(),
    })
}

pub(crate) fn next_id(
    ids: &dyn GatewayIdGenerator,
    kind: &'static str,
) -> Result<String, GatewayFailure> {
    ids.next_id(kind)
        .map_err(|_| GatewayFailure::repository_backpressure(250, AuditReason::EntropyUnavailable))
}

pub(crate) fn digest_bytes(value: &str) -> Result<Vec<u8>, GatewayFailure> {
    hex_digest(value)
}

pub(crate) fn decode_json<T: serde::de::DeserializeOwned>(
    value: Value,
) -> Result<T, GatewayFailure> {
    json_decode(value)
}

pub(crate) fn hash_runtime_identity(identity_ref: &str) -> Vec<u8> {
    crate::model::runtime_identity_digest(identity_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_deadlines_are_bounded_and_ordered() {
        let defaults = PostgresGatewayConfig::default();
        assert!(defaults.lock_timeout_ms() > 0);
        assert!(defaults.lock_timeout_ms() <= defaults.statement_timeout_ms());

        let configured = PostgresGatewayConfig::new(1_000, 2, 8)
            .and_then(|config| config.with_database_timeouts(250, 2_000));
        assert!(configured.is_ok());
        assert!(PostgresGatewayConfig::default()
            .with_database_timeouts(0, 2_000)
            .is_err());
        assert!(PostgresGatewayConfig::default()
            .with_database_timeouts(2_000, 1_000)
            .is_err());
        assert!(PostgresGatewayConfig::default()
            .with_database_timeouts(1_000, MAX_DATABASE_TIMEOUT_MS + 1)
            .is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    sync::{Arc, OnceLock},
};

use apolysis_contracts::{
    AuthenticatedSourceContext, ContractErrorCode, RunId, SourceKind, TrustProfile,
};
use apolysis_gateway::{AuditReason, GatewayClock, GatewayFailure};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use apolysis_gateway_testkit::{
    gateway_repository_conformance_tests, GatewayConformanceCounts, GatewayConformanceHarness,
    GatewayConformanceSnapshot, HarnessAdminFuture, HarnessFuture,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

static DATABASE_TEST_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

struct PostgresGatewayHarness {
    repository: PostgresGatewayRepository,
    inspection_pool: sqlx::PgPool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl GatewayConformanceHarness for PostgresGatewayHarness {
    type Repository = PostgresGatewayRepository;

    fn start() -> HarnessFuture<'static, Self> {
        Box::pin(async {
            let guard = DATABASE_TEST_LOCK
                .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
                .lock_owned()
                .await;
            let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL").map_err(|_| {
                "APOLYSIS_TEST_DATABASE_URL is required by the explicit PostgreSQL harness"
            })?;
            let protector = Arc::new(Aes256GcmReplayProtector::new(
                "integration-test-key",
                [("integration-test-key".to_string(), [41_u8; 32])],
            )?);
            let inspection_pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&database_url)
                .await?;
            MIGRATOR.run(&inspection_pool).await?;
            let config = PostgresGatewayConfig::new(24 * 60 * 60 * 1_000, 3, 4)?;
            let repository =
                PostgresGatewayRepository::connect(&database_url, protector, config).await?;
            sqlx::query(
                "TRUNCATE TABLE apolysis_gateway.organization_sequences \
                 RESTART IDENTITY CASCADE",
            )
            .execute(&inspection_pool)
            .await?;
            for statement in [
                "DELETE FROM apolysis_gateway.transaction_authority_audit",
                "DELETE FROM apolysis_gateway.gateway_authority_audit",
                "DELETE FROM apolysis_gateway.authority_change_audit",
                "DELETE FROM apolysis_gateway.source_authority_revisions",
                "DELETE FROM apolysis_gateway.transport_credentials",
                "DELETE FROM apolysis_gateway.source_registrations",
                "DELETE FROM apolysis_gateway.organizations",
            ] {
                sqlx::query(statement).execute(&inspection_pool).await?;
            }
            Ok(Self {
                repository,
                inspection_pool,
                _guard: guard,
            })
        })
    }

    fn repository(&self) -> Self::Repository {
        self.repository.clone()
    }

    fn snapshot(&self) -> HarnessFuture<'_, GatewayConformanceSnapshot> {
        Box::pin(async move {
            let counts = sqlx::query(
                "SELECT \
                    (SELECT count(*) FROM apolysis_gateway.record_items) AS records, \
                    (SELECT count(*) FROM apolysis_gateway.projection_outbox) AS outbox, \
                    (SELECT count(*) FROM apolysis_gateway.record_items \
                       WHERE fact_kind='run_state_changed' \
                         AND fact_json #>> '{fact,fact,to}'='incomplete') AS incomplete_records, \
                    (SELECT count(*) FROM apolysis_gateway.projection_outbox AS incomplete_outbox \
                       JOIN apolysis_gateway.record_items AS incomplete_record \
                         ON incomplete_record.organization_id=incomplete_outbox.organization_id \
                        AND incomplete_record.ingest_sequence=incomplete_outbox.ingest_sequence \
                       WHERE incomplete_record.fact_kind='run_state_changed' \
                         AND incomplete_record.fact_json #>> '{fact,fact,to}'='incomplete') \
                      AS incomplete_outbox, \
                    (SELECT count(*) FROM apolysis_gateway.evidence_events) AS events, \
                    (SELECT count(*) FROM apolysis_gateway.gateway_operations) AS operations, \
                    (SELECT count(*) FROM apolysis_gateway.operation_replays) AS replays, \
                    (SELECT count(*) FROM apolysis_gateway.finalization_declarations) AS finalizations, \
                    (SELECT count(*) FROM apolysis_gateway.source_streams) AS source_streams, \
                    (SELECT count(*) FROM apolysis_gateway.leases) AS leases, \
                    (SELECT count(*) FROM apolysis_gateway.runtime_bindings) AS runtime_bindings, \
                    (SELECT count(*) FROM apolysis_gateway.active_runtime_identities) \
                      AS active_runtime_identities, \
                    (SELECT count(*) FROM apolysis_gateway.join_authorizations \
                       WHERE authorization_state='pending') AS pending_join_authorizations, \
                    (SELECT count(*) FROM apolysis_gateway.join_authorizations \
                       WHERE authorization_state='consumed') AS consumed_join_authorizations",
            )
            .fetch_one(&self.inspection_pool)
            .await?;
            let trust_rows = sqlx::query(
                "SELECT effective_trust_profile \
                 FROM apolysis_gateway.evidence_events AS event \
                 JOIN apolysis_gateway.source_streams AS stream \
                   ON stream.organization_id=event.organization_id \
                  AND stream.run_id=event.run_id \
                  AND stream.source_registration_id=event.source_registration_id \
                  AND stream.source_stream_id=event.source_stream_id \
                 ORDER BY event.organization_id, event.ledger_ingest_sequence",
            )
            .fetch_all(&self.inspection_pool)
            .await?;
            let accepted_trust = trust_rows
                .into_iter()
                .map(|row| {
                    serde_json::from_value::<TrustProfile>(serde_json::Value::String(
                        row.try_get::<String, _>("effective_trust_profile")?,
                    ))
                    .map_err(Into::into)
                })
                .collect::<Result<Vec<_>, Box<dyn Error + Send + Sync>>>()?;
            Ok(GatewayConformanceSnapshot::new(
                GatewayConformanceCounts {
                    record_item_count: usize::try_from(counts.try_get::<i64, _>("records")?)?,
                    projection_outbox_count: usize::try_from(counts.try_get::<i64, _>("outbox")?)?,
                    incomplete_record_item_count: usize::try_from(
                        counts.try_get::<i64, _>("incomplete_records")?,
                    )?,
                    incomplete_projection_outbox_count: usize::try_from(
                        counts.try_get::<i64, _>("incomplete_outbox")?,
                    )?,
                    evidence_event_count: usize::try_from(counts.try_get::<i64, _>("events")?)?,
                    operation_count: usize::try_from(counts.try_get::<i64, _>("operations")?)?,
                    replay_count: usize::try_from(counts.try_get::<i64, _>("replays")?)?,
                    finalization_declaration_count: usize::try_from(
                        counts.try_get::<i64, _>("finalizations")?,
                    )?,
                    source_stream_count: usize::try_from(
                        counts.try_get::<i64, _>("source_streams")?,
                    )?,
                    lease_count: usize::try_from(counts.try_get::<i64, _>("leases")?)?,
                    runtime_binding_count: usize::try_from(
                        counts.try_get::<i64, _>("runtime_bindings")?,
                    )?,
                    active_runtime_identity_count: usize::try_from(
                        counts.try_get::<i64, _>("active_runtime_identities")?,
                    )?,
                    pending_join_authorization_count: usize::try_from(
                        counts.try_get::<i64, _>("pending_join_authorizations")?,
                    )?,
                    consumed_join_authorization_count: usize::try_from(
                        counts.try_get::<i64, _>("consumed_join_authorizations")?,
                    )?,
                },
                accepted_trust,
            ))
        })
    }

    fn seed_current_authority<'a>(
        &'a self,
        current: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move { seed_authority(&self.inspection_pool, current).await })
    }

    fn rotate_current_authority<'a>(
        &'a self,
        expected_current: &'a AuthenticatedSourceContext,
        replacement: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            rotate_authority(&self.inspection_pool, expected_current, replacement).await
        })
    }

    fn revoke_current_authority<'a>(
        &'a self,
        expected_current: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move { revoke_authority(&self.inspection_pool, expected_current).await })
    }

    fn register_join_grant<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            let clock = HarnessClock(
                issuer
                    .authentication()
                    .authenticated_at_unix_ms()
                    .max(joining_source.authentication().authenticated_at_unix_ms())
                    .saturating_add(1),
            );
            self.repository
                .register_join_grant(
                    issuer,
                    joining_source,
                    run_id,
                    source_kind,
                    proof_ref,
                    expires_at_unix_ms,
                    &clock,
                )
                .await
        })
    }

    fn register_join_policy<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            let clock = HarnessClock(
                issuer
                    .authentication()
                    .authenticated_at_unix_ms()
                    .max(joining_source.authentication().authenticated_at_unix_ms())
                    .saturating_add(1),
            );
            self.repository
                .register_join_policy(
                    issuer,
                    joining_source,
                    run_id,
                    source_kind,
                    proof_ref,
                    expires_at_unix_ms,
                    &clock,
                )
                .await
        })
    }
}

#[derive(Clone, Copy)]
struct HarnessClock(u64);

impl GatewayClock for HarnessClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

fn harness_failure(code: ContractErrorCode) -> GatewayFailure {
    GatewayFailure::classified(code, AuditReason::CurrentAuthorityStale)
}

fn repository_failure() -> GatewayFailure {
    GatewayFailure::repository_fault(AuditReason::RepositoryInvariant)
}

fn policy_document(context: &AuthenticatedSourceContext) -> serde_json::Value {
    let policy = context.registration_policy();
    serde_json::json!({
        "source_id": policy.source_id(),
        "allowed_source_kinds": policy.allowed_source_kinds(),
        "allowed_environments": policy.allowed_environments(),
        "allowed_operations": policy.allowed_operations(),
        "effective_trust_profile": policy.effective_trust_profile(),
        "allowed_capabilities": policy.allowed_capabilities(),
        "allowed_privacy_capabilities": policy.allowed_privacy_capabilities(),
        "allowed_redaction_profile_refs": policy.allowed_redaction_profile_refs(),
        "allowed_run_authorities": policy.allowed_run_authorities(),
        "allowed_run_privacy_profile_refs": policy.allowed_run_privacy_profile_refs(),
        "allowed_run_retention_profile_refs": policy.allowed_run_retention_profile_refs(),
        "required_run_source_kinds": policy.required_run_source_kinds(),
        "may_create_runs": policy.may_create_runs(),
        "may_join_runs": policy.may_join_runs(),
        "may_finalize_runs": policy.may_finalize_runs(),
    })
}

fn principal_kind(context: &AuthenticatedSourceContext) -> Result<String, GatewayFailure> {
    serde_json::to_value(context.principal().kind())
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(repository_failure)
}

fn certificate_fingerprint(context: &AuthenticatedSourceContext) -> Vec<u8> {
    Sha256::digest(
        format!(
            "{}\0{}\0{}",
            context.organization_id(),
            context.source_registration_id(),
            context.authentication().credential_id()
        )
        .as_bytes(),
    )
    .to_vec()
}

async fn seed_authority(
    pool: &sqlx::PgPool,
    context: &AuthenticatedSourceContext,
) -> Result<(), GatewayFailure> {
    let mut transaction = pool.begin().await.map_err(|_| repository_failure())?;
    let now = i64::try_from(context.authentication().authenticated_at_unix_ms())
        .map_err(|_| repository_failure())?;
    let expires = i64::try_from(context.authentication().expires_at_unix_ms())
        .map_err(|_| repository_failure())?;
    let policy_revision = i64::try_from(context.authentication().policy_revision())
        .map_err(|_| repository_failure())?;
    let credential_epoch = i64::try_from(context.authentication().credential_epoch())
        .map_err(|_| repository_failure())?;
    let principal_kind = principal_kind(context)?;
    let policy = policy_document(context);

    sqlx::query(
        "INSERT INTO apolysis_gateway.organizations (\
            organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,'active',$2,$2) \
         ON CONFLICT (organization_id) DO UPDATE \
         SET organization_state='active', updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
    )
    .bind(context.organization_id().as_str())
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_registrations (\
            source_registration_id, organization_id, source_id, principal_kind, principal_id, \
            registration_state, policy_revision, credential_epoch, effective_at_unix_ms, \
            expires_at_unix_ms, policy_document, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,'active',$6,$7,$8,$9,$10,$8,$8) \
         ON CONFLICT (source_registration_id) DO UPDATE SET \
            organization_id=EXCLUDED.organization_id, source_id=EXCLUDED.source_id, \
            principal_kind=EXCLUDED.principal_kind, principal_id=EXCLUDED.principal_id, \
            registration_state='active', policy_revision=EXCLUDED.policy_revision, \
            credential_epoch=EXCLUDED.credential_epoch, \
            effective_at_unix_ms=EXCLUDED.effective_at_unix_ms, \
            expires_at_unix_ms=EXCLUDED.expires_at_unix_ms, \
            policy_document=EXCLUDED.policy_document, updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
    )
    .bind(context.source_registration_id())
    .bind(context.organization_id().as_str())
    .bind(context.registration_policy().source_id().as_str())
    .bind(&principal_kind)
    .bind(context.principal().id())
    .bind(policy_revision)
    .bind(credential_epoch)
    .bind(now)
    .bind(expires)
    .bind(&policy)
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.transport_credentials (\
            credential_id, certificate_fingerprint, organization_id, source_registration_id, \
            credential_epoch, effective_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms, \
            revocation_reason, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,$6,$6) \
         ON CONFLICT (credential_id) DO UPDATE SET \
            certificate_fingerprint=EXCLUDED.certificate_fingerprint, \
            organization_id=EXCLUDED.organization_id, \
            source_registration_id=EXCLUDED.source_registration_id, \
            credential_epoch=EXCLUDED.credential_epoch, \
            effective_at_unix_ms=EXCLUDED.effective_at_unix_ms, \
            expires_at_unix_ms=EXCLUDED.expires_at_unix_ms, \
            revoked_at_unix_ms=NULL, revocation_reason=NULL, \
            updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
    )
    .bind(context.authentication().credential_id())
    .bind(certificate_fingerprint(context))
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(credential_epoch)
    .bind(now)
    .bind(expires)
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (\
            organization_id, source_registration_id, credential_id, credential_epoch, \
            registration_policy_revision, policy_document, effective_at_unix_ms, \
            expires_at_unix_ms, recorded_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$7) \
         ON CONFLICT DO NOTHING",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(context.authentication().credential_id())
    .bind(credential_epoch)
    .bind(policy_revision)
    .bind(policy)
    .bind(now)
    .bind(expires)
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    transaction.commit().await.map_err(|_| repository_failure())
}

async fn rotate_authority(
    pool: &sqlx::PgPool,
    expected: &AuthenticatedSourceContext,
    replacement: &AuthenticatedSourceContext,
) -> Result<(), GatewayFailure> {
    if expected.organization_id() != replacement.organization_id()
        || expected.source_registration_id() != replacement.source_registration_id()
        || expected.principal() != replacement.principal()
        || expected.registration_policy().source_id()
            != replacement.registration_policy().source_id()
    {
        return Err(harness_failure(ContractErrorCode::Forbidden));
    }
    let old_epoch = expected.authentication().credential_epoch();
    let new_epoch = replacement.authentication().credential_epoch();
    let old_policy = expected.authentication().policy_revision();
    let new_policy = replacement.authentication().policy_revision();
    let credential_rotation =
        expected.authentication().credential_id() != replacement.authentication().credential_id();
    let valid_sequence = if credential_rotation {
        new_epoch == old_epoch.saturating_add(1)
            && (new_policy == old_policy || new_policy == old_policy.saturating_add(1))
    } else {
        new_epoch == old_epoch && new_policy == old_policy.saturating_add(1)
    };
    if !valid_sequence {
        return Err(harness_failure(ContractErrorCode::Forbidden));
    }

    let mut transaction = pool.begin().await.map_err(|_| repository_failure())?;
    sqlx::query(
        "SELECT 1 FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(expected.organization_id().as_str())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?
    .ok_or_else(|| harness_failure(ContractErrorCode::Unauthenticated))?;
    let registration = sqlx::query(
        "SELECT policy_revision, credential_epoch FROM apolysis_gateway.source_registrations \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND registration_state='active' FOR UPDATE",
    )
    .bind(expected.organization_id().as_str())
    .bind(expected.source_registration_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?
    .ok_or_else(|| harness_failure(ContractErrorCode::Unauthenticated))?;
    let credential = sqlx::query(
        "SELECT credential_epoch FROM apolysis_gateway.transport_credentials \
         WHERE organization_id=$1 AND source_registration_id=$2 AND credential_id=$3 \
           AND revoked_at_unix_ms IS NULL FOR UPDATE",
    )
    .bind(expected.organization_id().as_str())
    .bind(expected.source_registration_id())
    .bind(expected.authentication().credential_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?
    .ok_or_else(|| harness_failure(ContractErrorCode::Unauthenticated))?;
    if registration
        .try_get::<i64, _>("policy_revision")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        != Some(old_policy)
        || registration
            .try_get::<i64, _>("credential_epoch")
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            != Some(old_epoch)
        || credential
            .try_get::<i64, _>("credential_epoch")
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            != Some(old_epoch)
    {
        return Err(harness_failure(ContractErrorCode::Unauthenticated));
    }

    let rotated_at_candidate = expected
        .authentication()
        .authenticated_at_unix_ms()
        .max(replacement.authentication().authenticated_at_unix_ms())
        .saturating_add(1);
    let rotated_at = authority_change_time(
        &mut transaction,
        expected,
        i64::try_from(rotated_at_candidate).map_err(|_| repository_failure())?,
    )
    .await?;
    if credential_rotation {
        sqlx::query(
            "UPDATE apolysis_gateway.transport_credentials \
             SET revoked_at_unix_ms=$4, revocation_reason='test_authority_rotation', \
                 updated_at_unix_ms=$4 \
             WHERE organization_id=$1 AND source_registration_id=$2 AND credential_id=$3 \
               AND revoked_at_unix_ms IS NULL",
        )
        .bind(expected.organization_id().as_str())
        .bind(expected.source_registration_id())
        .bind(expected.authentication().credential_id())
        .bind(rotated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| repository_failure())?;
    }

    let new_epoch_i64 = i64::try_from(new_epoch).map_err(|_| repository_failure())?;
    let new_policy_i64 = i64::try_from(new_policy).map_err(|_| repository_failure())?;
    let effective = i64::try_from(replacement.authentication().authenticated_at_unix_ms())
        .map_err(|_| repository_failure())?;
    let expires = i64::try_from(replacement.authentication().expires_at_unix_ms())
        .map_err(|_| repository_failure())?;
    let policy = policy_document(replacement);
    sqlx::query(
        "UPDATE apolysis_gateway.source_registrations \
         SET policy_revision=$3, credential_epoch=$4, effective_at_unix_ms=$5, \
             expires_at_unix_ms=$6, policy_document=$7, updated_at_unix_ms=$8 \
         WHERE organization_id=$1 AND source_registration_id=$2",
    )
    .bind(replacement.organization_id().as_str())
    .bind(replacement.source_registration_id())
    .bind(new_policy_i64)
    .bind(new_epoch_i64)
    .bind(effective)
    .bind(expires)
    .bind(&policy)
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    if credential_rotation {
        sqlx::query(
            "INSERT INTO apolysis_gateway.transport_credentials (\
                credential_id, certificate_fingerprint, organization_id, source_registration_id, \
                credential_epoch, effective_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms, \
                revocation_reason, created_at_unix_ms, updated_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,$8,$8)",
        )
        .bind(replacement.authentication().credential_id())
        .bind(certificate_fingerprint(replacement))
        .bind(replacement.organization_id().as_str())
        .bind(replacement.source_registration_id())
        .bind(new_epoch_i64)
        .bind(effective)
        .bind(expires)
        .bind(rotated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| repository_failure())?;
    }
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (\
            organization_id, source_registration_id, credential_id, credential_epoch, \
            registration_policy_revision, policy_document, effective_at_unix_ms, \
            expires_at_unix_ms, recorded_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(replacement.organization_id().as_str())
    .bind(replacement.source_registration_id())
    .bind(replacement.authentication().credential_id())
    .bind(new_epoch_i64)
    .bind(new_policy_i64)
    .bind(policy)
    .bind(effective)
    .bind(expires)
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    revoke_dependent_authority(&mut transaction, expected, rotated_at).await?;
    transaction.commit().await.map_err(|_| repository_failure())
}

async fn revoke_authority(
    pool: &sqlx::PgPool,
    expected: &AuthenticatedSourceContext,
) -> Result<(), GatewayFailure> {
    let mut transaction = pool.begin().await.map_err(|_| repository_failure())?;
    sqlx::query(
        "SELECT 1 FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(expected.organization_id().as_str())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?
    .ok_or_else(|| harness_failure(ContractErrorCode::Unauthenticated))?;
    sqlx::query(
        "SELECT 1 FROM apolysis_gateway.source_registrations \
         WHERE organization_id=$1 AND source_registration_id=$2 FOR UPDATE",
    )
    .bind(expected.organization_id().as_str())
    .bind(expected.source_registration_id())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?
    .ok_or_else(|| harness_failure(ContractErrorCode::Unauthenticated))?;
    let revoked_at_candidate = i64::try_from(
        expected
            .authentication()
            .authenticated_at_unix_ms()
            .saturating_add(1),
    )
    .map_err(|_| repository_failure())?;
    let revoked_at =
        authority_change_time(&mut transaction, expected, revoked_at_candidate).await?;
    let updated = sqlx::query(
        "UPDATE apolysis_gateway.transport_credentials \
         SET revoked_at_unix_ms=$4, revocation_reason='test_authority_revoke', \
             updated_at_unix_ms=$4 \
         WHERE organization_id=$1 AND source_registration_id=$2 AND credential_id=$3 \
           AND credential_epoch=$5 AND revoked_at_unix_ms IS NULL",
    )
    .bind(expected.organization_id().as_str())
    .bind(expected.source_registration_id())
    .bind(expected.authentication().credential_id())
    .bind(revoked_at)
    .bind(
        i64::try_from(expected.authentication().credential_epoch())
            .map_err(|_| repository_failure())?,
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| repository_failure())?;
    if updated.rows_affected() != 1 {
        return Err(harness_failure(ContractErrorCode::Unauthenticated));
    }
    revoke_dependent_authority(&mut transaction, expected, revoked_at).await?;
    transaction.commit().await.map_err(|_| repository_failure())
}

async fn revoke_dependent_authority(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    expected: &AuthenticatedSourceContext,
    revoked_at: i64,
) -> Result<(), GatewayFailure> {
    sqlx::query(
        "UPDATE apolysis_gateway.leases SET revoked_at_unix_ms=$3 \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(expected.organization_id().as_str())
    .bind(expected.source_registration_id())
    .bind(revoked_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| repository_failure())?;
    sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET authorization_state='revoked', revoked_at_unix_ms=$3 \
         WHERE organization_id=$1 AND authorization_state='pending' \
           AND (source_registration_id=$2 OR issued_by_source_registration_id=$2)",
    )
    .bind(expected.organization_id().as_str())
    .bind(expected.source_registration_id())
    .bind(revoked_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| repository_failure())?;
    Ok(())
}

async fn authority_change_time(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: &AuthenticatedSourceContext,
    candidate: i64,
) -> Result<i64, GatewayFailure> {
    sqlx::query_scalar(
        "SELECT greatest(\
            $3::bigint, \
            coalesce((\
                SELECT max(issued_at_unix_ms) FROM apolysis_gateway.leases \
                WHERE organization_id=$1 AND source_registration_id=$2\
            ),0), \
            coalesce((\
                SELECT max(issued_at_unix_ms) FROM apolysis_gateway.join_authorizations \
                WHERE organization_id=$1 \
                  AND (source_registration_id=$2 OR issued_by_source_registration_id=$2)\
            ),0)\
         )",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(candidate)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| repository_failure())
}

gateway_repository_conformance_tests!(
    #[ignore = "requires the explicit PostgreSQL integration harness"]
    PostgresGatewayHarness
);

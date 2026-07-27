// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
mod support;

use std::{
    error::Error,
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, ContractErrorCode, EnvironmentKind,
    GatewayOperation, PrincipalKind, PrincipalRef, SourceId, SourceKind, SourceRegistrationPolicy,
};
use apolysis_gateway::{AuditReason, ExecutionEvidenceGateway, GatewayClock};
use sqlx::{PgPool, Row};
use support::{create_request, source_context, FixedClock, FixedIds, TestDatabase, NOW_UNIX_MS};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const RUN_ID: &str = "run_join_authority_time_01";
const STREAM_ID: &str = "stream_join_authority_time_01";
const LEASE_ID: &str = "lease_join_authority_time_0123456789abcdef0123456789abcdef0123456789abcdef";
const PROOF_REF: &str = "grant_join_authority_final_time_01";
const TARGET_REGISTRATION_ID: &str = "registration_a_join_target";
const TARGET_SOURCE_ID: &str = "source_join_target";
const TARGET_PRINCIPAL_ID: &str = "principal_join_target";
const TARGET_CREDENTIAL_ID: &str = "credential_join_target";
const TARGET_POLICY_REVISION: u64 = 9;
const TARGET_CREDENTIAL_EPOCH: u64 = 2;

#[derive(Clone)]
struct ExpiringTransactionClock {
    before_expiry_unix_ms: u64,
    expiry_unix_ms: u64,
    samples: Arc<AtomicUsize>,
}

impl ExpiringTransactionClock {
    fn new(expiry_unix_ms: u64) -> Self {
        Self {
            before_expiry_unix_ms: expiry_unix_ms
                .checked_sub(1)
                .expect("authentication expiry follows the Unix epoch"),
            expiry_unix_ms,
            samples: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl GatewayClock for ExpiringTransactionClock {
    fn now_unix_ms(&self) -> u64 {
        self.before_expiry_unix_ms
    }

    fn transaction_now_unix_ms(&self) -> u64 {
        if self.samples.fetch_add(1, Ordering::SeqCst) == 0 {
            self.before_expiry_unix_ms
        } else {
            self.expiry_unix_ms
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL authority-time gate"]
async fn join_grant_rechecks_issuer_authentication_after_waiting_for_the_run_lock() -> TestResult {
    let database = TestDatabase::start().await?;
    let repository = database.repository().await?;
    let issuer = source_context();
    let joining_source = joining_source_context(&issuer)?;
    seed_joining_authority(database.pool(), &joining_source).await?;
    sqlx::query(
        "DELETE FROM apolysis_gateway.transaction_authority_audit \
         WHERE organization_id=$1",
    )
    .bind(issuer.organization_id().as_str())
    .execute(database.pool())
    .await?;

    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
    );
    let opened = gateway
        .open_run(
            &issuer,
            create_request(
                "operation_join_authority_time_01",
                "client_join_authority_time_01",
            ),
        )
        .await?;

    let mut run_lock = database.pool().begin().await?;
    let locked: i32 = sqlx::query_scalar(
        "SELECT 1 FROM apolysis_gateway.runs \
         WHERE organization_id=$1 AND run_id=$2 FOR UPDATE",
    )
    .bind(issuer.organization_id().as_str())
    .bind(opened.run_id().as_str())
    .fetch_one(&mut *run_lock)
    .await?;
    assert_eq!(locked, 1);

    let authentication_expiry = issuer.authentication().expires_at_unix_ms();
    let grant_expiry = authentication_expiry
        .checked_add(60_000)
        .expect("grant expiry fits the Gateway contract");
    let clock = ExpiringTransactionClock::new(authentication_expiry);
    let task = tokio::spawn({
        let repository = repository.clone();
        let issuer = issuer.clone();
        let joining_source = joining_source.clone();
        let run_id = opened.run_id().clone();
        let clock = clock.clone();
        async move {
            repository
                .register_join_grant(
                    &issuer,
                    &joining_source,
                    run_id,
                    SourceKind::SemanticHook,
                    PROOF_REF,
                    grant_expiry,
                    &clock,
                )
                .await
        }
    });

    wait_for_run_lock_waiter(database.pool()).await?;
    run_lock.rollback().await?;

    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .map_err(|_| io::Error::other("timed out waiting for join grant registration"))?
        .map_err(|_| io::Error::other("join grant registration task did not complete"))?;
    let inserted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.join_authorizations \
         WHERE organization_id=$1 AND run_id=$2",
    )
    .bind(issuer.organization_id().as_str())
    .bind(opened.run_id().as_str())
    .fetch_one(database.pool())
    .await?;

    let failure = outcome.err().ok_or_else(|| {
        io::Error::other(format!(
            "join grant remained authorized after authentication expired behind the run lock; \
                 committed join_authorizations={inserted}"
        ))
    })?;
    assert_eq!(failure.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(failure.audit_reason(), AuditReason::CurrentAuthorityStale);
    assert!(
        !failure.response()?.retryable(),
        "final-time authentication expiry must fail permanently"
    );
    assert_eq!(
        inserted, 0,
        "final-time authentication expiry must not persist a join authorization"
    );
    let target_final_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.transaction_authority_audit \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND checked_at_unix_ms=$3 AND decision='authorized'",
    )
    .bind(issuer.organization_id().as_str())
    .bind(joining_source.source_registration_id())
    .bind(i64::try_from(authentication_expiry)?)
    .fetch_one(database.pool())
    .await?;
    let issuer_final_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.transaction_authority_audit \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND checked_at_unix_ms=$3 AND decision='unauthenticated'",
    )
    .bind(issuer.organization_id().as_str())
    .bind(issuer.source_registration_id())
    .bind(i64::try_from(authentication_expiry)?)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        target_final_audits, 1,
        "the still-current target authority must be revalidated at final transaction time"
    );
    assert_eq!(
        issuer_final_audits, 1,
        "the expired issuer authority must be revalidated at final transaction time"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL authority-time gate"]
async fn rejected_create_does_not_initialize_sequence_before_final_authority() -> TestResult {
    let database = TestDatabase::start().await?;
    let repository = database.repository().await?;
    let context = source_context();
    let authentication_expiry = context.authentication().expires_at_unix_ms();
    let failure = ExecutionEvidenceGateway::new(
        repository,
        ExpiringTransactionClock::new(authentication_expiry),
        FixedIds::new(&[
            "run_create_final_authority_rejected",
            "stream_create_final_authority_rejected",
            "lease_efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        ]),
    )
    .open_run(
        &context,
        create_request(
            "operation_create_final_authority_rejected",
            "client_create_final_authority_rejected",
        ),
    )
    .await
    .expect_err("create must fail when authentication expires at final transaction time");
    assert_eq!(failure.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(failure.audit_reason(), AuditReason::CurrentAuthorityStale);
    assert!(!failure.response()?.retryable());

    let sequence_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.organization_sequences \
         WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(
        sequence_rows, 0,
        "a final-authority denial may commit audit only, not sequence initialization"
    );
    Ok(())
}

fn joining_source_context(
    issuer: &AuthenticatedSourceContext,
) -> TestResult<AuthenticatedSourceContext> {
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from(TARGET_SOURCE_ID)?,
        vec![SourceKind::SemanticHook],
        vec![EnvironmentKind::CiRunnerOrRemoteWorkspace],
        vec![GatewayOperation::Ingest],
        false,
        true,
    )?;
    Ok(AuthenticatedSourceContext::new(
        issuer.organization_id().clone(),
        PrincipalRef::new(PrincipalKind::Workload, TARGET_PRINCIPAL_ID)?,
        TARGET_REGISTRATION_ID,
        AuthenticationSnapshot::new(
            TARGET_CREDENTIAL_ID,
            TARGET_CREDENTIAL_EPOCH,
            TARGET_POLICY_REVISION,
            issuer.authentication().authenticated_at_unix_ms(),
            issuer
                .authentication()
                .expires_at_unix_ms()
                .checked_add(600_000)
                .ok_or_else(|| io::Error::other("target authentication expiry overflowed"))?,
        )?,
        policy,
    )?)
}

async fn seed_joining_authority(
    pool: &PgPool,
    joining_source: &AuthenticatedSourceContext,
) -> TestResult {
    let policy_document = serde_json::json!({
        "fixture": "join_authority_final_time",
        "source_id": TARGET_SOURCE_ID,
    });
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_registrations (\
            source_registration_id, organization_id, source_id, principal_kind, principal_id, \
            registration_state, policy_revision, credential_epoch, effective_at_unix_ms, \
            expires_at_unix_ms, policy_document, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,'workload',$4,'active',$5,$6,$7,$8,$9,$7,$7) \
         ON CONFLICT (source_registration_id) DO UPDATE \
         SET organization_id=EXCLUDED.organization_id, source_id=EXCLUDED.source_id, \
             principal_kind=EXCLUDED.principal_kind, principal_id=EXCLUDED.principal_id, \
             registration_state='active', policy_revision=EXCLUDED.policy_revision, \
             credential_epoch=EXCLUDED.credential_epoch, \
             effective_at_unix_ms=EXCLUDED.effective_at_unix_ms, \
             expires_at_unix_ms=EXCLUDED.expires_at_unix_ms, \
             policy_document=EXCLUDED.policy_document, \
             updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
    )
    .bind(joining_source.source_registration_id())
    .bind(joining_source.organization_id().as_str())
    .bind(joining_source.registration_policy().source_id().as_str())
    .bind(joining_source.principal().id())
    .bind(i64::try_from(TARGET_POLICY_REVISION)?)
    .bind(i64::try_from(TARGET_CREDENTIAL_EPOCH)?)
    .bind(i64::try_from(
        joining_source.authentication().authenticated_at_unix_ms(),
    )?)
    .bind(i64::try_from(
        joining_source.authentication().expires_at_unix_ms(),
    )?)
    .bind(&policy_document)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.transport_credentials (\
            credential_id, certificate_fingerprint, organization_id, source_registration_id, \
            credential_epoch, effective_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms, \
            revocation_reason, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,$6,$6) \
         ON CONFLICT (credential_id) DO UPDATE \
         SET certificate_fingerprint=EXCLUDED.certificate_fingerprint, \
             organization_id=EXCLUDED.organization_id, \
             source_registration_id=EXCLUDED.source_registration_id, \
             credential_epoch=EXCLUDED.credential_epoch, \
             effective_at_unix_ms=EXCLUDED.effective_at_unix_ms, \
             expires_at_unix_ms=EXCLUDED.expires_at_unix_ms, \
             revoked_at_unix_ms=NULL, revocation_reason=NULL, \
             updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
    )
    .bind(joining_source.authentication().credential_id())
    .bind([0x55_u8; 32].as_slice())
    .bind(joining_source.organization_id().as_str())
    .bind(joining_source.source_registration_id())
    .bind(i64::try_from(TARGET_CREDENTIAL_EPOCH)?)
    .bind(i64::try_from(
        joining_source.authentication().authenticated_at_unix_ms(),
    )?)
    .bind(i64::try_from(
        joining_source.authentication().expires_at_unix_ms(),
    )?)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (\
            organization_id, source_registration_id, credential_id, credential_epoch, \
            registration_policy_revision, policy_document, effective_at_unix_ms, \
            expires_at_unix_ms, recorded_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$7) \
         ON CONFLICT (organization_id, source_registration_id, credential_id, \
                      credential_epoch, registration_policy_revision) DO NOTHING",
    )
    .bind(joining_source.organization_id().as_str())
    .bind(joining_source.source_registration_id())
    .bind(joining_source.authentication().credential_id())
    .bind(i64::try_from(TARGET_CREDENTIAL_EPOCH)?)
    .bind(i64::try_from(TARGET_POLICY_REVISION)?)
    .bind(policy_document)
    .bind(i64::try_from(
        joining_source.authentication().authenticated_at_unix_ms(),
    )?)
    .bind(i64::try_from(
        joining_source.authentication().expires_at_unix_ms(),
    )?)
    .execute(pool)
    .await?;
    Ok(())
}

async fn wait_for_run_lock_waiter(pool: &PgPool) -> TestResult {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting = sqlx::query(
                "SELECT EXISTS (\
                    SELECT 1 FROM pg_catalog.pg_stat_activity \
                    WHERE pid <> pg_backend_pid() \
                      AND state='active' \
                      AND wait_event_type='Lock' \
                      AND query LIKE '%apolysis_gateway.runs%' \
                      AND query LIKE '%FOR UPDATE%'\
                 ) AS waiting",
            )
            .fetch_one(pool)
            .await
            .ok()
            .and_then(|row| row.try_get::<bool, _>("waiting").ok())
            .unwrap_or(false);
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("join grant registration did not wait for the run row lock"))?;
    Ok(())
}

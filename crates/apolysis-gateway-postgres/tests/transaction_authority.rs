// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    io,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    ContractErrorCode, EnvironmentKind, GatewayOperation, OpenRunRequest, OpenRunResponse,
    PrincipalKind, PrincipalRef, PrivacyCapability, SourceCapability, SourceId, SourceKind,
    SourceRegistrationPolicy, TrustProfile,
};
use apolysis_gateway::{
    canonical_request_digest, AuditReason, ExecutionEvidenceGateway, GatewayClock, GatewayFailure,
    GatewayIdGenerator,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Postgres, Row, Transaction,
};
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const NOW_UNIX_MS: u64 = 1_783_891_200_000;
const GATEWAY_APPLICATION_NAME: &str = "apolysis-authority-race-gateway";
const CONTROL_APPLICATION_NAME: &str = "apolysis-authority-race-control";
const ROTATED_AT_UNIX_MS: u64 = NOW_UNIX_MS + 1;
const AUTHENTICATED_AT_UNIX_MS: u64 = NOW_UNIX_MS - 100_000;
const AUTHENTICATION_EXPIRES_AT_UNIX_MS: u64 = NOW_UNIX_MS + 3_600_000;
const REPLAY_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);
const DATABASE_SERIALIZATION_LOCK_CLASS: i32 = 573_274_119;
const DATABASE_SERIALIZATION_LOCK_KEY: i32 = 1;

const RETRY_SEQUENCE: &str = "apolysis_gateway.transaction_authority_retry_once_sequence";
const COMMIT_RETRY_SEQUENCE: &str =
    "apolysis_gateway.transaction_authority_commit_retry_once_sequence";

static DATABASE_TEST_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl GatewayClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

struct FixedIds {
    values: Mutex<Vec<String>>,
}

impl FixedIds {
    fn new(values: &[&str]) -> Self {
        Self {
            values: Mutex::new(
                values
                    .iter()
                    .rev()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
        }
    }
}

impl GatewayIdGenerator for FixedIds {
    fn next_id(&self, _kind: &'static str) -> Result<String, String> {
        self.values
            .lock()
            .map_err(|_| "deterministic ID source is unavailable".to_string())?
            .pop()
            .ok_or_else(|| "no deterministic ID should be needed".to_string())
    }
}

#[derive(Clone, Copy)]
struct AuthorityIds {
    organization_id: &'static str,
    source_registration_id: &'static str,
    credential_id: &'static str,
    rotated_credential_id: &'static str,
}

const NOVEL_IDS: AuthorityIds = AuthorityIds {
    organization_id: "org_transaction_authority_novel",
    source_registration_id: "registration_transaction_authority_novel",
    credential_id: "credential_transaction_authority_novel_v1",
    rotated_credential_id: "credential_transaction_authority_novel_v2",
};

const REPLAY_IDS: AuthorityIds = AuthorityIds {
    organization_id: "org_transaction_authority_replay",
    source_registration_id: "registration_transaction_authority_replay",
    credential_id: "credential_transaction_authority_replay_v1",
    rotated_credential_id: "credential_transaction_authority_replay_v2",
};

const RETRY_IDS: AuthorityIds = AuthorityIds {
    organization_id: "org_transaction_authority_retry",
    source_registration_id: "registration_transaction_authority_retry",
    credential_id: "credential_transaction_authority_retry_v1",
    rotated_credential_id: "credential_transaction_authority_retry_v2",
};

const COMMIT_RETRY_IDS: AuthorityIds = AuthorityIds {
    organization_id: "org_transaction_authority_commit_retry",
    source_registration_id: "registration_transaction_authority_commit_retry",
    credential_id: "credential_transaction_authority_commit_retry_v1",
    rotated_credential_id: "credential_transaction_authority_commit_retry_v2",
};

struct AuthorityFixture {
    control_pool: PgPool,
    gateway_pool: PgPool,
    repository: PostgresGatewayRepository,
    ids: AuthorityIds,
    database_guard: Option<Transaction<'static, Postgres>>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl AuthorityFixture {
    async fn start(ids: AuthorityIds) -> TestResult<Self> {
        let guard = DATABASE_TEST_LOCK
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL").map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "APOLYSIS_TEST_DATABASE_URL is required by the transaction-authority race gate",
            )
        })?;
        let control_options = PgConnectOptions::from_str(&database_url)
            .map_err(|_| io::Error::other("invalid PostgreSQL test configuration"))?
            .application_name(CONTROL_APPLICATION_NAME);
        let gateway_options = PgConnectOptions::from_str(&database_url)
            .map_err(|_| io::Error::other("invalid PostgreSQL test configuration"))?
            .application_name(GATEWAY_APPLICATION_NAME);
        let control_pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(control_options)
            .await
            .map_err(|_| io::Error::other("failed to connect the authority-race control pool"))?;
        MIGRATOR
            .run(&control_pool)
            .await
            .map_err(|_| io::Error::other("failed to migrate the authority-race database"))?;
        let mut database_guard = control_pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
            .bind(DATABASE_SERIALIZATION_LOCK_CLASS)
            .bind(DATABASE_SERIALIZATION_LOCK_KEY)
            .execute(&mut *database_guard)
            .await?;
        remove_retry_fault(&control_pool).await?;
        remove_commit_retry_fault(&control_pool).await?;
        cleanup_organization(&control_pool, ids.organization_id).await?;

        let gateway_pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(gateway_options)
            .await
            .map_err(|_| io::Error::other("failed to connect the authority-race Gateway pool"))?;
        let replay_protector = Arc::new(Aes256GcmReplayProtector::new(
            "transaction-authority-test-key",
            [("transaction-authority-test-key".to_string(), [83_u8; 32])],
        )?);
        let config = PostgresGatewayConfig::new(REPLAY_TTL_MS, 3, 4)?
            .with_database_timeouts(5_000, 15_000)?;
        let repository =
            PostgresGatewayRepository::from_pool(gateway_pool.clone(), replay_protector, config);
        let context = source_context(ids, ids.credential_id, 1, 7)?;
        seed_authority(&control_pool, &context).await?;

        Ok(Self {
            control_pool,
            gateway_pool,
            repository,
            ids,
            database_guard: Some(database_guard),
            _guard: guard,
        })
    }

    fn repository(&self) -> PostgresGatewayRepository {
        self.repository.clone()
    }

    async fn cleanup(mut self) -> TestResult {
        let cleanup_result = async {
            remove_retry_fault(&self.control_pool).await?;
            remove_commit_retry_fault(&self.control_pool).await?;
            cleanup_organization(&self.control_pool, self.ids.organization_id).await
        }
        .await;
        self.gateway_pool.close().await;
        if let Some(database_guard) = self.database_guard.take() {
            let _ = database_guard.rollback().await;
        }
        self.control_pool.close().await;
        cleanup_result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Effects {
    records: i64,
    outbox: i64,
    operations: i64,
    replays: i64,
    leases: i64,
    source_streams: i64,
    runs: i64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit transaction-authority race gate"]
async fn novel_request_waiting_on_policy_rotation_observes_the_new_authority() -> TestResult {
    let fixture = AuthorityFixture::start(NOVEL_IDS).await?;
    let result = novel_policy_rotation_race(&fixture).await;
    let cleanup = fixture.cleanup().await;
    cleanup?;
    result
}

async fn novel_policy_rotation_race(fixture: &AuthorityFixture) -> TestResult {
    let context = source_context(fixture.ids, fixture.ids.credential_id, 1, 7)?;
    let baseline = effects(&fixture.control_pool, fixture.ids.organization_id).await?;
    ensure(
        baseline
            == (Effects {
                records: 0,
                outbox: 0,
                operations: 0,
                replays: 0,
                leases: 0,
                source_streams: 0,
                runs: 0,
            }),
        format!("unexpected pre-race effects: {baseline:?}"),
    )?;

    let rotation = hold_policy_rotation(&fixture.control_pool, &context, 8).await?;
    let request = create_request(
        "operation_transaction_authority_novel",
        "client_transaction_authority_novel",
    );
    let task = spawn_open_run(
        fixture.repository(),
        context,
        request,
        &[
            "run_transaction_authority_novel",
            "stream_transaction_authority_novel",
            "lease_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
    );

    if let Err(error) = wait_for_gateway_authority_lock(&fixture.control_pool).await {
        task.abort();
        let _ = task.await;
        let _ = rotation.rollback().await;
        return Err(error);
    }
    if let Err(error) = rotation.commit().await {
        task.abort();
        let _ = task.await;
        return Err(error.into());
    }
    let outcome = await_open_run(task).await?;
    let failure = require_failure(outcome, "the stale policy request must fail closed")?;
    ensure(
        failure.code() == ContractErrorCode::Forbidden,
        format!("stale policy returned unexpected code {:?}", failure.code()),
    )?;
    ensure(
        failure.audit_reason() == AuditReason::CurrentAuthorityStale,
        "stale policy returned the wrong protected audit reason",
    )?;

    ensure(
        effects(&fixture.control_pool, fixture.ids.organization_id).await? == baseline,
        "a request released after policy rotation created Gateway lifecycle effects",
    )?;
    assert_latest_authority_decision(
        &fixture.control_pool,
        fixture.ids.organization_id,
        "forbidden",
        "registration_policy_stale",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit transaction-authority race gate"]
async fn exact_replay_waiting_on_credential_rotation_never_opens_the_old_replay() -> TestResult {
    let fixture = AuthorityFixture::start(REPLAY_IDS).await?;
    let result = exact_replay_credential_rotation_race(&fixture).await;
    let cleanup = fixture.cleanup().await;
    cleanup?;
    result
}

async fn exact_replay_credential_rotation_race(fixture: &AuthorityFixture) -> TestResult {
    let context = source_context(fixture.ids, fixture.ids.credential_id, 1, 7)?;
    let request = create_request(
        "operation_transaction_authority_replay",
        "client_transaction_authority_replay",
    );
    let gateway = ExecutionEvidenceGateway::new(
        fixture.repository(),
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[
            "run_transaction_authority_replay",
            "stream_transaction_authority_replay",
            "lease_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ]),
    );
    gateway
        .open_run(&context, request.clone())
        .await
        .map_err(|_| io::Error::other("failed to create the replay race baseline"))?;
    drop(gateway);

    // A stale authority decision must win before authenticated replay opening.
    // Deliberately invalid ciphertext makes any attempt to reach AES-GCM
    // observable as repository backpressure instead of the required authority
    // classification.
    let corrupted = sqlx::query(
        "UPDATE apolysis_gateway.operation_replays \
         SET outcome_ciphertext=decode(repeat('00',octet_length(outcome_ciphertext)),'hex') \
         WHERE organization_id=$1",
    )
    .bind(fixture.ids.organization_id)
    .execute(&fixture.control_pool)
    .await?;
    ensure(
        corrupted.rows_affected() == 1,
        "the replay corruption oracle did not target exactly one encrypted result",
    )?;
    let baseline = effects(&fixture.control_pool, fixture.ids.organization_id).await?;
    ensure(
        baseline
            == (Effects {
                records: 3,
                outbox: 3,
                operations: 1,
                replays: 1,
                leases: 1,
                source_streams: 1,
                runs: 1,
            }),
        format!("unexpected exact-replay baseline: {baseline:?}"),
    )?;

    let rotation = hold_credential_rotation(
        &fixture.control_pool,
        &context,
        fixture.ids.rotated_credential_id,
    )
    .await?;
    let task = spawn_open_run(fixture.repository(), context, request, &[]);
    if let Err(error) = wait_for_gateway_authority_lock(&fixture.control_pool).await {
        task.abort();
        let _ = task.await;
        let _ = rotation.rollback().await;
        return Err(error);
    }
    if let Err(error) = rotation.commit().await {
        task.abort();
        let _ = task.await;
        return Err(error.into());
    }
    let outcome = await_open_run(task).await?;
    let failure = require_failure(outcome, "the old credential replay must fail closed")?;
    ensure(
        failure.code() == ContractErrorCode::Unauthenticated,
        format!(
            "rotated credential replay returned unexpected code {:?}",
            failure.code()
        ),
    )?;
    ensure(
        failure.audit_reason() == AuditReason::CurrentAuthorityStale,
        "rotated credential replay returned the wrong protected audit reason",
    )?;

    ensure(
        effects(&fixture.control_pool, fixture.ids.organization_id).await? == baseline,
        "a replay released after credential rotation created Gateway lifecycle effects",
    )?;
    let lease_state = sqlx::query(
        "SELECT count(*) AS total, \
                count(*) FILTER (WHERE revoked_at_unix_ms=$2) AS rotation_revoked \
         FROM apolysis_gateway.leases WHERE organization_id=$1",
    )
    .bind(fixture.ids.organization_id)
    .bind(i64::try_from(ROTATED_AT_UNIX_MS)?)
    .fetch_one(&fixture.control_pool)
    .await?;
    ensure(
        lease_state.try_get::<i64, _>("total")? == 1
            && lease_state.try_get::<i64, _>("rotation_revoked")? == 1,
        "credential rotation did not leave exactly the pre-existing revoked lease",
    )?;
    assert_latest_authority_decision(
        &fixture.control_pool,
        fixture.ids.organization_id,
        "unauthenticated",
        "credential_inactive",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit transaction-authority race gate"]
async fn serialization_retry_rechecks_current_authority_before_mutation() -> TestResult {
    let fixture = AuthorityFixture::start(RETRY_IDS).await?;
    let result = serialization_retry_authority_race(&fixture).await;
    let cleanup = fixture.cleanup().await;
    cleanup?;
    result
}

async fn serialization_retry_authority_race(fixture: &AuthorityFixture) -> TestResult {
    install_retry_fault(&fixture.control_pool).await?;
    let context = source_context(fixture.ids, fixture.ids.credential_id, 1, 7)?;
    let request = create_request(
        "operation_transaction_authority_retry",
        "client_transaction_authority_retry",
    );
    let task = spawn_open_run(
        fixture.repository(),
        context.clone(),
        request,
        &[
            "run_transaction_authority_retry",
            "stream_transaction_authority_retry",
            "lease_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ],
    );
    if let Err(error) = wait_for_retry_fault(&fixture.control_pool).await {
        task.abort();
        let _ = task.await;
        return Err(error);
    }

    let rotation_pool = fixture.control_pool.clone();
    let rotation_context = context;
    let mut rotation = tokio::spawn(async move {
        let transaction = hold_policy_rotation(&rotation_pool, &rotation_context, 8).await?;
        transaction.commit().await?;
        TestResult::Ok(())
    });
    if let Err(error) = wait_for_control_rotation_lock(&fixture.control_pool).await {
        task.abort();
        rotation.abort();
        let _ = task.await;
        let _ = rotation.await;
        return Err(error);
    }

    match tokio::time::timeout(REQUEST_TIMEOUT, &mut rotation).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            task.abort();
            let _ = task.await;
            return Err(error);
        }
        Ok(Err(_)) => {
            task.abort();
            let _ = task.await;
            return Err(io::Error::other("policy rotation task did not complete").into());
        }
        Err(_) => {
            task.abort();
            rotation.abort();
            let _ = task.await;
            let _ = rotation.await;
            return Err(io::Error::other("timed out waiting for policy rotation").into());
        }
    }
    let outcome = await_open_run(task).await?;
    let failure = require_failure(
        outcome,
        "the restarted transaction must reject the now-stale policy",
    )?;
    ensure(
        failure.code() == ContractErrorCode::Forbidden,
        format!(
            "serialization retry returned unexpected code {:?}",
            failure.code()
        ),
    )?;
    ensure(
        failure.audit_reason() == AuditReason::CurrentAuthorityStale,
        "serialization retry returned the wrong protected audit reason",
    )?;

    let retry_vector = sqlx::query(&format!(
        "SELECT last_value, is_called FROM {RETRY_SEQUENCE}"
    ))
    .fetch_one(&fixture.control_pool)
    .await?;
    ensure(
        retry_vector.try_get::<i64, _>("last_value")? == 1
            && retry_vector.try_get::<bool, _>("is_called")?,
        "the qualification fault did not produce exactly one late 40001 restart",
    )?;
    ensure(
        effects(&fixture.control_pool, fixture.ids.organization_id).await?
            == (Effects {
                records: 0,
                outbox: 0,
                operations: 0,
                replays: 0,
                leases: 0,
                source_streams: 0,
                runs: 0,
            }),
        "a 40001 restart crossed stale authority into Gateway lifecycle mutation",
    )?;
    let audit_vector = sqlx::query(
        "SELECT \
            count(*) FILTER (WHERE decision='authorized') AS authorized, \
            count(*) FILTER (WHERE decision='forbidden' \
                              AND reason_code='registration_policy_stale') AS forbidden \
         FROM apolysis_gateway.transaction_authority_audit \
         WHERE organization_id=$1",
    )
    .bind(fixture.ids.organization_id)
    .fetch_one(&fixture.control_pool)
    .await?;
    ensure(
        audit_vector.try_get::<i64, _>("authorized")? == 0
            && audit_vector.try_get::<i64, _>("forbidden")? == 1,
        "the rolled-back attempt leaked authority audit state or retry skipped revalidation",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit transaction-authority race gate"]
async fn authority_denial_commit_retry_restarts_the_whole_transaction() -> TestResult {
    let fixture = AuthorityFixture::start(COMMIT_RETRY_IDS).await?;
    let result = authority_denial_commit_retry(&fixture).await;
    let cleanup = fixture.cleanup().await;
    cleanup?;
    result
}

async fn authority_denial_commit_retry(fixture: &AuthorityFixture) -> TestResult {
    install_commit_retry_fault(&fixture.control_pool).await?;
    let context = source_context(fixture.ids, fixture.ids.credential_id, 1, 7)?;
    hold_policy_rotation(&fixture.control_pool, &context, 8)
        .await?
        .commit()
        .await?;

    let request = create_request(
        "operation_transaction_authority_commit_retry",
        "client_transaction_authority_commit_retry",
    );
    let failure = ExecutionEvidenceGateway::new(
        fixture.repository(),
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[
            "run_transaction_authority_commit_retry",
            "stream_transaction_authority_commit_retry",
            "lease_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ]),
    )
    .open_run(&context, request)
    .await
    .expect_err("stale authority must remain forbidden after a commit-time retry");
    ensure(
        failure.code() == ContractErrorCode::Forbidden
            && failure.audit_reason() == AuditReason::CurrentAuthorityStale,
        "commit-time retry changed the protected authority classification",
    )?;

    let retry_vector = sqlx::query(&format!(
        "SELECT last_value, is_called FROM {COMMIT_RETRY_SEQUENCE}"
    ))
    .fetch_one(&fixture.control_pool)
    .await?;
    ensure(
        retry_vector.try_get::<i64, _>("last_value")? == 2
            && retry_vector.try_get::<bool, _>("is_called")?,
        "the denial audit did not produce one failed and one successful deferred attempt",
    )?;
    ensure(
        effects(&fixture.control_pool, fixture.ids.organization_id).await?
            == (Effects {
                records: 0,
                outbox: 0,
                operations: 0,
                replays: 0,
                leases: 0,
                source_streams: 0,
                runs: 0,
            }),
        "a commit-time denial retry created Gateway lifecycle effects",
    )?;
    let audit_vector = sqlx::query(
        "SELECT count(*) AS total,
                count(*) FILTER (
                    WHERE decision='forbidden'
                      AND reason_code='registration_policy_stale'
                ) AS forbidden
         FROM apolysis_gateway.transaction_authority_audit
         WHERE organization_id=$1",
    )
    .bind(fixture.ids.organization_id)
    .fetch_one(&fixture.control_pool)
    .await?;
    ensure(
        audit_vector.try_get::<i64, _>("total")? == 1
            && audit_vector.try_get::<i64, _>("forbidden")? == 1,
        "commit-time retry leaked the rolled-back denial audit or skipped revalidation",
    )
}

fn spawn_open_run(
    repository: PostgresGatewayRepository,
    context: AuthenticatedSourceContext,
    request: OpenRunRequest,
    ids: &'static [&'static str],
) -> tokio::task::JoinHandle<Result<OpenRunResponse, GatewayFailure>> {
    tokio::spawn(async move {
        ExecutionEvidenceGateway::new(repository, FixedClock(NOW_UNIX_MS), FixedIds::new(ids))
            .open_run(&context, request)
            .await
    })
}

async fn await_open_run(
    mut task: tokio::task::JoinHandle<Result<OpenRunResponse, GatewayFailure>>,
) -> TestResult<Result<OpenRunResponse, GatewayFailure>> {
    match tokio::time::timeout(REQUEST_TIMEOUT, &mut task).await {
        Ok(result) => result
            .map_err(|_| io::Error::other("Gateway authority-race task did not complete"))
            .map_err(Into::into),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(io::Error::other("timed out waiting for the Gateway authority race").into())
        }
    }
}

fn require_failure(
    outcome: Result<OpenRunResponse, GatewayFailure>,
    message: &'static str,
) -> TestResult<GatewayFailure> {
    outcome
        .err()
        .ok_or_else(|| io::Error::other(message).into())
}

async fn wait_for_gateway_authority_lock(pool: &PgPool) -> TestResult {
    wait_until(
        "Gateway request did not wait on the current-authority lock",
        || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (\
                SELECT 1 FROM pg_catalog.pg_stat_activity \
                WHERE application_name=$1 AND state='active' \
                  AND wait_event_type='Lock' \
                  AND query LIKE '%lock_gateway_current_authority%'\
             )",
            )
            .bind(GATEWAY_APPLICATION_NAME)
            .fetch_one(pool)
            .await
            .unwrap_or(false)
        },
    )
    .await
}

async fn wait_for_retry_fault(pool: &PgPool) -> TestResult {
    wait_until(
        "Gateway request did not reach the one-shot 40001 fault",
        || async {
            sqlx::query_scalar::<_, bool>(&format!("SELECT is_called FROM {RETRY_SEQUENCE}"))
                .fetch_one(pool)
                .await
                .unwrap_or(false)
        },
    )
    .await
}

async fn wait_for_control_rotation_lock(pool: &PgPool) -> TestResult {
    wait_until(
        "policy rotation did not queue behind the first transaction's authority lock",
        || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (\
                    SELECT 1 FROM pg_catalog.pg_stat_activity \
                    WHERE pid <> pg_backend_pid() \
                      AND application_name=$1 AND state='active' \
                      AND wait_event_type='Lock' \
                      AND query LIKE '%transaction_authority_rotation%'\
                 )",
            )
            .bind(CONTROL_APPLICATION_NAME)
            .fetch_one(pool)
            .await
            .unwrap_or(false)
        },
    )
    .await
}

async fn wait_until<F, Fut>(message: &'static str, mut condition: F) -> TestResult
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(LOCK_OBSERVATION_TIMEOUT, async {
        loop {
            if condition().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other(message))?;
    Ok(())
}

async fn effects(pool: &PgPool, organization_id: &str) -> TestResult<Effects> {
    let row = sqlx::query(
        "SELECT \
            (SELECT count(*) FROM apolysis_gateway.record_items \
              WHERE organization_id=$1) AS records, \
            (SELECT count(*) FROM apolysis_gateway.projection_outbox \
              WHERE organization_id=$1) AS outbox, \
            (SELECT count(*) FROM apolysis_gateway.gateway_operations \
              WHERE organization_id=$1) AS operations, \
            (SELECT count(*) FROM apolysis_gateway.operation_replays \
              WHERE organization_id=$1) AS replays, \
            (SELECT count(*) FROM apolysis_gateway.leases \
              WHERE organization_id=$1) AS leases, \
            (SELECT count(*) FROM apolysis_gateway.source_streams \
              WHERE organization_id=$1) AS source_streams, \
            (SELECT count(*) FROM apolysis_gateway.runs \
              WHERE organization_id=$1) AS runs",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    Ok(Effects {
        records: row.try_get("records")?,
        outbox: row.try_get("outbox")?,
        operations: row.try_get("operations")?,
        replays: row.try_get("replays")?,
        leases: row.try_get("leases")?,
        source_streams: row.try_get("source_streams")?,
        runs: row.try_get("runs")?,
    })
}

async fn assert_latest_authority_decision(
    pool: &PgPool,
    organization_id: &str,
    expected_decision: &str,
    expected_reason: &str,
) -> TestResult {
    let row = sqlx::query(
        "SELECT decision, reason_code \
         FROM apolysis_gateway.transaction_authority_audit \
         WHERE organization_id=$1 \
         ORDER BY transaction_authority_audit_id DESC LIMIT 1",
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| io::Error::other("current-authority denial audit is missing"))?;
    ensure(
        row.try_get::<String, _>("decision")? == expected_decision
            && row.try_get::<String, _>("reason_code")? == expected_reason,
        "current-authority denial audit has the wrong classification",
    )
}

async fn hold_policy_rotation(
    pool: &PgPool,
    context: &AuthenticatedSourceContext,
    new_policy_revision: u64,
) -> TestResult<Transaction<'static, Postgres>> {
    let mut transaction = pool.begin().await?;
    lock_authority_for_rotation(&mut transaction, context).await?;
    let updated = sqlx::query(
        "UPDATE apolysis_gateway.source_registrations \
         SET policy_revision=$3, updated_at_unix_ms=$4 \
         WHERE organization_id=$1 AND source_registration_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(i64::try_from(new_policy_revision)?)
    .bind(i64::try_from(ROTATED_AT_UNIX_MS)?)
    .execute(&mut *transaction)
    .await?;
    ensure(
        updated.rows_affected() == 1,
        "policy rotation did not update exactly one registration",
    )?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (\
            organization_id, source_registration_id, credential_id, credential_epoch, \
            registration_policy_revision, policy_document, effective_at_unix_ms, \
            expires_at_unix_ms, recorded_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(context.authentication().credential_id())
    .bind(i64::try_from(context.authentication().credential_epoch())?)
    .bind(i64::try_from(new_policy_revision)?)
    .bind(policy_document(context))
    .bind(i64::try_from(AUTHENTICATED_AT_UNIX_MS)?)
    .bind(i64::try_from(AUTHENTICATION_EXPIRES_AT_UNIX_MS)?)
    .bind(i64::try_from(ROTATED_AT_UNIX_MS)?)
    .execute(&mut *transaction)
    .await?;
    Ok(transaction)
}

async fn hold_credential_rotation(
    pool: &PgPool,
    context: &AuthenticatedSourceContext,
    new_credential_id: &str,
) -> TestResult<Transaction<'static, Postgres>> {
    let mut transaction = pool.begin().await?;
    lock_authority_for_rotation(&mut transaction, context).await?;
    let rotated_at = i64::try_from(ROTATED_AT_UNIX_MS)?;
    let updated = sqlx::query(
        "UPDATE apolysis_gateway.transport_credentials \
         SET revoked_at_unix_ms=$4, revocation_reason='qualification_rotation', \
             updated_at_unix_ms=$4 \
         WHERE organization_id=$1 AND source_registration_id=$2 AND credential_id=$3 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(context.authentication().credential_id())
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await?;
    ensure(
        updated.rows_affected() == 1,
        "credential rotation did not revoke exactly one current credential",
    )?;
    sqlx::query(
        "UPDATE apolysis_gateway.source_registrations \
         SET credential_epoch=2, updated_at_unix_ms=$3 \
         WHERE organization_id=$1 AND source_registration_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.transport_credentials (\
            credential_id, certificate_fingerprint, organization_id, source_registration_id, \
            credential_epoch, effective_at_unix_ms, expires_at_unix_ms, created_at_unix_ms, \
            updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,2,$5,$6,$7,$7)",
    )
    .bind(new_credential_id)
    .bind(certificate_fingerprint(
        context.organization_id().as_str(),
        context.source_registration_id(),
        new_credential_id,
    ))
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(i64::try_from(NOW_UNIX_MS)?)
    .bind(i64::try_from(AUTHENTICATION_EXPIRES_AT_UNIX_MS)?)
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (\
            organization_id, source_registration_id, credential_id, credential_epoch, \
            registration_policy_revision, policy_document, effective_at_unix_ms, \
            expires_at_unix_ms, recorded_at_unix_ms\
         ) VALUES ($1,$2,$3,2,$4,$5,$6,$7,$8)",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(new_credential_id)
    .bind(i64::try_from(context.authentication().policy_revision())?)
    .bind(policy_document(context))
    .bind(i64::try_from(NOW_UNIX_MS)?)
    .bind(i64::try_from(AUTHENTICATION_EXPIRES_AT_UNIX_MS)?)
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE apolysis_gateway.leases SET revoked_at_unix_ms=$3 \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET authorization_state='revoked', revoked_at_unix_ms=$3 \
         WHERE organization_id=$1 AND authorization_state='pending' \
           AND (source_registration_id=$2 OR issued_by_source_registration_id=$2)",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(rotated_at)
    .execute(&mut *transaction)
    .await?;
    Ok(transaction)
}

async fn lock_authority_for_rotation(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
) -> TestResult {
    let organization = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 FOR UPDATE /* transaction_authority_rotation */",
    )
    .bind(context.organization_id().as_str())
    .fetch_optional(&mut **transaction)
    .await?;
    ensure(organization.is_some(), "rotation organization is missing")?;
    let registration = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM apolysis_gateway.source_registrations \
         WHERE organization_id=$1 AND source_registration_id=$2 \
         FOR UPDATE /* transaction_authority_rotation */",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .fetch_optional(&mut **transaction)
    .await?;
    ensure(registration.is_some(), "rotation registration is missing")?;
    let credential = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM apolysis_gateway.transport_credentials \
         WHERE organization_id=$1 AND source_registration_id=$2 AND credential_id=$3 \
         FOR UPDATE /* transaction_authority_rotation */",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(context.authentication().credential_id())
    .fetch_optional(&mut **transaction)
    .await?;
    ensure(credential.is_some(), "rotation credential is missing")
}

async fn seed_authority(pool: &PgPool, context: &AuthenticatedSourceContext) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.organizations (\
            organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,'active',$2,$2)",
    )
    .bind(context.organization_id().as_str())
    .bind(i64::try_from(AUTHENTICATED_AT_UNIX_MS)?)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_registrations (\
            source_registration_id, organization_id, source_id, principal_kind, principal_id, \
            registration_state, policy_revision, credential_epoch, effective_at_unix_ms, \
            expires_at_unix_ms, policy_document, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,'workload',$4,'active',$5,$6,$7,$8,$9,$7,$7)",
    )
    .bind(context.source_registration_id())
    .bind(context.organization_id().as_str())
    .bind(context.registration_policy().source_id().as_str())
    .bind(context.principal().id())
    .bind(i64::try_from(context.authentication().policy_revision())?)
    .bind(i64::try_from(context.authentication().credential_epoch())?)
    .bind(i64::try_from(AUTHENTICATED_AT_UNIX_MS)?)
    .bind(i64::try_from(AUTHENTICATION_EXPIRES_AT_UNIX_MS)?)
    .bind(policy_document(context))
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.transport_credentials (\
            credential_id, certificate_fingerprint, organization_id, source_registration_id, \
            credential_epoch, effective_at_unix_ms, expires_at_unix_ms, \
            created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$6,$6)",
    )
    .bind(context.authentication().credential_id())
    .bind(certificate_fingerprint(
        context.organization_id().as_str(),
        context.source_registration_id(),
        context.authentication().credential_id(),
    ))
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(i64::try_from(context.authentication().credential_epoch())?)
    .bind(i64::try_from(AUTHENTICATED_AT_UNIX_MS)?)
    .bind(i64::try_from(AUTHENTICATION_EXPIRES_AT_UNIX_MS)?)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (\
            organization_id, source_registration_id, credential_id, credential_epoch, \
            registration_policy_revision, policy_document, effective_at_unix_ms, \
            expires_at_unix_ms, recorded_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$7)",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(context.authentication().credential_id())
    .bind(i64::try_from(context.authentication().credential_epoch())?)
    .bind(i64::try_from(context.authentication().policy_revision())?)
    .bind(policy_document(context))
    .bind(i64::try_from(AUTHENTICATED_AT_UNIX_MS)?)
    .bind(i64::try_from(AUTHENTICATION_EXPIRES_AT_UNIX_MS)?)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn create_request(client_operation_id: &str, client_run_key: &str) -> OpenRunRequest {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/open_run_create_request.json"
    );
    let mut wire: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).expect("read the checked-in open_run fixture"),
    )
    .expect("decode the checked-in open_run fixture");
    wire["client_operation_id"] = serde_json::Value::String(client_operation_id.to_string());
    wire["client_run_key"] = serde_json::Value::String(client_run_key.to_string());
    wire["expected_source_kinds"] = serde_json::json!(["semantic_hook"]);
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: OpenRunRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid open_run fixture");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("open_run", &unsigned).expect("canonical open_run digest"),
    );
    serde_json::from_value(wire).expect("digest-valid open_run fixture")
}

fn source_context(
    ids: AuthorityIds,
    credential_id: &str,
    credential_epoch: u64,
    policy_revision: u64,
) -> TestResult<AuthenticatedSourceContext> {
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from("source_codex")?,
        vec![SourceKind::SemanticHook],
        vec![EnvironmentKind::CiRunnerOrRemoteWorkspace],
        vec![
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ],
        true,
        false,
    )?
    .with_run_authorities(vec![AuthorityRef::new(
        AuthorityKind::Service,
        "authority_ci",
    )?])?
    .with_run_profiles(
        vec!["privacy_structure_only_v1".to_string()],
        vec!["retention_30d_v1".to_string()],
        vec![SourceKind::SemanticHook],
    )?
    .with_evidence_policy(
        TrustProfile::HarnessObserved,
        vec![
            SourceCapability::SemanticLifecycle,
            SourceCapability::ToolCalls,
            SourceCapability::ClaimedOutcome,
        ],
        vec![PrivacyCapability::StructureOnly],
        vec!["redaction_structure_only_v1".to_string()],
    )?;
    Ok(AuthenticatedSourceContext::new(
        ids.organization_id.try_into()?,
        PrincipalRef::new(PrincipalKind::Workload, "principal_runner")?,
        ids.source_registration_id,
        AuthenticationSnapshot::new(
            credential_id,
            credential_epoch,
            policy_revision,
            AUTHENTICATED_AT_UNIX_MS,
            AUTHENTICATION_EXPIRES_AT_UNIX_MS,
        )?,
        policy,
    )?)
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

fn certificate_fingerprint(
    organization_id: &str,
    source_registration_id: &str,
    credential_id: &str,
) -> Vec<u8> {
    Sha256::digest(
        format!("{organization_id}\0{source_registration_id}\0{credential_id}").as_bytes(),
    )
    .to_vec()
}

async fn install_retry_fault(pool: &PgPool) -> TestResult {
    remove_retry_fault(pool).await?;
    sqlx::raw_sql(
        "CREATE SEQUENCE apolysis_gateway.transaction_authority_retry_once_sequence;

         CREATE FUNCTION apolysis_gateway.transaction_authority_retry_once()
         RETURNS trigger
         LANGUAGE plpgsql
         SET search_path = pg_catalog, apolysis_gateway, pg_temp
         AS $function$
         DECLARE
             fault_attempt bigint;
         BEGIN
             IF NEW.organization_id = 'org_transaction_authority_retry'
                AND NEW.client_operation_id = 'operation_transaction_authority_retry'
                AND NEW.operation_kind = 'open_run'
             THEN
                 fault_attempt := nextval(
                     'apolysis_gateway.transaction_authority_retry_once_sequence'::regclass
                 );
                 IF fault_attempt = 1 THEN
                     PERFORM pg_sleep(0.75);
                     RAISE EXCEPTION USING
                         ERRCODE = '40001',
                         MESSAGE = 'transaction authority qualification restart';
                 END IF;
             END IF;
             RETURN NEW;
         END;
         $function$;

         REVOKE ALL ON FUNCTION
             apolysis_gateway.transaction_authority_retry_once()
         FROM PUBLIC;

         CREATE TRIGGER transaction_authority_retry_once
         BEFORE INSERT ON apolysis_gateway.gateway_operations
         FOR EACH ROW
         EXECUTE FUNCTION apolysis_gateway.transaction_authority_retry_once();",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn remove_retry_fault(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(
        "DROP TRIGGER IF EXISTS transaction_authority_retry_once
             ON apolysis_gateway.gateway_operations;
         DROP FUNCTION IF EXISTS
             apolysis_gateway.transaction_authority_retry_once();
         DROP SEQUENCE IF EXISTS
             apolysis_gateway.transaction_authority_retry_once_sequence;",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn install_commit_retry_fault(pool: &PgPool) -> TestResult {
    remove_commit_retry_fault(pool).await?;
    sqlx::raw_sql(
        "CREATE SEQUENCE
             apolysis_gateway.transaction_authority_commit_retry_once_sequence;

         CREATE FUNCTION
             apolysis_gateway.transaction_authority_commit_retry_once()
         RETURNS trigger
         LANGUAGE plpgsql
         SET search_path = pg_catalog, apolysis_gateway, pg_temp
         AS $function$
         DECLARE
             fault_attempt bigint;
         BEGIN
             IF NEW.organization_id =
                    'org_transaction_authority_commit_retry'
                AND NEW.decision = 'forbidden'
                AND NEW.reason_code = 'registration_policy_stale'
             THEN
                 fault_attempt := nextval(
                     'apolysis_gateway.transaction_authority_commit_retry_once_sequence'
                     ::regclass
                 );
                 IF fault_attempt = 1 THEN
                     RAISE EXCEPTION USING
                         ERRCODE = '40001',
                         MESSAGE = 'transaction authority denial commit restart';
                 END IF;
             END IF;
             RETURN NEW;
         END;
         $function$;

         REVOKE ALL ON FUNCTION
             apolysis_gateway.transaction_authority_commit_retry_once()
         FROM PUBLIC;

         CREATE CONSTRAINT TRIGGER
             transaction_authority_commit_retry_once
         AFTER INSERT ON apolysis_gateway.transaction_authority_audit
         DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW
         EXECUTE FUNCTION
             apolysis_gateway.transaction_authority_commit_retry_once();",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn remove_commit_retry_fault(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(
        "DROP TRIGGER IF EXISTS transaction_authority_commit_retry_once
             ON apolysis_gateway.transaction_authority_audit;
         DROP FUNCTION IF EXISTS
             apolysis_gateway.transaction_authority_commit_retry_once();
         DROP SEQUENCE IF EXISTS
             apolysis_gateway.transaction_authority_commit_retry_once_sequence;",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn cleanup_organization(pool: &PgPool, organization_id: &str) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await?;
    for statement in [
        "DELETE FROM apolysis_gateway.transaction_authority_audit WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.gateway_authority_audit WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.authority_change_audit WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.operation_replays WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.gateway_operations WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.join_authorizations WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.lease_operations WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.leases WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.source_stream_capabilities WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.source_streams WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.projection_outbox WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.record_items WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.run_expected_source_kinds WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.client_runs WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.runs WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.organization_sequences WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.source_authority_revisions WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.transport_credentials WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.source_registrations WHERE organization_id=$1",
        "DELETE FROM apolysis_gateway.organizations WHERE organization_id=$1",
    ] {
        sqlx::query(statement)
            .bind(organization_id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.into()).into())
    }
}

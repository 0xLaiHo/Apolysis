// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
mod support;

use std::{
    error::Error,
    io,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, BindRuntimeRequest, FinishRunRequest, IngestRequest,
    OpenRunRequest, SourceCapability,
};
use apolysis_gateway::{
    canonical_request_digest, AuditReason, ExecutionEvidenceGateway, GatewayClock, GatewayFailure,
};
use apolysis_gateway_postgres::{PostgresGatewayConfig, PostgresGatewayRepository};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use support::{ingest_request, source_context, FixedClock, FixedIds, TestDatabase, NOW_UNIX_MS};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const REPLAY_TTL_MS: u64 = 1_000;
const REPLAY_EXPIRES_AT_UNIX_MS: u64 = NOW_UNIX_MS + REPLAY_TTL_MS;
const RUN_ID: &str = "run_replay_ttl_lock_wait";
const STREAM_ID: &str = "stream_replay_ttl_lock_wait";
const LEASE_ID: &str = "lease_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OPEN_OPERATION_ID: &str = "operation_replay_ttl_open";
const BIND_OPERATION_ID: &str = "operation_replay_ttl_bind";
const INGEST_OPERATION_ID: &str = "operation_replay_ttl_ingest";
const FINISH_OPERATION_ID: &str = "operation_replay_ttl_finish";

#[derive(Clone)]
struct ReplayRaceClock {
    admission_now_unix_ms: u64,
    transaction_now_unix_ms: Arc<AtomicU64>,
    transaction_samples: Arc<AtomicUsize>,
}

impl ReplayRaceClock {
    fn new(transaction_now_unix_ms: u64) -> Self {
        Self {
            admission_now_unix_ms: REPLAY_EXPIRES_AT_UNIX_MS - 1,
            transaction_now_unix_ms: Arc::new(AtomicU64::new(transaction_now_unix_ms)),
            transaction_samples: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn advance_transaction_time(&self, now_unix_ms: u64) {
        self.transaction_now_unix_ms
            .store(now_unix_ms, Ordering::SeqCst);
    }

    fn transaction_samples(&self) -> usize {
        self.transaction_samples.load(Ordering::SeqCst)
    }
}

impl GatewayClock for ReplayRaceClock {
    fn now_unix_ms(&self) -> u64 {
        self.admission_now_unix_ms
    }

    fn transaction_now_unix_ms(&self) -> u64 {
        self.transaction_samples.fetch_add(1, Ordering::SeqCst);
        self.transaction_now_unix_ms.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
enum ReplayCase {
    Open(OpenRunRequest),
    Bind(BindRuntimeRequest),
    Ingest(IngestRequest),
    Finish(FinishRunRequest),
}

impl ReplayCase {
    fn operation_kind(&self) -> &'static str {
        match self {
            Self::Open(_) => "open_run",
            Self::Bind(_) => "bind_runtime",
            Self::Ingest(_) => "ingest",
            Self::Finish(_) => "finish_run",
        }
    }

    fn client_operation_id(&self) -> &str {
        match self {
            Self::Open(request) => request.client_operation_id(),
            Self::Bind(request) => request.client_operation_id(),
            Self::Ingest(request) => request.client_operation_id(),
            Self::Finish(request) => request.client_operation_id(),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit replay-TTL lock-wait gate"]
async fn exact_replay_refreshes_ttl_time_after_waiting_for_the_operation_lock() -> TestResult {
    let database = TestDatabase::start().await?;
    let config = PostgresGatewayConfig::new(REPLAY_TTL_MS, 3, 4)?;
    let repository = database.repository_with_config(config).await?;
    let context = workload_capable_context()?;
    let requests = seed_complete_lifecycle(&repository, &context).await?;

    for replay_case in &requests {
        let first_clock = ReplayRaceClock::new(REPLAY_EXPIRES_AT_UNIX_MS - 1);
        let first_fingerprint = execute_replay(
            repository.clone(),
            first_clock.clone(),
            context.clone(),
            replay_case.clone(),
        )
        .await
        .map_err(|failure| {
            io::Error::other(format!(
                "{} positive replay failed with {:?}",
                replay_case.operation_kind(),
                failure.code()
            ))
        })?;
        assert_eq!(
            first_clock.transaction_samples(),
            1,
            "{} positive exact replay did not use one post-lock transaction time",
            replay_case.operation_kind()
        );

        let second_clock = ReplayRaceClock::new(REPLAY_EXPIRES_AT_UNIX_MS - 1);
        let second_fingerprint = execute_replay(
            repository.clone(),
            second_clock.clone(),
            context.clone(),
            replay_case.clone(),
        )
        .await
        .map_err(|failure| {
            io::Error::other(format!(
                "{} repeated positive replay failed with {:?}",
                replay_case.operation_kind(),
                failure.code()
            ))
        })?;
        assert_eq!(
            second_clock.transaction_samples(),
            1,
            "{} repeated exact replay did not use one post-lock transaction time",
            replay_case.operation_kind()
        );
        assert_eq!(
            first_fingerprint,
            second_fingerprint,
            "{} positive exact replay was not response-stable",
            replay_case.operation_kind()
        );
    }

    for replay_case in requests {
        corrupt_replay_ciphertext(database.pool(), &context, &replay_case).await?;
        let before = state_fingerprint(database.pool(), &context).await?;
        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        let locked_operation: i64 = sqlx::query_scalar(
            "SELECT operation_id FROM apolysis_gateway.gateway_operations \
             WHERE organization_id=$1 AND source_registration_id=$2 \
               AND principal_kind='workload' AND principal_id=$3 \
               AND operation_kind=$4 AND client_operation_id=$5 \
             FOR UPDATE",
        )
        .bind(context.organization_id().as_str())
        .bind(context.source_registration_id())
        .bind(context.principal().id())
        .bind(replay_case.operation_kind())
        .bind(replay_case.client_operation_id())
        .fetch_one(&mut *blocker)
        .await?;
        assert!(locked_operation > 0);

        let clock = ReplayRaceClock::new(REPLAY_EXPIRES_AT_UNIX_MS - 1);
        let task = tokio::spawn(execute_replay(
            repository.clone(),
            clock.clone(),
            context.clone(),
            replay_case.clone(),
        ));
        if let Err(error) = wait_for_operation_lock_waiter(database.pool(), blocker_pid).await {
            task.abort();
            let _ = task.await;
            let _ = blocker.rollback().await;
            return Err(error);
        }
        clock.advance_transaction_time(REPLAY_EXPIRES_AT_UNIX_MS);
        blocker.rollback().await?;

        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .map_err(|_| io::Error::other("timed out waiting for replay-TTL lock race"))?
            .map_err(|_| io::Error::other("replay-TTL lock-race task did not complete"))?;
        let failure = outcome.err().ok_or_else(|| {
            io::Error::other(format!(
                "{} decrypted an exact replay at its inclusive TTL boundary",
                replay_case.operation_kind()
            ))
        })?;
        assert_eq!(
            failure.code(),
            apolysis_contracts::ContractErrorCode::IdempotencyConflict
        );
        assert_eq!(failure.audit_reason(), AuditReason::IdempotencyConflict);
        let response = failure.response()?;
        assert!(!response.retryable());
        assert_eq!(response.retry_after_ms(), None);
        assert_eq!(
            clock.transaction_samples(),
            1,
            "{} expired exact replay did not use one post-lock transaction time",
            replay_case.operation_kind()
        );

        let after = state_fingerprint(database.pool(), &context).await?;
        assert_eq!(
            after,
            before,
            "{} expired replay changed durable Gateway state",
            replay_case.operation_kind()
        );
    }
    Ok(())
}

async fn seed_complete_lifecycle(
    repository: &PostgresGatewayRepository,
    context: &AuthenticatedSourceContext,
) -> TestResult<Vec<ReplayCase>> {
    let open_request = workload_open_request();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
    );
    let opened = gateway.open_run(context, open_request.clone()).await?;
    assert_eq!(opened.run_id().as_str(), RUN_ID);
    assert_eq!(opened.source_stream_id(), STREAM_ID);
    assert_eq!(opened.lease().lease_id(), LEASE_ID);

    let bind_request = bind_request();
    gateway.bind_runtime(context, bind_request.clone()).await?;
    let ingest_request = ingest_request(RUN_ID, LEASE_ID, STREAM_ID, INGEST_OPERATION_ID, 1..=3);
    gateway.ingest(context, ingest_request.clone()).await?;
    let finish_request = finish_request();
    gateway.finish_run(context, finish_request.clone()).await?;

    Ok(vec![
        ReplayCase::Open(open_request),
        ReplayCase::Bind(bind_request),
        ReplayCase::Ingest(ingest_request),
        ReplayCase::Finish(finish_request),
    ])
}

async fn execute_replay(
    repository: PostgresGatewayRepository,
    clock: ReplayRaceClock,
    context: AuthenticatedSourceContext,
    replay_case: ReplayCase,
) -> Result<[u8; 32], GatewayFailure> {
    let gateway = ExecutionEvidenceGateway::new(repository, clock, FixedIds::new(&[]));
    match replay_case {
        ReplayCase::Open(request) => gateway
            .open_run(&context, request)
            .await
            .map(|response| response_fingerprint(&response)),
        ReplayCase::Bind(request) => gateway
            .bind_runtime(&context, request)
            .await
            .map(|response| response_fingerprint(&response)),
        ReplayCase::Ingest(request) => gateway
            .ingest(&context, request)
            .await
            .map(|response| response_fingerprint(&response)),
        ReplayCase::Finish(request) => gateway
            .finish_run(&context, request)
            .await
            .map(|response| response_fingerprint(&response)),
    }
}

fn response_fingerprint(response: &impl Serialize) -> [u8; 32] {
    Sha256::digest(
        serde_json::to_vec(response).expect("serialize exact replay response for fingerprinting"),
    )
    .into()
}

fn workload_capable_context() -> TestResult<AuthenticatedSourceContext> {
    let base = source_context();
    let policy = base.registration_policy();
    let mut capabilities = policy.allowed_capabilities().to_vec();
    capabilities.push(SourceCapability::Workload);
    let policy = policy.clone().with_evidence_policy(
        policy.effective_trust_profile(),
        capabilities,
        policy.allowed_privacy_capabilities().to_vec(),
        policy.allowed_redaction_profile_refs().to_vec(),
    )?;
    Ok(AuthenticatedSourceContext::new(
        base.organization_id().clone(),
        base.principal().clone(),
        base.source_registration_id(),
        base.authentication().clone(),
        policy,
    )?)
}

fn workload_open_request() -> OpenRunRequest {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/open_run_create_request.json"
    )))
    .expect("decode open_run fixture");
    wire["client_operation_id"] = serde_json::json!(OPEN_OPERATION_ID);
    wire["client_run_key"] = serde_json::json!("client_replay_ttl_lock_wait");
    wire["expected_source_kinds"] = serde_json::json!(["semantic_hook"]);
    wire["source_manifest"]["capabilities"] = serde_json::json!([
        "semantic_lifecycle",
        "tool_calls",
        "claimed_outcome",
        "workload"
    ]);
    sign_request("open_run", wire)
}

fn bind_request() -> BindRuntimeRequest {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/bind_runtime_request.json"
    )))
    .expect("decode bind_runtime fixture");
    wire["client_operation_id"] = serde_json::json!(BIND_OPERATION_ID);
    wire["run_id"] = serde_json::json!(RUN_ID);
    wire["lease_id"] = serde_json::json!(LEASE_ID);
    wire["binding"]["binding_id"] = serde_json::json!("binding_replay_ttl_lock_wait");
    wire["binding"]["asserting_source_id"] = serde_json::json!("source_codex");
    sign_request("bind_runtime", wire)
}

fn finish_request() -> FinishRunRequest {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/finish_run_request.json"
    )))
    .expect("decode finish_run fixture");
    wire["client_operation_id"] = serde_json::json!(FINISH_OPERATION_ID);
    wire["run_id"] = serde_json::json!(RUN_ID);
    wire["lease_id"] = serde_json::json!(LEASE_ID);
    wire["terminal_positions"] = serde_json::json!([{
        "source_id": "source_codex",
        "source_stream_id": STREAM_ID,
        "final_source_sequence": 3
    }]);
    sign_request("finish_run", wire)
}

fn sign_request<T>(operation: &'static str, mut wire: serde_json::Value) -> T
where
    T: DeserializeOwned + Serialize,
{
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: T = serde_json::from_value(wire.clone()).expect("decode unsigned request");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest(operation, &unsigned).expect("compute canonical request digest"),
    );
    serde_json::from_value(wire).expect("decode signed request")
}

async fn corrupt_replay_ciphertext(
    pool: &PgPool,
    context: &AuthenticatedSourceContext,
    replay_case: &ReplayCase,
) -> TestResult {
    let updated = sqlx::query(
        "UPDATE apolysis_gateway.operation_replays AS replay \
         SET outcome_ciphertext=set_byte(\
             replay.outcome_ciphertext, 0, \
             (get_byte(replay.outcome_ciphertext,0)+1)%256\
         ) \
         FROM apolysis_gateway.gateway_operations AS operation \
         WHERE operation.organization_id=replay.organization_id \
           AND operation.operation_id=replay.operation_id \
           AND operation.organization_id=$1 \
           AND operation.source_registration_id=$2 \
           AND operation.principal_kind='workload' \
           AND operation.principal_id=$3 \
           AND operation.operation_kind=$4 \
           AND operation.client_operation_id=$5",
    )
    .bind(context.organization_id().as_str())
    .bind(context.source_registration_id())
    .bind(context.principal().id())
    .bind(replay_case.operation_kind())
    .bind(replay_case.client_operation_id())
    .execute(pool)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(io::Error::other("ciphertext corruption did not target one replay").into());
    }
    Ok(())
}

async fn wait_for_operation_lock_waiter(pool: &PgPool, blocker_pid: i32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (\
                    SELECT 1 FROM pg_catalog.pg_stat_activity \
                    WHERE pid <> pg_backend_pid() \
                      AND state='active' \
                      AND wait_event_type='Lock' \
                      AND query LIKE '%lock_gateway_operation%' \
                      AND $1=ANY(pg_catalog.pg_blocking_pids(pid))\
                 )",
            )
            .bind(blocker_pid)
            .fetch_one(pool)
            .await
            .unwrap_or(false);
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("exact replay did not wait on its operation row lock"))?;
    Ok(())
}

async fn state_fingerprint(
    pool: &PgPool,
    context: &AuthenticatedSourceContext,
) -> TestResult<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT relation_name, md5(COALESCE(rows, '[]'::jsonb)::text) AS fingerprint \
         FROM (\
             SELECT 'organization_sequences' AS relation_name, \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) AS rows \
               FROM apolysis_gateway.organization_sequences AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'runs', jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.runs AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'run_expected_source_kinds', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.run_expected_source_kinds AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'client_runs', jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.client_runs AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'record_items', jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.record_items AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'projection_outbox', jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.projection_outbox AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'source_streams', jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.source_streams AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'source_stream_capabilities', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.source_stream_capabilities AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'leases', jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.leases AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'lease_operations', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.lease_operations AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'join_authorizations', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.join_authorizations AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'gateway_operations', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.gateway_operations AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'operation_replays', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.operation_replays AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'evidence_events', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.evidence_events AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'runtime_bindings', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.runtime_bindings AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'active_runtime_identities', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.active_runtime_identities AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'finalization_declarations', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.finalization_declarations AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'finalization_terminal_positions', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.finalization_terminal_positions AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'finalization_outcome_claims', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.finalization_outcome_claims AS t WHERE organization_id=$1 \
             UNION ALL SELECT 'transaction_authority_audit', \
                    jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) \
               FROM apolysis_gateway.transaction_authority_audit AS t WHERE organization_id=$1\
         ) AS fingerprints ORDER BY relation_name",
    )
    .bind(context.organization_id().as_str())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| Ok((row.try_get("relation_name")?, row.try_get("fingerprint")?)))
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

// SPDX-License-Identifier: Apache-2.0

mod support;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use apolysis_contracts::{ContractErrorCode, OpenRunOutcome};
use apolysis_gateway::{
    AuditReason, ExecutionEvidenceGateway, GatewayFailure, GatewayIdGenerator, GatewayRepository,
    LedgerCommand, LedgerOutcome, OsRandomIdGenerator, RepositoryFuture, SystemClock,
};
use apolysis_gateway_postgres::{PostgresGatewayConfig, PostgresGatewayRepository};
use sqlx::Row;
use support::{
    create_request, ingest_request, runtime_source_context, source_context, FixedClock, FixedIds,
    TestDatabase, NOW_UNIX_MS,
};

const RUN_ID: &str = "run_durable_01";
const STREAM_ID: &str = "stream_durable_01";
const LEASE_ID: &str =
    "lease_durable_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn exact_open_run_retry_survives_repository_and_pool_reconstruction() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let context = source_context();
    let request = create_request("operation_restart_01", "client_restart_01");

    let repository = database
        .repository()
        .await
        .expect("construct the first repository and pool");
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
    );
    let opened = gateway
        .open_run(&context, request.clone())
        .await
        .expect("commit the initial open_run");
    assert_eq!(opened.outcome(), OpenRunOutcome::Created);
    drop(gateway);

    let reconstructed = database
        .repository()
        .await
        .expect("reconstruct the repository with a new pool");
    let retry_gateway =
        ExecutionEvidenceGateway::new(reconstructed, FixedClock(NOW_UNIX_MS), FixedIds::new(&[]));
    let retried = retry_gateway
        .open_run(&context, request)
        .await
        .expect("replay the committed open_run after reconstruction");

    assert_eq!(retried.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(retried.run_id(), opened.run_id());
    assert_eq!(retried.source_stream_id(), opened.source_stream_id());
    assert_eq!(retried.lease(), opened.lease());
}

#[derive(Clone)]
struct LoseFirstAcknowledgement {
    inner: PostgresGatewayRepository,
    lose_next_success: Arc<AtomicBool>,
}

impl LoseFirstAcknowledgement {
    fn new(inner: PostgresGatewayRepository) -> Self {
        Self {
            inner,
            lose_next_success: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl GatewayRepository for LoseFirstAcknowledgement {
    fn execute<'a>(
        &'a self,
        command: LedgerCommand,
        ids: &'a dyn GatewayIdGenerator,
    ) -> RepositoryFuture<'a, Result<LedgerOutcome, GatewayFailure>> {
        Box::pin(async move {
            let outcome = self.inner.execute(command, ids).await?;
            if self.lose_next_success.swap(false, Ordering::SeqCst) {
                Err(GatewayFailure::repository_backpressure(
                    250,
                    AuditReason::RepositoryInvariant,
                ))
            } else {
                Ok(outcome)
            }
        })
    }
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn retry_after_post_commit_pre_ack_loss_has_one_operation_result_and_atomic_outbox() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let repository = database
        .repository()
        .await
        .expect("construct the PostgreSQL repository");
    let gateway = ExecutionEvidenceGateway::new(
        LoseFirstAcknowledgement::new(repository),
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
    );
    let context = source_context();
    let request = create_request("operation_lost_ack_01", "client_lost_ack_01");

    let lost_ack = gateway
        .open_run(&context, request.clone())
        .await
        .expect_err("the wrapper must lose the first committed acknowledgement");
    assert_eq!(lost_ack.code(), ContractErrorCode::Backpressure);
    let retry_response = lost_ack.response().expect("safe lost-ack response");
    assert!(retry_response.retryable());
    assert_eq!(retry_response.retry_after_ms(), Some(250));

    let retried = gateway
        .open_run(&context, request)
        .await
        .expect("retry the committed operation after acknowledgement loss");
    assert_eq!(retried.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(retried.run_id().as_str(), RUN_ID);
    assert_eq!(retried.source_stream_id(), STREAM_ID);
    assert_eq!(retried.lease().lease_id(), LEASE_ID);

    let operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.gateway_operations WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count committed operation identities");
    let replay_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.operation_replays WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count encrypted operation results");
    let ledger_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.record_items WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count committed ledger records");
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.projection_outbox WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count committed projection outbox rows");

    assert_eq!(operation_count, 1);
    assert_eq!(replay_count, 1);
    assert_eq!(ledger_count, 3);
    assert_eq!(outbox_count, ledger_count);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn concurrent_identical_open_run_writers_converge_on_one_deterministic_result() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let left_repository = database
        .repository()
        .await
        .expect("construct the left PostgreSQL repository and pool");
    let right_repository = database
        .repository()
        .await
        .expect("construct the right PostgreSQL repository and pool");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let context = source_context();
    let request = create_request("operation_concurrent_01", "client_concurrent_01");

    let left = {
        let barrier = barrier.clone();
        let context = context.clone();
        let request = request.clone();
        async move {
            let gateway = ExecutionEvidenceGateway::new(
                left_repository,
                FixedClock(NOW_UNIX_MS),
                FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
            );
            barrier.wait().await;
            gateway.open_run(&context, request).await
        }
    };
    let right = {
        let barrier = barrier.clone();
        let context = context.clone();
        let request = request.clone();
        async move {
            let gateway = ExecutionEvidenceGateway::new(
                right_repository,
                FixedClock(NOW_UNIX_MS),
                FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
            );
            barrier.wait().await;
            gateway.open_run(&context, request).await
        }
    };

    let (left, right) = tokio::join!(left, right);
    let left = left.expect("left concurrent writer converges");
    let right = right.expect("right concurrent writer converges");

    assert_eq!(left.run_id().as_str(), RUN_ID);
    assert_eq!(right.run_id(), left.run_id());
    assert_eq!(left.source_stream_id(), STREAM_ID);
    assert_eq!(right.source_stream_id(), left.source_stream_id());
    assert_eq!(left.lease().lease_id(), LEASE_ID);
    assert_eq!(right.lease(), left.lease());
    assert_eq!(
        [left.outcome(), right.outcome()]
            .into_iter()
            .filter(|outcome| *outcome == OpenRunOutcome::Created)
            .count(),
        1
    );
    assert_eq!(
        [left.outcome(), right.outcome()]
            .into_iter()
            .filter(|outcome| *outcome == OpenRunOutcome::IdempotentRetry)
            .count(),
        1
    );

    let operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.gateway_operations WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count the converged operation identity");
    assert_eq!(operation_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn concurrent_distinct_operations_for_one_client_run_key_have_one_deterministic_winner() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let left_repository = database
        .repository()
        .await
        .expect("construct the left PostgreSQL repository and pool");
    let right_repository = database
        .repository()
        .await
        .expect("construct the right PostgreSQL repository and pool");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let context = source_context();

    let writer = |repository: PostgresGatewayRepository, operation_id: &'static str| {
        let barrier = barrier.clone();
        let context = context.clone();
        async move {
            let gateway = ExecutionEvidenceGateway::new(
                repository,
                FixedClock(NOW_UNIX_MS),
                FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
            );
            barrier.wait().await;
            gateway
                .open_run(
                    &context,
                    create_request(operation_id, "client_concurrent_identity_01"),
                )
                .await
        }
    };

    let (left, right) = tokio::join!(
        writer(left_repository, "operation_concurrent_identity_left_01"),
        writer(right_repository, "operation_concurrent_identity_right_01")
    );
    let mut created = 0;
    let mut conflicts = 0;
    for result in [left, right] {
        match result {
            Ok(response) => {
                assert_eq!(response.outcome(), OpenRunOutcome::Created);
                created += 1;
            }
            Err(error) => {
                assert_eq!(error.code(), ContractErrorCode::IdempotencyConflict);
                conflicts += 1;
            }
        }
    }
    assert_eq!(created, 1);
    assert_eq!(conflicts, 1);

    let client_run_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.client_runs WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count the unique client-run identity");
    let operation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.gateway_operations WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count the winning operation");
    assert_eq!(client_run_count, 1);
    assert_eq!(operation_count, 1);
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn plaintext_lease_token_is_absent_from_all_text_json_and_bytea_columns() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("construct the PostgreSQL repository"),
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(
            &context,
            create_request("operation_plaintext_scan_01", "client_plaintext_scan_01"),
        )
        .await
        .expect("commit an open_run before scanning persistence");
    assert_eq!(opened.lease().lease_id(), LEASE_ID);

    let columns = sqlx::query(
        "SELECT relation.relname AS table_name, attribute.attname AS column_name, \
                base_type.typname AS storage_type \
         FROM pg_catalog.pg_attribute AS attribute \
         JOIN pg_catalog.pg_class AS relation ON relation.oid=attribute.attrelid \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace \
         JOIN pg_catalog.pg_type AS declared_type ON declared_type.oid=attribute.atttypid \
         JOIN pg_catalog.pg_type AS base_type \
           ON base_type.oid=CASE WHEN declared_type.typtype='d' \
                                 THEN declared_type.typbasetype ELSE declared_type.oid END \
         WHERE namespace.nspname='apolysis_gateway' \
           AND relation.relkind IN ('r','p') \
           AND attribute.attnum>0 AND NOT attribute.attisdropped \
           AND base_type.typname IN ('text','varchar','bpchar','json','jsonb','bytea') \
         ORDER BY relation.relname, attribute.attnum",
    )
    .fetch_all(database.pool())
    .await
    .expect("enumerate persisted text, JSON, and bytea columns");
    let mut plaintext_locations = Vec::new();
    for column in columns {
        let table_name: String = column.get("table_name");
        let column_name: String = column.get("column_name");
        let storage_type: String = column.get("storage_type");
        let table = quote_identifier(&table_name);
        let field = quote_identifier(&column_name);
        let statement = if storage_type == "bytea" {
            format!(
                "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.{table} \
                 WHERE position($1::bytea in {field})>0)"
            )
        } else {
            format!(
                "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.{table} \
                 WHERE position($1::text in {field}::text)>0)"
            )
        };
        let found: bool = if storage_type == "bytea" {
            sqlx::query_scalar(&statement)
                .bind(LEASE_ID.as_bytes())
                .fetch_one(database.pool())
                .await
                .expect("scan one bytea persistence column")
        } else {
            sqlx::query_scalar(&statement)
                .bind(LEASE_ID)
                .fetch_one(database.pool())
                .await
                .expect("scan one textual persistence column")
        };
        if found {
            plaintext_locations.push(format!("{table_name}.{column_name}"));
        }
    }

    assert!(
        plaintext_locations.is_empty(),
        "plaintext lease material persisted in: {}",
        plaintext_locations.join(", ")
    );
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn organization_ledger_sequences_are_contiguous_with_exactly_one_outbox_per_record() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let left_repository = database
        .repository()
        .await
        .expect("construct the left PostgreSQL repository and pool");
    let right_repository = database
        .repository()
        .await
        .expect("construct the right PostgreSQL repository and pool");
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let context = source_context();

    let left = {
        let barrier = barrier.clone();
        let context = context.clone();
        async move {
            let gateway = ExecutionEvidenceGateway::new(
                left_repository,
                FixedClock(NOW_UNIX_MS),
                FixedIds::new(&[
                    "run_sequence_01",
                    "stream_sequence_01",
                    "lease_sequence_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ]),
            );
            barrier.wait().await;
            gateway
                .open_run(
                    &context,
                    create_request("operation_sequence_01", "client_sequence_01"),
                )
                .await
        }
    };
    let right = {
        let barrier = barrier.clone();
        let context = context.clone();
        async move {
            let gateway = ExecutionEvidenceGateway::new(
                right_repository,
                FixedClock(NOW_UNIX_MS),
                FixedIds::new(&[
                    "run_sequence_02",
                    "stream_sequence_02",
                    "lease_sequence_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ]),
            );
            barrier.wait().await;
            gateway
                .open_run(
                    &context,
                    create_request("operation_sequence_02", "client_sequence_02"),
                )
                .await
        }
    };

    let (left, right) = tokio::join!(left, right);
    assert_eq!(
        left.expect("append the left concurrent run").outcome(),
        OpenRunOutcome::Created
    );
    assert_eq!(
        right.expect("append the right concurrent run").outcome(),
        OpenRunOutcome::Created
    );

    let sequences: Vec<i64> = sqlx::query_scalar(
        "SELECT ingest_sequence FROM apolysis_gateway.record_items \
         WHERE organization_id=$1 ORDER BY ingest_sequence",
    )
    .bind(context.organization_id().as_str())
    .fetch_all(database.pool())
    .await
    .expect("read organization ledger sequences");
    assert_eq!(sequences, vec![1, 2, 3, 4, 5, 6]);

    let unmatched_records: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.record_items AS record \
         LEFT JOIN apolysis_gateway.projection_outbox AS outbox \
           ON outbox.organization_id=record.organization_id \
          AND outbox.ingest_sequence=record.ingest_sequence \
         WHERE record.organization_id=$1 AND outbox.ingest_sequence IS NULL",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("find ledger records without an outbox row");
    let unmatched_outbox: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.projection_outbox AS outbox \
         LEFT JOIN apolysis_gateway.record_items AS record \
           ON record.organization_id=outbox.organization_id \
          AND record.ingest_sequence=outbox.ingest_sequence \
         WHERE outbox.organization_id=$1 AND record.ingest_sequence IS NULL",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("find outbox rows without a ledger record");
    let paired_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.record_items AS record \
         JOIN apolysis_gateway.projection_outbox AS outbox \
           ON outbox.organization_id=record.organization_id \
          AND outbox.ingest_sequence=record.ingest_sequence \
         WHERE record.organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count ledger/outbox pairs");

    assert_eq!(unmatched_records, 0);
    assert_eq!(unmatched_outbox, 0);
    assert_eq!(paired_count, sequences.len() as i64);
}

async fn install_sequence_update_audit(database: &TestDatabase) {
    sqlx::raw_sql(
        "DROP TRIGGER IF EXISTS organization_sequence_update_audit \
             ON apolysis_gateway.organization_sequences; \
         DROP FUNCTION IF EXISTS apolysis_gateway.audit_organization_sequence_update(); \
         DROP TABLE IF EXISTS apolysis_gateway.sequence_update_audit; \
         CREATE TABLE apolysis_gateway.sequence_update_audit ( \
             old_next_ingest_sequence bigint NOT NULL, \
             new_next_ingest_sequence bigint NOT NULL \
         ); \
         CREATE FUNCTION apolysis_gateway.audit_organization_sequence_update() \
         RETURNS trigger LANGUAGE plpgsql AS $audit$ \
         BEGIN \
             INSERT INTO apolysis_gateway.sequence_update_audit ( \
                 old_next_ingest_sequence, new_next_ingest_sequence \
             ) VALUES (OLD.next_ingest_sequence, NEW.next_ingest_sequence); \
             RETURN NEW; \
         END \
         $audit$; \
         CREATE TRIGGER organization_sequence_update_audit \
         AFTER UPDATE ON apolysis_gateway.organization_sequences \
         FOR EACH ROW EXECUTE FUNCTION \
             apolysis_gateway.audit_organization_sequence_update();",
    )
    .execute(database.pool())
    .await
    .expect("install the real sequence-update audit trigger");
}

async fn clear_sequence_update_audit(database: &TestDatabase) {
    sqlx::query("TRUNCATE TABLE apolysis_gateway.sequence_update_audit")
        .execute(database.pool())
        .await
        .expect("clear the sequence reservation audit");
}

async fn sequence_update_audit(database: &TestDatabase) -> (i64, Option<i64>) {
    sqlx::query_as(
        "SELECT count(*), \
                sum(new_next_ingest_sequence-old_next_ingest_sequence)::bigint \
         FROM apolysis_gateway.sequence_update_audit",
    )
    .fetch_one(database.pool())
    .await
    .expect("read the sequence reservation audit")
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn max_ingest_batch_reserves_one_exact_organization_sequence_range() {
    const MAX_BATCH_ITEMS: u64 = 256;

    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("construct the PostgreSQL repository"),
        SystemClock,
        OsRandomIdGenerator,
    );
    let context = runtime_source_context();
    let opened = gateway
        .open_run(
            &context,
            create_request("operation_range_open_01", "client_range_open_01"),
        )
        .await
        .expect("open the range-reservation test run");

    install_sequence_update_audit(&database).await;

    let acknowledgement = gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_range_ingest_01",
                1..=MAX_BATCH_ITEMS,
            ),
        )
        .await
        .expect("commit one maximum-sized ingest batch");

    let updates = sequence_update_audit(&database).await;
    assert_eq!(updates.0, 1, "one ingest batch must reserve one range");
    assert_eq!(updates.1, Some(MAX_BATCH_ITEMS as i64));

    let assigned = acknowledgement
        .acknowledgements()
        .iter()
        .map(|acknowledgement| {
            acknowledgement
                .ingest_sequence()
                .expect("committed acknowledgement has an ingest sequence")
        })
        .collect::<Vec<_>>();
    assert_eq!(acknowledgement.committed_count(), MAX_BATCH_ITEMS as u32);
    assert_eq!(acknowledgement.duplicate_count(), 0);
    assert_eq!(assigned, (4..=MAX_BATCH_ITEMS + 3).collect::<Vec<_>>());
    assert_eq!(
        acknowledgement.durable_ingest_watermark(),
        MAX_BATCH_ITEMS + 3
    );

    let persisted_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM apolysis_gateway.evidence_events \
              WHERE organization_id=$1), \
             (SELECT count(*) FROM apolysis_gateway.record_items \
              WHERE organization_id=$1 AND fact_kind='evidence_accepted'), \
             (SELECT count(*) FROM apolysis_gateway.projection_outbox AS outbox \
              JOIN apolysis_gateway.record_items AS record \
                ON record.organization_id=outbox.organization_id \
               AND record.ingest_sequence=outbox.ingest_sequence \
              WHERE record.organization_id=$1 AND record.fact_kind='evidence_accepted')",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count committed evidence, ledger, and outbox rows");
    assert_eq!(
        persisted_counts,
        (
            MAX_BATCH_ITEMS as i64,
            MAX_BATCH_ITEMS as i64,
            MAX_BATCH_ITEMS as i64,
        )
    );
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn mixed_and_duplicate_batches_reserve_only_novel_sequences() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("construct the PostgreSQL repository"),
        SystemClock,
        OsRandomIdGenerator,
    );
    let context = runtime_source_context();
    let opened = gateway
        .open_run(
            &context,
            create_request("operation_mixed_open_01", "client_mixed_open_01"),
        )
        .await
        .expect("open the mixed-batch test run");
    install_sequence_update_audit(&database).await;

    let initial_request = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_mixed_initial_01",
        1..=4,
    );
    let initial = gateway
        .ingest(&context, initial_request.clone())
        .await
        .expect("commit the initial novel batch");
    assert_eq!(initial.committed_count(), 4);
    assert_eq!(sequence_update_audit(&database).await, (1, Some(4)));
    clear_sequence_update_audit(&database).await;

    let exact_replay = gateway
        .ingest(&context, initial_request)
        .await
        .expect("replay the exact committed ingest operation");
    assert_eq!(exact_replay, initial);
    assert_eq!(sequence_update_audit(&database).await, (0, None));

    // A later retry must rebuild exact duplicate envelopes independently of
    // the wall-clock millisecond in which the request is assembled.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let mixed = gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_mixed_retry_01",
                [1, 5, 2, 6],
            ),
        )
        .await
        .expect("commit only the novel members of a mixed batch");
    assert_eq!(mixed.committed_count(), 2);
    assert_eq!(mixed.duplicate_count(), 2);
    assert_eq!(
        mixed
            .acknowledgements()
            .iter()
            .map(|acknowledgement| acknowledgement.ingest_sequence().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![4, 8, 5, 9]
    );
    assert_eq!(sequence_update_audit(&database).await, (1, Some(2)));
    clear_sequence_update_audit(&database).await;

    let duplicates = gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_mixed_duplicates_01",
                [1, 2, 5, 6],
            ),
        )
        .await
        .expect("acknowledge an all-duplicate batch without allocation");
    assert_eq!(duplicates.committed_count(), 0);
    assert_eq!(duplicates.duplicate_count(), 4);
    assert_eq!(duplicates.durable_ingest_watermark(), 9);
    assert_eq!(sequence_update_audit(&database).await, (0, None));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn concurrent_ingest_writers_receive_disjoint_contiguous_sequence_ranges() {
    const EVENTS_PER_WRITER: u64 = 32;

    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let context = runtime_source_context();
    let left_gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("construct the left PostgreSQL repository and pool"),
        SystemClock,
        OsRandomIdGenerator,
    );
    let right_gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("construct the right PostgreSQL repository and pool"),
        SystemClock,
        OsRandomIdGenerator,
    );
    let left_opened = left_gateway
        .open_run(
            &context,
            create_request("operation_range_left_open_01", "client_range_left_open_01"),
        )
        .await
        .expect("open the left concurrent run");
    let right_opened = right_gateway
        .open_run(
            &context,
            create_request(
                "operation_range_right_open_01",
                "client_range_right_open_01",
            ),
        )
        .await
        .expect("open the right concurrent run");
    install_sequence_update_audit(&database).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let left_context = context.clone();
    let left_barrier = barrier.clone();
    let left = async move {
        let request = ingest_request(
            left_opened.run_id().as_str(),
            left_opened.lease().lease_id(),
            left_opened.source_stream_id(),
            "operation_range_left_ingest_01",
            1..=EVENTS_PER_WRITER,
        );
        left_barrier.wait().await;
        left_gateway.ingest(&left_context, request).await
    };
    let right_context = context.clone();
    let right = async move {
        let request = ingest_request(
            right_opened.run_id().as_str(),
            right_opened.lease().lease_id(),
            right_opened.source_stream_id(),
            "operation_range_right_ingest_01",
            1..=EVENTS_PER_WRITER,
        );
        barrier.wait().await;
        right_gateway.ingest(&right_context, request).await
    };
    let (left, right) = tokio::join!(left, right);
    let left = left.expect("commit the left concurrent range");
    let right = right.expect("commit the right concurrent range");

    let assigned = |acknowledgement: &apolysis_contracts::IngestAck| {
        acknowledgement
            .acknowledgements()
            .iter()
            .map(|item| item.ingest_sequence().unwrap_or_default())
            .collect::<Vec<_>>()
    };
    let left_assigned = assigned(&left);
    let right_assigned = assigned(&right);
    assert!(left_assigned
        .windows(2)
        .all(|window| window[1] == window[0] + 1));
    assert!(right_assigned
        .windows(2)
        .all(|window| window[1] == window[0] + 1));
    let mut all_assigned = left_assigned;
    all_assigned.extend(right_assigned);
    all_assigned.sort_unstable();
    assert_eq!(all_assigned, (7..=70).collect::<Vec<_>>());
    assert_eq!(sequence_update_audit(&database).await, (2, Some(64)));

    let deltas: Vec<i64> = sqlx::query_scalar(
        "SELECT new_next_ingest_sequence-old_next_ingest_sequence \
         FROM apolysis_gateway.sequence_update_audit \
         ORDER BY old_next_ingest_sequence",
    )
    .fetch_all(database.pool())
    .await
    .expect("read each concurrent sequence reservation");
    assert_eq!(deltas, vec![32, 32]);
    let ledger_sequences: Vec<i64> = sqlx::query_scalar(
        "SELECT ingest_sequence FROM apolysis_gateway.record_items \
         WHERE organization_id=$1 ORDER BY ingest_sequence",
    )
    .bind(context.organization_id().as_str())
    .fetch_all(database.pool())
    .await
    .expect("read the concurrent organization ledger");
    assert_eq!(ledger_sequences, (1..=70).collect::<Vec<_>>());
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn failed_write_rolls_back_the_reserved_range_without_a_ledger_hole() {
    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("construct the PostgreSQL repository"),
        SystemClock,
        OsRandomIdGenerator,
    );
    let context = runtime_source_context();
    let opened = gateway
        .open_run(
            &context,
            create_request(
                "operation_range_rollback_open_01",
                "client_range_rollback_01",
            ),
        )
        .await
        .expect("open the range-rollback test run");
    install_sequence_update_audit(&database).await;
    sqlx::raw_sql(
        "DROP TRIGGER IF EXISTS reject_range_test_evidence \
             ON apolysis_gateway.evidence_events; \
         DROP FUNCTION IF EXISTS apolysis_gateway.reject_range_test_evidence(); \
         CREATE FUNCTION apolysis_gateway.reject_range_test_evidence() \
         RETURNS trigger LANGUAGE plpgsql AS $reject$ \
         BEGIN \
             RAISE EXCEPTION 'range reservation rollback test rejection'; \
         END \
         $reject$; \
         CREATE TRIGGER reject_range_test_evidence \
         BEFORE INSERT ON apolysis_gateway.evidence_events \
         FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.reject_range_test_evidence();",
    )
    .execute(database.pool())
    .await
    .expect("install the test-owned evidence rejection trigger");

    let request = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_range_rollback_ingest_01",
        1..=4,
    );
    gateway
        .ingest(&context, request.clone())
        .await
        .expect_err("the real PostgreSQL trigger must reject the reserved batch");
    sqlx::raw_sql(
        "DROP TRIGGER reject_range_test_evidence \
             ON apolysis_gateway.evidence_events; \
         DROP FUNCTION apolysis_gateway.reject_range_test_evidence();",
    )
    .execute(database.pool())
    .await
    .expect("remove the test-owned evidence rejection trigger");

    let next_sequence: i64 = sqlx::query_scalar(
        "SELECT next_ingest_sequence \
         FROM apolysis_gateway.organization_sequences WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("read the sequence after rollback");
    assert_eq!(next_sequence, 4);
    assert_eq!(sequence_update_audit(&database).await, (0, None));
    let rolled_back_counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM apolysis_gateway.evidence_events WHERE organization_id=$1), \
             (SELECT count(*) FROM apolysis_gateway.record_items WHERE organization_id=$1), \
             (SELECT count(*) FROM apolysis_gateway.projection_outbox WHERE organization_id=$1), \
             (SELECT count(*) FROM apolysis_gateway.gateway_operations WHERE organization_id=$1), \
             (SELECT count(*) FROM apolysis_gateway.operation_replays WHERE organization_id=$1)",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("verify every reserved-batch write rolled back");
    assert_eq!(rolled_back_counts, (0, 3, 3, 1, 1));

    let retry = gateway
        .ingest(&context, request)
        .await
        .expect("retry the rolled-back operation without skipping its range");
    assert_eq!(
        retry
            .acknowledgements()
            .iter()
            .map(|acknowledgement| acknowledgement.ingest_sequence().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![4, 5, 6, 7]
    );
    assert_eq!(sequence_update_audit(&database).await, (1, Some(4)));
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL durability gate"]
async fn expired_replay_survives_reconstruction_as_an_idempotency_tombstone() {
    const REPLAY_TTL_MS: u64 = 1;

    let database = TestDatabase::start()
        .await
        .expect("start isolated PostgreSQL durability test");
    let config = PostgresGatewayConfig::new(REPLAY_TTL_MS, 3, 4)
        .expect("construct a short replay TTL configuration");
    let context = source_context();
    let request = create_request("operation_expired_replay_01", "client_expired_replay_01");

    let repository = database
        .repository_with_config(config.clone())
        .await
        .expect("construct the initial PostgreSQL repository and pool");
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(NOW_UNIX_MS),
        FixedIds::new(&[RUN_ID, STREAM_ID, LEASE_ID]),
    );
    gateway
        .open_run(&context, request.clone())
        .await
        .expect("commit the open_run before replay expiry");
    drop(gateway);

    let before: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM apolysis_gateway.gateway_operations \
             WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.operation_replays \
             WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.runs \
             WHERE organization_id=$1)",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count durable rows before the expired retry");
    assert_eq!(before, (1, 1, 1));

    let reconstructed = database
        .repository_with_config(config)
        .await
        .expect("reconstruct the PostgreSQL repository with a new pool");
    let retry_gateway = ExecutionEvidenceGateway::new(
        reconstructed,
        FixedClock(NOW_UNIX_MS + REPLAY_TTL_MS),
        FixedIds::new(&[]),
    );
    let error = retry_gateway
        .open_run(&context, request)
        .await
        .expect_err("an exactly expired replay must not execute as a novel operation");
    assert_eq!(error.code(), ContractErrorCode::IdempotencyConflict);

    let after: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM apolysis_gateway.gateway_operations \
             WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.operation_replays \
             WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.runs \
             WHERE organization_id=$1)",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count durable rows after the expired retry");
    assert_eq!(after, before);
}

// SPDX-License-Identifier: Apache-2.0

use crate::support::{create_request, open_run, source_context, TestDatabase, NOW_UNIX_MS};
use apolysis_projection_postgres::{
    ComputationVersion, InputFailureCode, PostgresRunProjection, ProjectionConfig,
    ProjectionErrorCode,
};

const MAX_LEDGER_ITEM_BYTES: i32 = 1_048_576;

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn compressed_jsonb_over_the_logical_limit_blocks_without_advancing_checkpoint() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_logical_size");
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    open_run(
        repository,
        &context,
        create_request(
            "operation_logical_size_0000",
            "client_logical_size_0000",
            "objective_logical_size_0000",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");

    sqlx::query(
        "UPDATE apolysis_gateway.record_items \
         SET fact_json=jsonb_set(\
             fact_json, '{projection_size_probe}', \
             to_jsonb(repeat('x', $3::integer)), true\
         ) \
         WHERE organization_id=$1 AND ingest_sequence=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(1_i64)
    .bind(MAX_LEDGER_ITEM_BYTES * 2)
    .execute(database.pool())
    .await
    .expect("plant a highly compressible oversized logical JSONB input");

    let (logical_size, physical_size): (i32, i32) = sqlx::query_as(
        "SELECT octet_length(fact_json::text), pg_column_size(fact_json) \
         FROM apolysis_gateway.record_items \
         WHERE organization_id=$1 AND ingest_sequence=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(1_i64)
    .fetch_one(database.pool())
    .await
    .expect("measure the logical and physical JSONB sizes in PostgreSQL");
    assert!(
        logical_size > MAX_LEDGER_ITEM_BYTES,
        "the planted JSON text must exceed the projection input limit"
    );
    assert!(
        physical_size < MAX_LEDGER_ITEM_BYTES,
        "TOAST compression must keep the physical JSONB size below the input limit"
    );

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    let generation = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-logical-size-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the active generation");

    let error = projection
        .project_next(generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect_err("an oversized logical input must block projection");
    assert_eq!(error.code(), ProjectionErrorCode::LedgerIntegrity);

    let status = projection
        .generation_status(generation.key(), NOW_UNIX_MS + 3)
        .await
        .expect("load the durably blocked checkpoint");
    assert_eq!(
        status.checkpoint().failure(),
        Some((InputFailureCode::OversizedInput, 1))
    );
    assert_eq!(status.checkpoint().input_watermark(), 0);
    assert_eq!(status.checkpoint().last_commit_revision(), None);
}

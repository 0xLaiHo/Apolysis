// SPDX-License-Identifier: Apache-2.0

use crate::support::{create_request, open_run, source_context, TestDatabase, NOW_UNIX_MS};
use apolysis_projection_postgres::{
    migrate_projection_schema, ComputationVersion, PostgresRunProjection, ProjectionBatchOutcome,
    ProjectionConfig, ProjectionErrorCode,
};

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn a_commit_with_a_mismatched_predecessor_watermark_is_rejected_at_real_commit() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_disconnected_commit");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_disconnected_commit",
            "client_disconnected_commit",
            "objective_disconnected_commit",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");
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
            ComputationVersion::try_from("run-lifecycle-disconnected-commit-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the generation");

    let mut transaction = database
        .pool()
        .begin()
        .await
        .expect("begin the disconnected-commit transaction");
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .expect("defer predecessor validation to COMMIT");
    sqlx::query(
        "INSERT INTO apolysis_projection.commits (\
             organization_id, generation_id, commit_revision, previous_commit_revision, \
             from_input_watermark, through_input_watermark, record_count, \
             projected_at_unix_ms, batch_digest\
         ) VALUES ($1,$2,1,NULL,0,3,3,$3,decode(repeat('10',32),'hex'))",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .bind(i64::try_from(NOW_UNIX_MS + 2).expect("SQL timestamp"))
    .execute(&mut *transaction)
    .await
    .expect("insert the valid predecessor in the same deferred transaction");
    sqlx::query(
        "INSERT INTO apolysis_projection.commits (\
             organization_id, generation_id, commit_revision, previous_commit_revision, \
             from_input_watermark, through_input_watermark, record_count, \
             projected_at_unix_ms, batch_digest\
         ) VALUES ($1,$2,2,1,4,5,1,$3,decode(repeat('11',32),'hex'))",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .bind(i64::try_from(NOW_UNIX_MS + 2).expect("SQL timestamp"))
    .execute(&mut *transaction)
    .await
    .expect("the deferred insert itself succeeds");
    let commit_error = transaction
        .commit()
        .await
        .expect_err("COMMIT must reject the predecessor watermark mismatch");
    assert_eq!(
        commit_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("commits_previous_fk")
    );
    let commit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_projection.commits \
         WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .fetch_one(database.pool())
    .await
    .expect("verify the rejected commit left no row");
    assert_eq!(commit_count, 0);
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn a_checkpoint_watermark_without_the_matching_commit_is_rejected_at_real_commit() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_mismatched_checkpoint_commit");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_mismatched_checkpoint_commit",
            "client_mismatched_checkpoint_commit",
            "objective_mismatched_checkpoint_commit",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");
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
            ComputationVersion::try_from("run-lifecycle-mismatched-checkpoint-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the generation");
    assert!(matches!(
        projection
            .project_next(generation.key(), NOW_UNIX_MS + 2)
            .await
            .expect("project one genuine commit"),
        ProjectionBatchOutcome::Applied(_)
    ));

    let mut transaction = database
        .pool()
        .begin()
        .await
        .expect("begin the mismatched-checkpoint transaction");
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .expect("defer checkpoint/commit validation to COMMIT");
    sqlx::query(
        "UPDATE apolysis_projection.checkpoints \
         SET input_watermark=2 WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .execute(&mut *transaction)
    .await
    .expect("the deferred checkpoint update itself succeeds");
    sqlx::query(
        "UPDATE apolysis_projection.organization_heads \
         SET query_visible_watermark=2 WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .execute(&mut *transaction)
    .await
    .expect("keep the deferred head/checkpoint link internally consistent");
    let commit_error = transaction
        .commit()
        .await
        .expect_err("COMMIT must reject a checkpoint without a matching commit watermark");
    assert_eq!(
        commit_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("checkpoints_commit_fk")
    );
    let durable_watermark: i64 = sqlx::query_scalar(
        "SELECT input_watermark FROM apolysis_projection.checkpoints \
         WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .fetch_one(database.pool())
    .await
    .expect("load the durable checkpoint after rollback");
    assert_eq!(durable_watermark, 3);
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn a_head_watermark_without_the_matching_checkpoint_is_rejected_at_real_commit() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_mismatched_head_checkpoint");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_mismatched_head_checkpoint",
            "client_mismatched_head_checkpoint",
            "objective_mismatched_head_checkpoint",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");
    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-mismatched-head-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the generation");

    let mut transaction = database
        .pool()
        .begin()
        .await
        .expect("begin the mismatched-head transaction");
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *transaction)
        .await
        .expect("defer head/checkpoint validation to COMMIT");
    sqlx::query(
        "UPDATE apolysis_projection.organization_heads \
         SET query_visible_watermark=1 WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .execute(&mut *transaction)
    .await
    .expect("the deferred head update itself succeeds");
    let commit_error = transaction
        .commit()
        .await
        .expect_err("COMMIT must reject a head without a matching checkpoint");
    assert_eq!(
        commit_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("organization_heads_checkpoint_fk")
    );
    let visible_watermark: i64 = sqlx::query_scalar(
        "SELECT query_visible_watermark \
         FROM apolysis_projection.organization_heads WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("load the durable head after rollback");
    assert_eq!(visible_watermark, 0);
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn tampered_description_checksum_and_extra_migration_history_fail_closed() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let original_description: String = sqlx::query_scalar(
        "SELECT description FROM apolysis_projection.schema_migrations WHERE version=1",
    )
    .fetch_one(database.pool())
    .await
    .expect("load the genuine migration description");
    let original_checksum: Vec<u8> = sqlx::query_scalar(
        "SELECT checksum FROM apolysis_projection.schema_migrations WHERE version=1",
    )
    .fetch_one(database.pool())
    .await
    .expect("load the genuine migration checksum");

    sqlx::query(
        "UPDATE apolysis_projection.schema_migrations \
         SET description='tampered migration history' WHERE version=1",
    )
    .execute(database.pool())
    .await
    .expect("tamper with the migration ledger");
    let tampered_result = migrate_projection_schema(database.pool()).await;
    sqlx::query("UPDATE apolysis_projection.schema_migrations SET description=$1 WHERE version=1")
        .bind(&original_description)
        .execute(database.pool())
        .await
        .expect("restore the genuine migration description");
    assert!(matches!(
        tampered_result,
        Err(ref error) if error.code() == ProjectionErrorCode::RepositoryInvariant
    ));

    sqlx::query(
        "UPDATE apolysis_projection.schema_migrations \
         SET checksum=decode(repeat('33',32),'hex') WHERE version=1",
    )
    .execute(database.pool())
    .await
    .expect("tamper with the migration checksum");
    let checksum_result = migrate_projection_schema(database.pool()).await;
    sqlx::query("UPDATE apolysis_projection.schema_migrations SET checksum=$1 WHERE version=1")
        .bind(&original_checksum)
        .execute(database.pool())
        .await
        .expect("restore the genuine migration checksum");
    assert!(matches!(
        checksum_result,
        Err(ref error) if error.code() == ProjectionErrorCode::RepositoryInvariant
    ));

    sqlx::query(
        "INSERT INTO apolysis_projection.schema_migrations \
         (version, description, checksum) \
         VALUES (2, 'unexpected migration', decode(repeat('22',32),'hex'))",
    )
    .execute(database.pool())
    .await
    .expect("append an unexpected migration history row");
    let extra_result = migrate_projection_schema(database.pool()).await;
    sqlx::query("DELETE FROM apolysis_projection.schema_migrations WHERE version=2")
        .execute(database.pool())
        .await
        .expect("remove the unexpected migration history row");
    assert!(matches!(
        extra_result,
        Err(ref error) if error.code() == ProjectionErrorCode::RepositoryInvariant
    ));

    migrate_projection_schema(database.pool())
        .await
        .expect("the restored exact migration ledger verifies successfully");
}

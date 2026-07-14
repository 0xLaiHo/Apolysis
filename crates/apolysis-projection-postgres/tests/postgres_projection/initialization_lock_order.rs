// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use crate::support::{create_request, open_run, source_context, TestDatabase, NOW_UNIX_MS};
use apolysis_projection_postgres::{ComputationVersion, PostgresRunProjection, ProjectionConfig};
use sqlx::{postgres::PgPoolOptions, PgPool};

const INITIALIZE_BARRIER_LOCK: i64 = 7_413_062_121;
const REBUILD_BARRIER_LOCK: i64 = 7_413_062_122;
const EXISTING_INITIALIZE_BARRIER_LOCK: i64 = 7_413_062_123;

async fn named_single_connection_pool(database: &TestDatabase, application_name: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(database.connect_options())
        .await
        .expect("construct an isolated real PostgreSQL pool");
    sqlx::query("SELECT set_config('application_name',$1,false)")
        .bind(application_name)
        .execute(&pool)
        .await
        .expect("identify the PostgreSQL lock-order participant");
    pool
}

async fn wait_for_application_lock(pool: &PgPool, application_name: &str) {
    for _ in 0..400 {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND application_name=$1 \
                   AND wait_event_type='Lock'\
             )",
        )
        .bind(application_name)
        .fetch_one(pool)
        .await
        .expect("inspect the real PostgreSQL lock wait");
        if waiting {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the expected PostgreSQL participant did not reach its forced lock wait");
}

fn single_attempt_config() -> ProjectionConfig {
    ProjectionConfig::new(100, 1, 5_000, 10_000).expect("bounded test configuration")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn concurrent_exact_first_initialization_returns_one_generation() {
    const LEFT_APPLICATION: &str = "apolysis_initialize_first_left_test";
    const RIGHT_APPLICATION: &str = "apolysis_initialize_first_right_test";

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_initialize_first_race");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_initialize_first_race_0000",
            "client_initialize_first_race_0000",
            "objective_initialize_first_race_0000",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");

    sqlx::raw_sql(
        "CREATE FUNCTION apolysis_projection.test_hold_first_generation_insert() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             PERFORM pg_advisory_xact_lock(7413062121); \
             RETURN NEW; \
           END \
         $function$; \
         CREATE TRIGGER test_hold_first_generation_insert \
           BEFORE INSERT ON apolysis_projection.generations \
           FOR EACH ROW EXECUTE FUNCTION \
             apolysis_projection.test_hold_first_generation_insert();",
    )
    .execute(database.pool())
    .await
    .expect("install the first-initialization transaction barrier");
    let mut barrier_connection = database
        .pool()
        .acquire()
        .await
        .expect("acquire the initialization barrier connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(INITIALIZE_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("hold the first-initialization barrier");

    let left_pool = named_single_connection_pool(&database, LEFT_APPLICATION).await;
    let right_pool = named_single_connection_pool(&database, RIGHT_APPLICATION).await;
    let left = PostgresRunProjection::from_pool(left_pool, single_attempt_config());
    let right = PostgresRunProjection::from_pool(right_pool, single_attempt_config());
    let left_organization = context.organization_id().clone();
    let right_organization = context.organization_id().clone();
    let left_task = tokio::spawn(async move {
        left.initialize_current(
            &left_organization,
            ComputationVersion::try_from("run-lifecycle-initialize-first-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
    });
    wait_for_application_lock(database.pool(), LEFT_APPLICATION).await;
    let right_task = tokio::spawn(async move {
        right
            .initialize_current(
                &right_organization,
                ComputationVersion::try_from("run-lifecycle-initialize-first-v1")
                    .expect("computation version"),
                NOW_UNIX_MS + 1,
            )
            .await
    });
    wait_for_application_lock(database.pool(), RIGHT_APPLICATION).await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(INITIALIZE_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("release the first-initialization barrier");
    let left_result = tokio::time::timeout(Duration::from_secs(10), left_task).await;
    let right_result = tokio::time::timeout(Duration::from_secs(10), right_task).await;
    sqlx::raw_sql(
        "DROP TRIGGER test_hold_first_generation_insert \
           ON apolysis_projection.generations; \
         DROP FUNCTION apolysis_projection.test_hold_first_generation_insert();",
    )
    .execute(database.pool())
    .await
    .expect("remove the first-initialization transaction barrier");

    let left_generation = left_result
        .expect("left initialization must finish")
        .expect("join the left initialization")
        .expect("left initialization must succeed");
    let right_generation = right_result
        .expect("right initialization must finish")
        .expect("join the right initialization")
        .expect("right initialization must load the winner");
    assert_eq!(left_generation, right_generation);
    let active_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_projection.generations \
         WHERE organization_id=$1 AND generation_state='active'",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("count the exact active-generation result");
    assert_eq!(active_count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn active_projection_and_start_rebuild_use_one_deadlock_free_lock_order() {
    const PROJECT_APPLICATION: &str = "apolysis_project_start_rebuild_test";
    const REBUILD_APPLICATION: &str = "apolysis_start_rebuild_lock_order_test";

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_start_rebuild_lock_order");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_start_rebuild_lock_order_0000",
            "client_start_rebuild_lock_order_0000",
            "objective_start_rebuild_lock_order_0000",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");

    let coordinator = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection coordinator pool"),
        single_attempt_config(),
    );
    let current = coordinator
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-start-rebuild-v1")
                .expect("current computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the current generation");

    sqlx::raw_sql(
        "CREATE FUNCTION apolysis_projection.test_hold_start_rebuild_project_commit() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             PERFORM pg_advisory_xact_lock(7413062122); \
             RETURN NEW; \
           END \
         $function$; \
         CREATE TRIGGER test_hold_start_rebuild_project_commit \
           BEFORE INSERT ON apolysis_projection.commits \
           FOR EACH ROW EXECUTE FUNCTION \
             apolysis_projection.test_hold_start_rebuild_project_commit();",
    )
    .execute(database.pool())
    .await
    .expect("install the active-project transaction barrier");
    let mut barrier_connection = database
        .pool()
        .acquire()
        .await
        .expect("acquire the active-project barrier connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(REBUILD_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("hold the active-project barrier");

    let project_pool = named_single_connection_pool(&database, PROJECT_APPLICATION).await;
    let projector = PostgresRunProjection::from_pool(project_pool, single_attempt_config());
    let projecting_key = current.key().clone();
    let project_task = tokio::spawn(async move {
        projector
            .project_next(&projecting_key, NOW_UNIX_MS + 2)
            .await
    });
    wait_for_application_lock(database.pool(), PROJECT_APPLICATION).await;

    let rebuild_pool = named_single_connection_pool(&database, REBUILD_APPLICATION).await;
    let rebuilder = PostgresRunProjection::from_pool(rebuild_pool, single_attempt_config());
    let rebuild_organization = context.organization_id().clone();
    let rebuild_task = tokio::spawn(async move {
        rebuilder
            .start_rebuild(
                &rebuild_organization,
                ComputationVersion::try_from("run-lifecycle-start-rebuild-v2")
                    .expect("rebuild computation version"),
                NOW_UNIX_MS + 3,
            )
            .await
    });
    wait_for_application_lock(database.pool(), REBUILD_APPLICATION).await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(REBUILD_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("release the active-project barrier");
    let project_result = tokio::time::timeout(Duration::from_secs(10), project_task).await;
    let rebuild_result = tokio::time::timeout(Duration::from_secs(10), rebuild_task).await;
    sqlx::raw_sql(
        "DROP TRIGGER test_hold_start_rebuild_project_commit \
           ON apolysis_projection.commits; \
         DROP FUNCTION apolysis_projection.test_hold_start_rebuild_project_commit();",
    )
    .execute(database.pool())
    .await
    .expect("remove the active-project transaction barrier");

    project_result
        .expect("active projection must finish")
        .expect("join the active projection")
        .expect("active projection must commit without a deadlock victim");
    let rebuilding = rebuild_result
        .expect("start_rebuild must finish")
        .expect("join start_rebuild")
        .expect("start_rebuild must commit without a deadlock victim");
    assert_eq!(rebuilding.rebuild_of(), Some(current.key().generation_id()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn active_projection_and_exact_initialization_retry_use_one_deadlock_free_lock_order() {
    const PROJECT_APPLICATION: &str = "apolysis_project_initialize_retry_test";
    const INITIALIZE_APPLICATION: &str = "apolysis_initialize_retry_lock_order_test";

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_initialize_retry_lock_order");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_initialize_retry_lock_order_0000",
            "client_initialize_retry_lock_order_0000",
            "objective_initialize_retry_lock_order_0000",
        ),
    )
    .await
    .expect("commit one genuine Gateway run");

    let coordinator = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection coordinator pool"),
        single_attempt_config(),
    );
    let current = coordinator
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-initialize-retry-v1")
                .expect("current computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the current generation");

    sqlx::raw_sql(
        "CREATE FUNCTION apolysis_projection.test_hold_initialize_retry_project_commit() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             PERFORM pg_advisory_xact_lock(7413062123); \
             RETURN NEW; \
           END \
         $function$; \
         CREATE TRIGGER test_hold_initialize_retry_project_commit \
           BEFORE INSERT ON apolysis_projection.commits \
           FOR EACH ROW EXECUTE FUNCTION \
             apolysis_projection.test_hold_initialize_retry_project_commit();",
    )
    .execute(database.pool())
    .await
    .expect("install the active-project transaction barrier");
    let mut barrier_connection = database
        .pool()
        .acquire()
        .await
        .expect("acquire the active-project barrier connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(EXISTING_INITIALIZE_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("hold the active-project barrier");

    let project_pool = named_single_connection_pool(&database, PROJECT_APPLICATION).await;
    let projector = PostgresRunProjection::from_pool(project_pool, single_attempt_config());
    let projecting_key = current.key().clone();
    let project_task = tokio::spawn(async move {
        projector
            .project_next(&projecting_key, NOW_UNIX_MS + 2)
            .await
    });
    wait_for_application_lock(database.pool(), PROJECT_APPLICATION).await;

    let initialize_pool = named_single_connection_pool(&database, INITIALIZE_APPLICATION).await;
    let initializer = PostgresRunProjection::from_pool(initialize_pool, single_attempt_config());
    let initialize_organization = context.organization_id().clone();
    let initialize_task = tokio::spawn(async move {
        initializer
            .initialize_current(
                &initialize_organization,
                ComputationVersion::try_from("run-lifecycle-initialize-retry-v1")
                    .expect("current computation version"),
                NOW_UNIX_MS + 1,
            )
            .await
    });
    wait_for_application_lock(database.pool(), INITIALIZE_APPLICATION).await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(EXISTING_INITIALIZE_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("release the active-project barrier");
    let project_result = tokio::time::timeout(Duration::from_secs(10), project_task).await;
    let initialize_result = tokio::time::timeout(Duration::from_secs(10), initialize_task).await;
    sqlx::raw_sql(
        "DROP TRIGGER test_hold_initialize_retry_project_commit \
           ON apolysis_projection.commits; \
         DROP FUNCTION apolysis_projection.test_hold_initialize_retry_project_commit();",
    )
    .execute(database.pool())
    .await
    .expect("remove the active-project transaction barrier");

    project_result
        .expect("active projection must finish")
        .expect("join the active projection")
        .expect("active projection must commit without a deadlock victim");
    let retried = initialize_result
        .expect("exact initialization retry must finish")
        .expect("join the exact initialization retry")
        .expect("exact initialization retry must load without a deadlock victim");
    assert_eq!(retried, current);
}

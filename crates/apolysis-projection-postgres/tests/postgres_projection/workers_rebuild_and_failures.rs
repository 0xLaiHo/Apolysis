// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::support::{self, create_request, open_run, source_context, TestDatabase, NOW_UNIX_MS};
use apolysis_contracts::{AuthenticatedSourceContext, RunState};
use apolysis_projection_postgres::{
    ComputationVersion, GenerationKey, GenerationState, InputFailureCode, PostgresRunProjection,
    ProjectionBatchOutcome, ProjectionConfig, ProjectionErrorCode,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

async fn prepare_caught_up_rebuild(
    database: &TestDatabase,
    organization_id: &str,
    prefix: &str,
    run_count: usize,
) -> (
    AuthenticatedSourceContext,
    PostgresRunProjection,
    GenerationKey,
    GenerationKey,
) {
    let context = source_context(organization_id);
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    for ordinal in 0..run_count {
        open_run(
            repository.clone(),
            &context,
            create_request(
                &format!("operation_{prefix}_{ordinal:04}"),
                &format!("client_{prefix}_{ordinal:04}"),
                &format!("objective_{prefix}_{ordinal:04}"),
            ),
        )
        .await
        .expect("commit one genuine Gateway run");
    }

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    let current = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from(format!("run-lifecycle-{prefix}-v1"))
                .expect("current computation version"),
            NOW_UNIX_MS + 100,
        )
        .await
        .expect("initialize the current generation");
    support::project_until_caught_up(&projection, current.key(), NOW_UNIX_MS + 101)
        .await
        .expect("project the current generation");
    let rebuilding = projection
        .start_rebuild(
            context.organization_id(),
            ComputationVersion::try_from(format!("run-lifecycle-{prefix}-v2"))
                .expect("rebuild computation version"),
            NOW_UNIX_MS + 200,
        )
        .await
        .expect("start the rebuild generation");
    support::project_until_caught_up(&projection, rebuilding.key(), NOW_UNIX_MS + 201)
        .await
        .expect("project the rebuild generation");

    (
        context,
        projection,
        current.key().clone(),
        rebuilding.key().clone(),
    )
}

async fn wait_for_blocked_query(pool: &PgPool, query_fragment: &str) {
    for _ in 0..200 {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND pid <> pg_backend_pid() \
                   AND wait_event_type='Lock' AND position($1 in query) > 0\
             )",
        )
        .bind(query_fragment)
        .fetch_one(pool)
        .await
        .expect("inspect real PostgreSQL lock waits");
        if blocked {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("the expected real PostgreSQL statement did not reach its forced lock wait");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn independent_pool_workers_commit_ordered_non_overlapping_input_exactly_once() {
    const RUN_COUNT: usize = 48;

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_workers");
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    for ordinal in 0..RUN_COUNT {
        open_run(
            repository.clone(),
            &context,
            create_request(
                &format!("operation_worker_{ordinal:04}"),
                &format!("client_worker_{ordinal:04}"),
                &format!("objective_worker_{ordinal:04}"),
            ),
        )
        .await
        .expect("commit one genuine Gateway run");
    }
    let expected_run_ids: Vec<String> = sqlx::query_scalar(
        "SELECT run_id FROM apolysis_gateway.runs \
         WHERE organization_id=$1 ORDER BY opened_at_unix_ms DESC, run_id ASC",
    )
    .bind(context.organization_id().as_str())
    .fetch_all(database.pool())
    .await
    .expect("load the production-generated source ordering");

    let config = ProjectionConfig::new(11, 8, 5_000, 30_000).expect("bounded config");
    let coordinator = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the coordinator pool"),
        config.clone(),
    );
    let generation = coordinator
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-concurrent-v1").expect("version"),
            NOW_UNIX_MS + 1_000,
        )
        .await
        .expect("initialize the active generation");

    let left = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the left worker pool"),
        config.clone(),
    );
    let right = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the right worker pool"),
        config,
    );
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let left_key = generation.key().clone();
    let right_key = generation.key().clone();
    let left_task = {
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            left.project_next(&left_key, NOW_UNIX_MS + 1_001).await
        })
    };
    let right_task = tokio::spawn(async move {
        barrier.wait().await;
        right.project_next(&right_key, NOW_UNIX_MS + 2_001).await
    });
    let (left_outcome, right_outcome) = tokio::join!(left_task, right_task);
    let left_outcome = left_outcome
        .expect("left worker task")
        .expect("left worker projection");
    let right_outcome = right_outcome
        .expect("right worker task")
        .expect("right worker projection");
    let mut commits = [left_outcome, right_outcome]
        .into_iter()
        .map(|outcome| match outcome {
            ProjectionBatchOutcome::Applied(commit) => commit,
            ProjectionBatchOutcome::CaughtUp(_) => {
                panic!("each independently pooled worker must claim one remaining batch")
            }
        })
        .collect::<Vec<_>>();
    commits.extend(
        support::project_until_caught_up(&coordinator, generation.key(), NOW_UNIX_MS + 3_001)
            .await
            .expect("drain the remaining bounded batches"),
    );
    commits.sort_by_key(|commit| commit.revision());

    assert!(!commits.is_empty());
    let mut expected_from = 0_u64;
    for (index, commit) in commits.iter().enumerate() {
        assert_eq!(
            commit.revision(),
            u64::try_from(index + 1).expect("bounded commit count")
        );
        assert_eq!(commit.from_input_watermark(), expected_from);
        assert_eq!(
            commit.through_input_watermark(),
            expected_from + u64::from(commit.record_count())
        );
        assert!(commit.record_count() <= 11);
        expected_from = commit.through_input_watermark();
    }
    assert_eq!(
        expected_from,
        u64::try_from(RUN_COUNT * 3).expect("watermark")
    );

    let page = coordinator
        .list_active_lifecycle(context.organization_id(), None, 200)
        .await
        .expect("list the exact projected inventory");
    assert_eq!(page.items().len(), RUN_COUNT);
    assert!(page.next_cursor().is_none());
    let actual_run_ids = page
        .items()
        .iter()
        .map(|item| item.run_id().as_str().to_string())
        .collect::<Vec<_>>();
    assert_eq!(actual_run_ids, expected_run_ids);
    assert_eq!(
        actual_run_ids.iter().collect::<BTreeSet<_>>().len(),
        RUN_COUNT,
        "one lifecycle row must exist per genuine Gateway run"
    );

    let status = coordinator
        .active_status(context.organization_id(), NOW_UNIX_MS + 3_000)
        .await
        .expect("load active projection status");
    assert!(status.is_current());
    assert_eq!(status.checkpoint().input_watermark(), expected_from);
    assert_eq!(status.durable_input_watermark(), expected_from);
    assert_eq!(status.query_visible_watermark(), expected_from);
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn rebuilt_generation_cuts_over_atomically_and_expires_the_old_cursor() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_rebuild");
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    let mut exemplar = None;
    for ordinal in 0..3 {
        let opened = open_run(
            repository.clone(),
            &context,
            create_request(
                &format!("operation_rebuild_{ordinal}"),
                &format!("client_rebuild_{ordinal}"),
                &format!("objective_rebuild_{ordinal}"),
            ),
        )
        .await
        .expect("commit one genuine Gateway run");
        exemplar = Some(opened.run_id().clone());
    }

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    let current = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 10,
        )
        .await
        .expect("initialize current generation");
    support::project_until_caught_up(&projection, current.key(), NOW_UNIX_MS + 11)
        .await
        .expect("project the current generation");
    let old_page = projection
        .list_active_lifecycle(context.organization_id(), None, 1)
        .await
        .expect("open a cursor on the current generation");
    let old_cursor = old_page
        .next_cursor()
        .expect("three runs require a cursor at limit one")
        .clone();

    let rebuilding = projection
        .start_rebuild(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v2").expect("version"),
            NOW_UNIX_MS + 20,
        )
        .await
        .expect("start a generation-scoped rebuild");
    assert_eq!(rebuilding.state(), GenerationState::Building);
    assert_eq!(rebuilding.rebuild_of(), Some(current.key().generation_id()));
    support::project_until_caught_up(&projection, rebuilding.key(), NOW_UNIX_MS + 21)
        .await
        .expect("recompute the rebuilding generation from durable inputs");

    let exemplar = exemplar.expect("capture a production-generated run identifier");
    let before_cutover = projection
        .load_active_lifecycle(context.organization_id(), &exemplar)
        .await
        .expect("load through the still-current generation")
        .expect("projected run");
    assert_eq!(
        before_cutover.generation_id(),
        current.key().generation_id()
    );

    let cutover = projection
        .cut_over(rebuilding.key(), NOW_UNIX_MS + 30)
        .await
        .expect("atomically activate the caught-up rebuild");
    assert_eq!(cutover.previous_generation(), current.key().generation_id());
    assert_eq!(
        cutover.active_generation(),
        rebuilding.key().generation_id()
    );
    assert_eq!(cutover.query_visible_watermark(), 9);

    let after_cutover = projection
        .load_active_lifecycle(context.organization_id(), &exemplar)
        .await
        .expect("load through the rebuilt active generation")
        .expect("projected run");
    assert_eq!(
        after_cutover.generation_id(),
        rebuilding.key().generation_id()
    );
    assert_eq!(after_cutover.state(), RunState::Active);

    let stale_cursor = projection
        .list_active_lifecycle(context.organization_id(), Some(&old_cursor), 1)
        .await
        .expect_err("a retired-generation cursor must never cross cutover");
    assert_eq!(stale_cursor.code(), ProjectionErrorCode::CursorExpired);

    let old_status = projection
        .generation_status(current.key(), NOW_UNIX_MS + 31)
        .await
        .expect("load retired generation status");
    assert_eq!(old_status.generation().state(), GenerationState::Retired);
    let active_status = projection
        .active_status(context.organization_id(), NOW_UNIX_MS + 31)
        .await
        .expect("load rebuilt active status");
    assert_eq!(active_status.generation().key(), rebuilding.key());
    assert_eq!(
        active_status.generation().computation_version().as_str(),
        "run-lifecycle-v2"
    );
    assert!(active_status.is_current());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn active_status_cannot_cross_a_generation_cutover() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let (context, coordinator, _current, rebuilding) = prepare_caught_up_rebuild(
        &database,
        "org_projection_active_status_cutover",
        "status_cutover",
        1,
    )
    .await;

    // A real one-connection sqlx pool pauses its second checkout. The buggy
    // active_status reaches that checkout between head resolution and status
    // construction; the fixed implementation completes on its first checkout.
    let checkout_count = Arc::new(AtomicUsize::new(0));
    let second_checkout = Arc::new(tokio::sync::Notify::new());
    let release_checkout = Arc::new(tokio::sync::Notify::new());
    let callback_count = checkout_count.clone();
    let callback_second = second_checkout.clone();
    let callback_release = release_checkout.clone();
    let status_pool = PgPoolOptions::new()
        .max_connections(1)
        .before_acquire(move |_connection, _metadata| {
            let callback_second = callback_second.clone();
            let callback_release = callback_release.clone();
            let checkout = callback_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if checkout == 1 {
                    callback_second.notify_one();
                    callback_release.notified().await;
                }
                Ok(true)
            })
        })
        .connect_with(database.connect_options())
        .await
        .expect("construct the interposed real PostgreSQL pool");
    drop(
        status_pool
            .acquire()
            .await
            .expect("warm the single real PostgreSQL connection"),
    );
    checkout_count.store(0, Ordering::SeqCst);
    let status_reader =
        PostgresRunProjection::from_pool(status_pool.clone(), ProjectionConfig::default());
    let status_organization = context.organization_id().clone();
    let mut status_task = tokio::spawn(async move {
        status_reader
            .active_status(&status_organization, NOW_UNIX_MS + 300)
            .await
    });

    let mut completed_status = None;
    tokio::select! {
        result = &mut status_task => {
            completed_status = Some(result.expect("join the single-transaction status task"));
        }
        () = second_checkout.notified() => {}
    }

    coordinator
        .cut_over(&rebuilding, NOW_UNIX_MS + 301)
        .await
        .expect("cut over while the old implementation is between transactions");
    release_checkout.notify_one();
    let status = match completed_status {
        Some(status) => status.expect("load one coherent active status"),
        None => tokio::time::timeout(std::time::Duration::from_secs(5), status_task)
            .await
            .expect("the interposed active status call must complete")
            .expect("join the interposed active status task")
            .expect("load one coherent active status"),
    };

    assert_eq!(status.generation().state(), GenerationState::Active);
    assert!(status.is_current());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn active_status_does_not_wait_on_an_in_flight_projection_checkpoint() {
    const PROJECT_BARRIER_LOCK: i64 = 7_413_062_119;

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_status_project_contention");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_status_project_contention_0000",
            "client_status_project_contention_0000",
            "objective_status_project_contention_0000",
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
            ComputationVersion::try_from("run-lifecycle-status-contention-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the current generation");

    sqlx::raw_sql(
        "CREATE FUNCTION apolysis_projection.test_hold_projection_commit() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             PERFORM pg_advisory_xact_lock(7413062119); \
             RETURN NEW; \
           END \
         $function$; \
         CREATE TRIGGER test_hold_projection_commit \
           BEFORE INSERT ON apolysis_projection.commits \
           FOR EACH ROW EXECUTE FUNCTION apolysis_projection.test_hold_projection_commit();",
    )
    .execute(database.pool())
    .await
    .expect("install the transaction-local real PostgreSQL barrier");
    let mut barrier_connection = database
        .pool()
        .acquire()
        .await
        .expect("acquire the barrier connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PROJECT_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("hold the projection commit barrier");

    let projecting_repository = projection.clone();
    let projecting_key = generation.key().clone();
    let project_task = tokio::spawn(async move {
        projecting_repository
            .project_next(&projecting_key, NOW_UNIX_MS + 2)
            .await
    });
    wait_for_blocked_query(database.pool(), "INSERT INTO apolysis_projection.commits").await;

    let status_reader = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the independent status pool"),
        ProjectionConfig::default(),
    );
    let status_result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        status_reader.active_status(context.organization_id(), NOW_UNIX_MS + 3),
    )
    .await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PROJECT_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("release the projection commit barrier");
    tokio::time::timeout(std::time::Duration::from_secs(5), project_task)
        .await
        .expect("the projection must finish after barrier release")
        .expect("join the projection task")
        .expect("commit the genuine projection batch");
    sqlx::raw_sql(
        "DROP TRIGGER test_hold_projection_commit ON apolysis_projection.commits; \
         DROP FUNCTION apolysis_projection.test_hold_projection_commit();",
    )
    .execute(database.pool())
    .await
    .expect("remove the real PostgreSQL barrier");

    let status = status_result
        .expect("active_status must not wait on the projector's generation/checkpoint locks")
        .expect("load the pre-commit active status");
    assert_eq!(status.generation().state(), GenerationState::Active);
    assert_eq!(status.checkpoint().input_watermark(), 0);
    assert_eq!(status.query_visible_watermark(), 0);
    assert_eq!(status.durable_input_watermark(), 3);
    assert!(!status.is_current());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn active_projection_and_cutover_use_one_deadlock_free_lock_order() {
    const PROJECT_BARRIER_LOCK: i64 = 7_413_062_120;
    const CUTOVER_APPLICATION_NAME: &str = "apolysis_cutover_lock_order_test";

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let (context, coordinator, current, rebuilding) = prepare_caught_up_rebuild(
        &database,
        "org_projection_cutover_lock_order",
        "cutover_lock_order",
        1,
    )
    .await;
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_cutover_lock_order_append_0001",
            "client_cutover_lock_order_append_0001",
            "objective_cutover_lock_order_append_0001",
        ),
    )
    .await
    .expect("append one genuine run after the rebuild starts");
    support::project_until_caught_up(&coordinator, &rebuilding, NOW_UNIX_MS + 301)
        .await
        .expect("catch the building generation up to the appended run");

    sqlx::raw_sql(
        "CREATE FUNCTION apolysis_projection.test_hold_active_project_commit() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             PERFORM pg_advisory_xact_lock(7413062120); \
             RETURN NEW; \
           END \
         $function$; \
         CREATE TRIGGER test_hold_active_project_commit \
           BEFORE INSERT ON apolysis_projection.commits \
           FOR EACH ROW EXECUTE FUNCTION apolysis_projection.test_hold_active_project_commit();",
    )
    .execute(database.pool())
    .await
    .expect("install the active-project transaction barrier");
    let mut barrier_connection = database
        .pool()
        .acquire()
        .await
        .expect("acquire the barrier connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PROJECT_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("hold the active-project commit barrier");

    let projecting_repository = coordinator.clone();
    let project_task = tokio::spawn(async move {
        projecting_repository
            .project_next(&current, NOW_UNIX_MS + 302)
            .await
    });
    wait_for_blocked_query(database.pool(), "INSERT INTO apolysis_projection.commits").await;

    let cutover_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(database.connect_options())
        .await
        .expect("construct the isolated cutover pool");
    sqlx::query("SELECT set_config('application_name',$1,false)")
        .bind(CUTOVER_APPLICATION_NAME)
        .execute(&cutover_pool)
        .await
        .expect("identify the cutover lock waiter");
    let cutover_repository =
        PostgresRunProjection::from_pool(cutover_pool, ProjectionConfig::default());
    let expected_active_generation = rebuilding.generation_id();
    let cutover_task = tokio::spawn(async move {
        cutover_repository
            .cut_over(&rebuilding, NOW_UNIX_MS + 303)
            .await
    });
    for _ in 0..200 {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND application_name=$1 \
                   AND wait_event_type='Lock'\
             )",
        )
        .bind(CUTOVER_APPLICATION_NAME)
        .fetch_one(database.pool())
        .await
        .expect("inspect the cutover lock wait");
        if blocked {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let cutover_blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM pg_stat_activity \
             WHERE datname=current_database() AND application_name=$1 \
               AND wait_event_type='Lock'\
         )",
    )
    .bind(CUTOVER_APPLICATION_NAME)
    .fetch_one(database.pool())
    .await
    .expect("confirm the cutover lock wait");
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PROJECT_BARRIER_LOCK)
        .execute(&mut *barrier_connection)
        .await
        .expect("release the active-project commit barrier");
    let project_result = tokio::time::timeout(std::time::Duration::from_secs(5), project_task)
        .await
        .expect("the active projection must finish")
        .expect("join the active projection task");
    let cutover_result = tokio::time::timeout(std::time::Duration::from_secs(5), cutover_task)
        .await
        .expect("the cutover must finish")
        .expect("join the cutover task");
    sqlx::raw_sql(
        "DROP TRIGGER test_hold_active_project_commit ON apolysis_projection.commits; \
         DROP FUNCTION apolysis_projection.test_hold_active_project_commit();",
    )
    .execute(database.pool())
    .await
    .expect("remove the active-project transaction barrier");

    assert!(
        cutover_blocked,
        "cutover must reach the old active generation/head contention point"
    );
    project_result.expect("the active projection must commit without a deadlock victim");
    let cutover = cutover_result.expect("cutover must commit without a deadlock victim");
    assert_eq!(cutover.active_generation(), expected_active_generation);
    assert_eq!(cutover.query_visible_watermark(), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn lifecycle_page_and_cursor_cannot_cross_a_generation_cutover() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let (context, coordinator, _current, rebuilding) =
        prepare_caught_up_rebuild(&database, "org_projection_page_cutover", "page_cutover", 2)
            .await;

    let lock_pool = database
        .independent_pool()
        .await
        .expect("construct the lock-control pool");
    let mut lifecycle_lock = lock_pool
        .begin()
        .await
        .expect("begin the lifecycle table lock");
    sqlx::query("LOCK TABLE apolysis_projection.run_lifecycle IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lifecycle_lock)
        .await
        .expect("force the lifecycle row fetch to wait");

    let page_reader = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the page reader pool"),
        ProjectionConfig::default(),
    );
    let page_organization = context.organization_id().clone();
    let page_task = tokio::spawn(async move {
        page_reader
            .list_active_lifecycle(&page_organization, None, 1)
            .await
    });
    wait_for_blocked_query(&lock_pool, "apolysis_projection.run_lifecycle AS lifecycle").await;

    let cutover_coordinator = coordinator.clone();
    let cutover_task = tokio::spawn(async move {
        cutover_coordinator
            .cut_over(&rebuilding, NOW_UNIX_MS + 302)
            .await
    });
    for _ in 0..200 {
        if cutover_task.is_finished() {
            break;
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM pg_stat_activity \
                 WHERE datname=current_database() AND pid <> pg_backend_pid() \
                   AND wait_event_type='Lock' \
                   AND position('SELECT active_generation_id, cutover_revision' in query) > 0\
             )",
        )
        .fetch_one(&lock_pool)
        .await
        .expect("inspect the cutover head lock wait");
        if blocked {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        cutover_task.is_finished()
            || sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (\
                     SELECT 1 FROM pg_stat_activity \
                     WHERE datname=current_database() AND pid <> pg_backend_pid() \
                       AND wait_event_type='Lock' \
                       AND position('SELECT active_generation_id, cutover_revision' in query) > 0\
                 )",
            )
            .fetch_one(&lock_pool)
            .await
            .expect("confirm the bounded cutover state"),
        "cutover must either complete without a head lock or wait on the shared head lock"
    );

    lifecycle_lock
        .commit()
        .await
        .expect("release the forced lifecycle row-fetch wait");
    let page = tokio::time::timeout(std::time::Duration::from_secs(5), page_task)
        .await
        .expect("the lifecycle page must complete")
        .expect("join the lifecycle page task")
        .expect("load one coherent lifecycle page");
    cutover_task
        .await
        .expect("join the cutover task")
        .expect("complete the generation cutover");

    let cursor = page
        .next_cursor()
        .expect("two genuine runs at limit one require a cursor");
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].generation_id(), cursor.generation_id());
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn corrupt_and_missing_head_inputs_block_only_their_organizations() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let corrupt = source_context("org_projection_corrupt");
    let missing = source_context("org_projection_missing");
    let healthy = source_context("org_projection_healthy");

    let mut healthy_run = None;
    for (context, prefix) in [
        (&corrupt, "corrupt"),
        (&missing, "missing"),
        (&healthy, "healthy"),
    ] {
        let opened = open_run(
            database
                .repository()
                .await
                .expect("construct a genuine Gateway repository"),
            context,
            create_request(
                &format!("operation_{prefix}_0"),
                &format!("client_{prefix}_0"),
                &format!("objective_{prefix}_0"),
            ),
        )
        .await
        .expect("commit one genuine Gateway run");
        if prefix == "healthy" {
            healthy_run = Some(opened.run_id().clone());
        }
    }

    sqlx::query(
        "UPDATE apolysis_gateway.record_items \
         SET fact_digest=decode(repeat('00', 32), 'hex') \
         WHERE organization_id=$1 AND ingest_sequence=1",
    )
    .bind(corrupt.organization_id().as_str())
    .execute(database.pool())
    .await
    .expect("plant a length-valid digest corruption");

    let mut missing_head = database
        .pool()
        .begin()
        .await
        .expect("begin corruption setup");
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *missing_head)
        .await
        .expect("defer the exact record/outbox relationship");
    sqlx::query(
        "DELETE FROM apolysis_gateway.projection_outbox \
         WHERE organization_id=$1 AND ingest_sequence=1",
    )
    .bind(missing.organization_id().as_str())
    .execute(&mut *missing_head)
    .await
    .expect("remove the missing head outbox row");
    sqlx::query(
        "DELETE FROM apolysis_gateway.record_items \
         WHERE organization_id=$1 AND ingest_sequence=1",
    )
    .bind(missing.organization_id().as_str())
    .execute(&mut *missing_head)
    .await
    .expect("remove the missing head record row");
    missing_head
        .commit()
        .await
        .expect("commit the deliberate missing-head fault");

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    let corrupt_generation = projection
        .initialize_current(
            corrupt.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize corrupt organization");
    let missing_generation = projection
        .initialize_current(
            missing.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize missing-head organization");
    let healthy_generation = projection
        .initialize_current(
            healthy.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize healthy organization");

    let corrupt_error = projection
        .project_next(corrupt_generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect_err("a mismatched canonical digest must block projection");
    assert_eq!(corrupt_error.code(), ProjectionErrorCode::LedgerIntegrity);
    let missing_error = projection
        .project_next(missing_generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect_err("a missing organization head must block projection");
    assert_eq!(
        missing_error.code(),
        ProjectionErrorCode::LedgerDiscontinuity
    );

    support::project_until_caught_up(&projection, healthy_generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect("the independent healthy organization must still progress");
    let healthy_run = healthy_run.expect("capture the production-generated healthy run ID");
    assert_eq!(
        projection
            .load_active_lifecycle(healthy.organization_id(), &healthy_run)
            .await
            .expect("load healthy organization")
            .expect("healthy lifecycle")
            .state(),
        RunState::Active
    );

    let corrupt_status = projection
        .generation_status(corrupt_generation.key(), NOW_UNIX_MS + 3)
        .await
        .expect("load the durable corrupt checkpoint");
    assert_eq!(
        corrupt_status.checkpoint().failure(),
        Some((InputFailureCode::DigestMismatch, 1))
    );
    assert_eq!(corrupt_status.checkpoint().input_watermark(), 0);
    let missing_status = projection
        .generation_status(missing_generation.key(), NOW_UNIX_MS + 3)
        .await
        .expect("load the durable missing-head checkpoint");
    assert_eq!(
        missing_status.checkpoint().failure(),
        Some((InputFailureCode::MissingInput, 1))
    );
    assert_eq!(missing_status.checkpoint().input_watermark(), 0);
    let healthy_status = projection
        .active_status(healthy.organization_id(), NOW_UNIX_MS + 3)
        .await
        .expect("load the healthy organization status");
    assert!(healthy_status.is_current());
    assert_eq!(healthy_status.query_visible_watermark(), 3);
}

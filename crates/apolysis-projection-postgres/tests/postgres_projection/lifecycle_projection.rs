// SPDX-License-Identifier: Apache-2.0

use crate::support::{
    self, create_request, finish_run_request, gap_fill_request, ingest_request, open_run,
    source_context, TestDatabase, NOW_UNIX_MS,
};
use apolysis_contracts::{OpenRunOutcome, RunState};
use apolysis_gateway::{ExecutionEvidenceGateway, GatewayClock, OsRandomIdGenerator, SystemClock};
use apolysis_projection_postgres::{
    ComputationVersion, PostgresRunProjection, ProjectionBatchOutcome, ProjectionConfig,
};

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn genuine_open_run_projects_lifecycle_and_exact_retry_adds_nothing() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_retry");
    let request = create_request(
        "operation_projection_retry_01",
        "client_projection_retry_01",
        "objective_projection_retry",
    );
    let opened_not_before_unix_ms = SystemClock.now_unix_ms();
    let opened = open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        request.clone(),
    )
    .await
    .expect("commit a genuine open_run through the Gateway");
    let opened_not_after_unix_ms = SystemClock.now_unix_ms();
    assert_eq!(opened.outcome(), OpenRunOutcome::Created);

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
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the current projection generation");
    let initialization_retry = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 99,
        )
        .await
        .expect("retry the exact projection initialization");
    assert_eq!(initialization_retry, generation);
    let first = projection
        .project_next(generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect("project the genuine Gateway batch");
    let commit = match first {
        ProjectionBatchOutcome::Applied(commit) => commit,
        ProjectionBatchOutcome::CaughtUp(_) => panic!("open_run must supply projection input"),
    };
    assert_eq!(commit.from_input_watermark(), 0);
    assert_eq!(commit.through_input_watermark(), 3);
    assert_eq!(commit.record_count(), 3);

    let run_id = opened.run_id().clone();
    let lifecycle = projection
        .load_active_lifecycle(context.organization_id(), &run_id)
        .await
        .expect("load the projected lifecycle")
        .expect("the opened run is visible");
    assert_eq!(lifecycle.organization_id(), context.organization_id());
    assert_eq!(lifecycle.run_id(), &run_id);
    assert_eq!(lifecycle.objective_ref(), "objective_projection_retry");
    assert_eq!(lifecycle.state(), RunState::Active);
    assert!(lifecycle.opened_at_unix_ms() >= opened_not_before_unix_ms);
    assert!(lifecycle.opened_at_unix_ms() <= opened_not_after_unix_ms);
    assert_eq!(
        lifecycle.state_changed_at_unix_ms(),
        lifecycle.opened_at_unix_ms()
    );
    assert_eq!(lifecycle.terminal_at_unix_ms(), None);
    assert_eq!(lifecycle.lifecycle_revision(), 2);
    assert_eq!(lifecycle.opened_ingest_sequence(), 1);
    assert_eq!(lifecycle.last_lifecycle_ingest_sequence(), 2);

    let retry_gateway = ExecutionEvidenceGateway::new(
        database
            .repository()
            .await
            .expect("reconstruct the genuine Gateway repository"),
        SystemClock,
        OsRandomIdGenerator,
    );
    let retried = retry_gateway
        .open_run(&context, request)
        .await
        .expect("replay the exact committed Gateway request");
    assert_eq!(retried.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(retried.run_id(), opened.run_id());
    assert_eq!(retried.source_stream_id(), opened.source_stream_id());
    assert_eq!(retried.lease(), opened.lease());

    let caught_up = projection
        .project_next(generation.key(), NOW_UNIX_MS + 3)
        .await
        .expect("observe that the retry appended no input");
    let checkpoint = match caught_up {
        ProjectionBatchOutcome::CaughtUp(checkpoint) => checkpoint,
        ProjectionBatchOutcome::Applied(_) => panic!("an exact retry must not append ledger facts"),
    };
    assert_eq!(checkpoint.input_watermark(), 3);
    assert_eq!(
        projection
            .load_active_lifecycle(context.organization_id(), &run_id)
            .await
            .expect("reload the projected lifecycle")
            .expect("the opened run remains visible"),
        lifecycle
    );
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn production_generated_runs_are_isolated_between_two_real_organizations() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let alpha = source_context("org_projection_alpha");
    let beta = source_context("org_projection_beta");

    let mut run_ids = Vec::new();
    for (context, objective, suffix) in [
        (&alpha, "objective_alpha", "alpha"),
        (&beta, "objective_beta", "beta"),
    ] {
        let opened = open_run(
            database
                .repository()
                .await
                .expect("construct a genuine Gateway repository"),
            context,
            create_request(
                &format!("operation_projection_{suffix}"),
                &format!("client_projection_{suffix}"),
                objective,
            ),
        )
        .await
        .expect("open the tenant-qualified run through the Gateway");
        run_ids.push(opened.run_id().clone());
    }

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    let alpha_generation = projection
        .initialize_current(
            alpha.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize alpha");
    let beta_generation = projection
        .initialize_current(
            beta.organization_id(),
            ComputationVersion::try_from("run-lifecycle-v1").expect("version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize beta");
    support::project_until_caught_up(&projection, alpha_generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect("project alpha");
    support::project_until_caught_up(&projection, beta_generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect("project beta");

    let alpha_read = projection
        .load_active_lifecycle(alpha.organization_id(), &run_ids[0])
        .await
        .expect("load alpha")
        .expect("alpha run");
    let beta_read = projection
        .load_active_lifecycle(beta.organization_id(), &run_ids[1])
        .await
        .expect("load beta")
        .expect("beta run");

    assert_eq!(alpha_read.organization_id(), alpha.organization_id());
    assert_eq!(alpha_read.objective_ref(), "objective_alpha");
    assert_eq!(beta_read.organization_id(), beta.organization_id());
    assert_eq!(beta_read.objective_ref(), "objective_beta");
    assert_ne!(alpha_read.run_id(), beta_read.run_id());
    assert_eq!(
        alpha_read.generation_id(),
        alpha_generation.key().generation_id()
    );
    assert_eq!(
        beta_read.generation_id(),
        beta_generation.key().generation_id()
    );
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn gap_filled_genuine_run_projects_finished_lifecycle_in_exact_order() {
    const FINISHED_AT: u64 = NOW_UNIX_MS + 300;

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_finished");
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    let opened_not_before_unix_ms = SystemClock.now_unix_ms();
    let opened = open_run(
        repository.clone(),
        &context,
        create_request(
            "operation_projection_finished_open_01",
            "client_projection_finished_01",
            "objective_projection_finished",
        ),
    )
    .await
    .expect("open the genuine run");
    let opened_not_after_unix_ms = SystemClock.now_unix_ms();

    let ingest_gateway =
        ExecutionEvidenceGateway::new(repository.clone(), SystemClock, OsRandomIdGenerator);
    let initial = ingest_gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("ingest genuine source sequences one and three");
    assert_eq!(initial.committed_count(), 2);
    assert_eq!(initial.source_watermark(), 3);
    assert_eq!(initial.known_gaps().len(), 1);
    assert_eq!(initial.known_gaps()[0].first_missing_sequence(), 2);
    assert_eq!(initial.known_gaps()[0].last_missing_sequence(), 2);

    let gap_gateway =
        ExecutionEvidenceGateway::new(repository.clone(), SystemClock, OsRandomIdGenerator);
    let gap_filled = gap_gateway
        .ingest(
            &context,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("fill genuine source sequence two");
    assert_eq!(gap_filled.committed_count(), 1);
    assert_eq!(gap_filled.source_watermark(), 3);
    assert!(gap_filled.known_gaps().is_empty());

    let finish_gateway =
        ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let finished_not_before_unix_ms = SystemClock.now_unix_ms();
    let finished = finish_gateway
        .finish_run(
            &context,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("finish the fully reconciled genuine run");
    let finished_not_after_unix_ms = SystemClock.now_unix_ms();
    assert_eq!(finished.state(), RunState::Finished);
    assert_eq!(finished.finalization_deadline_unix_ms(), None);

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::new(4, 4, 2_000, 15_000).expect("bounded cross-transition batches"),
    );
    let generation = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-finished-v1").expect("version"),
            FINISHED_AT + 1,
        )
        .await
        .expect("initialize the lifecycle generation");
    let commits = support::project_until_caught_up(&projection, generation.key(), FINISHED_AT + 2)
        .await
        .expect("project the ordered lifecycle across bounded batches");
    assert_eq!(
        commits
            .iter()
            .map(|commit| commit.record_count())
            .collect::<Vec<_>>(),
        vec![4, 4, 1]
    );
    assert_eq!(commits[0].from_input_watermark(), 0);
    assert_eq!(commits[0].through_input_watermark(), 4);
    assert_eq!(commits[1].from_input_watermark(), 4);
    assert_eq!(commits[1].through_input_watermark(), 8);
    assert_eq!(commits[2].from_input_watermark(), 8);
    assert_eq!(commits[2].through_input_watermark(), 9);

    let run_id = opened.run_id().clone();
    let lifecycle = projection
        .load_active_lifecycle(context.organization_id(), &run_id)
        .await
        .expect("load the finished lifecycle")
        .expect("finished run projection");
    assert_eq!(lifecycle.state(), RunState::Finished);
    assert!(lifecycle.opened_at_unix_ms() >= opened_not_before_unix_ms);
    assert!(lifecycle.opened_at_unix_ms() <= opened_not_after_unix_ms);
    assert!(lifecycle.state_changed_at_unix_ms() >= finished_not_before_unix_ms);
    assert!(lifecycle.state_changed_at_unix_ms() <= finished_not_after_unix_ms);
    assert_eq!(
        lifecycle.terminal_at_unix_ms(),
        Some(lifecycle.state_changed_at_unix_ms())
    );
    assert_eq!(lifecycle.lifecycle_revision(), 4);
    assert_eq!(lifecycle.opened_ingest_sequence(), 1);
    assert_eq!(lifecycle.last_lifecycle_ingest_sequence(), 9);

    let status = projection
        .active_status(context.organization_id(), FINISHED_AT + 10)
        .await
        .expect("load finished projection status");
    assert!(status.is_current());
    assert_eq!(status.checkpoint().input_watermark(), 9);
    assert_eq!(status.query_visible_watermark(), 9);
}

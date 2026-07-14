// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use crate::support::{self, create_request, open_run, source_context, TestDatabase, NOW_UNIX_MS};
use apolysis_projection_postgres::{
    ComputationVersion, PostgresRunProjection, ProjectionConfig, ProjectionErrorCode,
    MAX_LIFECYCLE_PAGE_SIZE,
};

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn more_than_two_hundred_genuine_runs_page_with_a_stable_bounded_cursor() {
    const ORIGINAL_RUN_COUNT: usize = 205;

    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_pagination");
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    for ordinal in 0..ORIGINAL_RUN_COUNT {
        open_run(
            repository.clone(),
            &context,
            create_request(
                &format!("operation_page_{ordinal:04}"),
                &format!("client_page_{ordinal:04}"),
                &format!("objective_page_{ordinal:04}"),
            ),
        )
        .await
        .expect("commit one genuine Gateway run");
    }
    let expected_descending: Vec<String> = sqlx::query_scalar(
        "SELECT run_id FROM apolysis_gateway.runs \
         WHERE organization_id=$1 ORDER BY opened_at_unix_ms DESC, run_id ASC",
    )
    .bind(context.organization_id().as_str())
    .fetch_all(database.pool())
    .await
    .expect("load the production-generated source ordering");

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::new(200, 4, 5_000, 30_000).expect("maximum bounded batch"),
    );
    let generation = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-pagination-v1").expect("version"),
            NOW_UNIX_MS + 1_000,
        )
        .await
        .expect("initialize the active generation");
    let commits =
        support::project_until_caught_up(&projection, generation.key(), NOW_UNIX_MS + 1_001)
            .await
            .expect("project every genuine Gateway input");
    assert_eq!(
        commits
            .iter()
            .map(|commit| usize::from(commit.record_count()))
            .sum::<usize>(),
        ORIGINAL_RUN_COUNT * 3
    );
    assert_eq!(
        commits
            .iter()
            .map(|commit| commit.record_count())
            .collect::<Vec<_>>(),
        vec![200, 200, 200, 15]
    );

    let oversized = projection
        .list_active_lifecycle(context.organization_id(), None, MAX_LIFECYCLE_PAGE_SIZE + 1)
        .await
        .expect_err("a page above the public bound must fail");
    assert_eq!(oversized.code(), ProjectionErrorCode::InvalidArgument);

    let first = projection
        .list_active_lifecycle(context.organization_id(), None, MAX_LIFECYCLE_PAGE_SIZE)
        .await
        .expect("load the first bounded page");
    assert_eq!(first.limit(), MAX_LIFECYCLE_PAGE_SIZE);
    assert_eq!(first.items().len(), 200);
    assert_eq!(first.visible_input_watermark(), 615);
    let cursor = first
        .next_cursor()
        .expect("five original runs remain")
        .clone();
    assert_eq!(cursor.generation_id(), generation.key().generation_id());
    assert_eq!(cursor.visible_input_watermark(), 615);
    assert_eq!(
        first
            .items()
            .iter()
            .map(|item| item.run_id().as_str().to_string())
            .collect::<Vec<_>>(),
        expected_descending[..200]
    );

    let other_context = source_context("org_projection_cursor_probe");
    open_run(
        repository.clone(),
        &other_context,
        create_request(
            "operation_cursor_probe_0000",
            "client_cursor_probe_0000",
            "objective_cursor_probe_0000",
        ),
    )
    .await
    .expect("commit a genuine run in the probing organization");
    let other_generation = projection
        .initialize_current(
            other_context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-cursor-probe-v1").expect("version"),
            NOW_UNIX_MS + 1_501,
        )
        .await
        .expect("initialize the probing organization");
    support::project_until_caught_up(&projection, other_generation.key(), NOW_UNIX_MS + 1_502)
        .await
        .expect("project the probing organization");
    let cross_organization = projection
        .list_active_lifecycle(
            other_context.organization_id(),
            Some(&cursor),
            MAX_LIFECYCLE_PAGE_SIZE,
        )
        .await
        .expect_err("cursor possession must not cross organization scope");
    assert_eq!(cross_organization.code(), ProjectionErrorCode::NotFound);

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let new_run = open_run(
        repository,
        &context,
        create_request(
            "operation_page_0205",
            "client_page_0205",
            "objective_page_0205",
        ),
    )
    .await
    .expect("commit a run after the cursor snapshot");
    let incremental =
        support::project_until_caught_up(&projection, generation.key(), NOW_UNIX_MS + 2_001)
            .await
            .expect("project the post-cursor run");
    assert_eq!(incremental.len(), 1);
    assert_eq!(incremental[0].record_count(), 3);

    let second = projection
        .list_active_lifecycle(
            context.organization_id(),
            Some(&cursor),
            MAX_LIFECYCLE_PAGE_SIZE,
        )
        .await
        .expect("continue the original cursor snapshot");
    assert_eq!(second.items().len(), 5);
    assert!(second.next_cursor().is_none());
    assert_eq!(second.visible_input_watermark(), 615);
    assert_eq!(
        second
            .items()
            .iter()
            .map(|item| item.run_id().as_str().to_string())
            .collect::<Vec<_>>(),
        expected_descending[200..]
    );

    let all_original = first
        .items()
        .iter()
        .chain(second.items())
        .map(|item| item.run_id().as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(all_original.len(), ORIGINAL_RUN_COUNT);
    assert!(!all_original.contains(new_run.run_id().as_str()));

    let fresh = projection
        .list_active_lifecycle(context.organization_id(), None, 1)
        .await
        .expect("open a fresh snapshot after incremental projection");
    assert_eq!(fresh.visible_input_watermark(), 618);
    assert_eq!(fresh.items()[0].run_id(), new_run.run_id());
}

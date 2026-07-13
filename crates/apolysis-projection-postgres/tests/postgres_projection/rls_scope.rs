// SPDX-License-Identifier: Apache-2.0

use crate::support::{self, create_request, open_run, source_context, TestDatabase, NOW_UNIX_MS};
use apolysis_projection_postgres::{ComputationVersion, PostgresRunProjection, ProjectionConfig};

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn forced_rls_scopes_an_ordinary_runtime_role_when_the_trusted_app_sets_tenant_context() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let alpha = source_context("org_projection_rls_alpha");
    let beta = source_context("org_projection_rls_beta");
    for (context, prefix) in [(&alpha, "rls_alpha"), (&beta, "rls_beta")] {
        open_run(
            database
                .repository()
                .await
                .expect("construct a genuine Gateway repository"),
            context,
            create_request(
                &format!("operation_{prefix}"),
                &format!("client_{prefix}"),
                &format!("objective_{prefix}"),
            ),
        )
        .await
        .expect("commit a genuine tenant run");
    }

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the projection pool"),
        ProjectionConfig::default(),
    );
    for context in [&alpha, &beta] {
        let generation = projection
            .initialize_current(
                context.organization_id(),
                ComputationVersion::try_from("run-lifecycle-rls-v1").expect("version"),
                NOW_UNIX_MS + 1,
            )
            .await
            .expect("initialize a tenant generation");
        support::project_until_caught_up(&projection, generation.key(), NOW_UNIX_MS + 2)
            .await
            .expect("project a tenant generation");
    }

    let role = format!("apolysis_projection_rls_probe_{}", std::process::id());
    assert!(role
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
    sqlx::query(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
    ))
    .execute(database.pool())
    .await
    .expect("create an ordinary RLS probe role");
    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA apolysis_projection TO {role}; \
         GRANT SELECT ON apolysis_projection.run_lifecycle TO {role}"
    ))
    .execute(database.pool())
    .await
    .expect("grant the minimum read permission");

    let mut transaction = database.pool().begin().await.expect("begin RLS probe");
    sqlx::query(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *transaction)
        .await
        .expect("assume the ordinary runtime role");
    let unscoped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM apolysis_projection.run_lifecycle")
            .fetch_one(&mut *transaction)
            .await
            .expect("query without tenant context");
    assert_eq!(unscoped, 0);
    sqlx::query("SELECT set_config('apolysis.organization_id',$1,true)")
        .bind(alpha.organization_id().as_str())
        .execute(&mut *transaction)
        .await
        .expect("set trusted application tenant context");
    let alpha_visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM apolysis_projection.run_lifecycle")
            .fetch_one(&mut *transaction)
            .await
            .expect("query under alpha context");
    assert_eq!(alpha_visible, 1);
    transaction.commit().await.expect("commit the RLS probe");

    sqlx::raw_sql(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
        .execute(database.pool())
        .await
        .expect("remove the exact RLS probe role");
}

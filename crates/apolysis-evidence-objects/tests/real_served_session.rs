// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, io, sync::Arc, time::Duration};

use apolysis_contracts::OrganizationId;
use apolysis_evidence_objects::{
    EvidenceObjectErrorCode, EvidenceObjectLifecycle, EvidenceObjectPolicy, ObjectLifecycleConfig,
    OperatorActor,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use apolysis_gateway_server::AuthorityStore;
use sqlx::{postgres::PgPoolOptions, PgPool};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const ORGANIZATION_ID: &str = "org_served_session_preflight";

async fn set_persistent_replication_role(pool: &PgPool, setting: &'static str) -> TestResult {
    let sql = match setting {
        "replica" => {
            "DO $block$ BEGIN EXECUTE format(\
                'ALTER ROLE %I IN DATABASE %I SET session_replication_role TO replica', \
                current_user, current_database()); END $block$"
        }
        "reset" => {
            "DO $block$ BEGIN EXECUTE format(\
                'ALTER ROLE %I IN DATABASE %I RESET session_replication_role', \
                current_user, current_database()); END $block$"
        }
        _ => return Err("unsupported served-session test setting".into()),
    };
    sqlx::query(sql).execute(pool).await?;
    Ok(())
}

async fn reset_persistent_replication_role(database_url: &str) -> TestResult {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let result = set_persistent_replication_role(&pool, "reset").await;
    pool.close().await;
    result
}

async fn run_replica_default_regression(database_url: &str) -> TestResult {
    let owner_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let is_superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user")
            .fetch_one(&owner_pool)
            .await?;
    if !is_superuser {
        return Err(
            "served-session qualification requires an ephemeral PostgreSQL superuser".into(),
        );
    }
    MIGRATOR.run(&owner_pool).await?;
    let now_unix_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&owner_pool)
            .await?;
    sqlx::query(
        "DELETE FROM apolysis_gateway.evidence_object_policy_revisions \
         WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .execute(&owner_pool)
    .await?;
    sqlx::query("DELETE FROM apolysis_gateway.organizations WHERE organization_id=$1")
        .bind(ORGANIZATION_ID)
        .execute(&owner_pool)
        .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.organizations (\
            organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,'active',$2,$2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(now_unix_ms)
    .execute(&owner_pool)
    .await?;
    set_persistent_replication_role(&owner_pool, "replica").await?;
    owner_pool.close().await;

    let mut replay_key = [0_u8; 32];
    getrandom::fill(&mut replay_key)?;
    let gateway = PostgresGatewayRepository::connect(
        database_url,
        Arc::new(Aes256GcmReplayProtector::new(
            "served-session-preflight-key",
            [("served-session-preflight-key".to_string(), replay_key)],
        )?),
        PostgresGatewayConfig::default(),
    )
    .await;
    if gateway.is_ok() {
        return Err("Gateway repository accepted a replica-default served session".into());
    }

    let authority = AuthorityStore::connect(database_url).await;
    if authority.is_ok() {
        return Err("authority store accepted a replica-default served session".into());
    }

    // The lifecycle deliberately accepts externally built pools. Its first
    // transaction must therefore qualify the checked-out session itself.
    let replica_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let has_replica_default: bool =
        sqlx::query_scalar("SELECT current_setting('session_replication_role', false) = 'replica'")
            .fetch_one(&replica_pool)
            .await?;
    if !has_replica_default {
        return Err("PostgreSQL did not apply the persistent replica test setting".into());
    }
    let lifecycle = EvidenceObjectLifecycle::new(
        replica_pool.clone(),
        replica_pool.clone(),
        replica_pool.clone(),
        ObjectLifecycleConfig::new(
            "http://127.0.0.1:1",
            "us-east-1",
            "served-session-preflight",
            "served_session_backend_v1",
            "served_session_access_key",
            "served_session_secret_key",
            "served_session_wrapping_v1",
            [91_u8; 32],
            Duration::from_secs(1),
            Duration::from_secs(2),
        )?,
    );
    let policy = EvidenceObjectPolicy::new(
        OrganizationId::try_from(ORGANIZATION_ID)?,
        "privacy_served_session_v1",
        "retention_served_session_v1",
        1,
        1_024,
        4_096,
        4,
        4,
        10_000,
        60_000,
        u64::try_from(now_unix_ms)?,
    )?;
    let failure = match lifecycle
        .install_policy(&OperatorActor::new("operator_served_session")?, &policy)
        .await
    {
        Ok(()) => return Err("lifecycle accepted a replica-default served session".into()),
        Err(failure) => failure,
    };
    if failure.code() != EvidenceObjectErrorCode::DatabaseUnavailable {
        return Err("replica-default lifecycle failure used an unexpected classification".into());
    }
    let mutation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.evidence_object_policy_revisions \
         WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&replica_pool)
    .await?;
    replica_pool.close().await;
    if mutation_count != 0 {
        return Err("replica-default lifecycle session mutated policy state".into());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the pinned real PostgreSQL 16 qualification provider"]
async fn replica_default_served_sessions_fail_before_mutation() -> TestResult {
    let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "APOLYSIS_TEST_DATABASE_URL is required by the served-session qualification",
        )
    })?;
    if std::env::var("APOLYSIS_TEST_ALLOW_DATABASE_RESET").as_deref() != Ok("1") {
        return Err(
            "served-session qualification requires explicit ephemeral database opt-in".into(),
        );
    }

    reset_persistent_replication_role(&database_url).await?;
    let qualification = run_replica_default_regression(&database_url).await;
    let cleanup = reset_persistent_replication_role(&database_url).await;
    qualification?;
    cleanup
}

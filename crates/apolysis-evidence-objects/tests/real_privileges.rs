// SPDX-License-Identifier: Apache-2.0

mod support;

use std::{error::Error, str::FromStr, sync::Arc, time::Duration};

use apolysis_contracts::OrganizationId;
use apolysis_evidence_objects::{EvidenceObjectLifecycle, ObjectLifecycleConfig, OperatorActor};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository,
};
use apolysis_gateway_server::AuthorityStore;
use sqlx::{
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
    Postgres,
};
use support::privileges::{ApplicationRolePools, BOOTSTRAP_ROLES_SQL, PRIVILEGES_SQL};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const CAPABILITY_ROLES: [&str; 6] = [
    "apolysis_schema_owner",
    "apolysis_gateway_runtime",
    "apolysis_gateway_control",
    "apolysis_evidence_runtime",
    "apolysis_evidence_control",
    "apolysis_deletion_ack",
];
const REAPER_ORGANIZATION_LOCK_FUNCTION: &str =
    "apolysis_gateway.lock_evidence_object_reaper_organizations(bigint,integer)";

fn assert_permission_denied(error: &sqlx::Error) {
    let database_error = error
        .as_database_error()
        .expect("PostgreSQL must report a database permission error");
    assert_eq!(database_error.code().as_deref(), Some("42501"), "{error}");
}

async fn assert_reaper_organization_lock_execution_denied(
    pool: &sqlx::PgPool,
    role_label: &str,
) -> TestResult {
    let error = sqlx::query_scalar::<_, String>(
        "SELECT apolysis_gateway.lock_evidence_object_reaper_organizations($1,$2)",
    )
    .bind(1_i64)
    .bind(1_i32)
    .fetch_all(pool)
    .await
    .expect_err(role_label);
    assert_permission_denied(&error);
    Ok(())
}

async fn assert_bootstrap_rejected(
    connection: &mut PoolConnection<Postgres>,
    expected_message: &str,
) -> TestResult {
    let error = sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut **connection)
        .await
        .expect_err("poisoned served authority must fail bootstrap");
    let database_error = error
        .as_database_error()
        .expect("bootstrap rejection must be a bounded database error");
    assert_eq!(database_error.code().as_deref(), Some("P0001"));
    assert!(
        database_error.message().contains(expected_message),
        "{error}"
    );
    sqlx::query("ROLLBACK").execute(&mut **connection).await?;
    Ok(())
}

async fn assert_bootstrap_converges(connection: &mut PoolConnection<Postgres>) -> TestResult {
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut **connection)
        .await?;
    Ok(())
}

async fn assert_served_login_can_select_replica_mode(
    connection: &mut PoolConnection<Postgres>,
    login_role: &str,
) -> TestResult {
    sqlx::query(&format!("SET ROLE {login_role}"))
        .execute(&mut **connection)
        .await?;
    sqlx::query("SET session_replication_role='replica'")
        .execute(&mut **connection)
        .await?;
    let replication_role: String =
        sqlx::query_scalar("SELECT current_setting('session_replication_role')")
            .fetch_one(&mut **connection)
            .await?;
    assert_eq!(replication_role, "replica");
    sqlx::query("RESET session_replication_role")
        .execute(&mut **connection)
        .await?;
    sqlx::query("RESET ROLE").execute(&mut **connection).await?;
    Ok(())
}

async fn assert_fresh_login_starts_in_replica_mode(
    database_url: &str,
    login_role: &str,
    password: &str,
) -> TestResult {
    let options = PgConnectOptions::from_str(database_url)?
        .username(login_role)
        .password(password);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let replication_role: String =
        sqlx::query_scalar("SELECT current_setting('session_replication_role')")
            .fetch_one(&pool)
            .await?;
    assert_eq!(replication_role, "replica");
    pool.close().await;
    Ok(())
}

async fn seed_retention_control_fixture(owner_pool: &sqlx::PgPool) -> TestResult {
    sqlx::raw_sql(
        r#"
        BEGIN;

        INSERT INTO apolysis_gateway.organization_sequences (
            organization_id,
            next_ingest_sequence,
            updated_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            2,
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.organizations (
            organization_id,
            organization_state,
            created_at_unix_ms,
            updated_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            'active',
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.source_registrations (
            source_registration_id,
            organization_id,
            source_id,
            principal_kind,
            principal_id,
            registration_state,
            policy_revision,
            credential_epoch,
            effective_at_unix_ms,
            expires_at_unix_ms,
            policy_document,
            created_at_unix_ms,
            updated_at_unix_ms
        ) VALUES (
            'registration_privilege_retention',
            'org_privilege_retention',
            'source_privilege_retention',
            'workload',
            'principal_privilege_retention',
            'active',
            1,
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms() - 1000,
            apolysis_gateway.evidence_object_db_now_unix_ms() + 600000,
            '{"allowed_operations":["ingest"],"allowed_capabilities":["tool_calls"]}'::jsonb,
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.runs (
            organization_id,
            run_id,
            state,
            environment,
            authority_kind,
            authority_id,
            principal_kind,
            principal_id,
            objective_ref,
            privacy_profile_ref,
            retention_profile_ref,
            initiating_source_registration_id,
            initiating_principal_kind,
            initiating_principal_id,
            opened_at_unix_ms,
            state_changed_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            'run_privilege_retention',
            'active',
            'ci_runner_or_remote_workspace',
            'service',
            'authority_privilege_retention',
            'workload',
            'principal_privilege_retention',
            'objective_privilege_retention',
            'privacy_privilege_retention',
            'retention_privilege_retention',
            'registration_privilege_retention',
            'workload',
            'principal_privilege_retention',
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.record_items (
            organization_id,
            run_id,
            ingest_sequence,
            ingested_at_unix_ms,
            fact_kind,
            fact_json,
            fact_digest,
            outbox_ingest_sequence
        ) VALUES (
            'org_privilege_retention',
            'run_privilege_retention',
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            'source_registered',
            '{}'::jsonb,
            decode(repeat('31', 32), 'hex'),
            1
        );
        INSERT INTO apolysis_gateway.projection_outbox (
            organization_id,
            ingest_sequence,
            available_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id,
            source_kind,
            environment,
            registration_principal_kind,
            registration_principal_id,
            registration_policy_revision,
            effective_trust_profile,
            manifest_digest,
            manifest_json,
            registered_ingest_sequence,
            registered_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            'run_privilege_retention',
            'registration_privilege_retention',
            'stream_privilege_retention',
            'source_privilege_retention',
            'semantic_hook',
            'ci_runner_or_remote_workspace',
            'workload',
            'principal_privilege_retention',
            1,
            'harness_observed',
            decode(repeat('32', 32), 'hex'),
            '{"privacy_capabilities":["authorized_content_reference"]}'::jsonb,
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.source_stream_capabilities (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            capability
        ) VALUES (
            'org_privilege_retention',
            'run_privilege_retention',
            'registration_privilege_retention',
            'stream_privilege_retention',
            'tool_calls'
        );
        INSERT INTO apolysis_gateway.leases (
            organization_id,
            lease_digest,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id,
            principal_kind,
            principal_id,
            registration_policy_revision,
            issued_at_unix_ms,
            expires_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            decode(repeat('33', 32), 'hex'),
            'run_privilege_retention',
            'registration_privilege_retention',
            'stream_privilege_retention',
            'source_privilege_retention',
            'workload',
            'principal_privilege_retention',
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms() - 1000,
            apolysis_gateway.evidence_object_db_now_unix_ms() + 600000
        );
        INSERT INTO apolysis_gateway.lease_operations (
            organization_id,
            lease_digest,
            operation_kind
        ) VALUES (
            'org_privilege_retention',
            decode(repeat('33', 32), 'hex'),
            'ingest'
        );
        INSERT INTO apolysis_gateway.evidence_object_policy_revisions (
            organization_id,
            privacy_profile_ref,
            retention_profile_ref,
            policy_revision,
            policy_state,
            max_object_size_bytes,
            organization_quota_bytes,
            organization_quota_objects,
            uploads_per_minute,
            upload_timeout_ms,
            retention_ms,
            effective_at_unix_ms,
            created_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            'privacy_privilege_retention',
            'retention_privilege_retention',
            1,
            'active',
            1024,
            4096,
            4,
            4,
            10000,
            120000,
            apolysis_gateway.evidence_object_db_now_unix_ms() - 1000,
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.evidence_objects (
            organization_id,
            object_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id,
            lease_digest,
            lease_policy_revision,
            client_upload_id,
            capture_request_digest,
            required_source_capability,
            payload_type,
            payload_version,
            content_digest,
            content_size_bytes,
            ciphertext_size_bytes,
            object_state,
            privacy_profile_ref,
            retention_profile_ref,
            object_policy_revision,
            requested_retention_ms,
            lifecycle_revision,
            created_at_unix_ms,
            lifecycle_changed_at_unix_ms,
            upload_deadline_unix_ms,
            expires_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            'object_privilege_retention',
            'run_privilege_retention',
            'registration_privilege_retention',
            'stream_privilege_retention',
            'source_privilege_retention',
            decode(repeat('33', 32), 'hex'),
            1,
            'upload_privilege_retention',
            decode(repeat('34', 32), 'hex'),
            'tool_calls',
            'tool_blob',
            '1.0.0',
            decode(repeat('35', 32), 'hex'),
            64,
            80,
            'uploading',
            'privacy_privilege_retention',
            'retention_privilege_retention',
            1,
            45000,
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            apolysis_gateway.evidence_object_db_now_unix_ms() + 10000,
            apolysis_gateway.evidence_object_db_now_unix_ms() + 45000
        );
        INSERT INTO apolysis_gateway.evidence_object_storage_material (
            organization_id,
            object_id,
            storage_backend_ref,
            storage_backend_binding_digest,
            storage_operation_timeout_ms,
            storage_key,
            encryption_algorithm,
            cipher_version,
            encryption_key_ref,
            encrypted_data_key,
            key_wrap_nonce,
            content_nonce,
            aad_digest
        ) VALUES (
            'org_privilege_retention',
            'object_privilege_retention',
            'backend_privilege_retention',
            decode(repeat('36', 32), 'hex'),
            1000,
            'key_privilege_retention',
            'aes-256-gcm',
            1,
            'key_ref_privilege_retention',
            decode(repeat('37', 48), 'hex'),
            decode(repeat('38', 12), 'hex'),
            decode(repeat('39', 12), 'hex'),
            decode(repeat('3a', 32), 'hex')
        );
        INSERT INTO apolysis_gateway.evidence_object_outbox (
            organization_id,
            object_id,
            lifecycle_revision,
            event_kind,
            event_json,
            available_at_unix_ms,
            created_at_unix_ms
        ) VALUES (
            'org_privilege_retention',
            'object_privilege_retention',
            1,
            'upload_reserved',
            '{}'::jsonb,
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            apolysis_gateway.evidence_object_db_now_unix_ms()
        );
        INSERT INTO apolysis_gateway.evidence_object_audit (
            organization_id,
            object_id,
            lifecycle_revision,
            occurred_at_unix_ms,
            actor_kind,
            actor_id,
            action,
            decision,
            reason_code,
            metadata_json
        ) VALUES (
            'org_privilege_retention',
            'object_privilege_retention',
            1,
            apolysis_gateway.evidence_object_db_now_unix_ms(),
            'system',
            'privilege_fixture',
            'reserve_upload',
            'completed',
            'privilege_fixture',
            '{}'::jsonb
        );

        COMMIT;
        "#,
    )
    .execute(owner_pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an explicit ephemeral real PostgreSQL privilege gate"]
async fn non_owner_application_roles_enforce_privilege_boundaries() -> TestResult {
    if std::env::var("APOLYSIS_TEST_ALLOW_DATABASE_RESET").as_deref() != Ok("1") {
        return Err("privilege gate requires explicit ephemeral database reset opt-in".into());
    }
    let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL")?;
    let owner_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await?;
    sqlx::query("DROP SCHEMA IF EXISTS apolysis_gateway CASCADE")
        .execute(&owner_pool)
        .await?;
    sqlx::query("DROP TABLE IF EXISTS public._sqlx_migrations")
        .execute(&owner_pool)
        .await?;

    let repository = PostgresGatewayRepository::connect(
        &database_url,
        Arc::new(Aes256GcmReplayProtector::new(
            "blank-connect-key",
            [("blank-connect-key".to_string(), [19_u8; 32])],
        )?),
        PostgresGatewayConfig::default(),
    )
    .await?;
    let authority = AuthorityStore::connect(&database_url).await?;
    drop(repository);
    drop(authority);
    let blank_connect_state: (bool, bool) = sqlx::query_as(
        "SELECT to_regnamespace('apolysis_gateway') IS NOT NULL, \
                to_regclass('public._sqlx_migrations') IS NOT NULL",
    )
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(blank_connect_state, (false, false));

    // PostgreSQL 16 gives a non-superuser CREATEROLE principal administrative
    // membership in roles it creates. Reject that operationally ambiguous
    // bootstrap path before it can create any fixed capability role.
    let mut candidate_suffix = [0_u8; 8];
    getrandom::fill(&mut candidate_suffix)?;
    let bootstrap_candidate = format!(
        "apolysis_test_bootstrap_candidate_{}",
        candidate_suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut candidate_connection = owner_pool.acquire().await?;
    sqlx::query(&format!(
        "CREATE ROLE {bootstrap_candidate} WITH LOGIN NOSUPERUSER NOINHERIT \
         NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS"
    ))
    .execute(&mut *candidate_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {bootstrap_candidate}"))
        .execute(&mut *candidate_connection)
        .await?;
    let candidate_error = sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *candidate_connection)
        .await
        .expect_err("non-superuser CREATEROLE bootstrap must fail closed");
    let candidate_database_error = candidate_error
        .as_database_error()
        .expect("bootstrap rejection must be a bounded database error");
    assert_eq!(candidate_database_error.code().as_deref(), Some("P0001"));
    assert_eq!(
        candidate_database_error.message(),
        "Apolysis role bootstrap requires a PostgreSQL superuser"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *candidate_connection)
        .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *candidate_connection)
        .await?;
    sqlx::query(&format!("DROP ROLE {bootstrap_candidate}"))
        .execute(&mut *candidate_connection)
        .await?;
    drop(candidate_connection);

    // Exercise the intended deployment order, including the first creation of
    // sqlx history and the application schema under the fixed NOLOGIN owner.
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&owner_pool)
        .await?;
    let bootstrap_poison_schema = format!(
        "apolysis_test_bootstrap_path_poison_{}",
        candidate_suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    sqlx::query(&format!("CREATE SCHEMA {bootstrap_poison_schema}"))
        .execute(&owner_pool)
        .await?;
    sqlx::query(&format!(
        "CREATE TABLE {bootstrap_poison_schema}.invocations(called boolean NOT NULL DEFAULT true)"
    ))
    .execute(&owner_pool)
    .await?;
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {bootstrap_poison_schema}.current_database() RETURNS name \
         LANGUAGE plpgsql AS $function$ \
         BEGIN \
             INSERT INTO {bootstrap_poison_schema}.invocations DEFAULT VALUES; \
             RETURN pg_catalog.current_database(); \
         END \
         $function$"
    ))
    .execute(&owner_pool)
    .await?;
    let mut bootstrap_path_connection = owner_pool.acquire().await?;
    sqlx::query(&format!(
        "SET search_path = {bootstrap_poison_schema}, pg_catalog"
    ))
    .execute(&mut *bootstrap_path_connection)
    .await?;
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *bootstrap_path_connection)
        .await?;
    sqlx::query("RESET search_path")
        .execute(&mut *bootstrap_path_connection)
        .await?;
    let bootstrap_poison_invocations: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {bootstrap_poison_schema}.invocations"
    ))
    .fetch_one(&mut *bootstrap_path_connection)
    .await?;
    assert_eq!(bootstrap_poison_invocations, 0);
    sqlx::query(&format!("DROP SCHEMA {bootstrap_poison_schema} CASCADE"))
        .execute(&mut *bootstrap_path_connection)
        .await?;
    drop(bootstrap_path_connection);

    sqlx::query("COMMENT ON ROLE apolysis_gateway_control IS 'foreign-role-collision'")
        .execute(&owner_pool)
        .await?;
    let mut collision_connection = owner_pool.acquire().await?;
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *collision_connection)
        .await
        .expect_err("an unmarked cluster-global role collision must fail closed");
    sqlx::query("ROLLBACK")
        .execute(&mut *collision_connection)
        .await?;
    sqlx::raw_sql(
        "DO $restore$ BEGIN \
           EXECUTE format(\
             'COMMENT ON ROLE apolysis_gateway_control IS %L', \
             format(\
               'apolysis-managed-role:v1:database=%s:role=apolysis_gateway_control', \
               current_database()\
             )\
           ); \
         END $restore$;",
    )
    .execute(&mut *collision_connection)
    .await?;
    drop(collision_connection);
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&owner_pool)
        .await?;
    AuthorityStore::migrate(&database_url).await?;
    sqlx::raw_sql(PRIVILEGES_SQL).execute(&owner_pool).await?;
    // Both artifacts are deliberately repeatable for deployment convergence.
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&owner_pool)
        .await?;
    sqlx::raw_sql(PRIVILEGES_SQL).execute(&owner_pool).await?;
    // Future migrations must retain access to history after privilege sealing.
    AuthorityStore::migrate(&database_url).await?;

    // ADMIN OPTION is authority to redistribute a fixed capability, even when
    // the original login otherwise has exactly one safe served-role
    // membership. Prove the delegation works before asking bootstrap to audit
    // the poisoned membership.
    let mut delegation_suffix = [0_u8; 8];
    getrandom::fill(&mut delegation_suffix)?;
    let delegation_suffix = delegation_suffix
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let delegating_login = format!("apolysis_test_delegating_served_{delegation_suffix}");
    let delegated_login = format!("apolysis_test_delegated_served_{delegation_suffix}");
    let mut delegation_connection = owner_pool.acquire().await?;
    for login in [&delegating_login, &delegated_login] {
        sqlx::query(&format!(
            "CREATE ROLE {login} WITH LOGIN NOSUPERUSER INHERIT \
             NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        ))
        .execute(&mut *delegation_connection)
        .await?;
    }
    sqlx::query(&format!(
        "GRANT apolysis_gateway_runtime TO {delegating_login} WITH ADMIN OPTION"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {delegating_login}"))
        .execute(&mut *delegation_connection)
        .await?;
    sqlx::query(&format!(
        "GRANT apolysis_gateway_runtime TO {delegated_login}"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *delegation_connection)
        .await?;
    let delegated_membership: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership \
           JOIN pg_catalog.pg_roles AS granted ON granted.oid=membership.roleid \
           JOIN pg_catalog.pg_roles AS member ON member.oid=membership.member \
           WHERE granted.rolname='apolysis_gateway_runtime' AND member.rolname=$1\
         )",
    )
    .bind(&delegated_login)
    .fetch_one(&mut *delegation_connection)
    .await?;
    assert!(delegated_membership);
    let delegation_error = sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *delegation_connection)
        .await
        .expect_err("served login with ADMIN OPTION must fail bootstrap");
    let delegation_database_error = delegation_error
        .as_database_error()
        .expect("delegation rejection must be a bounded database error");
    assert_eq!(delegation_database_error.code().as_deref(), Some("P0001"));
    assert!(
        delegation_database_error
            .message()
            .contains("can delegate Apolysis capability memberships"),
        "{delegation_error}"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *delegation_connection)
        .await?;
    sqlx::query(&format!("SET ROLE {delegating_login}"))
        .execute(&mut *delegation_connection)
        .await?;
    sqlx::query(&format!(
        "REVOKE apolysis_gateway_runtime FROM {delegated_login}"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *delegation_connection)
        .await?;
    sqlx::query(&format!(
        "REVOKE ADMIN OPTION FOR apolysis_gateway_runtime FROM {delegating_login}"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    sqlx::query(&format!(
        "REVOKE apolysis_gateway_runtime FROM {delegating_login}"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    sqlx::query(&format!(
        "GRANT apolysis_schema_owner TO {delegating_login} WITH ADMIN OPTION"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    let owner_delegation_error = sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *delegation_connection)
        .await
        .expect_err("schema-owner login with ADMIN OPTION must fail bootstrap");
    let owner_delegation_database_error = owner_delegation_error
        .as_database_error()
        .expect("schema-owner delegation rejection must be a bounded database error");
    assert_eq!(
        owner_delegation_database_error.code().as_deref(),
        Some("P0001")
    );
    assert!(
        owner_delegation_database_error
            .message()
            .contains("can delegate Apolysis capability memberships"),
        "{owner_delegation_error}"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *delegation_connection)
        .await?;
    sqlx::query(&format!(
        "REVOKE ADMIN OPTION FOR apolysis_schema_owner FROM {delegating_login}"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    sqlx::query(&format!(
        "REVOKE apolysis_schema_owner FROM {delegating_login}"
    ))
    .execute(&mut *delegation_connection)
    .await?;
    for login in [&delegated_login, &delegating_login] {
        sqlx::query(&format!("DROP ROLE {login}"))
            .execute(&mut *delegation_connection)
            .await?;
    }
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *delegation_connection)
        .await?;
    drop(delegation_connection);

    // One inherited built-in role is enough to bypass the table allowlist,
    // while one direct ACL survives all capability-role revokes. Bootstrap
    // must reject both authorities instead of accepting a superficially
    // exclusive application-role membership.
    let mut unsafe_suffix = [0_u8; 8];
    getrandom::fill(&mut unsafe_suffix)?;
    let unsafe_suffix = unsafe_suffix
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let unsafe_login = format!("apolysis_test_unsafe_served_{unsafe_suffix}");
    let mut unsafe_password_bytes = [0_u8; 24];
    getrandom::fill(&mut unsafe_password_bytes)?;
    let unsafe_password = Zeroizing::new(format!(
        "ApolysisRole_{}",
        unsafe_password_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let mut unsafe_connection = owner_pool.acquire().await?;
    let create_unsafe_login_sql: String = sqlx::query_scalar(
        "SELECT pg_catalog.format(\
           'CREATE ROLE %I WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE \
            NOREPLICATION NOBYPASSRLS PASSWORD %L',\
           $1, $2\
         )",
    )
    .bind(&unsafe_login)
    .bind(unsafe_password.as_str())
    .fetch_one(&mut *unsafe_connection)
    .await?;
    sqlx::raw_sql(&create_unsafe_login_sql)
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!(
        "GRANT apolysis_gateway_runtime, pg_read_all_data TO {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(
        "SELECT credential_digest \
         FROM apolysis_gateway.evidence_object_deletion_credentials LIMIT 1",
    )
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    let external_membership_error = sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *unsafe_connection)
        .await
        .expect_err("served login with pg_read_all_data must fail bootstrap");
    let external_membership_database_error = external_membership_error
        .as_database_error()
        .expect("external-membership rejection must be a bounded database error");
    assert_eq!(
        external_membership_database_error.code().as_deref(),
        Some("P0001")
    );
    assert!(
        external_membership_database_error
            .message()
            .contains("has external role memberships"),
        "{external_membership_error}"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("REVOKE pg_read_all_data FROM {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;

    sqlx::query(&format!(
        "GRANT SELECT ON apolysis_gateway.evidence_object_deletion_credentials \
         TO {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(
        "SELECT credential_digest \
         FROM apolysis_gateway.evidence_object_deletion_credentials LIMIT 1",
    )
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    let direct_acl_error = sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(&mut *unsafe_connection)
        .await
        .expect_err("served login with a direct verifier ACL must fail bootstrap");
    let direct_acl_database_error = direct_acl_error
        .as_database_error()
        .expect("direct-ACL rejection must be a bounded database error");
    assert_eq!(direct_acl_database_error.code().as_deref(), Some("P0001"));
    assert!(
        direct_acl_database_error
            .message()
            .contains("has direct database/object authority"),
        "{direct_acl_error}"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!(
        "REVOKE SELECT ON apolysis_gateway.evidence_object_deletion_credentials \
         FROM {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;

    // Direct authority outside the two application schemas is still direct
    // authority. Prove it is usable before requiring the cluster-wide audit to
    // reject it.
    // This deliberately matches SQL LIKE 'pg_temp_%' even though it is not a
    // PostgreSQL temporary schema. The audit must recognize only PostgreSQL's
    // exact numeric pg_temp_N / pg_toast_temp_N catalog names.
    let private_schema = format!("pgxtempa{unsafe_suffix}");
    sqlx::query(&format!("CREATE SCHEMA {private_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!(
        "CREATE TABLE {private_schema}.authority_probe(value bigint NOT NULL)"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!(
        "INSERT INTO {private_schema}.authority_probe(value) VALUES (1)"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA {private_schema} TO {unsafe_login}; \
         GRANT SELECT ON {private_schema}.authority_probe TO {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    let private_value: i64 = sqlx::query_scalar(&format!(
        "SELECT value FROM {private_schema}.authority_probe"
    ))
    .fetch_one(&mut *unsafe_connection)
    .await?;
    assert_eq!(private_value, 1);
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has direct database/object authority",
    )
    .await?;
    sqlx::raw_sql(&format!(
        "REVOKE SELECT ON {private_schema}.authority_probe FROM {unsafe_login}; \
         REVOKE USAGE ON SCHEMA {private_schema} FROM {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    // A capability role is itself a reviewed grant surface. Authority added to
    // it outside the application schema must not be inherited silently.
    sqlx::raw_sql(&format!(
        "GRANT USAGE ON SCHEMA {private_schema} TO apolysis_gateway_runtime; \
         GRANT SELECT ON {private_schema}.authority_probe TO apolysis_gateway_runtime"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    let inherited_private_value: i64 = sqlx::query_scalar(&format!(
        "SELECT value FROM {private_schema}.authority_probe"
    ))
    .fetch_one(&mut *unsafe_connection)
    .await?;
    assert_eq!(inherited_private_value, 1);
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "capability role apolysis_gateway_runtime has unexpected database/object authority",
    )
    .await?;
    sqlx::raw_sql(&format!(
        "REVOKE SELECT ON {private_schema}.authority_probe FROM apolysis_gateway_runtime; \
         REVOKE USAGE ON SCHEMA {private_schema} FROM apolysis_gateway_runtime"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    // Explicit capability ACLs in the application schema are reviewed by the
    // grant artifact, but capability-targeted defaults are never reviewed: a
    // later owner migration would silently materialize them on every new table.
    let capability_default_table = format!("capability_default_probe_{unsafe_suffix}");
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner \
         IN SCHEMA apolysis_gateway GRANT SELECT ON TABLES \
         TO apolysis_gateway_runtime",
    )
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query("SET ROLE apolysis_schema_owner")
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!(
        "CREATE TABLE apolysis_gateway.{capability_default_table}(value bigint NOT NULL)"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!(
        "INSERT INTO apolysis_gateway.{capability_default_table}(value) VALUES (1)"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    let capability_default_value: i64 = sqlx::query_scalar(&format!(
        "SELECT value FROM apolysis_gateway.{capability_default_table}"
    ))
    .fetch_one(&mut *unsafe_connection)
    .await?;
    assert_eq!(capability_default_value, 1);
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "capability role apolysis_gateway_runtime has unexpected database/object authority",
    )
    .await?;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner \
         IN SCHEMA apolysis_gateway REVOKE SELECT ON TABLES \
         FROM apolysis_gateway_runtime",
    )
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!(
        "DROP TABLE apolysis_gateway.{capability_default_table}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner \
         IN SCHEMA {private_schema} GRANT SELECT ON TABLES TO {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    let direct_default_acl: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
           SELECT 1 FROM pg_catalog.pg_default_acl AS defaults \
           JOIN pg_catalog.pg_roles AS owner ON owner.oid=defaults.defaclrole \
           JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=defaults.defaclnamespace \
           CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS acl \
           JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee \
           WHERE owner.rolname='apolysis_schema_owner' AND namespace.nspname=$1 \
             AND grantee.rolname=$2 AND acl.privilege_type='SELECT'\
         )",
    )
    .bind(&private_schema)
    .bind(&unsafe_login)
    .fetch_one(&mut *unsafe_connection)
    .await?;
    assert!(direct_default_acl);
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has direct database/object authority",
    )
    .await?;
    sqlx::query(&format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner \
         IN SCHEMA {private_schema} REVOKE SELECT ON TABLES FROM {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    sqlx::query(&format!(
        "ALTER SCHEMA {private_schema} OWNER TO {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has direct database/object authority",
    )
    .await?;
    sqlx::query(&format!(
        "ALTER SCHEMA {private_schema} OWNER TO apolysis_schema_owner"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    sqlx::query(&format!(
        "ALTER SCHEMA {private_schema} OWNER TO apolysis_gateway_runtime"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!(
        "CREATE TABLE {private_schema}.capability_owner_probe(value bigint)"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!(
        "DROP TABLE {private_schema}.capability_owner_probe"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "capability role apolysis_gateway_runtime has unexpected database/object authority",
    )
    .await?;
    sqlx::query(&format!(
        "ALTER SCHEMA {private_schema} OWNER TO apolysis_schema_owner"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    sqlx::query(&format!("DROP SCHEMA {private_schema} CASCADE"))
        .execute(&mut *unsafe_connection)
        .await?;

    // PostgreSQL permits SET authority for a superuser-only parameter to be
    // delegated directly, through the capability role, or through PUBLIC. All
    // three paths let this served writer disable origin triggers.
    for grantee in [unsafe_login.as_str(), "apolysis_gateway_runtime", "PUBLIC"] {
        sqlx::query(&format!(
            "GRANT SET ON PARAMETER session_replication_role TO {grantee}"
        ))
        .execute(&mut *unsafe_connection)
        .await?;
        assert_served_login_can_select_replica_mode(&mut unsafe_connection, &unsafe_login).await?;
        assert_bootstrap_rejected(
            &mut unsafe_connection,
            "has unsafe session_replication_role parameter authority",
        )
        .await?;
        sqlx::query(&format!(
            "REVOKE SET ON PARAMETER session_replication_role FROM {grantee}"
        ))
        .execute(&mut *unsafe_connection)
        .await?;
        assert_bootstrap_converges(&mut unsafe_connection).await?;
    }

    // Persistent role/database settings are applied at login without a served
    // process issuing SET, so audit the configuration source as well as ACLs.
    sqlx::query(&format!(
        "ALTER ROLE {unsafe_login} SET session_replication_role='replica'"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    let role_setting_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
           SELECT 1 FROM pg_catalog.pg_db_role_setting AS setting \
           JOIN pg_catalog.pg_roles AS role ON role.oid=setting.setrole \
           CROSS JOIN LATERAL unnest(setting.setconfig) AS configuration(value) \
           WHERE role.rolname=$1 AND setting.setdatabase=0 \
             AND configuration.value='session_replication_role=replica'\
         )",
    )
    .bind(&unsafe_login)
    .fetch_one(&mut *unsafe_connection)
    .await?;
    assert!(role_setting_present);
    assert_fresh_login_starts_in_replica_mode(
        &database_url,
        &unsafe_login,
        unsafe_password.as_str(),
    )
    .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has unsafe persistent session_replication_role setting",
    )
    .await?;
    sqlx::query(&format!(
        "ALTER ROLE {unsafe_login} RESET session_replication_role"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    let database_identifier: String =
        sqlx::query_scalar("SELECT pg_catalog.format('%I', current_database())")
            .fetch_one(&mut *unsafe_connection)
            .await?;
    sqlx::query(&format!(
        "ALTER DATABASE {database_identifier} SET session_replication_role='replica'"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_fresh_login_starts_in_replica_mode(
        &database_url,
        &unsafe_login,
        unsafe_password.as_str(),
    )
    .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has unsafe persistent session_replication_role setting",
    )
    .await?;
    sqlx::query(&format!(
        "ALTER DATABASE {database_identifier} RESET session_replication_role"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    // CREATE inherited through an application capability or PUBLIC is still
    // effective served authority. Exercise every reviewed DDL surface before
    // requiring bootstrap to reject the poison instead of silently revoking it.
    let capability_app_table = format!("capability_create_probe_{unsafe_suffix}");
    sqlx::query("GRANT CREATE ON SCHEMA apolysis_gateway TO apolysis_gateway_runtime")
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!(
        "CREATE TABLE apolysis_gateway.{capability_app_table}(value bigint)"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!(
        "DROP TABLE apolysis_gateway.{capability_app_table}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has unsafe effective database/schema CREATE authority",
    )
    .await?;
    sqlx::query("REVOKE CREATE ON SCHEMA apolysis_gateway FROM apolysis_gateway_runtime")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    let public_database_schema = format!("apolysis_test_public_database_{unsafe_suffix}");
    sqlx::query(&format!(
        "GRANT CREATE ON DATABASE {database_identifier} TO PUBLIC"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("CREATE SCHEMA {public_database_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("DROP SCHEMA {public_database_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "has unsafe effective database/schema CREATE authority",
    )
    .await?;
    sqlx::query(&format!(
        "REVOKE CREATE ON DATABASE {database_identifier} FROM PUBLIC"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    for schema_name in ["public", "apolysis_gateway"] {
        let public_create_table = format!("public_create_probe_{unsafe_suffix}");
        sqlx::query(&format!(
            "GRANT USAGE, CREATE ON SCHEMA {schema_name} TO PUBLIC"
        ))
        .execute(&mut *unsafe_connection)
        .await?;
        sqlx::query(&format!("SET ROLE {unsafe_login}"))
            .execute(&mut *unsafe_connection)
            .await?;
        sqlx::query(&format!(
            "CREATE TABLE {schema_name}.{public_create_table}(value bigint)"
        ))
        .execute(&mut *unsafe_connection)
        .await?;
        sqlx::query(&format!("DROP TABLE {schema_name}.{public_create_table}"))
            .execute(&mut *unsafe_connection)
            .await?;
        sqlx::query("RESET ROLE")
            .execute(&mut *unsafe_connection)
            .await?;
        assert_bootstrap_rejected(
            &mut unsafe_connection,
            "has unsafe effective database/schema CREATE authority",
        )
        .await?;
        sqlx::query(&format!(
            "REVOKE USAGE, CREATE ON SCHEMA {schema_name} FROM PUBLIC"
        ))
        .execute(&mut *unsafe_connection)
        .await?;
        assert_bootstrap_converges(&mut unsafe_connection).await?;
    }

    // Database CREATE and ownership attached to the capability are inherited
    // even though the served login itself has no direct database ACL.
    let probe_schema = format!("apolysis_test_database_create_{unsafe_suffix}");
    sqlx::query(&format!(
        "GRANT CREATE ON DATABASE {database_identifier} TO apolysis_gateway_runtime"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("CREATE SCHEMA {probe_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("DROP SCHEMA {probe_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "capability role apolysis_gateway_runtime has unexpected database/object authority",
    )
    .await?;
    sqlx::query(&format!(
        "REVOKE CREATE ON DATABASE {database_identifier} FROM apolysis_gateway_runtime"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    let database_owner_identifier: String = sqlx::query_scalar(
        "SELECT pg_catalog.format('%I', pg_catalog.pg_get_userbyid(database.datdba)) \
         FROM pg_catalog.pg_database AS database WHERE database.datname=current_database()",
    )
    .fetch_one(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!(
        "ALTER DATABASE {database_identifier} OWNER TO apolysis_gateway_runtime"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    let owner_probe_schema = format!("apolysis_test_database_owner_{unsafe_suffix}");
    sqlx::query(&format!("SET ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("CREATE SCHEMA {owner_probe_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query(&format!("DROP SCHEMA {owner_probe_schema}"))
        .execute(&mut *unsafe_connection)
        .await?;
    sqlx::query("RESET ROLE")
        .execute(&mut *unsafe_connection)
        .await?;
    assert_bootstrap_rejected(
        &mut unsafe_connection,
        "capability role apolysis_gateway_runtime has unexpected database/object authority",
    )
    .await?;
    sqlx::query(&format!(
        "ALTER DATABASE {database_identifier} OWNER TO {database_owner_identifier}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    assert_bootstrap_converges(&mut unsafe_connection).await?;

    sqlx::query(&format!(
        "REVOKE apolysis_gateway_runtime FROM {unsafe_login}"
    ))
    .execute(&mut *unsafe_connection)
    .await?;
    sqlx::query(&format!("DROP ROLE {unsafe_login}"))
        .execute(&mut *unsafe_connection)
        .await?;
    drop(unsafe_connection);

    let unsafe_role_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_roles \
         WHERE rolname=ANY($1::text[]) \
           AND (rolcanlogin OR rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole \
                OR rolreplication OR rolbypassrls)",
    )
    .bind(CAPABILITY_ROLES)
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(unsafe_role_count, 0);

    let wrong_relation_owner_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_class AS class \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=class.relnamespace \
         WHERE namespace.nspname='apolysis_gateway' \
           AND class.relkind IN ('r','p','v','m','S','f') \
           AND pg_catalog.pg_get_userbyid(class.relowner)<>'apolysis_schema_owner'",
    )
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(wrong_relation_owner_count, 0);
    let wrong_routine_owner_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_proc AS procedure \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace \
         WHERE namespace.nspname='apolysis_gateway' \
           AND pg_catalog.pg_get_userbyid(procedure.proowner)<>'apolysis_schema_owner'",
    )
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(wrong_routine_owner_count, 0);
    let migration_owner: String = sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_userbyid(class.relowner) \
         FROM pg_catalog.pg_class AS class \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=class.relnamespace \
         WHERE namespace.nspname='public' AND class.relname='_sqlx_migrations'",
    )
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(migration_owner, "apolysis_schema_owner");

    let role_pools = ApplicationRolePools::provision(&owner_pool, &database_url).await?;
    let expected_logins = role_pools.login_roles().to_vec();
    for (pool, expected_login) in [
        (&role_pools.gateway_runtime, &expected_logins[0]),
        (&role_pools.gateway_control, &expected_logins[1]),
        (&role_pools.evidence_runtime, &expected_logins[2]),
        (&role_pools.evidence_control, &expected_logins[3]),
        (&role_pools.deletion_ack, &expected_logins[4]),
    ] {
        let identity: (String, String, bool, i64) = sqlx::query_as(
            "SELECT role.rolname, session_user, role.rolsuper, \
                    (SELECT count(*) \
                     FROM pg_catalog.pg_auth_members AS membership \
                     JOIN pg_catalog.pg_roles AS granted ON granted.oid=membership.roleid \
                     WHERE membership.member=role.oid \
                       AND granted.rolname=ANY($1::text[])) \
             FROM pg_catalog.pg_roles AS role WHERE role.rolname=current_user",
        )
        .bind(CAPABILITY_ROLES)
        .fetch_one(pool)
        .await?;
        assert_eq!(identity.0, *expected_login);
        assert_eq!(identity.1, *expected_login);
        assert!(!identity.2);
        assert_eq!(identity.3, 1);
    }

    let reaper_function_public_boundary: (bool, bool) = sqlx::query_as(
        "SELECT to_regprocedure($1) IS NOT NULL, \
                EXISTS (\
                  SELECT 1 \
                  FROM pg_catalog.pg_proc AS procedure \
                  CROSS JOIN LATERAL pg_catalog.aclexplode(\
                    coalesce(\
                      procedure.proacl, \
                      pg_catalog.acldefault('f', procedure.proowner)\
                    )\
                  ) AS privilege \
                  WHERE procedure.oid=to_regprocedure($1) \
                    AND privilege.grantee=0 \
                    AND privilege.privilege_type='EXECUTE'\
                )",
    )
    .bind(REAPER_ORGANIZATION_LOCK_FUNCTION)
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(reaper_function_public_boundary, (true, false));

    for (pool, role_label) in [
        (
            &role_pools.gateway_runtime,
            "gateway runtime must not execute the reaper lock helper",
        ),
        (
            &role_pools.gateway_control,
            "gateway control must not execute the reaper lock helper",
        ),
        (
            &role_pools.evidence_control,
            "evidence control must not execute the reaper lock helper",
        ),
        (
            &role_pools.deletion_ack,
            "deletion acknowledgement must not execute the reaper lock helper",
        ),
    ] {
        let may_execute: bool =
            sqlx::query_scalar("SELECT has_function_privilege(current_user,$1,'EXECUTE')")
                .bind(REAPER_ORGANIZATION_LOCK_FUNCTION)
                .fetch_one(pool)
                .await?;
        assert!(!may_execute, "{role_label}");
        assert_reaper_organization_lock_execution_denied(pool, role_label).await?;
    }
    let evidence_runtime_may_execute: bool =
        sqlx::query_scalar("SELECT has_function_privilege(current_user,$1,'EXECUTE')")
            .bind(REAPER_ORGANIZATION_LOCK_FUNCTION)
            .fetch_one(&role_pools.evidence_runtime)
            .await?;
    assert!(evidence_runtime_may_execute);

    let runtime_object_update_surface: (bool, Vec<String>) = sqlx::query_as(
        "SELECT \
           has_table_privilege(\
             current_user, 'apolysis_gateway.evidence_objects', 'UPDATE'\
           ), \
           ARRAY(\
             SELECT attribute.attname::text \
             FROM pg_catalog.pg_attribute AS attribute \
             WHERE attribute.attrelid='apolysis_gateway.evidence_objects'::regclass \
               AND attribute.attnum>0 AND NOT attribute.attisdropped \
               AND has_column_privilege(\
                 current_user, attribute.attrelid, attribute.attname, 'UPDATE'\
               ) \
             ORDER BY attribute.attname\
           )",
    )
    .fetch_one(&role_pools.evidence_runtime)
    .await?;
    assert!(!runtime_object_update_surface.0);
    assert_eq!(
        runtime_object_update_surface.1,
        [
            "access_denied_at_unix_ms",
            "available_at_unix_ms",
            "delete_reason",
            "delete_request_revision",
            "delete_requested_at_unix_ms",
            "lifecycle_revision",
            "object_state",
            "purged_at_unix_ms",
            "reap_claim_until_unix_ms",
            "reap_claimed_at_unix_ms",
            "reap_claimed_by",
            "storage_purged_at_unix_ms",
            "upload_fence_started_at_unix_ms",
            "upload_fence_token",
            "upload_fence_until_unix_ms",
        ]
        .map(str::to_string)
    );

    let control_object_update_surface: (bool, Vec<String>) = sqlx::query_as(
        "SELECT \
           has_table_privilege(\
             current_user, 'apolysis_gateway.evidence_objects', 'UPDATE'\
           ), \
           ARRAY(\
             SELECT attribute.attname::text \
             FROM pg_catalog.pg_attribute AS attribute \
             WHERE attribute.attrelid='apolysis_gateway.evidence_objects'::regclass \
               AND attribute.attnum>0 AND NOT attribute.attisdropped \
               AND has_column_privilege(\
                 current_user, attribute.attrelid, attribute.attname, 'UPDATE'\
               ) \
             ORDER BY attribute.attname\
           )",
    )
    .fetch_one(&role_pools.evidence_control)
    .await?;
    assert!(!control_object_update_surface.0);
    assert_eq!(
        control_object_update_surface.1,
        ["expires_at_unix_ms", "lifecycle_revision"].map(str::to_string)
    );

    seed_retention_control_fixture(&owner_pool).await?;
    let runtime_locked_organizations: Vec<String> = sqlx::query_scalar(
        "SELECT apolysis_gateway.lock_evidence_object_reaper_organizations($1,$2)",
    )
    .bind(9_007_199_254_740_991_i64)
    .bind(1_i32)
    .fetch_all(&role_pools.evidence_runtime)
    .await?;
    assert_eq!(
        runtime_locked_organizations,
        ["org_privilege_retention".to_string()]
    );
    let retention_before: (i64, i64) = sqlx::query_as(
        "SELECT expires_at_unix_ms, lifecycle_revision \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id='org_privilege_retention' \
           AND object_id='object_privilege_retention'",
    )
    .fetch_one(&owner_pool)
    .await?;
    let extended_expiry = retention_before
        .0
        .checked_add(10_000)
        .ok_or("retention fixture expiry overflow")?;
    let runtime_retention_extension = sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET expires_at_unix_ms=$3, lifecycle_revision=lifecycle_revision+1 \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind("org_privilege_retention")
    .bind("object_privilege_retention")
    .bind(extended_expiry)
    .execute(&role_pools.evidence_runtime)
    .await
    .expect_err("evidence runtime must not extend object retention directly");
    assert_permission_denied(&runtime_retention_extension);
    let control_runtime_column_update = sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET object_state=object_state \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind("org_privilege_retention")
    .bind("object_privilege_retention")
    .execute(&role_pools.evidence_control)
    .await
    .expect_err("evidence control must not update runtime lifecycle columns");
    assert_permission_denied(&control_runtime_column_update);

    let lifecycle = EvidenceObjectLifecycle::new(
        role_pools.evidence_runtime.clone(),
        role_pools.evidence_control.clone(),
        role_pools.deletion_ack.clone(),
        ObjectLifecycleConfig::new(
            "http://127.0.0.1:9",
            "privilege-test-1",
            "privilege-gate",
            "backend_privilege_retention",
            "unused-access-key",
            "unused-secret-key",
            "key_ref_privilege_retention",
            [41_u8; 32],
            Duration::from_millis(100),
            Duration::from_millis(100),
        )?,
    );
    lifecycle
        .extend_retention(
            &OperatorActor::new("operator_privilege_retention")?,
            &OrganizationId::try_from("org_privilege_retention")?,
            "object_privilege_retention",
            u64::try_from(extended_expiry)?,
        )
        .await?;
    let retention_after: (i64, i64, bool, bool) = sqlx::query_as(
        "SELECT object.expires_at_unix_ms, object.lifecycle_revision, \
                EXISTS (\
                  SELECT 1 FROM apolysis_gateway.evidence_object_outbox AS outbox \
                  WHERE outbox.organization_id=object.organization_id \
                    AND outbox.object_id=object.object_id \
                    AND outbox.lifecycle_revision=object.lifecycle_revision \
                    AND outbox.event_kind='retention_extended'\
                ), \
                EXISTS (\
                  SELECT 1 FROM apolysis_gateway.evidence_object_audit AS audit \
                  WHERE audit.organization_id=object.organization_id \
                    AND audit.object_id=object.object_id \
                    AND audit.lifecycle_revision=object.lifecycle_revision \
                    AND audit.action='extend_retention'\
                ) \
         FROM apolysis_gateway.evidence_objects AS object \
         WHERE object.organization_id='org_privilege_retention' \
           AND object.object_id='object_privilege_retention'",
    )
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(
        retention_after,
        (extended_expiry, retention_before.1 + 1, true, true)
    );

    let ack_boundary: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
           has_schema_privilege(current_user,'apolysis_gateway','USAGE'), \
           has_schema_privilege(current_user,'apolysis_gateway','CREATE'), \
           has_function_privilege( \
             current_user, \
             'apolysis_gateway.acknowledge_evidence_object_deletion(text,text,text,bigint,text,text,text,bigint,bytea)', \
             'EXECUTE' \
           ), \
           has_table_privilege( \
             current_user, \
             'apolysis_gateway.evidence_object_deletion_credentials', \
             'SELECT' \
           ), \
           has_table_privilege( \
             current_user, \
             'apolysis_gateway.evidence_object_deletion_acknowledgements', \
             'INSERT,UPDATE,DELETE' \
           )",
    )
    .fetch_one(&role_pools.deletion_ack)
    .await?;
    assert_eq!(ack_boundary, (true, false, true, false, false));

    let application_table_privileges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_class AS class \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=class.relnamespace \
         WHERE (namespace.nspname='apolysis_gateway' \
                OR (namespace.nspname='public' AND class.relname='_sqlx_migrations')) \
           AND class.relkind IN ('r','p','v','m','S','f') \
           AND has_table_privilege( \
             'apolysis_deletion_ack', class.oid, \
             'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER' \
           )",
    )
    .fetch_one(&owner_pool)
    .await?;
    assert_eq!(application_table_privileges, 0);

    let credential_read = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT credential_digest \
         FROM apolysis_gateway.evidence_object_deletion_credentials LIMIT 1",
    )
    .fetch_optional(&role_pools.deletion_ack)
    .await
    .expect_err("acknowledgement login must not read stored credential verifiers");
    assert_permission_denied(&credential_read);

    let direct_ack = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_acknowledgements (\
           organization_id, object_id, component_id, lifecycle_revision, principal_kind, \
           principal_id, credential_id, credential_epoch, presented_credential_digest, \
           acknowledged_at_unix_ms\
         ) VALUES ('org_denied','object_denied','component_denied',1,'workload',\
                   'principal_denied','credential_denied',1,$1,1)",
    )
    .bind(vec![0_u8; 32])
    .execute(&role_pools.deletion_ack)
    .await
    .expect_err("acknowledgement login must not write the acknowledgement table directly");
    assert_permission_denied(&direct_ack);

    let migration_history_read = sqlx::query("SELECT version FROM public._sqlx_migrations")
        .execute(&role_pools.deletion_ack)
        .await
        .expect_err("served acknowledgement login must not read migration history");
    assert_permission_denied(&migration_history_read);
    let runtime_ddl =
        sqlx::query("CREATE TABLE public.apolysis_forbidden_runtime_table(id bigint)")
            .execute(&role_pools.gateway_runtime)
            .await
            .expect_err("served runtime login must not create migration objects");
    assert_permission_denied(&runtime_ddl);
    let runtime_schema = sqlx::query("CREATE SCHEMA apolysis_forbidden_runtime_schema")
        .execute(&role_pools.gateway_runtime)
        .await
        .expect_err("served runtime login must not create application schemas");
    assert_permission_denied(&runtime_schema);
    let owner_escalation = sqlx::query("SET ROLE apolysis_schema_owner")
        .execute(&role_pools.gateway_runtime)
        .await
        .expect_err("served runtime must not assume the schema-owner role");
    assert_permission_denied(&owner_escalation);
    let trigger_bypass =
        sqlx::query("ALTER TABLE apolysis_gateway.evidence_objects DISABLE TRIGGER USER")
            .execute(&role_pools.gateway_runtime)
            .await
            .expect_err("served runtime must not disable lifecycle guards");
    assert_permission_denied(&trigger_bypass);

    sqlx::query("SELECT organization_id FROM apolysis_gateway.organizations LIMIT 1")
        .execute(&role_pools.gateway_control)
        .await?;
    let gateway_control_credential_read = sqlx::query(
        "SELECT credential_digest \
         FROM apolysis_gateway.evidence_object_deletion_credentials LIMIT 1",
    )
    .execute(&role_pools.gateway_control)
    .await
    .expect_err("gateway control must not read deletion credential verifiers");
    assert_permission_denied(&gateway_control_credential_read);
    let gateway_control_ddl =
        sqlx::query("CREATE TABLE public.apolysis_forbidden_control_table(id bigint)")
            .execute(&role_pools.gateway_control)
            .await
            .expect_err("gateway control must not create migration objects");
    assert_permission_denied(&gateway_control_ddl);

    let forged_ack = sqlx::query_scalar::<_, bool>(
        "SELECT apolysis_gateway.acknowledge_evidence_object_deletion(\
           'org_missing','object_missing','component_missing',1,'workload',\
           'principal_missing','credential_missing',1,$1)",
    )
    .bind(vec![0_u8; 32])
    .fetch_one(&role_pools.deletion_ack)
    .await
    .expect_err("security-definer acknowledgement must reject an unknown credential");
    let forged_ack_error = forged_ack
        .as_database_error()
        .expect("acknowledgement function must return a bounded database error");
    assert_eq!(forged_ack_error.code().as_deref(), Some("23514"));
    assert_eq!(
        forged_ack_error.constraint(),
        Some("evidence_object_deletion_ack_authority_ck")
    );

    let runtime_credential_read = sqlx::query(
        "SELECT credential_digest \
         FROM apolysis_gateway.evidence_object_deletion_credentials LIMIT 1",
    )
    .execute(&role_pools.evidence_runtime)
    .await
    .expect_err("evidence runtime must not read deletion credential verifiers");
    assert_permission_denied(&runtime_credential_read);
    let control_credential_read = sqlx::query(
        "SELECT credential_digest \
         FROM apolysis_gateway.evidence_object_deletion_credentials LIMIT 1",
    )
    .execute(&role_pools.evidence_control)
    .await?;
    assert_eq!(control_credential_read.rows_affected(), 0);
    let control_ack = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_acknowledgements (\
           organization_id, object_id, component_id, lifecycle_revision, principal_kind, \
           principal_id, credential_id, credential_epoch, presented_credential_digest, \
           acknowledged_at_unix_ms\
         ) VALUES ('org_denied','object_denied','component_denied',1,'workload',\
                   'principal_denied','credential_denied',1,$1,1)",
    )
    .bind(vec![0_u8; 32])
    .execute(&role_pools.evidence_control)
    .await
    .expect_err("evidence control must not write acknowledgements directly");
    assert_permission_denied(&control_ack);
    let control_ack_function = sqlx::query_scalar::<_, bool>(
        "SELECT apolysis_gateway.acknowledge_evidence_object_deletion(\
           'org_denied','object_denied','component_denied',1,'workload',\
           'principal_denied','credential_denied',1,$1)",
    )
    .bind(vec![0_u8; 32])
    .fetch_one(&role_pools.evidence_control)
    .await
    .expect_err("evidence control must not execute the acknowledgement function");
    assert_permission_denied(&control_ack_function);

    role_pools.close_and_drop(&owner_pool).await?;
    owner_pool.close().await;
    Ok(())
}

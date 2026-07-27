// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, io, sync::Arc};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    BindRuntimeRequest, ContractErrorCode, EnvironmentKind, FinishRunRequest, GatewayOperation,
    IngestRequest, PrincipalKind, PrincipalRef, PrivacyCapability, SourceCapability, SourceId,
    SourceKind, SourceRegistrationPolicy, TrustProfile,
};
use apolysis_gateway::{
    canonical_request_digest, lease_id_digest, ExecutionEvidenceGateway, GatewayClock,
    GatewayFailure, GatewayIdGenerator,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use sqlx::{postgres::PgPoolOptions, Row};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const LEGACY_GATEWAY_LEDGER: &str = include_str!("../migrations/0001_gateway_ledger.sql");
const LEGACY_CURRENT_AUTHORITY: &str = include_str!("../migrations/0002_current_authority.sql");
const LEGACY_EVIDENCE_OBJECTS: &str =
    include_str!("../migrations/0003_evidence_object_lifecycle.sql");
const TRANSACTION_AUTHORITY_BINDING: &str =
    include_str!("../migrations/0004_transaction_authority_binding.sql");
const LEGACY_LEASE_ID: &str =
    "lease_upgrade_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GATEWAY_NOW_UNIX_MS: u64 = 1_783_891_200_000;
const IJSON_MAX: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy)]
struct FixedClock;

impl GatewayClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        GATEWAY_NOW_UNIX_MS
    }
}

struct NoIds;

impl GatewayIdGenerator for NoIds {
    fn next_id(&self, _kind: &'static str) -> Result<String, String> {
        Err("a rejected legacy lease must not allocate an identifier".to_string())
    }
}

fn legacy_context() -> AuthenticatedSourceContext {
    let principal =
        PrincipalRef::new(PrincipalKind::Workload, "principal_upgrade").expect("principal fixture");
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from("source_upgrade").expect("source fixture"),
        vec![SourceKind::SemanticHook],
        vec![EnvironmentKind::LocalCliOrIde],
        vec![
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ],
        true,
        true,
    )
    .expect("policy fixture")
    .with_run_authorities(vec![AuthorityRef::new(
        AuthorityKind::Service,
        "authority_upgrade",
    )
    .expect("authority fixture")])
    .expect("authority policy fixture")
    .with_run_profiles(
        vec!["privacy_upgrade".to_string()],
        vec!["retention_upgrade".to_string()],
        vec![SourceKind::SemanticHook],
    )
    .expect("run-profile fixture")
    .with_evidence_policy(
        TrustProfile::HarnessObserved,
        vec![SourceCapability::ToolCalls, SourceCapability::Workload],
        vec![PrivacyCapability::StructureOnly],
        vec!["redaction_upgrade".to_string()],
    )
    .expect("evidence-policy fixture");
    AuthenticatedSourceContext::new(
        "org_upgrade".try_into().expect("organization fixture"),
        principal,
        "registration_upgrade",
        AuthenticationSnapshot::new("credential_upgrade", 3, 7, 100, IJSON_MAX)
            .expect("authentication fixture"),
        policy,
    )
    .expect("context fixture")
}

fn sign_request<T>(operation: &str, mut wire: serde_json::Value) -> T
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: T = serde_json::from_value(wire.clone()).expect("request fixture shape");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest(operation, &unsigned).expect("canonical request digest"),
    );
    serde_json::from_value(wire).expect("signed request fixture")
}

fn legacy_bind_request() -> BindRuntimeRequest {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/bind_runtime_request.json"
    )))
    .expect("bind fixture");
    wire["run_id"] = serde_json::json!("run_upgrade");
    wire["lease_id"] = serde_json::json!(LEGACY_LEASE_ID);
    wire["binding"]["asserting_source_id"] = serde_json::json!("source_upgrade");
    wire["binding"]["valid_from_unix_ms"] = serde_json::json!(100);
    wire["binding"]["valid_until_unix_ms"] = serde_json::json!(IJSON_MAX);
    sign_request("bind_runtime", wire)
}

fn legacy_ingest_request() -> IngestRequest {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/ingest_request.json"
    )))
    .expect("ingest fixture");
    wire["run_id"] = serde_json::json!("run_upgrade");
    wire["lease_id"] = serde_json::json!(LEGACY_LEASE_ID);
    for envelope in wire["envelopes"].as_array_mut().expect("envelope fixture") {
        envelope["run_id"] = serde_json::json!("run_upgrade");
        envelope["source_id"] = serde_json::json!("source_upgrade");
        envelope["source_stream_id"] = serde_json::json!("stream_upgrade");
    }
    sign_request("ingest", wire)
}

fn legacy_finish_request() -> FinishRunRequest {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/finish_run_request.json"
    )))
    .expect("finish fixture");
    wire["run_id"] = serde_json::json!("run_upgrade");
    wire["lease_id"] = serde_json::json!(LEGACY_LEASE_ID);
    wire["terminal_positions"] = serde_json::json!([{
        "source_id": "source_upgrade",
        "source_stream_id": "stream_upgrade",
        "final_source_sequence": 3
    }]);
    wire["requested_finalization_deadline_unix_ms"] =
        serde_json::json!(GATEWAY_NOW_UNIX_MS + 600_000);
    sign_request("finish_run", wire)
}

fn assert_legacy_lease_revoked(error: GatewayFailure) {
    assert_eq!(error.code(), ContractErrorCode::LeaseRevoked);
    assert!(
        !error
            .response()
            .expect("safe lease-revocation response")
            .retryable(),
        "legacy-unbound leases must not surface as repository backpressure"
    );
}

async fn test_pool() -> TestResult<sqlx::PgPool> {
    let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "APOLYSIS_TEST_DATABASE_URL is required by the authority migration gate",
        )
    })?;
    Ok(PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?)
}

async fn reset_schema(pool: &sqlx::PgPool) -> TestResult {
    sqlx::raw_sql(
        "DROP SCHEMA IF EXISTS apolysis_gateway CASCADE;
         DROP TABLE IF EXISTS public._sqlx_migrations;",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL migration gate"]
async fn fresh_schema_has_transaction_authority_bindings() -> TestResult {
    let pool = test_pool().await?;
    reset_schema(&pool).await?;

    MIGRATOR.run(&pool).await?;

    let latest_version: i64 =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations")
            .fetch_one(&pool)
            .await?;
    assert_eq!(latest_version, 4);

    let rows = sqlx::query(
        "SELECT table_name, column_name
         FROM information_schema.columns
         WHERE table_schema = 'apolysis_gateway'
           AND (
             (table_name = 'leases'
              AND column_name IN ('credential_id', 'credential_epoch'))
             OR
             (table_name IN ('gateway_operations', 'operation_replays')
              AND column_name IN (
                'credential_id',
                'credential_epoch',
                'registration_policy_revision'
              ))
             OR
             (table_name = 'join_authorizations'
              AND column_name IN (
                'credential_id',
                'credential_epoch',
                'issued_by_credential_id',
                'issued_by_credential_epoch',
                'issued_by_registration_policy_revision'
              ))
           )
         ORDER BY table_name, column_name",
    )
    .fetch_all(&pool)
    .await?;
    let columns = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("table_name")?,
                row.try_get::<String, _>("column_name")?,
            ))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    assert_eq!(
        columns,
        [
            ("gateway_operations", "credential_epoch"),
            ("gateway_operations", "credential_id"),
            ("gateway_operations", "registration_policy_revision"),
            ("join_authorizations", "credential_epoch"),
            ("join_authorizations", "credential_id"),
            ("join_authorizations", "issued_by_credential_epoch"),
            ("join_authorizations", "issued_by_credential_id"),
            (
                "join_authorizations",
                "issued_by_registration_policy_revision"
            ),
            ("leases", "credential_epoch"),
            ("leases", "credential_id"),
            ("operation_replays", "credential_epoch"),
            ("operation_replays", "credential_id"),
            ("operation_replays", "registration_policy_revision"),
        ]
        .map(|(table, column)| (table.to_string(), column.to_string()))
    );

    let helper_exists: bool = sqlx::query_scalar(
        "SELECT to_regprocedure(
            'apolysis_gateway.lock_gateway_current_authority(text,text,text)'
         ) IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(helper_exists);

    let audit_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass(
            'apolysis_gateway.transaction_authority_audit'
         ) IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(audit_exists);

    let public_can_execute_helper: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS procedure
            CROSS JOIN LATERAL pg_catalog.aclexplode(
              coalesce(
                procedure.proacl,
                pg_catalog.acldefault('f', procedure.proowner)
              )
            ) AS privilege
            WHERE procedure.oid = to_regprocedure(
              'apolysis_gateway.lock_gateway_current_authority(text,text,text)'
            )
              AND privilege.grantee = 0
              AND privilege.privilege_type = 'EXECUTE'
         )",
    )
    .fetch_one(&pool)
    .await?;
    assert!(!public_can_execute_helper);

    sqlx::raw_sql(
        "INSERT INTO apolysis_gateway.organizations (
             organization_id, organization_state,
             created_at_unix_ms, updated_at_unix_ms
         ) VALUES ('org_lock', 'active', 100, 100);
         INSERT INTO apolysis_gateway.source_registrations (
             source_registration_id, organization_id, source_id,
             principal_kind, principal_id, registration_state,
             policy_revision, credential_epoch, effective_at_unix_ms,
             expires_at_unix_ms, policy_document,
             created_at_unix_ms, updated_at_unix_ms
         ) VALUES (
             'registration_lock', 'org_lock', 'source_lock', 'workload',
             'principal_lock', 'active', 1, 1, 100, 9007199254740000,
             '{}'::jsonb, 100, 100
         );
         INSERT INTO apolysis_gateway.transport_credentials (
             credential_id, certificate_fingerprint, organization_id,
             source_registration_id, credential_epoch, effective_at_unix_ms,
             expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms
         ) VALUES (
             'credential_lock', decode(repeat('10', 32), 'hex'), 'org_lock',
             'registration_lock', 1, 100, 9007199254740000, 100, 100
         );",
    )
    .execute(&pool)
    .await?;

    let mut authority_transaction = pool.begin().await?;
    let authority_locked: bool =
        sqlx::query_scalar("SELECT apolysis_gateway.lock_gateway_current_authority($1, $2, $3)")
            .bind("org_lock")
            .bind("registration_lock")
            .bind("credential_lock")
            .fetch_one(&mut *authority_transaction)
            .await?;
    assert!(authority_locked);

    let mut rotation_connection = pool.acquire().await?;
    sqlx::query("SET lock_timeout = '100ms'")
        .execute(&mut *rotation_connection)
        .await?;
    let blocked_rotation = sqlx::query(
        "UPDATE apolysis_gateway.source_registrations
         SET updated_at_unix_ms = 101
         WHERE source_registration_id = 'registration_lock'",
    )
    .execute(&mut *rotation_connection)
    .await
    .expect_err("current-authority locks must serialize registration rotation");
    assert_eq!(
        blocked_rotation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55P03")
    );

    authority_transaction.rollback().await?;
    sqlx::query("SET lock_timeout = DEFAULT")
        .execute(&mut *rotation_connection)
        .await?;
    let rotated = sqlx::query(
        "UPDATE apolysis_gateway.source_registrations
         SET updated_at_unix_ms = 101
         WHERE source_registration_id = 'registration_lock'",
    )
    .execute(&mut *rotation_connection)
    .await?;
    assert_eq!(rotated.rows_affected(), 1);
    drop(rotation_connection);

    reset_schema(&pool).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit PostgreSQL migration gate"]
async fn upgrade_fails_legacy_capabilities_closed_and_preserves_tombstones() -> TestResult {
    let pool = test_pool().await?;
    reset_schema(&pool).await?;

    for migration in [
        LEGACY_GATEWAY_LEDGER,
        LEGACY_CURRENT_AUTHORITY,
        LEGACY_EVIDENCE_OBJECTS,
    ] {
        sqlx::raw_sql(migration).execute(&pool).await?;
    }

    let mut legacy_transaction = pool.begin().await?;
    sqlx::raw_sql(
        "INSERT INTO apolysis_gateway.organizations (
             organization_id, organization_state,
             created_at_unix_ms, updated_at_unix_ms
         ) VALUES ('org_upgrade', 'active', 100, 100);
         INSERT INTO apolysis_gateway.source_registrations (
             source_registration_id, organization_id, source_id,
             principal_kind, principal_id, registration_state,
             policy_revision, credential_epoch, effective_at_unix_ms,
             expires_at_unix_ms, policy_document,
             created_at_unix_ms, updated_at_unix_ms
         ) VALUES (
             'registration_upgrade', 'org_upgrade', 'source_upgrade',
             'workload', 'principal_upgrade', 'active', 7, 3, 100,
             9007199254740000, '{}'::jsonb, 100, 100
         );
         INSERT INTO apolysis_gateway.transport_credentials (
             credential_id, certificate_fingerprint, organization_id,
             source_registration_id, credential_epoch, effective_at_unix_ms,
             expires_at_unix_ms, created_at_unix_ms, updated_at_unix_ms
         ) VALUES (
             'credential_upgrade', decode(repeat('11', 32), 'hex'),
             'org_upgrade', 'registration_upgrade', 3, 100,
             9007199254740000, 100, 100
         );
         INSERT INTO apolysis_gateway.organization_sequences (
             organization_id, next_ingest_sequence, updated_at_unix_ms
         ) VALUES ('org_upgrade', 2, 100);
         INSERT INTO apolysis_gateway.runs (
             organization_id, run_id, state, environment, authority_kind,
             authority_id, principal_kind, principal_id, objective_ref,
             privacy_profile_ref, retention_profile_ref,
             initiating_source_registration_id, initiating_principal_kind,
             initiating_principal_id, opened_at_unix_ms,
             state_changed_at_unix_ms
         ) VALUES (
             'org_upgrade', 'run_upgrade', 'active', 'local_cli_or_ide',
             'service', 'authority_upgrade', 'workload', 'principal_upgrade',
             'objective_upgrade', 'privacy_upgrade', 'retention_upgrade',
             'registration_upgrade', 'workload', 'principal_upgrade', 100, 100
         );
         INSERT INTO apolysis_gateway.record_items (
             organization_id, run_id, ingest_sequence, ingested_at_unix_ms,
             fact_kind, fact_json, fact_digest, outbox_ingest_sequence
         ) VALUES (
             'org_upgrade', 'run_upgrade', 1, 100, 'source_registered',
             '{}'::jsonb, decode(repeat('12', 32), 'hex'), 1
         );
         INSERT INTO apolysis_gateway.projection_outbox (
             organization_id, ingest_sequence, available_at_unix_ms
         ) VALUES ('org_upgrade', 1, 100);
         INSERT INTO apolysis_gateway.source_streams (
             organization_id, run_id, source_registration_id,
             source_stream_id, source_id, source_kind, environment,
             registration_principal_kind, registration_principal_id,
             registration_policy_revision, effective_trust_profile,
             manifest_digest, manifest_json, registered_ingest_sequence,
             registered_at_unix_ms
         ) VALUES (
             'org_upgrade', 'run_upgrade', 'registration_upgrade',
             'stream_upgrade', 'source_upgrade', 'semantic_hook',
             'local_cli_or_ide', 'workload', 'principal_upgrade', 7,
             'harness_observed', decode(repeat('13', 32), 'hex'),
             '{}'::jsonb, 1, 100
         );
         INSERT INTO apolysis_gateway.leases (
             organization_id, lease_digest, run_id, source_registration_id,
             source_stream_id, source_id, principal_kind, principal_id,
             registration_policy_revision, issued_at_unix_ms,
             expires_at_unix_ms
         ) VALUES (
             'org_upgrade', decode(repeat('22', 32), 'hex'), 'run_upgrade',
             'registration_upgrade', 'stream_upgrade', 'source_upgrade',
             'workload', 'principal_upgrade', 7, 100, 9007199254740000
         );
         INSERT INTO apolysis_gateway.gateway_operations (
             organization_id, source_registration_id, principal_kind,
             principal_id, operation_kind, client_operation_id,
             request_digest, run_id, outcome_kind, committed_at_unix_ms
         ) VALUES (
             'org_upgrade', 'registration_upgrade', 'workload',
             'principal_upgrade', 'open_run', 'operation_upgrade',
             decode(repeat('33', 32), 'hex'), 'run_upgrade', 'open_run', 100
         );
         INSERT INTO apolysis_gateway.operation_replays (
             organization_id, operation_id, encryption_algorithm,
             cipher_version, encryption_key_ref, nonce, authentication_tag,
             aad_digest, outcome_ciphertext, created_at_unix_ms,
             expires_at_unix_ms
         ) VALUES (
             'org_upgrade', 1, 'aes-256-gcm', 1, 'upgrade-key',
             decode(repeat('44', 12), 'hex'),
             decode(repeat('55', 16), 'hex'),
             decode(repeat('66', 32), 'hex'), decode('77', 'hex'), 100, 200
         );
         INSERT INTO apolysis_gateway.join_authorizations (
             organization_id, proof_digest, authorization_kind, run_id,
             source_id, source_kind, environment, source_registration_id,
             principal_kind, principal_id, registration_policy_revision,
             issued_by_source_registration_id, issued_by_principal_kind,
             issued_by_principal_id, issued_at_unix_ms, expires_at_unix_ms
         ) VALUES (
             'org_upgrade', decode(repeat('88', 32), 'hex'), 'grant',
             'run_upgrade', 'source_upgrade', 'semantic_hook',
             'local_cli_or_ide', 'registration_upgrade', 'workload',
             'principal_upgrade', 7, 'registration_upgrade', 'workload',
             'principal_upgrade', 100, 9007199254740000
         );",
    )
    .execute(&mut *legacy_transaction)
    .await?;
    let rebound_legacy_lease = sqlx::query(
        "UPDATE apolysis_gateway.leases
         SET lease_digest = decode($1, 'hex')
         WHERE organization_id = 'org_upgrade'
           AND run_id = 'run_upgrade'",
    )
    .bind(lease_id_digest(LEGACY_LEASE_ID))
    .execute(&mut *legacy_transaction)
    .await?;
    assert_eq!(rebound_legacy_lease.rows_affected(), 1);
    legacy_transaction.commit().await?;

    sqlx::raw_sql(TRANSACTION_AUTHORITY_BINDING)
        .execute(&pool)
        .await?;

    let upgrade_state = sqlx::query(
        "SELECT
           (SELECT count(*) FROM apolysis_gateway.source_authority_revisions)
             AS authority_revisions,
           (SELECT count(*) FROM apolysis_gateway.gateway_operations
             WHERE authority_binding_version =
               'apolysis.gateway.authority-binding/legacy-unbound-v0'
               AND credential_id IS NULL
               AND credential_epoch IS NULL
               AND registration_policy_revision IS NULL)
             AS legacy_tombstones,
           (SELECT count(*) FROM apolysis_gateway.operation_replays)
             AS replays,
           (SELECT count(*) FROM apolysis_gateway.leases
             WHERE authority_binding_version =
               'apolysis.gateway.authority-binding/legacy-unbound-v0'
               AND revoked_at_unix_ms IS NOT NULL)
             AS revoked_leases,
           (SELECT count(*) FROM apolysis_gateway.join_authorizations
             WHERE authority_binding_version =
               'apolysis.gateway.authority-binding/legacy-unbound-v0'
               AND authorization_state = 'revoked'
               AND revoked_at_unix_ms IS NOT NULL)
             AS revoked_grants",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(upgrade_state.try_get::<i64, _>("authority_revisions")?, 1);
    assert_eq!(upgrade_state.try_get::<i64, _>("legacy_tombstones")?, 1);
    assert_eq!(upgrade_state.try_get::<i64, _>("replays")?, 0);
    assert_eq!(upgrade_state.try_get::<i64, _>("revoked_leases")?, 1);
    assert_eq!(upgrade_state.try_get::<i64, _>("revoked_grants")?, 1);

    let authority_locked: bool =
        sqlx::query_scalar("SELECT apolysis_gateway.lock_gateway_current_authority($1, $2, $3)")
            .bind("org_upgrade")
            .bind("registration_upgrade")
            .bind("credential_upgrade")
            .fetch_one(&pool)
            .await?;
    assert!(authority_locked);

    let repository = PostgresGatewayRepository::from_pool(
        pool.clone(),
        Arc::new(Aes256GcmReplayProtector::new(
            "migration-test-key",
            [("migration-test-key".to_string(), [97_u8; 32])],
        )?),
        PostgresGatewayConfig::default(),
    );
    let gateway = ExecutionEvidenceGateway::new(repository, FixedClock, NoIds);
    let context = legacy_context();
    assert_legacy_lease_revoked(
        gateway
            .bind_runtime(&context, legacy_bind_request())
            .await
            .expect_err("legacy bind lease must fail closed"),
    );
    assert_legacy_lease_revoked(
        gateway
            .ingest(&context, legacy_ingest_request())
            .await
            .expect_err("legacy ingest lease must fail closed"),
    );
    assert_legacy_lease_revoked(
        gateway
            .finish_run(&context, legacy_finish_request())
            .await
            .expect_err("legacy finalization lease must fail closed"),
    );

    let unbound_insert = sqlx::query(
        "INSERT INTO apolysis_gateway.gateway_operations (
             organization_id, source_registration_id, principal_kind,
             principal_id, operation_kind, client_operation_id,
             request_digest, run_id, outcome_kind, committed_at_unix_ms
         ) VALUES (
             'org_upgrade', 'registration_upgrade', 'workload',
             'principal_upgrade', 'open_run', 'unbound_forbidden',
             decode(repeat('99', 32), 'hex'), 'run_upgrade', 'open_run', 101
         )",
    )
    .execute(&pool)
    .await
    .expect_err("new operations without authority bindings must fail closed");
    assert_eq!(
        unbound_insert
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );

    let bound_operation_id: i64 = sqlx::query_scalar(
        "INSERT INTO apolysis_gateway.gateway_operations (
             organization_id, source_registration_id, principal_kind,
             principal_id, operation_kind, client_operation_id,
             request_digest, run_id, outcome_kind, committed_at_unix_ms,
             credential_id, credential_epoch, registration_policy_revision
         ) VALUES (
             'org_upgrade', 'registration_upgrade', 'workload',
             'principal_upgrade', 'open_run', 'bound_operation',
             decode(repeat('aa', 32), 'hex'), 'run_upgrade', 'open_run', 102,
             'credential_upgrade', 3, 7
         )
         RETURNING operation_id",
    )
    .fetch_one(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions (
             organization_id, source_registration_id, credential_id,
             credential_epoch, registration_policy_revision, policy_document,
             effective_at_unix_ms, expires_at_unix_ms, recorded_at_unix_ms
         )
         SELECT organization_id, source_registration_id, credential_id,
                credential_epoch, 8, policy_document,
                effective_at_unix_ms, expires_at_unix_ms, 103
         FROM apolysis_gateway.source_authority_revisions
         WHERE organization_id='org_upgrade'
           AND source_registration_id='registration_upgrade'
           AND credential_id='credential_upgrade'
           AND credential_epoch=3
           AND registration_policy_revision=7",
    )
    .execute(&pool)
    .await?;
    let mismatched_replay = sqlx::query(
        "INSERT INTO apolysis_gateway.operation_replays (
             organization_id, operation_id, encryption_algorithm,
             cipher_version, encryption_key_ref, nonce, authentication_tag,
             aad_digest, outcome_ciphertext, created_at_unix_ms,
             expires_at_unix_ms, credential_id, credential_epoch,
             registration_policy_revision
         ) VALUES (
             'org_upgrade', $1, 'aes-256-gcm', 1, 'upgrade-key',
             decode(repeat('ab', 12), 'hex'),
             decode(repeat('ac', 16), 'hex'),
             decode(repeat('ad', 32), 'hex'), decode('ae', 'hex'), 102, 202,
             'credential_upgrade', 3, 8
         )",
    )
    .bind(bound_operation_id)
    .execute(&pool)
    .await
    .expect_err("a replay must carry exactly its operation's authority tuple");
    assert_eq!(
        mismatched_replay
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23503")
    );
    assert_eq!(
        mismatched_replay
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("operation_replays_operation_authority_fk")
    );

    let rewritten_binding = sqlx::query(
        "UPDATE apolysis_gateway.gateway_operations
         SET registration_policy_revision = 8
         WHERE organization_id = 'org_upgrade'
           AND operation_id = $1",
    )
    .bind(bound_operation_id)
    .execute(&pool)
    .await
    .expect_err("stored operation authority tuples must be immutable");
    assert_eq!(
        rewritten_binding
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );

    reset_schema(&pool).await?;
    Ok(())
}

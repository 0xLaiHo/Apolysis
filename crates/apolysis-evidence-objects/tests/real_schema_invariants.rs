// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use apolysis_gateway_server::AuthorityStore;
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool, Postgres, Transaction};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const ORGANIZATION_ID: &str = "org_schema_invariants";
const RUN_A: &str = "run_schema_a";
const RUN_B: &str = "run_schema_b";
const REGISTRATION_A: &str = "registration_schema_a";
const REGISTRATION_B: &str = "registration_schema_b";
const STREAM_A: &str = "stream_schema_a";
const STREAM_B: &str = "stream_schema_b";
const SOURCE_A: &str = "source_schema_a";
const SOURCE_B: &str = "source_schema_b";
const PRIVACY_PROFILE: &str = "privacy_schema_main";
const RETENTION_PROFILE: &str = "retention_schema_main";
const OTHER_PRIVACY_PROFILE: &str = "privacy_schema_other";
const OTHER_RETENTION_PROFILE: &str = "retention_schema_other";
const PAYLOAD_TYPE: &str = "tool_interaction_blob";
const PAYLOAD_VERSION: &str = "1.0.0";
const BOOTSTRAP_ROLES_SQL: &str =
    include_str!("../../apolysis-gateway-postgres/deploy/bootstrap_roles.sql");
const SECURITY_DEFINER_SEARCH_PATH: &str = "search_path=pg_catalog, apolysis_gateway, pg_temp";
const SECURITY_DEFINER_ROUTINES: [&str; 20] = [
    "acknowledge_evidence_object_deletion",
    "enforce_evidence_object_transition",
    "lock_evidence_object_deletion_target",
    "lock_evidence_object_lease_shared",
    "lock_evidence_object_organization",
    "lock_evidence_object_organization_shared",
    "lock_evidence_object_reaper_organizations",
    "lock_evidence_object_run_shared",
    "lock_evidence_objects_for_ingest",
    "lock_evidence_source_authority_shared",
    "lock_gateway_authority_by_fingerprint",
    "lock_gateway_client_run",
    "lock_gateway_lease",
    "lock_gateway_operation",
    "lock_gateway_runtime_binding",
    "reserve_evidence_object_capacity",
    "snapshot_evidence_object_deletion_targets",
    "validate_evidence_event_object_link",
    "validate_evidence_object_deletion",
    "validate_evidence_object_usage_aggregate",
];

#[derive(Clone)]
struct ObjectRow {
    object_id: String,
    run_id: String,
    source_registration_id: String,
    source_stream_id: String,
    source_id: String,
    lease_digest: Vec<u8>,
    client_upload_id: String,
    required_source_capability: String,
    privacy_profile_ref: String,
    retention_profile_ref: String,
    capture_request_digest: Vec<u8>,
    content_digest: Vec<u8>,
    content_size_bytes: i64,
    created_at_unix_ms: i64,
}

impl ObjectRow {
    fn new(object_id: &str, size_bytes: i64, now_unix_ms: i64, seed: u8) -> Self {
        Self {
            object_id: object_id.to_string(),
            run_id: RUN_A.to_string(),
            source_registration_id: REGISTRATION_A.to_string(),
            source_stream_id: STREAM_A.to_string(),
            source_id: SOURCE_A.to_string(),
            lease_digest: vec![31_u8; 32],
            client_upload_id: format!("upload:{object_id}"),
            required_source_capability: "tool_calls".to_string(),
            privacy_profile_ref: PRIVACY_PROFILE.to_string(),
            retention_profile_ref: RETENTION_PROFILE.to_string(),
            capture_request_digest: vec![seed; 32],
            content_digest: vec![seed.wrapping_add(1); 32],
            content_size_bytes: size_bytes,
            created_at_unix_ms: now_unix_ms,
        }
    }
}

fn assert_database_error(error: &sqlx::Error, sqlstate: &str, constraint: &str) {
    let database_error = error
        .as_database_error()
        .expect("PostgreSQL must report a database constraint error");
    assert_eq!(database_error.code().as_deref(), Some(sqlstate), "{error}");
    assert_eq!(database_error.constraint(), Some(constraint), "{error}");
}

fn assert_bounded_database_error(error: &sqlx::Error, sqlstate: &str, message: &str) {
    let database_error = error
        .as_database_error()
        .expect("PostgreSQL must report a bounded database error");
    assert_eq!(database_error.code().as_deref(), Some(sqlstate), "{error}");
    assert_eq!(database_error.message(), message, "{error}");
}

fn assert_foreign_key_error(error: &sqlx::Error, table_prefix: &str) {
    let database_error = error
        .as_database_error()
        .expect("PostgreSQL must report a database constraint error");
    assert_eq!(database_error.code().as_deref(), Some("23503"), "{error}");
    let constraint = database_error
        .constraint()
        .expect("foreign-key violation must identify its constraint");
    assert!(
        constraint.starts_with(table_prefix),
        "{constraint}: {error}"
    );
}

async fn database_now_unix_ms(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(pool)
        .await
}

async fn seed_gateway_scope(pool: &PgPool, now_unix_ms: i64) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.organization_sequences (\
            organization_id, next_ingest_sequence, updated_at_unix_ms\
         ) VALUES ($1,4,$2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.organizations (\
            organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,'active',$2,$2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await?;

    for (registration_id, source_id) in [(REGISTRATION_A, SOURCE_A), (REGISTRATION_B, SOURCE_B)] {
        sqlx::query(
            "INSERT INTO apolysis_gateway.source_registrations (\
                source_registration_id, organization_id, source_id, principal_kind, \
                principal_id, registration_state, policy_revision, credential_epoch, \
                effective_at_unix_ms, expires_at_unix_ms, policy_document, \
                created_at_unix_ms, updated_at_unix_ms\
             ) VALUES (\
                $1,$2,$3,'workload','principal_schema','active',1,1,$4,$5,$6,$4,$4\
             )",
        )
        .bind(registration_id)
        .bind(ORGANIZATION_ID)
        .bind(source_id)
        .bind(now_unix_ms - 1_000)
        .bind(now_unix_ms + 600_000)
        .bind(json!({
            "allowed_operations": ["ingest"],
            "allowed_capabilities": ["tool_calls"],
            "allowed_privacy_capabilities": ["authorized_content_reference"]
        }))
        .execute(&mut *transaction)
        .await?;
    }

    for (run_id, registration_id) in [(RUN_A, REGISTRATION_A), (RUN_B, REGISTRATION_B)] {
        sqlx::query(
            "INSERT INTO apolysis_gateway.runs (\
                organization_id, run_id, state, environment, authority_kind, authority_id, \
                principal_kind, principal_id, objective_ref, privacy_profile_ref, \
                retention_profile_ref, initiating_source_registration_id, \
                initiating_principal_kind, initiating_principal_id, opened_at_unix_ms, \
                state_changed_at_unix_ms\
             ) VALUES (\
                $1,$2,'active','ci_runner_or_remote_workspace','service','authority_schema', \
                'workload','principal_schema','objective_schema',$3,$4,$5, \
                'workload','principal_schema',$6,$6\
             )",
        )
        .bind(ORGANIZATION_ID)
        .bind(run_id)
        .bind(PRIVACY_PROFILE)
        .bind(RETENTION_PROFILE)
        .bind(registration_id)
        .bind(now_unix_ms)
        .execute(&mut *transaction)
        .await?;
    }

    for (sequence, run_id, fact_kind) in [
        (1_i64, RUN_A, "source_registered"),
        (2_i64, RUN_B, "source_registered"),
        (3_i64, RUN_B, "evidence_accepted"),
    ] {
        sqlx::query(
            "INSERT INTO apolysis_gateway.record_items (\
                organization_id, run_id, ingest_sequence, ingested_at_unix_ms, fact_kind, \
                fact_json, fact_digest, outbox_ingest_sequence\
             ) VALUES ($1,$2,$3,$4,$5,'{}'::jsonb,$6,$3)",
        )
        .bind(ORGANIZATION_ID)
        .bind(run_id)
        .bind(sequence)
        .bind(now_unix_ms)
        .bind(fact_kind)
        .bind(vec![u8::try_from(sequence)?; 32])
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.projection_outbox (\
                organization_id, ingest_sequence, available_at_unix_ms\
             ) VALUES ($1,$2,$3)",
        )
        .bind(ORGANIZATION_ID)
        .bind(sequence)
        .bind(now_unix_ms)
        .execute(&mut *transaction)
        .await?;
    }

    for (run_id, registration_id, stream_id, source_id, sequence) in [
        (RUN_A, REGISTRATION_A, STREAM_A, SOURCE_A, 1_i64),
        (RUN_B, REGISTRATION_B, STREAM_B, SOURCE_B, 2_i64),
    ] {
        sqlx::query(
            "INSERT INTO apolysis_gateway.source_streams (\
                organization_id, run_id, source_registration_id, source_stream_id, source_id, \
                source_kind, environment, registration_principal_kind, \
                registration_principal_id, registration_policy_revision, \
                effective_trust_profile, manifest_digest, manifest_json, \
                registered_ingest_sequence, registered_at_unix_ms\
             ) VALUES (\
                $1,$2,$3,$4,$5,'semantic_hook','ci_runner_or_remote_workspace', \
                'workload','principal_schema',1,'harness_observed',$6,$7,$8,$9\
             )",
        )
        .bind(ORGANIZATION_ID)
        .bind(run_id)
        .bind(registration_id)
        .bind(stream_id)
        .bind(source_id)
        .bind(vec![u8::try_from(sequence + 10)?; 32])
        .bind(json!({"privacy_capabilities": ["authorized_content_reference"]}))
        .bind(sequence)
        .bind(now_unix_ms)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.source_stream_capabilities (\
                organization_id, run_id, source_registration_id, source_stream_id, capability\
             ) VALUES ($1,$2,$3,$4,'tool_calls')",
        )
        .bind(ORGANIZATION_ID)
        .bind(run_id)
        .bind(registration_id)
        .bind(stream_id)
        .execute(&mut *transaction)
        .await?;
    }

    for (run_id, registration_id, stream_id, source_id, lease_seed) in [
        (RUN_A, REGISTRATION_A, STREAM_A, SOURCE_A, 31_u8),
        (RUN_B, REGISTRATION_B, STREAM_B, SOURCE_B, 32_u8),
    ] {
        let lease_digest = vec![lease_seed; 32];
        sqlx::query(
            "INSERT INTO apolysis_gateway.leases (\
                organization_id, lease_digest, run_id, source_registration_id, \
                source_stream_id, source_id, principal_kind, principal_id, \
                registration_policy_revision, issued_at_unix_ms, expires_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,'workload','principal_schema',1,$7,$8)",
        )
        .bind(ORGANIZATION_ID)
        .bind(&lease_digest)
        .bind(run_id)
        .bind(registration_id)
        .bind(stream_id)
        .bind(source_id)
        .bind(now_unix_ms - 1_000)
        .bind(now_unix_ms + 600_000)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.lease_operations (\
                organization_id, lease_digest, operation_kind\
             ) VALUES ($1,$2,'ingest')",
        )
        .bind(ORGANIZATION_ID)
        .bind(lease_digest)
        .execute(&mut *transaction)
        .await?;
    }

    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_events (\
            organization_id, run_id, source_registration_id, source_stream_id, source_id, \
            source_event_id, source_sequence, envelope_digest, ledger_ingest_sequence, \
            accepted_at_unix_ms, payload_type, accepted_envelope_json\
         ) VALUES ($1,$2,$3,$4,$5,'event_schema_b',1,$6,3,$7,$8,$9)",
    )
    .bind(ORGANIZATION_ID)
    .bind(RUN_B)
    .bind(REGISTRATION_B)
    .bind(STREAM_B)
    .bind(SOURCE_B)
    .bind(vec![23_u8; 32])
    .bind(now_unix_ms)
    .bind(PAYLOAD_TYPE)
    .bind(json!({
        "source_registration_id": REGISTRATION_B,
        "source_stream_id": STREAM_B,
        "envelope": {
            "run_id": RUN_B,
            "source_id": SOURCE_B,
            "source_stream_id": STREAM_B,
            "source_event_id": "event_schema_b",
            "payload_type": PAYLOAD_TYPE,
            "payload_version": PAYLOAD_VERSION,
            "payload_digest": "29".repeat(32),
            "flags": {"contains_content": true},
            "inline_payload": null,
            "object_ref": {
                "object_id": "object_schema_a",
                "sha256": "29".repeat(32),
                "size_bytes": 512
            }
        }
    }))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn install_object_policies(pool: &PgPool, now_unix_ms: i64) -> TestResult {
    for (privacy_profile, retention_profile) in [
        (PRIVACY_PROFILE, RETENTION_PROFILE),
        (OTHER_PRIVACY_PROFILE, OTHER_RETENTION_PROFILE),
    ] {
        sqlx::query(
            "INSERT INTO apolysis_gateway.evidence_object_policy_revisions (\
                organization_id, privacy_profile_ref, retention_profile_ref, policy_revision, \
                policy_state, max_object_size_bytes, organization_quota_bytes, \
                organization_quota_objects, uploads_per_minute, upload_timeout_ms, \
                retention_ms, effective_at_unix_ms, created_at_unix_ms\
             ) VALUES ($1,$2,$3,1,'active',1024,1024,10,2,10000,60000,$4,$4)",
        )
        .bind(ORGANIZATION_ID)
        .bind(privacy_profile)
        .bind(retention_profile)
        .bind(now_unix_ms - 1_000)
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn insert_object(
    connection: &mut PgConnection,
    object: &ObjectRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_objects (\
            organization_id, object_id, run_id, source_registration_id, source_stream_id, \
            source_id, lease_digest, lease_policy_revision, client_upload_id, \
            capture_request_digest, required_source_capability, payload_type, payload_version, \
            content_digest, content_size_bytes, ciphertext_size_bytes, object_state, \
            privacy_profile_ref, retention_profile_ref, object_policy_revision, \
            requested_retention_ms, lifecycle_revision, created_at_unix_ms, \
            lifecycle_changed_at_unix_ms, upload_deadline_unix_ms, expires_at_unix_ms\
         ) VALUES (\
            $1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,$13,$14,$15,'uploading',$16,$17,1, \
            45000,1,$18,$18,$19,$20\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object.object_id)
    .bind(&object.run_id)
    .bind(&object.source_registration_id)
    .bind(&object.source_stream_id)
    .bind(&object.source_id)
    .bind(&object.lease_digest)
    .bind(&object.client_upload_id)
    .bind(&object.capture_request_digest)
    .bind(&object.required_source_capability)
    .bind(PAYLOAD_TYPE)
    .bind(PAYLOAD_VERSION)
    .bind(&object.content_digest)
    .bind(object.content_size_bytes)
    .bind(object.content_size_bytes + 16)
    .bind(&object.privacy_profile_ref)
    .bind(&object.retention_profile_ref)
    .bind(object.created_at_unix_ms)
    .bind(object.created_at_unix_ms + 10_000)
    .bind(object.created_at_unix_ms + 45_000)
    .execute(connection)
    .await?;
    Ok(())
}

async fn insert_storage_material(
    connection: &mut PgConnection,
    object_id: &str,
    seed: u8,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_storage_material (\
            organization_id, object_id, storage_backend_ref, storage_backend_binding_digest, \
            storage_operation_timeout_ms, storage_key, \
            encryption_algorithm, cipher_version, encryption_key_ref, encrypted_data_key, \
            key_wrap_nonce, content_nonce, aad_digest\
         ) VALUES (\
            $1,$2,'schema_backend',$3,1000,$4,'aes-256-gcm',1,'schema_wrapping_key', \
            $5,$6,$7,$8\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_id)
    .bind(vec![seed.wrapping_add(3); 32])
    .bind(format!("key:{object_id}"))
    .bind(vec![seed; 48])
    .bind(vec![seed; 12])
    .bind(vec![seed.wrapping_add(1); 12])
    .bind(vec![seed.wrapping_add(2); 32])
    .execute(connection)
    .await?;
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn insert_evidence_event_for_object(
    connection: &mut PgConnection,
    object: &ObjectRow,
    source_event_id: &str,
    source_sequence: i64,
    ingest_sequence: i64,
    accepted_at_unix_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.record_items (\
            organization_id, run_id, ingest_sequence, ingested_at_unix_ms, fact_kind, \
            fact_json, fact_digest, outbox_ingest_sequence\
         ) VALUES ($1,$2,$3,$4,'evidence_accepted','{}'::jsonb,$5,$3)",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object.run_id)
    .bind(ingest_sequence)
    .bind(accepted_at_unix_ms)
    .bind(vec![
        u8::try_from(ingest_sequence)
            .expect("test ingest sequence fits u8");
        32
    ])
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.projection_outbox (\
            organization_id, ingest_sequence, available_at_unix_ms\
         ) VALUES ($1,$2,$3)",
    )
    .bind(ORGANIZATION_ID)
    .bind(ingest_sequence)
    .bind(accepted_at_unix_ms)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_events (\
            organization_id, run_id, source_registration_id, source_stream_id, source_id, \
            source_event_id, source_sequence, envelope_digest, ledger_ingest_sequence, \
            accepted_at_unix_ms, payload_type, accepted_envelope_json\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object.run_id)
    .bind(&object.source_registration_id)
    .bind(&object.source_stream_id)
    .bind(&object.source_id)
    .bind(source_event_id)
    .bind(source_sequence)
    .bind(vec![
        u8::try_from(ingest_sequence + 20)
            .expect("test digest seed fits u8");
        32
    ])
    .bind(ingest_sequence)
    .bind(accepted_at_unix_ms)
    .bind(PAYLOAD_TYPE)
    .bind(json!({
        "source_registration_id": object.source_registration_id.as_str(),
        "source_stream_id": object.source_stream_id.as_str(),
        "envelope": {
            "run_id": object.run_id.as_str(),
            "source_id": object.source_id.as_str(),
            "source_stream_id": object.source_stream_id.as_str(),
            "source_event_id": source_event_id,
            "payload_type": PAYLOAD_TYPE,
            "payload_version": PAYLOAD_VERSION,
            "payload_digest": hex_digest(&object.content_digest),
            "flags": {"contains_content": true},
            "inline_payload": null,
            "object_ref": {
                "object_id": object.object_id.as_str(),
                "sha256": hex_digest(&object.content_digest),
                "size_bytes": object.content_size_bytes
            }
        }
    }))
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_outbox(
    connection: &mut PgConnection,
    object_id: &str,
    revision: i64,
    event_kind: &str,
    now_unix_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_outbox (\
            organization_id, object_id, lifecycle_revision, event_kind, event_json, \
            available_at_unix_ms, created_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,'{}'::jsonb,$5,$5)",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_id)
    .bind(revision)
    .bind(event_kind)
    .bind(now_unix_ms)
    .execute(connection)
    .await?;
    Ok(())
}

async fn insert_audit(
    connection: &mut PgConnection,
    object_id: &str,
    revision: i64,
    action: &str,
    now_unix_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_audit (\
            organization_id, object_id, lifecycle_revision, occurred_at_unix_ms, actor_kind, \
            actor_id, action, decision, reason_code, metadata_json\
         ) VALUES ($1,$2,$3,$4,'system','schema_test',$5,'completed','schema_test','{}'::jsonb)",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_id)
    .bind(revision)
    .bind(now_unix_ms)
    .bind(action)
    .execute(connection)
    .await?;
    Ok(())
}

async fn insert_valid_object(pool: &PgPool, object: &ObjectRow, seed: u8) -> TestResult {
    let mut transaction = pool.begin().await?;
    insert_object(&mut transaction, object).await?;
    insert_storage_material(&mut transaction, &object.object_id, seed).await?;
    insert_outbox(
        &mut transaction,
        &object.object_id,
        1,
        "upload_reserved",
        object.created_at_unix_ms,
    )
    .await?;
    insert_audit(
        &mut transaction,
        &object.object_id,
        1,
        "reserve_upload",
        object.created_at_unix_ms,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn expect_object_insert_error(
    pool: &PgPool,
    object: &ObjectRow,
    sqlstate: &str,
    constraint: Option<&str>,
) -> TestResult {
    let mut transaction = pool.begin().await?;
    let error = insert_object(&mut transaction, object)
        .await
        .expect_err("direct invalid object insert must fail");
    if let Some(constraint) = constraint {
        assert_database_error(&error, sqlstate, constraint);
    } else {
        assert_foreign_key_error(&error, "evidence_objects_");
    }
    transaction.rollback().await?;
    Ok(())
}

async fn expect_commit_constraint(
    transaction: Transaction<'_, Postgres>,
    constraint: &str,
) -> TestResult {
    let error = transaction
        .commit()
        .await
        .expect_err("deferred constraint must reject commit");
    assert_database_error(&error, "23503", constraint);
    Ok(())
}

async fn expect_commit_check_constraint(
    transaction: Transaction<'_, Postgres>,
    constraint: &str,
) -> TestResult {
    let error = transaction
        .commit()
        .await
        .expect_err("deferred check constraint must reject commit");
    assert_database_error(&error, "23514", constraint);
    Ok(())
}

async fn migrate_with_hostile_database_search_path(
    pool: &PgPool,
    database_url: &str,
) -> TestResult {
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL).execute(pool).await?;
    sqlx::query("CREATE SCHEMA apolysis_migration_shadow AUTHORIZATION apolysis_schema_owner")
        .execute(pool)
        .await?;
    sqlx::raw_sql(
        r#"
        DO $set_database_search_path$
        BEGIN
            EXECUTE pg_catalog.format(
                'ALTER DATABASE %I SET search_path TO pg_temp, apolysis_migration_shadow, public',
                pg_catalog.current_database()
            );
        END
        $set_database_search_path$;
        "#,
    )
    .execute(pool)
    .await?;

    // AuthorityStore opens a fresh dedicated migration connection after the
    // database default is poisoned. Always restore the default before
    // propagating the migration result so later provider-gate connections do
    // not inherit this adversarial setup.
    let migration_result = AuthorityStore::migrate(database_url).await;
    let reset_result = sqlx::raw_sql(
        r#"
        DO $reset_database_search_path$
        BEGIN
            EXECUTE pg_catalog.format(
                'ALTER DATABASE %I RESET search_path',
                pg_catalog.current_database()
            );
        END
        $reset_database_search_path$;
        "#,
    )
    .execute(pool)
    .await;
    reset_result?;
    migration_result?;

    let migration_history: (bool, bool, String) = sqlx::query_as(
        r#"
        SELECT
            pg_catalog.to_regclass('public._sqlx_migrations') IS NOT NULL,
            pg_catalog.to_regclass(
                'apolysis_migration_shadow._sqlx_migrations'
            ) IS NOT NULL,
            owner.rolname
        FROM pg_catalog.pg_class AS history
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid=history.relnamespace
        JOIN pg_catalog.pg_roles AS owner ON owner.oid=history.relowner
        WHERE namespace.nspname='public'
          AND history.relname='_sqlx_migrations'
        "#,
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(
        migration_history,
        (true, false, "apolysis_schema_owner".to_string())
    );
    sqlx::query("DROP SCHEMA apolysis_migration_shadow RESTRICT")
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_security_definer_search_paths(pool: &PgPool) -> TestResult {
    let routines: Vec<(String, Vec<String>)> = sqlx::query_as(
        r#"
        SELECT procedure.proname,
               coalesce(procedure.proconfig, ARRAY[]::text[])
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid=procedure.pronamespace
        WHERE namespace.nspname='apolysis_gateway'
          AND procedure.prosecdef
        ORDER BY procedure.proname
        "#,
    )
    .fetch_all(pool)
    .await?;
    let routine_names = routines
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let expected_names = SECURITY_DEFINER_ROUTINES
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    assert_eq!(routine_names, expected_names);
    for (name, configuration) in routines {
        assert_eq!(
            configuration,
            vec![SECURITY_DEFINER_SEARCH_PATH.to_string()],
            "security-definer routine {name} must pin one exact search_path"
        );
    }
    Ok(())
}

async fn assert_reaper_organization_lock_rejects_invalid_arguments(pool: &PgPool) -> TestResult {
    const ERROR_MESSAGE: &str = "evidence object organization lock batch is invalid";
    let invalid_arguments = [
        (None, Some(1_i32), "null database time"),
        (Some(1_i64), None, "null batch limit"),
        (Some(0_i64), Some(1_i32), "zero database time"),
        (
            Some(9_007_199_254_740_992_i64),
            Some(1_i32),
            "database time above the I-JSON ceiling",
        ),
        (Some(1_i64), Some(0_i32), "zero batch limit"),
        (Some(1_i64), Some(257_i32), "batch limit above 256"),
    ];
    for (now_unix_ms, limit, description) in invalid_arguments {
        let error = sqlx::query_scalar::<_, String>(
            "SELECT apolysis_gateway.lock_evidence_object_reaper_organizations($1,$2)",
        )
        .bind(now_unix_ms)
        .bind(limit)
        .fetch_all(pool)
        .await
        .expect_err(description);
        assert_bounded_database_error(&error, "22023", ERROR_MESSAGE);
    }
    Ok(())
}

async fn exercise_definers_with_hostile_caller_search_path(pool: &PgPool) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::raw_sql(
        r#"
        CREATE TEMPORARY TABLE organizations (organization_id text PRIMARY KEY);
        INSERT INTO organizations VALUES ('org_temp_shadow');
        CREATE TEMPORARY TABLE source_registrations (
            organization_id text NOT NULL,
            source_registration_id text NOT NULL
        );
        INSERT INTO source_registrations
        VALUES ('org_temp_shadow', 'registration_temp_shadow');
        CREATE TEMPORARY TABLE transport_credentials (
            certificate_fingerprint bytea NOT NULL,
            organization_id text NOT NULL,
            source_registration_id text NOT NULL
        );
        INSERT INTO transport_credentials
        VALUES (
            decode(repeat('3d', 32), 'hex'),
            'org_temp_shadow',
            'registration_temp_shadow'
        );
        CREATE TEMPORARY TABLE evidence_objects (
            organization_id text NOT NULL,
            object_id text NOT NULL
        );
        INSERT INTO evidence_objects VALUES ('org_temp_shadow', 'object_temp_shadow');
        CREATE FUNCTION pg_temp.cardinality(text[]) RETURNS integer
        LANGUAGE sql IMMUTABLE AS 'SELECT 999';
        SET LOCAL search_path = pg_temp, public, apolysis_gateway, pg_catalog;
        "#,
    )
    .execute(&mut *transaction)
    .await?;

    let organization_found: bool =
        sqlx::query_scalar("SELECT apolysis_gateway.lock_evidence_object_organization($1)")
            .bind("org_temp_shadow")
            .fetch_one(&mut *transaction)
            .await?;
    assert!(!organization_found);
    let locked_objects: i64 = sqlx::query_scalar(
        "SELECT apolysis_gateway.lock_evidence_objects_for_ingest(\
             $1, ARRAY[$2]::text[]\
         )",
    )
    .bind("org_temp_shadow")
    .bind("object_temp_shadow")
    .fetch_one(&mut *transaction)
    .await?;
    assert_eq!(locked_objects, 0);
    let authority_found: bool =
        sqlx::query_scalar("SELECT apolysis_gateway.lock_gateway_authority_by_fingerprint($1)")
            .bind(vec![61_u8; 32])
            .fetch_one(&mut *transaction)
            .await?;
    assert!(!authority_found);
    let reaper_organizations: Vec<String> = sqlx::query_scalar(
        "SELECT apolysis_gateway.lock_evidence_object_reaper_organizations($1,$2)",
    )
    .bind(9_007_199_254_740_991_i64)
    .bind(256_i32)
    .fetch_all(&mut *transaction)
    .await?;
    assert!(
        reaper_organizations.is_empty(),
        "security-definer reaper discovery must not read pg_temp shadow relations"
    );

    transaction.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL and an explicit real PostgreSQL schema gate"]
async fn migration_0003_rejects_direct_sql_lifecycle_bypasses() -> TestResult {
    let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await?;
    migrate_with_hostile_database_search_path(&pool, &database_url).await?;
    assert_security_definer_search_paths(&pool).await?;
    assert_reaper_organization_lock_rejects_invalid_arguments(&pool).await?;
    exercise_definers_with_hostile_caller_search_path(&pool).await?;
    let now_unix_ms = database_now_unix_ms(&pool).await?;
    seed_gateway_scope(&pool, now_unix_ms).await?;
    install_object_policies(&pool, now_unix_ms).await?;

    let object_a = ObjectRow::new("object_schema_a", 512, now_unix_ms, 40);
    insert_valid_object(&pool, &object_a, 40).await?;

    let mut duplicate_upload = ObjectRow::new("object_schema_duplicate_upload", 1, now_unix_ms, 39);
    duplicate_upload.client_upload_id = object_a.client_upload_id.clone();
    expect_object_insert_error(
        &pool,
        &duplicate_upload,
        "23505",
        Some("evidence_object_upload_identity_uq"),
    )
    .await?;

    let event_rewrite = sqlx::query(
        "UPDATE apolysis_gateway.evidence_events SET payload_type='rewritten' \
         WHERE organization_id=$1 AND source_event_id='event_schema_b'",
    )
    .bind(ORGANIZATION_ID)
    .execute(&pool)
    .await
    .expect_err("accepted event history must be append-only");
    assert_database_error(&event_rewrite, "23514", "evidence_object_append_only_ck");

    let audit_rewrite = sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_audit SET reason_code='rewritten' \
         WHERE organization_id=$1 AND object_id=$2 AND lifecycle_revision=1",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("object audit history must be append-only");
    assert_database_error(&audit_rewrite, "23514", "evidence_object_append_only_ck");

    let outbox_delete = sqlx::query(
        "DELETE FROM apolysis_gateway.evidence_object_outbox \
         WHERE organization_id=$1 AND object_id=$2 AND lifecycle_revision=1",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("object outbox history must not be deleted");
    assert_database_error(&outbox_delete, "23514", "evidence_object_outbox_history_ck");

    sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_outbox \
         SET delivery_state='processing', attempt_count=1, claimed_by='schema_dispatcher', \
             claimed_at_unix_ms=$1, claim_until_unix_ms=$1+1000 \
         WHERE organization_id=$2 AND object_id=$3 AND lifecycle_revision=1",
    )
    .bind(now_unix_ms + 1)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_outbox \
         SET delivery_state='published', claimed_by=NULL, claimed_at_unix_ms=NULL, \
             claim_until_unix_ms=NULL, published_at_unix_ms=$1 \
         WHERE organization_id=$2 AND object_id=$3 AND lifecycle_revision=1",
    )
    .bind(now_unix_ms + 2)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await?;
    let outbox_reopen = sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_outbox \
         SET delivery_state='pending', published_at_unix_ms=NULL \
         WHERE organization_id=$1 AND object_id=$2 AND lifecycle_revision=1",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("published outbox fact must never become dispatchable again");
    assert_database_error(
        &outbox_reopen,
        "23514",
        "evidence_object_outbox_terminal_ck",
    );

    let object_delete = sqlx::query(
        "DELETE FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("object tombstones must not be deleted");
    assert_database_error(&object_delete, "23514", "evidence_object_append_only_ck");

    let policy_delete = sqlx::query(
        "DELETE FROM apolysis_gateway.evidence_object_policy_revisions \
         WHERE organization_id=$1 AND privacy_profile_ref=$2 \
           AND retention_profile_ref=$3 AND policy_revision=1",
    )
    .bind(ORGANIZATION_ID)
    .bind(PRIVACY_PROFILE)
    .bind(RETENTION_PROFILE)
    .execute(&pool)
    .await
    .expect_err("object policy history must not be deleted");
    assert_database_error(&policy_delete, "23514", "evidence_object_append_only_ck");

    // The reverse references are deferred so one transaction can insert the
    // object and its facts in either order, but neither fact may be omitted.
    let missing_outbox = ObjectRow::new("object_missing_outbox", 1, now_unix_ms, 41);
    let mut transaction = pool.begin().await?;
    insert_object(&mut transaction, &missing_outbox).await?;
    insert_storage_material(&mut transaction, &missing_outbox.object_id, 41).await?;
    insert_audit(
        &mut transaction,
        &missing_outbox.object_id,
        1,
        "reserve_upload",
        now_unix_ms,
    )
    .await?;
    expect_commit_constraint(transaction, "evidence_objects_current_outbox_fk").await?;

    let missing_audit = ObjectRow::new("object_missing_audit", 1, now_unix_ms, 42);
    let mut transaction = pool.begin().await?;
    insert_object(&mut transaction, &missing_audit).await?;
    insert_storage_material(&mut transaction, &missing_audit.object_id, 42).await?;
    insert_outbox(
        &mut transaction,
        &missing_audit.object_id,
        1,
        "upload_reserved",
        now_unix_ms,
    )
    .await?;
    expect_commit_constraint(transaction, "evidence_objects_current_audit_fk").await?;

    let mut wrong_profile = ObjectRow::new("object_wrong_profile", 1, now_unix_ms, 43);
    wrong_profile.privacy_profile_ref = OTHER_PRIVACY_PROFILE.to_string();
    wrong_profile.retention_profile_ref = OTHER_RETENTION_PROFILE.to_string();
    expect_object_insert_error(&pool, &wrong_profile, "23503", None).await?;

    let mut wrong_source = ObjectRow::new("object_wrong_source", 1, now_unix_ms, 44);
    wrong_source.source_id = "source_not_registered_for_stream".to_string();
    expect_object_insert_error(
        &pool,
        &wrong_source,
        "23514",
        Some("evidence_object_current_lease_ck"),
    )
    .await?;

    let mut wrong_capability = ObjectRow::new("object_wrong_capability", 1, now_unix_ms, 45);
    wrong_capability.required_source_capability = "network".to_string();
    expect_object_insert_error(&pool, &wrong_capability, "23503", None).await?;

    let mut transaction = pool.begin().await?;
    let available_at_unix_ms: i64 = sqlx::query_scalar(
        "UPDATE apolysis_gateway.evidence_objects \
         SET object_state='available', lifecycle_revision=2, available_at_unix_ms=$1 \
         WHERE organization_id=$2 AND object_id=$3 \
         RETURNING available_at_unix_ms",
    )
    .bind(9_007_199_254_740_991_i64)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_outbox(
        &mut transaction,
        &object_a.object_id,
        2,
        "object_available",
        available_at_unix_ms,
    )
    .await?;
    insert_audit(
        &mut transaction,
        &object_a.object_id,
        2,
        "finalize_upload",
        available_at_unix_ms,
    )
    .await?;
    transaction.commit().await?;

    let event_scope_error = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_event_objects (\
            organization_id, run_id, source_registration_id, source_stream_id, source_id, \
            source_event_id, object_id, lease_digest, required_source_capability, payload_type, \
            payload_version, content_digest, content_size_bytes, bound_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,'event_schema_b',$6,$7,'tool_calls',$8,$9,$10,$11,$12)",
    )
    .bind(ORGANIZATION_ID)
    .bind(RUN_B)
    .bind(REGISTRATION_B)
    .bind(STREAM_B)
    .bind(SOURCE_B)
    .bind(&object_a.object_id)
    .bind(&object_a.lease_digest)
    .bind(PAYLOAD_TYPE)
    .bind(PAYLOAD_VERSION)
    .bind(&object_a.content_digest)
    .bind(object_a.content_size_bytes)
    .bind(now_unix_ms)
    .execute(&pool)
    .await
    .expect_err("cross-run event/object binding must fail");
    assert_database_error(
        &event_scope_error,
        "23514",
        "evidence_object_current_lease_ck",
    );

    let event_json_mismatch = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_event_objects (\
            organization_id, run_id, source_registration_id, source_stream_id, source_id, \
            source_event_id, object_id, lease_digest, required_source_capability, payload_type, \
            payload_version, content_digest, content_size_bytes, bound_at_unix_ms\
         ) VALUES (\
            $1,$2,$3,$4,$5,'event_schema_b',$6,$7,'tool_calls',$8,'9.9.9',$9,$10,$11\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(RUN_B)
    .bind(REGISTRATION_B)
    .bind(STREAM_B)
    .bind(SOURCE_B)
    .bind(&object_a.object_id)
    .bind(&object_a.lease_digest)
    .bind(PAYLOAD_TYPE)
    .bind(&object_a.content_digest)
    .bind(object_a.content_size_bytes)
    .bind(now_unix_ms)
    .execute(&pool)
    .await
    .expect_err("link metadata must match the immutable accepted envelope JSON");
    assert_database_error(
        &event_json_mismatch,
        "23514",
        "evidence_event_object_exact_binding_ck",
    );

    let bound_before_unix_ms = database_now_unix_ms(&pool).await?;
    let mut transaction = pool.begin().await?;
    insert_evidence_event_for_object(
        &mut transaction,
        &object_a,
        "event_schema_available",
        1,
        4,
        bound_before_unix_ms,
    )
    .await?;
    let bound_at_unix_ms: i64 = sqlx::query_scalar(
        "INSERT INTO apolysis_gateway.evidence_event_objects (\
            organization_id, run_id, source_registration_id, source_stream_id, source_id, \
            source_event_id, object_id, lease_digest, required_source_capability, payload_type, \
            payload_version, content_digest, content_size_bytes, bound_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1) \
         RETURNING bound_at_unix_ms",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.run_id)
    .bind(&object_a.source_registration_id)
    .bind(&object_a.source_stream_id)
    .bind(&object_a.source_id)
    .bind("event_schema_available")
    .bind(&object_a.object_id)
    .bind(&object_a.lease_digest)
    .bind(&object_a.required_source_capability)
    .bind(PAYLOAD_TYPE)
    .bind(PAYLOAD_VERSION)
    .bind(&object_a.content_digest)
    .bind(object_a.content_size_bytes)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let bound_after_unix_ms = database_now_unix_ms(&pool).await?;
    assert_ne!(bound_at_unix_ms, 1);
    assert!(bound_at_unix_ms >= bound_before_unix_ms);
    assert!(bound_at_unix_ms <= bound_after_unix_ms);

    let immutable_error = sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET capture_request_digest=$1 WHERE organization_id=$2 AND object_id=$3",
    )
    .bind(vec![99_u8; 32])
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("immutable object metadata update must fail");
    assert_database_error(&immutable_error, "23514", "evidence_object_immutable_ck");

    let material_error = sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_storage_material \
         SET encrypted_data_key=$1 WHERE organization_id=$2 AND object_id=$3",
    )
    .bind(vec![99_u8; 48])
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("immutable storage material update must fail");
    assert_database_error(
        &material_error,
        "23514",
        "evidence_object_storage_material_immutable_ck",
    );

    let illegal_transition_error = sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET object_state='deleted', lifecycle_revision=3, delete_request_revision=3, \
             access_denied_at_unix_ms=$1, delete_requested_at_unix_ms=$1, \
             storage_purged_at_unix_ms=$1+1, purged_at_unix_ms=$1+2, \
             delete_reason='schema_test' \
         WHERE organization_id=$2 AND object_id=$3",
    )
    .bind(now_unix_ms + 1)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await
    .expect_err("uploading-to-deleted transition must fail");
    assert_database_error(
        &illegal_transition_error,
        "23514",
        "evidence_object_transition_ck",
    );

    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_targets (\
            organization_id, component_id, principal_kind, principal_id, required, \
            registered_at_unix_ms\
         ) VALUES (\
            $1,'projection_schema','workload','projection_schema_principal',true,$2\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(now_unix_ms)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_credentials (\
            organization_id, component_id, principal_kind, principal_id, credential_id, \
            credential_epoch, credential_digest, effective_at_unix_ms, expires_at_unix_ms, \
            created_at_unix_ms\
         ) VALUES (\
            $1,'projection_schema','workload','projection_schema_principal', \
            'projection_schema_credential',1,$2,$3,$4,$3\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![77_u8; 32])
    .bind(now_unix_ms - 1_000)
    .bind(now_unix_ms + 600_000)
    .execute(&pool)
    .await?;
    let arbitrary_ack_error = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_acknowledgements (\
            organization_id, object_id, component_id, lifecycle_revision, \
            principal_kind, principal_id, credential_id, credential_epoch, \
            presented_credential_digest, acknowledged_at_unix_ms\
         ) VALUES (\
            $1,$2,'projection_schema',999,'workload','projection_schema_principal', \
            'projection_schema_credential',1,$3,$4\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .bind(vec![77_u8; 32])
    .bind(now_unix_ms + 1)
    .execute(&pool)
    .await
    .expect_err("acknowledgement without a snapshotted requirement must fail");
    assert_database_error(
        &arbitrary_ack_error,
        "23503",
        "evidence_object_deletion_ack_requirement_fk",
    );

    // Quota is checked after the rate reservation in the same statement. A
    // rejected quota attempt must roll both counter changes back atomically.
    let quota_bypass = ObjectRow::new("object_quota_bypass", 600, now_unix_ms, 46);
    expect_object_insert_error(
        &pool,
        &quota_bypass,
        "23514",
        Some("evidence_object_quota_ck"),
    )
    .await?;

    let object_b = ObjectRow::new("object_schema_b", 1, now_unix_ms, 47);
    insert_valid_object(&pool, &object_b, 47).await?;
    let mut transaction = pool.begin().await?;
    insert_evidence_event_for_object(
        &mut transaction,
        &object_b,
        "event_schema_non_available",
        2,
        5,
        database_now_unix_ms(&pool).await?,
    )
    .await?;
    let non_available_link_error = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_event_objects (\
            organization_id, run_id, source_registration_id, source_stream_id, source_id, \
            source_event_id, object_id, lease_digest, required_source_capability, payload_type, \
            payload_version, content_digest, content_size_bytes, bound_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_b.run_id)
    .bind(&object_b.source_registration_id)
    .bind(&object_b.source_stream_id)
    .bind(&object_b.source_id)
    .bind("event_schema_non_available")
    .bind(&object_b.object_id)
    .bind(&object_b.lease_digest)
    .bind(&object_b.required_source_capability)
    .bind(PAYLOAD_TYPE)
    .bind(PAYLOAD_VERSION)
    .bind(&object_b.content_digest)
    .bind(object_b.content_size_bytes)
    .bind(1_i64)
    .execute(&mut *transaction)
    .await
    .expect_err("an uploading object must not be linked as accepted evidence");
    assert_database_error(
        &non_available_link_error,
        "23514",
        "evidence_event_object_current_authority_ck",
    );
    transaction.rollback().await?;

    let outbox_skip_attempt = sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_outbox \
         SET delivery_state='dead_letter' \
         WHERE organization_id=$1 AND object_id=$2 AND lifecycle_revision=1",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_b.object_id)
    .execute(&pool)
    .await
    .expect_err("unattempted outbox fact must not jump directly to dead letter");
    assert_database_error(
        &outbox_skip_attempt,
        "23514",
        "evidence_object_outbox_transition_ck",
    );
    let outbox_terminal_insert = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_outbox (\
            organization_id, object_id, lifecycle_revision, event_kind, event_json, \
            delivery_state, attempt_count, available_at_unix_ms, created_at_unix_ms\
         ) VALUES ($1,$2,1,'upload_reserved','{}'::jsonb,'dead_letter',0,$3,$3)",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_b.object_id)
    .bind(now_unix_ms)
    .execute(&pool)
    .await
    .expect_err("outbox history must not be inserted directly in a terminal state");
    assert_database_error(
        &outbox_terminal_insert,
        "23514",
        "evidence_object_outbox_initial_ck",
    );
    let rate_bypass = ObjectRow::new("object_rate_bypass", 1, now_unix_ms, 48);
    expect_object_insert_error(
        &pool,
        &rate_bypass,
        "23514",
        Some("evidence_object_rate_limit_ck"),
    )
    .await?;

    let (reserved_bytes, reserved_objects): (i64, i64) = sqlx::query_as(
        "SELECT reserved_bytes, reserved_objects \
         FROM apolysis_gateway.organization_object_usage WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert_eq!((reserved_bytes, reserved_objects), (513, 2));
    let accepted_uploads: i64 = sqlx::query_scalar(
        "SELECT sum(accepted_uploads)::bigint \
         FROM apolysis_gateway.evidence_object_rate_windows WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert_eq!(accepted_uploads, 2);

    let mut transaction = pool.begin().await?;
    let current_rate_window: i64 = sqlx::query_scalar(
        "INSERT INTO apolysis_gateway.evidence_object_rate_windows AS rate_window (\
            organization_id, window_start_unix_ms, accepted_uploads, updated_at_unix_ms\
         ) VALUES ($1,0,999,1) \
         ON CONFLICT (organization_id, window_start_unix_ms) DO UPDATE \
             SET accepted_uploads=rate_window.accepted_uploads+1 \
         RETURNING window_start_unix_ms",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&mut *transaction)
    .await?;
    let manipulated_rows = sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_rate_windows \
         SET accepted_uploads=accepted_uploads+1 \
         WHERE organization_id=$1 AND window_start_unix_ms=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(current_rate_window)
    .execute(&mut *transaction)
    .await?;
    assert_eq!(manipulated_rows.rows_affected(), 1);
    expect_commit_check_constraint(transaction, "evidence_object_rate_aggregate_ck").await?;

    let untrusted_future_delete_requested_at = 9_007_199_254_740_991_i64;
    let mut transaction = pool.begin().await?;
    let durable_delete_requested_at: i64 = sqlx::query_scalar(
        "UPDATE apolysis_gateway.evidence_objects \
         SET object_state='delete_pending', lifecycle_revision=3, delete_request_revision=3, \
             access_denied_at_unix_ms=$1, delete_requested_at_unix_ms=$1, \
             delete_reason='schema_test' \
         WHERE organization_id=$2 AND object_id=$3 \
         RETURNING delete_requested_at_unix_ms",
    )
    .bind(untrusted_future_delete_requested_at)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&mut *transaction)
    .await?;
    assert!(durable_delete_requested_at < untrusted_future_delete_requested_at);
    insert_outbox(
        &mut transaction,
        &object_a.object_id,
        3,
        "deletion_requested",
        durable_delete_requested_at,
    )
    .await?;
    insert_audit(
        &mut transaction,
        &object_a.object_id,
        3,
        "request_delete",
        durable_delete_requested_at,
    )
    .await?;
    transaction.commit().await?;

    let requirement_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.evidence_object_deletion_requirements \
         WHERE organization_id=$1 AND object_id=$2 AND lifecycle_revision=3",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(requirement_count, 1);

    let mut transaction = pool.begin().await?;
    let direct_ack_error = sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_acknowledgements (\
            organization_id, object_id, component_id, lifecycle_revision, \
            principal_kind, principal_id, credential_id, credential_epoch, \
            acknowledged_at_unix_ms\
         ) VALUES (\
            $1,$2,'projection_schema',3,'workload','projection_schema_principal', \
            'projection_schema_credential',1,$3\
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .bind(durable_delete_requested_at)
    .execute(&mut *transaction)
    .await
    .expect_err("direct acknowledgement without a presented credential digest must fail");
    assert_database_error(
        &direct_ack_error,
        "23514",
        "evidence_object_deletion_ack_authority_ck",
    );
    transaction.rollback().await?;

    let (stored_delete_requested_at, outbox_delete_requested_at, audit_delete_requested_at): (
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT object.delete_requested_at_unix_ms, outbox.created_at_unix_ms, \
                audit.occurred_at_unix_ms \
         FROM apolysis_gateway.evidence_objects AS object \
         JOIN apolysis_gateway.evidence_object_outbox AS outbox \
           ON outbox.organization_id=object.organization_id \
          AND outbox.object_id=object.object_id \
          AND outbox.lifecycle_revision=object.lifecycle_revision \
         JOIN apolysis_gateway.evidence_object_audit AS audit \
           ON audit.organization_id=object.organization_id \
          AND audit.object_id=object.object_id \
          AND audit.lifecycle_revision=object.lifecycle_revision \
         WHERE object.organization_id=$1 AND object.object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored_delete_requested_at, durable_delete_requested_at);
    assert_eq!(outbox_delete_requested_at, durable_delete_requested_at);
    assert_eq!(audit_delete_requested_at, durable_delete_requested_at);

    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DELETE FROM apolysis_gateway.evidence_object_storage_material \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET object_state='deleted', lifecycle_revision=4, \
             storage_purged_at_unix_ms=$1, purged_at_unix_ms=$1+1 \
         WHERE organization_id=$2 AND object_id=$3",
    )
    .bind(durable_delete_requested_at + 1)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&mut *transaction)
    .await?;
    insert_outbox(
        &mut transaction,
        &object_a.object_id,
        4,
        "object_deleted",
        durable_delete_requested_at + 2,
    )
    .await?;
    insert_audit(
        &mut transaction,
        &object_a.object_id,
        4,
        "purge_object",
        durable_delete_requested_at + 2,
    )
    .await?;
    let completion_error = transaction
        .commit()
        .await
        .expect_err("deletion with an unacknowledged requirement must fail at commit");
    assert_database_error(
        &completion_error,
        "23514",
        "evidence_object_deletion_completion_ck",
    );

    let object_state: String = sqlx::query_scalar(
        "SELECT object_state::text FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(object_state, "delete_pending");
    let storage_material_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.evidence_object_storage_material \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(storage_material_count, 1);
    let reserved_objects_after_failed_completion: i64 = sqlx::query_scalar(
        "SELECT reserved_objects FROM apolysis_gateway.organization_object_usage \
         WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert_eq!(reserved_objects_after_failed_completion, 2);

    let delete_request_time: i64 = sqlx::query_scalar(
        "SELECT delete_requested_at_unix_ms \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .fetch_one(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_deletion_targets (\
            organization_id, component_id, principal_kind, principal_id, required, \
            registered_at_unix_ms\
         ) VALUES (\
            $1,'projection_after_delete','workload','projection_after_delete_principal',true,1\
         )",
    )
    .bind(ORGANIZATION_ID)
    .execute(&pool)
    .await?;
    let late_registration_time: i64 = sqlx::query_scalar(
        "SELECT registered_at_unix_ms \
         FROM apolysis_gateway.evidence_object_deletion_targets \
         WHERE organization_id=$1 AND component_id='projection_after_delete'",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert!(late_registration_time > delete_request_time);
    sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET reap_claimed_by='schema_reaper', reap_claim_until_unix_ms=$1 \
         WHERE organization_id=$2 AND object_id=$3",
    )
    .bind(late_registration_time + 1_000)
    .bind(ORGANIZATION_ID)
    .bind(&object_a.object_id)
    .execute(&pool)
    .await?;

    Ok(())
}

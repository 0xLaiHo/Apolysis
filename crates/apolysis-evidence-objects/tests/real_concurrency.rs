// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    fs,
    str::FromStr,
    sync::{Arc, Barrier},
    time::Duration,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    EnvironmentKind, GatewayOperation, OpenRunRequest, OpenRunResponse, OrganizationId,
    PrincipalKind, PrincipalRef, PrivacyCapability, SourceCapability, SourceId, SourceKind,
    SourceRegistrationPolicy, TrustProfile,
};
use apolysis_evidence_objects::{
    AuthenticatedDeletionComponent, CaptureRequest, EvidenceObjectErrorCode,
    EvidenceObjectLifecycle, EvidenceObjectPolicy, EvidenceObjectRunLease, ObjectLifecycleConfig,
    OperatorActor,
};
use apolysis_gateway::{
    canonical_request_digest, ExecutionEvidenceGateway, OsRandomIdGenerator, SystemClock,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{retry::RetryConfig, BehaviorVersion, Region},
    primitives::ByteStream,
    types::{BucketVersioningStatus, VersioningConfiguration},
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const ORGANIZATION_ID: &str = "org_object_concurrency";
const SECONDARY_ORGANIZATION_ID: &str = "org_object_concurrency_secondary";
const SOURCE_REGISTRATION_ID: &str = "registration_object_concurrency";
const SECONDARY_SOURCE_REGISTRATION_ID: &str = "registration_object_concurrency_secondary";
const SOURCE_ID: &str = "source_object_concurrency";
const PRINCIPAL_ID: &str = "principal_object_concurrency";
const CREDENTIAL_ID: &str = "credential_object_concurrency";
const SECONDARY_CREDENTIAL_ID: &str = "credential_object_concurrency_secondary";
const PRIVACY_PROFILE: &str = "privacy_object_concurrency";
const RETENTION_PROFILE: &str = "retention_object_concurrency";
const STORAGE_BACKEND_REF: &str = "seaweedfs_concurrency_v1";
const ENCRYPTION_KEY_REF: &str = "object_concurrency_wrapping_v1";
const OPERATION_BOUND: Duration = Duration::from_secs(15);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    access_key_id: String,
    secret_access_key: String,
}

#[derive(Clone)]
struct GateEnvironment {
    database_url: String,
    endpoint: String,
    bucket: String,
    credentials: CredentialFile,
    wrapping_key: [u8; 32],
}

impl GateEnvironment {
    fn read() -> TestResult<Self> {
        let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL")?;
        let endpoint = std::env::var("APOLYSIS_TEST_S3_ENDPOINT")?;
        let bucket = std::env::var("APOLYSIS_TEST_S3_BUCKET")?;
        let credential_path = std::env::var("APOLYSIS_TEST_S3_CREDENTIAL_FILE")?;
        let wrapping_key_path = std::env::var("APOLYSIS_TEST_OBJECT_WRAPPING_KEY_FILE")?;
        let credentials: CredentialFile = serde_json::from_slice(&fs::read(credential_path)?)?;
        let wrapping_key: [u8; 32] = fs::read(wrapping_key_path)?
            .try_into()
            .map_err(|_| "wrapping key file must contain exactly 32 bytes")?;
        Ok(Self {
            database_url,
            endpoint,
            bucket,
            credentials,
            wrapping_key,
        })
    }

    fn lifecycle_config(
        &self,
        endpoint: &str,
        bucket: &str,
    ) -> Result<ObjectLifecycleConfig, apolysis_evidence_objects::EvidenceObjectError> {
        self.lifecycle_config_with_timeout(
            endpoint,
            bucket,
            Duration::from_secs(5),
            Duration::from_secs(15),
        )
    }

    fn lifecycle_config_with_timeout(
        &self,
        endpoint: &str,
        bucket: &str,
        operation_timeout: Duration,
        reaper_claim_ttl: Duration,
    ) -> Result<ObjectLifecycleConfig, apolysis_evidence_objects::EvidenceObjectError> {
        ObjectLifecycleConfig::new(
            endpoint,
            "us-east-1",
            bucket,
            STORAGE_BACKEND_REF,
            &self.credentials.access_key_id,
            &self.credentials.secret_access_key,
            ENCRYPTION_KEY_REF,
            self.wrapping_key,
            operation_timeout,
            reaper_claim_ttl,
        )
    }
}

struct Fixture {
    environment: GateEnvironment,
    pool: PgPool,
    context: AuthenticatedSourceContext,
    opened: OpenRunResponse,
    lease: EvidenceObjectRunLease,
    operator: OperatorActor,
}

impl Fixture {
    async fn new(gateway_application_name: &str) -> TestResult<Self> {
        let environment = GateEnvironment::read()?;
        if std::env::var("APOLYSIS_TEST_ALLOW_DATABASE_RESET").as_deref() != Ok("1") {
            return Err(
                "real concurrency gate requires explicit ephemeral database reset opt-in".into(),
            );
        }
        let pool = named_pool(&environment.database_url, gateway_application_name, 12).await?;
        sqlx::query("DROP SCHEMA IF EXISTS apolysis_gateway CASCADE")
            .execute(&pool)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS _sqlx_migrations")
            .execute(&pool)
            .await?;
        MIGRATOR.run(&pool).await?;
        let now = database_now(&pool).await?;
        seed_current_authority(&pool, now).await?;
        let context = source_context(now);

        let mut replay_key = [0_u8; 32];
        getrandom::fill(&mut replay_key)?;
        let repository = PostgresGatewayRepository::from_pool(
            pool.clone(),
            Arc::new(Aes256GcmReplayProtector::new(
                "object-concurrency-replay-key",
                [("object-concurrency-replay-key".to_string(), replay_key)],
            )?),
            PostgresGatewayConfig::default(),
        );
        let gateway = Arc::new(ExecutionEvidenceGateway::new(
            repository,
            SystemClock,
            OsRandomIdGenerator,
        ));
        let opened = gateway.open_run(&context, open_request("primary")).await?;
        let lease = EvidenceObjectRunLease::from_open_response(&opened)?;
        Ok(Self {
            environment,
            pool,
            context,
            opened,
            lease,
            operator: OperatorActor::new("operator_object_concurrency")?,
        })
    }

    fn lifecycle(&self, pool: PgPool, bucket: &str) -> TestResult<EvidenceObjectLifecycle> {
        Ok(EvidenceObjectLifecycle::new(
            pool.clone(),
            pool.clone(),
            pool,
            self.environment
                .lifecycle_config(&self.environment.endpoint, bucket)?,
        ))
    }

    async fn install_policy(
        &self,
        lifecycle: &EvidenceObjectLifecycle,
        revision: u64,
        max_object_size: u64,
        upload_timeout_ms: u64,
        retention_ms: u64,
    ) -> TestResult {
        lifecycle
            .install_policy(
                &self.operator,
                &EvidenceObjectPolicy::new(
                    OrganizationId::try_from(ORGANIZATION_ID)?,
                    PRIVACY_PROFILE,
                    RETENTION_PROFILE,
                    revision,
                    max_object_size,
                    8 * 1024 * 1024,
                    32,
                    64,
                    upload_timeout_ms,
                    retention_ms,
                    u64::try_from(database_now(&self.pool).await?)?,
                )?,
            )
            .await?;
        Ok(())
    }
}

async fn named_pool(database_url: &str, application_name: &str, max: u32) -> TestResult<PgPool> {
    let options = PgConnectOptions::from_str(database_url)?.application_name(application_name);
    Ok(PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options)
        .await?)
}

async fn database_now(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT apolysis_gateway.evidence_object_db_now_unix_ms()")
        .fetch_one(pool)
        .await
}

async fn wait_for_database_time_after(pool: &PgPool, observed: i64) -> TestResult<i64> {
    let deadline = tokio::time::Instant::now() + OPERATION_BOUND;
    loop {
        let now = database_now(pool).await?;
        if now > observed {
            return Ok(now);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("PostgreSQL time did not advance within its bound".into());
        }
        tokio::task::yield_now().await;
    }
}

fn source_policy() -> SourceRegistrationPolicy {
    SourceRegistrationPolicy::new(
        SourceId::try_from(SOURCE_ID).expect("source id"),
        vec![SourceKind::SemanticHook],
        vec![EnvironmentKind::CiRunnerOrRemoteWorkspace],
        vec![
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ],
        true,
        false,
    )
    .expect("source policy")
    .with_run_authorities(vec![AuthorityRef::new(
        AuthorityKind::Service,
        "authority_object_concurrency",
    )
    .expect("authority")])
    .expect("run authorities")
    .with_run_profiles(
        vec![PRIVACY_PROFILE.to_string()],
        vec![RETENTION_PROFILE.to_string()],
        vec![SourceKind::SemanticHook],
    )
    .expect("run profiles")
    .with_evidence_policy(
        TrustProfile::HarnessObserved,
        vec![SourceCapability::ToolCalls, SourceCapability::SourceHealth],
        vec![
            PrivacyCapability::StructureOnly,
            PrivacyCapability::AuthorizedContentReference,
        ],
        vec!["redaction_object_concurrency".to_string()],
    )
    .expect("evidence policy")
    .with_finalization_permission(true)
}

fn source_context(now: i64) -> AuthenticatedSourceContext {
    source_context_for(ORGANIZATION_ID, SOURCE_REGISTRATION_ID, CREDENTIAL_ID, now)
}

fn source_context_for(
    organization_id: &str,
    source_registration_id: &str,
    credential_id: &str,
    now: i64,
) -> AuthenticatedSourceContext {
    let now = u64::try_from(now).expect("positive database time");
    AuthenticatedSourceContext::new(
        OrganizationId::try_from(organization_id).expect("organization id"),
        PrincipalRef::new(PrincipalKind::Workload, PRINCIPAL_ID).expect("principal"),
        source_registration_id,
        AuthenticationSnapshot::new(credential_id, 1, now - 1_000, now + 3_600_000)
            .expect("authentication snapshot"),
        source_policy(),
    )
    .expect("authenticated context")
}

async fn seed_current_authority(pool: &PgPool, now: i64) -> TestResult {
    seed_authority(
        pool,
        now,
        ORGANIZATION_ID,
        SOURCE_REGISTRATION_ID,
        CREDENTIAL_ID,
    )
    .await
}

async fn seed_authority(
    pool: &PgPool,
    now: i64,
    organization_id: &str,
    source_registration_id: &str,
    credential_id: &str,
) -> TestResult {
    sqlx::query(
        "INSERT INTO apolysis_gateway.organizations (\
            organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,'active',$2,$2)",
    )
    .bind(organization_id)
    .bind(now)
    .execute(pool)
    .await?;
    let policy = json!({
        "source_id": SOURCE_ID,
        "allowed_source_kinds": ["semantic_hook"],
        "allowed_environments": ["ci_runner_or_remote_workspace"],
        "allowed_operations": ["bind_runtime", "ingest", "finish_run"],
        "effective_trust_profile": "harness_observed",
        "allowed_capabilities": ["tool_calls", "source_health"],
        "allowed_privacy_capabilities": ["structure_only", "authorized_content_reference"],
        "allowed_redaction_profile_refs": ["redaction_object_concurrency"],
        "allowed_run_authorities": [{"kind": "service", "id": "authority_object_concurrency"}],
        "allowed_run_privacy_profile_refs": [PRIVACY_PROFILE],
        "allowed_run_retention_profile_refs": [RETENTION_PROFILE],
        "required_run_source_kinds": ["semantic_hook"],
        "may_create_runs": true,
        "may_join_runs": false,
        "may_finalize_runs": true
    });
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_registrations (\
            source_registration_id, organization_id, source_id, principal_kind, principal_id, \
            registration_state, policy_revision, credential_epoch, effective_at_unix_ms, \
            expires_at_unix_ms, policy_document, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,'workload',$4,'active',1,1,$5,$6,$7,$5,$5)",
    )
    .bind(source_registration_id)
    .bind(organization_id)
    .bind(SOURCE_ID)
    .bind(PRINCIPAL_ID)
    .bind(now - 60_000)
    .bind(now + 3_600_000)
    .bind(policy)
    .execute(pool)
    .await?;
    let mut fingerprint = [0_u8; 32];
    getrandom::fill(&mut fingerprint)?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.transport_credentials (\
            credential_id, certificate_fingerprint, organization_id, source_registration_id, \
            credential_epoch, effective_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms, \
            revocation_reason, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,1,$5,$6,NULL,NULL,$5,$5)",
    )
    .bind(credential_id)
    .bind(fingerprint.as_slice())
    .bind(organization_id)
    .bind(source_registration_id)
    .bind(now - 60_000)
    .bind(now + 3_600_000)
    .execute(pool)
    .await?;
    Ok(())
}

fn open_request(suffix: &str) -> OpenRunRequest {
    let mut wire = json!({
        "schema_version": "0.1",
        "mode": "create",
        "client_operation_id": format!("operation_object_concurrency_open_{suffix}"),
        "request_digest": "0".repeat(64),
        "client_run_key": format!("object_concurrency_run_{suffix}"),
        "environment": "ci_runner_or_remote_workspace",
        "authority": {"kind": "service", "id": "authority_object_concurrency"},
        "principal": {"kind": "workload", "id": PRINCIPAL_ID},
        "objective_ref": format!("objective_object_concurrency_{suffix}"),
        "privacy_profile_ref": PRIVACY_PROFILE,
        "retention_profile_ref": RETENTION_PROFILE,
        "expected_source_kinds": ["semantic_hook"],
        "source_manifest": {
            "schema_version": "0.1",
            "source_id": SOURCE_ID,
            "source_kind": "semantic_hook",
            "declared_boundary": "agent_harness",
            "adapter_name": "real_object_concurrency",
            "adapter_version": "1.0.0",
            "environment": "ci_runner_or_remote_workspace",
            "capabilities": ["tool_calls", "source_health"],
            "expected_lifecycle": ["started", "finished"],
            "ordering": "strict_per_stream",
            "samples": false,
            "redaction_profile_ref": "redaction_object_concurrency",
            "redacted_fields": ["payload.content"],
            "privacy_capabilities": ["structure_only", "authorized_content_reference"]
        }
    });
    let unsigned: OpenRunRequest = serde_json::from_value(wire.clone()).expect("open request");
    wire["request_digest"] =
        json!(canonical_request_digest("open_run", &unsigned).expect("open digest"));
    serde_json::from_value(wire).expect("signed open request")
}

fn random_payload(size: usize) -> Vec<u8> {
    let mut value = vec![0_u8; size];
    getrandom::fill(&mut value).expect("OS random payload");
    value
}

fn payload_digest(payload: &[u8]) -> String {
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn capture_request(
    opened: &OpenRunResponse,
    upload_id: &str,
    payload: &[u8],
    retention_ms: u64,
) -> CaptureRequest {
    CaptureRequest::new(
        opened.run_id().clone(),
        opened.source_stream_id(),
        upload_id,
        SourceCapability::ToolCalls,
        "tool_interaction_blob",
        "1.0.0",
        payload_digest(payload),
        payload.len() as u64,
        retention_ms,
    )
    .expect("capture request")
}

fn raw_s3_client(environment: &GateEnvironment) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(&environment.endpoint)
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(
            environment.credentials.access_key_id.clone(),
            environment.credentials.secret_access_key.clone(),
            None,
            None,
            "apolysis-real-concurrency",
        ))
        .force_path_style(true)
        .retry_config(RetryConfig::standard().with_max_attempts(1))
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn enable_versioning(client: &aws_sdk_s3::Client, bucket: &str) -> TestResult {
    tokio::time::timeout(
        OPERATION_BOUND,
        client
            .put_bucket_versioning()
            .bucket(bucket)
            .versioning_configuration(
                VersioningConfiguration::builder()
                    .status(BucketVersioningStatus::Enabled)
                    .build(),
            )
            .send(),
    )
    .await
    .map_err(|_| "S3 versioning operation exceeded its bound")??;
    Ok(())
}

async fn version_count(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> TestResult<usize> {
    let listed = tokio::time::timeout(
        OPERATION_BOUND,
        client
            .list_object_versions()
            .bucket(bucket)
            .prefix(key)
            .send(),
    )
    .await
    .map_err(|_| "S3 version listing exceeded its bound")??;
    Ok(listed
        .versions()
        .iter()
        .filter(|version| version.key() == Some(key))
        .count()
        + listed
            .delete_markers()
            .iter()
            .filter(|marker| marker.key() == Some(key))
            .count())
}

async fn assert_only_purge_barrier(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
) -> TestResult {
    assert_eq!(version_count(client, bucket, key).await?, 1);
    let head = tokio::time::timeout(
        OPERATION_BOUND,
        client.head_object().bucket(bucket).key(key).send(),
    )
    .await
    .map_err(|_| "S3 purge-barrier probe exceeded its bound")??;
    assert_eq!(head.content_length(), Some(0));
    assert_eq!(
        head.metadata()
            .and_then(|metadata| metadata.get("apolysis-purge-barrier"))
            .map(String::as_str),
        Some("1")
    );
    Ok(())
}

async fn storage_key(pool: &PgPool, object_id: &str) -> TestResult<String> {
    Ok(sqlx::query_scalar(
        "SELECT storage_key FROM apolysis_gateway.evidence_object_storage_material \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_id)
    .fetch_one(pool)
    .await?)
}

async fn delete_and_reap(
    fixture: &Fixture,
    lifecycle: &EvidenceObjectLifecycle,
    object_ids: &[&str],
) -> TestResult {
    for object_id in object_ids {
        lifecycle
            .request_delete(&fixture.context, object_id, "concurrency_cleanup")
            .await?;
    }

    // A reaper batch intentionally claims at most one object per organization.
    // Keep cleanup bounded while verifying the requested objects themselves,
    // rather than assuming one oversized batch can purge a whole tenant queue.
    for _ in 0..object_ids.len() {
        lifecycle.reap_once("reaper_object_concurrency", 64).await?;

        let mut deleted = 0;
        for object_id in object_ids {
            let state: String = sqlx::query_scalar(
                "SELECT object_state::text FROM apolysis_gateway.evidence_objects \
                 WHERE organization_id=$1 AND object_id=$2",
            )
            .bind(ORGANIZATION_ID)
            .bind(*object_id)
            .fetch_one(&fixture.pool)
            .await?;
            deleted += usize::from(state == "deleted");
        }
        if deleted == object_ids.len() {
            return Ok(());
        }
    }

    Err(format!(
        "cleanup did not delete all {} objects within its bounded reaper passes",
        object_ids.len()
    )
    .into())
}

fn deletion_component(
    epoch: u64,
    credential_id: &str,
    credential_digest: [u8; 32],
    now: u64,
) -> Result<AuthenticatedDeletionComponent, apolysis_evidence_objects::EvidenceObjectError> {
    AuthenticatedDeletionComponent::new(
        OrganizationId::try_from(ORGANIZATION_ID).expect("organization id"),
        "projection_object_concurrency",
        PrincipalKind::Workload,
        "principal_projection_object_concurrency",
        credential_id,
        epoch,
        credential_digest,
        now.saturating_sub(1_000),
        now + 3_600_000,
    )
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    let database = error
        .as_database_error()
        .expect("PostgreSQL constraint error");
    assert_eq!(database.code().as_deref(), Some("23514"), "{error}");
    assert_eq!(database.constraint(), Some(expected), "{error}");
}

async fn wait_for_reserve_barrier(pool: &PgPool, applications: &[&str]) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE application_name=ANY($1::text[]) AND wait_event_type='Lock'",
        )
        .bind(applications)
        .fetch_one(pool)
        .await?;
        let at_insert: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
              WHERE application_name=ANY($1::text[]) \
                AND position('INSERT INTO apolysis_gateway.evidence_objects' in query)>0)",
        )
        .bind(applications)
        .fetch_one(pool)
        .await?;
        if waiting == i64::try_from(applications.len())? && at_insert {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "reserve sessions did not reach deterministic barriers: waiting={waiting}, insert={at_insert}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn concurrent_same_upload_identity_admits_exactly_one_object() -> TestResult {
    let fixture = Fixture::new("apolysis_concurrency_setup").await?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    let pool_a = named_pool(&fixture.environment.database_url, "apolysis_reserve_a", 2).await?;
    let pool_b = named_pool(&fixture.environment.database_url, "apolysis_reserve_b", 2).await?;
    let lifecycle_a = fixture.lifecycle(pool_a, &fixture.environment.bucket)?;
    let lifecycle_b = fixture.lifecycle(pool_b, &fixture.environment.bucket)?;
    fixture
        .install_policy(&lifecycle_a, 1, 1024 * 1024, 30_000, 180_000)
        .await?;

    sqlx::query(
        "CREATE FUNCTION apolysis_gateway.test_reserve_barrier() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF current_setting('application_name', true) LIKE 'apolysis_reserve_%' THEN \
             PERFORM pg_advisory_xact_lock(76001, 1); \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&fixture.pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER aaa_test_reserve_barrier BEFORE INSERT \
         ON apolysis_gateway.evidence_objects FOR EACH ROW \
         EXECUTE FUNCTION apolysis_gateway.test_reserve_barrier()",
    )
    .execute(&fixture.pool)
    .await?;
    let mut controller = fixture.pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock(76001, 1)")
        .execute(&mut *controller)
        .await?;

    let payload = random_payload(48 * 1024);
    let request = capture_request(
        &fixture.opened,
        "upload_concurrent_identical",
        &payload,
        120_000,
    );
    let start = Arc::new(Barrier::new(3));
    let task_a = {
        let start = start.clone();
        let context = fixture.context.clone();
        let lease = fixture.lease.clone();
        let request = request.clone();
        tokio::spawn(async move {
            start.wait();
            lifecycle_a.begin_upload(&context, &lease, &request).await
        })
    };
    let task_b = {
        let start = start.clone();
        let context = fixture.context.clone();
        let lease = fixture.lease.clone();
        let request = request.clone();
        tokio::spawn(async move {
            start.wait();
            lifecycle_b.begin_upload(&context, &lease, &request).await
        })
    };
    start.wait();
    let barrier_result =
        wait_for_reserve_barrier(&fixture.pool, &["apolysis_reserve_a", "apolysis_reserve_b"])
            .await;
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(76001, 1)")
        .fetch_one(&mut *controller)
        .await?;
    assert!(
        unlocked,
        "controller must release the deterministic test lock"
    );
    drop(controller);
    barrier_result?;

    let first = tokio::time::timeout(OPERATION_BOUND, task_a)
        .await
        .map_err(|_| "first concurrent reserve exceeded its bound")???;
    let second = tokio::time::timeout(OPERATION_BOUND, task_b)
        .await
        .map_err(|_| "second concurrent reserve exceeded its bound")???;
    assert_eq!(first.object_id(), second.object_id());

    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM apolysis_gateway.evidence_objects \
             WHERE organization_id=$1 AND client_upload_id=$2), \
           (SELECT count(*) FROM apolysis_gateway.evidence_object_storage_material \
             WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.evidence_object_outbox \
             WHERE organization_id=$1), \
           (SELECT reserved_objects FROM apolysis_gateway.organization_object_usage \
             WHERE organization_id=$1), \
           (SELECT sum(accepted_uploads)::bigint \
              FROM apolysis_gateway.evidence_object_rate_windows WHERE organization_id=$1)",
    )
    .bind(ORGANIZATION_ID)
    .bind("upload_concurrent_identical")
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(counts, (1, 1, 1, 1, 1));

    let created_at: i64 = sqlx::query_scalar(
        "SELECT created_at_unix_ms FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(first.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    let db_now = database_now(&fixture.pool).await?;
    assert!(created_at <= db_now && db_now - created_at < 10_000);

    let usage_rewrite = sqlx::query(
        "UPDATE apolysis_gateway.organization_object_usage \
         SET reserved_bytes=0, reserved_objects=0 WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .execute(&fixture.pool)
    .await
    .expect_err("usage counter reset must fail");
    assert_constraint(&usage_rewrite, "evidence_object_usage_aggregate_ck");
    let rate_rewrite = sqlx::query(
        "UPDATE apolysis_gateway.evidence_object_rate_windows \
         SET accepted_uploads=accepted_uploads+1 \
         WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .execute(&fixture.pool)
    .await
    .expect_err("rate counter reset must fail");
    assert_constraint(&rate_rewrite, "evidence_object_rate_aggregate_ck");

    sqlx::query("DROP TRIGGER aaa_test_reserve_barrier ON apolysis_gateway.evidence_objects")
        .execute(&fixture.pool)
        .await?;
    sqlx::query("DROP FUNCTION apolysis_gateway.test_reserve_barrier()")
        .execute(&fixture.pool)
        .await?;
    let lifecycle = fixture.lifecycle(fixture.pool.clone(), &fixture.environment.bucket)?;
    delete_and_reap(&fixture, &lifecycle, &[first.object_id()]).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn served_transactions_bound_database_lock_waits() -> TestResult {
    let fixture = Fixture::new("apolysis_database_deadline_setup").await?;
    let operation_timeout = Duration::from_millis(250);
    let deadline_pool = named_pool(
        &fixture.environment.database_url,
        "apolysis_database_deadline_runtime",
        1,
    )
    .await?;
    let lifecycle = EvidenceObjectLifecycle::new(
        deadline_pool.clone(),
        deadline_pool.clone(),
        deadline_pool.clone(),
        fixture.environment.lifecycle_config_with_timeout(
            &fixture.environment.endpoint,
            &fixture.environment.bucket,
            operation_timeout,
            Duration::from_secs(1),
        )?,
    );

    let mut blocker = fixture.pool.begin().await?;
    sqlx::query(
        "SELECT organization_id FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(ORGANIZATION_ID)
    .execute(&mut *blocker)
    .await?;

    let policy = EvidenceObjectPolicy::new(
        OrganizationId::try_from(ORGANIZATION_ID)?,
        PRIVACY_PROFILE,
        RETENTION_PROFILE,
        1,
        1024 * 1024,
        8 * 1024 * 1024,
        32,
        64,
        30_000,
        180_000,
        u64::try_from(database_now(&fixture.pool).await?)?,
    )?;
    let started = tokio::time::Instant::now();
    let failure = tokio::time::timeout(
        Duration::from_secs(1),
        lifecycle.install_policy(&fixture.operator, &policy),
    )
    .await
    .map_err(|_| "database lock wait exceeded its configured deadline")?
    .expect_err("blocked lifecycle transaction must fail closed at its database deadline");
    assert_eq!(failure.code(), EvidenceObjectErrorCode::DatabaseUnavailable);
    assert!(failure.retryable());
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "database lock wait did not exercise the configured deadline"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "database lock wait was not bounded"
    );
    blocker.rollback().await?;
    let reset_settings: (String, String) = sqlx::query_as(
        "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')",
    )
    .fetch_one(&deadline_pool)
    .await?;
    assert_eq!(reset_settings, ("0".to_string(), "0".to_string()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn reaper_claim_obeys_organization_before_object_lock_order() -> TestResult {
    const REAPER_APPLICATION: &str = "apolysis_reaper_lock_order";

    let fixture = Fixture::new("apolysis_reaper_lock_setup").await?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    let lifecycle = fixture.lifecycle(fixture.pool.clone(), &fixture.environment.bucket)?;
    fixture
        .install_policy(&lifecycle, 1, 1024 * 1024, 1_000, 30_000)
        .await?;
    let payload = random_payload(32 * 1024);
    let request = capture_request(
        &fixture.opened,
        "upload_reaper_lock_order",
        &payload,
        20_000,
    );
    let pending = lifecycle
        .begin_upload(&fixture.context, &fixture.lease, &request)
        .await?;
    let expiry_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let reap_eligible: bool = sqlx::query_scalar(
            "SELECT upload_deadline_unix_ms <= \
                    apolysis_gateway.evidence_object_db_now_unix_ms() \
             FROM apolysis_gateway.evidence_objects \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(ORGANIZATION_ID)
        .bind(pending.object_id())
        .fetch_one(&fixture.pool)
        .await?;
        if reap_eligible {
            break;
        }
        if tokio::time::Instant::now() >= expiry_deadline {
            return Err("upload did not become reaper-eligible within bounds".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut controller = fixture.pool.begin().await?;
    sqlx::query(
        "SELECT organization_id FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 FOR UPDATE",
    )
    .bind(ORGANIZATION_ID)
    .execute(&mut *controller)
    .await?;

    let reaper_pool = named_pool(&fixture.environment.database_url, REAPER_APPLICATION, 2).await?;
    let reaper = fixture.lifecycle(reaper_pool, &fixture.environment.bucket)?;
    let mut reaper_task =
        tokio::spawn(async move { reaper.reap_once("reaper_lock_order", 1).await });
    let observation_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let reaper_waited = loop {
        if reaper_task.is_finished() {
            break false;
        }
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
             WHERE application_name=$1 AND wait_event_type='Lock')",
        )
        .bind(REAPER_APPLICATION)
        .fetch_one(&fixture.pool)
        .await?;
        if waiting {
            break true;
        }
        if tokio::time::Instant::now() >= observation_deadline {
            return Err("reaper neither skipped nor reached its organization lock barrier".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let object_lock = tokio::time::timeout(
        OPERATION_BOUND,
        sqlx::query(
            "SELECT object_id FROM apolysis_gateway.evidence_objects \
             WHERE organization_id=$1 AND object_id=$2 FOR UPDATE",
        )
        .bind(ORGANIZATION_ID)
        .bind(pending.object_id())
        .execute(&mut *controller),
    )
    .await
    .map_err(|_| "controller object lock exceeded its bound")?;
    controller.commit().await?;
    object_lock?;

    let mut report = tokio::time::timeout(OPERATION_BOUND, &mut reaper_task)
        .await
        .map_err(|_| "reaper lock-order regression exceeded its bound")???;
    if !reaper_waited {
        assert_eq!(report.claimed, 0, "busy organizations must be skipped");
        report = lifecycle.reap_once("reaper_lock_order_retry", 1).await?;
    }
    assert_eq!(report.claimed, 1);
    assert_eq!(report.purged, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn reaper_batch_claims_at_most_one_object_per_organization() -> TestResult {
    const WORKER_ID: &str = "reaper_per_organization_fairness";

    let fixture = Fixture::new("apolysis_reaper_fairness_setup").await?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    let lifecycle = fixture.lifecycle(fixture.pool.clone(), &fixture.environment.bucket)?;
    fixture
        .install_policy(&lifecycle, 1, 1024 * 1024, 30_000, 180_000)
        .await?;

    let authority_time = database_now(&fixture.pool).await?;
    seed_authority(
        &fixture.pool,
        authority_time,
        SECONDARY_ORGANIZATION_ID,
        SECONDARY_SOURCE_REGISTRATION_ID,
        SECONDARY_CREDENTIAL_ID,
    )
    .await?;
    let secondary_context = source_context_for(
        SECONDARY_ORGANIZATION_ID,
        SECONDARY_SOURCE_REGISTRATION_ID,
        SECONDARY_CREDENTIAL_ID,
        authority_time,
    );
    let mut replay_key = [0_u8; 32];
    getrandom::fill(&mut replay_key)?;
    let secondary_repository = PostgresGatewayRepository::from_pool(
        fixture.pool.clone(),
        Arc::new(Aes256GcmReplayProtector::new(
            "object-concurrency-fairness-replay-key",
            [(
                "object-concurrency-fairness-replay-key".to_string(),
                replay_key,
            )],
        )?),
        PostgresGatewayConfig::default(),
    );
    let secondary_gateway =
        ExecutionEvidenceGateway::new(secondary_repository, SystemClock, OsRandomIdGenerator);
    let secondary_opened = secondary_gateway
        .open_run(&secondary_context, open_request("fairness_secondary"))
        .await?;
    let secondary_lease = EvidenceObjectRunLease::from_open_response(&secondary_opened)?;
    lifecycle
        .install_policy(
            &fixture.operator,
            &EvidenceObjectPolicy::new(
                OrganizationId::try_from(SECONDARY_ORGANIZATION_ID)?,
                PRIVACY_PROFILE,
                RETENTION_PROFILE,
                1,
                1024 * 1024,
                8 * 1024 * 1024,
                32,
                64,
                30_000,
                180_000,
                u64::try_from(database_now(&fixture.pool).await?)?,
            )?,
        )
        .await?;

    let primary_payload_one = random_payload(24 * 1024);
    let primary_one = lifecycle
        .capture(
            &fixture.context,
            &fixture.lease,
            &capture_request(
                &fixture.opened,
                "upload_reaper_fairness_primary_one",
                &primary_payload_one,
                120_000,
            ),
            Bytes::from(primary_payload_one),
        )
        .await?;
    let primary_payload_two = random_payload(24 * 1024);
    let primary_two = lifecycle
        .capture(
            &fixture.context,
            &fixture.lease,
            &capture_request(
                &fixture.opened,
                "upload_reaper_fairness_primary_two",
                &primary_payload_two,
                120_000,
            ),
            Bytes::from(primary_payload_two),
        )
        .await?;
    for object_id in [primary_one.object_id(), primary_two.object_id()] {
        lifecycle
            .request_delete(&fixture.context, object_id, "reaper_fairness")
            .await?;
    }
    let primary_delete_cutoff: i64 = sqlx::query_scalar(
        "SELECT max(delete_requested_at_unix_ms) \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=ANY($2::text[])",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![primary_one.object_id(), primary_two.object_id()])
    .fetch_one(&fixture.pool)
    .await?;
    wait_for_database_time_after(&fixture.pool, primary_delete_cutoff).await?;

    let secondary_payload = random_payload(24 * 1024);
    let secondary = lifecycle
        .capture(
            &secondary_context,
            &secondary_lease,
            &capture_request(
                &secondary_opened,
                "upload_reaper_fairness_secondary",
                &secondary_payload,
                120_000,
            ),
            Bytes::from(secondary_payload),
        )
        .await?;
    lifecycle
        .request_delete(&secondary_context, secondary.object_id(), "reaper_fairness")
        .await?;
    let secondary_delete_time: i64 = sqlx::query_scalar(
        "SELECT delete_requested_at_unix_ms \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(SECONDARY_ORGANIZATION_ID)
    .bind(secondary.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert!(secondary_delete_time > primary_delete_cutoff);

    let primary_one_key = storage_key(&fixture.pool, primary_one.object_id()).await?;
    let primary_two_key = storage_key(&fixture.pool, primary_two.object_id()).await?;
    let secondary_key: String = sqlx::query_scalar(
        "SELECT storage_key FROM apolysis_gateway.evidence_object_storage_material \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(SECONDARY_ORGANIZATION_ID)
    .bind(secondary.object_id())
    .fetch_one(&fixture.pool)
    .await?;

    let report = lifecycle.reap_once(WORKER_ID, 2).await?;
    assert_eq!(report.claimed, 2);
    assert_eq!(report.purged, 2);
    assert_eq!(report.deferred, 0);

    let primary_states: (i64, i64) = sqlx::query_as(
        "SELECT \
             count(*) FILTER (WHERE object_state='deleted'), \
             count(*) FILTER (WHERE object_state='delete_pending') \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=ANY($2::text[])",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![primary_one.object_id(), primary_two.object_id()])
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(primary_states, (1, 1));
    let secondary_state: String = sqlx::query_scalar(
        "SELECT object_state::text FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(SECONDARY_ORGANIZATION_ID)
    .bind(secondary.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(secondary_state, "deleted");
    let completed_organizations: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT organization_id FROM apolysis_gateway.evidence_object_audit \
         WHERE actor_id=$1 AND action='purge_object' AND decision='completed' \
         ORDER BY organization_id",
    )
    .bind(WORKER_ID)
    .fetch_all(&fixture.pool)
    .await?;
    assert_eq!(
        completed_organizations,
        vec![
            ORGANIZATION_ID.to_string(),
            SECONDARY_ORGANIZATION_ID.to_string()
        ]
    );

    let deleted_primary_id: String = sqlx::query_scalar(
        "SELECT object_id FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=ANY($2::text[]) AND object_state='deleted'",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![primary_one.object_id(), primary_two.object_id()])
    .fetch_one(&fixture.pool)
    .await?;
    let deleted_primary_key = if deleted_primary_id == primary_one.object_id() {
        &primary_one_key
    } else {
        assert_eq!(deleted_primary_id, primary_two.object_id());
        &primary_two_key
    };
    assert_only_purge_barrier(&raw, &fixture.environment.bucket, deleted_primary_key).await?;
    assert_only_purge_barrier(&raw, &fixture.environment.bucket, &secondary_key).await?;

    let cleanup = lifecycle.reap_once("reaper_fairness_cleanup", 2).await?;
    assert_eq!(cleanup.claimed, 1);
    assert_eq!(cleanup.purged, 1);
    let remaining_primary_key = if deleted_primary_id == primary_one.object_id() {
        primary_two_key
    } else {
        primary_one_key
    };
    assert_only_purge_barrier(&raw, &fixture.environment.bucket, &remaining_primary_key).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn expired_reaper_attempt_is_fenced_before_database_commit() -> TestResult {
    const FIRST_WORKER: &str = "reaper_expired_fence_first";
    const REASSIGNED_WORKER: &str = "reaper_expired_fence_second";
    const FINAL_WORKER: &str = "reaper_expired_fence_final";
    const EXTRA_CIPHERTEXT_VERSIONS: usize = 1_024;
    const SHORT_CLAIM: Duration = Duration::from_secs(1);
    const REAPER_BOUND: Duration = Duration::from_secs(60);

    let fixture = Fixture::new("apolysis_reaper_expired_fence").await?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    let lifecycle = EvidenceObjectLifecycle::new(
        fixture.pool.clone(),
        fixture.pool.clone(),
        fixture.pool.clone(),
        fixture.environment.lifecycle_config_with_timeout(
            &fixture.environment.endpoint,
            &fixture.environment.bucket,
            SHORT_CLAIM,
            SHORT_CLAIM,
        )?,
    );
    fixture
        .install_policy(&lifecycle, 1, 1024 * 1024, 30_000, 180_000)
        .await?;
    let payload = random_payload(16 * 1024);
    let request = capture_request(
        &fixture.opened,
        "upload_reaper_expired_fence",
        &payload,
        120_000,
    );
    let object_ref = lifecycle
        .capture(
            &fixture.context,
            &fixture.lease,
            &request,
            Bytes::from(payload),
        )
        .await?;
    let key = storage_key(&fixture.pool, object_ref.object_id()).await?;
    for _ in 0..EXTRA_CIPHERTEXT_VERSIONS {
        tokio::time::timeout(
            OPERATION_BOUND,
            raw.put_object()
                .bucket(&fixture.environment.bucket)
                .key(&key)
                .body(ByteStream::from_static(b"expired-claim-ciphertext"))
                .send(),
        )
        .await
        .map_err(|_| "real version setup exceeded its per-operation bound")??;
    }
    lifecycle
        .request_delete(
            &fixture.context,
            object_ref.object_id(),
            "expired_reaper_claim",
        )
        .await?;

    let first_lifecycle = lifecycle.clone();
    let mut first_task =
        tokio::spawn(async move { first_lifecycle.reap_once(FIRST_WORKER, 1).await });
    let observation_deadline = tokio::time::Instant::now() + OPERATION_BOUND;
    let (first_claimed_at, first_claim_until): (i64, i64) = loop {
        let claim: Option<(i64, i64)> = sqlx::query_as(
            "SELECT reap_claimed_at_unix_ms, reap_claim_until_unix_ms \
             FROM apolysis_gateway.evidence_objects \
             WHERE organization_id=$1 AND object_id=$2 AND reap_claimed_by=$3",
        )
        .bind(ORGANIZATION_ID)
        .bind(object_ref.object_id())
        .bind(FIRST_WORKER)
        .fetch_optional(&fixture.pool)
        .await?;
        if let Some(claim) = claim {
            break claim;
        }
        if first_task.is_finished() || tokio::time::Instant::now() >= observation_deadline {
            return Err("first reaper did not expose its committed claim before S3 purge".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    while database_now(&fixture.pool).await? < first_claim_until {
        if first_task.is_finished() {
            return Err("real S3 purge did not outlive the short reaper claim".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let reassigned: (i64, i64) = sqlx::query_as(
        "UPDATE apolysis_gateway.evidence_objects \
         SET reap_claimed_by=$4, \
             reap_claim_until_unix_ms=apolysis_gateway.evidence_object_db_now_unix_ms()+$5 \
         WHERE organization_id=$1 AND object_id=$2 AND reap_claimed_by=$3 \
           AND reap_claimed_at_unix_ms=$6 \
           AND reap_claim_until_unix_ms<=apolysis_gateway.evidence_object_db_now_unix_ms() \
         RETURNING reap_claimed_at_unix_ms, reap_claim_until_unix_ms",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .bind(FIRST_WORKER)
    .bind(REASSIGNED_WORKER)
    .bind(i64::try_from(SHORT_CLAIM.as_millis())?)
    .bind(first_claimed_at)
    .fetch_one(&fixture.pool)
    .await?;
    assert_ne!(reassigned.0, first_claimed_at);

    let first_report = tokio::time::timeout(REAPER_BOUND, &mut first_task)
        .await
        .map_err(|_| "stale real-provider reaper did not finish within bounds")???;
    assert_eq!(first_report.claimed, 1);
    assert_eq!(first_report.purged, 0);
    assert_eq!(first_report.deferred, 1);
    let fenced_state: (
        String,
        bool,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT object_state::text, \
                EXISTS (SELECT 1 FROM apolysis_gateway.evidence_object_storage_material \
                        WHERE organization_id=$1 AND object_id=$2), \
                storage_purged_at_unix_ms, reap_claimed_by, \
                reap_claimed_at_unix_ms, reap_claim_until_unix_ms \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(
        fenced_state,
        (
            "delete_pending".to_string(),
            true,
            None,
            Some(REASSIGNED_WORKER.to_string()),
            Some(reassigned.0),
            Some(reassigned.1),
        )
    );
    let stale_completed_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.evidence_object_audit \
         WHERE organization_id=$1 AND object_id=$2 AND actor_id=$3 \
           AND action='purge_object' AND decision='completed'",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .bind(FIRST_WORKER)
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(stale_completed_audits, 0);

    while database_now(&fixture.pool).await? < reassigned.1 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let final_report = lifecycle.reap_once(FINAL_WORKER, 1).await?;
    assert_eq!(final_report.claimed, 1);
    assert_eq!(final_report.purged, 1);
    assert_only_purge_barrier(&raw, &fixture.environment.bucket, &key).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn policy_tightening_before_finalize_is_fail_closed() -> TestResult {
    let fixture = Fixture::new("apolysis_policy_tightening").await?;
    let lifecycle = fixture.lifecycle(fixture.pool.clone(), &fixture.environment.bucket)?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    fixture
        .install_policy(&lifecycle, 1, 1024 * 1024, 30_000, 180_000)
        .await?;

    let large_payload = random_payload(128 * 1024);
    let large_request = capture_request(
        &fixture.opened,
        "upload_policy_tightening_large",
        &large_payload,
        120_000,
    );
    let pending = lifecycle
        .begin_upload(&fixture.context, &fixture.lease, &large_request)
        .await?;
    let uploaded = lifecycle
        .upload_pending(
            &fixture.context,
            &fixture.lease,
            &pending,
            Bytes::from(large_payload),
        )
        .await?;
    let large_key = storage_key(&fixture.pool, pending.object_id()).await?;
    assert!(version_count(&raw, &fixture.environment.bucket, &large_key).await? > 0);

    let small_payload = random_payload(32 * 1024);
    let small_request = capture_request(
        &fixture.opened,
        "upload_policy_tightening_small",
        &small_payload,
        50_000,
    );
    let small_ref = lifecycle
        .capture(
            &fixture.context,
            &fixture.lease,
            &small_request,
            Bytes::from(small_payload),
        )
        .await?;
    let (small_created, small_expiry, small_revision): (i64, i64, i64) = sqlx::query_as(
        "SELECT created_at_unix_ms, expires_at_unix_ms, lifecycle_revision \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(small_ref.object_id())
    .fetch_one(&fixture.pool)
    .await?;

    fixture
        .install_policy(&lifecycle, 2, 64 * 1024, 20_000, 70_000)
        .await?;
    let finalize_error = lifecycle
        .finalize_upload(&fixture.context, &fixture.lease, &uploaded)
        .await
        .expect_err("current tighter policy must reject pre-policy upload finalization");
    assert_eq!(finalize_error.code(), EvidenceObjectErrorCode::Unauthorized);
    let state: String = sqlx::query_scalar(
        "SELECT object_state::text FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(pending.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert_ne!(state, "available");

    let extension_error = lifecycle
        .extend_retention(
            &fixture.operator,
            &OrganizationId::try_from(ORGANIZATION_ID)?,
            small_ref.object_id(),
            u64::try_from(small_created + 90_000)?,
        )
        .await
        .expect_err("extension beyond current policy must fail");
    assert_eq!(
        extension_error.code(),
        EvidenceObjectErrorCode::Unauthorized
    );
    let after: (i64, i64) = sqlx::query_as(
        "SELECT expires_at_unix_ms, lifecycle_revision \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(small_ref.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(after, (small_expiry, small_revision));

    delete_and_reap(
        &fixture,
        &lifecycle,
        &[pending.object_id(), small_ref.object_id()],
    )
    .await?;
    assert_only_purge_barrier(&raw, &fixture.environment.bucket, &large_key).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn same_logical_backend_with_different_real_bucket_cannot_reap() -> TestResult {
    let fixture = Fixture::new("apolysis_backend_binding").await?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    let secondary_bucket = format!("{}-secondary", fixture.environment.bucket);
    tokio::time::timeout(
        OPERATION_BOUND,
        raw.create_bucket().bucket(&secondary_bucket).send(),
    )
    .await
    .map_err(|_| "secondary bucket creation exceeded its bound")??;
    enable_versioning(&raw, &secondary_bucket).await?;

    let lifecycle_for_bucket = |bucket: &str| -> TestResult<EvidenceObjectLifecycle> {
        Ok(EvidenceObjectLifecycle::new(
            fixture.pool.clone(),
            fixture.pool.clone(),
            fixture.pool.clone(),
            fixture.environment.lifecycle_config_with_timeout(
                &fixture.environment.endpoint,
                bucket,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )?,
        ))
    };
    let primary = lifecycle_for_bucket(&fixture.environment.bucket)?;
    let secondary = lifecycle_for_bucket(&secondary_bucket)?;
    fixture
        .install_policy(&primary, 1, 1024 * 1024, 30_000, 180_000)
        .await?;
    let payload = random_payload(64 * 1024);
    let request = capture_request(&fixture.opened, "upload_backend_binding", &payload, 120_000);
    let pending = primary
        .begin_upload(&fixture.context, &fixture.lease, &request)
        .await?;
    let mismatch = secondary
        .upload_pending(
            &fixture.context,
            &fixture.lease,
            &pending,
            Bytes::from(payload.clone()),
        )
        .await
        .expect_err("different bucket must not accept a primary reservation");
    assert_eq!(mismatch.code(), EvidenceObjectErrorCode::StorageUnavailable);
    let key = storage_key(&fixture.pool, pending.object_id()).await?;
    assert_eq!(version_count(&raw, &secondary_bucket, &key).await?, 0);

    let uploaded = primary
        .upload_pending(
            &fixture.context,
            &fixture.lease,
            &pending,
            Bytes::from(payload),
        )
        .await?;
    primary
        .finalize_upload(&fixture.context, &fixture.lease, &uploaded)
        .await?;
    assert!(version_count(&raw, &fixture.environment.bucket, &key).await? > 0);
    primary
        .request_delete(
            &fixture.context,
            pending.object_id(),
            "backend_binding_cleanup",
        )
        .await?;
    let wrong_report = secondary.reap_once("reaper_wrong_backend", 8).await?;
    assert_eq!(wrong_report.purged, 0);
    assert!(wrong_report.deferred >= 1);
    let retained: (String, bool, i64) = sqlx::query_as(
        "SELECT object.object_state::text, \
                EXISTS (SELECT 1 FROM apolysis_gateway.evidence_object_storage_material material \
                 WHERE material.organization_id=object.organization_id \
                   AND material.object_id=object.object_id), \
                usage.reserved_objects \
         FROM apolysis_gateway.evidence_objects object \
         JOIN apolysis_gateway.organization_object_usage usage USING (organization_id) \
         WHERE object.organization_id=$1 AND object.object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(pending.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(retained, ("delete_pending".to_string(), true, 1));
    assert!(version_count(&raw, &fixture.environment.bucket, &key).await? > 0);

    let claim_until: i64 = sqlx::query_scalar(
        "SELECT reap_claim_until_unix_ms \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(pending.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    let retry_deadline = tokio::time::Instant::now() + OPERATION_BOUND;
    while database_now(&fixture.pool).await? < claim_until {
        if tokio::time::Instant::now() >= retry_deadline {
            return Err("failed backend claim did not expire within bounds".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let correct_report = primary.reap_once("reaper_correct_backend", 8).await?;
    assert_eq!(correct_report.purged, 1);
    assert_only_purge_barrier(&raw, &fixture.environment.bucket, &key).await?;
    assert_eq!(version_count(&raw, &secondary_bucket, &key).await?, 0);
    tokio::time::timeout(
        OPERATION_BOUND,
        raw.delete_bucket().bucket(&secondary_bucket).send(),
    )
    .await
    .map_err(|_| "secondary bucket deletion exceeded its bound")??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit real PostgreSQL and SeaweedFS qualification services"]
async fn deletion_acknowledgement_requires_current_rotated_credential() -> TestResult {
    let fixture = Fixture::new("apolysis_deletion_rotation").await?;
    let lifecycle = fixture.lifecycle(fixture.pool.clone(), &fixture.environment.bucket)?;
    let raw = raw_s3_client(&fixture.environment);
    enable_versioning(&raw, &fixture.environment.bucket).await?;
    fixture
        .install_policy(&lifecycle, 1, 1024 * 1024, 30_000, 180_000)
        .await?;
    let now = u64::try_from(database_now(&fixture.pool).await?)?;
    let digest_v1: [u8; 32] = Sha256::digest(b"deletion-component-v1").into();
    let component_v1 = deletion_component(1, "credential_projection_v1", digest_v1, now)?;
    lifecycle
        .register_deletion_target(&fixture.operator, &component_v1)
        .await?;

    let payload = random_payload(32 * 1024);
    let request = capture_request(
        &fixture.opened,
        "upload_deletion_rotation",
        &payload,
        120_000,
    );
    let object_ref = lifecycle
        .capture(
            &fixture.context,
            &fixture.lease,
            &request,
            Bytes::from(payload),
        )
        .await?;
    lifecycle
        .request_delete(
            &fixture.context,
            object_ref.object_id(),
            "deletion_rotation",
        )
        .await?;
    let first_reap = lifecycle.reap_once("reaper_deletion_rotation", 8).await?;
    assert_eq!(first_reap.purged, 0);
    assert!(first_reap.deferred >= 1);
    let revision: i64 = sqlx::query_scalar(
        "SELECT delete_request_revision FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .fetch_one(&fixture.pool)
    .await?;

    let wrong = deletion_component(
        1,
        "credential_projection_v1",
        Sha256::digest(b"wrong-deletion-component").into(),
        now,
    )?;
    let wrong_error = lifecycle
        .acknowledge_deletion(&wrong, object_ref.object_id(), u64::try_from(revision)?)
        .await
        .expect_err("wrong credential digest must not acknowledge deletion");
    assert_eq!(wrong_error.code(), EvidenceObjectErrorCode::Unauthorized);

    let digest_v2: [u8; 32] = Sha256::digest(b"deletion-component-v2").into();
    let component_v2 = deletion_component(2, "credential_projection_v2", digest_v2, now)?;
    lifecycle
        .register_deletion_target(&fixture.operator, &component_v2)
        .await?;
    let stale_error = lifecycle
        .acknowledge_deletion(
            &component_v1,
            object_ref.object_id(),
            u64::try_from(revision)?,
        )
        .await
        .expect_err("rotated credential must revoke prior epoch");
    assert_eq!(stale_error.code(), EvidenceObjectErrorCode::Unauthorized);
    lifecycle
        .acknowledge_deletion(
            &component_v2,
            object_ref.object_id(),
            u64::try_from(revision)?,
        )
        .await?;
    lifecycle
        .acknowledge_deletion(
            &component_v2,
            object_ref.object_id(),
            u64::try_from(revision)?,
        )
        .await?;
    let acknowledgement_count: i64 = sqlx::query_scalar(
        "SELECT count(*) \
         FROM apolysis_gateway.evidence_object_deletion_acknowledgements \
         WHERE organization_id=$1 AND object_id=$2 AND lifecycle_revision=$3",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .bind(revision)
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(acknowledgement_count, 1);
    let second_reap = lifecycle.reap_once("reaper_deletion_rotation", 8).await?;
    assert_eq!(second_reap.purged, 1);
    let state: String = sqlx::query_scalar(
        "SELECT object_state::text FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(state, "deleted");
    Ok(())
}

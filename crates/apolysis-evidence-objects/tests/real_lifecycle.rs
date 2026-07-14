// SPDX-License-Identifier: Apache-2.0

mod support;

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::Arc,
    time::Duration,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    BindRuntimeRequest, EnvironmentKind, FinishRunRequest, GatewayOperation, IngestRequest,
    OpenRunOutcome, OpenRunRequest, OrganizationId, PrincipalKind, PrincipalRef, PrivacyCapability,
    RunState, SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy, TrustProfile,
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
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository,
};
use apolysis_gateway_server::AuthorityStore;
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
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use support::privileges::{
    apply_post_migration_privileges, ApplicationRolePools, BOOTSTRAP_ROLES_SQL,
};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const ORGANIZATION_ID: &str = "org_object_gate";
const SOURCE_REGISTRATION_ID: &str = "registration_object_gate";
const SOURCE_ID: &str = "source_object_gate";
const PRINCIPAL_ID: &str = "principal_object_gate";
const CREDENTIAL_ID: &str = "credential_object_gate";
const DELETION_COMPONENT_ID: &str = "projection_object_gate";
const DELETION_COMPONENT_PRINCIPAL_ID: &str = "principal_projection_object_gate";
const DELETION_COMPONENT_CREDENTIAL_ID: &str = "credential_projection_object_gate";
const PRIVACY_PROFILE: &str = "privacy_authorized_objects_v1";
const RETENTION_PROFILE: &str = "retention_object_gate_v1";
const MTLS_LEAF_DER: &[u8] = b"apolysis-real-object-gate-mtls-leaf";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    access_key_id: String,
    secret_access_key: String,
}

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
        let key = fs::read(wrapping_key_path)?;
        let wrapping_key: [u8; 32] = key
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
        credentials: &CredentialFile,
    ) -> Result<ObjectLifecycleConfig, apolysis_evidence_objects::EvidenceObjectError> {
        ObjectLifecycleConfig::new(
            &self.endpoint,
            "us-east-1",
            &self.bucket,
            "seaweedfs_gate_v1",
            &credentials.access_key_id,
            &credentials.secret_access_key,
            "object_gate_wrapping_key_v1",
            self.wrapping_key,
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
    }
}

fn real_now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_millis(),
    )
    .expect("current time fits u64")
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
        "authority_object_gate",
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
        vec![
            SourceCapability::ToolCalls,
            SourceCapability::SourceHealth,
            SourceCapability::Workload,
        ],
        vec![
            PrivacyCapability::StructureOnly,
            PrivacyCapability::AuthorizedContentReference,
        ],
        vec!["redaction_object_gate_v1".to_string()],
    )
    .expect("evidence policy")
    .with_finalization_permission(true)
}

fn source_context(organization_id: &str, now: u64) -> AuthenticatedSourceContext {
    AuthenticatedSourceContext::new(
        OrganizationId::try_from(organization_id).expect("organization id"),
        PrincipalRef::new(PrincipalKind::Workload, PRINCIPAL_ID).expect("principal"),
        SOURCE_REGISTRATION_ID,
        AuthenticationSnapshot::new(CREDENTIAL_ID, 1, now - 1_000, now + 3_600_000)
            .expect("authentication snapshot"),
        source_policy(),
    )
    .expect("authenticated context")
}

fn deletion_component(now: u64) -> AuthenticatedDeletionComponent {
    AuthenticatedDeletionComponent::new(
        OrganizationId::try_from(ORGANIZATION_ID).expect("organization id"),
        DELETION_COMPONENT_ID,
        PrincipalKind::Workload,
        DELETION_COMPONENT_PRINCIPAL_ID,
        DELETION_COMPONENT_CREDENTIAL_ID,
        1,
        Sha256::digest(b"apolysis-real-gate-deletion-component-credential").into(),
        now.saturating_sub(1_000),
        now + 3_600_000,
    )
    .expect("authenticated deletion component")
}

async fn prepare_database(database_url: &str, now: u64) -> TestResult<PgPool> {
    if std::env::var("APOLYSIS_TEST_ALLOW_DATABASE_RESET").as_deref() != Ok("1") {
        return Err(
            "real lifecycle gate requires an explicit ephemeral database reset opt-in".into(),
        );
    }
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    sqlx::query("DROP SCHEMA IF EXISTS apolysis_gateway CASCADE")
        .execute(&pool)
        .await?;
    sqlx::query("DROP TABLE IF EXISTS _sqlx_migrations")
        .execute(&pool)
        .await?;
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL).execute(&pool).await?;
    AuthorityStore::migrate(database_url).await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.organizations (\
            organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,'active',$2,$2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(i64::try_from(now)?)
    .execute(&pool)
    .await?;
    let stored_policy = json!({
        "source_id": SOURCE_ID,
        "allowed_source_kinds": ["semantic_hook"],
        "allowed_environments": ["ci_runner_or_remote_workspace"],
        "allowed_operations": ["bind_runtime", "ingest", "finish_run"],
        "effective_trust_profile": "harness_observed",
        "allowed_capabilities": ["tool_calls", "source_health", "workload"],
        "allowed_privacy_capabilities": ["structure_only", "authorized_content_reference"],
        "allowed_redaction_profile_refs": ["redaction_object_gate_v1"],
        "allowed_run_authorities": [{"kind": "service", "id": "authority_object_gate"}],
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
    .bind(SOURCE_REGISTRATION_ID)
    .bind(ORGANIZATION_ID)
    .bind(SOURCE_ID)
    .bind(PRINCIPAL_ID)
    .bind(i64::try_from(now - 60_000)?)
    .bind(i64::try_from(now + 3_600_000)?)
    .bind(stored_policy)
    .execute(&pool)
    .await?;
    let mut fingerprint_digest = Sha256::new();
    fingerprint_digest.update(b"apolysis.gateway.mtls-leaf/v1\0");
    fingerprint_digest.update(MTLS_LEAF_DER);
    let fingerprint: [u8; 32] = fingerprint_digest.finalize().into();
    sqlx::query(
        "INSERT INTO apolysis_gateway.transport_credentials (\
            credential_id, certificate_fingerprint, organization_id, source_registration_id, \
            credential_epoch, effective_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms, \
            revocation_reason, created_at_unix_ms, updated_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,1,$5,$6,NULL,NULL,$5,$5)",
    )
    .bind(CREDENTIAL_ID)
    .bind(fingerprint.as_slice())
    .bind(ORGANIZATION_ID)
    .bind(SOURCE_REGISTRATION_ID)
    .bind(i64::try_from(now - 60_000)?)
    .bind(i64::try_from(now + 3_600_000)?)
    .execute(&pool)
    .await?;
    Ok(pool)
}

fn open_request() -> OpenRunRequest {
    let mut wire = json!({
        "schema_version": "0.1",
        "mode": "create",
        "client_operation_id": "operation_object_gate_open",
        "request_digest": "0".repeat(64),
        "client_run_key": "object_gate_run",
        "environment": "ci_runner_or_remote_workspace",
        "authority": {"kind": "service", "id": "authority_object_gate"},
        "principal": {"kind": "workload", "id": PRINCIPAL_ID},
        "objective_ref": "objective_object_gate",
        "privacy_profile_ref": PRIVACY_PROFILE,
        "retention_profile_ref": RETENTION_PROFILE,
        "expected_source_kinds": ["semantic_hook"],
        "source_manifest": {
            "schema_version": "0.1",
            "source_id": SOURCE_ID,
            "source_kind": "semantic_hook",
            "declared_boundary": "agent_harness",
            "adapter_name": "real_object_gate",
            "adapter_version": "1.0.0",
            "environment": "ci_runner_or_remote_workspace",
            "capabilities": ["tool_calls", "source_health", "workload"],
            "expected_lifecycle": ["started", "finished"],
            "ordering": "strict_per_stream",
            "samples": false,
            "redaction_profile_ref": "redaction_object_gate_v1",
            "redacted_fields": ["payload.content"],
            "privacy_capabilities": ["structure_only", "authorized_content_reference"]
        }
    });
    let unsigned: OpenRunRequest = serde_json::from_value(wire.clone()).expect("open request");
    wire["request_digest"] =
        json!(canonical_request_digest("open_run", &unsigned).expect("canonical open request"));
    serde_json::from_value(wire).expect("signed open request")
}

fn bind_runtime_request(run_id: &str, lease_id: &str) -> BindRuntimeRequest {
    let now = real_now_ms();
    let mut wire = json!({
        "schema_version": "0.1",
        "client_operation_id": "operation_object_gate_bind",
        "request_digest": "0".repeat(64),
        "run_id": run_id,
        "lease_id": lease_id,
        "binding": {
            "binding_id": "binding_object_gate_01",
            "asserting_source_id": SOURCE_ID,
            "identity_kind": "pod",
            "identity_ref": "cluster_object_gate:namespace_default:pod_agent_01",
            "valid_from_unix_ms": now.saturating_sub(1_000),
            "valid_until_unix_ms": now + 60_000,
            "evidence_basis": "propagated_and_validated",
            "evidence_basis_ref": "object_gate_uid_readback_01",
            "attribution": "exact",
            "reason_codes": [],
            "confidence_bps": null,
            "alternative_runtime_candidates": []
        }
    });
    let unsigned: BindRuntimeRequest =
        serde_json::from_value(wire.clone()).expect("bind runtime request");
    wire["request_digest"] =
        json!(canonical_request_digest("bind_runtime", &unsigned).expect("canonical bind request"));
    serde_json::from_value(wire).expect("signed bind runtime request")
}

fn finish_run_request(run_id: &str, lease_id: &str, stream_id: &str) -> FinishRunRequest {
    let mut wire = json!({
        "schema_version": "0.1",
        "client_operation_id": "operation_object_gate_finish",
        "request_digest": "0".repeat(64),
        "run_id": run_id,
        "lease_id": lease_id,
        "terminal_positions": [{
            "source_id": SOURCE_ID,
            "source_stream_id": stream_id,
            "final_source_sequence": 1
        }],
        "outcome_claim_refs": [],
        "requested_finalization_deadline_unix_ms": real_now_ms() + 30_000
    });
    let unsigned: FinishRunRequest =
        serde_json::from_value(wire.clone()).expect("finish run request");
    wire["request_digest"] =
        json!(canonical_request_digest("finish_run", &unsigned).expect("canonical finish request"));
    serde_json::from_value(wire).expect("signed finish run request")
}

#[allow(clippy::too_many_arguments)]
fn ingest_request(
    run_id: &str,
    stream_id: &str,
    lease_id: &str,
    object_id: &str,
    digest: &str,
    size: u64,
    event_id: &str,
    operation_id: &str,
) -> IngestRequest {
    let mut wire = json!({
        "schema_version": "0.1",
        "client_operation_id": operation_id,
        "request_digest": "0".repeat(64),
        "run_id": run_id,
        "lease_id": lease_id,
        "envelopes": [{
            "schema_version": "0.1",
            "run_id": run_id,
            "source_id": SOURCE_ID,
            "source_stream_id": stream_id,
            "source_event_id": event_id,
            "source_sequence": 1,
            "observed_at": {
                "unix_ms": real_now_ms(),
                "clock_basis": "wall_clock",
                "uncertainty_ms": 1
            },
            "correlation": {
                "trace_ref": "trace_object_gate",
                "agent_ref": "agent_object_gate",
                "tool_ref": "tool_object_gate",
                "runtime_ref": null
            },
            "flags": {"loss_detected": false, "redacted": true, "contains_content": true},
            "payload_type": "tool_interaction_blob",
            "payload_version": "1.0.0",
            "payload_digest": digest,
            "inline_payload": null,
            "object_ref": {"object_id": object_id, "sha256": digest, "size_bytes": size}
        }]
    });
    let unsigned: IngestRequest = serde_json::from_value(wire.clone()).expect("ingest request");
    wire["request_digest"] =
        json!(canonical_request_digest("ingest", &unsigned).expect("canonical ingest request"));
    serde_json::from_value(wire).expect("signed ingest request")
}

fn reidentify_ingest_request(original: &IngestRequest, operation_id: &str) -> IngestRequest {
    let mut wire = serde_json::to_value(original).expect("serialize original ingest request");
    wire["client_operation_id"] = json!(operation_id);
    wire["request_digest"] = json!("0".repeat(64));
    let unsigned: IngestRequest =
        serde_json::from_value(wire.clone()).expect("reidentified ingest request");
    wire["request_digest"] =
        json!(canonical_request_digest("ingest", &unsigned).expect("canonical replay request"));
    serde_json::from_value(wire).expect("signed replay request")
}

fn random_payload(size: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; size];
    getrandom::fill(&mut payload).expect("OS random payload");
    payload
}

fn digest(payload: &[u8]) -> String {
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn capture_request(
    run_id: &str,
    stream_id: &str,
    client_upload_id: &str,
    payload: &[u8],
) -> CaptureRequest {
    capture_request_with_retention(run_id, stream_id, client_upload_id, payload, 45_000)
}

fn capture_request_with_retention(
    run_id: &str,
    stream_id: &str,
    client_upload_id: &str,
    payload: &[u8],
    requested_retention_ms: u64,
) -> CaptureRequest {
    CaptureRequest::new(
        run_id.try_into().expect("run id"),
        stream_id,
        client_upload_id,
        SourceCapability::ToolCalls,
        "tool_interaction_blob",
        "1.0.0",
        digest(payload),
        payload.len() as u64,
        requested_retention_ms,
    )
    .expect("capture request")
}

fn raw_s3_client(
    environment: &GateEnvironment,
    credentials: &CredentialFile,
) -> aws_sdk_s3::Client {
    let sdk_config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(&environment.endpoint)
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(
            credentials.access_key_id.clone(),
            credentials.secret_access_key.clone(),
            None,
            None,
            "apolysis-real-gate",
        ))
        .force_path_style(true)
        .retry_config(RetryConfig::standard().with_max_attempts(1))
        .build();
    aws_sdk_s3::Client::from_conf(sdk_config)
}

async fn assert_only_purge_barrier(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
) -> TestResult<()> {
    let versions = client
        .list_object_versions()
        .bucket(bucket)
        .prefix(key)
        .send()
        .await?;
    let retained_versions = versions
        .versions()
        .iter()
        .filter(|item| item.key() == Some(key))
        .collect::<Vec<_>>();
    assert_eq!(retained_versions.len(), 1);
    assert!(!versions
        .delete_markers()
        .iter()
        .any(|item| item.key() == Some(key)));
    let barrier = client.head_object().bucket(bucket).key(key).send().await?;
    assert_eq!(barrier.content_length(), Some(0));
    assert_eq!(
        barrier
            .metadata()
            .and_then(|metadata| metadata.get("apolysis-purge-barrier"))
            .map(String::as_str),
        Some("1")
    );
    Ok(())
}

async fn count_deleted_targets(pool: &PgPool, object_ids: &[String]) -> TestResult<usize> {
    let mut deleted = 0;
    for object_id in object_ids {
        let state: String = sqlx::query_scalar(
            "SELECT object_state::text FROM apolysis_gateway.evidence_objects \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(ORGANIZATION_ID)
        .bind(object_id)
        .fetch_one(pool)
        .await?;
        deleted += usize::from(state == "deleted");
    }
    Ok(deleted)
}

async fn reap_targets_until_deleted(
    pool: &PgPool,
    lifecycle: &EvidenceObjectLifecycle,
    worker_id: &str,
    object_ids: &[String],
) -> TestResult<u32> {
    let mut deleted = count_deleted_targets(pool, object_ids).await?;
    let mut purged = 0_u32;
    if deleted == object_ids.len() {
        return Ok(purged);
    }

    // Fair reaper batches claim at most one object per organization. Bound
    // cleanup by the target count and require target-state progress each pass.
    for _ in 0..object_ids.len() {
        let report = lifecycle.reap_once(worker_id, 16).await?;
        purged = purged
            .checked_add(report.purged)
            .ok_or("reaper purge count overflowed")?;
        let current_deleted = count_deleted_targets(pool, object_ids).await?;
        if current_deleted == object_ids.len() {
            return Ok(purged);
        }
        if current_deleted <= deleted {
            return Err("reaper made no progress on the requested cleanup targets".into());
        }
        deleted = current_deleted;
    }

    Err("reaper did not delete all cleanup targets within the bounded passes".into())
}

fn write_private_marker(path: &str, value: &str) -> TestResult<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(value.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn read_private_replay_key(path: &str) -> TestResult<[u8; 32]> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err("crash replay key must be a regular mode-0600 file".into());
    }
    fs::read(path)?
        .try_into()
        .map_err(|_| "crash replay key file must contain exactly 32 bytes".into())
}

async fn crash_gate_setup(
    environment: &GateEnvironment,
    mode: &str,
    state_path: &str,
    ready_path: &str,
    replay_key_path: &str,
) -> TestResult<()> {
    let now = real_now_ms();
    let pool = prepare_database(&environment.database_url, now).await?;
    let context = source_context(ORGANIZATION_ID, now);
    let replay_key = read_private_replay_key(replay_key_path)?;
    let repository = PostgresGatewayRepository::connect(
        &environment.database_url,
        Arc::new(Aes256GcmReplayProtector::new(
            "object-crash-replay-key",
            [("object-crash-replay-key".to_string(), replay_key)],
        )?),
        PostgresGatewayConfig::default(),
    )
    .await?;
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let opened = gateway.open_run(&context, open_request()).await?;
    let lease = EvidenceObjectRunLease::from_open_response(&opened)?;
    let lifecycle = EvidenceObjectLifecycle::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        environment.lifecycle_config(&environment.credentials)?,
    );
    raw_s3_client(environment, &environment.credentials)
        .put_bucket_versioning()
        .bucket(&environment.bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await?;
    lifecycle.probe_storage().await?;
    let upload_timeout_ms = if mode == "after_put" { 120_000 } else { 2_000 };
    lifecycle
        .install_policy(
            &OperatorActor::new("operator_object_crash_gate")?,
            &EvidenceObjectPolicy::new(
                ORGANIZATION_ID.try_into()?,
                PRIVACY_PROFILE,
                RETENTION_PROFILE,
                1,
                1_048_576,
                2_097_152,
                8,
                8,
                upload_timeout_ms,
                240_000,
                real_now_ms(),
            )?,
        )
        .await?;
    let payload = random_payload(96 * 1024);
    let request = capture_request_with_retention(
        opened.run_id().as_str(),
        opened.source_stream_id(),
        "upload_object_crash_gate",
        &payload,
        if mode == "after_put" { 180_000 } else { 45_000 },
    );
    let pending = lifecycle.begin_upload(&context, &lease, &request).await?;
    if mode == "after_put" {
        lifecycle
            .upload_pending(&context, &lease, &pending, Bytes::from(payload))
            .await?;
    }
    write_private_marker(state_path, pending.object_id())?;
    write_private_marker(ready_path, mode)?;
    std::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn crash_gate_recover(
    environment: &GateEnvironment,
    mode: &str,
    state_path: &str,
    ready_path: &str,
    replay_key_path: &str,
) -> TestResult<()> {
    let object_id = fs::read_to_string(state_path)?.trim().to_string();
    let _ = OrganizationId::try_from(object_id.as_str())?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&environment.database_url)
        .await?;
    AuthorityStore::migrate(&environment.database_url).await?;
    let context = source_context(ORGANIZATION_ID, real_now_ms());
    let replay_key = read_private_replay_key(replay_key_path)?;
    let repository = PostgresGatewayRepository::connect(
        &environment.database_url,
        Arc::new(Aes256GcmReplayProtector::new(
            "object-crash-replay-key",
            [("object-crash-replay-key".to_string(), replay_key)],
        )?),
        PostgresGatewayConfig::default(),
    )
    .await?;
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let opened = gateway.open_run(&context, open_request()).await?;
    assert_eq!(opened.outcome(), OpenRunOutcome::IdempotentRetry);
    let lease = EvidenceObjectRunLease::from_open_response(&opened)?;
    let lifecycle = EvidenceObjectLifecycle::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        environment.lifecycle_config(&environment.credentials)?,
    );
    if mode == "recover_put_unavailable" {
        let error = lifecycle
            .probe_storage()
            .await
            .expect_err("a killed provider must surface bounded storage backpressure");
        assert_eq!(error.code(), EvidenceObjectErrorCode::StorageUnavailable);
        let retained: (String, bool, i64, i64) = sqlx::query_as(
            "SELECT object.object_state::text, \
                    EXISTS (SELECT 1 \
                      FROM apolysis_gateway.evidence_object_storage_material AS material \
                     WHERE material.organization_id=object.organization_id \
                       AND material.object_id=object.object_id), \
                    usage.reserved_bytes, usage.reserved_objects \
             FROM apolysis_gateway.evidence_objects AS object \
             JOIN apolysis_gateway.organization_object_usage AS usage \
               ON usage.organization_id=object.organization_id \
             WHERE object.organization_id=$1 AND object.object_id=$2",
        )
        .bind(ORGANIZATION_ID)
        .bind(&object_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(retained.0, "uploading");
        assert!(retained.1);
        assert!(retained.2 > 0);
        assert_eq!(retained.3, 1);
        write_private_marker(ready_path, mode)?;
        return Ok(());
    }
    lifecycle.probe_storage().await?;
    let storage_key: String = sqlx::query_scalar(
        "SELECT storage_key FROM apolysis_gateway.evidence_object_storage_material \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_id)
    .fetch_one(&pool)
    .await?;

    match mode {
        "recover_reserve" => {
            let deadline: i64 = sqlx::query_scalar(
                "SELECT upload_deadline_unix_ms FROM apolysis_gateway.evidence_objects \
                 WHERE organization_id=$1 AND object_id=$2",
            )
            .bind(ORGANIZATION_ID)
            .bind(&object_id)
            .fetch_one(&pool)
            .await?;
            let remaining = u64::try_from(deadline)?
                .saturating_sub(real_now_ms())
                .saturating_add(250);
            tokio::time::sleep(Duration::from_millis(remaining)).await;
        }
        "recover_put" => {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                match lifecycle
                    .reconcile_upload(&context, &lease, &object_id)
                    .await
                {
                    Ok(_) => break,
                    Err(error)
                        if error.code() == EvidenceObjectErrorCode::StorageUnavailable
                            && tokio::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            lifecycle
                .request_delete(&context, &object_id, "crash_recovery_complete")
                .await?;
        }
        _ => return Err(format!("unsupported recovery mode: {mode}").into()),
    }

    let report = lifecycle.reap_once("reaper_object_crash_gate", 8).await?;
    assert_eq!(report.purged, 1);
    let state: String = sqlx::query_scalar(
        "SELECT object_state FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(state, "deleted");
    let has_material: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 \
           FROM apolysis_gateway.evidence_object_storage_material \
          WHERE organization_id=$1 AND object_id=$2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(&object_id)
    .fetch_one(&pool)
    .await?;
    assert!(!has_material);
    let usage: (i64, i64) = sqlx::query_as(
        "SELECT reserved_bytes, reserved_objects \
         FROM apolysis_gateway.organization_object_usage WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert_eq!(usage, (0, 0));
    assert_only_purge_barrier(
        &raw_s3_client(environment, &environment.credentials),
        &environment.bucket,
        &storage_key,
    )
    .await?;
    write_private_marker(ready_path, mode)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires an external process supervisor plus real PostgreSQL and S3 services"]
async fn real_postgres_and_s3_object_crash_seams_recover() -> TestResult<()> {
    let environment = GateEnvironment::read()?;
    let mode = std::env::var("APOLYSIS_TEST_CRASH_MODE")?;
    let state_path = std::env::var("APOLYSIS_TEST_CRASH_STATE_FILE")?;
    let ready_path = std::env::var("APOLYSIS_TEST_CRASH_READY_FILE")?;
    let replay_key_path = std::env::var("APOLYSIS_TEST_CRASH_REPLAY_KEY_FILE")?;
    match mode.as_str() {
        "after_reserve" | "after_put" => {
            crash_gate_setup(
                &environment,
                &mode,
                &state_path,
                &ready_path,
                &replay_key_path,
            )
            .await
        }
        "recover_reserve" | "recover_put" | "recover_put_unavailable" => {
            crash_gate_recover(
                &environment,
                &mode,
                &state_path,
                &ready_path,
                &replay_key_path,
            )
            .await
        }
        _ => Err(format!("unsupported crash qualification mode: {mode}").into()),
    }
}

#[tokio::test]
#[ignore = "requires explicit real PostgreSQL and S3-compatible qualification services"]
async fn real_postgres_and_s3_object_lifecycle_is_fail_closed() -> TestResult<()> {
    let environment = GateEnvironment::read()?;
    let now = real_now_ms();
    let pool = prepare_database(&environment.database_url, now).await?;
    apply_post_migration_privileges(&pool).await?;
    let role_pools = ApplicationRolePools::provision(&pool, &environment.database_url).await?;
    let authority = AuthorityStore::connect(role_pools.gateway_runtime_database_url()).await?;
    let context = authority
        .resolve_mtls(MTLS_LEAF_DER, "open_run", now)
        .await?;

    let mut replay_key = [0_u8; 32];
    getrandom::fill(&mut replay_key)?;
    let repository = PostgresGatewayRepository::from_pool(
        role_pools.gateway_runtime.clone(),
        Arc::new(Aes256GcmReplayProtector::new(
            "object-gate-replay-key",
            [("object-gate-replay-key".to_string(), replay_key)],
        )?),
        PostgresGatewayConfig::default(),
    );
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let opened = gateway.open_run(&context, open_request()).await?;
    let lease = EvidenceObjectRunLease::from_open_response(&opened)?;
    let binding = gateway
        .bind_runtime(
            &context,
            bind_runtime_request(opened.run_id().as_str(), opened.lease().lease_id()),
        )
        .await?;
    assert!(binding.accepted());

    let operator = OperatorActor::new("operator_object_gate")?;
    let deletion_component = deletion_component(now);
    let lifecycle = EvidenceObjectLifecycle::new(
        role_pools.evidence_runtime.clone(),
        role_pools.evidence_control.clone(),
        role_pools.deletion_ack.clone(),
        environment.lifecycle_config(&environment.credentials)?,
    );
    let raw_client = raw_s3_client(&environment, &environment.credentials);
    raw_client
        .put_bucket_versioning()
        .bucket(&environment.bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await?;
    lifecycle.probe_storage().await?;
    let wrong_credentials = CredentialFile {
        access_key_id: "wrong_access_key".to_string(),
        secret_access_key: "wrong_secret_key".to_string(),
    };
    let wrong_lifecycle = EvidenceObjectLifecycle::new(
        role_pools.evidence_runtime.clone(),
        role_pools.evidence_control.clone(),
        role_pools.deletion_ack.clone(),
        environment.lifecycle_config(&wrong_credentials)?,
    );
    assert!(wrong_lifecycle.probe_storage().await.is_err());

    let versioning = raw_client
        .get_bucket_versioning()
        .bucket(&environment.bucket)
        .send()
        .await?;
    assert_eq!(versioning.status(), Some(&BucketVersioningStatus::Enabled));

    lifecycle
        .install_policy(
            &operator,
            &EvidenceObjectPolicy::new(
                ORGANIZATION_ID.try_into()?,
                PRIVACY_PROFILE,
                RETENTION_PROFILE,
                1,
                1_048_576,
                2_097_152,
                2,
                4,
                15_000,
                60_000,
                real_now_ms(),
            )?,
        )
        .await?;
    lifecycle
        .register_deletion_target(&operator, &deletion_component)
        .await?;

    let first_payload = random_payload(256 * 1024);
    let first_request = capture_request(
        opened.run_id().as_str(),
        opened.source_stream_id(),
        "upload_object_gate_01",
        &first_payload,
    );
    let pending = lifecycle
        .begin_upload(&context, &lease, &first_request)
        .await?;
    let replayed_pending = lifecycle
        .begin_upload(&context, &lease, &first_request)
        .await?;
    assert_eq!(pending.object_id(), replayed_pending.object_id());
    let uploaded = lifecycle
        .upload_pending(
            &context,
            &lease,
            &pending,
            Bytes::from(first_payload.clone()),
        )
        .await?;
    let object_ref = lifecycle
        .finalize_upload(&context, &lease, &uploaded)
        .await?;
    assert_eq!(object_ref.sha256(), digest(&first_payload));

    let storage = sqlx::query(
        "SELECT material.storage_key, octet_length(material.encrypted_data_key) AS key_bytes, \
                object.object_state \
         FROM apolysis_gateway.evidence_objects AS object \
         JOIN apolysis_gateway.evidence_object_storage_material AS material \
           USING (organization_id, object_id) \
         WHERE object.organization_id=$1 AND object.object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .fetch_one(&pool)
    .await?;
    assert_eq!(storage.try_get::<String, _>("object_state")?, "available");
    assert_eq!(storage.try_get::<i32, _>("key_bytes")?, 48);
    let storage_key: String = storage.try_get("storage_key")?;
    let raw = raw_client
        .get_object()
        .bucket(&environment.bucket)
        .key(&storage_key)
        .send()
        .await?
        .body
        .collect()
        .await?
        .into_bytes();
    assert_eq!(raw.len(), first_payload.len() + 16);
    assert_ne!(raw.as_ref(), first_payload.as_slice());

    let ingest = ingest_request(
        opened.run_id().as_str(),
        opened.source_stream_id(),
        opened.lease().lease_id(),
        object_ref.object_id(),
        object_ref.sha256(),
        object_ref.size_bytes(),
        "event_object_gate_01",
        "operation_object_gate_ingest_01",
    );
    gateway.ingest(&context, ingest.clone()).await?;
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.evidence_event_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .fetch_one(&pool)
    .await?;
    assert_eq!(linked, 1);

    let wrong_digest = "f".repeat(64);
    let denied = ingest_request(
        opened.run_id().as_str(),
        opened.source_stream_id(),
        opened.lease().lease_id(),
        object_ref.object_id(),
        &wrong_digest,
        object_ref.size_bytes(),
        "event_object_gate_02",
        "operation_object_gate_ingest_bad",
    );
    assert!(gateway.ingest(&context, denied).await.is_err());
    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.evidence_events WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert_eq!(event_count, 1);

    let other_context = source_context("org_other_gate", real_now_ms());
    let cross_org = lifecycle
        .reconcile_upload(&other_context, &lease, object_ref.object_id())
        .await
        .expect_err("cross-organization reference possession must fail");
    assert_eq!(cross_org.code(), EvidenceObjectErrorCode::NotFound);

    let second_payload = random_payload(128 * 1024);
    let second_request = capture_request(
        opened.run_id().as_str(),
        opened.source_stream_id(),
        "upload_object_gate_02",
        &second_payload,
    );
    let second = lifecycle
        .begin_upload(&context, &lease, &second_request)
        .await?;
    let quota_payload = random_payload(64 * 1024);
    let quota_error = lifecycle
        .begin_upload(
            &context,
            &lease,
            &capture_request(
                opened.run_id().as_str(),
                opened.source_stream_id(),
                "upload_object_gate_quota",
                &quota_payload,
            ),
        )
        .await
        .expect_err("third reserved object must exceed object-count quota");
    assert_eq!(quota_error.code(), EvidenceObjectErrorCode::QuotaExceeded);

    let extension = real_now_ms() + 55_000;
    lifecycle
        .extend_retention(
            &operator,
            &OrganizationId::try_from(ORGANIZATION_ID)?,
            object_ref.object_id(),
            extension,
        )
        .await?;

    // Deliberately create another data version, then a delete marker. The key
    // is logically absent while old ciphertext remains. Race a conditional
    // late PUT against lifecycle purge: it may linearize before the retained
    // purge barrier (and be deleted) or lose with 412 after the barrier, but it
    // must never resurrect evidence after purge completes.
    raw_client
        .put_object()
        .bucket(&environment.bucket)
        .key(&storage_key)
        .body(ByteStream::from(random_payload(first_payload.len() + 16)))
        .send()
        .await?;
    raw_client
        .delete_object()
        .bucket(&environment.bucket)
        .key(&storage_key)
        .send()
        .await?;

    lifecycle
        .request_delete(&context, object_ref.object_id(), "operator_requested")
        .await?;
    lifecycle
        .request_delete(&context, second.object_id(), "operator_requested")
        .await?;
    let requested_deletions = vec![
        object_ref.object_id().to_string(),
        second.object_id().to_string(),
    ];
    let late_ciphertext = random_payload(first_payload.len() + 16);
    let late_put = raw_client
        .put_object()
        .bucket(&environment.bucket)
        .key(&storage_key)
        .if_none_match("*")
        .body(ByteStream::from(late_ciphertext))
        .send();
    let (first_pass, late_put_result) =
        tokio::join!(lifecycle.reap_once("reaper_object_gate", 16), late_put);
    let first_pass = first_pass?;
    if let Err(error) = late_put_result {
        assert_eq!(
            error
                .raw_response()
                .map(|response| response.status().as_u16()),
            Some(412),
            "late conditional PUT failed for an unexpected provider reason"
        );
    }
    assert_eq!(first_pass.claimed, 1);
    assert_eq!(first_pass.purged, 0);
    assert_eq!(first_pass.deferred, 1);
    let fail_closed_state: (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE object_state='delete_pending'), \
                count(*) FILTER (WHERE storage_purged_at_unix_ms IS NOT NULL) \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id IN ($2,$3)",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .bind(second.object_id())
    .fetch_one(&pool)
    .await?;
    assert_eq!(fail_closed_state, (2, 1));

    let pending_deletions = sqlx::query(
        "SELECT object_id, delete_request_revision FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_state='delete_pending' ORDER BY object_id",
    )
    .bind(ORGANIZATION_ID)
    .fetch_all(&pool)
    .await?;
    for row in pending_deletions {
        lifecycle
            .acknowledge_deletion(
                &deletion_component,
                &row.try_get::<String, _>("object_id")?,
                u64::try_from(row.try_get::<i64, _>("delete_request_revision")?)?,
            )
            .await?;
    }
    let purged = reap_targets_until_deleted(
        &pool,
        &lifecycle,
        "reaper_object_gate",
        &requested_deletions,
    )
    .await?;
    assert_eq!(purged, 2);
    assert_only_purge_barrier(&raw_client, &environment.bucket, &storage_key).await?;

    let tombstone = sqlx::query(
        "SELECT object.object_state, object.content_digest, \
                EXISTS (SELECT 1 FROM apolysis_gateway.evidence_object_storage_material AS material \
                        WHERE material.organization_id=object.organization_id \
                          AND material.object_id=object.object_id) AS has_crypto \
         FROM apolysis_gateway.evidence_objects AS object \
         WHERE object.organization_id=$1 AND object.object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .fetch_one(&pool)
    .await?;
    assert_eq!(tombstone.try_get::<String, _>("object_state")?, "deleted");
    assert!(!tombstone.try_get::<bool, _>("has_crypto")?);
    let purge_fact_rewrite = sqlx::query(
        "UPDATE apolysis_gateway.evidence_objects \
         SET storage_purged_at_unix_ms=delete_requested_at_unix_ms \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(object_ref.object_id())
    .execute(&pool)
    .await
    .expect_err("terminal physical-purge fact must be immutable");
    assert_eq!(
        purge_fact_rewrite
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("evidence_object_storage_purge_fact_ck")
    );

    let duplicate = reidentify_ingest_request(&ingest, "operation_object_gate_ingest_replay");
    gateway
        .ingest(&context, duplicate)
        .await
        .expect("durable event duplicate must replay after object deletion");

    let mismatch_payload = random_payload(64 * 1024);
    let mismatch = lifecycle
        .begin_upload(
            &context,
            &lease,
            &capture_request(
                opened.run_id().as_str(),
                opened.source_stream_id(),
                "upload_object_gate_mismatch",
                &mismatch_payload,
            ),
        )
        .await?;
    let mismatch_error = lifecycle
        .upload_pending(
            &context,
            &lease,
            &mismatch,
            Bytes::from(random_payload(mismatch_payload.len())),
        )
        .await
        .expect_err("wrong bytes must fail integrity before availability");
    assert_eq!(
        mismatch_error.code(),
        EvidenceObjectErrorCode::IntegrityMismatch
    );

    let fourth_payload = random_payload(32 * 1024);
    let fourth = lifecycle
        .begin_upload(
            &context,
            &lease,
            &capture_request(
                opened.run_id().as_str(),
                opened.source_stream_id(),
                "upload_object_gate_04",
                &fourth_payload,
            ),
        )
        .await?;
    let rate_payload = random_payload(16 * 1024);
    let rate_error = lifecycle
        .begin_upload(
            &context,
            &lease,
            &capture_request(
                opened.run_id().as_str(),
                opened.source_stream_id(),
                "upload_object_gate_rate",
                &rate_payload,
            ),
        )
        .await
        .expect_err("fifth accepted reservation in one real minute must be rate limited");
    assert_eq!(rate_error.code(), EvidenceObjectErrorCode::RateLimited);

    lifecycle
        .request_delete(&context, fourth.object_id(), "test_cleanup")
        .await?;
    let cleanup_objects = sqlx::query(
        "SELECT object_id, delete_request_revision FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_state='delete_pending'",
    )
    .bind(ORGANIZATION_ID)
    .fetch_all(&pool)
    .await?;
    let mut cleanup_object_ids = Vec::with_capacity(cleanup_objects.len());
    for row in cleanup_objects {
        let object_id = row.try_get::<String, _>("object_id")?;
        lifecycle
            .acknowledge_deletion(
                &deletion_component,
                &object_id,
                u64::try_from(row.try_get::<i64, _>("delete_request_revision")?)?,
            )
            .await?;
        cleanup_object_ids.push(object_id);
    }
    let cleanup_purged =
        reap_targets_until_deleted(&pool, &lifecycle, "reaper_object_gate", &cleanup_object_ids)
            .await?;
    assert_eq!(cleanup_purged, u32::try_from(cleanup_object_ids.len())?);

    let usage = sqlx::query(
        "SELECT reserved_bytes, reserved_objects \
         FROM apolysis_gateway.organization_object_usage WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&pool)
    .await?;
    assert_eq!(usage.try_get::<i64, _>("reserved_bytes")?, 0);
    assert_eq!(usage.try_get::<i64, _>("reserved_objects")?, 0);

    let finished = gateway
        .finish_run(
            &context,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await?;
    assert_eq!(finished.state(), RunState::Finished);

    sqlx::query(
        "UPDATE apolysis_gateway.transport_credentials \
         SET revoked_at_unix_ms=$2, revocation_reason='qualification_complete', \
             updated_at_unix_ms=$2 WHERE credential_id=$1",
    )
    .bind(CREDENTIAL_ID)
    .bind(i64::try_from(real_now_ms())?)
    .execute(&pool)
    .await?;
    authority
        .resolve_mtls(MTLS_LEAF_DER, "ingest", real_now_ms())
        .await
        .expect_err("revoked current credential must fail closed at authority resolution");
    drop(authority);
    drop(wrong_lifecycle);
    drop(lifecycle);
    drop(gateway);
    role_pools.close_and_drop(&pool).await?;
    Ok(())
}

// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use apolysis_contracts::{
    AuthenticatedSourceContext, EvidenceObjectRef, GatewayOperation, OrganizationId, PrincipalKind,
    PrivacyCapability, SourceCapability,
};
use apolysis_gateway::lease_id_digest;
use bytes::Bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        decode_digest, hex_digest, new_crypto_material, open_content, random_identifier,
        seal_content, sha256_bytes, ObjectBinding,
    },
    error::{EvidenceObjectError, EvidenceObjectErrorCode, FailureCause, FailureStage},
    model::{
        evidence_reference, AuthenticatedDeletionComponent, CaptureRequest, EvidenceObjectPolicy,
        EvidenceObjectRunLease, EvidenceObjectState, ObjectLifecycleConfig, OperatorActor,
        PendingObjectUpload, ReapReport, UploadedEvidenceObject, AES_GCM_TAG_BYTES,
        MAX_IJSON_INTEGER,
    },
    storage::{RetrievedObject, S3Storage},
};

const MAX_REAPER_BATCH: u32 = 256;
const RATE_WINDOW_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone)]
pub struct EvidenceObjectLifecycle {
    runtime_pool: PgPool,
    control_pool: PgPool,
    acknowledgement_pool: PgPool,
    storage: S3Storage,
    storage_backend_ref: String,
    storage_backend_binding: [u8; 32],
    encryption_key_ref: String,
    wrapping_key: Arc<Zeroizing<[u8; 32]>>,
    storage_operation_timeout_ms: u64,
    upload_fence_ttl_ms: u64,
    reaper_claim_ttl_ms: u64,
}

#[derive(Clone, Debug)]
struct AuthorizedPolicy {
    privacy_profile_ref: String,
    retention_profile_ref: String,
    policy_revision: u64,
    max_object_size_bytes: u64,
    upload_timeout_ms: u64,
    retention_ms: u64,
    lease_digest: [u8; 32],
    lease_policy_revision: u64,
    lease_expires_at_unix_ms: u64,
}

#[derive(Clone)]
struct ObjectRow {
    organization_id: String,
    object_id: String,
    run_id: String,
    source_registration_id: String,
    source_stream_id: String,
    source_id: String,
    lease_digest: [u8; 32],
    lease_policy_revision: u64,
    required_source_capability: String,
    payload_type: String,
    payload_version: String,
    content_digest: String,
    content_size_bytes: u64,
    ciphertext_size_bytes: u64,
    privacy_profile_ref: String,
    retention_profile_ref: String,
    object_policy_revision: u64,
    requested_retention_ms: u64,
    object_state: EvidenceObjectState,
    lifecycle_revision: u64,
    delete_request_revision: Option<u64>,
    created_at_unix_ms: u64,
    upload_deadline_unix_ms: u64,
    expires_at_unix_ms: u64,
    storage_purged_at_unix_ms: Option<u64>,
    upload_fence_token: Option<String>,
    upload_fence_until_unix_ms: Option<u64>,
}

#[derive(Clone)]
struct StorageMaterial {
    storage_backend_ref: String,
    storage_backend_binding_digest: [u8; 32],
    storage_operation_timeout_ms: u64,
    storage_key: String,
    encryption_key_ref: String,
    encrypted_data_key: Vec<u8>,
    key_wrap_nonce: [u8; 12],
    content_nonce: [u8; 12],
    aad_digest: [u8; 32],
}

#[derive(Clone)]
struct ReaperClaim {
    organization_id: String,
    object_id: String,
    claimed_at_unix_ms: u64,
}

#[derive(Clone, Copy)]
enum ObjectLock {
    None,
    Share,
    Update,
}

impl ObjectRow {
    fn binding<'a>(
        &'a self,
        encryption_key_ref: &'a str,
        storage_backend_binding: &'a [u8; 32],
    ) -> ObjectBinding<'a> {
        ObjectBinding {
            organization_id: &self.organization_id,
            object_id: &self.object_id,
            run_id: &self.run_id,
            source_registration_id: &self.source_registration_id,
            source_stream_id: &self.source_stream_id,
            source_id: &self.source_id,
            lease_digest: &self.lease_digest,
            required_source_capability: &self.required_source_capability,
            payload_type: &self.payload_type,
            payload_version: &self.payload_version,
            content_digest: &self.content_digest,
            content_size_bytes: self.content_size_bytes,
            encryption_key_ref,
            storage_backend_binding,
        }
    }

    fn reference(&self) -> Result<EvidenceObjectRef, EvidenceObjectError> {
        evidence_reference(
            &self.object_id,
            &self.content_digest,
            self.content_size_bytes,
        )
    }
}

fn sql_i64(value: u64) -> Result<i64, EvidenceObjectError> {
    i64::try_from(value).map_err(|_| EvidenceObjectError::invalid())
}

fn sql_u64(value: i64) -> Result<u64, EvidenceObjectError> {
    u64::try_from(value).map_err(|_| EvidenceObjectError::database())
}

async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
    stage: FailureStage,
) -> Result<u64, EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    sql_u64(
        sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?,
    )
}

async fn begin_served_transaction(
    pool: &PgPool,
    stage: FailureStage,
    operation_timeout_ms: u64,
) -> Result<Transaction<'_, Postgres>, EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    let mut transaction = pool.begin().await.map_err(map_database_error)?;
    let has_origin_replication_role: bool =
        sqlx::query_scalar("SELECT current_setting('session_replication_role', false) = 'origin'")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
    if !has_origin_replication_role {
        return Err(EvidenceObjectError::database_invariant(stage));
    }
    let operation_timeout = format!("{operation_timeout_ms}ms");
    sqlx::query(
        "SELECT set_config('lock_timeout',$1,true), \
                set_config('statement_timeout',$1,true)",
    )
    .bind(operation_timeout)
    .execute(&mut *transaction)
    .await
    .map_err(map_database_error)?;
    Ok(transaction)
}

async fn lock_upload_identity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    source_registration_id: &str,
    client_upload_id: &str,
) -> Result<(), EvidenceObjectError> {
    let map_database_error = |error| map_database_error(FailureStage::BeginUpload, error);
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(\
            'apolysis.evidence-object-upload/v1:' || length($1)::text || ':' || $1 || \
            ':' || length($2)::text || ':' || $2 || ':' || length($3)::text || ':' || $3,\
            0\
         ))",
    )
    .bind(organization_id)
    .bind(source_registration_id)
    .bind(client_upload_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

fn principal_kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Human => "human",
        PrincipalKind::Workload => "workload",
    }
}

fn capability_name(capability: SourceCapability) -> Result<String, EvidenceObjectError> {
    serde_json::to_value(capability)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(EvidenceObjectError::invalid)
}

fn parse_capability(value: &str) -> Result<SourceCapability, EvidenceObjectError> {
    match value {
        "semantic_lifecycle" => Ok(SourceCapability::SemanticLifecycle),
        "delegation" => Ok(SourceCapability::Delegation),
        "tool_calls" => Ok(SourceCapability::ToolCalls),
        "mcp" => Ok(SourceCapability::Mcp),
        "a2a" => Ok(SourceCapability::A2a),
        "policy_decisions" => Ok(SourceCapability::PolicyDecisions),
        "policy_actuation" => Ok(SourceCapability::PolicyActuation),
        "process" => Ok(SourceCapability::Process),
        "file" => Ok(SourceCapability::File),
        "network" => Ok(SourceCapability::Network),
        "identity" => Ok(SourceCapability::Identity),
        "workload" => Ok(SourceCapability::Workload),
        "claimed_outcome" => Ok(SourceCapability::ClaimedOutcome),
        "verified_outcome" => Ok(SourceCapability::VerifiedOutcome),
        "source_health" => Ok(SourceCapability::SourceHealth),
        _ => Err(EvidenceObjectError::database()),
    }
}

fn evidence_lease_digest(lease: &EvidenceObjectRunLease) -> Result<[u8; 32], EvidenceObjectError> {
    decode_digest(&lease_id_digest(lease.lease_id.as_str()))
}

fn ensure_lease_request_scope(
    lease: &EvidenceObjectRunLease,
    request: &CaptureRequest,
) -> Result<(), EvidenceObjectError> {
    if lease.run_id != request.run_id || lease.source_stream_id != request.source_stream_id {
        return Err(EvidenceObjectError::unauthorized());
    }
    Ok(())
}

fn capture_digest(
    request: &CaptureRequest,
    lease_digest: &[u8; 32],
) -> Result<[u8; 32], EvidenceObjectError> {
    let canonical =
        serde_json_canonicalizer::to_vec(request).map_err(|_| EvidenceObjectError::invalid())?;
    let mut digest = Sha256::new();
    digest.update(b"apolysis.evidence-object-capture-request/v1\0");
    digest.update(lease_digest);
    digest.update(canonical);
    Ok(digest.finalize().into())
}

fn array_12(value: Vec<u8>) -> Result<[u8; 12], EvidenceObjectError> {
    value
        .try_into()
        .map_err(|_| EvidenceObjectError::database())
}

fn array_32(value: Vec<u8>) -> Result<[u8; 32], EvidenceObjectError> {
    value
        .try_into()
        .map_err(|_| EvidenceObjectError::database())
}

fn decode_object_row(row: &PgRow) -> Result<ObjectRow, EvidenceObjectError> {
    let digest: Vec<u8> = row
        .try_get("content_digest")
        .map_err(map_database_decode_error)?;
    if digest.len() != 32 {
        return Err(EvidenceObjectError::database());
    }
    let lease_digest: Vec<u8> = row
        .try_get("lease_digest")
        .map_err(map_database_decode_error)?;
    Ok(ObjectRow {
        organization_id: row
            .try_get("organization_id")
            .map_err(map_database_decode_error)?,
        object_id: row
            .try_get("object_id")
            .map_err(map_database_decode_error)?,
        run_id: row.try_get("run_id").map_err(map_database_decode_error)?,
        source_registration_id: row
            .try_get("source_registration_id")
            .map_err(map_database_decode_error)?,
        source_stream_id: row
            .try_get("source_stream_id")
            .map_err(map_database_decode_error)?,
        source_id: row
            .try_get("source_id")
            .map_err(map_database_decode_error)?,
        lease_digest: array_32(lease_digest)?,
        lease_policy_revision: sql_u64(
            row.try_get("lease_policy_revision")
                .map_err(map_database_decode_error)?,
        )?,
        required_source_capability: row
            .try_get("required_source_capability")
            .map_err(map_database_decode_error)?,
        payload_type: row
            .try_get("payload_type")
            .map_err(map_database_decode_error)?,
        payload_version: row
            .try_get("payload_version")
            .map_err(map_database_decode_error)?,
        content_digest: hex_digest(&digest),
        content_size_bytes: sql_u64(
            row.try_get("content_size_bytes")
                .map_err(map_database_decode_error)?,
        )?,
        ciphertext_size_bytes: sql_u64(
            row.try_get("ciphertext_size_bytes")
                .map_err(map_database_decode_error)?,
        )?,
        privacy_profile_ref: row
            .try_get("privacy_profile_ref")
            .map_err(map_database_decode_error)?,
        retention_profile_ref: row
            .try_get("retention_profile_ref")
            .map_err(map_database_decode_error)?,
        object_policy_revision: sql_u64(
            row.try_get("object_policy_revision")
                .map_err(map_database_decode_error)?,
        )?,
        requested_retention_ms: sql_u64(
            row.try_get("requested_retention_ms")
                .map_err(map_database_decode_error)?,
        )?,
        object_state: EvidenceObjectState::parse(
            row.try_get::<String, _>("object_state")
                .map_err(map_database_decode_error)?
                .as_str(),
        )?,
        lifecycle_revision: sql_u64(
            row.try_get("lifecycle_revision")
                .map_err(map_database_decode_error)?,
        )?,
        delete_request_revision: row
            .try_get::<Option<i64>, _>("delete_request_revision")
            .map_err(map_database_decode_error)?
            .map(sql_u64)
            .transpose()?,
        created_at_unix_ms: sql_u64(
            row.try_get("created_at_unix_ms")
                .map_err(map_database_decode_error)?,
        )?,
        upload_deadline_unix_ms: sql_u64(
            row.try_get("upload_deadline_unix_ms")
                .map_err(map_database_decode_error)?,
        )?,
        expires_at_unix_ms: sql_u64(
            row.try_get("expires_at_unix_ms")
                .map_err(map_database_decode_error)?,
        )?,
        storage_purged_at_unix_ms: row
            .try_get::<Option<i64>, _>("storage_purged_at_unix_ms")
            .map_err(map_database_decode_error)?
            .map(sql_u64)
            .transpose()?,
        upload_fence_token: row
            .try_get("upload_fence_token")
            .map_err(map_database_decode_error)?,
        upload_fence_until_unix_ms: row
            .try_get::<Option<i64>, _>("upload_fence_until_unix_ms")
            .map_err(map_database_decode_error)?
            .map(sql_u64)
            .transpose()?,
    })
}

fn decode_material(row: &PgRow) -> Result<StorageMaterial, EvidenceObjectError> {
    Ok(StorageMaterial {
        storage_backend_ref: row
            .try_get("storage_backend_ref")
            .map_err(map_database_decode_error)?,
        storage_backend_binding_digest: array_32(
            row.try_get("storage_backend_binding_digest")
                .map_err(map_database_decode_error)?,
        )?,
        storage_operation_timeout_ms: sql_u64(
            row.try_get("storage_operation_timeout_ms")
                .map_err(map_database_decode_error)?,
        )?,
        storage_key: row
            .try_get("storage_key")
            .map_err(map_database_decode_error)?,
        encryption_key_ref: row
            .try_get("encryption_key_ref")
            .map_err(map_database_decode_error)?,
        encrypted_data_key: row
            .try_get("encrypted_data_key")
            .map_err(map_database_decode_error)?,
        key_wrap_nonce: array_12(
            row.try_get("key_wrap_nonce")
                .map_err(map_database_decode_error)?,
        )?,
        content_nonce: array_12(
            row.try_get("content_nonce")
                .map_err(map_database_decode_error)?,
        )?,
        aad_digest: array_32(
            row.try_get("aad_digest")
                .map_err(map_database_decode_error)?,
        )?,
    })
}

fn map_database_error(stage: FailureStage, error: sqlx::Error) -> EvidenceObjectError {
    let constraint = error
        .as_database_error()
        .and_then(|database| database.constraint());
    match constraint {
        Some("evidence_object_rate_limit_ck") => EvidenceObjectError::new(
            EvidenceObjectErrorCode::RateLimited,
            "Evidence object upload rate was exceeded",
            true,
        )
        .with_diagnostic(stage, FailureCause::DatabaseRejected),
        Some("evidence_object_quota_ck") => EvidenceObjectError::new(
            EvidenceObjectErrorCode::QuotaExceeded,
            "Evidence object organization quota was exceeded",
            true,
        )
        .with_diagnostic(stage, FailureCause::DatabaseRejected),
        Some("evidence_object_upload_identity_uq") => EvidenceObjectError::new(
            EvidenceObjectErrorCode::Conflict,
            "Evidence object upload identity conflicts with durable state",
            false,
        )
        .with_diagnostic(stage, FailureCause::DatabaseRejected),
        Some("evidence_object_current_lease_ck")
        | Some("evidence_object_deletion_ack_authority_ck")
        | Some("evidence_object_deletion_ack_provenance_ck") => EvidenceObjectError::unauthorized()
            .with_diagnostic(stage, FailureCause::DatabaseRejected),
        Some("evidence_object_storage_backend_binding_ck") => {
            EvidenceObjectError::storage_failure(stage, FailureCause::DatabaseRejected)
        }
        _ => EvidenceObjectError::database_failure(stage, &error),
    }
}

fn map_database_decode_error(error: sqlx::Error) -> EvidenceObjectError {
    EvidenceObjectError::database_failure(FailureStage::DatabaseDecode, &error)
}

const OBJECT_SELECT: &str = "SELECT object.organization_id, object.object_id, object.run_id, \
            object.source_registration_id, object.source_stream_id, object.source_id, \
            object.lease_digest, object.lease_policy_revision, \
            object.required_source_capability, object.payload_type, \
            object.payload_version, \
            object.content_digest, object.content_size_bytes, object.ciphertext_size_bytes, \
            object.privacy_profile_ref, object.retention_profile_ref, \
            object.object_policy_revision, object.requested_retention_ms, \
            object.object_state, object.lifecycle_revision, object.delete_request_revision, \
            object.created_at_unix_ms, object.upload_deadline_unix_ms, object.expires_at_unix_ms, \
            object.storage_purged_at_unix_ms, object.upload_fence_token, \
            object.upload_fence_until_unix_ms \
     FROM apolysis_gateway.evidence_objects AS object";

const REAPER_ELIGIBILITY: &str = r#"
    (
        object.object_state='uploading' AND (
            LEAST(
                object.upload_deadline_unix_ms,
                object.created_at_unix_ms + COALESCE((
                    SELECT policy.upload_timeout_ms
                    FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                    WHERE policy.organization_id=object.organization_id
                      AND policy.privacy_profile_ref=object.privacy_profile_ref
                      AND policy.retention_profile_ref=object.retention_profile_ref
                      AND policy.policy_state='active'
                      AND policy.effective_at_unix_ms<=$1
                ), object.upload_deadline_unix_ms-object.created_at_unix_ms)
            )<=$1
            OR NOT EXISTS (
                SELECT 1
                FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                WHERE policy.organization_id=object.organization_id
                  AND policy.privacy_profile_ref=object.privacy_profile_ref
                  AND policy.retention_profile_ref=object.retention_profile_ref
                  AND policy.policy_state='active'
                  AND policy.effective_at_unix_ms<=$1
                  AND object.content_size_bytes<=policy.max_object_size_bytes
                  AND object.requested_retention_ms<=policy.retention_ms
            )
            OR NOT EXISTS (
                SELECT 1
                FROM apolysis_gateway.organizations AS organization
                JOIN apolysis_gateway.runs AS run
                  ON run.organization_id=organization.organization_id
                JOIN apolysis_gateway.source_registrations AS registration
                  ON registration.organization_id=organization.organization_id
                JOIN apolysis_gateway.leases AS lease
                  ON lease.organization_id=organization.organization_id
                 AND lease.run_id=run.run_id
                 AND lease.source_registration_id=registration.source_registration_id
                JOIN apolysis_gateway.lease_operations AS lease_operation
                  ON lease_operation.organization_id=lease.organization_id
                 AND lease_operation.lease_digest=lease.lease_digest
                 AND lease_operation.operation_kind='ingest'
                WHERE organization.organization_id=object.organization_id
                  AND organization.organization_state='active'
                  AND run.run_id=object.run_id
                  AND run.state IN ('active','finishing')
                  AND registration.source_registration_id=object.source_registration_id
                  AND registration.source_id=object.source_id
                  AND registration.registration_state='active'
                  AND registration.policy_revision=object.lease_policy_revision
                  AND registration.effective_at_unix_ms<=$1
                  AND registration.expires_at_unix_ms>$1
                  AND lease.lease_digest=object.lease_digest
                  AND lease.source_stream_id=object.source_stream_id
                  AND lease.source_id=object.source_id
                  AND lease.registration_policy_revision=object.lease_policy_revision
                  AND lease.issued_at_unix_ms<=$1
                  AND lease.expires_at_unix_ms>$1
                  AND lease.revoked_at_unix_ms IS NULL
            )
        )
        OR object.object_state='available' AND (
            LEAST(
                object.expires_at_unix_ms,
                object.created_at_unix_ms + COALESCE((
                    SELECT policy.retention_ms
                    FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                    WHERE policy.organization_id=object.organization_id
                      AND policy.privacy_profile_ref=object.privacy_profile_ref
                      AND policy.retention_profile_ref=object.retention_profile_ref
                      AND policy.policy_state='active'
                      AND policy.effective_at_unix_ms<=$1
                ), object.requested_retention_ms)
            )<=$1
            OR NOT EXISTS (
                SELECT 1
                FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                WHERE policy.organization_id=object.organization_id
                  AND policy.privacy_profile_ref=object.privacy_profile_ref
                  AND policy.retention_profile_ref=object.retention_profile_ref
                  AND policy.policy_state='active'
                  AND policy.effective_at_unix_ms<=$1
                  AND object.content_size_bytes<=policy.max_object_size_bytes
                  AND object.requested_retention_ms<=policy.retention_ms
            )
        )
        OR object.object_state='delete_pending' AND (
            object.storage_purged_at_unix_ms IS NULL
            OR NOT EXISTS (
                SELECT 1
                FROM apolysis_gateway.evidence_object_deletion_requirements AS requirement
                WHERE requirement.organization_id=object.organization_id
                  AND requirement.object_id=object.object_id
                  AND requirement.lifecycle_revision=object.delete_request_revision
                  AND NOT EXISTS (
                      SELECT 1
                      FROM apolysis_gateway.evidence_object_deletion_acknowledgements AS ack
                      WHERE ack.organization_id=requirement.organization_id
                        AND ack.object_id=requirement.object_id
                        AND ack.lifecycle_revision=requirement.lifecycle_revision
                        AND ack.component_id=requirement.component_id
                  )
            )
        )
    )
    AND (object.reap_claim_until_unix_ms IS NULL
         OR object.reap_claim_until_unix_ms<=$1)
    AND (object.upload_fence_until_unix_ms IS NULL
         OR object.upload_fence_until_unix_ms<=$1)
"#;

impl EvidenceObjectLifecycle {
    async fn authorize_source_owner_for_delete(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        object: &ObjectRow,
        now: u64,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::DeleteRequest, error);
        if object.organization_id != context.organization_id().as_str()
            || object.source_registration_id != context.source_registration_id()
            || object.source_id != context.registration_policy().source_id().as_str()
            || now >= context.authentication().expires_at_unix_ms()
            || !context
                .registration_policy()
                .allowed_operations()
                .contains(&GatewayOperation::Ingest)
        {
            return Err(EvidenceObjectError::not_found());
        }
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_organization_shared($1)",
        )
        .bind(&object.organization_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.organizations \
             WHERE organization_id=$1 AND organization_state='active')",
        )
        .bind(&object.organization_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_run_shared($1,$2)",
        )
        .bind(&object.organization_id)
        .bind(&object.run_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.runs \
             WHERE organization_id=$1 AND run_id=$2 \
               AND state=ANY($3::text[]))",
        )
        .bind(&object.organization_id)
        .bind(&object.run_id)
        .bind(["opening", "active", "finishing", "finished", "incomplete"])
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_source_authority_shared($1,$2,$3,$4,$5)",
        )
        .bind(&object.organization_id)
        .bind(&object.source_registration_id)
        .bind(context.authentication().credential_id())
        .bind(&object.run_id)
        .bind(&object.source_stream_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM apolysis_gateway.source_registrations AS registration \
             JOIN apolysis_gateway.transport_credentials AS credential \
               ON credential.organization_id=registration.organization_id \
              AND credential.source_registration_id=registration.source_registration_id \
             JOIN apolysis_gateway.source_streams AS stream \
               ON stream.organization_id=registration.organization_id \
              AND stream.source_registration_id=registration.source_registration_id \
             WHERE registration.organization_id=$1 \
               AND registration.source_registration_id=$2 AND registration.source_id=$3 \
               AND registration.principal_kind=$4 AND registration.principal_id=$5 \
               AND registration.registration_state='active' \
               AND registration.policy_revision=$6 \
               AND registration.effective_at_unix_ms<=$7 \
               AND registration.expires_at_unix_ms>$7 \
               AND credential.credential_id=$8 \
               AND credential.credential_epoch=registration.credential_epoch \
               AND credential.effective_at_unix_ms<=$7 \
               AND credential.expires_at_unix_ms>$7 \
               AND credential.revoked_at_unix_ms IS NULL \
               AND stream.run_id=$9 AND stream.source_stream_id=$10 \
               AND stream.source_id=registration.source_id",
        )
        .bind(&object.organization_id)
        .bind(&object.source_registration_id)
        .bind(&object.source_id)
        .bind(principal_kind_name(context.principal().kind()))
        .bind(context.principal().id())
        .bind(sql_i64(context.authentication().policy_revision())?)
        .bind(sql_i64(now)?)
        .bind(context.authentication().credential_id())
        .bind(&object.run_id)
        .bind(&object.source_stream_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        Ok(())
    }

    /// Construct the lifecycle around plane-specific externally owned pools.
    ///
    /// Because the caller controls physical connection creation, every
    /// lifecycle transaction independently rejects PostgreSQL sessions whose
    /// replication role is not `origin` before running mutable SQL.
    pub fn new(
        runtime_pool: PgPool,
        control_pool: PgPool,
        acknowledgement_pool: PgPool,
        config: ObjectLifecycleConfig,
    ) -> Self {
        let storage = S3Storage::new(&config);
        let storage_operation_timeout_ms = config.operation_timeout.as_millis() as u64;
        let upload_fence_ttl_ms = storage_operation_timeout_ms
            .saturating_mul(3)
            .saturating_add(5_000);
        Self {
            runtime_pool,
            control_pool,
            acknowledgement_pool,
            storage,
            storage_backend_ref: config.storage_backend_ref,
            storage_backend_binding: config.storage_backend_binding,
            encryption_key_ref: config.encryption_key_ref,
            wrapping_key: Arc::new(config.wrapping_key),
            storage_operation_timeout_ms,
            upload_fence_ttl_ms,
            reaper_claim_ttl_ms: config.reaper_claim_ttl.as_millis() as u64,
        }
    }

    /// Require an authenticated S3 bucket operation before accepting capture
    /// traffic. An HTTP health endpoint is not semantic readiness.
    pub async fn probe_storage(&self) -> Result<(), EvidenceObjectError> {
        self.storage.probe_bucket().await
    }

    /// Install an immutable active policy revision through the trusted control
    /// plane. Existing active revisions for the same profile pair are retired
    /// in the same PostgreSQL transaction.
    pub async fn install_policy(
        &self,
        _actor: &OperatorActor,
        policy: &EvidenceObjectPolicy,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::ControlPolicy, error);
        let mut transaction = begin_served_transaction(
            &self.control_pool,
            FailureStage::ControlPolicy,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::ControlPolicy).await?;
        if policy.effective_at_unix_ms > now {
            return Err(EvidenceObjectError::invalid());
        }
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_organization($1)",
        )
        .bind(policy.organization_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        if let Some(existing) = sqlx::query(
            "SELECT policy_revision, max_object_size_bytes, organization_quota_bytes, \
                    organization_quota_objects, uploads_per_minute, upload_timeout_ms, \
                    retention_ms, effective_at_unix_ms \
             FROM apolysis_gateway.evidence_object_policy_revisions \
             WHERE organization_id=$1 AND privacy_profile_ref=$2 \
               AND retention_profile_ref=$3 AND policy_state='active' \
             FOR UPDATE",
        )
        .bind(policy.organization_id.as_str())
        .bind(&policy.privacy_profile_ref)
        .bind(&policy.retention_profile_ref)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database_error)?
        {
            let revision = sql_u64(
                existing
                    .try_get("policy_revision")
                    .map_err(map_database_decode_error)?,
            )?;
            if revision == policy.policy_revision {
                let identical = sql_u64(
                    existing
                        .try_get("max_object_size_bytes")
                        .map_err(map_database_decode_error)?,
                )? == policy.max_object_size_bytes
                    && sql_u64(
                        existing
                            .try_get("organization_quota_bytes")
                            .map_err(map_database_decode_error)?,
                    )? == policy.organization_quota_bytes
                    && sql_u64(
                        existing
                            .try_get("organization_quota_objects")
                            .map_err(map_database_decode_error)?,
                    )? == policy.organization_quota_objects
                    && sql_u64(
                        existing
                            .try_get("uploads_per_minute")
                            .map_err(map_database_decode_error)?,
                    )? == policy.uploads_per_minute
                    && sql_u64(
                        existing
                            .try_get("upload_timeout_ms")
                            .map_err(map_database_decode_error)?,
                    )? == policy.upload_timeout_ms
                    && sql_u64(
                        existing
                            .try_get("retention_ms")
                            .map_err(map_database_decode_error)?,
                    )? == policy.retention_ms
                    && sql_u64(
                        existing
                            .try_get("effective_at_unix_ms")
                            .map_err(map_database_decode_error)?,
                    )? == policy.effective_at_unix_ms;
                if identical {
                    transaction.commit().await.map_err(map_database_error)?;
                    return Ok(());
                }
                return Err(EvidenceObjectError::new(
                    EvidenceObjectErrorCode::Conflict,
                    "Evidence object policy revision conflicts with durable state",
                    false,
                ));
            }
            if revision >= policy.policy_revision {
                return Err(EvidenceObjectError::new(
                    EvidenceObjectErrorCode::Conflict,
                    "Evidence object policy revision is stale",
                    false,
                ));
            }
            sqlx::query(
                "UPDATE apolysis_gateway.evidence_object_policy_revisions \
                 SET policy_state='retired', retired_at_unix_ms=$4 \
                 WHERE organization_id=$1 AND privacy_profile_ref=$2 \
                   AND retention_profile_ref=$3 AND policy_state='active'",
            )
            .bind(policy.organization_id.as_str())
            .bind(&policy.privacy_profile_ref)
            .bind(&policy.retention_profile_ref)
            .bind(sql_i64(now)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        }
        sqlx::query(
            "INSERT INTO apolysis_gateway.evidence_object_policy_revisions (\
                organization_id, privacy_profile_ref, retention_profile_ref, policy_revision, \
                policy_state, max_object_size_bytes, organization_quota_bytes, \
                organization_quota_objects, uploads_per_minute, upload_timeout_ms, \
                retention_ms, effective_at_unix_ms, retired_at_unix_ms, created_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,$11,NULL,$12)",
        )
        .bind(policy.organization_id.as_str())
        .bind(&policy.privacy_profile_ref)
        .bind(&policy.retention_profile_ref)
        .bind(sql_i64(policy.policy_revision)?)
        .bind(sql_i64(policy.max_object_size_bytes)?)
        .bind(sql_i64(policy.organization_quota_bytes)?)
        .bind(sql_i64(policy.organization_quota_objects)?)
        .bind(sql_i64(policy.uploads_per_minute)?)
        .bind(sql_i64(policy.upload_timeout_ms)?)
        .bind(sql_i64(policy.retention_ms)?)
        .bind(sql_i64(policy.effective_at_unix_ms)?)
        .bind(sql_i64(now)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        transaction.commit().await.map_err(map_database_error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize_scope(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        request: &CaptureRequest,
        now: u64,
        allowed_states: &[&str],
        stage: FailureStage,
    ) -> Result<AuthorizedPolicy, EvidenceObjectError> {
        let map_database_error = |error| map_database_error(stage, error);
        ensure_lease_request_scope(lease, request)?;
        if now >= context.authentication().expires_at_unix_ms()
            || !context
                .registration_policy()
                .allowed_operations()
                .contains(&GatewayOperation::Ingest)
            || !context
                .registration_policy()
                .allowed_privacy_capabilities()
                .contains(&PrivacyCapability::AuthorizedContentReference)
            || !context
                .registration_policy()
                .allowed_capabilities()
                .contains(&request.required_source_capability)
        {
            return Err(EvidenceObjectError::unauthorized());
        }
        let capability = capability_name(request.required_source_capability)?;
        let lease_digest = evidence_lease_digest(lease)?;

        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_organization_shared($1)",
        )
        .bind(context.organization_id().as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.organizations \
             WHERE organization_id=$1 AND organization_state='active')",
        )
        .bind(context.organization_id().as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;

        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_run_shared($1,$2)",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id.as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;

        let run = sqlx::query(
            "SELECT privacy_profile_ref, retention_profile_ref \
             FROM apolysis_gateway.runs \
             WHERE organization_id=$1 AND run_id=$2 AND state=ANY($3::text[])",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id.as_str())
        .bind(allowed_states)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        let privacy_profile_ref: String = run
            .try_get("privacy_profile_ref")
            .map_err(map_database_decode_error)?;
        let retention_profile_ref: String = run
            .try_get("retention_profile_ref")
            .map_err(map_database_decode_error)?;

        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_lease_shared($1,$2)",
        )
        .bind(context.organization_id().as_str())
        .bind(lease_digest.as_slice())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;

        let lease_row = sqlx::query(
            "SELECT registration_policy_revision, expires_at_unix_ms \
             FROM apolysis_gateway.leases \
             WHERE organization_id=$1 AND lease_digest=$2 AND run_id=$3 \
               AND source_registration_id=$4 AND source_stream_id=$5 AND source_id=$6 \
               AND principal_kind=$7 AND principal_id=$8 \
               AND registration_policy_revision=$9 \
               AND issued_at_unix_ms<=$10 AND expires_at_unix_ms>$10 \
               AND revoked_at_unix_ms IS NULL",
        )
        .bind(context.organization_id().as_str())
        .bind(lease_digest.as_slice())
        .bind(request.run_id.as_str())
        .bind(context.source_registration_id())
        .bind(&request.source_stream_id)
        .bind(context.registration_policy().source_id().as_str())
        .bind(principal_kind_name(context.principal().kind()))
        .bind(context.principal().id())
        .bind(sql_i64(context.authentication().policy_revision())?)
        .bind(sql_i64(now)?)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        let lease_policy_revision = sql_u64(
            lease_row
                .try_get("registration_policy_revision")
                .map_err(map_database_decode_error)?,
        )?;
        let lease_expires_at_unix_ms = sql_u64(
            lease_row
                .try_get("expires_at_unix_ms")
                .map_err(map_database_decode_error)?,
        )?;
        let has_ingest = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.lease_operations \
             WHERE organization_id=$1 AND lease_digest=$2 AND operation_kind='ingest')",
        )
        .bind(context.organization_id().as_str())
        .bind(lease_digest.as_slice())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?;
        if !has_ingest {
            return Err(EvidenceObjectError::unauthorized());
        }

        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_source_authority_shared($1,$2,$3,$4,$5)",
        )
        .bind(context.organization_id().as_str())
        .bind(context.source_registration_id())
        .bind(context.authentication().credential_id())
        .bind(request.run_id.as_str())
        .bind(&request.source_stream_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;

        let row = sqlx::query(
            "SELECT object_policy.privacy_profile_ref, object_policy.retention_profile_ref, \
                    object_policy.policy_revision, object_policy.max_object_size_bytes, \
                    object_policy.upload_timeout_ms, object_policy.retention_ms \
             FROM apolysis_gateway.source_registrations AS registration \
             JOIN apolysis_gateway.transport_credentials AS credential \
               ON credential.organization_id=registration.organization_id \
              AND credential.source_registration_id=registration.source_registration_id \
             JOIN apolysis_gateway.source_streams AS stream \
               ON stream.organization_id=registration.organization_id \
              AND stream.source_registration_id=registration.source_registration_id \
             JOIN apolysis_gateway.source_stream_capabilities AS stream_capability \
               ON stream_capability.organization_id=stream.organization_id \
              AND stream_capability.run_id=stream.run_id \
              AND stream_capability.source_registration_id=stream.source_registration_id \
              AND stream_capability.source_stream_id=stream.source_stream_id \
             JOIN apolysis_gateway.evidence_object_policy_revisions AS object_policy \
               ON object_policy.organization_id=registration.organization_id \
             WHERE registration.organization_id=$1 AND registration.source_registration_id=$2 \
               AND registration.source_id=$3 \
               AND registration.principal_kind=$4 AND registration.principal_id=$5 \
               AND registration.registration_state='active' \
               AND registration.policy_revision=$6 \
               AND registration.effective_at_unix_ms<=$7 \
               AND registration.expires_at_unix_ms>$7 \
               AND registration.policy_document->'allowed_privacy_capabilities' \
                    ? 'authorized_content_reference' \
               AND registration.policy_document->'allowed_capabilities' ? $8 \
               AND credential.credential_id=$9 \
               AND credential.credential_epoch=registration.credential_epoch \
               AND credential.effective_at_unix_ms<=$7 \
               AND credential.expires_at_unix_ms>$7 \
               AND credential.revoked_at_unix_ms IS NULL \
               AND stream.run_id=$10 AND stream.source_stream_id=$11 \
               AND stream.source_id=registration.source_id \
               AND stream.registration_policy_revision=registration.policy_revision \
               AND stream.manifest_json->'privacy_capabilities' \
                    ? 'authorized_content_reference' \
               AND stream_capability.capability=$8 \
               AND object_policy.privacy_profile_ref=$12 \
               AND object_policy.retention_profile_ref=$13 \
               AND object_policy.policy_state='active' \
               AND object_policy.effective_at_unix_ms<=$7",
        )
        .bind(context.organization_id().as_str())
        .bind(context.source_registration_id())
        .bind(context.registration_policy().source_id().as_str())
        .bind(principal_kind_name(context.principal().kind()))
        .bind(context.principal().id())
        .bind(sql_i64(context.authentication().policy_revision())?)
        .bind(sql_i64(now)?)
        .bind(&capability)
        .bind(context.authentication().credential_id())
        .bind(request.run_id.as_str())
        .bind(&request.source_stream_id)
        .bind(&privacy_profile_ref)
        .bind(&retention_profile_ref)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database_error)?
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        Ok(AuthorizedPolicy {
            privacy_profile_ref: row
                .try_get("privacy_profile_ref")
                .map_err(map_database_decode_error)?,
            retention_profile_ref: row
                .try_get("retention_profile_ref")
                .map_err(map_database_decode_error)?,
            policy_revision: sql_u64(
                row.try_get("policy_revision")
                    .map_err(map_database_decode_error)?,
            )?,
            max_object_size_bytes: sql_u64(
                row.try_get("max_object_size_bytes")
                    .map_err(map_database_decode_error)?,
            )?,
            upload_timeout_ms: sql_u64(
                row.try_get("upload_timeout_ms")
                    .map_err(map_database_decode_error)?,
            )?,
            retention_ms: sql_u64(
                row.try_get("retention_ms")
                    .map_err(map_database_decode_error)?,
            )?,
            lease_digest,
            lease_policy_revision,
            lease_expires_at_unix_ms,
        })
    }

    pub async fn begin_upload(
        &self,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        request: &CaptureRequest,
    ) -> Result<PendingObjectUpload, EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::BeginUpload, error);
        let lease_digest = evidence_lease_digest(lease)?;
        let request_digest = capture_digest(request, &lease_digest)?;
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::BeginUpload,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::BeginUpload).await?;
        let policy = self
            .authorize_scope(
                &mut transaction,
                context,
                lease,
                request,
                now,
                &["active"],
                FailureStage::BeginUpload,
            )
            .await?;
        if request.size_bytes > policy.max_object_size_bytes
            || request.requested_retention_ms > policy.retention_ms
            || request.requested_retention_ms <= policy.upload_timeout_ms
        {
            return Err(EvidenceObjectError::new(
                EvidenceObjectErrorCode::QuotaExceeded,
                "Evidence object exceeds the active policy",
                false,
            ));
        }
        lock_upload_identity(
            &mut transaction,
            context.organization_id().as_str(),
            context.source_registration_id(),
            &request.client_upload_id,
        )
        .await?;
        if let Some(existing) = sqlx::query(&format!(
            "{OBJECT_SELECT} WHERE object.organization_id=$1 \
             AND object.source_registration_id=$2 AND object.client_upload_id=$3 FOR UPDATE"
        ))
        .bind(context.organization_id().as_str())
        .bind(context.source_registration_id())
        .bind(&request.client_upload_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database_error)?
        {
            let stored_digest: Vec<u8> = sqlx::query_scalar(
                "SELECT capture_request_digest FROM apolysis_gateway.evidence_objects \
                 WHERE organization_id=$1 AND object_id=$2",
            )
            .bind(context.organization_id().as_str())
            .bind(
                existing
                    .try_get::<String, _>("object_id")
                    .map_err(map_database_decode_error)?,
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            if stored_digest.as_slice() != request_digest {
                return Err(EvidenceObjectError::new(
                    EvidenceObjectErrorCode::Conflict,
                    "Evidence object upload identity conflicts with durable state",
                    false,
                ));
            }
            let object = decode_object_row(&existing)?;
            if matches!(
                object.object_state,
                EvidenceObjectState::DeletePending | EvidenceObjectState::Deleted
            ) {
                return Err(EvidenceObjectError::expired());
            }
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(PendingObjectUpload {
                organization_id: context.organization_id().clone(),
                object_id: object.object_id,
            });
        }

        let object_id = random_identifier("object_")?;
        let storage_key = random_identifier("storage_")?;
        let capability = capability_name(request.required_source_capability)?;
        let upload_deadline = now
            .checked_add(policy.upload_timeout_ms)
            .map(|value| value.min(policy.lease_expires_at_unix_ms))
            .filter(|value| *value <= MAX_IJSON_INTEGER)
            .ok_or_else(EvidenceObjectError::invalid)?;
        let expires_at = now
            .checked_add(request.requested_retention_ms)
            .filter(|value| *value <= MAX_IJSON_INTEGER)
            .ok_or_else(EvidenceObjectError::invalid)?;
        let binding = ObjectBinding {
            organization_id: context.organization_id().as_str(),
            object_id: &object_id,
            run_id: request.run_id.as_str(),
            source_registration_id: context.source_registration_id(),
            source_stream_id: &request.source_stream_id,
            source_id: context.registration_policy().source_id().as_str(),
            lease_digest: &policy.lease_digest,
            required_source_capability: &capability,
            payload_type: &request.payload_type,
            payload_version: &request.payload_version,
            content_digest: &request.sha256,
            content_size_bytes: request.size_bytes,
            storage_backend_binding: &self.storage_backend_binding,
            encryption_key_ref: &self.encryption_key_ref,
        };
        let crypto = new_crypto_material(self.wrapping_key.as_ref(), &binding)?;
        let content_digest = decode_digest(&request.sha256)?;
        let reserved = sqlx::query(
            "INSERT INTO apolysis_gateway.evidence_objects (\
                organization_id, object_id, run_id, source_registration_id, source_stream_id, \
                source_id, lease_digest, lease_policy_revision, client_upload_id, \
                capture_request_digest, required_source_capability, \
                payload_type, payload_version, content_digest, content_size_bytes, \
                ciphertext_size_bytes, object_state, privacy_profile_ref, retention_profile_ref, \
                object_policy_revision, requested_retention_ms, lifecycle_revision, \
                delete_request_revision, \
                created_at_unix_ms, upload_deadline_unix_ms, available_at_unix_ms, \
                expires_at_unix_ms, access_denied_at_unix_ms, delete_requested_at_unix_ms, \
                storage_purged_at_unix_ms, purged_at_unix_ms, delete_reason, \
                upload_fence_token, upload_fence_started_at_unix_ms, \
                upload_fence_until_unix_ms, reap_claimed_by, reap_claimed_at_unix_ms, \
                reap_claim_until_unix_ms\
             ) VALUES (\
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'uploading',\
                $17,$18,$19,$20,1,NULL,$21,$22,NULL,$23,NULL,NULL,NULL,NULL,NULL,\
                NULL,NULL,NULL,NULL,NULL,NULL\
             ) RETURNING created_at_unix_ms, upload_deadline_unix_ms, expires_at_unix_ms",
        )
        .bind(context.organization_id().as_str())
        .bind(&object_id)
        .bind(request.run_id.as_str())
        .bind(context.source_registration_id())
        .bind(&request.source_stream_id)
        .bind(context.registration_policy().source_id().as_str())
        .bind(policy.lease_digest.as_slice())
        .bind(sql_i64(policy.lease_policy_revision)?)
        .bind(&request.client_upload_id)
        .bind(request_digest.as_slice())
        .bind(&capability)
        .bind(&request.payload_type)
        .bind(&request.payload_version)
        .bind(content_digest.as_slice())
        .bind(sql_i64(request.size_bytes)?)
        .bind(sql_i64(request.size_bytes + AES_GCM_TAG_BYTES)?)
        .bind(&policy.privacy_profile_ref)
        .bind(&policy.retention_profile_ref)
        .bind(sql_i64(policy.policy_revision)?)
        .bind(sql_i64(request.requested_retention_ms)?)
        .bind(sql_i64(now)?)
        .bind(sql_i64(upload_deadline)?)
        .bind(sql_i64(expires_at)?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let durable_created_at = sql_u64(
            reserved
                .try_get("created_at_unix_ms")
                .map_err(map_database_decode_error)?,
        )?;
        let durable_upload_deadline = sql_u64(
            reserved
                .try_get("upload_deadline_unix_ms")
                .map_err(map_database_decode_error)?,
        )?;
        let durable_expires_at = sql_u64(
            reserved
                .try_get("expires_at_unix_ms")
                .map_err(map_database_decode_error)?,
        )?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.evidence_object_storage_material (\
                organization_id, object_id, storage_backend_ref, storage_backend_binding_digest, \
                storage_operation_timeout_ms, storage_key, storage_etag, \
                storage_version_id, encryption_algorithm, cipher_version, encryption_key_ref, \
                encrypted_data_key, key_wrap_nonce, content_nonce, aad_digest\
             ) VALUES ($1,$2,$3,$4,$5,$6,NULL,NULL,'aes-256-gcm',1,$7,$8,$9,$10,$11)",
        )
        .bind(context.organization_id().as_str())
        .bind(&object_id)
        .bind(&self.storage_backend_ref)
        .bind(self.storage_backend_binding.as_slice())
        .bind(sql_i64(self.storage_operation_timeout_ms)?)
        .bind(storage_key)
        .bind(&self.encryption_key_ref)
        .bind(&crypto.encrypted_data_key)
        .bind(crypto.key_wrap_nonce.as_slice())
        .bind(crypto.content_nonce.as_slice())
        .bind(crypto.aad_digest.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        insert_outbox(
            &mut transaction,
            context.organization_id().as_str(),
            &object_id,
            1,
            "upload_reserved",
            json!({
                "object_id": object_id,
                "state": "uploading",
                "upload_deadline_unix_ms": durable_upload_deadline,
                "expires_at_unix_ms": durable_expires_at,
                "size_bytes": request.size_bytes,
            }),
            durable_created_at,
            FailureStage::BeginUpload,
        )
        .await?;
        insert_audit(
            &mut transaction,
            context.organization_id().as_str(),
            Some(&object_id),
            Some(1),
            durable_created_at,
            "source",
            context.source_registration_id(),
            "reserve_upload",
            "allowed",
            "privacy_authorized",
            json!({"size_bytes": request.size_bytes}),
            FailureStage::BeginUpload,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)?;
        Ok(PendingObjectUpload {
            organization_id: context.organization_id().clone(),
            object_id,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    object_id: &str,
    lifecycle_revision: u64,
    event_kind: &str,
    event_json: Value,
    now: u64,
    stage: FailureStage,
) -> Result<(), EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_outbox (\
            organization_id, object_id, lifecycle_revision, event_kind, event_json, \
            delivery_state, attempt_count, available_at_unix_ms, claimed_by, \
            claimed_at_unix_ms, claim_until_unix_ms, published_at_unix_ms, \
            last_error_code, created_at_unix_ms\
         ) VALUES ($1,$2,$3,$4,$5,'pending',0,$6,NULL,NULL,NULL,NULL,NULL,$6)",
    )
    .bind(organization_id)
    .bind(object_id)
    .bind(sql_i64(lifecycle_revision)?)
    .bind(event_kind)
    .bind(event_json)
    .bind(sql_i64(now)?)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    object_id: Option<&str>,
    lifecycle_revision: Option<u64>,
    now: u64,
    actor_kind: &str,
    actor_id: &str,
    action: &str,
    decision: &str,
    reason_code: &str,
    metadata_json: Value,
    stage: FailureStage,
) -> Result<(), EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    sqlx::query(
        "INSERT INTO apolysis_gateway.evidence_object_audit (\
            organization_id, object_id, lifecycle_revision, occurred_at_unix_ms, \
            actor_kind, actor_id, action, decision, reason_code, metadata_json\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(organization_id)
    .bind(object_id)
    .bind(lifecycle_revision.map(sql_i64).transpose()?)
    .bind(sql_i64(now)?)
    .bind(actor_kind)
    .bind(actor_id)
    .bind(action)
    .bind(decision)
    .bind(reason_code)
    .bind(metadata_json)
    .execute(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

async fn load_object(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    object_id: &str,
    lock: ObjectLock,
    stage: FailureStage,
) -> Result<ObjectRow, EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    let lock_clause = match lock {
        ObjectLock::None => "",
        ObjectLock::Share => " FOR SHARE OF object",
        ObjectLock::Update => " FOR UPDATE OF object",
    };
    let row = sqlx::query(&format!(
        "{OBJECT_SELECT} WHERE object.organization_id=$1 AND object.object_id=$2{lock_clause}"
    ))
    .bind(organization_id)
    .bind(object_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?
    .ok_or_else(EvidenceObjectError::not_found)?;
    decode_object_row(&row)
}

async fn reaper_claim_is_current(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &ReaperClaim,
    worker_id: &str,
    stage: FailureStage,
) -> Result<bool, EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    let current: (Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT reap_claimed_by, reap_claimed_at_unix_ms \
         FROM apolysis_gateway.evidence_objects \
         WHERE organization_id=$1 AND object_id=$2",
    )
    .bind(&claim.organization_id)
    .bind(&claim.object_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_database_error)?;
    Ok(current.0.as_deref() == Some(worker_id)
        && current.1 == Some(sql_i64(claim.claimed_at_unix_ms)?))
}

async fn require_current_reaper_claim(
    transaction: &mut Transaction<'_, Postgres>,
    claim: &ReaperClaim,
    worker_id: &str,
    stage: FailureStage,
) -> Result<(), EvidenceObjectError> {
    if !reaper_claim_is_current(transaction, claim, worker_id, stage).await? {
        return Err(EvidenceObjectError::new(
            EvidenceObjectErrorCode::Conflict,
            "Evidence object reaper claim was lost",
            true,
        ));
    }
    Ok(())
}

async fn load_material(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    object_id: &str,
    for_update: bool,
    stage: FailureStage,
) -> Result<StorageMaterial, EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    let lock = if for_update {
        " FOR UPDATE"
    } else {
        " FOR SHARE"
    };
    let row = sqlx::query(&format!(
        "SELECT storage_backend_ref, storage_backend_binding_digest, \
                storage_operation_timeout_ms, storage_key, encryption_key_ref, \
                encrypted_data_key, key_wrap_nonce, content_nonce, aad_digest \
         FROM apolysis_gateway.evidence_object_storage_material \
         WHERE organization_id=$1 AND object_id=$2{lock}"
    ))
    .bind(organization_id)
    .bind(object_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database_error)?
    .ok_or_else(EvidenceObjectError::not_found)?;
    decode_material(&row)
}

fn request_from_object(object: &ObjectRow) -> Result<CaptureRequest, EvidenceObjectError> {
    CaptureRequest::new(
        apolysis_contracts::RunId::try_from(object.run_id.as_str())
            .map_err(|_| EvidenceObjectError::database())?,
        &object.source_stream_id,
        "durable_object_scope",
        parse_capability(&object.required_source_capability)?,
        &object.payload_type,
        &object.payload_version,
        &object.content_digest,
        object.content_size_bytes,
        1,
    )
}

impl EvidenceObjectLifecycle {
    #[allow(clippy::too_many_arguments)]
    async fn authorize_object(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        object: &ObjectRow,
        now: u64,
        allowed_states: &[&str],
        stage: FailureStage,
    ) -> Result<(), EvidenceObjectError> {
        if object.organization_id != context.organization_id().as_str()
            || object.source_registration_id != context.source_registration_id()
            || object.source_id != context.registration_policy().source_id().as_str()
        {
            return Err(EvidenceObjectError::not_found());
        }
        let policy = self
            .authorize_scope(
                transaction,
                context,
                lease,
                &request_from_object(object)?,
                now,
                allowed_states,
                stage,
            )
            .await?;
        if object.lease_digest != policy.lease_digest
            || object.lease_policy_revision != policy.lease_policy_revision
            || object.privacy_profile_ref != policy.privacy_profile_ref
            || object.retention_profile_ref != policy.retention_profile_ref
            || object.content_size_bytes > policy.max_object_size_bytes
            || object.requested_retention_ms > policy.retention_ms
        {
            return Err(EvidenceObjectError::unauthorized());
        }
        let current_expiry = object
            .created_at_unix_ms
            .checked_add(policy.retention_ms)
            .map(|value| value.min(object.expires_at_unix_ms))
            .ok_or_else(EvidenceObjectError::database)?;
        let current_upload_deadline = object
            .created_at_unix_ms
            .checked_add(policy.upload_timeout_ms)
            .map(|value| {
                value
                    .min(object.upload_deadline_unix_ms)
                    .min(policy.lease_expires_at_unix_ms)
            })
            .ok_or_else(EvidenceObjectError::database)?;
        if now >= current_expiry
            || (object.object_state == EvidenceObjectState::Uploading
                && now >= current_upload_deadline)
        {
            return Err(EvidenceObjectError::expired());
        }
        Ok(())
    }

    fn ensure_material_matches(
        &self,
        material: &StorageMaterial,
    ) -> Result<(), EvidenceObjectError> {
        if material.storage_backend_ref != self.storage_backend_ref
            || material.storage_backend_binding_digest != self.storage_backend_binding
            || material.storage_operation_timeout_ms != self.storage_operation_timeout_ms
            || material.encryption_key_ref != self.encryption_key_ref
        {
            return Err(EvidenceObjectError::storage());
        }
        Ok(())
    }

    async fn retrieve_and_verify(
        &self,
        object: &ObjectRow,
        material: &StorageMaterial,
    ) -> Result<RetrievedObject, EvidenceObjectError> {
        self.ensure_material_matches(material)?;
        let retrieved = self
            .storage
            .get_exact(&material.storage_key, object.ciphertext_size_bytes)
            .await?;
        let plaintext = open_content(
            self.wrapping_key.as_ref(),
            &object.binding(&self.encryption_key_ref, &self.storage_backend_binding),
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &retrieved.bytes,
        )?;
        if plaintext.len() as u64 != object.content_size_bytes
            || sha256_bytes(&plaintext) != decode_digest(&object.content_digest)?
        {
            return Err(EvidenceObjectError::integrity());
        }
        Ok(retrieved)
    }

    async fn clear_upload_fence(
        &self,
        organization_id: &str,
        object_id: &str,
        fence_token: &str,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::UploadClaim, error);
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::UploadClaim,
            self.storage_operation_timeout_ms,
        )
        .await?;
        database_now(&mut transaction, FailureStage::UploadClaim).await?;
        sqlx::query(
            "UPDATE apolysis_gateway.evidence_objects \
             SET upload_fence_token=NULL, upload_fence_started_at_unix_ms=NULL, \
                 upload_fence_until_unix_ms=NULL \
             WHERE organization_id=$1 AND object_id=$2 AND upload_fence_token=$3",
        )
        .bind(organization_id)
        .bind(object_id)
        .bind(fence_token)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        transaction.commit().await.map_err(map_database_error)
    }

    /// Encrypt and put the reserved content. A failed or outcome-unknown PUT
    /// is reconciled with a full authenticated GET; blind overwrite retries are
    /// never used.
    pub async fn upload_pending(
        &self,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        pending: &PendingObjectUpload,
        plaintext: Bytes,
    ) -> Result<UploadedEvidenceObject, EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::UploadClaim, error);
        if pending.organization_id != *context.organization_id() {
            return Err(EvidenceObjectError::not_found());
        }
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::UploadClaim,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::UploadClaim).await?;
        let scope = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            &pending.object_id,
            ObjectLock::None,
            FailureStage::UploadClaim,
        )
        .await?;
        self.authorize_object(
            &mut transaction,
            context,
            lease,
            &scope,
            now,
            &["active", "finishing"],
            FailureStage::UploadClaim,
        )
        .await?;
        let object = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            &pending.object_id,
            ObjectLock::Update,
            FailureStage::UploadClaim,
        )
        .await?;
        if object.object_state == EvidenceObjectState::Available {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(UploadedEvidenceObject {
                organization_id: pending.organization_id.clone(),
                object_id: pending.object_id.clone(),
            });
        }
        if object.object_state != EvidenceObjectState::Uploading
            || now >= object.upload_deadline_unix_ms
        {
            transaction.commit().await.map_err(map_database_error)?;
            if object.object_state == EvidenceObjectState::Uploading {
                let _ = self
                    .transition_system_delete(
                        context.organization_id().as_str(),
                        &pending.object_id,
                        "upload_expired",
                        context.source_registration_id(),
                    )
                    .await;
            }
            return Err(EvidenceObjectError::expired());
        }
        if object.upload_fence_token.is_some()
            && object
                .upload_fence_until_unix_ms
                .is_some_and(|until| until > now)
        {
            return Err(EvidenceObjectError::new(
                EvidenceObjectErrorCode::Conflict,
                "Evidence object upload is already in progress",
                true,
            ));
        }
        let material = load_material(
            &mut transaction,
            context.organization_id().as_str(),
            &pending.object_id,
            true,
            FailureStage::UploadClaim,
        )
        .await?;
        self.ensure_material_matches(&material)?;
        let fence_token = random_identifier("upload_fence_")?;
        let fence_until = now
            .checked_add(self.upload_fence_ttl_ms)
            .filter(|value| *value <= MAX_IJSON_INTEGER)
            .ok_or_else(EvidenceObjectError::database)?;
        sqlx::query(
            "UPDATE apolysis_gateway.evidence_objects \
             SET upload_fence_token=$3, upload_fence_started_at_unix_ms=$4, \
                 upload_fence_until_unix_ms=$5 \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(&pending.object_id)
        .bind(&fence_token)
        .bind(sql_i64(now)?)
        .bind(sql_i64(fence_until)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        transaction.commit().await.map_err(map_database_error)?;

        if plaintext.len() as u64 != object.content_size_bytes
            || sha256_bytes(&plaintext) != decode_digest(&object.content_digest)?
        {
            self.clear_upload_fence(
                context.organization_id().as_str(),
                &pending.object_id,
                &fence_token,
            )
            .await?;
            self.transition_system_delete(
                context.organization_id().as_str(),
                &pending.object_id,
                "integrity_mismatch",
                context.source_registration_id(),
            )
            .await?;
            return Err(EvidenceObjectError::integrity());
        }
        let ciphertext = seal_content(
            self.wrapping_key.as_ref(),
            &object.binding(&self.encryption_key_ref, &self.storage_backend_binding),
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &plaintext,
        )?;
        let put_result = self
            .storage
            .put_if_absent(&material.storage_key, ciphertext)
            .await;
        if put_result.is_err() && self.retrieve_and_verify(&object, &material).await.is_err() {
            // The PUT outcome is unknown. Keep the durable fence until its
            // database-controlled expiry so a late provider commit cannot
            // outlive deletion and physical reconciliation.
            return Err(EvidenceObjectError::storage());
        }
        self.clear_upload_fence(
            context.organization_id().as_str(),
            &pending.object_id,
            &fence_token,
        )
        .await?;
        Ok(UploadedEvidenceObject {
            organization_id: pending.organization_id.clone(),
            object_id: pending.object_id.clone(),
        })
    }

    /// Perform a bounded full GET, decrypt, and verify exact SHA-256 and size
    /// before making the object available to atomic ingest binding.
    pub async fn finalize_upload(
        &self,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        uploaded: &UploadedEvidenceObject,
    ) -> Result<EvidenceObjectRef, EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::UploadFinalize, error);
        if uploaded.organization_id != *context.organization_id() {
            return Err(EvidenceObjectError::not_found());
        }
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::UploadFinalize,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::UploadFinalize).await?;
        let scope = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            ObjectLock::None,
            FailureStage::UploadFinalize,
        )
        .await?;
        self.authorize_object(
            &mut transaction,
            context,
            lease,
            &scope,
            now,
            &["active", "finishing"],
            FailureStage::UploadFinalize,
        )
        .await?;
        let object = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            ObjectLock::Share,
            FailureStage::UploadFinalize,
        )
        .await?;
        if object.object_state == EvidenceObjectState::Available {
            transaction.commit().await.map_err(map_database_error)?;
            return object.reference();
        }
        if object.object_state != EvidenceObjectState::Uploading
            || now >= object.upload_deadline_unix_ms
            || now >= object.expires_at_unix_ms
        {
            transaction.commit().await.map_err(map_database_error)?;
            if object.object_state == EvidenceObjectState::Uploading {
                let _ = self
                    .transition_system_delete(
                        context.organization_id().as_str(),
                        &uploaded.object_id,
                        "upload_expired",
                        context.source_registration_id(),
                    )
                    .await;
            }
            return Err(EvidenceObjectError::expired());
        }
        let material = load_material(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            false,
            FailureStage::UploadFinalize,
        )
        .await?;
        self.ensure_material_matches(&material)?;
        transaction.commit().await.map_err(map_database_error)?;

        let retrieved = match self.retrieve_and_verify(&object, &material).await {
            Ok(retrieved) => retrieved,
            Err(error) if error.code() == EvidenceObjectErrorCode::IntegrityMismatch => {
                self.transition_system_delete(
                    context.organization_id().as_str(),
                    &uploaded.object_id,
                    "integrity_mismatch",
                    context.source_registration_id(),
                )
                .await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::UploadFinalize,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let commit_now = database_now(&mut transaction, FailureStage::UploadFinalize).await?;
        let scope = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            ObjectLock::None,
            FailureStage::UploadFinalize,
        )
        .await?;
        self.authorize_object(
            &mut transaction,
            context,
            lease,
            &scope,
            commit_now,
            &["active", "finishing"],
            FailureStage::UploadFinalize,
        )
        .await?;
        let locked = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            ObjectLock::Update,
            FailureStage::UploadFinalize,
        )
        .await?;
        if locked.object_state == EvidenceObjectState::Available {
            transaction.commit().await.map_err(map_database_error)?;
            return locked.reference();
        }
        if locked.object_state != EvidenceObjectState::Uploading
            || commit_now >= locked.upload_deadline_unix_ms
            || commit_now >= locked.expires_at_unix_ms
        {
            transaction.rollback().await.map_err(map_database_error)?;
            let _ = self
                .transition_system_delete(
                    context.organization_id().as_str(),
                    &uploaded.object_id,
                    "upload_expired",
                    context.source_registration_id(),
                )
                .await;
            return Err(EvidenceObjectError::expired());
        }
        let locked_material = load_material(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            true,
            FailureStage::UploadFinalize,
        )
        .await?;
        self.ensure_material_matches(&locked_material)?;
        sqlx::query(
            "UPDATE apolysis_gateway.evidence_object_storage_material \
             SET storage_etag=$3, storage_version_id=$4 \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(&uploaded.object_id)
        .bind(retrieved.etag)
        .bind(retrieved.version_id)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let revision = locked
            .lifecycle_revision
            .checked_add(1)
            .ok_or_else(EvidenceObjectError::database)?;
        sqlx::query(
            "UPDATE apolysis_gateway.evidence_objects \
             SET object_state='available', lifecycle_revision=$3, available_at_unix_ms=$4 \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(&uploaded.object_id)
        .bind(sql_i64(revision)?)
        .bind(sql_i64(commit_now)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        insert_outbox(
            &mut transaction,
            context.organization_id().as_str(),
            &uploaded.object_id,
            revision,
            "object_available",
            json!({
                "object_id": uploaded.object_id,
                "state": "available",
                "expires_at_unix_ms": locked.expires_at_unix_ms,
            }),
            commit_now,
            FailureStage::UploadFinalize,
        )
        .await?;
        insert_audit(
            &mut transaction,
            context.organization_id().as_str(),
            Some(&uploaded.object_id),
            Some(revision),
            commit_now,
            "source",
            context.source_registration_id(),
            "finalize_upload",
            "completed",
            "integrity_verified",
            json!({"size_bytes": locked.content_size_bytes}),
            FailureStage::UploadFinalize,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)?;
        locked.reference()
    }

    /// Convenience saga for callers that do not need an explicit crash seam.
    pub async fn capture(
        &self,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        request: &CaptureRequest,
        plaintext: Bytes,
    ) -> Result<EvidenceObjectRef, EvidenceObjectError> {
        let pending = self.begin_upload(context, lease, request).await?;
        let uploaded = self
            .upload_pending(context, lease, &pending, plaintext)
            .await?;
        self.finalize_upload(context, lease, &uploaded).await
    }

    /// Reconcile an outcome-unknown/crashed upload using only the opaque
    /// registry identity. The method performs the same full S3 read-back,
    /// decryption, digest, size, authority, and lifecycle checks as normal
    /// finalization.
    pub async fn reconcile_upload(
        &self,
        context: &AuthenticatedSourceContext,
        lease: &EvidenceObjectRunLease,
        object_id: &str,
    ) -> Result<EvidenceObjectRef, EvidenceObjectError> {
        if OrganizationId::try_from(object_id).is_err() {
            return Err(EvidenceObjectError::invalid());
        }
        self.finalize_upload(
            context,
            lease,
            &UploadedEvidenceObject {
                organization_id: context.organization_id().clone(),
                object_id: object_id.to_string(),
            },
        )
        .await
    }

    async fn transition_source_delete(
        &self,
        context: &AuthenticatedSourceContext,
        object_id: &str,
        reason: &str,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::DeleteRequest, error);
        if apolysis_contracts::OrganizationId::try_from(reason).is_err() {
            return Err(EvidenceObjectError::invalid());
        }
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::DeleteRequest,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::DeleteRequest).await?;
        let scope = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            object_id,
            ObjectLock::None,
            FailureStage::DeleteRequest,
        )
        .await?;
        self.authorize_source_owner_for_delete(&mut transaction, context, &scope, now)
            .await?;
        let object = load_object(
            &mut transaction,
            context.organization_id().as_str(),
            object_id,
            ObjectLock::Update,
            FailureStage::DeleteRequest,
        )
        .await?;
        if object.object_state == EvidenceObjectState::Deleted
            || object.object_state == EvidenceObjectState::DeletePending
        {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(());
        }
        transition_to_delete_pending(
            &mut transaction,
            &object,
            now,
            reason,
            "source",
            context.source_registration_id(),
            FailureStage::DeleteRequest,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)
    }

    async fn transition_system_delete(
        &self,
        organization_id: &str,
        object_id: &str,
        reason: &str,
        actor_id: &str,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::DeleteRequest, error);
        if OrganizationId::try_from(reason).is_err() || OrganizationId::try_from(actor_id).is_err()
        {
            return Err(EvidenceObjectError::invalid());
        }
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::DeleteRequest,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::DeleteRequest).await?;
        let scope = load_object(
            &mut transaction,
            organization_id,
            object_id,
            ObjectLock::None,
            FailureStage::DeleteRequest,
        )
        .await?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_organization_shared($1)",
        )
        .bind(organization_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_run_shared($1,$2)",
        )
        .bind(organization_id)
        .bind(&scope.run_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        let object = load_object(
            &mut transaction,
            organization_id,
            object_id,
            ObjectLock::Update,
            FailureStage::DeleteRequest,
        )
        .await?;
        if matches!(
            object.object_state,
            EvidenceObjectState::DeletePending | EvidenceObjectState::Deleted
        ) {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(());
        }
        transition_to_delete_pending(
            &mut transaction,
            &object,
            now,
            reason,
            "system",
            actor_id,
            FailureStage::DeleteRequest,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)
    }

    /// Immediately deny future ingest/read resolution and enqueue asynchronous
    /// physical purge. Possession of the returned reference never affects this
    /// decision.
    pub async fn request_delete(
        &self,
        context: &AuthenticatedSourceContext,
        object_id: &str,
        reason: &str,
    ) -> Result<(), EvidenceObjectError> {
        self.transition_source_delete(context, object_id, reason)
            .await
    }
}

async fn transition_to_delete_pending(
    transaction: &mut Transaction<'_, Postgres>,
    object: &ObjectRow,
    now: u64,
    reason: &str,
    actor_kind: &str,
    actor_id: &str,
    stage: FailureStage,
) -> Result<u64, EvidenceObjectError> {
    let map_database_error = |error| map_database_error(stage, error);
    let revision = object
        .lifecycle_revision
        .checked_add(1)
        .ok_or_else(EvidenceObjectError::database)?;
    let durable_delete_requested_at = sql_u64(
        sqlx::query_scalar::<_, i64>(
            "UPDATE apolysis_gateway.evidence_objects \
         SET object_state='delete_pending', lifecycle_revision=$3, delete_request_revision=$3, \
             access_denied_at_unix_ms=$4, delete_requested_at_unix_ms=$4, delete_reason=$5, \
             reap_claimed_by=NULL, reap_claimed_at_unix_ms=NULL, \
             reap_claim_until_unix_ms=NULL \
         WHERE organization_id=$1 AND object_id=$2 \
         RETURNING delete_requested_at_unix_ms",
        )
        .bind(&object.organization_id)
        .bind(&object.object_id)
        .bind(sql_i64(revision)?)
        .bind(sql_i64(now)?)
        .bind(reason)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?,
    )?;
    insert_outbox(
        transaction,
        &object.organization_id,
        &object.object_id,
        revision,
        "deletion_requested",
        json!({
            "object_id": object.object_id,
            "state": "delete_pending",
            "reason_code": reason,
        }),
        durable_delete_requested_at,
        stage,
    )
    .await?;
    insert_audit(
        transaction,
        &object.organization_id,
        Some(&object.object_id),
        Some(revision),
        durable_delete_requested_at,
        actor_kind,
        actor_id,
        if reason == "integrity_mismatch" {
            "reject_upload"
        } else {
            "request_delete"
        },
        "allowed",
        reason,
        json!({}),
        stage,
    )
    .await?;
    Ok(revision)
}

impl EvidenceObjectLifecycle {
    /// Extend a still-readable object's shorter requested lifetime up to, but
    /// never beyond, its immutable policy ceiling. Deleted or already expired
    /// objects cannot be revived.
    pub async fn extend_retention(
        &self,
        actor: &OperatorActor,
        organization_id: &OrganizationId,
        object_id: &str,
        new_expires_at_unix_ms: u64,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::ControlRetention, error);
        if OrganizationId::try_from(object_id).is_err()
            || new_expires_at_unix_ms == 0
            || new_expires_at_unix_ms > MAX_IJSON_INTEGER
        {
            return Err(EvidenceObjectError::invalid());
        }
        let mut transaction = begin_served_transaction(
            &self.control_pool,
            FailureStage::ControlRetention,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::ControlRetention).await?;
        let scope = load_object(
            &mut transaction,
            organization_id.as_str(),
            object_id,
            ObjectLock::None,
            FailureStage::ControlRetention,
        )
        .await?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_organization($1)",
        )
        .bind(organization_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.organizations \
             WHERE organization_id=$1 AND organization_state='active')",
        )
        .bind(organization_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .then_some(())
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        let policy = sqlx::query(
            "SELECT policy_revision, retention_ms \
             FROM apolysis_gateway.evidence_object_policy_revisions \
             WHERE organization_id=$1 AND privacy_profile_ref=$2 \
               AND retention_profile_ref=$3 AND policy_state='active' \
               AND effective_at_unix_ms<=$4 FOR SHARE",
        )
        .bind(organization_id.as_str())
        .bind(&scope.privacy_profile_ref)
        .bind(&scope.retention_profile_ref)
        .bind(sql_i64(now)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database_error)?
        .ok_or_else(EvidenceObjectError::unauthorized)?;
        let current_policy_revision = sql_u64(
            policy
                .try_get("policy_revision")
                .map_err(map_database_decode_error)?,
        )?;
        let retention_ms = sql_u64(
            policy
                .try_get("retention_ms")
                .map_err(map_database_decode_error)?,
        )?;
        let object = load_object(
            &mut transaction,
            organization_id.as_str(),
            object_id,
            ObjectLock::Update,
            FailureStage::ControlRetention,
        )
        .await?;
        if !matches!(
            object.object_state,
            EvidenceObjectState::Uploading | EvidenceObjectState::Available
        ) || now >= object.expires_at_unix_ms
        {
            return Err(EvidenceObjectError::expired());
        }
        let ceiling = object
            .created_at_unix_ms
            .checked_add(retention_ms)
            .ok_or_else(EvidenceObjectError::database)?;
        if new_expires_at_unix_ms == object.expires_at_unix_ms && new_expires_at_unix_ms <= ceiling
        {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(());
        }
        if new_expires_at_unix_ms <= object.expires_at_unix_ms || new_expires_at_unix_ms > ceiling {
            return Err(EvidenceObjectError::new(
                EvidenceObjectErrorCode::Unauthorized,
                "Evidence object retention extension is not authorized",
                false,
            ));
        }
        let revision = object
            .lifecycle_revision
            .checked_add(1)
            .ok_or_else(EvidenceObjectError::database)?;
        sqlx::query(
            "UPDATE apolysis_gateway.evidence_objects \
             SET expires_at_unix_ms=$3, lifecycle_revision=$4 \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(organization_id.as_str())
        .bind(object_id)
        .bind(sql_i64(new_expires_at_unix_ms)?)
        .bind(sql_i64(revision)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        insert_outbox(
            &mut transaction,
            organization_id.as_str(),
            object_id,
            revision,
            "retention_extended",
            json!({
                "object_id": object_id,
                "state": match object.object_state {
                    EvidenceObjectState::Uploading => "uploading",
                    EvidenceObjectState::Available => "available",
                    EvidenceObjectState::DeletePending => "delete_pending",
                    EvidenceObjectState::Deleted => "deleted",
                },
                "expires_at_unix_ms": new_expires_at_unix_ms,
            }),
            now,
            FailureStage::ControlRetention,
        )
        .await?;
        insert_audit(
            &mut transaction,
            organization_id.as_str(),
            Some(object_id),
            Some(revision),
            now,
            "operator",
            &actor.actor_id,
            "extend_retention",
            "allowed",
            "within_policy_ceiling",
            json!({
                "expires_at_unix_ms": new_expires_at_unix_ms,
                "object_policy_revision": object.object_policy_revision,
                "current_policy_revision": current_policy_revision,
            }),
            FailureStage::ControlRetention,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)
    }

    /// Register a component before it begins retaining object reachability.
    /// The registry is append-only; deletion requests snapshot all required
    /// components already registered at request time.
    pub async fn register_deletion_target(
        &self,
        actor: &OperatorActor,
        component: &AuthenticatedDeletionComponent,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::ControlConsumer, error);
        let mut transaction = begin_served_transaction(
            &self.control_pool,
            FailureStage::ControlConsumer,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::ControlConsumer).await?;
        if component.authenticated_at_unix_ms > now || component.expires_at_unix_ms <= now {
            return Err(EvidenceObjectError::unauthorized());
        }
        let organization_locked = sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_organization($1)",
        )
        .bind(component.organization_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if !organization_locked {
            return Err(EvidenceObjectError::unauthorized());
        }
        let organization_active = sqlx::query_scalar::<_, bool>(
            "SELECT organization_state='active' \
             FROM apolysis_gateway.organizations WHERE organization_id=$1",
        )
        .bind(component.organization_id.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if !organization_active {
            return Err(EvidenceObjectError::unauthorized());
        }
        sqlx::query(
            "INSERT INTO apolysis_gateway.evidence_object_deletion_targets (\
                organization_id, component_id, principal_kind, principal_id, required, \
                registered_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,true,$5) \
             ON CONFLICT (organization_id, component_id) DO NOTHING",
        )
        .bind(component.organization_id.as_str())
        .bind(&component.component_id)
        .bind(principal_kind_name(component.principal.kind()))
        .bind(component.principal.id())
        .bind(sql_i64(now)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;

        let target_locked = sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_evidence_object_deletion_target($1,$2)",
        )
        .bind(component.organization_id.as_str())
        .bind(&component.component_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if !target_locked {
            return Err(EvidenceObjectError::database());
        }
        let target_matches = sqlx::query_scalar::<_, bool>(
            "SELECT principal_kind::text=$3 AND principal_id=$4 \
             FROM apolysis_gateway.evidence_object_deletion_targets \
             WHERE organization_id=$1 AND component_id=$2",
        )
        .bind(component.organization_id.as_str())
        .bind(&component.component_id)
        .bind(principal_kind_name(component.principal.kind()))
        .bind(component.principal.id())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if !target_matches {
            return Err(EvidenceObjectError::new(
                EvidenceObjectErrorCode::Conflict,
                "Deletion component identity conflicts with durable state",
                false,
            ));
        }

        let current = sqlx::query(
            "SELECT credential_id, credential_epoch, credential_digest, \
                    expires_at_unix_ms \
             FROM apolysis_gateway.evidence_object_deletion_credentials \
             WHERE organization_id=$1 AND component_id=$2 \
               AND revoked_at_unix_ms IS NULL FOR UPDATE",
        )
        .bind(component.organization_id.as_str())
        .bind(&component.component_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if let Some(current) = current {
            let current_id: String = current
                .try_get("credential_id")
                .map_err(map_database_decode_error)?;
            let current_epoch = sql_u64(
                current
                    .try_get("credential_epoch")
                    .map_err(map_database_decode_error)?,
            )?;
            let current_digest: Vec<u8> = current
                .try_get("credential_digest")
                .map_err(map_database_decode_error)?;
            let current_expiry = sql_u64(
                current
                    .try_get("expires_at_unix_ms")
                    .map_err(map_database_decode_error)?,
            )?;
            if current_id == component.credential_id
                && current_epoch == component.credential_epoch
                && current_digest.as_slice() == component.credential_digest.as_ref()
                && current_expiry == component.expires_at_unix_ms
            {
                transaction.commit().await.map_err(map_database_error)?;
                return Ok(());
            }
            if component.credential_epoch != current_epoch.saturating_add(1) {
                return Err(EvidenceObjectError::new(
                    EvidenceObjectErrorCode::Conflict,
                    "Deletion component credential epoch conflicts with durable state",
                    false,
                ));
            }
            sqlx::query(
                "UPDATE apolysis_gateway.evidence_object_deletion_credentials \
                 SET revoked_at_unix_ms=$3 \
                 WHERE organization_id=$1 AND component_id=$2 \
                   AND revoked_at_unix_ms IS NULL",
            )
            .bind(component.organization_id.as_str())
            .bind(&component.component_id)
            .bind(sql_i64(now)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
        }
        sqlx::query(
            "INSERT INTO apolysis_gateway.evidence_object_deletion_credentials (\
                organization_id, component_id, principal_kind, principal_id, credential_id, \
                credential_epoch, credential_digest, credential_hash_version, \
                effective_at_unix_ms, expires_at_unix_ms, revoked_at_unix_ms, \
                created_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,\
                'apolysis.evidence-deletion-component/v1',$8,$9,NULL,$10)",
        )
        .bind(component.organization_id.as_str())
        .bind(&component.component_id)
        .bind(principal_kind_name(component.principal.kind()))
        .bind(component.principal.id())
        .bind(&component.credential_id)
        .bind(sql_i64(component.credential_epoch)?)
        .bind(&component.credential_digest[..])
        .bind(sql_i64(component.authenticated_at_unix_ms)?)
        .bind(sql_i64(component.expires_at_unix_ms)?)
        .bind(sql_i64(now)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        insert_audit(
            &mut transaction,
            component.organization_id.as_str(),
            None,
            None,
            now,
            "operator",
            &actor.actor_id,
            "register_deletion_target",
            "allowed",
            "authenticated_component",
            json!({"component_id": component.component_id}),
            FailureStage::ControlConsumer,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)
    }

    /// Acknowledge removal from one registered projection/cache/grant/export
    /// component for the exact snapshotted deletion revision.
    pub async fn acknowledge_deletion(
        &self,
        component: &AuthenticatedDeletionComponent,
        object_id: &str,
        delete_request_revision: u64,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::DeletionAck, error);
        if OrganizationId::try_from(object_id).is_err() || delete_request_revision == 0 {
            return Err(EvidenceObjectError::invalid());
        }
        let mut transaction = begin_served_transaction(
            &self.acknowledgement_pool,
            FailureStage::DeletionAck,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let acknowledged = sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.acknowledge_evidence_object_deletion(\
                $1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(component.organization_id.as_str())
        .bind(object_id)
        .bind(&component.component_id)
        .bind(sql_i64(delete_request_revision)?)
        .bind(principal_kind_name(component.principal.kind()))
        .bind(component.principal.id())
        .bind(&component.credential_id)
        .bind(sql_i64(component.credential_epoch)?)
        .bind(&component.credential_digest[..])
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if !acknowledged {
            return Err(EvidenceObjectError::database());
        }
        transaction.commit().await.map_err(map_database_error)
    }

    /// Claim and process a bounded set using PostgreSQL time and real S3
    /// reconciliation. Storage outage leaves objects immediately denied and
    /// quota-reserved until a later pass proves physical purge.
    pub async fn reap_once(
        &self,
        worker_id: &str,
        limit: u32,
    ) -> Result<ReapReport, EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::ReaperClaim, error);
        if OrganizationId::try_from(worker_id).is_err() || limit == 0 || limit > MAX_REAPER_BATCH {
            return Err(EvidenceObjectError::invalid());
        }
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::ReaperClaim,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::ReaperClaim).await?;
        let claim_until = now
            .checked_add(self.reaper_claim_ttl_ms)
            .filter(|value| *value <= MAX_IJSON_INTEGER)
            .ok_or_else(EvidenceObjectError::database)?;
        // The security-definer helper discovers due work and locks ancestor
        // organizations in oldest-attempt order before any object lock. It
        // applies SKIP LOCKED before its bounded LIMIT so one busy or poisoned
        // organization cannot head-of-line block unrelated tenants.
        let locked_organizations = sqlx::query_scalar::<_, String>(
            "SELECT apolysis_gateway.lock_evidence_object_reaper_organizations($1,$2)",
        )
        .bind(sql_i64(now)?)
        .bind(i32::try_from(limit).map_err(|_| EvidenceObjectError::invalid())?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        let rows = if locked_organizations.is_empty() {
            Vec::new()
        } else {
            sqlx::query(&format!(
                "SELECT candidate.* \
                 FROM unnest($2::text[]) WITH ORDINALITY \
                      AS locked_organization(organization_id, priority_order) \
                 JOIN LATERAL ( \
                     {OBJECT_SELECT} \
                     WHERE object.organization_id=locked_organization.organization_id \
                       AND {REAPER_ELIGIBILITY} \
                     ORDER BY coalesce( \
                                  object.reap_claimed_at_unix_ms, \
                                  object.delete_requested_at_unix_ms, \
                                  object.created_at_unix_ms \
                              ), object.object_id \
                     FOR UPDATE OF object SKIP LOCKED LIMIT 1 \
                 ) AS candidate ON true \
                 ORDER BY locked_organization.priority_order"
            ))
            .bind(sql_i64(now)?)
            .bind(&locked_organizations)
            .fetch_all(&mut *transaction)
            .await
            .map_err(map_database_error)?
        };
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let mut object = decode_object_row(&row)?;
            if object.object_state != EvidenceObjectState::DeletePending {
                let reason = if object.object_state == EvidenceObjectState::Uploading {
                    "upload_expired"
                } else {
                    "retention_expired"
                };
                let revision = transition_to_delete_pending(
                    &mut transaction,
                    &object,
                    now,
                    reason,
                    "system",
                    worker_id,
                    FailureStage::ReaperClaim,
                )
                .await?;
                object.object_state = EvidenceObjectState::DeletePending;
                object.lifecycle_revision = revision;
                object.delete_request_revision = Some(revision);
            }
            let claimed_at_unix_ms = sql_u64(
                sqlx::query_scalar::<_, i64>(
                    "UPDATE apolysis_gateway.evidence_objects \
                 SET upload_fence_token=NULL, upload_fence_started_at_unix_ms=NULL, \
                     upload_fence_until_unix_ms=NULL, reap_claimed_by=$3, \
                     reap_claimed_at_unix_ms=$4, reap_claim_until_unix_ms=$5 \
                 WHERE organization_id=$1 AND object_id=$2 \
                 RETURNING reap_claimed_at_unix_ms",
                )
                .bind(&object.organization_id)
                .bind(&object.object_id)
                .bind(worker_id)
                .bind(sql_i64(now)?)
                .bind(sql_i64(claim_until)?)
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_database_error)?,
            )?;
            claimed.push(ReaperClaim {
                organization_id: object.organization_id.clone(),
                object_id: object.object_id.clone(),
                claimed_at_unix_ms,
            });
        }
        transaction.commit().await.map_err(map_database_error)?;

        let mut report = ReapReport {
            claimed: u32::try_from(claimed.len()).map_err(|_| EvidenceObjectError::database())?,
            ..ReapReport::default()
        };
        for claim in claimed {
            match self.purge_claimed(worker_id, &claim).await {
                Ok(true) => report.purged += 1,
                Ok(false) | Err(_) => report.deferred += 1,
            }
        }
        let mut cleanup = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::ReaperClaim,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let cleanup_now = database_now(&mut cleanup, FailureStage::ReaperClaim).await?;
        let cutoff = cleanup_now.saturating_sub(RATE_WINDOW_RETENTION_MS);
        sqlx::query(
            "DELETE FROM apolysis_gateway.evidence_object_rate_windows \
             WHERE window_start_unix_ms<$1",
        )
        .bind(sql_i64(cutoff)?)
        .execute(&mut *cleanup)
        .await
        .map_err(map_database_error)?;
        cleanup.commit().await.map_err(map_database_error)?;
        Ok(report)
    }

    async fn purge_claimed(
        &self,
        worker_id: &str,
        claim: &ReaperClaim,
    ) -> Result<bool, EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::ReaperPurge, error);
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::ReaperPurge,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let object = load_object(
            &mut transaction,
            &claim.organization_id,
            &claim.object_id,
            ObjectLock::Update,
            FailureStage::ReaperPurge,
        )
        .await?;
        if object.object_state != EvidenceObjectState::DeletePending {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(object.object_state == EvidenceObjectState::Deleted);
        }
        require_current_reaper_claim(
            &mut transaction,
            claim,
            worker_id,
            FailureStage::ReaperPurge,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::ReaperPurge).await?;
        if object.upload_fence_token.is_some()
            && object
                .upload_fence_until_unix_ms
                .is_some_and(|until| until > now)
        {
            sqlx::query(
                "UPDATE apolysis_gateway.evidence_objects \
                 SET reap_claimed_by=NULL, reap_claimed_at_unix_ms=NULL, \
                     reap_claim_until_unix_ms=NULL \
                 WHERE organization_id=$1 AND object_id=$2 AND reap_claimed_by=$3 \
                   AND reap_claimed_at_unix_ms=$4",
            )
            .bind(&claim.organization_id)
            .bind(&claim.object_id)
            .bind(worker_id)
            .bind(sql_i64(claim.claimed_at_unix_ms)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(false);
        }
        let material = if object.storage_purged_at_unix_ms.is_none() {
            let material = load_material(
                &mut transaction,
                &claim.organization_id,
                &claim.object_id,
                false,
                FailureStage::ReaperPurge,
            )
            .await?;
            if self.ensure_material_matches(&material).is_err() {
                transaction.rollback().await.map_err(map_database_error)?;
                self.release_failed_claim(worker_id, claim).await?;
                return Err(EvidenceObjectError::storage());
            }
            Some(material)
        } else {
            None
        };
        transaction.commit().await.map_err(map_database_error)?;

        if let Some(material) = material {
            if let Err(error) = self.storage.purge_all_versions(&material.storage_key).await {
                self.release_failed_claim(worker_id, claim).await?;
                return Err(error);
            }
            let mut transaction = begin_served_transaction(
                &self.runtime_pool,
                FailureStage::ReaperPurge,
                self.storage_operation_timeout_ms,
            )
            .await?;
            let purge_time = database_now(&mut transaction, FailureStage::ReaperPurge).await?;
            let locked = load_object(
                &mut transaction,
                &claim.organization_id,
                &claim.object_id,
                ObjectLock::Update,
                FailureStage::ReaperPurge,
            )
            .await?;
            if locked.object_state != EvidenceObjectState::DeletePending {
                transaction.commit().await.map_err(map_database_error)?;
                return Ok(locked.object_state == EvidenceObjectState::Deleted);
            }
            require_current_reaper_claim(
                &mut transaction,
                claim,
                worker_id,
                FailureStage::ReaperPurge,
            )
            .await?;
            sqlx::query(
                "DELETE FROM apolysis_gateway.evidence_object_storage_material \
                 WHERE organization_id=$1 AND object_id=$2",
            )
            .bind(&claim.organization_id)
            .bind(&claim.object_id)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            sqlx::query(
                "UPDATE apolysis_gateway.evidence_objects \
                 SET storage_purged_at_unix_ms=$3 \
                 WHERE organization_id=$1 AND object_id=$2",
            )
            .bind(&claim.organization_id)
            .bind(&claim.object_id)
            .bind(sql_i64(purge_time)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            insert_audit(
                &mut transaction,
                &claim.organization_id,
                Some(&claim.object_id),
                None,
                purge_time,
                "system",
                worker_id,
                "purge_object",
                "completed",
                "storage_absence_verified",
                json!({}),
                FailureStage::ReaperPurge,
            )
            .await?;
            transaction.commit().await.map_err(map_database_error)?;
        }

        let map_database_error =
            |error| crate::service::map_database_error(FailureStage::ReaperComplete, error);
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::ReaperComplete,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let completion_time = database_now(&mut transaction, FailureStage::ReaperComplete).await?;
        let object = load_object(
            &mut transaction,
            &claim.organization_id,
            &claim.object_id,
            ObjectLock::Update,
            FailureStage::ReaperComplete,
        )
        .await?;
        if object.object_state != EvidenceObjectState::DeletePending {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(object.object_state == EvidenceObjectState::Deleted);
        }
        require_current_reaper_claim(
            &mut transaction,
            claim,
            worker_id,
            FailureStage::ReaperComplete,
        )
        .await?;
        let delete_revision = object
            .delete_request_revision
            .ok_or_else(EvidenceObjectError::database)?;
        let missing_ack = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                SELECT 1 \
                FROM apolysis_gateway.evidence_object_deletion_requirements AS requirement \
                WHERE requirement.organization_id=$1 AND requirement.object_id=$2 \
                  AND requirement.lifecycle_revision=$3 \
                  AND NOT EXISTS (\
                      SELECT 1 \
                      FROM apolysis_gateway.evidence_object_deletion_acknowledgements AS ack \
                      WHERE ack.organization_id=requirement.organization_id \
                        AND ack.object_id=requirement.object_id \
                        AND ack.lifecycle_revision=requirement.lifecycle_revision \
                        AND ack.component_id=requirement.component_id\
                  )\
             )",
        )
        .bind(&claim.organization_id)
        .bind(&claim.object_id)
        .bind(sql_i64(delete_revision)?)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        if missing_ack {
            // Storage-purged objects with outstanding deletion requirements
            // are excluded by both candidate predicates. Release this claim
            // so the exact final acknowledgement can make the object
            // immediately eligible without allowing it to monopolize passes.
            sqlx::query(
                "UPDATE apolysis_gateway.evidence_objects \
                 SET reap_claimed_by=NULL, reap_claimed_at_unix_ms=NULL, \
                     reap_claim_until_unix_ms=NULL \
                 WHERE organization_id=$1 AND object_id=$2 AND reap_claimed_by=$3 \
                   AND reap_claimed_at_unix_ms=$4",
            )
            .bind(&claim.organization_id)
            .bind(&claim.object_id)
            .bind(worker_id)
            .bind(sql_i64(claim.claimed_at_unix_ms)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database_error)?;
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(false);
        }
        if object.storage_purged_at_unix_ms.is_none() {
            return Err(EvidenceObjectError::database());
        }
        let revision = object
            .lifecycle_revision
            .checked_add(1)
            .ok_or_else(EvidenceObjectError::database)?;
        sqlx::query(
            "UPDATE apolysis_gateway.evidence_objects \
             SET object_state='deleted', lifecycle_revision=$3, purged_at_unix_ms=$4, \
                 reap_claimed_by=NULL, reap_claimed_at_unix_ms=NULL, \
                 reap_claim_until_unix_ms=NULL \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(&claim.organization_id)
        .bind(&claim.object_id)
        .bind(sql_i64(revision)?)
        .bind(sql_i64(completion_time)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database_error)?;
        insert_outbox(
            &mut transaction,
            &claim.organization_id,
            &claim.object_id,
            revision,
            "object_deleted",
            json!({"object_id": claim.object_id, "state": "deleted"}),
            completion_time,
            FailureStage::ReaperComplete,
        )
        .await?;
        insert_audit(
            &mut transaction,
            &claim.organization_id,
            Some(&claim.object_id),
            Some(revision),
            completion_time,
            "system",
            worker_id,
            "purge_object",
            "completed",
            "deletion_propagated",
            json!({}),
            FailureStage::ReaperComplete,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)?;
        Ok(true)
    }

    async fn release_failed_claim(
        &self,
        worker_id: &str,
        claim: &ReaperClaim,
    ) -> Result<(), EvidenceObjectError> {
        let map_database_error = |error| map_database_error(FailureStage::ReaperComplete, error);
        let mut transaction = begin_served_transaction(
            &self.runtime_pool,
            FailureStage::ReaperComplete,
            self.storage_operation_timeout_ms,
        )
        .await?;
        let now = database_now(&mut transaction, FailureStage::ReaperComplete).await?;
        let object = load_object(
            &mut transaction,
            &claim.organization_id,
            &claim.object_id,
            ObjectLock::Update,
            FailureStage::ReaperComplete,
        )
        .await?;
        if object.object_state != EvidenceObjectState::DeletePending
            || !reaper_claim_is_current(
                &mut transaction,
                claim,
                worker_id,
                FailureStage::ReaperComplete,
            )
            .await?
        {
            transaction.commit().await.map_err(map_database_error)?;
            return Ok(());
        }
        // Preserve the claim's attempt timestamp and bounded TTL after a
        // provider failure. This is durable retry backoff and prevents a
        // poison object from being selected again ahead of untried work.
        insert_audit(
            &mut transaction,
            &claim.organization_id,
            Some(&claim.object_id),
            None,
            now,
            "system",
            worker_id,
            "purge_object",
            "failed",
            "storage_unavailable",
            json!({}),
            FailureStage::ReaperComplete,
        )
        .await?;
        transaction.commit().await.map_err(map_database_error)
    }
}

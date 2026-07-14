// SPDX-License-Identifier: Apache-2.0

use std::{fmt, time::Duration};

use apolysis_contracts::{
    EvidenceObjectRef, GatewayOperation, OpenRunResponse, OrganizationId, PrincipalKind,
    PrincipalRef, RunId, SourceCapability,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{EvidenceObjectError, EvidenceObjectErrorCode};

pub(crate) const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;
pub(crate) const AES_GCM_TAG_BYTES: u64 = 16;

/// Maximum plaintext evidence-object size accepted by the current in-memory
/// encryption and verification implementation (64 MiB).
pub const MAX_IN_MEMORY_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

fn valid_identifier(value: &str) -> bool {
    OrganizationId::try_from(value).is_ok()
}

fn valid_reference(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Runtime-only S3 and envelope-encryption configuration.
pub struct ObjectLifecycleConfig {
    pub(crate) endpoint_url: String,
    pub(crate) region: String,
    pub(crate) bucket: String,
    pub(crate) storage_backend_ref: String,
    pub(crate) storage_backend_binding: [u8; 32],
    pub(crate) access_key_id: Zeroizing<String>,
    pub(crate) secret_access_key: Zeroizing<String>,
    pub(crate) encryption_key_ref: String,
    pub(crate) wrapping_key: Zeroizing<[u8; 32]>,
    pub(crate) operation_timeout: Duration,
    pub(crate) reaper_claim_ttl: Duration,
}

impl ObjectLifecycleConfig {
    /// Build explicit, static S3-compatible client configuration. Credentials
    /// and the wrapping key remain runtime inputs and are never serialized.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_url: impl Into<String>,
        region: impl Into<String>,
        bucket: impl Into<String>,
        storage_backend_ref: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        encryption_key_ref: impl Into<String>,
        wrapping_key: [u8; 32],
        operation_timeout: Duration,
        reaper_claim_ttl: Duration,
    ) -> Result<Self, EvidenceObjectError> {
        let value = Self {
            endpoint_url: endpoint_url.into(),
            region: region.into(),
            bucket: bucket.into(),
            storage_backend_ref: storage_backend_ref.into(),
            storage_backend_binding: [0_u8; 32],
            access_key_id: Zeroizing::new(access_key_id.into()),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            encryption_key_ref: encryption_key_ref.into(),
            wrapping_key: Zeroizing::new(wrapping_key),
            operation_timeout,
            reaper_claim_ttl,
        };
        value.validate()?;
        let mut value = value;
        value.storage_backend_binding = storage_backend_binding(
            &value.endpoint_url,
            &value.region,
            &value.bucket,
            &value.storage_backend_ref,
            &value.wrapping_key,
        )?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), EvidenceObjectError> {
        let endpoint_ok = (self.endpoint_url.starts_with("http://")
            || self.endpoint_url.starts_with("https://"))
            && self.endpoint_url.len() <= 2_048
            && !self.endpoint_url.contains('@')
            && !self.endpoint_url.contains('#')
            && !self.endpoint_url.contains('?');
        let bucket_ok = (3..=63).contains(&self.bucket.len())
            && self
                .bucket
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && self.bucket.as_bytes()[0].is_ascii_alphanumeric()
            && self.bucket.as_bytes()[self.bucket.len() - 1].is_ascii_alphanumeric();
        if !endpoint_ok
            || self.region.is_empty()
            || self.region.len() > 128
            || !bucket_ok
            || !valid_identifier(&self.storage_backend_ref)
            || self.access_key_id.is_empty()
            || self.access_key_id.len() > 256
            || self.secret_access_key.is_empty()
            || self.secret_access_key.len() > 512
            || !valid_reference(&self.encryption_key_ref)
            || self.operation_timeout < Duration::from_millis(100)
            || self.operation_timeout > Duration::from_secs(300)
            || self.reaper_claim_ttl < self.operation_timeout
            || self.reaper_claim_ttl > Duration::from_secs(3_600)
        {
            return Err(EvidenceObjectError::invalid());
        }
        Ok(())
    }
}

fn storage_backend_binding(
    endpoint_url: &str,
    region: &str,
    bucket: &str,
    storage_backend_ref: &str,
    binding_key: &[u8; 32],
) -> Result<[u8; 32], EvidenceObjectError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(binding_key).map_err(|_| EvidenceObjectError::invalid())?;
    mac.update(b"apolysis.evidence-object-storage-backend/v1\0");
    for value in [
        endpoint_url,
        region,
        bucket,
        storage_backend_ref,
        "force_path_style=true",
    ] {
        let length = u64::try_from(value.len()).map_err(|_| EvidenceObjectError::invalid())?;
        mac.update(&length.to_be_bytes());
        mac.update(value.as_bytes());
    }
    Ok(mac.finalize().into_bytes().into())
}

impl fmt::Debug for ObjectLifecycleConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectLifecycleConfig")
            .field("endpoint_url", &"[configured]")
            .field("region", &self.region)
            .field("bucket", &"[configured]")
            .field("storage_backend_ref", &self.storage_backend_ref)
            .field("access_key_id", &"[redacted]")
            .field("secret_access_key", &"[redacted]")
            .field("encryption_key_ref", &self.encryption_key_ref)
            .field("wrapping_key", &"[redacted]")
            .field("operation_timeout", &self.operation_timeout)
            .field("reaper_claim_ttl", &self.reaper_claim_ttl)
            .finish()
    }
}

/// Versioned organization policy installed by the trusted control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceObjectPolicy {
    pub(crate) organization_id: OrganizationId,
    pub(crate) privacy_profile_ref: String,
    pub(crate) retention_profile_ref: String,
    pub(crate) policy_revision: u64,
    pub(crate) max_object_size_bytes: u64,
    pub(crate) organization_quota_bytes: u64,
    pub(crate) organization_quota_objects: u64,
    pub(crate) uploads_per_minute: u64,
    pub(crate) upload_timeout_ms: u64,
    pub(crate) retention_ms: u64,
    pub(crate) effective_at_unix_ms: u64,
}

impl EvidenceObjectPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        privacy_profile_ref: impl Into<String>,
        retention_profile_ref: impl Into<String>,
        policy_revision: u64,
        max_object_size_bytes: u64,
        organization_quota_bytes: u64,
        organization_quota_objects: u64,
        uploads_per_minute: u64,
        upload_timeout_ms: u64,
        retention_ms: u64,
        effective_at_unix_ms: u64,
    ) -> Result<Self, EvidenceObjectError> {
        let value = Self {
            organization_id,
            privacy_profile_ref: privacy_profile_ref.into(),
            retention_profile_ref: retention_profile_ref.into(),
            policy_revision,
            max_object_size_bytes,
            organization_quota_bytes,
            organization_quota_objects,
            uploads_per_minute,
            upload_timeout_ms,
            retention_ms,
            effective_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), EvidenceObjectError> {
        let positive_safe = |value| value > 0 && value <= MAX_IJSON_INTEGER;
        if !valid_identifier(&self.privacy_profile_ref)
            || !valid_identifier(&self.retention_profile_ref)
            || !positive_safe(self.policy_revision)
            || !positive_safe(self.max_object_size_bytes)
            || !positive_safe(self.organization_quota_bytes)
            || !positive_safe(self.organization_quota_objects)
            || !positive_safe(self.uploads_per_minute)
            || !positive_safe(self.upload_timeout_ms)
            || !positive_safe(self.retention_ms)
            || !positive_safe(self.effective_at_unix_ms)
            || self.max_object_size_bytes > self.organization_quota_bytes
            || self.max_object_size_bytes > MAX_IN_MEMORY_OBJECT_BYTES
            || self.upload_timeout_ms >= self.retention_ms
        {
            return Err(EvidenceObjectError::invalid());
        }
        Ok(())
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
}

/// Source request to reserve immutable content metadata before any S3 write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaptureRequest {
    pub(crate) run_id: RunId,
    pub(crate) source_stream_id: String,
    pub(crate) client_upload_id: String,
    pub(crate) required_source_capability: SourceCapability,
    pub(crate) payload_type: String,
    pub(crate) payload_version: String,
    pub(crate) sha256: String,
    pub(crate) size_bytes: u64,
    pub(crate) requested_retention_ms: u64,
}

impl CaptureRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: RunId,
        source_stream_id: impl Into<String>,
        client_upload_id: impl Into<String>,
        required_source_capability: SourceCapability,
        payload_type: impl Into<String>,
        payload_version: impl Into<String>,
        sha256: impl Into<String>,
        size_bytes: u64,
        requested_retention_ms: u64,
    ) -> Result<Self, EvidenceObjectError> {
        let value = Self {
            run_id,
            source_stream_id: source_stream_id.into(),
            client_upload_id: client_upload_id.into(),
            required_source_capability,
            payload_type: payload_type.into(),
            payload_version: payload_version.into(),
            sha256: sha256.into(),
            size_bytes,
            requested_retention_ms,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), EvidenceObjectError> {
        if !valid_identifier(&self.source_stream_id)
            || !valid_identifier(&self.client_upload_id)
            || !valid_identifier(&self.payload_type)
            || !valid_reference(&self.payload_version)
            || !valid_digest(&self.sha256)
            || self.size_bytes == 0
            || self.size_bytes > MAX_IN_MEMORY_OBJECT_BYTES
            || self.requested_retention_ms == 0
            || self.requested_retention_ms > MAX_IJSON_INTEGER
        {
            return Err(EvidenceObjectError::invalid());
        }
        Ok(())
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    pub fn required_source_capability(&self) -> SourceCapability {
        self.required_source_capability
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Opaque reservation handle. It does not contain an S3 bucket, key, URL, or
/// storage credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingObjectUpload {
    pub(crate) organization_id: OrganizationId,
    pub(crate) object_id: String,
}

impl PendingObjectUpload {
    pub fn object_id(&self) -> &str {
        &self.object_id
    }
}

/// Opaque handle proving an S3 PUT completed; availability is granted only
/// after a separate full read-back verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadedEvidenceObject {
    pub(crate) organization_id: OrganizationId,
    pub(crate) object_id: String,
}

impl UploadedEvidenceObject {
    pub fn object_id(&self) -> &str {
        &self.object_id
    }
}

/// Runtime-only lease authority for evidence-object capture. It is derived
/// from an exact Gateway open response, cannot be serialized, and never
/// exposes the bearer lease through its public interface or `Debug` output.
///
/// The bearer intentionally remains available only to crate-internal
/// authorization code:
///
/// ```compile_fail
/// use apolysis_evidence_objects::EvidenceObjectRunLease;
///
/// fn expose(lease: &EvidenceObjectRunLease) -> &str {
///     lease.lease_id.as_str()
/// }
/// ```
///
/// This authority type must never become a wire contract:
///
/// ```compile_fail
/// use apolysis_evidence_objects::EvidenceObjectRunLease;
///
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<EvidenceObjectRunLease>();
/// ```
///
/// ```compile_fail
/// use apolysis_evidence_objects::EvidenceObjectRunLease;
///
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<EvidenceObjectRunLease>();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct EvidenceObjectRunLease {
    pub(crate) run_id: RunId,
    pub(crate) source_stream_id: String,
    pub(crate) lease_id: Zeroizing<String>,
}

impl EvidenceObjectRunLease {
    pub fn from_open_response(response: &OpenRunResponse) -> Result<Self, EvidenceObjectError> {
        let lease_id = response.lease().lease_id();
        if !valid_identifier(lease_id)
            || !valid_identifier(response.source_stream_id())
            || !response
                .lease()
                .allowed_operations()
                .contains(&GatewayOperation::Ingest)
        {
            return Err(EvidenceObjectError::invalid());
        }
        Ok(Self {
            run_id: response.run_id().clone(),
            source_stream_id: response.source_stream_id().to_string(),
            lease_id: Zeroizing::new(lease_id.to_string()),
        })
    }
}

impl fmt::Debug for EvidenceObjectRunLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceObjectRunLease")
            .field("run_id", &self.run_id)
            .field("source_stream_id", &self.source_stream_id)
            .field("lease_id", &"[REDACTED]")
            .finish()
    }
}

/// Server-derived current authority for one deletion-propagation component.
/// The constructor is the application trust seam: callers must populate it
/// only after transport authentication and current registry lookup.
///
/// ```compile_fail
/// use apolysis_evidence_objects::AuthenticatedDeletionComponent;
///
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<AuthenticatedDeletionComponent>();
/// ```
///
/// ```compile_fail
/// use apolysis_evidence_objects::AuthenticatedDeletionComponent;
///
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<AuthenticatedDeletionComponent>();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedDeletionComponent {
    pub(crate) organization_id: OrganizationId,
    pub(crate) component_id: String,
    pub(crate) principal: PrincipalRef,
    pub(crate) credential_id: String,
    pub(crate) credential_epoch: u64,
    pub(crate) credential_digest: Zeroizing<[u8; 32]>,
    pub(crate) authenticated_at_unix_ms: u64,
    pub(crate) expires_at_unix_ms: u64,
}

impl AuthenticatedDeletionComponent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        component_id: impl Into<String>,
        principal_kind: PrincipalKind,
        principal_id: impl Into<String>,
        credential_id: impl Into<String>,
        credential_epoch: u64,
        credential_digest: [u8; 32],
        authenticated_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, EvidenceObjectError> {
        let component_id = component_id.into();
        let credential_id = credential_id.into();
        if !valid_identifier(&component_id)
            || !valid_identifier(&credential_id)
            || credential_epoch == 0
            || credential_epoch > MAX_IJSON_INTEGER
            || authenticated_at_unix_ms == 0
            || expires_at_unix_ms <= authenticated_at_unix_ms
            || expires_at_unix_ms > MAX_IJSON_INTEGER
        {
            return Err(EvidenceObjectError::invalid());
        }
        let principal = PrincipalRef::new(principal_kind, principal_id)
            .map_err(|_| EvidenceObjectError::invalid())?;
        Ok(Self {
            organization_id,
            component_id,
            principal,
            credential_id,
            credential_epoch,
            credential_digest: Zeroizing::new(credential_digest),
            authenticated_at_unix_ms,
            expires_at_unix_ms,
        })
    }

    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    pub fn component_id(&self) -> &str {
        &self.component_id
    }
}

impl fmt::Debug for AuthenticatedDeletionComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedDeletionComponent")
            .field("organization_id", &self.organization_id)
            .field("component_id", &self.component_id)
            .field("principal", &"[AUTHENTICATED]")
            .field("credential_id", &"[REDACTED]")
            .field("credential_epoch", &self.credential_epoch)
            .field("credential_digest", &"[REDACTED]")
            .field("authenticated_at_unix_ms", &self.authenticated_at_unix_ms)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceObjectState {
    Uploading,
    Available,
    DeletePending,
    Deleted,
}

impl EvidenceObjectState {
    pub(crate) fn parse(value: &str) -> Result<Self, EvidenceObjectError> {
        match value {
            "uploading" => Ok(Self::Uploading),
            "available" => Ok(Self::Available),
            "delete_pending" => Ok(Self::DeletePending),
            "deleted" => Ok(Self::Deleted),
            _ => Err(EvidenceObjectError::database()),
        }
    }
}

/// Trusted operator identity used only by the control-plane retention seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorActor {
    pub(crate) actor_id: String,
}

impl OperatorActor {
    pub fn new(actor_id: impl Into<String>) -> Result<Self, EvidenceObjectError> {
        let actor_id = actor_id.into();
        if !valid_identifier(&actor_id) {
            return Err(EvidenceObjectError::new(
                EvidenceObjectErrorCode::InvalidRequest,
                "Operator identity is invalid",
                false,
            ));
        }
        Ok(Self { actor_id })
    }
}

/// Bounded result from one real reaper pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReapReport {
    pub claimed: u32,
    pub purged: u32,
    pub deferred: u32,
}

pub(crate) fn evidence_reference(
    object_id: &str,
    sha256: &str,
    size_bytes: u64,
) -> Result<EvidenceObjectRef, EvidenceObjectError> {
    EvidenceObjectRef::new(object_id, sha256, size_bytes)
        .map_err(|_| EvidenceObjectError::database())
}

#[cfg(test)]
mod tests {
    use super::*;
    use apolysis_contracts::{OpenRunOutcome, RunLease, SourceId};

    const LEASE_CANARY: &str = "lease_model_secret_canary";
    const CREDENTIAL_CANARY: &str = "credential_model_secret_canary";

    fn open_response(operations: Vec<GatewayOperation>) -> OpenRunResponse {
        OpenRunResponse::new(
            RunId::try_from("run_model_test").expect("run id"),
            SourceId::try_from("source_model_test").expect("source id"),
            "stream_model_test",
            OpenRunOutcome::Created,
            RunLease::new(LEASE_CANARY, 9_000_000, operations).expect("run lease"),
        )
        .expect("open response")
    }

    fn capture_request() -> CaptureRequest {
        CaptureRequest::new(
            RunId::try_from("run_model_test").expect("run id"),
            "stream_model_test",
            "upload_model_test",
            SourceCapability::ToolCalls,
            "tool_blob",
            "1.0.0",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            3,
            2_000,
        )
        .expect("capture request")
    }

    #[test]
    fn run_lease_is_redacted_and_separate_from_serializable_request_and_handles() {
        let lease = EvidenceObjectRunLease::from_open_response(&open_response(vec![
            GatewayOperation::Ingest,
        ]))
        .expect("evidence lease");
        let lease_debug = format!("{lease:?}");
        assert!(!lease_debug.contains(LEASE_CANARY));
        assert!(lease_debug.contains("[REDACTED]"));

        let request_json = serde_json::to_string(&capture_request()).expect("serialize request");
        assert!(!request_json.contains(LEASE_CANARY));

        let pending = PendingObjectUpload {
            organization_id: OrganizationId::try_from("org_model_test").expect("organization id"),
            object_id: "object_model_test".to_string(),
        };
        let uploaded = UploadedEvidenceObject {
            organization_id: pending.organization_id.clone(),
            object_id: pending.object_id.clone(),
        };
        assert!(!format!("{pending:?}").contains(LEASE_CANARY));
        assert!(!format!("{uploaded:?}").contains(LEASE_CANARY));
    }

    #[test]
    fn evidence_lease_requires_an_ingest_grant() {
        let response = open_response(vec![GatewayOperation::FinishRun]);
        assert!(EvidenceObjectRunLease::from_open_response(&response).is_err());
    }

    #[test]
    fn deletion_component_debug_redacts_authenticated_proof() {
        let context = AuthenticatedDeletionComponent::new(
            OrganizationId::try_from("org_model_test").expect("organization id"),
            "projection_model_test",
            PrincipalKind::Workload,
            "principal_model_secret_canary",
            CREDENTIAL_CANARY,
            7,
            [0xab; 32],
            1_000,
            2_000,
        )
        .expect("deletion component context");
        let debug = format!("{context:?}");
        assert!(!debug.contains(CREDENTIAL_CANARY));
        assert!(!debug.contains("principal_model_secret_canary"));
        assert!(!debug.contains(&"ab".repeat(32)));
        assert!(!debug.contains("171, 171, 171"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn backend_binding_covers_locator_and_logical_identity_but_not_credentials() {
        let make_config = |bucket: &str, backend_ref: &str, access_key: &str, secret_key: &str| {
            ObjectLifecycleConfig::new(
                "http://storage.model.test:8333",
                "region-model-1",
                bucket,
                backend_ref,
                access_key,
                secret_key,
                "wrapping_key_model_v1",
                [0x5a; 32],
                Duration::from_secs(1),
                Duration::from_secs(2),
            )
            .expect("object lifecycle config")
        };
        let first = make_config(
            "bucket-model-a",
            "backend_model_a",
            "access_model_a",
            "secret_model_a",
        );
        let rotated_credentials = make_config(
            "bucket-model-a",
            "backend_model_a",
            "access_model_rotated",
            "secret_model_rotated",
        );
        let other_bucket = make_config(
            "bucket-model-b",
            "backend_model_a",
            "access_model_a",
            "secret_model_a",
        );
        let other_reference = make_config(
            "bucket-model-a",
            "backend_model_b",
            "access_model_a",
            "secret_model_a",
        );

        assert_eq!(
            first.storage_backend_binding,
            rotated_credentials.storage_backend_binding
        );
        assert_ne!(
            first.storage_backend_binding,
            other_bucket.storage_backend_binding
        );
        assert_ne!(
            first.storage_backend_binding,
            other_reference.storage_backend_binding
        );

        let debug = format!("{first:?}");
        for canary in [
            "http://storage.model.test:8333",
            "bucket-model-a",
            "access_model_a",
            "secret_model_a",
            &"5a".repeat(32),
            "90, 90, 90",
        ] {
            assert!(!debug.contains(canary), "debug leaked {canary}");
        }
    }

    #[test]
    fn policy_and_capture_request_enforce_the_in_memory_object_ceiling() {
        let policy = |max_object_size_bytes| {
            EvidenceObjectPolicy::new(
                OrganizationId::try_from("org_model_test").expect("organization id"),
                "privacy_model_test",
                "retention_model_test",
                1,
                max_object_size_bytes,
                max_object_size_bytes,
                1,
                1,
                1_000,
                2_000,
                1,
            )
        };
        assert!(policy(MAX_IN_MEMORY_OBJECT_BYTES).is_ok());
        let policy_error =
            policy(MAX_IN_MEMORY_OBJECT_BYTES + 1).expect_err("oversized policy must be rejected");
        assert_eq!(policy_error.code(), EvidenceObjectErrorCode::InvalidRequest);

        let capture = |size_bytes| {
            CaptureRequest::new(
                RunId::try_from("run_model_test").expect("run id"),
                "stream_model_test",
                "upload_model_test",
                SourceCapability::ToolCalls,
                "tool_blob",
                "1.0.0",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                size_bytes,
                2_000,
            )
        };
        assert!(capture(MAX_IN_MEMORY_OBJECT_BYTES).is_ok());
        let capture_error = capture(MAX_IN_MEMORY_OBJECT_BYTES + 1)
            .expect_err("oversized capture request must be rejected");
        assert_eq!(
            capture_error.code(),
            EvidenceObjectErrorCode::InvalidRequest
        );
    }
}

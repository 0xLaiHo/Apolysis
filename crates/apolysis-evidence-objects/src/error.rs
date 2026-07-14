// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use apolysis_contracts::ContractErrorCode;
use aws_sdk_s3::error::SdkError;
use thiserror::Error;

/// Stable, content-free lifecycle error classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceObjectErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    QuotaExceeded,
    RateLimited,
    Backpressure,
    IntegrityMismatch,
    StorageUnavailable,
    Expired,
    DatabaseUnavailable,
}

impl EvidenceObjectErrorCode {
    /// Map the object lifecycle classification into the closed Gateway wire
    /// vocabulary without exposing storage or database details.
    pub fn gateway_code(self) -> ContractErrorCode {
        match self {
            Self::InvalidRequest | Self::IntegrityMismatch => ContractErrorCode::InvalidContract,
            Self::Unauthorized => ContractErrorCode::ContentNotAuthorized,
            Self::NotFound => ContractErrorCode::NotFound,
            Self::Conflict => ContractErrorCode::IdempotencyConflict,
            Self::QuotaExceeded | Self::Backpressure | Self::StorageUnavailable => {
                ContractErrorCode::Backpressure
            }
            Self::RateLimited => ContractErrorCode::RateLimited,
            Self::Expired => ContractErrorCode::InvalidLifecycleTransition,
            Self::DatabaseUnavailable => ContractErrorCode::Backpressure,
        }
    }
}

/// Bounded internal operation stages. These labels are deliberately static:
/// callers must never put SQL, URLs, identifiers, or request data in them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureStage {
    ControlPolicy,
    BeginUpload,
    UploadClaim,
    UploadFinalize,
    DeleteRequest,
    ControlRetention,
    ControlConsumer,
    DeletionAck,
    ReaperClaim,
    ReaperPurge,
    ReaperComplete,
    DatabaseDecode,
    DatabaseInvariant,
    StorageProbe,
    StorageWrite,
    StorageRead,
    StoragePurge,
    EntropyIdentifier,
    EntropyDataKey,
    EntropyKeyWrapNonce,
    EntropyContentNonce,
    CryptographicKeyWrap,
}

impl FailureStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ControlPolicy => "control_policy",
            Self::BeginUpload => "begin_upload",
            Self::UploadClaim => "upload_claim",
            Self::UploadFinalize => "upload_finalize",
            Self::DeleteRequest => "delete_request",
            Self::ControlRetention => "control_retention",
            Self::ControlConsumer => "control_consumer",
            Self::DeletionAck => "deletion_ack",
            Self::ReaperClaim => "reaper_claim",
            Self::ReaperPurge => "reaper_purge",
            Self::ReaperComplete => "reaper_complete",
            Self::DatabaseDecode => "database_decode",
            Self::DatabaseInvariant => "database_invariant",
            Self::StorageProbe => "storage_probe",
            Self::StorageWrite => "storage_write",
            Self::StorageRead => "storage_read",
            Self::StoragePurge => "storage_purge",
            Self::EntropyIdentifier => "entropy_identifier",
            Self::EntropyDataKey => "entropy_data_key",
            Self::EntropyKeyWrapNonce => "entropy_key_wrap_nonce",
            Self::EntropyContentNonce => "entropy_content_nonce",
            Self::CryptographicKeyWrap => "cryptographic_key_wrap",
        }
    }
}

/// Bounded internal cause classes. No provider or driver error text is retained
/// because those strings can contain endpoints, SQL, identifiers, or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureCause {
    DatabaseConnection,
    DatabaseTransaction,
    DatabaseResource,
    DatabaseRejected,
    DatabaseIo,
    DatabaseTls,
    DatabasePoolTimeout,
    DatabasePoolClosed,
    DatabaseWorkerCrashed,
    DatabaseRowMissing,
    DatabaseColumn,
    DatabaseDecode,
    DatabaseDriver,
    ProviderConstruction,
    ProviderTimeout,
    ProviderDispatch,
    ProviderResponse,
    ProviderService,
    ProviderOther,
    OperationDeadline,
    BodyIo,
    InvalidProviderResponse,
    ResourceLimit,
    EntropyUnavailable,
    CryptographicOperation,
    DataInvariant,
}

impl FailureCause {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DatabaseConnection => "database_connection",
            Self::DatabaseTransaction => "database_transaction",
            Self::DatabaseResource => "database_resource",
            Self::DatabaseRejected => "database_rejected",
            Self::DatabaseIo => "database_io",
            Self::DatabaseTls => "database_tls",
            Self::DatabasePoolTimeout => "database_pool_timeout",
            Self::DatabasePoolClosed => "database_pool_closed",
            Self::DatabaseWorkerCrashed => "database_worker_crashed",
            Self::DatabaseRowMissing => "database_row_missing",
            Self::DatabaseColumn => "database_column",
            Self::DatabaseDecode => "database_decode",
            Self::DatabaseDriver => "database_driver",
            Self::ProviderConstruction => "provider_construction",
            Self::ProviderTimeout => "provider_timeout",
            Self::ProviderDispatch => "provider_dispatch",
            Self::ProviderResponse => "provider_response",
            Self::ProviderService => "provider_service",
            Self::ProviderOther => "provider_other",
            Self::OperationDeadline => "operation_deadline",
            Self::BodyIo => "body_io",
            Self::InvalidProviderResponse => "invalid_provider_response",
            Self::ResourceLimit => "resource_limit",
            Self::EntropyUnavailable => "entropy_unavailable",
            Self::CryptographicOperation => "cryptographic_operation",
            Self::DataInvariant => "data_invariant",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FailureDiagnostic {
    stage: FailureStage,
    cause: FailureCause,
}

/// Safe object-lifecycle failure. The message intentionally contains no
/// bucket, storage key, endpoint, credential, object bytes, or SQL text.
#[derive(Clone, Error)]
#[error("{message}")]
pub struct EvidenceObjectError {
    code: EvidenceObjectErrorCode,
    message: &'static str,
    retryable: bool,
    diagnostic: Option<FailureDiagnostic>,
}

impl EvidenceObjectError {
    pub(crate) const fn new(
        code: EvidenceObjectErrorCode,
        message: &'static str,
        retryable: bool,
    ) -> Self {
        Self {
            code,
            message,
            retryable,
            diagnostic: None,
        }
    }

    fn diagnosed(
        code: EvidenceObjectErrorCode,
        message: &'static str,
        retryable: bool,
        stage: FailureStage,
        cause: FailureCause,
    ) -> Self {
        Self::new(code, message, retryable).with_diagnostic(stage, cause)
    }

    pub(crate) fn with_diagnostic(mut self, stage: FailureStage, cause: FailureCause) -> Self {
        tracing::warn!(
            target: "apolysis_evidence_objects",
            stage = stage.as_str(),
            cause = cause.as_str(),
            "Evidence object operation failed"
        );
        self.diagnostic = Some(FailureDiagnostic { stage, cause });
        self
    }

    pub(crate) fn database() -> Self {
        Self::database_invariant(FailureStage::DatabaseInvariant)
    }

    pub(crate) fn database_invariant(stage: FailureStage) -> Self {
        Self::diagnosed(
            EvidenceObjectErrorCode::DatabaseUnavailable,
            "Evidence object registry is unavailable",
            true,
            stage,
            FailureCause::DataInvariant,
        )
    }

    pub(crate) fn database_failure(stage: FailureStage, error: &sqlx::Error) -> Self {
        Self::diagnosed(
            EvidenceObjectErrorCode::DatabaseUnavailable,
            "Evidence object registry is unavailable",
            true,
            stage,
            database_cause(error),
        )
    }

    pub(crate) fn storage() -> Self {
        Self::storage_failure(
            FailureStage::StorageRead,
            FailureCause::InvalidProviderResponse,
        )
    }

    pub(crate) fn storage_failure(stage: FailureStage, cause: FailureCause) -> Self {
        Self::diagnosed(
            EvidenceObjectErrorCode::StorageUnavailable,
            "Evidence object storage is unavailable",
            true,
            stage,
            cause,
        )
    }

    pub(crate) fn provider_failure<E, R>(stage: FailureStage, error: &SdkError<E, R>) -> Self {
        let cause = match error {
            SdkError::ConstructionFailure(_) => FailureCause::ProviderConstruction,
            SdkError::TimeoutError(_) => FailureCause::ProviderTimeout,
            SdkError::DispatchFailure(_) => FailureCause::ProviderDispatch,
            SdkError::ResponseError(_) => FailureCause::ProviderResponse,
            SdkError::ServiceError(_) => FailureCause::ProviderService,
            _ => FailureCause::ProviderOther,
        };
        Self::storage_failure(stage, cause)
    }

    pub(crate) fn entropy_failure(stage: FailureStage, _error: &getrandom::Error) -> Self {
        Self::diagnosed(
            EvidenceObjectErrorCode::DatabaseUnavailable,
            "Evidence object registry is unavailable",
            true,
            stage,
            FailureCause::EntropyUnavailable,
        )
    }

    pub(crate) fn cryptographic_failure(stage: FailureStage) -> Self {
        Self::diagnosed(
            EvidenceObjectErrorCode::DatabaseUnavailable,
            "Evidence object registry is unavailable",
            true,
            stage,
            FailureCause::CryptographicOperation,
        )
    }

    pub(crate) const fn invalid() -> Self {
        Self::new(
            EvidenceObjectErrorCode::InvalidRequest,
            "Evidence object request is invalid",
            false,
        )
    }

    pub(crate) const fn unauthorized() -> Self {
        Self::new(
            EvidenceObjectErrorCode::Unauthorized,
            "Evidence object is not authorized",
            false,
        )
    }

    pub(crate) const fn not_found() -> Self {
        Self::new(
            EvidenceObjectErrorCode::NotFound,
            "Evidence object was not found",
            false,
        )
    }

    pub(crate) const fn expired() -> Self {
        Self::new(
            EvidenceObjectErrorCode::Expired,
            "Evidence object lifecycle window has expired",
            false,
        )
    }

    pub(crate) const fn integrity() -> Self {
        Self::new(
            EvidenceObjectErrorCode::IntegrityMismatch,
            "Evidence object integrity verification failed",
            false,
        )
    }

    /// Return the stable error class.
    pub fn code(&self) -> EvidenceObjectErrorCode {
        self.code
    }

    /// Return whether a bounded retry can be attempted without changing the
    /// request identity.
    pub fn retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Debug for EvidenceObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The diagnostic remains available inside this crate, but Debug is a
        // public surface and must preserve the original content-free shape.
        let _internal_diagnostic = self.diagnostic;
        formatter
            .debug_struct("EvidenceObjectError")
            .field("code", &self.code)
            .field("message", &self.message)
            .field("retryable", &self.retryable)
            .finish()
    }
}

impl PartialEq for EvidenceObjectError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.message == other.message
            && self.retryable == other.retryable
    }
}

impl Eq for EvidenceObjectError {}

fn database_cause(error: &sqlx::Error) -> FailureCause {
    match error {
        sqlx::Error::Database(database) => match database.code().as_deref() {
            Some(code) if code.starts_with("08") => FailureCause::DatabaseConnection,
            Some(code) if code.starts_with("40") => FailureCause::DatabaseTransaction,
            Some(code) if code.starts_with("53") || code.starts_with("57") => {
                FailureCause::DatabaseResource
            }
            _ => FailureCause::DatabaseRejected,
        },
        sqlx::Error::Io(_) => FailureCause::DatabaseIo,
        sqlx::Error::Tls(_) => FailureCause::DatabaseTls,
        sqlx::Error::PoolTimedOut => FailureCause::DatabasePoolTimeout,
        sqlx::Error::PoolClosed => FailureCause::DatabasePoolClosed,
        sqlx::Error::WorkerCrashed => FailureCause::DatabaseWorkerCrashed,
        sqlx::Error::RowNotFound => FailureCause::DatabaseRowMissing,
        sqlx::Error::ColumnNotFound(_) | sqlx::Error::ColumnIndexOutOfBounds { .. } => {
            FailureCause::DatabaseColumn
        }
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => FailureCause::DatabaseDecode,
        _ => FailureCause::DatabaseDriver,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_CANARY: &str = "secret-endpoint-or-sql-canary";

    fn assert_public_contract(error: &EvidenceObjectError, expected: EvidenceObjectErrorCode) {
        assert_eq!(error.code(), expected);
        assert!(error.retryable());
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains(SECRET_CANARY));
        assert!(!debug.contains(SECRET_CANARY));
        assert!(!debug.contains("FailureDiagnostic"));
        assert!(!debug.contains("FailureStage"));
        assert!(!debug.contains("FailureCause"));
    }

    #[test]
    fn database_failures_carry_bounded_diagnostics_without_changing_public_contract() {
        let driver_error = sqlx::Error::Tls(Box::new(std::io::Error::other(SECRET_CANARY)));
        let error = EvidenceObjectError::database_failure(FailureStage::BeginUpload, &driver_error);

        assert_public_contract(&error, EvidenceObjectErrorCode::DatabaseUnavailable);
        assert_eq!(
            error.diagnostic,
            Some(FailureDiagnostic {
                stage: FailureStage::BeginUpload,
                cause: FailureCause::DatabaseTls,
            })
        );
        assert_eq!(error, EvidenceObjectError::database());
    }

    #[test]
    fn provider_failures_retain_only_sdk_variant_and_static_stage() {
        let provider_error = SdkError::<std::io::Error, ()>::construction_failure(
            std::io::Error::other(SECRET_CANARY),
        );
        let error =
            EvidenceObjectError::provider_failure(FailureStage::StorageProbe, &provider_error);

        assert_public_contract(&error, EvidenceObjectErrorCode::StorageUnavailable);
        assert_eq!(
            error.diagnostic,
            Some(FailureDiagnostic {
                stage: FailureStage::StorageProbe,
                cause: FailureCause::ProviderConstruction,
            })
        );
    }

    #[test]
    fn fixed_storage_and_entropy_causes_remain_private() {
        let storage = EvidenceObjectError::storage_failure(
            FailureStage::StoragePurge,
            FailureCause::OperationDeadline,
        );
        assert_public_contract(&storage, EvidenceObjectErrorCode::StorageUnavailable);
        assert_eq!(
            storage.diagnostic,
            Some(FailureDiagnostic {
                stage: FailureStage::StoragePurge,
                cause: FailureCause::OperationDeadline,
            })
        );

        let entropy = EvidenceObjectError::entropy_failure(
            FailureStage::EntropyDataKey,
            &getrandom::Error::new_custom(42),
        );
        assert_public_contract(&entropy, EvidenceObjectErrorCode::DatabaseUnavailable);
        assert_eq!(
            entropy.diagnostic,
            Some(FailureDiagnostic {
                stage: FailureStage::EntropyDataKey,
                cause: FailureCause::EntropyUnavailable,
            })
        );
    }
}

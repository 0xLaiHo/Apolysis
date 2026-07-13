// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use apolysis_contracts::{ContractError, ContractErrorCode, GatewayErrorResponse};

const MIN_REPOSITORY_RETRY_AFTER_MS: u64 = 1;
const MAX_REPOSITORY_RETRY_AFTER_MS: u64 = 60_000;

/// Internal audit classification. It is deliberately not serializable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditReason {
    AuthenticationExpired,
    PrincipalMismatch,
    SourceRegistrationMismatch,
    SourcePolicyMismatch,
    RequestContractInvalid,
    RequestDigestMismatch,
    IdempotencyConflict,
    ClientRunKeyConflict,
    RepositoryUnavailable,
    RepositoryInvariant,
    AdmissionLimit,
    EntropyUnavailable,
}

/// Safe external failure plus a non-wire internal audit reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayFailure {
    code: ContractErrorCode,
    safe_message: &'static str,
    retryable: bool,
    retry_after_ms: Option<u64>,
    audit_reason: AuditReason,
}

impl GatewayFailure {
    pub(crate) fn new(
        code: ContractErrorCode,
        safe_message: &'static str,
        audit_reason: AuditReason,
    ) -> Self {
        let (retryable, retry_after_ms) = match code {
            ContractErrorCode::Backpressure => (true, Some(250)),
            ContractErrorCode::RateLimited => (true, Some(1_000)),
            _ => (false, None),
        };
        Self {
            code,
            safe_message,
            retryable,
            retry_after_ms,
            audit_reason,
        }
    }

    /// Construct a persistence-safe classified error without allowing an
    /// adapter to choose caller-visible text.
    pub fn classified(code: ContractErrorCode, audit_reason: AuditReason) -> Self {
        let safe_message = match code {
            ContractErrorCode::Unauthenticated => "Authentication is missing or expired",
            ContractErrorCode::Forbidden => "Operation is not authorized",
            ContractErrorCode::NotFound => "Requested resource was not found",
            ContractErrorCode::LeaseExpired
            | ContractErrorCode::LeaseRevoked
            | ContractErrorCode::LeaseScopeMismatch => {
                "Lease is expired or not valid for this operation scope"
            }
            ContractErrorCode::Backpressure => "Gateway persistence is temporarily unavailable",
            ContractErrorCode::RateLimited => "Gateway request rate was exceeded",
            _ => "Gateway operation was rejected",
        };
        Self::new(code, safe_message, audit_reason)
    }

    /// Construct retryable repository backpressure with a bounded retry hint.
    pub fn repository_backpressure(retry_after_ms: u64, audit_reason: AuditReason) -> Self {
        let mut failure = Self::new(
            ContractErrorCode::Backpressure,
            "Gateway persistence is temporarily unavailable",
            audit_reason,
        );
        failure.retryable = true;
        failure.retry_after_ms = Some(
            retry_after_ms.clamp(MIN_REPOSITORY_RETRY_AFTER_MS, MAX_REPOSITORY_RETRY_AFTER_MS),
        );
        failure
    }

    /// Preserve the frozen v0.1 bounded-backpressure response for an internal
    /// repository fault. Protected diagnostics distinguish the real invariant;
    /// the caller sees no SQL, storage identifier, or implementation detail.
    /// A future contract version needs a dedicated permanent internal code.
    pub fn repository_fault(audit_reason: AuditReason) -> Self {
        Self::repository_backpressure(250, audit_reason)
    }

    /// Reject a run-scoped admission limit without classifying it as transient
    /// persistence backpressure in the frozen v0.1 contract.
    pub fn admission_limit(audit_reason: AuditReason) -> Self {
        Self::new(
            ContractErrorCode::InvalidLifecycleTransition,
            "Gateway operation cannot be completed in its current state",
            audit_reason,
        )
    }

    /// Return the stable machine error code.
    pub fn code(&self) -> ContractErrorCode {
        self.code
    }

    /// Return the non-wire reason suitable for a protected operator audit.
    pub fn audit_reason(&self) -> AuditReason {
        self.audit_reason
    }

    /// Convert to the enumeration-safe wire body.
    pub fn response(&self) -> Result<GatewayErrorResponse, ContractError> {
        GatewayErrorResponse::new(
            self.code,
            self.safe_message,
            self.retryable,
            self.retry_after_ms,
        )
    }
}

impl fmt::Display for GatewayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message)
    }
}

impl std::error::Error for GatewayFailure {}

pub type GatewayResult<T> = Result<T, GatewayFailure>;

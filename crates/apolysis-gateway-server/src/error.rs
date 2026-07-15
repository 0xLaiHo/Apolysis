// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io};

use apolysis_contracts::ContractErrorCode;
use apolysis_gateway::{AuditReason, GatewayFailure};

/// A server-side failure whose display text is safe for process output.
///
/// Only compile-time configuration text and closed diagnostic classifications
/// are retained. Source errors are discarded at construction, so database
/// connection strings, filesystem paths, request bodies, TLS material, and
/// bearer leases cannot later escape through `Display` or `Debug`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayServerError {
    kind: GatewayServerErrorKind,
    diagnostic: SafeDiagnostic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GatewayServerErrorKind {
    Configuration,
    Io,
    Database,
    Unauthenticated,
    Forbidden,
    Gateway,
    Tls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SafeDiagnostic {
    Configuration(&'static str),
    Io {
        context: IoContext,
        category: IoCategory,
    },
    Database {
        context: DatabaseContext,
        category: DatabaseCategory,
    },
    Unauthenticated,
    Forbidden,
    Gateway {
        code: ContractErrorCode,
        audit_reason: AuditReason,
    },
    Tls(TlsContext),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoContext {
    InputOpen,
    InputMetadata,
    InputRead,
    ListenerServe,
    ReadyOpen,
    ReadyWrite,
    ReadySync,
    QualificationParentOpen,
    QualificationParentMetadata,
    QualificationParentSync,
    QualificationMarkerOpen,
    QualificationMarkerMetadata,
    QualificationMarkerWrite,
    QualificationMarkerSync,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoCategory {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    WouldBlock,
    TimedOut,
    Interrupted,
    InvalidData,
    BrokenPipe,
    Connection,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseContext {
    Authority,
    AuthorityConnect,
    AuthorityMigration,
    GatewayConnect,
    GatewayMigration,
    GatewayQuery,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseCategory {
    Pool,
    Row,
    Constraint,
    Timeout,
    Transport,
    Configuration,
    Migration,
    Protocol,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlsContext {
    ServerCertificate,
    ServerPrivateKey,
    ClientCa,
    ClientVerifier,
    ProtocolVersions,
    ServerIdentity,
    Unspecified,
}

impl GatewayServerError {
    /// Construct a configuration failure from compile-time, allowlisted text.
    ///
    /// The static type plus exact allowlist prevents this boundary from
    /// retaining a path, URL, parsed request, or source-error message; unknown
    /// text collapses to one generic diagnostic.
    pub fn configuration(message: &'static str) -> Self {
        Self {
            kind: GatewayServerErrorKind::Configuration,
            diagnostic: SafeDiagnostic::Configuration(safe_configuration_message(message)),
        }
    }

    /// Classify a filesystem failure without exposing its path or OS message.
    ///
    /// Existing callers retain a safe generic context. New boundary code
    /// should prefer `io_at` so operators can distinguish open, read, and
    /// readiness publication failures.
    pub fn io(_error: impl fmt::Display) -> Self {
        Self::io_diagnostic(IoContext::Unspecified, IoCategory::Other)
    }

    pub(crate) fn io_at(context: &'static str, error: io::Error) -> Self {
        Self::io_diagnostic(io_context(context), io_category(error.kind()))
    }

    fn io_diagnostic(context: IoContext, category: IoCategory) -> Self {
        Self {
            kind: GatewayServerErrorKind::Io,
            diagnostic: SafeDiagnostic::Io { context, category },
        }
    }

    /// Classify a PostgreSQL failure without exposing connection or row data.
    ///
    /// The legacy constructor keeps authority call sites source-compatible and
    /// still preserves the closed failure category.
    pub fn database(error: sqlx::Error) -> Self {
        Self::database_diagnostic(DatabaseContext::Authority, database_category(&error))
    }

    pub fn database_at(context: &'static str, error: sqlx::Error) -> Self {
        Self::database_diagnostic(database_context(context), database_category(&error))
    }

    fn database_diagnostic(context: DatabaseContext, category: DatabaseCategory) -> Self {
        Self {
            kind: GatewayServerErrorKind::Database,
            diagnostic: SafeDiagnostic::Database { context, category },
        }
    }

    /// Classify an invalid or no-longer-current transport credential.
    pub fn unauthenticated(_message: impl Into<String>) -> Self {
        Self {
            kind: GatewayServerErrorKind::Unauthenticated,
            diagnostic: SafeDiagnostic::Unauthenticated,
        }
    }

    /// Classify a current credential that lacks the requested operation.
    pub fn forbidden(_message: impl Into<String>) -> Self {
        Self {
            kind: GatewayServerErrorKind::Forbidden,
            diagnostic: SafeDiagnostic::Forbidden,
        }
    }

    /// Preserve only the Gateway's closed wire code and protected audit
    /// reason; its source object and any future attached detail are discarded.
    pub fn gateway(error: GatewayFailure) -> Self {
        Self {
            kind: GatewayServerErrorKind::Gateway,
            diagnostic: SafeDiagnostic::Gateway {
                code: error.code(),
                audit_reason: error.audit_reason(),
            },
        }
    }

    /// Classify a TLS configuration failure using a generic safe context.
    pub fn tls() -> Self {
        Self::tls_diagnostic(TlsContext::Unspecified)
    }

    pub(crate) fn tls_at(context: &'static str) -> Self {
        Self::tls_diagnostic(tls_context(context))
    }

    fn tls_diagnostic(context: TlsContext) -> Self {
        Self {
            kind: GatewayServerErrorKind::Tls,
            diagnostic: SafeDiagnostic::Tls(context),
        }
    }

    pub(crate) fn kind(&self) -> GatewayServerErrorKind {
        self.kind
    }
}

impl fmt::Display for GatewayServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.diagnostic {
            SafeDiagnostic::Configuration(message) => formatter.write_str(message),
            SafeDiagnostic::Io { context, category } => write!(
                formatter,
                "Gateway file operation failed [context={}, category={}]",
                io_context_name(context),
                io_category_name(category)
            ),
            SafeDiagnostic::Database { context, category } => write!(
                formatter,
                "Gateway database operation failed [context={}, category={}]",
                database_context_name(context),
                database_category_name(category)
            ),
            SafeDiagnostic::Unauthenticated => formatter.write_str("Gateway authentication failed"),
            SafeDiagnostic::Forbidden => formatter.write_str("Gateway authorization failed"),
            SafeDiagnostic::Gateway { code, audit_reason } => write!(
                formatter,
                "Gateway application operation failed [code={}, audit_reason={}]",
                contract_code_name(code),
                audit_reason_name(audit_reason)
            ),
            SafeDiagnostic::Tls(context) => write!(
                formatter,
                "Gateway TLS configuration failed [context={}]",
                tls_context_name(context)
            ),
        }
    }
}

impl std::error::Error for GatewayServerError {}

fn safe_configuration_message(message: &'static str) -> &'static str {
    match message {
        "A revoked client certificate cannot be registered again"
        | "Authority command is required"
        | "Authority command is unsupported"
        | "Authority command names must be UTF-8"
        | "Authority file paths must be absolute"
        | "Authority is missing a required option"
        | "Authority option is missing its value"
        | "Authority option names must be UTF-8"
        | "Authority option values must be UTF-8"
        | "Authority option was supplied more than once"
        | "Authority received an unsupported option"
        | "Client certificate DER is invalid"
        | "Client certificate PEM contains no certificate"
        | "Client certificate PEM is invalid"
        | "Client certificate binding conflicts with current authority"
        | "Client certificate file is invalid"
        | "Client certificate is already bound to another source"
        | "Client certificate is invalid"
        | "Client certificate must be a leaf certificate"
        | "Client certificate must declare clientAuth"
        | "Client certificate usage is invalid"
        | "Client certificate validity is invalid"
        | "Gateway authority operation is invalid"
        | "Gateway clock is invalid"
        | "Gateway database URL file is invalid"
        | "Gateway database URL file must be UTF-8"
        | "Gateway database URL is invalid"
        | "Gateway database URL uses an unsupported scheme"
        | "Gateway file option must not be empty"
        | "Gateway file paths must be absolute"
        | "Gateway input file exceeds its size limit"
        | "Gateway input file is not a bounded regular file"
        | "Gateway is missing a required option"
        | "Gateway listen address is invalid"
        | "Gateway listener failed to bind"
        | "Gateway option is missing its value"
        | "Gateway option names must be UTF-8"
        | "Gateway option values must be UTF-8"
        | "Gateway option was supplied more than once"
        | "Gateway qualification listener must use 127.0.0.1:0"
        | "Gateway qualification marker is not a private regular file"
        | "Gateway qualification marker must differ from the ready file"
        | "Gateway qualification marker parent is invalid"
        | "Gateway qualification marker parent must be private"
        | "Gateway qualification marker path must be absolute"
        | "Gateway qualification operation is unsupported"
        | "Gateway received an unsupported option"
        | "Gateway replay key must be 32-byte lowercase hexadecimal"
        | "Gateway secret file is not UTF-8"
        | "Gateway secret file must not be empty"
        | "Gateway secret file permissions are too broad"
        | "Gateway stopped before becoming ready"
        | "Revocation reason is invalid"
        | "Source authority updates require the credential rotation gate"
        | "Source policy is invalid"
        | "Source policy revision is invalid"
        | "Source policy serialization failed"
        | "Source registration JSON is invalid"
        | "Source registration exceeds client certificate validity"
        | "Source registration file is invalid"
        | "Source registration identifier is invalid"
        | "Source registration identity is immutable"
        | "Source registration validity is invalid"
        | "Transport credential epoch is invalid"
        | "Transport credential is not registered" => message,
        _ => "Gateway configuration is invalid",
    }
}

fn io_context(context: &'static str) -> IoContext {
    match context {
        "input-open" => IoContext::InputOpen,
        "input-metadata" => IoContext::InputMetadata,
        "input-read" => IoContext::InputRead,
        "listener-serve" => IoContext::ListenerServe,
        "ready-open" => IoContext::ReadyOpen,
        "ready-write" => IoContext::ReadyWrite,
        "ready-sync" => IoContext::ReadySync,
        "qualification-parent-open" => IoContext::QualificationParentOpen,
        "qualification-parent-metadata" => IoContext::QualificationParentMetadata,
        "qualification-parent-sync" => IoContext::QualificationParentSync,
        "qualification-marker-open" => IoContext::QualificationMarkerOpen,
        "qualification-marker-metadata" => IoContext::QualificationMarkerMetadata,
        "qualification-marker-write" => IoContext::QualificationMarkerWrite,
        "qualification-marker-sync" => IoContext::QualificationMarkerSync,
        _ => IoContext::Unspecified,
    }
}

fn io_context_name(context: IoContext) -> &'static str {
    match context {
        IoContext::InputOpen => "input-open",
        IoContext::InputMetadata => "input-metadata",
        IoContext::InputRead => "input-read",
        IoContext::ListenerServe => "listener-serve",
        IoContext::ReadyOpen => "ready-open",
        IoContext::ReadyWrite => "ready-write",
        IoContext::ReadySync => "ready-sync",
        IoContext::QualificationParentOpen => "qualification-parent-open",
        IoContext::QualificationParentMetadata => "qualification-parent-metadata",
        IoContext::QualificationParentSync => "qualification-parent-sync",
        IoContext::QualificationMarkerOpen => "qualification-marker-open",
        IoContext::QualificationMarkerMetadata => "qualification-marker-metadata",
        IoContext::QualificationMarkerWrite => "qualification-marker-write",
        IoContext::QualificationMarkerSync => "qualification-marker-sync",
        IoContext::Unspecified => "unspecified",
    }
}

fn io_category(kind: io::ErrorKind) -> IoCategory {
    match kind {
        io::ErrorKind::NotFound => IoCategory::NotFound,
        io::ErrorKind::PermissionDenied => IoCategory::PermissionDenied,
        io::ErrorKind::AlreadyExists => IoCategory::AlreadyExists,
        io::ErrorKind::WouldBlock => IoCategory::WouldBlock,
        io::ErrorKind::TimedOut => IoCategory::TimedOut,
        io::ErrorKind::Interrupted => IoCategory::Interrupted,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof => {
            IoCategory::InvalidData
        }
        io::ErrorKind::BrokenPipe => IoCategory::BrokenPipe,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected => IoCategory::Connection,
        _ => IoCategory::Other,
    }
}

fn io_category_name(category: IoCategory) -> &'static str {
    match category {
        IoCategory::NotFound => "not-found",
        IoCategory::PermissionDenied => "permission-denied",
        IoCategory::AlreadyExists => "already-exists",
        IoCategory::WouldBlock => "would-block",
        IoCategory::TimedOut => "timeout",
        IoCategory::Interrupted => "interrupted",
        IoCategory::InvalidData => "invalid-data",
        IoCategory::BrokenPipe => "broken-pipe",
        IoCategory::Connection => "connection",
        IoCategory::Other => "other",
    }
}

fn database_context(context: &'static str) -> DatabaseContext {
    match context {
        "authority-connect" => DatabaseContext::AuthorityConnect,
        "authority-migration" => DatabaseContext::AuthorityMigration,
        "gateway-connect" => DatabaseContext::GatewayConnect,
        "gateway-migration" => DatabaseContext::GatewayMigration,
        "gateway-query" => DatabaseContext::GatewayQuery,
        _ => DatabaseContext::Unspecified,
    }
}

fn database_context_name(context: DatabaseContext) -> &'static str {
    match context {
        DatabaseContext::Authority => "authority",
        DatabaseContext::AuthorityConnect => "authority-connect",
        DatabaseContext::AuthorityMigration => "authority-migration",
        DatabaseContext::GatewayConnect => "gateway-connect",
        DatabaseContext::GatewayMigration => "gateway-migration",
        DatabaseContext::GatewayQuery => "gateway-query",
        DatabaseContext::Unspecified => "unspecified",
    }
}

fn database_category(error: &sqlx::Error) -> DatabaseCategory {
    match error {
        sqlx::Error::PoolTimedOut => DatabaseCategory::Timeout,
        sqlx::Error::PoolClosed | sqlx::Error::WorkerCrashed => DatabaseCategory::Pool,
        sqlx::Error::RowNotFound
        | sqlx::Error::ColumnIndexOutOfBounds { .. }
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::Decode(_) => DatabaseCategory::Row,
        sqlx::Error::Database(database_error) => {
            if database_error.code().as_deref() == Some("57014") {
                DatabaseCategory::Timeout
            } else if !matches!(database_error.kind(), sqlx::error::ErrorKind::Other) {
                DatabaseCategory::Constraint
            } else {
                DatabaseCategory::Other
            }
        }
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) => DatabaseCategory::Transport,
        sqlx::Error::Configuration(_) | sqlx::Error::InvalidArgument(_) => {
            DatabaseCategory::Configuration
        }
        sqlx::Error::Migrate(_) => DatabaseCategory::Migration,
        sqlx::Error::Protocol(_) => DatabaseCategory::Protocol,
        _ => DatabaseCategory::Other,
    }
}

fn database_category_name(category: DatabaseCategory) -> &'static str {
    match category {
        DatabaseCategory::Pool => "pool",
        DatabaseCategory::Row => "row",
        DatabaseCategory::Constraint => "constraint",
        DatabaseCategory::Timeout => "timeout",
        DatabaseCategory::Transport => "transport",
        DatabaseCategory::Configuration => "configuration",
        DatabaseCategory::Migration => "migration",
        DatabaseCategory::Protocol => "protocol",
        DatabaseCategory::Other => "other",
    }
}

fn tls_context(context: &'static str) -> TlsContext {
    match context {
        "server-certificate" => TlsContext::ServerCertificate,
        "server-private-key" => TlsContext::ServerPrivateKey,
        "client-ca" => TlsContext::ClientCa,
        "client-verifier" => TlsContext::ClientVerifier,
        "protocol-versions" => TlsContext::ProtocolVersions,
        "server-identity" => TlsContext::ServerIdentity,
        _ => TlsContext::Unspecified,
    }
}

fn tls_context_name(context: TlsContext) -> &'static str {
    match context {
        TlsContext::ServerCertificate => "server-certificate",
        TlsContext::ServerPrivateKey => "server-private-key",
        TlsContext::ClientCa => "client-ca",
        TlsContext::ClientVerifier => "client-verifier",
        TlsContext::ProtocolVersions => "protocol-versions",
        TlsContext::ServerIdentity => "server-identity",
        TlsContext::Unspecified => "unspecified",
    }
}

fn contract_code_name(code: ContractErrorCode) -> &'static str {
    match code {
        ContractErrorCode::Unauthenticated => "unauthenticated",
        ContractErrorCode::Forbidden => "forbidden",
        ContractErrorCode::NotFound => "not_found",
        ContractErrorCode::UnsupportedContractVersion => "unsupported_contract_version",
        ContractErrorCode::UnsupportedSourceVersion => "unsupported_source_version",
        ContractErrorCode::InvalidContract => "invalid_contract",
        ContractErrorCode::InvalidLifecycleTransition => "invalid_lifecycle_transition",
        ContractErrorCode::LeaseExpired => "lease_expired",
        ContractErrorCode::LeaseRevoked => "lease_revoked",
        ContractErrorCode::LeaseScopeMismatch => "lease_scope_mismatch",
        ContractErrorCode::IdempotencyConflict => "idempotency_conflict",
        ContractErrorCode::SourceEventConflict => "source_event_conflict",
        ContractErrorCode::SequenceConflict => "sequence_conflict",
        ContractErrorCode::CapabilityMismatch => "capability_mismatch",
        ContractErrorCode::RedactionRequired => "redaction_required",
        ContractErrorCode::ContentNotAuthorized => "content_not_authorized",
        ContractErrorCode::RetentionNotAuthorized => "retention_not_authorized",
        ContractErrorCode::BatchTooLarge => "batch_too_large",
        ContractErrorCode::Backpressure => "backpressure",
        ContractErrorCode::RateLimited => "rate_limited",
        ContractErrorCode::CursorInvalid => "cursor_invalid",
        ContractErrorCode::CursorExpired => "cursor_expired",
        ContractErrorCode::ProjectionUnavailable => "projection_unavailable",
    }
}

fn audit_reason_name(reason: AuditReason) -> &'static str {
    match reason {
        AuditReason::AuthenticationExpired => "authentication_expired",
        AuditReason::PrincipalMismatch => "principal_mismatch",
        AuditReason::SourceRegistrationMismatch => "source_registration_mismatch",
        AuditReason::SourcePolicyMismatch => "source_policy_mismatch",
        AuditReason::RequestContractInvalid => "request_contract_invalid",
        AuditReason::RequestDigestMismatch => "request_digest_mismatch",
        AuditReason::IdempotencyConflict => "idempotency_conflict",
        AuditReason::ClientRunKeyConflict => "client_run_key_conflict",
        AuditReason::RepositoryUnavailable => "repository_unavailable",
        AuditReason::RepositoryInvariant => "repository_invariant",
        AuditReason::AdmissionLimit => "admission_limit",
        AuditReason::EntropyUnavailable => "entropy_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, error::Error, fmt, io};

    use apolysis_contracts::ContractErrorCode;
    use apolysis_gateway::{AuditReason, GatewayFailure};
    use sqlx::error::{DatabaseError, ErrorKind};

    use super::GatewayServerError;

    #[derive(Debug)]
    struct SecretConstraintError;

    impl fmt::Display for SecretConstraintError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("duplicate secret-row-value")
        }
    }

    impl Error for SecretConstraintError {}

    impl DatabaseError for SecretConstraintError {
        fn message(&self) -> &str {
            "duplicate secret-row-value"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed("23505"))
        }

        fn as_error(&self) -> &(dyn Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::UniqueViolation
        }
    }

    #[test]
    fn io_diagnostic_retains_only_allowlisted_context_and_category() {
        let error = GatewayServerError::io_at(
            "input-open",
            io::Error::new(io::ErrorKind::PermissionDenied, "/secret/path"),
        );
        let display = error.to_string();

        assert_eq!(
            display,
            "Gateway file operation failed [context=input-open, category=permission-denied]"
        );
        assert!(!display.contains("/secret/path"));
    }

    #[test]
    fn database_diagnostic_distinguishes_closed_categories_without_source_text() {
        let timeout = GatewayServerError::database(sqlx::Error::PoolTimedOut).to_string();
        let pool = GatewayServerError::database(sqlx::Error::PoolClosed).to_string();
        let row = GatewayServerError::database(sqlx::Error::RowNotFound).to_string();
        let constraint =
            GatewayServerError::database(sqlx::Error::Database(Box::new(SecretConstraintError)))
                .to_string();

        assert!(timeout.contains("category=timeout"));
        assert!(pool.contains("category=pool"));
        assert!(row.contains("category=row"));
        assert!(constraint.contains("category=constraint"));
        assert!(!constraint.contains("secret-row-value"));
    }

    #[test]
    fn gateway_diagnostic_retains_only_closed_code_and_audit_reason() {
        let failure = GatewayFailure::classified(
            ContractErrorCode::Backpressure,
            AuditReason::RepositoryUnavailable,
        );
        let display = GatewayServerError::gateway(failure).to_string();

        assert!(display.contains("code=backpressure"));
        assert!(display.contains("audit_reason=repository_unavailable"));
    }

    #[test]
    fn unknown_context_is_not_forwarded() {
        let display = GatewayServerError::tls_at("private-key-path-value").to_string();

        assert!(display.contains("context=unspecified"));
        assert!(!display.contains("private-key-path-value"));
    }

    #[test]
    fn unknown_configuration_text_is_not_forwarded() {
        let display =
            GatewayServerError::configuration("postgres://user:secret@host/database").to_string();

        assert_eq!(display, "Gateway configuration is invalid");
        assert!(!display.contains("secret"));
    }
}

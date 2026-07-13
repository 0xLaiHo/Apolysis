// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::ContractErrorCode;
use apolysis_gateway::{AuditReason, GatewayFailure};

pub(crate) fn repository_failure() -> GatewayFailure {
    GatewayFailure::repository_fault(AuditReason::RepositoryInvariant)
}

pub(crate) fn database_failure(stage: &'static str, error: &sqlx::Error) -> GatewayFailure {
    let transient = is_transient_database_error(error);
    let database_error = error.as_database_error();
    let sqlstate = database_error
        .and_then(|error| error.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| "none".to_string());
    let constraint = database_error
        .and_then(|error| error.constraint())
        .unwrap_or("none");
    tracing::warn!(
        target: "apolysis_gateway_postgres",
        stage,
        error_kind = sqlx_error_kind(error),
        sqlstate,
        constraint,
        transient,
        "PostgreSQL Gateway operation failed"
    );
    if transient {
        GatewayFailure::repository_backpressure(250, AuditReason::RepositoryUnavailable)
    } else {
        repository_failure()
    }
}

pub(crate) fn report_database_retry(
    stage: &'static str,
    error: &sqlx::Error,
    attempt: u32,
    max_attempts: u32,
) {
    let database_error = error.as_database_error();
    let sqlstate = database_error
        .and_then(|error| error.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| "none".to_string());
    let constraint = database_error
        .and_then(|error| error.constraint())
        .unwrap_or("none");
    tracing::debug!(
        target: "apolysis_gateway_postgres",
        stage,
        error_kind = sqlx_error_kind(error),
        sqlstate,
        constraint,
        attempt,
        max_attempts,
        "Retrying a PostgreSQL Gateway transaction"
    );
}

#[allow(deprecated)]
pub(crate) fn migration_failure(error: &sqlx::migrate::MigrateError) -> GatewayFailure {
    let error_kind = match error {
        sqlx::migrate::MigrateError::Execute(error) => {
            return database_failure("migrate_execute", error);
        }
        sqlx::migrate::MigrateError::ExecuteMigration(error, _) => {
            return database_failure("migrate_execute_migration", error);
        }
        sqlx::migrate::MigrateError::Source(_) => "source",
        sqlx::migrate::MigrateError::VersionMissing(_) => "version_missing",
        sqlx::migrate::MigrateError::VersionMismatch(_) => "version_mismatch",
        sqlx::migrate::MigrateError::VersionNotPresent(_) => "version_not_present",
        sqlx::migrate::MigrateError::VersionTooOld(_, _) => "version_too_old",
        sqlx::migrate::MigrateError::VersionTooNew(_, _) => "version_too_new",
        sqlx::migrate::MigrateError::ForceNotSupported => "force_not_supported",
        sqlx::migrate::MigrateError::InvalidMixReversibleAndSimple => {
            "invalid_mix_reversible_and_simple"
        }
        sqlx::migrate::MigrateError::Dirty(_) => "dirty",
        _ => "unknown",
    };
    tracing::error!(
        target: "apolysis_gateway_postgres",
        stage = "migrate",
        error_kind,
        transient = false,
        "PostgreSQL Gateway migration failed"
    );
    repository_failure()
}

fn is_transient_database_error(error: &sqlx::Error) -> bool {
    if let Some(code) = error.as_database_error().and_then(|error| error.code()) {
        return code.starts_with("08")
            || code.starts_with("53")
            || matches!(
                code.as_ref(),
                "40001"
                    | "40003"
                    | "40P01"
                    | "55P03"
                    | "57014"
                    | "57P01"
                    | "57P02"
                    | "57P03"
                    | "57P05"
            );
    }
    match error {
        sqlx::Error::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::UnexpectedEof
        ),
        sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => true,
        _ => false,
    }
}

fn sqlx_error_kind(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Database(_) => "database",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::WorkerCrashed => "worker_crashed",
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::ColumnNotFound(_) | sqlx::Error::ColumnIndexOutOfBounds { .. } => "column",
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => "decode",
        _ => "driver",
    }
}

pub(crate) fn contract_failure() -> GatewayFailure {
    GatewayFailure::classified(
        ContractErrorCode::InvalidContract,
        AuditReason::RepositoryInvariant,
    )
}

pub(crate) fn idempotency_conflict() -> GatewayFailure {
    GatewayFailure::classified(
        ContractErrorCode::IdempotencyConflict,
        AuditReason::IdempotencyConflict,
    )
}

pub(crate) fn not_found() -> GatewayFailure {
    GatewayFailure::classified(
        ContractErrorCode::NotFound,
        AuditReason::SourceRegistrationMismatch,
    )
}

pub(crate) fn lease_failure(code: ContractErrorCode) -> GatewayFailure {
    GatewayFailure::classified(code, AuditReason::SourceRegistrationMismatch)
}

pub(crate) fn policy_failure(code: ContractErrorCode) -> GatewayFailure {
    GatewayFailure::classified(code, AuditReason::SourcePolicyMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_repository_faults_preserve_v0_1_bounded_backpressure() {
        let response = repository_failure().response().expect("safe response");
        assert!(response.retryable());
        assert_eq!(response.retry_after_ms(), Some(250));
    }

    #[test]
    fn transient_pool_timeouts_remain_retryable() {
        let failure = database_failure("test_pool_timeout", &sqlx::Error::PoolTimedOut);
        let response = failure.response().expect("safe response");
        assert!(response.retryable());
        assert_eq!(response.retry_after_ms(), Some(250));
    }

    #[test]
    fn network_and_internal_io_failures_use_bounded_v0_1_backpressure() {
        let timeout = sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));
        let invalid_data = sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::InvalidData));

        let timeout_response = database_failure("test_io_timeout", &timeout)
            .response()
            .expect("safe timeout response");
        let invalid_response = database_failure("test_io_invalid_data", &invalid_data)
            .response()
            .expect("safe invalid-data response");
        assert!(timeout_response.retryable());
        assert!(invalid_response.retryable());
        assert_eq!(invalid_response.retry_after_ms(), Some(250));
    }

    #[test]
    fn tls_failures_preserve_v0_1_bounded_backpressure() {
        let tls_error = sqlx::Error::Tls(Box::new(std::io::Error::other("sensitive detail")));
        let failure = database_failure("test_tls", &tls_error);
        let response = failure.response().expect("safe response");
        assert!(response.retryable());
        assert_eq!(response.retry_after_ms(), Some(250));
    }

    #[test]
    fn migration_execute_reuses_transient_database_classification() {
        let error = sqlx::migrate::MigrateError::Execute(sqlx::Error::PoolTimedOut);
        let failure = migration_failure(&error);
        let response = failure.response().expect("safe response");
        assert!(response.retryable());
        assert_eq!(response.retry_after_ms(), Some(250));
    }

    #[test]
    fn migration_execute_tls_preserves_v0_1_bounded_backpressure() {
        let tls_error = sqlx::Error::Tls(Box::new(std::io::Error::other("sensitive detail")));
        let error = sqlx::migrate::MigrateError::ExecuteMigration(tls_error, 42);
        let failure = migration_failure(&error);
        let response = failure.response().expect("safe response");
        assert!(response.retryable());
        assert_eq!(response.retry_after_ms(), Some(250));
    }

    #[test]
    fn migration_metadata_failures_preserve_v0_1_bounded_backpressure() {
        let error = sqlx::migrate::MigrateError::VersionMismatch(42);
        let failure = migration_failure(&error);
        let response = failure.response().expect("safe response");
        assert!(response.retryable());
        assert_eq!(response.retry_after_ms(), Some(250));
    }
}

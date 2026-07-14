// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Stable, content-free failure classes returned by the projection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionErrorCode {
    InvalidArgument,
    DatabaseUnavailable,
    CommitOutcomeUnknown,
    RepositoryInvariant,
    LedgerIntegrity,
    LedgerDiscontinuity,
    LifecycleConflict,
    GenerationConflict,
    GenerationNotReady,
    NotFound,
    CursorExpired,
}

/// A bounded projection failure that never includes SQL, credentials, or facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionError {
    code: ProjectionErrorCode,
    retryable: bool,
    retry_after_ms: Option<u64>,
}

impl ProjectionError {
    pub(crate) const fn permanent(code: ProjectionErrorCode) -> Self {
        Self {
            code,
            retryable: false,
            retry_after_ms: None,
        }
    }

    pub(crate) const fn retryable(code: ProjectionErrorCode) -> Self {
        Self {
            code,
            retryable: true,
            retry_after_ms: Some(250),
        }
    }

    /// Return the stable failure class without an internal diagnostic string.
    pub const fn code(&self) -> ProjectionErrorCode {
        self.code
    }

    /// Return whether a bounded retry can make progress without changing input.
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// Return the server-selected retry delay for retryable failures.
    pub const fn retry_after_ms(&self) -> Option<u64> {
        self.retry_after_ms
    }
}

pub(crate) fn database_failure(stage: &'static str, error: &sqlx::Error) -> ProjectionError {
    if log_database_failure(stage, error) {
        ProjectionError::retryable(ProjectionErrorCode::DatabaseUnavailable)
    } else {
        ProjectionError::permanent(ProjectionErrorCode::RepositoryInvariant)
    }
}

pub(crate) enum CommitFailure {
    Definite(ProjectionError),
    OutcomeUnknown(ProjectionError),
}

/// Classify a failure returned while waiting for PostgreSQL to complete
/// `COMMIT`. A received SQL error is a definitive server outcome except for
/// connection-class and explicit statement-completion-unknown SQLSTATEs.
/// Transport, TLS, protocol, and driver failures cannot establish which side
/// of the durable commit point the server reached.
pub(crate) fn classify_commit_failure(stage: &'static str, error: &sqlx::Error) -> CommitFailure {
    let definitive_database_rejection = error
        .as_database_error()
        .and_then(|value| value.code())
        .is_some_and(|code| !code.starts_with("08") && code.as_ref() != "40003");
    if definitive_database_rejection {
        CommitFailure::Definite(database_failure(stage, error))
    } else {
        CommitFailure::OutcomeUnknown(commit_outcome_unknown(stage, error))
    }
}

/// A connection or protocol failure while waiting for COMMIT can occur on
/// either side of PostgreSQL's durable commit point. The caller must reconcile
/// the checkpoint before scheduling another batch; blindly retrying this call
/// could apply a second batch after the first one actually committed.
pub(crate) fn commit_outcome_unknown(stage: &'static str, error: &sqlx::Error) -> ProjectionError {
    log_database_failure(stage, error);
    ProjectionError::permanent(ProjectionErrorCode::CommitOutcomeUnknown)
}

fn log_database_failure(stage: &'static str, error: &sqlx::Error) -> bool {
    let database_error = error.as_database_error();
    let sqlstate = database_error
        .and_then(|value| value.code())
        .map(|value| value.into_owned())
        .unwrap_or_else(|| "none".to_string());
    let constraint = database_error
        .and_then(|value| value.constraint())
        .unwrap_or("none");
    let transient = is_transient_database_error(error);
    tracing::error!(
        target: "apolysis_projection_postgres",
        stage,
        error_kind = sqlx_error_kind(error),
        sqlstate,
        constraint,
        transient,
        "PostgreSQL projection operation failed"
    );
    transient
}

pub(crate) fn invariant_failure(stage: &'static str) -> ProjectionError {
    tracing::error!(
        target: "apolysis_projection_postgres",
        stage,
        "PostgreSQL projection invariant failed"
    );
    ProjectionError::permanent(ProjectionErrorCode::RepositoryInvariant)
}

pub(crate) fn is_transient_database_error(error: &sqlx::Error) -> bool {
    if let Some(code) = error.as_database_error().and_then(|value| value.code()) {
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
        sqlx::Error::Io(value) => matches!(
            value.kind(),
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

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "projection operation failed ({:?})", self.code)
    }
}

impl std::error::Error for ProjectionError {}

pub type ProjectionResult<T> = Result<T, ProjectionError>;

// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// A server-side failure whose display text is safe for process output.
///
/// Sensitive source errors are deliberately discarded at this boundary. The
/// Gateway must never copy database connection strings, TLS material, request
/// bodies, or bearer leases into stderr.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayServerError {
    kind: GatewayServerErrorKind,
    safe_message: String,
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

impl GatewayServerError {
    /// Construct a configuration failure from caller-controlled, non-secret
    /// validation text.
    pub fn configuration(message: impl Into<String>) -> Self {
        Self {
            kind: GatewayServerErrorKind::Configuration,
            safe_message: message.into(),
        }
    }

    /// Classify a filesystem failure without exposing a path or OS detail.
    pub fn io(_error: impl fmt::Display) -> Self {
        Self {
            kind: GatewayServerErrorKind::Io,
            safe_message: "Gateway file operation failed".to_string(),
        }
    }

    /// Classify a PostgreSQL failure without exposing its connection details.
    pub fn database(_error: sqlx::Error) -> Self {
        Self {
            kind: GatewayServerErrorKind::Database,
            safe_message: "Gateway database operation failed".to_string(),
        }
    }

    /// Classify an invalid or no-longer-current transport credential.
    pub fn unauthenticated(_message: impl Into<String>) -> Self {
        Self {
            kind: GatewayServerErrorKind::Unauthenticated,
            safe_message: "Gateway authentication failed".to_string(),
        }
    }

    /// Classify a current credential that lacks the requested operation.
    pub fn forbidden(_message: impl Into<String>) -> Self {
        Self {
            kind: GatewayServerErrorKind::Forbidden,
            safe_message: "Gateway authorization failed".to_string(),
        }
    }

    /// Classify a failure returned by the application or persistence core.
    pub fn gateway(_error: apolysis_gateway::GatewayFailure) -> Self {
        Self {
            kind: GatewayServerErrorKind::Gateway,
            safe_message: "Gateway application operation failed".to_string(),
        }
    }

    /// Classify a TLS configuration or listener failure without forwarding
    /// parser or key-loader details.
    pub fn tls() -> Self {
        Self {
            kind: GatewayServerErrorKind::Tls,
            safe_message: "Gateway TLS configuration failed".to_string(),
        }
    }

    pub(crate) fn kind(&self) -> GatewayServerErrorKind {
        self.kind
    }
}

impl fmt::Display for GatewayServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_message)
    }
}

impl std::error::Error for GatewayServerError {}

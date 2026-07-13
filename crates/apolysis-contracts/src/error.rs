// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// A validation failure at the Agent Execution Record wire boundary.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq)]
#[schemars(deny_unknown_fields)]
pub enum ContractError {
    /// A contract identifier is empty, oversized, or contains unsafe syntax.
    InvalidIdentifier {
        /// The field that failed validation.
        field: &'static str,
        /// A stable explanation suitable for diagnostics.
        reason: &'static str,
    },
    /// A required reference or version field is invalid.
    InvalidField {
        /// The field that failed validation.
        field: &'static str,
        /// A stable explanation suitable for diagnostics.
        reason: &'static str,
    },
    /// A run lifecycle transition violates the v0.1 state machine.
    InvalidTransition {
        /// Current lifecycle state.
        from: &'static str,
        /// Requested lifecycle state.
        to: &'static str,
    },
    /// A list that represents a set contains a duplicate value.
    DuplicateValue {
        /// The field containing the duplicate.
        field: &'static str,
    },
    /// An envelope did not contain exactly one payload representation.
    PayloadRepresentation,
    /// Coverage values disagree at their public semantic boundary.
    InvalidCoverage {
        /// A stable explanation suitable for diagnostics.
        reason: &'static str,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::InvalidField { field, reason } => write!(formatter, "invalid {field}: {reason}"),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid run state transition: {from} -> {to}")
            }
            Self::DuplicateValue { field } => write!(formatter, "duplicate value in {field}"),
            Self::PayloadRepresentation => formatter
                .write_str("source envelope requires exactly one of inline_payload or object_ref"),
            Self::InvalidCoverage { reason } => write!(formatter, "invalid coverage: {reason}"),
        }
    }
}

impl std::error::Error for ContractError {}

// SPDX-License-Identifier: Apache-2.0

//! Helpers for the small YAML-like configuration subset used in fixtures.
//!
//! The project deliberately avoids pulling in a full parser while the schema is
//! still changing.  These helpers centralize the low-level scalar handling so
//! policy and metadata parsers do not grow subtly different behavior.

/// Trim whitespace and one layer of single or double quotes from a scalar.
pub fn clean_scalar(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

/// Parse a strict boolean literal and include the field name in the error.
pub fn parse_bool(value: &str, field: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        unknown => Err(format!("invalid {field} boolean: {unknown}")),
    }
}

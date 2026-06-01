// SPDX-License-Identifier: Apache-2.0

//! Small parsing helpers for pipe-delimited fixture records.
//!
//! Host visibility fixtures and raw observer fixtures both use compact
//! `key=value|key=value` lines.  This module keeps that mechanical parsing out
//! of runtime-specific crates so each adapter only owns its semantic mapping.

use std::collections::BTreeMap;

/// Parsed `key=value|key=value` fields with typed accessors.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PipeFields {
    inner: BTreeMap<String, String>,
}

impl PipeFields {
    /// Parse a pipe-delimited record into trimmed keys and values.
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut inner = BTreeMap::new();
        for part in line.split('|') {
            let part = part.trim();
            let Some((key, value)) = part.split_once('=') else {
                return Err(format!("invalid pipe field: {part}"));
            };
            inner.insert(key.trim().to_string(), value.trim().to_string());
        }
        Ok(Self { inner })
    }

    /// Return an optional field as a borrowed string slice.
    pub fn optional(&self, key: &str) -> Option<&str> {
        self.inner.get(key).map(String::as_str)
    }

    /// Return a required non-empty field.
    pub fn required(&self, key: &str) -> Result<&str, String> {
        self.optional(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing pipe field: {key}"))
    }

    /// Parse a required `u32` field with the field name in the error.
    pub fn parse_u32(&self, key: &str) -> Result<u32, String> {
        self.required(key)?
            .parse()
            .map_err(|error| format!("invalid {key}: {error}"))
    }

    /// Parse a required `u128` field with the field name in the error.
    pub fn parse_u128(&self, key: &str) -> Result<u128, String> {
        self.required(key)?
            .parse()
            .map_err(|error| format!("invalid {key}: {error}"))
    }
}

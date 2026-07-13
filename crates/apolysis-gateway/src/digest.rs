// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use apolysis_contracts::{RuntimeBinding, SourceEnvelope, SourceManifest, TypedEvidencePayload};

const REQUEST_DIGEST_DOMAIN: &[u8] = b"apolysis.gateway.request/v1\0";
const INLINE_PAYLOAD_DIGEST_DOMAIN: &[u8] = b"apolysis.evidence.inline-payload/v1\0";
const SOURCE_ENVELOPE_DIGEST_DOMAIN: &[u8] = b"apolysis.evidence.source-envelope/v1\0";
const SOURCE_MANIFEST_DIGEST_DOMAIN: &[u8] = b"apolysis.evidence.source-manifest/v1\0";
const RUNTIME_BINDING_DIGEST_DOMAIN: &[u8] = b"apolysis.gateway.runtime-binding/v1\0";
const LEASE_ID_DIGEST_DOMAIN: &[u8] = b"apolysis.gateway.lease-id/v1\0";
const MAX_I_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// A deterministic request-digest construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestError(String);

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DigestError {}

/// Compute the RFC 8785 digest of one Gateway request without trusting its
/// claimed `request_digest` field.
///
/// The operation name is domain-separated and the claimed digest is removed
/// before canonicalization. The tagged `open_run` mode remains in the body, so
/// create and join requests cannot share digest material.
pub fn canonical_request_digest<T: Serialize>(
    operation: &str,
    request: &T,
) -> Result<String, DigestError> {
    if operation.is_empty()
        || !operation
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(DigestError(
            "operation must contain lowercase ASCII letters or underscores".to_string(),
        ));
    }
    let mut value = serde_json::to_value(request)
        .map_err(|error| DigestError(format!("request serialization failed: {error}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| DigestError("Gateway request must serialize as an object".to_string()))?;
    if object.remove("request_digest").is_none() {
        return Err(DigestError(
            "Gateway request is missing request_digest".to_string(),
        ));
    }
    canonical_value_digest(REQUEST_DIGEST_DOMAIN, operation.as_bytes(), &value)
}

/// Compute the source-supplied digest for one structure-only typed payload.
pub fn canonical_inline_payload_digest(
    payload: &TypedEvidencePayload,
) -> Result<String, DigestError> {
    let value = serde_json::to_value(payload)
        .map_err(|error| DigestError(format!("payload serialization failed: {error}")))?;
    canonical_value_digest(
        INLINE_PAYLOAD_DIGEST_DOMAIN,
        payload.evidence_type().as_bytes(),
        &value,
    )
}

/// Compute the immutable digest of the source manifest effective at ingest.
pub fn canonical_source_manifest_digest(manifest: &SourceManifest) -> Result<String, DigestError> {
    let value = serde_json::to_value(manifest)
        .map_err(|error| DigestError(format!("manifest serialization failed: {error}")))?;
    canonical_value_digest(
        SOURCE_MANIFEST_DIGEST_DOMAIN,
        manifest.source_id().as_str().as_bytes(),
        &value,
    )
}

/// Compute the immutable deduplication digest of a source envelope.
pub fn canonical_source_envelope_digest(envelope: &SourceEnvelope) -> Result<String, DigestError> {
    let value = serde_json::to_value(envelope)
        .map_err(|error| DigestError(format!("envelope serialization failed: {error}")))?;
    canonical_value_digest(
        SOURCE_ENVELOPE_DIGEST_DOMAIN,
        envelope.payload_type().as_bytes(),
        &value,
    )
}

/// Compute the immutable conflict-detection digest of a runtime binding.
pub fn canonical_runtime_binding_digest(binding: &RuntimeBinding) -> Result<String, DigestError> {
    let value = serde_json::to_value(binding)
        .map_err(|error| DigestError(format!("binding serialization failed: {error}")))?;
    canonical_value_digest(RUNTIME_BINDING_DIGEST_DOMAIN, b"runtime_binding", &value)
}

/// Hash an already validated bearer lease token before persistence or lookup.
///
/// Lease identifiers have 256 bits of CSPRNG entropy in the production ID
/// generator. Adapters use this digest as the primary lookup key. If an
/// adapter persists the original token to satisfy exact response replay after
/// restart, that replay material must be separately envelope-encrypted with a
/// strict TTL and must never be stored or logged as plaintext.
pub fn lease_id_digest(lease_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(LEASE_ID_DIGEST_DOMAIN);
    hasher.update(lease_id.as_bytes());
    hex(&hasher.finalize())
}

pub(crate) fn canonical_value_digest(
    domain: &[u8],
    discriminator: &[u8],
    value: &Value,
) -> Result<String, DigestError> {
    validate_i_json_numbers(value)?;
    let canonical = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| DigestError(format!("canonical JSON failed: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(discriminator);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(hex(&hasher.finalize()))
}

fn validate_i_json_numbers(value: &Value) -> Result<(), DigestError> {
    match value {
        Value::Number(number) => {
            let safe = number
                .as_u64()
                .map(|value| value <= MAX_I_JSON_INTEGER)
                .or_else(|| {
                    number.as_i64().map(|value| {
                        value >= -(MAX_I_JSON_INTEGER as i64) && value <= MAX_I_JSON_INTEGER as i64
                    })
                })
                .unwrap_or_else(|| number.as_f64().is_some_and(f64::is_finite));
            if !safe {
                return Err(DigestError(
                    "canonical JSON contains a number outside the I-JSON safe range".to_string(),
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_i_json_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_i_json_numbers(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

pub(crate) fn constant_time_digest_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

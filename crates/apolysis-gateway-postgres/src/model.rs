// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    BindRuntimeResponse, FinishRunResponse, IngestAck, OpenRunResponse, PrincipalKind,
};
use apolysis_gateway::{GatewayFailure, LedgerOutcome};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{contract_failure, repository_failure};

pub(crate) const MAX_SQL_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OperationIdentity {
    pub(crate) organization_id: String,
    pub(crate) source_registration_id: String,
    pub(crate) principal_kind: String,
    pub(crate) principal_id: String,
    pub(crate) operation_kind: &'static str,
    pub(crate) client_operation_id: String,
}

impl OperationIdentity {
    pub(crate) fn advisory_lock_key(&self) -> String {
        let mut value = String::new();
        for component in [
            self.organization_id.as_str(),
            self.source_registration_id.as_str(),
            self.principal_kind.as_str(),
            self.principal_id.as_str(),
            self.operation_kind,
            self.client_operation_id.as_str(),
        ] {
            value.push_str(&component.len().to_string());
            value.push(':');
            value.push_str(component);
        }
        value
    }

    pub(crate) fn associated_data(
        &self,
        request_digest: &str,
        replay_expires_at_unix_ms: i64,
    ) -> Vec<u8> {
        let mut value = Vec::with_capacity(
            self.organization_id.len()
                + self.source_registration_id.len()
                + self.principal_kind.len()
                + self.principal_id.len()
                + self.operation_kind.len()
                + self.client_operation_id.len()
                + request_digest.len()
                + 96,
        );
        for component in [
            "apolysis.gateway.operation-replay.v1",
            self.organization_id.as_str(),
            self.source_registration_id.as_str(),
            self.principal_kind.as_str(),
            self.principal_id.as_str(),
            self.operation_kind,
            self.client_operation_id.as_str(),
            request_digest,
        ] {
            value.extend_from_slice(component.as_bytes());
            value.push(0);
        }
        value.extend_from_slice(&replay_expires_at_unix_ms.to_be_bytes());
        value
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "outcome_kind", content = "outcome", rename_all = "snake_case")]
pub(crate) enum ReplayOutcome {
    OpenRun(OpenRunResponse),
    BindRuntime(BindRuntimeResponse),
    Ingest(IngestAck),
    FinishRun(FinishRunResponse),
}

impl From<LedgerOutcome> for ReplayOutcome {
    fn from(value: LedgerOutcome) -> Self {
        match value {
            LedgerOutcome::OpenRun(response) => Self::OpenRun(response),
            LedgerOutcome::BindRuntime(response) => Self::BindRuntime(response),
            LedgerOutcome::Ingest(response) => Self::Ingest(response),
            LedgerOutcome::FinishRun(response) => Self::FinishRun(response),
        }
    }
}

impl From<ReplayOutcome> for LedgerOutcome {
    fn from(value: ReplayOutcome) -> Self {
        match value {
            ReplayOutcome::OpenRun(response) => Self::OpenRun(response),
            ReplayOutcome::BindRuntime(response) => Self::BindRuntime(response),
            ReplayOutcome::Ingest(response) => Self::Ingest(response),
            ReplayOutcome::FinishRun(response) => Self::FinishRun(response),
        }
    }
}

pub(crate) fn sql_i64(value: u64) -> Result<i64, GatewayFailure> {
    i64::try_from(value).map_err(|_| contract_failure())
}

pub(crate) fn sql_u64(value: i64) -> Result<u64, GatewayFailure> {
    u64::try_from(value).map_err(|_| repository_failure())
}

pub(crate) fn json_value<T: Serialize>(value: &T) -> Result<serde_json::Value, GatewayFailure> {
    serde_json::to_value(value).map_err(|_| repository_failure())
}

pub(crate) fn json_decode<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, GatewayFailure> {
    serde_json::from_value(value).map_err(|_| repository_failure())
}

pub(crate) fn enum_name<T: Serialize>(value: &T) -> Result<String, GatewayFailure> {
    match serde_json::to_value(value).map_err(|_| repository_failure())? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(repository_failure()),
    }
}

pub(crate) fn principal_kind_name(value: PrincipalKind) -> Result<String, GatewayFailure> {
    enum_name(&value)
}

pub(crate) fn join_proof_digest(proof_ref: &str) -> Vec<u8> {
    domain_digest(
        b"apolysis.gateway.join-proof-ref/v1\0",
        proof_ref.as_bytes(),
    )
}

pub(crate) fn runtime_identity_digest(identity_ref: &str) -> Vec<u8> {
    domain_digest(
        b"apolysis.gateway.runtime-identity-ref/v1\0",
        identity_ref.as_bytes(),
    )
}

pub(crate) fn sha256_bytes(value: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().to_vec()
}

pub(crate) fn domain_digest(domain: &[u8], value: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().to_vec()
}

pub(crate) fn hex_digest(value: &str) -> Result<Vec<u8>, GatewayFailure> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(repository_failure());
    }
    let mut decoded = Vec::with_capacity(32);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(repository_failure)?;
        let low = hex_nibble(pair[1]).ok_or_else(repository_failure)?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

pub(crate) fn encode_digest(value: &[u8]) -> Result<String, GatewayFailure> {
    if value.len() != 32 {
        return Err(repository_failure());
    }
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in value {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_aad_is_unambiguous() {
        let identity = OperationIdentity {
            organization_id: "org-a".into(),
            source_registration_id: "source-a".into(),
            principal_kind: "service".into(),
            principal_id: "principal-a".into(),
            operation_kind: "open_run",
            client_operation_id: "operation-a".into(),
        };
        assert_ne!(
            identity.associated_data("digest-a", 100),
            identity.associated_data("digest-a", 101)
        );
        assert_ne!(
            identity.associated_data("digest-a", 100),
            identity.associated_data("digest-b", 100)
        );
    }

    #[test]
    fn advisory_lock_key_is_postgres_text_safe_and_boundary_unambiguous() {
        let identity = OperationIdentity {
            organization_id: "ab".into(),
            source_registration_id: "c".into(),
            principal_kind: "workload".into(),
            principal_id: "principal".into(),
            operation_kind: "open_run",
            client_operation_id: "operation".into(),
        };
        let different_boundary = OperationIdentity {
            organization_id: "a".into(),
            source_registration_id: "bc".into(),
            ..identity.clone()
        };
        assert!(!identity.advisory_lock_key().contains('\0'));
        assert_ne!(
            identity.advisory_lock_key(),
            different_boundary.advisory_lock_key()
        );
    }

    #[test]
    fn join_proof_digest_is_domain_separated_and_not_plaintext() {
        let digest = join_proof_digest("grant-secret");
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, b"grant-secret");
        assert_ne!(
            digest,
            hex_digest(&apolysis_gateway::lease_id_digest("grant-secret")).expect("lease digest")
        );
    }
}

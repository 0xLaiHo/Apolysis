// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{RuntimeBindingRecordType, RuntimeBindingWireV1};

pub const KUBERNETES_ATTRIBUTION_SCHEMA_VERSION: u32 = 1;
pub const MAX_KUBERNETES_POD_UID_BYTES: usize = 36;
pub const KUBERNETES_REFERENCE_BYTES: usize = 64;
const KUBERNETES_REFERENCE_PREFIX_V1: &[u8] = b"apolysis:kubernetes-reference:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KubernetesReferenceKind {
    Namespace,
    Node,
    Container,
    RuntimeClass,
}

impl KubernetesReferenceKind {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Namespace => b"namespace",
            Self::Node => b"node",
            Self::Container => b"container",
            Self::RuntimeClass => b"runtime_class",
        }
    }

    const fn field(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Node => "node",
            Self::Container => "container",
            Self::RuntimeClass => "runtime_class",
        }
    }

    const fn maximum(self) -> usize {
        match self {
            Self::Namespace | Self::Container => 63,
            Self::Node | Self::RuntimeClass => 253,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KubernetesReferenceError {
    field: &'static str,
    reason: &'static str,
}

impl KubernetesReferenceError {
    pub const fn field(self) -> &'static str {
        self.field
    }

    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for KubernetesReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "kubernetes_reference_invalid field={} reason={}",
            self.field, self.reason
        )
    }
}

impl std::error::Error for KubernetesReferenceError {}

/// Produce the stable, domain-separated content-off reference for one selected
/// Kubernetes identifier. Rejected values are never included in diagnostics.
pub fn kubernetes_reference_v1(
    kind: KubernetesReferenceKind,
    raw: &str,
) -> Result<String, KubernetesReferenceError> {
    let bytes = raw.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= kind.maximum()
        && match kind {
            KubernetesReferenceKind::Namespace | KubernetesReferenceKind::Container => {
                valid_dns_label(bytes)
            }
            KubernetesReferenceKind::Node | KubernetesReferenceKind::RuntimeClass => raw
                .split('.')
                .all(|label| valid_dns_label(label.as_bytes())),
        };
    if !valid {
        return Err(KubernetesReferenceError {
            field: kind.field(),
            reason: "must be a bounded canonical lowercase Kubernetes identifier",
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(KUBERNETES_REFERENCE_PREFIX_V1);
    hasher.update([0]);
    hasher.update(kind.domain());
    hasher.update([0]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(KUBERNETES_REFERENCE_BYTES);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(output)
}

fn valid_dns_label(bytes: &[u8]) -> bool {
    let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 63
        && valid_edge(bytes[0])
        && valid_edge(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| valid_edge(*byte) || *byte == b'-')
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KubernetesAttributionRecordType {
    #[serde(rename = "kubernetes_attribution_observed")]
    Observed,
    #[serde(rename = "kubernetes_attribution_retired")]
    Retired,
    #[serde(rename = "kubernetes_attribution_suspended")]
    Suspended,
}

impl KubernetesAttributionRecordType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "kubernetes_attribution_observed",
            Self::Retired => "kubernetes_attribution_retired",
            Self::Suspended => "kubernetes_attribution_suspended",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesContainerKind {
    Application,
    Init,
    Ephemeral,
}

impl KubernetesContainerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Init => "init",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// Explicitly nullable privacy-safe reference used by the stable wire contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct KubernetesAttributionOptionalRef(pub Option<String>);

impl<'de> Deserialize<'de> for KubernetesAttributionOptionalRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionalRefVisitor;

        impl<'de> Visitor<'de> for OptionalRefVisitor {
            type Value = KubernetesAttributionOptionalRef;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a privacy reference string or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(KubernetesAttributionOptionalRef(None))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(KubernetesAttributionOptionalRef(None))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(KubernetesAttributionOptionalRef(Some(value.to_string())))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(KubernetesAttributionOptionalRef(Some(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(KubernetesAttributionOptionalRef(Some(value)))
            }
        }

        deserializer.deserialize_any(OptionalRefVisitor)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesWorkloadClaimV1 {
    pub schema_version: u32,
    pub claim_revision: u64,
    pub cluster_id: String,
    pub namespace_ref: String,
    pub pod_uid: String,
    pub container_kind: KubernetesContainerKind,
    pub container_ref: String,
}

impl KubernetesWorkloadClaimV1 {
    pub fn validate(&self) -> Result<(), KubernetesAttributionWireValidationError> {
        if self.schema_version != KUBERNETES_ATTRIBUTION_SCHEMA_VERSION {
            return Err(KubernetesAttributionWireValidationError::UnsupportedSchemaVersion);
        }
        if self.claim_revision == 0 {
            return Err(KubernetesAttributionWireValidationError::InvalidField {
                field: "claim_revision",
                reason: "must be non-zero",
            });
        }
        validate_uuid("cluster_id", &self.cluster_id)?;
        validate_reference("namespace_ref", &self.namespace_ref)?;
        validate_uuid("pod_uid", &self.pod_uid)?;
        validate_reference("container_ref", &self.container_ref)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAttributionWireV1 {
    pub record_type: KubernetesAttributionRecordType,
    pub schema_version: u32,
    pub agent_run_id: String,
    pub cluster_id: String,
    pub namespace_ref: String,
    pub pod_uid: String,
    pub node_ref: String,
    pub runtime_class_ref: KubernetesAttributionOptionalRef,
    pub container_kind: KubernetesContainerKind,
    pub container_ref: String,
    pub runtime_binding: RuntimeBindingWireV1,
}

impl KubernetesAttributionWireV1 {
    pub fn validate(&self) -> Result<(), KubernetesAttributionWireValidationError> {
        if self.schema_version != KUBERNETES_ATTRIBUTION_SCHEMA_VERSION {
            return Err(KubernetesAttributionWireValidationError::UnsupportedSchemaVersion);
        }
        validate_identifier("agent_run_id", &self.agent_run_id, 128)?;
        validate_uuid("cluster_id", &self.cluster_id)?;
        validate_reference("namespace_ref", &self.namespace_ref)?;
        validate_uuid("pod_uid", &self.pod_uid)?;
        validate_reference("node_ref", &self.node_ref)?;
        if let Some(value) = self.runtime_class_ref.0.as_deref() {
            validate_reference("runtime_class_ref", value)?;
        }
        validate_reference("container_ref", &self.container_ref)?;
        if !matches!(
            self.runtime_binding.adapter.as_str(),
            "containerd" | "k3s_containerd"
        ) {
            return Err(KubernetesAttributionWireValidationError::InvalidField {
                field: "runtime_binding.adapter",
                reason: "must be containerd or k3s_containerd",
            });
        }
        self.runtime_binding.validate().map_err(|_| {
            KubernetesAttributionWireValidationError::InvalidField {
                field: "runtime_binding",
                reason: "must be a valid exact runtime binding",
            }
        })?;
        if self.runtime_binding.record_type != RuntimeBindingRecordType::Observed {
            return Err(KubernetesAttributionWireValidationError::InvalidField {
                field: "runtime_binding.record_type",
                reason: "must reference an observed runtime binding",
            });
        }
        if self.agent_run_id != self.runtime_binding.agent_run_id {
            return Err(KubernetesAttributionWireValidationError::InvalidField {
                field: "runtime_binding.agent_run_id",
                reason: "must equal the attribution agent run",
            });
        }
        Ok(())
    }

    pub fn with_record_type(&self, record_type: KubernetesAttributionRecordType) -> Self {
        let mut value = self.clone();
        value.record_type = record_type;
        value
    }

    pub fn has_same_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.agent_run_id == other.agent_run_id
            && self.cluster_id == other.cluster_id
            && self.namespace_ref == other.namespace_ref
            && self.pod_uid == other.pod_uid
            && self.node_ref == other.node_ref
            && self.runtime_class_ref == other.runtime_class_ref
            && self.container_kind == other.container_kind
            && self.container_ref == other.container_ref
            && self
                .runtime_binding
                .has_same_identity(&other.runtime_binding)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KubernetesAttributionWireValidationError {
    UnsupportedSchemaVersion,
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

impl KubernetesAttributionWireValidationError {
    pub const fn field(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "schema_version",
            Self::InvalidField { field, .. } => field,
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "must equal the v1 schema version",
            Self::InvalidField { reason, .. } => reason,
        }
    }
}

impl fmt::Display for KubernetesAttributionWireValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "kubernetes_attribution_wire_invalid field={} reason={}",
            self.field(),
            self.reason()
        )
    }
}

impl std::error::Error for KubernetesAttributionWireValidationError {}

fn validate_reference(
    field: &'static str,
    value: &str,
) -> Result<(), KubernetesAttributionWireValidationError> {
    if value.len() != KUBERNETES_REFERENCE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(KubernetesAttributionWireValidationError::InvalidField {
            field,
            reason: "must be a 64-byte lowercase hexadecimal privacy reference",
        });
    }
    Ok(())
}

fn validate_uuid(
    field: &'static str,
    value: &str,
) -> Result<(), KubernetesAttributionWireValidationError> {
    if !is_canonical_nonzero_uuid(value) {
        return Err(KubernetesAttributionWireValidationError::InvalidField {
            field,
            reason: "must be a canonical lowercase non-zero UUID",
        });
    }
    Ok(())
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), KubernetesAttributionWireValidationError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KubernetesAttributionWireValidationError::InvalidField {
            field,
            reason: "must be a bounded canonical identifier",
        });
    }
    Ok(())
}

fn is_canonical_nonzero_uuid(value: &str) -> bool {
    if value.len() != MAX_KUBERNETES_POD_UID_BYTES {
        return false;
    }
    let mut non_zero = false;
    for (index, byte) in value.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
            return false;
        } else if byte != b'0' {
            non_zero = true;
        }
    }
    non_zero
}

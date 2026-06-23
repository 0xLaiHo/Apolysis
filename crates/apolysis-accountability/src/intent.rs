// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

pub const INTENT_SCHEMA_V1: u32 = 1;
pub const MAX_INTENT_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_TENANT_ID: &str = "default";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntentRequest {
    Register {
        intent: SessionIntent,
    },
    Renew {
        session_id: String,
        expires_at_unix_ms: u64,
    },
    Close {
        session_id: String,
    },
    Query {
        #[serde(default = "default_tenant_id")]
        tenant_id: String,
        session_id: String,
    },
    ListSessions {
        tenant_id: String,
        #[serde(default)]
        retention_tier: Option<RetentionTier>,
    },
    ApplyRetention {
        tenant_id: String,
        #[serde(default = "default_true")]
        dry_run: bool,
        #[serde(default)]
        now_unix_ms: Option<u64>,
    },
    Health,
}

impl IntentRequest {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), IntentError> {
        match self {
            Self::Register { intent } => intent.validate(now_unix_ms),
            Self::Renew {
                session_id,
                expires_at_unix_ms,
            } => {
                validate_session_id(session_id)?;
                if *expires_at_unix_ms <= now_unix_ms {
                    return Err(IntentError::Expired);
                }
                Ok(())
            }
            Self::Close { session_id } => validate_session_id(session_id),
            Self::Query {
                tenant_id,
                session_id,
            } => {
                validate_tenant_id(tenant_id)?;
                validate_session_id(session_id)
            }
            Self::ListSessions { tenant_id, .. } => validate_tenant_id(tenant_id),
            Self::ApplyRetention { tenant_id, .. } => validate_tenant_id(tenant_id),
            Self::Health => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionTier {
    Short,
    #[default]
    Standard,
    Extended,
}

impl RetentionTier {
    pub const fn retention_window_ms(self) -> u64 {
        const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
        match self {
            Self::Short => 7 * DAY_MS,
            Self::Standard => 30 * DAY_MS,
            Self::Extended => 365 * DAY_MS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionIntent {
    pub schema_version: u32,
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    #[serde(default)]
    pub retention_tier: RetentionTier,
    pub session_id: String,
    pub expires_at_unix_ms: u64,
    pub declared_actions: Vec<ActionClass>,
    pub allowed_resources: Vec<ResourceSelector>,
    pub policy_ref: String,
    pub workload_selectors: Vec<WorkloadSelector>,
}

impl SessionIntent {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), IntentError> {
        if self.schema_version != INTENT_SCHEMA_V1 {
            return Err(IntentError::UnsupportedSchemaVersion(self.schema_version));
        }
        validate_tenant_id(&self.tenant_id)?;
        validate_session_id(&self.session_id)?;
        if self.expires_at_unix_ms <= now_unix_ms {
            return Err(IntentError::Expired);
        }
        if self.policy_ref.trim().is_empty() {
            return Err(IntentError::EmptyPolicyRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Test,
    Build,
    Execute,
    ReadFile,
    WriteFile,
    Network,
    Credential,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Workspace,
    Path,
    Egress,
    Command,
    Credential,
    ServiceAccountToken,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSelector {
    pub kind: ResourceKind,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSelector {
    Local,
    Docker,
    Containerd,
    Kubernetes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadSelector {
    pub runtime: RuntimeSelector,
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentError {
    FrameTooLarge(usize),
    InvalidJson(String),
    UnsupportedSchemaVersion(u32),
    EmptyTenantId,
    InvalidTenantId,
    EmptySessionId,
    InvalidSessionId,
    EmptyPolicyRef,
    Expired,
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLarge(size) => write!(formatter, "intent frame is too large: {size}"),
            Self::InvalidJson(error) => write!(formatter, "invalid intent JSON: {error}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported intent schema version: {version}")
            }
            Self::EmptyTenantId => formatter.write_str("tenant id must not be empty"),
            Self::InvalidTenantId => formatter.write_str(
                "tenant id must be 1-63 ASCII letters, digits, dots, underscores, or hyphens",
            ),
            Self::EmptySessionId => formatter.write_str("session id must not be empty"),
            Self::InvalidSessionId => formatter.write_str(
                "session id must be 1-128 ASCII letters, digits, dots, underscores, or hyphens",
            ),
            Self::EmptyPolicyRef => formatter.write_str("policy reference must not be empty"),
            Self::Expired => formatter.write_str("intent is expired"),
        }
    }
}

fn default_tenant_id() -> String {
    DEFAULT_TENANT_ID.to_string()
}

fn default_true() -> bool {
    true
}

impl std::error::Error for IntentError {}

pub fn decode_intent_frame(frame: &[u8], now_unix_ms: u64) -> Result<IntentRequest, IntentError> {
    if frame.len() > MAX_INTENT_FRAME_BYTES {
        return Err(IntentError::FrameTooLarge(frame.len()));
    }

    let request: IntentRequest = serde_json::from_slice(frame)
        .map_err(|error| IntentError::InvalidJson(error.to_string()))?;
    request.validate(now_unix_ms)?;
    Ok(request)
}

fn validate_session_id(session_id: &str) -> Result<(), IntentError> {
    if session_id.trim().is_empty() {
        return Err(IntentError::EmptySessionId);
    }
    if session_id.len() > 128
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(IntentError::InvalidSessionId);
    }
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), IntentError> {
    if tenant_id.trim().is_empty() {
        return Err(IntentError::EmptyTenantId);
    }
    if tenant_id.len() > 63
        || !tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(IntentError::InvalidTenantId);
    }
    Ok(())
}

// SPDX-License-Identifier: Apache-2.0

//! Core domain types for Apolysis.
//!
//! This crate intentionally has no third-party dependencies in M1.  The event
//! schema is the contract shared by the CLI, policy engine, store, and future
//! eBPF observer.  Keeping it small makes early JSONL fixtures stable and easy
//! to inspect during kernel/runtime experiments.

use std::time::{SystemTime, UNIX_EPOCH};

/// Anything that can be written as one JSONL record.
///
/// The project will likely move to `serde` once the schema settles.  For M1 we
/// keep serialization explicit so every emitted field is deliberate and visible.
pub trait JsonLine {
    fn to_json_line(&self) -> String;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeKind {
    Local,
    Docker,
    Kubernetes,
    Firecracker,
}

impl RuntimeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Docker => "docker",
            Self::Kubernetes => "kubernetes",
            Self::Firecracker => "firecracker",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventSource {
    Manual,
    ProcessTree,
    KernelTracepoint,
    BpfLsm,
    Uprobe,
    RuntimeMetadata,
    AgentFeedback,
}

impl EventSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::ProcessTree => "process_tree",
            Self::KernelTracepoint => "kernel_tracepoint",
            Self::BpfLsm => "bpf_lsm",
            Self::Uprobe => "uprobe",
            Self::RuntimeMetadata => "runtime_metadata",
            Self::AgentFeedback => "agent_feedback",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventType {
    SessionStarted,
    RuntimeMetadata,
    Exec,
    FileOpen,
    NetworkConnect,
    CredentialRead,
    ProcessExit,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SessionStarted => "session_started",
            Self::RuntimeMetadata => "runtime_metadata",
            Self::Exec => "exec",
            Self::FileOpen => "file_open",
            Self::NetworkConnect => "network_connect",
            Self::CredentialRead => "credential_read",
            Self::ProcessExit => "process_exit",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Notify,
    Block,
    Kill,
    Review,
}

impl PolicyDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Notify => "notify",
            Self::Block => "block",
            Self::Kill => "kill",
            Self::Review => "review",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnforcementBackend {
    AuditOnly,
    TracepointNotify,
    BpfLsmBlock,
    SignalKill,
}

impl EnforcementBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuditOnly => "audit_only",
            Self::TracepointNotify => "tracepoint_notify",
            Self::BpfLsmBlock => "bpf_lsm_block",
            Self::SignalKill => "signal_kill",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSession {
    pub id: String,
    pub runtime: RuntimeKind,
    pub root: Option<String>,
    pub policy_path: String,
    pub started_at_unix_ms: u128,
}

impl SandboxSession {
    pub fn new(
        id: impl Into<String>,
        runtime: RuntimeKind,
        policy_path: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            runtime,
            root: None,
            policy_path: policy_path.into(),
            started_at_unix_ms: now_unix_ms(),
        }
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for SandboxSession {
    fn to_json_line(&self) -> String {
        let root = self
            .root
            .as_ref()
            .map(|value| json_string(value))
            .unwrap_or_else(|| "null".to_string());

        format!(
            "{{\"record_type\":\"session\",\"id\":{},\"runtime\":{},\"root\":{},\"policy_path\":{},\"started_at_unix_ms\":{}}}",
            json_string(&self.id),
            json_string(self.runtime.as_str()),
            root,
            json_string(&self.policy_path),
            self.started_at_unix_ms
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalEvent {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub event_source: EventSource,
    pub event_type: EventType,
    pub pid: u32,
    pub ppid: u32,
    pub actor: String,
    pub resource: String,
    pub action: String,
}

impl CanonicalEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        event_source: EventSource,
        event_type: EventType,
        pid: u32,
        ppid: u32,
        actor: impl Into<String>,
        resource: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            session_id: session_id.into(),
            event_source,
            event_type,
            pid,
            ppid,
            actor: actor.into(),
            resource: resource.into(),
            action: action.into(),
        }
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for CanonicalEvent {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":\"event\",\"timestamp_unix_ms\":{},\"session_id\":{},\"event_source\":{},\"event_type\":{},\"pid\":{},\"ppid\":{},\"actor\":{},\"resource\":{},\"action\":{}}}",
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(self.event_source.as_str()),
            json_string(self.event_type.as_str()),
            self.pid,
            self.ppid,
            json_string(&self.actor),
            json_string(&self.resource),
            json_string(&self.action)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyViolation {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub rule_id: String,
    pub decision: PolicyDecision,
    pub reason: String,
    pub pid: u32,
    pub target: String,
    pub enforcement_backend: EnforcementBackend,
}

impl PolicyViolation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        rule_id: impl Into<String>,
        decision: PolicyDecision,
        reason: impl Into<String>,
        pid: u32,
        target: impl Into<String>,
        enforcement_backend: EnforcementBackend,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            session_id: session_id.into(),
            rule_id: rule_id.into(),
            decision,
            reason: reason.into(),
            pid,
            target: target.into(),
            enforcement_backend,
        }
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for PolicyViolation {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":\"policy_violation\",\"timestamp_unix_ms\":{},\"session_id\":{},\"rule_id\":{},\"decision\":{},\"reason\":{},\"pid\":{},\"target\":{},\"enforcement_backend\":{}}}",
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(&self.rule_id),
            json_string(self.decision.as_str()),
            json_string(&self.reason),
            self.pid,
            json_string(&self.target),
            json_string(self.enforcement_backend.as_str())
        )
    }
}

/// Escape a Rust string as a JSON string.
///
/// This only implements the JSON escapes Apolysis can emit today.  It handles
/// control characters so JSONL consumers do not receive malformed records.
pub fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

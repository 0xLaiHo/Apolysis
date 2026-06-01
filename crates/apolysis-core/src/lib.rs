// SPDX-License-Identifier: Apache-2.0

//! Core domain types for Apolysis.
//!
//! This crate intentionally has no third-party dependencies.  The event
//! schema is the contract shared by the CLI, policy engine, store, and future
//! eBPF observer.  Keeping it small makes early JSONL fixtures stable and easy
//! to inspect during kernel/runtime experiments.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod fields;
pub mod scalars;
pub mod vocabulary;

pub use vocabulary::{actions, actors, env, feedback, records, resources, runtimes};

/// Anything that can be written as one JSONL record.
///
/// The project will likely move to `serde` once the schema settles.  For now we
/// keep serialization explicit so every emitted field is deliberate and visible.
pub trait JsonLine {
    /// Render one complete JSON object without a trailing newline.
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
    /// Return the stable schema string for this runtime.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => runtimes::LOCAL,
            Self::Docker => runtimes::DOCKER,
            Self::Kubernetes => runtimes::KUBERNETES,
            Self::Firecracker => runtimes::FIRECRACKER,
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
    /// Return the stable schema string for this event source.
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
    FileCreate,
    FileTruncate,
    FileUnlink,
    FileRename,
    NetworkConnect,
    CredentialRead,
    ProcessExit,
}

impl EventType {
    /// Return the stable schema string for this event type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SessionStarted => "session_started",
            Self::RuntimeMetadata => "runtime_metadata",
            Self::Exec => "exec",
            Self::FileOpen => "file_open",
            Self::FileCreate => "file_create",
            Self::FileTruncate => "file_truncate",
            Self::FileUnlink => "file_unlink",
            Self::FileRename => "file_rename",
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
    /// Return the stable schema string for this policy decision.
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
    /// Return the stable schema string for this enforcement backend.
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
    /// Create a session record with the current wall-clock timestamp.
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

    /// Render this session as a JSONL record.
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
            "{{\"record_type\":{},\"id\":{},\"runtime\":{},\"root\":{},\"policy_path\":{},\"started_at_unix_ms\":{}}}",
            json_string(records::SESSION),
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
    pub container_id: Option<String>,
    pub cgroup_id: Option<String>,
}

impl CanonicalEvent {
    /// Create a normalized event with the current wall-clock timestamp.
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
            container_id: None,
            cgroup_id: None,
        }
    }

    /// Override the event timestamp, primarily for replayed kernel fixtures.
    pub fn with_timestamp(mut self, timestamp_unix_ms: u128) -> Self {
        self.timestamp_unix_ms = timestamp_unix_ms;
        self
    }

    /// Attach runtime/container identity after the semantic event is created.
    pub fn with_runtime_identity(
        mut self,
        container_id: Option<String>,
        cgroup_id: Option<String>,
    ) -> Self {
        self.container_id = container_id;
        self.cgroup_id = cgroup_id;
        self
    }

    /// Render this event as a JSONL record.
    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for CanonicalEvent {
    fn to_json_line(&self) -> String {
        let container_id = self
            .container_id
            .as_ref()
            .map(|value| json_string(value))
            .unwrap_or_else(|| "null".to_string());
        let cgroup_id = self
            .cgroup_id
            .as_ref()
            .map(|value| json_string(value))
            .unwrap_or_else(|| "null".to_string());

        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"event_source\":{},\"event_type\":{},\"pid\":{},\"ppid\":{},\"actor\":{},\"resource\":{},\"action\":{},\"container_id\":{},\"cgroup_id\":{}}}",
            json_string(records::EVENT),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(self.event_source.as_str()),
            json_string(self.event_type.as_str()),
            self.pid,
            self.ppid,
            json_string(&self.actor),
            json_string(&self.resource),
            json_string(&self.action),
            container_id,
            cgroup_id
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawKernelEvent {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub event_source: EventSource,
    pub event_name: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub resource: String,
    pub action: String,
    pub container_id: Option<String>,
    pub cgroup_id: Option<String>,
    pub raw_payload: String,
}

impl RawKernelEvent {
    /// Create a raw kernel event exactly as delivered by an observer backend.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp_unix_ms: u128,
        session_id: impl Into<String>,
        event_source: EventSource,
        event_name: impl Into<String>,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: impl Into<String>,
        resource: impl Into<String>,
        action: impl Into<String>,
        container_id: Option<String>,
        cgroup_id: Option<String>,
        raw_payload: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms,
            session_id: session_id.into(),
            event_source,
            event_name: event_name.into(),
            pid,
            ppid,
            uid,
            gid,
            comm: comm.into(),
            resource: resource.into(),
            action: action.into(),
            container_id,
            cgroup_id,
            raw_payload: raw_payload.into(),
        }
    }

    /// Render this raw kernel event as a JSONL record.
    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for RawKernelEvent {
    fn to_json_line(&self) -> String {
        let container_id = self
            .container_id
            .as_ref()
            .map(|value| json_string(value))
            .unwrap_or_else(|| "null".to_string());
        let cgroup_id = self
            .cgroup_id
            .as_ref()
            .map(|value| json_string(value))
            .unwrap_or_else(|| "null".to_string());

        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"event_source\":{},\"event_name\":{},\"pid\":{},\"ppid\":{},\"uid\":{},\"gid\":{},\"comm\":{},\"resource\":{},\"action\":{},\"container_id\":{},\"cgroup_id\":{},\"raw_payload\":{}}}",
            json_string(records::RAW_KERNEL_EVENT),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(self.event_source.as_str()),
            json_string(&self.event_name),
            self.pid,
            self.ppid,
            self.uid,
            self.gid,
            json_string(&self.comm),
            json_string(&self.resource),
            json_string(&self.action),
            container_id,
            cgroup_id,
            json_string(&self.raw_payload)
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
    /// Create a policy violation record with the current wall-clock timestamp.
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

    /// Render this violation as a JSONL record.
    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for PolicyViolation {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"rule_id\":{},\"decision\":{},\"reason\":{},\"pid\":{},\"target\":{},\"enforcement_backend\":{}}}",
            json_string(records::POLICY_VIOLATION),
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

/// Return the current Unix timestamp in milliseconds.
pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

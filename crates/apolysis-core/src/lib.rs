// SPDX-License-Identifier: Apache-2.0

//! Core domain types for Apolysis.
//!
//! This crate intentionally has no third-party dependencies. Its explicit
//! records form the local JSONL v1 observation contract shared by the eBPF
//! observer, CLI, daemon, store, and runtime-attribution crates. Keeping this
//! crate small preserves compatibility across the collector and userspace
//! pipeline.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod fields;
pub mod scalars;
pub mod vocabulary;

pub use vocabulary::{actions, actors, records, resources};

/// Anything that can be written as one JSONL record.
///
/// The project will likely move to `serde` once the schema settles.  For now we
/// keep serialization explicit so every emitted field is deliberate and visible.
pub trait JsonLine {
    /// Render one complete JSON object without a trailing newline.
    fn to_json_line(&self) -> String;
}

pub const COLLECTOR_CAPABILITY_SCHEMA_VERSION: u32 = 1;
pub const COLLECTOR_LIFECYCLE_SCHEMA_VERSION: u32 = 1;
pub const OBSERVATION_GAP_SCHEMA_VERSION: u32 = 1;

pub fn new_collector_instance_id() -> Result<String, String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map_err(|error| format!("failed to allocate collector instance ID: {error}"))?;
    let value = value.trim();
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        return Err("kernel returned an invalid collector instance ID".to_string());
    }
    Ok(value.to_ascii_lowercase())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorLifecycleState {
    Started,
    Checkpoint,
    Stopped,
    Failed,
}

impl CollectorLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Checkpoint => "checkpoint",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorHealthState {
    Healthy,
    Degraded,
    Failed,
}

impl CollectorHealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorNormalStopReason {
    AgentRunClosed,
    DaemonShutdown,
    DurationElapsed,
    AgentExited,
    ShutdownSignal,
}

impl CollectorNormalStopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentRunClosed => "agent_run_closed",
            Self::DaemonShutdown => "daemon_shutdown",
            Self::DurationElapsed => "duration_elapsed",
            Self::AgentExited => "agent_exited",
            Self::ShutdownSignal => "shutdown_signal",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorFailureReason {
    AttachFailure,
    VerifierFailure,
    AbiMismatch,
    DecodeFailure,
    CounterReadFailure,
    StorageFailure,
    ObserverFailure,
    CollectorRestart,
    IncompleteTerminalFlush,
}

impl CollectorFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AttachFailure => "attach_failure",
            Self::VerifierFailure => "verifier_failure",
            Self::AbiMismatch => "abi_mismatch",
            Self::DecodeFailure => "decode_failure",
            Self::CounterReadFailure => "counter_read_failure",
            Self::StorageFailure => "storage_failure",
            Self::ObserverFailure => "observer_failure",
            Self::CollectorRestart => "collector_restart",
            Self::IncompleteTerminalFlush => "incomplete_terminal_flush",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CollectorLifecycleCounters {
    pub global_reserve_failures: u64,
    pub global_map_pressure: u64,
    pub global_abi_mismatches: u64,
    pub global_decode_failures: u64,
    pub global_truncations: u64,
    pub scope_missing_entries: u64,
    pub scope_missing_exits: u64,
    pub scope_pending: u64,
}

impl CollectorLifecycleCounters {
    pub fn has_loss(self) -> bool {
        self.global_reserve_failures > 0
            || self.global_map_pressure > 0
            || self.global_abi_mismatches > 0
            || self.global_decode_failures > 0
            || self.global_truncations > 0
            || self.scope_missing_entries > 0
            || self.scope_missing_exits > 0
    }

    fn checkpoint_health(self) -> CollectorHealthState {
        if self.has_loss() {
            CollectorHealthState::Degraded
        } else {
            CollectorHealthState::Healthy
        }
    }

    fn terminal_health(self) -> CollectorHealthState {
        if self.has_loss() || self.scope_pending > 0 {
            CollectorHealthState::Degraded
        } else {
            CollectorHealthState::Healthy
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorLifecycleRecord {
    schema_version: u32,
    timestamp_unix_ms: u128,
    agent_run_id: String,
    collector_instance_id: String,
    state: CollectorLifecycleState,
    health: CollectorHealthState,
    stop_reason: Option<&'static str>,
    counters: CollectorLifecycleCounters,
}

impl CollectorLifecycleRecord {
    pub fn started(
        agent_run_id: impl Into<String>,
        collector_instance_id: impl Into<String>,
    ) -> Self {
        Self::new(
            agent_run_id,
            collector_instance_id,
            CollectorLifecycleState::Started,
            CollectorHealthState::Healthy,
            None,
            CollectorLifecycleCounters::default(),
        )
    }

    pub fn checkpoint(
        agent_run_id: impl Into<String>,
        collector_instance_id: impl Into<String>,
        counters: CollectorLifecycleCounters,
    ) -> Self {
        Self::new(
            agent_run_id,
            collector_instance_id,
            CollectorLifecycleState::Checkpoint,
            counters.checkpoint_health(),
            None,
            counters,
        )
    }

    pub fn stopped(
        agent_run_id: impl Into<String>,
        collector_instance_id: impl Into<String>,
        reason: CollectorNormalStopReason,
        counters: CollectorLifecycleCounters,
    ) -> Self {
        Self::new(
            agent_run_id,
            collector_instance_id,
            CollectorLifecycleState::Stopped,
            counters.terminal_health(),
            Some(reason.as_str()),
            counters,
        )
    }

    pub fn failed(
        agent_run_id: impl Into<String>,
        collector_instance_id: impl Into<String>,
        reason: CollectorFailureReason,
        counters: CollectorLifecycleCounters,
    ) -> Self {
        Self::new(
            agent_run_id,
            collector_instance_id,
            CollectorLifecycleState::Failed,
            CollectorHealthState::Failed,
            Some(reason.as_str()),
            counters,
        )
    }

    fn new(
        agent_run_id: impl Into<String>,
        collector_instance_id: impl Into<String>,
        state: CollectorLifecycleState,
        health: CollectorHealthState,
        stop_reason: Option<&'static str>,
        counters: CollectorLifecycleCounters,
    ) -> Self {
        Self {
            schema_version: COLLECTOR_LIFECYCLE_SCHEMA_VERSION,
            timestamp_unix_ms: now_unix_ms(),
            agent_run_id: agent_run_id.into(),
            collector_instance_id: collector_instance_id.into(),
            state,
            health,
            stop_reason,
            counters,
        }
    }

    pub fn with_timestamp(mut self, timestamp_unix_ms: u128) -> Self {
        self.timestamp_unix_ms = timestamp_unix_ms;
        self
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }

    pub fn agent_run_id(&self) -> &str {
        &self.agent_run_id
    }
}

impl JsonLine for CollectorLifecycleRecord {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":{},\"schema_version\":{},\"timestamp_unix_ms\":{},\"agent_run_id\":{},\"collector\":{},\"collector_instance_id\":{},\"state\":{},\"health\":{},\"stop_reason\":{},\"counters\":{{\"global_reserve_failures\":{},\"global_map_pressure\":{},\"global_abi_mismatches\":{},\"global_decode_failures\":{},\"global_truncations\":{},\"scope_missing_entries\":{},\"scope_missing_exits\":{},\"scope_pending\":{}}}}}",
            json_string(records::COLLECTOR_LIFECYCLE),
            self.schema_version,
            self.timestamp_unix_ms,
            json_string(&self.agent_run_id),
            json_string("apolysis_observer"),
            json_string(&self.collector_instance_id),
            json_string(self.state.as_str()),
            json_string(self.health.as_str()),
            optional_json_string(self.stop_reason),
            self.counters.global_reserve_failures,
            self.counters.global_map_pressure,
            self.counters.global_abi_mismatches,
            self.counters.global_decode_failures,
            self.counters.global_truncations,
            self.counters.scope_missing_entries,
            self.counters.scope_missing_exits,
            self.counters.scope_pending,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeRelation {
    Exact,
    Inferred,
    Ambiguous,
    Unattributed,
}

impl RuntimeRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Inferred => "inferred",
            Self::Ambiguous => "ambiguous",
            Self::Unattributed => "unattributed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationGapKind {
    MissingEntry,
    MissingExit,
    CollectorRestart,
}

impl ObservationGapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingEntry => "missing_entry",
            Self::MissingExit => "missing_exit",
            Self::CollectorRestart => "collector_restart",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationGap {
    pub schema_version: u32,
    pub timestamp_unix_ms: u128,
    pub agent_run_id: String,
    pub operation: String,
    pub kind: ObservationGapKind,
    pub count: u64,
    pub detail: String,
}

impl ObservationGap {
    pub fn new(
        agent_run_id: impl Into<String>,
        operation: impl Into<String>,
        kind: ObservationGapKind,
        count: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: OBSERVATION_GAP_SCHEMA_VERSION,
            timestamp_unix_ms: now_unix_ms(),
            agent_run_id: agent_run_id.into(),
            operation: operation.into(),
            kind,
            count,
            detail: detail.into(),
        }
    }

    pub fn with_timestamp(mut self, timestamp_unix_ms: u128) -> Self {
        self.timestamp_unix_ms = timestamp_unix_ms;
        self
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for ObservationGap {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":{},\"schema_version\":{},\"timestamp_unix_ms\":{},\"agent_run_id\":{},\"operation\":{},\"kind\":{},\"count\":{},\"detail\":{}}}",
            json_string(records::OBSERVATION_GAP),
            self.schema_version,
            self.timestamp_unix_ms,
            json_string(&self.agent_run_id),
            json_string(&self.operation),
            json_string(self.kind.as_str()),
            self.count,
            json_string(&self.detail),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationOutcome {
    Attempted,
    Succeeded,
    Failed,
    Denied,
    Pending,
    Unknown,
}

impl OperationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Pending => "pending",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationResult {
    pub outcome: OperationOutcome,
    pub return_value: i64,
    pub errno: Option<i32>,
}

impl OperationResult {
    pub fn new(outcome: OperationOutcome, return_value: i64, errno: Option<i32>) -> Self {
        Self {
            outcome,
            return_value,
            errno,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorCapability {
    pub operation: String,
    pub event_sources: Vec<String>,
    pub outcomes: Vec<OperationOutcome>,
}

impl CollectorCapability {
    pub fn new<I, S>(
        operation: impl Into<String>,
        event_sources: I,
        outcomes: Vec<OperationOutcome>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            operation: operation.into(),
            event_sources: event_sources.into_iter().map(Into::into).collect(),
            outcomes,
        }
    }

    fn to_json_object(&self) -> String {
        let event_sources = json_array(self.event_sources.iter().map(|value| json_string(value)));
        let outcomes = json_array(
            self.outcomes
                .iter()
                .map(|outcome| json_string(outcome.as_str())),
        );
        format!(
            "{{\"operation\":{},\"event_sources\":{event_sources},\"outcomes\":{outcomes}}}",
            json_string(&self.operation)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectorCapabilityManifest {
    pub schema_version: u32,
    pub timestamp_unix_ms: u128,
    pub agent_run_id: String,
    pub collector: String,
    pub collector_version: String,
    pub kernel_abi_version: u32,
    pub kernel_record_size: u32,
    pub observation_scope: String,
    pub privacy_profile: String,
    pub capabilities: Vec<CollectorCapability>,
}

impl CollectorCapabilityManifest {
    pub fn new(
        agent_run_id: impl Into<String>,
        collector_version: impl Into<String>,
        kernel_abi_version: u32,
        kernel_record_size: u32,
        observation_scope: impl Into<String>,
        capabilities: Vec<CollectorCapability>,
    ) -> Self {
        Self {
            schema_version: COLLECTOR_CAPABILITY_SCHEMA_VERSION,
            timestamp_unix_ms: now_unix_ms(),
            agent_run_id: agent_run_id.into(),
            collector: "apolysis_observer".to_string(),
            collector_version: collector_version.into(),
            kernel_abi_version,
            kernel_record_size,
            observation_scope: observation_scope.into(),
            privacy_profile: "content_off".to_string(),
            capabilities,
        }
    }

    pub fn with_timestamp(mut self, timestamp_unix_ms: u128) -> Self {
        self.timestamp_unix_ms = timestamp_unix_ms;
        self
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for CollectorCapabilityManifest {
    fn to_json_line(&self) -> String {
        let capabilities = json_array(
            self.capabilities
                .iter()
                .map(CollectorCapability::to_json_object),
        );
        format!(
            "{{\"record_type\":{},\"schema_version\":{},\"timestamp_unix_ms\":{},\"agent_run_id\":{},\"collector\":{},\"collector_version\":{},\"kernel_abi_version\":{},\"kernel_record_size\":{},\"observation_scope\":{},\"privacy_profile\":{},\"capabilities\":{capabilities}}}",
            json_string(records::COLLECTOR_CAPABILITY_MANIFEST),
            self.schema_version,
            self.timestamp_unix_ms,
            json_string(&self.agent_run_id),
            json_string(&self.collector),
            json_string(&self.collector_version),
            self.kernel_abi_version,
            self.kernel_record_size,
            json_string(&self.observation_scope),
            json_string(&self.privacy_profile),
        )
    }
}

fn json_array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventSource {
    Manual,
    ProcessTree,
    KernelTracepoint,
    Uprobe,
    RuntimeMetadata,
}

impl EventSource {
    /// Return the stable schema string for this event source.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::ProcessTree => "process_tree",
            Self::KernelTracepoint => "kernel_tracepoint",
            Self::Uprobe => "uprobe",
            Self::RuntimeMetadata => "runtime_metadata",
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
pub struct CanonicalEvent {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub event_source: EventSource,
    pub event_type: EventType,
    pub raw_event_id: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    pub actor: String,
    pub resource: String,
    pub action: String,
    pub operation_result: Option<OperationResult>,
    pub container_id: Option<String>,
    pub cgroup_id: Option<String>,
    pub host_boot_id: Option<String>,
    pub scope_generation: Option<u64>,
    pub process_generation: Option<u64>,
    pub process_start_time_ns: Option<u64>,
    pub exec_generation: Option<u32>,
    pub parent_process_generation: Option<u64>,
    pub parent_exec_generation: Option<u32>,
    pub relation_status: RuntimeRelation,
    pub relation_reason: String,
    pub process_command: Option<String>,
    pub process_executable: Option<String>,
    pub process_started_at_unix_ms: Option<u128>,
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
            raw_event_id: None,
            pid,
            ppid,
            actor: actor.into(),
            resource: resource.into(),
            action: action.into(),
            operation_result: None,
            container_id: None,
            cgroup_id: None,
            host_boot_id: None,
            scope_generation: None,
            process_generation: None,
            process_start_time_ns: None,
            exec_generation: None,
            parent_process_generation: None,
            parent_exec_generation: None,
            relation_status: RuntimeRelation::Inferred,
            relation_reason: "pid_only_runtime_identity".to_string(),
            process_command: None,
            process_executable: None,
            process_started_at_unix_ms: None,
        }
    }

    /// Override the event timestamp, primarily for replayed kernel fixtures.
    pub fn with_timestamp(mut self, timestamp_unix_ms: u128) -> Self {
        self.timestamp_unix_ms = timestamp_unix_ms;
        self
    }

    /// Link this canonical record to the raw kernel event that produced it.
    pub fn with_raw_event_id(mut self, raw_event_id: impl Into<String>) -> Self {
        self.raw_event_id = Some(raw_event_id.into());
        self
    }

    /// Attach an outcome supported by the active Collector Capability.
    pub fn with_operation_result(mut self, operation_result: OperationResult) -> Self {
        self.operation_result = Some(operation_result);
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

    /// Copy the process and scope generations assigned to the source observation.
    pub fn with_process_identity_from(mut self, raw: &RawKernelEvent) -> Self {
        self.host_boot_id = raw.host_boot_id.clone();
        self.scope_generation = raw.scope_generation;
        self.process_generation = raw.process_generation;
        self.process_start_time_ns = raw.process_start_time_ns;
        self.exec_generation = raw.exec_generation;
        self.parent_process_generation = raw.parent_process_generation;
        self.parent_exec_generation = raw.parent_exec_generation;
        self.relation_status = raw.relation_status;
        self.relation_reason = raw.relation_reason.clone();
        self
    }

    /// Attach userspace command context known for this process at observation time.
    pub fn with_process_context(
        mut self,
        command: impl Into<String>,
        executable: impl Into<String>,
        started_at_unix_ms: u128,
    ) -> Self {
        self.process_command = Some(command.into());
        self.process_executable = Some(executable.into());
        self.process_started_at_unix_ms = Some(started_at_unix_ms);
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
        let outcome = self
            .operation_result
            .map(|result| json_string(result.outcome.as_str()))
            .unwrap_or_else(|| "null".to_string());
        let return_value = self
            .operation_result
            .map(|result| result.return_value.to_string())
            .unwrap_or_else(|| "null".to_string());
        let errno = self
            .operation_result
            .and_then(|result| result.errno)
            .map(|errno| errno.to_string())
            .unwrap_or_else(|| "null".to_string());

        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"event_source\":{},\"event_type\":{},\"raw_event_id\":{},\"pid\":{},\"ppid\":{},\"actor\":{},\"resource\":{},\"action\":{},\"outcome\":{outcome},\"return_value\":{return_value},\"errno\":{errno},\"container_id\":{},\"cgroup_id\":{},\"host_boot_id\":{},\"scope_generation\":{},\"process_generation\":{},\"process_start_time_ns\":{},\"exec_generation\":{},\"parent_process_generation\":{},\"parent_exec_generation\":{},\"relation_status\":{},\"relation_reason\":{},\"process_command\":{},\"process_executable\":{},\"process_started_at_unix_ms\":{}}}",
            json_string(records::EVENT),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(self.event_source.as_str()),
            json_string(self.event_type.as_str()),
            optional_json_string(self.raw_event_id.as_deref()),
            self.pid,
            self.ppid,
            json_string(&self.actor),
            json_string(&self.resource),
            json_string(&self.action),
            container_id,
            cgroup_id,
            optional_json_string(self.host_boot_id.as_deref()),
            optional_json_u64(self.scope_generation),
            optional_json_u64(self.process_generation),
            optional_json_u64(self.process_start_time_ns),
            optional_json_u32(self.exec_generation),
            optional_json_u64(self.parent_process_generation),
            optional_json_u32(self.parent_exec_generation),
            json_string(self.relation_status.as_str()),
            json_string(&self.relation_reason),
            optional_json_string(self.process_command.as_deref()),
            optional_json_string(self.process_executable.as_deref()),
            self.process_started_at_unix_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_string())
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawKernelEvent {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub event_source: EventSource,
    pub event_name: String,
    pub event_id: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub resource: String,
    pub action: String,
    pub operation_result: Option<OperationResult>,
    pub container_id: Option<String>,
    pub cgroup_id: Option<String>,
    pub host_boot_id: Option<String>,
    pub scope_generation: Option<u64>,
    pub process_generation: Option<u64>,
    pub process_start_time_ns: Option<u64>,
    pub exec_generation: Option<u32>,
    pub parent_process_generation: Option<u64>,
    pub parent_exec_generation: Option<u32>,
    pub relation_status: RuntimeRelation,
    pub relation_reason: String,
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
            event_id: None,
            pid,
            ppid,
            uid,
            gid,
            comm: comm.into(),
            resource: resource.into(),
            action: action.into(),
            operation_result: None,
            container_id,
            cgroup_id,
            host_boot_id: None,
            scope_generation: None,
            process_generation: None,
            process_start_time_ns: None,
            exec_generation: None,
            parent_process_generation: None,
            parent_exec_generation: None,
            relation_status: RuntimeRelation::Inferred,
            relation_reason: "pid_only_runtime_identity".to_string(),
            raw_payload: raw_payload.into(),
        }
    }

    /// Attach a stable event identifier for joining raw and derived records.
    pub fn with_event_id(mut self, event_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self
    }

    /// Attach an outcome supported by the active Collector Capability.
    pub fn with_operation_result(mut self, operation_result: OperationResult) -> Self {
        self.operation_result = Some(operation_result);
        self
    }

    /// Attach the bounded kernel/runtime generations used for exact attribution.
    #[allow(clippy::too_many_arguments)]
    pub fn with_process_identity(
        mut self,
        host_boot_id: Option<String>,
        scope_generation: Option<u64>,
        process_generation: Option<u64>,
        process_start_time_ns: Option<u64>,
        exec_generation: Option<u32>,
        parent_process_generation: Option<u64>,
        parent_exec_generation: Option<u32>,
    ) -> Self {
        self.host_boot_id = host_boot_id.filter(|value| !value.trim().is_empty());
        self.scope_generation = scope_generation.filter(|value| *value != 0);
        self.process_generation = process_generation.filter(|value| *value != 0);
        self.process_start_time_ns = process_start_time_ns.filter(|value| *value != 0);
        self.exec_generation = exec_generation;
        self.parent_process_generation = parent_process_generation.filter(|value| *value != 0);
        self.parent_exec_generation = parent_exec_generation;
        if self.host_boot_id.is_some()
            && self.scope_generation.is_some()
            && self.process_generation.is_some()
            && self.process_start_time_ns.is_some()
            && self.exec_generation.is_some()
        {
            self.relation_status = RuntimeRelation::Exact;
            self.relation_reason = "host_boot_scope_process_start_exec_generation".to_string();
        } else {
            self.relation_status = RuntimeRelation::Inferred;
            self.relation_reason = "runtime_generation_unavailable".to_string();
        }
        self
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
        let outcome = self
            .operation_result
            .map(|result| json_string(result.outcome.as_str()))
            .unwrap_or_else(|| "null".to_string());
        let return_value = self
            .operation_result
            .map(|result| result.return_value.to_string())
            .unwrap_or_else(|| "null".to_string());
        let errno = self
            .operation_result
            .and_then(|result| result.errno)
            .map(|errno| errno.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"event_source\":{},\"event_name\":{},\"event_id\":{},\"pid\":{},\"ppid\":{},\"uid\":{},\"gid\":{},\"comm\":{},\"resource\":{},\"action\":{},\"outcome\":{outcome},\"return_value\":{return_value},\"errno\":{errno},\"container_id\":{},\"cgroup_id\":{},\"host_boot_id\":{},\"scope_generation\":{},\"process_generation\":{},\"process_start_time_ns\":{},\"exec_generation\":{},\"parent_process_generation\":{},\"parent_exec_generation\":{},\"relation_status\":{},\"relation_reason\":{},\"raw_payload\":{}}}",
            json_string(records::RAW_KERNEL_EVENT),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(self.event_source.as_str()),
            json_string(&self.event_name),
            optional_json_string(self.event_id.as_deref()),
            self.pid,
            self.ppid,
            self.uid,
            self.gid,
            json_string(&self.comm),
            json_string(&self.resource),
            json_string(&self.action),
            container_id,
            cgroup_id,
            optional_json_string(self.host_boot_id.as_deref()),
            optional_json_u64(self.scope_generation),
            optional_json_u64(self.process_generation),
            optional_json_u64(self.process_start_time_ns),
            optional_json_u32(self.exec_generation),
            optional_json_u64(self.parent_process_generation),
            optional_json_u32(self.parent_exec_generation),
            json_string(self.relation_status.as_str()),
            json_string(&self.relation_reason),
            json_string(&self.raw_payload)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIntentRecord {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub intent_source: String,
    pub intent_id: String,
    pub source_event_id: Option<String>,
    pub intent_type: String,
    pub tool_name: String,
    pub declared_action: Option<String>,
    pub target: Option<String>,
    pub command: Option<String>,
    pub raw_event_id: Option<String>,
}

impl SessionIntentRecord {
    /// Create an append-only record for declared harness intent.
    pub fn new(
        session_id: impl Into<String>,
        intent_source: impl Into<String>,
        intent_id: impl Into<String>,
        intent_type: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            session_id: session_id.into(),
            intent_source: intent_source.into(),
            intent_id: intent_id.into(),
            source_event_id: None,
            intent_type: intent_type.into(),
            tool_name: tool_name.into(),
            declared_action: None,
            target: None,
            command: None,
            raw_event_id: None,
        }
    }

    pub fn with_timestamp(mut self, timestamp_unix_ms: u128) -> Self {
        self.timestamp_unix_ms = timestamp_unix_ms;
        self
    }

    pub fn with_source_event_id(mut self, source_event_id: impl Into<String>) -> Self {
        self.source_event_id = Some(source_event_id.into());
        self
    }

    pub fn with_declared_action(mut self, declared_action: impl Into<String>) -> Self {
        self.declared_action = Some(declared_action.into());
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    pub fn with_raw_event_id(mut self, raw_event_id: impl Into<String>) -> Self {
        self.raw_event_id = Some(raw_event_id.into());
        self
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for SessionIntentRecord {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"intent_source\":{},\"intent_id\":{},\"source_event_id\":{},\"intent_type\":{},\"tool_name\":{},\"declared_action\":{},\"target\":{},\"command\":{},\"raw_event_id\":{}}}",
            json_string(records::INTENT),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(&self.intent_source),
            json_string(&self.intent_id),
            optional_json_string(self.source_event_id.as_deref()),
            json_string(&self.intent_type),
            json_string(&self.tool_name),
            optional_json_string(self.declared_action.as_deref()),
            optional_json_string(self.target.as_deref()),
            optional_json_string(self.command.as_deref()),
            optional_json_string(self.raw_event_id.as_deref()),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserverDiagnosticKind {
    AbiMismatch,
    RingBufferReserveFailure,
    MapPressure,
    DecodeFailure,
    Truncation,
    AttachFailure,
    VerifierFailure,
    Summary,
}

impl ObserverDiagnosticKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AbiMismatch => "abi_mismatch",
            Self::RingBufferReserveFailure => "ring_buffer_reserve_failure",
            Self::MapPressure => "map_pressure",
            Self::DecodeFailure => "decode_failure",
            Self::Truncation => "truncation",
            Self::AttachFailure => "attach_failure",
            Self::VerifierFailure => "verifier_failure",
            Self::Summary => "summary",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverDiagnostic {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub kind: ObserverDiagnosticKind,
    pub count: u64,
    pub detail: String,
}

impl ObserverDiagnostic {
    pub fn new(
        session_id: impl Into<String>,
        kind: ObserverDiagnosticKind,
        count: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            session_id: session_id.into(),
            kind,
            count,
            detail: detail.into(),
        }
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

impl JsonLine for ObserverDiagnostic {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"kind\":{},\"count\":{},\"detail\":{}}}",
            json_string(records::OBSERVER_DIAGNOSTIC),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(self.kind.as_str()),
            self.count,
            json_string(&self.detail)
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

fn optional_json_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn optional_json_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn optional_json_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Return the current Unix timestamp in milliseconds.
pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

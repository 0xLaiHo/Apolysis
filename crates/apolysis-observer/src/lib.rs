// SPDX-License-Identifier: Apache-2.0

//! Observer pipeline for kernel-derived events.
//!
//! Raw ring-buffer records are normalized into canonical runtime observations,
//! redacted at the persistence seam, and written into the bounded JSONL
//! timeline. The observer reports what happened and where collection degraded;
//! it does not make or execute policy decisions.

pub mod abi;
pub mod capabilities;
mod live;
mod process_context;
mod redaction;
mod scope;

pub use live::{
    discover_agent_registration, discover_process_tree_scope_pids, enable_multi_cgroup_scope,
    file_operation_observation_gaps, network_connect_observation_gaps, observe_live,
    raw_event_from_record, scope_observation_gaps, update_tracked_cgroup, AgentDiscoveryRequest,
    AgentRegistration, AgentRunRequest, DaemonKernelEvent, DaemonObserver, DaemonObserverBatch,
    DaemonObserverConfig, DaemonObserverCounters, FileOperationCounters, LiveObserveRequest,
    LiveScope, NetworkConnectCounters, ObserverBatchDecoder, OperationPairCounters,
    ScopeObservationGapCounters,
};
pub use redaction::{
    redact_command_text_for_persistence, RedactedValue, Redactor, RuntimeEvidencePersistence,
};
pub use scope::{ScopeSet, ScopeSetError, MAX_TRACKED_CGROUPS};

use std::fs;
use std::path::{Path, PathBuf};

use apolysis_core::{
    actors, fields::PipeFields, resources, CanonicalEvent, CollectorCapability,
    CollectorCapabilityManifest, EventSource, EventType, OperationOutcome, RawKernelEvent,
};
use apolysis_kubernetes::KubernetesMetadata;
use apolysis_store::{JsonlRotationPolicy, JsonlStore};

use crate::process_context::ProcessContextTable;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureObserveRequest {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub session_id: String,
    pub kubernetes_metadata_path: Option<PathBuf>,
    pub output_rotation: Option<JsonlRotationPolicy>,
}

impl FixtureObserveRequest {
    /// Create a fixture observer request with optional integrations disabled.
    pub fn new(
        input_path: impl Into<PathBuf>,
        output_path: impl Into<PathBuf>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            input_path: input_path.into(),
            output_path: output_path.into(),
            session_id: session_id.into(),
            kubernetes_metadata_path: None,
            output_rotation: None,
        }
    }

    /// Attach optional Kubernetes metadata that should be mirrored into the timeline.
    pub fn with_kubernetes_metadata_path(mut self, path: Option<impl Into<PathBuf>>) -> Self {
        self.kubernetes_metadata_path = path.map(Into::into);
        self
    }

    /// Attach an optional output rotation policy for bounded local timelines.
    pub fn with_output_rotation(mut self, rotation: Option<JsonlRotationPolicy>) -> Self {
        self.output_rotation = rotation;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveResult {
    pub raw_events: usize,
    pub canonical_events: usize,
    pub backend: ObserverBackend,
    pub mode: ObserverMode,
    pub agent_exit_code: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserverBackend {
    FixtureRingBuffer,
    AyaRingBuffer,
}

impl ObserverBackend {
    /// Return the stable backend string emitted to timeline metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FixtureRingBuffer => "fixture_ring_buffer",
            Self::AyaRingBuffer => "aya_ring_buffer",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserverMode {
    AuditOnly,
}

impl ObserverMode {
    /// Return the stable observer mode string emitted to timeline metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuditOnly => "audit-only",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverRunnerPlan {
    pub process: bool,
    pub system: bool,
    pub stdio: bool,
    pub ssl_http_uprobe: bool,
}

impl ObserverRunnerPlan {
    /// Return the HostObserver default host observer runner plan.
    pub fn host_observer_default() -> Self {
        Self {
            process: true,
            system: true,
            stdio: false,
            ssl_http_uprobe: false,
        }
    }

    /// Summarize enabled and disabled runners for timeline metadata.
    pub fn summary(&self) -> String {
        format!(
            "process:{},system:{},stdio:{},ssl-http-uprobe:{}",
            enabled(self.process),
            enabled(self.system),
            enabled(self.stdio),
            enabled(self.ssl_http_uprobe)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaLoaderPlan {
    pub object_path: PathBuf,
    pub ring_buffer_map: String,
    pub tracepoints: Vec<TracepointAttach>,
}

impl AyaLoaderPlan {
    /// Return the initial Aya loader plan and tracepoint attachment set.
    pub fn host_observer_default(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
            ring_buffer_map: "APOLYSIS_EVENTS".to_string(),
            tracepoints: vec![
                TracepointAttach::new("sched", "sched_process_exec"),
                TracepointAttach::new("sched", "sched_process_exit"),
                TracepointAttach::new("syscalls", "sys_enter_execve"),
                TracepointAttach::new("syscalls", "sys_enter_execveat"),
                TracepointAttach::new("syscalls", "sys_enter_openat"),
                TracepointAttach::new("syscalls", "sys_exit_openat"),
                TracepointAttach::new("syscalls", "sys_enter_openat2"),
                TracepointAttach::new("syscalls", "sys_exit_openat2"),
                TracepointAttach::new("syscalls", "sys_enter_creat"),
                TracepointAttach::new("syscalls", "sys_exit_creat"),
                TracepointAttach::new("syscalls", "sys_enter_truncate"),
                TracepointAttach::new("syscalls", "sys_exit_truncate"),
                TracepointAttach::new("syscalls", "sys_enter_unlinkat"),
                TracepointAttach::new("syscalls", "sys_exit_unlinkat"),
                TracepointAttach::new("syscalls", "sys_enter_renameat2"),
                TracepointAttach::new("syscalls", "sys_exit_renameat2"),
                TracepointAttach::new("syscalls", "sys_enter_connect"),
                TracepointAttach::new("syscalls", "sys_exit_connect"),
            ],
        }
    }

    /// Return the AuditObserver live observer attachment set.
    pub fn audit_observer_default(object_path: impl Into<PathBuf>) -> Self {
        let mut plan = Self::host_observer_default(object_path);
        plan.tracepoints
            .insert(1, TracepointAttach::new("sched", "sched_process_fork"));
        plan
    }
}

type TracepointId = (&'static str, &'static str);

struct CapabilityDeclaration {
    operation: &'static str,
    sources: &'static [TracepointId],
    required_sources: &'static [TracepointId],
    outcomes: &'static [OperationOutcome],
}

const FILE_OPERATION_OUTCOMES: &[OperationOutcome] = &[
    OperationOutcome::Succeeded,
    OperationOutcome::Failed,
    OperationOutcome::Denied,
];
const FILE_OPEN_SOURCES: &[TracepointId] = &[
    ("syscalls", "sys_enter_openat"),
    ("syscalls", "sys_exit_openat"),
    ("syscalls", "sys_enter_openat2"),
    ("syscalls", "sys_exit_openat2"),
];
const FILE_CREATE_SOURCES: &[TracepointId] = &[
    ("syscalls", "sys_enter_openat"),
    ("syscalls", "sys_exit_openat"),
    ("syscalls", "sys_enter_openat2"),
    ("syscalls", "sys_exit_openat2"),
    ("syscalls", "sys_enter_creat"),
    ("syscalls", "sys_exit_creat"),
];
const FILE_TRUNCATE_SOURCES: &[TracepointId] = &[
    ("syscalls", "sys_enter_openat"),
    ("syscalls", "sys_exit_openat"),
    ("syscalls", "sys_enter_openat2"),
    ("syscalls", "sys_exit_openat2"),
    ("syscalls", "sys_enter_truncate"),
    ("syscalls", "sys_exit_truncate"),
];
const FILE_UNLINK_SOURCES: &[TracepointId] = &[
    ("syscalls", "sys_enter_unlinkat"),
    ("syscalls", "sys_exit_unlinkat"),
];
const FILE_RENAME_SOURCES: &[TracepointId] = &[
    ("syscalls", "sys_enter_renameat2"),
    ("syscalls", "sys_exit_renameat2"),
];

const AUDIT_OBSERVER_CAPABILITIES: &[CapabilityDeclaration] = &[
    CapabilityDeclaration {
        operation: "process_fork",
        sources: &[("sched", "sched_process_fork")],
        required_sources: &[],
        outcomes: &[OperationOutcome::Succeeded],
    },
    CapabilityDeclaration {
        operation: "process_exec",
        sources: &[
            ("sched", "sched_process_exec"),
            ("syscalls", "sys_enter_execve"),
            ("syscalls", "sys_enter_execveat"),
        ],
        required_sources: &[("sched", "sched_process_exec")],
        outcomes: &[OperationOutcome::Succeeded],
    },
    CapabilityDeclaration {
        operation: "process_exit",
        sources: &[("sched", "sched_process_exit")],
        required_sources: &[],
        outcomes: &[OperationOutcome::Unknown],
    },
    CapabilityDeclaration {
        operation: "file_open",
        sources: FILE_OPEN_SOURCES,
        required_sources: FILE_OPEN_SOURCES,
        outcomes: FILE_OPERATION_OUTCOMES,
    },
    CapabilityDeclaration {
        operation: "file_create",
        sources: FILE_CREATE_SOURCES,
        required_sources: FILE_CREATE_SOURCES,
        outcomes: FILE_OPERATION_OUTCOMES,
    },
    CapabilityDeclaration {
        operation: "file_truncate",
        sources: FILE_TRUNCATE_SOURCES,
        required_sources: FILE_TRUNCATE_SOURCES,
        outcomes: FILE_OPERATION_OUTCOMES,
    },
    CapabilityDeclaration {
        operation: "file_unlink",
        sources: FILE_UNLINK_SOURCES,
        required_sources: FILE_UNLINK_SOURCES,
        outcomes: FILE_OPERATION_OUTCOMES,
    },
    CapabilityDeclaration {
        operation: "file_rename",
        sources: FILE_RENAME_SOURCES,
        required_sources: FILE_RENAME_SOURCES,
        outcomes: FILE_OPERATION_OUTCOMES,
    },
    CapabilityDeclaration {
        operation: "network_connect",
        sources: &[
            ("syscalls", "sys_enter_connect"),
            ("syscalls", "sys_exit_connect"),
        ],
        required_sources: &[
            ("syscalls", "sys_enter_connect"),
            ("syscalls", "sys_exit_connect"),
        ],
        outcomes: &[
            OperationOutcome::Succeeded,
            OperationOutcome::Failed,
            OperationOutcome::Denied,
            OperationOutcome::Pending,
        ],
    },
    CapabilityDeclaration {
        operation: "credential_path_access",
        sources: FILE_OPEN_SOURCES,
        required_sources: FILE_OPEN_SOURCES,
        outcomes: FILE_OPERATION_OUTCOMES,
    },
];

/// Describe exactly what the configured AuditObserver can report for one Agent Run.
pub fn audit_observer_capability_manifest(
    agent_run_id: &str,
    scope: &LiveScope,
    loader_plan: &AyaLoaderPlan,
) -> CollectorCapabilityManifest {
    let capabilities = AUDIT_OBSERVER_CAPABILITIES
        .iter()
        .filter_map(|declaration| {
            let is_attached = |category: &str, name: &str| {
                loader_plan
                    .tracepoints
                    .iter()
                    .any(|attach| attach.category == category && attach.name == name)
            };
            if declaration
                .required_sources
                .iter()
                .any(|(category, name)| !is_attached(category, name))
            {
                return None;
            }
            let event_sources = declaration
                .sources
                .iter()
                .filter(|(category, name)| is_attached(category, name))
                .map(|(category, name)| format!("{category}/{name}"))
                .collect::<Vec<_>>();
            if event_sources.is_empty() {
                None
            } else {
                Some(CollectorCapability::new(
                    declaration.operation,
                    event_sources,
                    declaration.outcomes.to_vec(),
                ))
            }
        })
        .collect();
    let observation_scope = match scope {
        LiveScope::Cgroup(_) => "cgroup",
        LiveScope::ProcessTree(_) => "process_tree",
    };
    CollectorCapabilityManifest::new(
        agent_run_id,
        env!("CARGO_PKG_VERSION"),
        abi::KERNEL_ABI_VERSION,
        abi::KERNEL_EVENT_RECORD_LEN as u32,
        observation_scope,
        capabilities,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracepointAttach {
    pub category: String,
    pub name: String,
}

impl TracepointAttach {
    /// Create one tracepoint attachment descriptor.
    pub fn new(category: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
        }
    }

    pub fn program_name(&self) -> String {
        format!("apolysis_{}", self.name)
    }
}

pub(crate) struct EventIdSequence {
    session_id: String,
    next: u64,
}

impl EventIdSequence {
    pub(crate) fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            next: 1,
        }
    }

    pub(crate) fn next_raw_event_id(&mut self) -> String {
        let event_id = format!("{}:event:{:016x}", self.session_id, self.next);
        self.next += 1;
        event_id
    }
}

/// Replay a raw observer fixture into raw and canonical timeline records.
pub fn observe_fixture(request: FixtureObserveRequest) -> Result<ObserveResult, String> {
    let mut store =
        JsonlStore::create_with_rotation_policy(&request.output_path, request.output_rotation)
            .map_err(|error| format!("failed to create observer timeline: {error}"))?;
    let runner_plan = ObserverRunnerPlan::host_observer_default();

    write_observer_metadata(
        &request.session_id,
        &runner_plan,
        ObserverBackend::FixtureRingBuffer,
        request.output_rotation,
        &mut store,
    )?;
    write_kubernetes_metadata(
        &request.session_id,
        request.kubernetes_metadata_path.as_deref(),
        &mut store,
    )?;

    let input = fs::read_to_string(&request.input_path)
        .map_err(|error| format!("failed to read observer fixture: {error}"))?;
    let mut raw_count = 0;
    let mut canonical_count = 0;
    let mut event_ids = EventIdSequence::new(&request.session_id);
    let mut process_context = ProcessContextTable::default();
    let workspace_root = std::env::current_dir()
        .map_err(|error| format!("failed to resolve fixture workspace root: {error}"))?;
    let redactor = Redactor::new(&request.session_id, workspace_root);

    for raw_line in input.lines() {
        let raw_line = raw_line.trim();
        if raw_line.is_empty() || raw_line.starts_with('#') {
            continue;
        }

        let raw = parse_fixture_raw_event(raw_line, &request.session_id)?
            .with_event_id(event_ids.next_raw_event_id());
        let canonical = process_context.observe(&raw, canonicalize(&raw));
        let (persisted_raw, persisted_canonical) = RuntimeEvidencePersistence::new(&redactor)
            .persist_event(
                &raw,
                &canonical,
                canonical.event_type == EventType::CredentialRead,
            );
        store
            .append(&persisted_raw)
            .map_err(|error| format!("failed to write raw kernel event: {error}"))?;
        raw_count += 1;
        store
            .append(&persisted_canonical)
            .map_err(|error| format!("failed to write canonical event: {error}"))?;
        canonical_count += 1;
    }

    store
        .flush()
        .map_err(|error| format!("failed to flush observer timeline: {error}"))?;

    Ok(ObserveResult {
        raw_events: raw_count,
        canonical_events: canonical_count,
        backend: ObserverBackend::FixtureRingBuffer,
        mode: ObserverMode::AuditOnly,
        agent_exit_code: None,
    })
}

fn write_kubernetes_metadata(
    session_id: &str,
    metadata_path: Option<&Path>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let Some(metadata_path) = metadata_path else {
        return Ok(());
    };

    let input = fs::read_to_string(metadata_path)
        .map_err(|error| format!("failed to read kubernetes metadata: {error}"))?;
    let metadata = KubernetesMetadata::parse(&input)?;
    for event in metadata.to_timeline_events(session_id) {
        store
            .append(&event)
            .map_err(|error| format!("failed to write kubernetes metadata: {error}"))?;
    }

    Ok(())
}

fn write_observer_metadata(
    session_id: &str,
    runner_plan: &ObserverRunnerPlan,
    backend: ObserverBackend,
    output_rotation: Option<JsonlRotationPolicy>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let mut metadata = vec![
        (
            resources::OBSERVER_MODE,
            ObserverMode::AuditOnly.as_str().to_string(),
        ),
        (resources::OBSERVER_BACKEND, backend.as_str().to_string()),
        (resources::OBSERVER_RUNNERS, runner_plan.summary()),
    ];
    if let Some(rotation) = output_rotation {
        metadata.push((
            resources::OBSERVER_OUTPUT_ROTATION,
            format!(
                "max_file_bytes:{},max_archived_files:{}",
                rotation.max_file_bytes, rotation.max_archived_files
            ),
        ));
    }

    for (resource, action) in metadata {
        let event = CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            actors::OBSERVER,
            resource,
            action,
        );
        store
            .append(&event)
            .map_err(|error| format!("failed to write observer metadata: {error}"))?;
    }

    Ok(())
}

fn canonicalize(raw: &RawKernelEvent) -> CanonicalEvent {
    let event_type = match raw.event_name.as_str() {
        "exec" | "execve" | "sched_process_exec" => EventType::Exec,
        "open" | "openat" | "openat2" => {
            if is_credential_path(&raw.resource) {
                EventType::CredentialRead
            } else {
                EventType::FileOpen
            }
        }
        "creat" => EventType::FileCreate,
        "truncate" | "ftruncate" => EventType::FileTruncate,
        "unlink" | "unlinkat" => EventType::FileUnlink,
        "rename" | "renameat" | "renameat2" => EventType::FileRename,
        "connect" => EventType::NetworkConnect,
        "sched_process_exit" | "process_exit" => EventType::ProcessExit,
        _ => EventType::RuntimeMetadata,
    };

    let mut event = CanonicalEvent::new(
        &raw.session_id,
        EventSource::KernelTracepoint,
        event_type,
        raw.pid,
        raw.ppid,
        &raw.comm,
        &raw.resource,
        &raw.action,
    )
    .with_timestamp(raw.timestamp_unix_ms)
    .with_runtime_identity(raw.container_id.clone(), raw.cgroup_id.clone());
    if let Some(raw_event_id) = raw.event_id.as_deref() {
        event = event.with_raw_event_id(raw_event_id);
    }
    if let Some(operation_result) = raw.operation_result {
        event = event.with_operation_result(operation_result);
    }
    event
}

/// Return whether a path belongs to the observer's built-in credential classes.
pub fn is_credential_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized == ".env"
        || normalized.ends_with("/.env")
        || normalized.contains("/.env.")
        || normalized.ends_with("/.ssh")
        || normalized.contains("/.ssh/")
        || normalized.ends_with("/.aws")
        || normalized.contains("/.aws/")
        || normalized == "/var/run/secrets"
        || normalized.starts_with("/var/run/secrets/")
}

fn parse_fixture_raw_event(line: &str, session_id: &str) -> Result<RawKernelEvent, String> {
    let fields =
        PipeFields::parse(line).map_err(|error| error.replace("pipe field", "raw event field"))?;
    let timestamp = parse_raw_u128(&fields, "timestamp")?;
    let pid = parse_raw_u32(&fields, "pid")?;
    let ppid = parse_raw_u32(&fields, "ppid")?;
    let uid = parse_raw_u32(&fields, "uid")?;
    let gid = parse_raw_u32(&fields, "gid")?;
    let comm = required_raw(&fields, "comm")?;
    let event_name = required_raw(&fields, "event")?;
    let resource = required_raw(&fields, "resource")?;
    let action = required_raw(&fields, "action")?;
    let container_id = fields.optional("container_id").map(ToString::to_string);
    let cgroup_id = fields.optional("cgroup_id").map(ToString::to_string);
    let raw_payload = fields.optional("payload").unwrap_or_default();

    Ok(RawKernelEvent::new(
        timestamp,
        session_id,
        EventSource::KernelTracepoint,
        event_name,
        pid,
        ppid,
        uid,
        gid,
        comm,
        resource,
        action,
        container_id,
        cgroup_id,
        raw_payload,
    ))
}

fn required_raw<'a>(fields: &'a PipeFields, key: &str) -> Result<&'a str, String> {
    fields
        .required(key)
        .map_err(|_| format!("missing raw event field: {key}"))
}

fn parse_raw_u32(fields: &PipeFields, key: &str) -> Result<u32, String> {
    required_raw(fields, key)?
        .parse()
        .map_err(|error| format!("invalid {key}: {error}"))
}

fn parse_raw_u128(fields: &PipeFields, key: &str) -> Result<u128, String> {
    required_raw(fields, key)?
        .parse()
        .map_err(|error| format!("invalid {key}: {error}"))
}

fn enabled(value: bool) -> &'static str {
    if value {
        "enabled"
    } else {
        "disabled"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_observer_default_aya_loader_plan_names_tracepoints_and_ring_buffer() {
        let plan = AyaLoaderPlan::audit_observer_default("target/ebpf/apolysis_observer.bpf.o");

        assert_eq!(plan.ring_buffer_map, "APOLYSIS_EVENTS");
        assert_eq!(plan.tracepoints.len(), 19);
        assert_eq!(
            plan.tracepoints
                .iter()
                .filter(|attach| attach.name == "sched_process_exit")
                .count(),
            1
        );
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("sched", "sched_process_exec")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("sched", "sched_process_fork")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("sched", "sched_process_exit")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("syscalls", "sys_enter_connect")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("syscalls", "sys_exit_connect")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("syscalls", "sys_enter_execve")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("syscalls", "sys_enter_execveat")));
        for syscall in [
            "openat",
            "openat2",
            "creat",
            "truncate",
            "unlinkat",
            "renameat2",
        ] {
            for direction in ["enter", "exit"] {
                assert!(plan.tracepoints.contains(&TracepointAttach::new(
                    "syscalls",
                    format!("sys_{direction}_{syscall}"),
                )));
            }
        }
    }

    #[test]
    fn host_observer_default_runner_plan_keeps_optional_runners_disabled() {
        let plan = ObserverRunnerPlan::host_observer_default();

        assert_eq!(
            plan.summary(),
            "process:enabled,system:enabled,stdio:disabled,ssl-http-uprobe:disabled"
        );
    }

    #[test]
    fn live_process_exit_maps_to_the_canonical_process_exit_type() {
        let raw = RawKernelEvent::new(
            1,
            "session-live",
            EventSource::KernelTracepoint,
            "sched_process_exit",
            42,
            1,
            1000,
            1000,
            "python3",
            "",
            "exit",
            None,
            Some("77".to_string()),
            "",
        );

        let canonical = canonicalize(&raw);

        assert_eq!(canonical.event_type, EventType::ProcessExit);
    }

    #[test]
    fn credential_paths_are_classified_without_policy_actuation() {
        for path in [
            "/home/agent/.ssh/id_ed25519",
            "/home/agent/.aws/credentials",
            "/workspace/.env.local",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ] {
            assert!(is_credential_path(path), "expected credential path: {path}");
        }
        assert!(!is_credential_path("/workspace/src/main.rs"));
    }
}

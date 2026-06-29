// SPDX-License-Identifier: Apache-2.0

//! Observer pipeline for kernel-derived events.
//!
//! HostObserver established the userspace contract that a future Aya loader will feed:
//! raw ring-buffer records are preserved, analyzed into canonical events, and
//! written into the JSONL timeline. PolicyFeedback adds policy evaluation, downgrade
//! metadata, and agent-facing feedback while keeping real blocking disabled
//! until BPF-LSM support is proven at runtime.

pub mod abi;
pub mod capabilities;
mod live;
mod redaction;
mod scope;

pub use live::{
    discover_process_tree_scope_pids, enable_multi_cgroup_scope, observe_live,
    raw_event_from_record, update_tracked_cgroup, AgentRunRequest, DaemonKernelEvent,
    DaemonObserver, DaemonObserverBatch, DaemonObserverConfig, DaemonObserverCounters,
    LiveObserveRequest, LiveScope, ObserverBatchDecoder,
};
pub use redaction::{redact_raw_event_for_persistence, RedactedValue, Redactor};
pub use scope::{ScopeSet, ScopeSetError, MAX_TRACKED_CGROUPS};

use std::fs;
use std::path::{Path, PathBuf};

use apolysis_core::{
    actors, fields::PipeFields, now_unix_ms, resources, CanonicalEvent, EnforcementMetadata,
    EventSource, EventType, PolicyViolation, RawKernelEvent,
};
use apolysis_feedback::FeedbackWriter;
use apolysis_kubernetes::KubernetesMetadata;
use apolysis_policy::{DecisionDowngrade, Policy, PolicyRuntimeCapabilities};
use apolysis_store::JsonlStore;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureObserveRequest {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub policy_path: PathBuf,
    pub session_id: String,
    pub feedback_dir: Option<PathBuf>,
    pub kubernetes_metadata_path: Option<PathBuf>,
}

impl FixtureObserveRequest {
    /// Create a fixture observer request with optional integrations disabled.
    pub fn new(
        input_path: impl Into<PathBuf>,
        output_path: impl Into<PathBuf>,
        policy_path: impl Into<PathBuf>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            input_path: input_path.into(),
            output_path: output_path.into(),
            policy_path: policy_path.into(),
            session_id: session_id.into(),
            feedback_dir: None,
            kubernetes_metadata_path: None,
        }
    }

    /// Attach an optional feedback directory for agent-facing violation files.
    pub fn with_feedback_dir(mut self, feedback_dir: Option<impl Into<PathBuf>>) -> Self {
        self.feedback_dir = feedback_dir.map(Into::into);
        self
    }

    /// Attach optional Kubernetes metadata that should be mirrored into the timeline.
    pub fn with_kubernetes_metadata_path(mut self, path: Option<impl Into<PathBuf>>) -> Self {
        self.kubernetes_metadata_path = path.map(Into::into);
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
                TracepointAttach::new("syscalls", "sys_enter_openat"),
                TracepointAttach::new("syscalls", "sys_enter_openat2"),
                TracepointAttach::new("syscalls", "sys_enter_creat"),
                TracepointAttach::new("syscalls", "sys_enter_truncate"),
                TracepointAttach::new("syscalls", "sys_enter_unlinkat"),
                TracepointAttach::new("syscalls", "sys_enter_renameat2"),
                TracepointAttach::new("syscalls", "sys_enter_connect"),
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

/// Replay a raw observer fixture into raw, canonical, and policy timeline records.
pub fn observe_fixture(request: FixtureObserveRequest) -> Result<ObserveResult, String> {
    let policy = load_policy(&request.policy_path)?;
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create observer timeline: {error}"))?;
    let runner_plan = ObserverRunnerPlan::host_observer_default();
    let capabilities = PolicyRuntimeCapabilities::detect();
    let feedback = request.feedback_dir.clone().map(FeedbackWriter::new);

    write_observer_metadata(
        &request.session_id,
        &runner_plan,
        ObserverBackend::FixtureRingBuffer,
        policy.startup_downgrade(&capabilities),
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

    for raw_line in input.lines() {
        let raw_line = raw_line.trim();
        if raw_line.is_empty() || raw_line.starts_with('#') {
            continue;
        }

        let raw = parse_fixture_raw_event(raw_line, &request.session_id)?;
        store
            .append(&raw)
            .map_err(|error| format!("failed to write raw kernel event: {error}"))?;
        raw_count += 1;

        let canonical = canonicalize(&raw, &policy);
        store
            .append(&canonical)
            .map_err(|error| format!("failed to write canonical event: {error}"))?;
        append_policy_evaluation(
            &canonical,
            &policy,
            &capabilities,
            feedback.as_ref(),
            None,
            &mut store,
        )?;
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
    startup_downgrade: Option<DecisionDowngrade>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    for (resource, action) in [
        (
            resources::OBSERVER_MODE,
            ObserverMode::AuditOnly.as_str().to_string(),
        ),
        (resources::OBSERVER_BACKEND, backend.as_str().to_string()),
        (resources::OBSERVER_RUNNERS, runner_plan.summary()),
    ] {
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

    if let Some(downgrade) = startup_downgrade {
        let event = CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            actors::POLICY,
            resources::BPF_LSM,
            format!(
                "unavailable:downgrade:{}->{}",
                downgrade.from.as_str(),
                downgrade.to.as_str()
            ),
        );
        store
            .append(&event)
            .map_err(|error| format!("failed to write policy metadata: {error}"))?;
    }

    Ok(())
}

fn append_policy_evaluation(
    canonical: &CanonicalEvent,
    policy: &Policy,
    capabilities: &PolicyRuntimeCapabilities,
    feedback: Option<&FeedbackWriter>,
    persisted_target: Option<&str>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let evaluation = policy.evaluate_event(canonical, capabilities);
    if evaluation.decision.is_allow() {
        return Ok(());
    }

    let rule_id = evaluation
        .decision
        .rule_id()
        .ok_or_else(|| "policy violation missing rule id".to_string())?;
    let reason = evaluation
        .decision
        .reason()
        .ok_or_else(|| "policy violation missing reason".to_string())?;
    let violation = PolicyViolation::new(
        &canonical.session_id,
        rule_id,
        evaluation.decision.core_decision(),
        reason,
        canonical.pid,
        persisted_target.unwrap_or(&canonical.resource),
        evaluation.enforcement_backend.clone(),
    );
    store
        .append(&violation)
        .map_err(|error| format!("failed to write policy violation: {error}"))?;

    let downgrade_reason = evaluation
        .downgrade
        .as_ref()
        .map(|downgrade| downgrade.reason.clone());
    let metadata = EnforcementMetadata::new(
        &canonical.session_id,
        evaluation.requested.core_decision(),
        evaluation.effective.core_decision(),
        evaluation.enforcement_backend,
        evaluation.timing.as_str(),
        evaluation.runtime.as_str(),
        evaluation.action.as_str(),
        evaluation.preoperation_prevention,
    )
    .with_rule_id(rule_id)
    .with_downgrade_reason(downgrade_reason)
    .with_measurement(canonical.timestamp_unix_ms, now_unix_ms());
    store
        .append(&metadata)
        .map_err(|error| format!("failed to write enforcement metadata: {error}"))?;

    if let Some(writer) = feedback {
        writer.write_last_violation(&violation)?;
    }

    Ok(())
}

fn canonicalize(raw: &RawKernelEvent, policy: &Policy) -> CanonicalEvent {
    let event_type = match raw.event_name.as_str() {
        "exec" | "execve" | "sched_process_exec" => EventType::Exec,
        "open" | "openat" | "openat2" => {
            if policy.denies_credential_path(&raw.resource) {
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

    CanonicalEvent::new(
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
    .with_runtime_identity(raw.container_id.clone(), raw.cgroup_id.clone())
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

fn load_policy(path: &Path) -> Result<Policy, String> {
    let input =
        fs::read_to_string(path).map_err(|error| format!("failed to read policy: {error}"))?;
    Policy::parse(&input).map_err(|error| format!("failed to parse policy: {error}"))
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
        assert_eq!(plan.tracepoints.len(), 10);
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
        let policy = Policy::default();
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

        let canonical = canonicalize(&raw, &policy);

        assert_eq!(canonical.event_type, EventType::ProcessExit);
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_core::{
    actors, resources, CanonicalEvent, EventSource, EventType, ObserverDiagnostic,
    ObserverDiagnosticKind, RawKernelEvent,
};
use apolysis_feedback::FeedbackWriter;
use apolysis_policy::PolicyRuntimeCapabilities;
use apolysis_store::JsonlStore;
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader, Pod};
use tokio::io::unix::AsyncFd;
use tokio::process::Child;

use crate::abi::{
    KernelEventKind, KernelEventRecord, FLAG_ARGV_TRUNCATED, FLAG_PAYLOAD_SOCKADDR,
    FLAG_PAYLOAD_TRUNCATED, FLAG_RESOURCE_TRUNCATED,
};
use crate::capabilities::validate_live_prerequisites;
use crate::{
    append_policy_evaluation, canonicalize, load_policy, write_observer_metadata, AyaLoaderPlan,
    EventIdSequence, ObserveResult, ObserverBackend, ObserverMode, ObserverRunnerPlan, Redactor,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveScope {
    Cgroup(u64),
    ProcessTree(u32),
}

impl LiveScope {
    pub fn metadata_value(&self) -> String {
        match self {
            Self::Cgroup(id) => format!("mode:cgroup,cgroup_id:{id}"),
            Self::ProcessTree(pid) => format!("mode:process_tree,root_pid:{pid}"),
        }
    }
}

pub fn discover_process_tree_scope_pids(
    root_pid: u32,
    proc_root: impl AsRef<Path>,
) -> Result<Vec<u32>, String> {
    if root_pid == 0 {
        return Err("process-tree root PID must be non-zero".to_string());
    }

    let proc_root = proc_root.as_ref();
    let mut pids = BTreeSet::from([root_pid]);
    let mut changed = true;
    while changed {
        changed = false;
        let snapshot = pids.iter().copied().collect::<Vec<_>>();

        for pid in &snapshot {
            for tid in proc_task_ids(proc_root, *pid) {
                changed |= pids.insert(tid);
                for child in proc_task_children(proc_root, *pid, tid) {
                    changed |= pids.insert(child);
                }
            }
        }

        for (pid, ppid) in proc_parent_pairs(proc_root)? {
            if pids.contains(&ppid) {
                changed |= pids.insert(pid);
            }
        }
    }

    Ok(pids.into_iter().collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunRequest {
    pub kind: String,
    pub command: Vec<String>,
}

impl AgentRunRequest {
    pub fn new(kind: impl Into<String>, command: Vec<String>) -> Result<Self, String> {
        let kind = kind.into();
        if kind.trim().is_empty() {
            return Err("agent kind must not be empty".to_string());
        }
        if command.is_empty() {
            return Err("agent command must not be empty".to_string());
        }
        Ok(Self { kind, command })
    }

    fn executable(&self) -> &str {
        &self.command[0]
    }

    fn args(&self) -> &[String] {
        &self.command[1..]
    }

    fn redacted_command(&self) -> String {
        redact_command(&self.command).join(" ")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveObserveRequest {
    pub object_path: PathBuf,
    pub output_path: PathBuf,
    pub policy_path: PathBuf,
    pub session_id: String,
    pub feedback_dir: Option<PathBuf>,
    pub scope: Option<LiveScope>,
    pub agent_run: Option<AgentRunRequest>,
    pub duration: Option<Duration>,
    pub workspace_root: PathBuf,
}

impl LiveObserveRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !self.object_path.is_file() {
            return Err(format!(
                "BPF object does not exist: {}",
                self.object_path.display()
            ));
        }
        match (&self.scope, &self.agent_run) {
            (Some(_), None) | (None, Some(_)) => {}
            (None, None) => {
                return Err("live observer requires either a scope or --agent-run".to_string());
            }
            (Some(_), Some(_)) => {
                return Err(
                    "--agent-run cannot be combined with --scope-pid or --scope-cgroup".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ManagedAgentChild {
    child: Child,
    metadata: ManagedAgentMetadata,
}

#[derive(Debug)]
struct ManagedAgentMetadata {
    kind: String,
    root_pid: u32,
    executable: String,
    command: String,
    workspace_root: String,
    start_time_ticks: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonObserverConfig {
    pub object_path: PathBuf,
}

impl DaemonObserverConfig {
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.object_path.is_file() {
            return Err(format!(
                "BPF object does not exist: {}",
                self.object_path.display()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonKernelEvent {
    pub timestamp_unix_ms: u128,
    pub record: KernelEventRecord,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaemonObserverBatch {
    pub events: Vec<DaemonKernelEvent>,
    pub decode_failures: u64,
    pub truncations: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaemonObserverCounters {
    pub reserve_failures: u64,
    pub map_pressure: u64,
}

pub struct DaemonObserver {
    ebpf: Ebpf,
    ring: AsyncFd<RingBuf<MapData>>,
    decoder: ObserverBatchDecoder,
}

impl DaemonObserver {
    pub fn load(config: DaemonObserverConfig) -> Result<Self, String> {
        config.validate()?;
        let loader_plan = AyaLoaderPlan::audit_observer_default(&config.object_path);
        validate_live_prerequisites(&LiveScope::Cgroup(1), &loader_plan)
            .map_err(|error| format!("daemon observer prerequisite failed: {error}"))?;
        let mut ebpf = EbpfLoader::new()
            .load_file(&loader_plan.object_path)
            .map_err(|error| format!("BPF load or verifier failure: {error:#}"))?;
        enable_multi_cgroup_scope(&mut ebpf)?;
        attach_tracepoints(&mut ebpf, &loader_plan)?;
        let ring_map = ebpf
            .take_map(&loader_plan.ring_buffer_map)
            .ok_or_else(|| format!("missing BPF map: {}", loader_plan.ring_buffer_map))?;
        let ring_buffer = RingBuf::try_from(ring_map)
            .map_err(|error| format!("failed to open observer ring buffer: {error}"))?;
        let ring = AsyncFd::new(ring_buffer)
            .map_err(|error| format!("failed to poll observer ring buffer: {error}"))?;
        Ok(Self {
            ebpf,
            ring,
            decoder: ObserverBatchDecoder::capture()?,
        })
    }

    pub fn track_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        update_tracked_cgroup(&mut self.ebpf, cgroup_id, true)
    }

    pub fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        update_tracked_cgroup(&mut self.ebpf, cgroup_id, false)
    }

    pub async fn read_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        let records = read_ring_batch(&mut self.ring).await?;
        Ok(self.decoder.decode(records))
    }

    pub fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        let counters = read_observer_counters(&mut self.ebpf)?;
        Ok(DaemonObserverCounters {
            reserve_failures: counters.reserve_failures,
            map_pressure: counters.map_pressure,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct ScopeConfig {
    cgroup_id: u64,
    root_pid: u32,
    mode: u32,
}

unsafe impl Pod for ScopeConfig {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct ObserverCounters {
    reserve_failures: u64,
    map_pressure: u64,
}

unsafe impl Pod for ObserverCounters {}

pub async fn observe_live(request: LiveObserveRequest) -> Result<crate::ObserveResult, String> {
    request.validate()?;
    let policy = load_policy(&request.policy_path)?;
    let capabilities = PolicyRuntimeCapabilities::detect();
    let feedback = request.feedback_dir.clone().map(FeedbackWriter::new);
    let runner_plan = ObserverRunnerPlan::host_observer_default();
    let loader_plan = AyaLoaderPlan::audit_observer_default(&request.object_path);
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create live observer timeline: {error}"))?;

    write_observer_metadata(
        &request.session_id,
        &runner_plan,
        ObserverBackend::AyaRingBuffer,
        policy.startup_downgrade(&capabilities),
        &mut store,
    )?;
    let prerequisite_scope = request
        .scope
        .as_ref()
        .cloned()
        .unwrap_or_else(|| LiveScope::ProcessTree(std::process::id()));
    if let Err(error) = validate_live_prerequisites(&prerequisite_scope, &loader_plan) {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AttachFailure,
            1,
            &error,
            &mut store,
        )?;
        store
            .flush()
            .map_err(|flush| format!("failed to flush prerequisite diagnostic: {flush}"))?;
        return Err(format!("live observer prerequisite failed: {error}"));
    }

    let mut managed_agent = if let Some(agent_run) = request.agent_run.as_ref() {
        let managed = spawn_managed_agent(agent_run, &request.workspace_root)?;
        write_agent_supervisor_metadata(&request.session_id, &managed.metadata, &mut store)?;
        Some(managed)
    } else {
        None
    };
    let scope = managed_agent
        .as_ref()
        .map(|agent| LiveScope::ProcessTree(agent.metadata.root_pid))
        .or_else(|| request.scope.clone())
        .expect("live request validation requires a scope or managed agent");
    write_scope_metadata(&request.session_id, &scope, &mut store)?;

    let mut ebpf = match EbpfLoader::new().load_file(&loader_plan.object_path) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            terminate_managed_agent(managed_agent.as_mut()).await;
            append_diagnostic(
                &request.session_id,
                ObserverDiagnosticKind::VerifierFailure,
                1,
                format!("{error:#}"),
                &mut store,
            )?;
            store
                .flush()
                .map_err(|flush| format!("failed to flush verifier diagnostic: {flush}"))?;
            return Err(format!("BPF load or verifier failure: {error:#}"));
        }
    };
    if let Err(error) = configure_scope(&mut ebpf, &scope) {
        terminate_managed_agent(managed_agent.as_mut()).await;
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AttachFailure,
            1,
            &error,
            &mut store,
        )?;
        store
            .flush()
            .map_err(|flush| format!("failed to flush scope diagnostic: {flush}"))?;
        return Err(error);
    }
    if let Err(error) = attach_tracepoints(&mut ebpf, &loader_plan) {
        terminate_managed_agent(managed_agent.as_mut()).await;
        let kind = if error.contains("verifier") {
            ObserverDiagnosticKind::VerifierFailure
        } else {
            ObserverDiagnosticKind::AttachFailure
        };
        append_diagnostic(&request.session_id, kind, 1, &error, &mut store)?;
        store
            .flush()
            .map_err(|flush| format!("failed to flush attach diagnostic: {flush}"))?;
        return Err(error);
    }

    let ring_map = ebpf
        .take_map(&loader_plan.ring_buffer_map)
        .ok_or_else(|| format!("missing BPF map: {}", loader_plan.ring_buffer_map))?;
    let ring_buffer = RingBuf::try_from(ring_map)
        .map_err(|error| format!("failed to open observer ring buffer: {error}"))?;
    let mut async_ring = AsyncFd::new(ring_buffer)
        .map_err(|error| format!("failed to poll observer ring buffer: {error}"))?;
    let calibration = ObserverBatchDecoder::capture()?;
    let deadline = request
        .duration
        .map(|duration| tokio::time::Instant::now() + duration);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut raw_count = 0;
    let mut canonical_count = 0;
    let mut decode_failures = 0_u64;
    let mut truncations = 0_u64;
    let mut event_ids = EventIdSequence::new(&request.session_id);
    let redactor = Redactor::new(&request.session_id, &request.workspace_root);
    let mut agent_exit_status: Option<ExitStatus> = None;
    let mut agent_drain_deadline: Option<tokio::time::Instant> = None;

    loop {
        if agent_exit_status.is_none() {
            if let Some(agent) = managed_agent.as_mut() {
                if let Some(status) = agent
                    .child
                    .try_wait()
                    .map_err(|error| format!("failed to poll managed agent exit: {error}"))?
                {
                    agent_drain_deadline =
                        Some(tokio::time::Instant::now() + Duration::from_millis(300));
                    agent_exit_status = Some(status);
                }
            }
        }

        let effective_deadline = earliest_deadline(deadline, agent_drain_deadline);
        let batch = if let Some(deadline) = effective_deadline {
            tokio::select! {
                result = read_ring_batch(&mut async_ring) => Some(result?),
                result = &mut shutdown => {
                    result?;
                    None
                },
                _ = tokio::time::sleep(Duration::from_millis(100)), if managed_agent.is_some() && agent_exit_status.is_none() => {
                    Some(Vec::new())
                },
                _ = tokio::time::sleep_until(deadline) => None,
            }
        } else {
            tokio::select! {
                result = read_ring_batch(&mut async_ring) => Some(result?),
                result = &mut shutdown => {
                    result?;
                    None
                },
                _ = tokio::time::sleep(Duration::from_millis(100)), if managed_agent.is_some() && agent_exit_status.is_none() => {
                    Some(Vec::new())
                }
            }
        };

        let Some(batch) = batch else {
            break;
        };

        for bytes in batch {
            let record = match KernelEventRecord::decode(&bytes) {
                Ok(record) => record,
                Err(_) => {
                    decode_failures += 1;
                    continue;
                }
            };
            if record.flags & (FLAG_RESOURCE_TRUNCATED | FLAG_PAYLOAD_TRUNCATED) != 0 {
                truncations += 1;
            }
            let raw = match raw_event_from_record(
                &record,
                &request.session_id,
                calibration.to_unix_ms(record.timestamp_ns),
            ) {
                Ok(raw) => raw.with_event_id(event_ids.next_raw_event_id()),
                Err(_) => {
                    decode_failures += 1;
                    continue;
                }
            };
            let canonical = canonicalize(&raw, &policy);
            let (persisted_raw, persisted_canonical) =
                redact_for_persistence(&raw, &canonical, &redactor);
            store
                .append(&persisted_raw)
                .map_err(|error| format!("failed to write live raw event: {error}"))?;
            raw_count += 1;

            store
                .append(&persisted_canonical)
                .map_err(|error| format!("failed to write live canonical event: {error}"))?;
            append_policy_evaluation(
                &canonical,
                &policy,
                &capabilities,
                feedback.as_ref(),
                Some(&persisted_canonical.resource),
                &mut store,
            )?;
            canonical_count += 1;
        }
    }

    if let Some(status) = agent_exit_status {
        write_agent_exit_metadata(&request.session_id, status_exit_code(status), &mut store)?;
    }

    let counters = read_observer_counters(&mut ebpf)?;
    if counters.reserve_failures > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::RingBufferReserveFailure,
            counters.reserve_failures,
            "kernel APOLYSIS_COUNTERS",
            &mut store,
        )?;
    }
    if counters.map_pressure > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::MapPressure,
            counters.map_pressure,
            "kernel APOLYSIS_COUNTERS",
            &mut store,
        )?;
    }
    if decode_failures > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::DecodeFailure,
            decode_failures,
            "userspace ring-buffer decoder",
            &mut store,
        )?;
    }
    if truncations > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::Truncation,
            truncations,
            "kernel event flags",
            &mut store,
        )?;
    }
    append_diagnostic(
        &request.session_id,
        ObserverDiagnosticKind::Summary,
        raw_count as u64,
        format!(
            "raw_events:{raw_count},canonical_events:{canonical_count},reserve_failures:{},map_pressure:{},decode_failures:{decode_failures},truncations:{truncations}",
            counters.reserve_failures, counters.map_pressure
        ),
        &mut store,
    )?;

    store
        .flush()
        .map_err(|error| format!("failed to flush live observer timeline: {error}"))?;

    Ok(ObserveResult {
        raw_events: raw_count,
        canonical_events: canonical_count,
        backend: ObserverBackend::AyaRingBuffer,
        mode: ObserverMode::AuditOnly,
        agent_exit_code: agent_exit_status.map(status_exit_code),
    })
}

fn spawn_managed_agent(
    request: &AgentRunRequest,
    workspace_root: &Path,
) -> Result<ManagedAgentChild, String> {
    let mut command = tokio::process::Command::new(request.executable());
    command
        .args(request.args())
        .current_dir(workspace_root)
        .kill_on_drop(true);
    let child = command.spawn().map_err(|error| {
        format!(
            "failed to start managed agent command '{}': {error}",
            request.redacted_command()
        )
    })?;
    let root_pid = child
        .id()
        .ok_or_else(|| "managed agent child pid is unavailable".to_string())?;
    let metadata = ManagedAgentMetadata {
        kind: request.kind.clone(),
        root_pid,
        executable: request.executable().to_string(),
        command: request.redacted_command(),
        workspace_root: workspace_root.display().to_string(),
        start_time_ticks: read_process_start_time_ticks(root_pid),
    };
    Ok(ManagedAgentChild { child, metadata })
}

async fn terminate_managed_agent(agent: Option<&mut ManagedAgentChild>) {
    if let Some(agent) = agent {
        let _ = agent.child.start_kill();
        let _ = agent.child.wait().await;
    }
}

fn write_agent_supervisor_metadata(
    session_id: &str,
    metadata: &ManagedAgentMetadata,
    store: &mut JsonlStore,
) -> Result<(), String> {
    for (resource, action) in [
        (
            resources::AGENT_SUPERVISOR_MODE,
            "apolysis_managed_launch".to_string(),
        ),
        (resources::AGENT_KIND, metadata.kind.clone()),
        (resources::AGENT_ROOT_PID, metadata.root_pid.to_string()),
        (resources::AGENT_COMMAND, metadata.command.clone()),
        (resources::AGENT_EXECUTABLE, metadata.executable.clone()),
        (
            resources::AGENT_WORKSPACE_ROOT,
            metadata.workspace_root.clone(),
        ),
        (
            resources::AGENT_START_TIME,
            metadata
                .start_time_ticks
                .map(|ticks| format!("start_time_ticks:{ticks}"))
                .unwrap_or_else(|| "start_time_ticks:unavailable".to_string()),
        ),
    ] {
        write_runtime_metadata_event(session_id, actors::OBSERVER, resource, action, store)?;
    }
    Ok(())
}

fn write_agent_exit_metadata(
    session_id: &str,
    exit_code: i32,
    store: &mut JsonlStore,
) -> Result<(), String> {
    write_runtime_metadata_event(
        session_id,
        actors::OBSERVER,
        resources::AGENT_EXIT_STATUS,
        format!("exit:{exit_code}"),
        store,
    )
}

fn write_runtime_metadata_event(
    session_id: &str,
    actor: &str,
    resource: &str,
    action: impl Into<String>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let event = CanonicalEvent::new(
        session_id,
        EventSource::RuntimeMetadata,
        EventType::RuntimeMetadata,
        std::process::id(),
        0,
        actor,
        resource,
        action,
    );
    store
        .append(&event)
        .map_err(|error| format!("failed to write live observer metadata: {error}"))
}

fn earliest_deadline(
    first: Option<tokio::time::Instant>,
    second: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(first), None) => Some(first),
        (None, Some(second)) => Some(second),
        (None, None) => None,
    }
}

fn status_exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

fn read_process_start_time_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn redact_command(command: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(command.len());
    let mut redact_next = false;
    for arg in command {
        if redact_next {
            redacted.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }

        if secret_flag(arg) {
            redacted.push(arg.clone());
            redact_next = true;
            continue;
        }

        if let Some((key, _)) = arg.split_once('=') {
            if secret_word(key) {
                redacted.push(format!("{key}=<redacted>"));
                continue;
            }
        }

        if looks_like_secret_value(arg) {
            redacted.push("<redacted>".to_string());
        } else {
            redacted.push(shell_display_arg(arg));
        }
    }
    redacted
}

fn secret_flag(value: &str) -> bool {
    value.starts_with("--") && secret_word(value.trim_start_matches('-'))
}

fn secret_word(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "api-key",
        "apikey",
    ]
    .iter()
    .any(|word| normalized.contains(word))
}

fn looks_like_secret_value(value: &str) -> bool {
    value.starts_with("sk-") || value.starts_with("ghp_") || value.starts_with("github_pat_")
}

fn shell_display_arg(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

async fn shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("failed to install SIGTERM handler: {error}"))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("failed to install SIGINT handler: {error}"))
        }
        _ = terminate.recv() => Ok(()),
    }
}

fn configure_scope(ebpf: &mut Ebpf, scope: &LiveScope) -> Result<(), String> {
    let config = match scope {
        LiveScope::Cgroup(cgroup_id) => ScopeConfig {
            cgroup_id: *cgroup_id,
            root_pid: 0,
            mode: 1,
        },
        LiveScope::ProcessTree(root_pid) => ScopeConfig {
            cgroup_id: 0,
            root_pid: *root_pid,
            mode: 2,
        },
    };
    let config_map = ebpf
        .map_mut("APOLYSIS_CONFIG")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONFIG".to_string())?;
    let mut config_array = Array::<_, ScopeConfig>::try_from(config_map)
        .map_err(|error| format!("invalid APOLYSIS_CONFIG map: {error}"))?;
    config_array
        .set(0, config, 0)
        .map_err(|error| format!("failed to configure live observer scope: {error}"))?;

    if let LiveScope::ProcessTree(root_pid) = scope {
        let tracked_map = ebpf
            .map_mut("APOLYSIS_TRACKED_PIDS")
            .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_PIDS".to_string())?;
        let mut tracked = HashMap::<_, u32, u8>::try_from(tracked_map)
            .map_err(|error| format!("invalid APOLYSIS_TRACKED_PIDS map: {error}"))?;
        for pid in discover_process_tree_scope_pids(*root_pid, "/proc")? {
            tracked
                .insert(pid, 1, 0)
                .map_err(|error| format!("failed to seed process-tree scope pid {pid}: {error}"))?;
        }
    }
    Ok(())
}

fn proc_task_ids(proc_root: &Path, pid: u32) -> Vec<u32> {
    let task_root = proc_root.join(pid.to_string()).join("task");
    let Ok(entries) = fs::read_dir(task_root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .collect()
}

fn proc_task_children(proc_root: &Path, pid: u32, tid: u32) -> Vec<u32> {
    let children_path = proc_root
        .join(pid.to_string())
        .join("task")
        .join(tid.to_string())
        .join("children");
    let Ok(children) = fs::read_to_string(children_path) else {
        return Vec::new();
    };
    children
        .split_whitespace()
        .filter_map(|child| child.parse::<u32>().ok())
        .collect()
}

fn proc_parent_pairs(proc_root: &Path) -> Result<Vec<(u32, u32)>, String> {
    let entries = fs::read_dir(proc_root)
        .map_err(|error| format!("failed to scan proc root {}: {error}", proc_root.display()))?;
    let mut pairs = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let stat_path = entry.path().join("stat");
        let Ok(stat) = fs::read_to_string(stat_path) else {
            continue;
        };
        if let Some(ppid) = parse_proc_stat_ppid(&stat) {
            pairs.push((pid, ppid));
        }
    }
    Ok(pairs)
}

fn parse_proc_stat_ppid(stat: &str) -> Option<u32> {
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

/// Configure the observer to accept events from a dynamically managed cgroup set.
pub fn enable_multi_cgroup_scope(ebpf: &mut Ebpf) -> Result<(), String> {
    let config = ScopeConfig {
        cgroup_id: 0,
        root_pid: 0,
        mode: 3,
    };
    let config_map = ebpf
        .map_mut("APOLYSIS_CONFIG")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONFIG".to_string())?;
    let mut config_array = Array::<_, ScopeConfig>::try_from(config_map)
        .map_err(|error| format!("invalid APOLYSIS_CONFIG map: {error}"))?;
    config_array
        .set(0, config, 0)
        .map_err(|error| format!("failed to configure multi-cgroup observer scope: {error}"))
}

/// Add or remove one cgroup id from the daemon observer scope map.
pub fn update_tracked_cgroup(ebpf: &mut Ebpf, cgroup_id: u64, present: bool) -> Result<(), String> {
    if cgroup_id == 0 {
        return Err("cgroup id must be non-zero".to_string());
    }
    let tracked_map = ebpf
        .map_mut("APOLYSIS_TRACKED_CGROUPS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_CGROUPS".to_string())?;
    let mut tracked = HashMap::<_, u64, u8>::try_from(tracked_map)
        .map_err(|error| format!("invalid APOLYSIS_TRACKED_CGROUPS map: {error}"))?;
    if present {
        tracked
            .insert(cgroup_id, 1, 0)
            .map_err(|error| format!("failed to add cgroup observer scope: {error}"))
    } else {
        tracked
            .remove(&cgroup_id)
            .map_err(|error| format!("failed to remove cgroup observer scope: {error}"))
    }
}

fn attach_tracepoints(ebpf: &mut Ebpf, plan: &AyaLoaderPlan) -> Result<(), String> {
    for attach in &plan.tracepoints {
        let program_name = attach.program_name();
        let program = ebpf
            .program_mut(&program_name)
            .ok_or_else(|| format!("missing BPF program: {program_name}"))?;
        let tracepoint: &mut TracePoint = program
            .try_into()
            .map_err(|error| format!("invalid tracepoint program {program_name}: {error}"))?;
        tracepoint
            .load()
            .map_err(|error| format!("BPF load or verifier failure for {program_name}: {error}"))?;
        tracepoint
            .attach(&attach.category, &attach.name)
            .map_err(|error| {
                format!(
                    "BPF attach failure for {program_name} at {}/{}: {error}",
                    attach.category, attach.name
                )
            })?;
    }
    Ok(())
}

fn read_observer_counters(ebpf: &mut Ebpf) -> Result<ObserverCounters, String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_COUNTERS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_COUNTERS".to_string())?;
    let counters = Array::<_, ObserverCounters>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_COUNTERS map: {error}"))?;
    counters
        .get(&0, 0)
        .map_err(|error| format!("failed to read observer counters: {error}"))
}

async fn read_ring_batch(ring: &mut AsyncFd<RingBuf<MapData>>) -> Result<Vec<Vec<u8>>, String> {
    let mut guard = ring
        .readable_mut()
        .await
        .map_err(|error| format!("ring-buffer poll failure: {error}"))?;
    let mut batch = Vec::new();
    while let Some(item) = guard.get_inner_mut().next() {
        batch.push(item.to_vec());
    }
    guard.clear_ready();
    Ok(batch)
}

fn write_scope_metadata(
    session_id: &str,
    scope: &LiveScope,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let event = apolysis_core::CanonicalEvent::new(
        session_id,
        apolysis_core::EventSource::RuntimeMetadata,
        apolysis_core::EventType::RuntimeMetadata,
        std::process::id(),
        0,
        apolysis_core::actors::OBSERVER,
        apolysis_core::resources::OBSERVER_SCOPE,
        scope.metadata_value(),
    );
    store
        .append(&event)
        .map_err(|error| format!("failed to write live observer scope: {error}"))
}

fn append_diagnostic(
    session_id: &str,
    kind: ObserverDiagnosticKind,
    count: u64,
    detail: impl Into<String>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let diagnostic = ObserverDiagnostic::new(session_id, kind, count, detail);
    store
        .append(&diagnostic)
        .map_err(|error| format!("failed to write observer diagnostic: {error}"))
}

fn redact_for_persistence(
    raw: &RawKernelEvent,
    canonical: &CanonicalEvent,
    redactor: &Redactor,
) -> (RawKernelEvent, CanonicalEvent) {
    let mut persisted_raw = raw.clone();
    let mut persisted_canonical = canonical.clone();
    let resource = redactor.redact_resource(canonical.event_type.clone(), &canonical.resource);
    persisted_raw.resource.clone_from(&resource.value);
    persisted_canonical.resource = resource.value;
    if resource.redacted {
        append_marker(&mut persisted_raw.raw_payload, "redacted:resource");
    }

    if canonical.event_type == apolysis_core::EventType::FileRename && !raw.raw_payload.is_empty() {
        let payload =
            redactor.redact_resource(apolysis_core::EventType::FileRename, &raw.raw_payload);
        persisted_raw.raw_payload = payload.value;
        if payload.redacted {
            append_marker(&mut persisted_raw.raw_payload, "redacted:payload");
        }
    }
    if canonical.event_type == apolysis_core::EventType::Exec && !raw.raw_payload.is_empty() {
        let (payload, redacted) = redact_exec_payload_for_persistence(&raw.raw_payload, redactor);
        persisted_raw.raw_payload = payload;
        if redacted {
            append_marker(&mut persisted_raw.raw_payload, "redacted:payload");
        }
    }
    (persisted_raw, persisted_canonical)
}

fn append_marker(payload: &mut String, marker: &str) {
    if !payload.is_empty() {
        payload.push(',');
    }
    payload.push_str(marker);
}

fn redact_exec_payload_for_persistence(payload: &str, redactor: &Redactor) -> (String, bool) {
    let (argv, markers) = payload.split_once(',').unwrap_or((payload, ""));
    let Some(argv) = argv.strip_prefix("argv:") else {
        return (payload.to_string(), false);
    };

    let mut redacted = false;
    let mut redact_next = false;
    let mut args = Vec::new();
    for arg in argv.split_whitespace() {
        if redact_next {
            args.push("<redacted>".to_string());
            redacted = true;
            redact_next = false;
            continue;
        }

        if secret_flag(arg) {
            args.push(arg.to_string());
            redact_next = true;
            continue;
        }

        if let Some((key, value)) = arg.split_once('=') {
            if secret_word(key) {
                args.push(format!("{key}=<redacted>"));
                redacted = true;
                continue;
            }
            let (value, value_redacted) = redact_argv_resource(value, redactor);
            if value_redacted {
                args.push(format!("{key}={value}"));
                redacted = true;
                continue;
            }
        }

        if looks_like_secret_value(arg) {
            args.push("<redacted>".to_string());
            redacted = true;
            continue;
        }

        let (arg, arg_redacted) = redact_argv_resource(arg, redactor);
        args.push(arg);
        redacted |= arg_redacted;
    }

    let mut persisted = format!("argv:{}", args.join(" "));
    if !markers.is_empty() {
        persisted.push(',');
        persisted.push_str(markers);
    }
    (persisted, redacted)
}

fn redact_argv_resource(value: &str, redactor: &Redactor) -> (String, bool) {
    if !looks_like_path_argument(value) {
        return (value.to_string(), false);
    }
    let event_type = if looks_like_credential_path(value) {
        apolysis_core::EventType::CredentialRead
    } else {
        apolysis_core::EventType::FileOpen
    };
    let redacted = redactor.redact_resource(event_type, value);
    (redacted.value, redacted.redacted)
}

fn looks_like_path_argument(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
}

fn looks_like_credential_path(value: &str) -> bool {
    value.ends_with("/.env")
        || value.contains("/.env.")
        || value.contains("/.ssh/")
        || value.contains("/.aws/")
        || value.contains("/var/run/secrets/")
}

pub struct ObserverBatchDecoder {
    monotonic_ns: u64,
    unix_ms: u128,
}

impl ObserverBatchDecoder {
    pub fn new(monotonic_ns: u64, unix_ms: u128) -> Self {
        Self {
            monotonic_ns,
            unix_ms,
        }
    }

    fn capture() -> Result<Self, String> {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
            .as_millis();
        Ok(Self {
            monotonic_ns: monotonic_now_ns()?,
            unix_ms,
        })
    }

    pub fn decode(&self, records: Vec<Vec<u8>>) -> DaemonObserverBatch {
        let mut batch = DaemonObserverBatch::default();
        for bytes in records {
            let Ok(record) = KernelEventRecord::decode(&bytes) else {
                batch.decode_failures += 1;
                continue;
            };
            if record.flags & (FLAG_RESOURCE_TRUNCATED | FLAG_PAYLOAD_TRUNCATED) != 0 {
                batch.truncations += 1;
            }
            batch.events.push(DaemonKernelEvent {
                timestamp_unix_ms: self.to_unix_ms(record.timestamp_ns),
                record,
            });
        }
        batch
    }

    fn to_unix_ms(&self, timestamp_ns: u64) -> u128 {
        if timestamp_ns >= self.monotonic_ns {
            self.unix_ms + u128::from(timestamp_ns - self.monotonic_ns) / 1_000_000
        } else {
            self.unix_ms
                .saturating_sub(u128::from(self.monotonic_ns - timestamp_ns) / 1_000_000)
        }
    }
}

fn monotonic_now_ns() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes the provided timespec on success.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
    if status != 0 {
        return Err(format!(
            "failed to read monotonic clock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64)
}

pub fn raw_event_from_record(
    record: &KernelEventRecord,
    session_id: &str,
    timestamp_unix_ms: u128,
) -> Result<RawKernelEvent, String> {
    let kind = record.kind()?;
    let event_name = match kind {
        KernelEventKind::Exec => "sched_process_exec",
        KernelEventKind::Open => "openat",
        KernelEventKind::Create => "creat",
        KernelEventKind::Truncate => "truncate",
        KernelEventKind::Unlink => "unlinkat",
        KernelEventKind::Rename => "renameat2",
        KernelEventKind::Connect => "connect",
        KernelEventKind::Exit => "sched_process_exit",
        KernelEventKind::Fork => "sched_process_fork",
    };

    let mut resource = record.resource();
    let mut payload = record.payload();
    if record.flags & FLAG_PAYLOAD_SOCKADDR != 0 {
        let (address, family) = decode_sockaddr(record.payload_bytes())?;
        resource = address;
        payload = format!("family:{family}");
    }

    let mut markers = Vec::new();
    if record.flags & FLAG_RESOURCE_TRUNCATED != 0 {
        markers.push("resource_truncated:true");
    }
    if record.flags & FLAG_ARGV_TRUNCATED != 0 {
        markers.push("argv_truncated:true");
    }
    if record.flags & FLAG_PAYLOAD_TRUNCATED != 0 {
        markers.push("payload_truncated:true");
    }
    if !markers.is_empty() {
        if !payload.is_empty() {
            markers.insert(0, payload.as_str());
        }
        payload = markers.join(",");
    }

    Ok(RawKernelEvent::new(
        timestamp_unix_ms,
        session_id,
        EventSource::KernelTracepoint,
        event_name,
        record.pid,
        record.ppid,
        record.uid,
        record.gid,
        record.comm(),
        resource,
        record.action(),
        None,
        Some(record.cgroup_id.to_string()),
        payload,
    ))
}

fn decode_sockaddr(bytes: &[u8]) -> Result<(String, &'static str), String> {
    if bytes.len() < 4 {
        return Err("socket address payload is too short".to_string());
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        2 if bytes.len() >= 8 => {
            let address = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Ok((format!("{address}:{port}"), "inet"))
        }
        10 if bytes.len() >= 24 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let address = std::net::Ipv6Addr::from(octets);
            Ok((format!("[{address}]:{port}"), "inet6"))
        }
        2 | 10 => Err("socket address payload is truncated".to_string()),
        unknown => Ok((format!("family:{unknown},port:{port}"), "unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apolysis_core::{CanonicalEvent, EventType};

    #[test]
    fn persisted_live_events_redact_credentials_before_jsonl_output() {
        let raw = RawKernelEvent::new(
            1,
            "session-a",
            EventSource::KernelTracepoint,
            "openat",
            10,
            1,
            1000,
            1000,
            "cat",
            "/workspace/.env",
            "read",
            None,
            Some("42".to_string()),
            "",
        );
        let canonical = CanonicalEvent::new(
            "session-a",
            EventSource::KernelTracepoint,
            EventType::CredentialRead,
            10,
            1,
            "cat",
            "/workspace/.env",
            "read",
        );
        let redactor = crate::Redactor::new("session-a", "/workspace");

        let (persisted_raw, persisted_canonical) =
            redact_for_persistence(&raw, &canonical, &redactor);

        assert!(!persisted_raw.to_json_line().contains("/workspace/.env"));
        assert!(!persisted_canonical
            .to_json_line()
            .contains("/workspace/.env"));
        assert!(persisted_raw.resource.starts_with("path_token:"));
        assert!(persisted_raw.raw_payload.contains("redacted:resource"));
    }

    #[test]
    fn managed_agent_command_metadata_redacts_secret_values() {
        let request = AgentRunRequest::new(
            "codex",
            vec![
                "codex".to_string(),
                "resume".to_string(),
                "--api-key".to_string(),
                "sk-test-secret".to_string(),
                "TOKEN=plain-secret".to_string(),
            ],
        )
        .expect("agent run request");

        let command = request.redacted_command();

        assert!(command.contains("codex resume --api-key <redacted>"));
        assert!(command.contains("TOKEN=<redacted>"));
        assert!(!command.contains("sk-test-secret"));
        assert!(!command.contains("plain-secret"));
    }

    #[test]
    fn persisted_exec_payload_redacts_argv_credentials_and_sensitive_paths() {
        let raw = RawKernelEvent::new(
            1,
            "session-a",
            EventSource::KernelTracepoint,
            "sched_process_exec",
            101,
            100,
            1000,
            1000,
            "codex",
            "/usr/bin/codex",
            "exec",
            None,
            Some("42".to_string()),
            "argv:/usr/bin/codex exec --api-key sk-test-secret /workspace/.env /workspace/src/main.rs",
        );
        let canonical = CanonicalEvent::new(
            "session-a",
            EventSource::KernelTracepoint,
            EventType::Exec,
            101,
            100,
            "codex",
            "/usr/bin/codex",
            "exec",
        );
        let redactor = crate::Redactor::new("session-a", "/workspace");

        let (persisted_raw, _persisted_canonical) =
            redact_for_persistence(&raw, &canonical, &redactor);

        assert!(persisted_raw.raw_payload.contains("--api-key <redacted>"));
        assert!(persisted_raw.raw_payload.contains("path_token:"));
        assert!(persisted_raw.raw_payload.contains("/workspace/src/main.rs"));
        assert!(persisted_raw.raw_payload.contains("redacted:payload"));
        assert!(!persisted_raw.raw_payload.contains("sk-test-secret"));
        assert!(!persisted_raw.raw_payload.contains("/workspace/.env"));
    }

    #[test]
    fn live_request_rejects_managed_agent_and_manual_scope_together() {
        let request = LiveObserveRequest {
            object_path: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
            output_path: PathBuf::from("target/test.jsonl"),
            policy_path: PathBuf::from("policies/local-dev.yaml"),
            session_id: "session-agent-scope-conflict".to_string(),
            feedback_dir: None,
            scope: Some(LiveScope::ProcessTree(42)),
            agent_run: Some(
                AgentRunRequest::new("codex", vec!["codex".to_string()])
                    .expect("agent run request"),
            ),
            duration: None,
            workspace_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        };

        assert_eq!(
            request.validate(),
            Err("--agent-run cannot be combined with --scope-pid or --scope-cgroup".to_string())
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_core::{
    actors, resources, CanonicalEvent, EventSource, EventType, ObserverDiagnostic,
    ObserverDiagnosticKind, RawKernelEvent,
};
use apolysis_feedback::FeedbackWriter;
use apolysis_policy::PolicyRuntimeCapabilities;
use apolysis_store::JsonlRotationPolicy;
use apolysis_store::JsonlStore;
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader, Pod};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::process::Child;

use crate::abi::{
    KernelEventKind, KernelEventRecord, FLAG_ARGV_TRUNCATED, FLAG_PAYLOAD_SOCKADDR,
    FLAG_PAYLOAD_TRUNCATED, FLAG_RESOURCE_TRUNCATED,
};
use crate::capabilities::validate_live_prerequisites;
use crate::process_context::ProcessContextTable;
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AgentRegistration {
    #[serde(alias = "agent_kind")]
    pub kind: String,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub workspace_root: PathBuf,
    pub executable: String,
    pub command_fingerprint: String,
    #[serde(default)]
    pub command: Option<String>,
}

impl AgentRegistration {
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|error| {
            format!(
                "failed to read agent registration {}: {error}",
                path.display()
            )
        })?;
        let registration = serde_json::from_str::<Self>(&input).map_err(|error| {
            format!(
                "failed to parse agent registration {}: {error}",
                path.display()
            )
        })?;
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.kind.trim().is_empty() {
            return Err("agent registration kind must not be empty".to_string());
        }
        if self.pid == 0 {
            return Err("agent registration pid must be non-zero".to_string());
        }
        if self.start_time_ticks == 0 {
            return Err("agent registration start_time_ticks must be non-zero".to_string());
        }
        if !self.workspace_root.is_absolute() {
            return Err("agent registration workspace_root must be absolute".to_string());
        }
        if self.executable.trim().is_empty() {
            return Err("agent registration executable must not be empty".to_string());
        }
        if self.command_fingerprint.trim().is_empty() {
            return Err("agent registration command_fingerprint must not be empty".to_string());
        }
        Ok(())
    }

    pub fn validate_proc_identity(&self, proc_root: impl AsRef<Path>) -> Result<(), String> {
        self.validate()?;
        let actual = read_process_start_time_ticks_at(proc_root, self.pid).ok_or_else(|| {
            format!(
                "agent registration PID identity is unavailable before attach: pid={}",
                self.pid
            )
        })?;
        if actual != self.start_time_ticks {
            return Err(format!(
                "agent registration rejected possible PID reuse: pid={},expected_start_time_ticks={},actual_start_time_ticks={actual}",
                self.pid, self.start_time_ticks
            ));
        }
        Ok(())
    }

    fn into_metadata(self, supervisor_mode: impl Into<String>) -> AgentScopeMetadata {
        AgentScopeMetadata {
            supervisor_mode: supervisor_mode.into(),
            kind: self.kind,
            root_pid: self.pid,
            executable: self.executable,
            command: self
                .command
                .unwrap_or_else(|| format!("fingerprint:{}", self.command_fingerprint)),
            command_fingerprint: Some(self.command_fingerprint),
            workspace_root: self.workspace_root.display().to_string(),
            start_time_ticks: Some(self.start_time_ticks),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDiscoveryRequest {
    pub kind: String,
}

impl AgentDiscoveryRequest {
    pub fn new(kind: impl Into<String>) -> Result<Self, String> {
        let kind = kind.into();
        if kind.trim().is_empty() {
            return Err("agent kind must not be empty".to_string());
        }
        Ok(Self { kind })
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
    pub agent_registration_path: Option<PathBuf>,
    pub agent_discovery: Option<AgentDiscoveryRequest>,
    pub duration: Option<Duration>,
    pub workspace_root: PathBuf,
    pub output_rotation: Option<JsonlRotationPolicy>,
}

impl LiveObserveRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !self.object_path.is_file() {
            return Err(format!(
                "BPF object does not exist: {}",
                self.object_path.display()
            ));
        }
        if self.agent_run.is_some() && self.scope.is_some() {
            return Err(
                "--agent-run cannot be combined with --scope-pid or --scope-cgroup".to_string(),
            );
        }
        if self.agent_registration_path.is_some() && self.scope.is_some() {
            return Err(
                "--agent-registration cannot be combined with --scope-pid or --scope-cgroup"
                    .to_string(),
            );
        }
        if self.agent_discovery.is_some() && self.scope.is_some() {
            return Err(
                "--agent-discover cannot be combined with --scope-pid or --scope-cgroup"
                    .to_string(),
            );
        }
        if self.agent_run.is_some()
            && (self.agent_registration_path.is_some() || self.agent_discovery.is_some())
        {
            return Err(
                "--agent-run cannot be combined with --agent-registration or --agent-discover"
                    .to_string(),
            );
        }
        if self.agent_registration_path.is_some() && self.agent_discovery.is_some() {
            return Err(
                "--agent-registration cannot be combined with --agent-discover".to_string(),
            );
        }

        let scope_modes = usize::from(self.scope.is_some())
            + usize::from(self.agent_run.is_some())
            + usize::from(self.agent_registration_path.is_some())
            + usize::from(self.agent_discovery.is_some());
        if scope_modes != 1 {
            return Err(live_scope_requirement());
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ManagedAgentChild {
    child: Child,
    metadata: AgentScopeMetadata,
    /// Write end of the pre-exec gate; one byte releases the workload.
    gate: Option<OwnedFd>,
}

impl ManagedAgentChild {
    /// Release the gate so the workload runs now that the observer's tracepoints
    /// are attached and the pid tree is registered. Writing a newline completes
    /// the wrapper's `read`, which then `exec`s the real command.
    fn release_gate(&mut self) {
        if let Some(gate) = self.gate.take() {
            let byte = [b'\n'; 1];
            // SAFETY: gate owns a valid write fd; best-effort single-byte write
            // to complete the wrapper's gate read. The fd closes on drop.
            unsafe {
                libc::write(gate.as_raw_fd(), byte.as_ptr().cast(), 1);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedAgentRunAs {
    uid: u32,
    gid: u32,
    home: Option<String>,
    codex_home: Option<String>,
}

fn managed_agent_run_as_from_env(
    current_euid: u32,
    get_env: impl Fn(&str) -> Option<String>,
) -> Option<ManagedAgentRunAs> {
    if current_euid != 0 {
        return None;
    }

    let uid = parse_env_u32(get_env("SUDO_UID")?)?;
    let gid = parse_env_u32(get_env("SUDO_GID")?)?;
    if uid == 0 {
        return None;
    }

    Some(ManagedAgentRunAs {
        uid,
        gid,
        home: get_env("HOME").filter(|value| !value.trim().is_empty()),
        codex_home: get_env("CODEX_HOME").filter(|value| !value.trim().is_empty()),
    })
}

fn parse_env_u32(value: String) -> Option<u32> {
    value.parse::<u32>().ok()
}

fn current_managed_agent_run_as() -> Option<ManagedAgentRunAs> {
    managed_agent_run_as_from_env(unsafe { libc::geteuid() as u32 }, |key| {
        std::env::var(key).ok()
    })
}

#[derive(Debug)]
struct AgentScopeMetadata {
    supervisor_mode: String,
    kind: String,
    root_pid: u32,
    executable: String,
    command: String,
    command_fingerprint: Option<String>,
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
    let mut store =
        JsonlStore::create_with_rotation_policy(&request.output_path, request.output_rotation)
            .map_err(|error| format!("failed to create live observer timeline: {error}"))?;

    write_observer_metadata(
        &request.session_id,
        &runner_plan,
        ObserverBackend::AyaRingBuffer,
        policy.startup_downgrade(&capabilities),
        request.output_rotation,
        &mut store,
    )?;
    let registered_agent = match resolve_registered_agent(&request) {
        Ok(agent) => agent,
        Err(error) => {
            append_diagnostic(
                &request.session_id,
                ObserverDiagnosticKind::AttachFailure,
                1,
                &error,
                &mut store,
            )?;
            store.flush().map_err(|flush| {
                format!("failed to flush agent registration diagnostic: {flush}")
            })?;
            return Err(error);
        }
    };
    let prerequisite_scope = request
        .scope
        .as_ref()
        .cloned()
        .or_else(|| {
            registered_agent
                .as_ref()
                .map(|agent| LiveScope::ProcessTree(agent.root_pid))
        })
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
    if let Some(agent) = registered_agent.as_ref() {
        write_agent_supervisor_metadata(&request.session_id, agent, &mut store)?;
    }
    let scope = managed_agent
        .as_ref()
        .map(|agent| LiveScope::ProcessTree(agent.metadata.root_pid))
        .or_else(|| {
            registered_agent
                .as_ref()
                .map(|agent| LiveScope::ProcessTree(agent.root_pid))
        })
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

    // Tracepoints are attached and the pid tree is registered; release the
    // gated workload so every side effect from here on is captured.
    if let Some(agent) = managed_agent.as_mut() {
        agent.release_gate();
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
    let mut process_context = ProcessContextTable::default();
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
            let canonical = process_context.observe(&raw, canonicalize(&raw, &policy));
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

    // Fail loud: silent event loss would let a quiet timeline pass for proof of
    // absence, which is the one thing an evidence tool must never do.
    let dropped_events = counters.reserve_failures + counters.map_pressure + decode_failures;
    if dropped_events > 0 || truncations > 0 {
        eprintln!(
            "apolysis: ⚠ evidence may be incomplete — {dropped_events} event(s) dropped, \
             {truncations} truncated. A quiet timeline is not proof of absence."
        );
    }

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

fn resolve_registered_agent(
    request: &LiveObserveRequest,
) -> Result<Option<AgentScopeMetadata>, String> {
    if let Some(path) = request.agent_registration_path.as_deref() {
        let registration = AgentRegistration::from_json_file(path)?;
        registration.validate_proc_identity("/proc")?;
        return Ok(Some(registration.into_metadata("external_registration")));
    }

    if let Some(discovery) = request.agent_discovery.as_ref() {
        let registration = discover_agent_registration(
            discovery,
            "/proc",
            &request.session_id,
            &request.workspace_root,
        )?;
        registration.validate_proc_identity("/proc")?;
        return Ok(Some(registration.into_metadata("proc_discovery")));
    }

    Ok(None)
}

pub fn discover_agent_registration(
    request: &AgentDiscoveryRequest,
    proc_root: impl AsRef<Path>,
    session_id: &str,
    workspace_root: &Path,
) -> Result<AgentRegistration, String> {
    let proc_root = proc_root.as_ref();
    let identities = read_proc_identities(proc_root)?;
    let by_pid = identities
        .iter()
        .map(|identity| (identity.pid, identity.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut candidates = identities
        .into_iter()
        .filter_map(|identity| {
            let score = score_discovery_candidate(
                &identity,
                &by_pid,
                &request.kind,
                session_id,
                workspace_root,
            );
            (score > 0).then_some(AgentDiscoveryCandidate { identity, score })
        })
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Err(format!(
            "agent discovery found no matching {} process",
            request.kind
        ));
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.identity.pid.cmp(&right.identity.pid))
    });
    let top_score = candidates[0].score;
    let top = candidates
        .iter()
        .filter(|candidate| candidate.score == top_score)
        .collect::<Vec<_>>();
    if top.len() != 1 {
        return Err(format!(
            "agent discovery is ambiguous; refusing to attach: {}",
            top.iter()
                .map(|candidate| candidate.summary())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }

    Ok(top[0]
        .identity
        .to_registration(&request.kind, workspace_root))
}

fn spawn_managed_agent(
    request: &AgentRunRequest,
    workspace_root: &Path,
) -> Result<ManagedAgentChild, String> {
    // Gate the workload so the observer attaches BEFORE it runs. Without this, a
    // fast command exec()s and exits during the tens of milliseconds the eBPF
    // verifier and tracepoint attach take, and no events are captured.
    //
    // We cannot simply block in pre_exec: std's spawn() waits for the child to
    // exec() before returning, so a child that blocks before exec would deadlock
    // spawn(). Instead we exec a tiny shell wrapper that blocks on a pipe fd
    // AFTER exec, then exec()s the real command. spawn() returns as soon as the
    // wrapper execs; the real command's exec — and every side effect after it —
    // happens only once the observer writes the release byte.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds is a valid two-element array that pipe2 fills.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "failed to create managed agent gate pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    let gate_read = fds[0];
    let gate_write_raw = fds[1];
    // SAFETY: pipe2 returned a valid, owned write fd; wrap it for RAII.
    let gate_write = unsafe { OwnedFd::from_raw_fd(gate_write_raw) };

    // fd inherited by the wrapper (cleared of CLOEXEC via dup2) that its `read`
    // waits on. `read` fails on EOF, so a dropped gate (observer setup failed)
    // makes the wrapper exit without running the workload.
    const GATE_FD: libc::c_int = 3;
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("IFS= read -r _ <&3 || exit 127; exec \"$@\"")
        .arg("apolysis-agent-gate")
        .arg(request.executable())
        .args(request.args())
        .current_dir(workspace_root)
        .kill_on_drop(true);
    if let Some(run_as) = current_managed_agent_run_as() {
        command.uid(run_as.uid).gid(run_as.gid);
        if let Some(home) = run_as.home {
            command.env("HOME", home);
        }
        if let Some(codex_home) = run_as.codex_home {
            command.env("CODEX_HOME", codex_home);
        }
    }
    // SAFETY: runs post-fork/pre-exec, async-signal-safe only. dup2 the gate read
    // end onto GATE_FD (which clears CLOEXEC), so it survives the wrapper's exec
    // and the shell can read it; the original CLOEXEC fds close on exec.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(gate_read, GATE_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().map_err(|error| {
        format!(
            "failed to start managed agent command '{}': {error}",
            request.redacted_command()
        )
    })?;
    // Only the wrapper reads the gate; the parent keeps the write end.
    // SAFETY: gate_read is a valid fd not used again in the parent.
    unsafe {
        libc::close(gate_read);
    }

    let root_pid = child
        .id()
        .ok_or_else(|| "managed agent child pid is unavailable".to_string())?;
    let metadata = AgentScopeMetadata {
        supervisor_mode: "apolysis_managed_launch".to_string(),
        kind: request.kind.clone(),
        root_pid,
        executable: request.executable().to_string(),
        command: request.redacted_command(),
        command_fingerprint: Some(command_fingerprint_from_args(&request.command)),
        workspace_root: workspace_root.display().to_string(),
        start_time_ticks: read_process_start_time_ticks(root_pid),
    };
    Ok(ManagedAgentChild {
        child,
        metadata,
        gate: Some(gate_write),
    })
}

async fn terminate_managed_agent(agent: Option<&mut ManagedAgentChild>) {
    if let Some(agent) = agent {
        let _ = agent.child.start_kill();
        let _ = agent.child.wait().await;
    }
}

fn write_agent_supervisor_metadata(
    session_id: &str,
    metadata: &AgentScopeMetadata,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let mut entries = vec![
        (
            resources::AGENT_SUPERVISOR_MODE,
            metadata.supervisor_mode.clone(),
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
    ];
    if let Some(fingerprint) = metadata.command_fingerprint.as_ref() {
        entries.push((resources::AGENT_COMMAND_FINGERPRINT, fingerprint.clone()));
    }
    for (resource, action) in entries {
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
    read_process_start_time_ticks_at("/proc", pid)
}

fn read_process_start_time_ticks_at(proc_root: impl AsRef<Path>, pid: u32) -> Option<u64> {
    let stat = read_proc_stat(proc_root.as_ref(), pid)?;
    parse_proc_stat_start_time_ticks(&stat)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcIdentity {
    pid: u32,
    ppid: u32,
    start_time_ticks: u64,
    comm: String,
    executable: String,
    cwd: Option<PathBuf>,
    command_args: Vec<String>,
    command_fingerprint: String,
}

impl ProcIdentity {
    fn command(&self) -> String {
        if self.command_args.is_empty() {
            self.comm.clone()
        } else {
            redact_command(&self.command_args).join(" ")
        }
    }

    fn command_for_matching(&self) -> String {
        if self.command_args.is_empty() {
            self.comm.clone()
        } else {
            self.command_args.join(" ")
        }
    }

    fn to_registration(&self, kind: &str, workspace_root: &Path) -> AgentRegistration {
        AgentRegistration {
            kind: kind.to_string(),
            pid: self.pid,
            start_time_ticks: self.start_time_ticks,
            workspace_root: workspace_root.to_path_buf(),
            executable: if self.executable.is_empty() {
                self.comm.clone()
            } else {
                self.executable.clone()
            },
            command_fingerprint: self.command_fingerprint.clone(),
            command: Some(self.command()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AgentDiscoveryCandidate {
    identity: ProcIdentity,
    score: u32,
}

impl AgentDiscoveryCandidate {
    fn summary(&self) -> String {
        format!(
            "pid={},score={},executable={},command={}",
            self.identity.pid,
            self.score,
            self.identity.executable,
            self.identity.command()
        )
    }
}

fn read_proc_identities(proc_root: &Path) -> Result<Vec<ProcIdentity>, String> {
    let entries = fs::read_dir(proc_root)
        .map_err(|error| format!("failed to scan proc root {}: {error}", proc_root.display()))?;
    let mut identities = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Some(stat) = read_proc_stat(proc_root, pid) else {
            continue;
        };
        let Some(ppid) = parse_proc_stat_ppid(&stat) else {
            continue;
        };
        let Some(start_time_ticks) = parse_proc_stat_start_time_ticks(&stat) else {
            continue;
        };
        let comm = parse_proc_stat_comm(&stat).unwrap_or_else(|| pid.to_string());
        let command_args = read_proc_cmdline(proc_root, pid);
        let executable = fs::read_link(proc_root.join(pid.to_string()).join("exe"))
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let cwd = fs::read_link(proc_root.join(pid.to_string()).join("cwd")).ok();
        let fingerprint_input = if command_args.is_empty() {
            comm.as_bytes().to_vec()
        } else {
            command_args.join("\0").into_bytes()
        };
        identities.push(ProcIdentity {
            pid,
            ppid,
            start_time_ticks,
            comm,
            executable,
            cwd,
            command_args,
            command_fingerprint: command_fingerprint(&fingerprint_input),
        });
    }
    Ok(identities)
}

fn score_discovery_candidate(
    identity: &ProcIdentity,
    by_pid: &BTreeMap<u32, ProcIdentity>,
    kind: &str,
    session_id: &str,
    workspace_root: &Path,
) -> u32 {
    let kind = kind.to_ascii_lowercase();
    let executable = identity.executable.to_ascii_lowercase();
    let command = identity.command_for_matching();
    let command_lower = command.to_ascii_lowercase();
    let comm = identity.comm.to_ascii_lowercase();
    let workspace = workspace_root.display().to_string();
    let workspace_match = identity.cwd.as_deref() == Some(workspace_root)
        || (!workspace.is_empty() && command.contains(&workspace));
    let session_match = !session_id.is_empty() && command.contains(session_id);
    let executable_kind_match = !identity.executable.is_empty() && executable.contains(&kind);
    let command_kind_match = command_lower.contains(&kind) || comm.contains(&kind);
    let parent_chain_kind_match = parent_chain_contains_kind(identity, by_pid, &kind);

    if !(executable_kind_match
        || command_kind_match
        || (workspace_match && session_match)
        || parent_chain_kind_match)
    {
        return 0;
    }

    let mut score = 0;
    if executable_kind_match {
        score += 4;
    }
    if command_kind_match {
        score += 3;
    }
    if workspace_match {
        score += 2;
    }
    if session_match {
        score += 2;
    }
    if parent_chain_kind_match {
        score += 1;
    }
    score
}

fn parent_chain_contains_kind(
    identity: &ProcIdentity,
    by_pid: &BTreeMap<u32, ProcIdentity>,
    kind: &str,
) -> bool {
    let mut ppid = identity.ppid;
    let mut visited = BTreeSet::new();
    while ppid != 0 && visited.insert(ppid) {
        let Some(parent) = by_pid.get(&ppid) else {
            return false;
        };
        let executable = parent.executable.to_ascii_lowercase();
        let command = parent.command_for_matching().to_ascii_lowercase();
        let comm = parent.comm.to_ascii_lowercase();
        if executable.contains(kind) || command.contains(kind) || comm.contains(kind) {
            return true;
        }
        ppid = parent.ppid;
    }
    false
}

fn read_proc_stat(proc_root: &Path, pid: u32) -> Option<String> {
    fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()
}

fn read_proc_cmdline(proc_root: &Path, pid: u32) -> Vec<String> {
    let bytes = fs::read(proc_root.join(pid.to_string()).join("cmdline")).unwrap_or_default();
    bytes
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .filter_map(|value| String::from_utf8(value.to_vec()).ok())
        .collect()
}

fn parse_proc_stat_comm(stat: &str) -> Option<String> {
    let start = stat.find(" (")? + 2;
    let end = stat.rfind(") ")?;
    stat.get(start..end).map(ToString::to_string)
}

fn parse_proc_stat_start_time_ticks(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn command_fingerprint_from_args(args: &[String]) -> String {
    command_fingerprint(args.join("\0").as_bytes())
}

fn command_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::from("sha256:");
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn live_scope_requirement() -> String {
    "live observer requires exactly one of --scope-cgroup, --scope-pid, --agent-run, --agent-registration, or --agent-discover".to_string()
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
            redacted.push(shell_display_arg(&redact_command_credential_paths(arg)));
        }
    }
    redacted
}

/// Replace credential-file tokens (`~/.aws/...`, `.env`, `/var/run/secrets/...`)
/// inside a launch argv element with a placeholder, so a `bash -c "<script>"`
/// command cannot leak a credential path into agent-command metadata.
//
// ponytail: credential-paths only. The launch command is operator-authored, so
// non-credential paths stay readable; observed side effects use the stricter
// session-salted Redactor.
fn redact_command_credential_paths(arg: &str) -> String {
    if !arg.contains('/') {
        return arg.to_string();
    }
    let mut redacted = false;
    let tokens: Vec<String> = arg
        .split_whitespace()
        .map(|token| {
            let core =
                token.trim_matches(|ch| matches!(ch, '\'' | '"' | '`' | ';' | ',' | '(' | ')'));
            if looks_like_credential_path(core) {
                redacted = true;
                "<credential-path>".to_string()
            } else {
                token.to_string()
            }
        })
        .collect();
    if redacted {
        tokens.join(" ")
    } else {
        arg.to_string()
    }
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
    if let Some(command) = canonical.process_command.as_deref() {
        let (command, _) = redact_process_command_for_persistence(
            command,
            canonical.process_executable.as_deref(),
            redactor,
        );
        persisted_canonical.process_command = Some(command);
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

fn redact_process_command_for_persistence(
    command: &str,
    executable: Option<&str>,
    redactor: &Redactor,
) -> (String, bool) {
    let mut redacted = false;
    let mut redact_next = false;
    let mut args = Vec::new();
    for (index, arg) in command.split_whitespace().enumerate() {
        if index == 0 && executable == Some(arg) {
            args.push(arg.to_string());
            continue;
        }

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

    (args.join(" "), redacted)
}

fn redact_argv_resource(value: &str, redactor: &Redactor) -> (String, bool) {
    if let Some(resource) = network_argument_resource(value) {
        let redacted =
            redactor.redact_resource(apolysis_core::EventType::NetworkConnect, &resource);
        return (redacted.value, redacted.redacted);
    }
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

fn network_argument_resource(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(|ch| matches!(ch, '\'' | '"' | ',' | ';'));
    if trimmed.parse::<SocketAddr>().is_ok() {
        return Some(trimmed.to_string());
    }

    let ip = trimmed.trim_start_matches('[').trim_end_matches(']');
    ip.parse::<IpAddr>().ok().map(|_| ip.to_string())
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
    use std::os::unix::fs::symlink;

    #[test]
    fn agent_command_metadata_redacts_credential_paths_in_shell_scripts() {
        let request = AgentRunRequest::new(
            "bash",
            vec![
                "bash".to_string(),
                "-c".to_string(),
                "cat /tmp/demo-home/.aws/credentials && echo done".to_string(),
            ],
        )
        .unwrap();
        let command = request.redacted_command();
        assert!(
            !command.contains("/tmp/demo-home/.aws/credentials"),
            "raw credential path leaked into agent-command metadata: {command}"
        );
        assert!(command.contains("<credential-path>"), "got: {command}");
        // Non-credential structure stays readable.
        assert!(command.contains("bash -c"), "got: {command}");
        assert!(command.contains("echo done"), "got: {command}");
    }

    #[test]
    fn agent_command_metadata_keeps_ordinary_executable_paths() {
        let request = AgentRunRequest::new(
            "codex",
            vec![
                "/usr/bin/codex".to_string(),
                "exec".to_string(),
                "--json".to_string(),
            ],
        )
        .unwrap();
        let command = request.redacted_command();
        assert!(command.contains("/usr/bin/codex"), "got: {command}");
        assert!(!command.contains("<credential-path>"), "got: {command}");
    }

    #[tokio::test]
    async fn managed_agent_waits_for_gate_release_before_running() {
        let marker = std::env::temp_dir().join(format!(
            "apolysis-gate-test-{}-{}.marker",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&marker);
        let request = AgentRunRequest::new(
            "sh",
            vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("echo ran > {}", marker.display()),
            ],
        )
        .unwrap();

        let mut managed = spawn_managed_agent(&request, Path::new(".")).unwrap();
        // The child is blocked in pre_exec before running the workload.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !marker.exists(),
            "workload ran before the observer released the gate"
        );

        managed.release_gate();
        let status = managed.child.wait().await.unwrap();
        assert!(
            status.success(),
            "workload exited unsuccessfully: {status:?}"
        );
        assert!(
            marker.exists(),
            "workload did not run after the gate was released"
        );
        let _ = std::fs::remove_file(&marker);
    }

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
    fn managed_agent_run_as_uses_sudo_operator_identity_for_root_observer() {
        let env = BTreeMap::from([
            ("SUDO_UID", "1000"),
            ("SUDO_GID", "1001"),
            ("HOME", "/home/operator"),
            ("CODEX_HOME", "/home/operator/.codex"),
        ]);

        let run_as =
            managed_agent_run_as_from_env(0, |key| env.get(key).map(|value| value.to_string()));

        assert_eq!(
            run_as,
            Some(ManagedAgentRunAs {
                uid: 1000,
                gid: 1001,
                home: Some("/home/operator".to_string()),
                codex_home: Some("/home/operator/.codex".to_string()),
            })
        );
    }

    #[test]
    fn managed_agent_run_as_is_disabled_without_non_root_sudo_identity() {
        let non_root_env = BTreeMap::from([("SUDO_UID", "1000"), ("SUDO_GID", "1001")]);
        assert_eq!(
            managed_agent_run_as_from_env(1000, |key| {
                non_root_env.get(key).map(|value| value.to_string())
            }),
            None
        );

        let root_sudo_env = BTreeMap::from([("SUDO_UID", "0"), ("SUDO_GID", "0")]);
        assert_eq!(
            managed_agent_run_as_from_env(0, |key| {
                root_sudo_env.get(key).map(|value| value.to_string())
            }),
            None
        );

        let incomplete_env = BTreeMap::from([("SUDO_UID", "1000")]);
        assert_eq!(
            managed_agent_run_as_from_env(0, |key| {
                incomplete_env.get(key).map(|value| value.to_string())
            }),
            None
        );
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
            "argv:/usr/bin/codex exec --api-key sk-test-secret /workspace/.env /workspace/src/main.rs 127.0.0.1",
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
        assert!(persisted_raw.raw_payload.contains("address_token:"));
        assert!(persisted_raw.raw_payload.contains("/workspace/src/main.rs"));
        assert!(persisted_raw.raw_payload.contains("redacted:payload"));
        assert!(!persisted_raw.raw_payload.contains("sk-test-secret"));
        assert!(!persisted_raw.raw_payload.contains("/workspace/.env"));
        assert!(!persisted_raw.raw_payload.contains("127.0.0.1"));
    }

    #[test]
    fn persisted_process_command_redacts_argv_credentials_and_sensitive_paths() {
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
            "argv:/usr/bin/codex exec --api-key sk-test-secret /workspace/.env /workspace/src/main.rs 127.0.0.1",
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
        )
        .with_process_context(
            "/usr/bin/codex exec --api-key sk-test-secret /workspace/.env /workspace/src/main.rs 127.0.0.1",
            "/usr/bin/codex",
            1,
        );
        let redactor = crate::Redactor::new("session-a", "/workspace");

        let (_persisted_raw, persisted_canonical) =
            redact_for_persistence(&raw, &canonical, &redactor);

        let process_command = persisted_canonical
            .process_command
            .as_deref()
            .expect("process command");
        assert!(process_command.starts_with("/usr/bin/codex exec --api-key <redacted>"));
        assert!(process_command.contains("--api-key <redacted>"));
        assert!(process_command.contains("path_token:"));
        assert!(process_command.contains("address_token:"));
        assert!(process_command.contains("/workspace/src/main.rs"));
        assert!(!process_command.contains("sk-test-secret"));
        assert!(!process_command.contains("/workspace/.env"));
        assert!(!process_command.contains("127.0.0.1"));
    }

    #[test]
    fn process_context_enriches_exec_and_exit_before_cleanup() {
        let policy = apolysis_policy::Policy::default();
        let mut contexts = crate::process_context::ProcessContextTable::default();
        let exec_raw = RawKernelEvent::new(
            1_780_328_000_004,
            "session-a",
            EventSource::KernelTracepoint,
            "sched_process_exec",
            44,
            40,
            1000,
            1000,
            "sed",
            "/usr/bin/sed",
            "exec",
            None,
            Some("901".to_string()),
            "argv:/usr/bin/sed -n 1,5p README.md",
        )
        .with_event_id("raw-exec");

        let exec_event = contexts.observe(&exec_raw, canonicalize(&exec_raw, &policy));

        assert_eq!(
            exec_event.process_command.as_deref(),
            Some("/usr/bin/sed -n 1,5p README.md")
        );
        assert_eq!(
            exec_event.process_executable.as_deref(),
            Some("/usr/bin/sed")
        );
        assert_eq!(
            exec_event.process_started_at_unix_ms,
            Some(1_780_328_000_004)
        );

        let exit_raw = RawKernelEvent::new(
            1_780_328_000_123,
            "session-a",
            EventSource::KernelTracepoint,
            "sched_process_exit",
            44,
            40,
            1000,
            1000,
            "sed",
            "",
            "exit",
            None,
            Some("901".to_string()),
            "",
        )
        .with_event_id("raw-exit");

        let exit_event = contexts.observe(&exit_raw, canonicalize(&exit_raw, &policy));

        assert_eq!(
            exit_event.process_command.as_deref(),
            Some("/usr/bin/sed -n 1,5p README.md")
        );
        assert_eq!(
            exit_event.process_executable.as_deref(),
            Some("/usr/bin/sed")
        );
        assert_eq!(
            exit_event.process_started_at_unix_ms,
            Some(1_780_328_000_004)
        );

        let stale_raw = RawKernelEvent::new(
            1_780_328_000_124,
            "session-a",
            EventSource::KernelTracepoint,
            "openat",
            44,
            40,
            1000,
            1000,
            "sed",
            "README.md",
            "read",
            None,
            Some("901".to_string()),
            "",
        );

        let stale_event = contexts.observe(&stale_raw, canonicalize(&stale_raw, &policy));

        assert_eq!(stale_event.process_command, None);
        assert_eq!(stale_event.process_executable, None);
        assert_eq!(stale_event.process_started_at_unix_ms, None);
    }

    #[test]
    fn agent_registration_rejects_pid_reuse_by_start_time() {
        let proc_root = temp_proc_root("agent-registration-reuse");
        write_fake_proc(
            &proc_root,
            FakeProc {
                pid: 101,
                ppid: 1,
                start_time_ticks: 9_001,
                comm: "codex",
                executable: "/usr/bin/codex",
                cwd: "/workspace/apolysis",
                argv: &["codex", "resume", "session-a"],
            },
        );
        let registration = AgentRegistration {
            kind: "codex".to_string(),
            pid: 101,
            start_time_ticks: 9_999,
            workspace_root: PathBuf::from("/workspace/apolysis"),
            executable: "/usr/bin/codex".to_string(),
            command_fingerprint: "sha256:test".to_string(),
            command: None,
        };

        let error = registration
            .validate_proc_identity(&proc_root)
            .expect_err("registration with stale start time must fail closed");

        assert!(error.contains("PID reuse"));
        assert!(error.contains("pid=101"));
        assert!(error.contains("expected_start_time_ticks=9999"));
        assert!(error.contains("actual_start_time_ticks=9001"));

        let _ = std::fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn agent_discovery_fails_closed_on_ambiguous_candidates() {
        let proc_root = temp_proc_root("agent-discovery-ambiguous");
        for pid in [201, 202] {
            write_fake_proc(
                &proc_root,
                FakeProc {
                    pid,
                    ppid: 1,
                    start_time_ticks: 7_000 + pid as u64,
                    comm: "codex",
                    executable: "/usr/bin/codex",
                    cwd: "/workspace/apolysis",
                    argv: &["codex", "resume", "session-a"],
                },
            );
        }
        let request = AgentDiscoveryRequest::new("codex").expect("discovery request");

        let error = discover_agent_registration(
            &request,
            &proc_root,
            "session-a",
            Path::new("/workspace/apolysis"),
        )
        .expect_err("ambiguous discovery must fail closed");

        assert!(error.contains("agent discovery is ambiguous"));
        assert!(error.contains("pid=201"));
        assert!(error.contains("pid=202"));

        let _ = std::fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn agent_discovery_selects_unique_highest_scored_candidate() {
        let proc_root = temp_proc_root("agent-discovery-unique");
        write_fake_proc(
            &proc_root,
            FakeProc {
                pid: 301,
                ppid: 1,
                start_time_ticks: 8_001,
                comm: "codex",
                executable: "/usr/bin/codex",
                cwd: "/workspace/apolysis",
                argv: &["codex", "resume", "session-target"],
            },
        );
        write_fake_proc(
            &proc_root,
            FakeProc {
                pid: 302,
                ppid: 1,
                start_time_ticks: 8_002,
                comm: "codex",
                executable: "/usr/bin/codex",
                cwd: "/tmp/other",
                argv: &["codex", "resume", "other-session"],
            },
        );
        let request = AgentDiscoveryRequest::new("codex").expect("discovery request");

        let registration = discover_agent_registration(
            &request,
            &proc_root,
            "session-target",
            Path::new("/workspace/apolysis"),
        )
        .expect("unique discovery candidate");

        assert_eq!(registration.pid, 301);
        assert_eq!(registration.start_time_ticks, 8_001);
        assert_eq!(
            registration.workspace_root,
            PathBuf::from("/workspace/apolysis")
        );
        assert_eq!(registration.executable, "/usr/bin/codex");
        assert!(registration.command_fingerprint.starts_with("sha256:"));
        assert_eq!(
            registration.command.as_deref(),
            Some("codex resume session-target")
        );

        let _ = std::fs::remove_dir_all(&proc_root);
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
            agent_registration_path: None,
            agent_discovery: None,
            duration: None,
            workspace_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            output_rotation: None,
        };

        assert_eq!(
            request.validate(),
            Err("--agent-run cannot be combined with --scope-pid or --scope-cgroup".to_string())
        );
    }

    struct FakeProc<'a> {
        pid: u32,
        ppid: u32,
        start_time_ticks: u64,
        comm: &'a str,
        executable: &'a str,
        cwd: &'a str,
        argv: &'a [&'a str],
    }

    fn temp_proc_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("apolysis-{name}-{}", std::process::id()))
    }

    fn write_fake_proc(proc_root: &Path, process: FakeProc<'_>) {
        let pid_root = proc_root.join(process.pid.to_string());
        std::fs::create_dir_all(&pid_root).expect("create fake proc pid");
        std::fs::write(
            pid_root.join("stat"),
            fake_proc_stat(
                process.pid,
                process.ppid,
                process.comm,
                process.start_time_ticks,
            ),
        )
        .expect("write fake proc stat");
        std::fs::write(pid_root.join("cmdline"), process.argv.join("\0"))
            .expect("write fake proc cmdline");
        symlink(process.executable, pid_root.join("exe")).expect("fake proc exe symlink");
        symlink(process.cwd, pid_root.join("cwd")).expect("fake proc cwd symlink");
    }

    fn fake_proc_stat(pid: u32, ppid: u32, comm: &str, start_time_ticks: u64) -> String {
        format!(
            "{pid} ({comm}) S {ppid} 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 {start_time_ticks} 0 0\n"
        )
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_core::{
    actors, new_collector_instance_id, resources, CanonicalEvent, CollectorFailureReason,
    CollectorLifecycleCounters, CollectorLifecycleRecord, CollectorNormalStopReason, EventSource,
    EventType, JsonLine, ObservationGap, ObservationGapKind, ObserverDiagnostic,
    ObserverDiagnosticKind, OperationOutcome, OperationResult, RawKernelEvent,
};
use apolysis_store::JsonlRotationPolicy;
use apolysis_store::JsonlStore;
use aya::maps::{Array, HashMap, Map, MapData, MapError, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader, Pod};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::process::Child;

const LIVE_COLLECTOR_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

use crate::abi::{
    FileOperationCountersAbi, KernelEventKind, KernelEventRecord, NetworkConnectCountersAbi,
    ObserverCountersAbi, OperationPairCountersAbi, TrackedCgroupScopeAbi, TrackedCgroupState,
    TrackedProcessIdentityAbi, FLAG_ARGV_TRUNCATED, FLAG_PAYLOAD_SOCKADDR, FLAG_PAYLOAD_TRUNCATED,
    FLAG_RESOURCE_TRUNCATED,
};
use crate::capabilities::validate_live_prerequisites;
use crate::process_context::ProcessContextTable;
use crate::{
    audit_observer_capability_manifest, canonicalize, write_observer_metadata, AyaLoaderPlan,
    EventIdSequence, ObserveResult, ObserverBackend, ObserverMode, ObserverRunnerPlan, Redactor,
    RuntimeEvidencePersistence,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessRuntimeIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessLineageIdentity {
    runtime: ProcessRuntimeIdentity,
    ppid: u32,
    tgid: u32,
}

#[derive(Debug)]
struct AnchoredProcessIdentity {
    lineage: ProcessLineageIdentity,
    pidfd: OwnedFd,
}

impl ProcessRuntimeIdentity {
    pub fn new(pid: u32, start_time_ticks: u64) -> Result<Self, String> {
        if pid == 0 {
            return Err("process runtime identity PID must be non-zero".to_string());
        }
        Ok(Self {
            pid,
            start_time_ticks,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartBoottimeWindow {
    pub lower_ns: u64,
    pub upper_ns: u64,
}

impl StartBoottimeWindow {
    pub fn new(lower_ns: u64, upper_ns: u64) -> Result<Self, String> {
        if lower_ns >= upper_ns {
            return Err("process start boottime window must be non-empty".to_string());
        }
        Ok(Self { lower_ns, upper_ns })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcStartClock {
    tick_ns: u64,
}

impl ProcStartClock {
    pub fn new(ticks_per_second: u64) -> Result<Self, String> {
        const NSEC_PER_SEC: u64 = 1_000_000_000;
        if ticks_per_second == 0 {
            return Err("proc clock ticks per second must be non-zero".to_string());
        }
        if !NSEC_PER_SEC.is_multiple_of(ticks_per_second) {
            return Err(format!(
                "proc clock rate {ticks_per_second} does not divide one second into integral nanoseconds"
            ));
        }
        Ok(Self {
            tick_ns: NSEC_PER_SEC / ticks_per_second,
        })
    }

    pub fn host() -> Result<Self, String> {
        let offsets = fs::read_to_string("/proc/self/timens_offsets")
            .map_err(|_| "failed to read observer time namespace offsets".to_string())?;
        validate_initial_time_namespace_offsets(&offsets)?;
        // SAFETY: sysconf reads a process-wide immutable clock conversion value.
        let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks_per_second <= 0 {
            return Err("failed to read the host proc clock rate".to_string());
        }
        Self::new(ticks_per_second as u64)
    }

    pub fn start_boottime_window(
        self,
        identity: ProcessRuntimeIdentity,
    ) -> Result<StartBoottimeWindow, String> {
        let lower_ns = identity
            .start_time_ticks
            .checked_mul(self.tick_ns)
            .ok_or_else(|| "process start boottime lower bound overflowed".to_string())?;
        let upper_ns = identity
            .start_time_ticks
            .checked_add(1)
            .and_then(|ticks| ticks.checked_mul(self.tick_ns))
            .ok_or_else(|| "process start boottime upper bound overflowed".to_string())?;
        StartBoottimeWindow::new(lower_ns, upper_ns)
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

pub fn discover_process_tree_scope_identities(
    root_pid: u32,
    proc_root: impl AsRef<Path>,
) -> Result<Vec<ProcessRuntimeIdentity>, String> {
    Ok(discover_process_tree_scope_lineages(root_pid, proc_root)?
        .into_iter()
        .map(|identity| identity.runtime)
        .collect())
}

fn discover_process_tree_scope_lineages(
    root_pid: u32,
    proc_root: impl AsRef<Path>,
) -> Result<Vec<ProcessLineageIdentity>, String> {
    let proc_root = proc_root.as_ref();
    let root = read_process_lineage_identity_at(proc_root, root_pid).ok_or_else(|| {
        format!("process-tree root runtime identity is unavailable: pid={root_pid}")
    })?;
    if root.tgid != root_pid {
        return Err(format!(
            "process-tree root must identify a thread-group leader: pid={root_pid},tgid={}",
            root.tgid
        ));
    }

    let entries = fs::read_dir(proc_root)
        .map_err(|error| format!("failed to scan process identities: {error}"))?;
    let mut snapshot = BTreeMap::new();
    for entry in entries.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let Some(identity) = read_process_lineage_identity_at(proc_root, pid) else {
            continue;
        };
        if identity.tgid == pid {
            snapshot.insert(pid, identity);
        }
    }
    snapshot.insert(root_pid, root);

    let mut children_by_parent = BTreeMap::<u32, Vec<ProcessLineageIdentity>>::new();
    for identity in snapshot.values().copied() {
        if identity.runtime.pid != root_pid {
            children_by_parent
                .entry(identity.ppid)
                .or_default()
                .push(identity);
        }
    }

    let mut accepted = BTreeMap::from([(root_pid, root)]);
    let mut pending = VecDeque::from([root_pid]);
    while let Some(parent_pid) = pending.pop_front() {
        let Some(expected_parent) = accepted.get(&parent_pid).copied() else {
            continue;
        };
        let Some(actual_parent) = read_process_lineage_identity_at(proc_root, parent_pid) else {
            continue;
        };
        if actual_parent.runtime != expected_parent.runtime || actual_parent.tgid != parent_pid {
            continue;
        }
        for candidate in children_by_parent.get(&parent_pid).into_iter().flatten() {
            let pid = candidate.runtime.pid;
            if accepted.contains_key(&pid) {
                continue;
            }
            let Some(actual) = read_process_lineage_identity_at(proc_root, pid) else {
                continue;
            };
            if actual != *candidate || actual.tgid != pid {
                continue;
            }
            accepted.insert(pid, actual);
            pending.push_back(pid);
        }
    }

    let final_root = read_process_lineage_identity_at(proc_root, root_pid).ok_or_else(|| {
        format!("process-tree root runtime identity is unavailable: pid={root_pid}")
    })?;
    if final_root.runtime != root.runtime || final_root.tgid != root_pid {
        return Err("process-tree root identity changed during lineage snapshot".to_string());
    }

    Ok(accepted.into_values().collect())
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
    pub host_boot_id: String,
    pub workspace_root: PathBuf,
    pub executable: String,
    pub command_fingerprint: String,
    #[serde(default)]
    pub command: Option<String>,
}

impl AgentRegistration {
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let input = fs::read_to_string(path)
            .map_err(|error| format!("failed to read agent registration: {error}"))?;
        let registration = serde_json::from_str::<Self>(&input)
            .map_err(|error| format!("failed to parse agent registration: {error}"))?;
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
        if !valid_host_boot_id(&self.host_boot_id) {
            return Err("agent registration host_boot_id must be a UUID".to_string());
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

    pub fn validate_runtime_identity(
        &self,
        proc_root: impl AsRef<Path>,
        current_host_boot_id: &str,
    ) -> Result<ProcessRuntimeIdentity, String> {
        self.validate()?;
        if !valid_host_boot_id(current_host_boot_id) {
            return Err("current host boot identity is invalid".to_string());
        }
        if !self.host_boot_id.eq_ignore_ascii_case(current_host_boot_id) {
            return Err("agent registration host boot identity mismatch".to_string());
        }
        let actual = read_proc_identity(proc_root.as_ref(), self.pid).ok_or_else(|| {
            format!(
                "agent registration PID identity is unavailable before attach: pid={}",
                self.pid
            )
        })?;
        if actual.start_time_ticks != self.start_time_ticks {
            return Err(format!(
                "agent registration rejected possible PID reuse: pid={},expected_start_time_ticks={},actual_start_time_ticks={}",
                self.pid, self.start_time_ticks, actual.start_time_ticks
            ));
        }
        if actual.executable != self.executable {
            return Err(format!(
                "agent registration executable identity mismatch: pid={}",
                self.pid
            ));
        }
        if actual.command_fingerprint != self.command_fingerprint {
            return Err(format!(
                "agent registration command identity mismatch: pid={}",
                self.pid
            ));
        }
        ProcessRuntimeIdentity::new(self.pid, self.start_time_ticks)
    }

    fn to_metadata(&self, supervisor_mode: impl Into<String>) -> AgentScopeMetadata {
        AgentScopeMetadata {
            supervisor_mode: supervisor_mode.into(),
            kind: self.kind.clone(),
            root_pid: self.pid,
            executable: self.executable.clone(),
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
    pub session_id: String,
    pub scope: Option<LiveScope>,
    pub agent_run: Option<AgentRunRequest>,
    pub agent_registration_path: Option<PathBuf>,
    pub agent_discovery: Option<AgentDiscoveryRequest>,
    pub duration: Option<Duration>,
    pub workspace_root: PathBuf,
    pub output_rotation: Option<JsonlRotationPolicy>,
    /// Optional raw monotonic timing samples for the separate qualification
    /// harness. The production CLI always leaves this disabled.
    pub qualification_telemetry: Option<QualificationTelemetryConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationTelemetryConfig {
    pub output_path: PathBuf,
    pub max_samples: usize,
    pub resource_sample_interval: Duration,
    pub collector_cgroup_path: PathBuf,
    pub managed_agent_cgroup_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct QualificationTelemetrySample {
    event_name: String,
    kernel_timestamp_ns: u64,
    decoded_monotonic_ns: u64,
    appended_monotonic_ns: u64,
}

#[derive(Debug, Serialize)]
struct QualificationResourceSample {
    monotonic_ns: u64,
    process_user_cpu_ns: u64,
    process_system_cpu_ns: u64,
    process_rss_bytes: u64,
    process_peak_rss_bytes: u64,
    collector_cgroup_memory_current_bytes: u64,
    collector_cgroup_memory_peak_bytes: u64,
}

#[derive(Debug, Serialize)]
struct QualificationLossSample {
    monotonic_ns: u64,
    loss_counters: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessMemory {
    rss_bytes: u64,
    peak_rss_bytes: u64,
}

#[derive(Debug)]
struct QualificationTelemetryRecorder {
    max_samples: usize,
    samples: Vec<QualificationTelemetrySample>,
    dropped_samples: u64,
    resource_samples: Vec<QualificationResourceSample>,
    resource_sample_interval_ns: u64,
    resource_sample_gap_limit_ns: u64,
    resource_sample_max_gap_ns: u64,
    loss_samples: Vec<QualificationLossSample>,
    collector_cgroup_path: PathBuf,
    collector_cgroup_isolated: bool,
    bpf_map_memory_bytes: u64,
    bpf_program_memory_bytes: u64,
}

#[derive(Serialize)]
struct QualificationTelemetryReport<'a> {
    schema_version: u32,
    clock: &'static str,
    samples: &'a [QualificationTelemetrySample],
    dropped_samples: u64,
    resource_sample_interval_ns: u64,
    resource_sample_gap_limit_ns: u64,
    resource_sample_max_gap_ns: u64,
    resource_samples: &'a [QualificationResourceSample],
    loss_samples: &'a [QualificationLossSample],
    collector_cgroup_isolated: bool,
    bpf_map_memory_bytes: u64,
    bpf_program_memory_bytes: u64,
}

impl QualificationTelemetryRecorder {
    #[cfg(test)]
    fn empty_for_test(max_samples: usize) -> Self {
        Self {
            max_samples,
            samples: Vec::with_capacity(max_samples),
            dropped_samples: 0,
            resource_samples: Vec::new(),
            resource_sample_interval_ns: 1,
            resource_sample_gap_limit_ns: 4,
            resource_sample_max_gap_ns: 0,
            loss_samples: Vec::new(),
            collector_cgroup_path: PathBuf::new(),
            collector_cgroup_isolated: true,
            bpf_map_memory_bytes: 0,
            bpf_program_memory_bytes: 0,
        }
    }

    fn new(
        max_samples: usize,
        resource_sample_interval: Duration,
        collector_cgroup_path: PathBuf,
        managed_agent_cgroup_path: &Path,
        managed_agent_pid: Option<u32>,
        ebpf: &Ebpf,
    ) -> Result<Self, String> {
        if resource_sample_interval.is_zero() {
            return Err("qualification resource sample interval must be non-zero".to_string());
        }
        verify_qualification_cgroup_isolation(
            &collector_cgroup_path,
            managed_agent_cgroup_path,
            managed_agent_pid.ok_or_else(|| {
                "qualification resource telemetry requires a managed workload".to_string()
            })?,
        )?;
        let (bpf_map_memory_bytes, bpf_program_memory_bytes) = bpf_memory_bytes(ebpf)?;
        let resource_sample_interval_ns = u64::try_from(resource_sample_interval.as_nanos())
            .map_err(|_| "qualification resource sample interval exceeds u64".to_string())?;
        let mut recorder = Self {
            max_samples,
            samples: Vec::with_capacity(max_samples.min(16_384)),
            dropped_samples: 0,
            resource_samples: Vec::new(),
            resource_sample_interval_ns,
            resource_sample_gap_limit_ns: resource_sample_interval_ns.saturating_mul(4),
            resource_sample_max_gap_ns: 0,
            loss_samples: Vec::new(),
            collector_cgroup_path,
            collector_cgroup_isolated: true,
            bpf_map_memory_bytes,
            bpf_program_memory_bytes,
        };
        recorder.record_resource_sample()?;
        Ok(recorder)
    }

    fn record(
        &mut self,
        event_name: &str,
        kernel_timestamp_ns: u64,
        decoded_monotonic_ns: u64,
        appended_monotonic_ns: u64,
    ) {
        if self.samples.len() == self.max_samples {
            self.dropped_samples = self.dropped_samples.saturating_add(1);
            return;
        }
        self.samples.push(QualificationTelemetrySample {
            event_name: event_name.to_string(),
            kernel_timestamp_ns,
            decoded_monotonic_ns,
            appended_monotonic_ns,
        });
    }

    fn report(&self) -> QualificationTelemetryReport<'_> {
        QualificationTelemetryReport {
            schema_version: 1,
            clock: "clock_monotonic",
            samples: &self.samples,
            dropped_samples: self.dropped_samples,
            resource_sample_interval_ns: self.resource_sample_interval_ns,
            resource_sample_gap_limit_ns: self.resource_sample_gap_limit_ns,
            resource_sample_max_gap_ns: self.resource_sample_max_gap_ns,
            resource_samples: &self.resource_samples,
            loss_samples: &self.loss_samples,
            collector_cgroup_isolated: self.collector_cgroup_isolated,
            bpf_map_memory_bytes: self.bpf_map_memory_bytes,
            bpf_program_memory_bytes: self.bpf_program_memory_bytes,
        }
    }

    fn record_resource_sample(&mut self) -> Result<(), String> {
        let monotonic_ns = monotonic_now_ns()?;
        if let Some(previous) = self.resource_samples.last() {
            let gap = monotonic_ns.saturating_sub(previous.monotonic_ns);
            self.resource_sample_max_gap_ns = self.resource_sample_max_gap_ns.max(gap);
            if gap > self.resource_sample_gap_limit_ns {
                return Err(format!(
                    "qualification resource sample gap {gap}ns exceeds {}ns",
                    self.resource_sample_gap_limit_ns
                ));
            }
        }
        let process_cpu = process_cpu_usage()?;
        let process_memory = read_process_memory(Path::new("/proc/self/status"))?;
        let cgroup_current = read_u64_file(&self.collector_cgroup_path.join("memory.current"))?;
        let cgroup_peak = read_u64_file(&self.collector_cgroup_path.join("memory.peak"))?;
        self.resource_samples.push(QualificationResourceSample {
            monotonic_ns,
            process_user_cpu_ns: process_cpu.0,
            process_system_cpu_ns: process_cpu.1,
            process_rss_bytes: process_memory.rss_bytes,
            process_peak_rss_bytes: process_memory.peak_rss_bytes,
            collector_cgroup_memory_current_bytes: cgroup_current,
            collector_cgroup_memory_peak_bytes: cgroup_peak,
        });
        Ok(())
    }

    fn record_loss_sample(&mut self, counters: CollectorLifecycleCounters) -> Result<(), String> {
        let monotonic_ns = self
            .resource_samples
            .last()
            .map(|sample| sample.monotonic_ns)
            .ok_or_else(|| "qualification loss sample has no resource timestamp".to_string())?;
        self.loss_samples.push(QualificationLossSample {
            monotonic_ns,
            loss_counters: qualification_loss_counters(counters, self.dropped_samples),
        });
        Ok(())
    }

    fn persist(&self, path: &Path) -> Result<(), String> {
        let rendered = serde_json::to_string(&self.report())
            .map_err(|error| format!("failed to serialize qualification telemetry: {error}"))?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                format!(
                    "failed to create qualification telemetry {}: {error}",
                    path.display()
                )
            })?;
        file.write_all(format!("{rendered}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                format!(
                    "failed to persist qualification telemetry {}: {error}",
                    path.display()
                )
            })
    }
}

impl LiveObserveRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !self.object_path.is_file() {
            return Err(format!(
                "BPF object does not exist: {}",
                self.object_path.display()
            ));
        }
        if let Some(telemetry) = self.qualification_telemetry.as_ref() {
            if telemetry.max_samples == 0 {
                return Err("qualification telemetry max_samples must be positive".to_string());
            }
            if telemetry.output_path == self.output_path {
                return Err(
                    "qualification telemetry output must differ from the timeline".to_string(),
                );
            }
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
        if matches!(self.scope, Some(LiveScope::ProcessTree(_))) {
            return Err(
                "--scope-pid is not a protected existing-process attach; use --agent-registration, --agent-discover, or --agent-run"
                    .to_string(),
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

#[derive(Clone, Debug)]
struct AgentScopeMetadata {
    supervisor_mode: String,
    kind: String,
    root_pid: u32,
    executable: String,
    workspace_root: String,
    start_time_ticks: Option<u64>,
}

#[derive(Debug)]
struct PreparedExistingProcessAttach {
    registration: AgentRegistration,
    metadata: AgentScopeMetadata,
    workspace_root: PathBuf,
    clock: ProcStartClock,
    root_pidfd: OwnedFd,
    provenance: &'static str,
    root_selection: &'static str,
}

impl PreparedExistingProcessAttach {
    fn prepare(
        registration: AgentRegistration,
        supervisor_mode: &'static str,
        root_selection: &'static str,
        workspace_root: &Path,
        current_host_boot_id: &str,
    ) -> Result<Self, String> {
        let workspace_root =
            validate_workspace_boundary(&registration.workspace_root, workspace_root)?;
        let root_pidfd = open_pidfd(registration.pid)?;
        ensure_pidfd_alive(&root_pidfd)?;
        validate_native_pid_namespace(registration.pid)?;
        validate_same_time_namespace(registration.pid)?;
        validate_process_workspace_boundary_at("/proc", registration.pid, &workspace_root)?;
        let clock = ProcStartClock::host()?;
        let root_identity =
            registration.validate_runtime_identity("/proc", current_host_boot_id)?;
        let identities = discover_process_tree_scope_identities(registration.pid, "/proc")?;
        if identities
            .iter()
            .find(|identity| identity.pid == registration.pid)
            .copied()
            != Some(root_identity)
        {
            return Err("process-tree root identity changed during attach preparation".to_string());
        }
        ensure_pidfd_alive(&root_pidfd)?;
        let metadata = registration.to_metadata(supervisor_mode);
        Ok(Self {
            registration,
            metadata,
            workspace_root,
            clock,
            root_pidfd,
            provenance: supervisor_mode,
            root_selection,
        })
    }

    fn root_pid(&self) -> u32 {
        self.registration.pid
    }

    fn validate_root(&self, current_host_boot_id: &str) -> Result<(), String> {
        ensure_pidfd_alive(&self.root_pidfd)?;
        validate_native_pid_namespace(self.registration.pid)?;
        validate_same_time_namespace(self.registration.pid)?;
        validate_process_workspace_boundary_at(
            "/proc",
            self.registration.pid,
            &self.workspace_root,
        )?;
        self.registration
            .validate_runtime_identity("/proc", current_host_boot_id)?;
        ensure_pidfd_alive(&self.root_pidfd)?;
        Ok(())
    }

    fn late_attach_detail(&self) -> String {
        format!(
            "collection_boundary:protected_existing_process_attach,history:unknown,provenance:{},root_selection:{}",
            self.provenance, self.root_selection
        )
    }
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
    pub host_boot_id: Option<String>,
    pub record: KernelEventRecord,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaemonObserverBatch {
    pub events: Vec<DaemonKernelEvent>,
    pub abi_mismatches: u64,
    pub decode_failures: u64,
    pub truncations: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaemonObserverCounters {
    pub reserve_failures: u64,
    pub map_pressure: u64,
    pub connect_missing_entries: u64,
    pub connect_missing_exits: u64,
    pub connect_pending: u64,
    pub file_operations: FileOperationCounters,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetworkConnectCounters {
    pub missing_entries: u64,
    pub missing_exits: u64,
    pub pending: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationPairCounters {
    pub missing_entries: u64,
    pub missing_exits: u64,
    pub pending: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileOperationCounters {
    pub open: OperationPairCounters,
    pub create: OperationPairCounters,
    pub truncate: OperationPairCounters,
    pub unlink: OperationPairCounters,
    pub rename: OperationPairCounters,
}

impl FileOperationCounters {
    fn totals(&self) -> OperationPairCounters {
        [
            self.open,
            self.create,
            self.truncate,
            self.unlink,
            self.rename,
        ]
        .into_iter()
        .fold(OperationPairCounters::default(), |totals, counters| {
            OperationPairCounters {
                missing_entries: totals
                    .missing_entries
                    .saturating_add(counters.missing_entries),
                missing_exits: totals.missing_exits.saturating_add(counters.missing_exits),
                pending: totals.pending.saturating_add(counters.pending),
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScopeObservationGapCounters {
    pub network_connect: NetworkConnectCounters,
    pub file_operations: FileOperationCounters,
}

pub fn network_connect_observation_gaps(
    agent_run_id: &str,
    counters: &NetworkConnectCounters,
) -> Vec<ObservationGap> {
    operation_pair_observation_gaps(
        agent_run_id,
        "network_connect",
        "connect",
        &OperationPairCounters {
            missing_entries: counters.missing_entries,
            missing_exits: counters.missing_exits,
            pending: counters.pending,
        },
    )
}

pub fn file_operation_observation_gaps(
    agent_run_id: &str,
    counters: &FileOperationCounters,
) -> Vec<ObservationGap> {
    [
        ("file_open", "open", &counters.open),
        ("file_create", "create", &counters.create),
        ("file_truncate", "truncate", &counters.truncate),
        ("file_unlink", "unlink", &counters.unlink),
        ("file_rename", "rename", &counters.rename),
    ]
    .into_iter()
    .flat_map(|(operation, subject, counters)| {
        operation_pair_observation_gaps(agent_run_id, operation, subject, counters)
    })
    .collect()
}

pub fn scope_observation_gaps(
    agent_run_id: &str,
    counters: &ScopeObservationGapCounters,
) -> Vec<ObservationGap> {
    let mut gaps = network_connect_observation_gaps(agent_run_id, &counters.network_connect);
    gaps.extend(file_operation_observation_gaps(
        agent_run_id,
        &counters.file_operations,
    ));
    gaps
}

fn operation_pair_observation_gaps(
    agent_run_id: &str,
    operation: &str,
    subject: &str,
    counters: &OperationPairCounters,
) -> Vec<ObservationGap> {
    let mut gaps = Vec::new();
    if counters.missing_entries > 0 {
        gaps.push(ObservationGap::new(
            agent_run_id,
            operation,
            ObservationGapKind::MissingEntry,
            counters.missing_entries,
            format!("{subject} exits observed without matching entries"),
        ));
    }
    let missing_exits = counters.missing_exits.saturating_add(counters.pending);
    if missing_exits > 0 {
        gaps.push(ObservationGap::new(
            agent_run_id,
            operation,
            ObservationGapKind::MissingExit,
            missing_exits,
            format!(
                "kernel_reported:{},pending_at_stop:{}",
                counters.missing_exits, counters.pending
            ),
        ));
    }
    gaps
}

pub struct DaemonObserver {
    ebpf: Ebpf,
    ring: AsyncFd<RingBuf<MapData>>,
    decoder: ObserverBatchDecoder,
    scope_generations: ScopeGenerationSequence,
    active_scope_generations: BTreeMap<u64, ScopeGeneration>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScopeGeneration(u64);

impl ScopeGeneration {
    pub fn new(generation: u64) -> Result<Self, String> {
        if generation == 0 {
            return Err("cgroup scope generation must be non-zero".to_string());
        }
        Ok(Self(generation))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
struct ScopeGenerationSequence {
    next: u64,
}

impl Default for ScopeGenerationSequence {
    fn default() -> Self {
        Self { next: 1 }
    }
}

impl ScopeGenerationSequence {
    fn allocate(&mut self) -> Result<ScopeGeneration, String> {
        let generation = ScopeGeneration::new(self.next)?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| "cgroup scope generation exhausted".to_string())?;
        Ok(generation)
    }
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
            scope_generations: ScopeGenerationSequence::default(),
            active_scope_generations: BTreeMap::new(),
        })
    }

    pub fn track_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeGeneration, String> {
        if let Some(generation) = self.active_scope_generations.get(&cgroup_id) {
            return Ok(*generation);
        }
        let generation = self.scope_generations.allocate()?;
        track_cgroup_with_observation_counters(&mut self.ebpf, cgroup_id, generation)?;
        self.active_scope_generations.insert(cgroup_id, generation);
        Ok(generation)
    }

    pub fn untrack_cgroup(
        &mut self,
        cgroup_id: u64,
    ) -> Result<ScopeObservationGapCounters, String> {
        let generation = self
            .active_scope_generations
            .get(&cgroup_id)
            .copied()
            .ok_or_else(|| format!("cgroup observer scope {cgroup_id} is not tracked"))?;
        let counters = drain_tracked_cgroup(&mut self.ebpf, cgroup_id, generation)?;
        self.active_scope_generations.remove(&cgroup_id);
        Ok(counters)
    }

    pub fn scope_counters(
        &mut self,
        cgroup_id: u64,
    ) -> Result<ScopeObservationGapCounters, String> {
        let generation = self
            .active_scope_generations
            .get(&cgroup_id)
            .copied()
            .ok_or_else(|| format!("cgroup observer scope {cgroup_id} is not tracked"))?;
        snapshot_tracked_cgroup(&mut self.ebpf, cgroup_id, generation)
    }

    pub async fn read_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        let records = read_ring_batch(&mut self.ring).await?;
        Ok(self.decoder.decode(records))
    }

    pub fn drain_batch(&mut self) -> DaemonObserverBatch {
        self.decoder.decode(drain_ring_batch_now(&mut self.ring))
    }

    pub fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        Ok(read_observer_counters(&mut self.ebpf)?.into())
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

const SCOPE_MODE_INACTIVE: u32 = 0;
const SCOPE_MODE_CGROUP: u32 = 1;
const SCOPE_MODE_PID_TREE: u32 = 2;
const SCOPE_MODE_PID_TREE_SEEDING: u32 = 4;
impl From<NetworkConnectCountersAbi> for NetworkConnectCounters {
    fn from(counters: NetworkConnectCountersAbi) -> Self {
        Self {
            missing_entries: counters.missing_entries,
            missing_exits: counters.missing_exits,
            pending: counters.pending,
        }
    }
}

impl From<OperationPairCountersAbi> for OperationPairCounters {
    fn from(counters: OperationPairCountersAbi) -> Self {
        Self {
            missing_entries: counters.missing_entries,
            missing_exits: counters.missing_exits,
            pending: counters.pending,
        }
    }
}

impl From<FileOperationCountersAbi> for FileOperationCounters {
    fn from(counters: FileOperationCountersAbi) -> Self {
        Self {
            open: counters.open.into(),
            create: counters.create.into(),
            truncate: counters.truncate.into(),
            unlink: counters.unlink.into(),
            rename: counters.rename.into(),
        }
    }
}

impl From<ObserverCountersAbi> for DaemonObserverCounters {
    fn from(counters: ObserverCountersAbi) -> Self {
        Self {
            reserve_failures: counters.reserve_failures,
            map_pressure: counters.map_pressure,
            connect_missing_entries: counters.connect_missing_entries,
            connect_missing_exits: counters.connect_missing_exits,
            connect_pending: counters.connect_pending,
            file_operations: counters.file_operations.into(),
        }
    }
}

impl From<DaemonObserverCounters> for NetworkConnectCounters {
    fn from(counters: DaemonObserverCounters) -> Self {
        Self {
            missing_entries: counters.connect_missing_entries,
            missing_exits: counters.connect_missing_exits,
            pending: counters.connect_pending,
        }
    }
}

pub async fn observe_live(request: LiveObserveRequest) -> Result<crate::ObserveResult, String> {
    request.validate()?;
    let runner_plan = ObserverRunnerPlan::host_observer_default();
    let loader_plan = AyaLoaderPlan::audit_observer_default(&request.object_path);
    let mut store =
        JsonlStore::create_with_rotation_policy(&request.output_path, request.output_rotation)
            .map_err(|error| format!("failed to create live observer timeline: {error}"))?;
    let collector_instance_id = new_collector_instance_id()?;

    write_observer_metadata(
        &request.session_id,
        &runner_plan,
        ObserverBackend::AyaRingBuffer,
        request.output_rotation,
        &mut store,
    )?;
    let current_host_boot_id = match read_host_boot_id_at("/proc/sys/kernel/random/boot_id") {
        Ok(host_boot_id) => host_boot_id,
        Err(error) => {
            append_diagnostic(
                &request.session_id,
                ObserverDiagnosticKind::AttachFailure,
                1,
                "host boot identity is unavailable before attach",
                &mut store,
            )?;
            append_failed_collector_lifecycle(
                &request.session_id,
                &collector_instance_id,
                CollectorFailureReason::AttachFailure,
                CollectorLifecycleCounters::default(),
                &mut store,
            )?;
            return Err(error);
        }
    };
    let registered_agent = match resolve_registered_agent(&request, &current_host_boot_id) {
        Ok(agent) => agent,
        Err(error) => {
            append_diagnostic(
                &request.session_id,
                ObserverDiagnosticKind::AttachFailure,
                1,
                &error,
                &mut store,
            )?;
            append_failed_collector_lifecycle(
                &request.session_id,
                &collector_instance_id,
                CollectorFailureReason::AttachFailure,
                CollectorLifecycleCounters::default(),
                &mut store,
            )?;
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
                .map(|agent| LiveScope::ProcessTree(agent.root_pid()))
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
        append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            CollectorFailureReason::AttachFailure,
            CollectorLifecycleCounters::default(),
            &mut store,
        )?;
        return Err(format!("live observer prerequisite failed: {error}"));
    }

    let mut managed_agent = if let Some(agent_run) = request.agent_run.as_ref() {
        let managed_agent_cgroup = request
            .qualification_telemetry
            .as_ref()
            .map(|config| config.managed_agent_cgroup_path.as_path());
        let managed =
            match spawn_managed_agent(agent_run, &request.workspace_root, managed_agent_cgroup) {
                Ok(managed) => managed,
                Err(error) => {
                    append_diagnostic(
                        &request.session_id,
                        ObserverDiagnosticKind::AttachFailure,
                        1,
                        &error,
                        &mut store,
                    )?;
                    append_failed_collector_lifecycle(
                        &request.session_id,
                        &collector_instance_id,
                        CollectorFailureReason::AttachFailure,
                        CollectorLifecycleCounters::default(),
                        &mut store,
                    )?;
                    return Err(error);
                }
            };
        write_agent_supervisor_metadata(&request.session_id, &managed.metadata, &mut store)?;
        Some(managed)
    } else {
        None
    };
    if let Some(agent) = registered_agent.as_ref() {
        write_agent_supervisor_metadata(&request.session_id, &agent.metadata, &mut store)?;
    }
    let scope = managed_agent
        .as_ref()
        .map(|agent| LiveScope::ProcessTree(agent.metadata.root_pid))
        .or_else(|| {
            registered_agent
                .as_ref()
                .map(|agent| LiveScope::ProcessTree(agent.root_pid()))
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
            append_failed_collector_lifecycle(
                &request.session_id,
                &collector_instance_id,
                CollectorFailureReason::VerifierFailure,
                CollectorLifecycleCounters::default(),
                &mut store,
            )?;
            return Err(format!("BPF load or verifier failure: {error:#}"));
        }
    };
    if let Err(error) = configure_scope_inactive(&mut ebpf, &scope) {
        terminate_managed_agent(managed_agent.as_mut()).await;
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AttachFailure,
            1,
            &error,
            &mut store,
        )?;
        append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            CollectorFailureReason::AttachFailure,
            CollectorLifecycleCounters::default(),
            &mut store,
        )?;
        return Err(error);
    }
    if let Err(error) = attach_tracepoints(&mut ebpf, &loader_plan) {
        terminate_managed_agent(managed_agent.as_mut()).await;
        let (kind, reason) = if error.contains("verifier") {
            (
                ObserverDiagnosticKind::VerifierFailure,
                CollectorFailureReason::VerifierFailure,
            )
        } else {
            (
                ObserverDiagnosticKind::AttachFailure,
                CollectorFailureReason::AttachFailure,
            )
        };
        append_diagnostic(&request.session_id, kind, 1, &error, &mut store)?;
        append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            reason,
            CollectorLifecycleCounters::default(),
            &mut store,
        )?;
        return Err(error);
    }

    if let Err(error) = prepare_scope_after_tracepoint_attach(
        &mut ebpf,
        &scope,
        registered_agent.as_ref(),
        &current_host_boot_id,
    ) {
        terminate_managed_agent(managed_agent.as_mut()).await;
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AttachFailure,
            1,
            &error,
            &mut store,
        )?;
        append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            CollectorFailureReason::AttachFailure,
            CollectorLifecycleCounters::default(),
            &mut store,
        )?;
        return Err(error);
    }

    let mut qualification_telemetry = match request.qualification_telemetry.as_ref() {
        Some(config) => match QualificationTelemetryRecorder::new(
            config.max_samples,
            config.resource_sample_interval,
            config.collector_cgroup_path.clone(),
            &config.managed_agent_cgroup_path,
            managed_agent.as_ref().map(|agent| agent.metadata.root_pid),
            &ebpf,
        ) {
            Ok(mut recorder) => {
                let counters = match read_observer_counters(&mut ebpf) {
                    Ok(counters) => counters,
                    Err(error) => {
                        terminate_managed_agent(managed_agent.as_mut()).await;
                        append_failed_collector_lifecycle(
                            &request.session_id,
                            &collector_instance_id,
                            CollectorFailureReason::CounterReadFailure,
                            CollectorLifecycleCounters::default(),
                            &mut store,
                        )?;
                        return Err(format!(
                            "failed to initialize qualification loss telemetry: {error}"
                        ));
                    }
                };
                recorder.record_loss_sample(live_collector_lifecycle_counters(
                    DaemonObserverCounters::from(counters),
                    0,
                    0,
                    0,
                ))?;
                Some(recorder)
            }
            Err(error) => {
                terminate_managed_agent(managed_agent.as_mut()).await;
                append_failed_collector_lifecycle(
                    &request.session_id,
                    &collector_instance_id,
                    CollectorFailureReason::ObserverFailure,
                    CollectorLifecycleCounters::default(),
                    &mut store,
                )?;
                return Err(format!(
                    "failed to initialize qualification resource telemetry: {error}"
                ));
            }
        },
        None => None,
    };

    let activation_result = match registered_agent.as_ref() {
        Some(agent) => {
            activate_existing_process_scope(&mut ebpf, &scope, agent, &current_host_boot_id)
        }
        None => activate_scope(&mut ebpf, &scope),
    };
    if let Err(error) = activation_result {
        terminate_managed_agent(managed_agent.as_mut()).await;
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AttachFailure,
            1,
            &error,
            &mut store,
        )?;
        append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            CollectorFailureReason::AttachFailure,
            CollectorLifecycleCounters::default(),
            &mut store,
        )?;
        return Err(error);
    }

    let late_attach_detail = registered_agent
        .as_ref()
        .map(PreparedExistingProcessAttach::late_attach_detail);
    if let Err(error) = persist_collector_start_boundary(
        &request.session_id,
        &collector_instance_id,
        &scope,
        &loader_plan,
        late_attach_detail.as_deref(),
        &mut store,
    ) {
        let _ = set_scope_config(&mut ebpf, &scope, SCOPE_MODE_INACTIVE);
        terminate_managed_agent(managed_agent.as_mut()).await;
        return match append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            CollectorFailureReason::StorageFailure,
            CollectorLifecycleCounters::default(),
            &mut store,
        ) {
            Ok(()) => Err(error),
            Err(lifecycle_error) => Err(format!(
                "{error}; additionally failed to persist collector failure lifecycle: {lifecycle_error}"
            )),
        };
    }

    // Tracepoints are attached, the pid tree is registered, and the declared
    // Collector Capability and lifecycle start are durable; release the gated
    // Agent now.
    if let Some(agent) = managed_agent.as_mut() {
        agent.release_gate();
    }

    let mut last_lifecycle_counters = CollectorLifecycleCounters::default();
    let run_result: Result<ObserveResult, String> = async {
    let ring_map = ebpf
        .take_map(&loader_plan.ring_buffer_map)
        .ok_or_else(|| format!("missing BPF map: {}", loader_plan.ring_buffer_map))?;
    let ring_buffer = RingBuf::try_from(ring_map)
        .map_err(|error| format!("failed to open observer ring buffer: {error}"))?;
    let mut async_ring = AsyncFd::new(ring_buffer)
        .map_err(|error| format!("failed to poll observer ring buffer: {error}"))?;
    let calibration =
        ObserverBatchDecoder::capture_with_host_boot_id(current_host_boot_id.clone())?;
    let deadline = request
        .duration
        .map(|duration| tokio::time::Instant::now() + duration);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut raw_count = 0;
    let mut canonical_count = 0;
    let mut abi_mismatches = 0_u64;
    let mut first_abi_mismatch = None;
    let mut decode_failures = 0_u64;
    let mut truncations = 0_u64;
    let mut event_ids = EventIdSequence::new(&request.session_id);
    let mut process_context = ProcessContextTable::default();
    let redactor = Redactor::new(&request.session_id, &request.workspace_root);
    let mut agent_exit_status: Option<ExitStatus> = None;
    let mut agent_drain_deadline: Option<tokio::time::Instant> = None;
    let mut stop_reason = CollectorNormalStopReason::ShutdownSignal;
    let mut checkpoint = tokio::time::interval_at(
        tokio::time::Instant::now() + LIVE_COLLECTOR_CHECKPOINT_INTERVAL,
        LIVE_COLLECTOR_CHECKPOINT_INTERVAL,
    );
    checkpoint.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let resource_sample_interval = request
        .qualification_telemetry
        .as_ref()
        .map(|config| config.resource_sample_interval)
        .unwrap_or(Duration::from_secs(1));
    let mut resource_sampler = tokio::time::interval_at(
        tokio::time::Instant::now() + resource_sample_interval,
        resource_sample_interval,
    );
    resource_sampler.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
        let mut checkpoint_due = false;
        let mut resource_sample_due = false;
        let batch = if let Some(deadline) = effective_deadline {
            tokio::select! {
                result = read_ring_batch(&mut async_ring) => Some(result?),
                result = &mut shutdown => {
                    result?;
                    stop_reason = CollectorNormalStopReason::ShutdownSignal;
                    None
                },
                _ = tokio::time::sleep(Duration::from_millis(100)), if managed_agent.is_some() && agent_exit_status.is_none() => {
                    Some(Vec::new())
                },
                _ = checkpoint.tick() => {
                    checkpoint_due = true;
                    Some(Vec::new())
                },
                _ = resource_sampler.tick(), if qualification_telemetry.is_some() => {
                    resource_sample_due = true;
                    Some(Vec::new())
                },
                _ = tokio::time::sleep_until(deadline) => {
                    stop_reason = if agent_drain_deadline == Some(deadline) {
                        CollectorNormalStopReason::AgentExited
                    } else {
                        CollectorNormalStopReason::DurationElapsed
                    };
                    None
                },
            }
        } else {
            tokio::select! {
                result = read_ring_batch(&mut async_ring) => Some(result?),
                result = &mut shutdown => {
                    result?;
                    stop_reason = CollectorNormalStopReason::ShutdownSignal;
                    None
                },
                _ = tokio::time::sleep(Duration::from_millis(100)), if managed_agent.is_some() && agent_exit_status.is_none() => {
                    Some(Vec::new())
                },
                _ = checkpoint.tick() => {
                    checkpoint_due = true;
                    Some(Vec::new())
                },
                _ = resource_sampler.tick(), if qualification_telemetry.is_some() => {
                    resource_sample_due = true;
                    Some(Vec::new())
                }
            }
        };

        let Some(batch) = batch else {
            break;
        };

        if resource_sample_due {
            if let Some(telemetry) = qualification_telemetry.as_mut() {
                telemetry.record_resource_sample()?;
                let counters = DaemonObserverCounters::from(read_observer_counters(&mut ebpf)?);
                telemetry.record_loss_sample(live_collector_lifecycle_counters(
                    counters,
                    abi_mismatches,
                    decode_failures,
                    truncations,
                ))?;
            }
        }

        for bytes in batch {
            let record = match KernelEventRecord::decode(&bytes) {
                Ok(record) => record,
                Err(error) if error.is_abi_mismatch() => {
                    abi_mismatches += 1;
                    first_abi_mismatch.get_or_insert_with(|| error.to_string());
                    continue;
                }
                Err(_) => {
                    decode_failures += 1;
                    continue;
                }
            };
            let decoded_monotonic_ns = if qualification_telemetry.is_some() {
                Some(monotonic_now_ns()?)
            } else {
                None
            };
            if record.flags & (FLAG_RESOURCE_TRUNCATED | FLAG_PAYLOAD_TRUNCATED) != 0 {
                truncations += 1;
            }
            let raw = match raw_event_from_record(
                &record,
                &request.session_id,
                calibration.to_unix_ms(record.timestamp_ns),
                calibration.host_boot_id.as_deref().unwrap_or_default(),
            ) {
                Ok(raw) => raw.with_event_id(event_ids.next_raw_event_id()),
                Err(_) => {
                    decode_failures += 1;
                    continue;
                }
            };
            let canonical = process_context.observe(&raw, canonicalize(&raw))?;
            append_content_off_runtime_event(&raw, &canonical, &redactor, &mut store)?;
            if let (Some(telemetry), Some(decoded_monotonic_ns)) =
                (qualification_telemetry.as_mut(), decoded_monotonic_ns)
            {
                telemetry.record(
                    &raw.event_name,
                    record.timestamp_ns,
                    decoded_monotonic_ns,
                    monotonic_now_ns()?,
                );
            }
            raw_count += 1;
            canonical_count += 1;
        }

        if checkpoint_due {
            let counters = DaemonObserverCounters::from(read_observer_counters(&mut ebpf)?);
            last_lifecycle_counters = live_collector_lifecycle_counters(
                counters,
                abi_mismatches,
                decode_failures,
                truncations,
            );
            store
                .append(&CollectorLifecycleRecord::checkpoint(
                    &request.session_id,
                    &collector_instance_id,
                    last_lifecycle_counters,
                ))
                .map_err(|error| format!("failed to write collector lifecycle checkpoint: {error}"))?;
            store.flush().map_err(|error| {
                format!("failed to flush collector lifecycle checkpoint: {error}")
            })?;
        }
    }

    if let Some(status) = agent_exit_status {
        write_agent_exit_metadata(&request.session_id, status_exit_code(status), &mut store)?;
    }

    let counters = read_observer_counters(&mut ebpf)?;
    let public_counters = DaemonObserverCounters::from(counters);
    last_lifecycle_counters = live_collector_lifecycle_counters(
        public_counters,
        abi_mismatches,
        decode_failures,
        truncations,
    );
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
    if abi_mismatches > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AbiMismatch,
            abi_mismatches,
            first_abi_mismatch.unwrap_or_else(|| "kernel/userspace ABI mismatch".to_string()),
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
    for gap in network_connect_observation_gaps(&request.session_id, &public_counters.into()) {
        store
            .append(&gap)
            .map_err(|error| format!("failed to write network Observation Gap: {error}"))?;
    }
    for gap in
        file_operation_observation_gaps(&request.session_id, &public_counters.file_operations)
    {
        store
            .append(&gap)
            .map_err(|error| format!("failed to write file Observation Gap: {error}"))?;
    }
    let file_totals = public_counters.file_operations.totals();
    append_diagnostic(
        &request.session_id,
        ObserverDiagnosticKind::Summary,
        raw_count as u64,
        format!(
            "raw_events:{raw_count},canonical_events:{canonical_count},reserve_failures:{},map_pressure:{},connect_missing_entries:{},connect_missing_exits:{},connect_pending:{},file_missing_entries:{},file_missing_exits:{},file_pending:{},abi_mismatches:{abi_mismatches},decode_failures:{decode_failures},truncations:{truncations}",
            counters.reserve_failures,
            counters.map_pressure,
            counters.connect_missing_entries,
            counters.connect_missing_exits,
            counters.connect_pending,
            file_totals.missing_entries,
            file_totals.missing_exits,
            file_totals.pending,
        ),
        &mut store,
    )?;
    store
        .append(&CollectorLifecycleRecord::stopped(
            &request.session_id,
            &collector_instance_id,
            stop_reason,
            last_lifecycle_counters,
        ))
        .map_err(|error| format!("failed to write collector lifecycle stop: {error}"))?;

    // Fail loud: silent event loss would let a quiet timeline pass for proof of
    // absence, which is the one thing an evidence tool must never do.
    let dropped_events =
        counters.reserve_failures + counters.map_pressure + abi_mismatches + decode_failures;
    let observation_gaps = counters
        .connect_missing_entries
        .saturating_add(counters.connect_missing_exits)
        .saturating_add(counters.connect_pending)
        .saturating_add(file_totals.missing_entries)
        .saturating_add(file_totals.missing_exits)
        .saturating_add(file_totals.pending);
    if dropped_events > 0 || observation_gaps > 0 || truncations > 0 {
        eprintln!(
            "apolysis: ⚠ evidence may be incomplete — {dropped_events} event(s) dropped, \
             {observation_gaps} pairing Observation Gap(s), {truncations} truncated. \
             A quiet timeline is not proof of absence."
        );
    }

    store
        .flush()
        .map_err(|error| format!("failed to flush live observer timeline: {error}"))?;
    if let (Some(config), Some(telemetry)) = (
        request.qualification_telemetry.as_ref(),
        qualification_telemetry.as_mut(),
    ) {
        telemetry.record_resource_sample()?;
        telemetry.record_loss_sample(last_lifecycle_counters)?;
        telemetry.persist(&config.output_path)?;
    }

    Ok(ObserveResult {
        raw_events: raw_count,
        canonical_events: canonical_count,
        backend: ObserverBackend::AyaRingBuffer,
        mode: ObserverMode::AuditOnly,
        agent_exit_code: agent_exit_status.map(status_exit_code),
    })
    }
    .await;

    if let Err(error) = &run_result {
        terminate_managed_agent(managed_agent.as_mut()).await;
        let failure_reason = live_collector_failure_reason(error);
        if let Err(lifecycle_error) = append_failed_collector_lifecycle(
            &request.session_id,
            &collector_instance_id,
            failure_reason,
            last_lifecycle_counters,
            &mut store,
        ) {
            return Err(format!(
                "{error}; additionally failed to persist collector failure lifecycle: {lifecycle_error}"
            ));
        }
    }

    run_result
}

fn resolve_registered_agent(
    request: &LiveObserveRequest,
    current_host_boot_id: &str,
) -> Result<Option<PreparedExistingProcessAttach>, String> {
    if let Some(path) = request.agent_registration_path.as_deref() {
        let registration = AgentRegistration::from_json_file(path)?;
        return PreparedExistingProcessAttach::prepare(
            registration,
            "external_registration",
            "registration_qualified",
            &request.workspace_root,
            current_host_boot_id,
        )
        .map(Some);
    }

    if let Some(discovery) = request.agent_discovery.as_ref() {
        let registration = discover_agent_registration_with_boot_id(
            discovery,
            "/proc",
            &request.session_id,
            &request.workspace_root,
            current_host_boot_id,
        )?;
        return PreparedExistingProcessAttach::prepare(
            registration,
            "proc_discovery",
            "inferred",
            &request.workspace_root,
            current_host_boot_id,
        )
        .map(Some);
    }

    Ok(None)
}

pub fn discover_agent_registration(
    request: &AgentDiscoveryRequest,
    proc_root: impl AsRef<Path>,
    session_id: &str,
    workspace_root: &Path,
) -> Result<AgentRegistration, String> {
    discover_agent_registration_with_boot_id(
        request,
        proc_root,
        session_id,
        workspace_root,
        &read_host_boot_id_at("/proc/sys/kernel/random/boot_id")?,
    )
}

fn discover_agent_registration_with_boot_id(
    request: &AgentDiscoveryRequest,
    proc_root: impl AsRef<Path>,
    session_id: &str,
    workspace_root: &Path,
    host_boot_id: &str,
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
        return Err("agent discovery found no matching process".to_string());
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
        .to_registration(&request.kind, workspace_root, host_boot_id.to_string()))
}

fn spawn_managed_agent(
    request: &AgentRunRequest,
    workspace_root: &Path,
    managed_agent_cgroup: Option<&Path>,
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
    let managed_agent_cgroup_fd = managed_agent_cgroup
        .map(|path| {
            fs::OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.procs"))
                .map_err(|error| {
                    format!(
                        "failed to open qualification workload cgroup {}: {error}",
                        path.display()
                    )
                })
        })
        .transpose()?;

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
    let managed_identity = current_managed_agent_run_as();
    let managed_uid_gid = managed_identity
        .as_ref()
        .map(|run_as| (run_as.uid, run_as.gid));
    if let Some(run_as) = managed_identity {
        if let Some(home) = run_as.home {
            command.env("HOME", home);
        }
        if let Some(codex_home) = run_as.codex_home {
            command.env("CODEX_HOME", codex_home);
        }
    }
    // SAFETY: runs post-fork/pre-exec and uses async-signal-safe syscalls only.
    // dup2 keeps the gate through the wrapper exec. When sudo identity
    // restoration applies, supplementary groups are cleared before gid/uid so
    // the managed and collector-off workloads have the same least privilege.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(gate_read, GATE_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(cgroup_fd) = managed_agent_cgroup_fd.as_ref() {
                write_self_pid_to_cgroup(cgroup_fd.as_raw_fd())?;
            }
            if let Some((uid, gid)) = managed_uid_gid {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
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
        workspace_root: workspace_root.display().to_string(),
        start_time_ticks: read_process_start_time_ticks(root_pid),
    };
    Ok(ManagedAgentChild {
        child,
        metadata,
        gate: Some(gate_write),
    })
}

fn write_self_pid_to_cgroup(fd: libc::c_int) -> std::io::Result<()> {
    let mut pid = unsafe { libc::getpid() } as u32;
    let mut buffer = [0_u8; 11];
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    let mut written = 0;
    let bytes = &buffer[start..];
    while written < bytes.len() {
        let status =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if status < 0 {
            return Err(std::io::Error::last_os_error());
        }
        written += status as usize;
    }
    Ok(())
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
    let redactor = Redactor::new(session_id, &metadata.workspace_root);
    let executable_ref = redactor
        .redact_resource(EventType::Exec, &metadata.executable)
        .value;
    let entries = vec![
        (
            resources::AGENT_SUPERVISOR_MODE,
            metadata.supervisor_mode.clone(),
        ),
        (resources::AGENT_KIND, metadata.kind.clone()),
        (resources::AGENT_ROOT_PID, metadata.root_pid.to_string()),
        (
            resources::AGENT_COMMAND,
            "argv_redacted:true,content_off:true".to_string(),
        ),
        (resources::AGENT_EXECUTABLE, executable_ref),
        (
            resources::AGENT_WORKSPACE_ROOT,
            "workspace_ref:redacted".to_string(),
        ),
        (
            resources::AGENT_START_TIME,
            metadata
                .start_time_ticks
                .map(|ticks| format!("start_time_ticks:{ticks}"))
                .unwrap_or_else(|| "start_time_ticks:unavailable".to_string()),
        ),
    ];
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

fn validate_workspace_boundary(
    registered_workspace: &Path,
    requested_workspace: &Path,
) -> Result<PathBuf, String> {
    let registered = fs::canonicalize(registered_workspace)
        .map_err(|_| "agent registration workspace boundary is unavailable".to_string())?;
    let requested = fs::canonicalize(requested_workspace)
        .map_err(|_| "requested workspace boundary is unavailable".to_string())?;
    if registered != requested {
        return Err("agent registration workspace boundary mismatch".to_string());
    }
    Ok(requested)
}

fn validate_process_workspace_boundary_at(
    proc_root: impl AsRef<Path>,
    pid: u32,
    workspace_root: &Path,
) -> Result<(), String> {
    let cwd = fs::canonicalize(proc_root.as_ref().join(pid.to_string()).join("cwd"))
        .map_err(|_| "existing-process root workspace identity is unavailable".to_string())?;
    if cwd != workspace_root && !cwd.starts_with(workspace_root) {
        return Err("existing-process root workspace boundary mismatch".to_string());
    }
    Ok(())
}

fn validate_same_time_namespace(pid: u32) -> Result<(), String> {
    let namespace_inode = fs::metadata("/proc/self/ns/time")
        .map_err(|_| "observer time namespace identity is unavailable".to_string())?
        .ino();
    validate_initial_time_namespace_inode(namespace_inode)?;
    validate_matching_namespace_links(
        "/proc/self/ns/time",
        format!("/proc/{pid}/ns/time"),
        "observer time namespace identity is unavailable",
        "target time namespace identity is unavailable",
        "protected existing-process attach requires the observer and target to share a time namespace",
    )
}

fn validate_initial_time_namespace_inode(inode: u64) -> Result<(), String> {
    // Linux UAPI `TIME_NS_INIT_INO`; zero offsets alone do not prove that the
    // observer is in the initial time namespace.
    const TIME_NS_INIT_INO: u64 = 0xEFFF_FFFA;
    if inode != TIME_NS_INIT_INO {
        return Err(
            "protected existing-process attach requires the initial time namespace".to_string(),
        );
    }
    Ok(())
}

fn validate_native_pid_namespace(pid: u32) -> Result<(), String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|_| "observer PID namespace identity is unavailable".to_string())?;
    validate_initial_pid_namespace_status(&status)?;
    let namespace_inode = fs::metadata("/proc/self/ns/pid")
        .map_err(|_| "observer PID namespace identity is unavailable".to_string())?
        .ino();
    validate_initial_pid_namespace_inode(namespace_inode)?;
    validate_matching_namespace_links(
        "/proc/self/ns/pid",
        format!("/proc/{pid}/ns/pid"),
        "observer PID namespace identity is unavailable",
        "target PID namespace identity is unavailable",
        "protected process-tree attach requires the observer and target to share the initial PID namespace",
    )
}

fn validate_matching_namespace_links(
    observer_path: impl AsRef<Path>,
    target_path: impl AsRef<Path>,
    observer_unavailable: &str,
    target_unavailable: &str,
    mismatch: &str,
) -> Result<(), String> {
    let observer = fs::read_link(observer_path).map_err(|_| observer_unavailable.to_string())?;
    let target = fs::read_link(target_path).map_err(|_| target_unavailable.to_string())?;
    if observer != target {
        return Err(mismatch.to_string());
    }
    Ok(())
}

fn validate_initial_pid_namespace_inode(inode: u64) -> Result<(), String> {
    // Linux UAPI `PID_NS_INIT_INO`; unlike NSpid, this remains stable when a
    // nested PID namespace mounts its own procfs view.
    const PID_NS_INIT_INO: u64 = 0xEFFF_FFFC;
    if inode != PID_NS_INIT_INO {
        return Err("protected process-tree attach requires the initial PID namespace".to_string());
    }
    Ok(())
}

fn validate_initial_pid_namespace_status(status: &str) -> Result<(), String> {
    let pids = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .ok_or_else(|| "observer initial PID namespace identity is unavailable".to_string())?
        .split_whitespace()
        .map(|value| value.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "observer initial PID namespace identity is invalid".to_string())?;
    if pids.len() != 1 || pids[0] == 0 {
        return Err("protected process-tree attach requires the initial PID namespace".to_string());
    }
    Ok(())
}

fn open_pidfd(pid: u32) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open receives a numeric PID and zero flags, and returns a new fd on success.
    let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) as libc::c_int };
    if raw_fd < 0 {
        return Err(format!(
            "failed to anchor existing-process runtime identity: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: pidfd_open returned ownership of this valid file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

fn ensure_pidfd_alive(pidfd: &OwnedFd) -> Result<(), String> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pollfd points to one initialized element and the timeout is non-blocking.
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(format!(
            "failed to validate existing-process liveness: {}",
            std::io::Error::last_os_error()
        ));
    }
    if result != 0 {
        return Err("existing process exited before protected attach activation".to_string());
    }
    Ok(())
}

fn discover_anchored_process_tree_scope_identities(
    root_pid: u32,
) -> Result<Vec<AnchoredProcessIdentity>, String> {
    let lineages = discover_process_tree_scope_lineages(root_pid, "/proc")?;
    let mut anchors = Vec::with_capacity(lineages.len());
    for lineage in lineages {
        anchors.push(AnchoredProcessIdentity {
            pidfd: open_pidfd(lineage.runtime.pid)?,
            lineage,
        });
    }
    validate_anchored_process_identities(&anchors)?;
    Ok(anchors)
}

fn validate_anchored_process_identity(anchor: &AnchoredProcessIdentity) -> Result<(), String> {
    ensure_pidfd_alive(&anchor.pidfd)?;
    validate_native_pid_namespace(anchor.lineage.runtime.pid)?;
    validate_same_time_namespace(anchor.lineage.runtime.pid)?;
    let current = read_process_lineage_identity_at(Path::new("/proc"), anchor.lineage.runtime.pid)
        .ok_or_else(|| {
            "existing process identity became unavailable before protected attach activation"
                .to_string()
        })?;
    if current != anchor.lineage || current.tgid != current.runtime.pid {
        return Err(
            "existing process identity changed before protected attach activation".to_string(),
        );
    }
    ensure_pidfd_alive(&anchor.pidfd)?;
    Ok(())
}

fn validate_anchored_process_identities(anchors: &[AnchoredProcessIdentity]) -> Result<(), String> {
    for anchor in anchors {
        validate_anchored_process_identity(anchor)?;
    }
    Ok(())
}

fn with_stable_anchored_process_identities<T>(
    anchors: &[AnchoredProcessIdentity],
    update: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    with_identity_validation_sandwich(|| validate_anchored_process_identities(anchors), update)
}

fn with_identity_validation_sandwich<T>(
    mut validate: impl FnMut() -> Result<(), String>,
    update: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    validate()?;
    let output = update()?;
    validate()?;
    Ok(output)
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

    fn to_registration(
        &self,
        kind: &str,
        workspace_root: &Path,
        host_boot_id: String,
    ) -> AgentRegistration {
        AgentRegistration {
            kind: kind.to_string(),
            pid: self.pid,
            start_time_ticks: self.start_time_ticks,
            host_boot_id,
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
        format!("pid={},score={}", self.identity.pid, self.score)
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
        if let Some(identity) = read_proc_identity(proc_root, pid) {
            identities.push(identity);
        }
    }
    Ok(identities)
}

fn read_proc_identity(proc_root: &Path, pid: u32) -> Option<ProcIdentity> {
    let stat = read_proc_stat(proc_root, pid)?;
    let ppid = parse_proc_stat_ppid(&stat)?;
    let start_time_ticks = parse_proc_stat_start_time_ticks(&stat)?;
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
    Some(ProcIdentity {
        pid,
        ppid,
        start_time_ticks,
        comm,
        executable,
        cwd,
        command_args,
        command_fingerprint: command_fingerprint(&fingerprint_input),
    })
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

fn read_process_tgid_at(proc_root: &Path, pid: u32) -> Option<u32> {
    let status = fs::read_to_string(proc_root.join(pid.to_string()).join("status")).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Tgid:")
            .and_then(|value| value.trim().parse::<u32>().ok())
    })
}

fn read_process_lineage_identity_at(proc_root: &Path, pid: u32) -> Option<ProcessLineageIdentity> {
    let stat = read_proc_stat(proc_root, pid)?;
    if matches!(parse_proc_stat_state(&stat)?, 'Z' | 'X' | 'x') {
        return None;
    }
    Some(ProcessLineageIdentity {
        runtime: ProcessRuntimeIdentity {
            pid,
            start_time_ticks: parse_proc_stat_start_time_ticks(&stat)?,
        },
        ppid: parse_proc_stat_ppid(&stat)?,
        tgid: read_process_tgid_at(proc_root, pid)?,
    })
}

fn parse_proc_stat_state(stat: &str) -> Option<char> {
    stat.rsplit_once(") ")?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
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

fn command_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::from("sha256:");
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn live_scope_requirement() -> String {
    "live observer requires exactly one of --scope-cgroup, --agent-run, --agent-registration, or --agent-discover".to_string()
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

fn looks_like_credential_path(value: &str) -> bool {
    value.ends_with("/.env")
        || value.contains("/.env.")
        || value.contains("/.ssh/")
        || value.contains("/.aws/")
        || value.contains("/var/run/secrets/")
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

fn configure_scope_inactive(ebpf: &mut Ebpf, scope: &LiveScope) -> Result<(), String> {
    set_scope_config(ebpf, scope, SCOPE_MODE_INACTIVE)
}

fn attached_scope_preparation_mode(scope: &LiveScope, protected_existing_process: bool) -> u32 {
    match scope {
        LiveScope::ProcessTree(_) if protected_existing_process => SCOPE_MODE_PID_TREE_SEEDING,
        _ => SCOPE_MODE_INACTIVE,
    }
}

fn prepare_scope_after_tracepoint_attach(
    ebpf: &mut Ebpf,
    scope: &LiveScope,
    existing_process: Option<&PreparedExistingProcessAttach>,
    current_host_boot_id: &str,
) -> Result<(), String> {
    let LiveScope::ProcessTree(root_pid) = scope else {
        return Ok(());
    };
    validate_native_pid_namespace(*root_pid)?;
    match existing_process {
        Some(existing) => {
            set_scope_config(ebpf, scope, attached_scope_preparation_mode(scope, true))?;
            existing.validate_root(current_host_boot_id)?;
            let root = ProcessRuntimeIdentity::new(
                existing.registration.pid,
                existing.registration.start_time_ticks,
            )?;
            seed_process_tree_identities(ebpf, &[root], existing.clock, true)?;
            existing.validate_root(current_host_boot_id)?;
            let identities = discover_anchored_process_tree_scope_identities(*root_pid)?;
            seed_anchored_process_tree_identities(ebpf, &identities, existing.clock, false)?;
            existing.validate_root(current_host_boot_id)
        }
        None => {
            let clock = ProcStartClock::host()?;
            let identities = discover_process_tree_scope_identities(*root_pid, "/proc")?;
            seed_process_tree_identities(ebpf, &identities, clock, true)
        }
    }
}

fn activate_scope(ebpf: &mut Ebpf, scope: &LiveScope) -> Result<(), String> {
    let mode = match scope {
        LiveScope::Cgroup(_) => SCOPE_MODE_CGROUP,
        LiveScope::ProcessTree(_) => SCOPE_MODE_PID_TREE,
    };
    set_scope_config(ebpf, scope, mode)
}

fn set_scope_config(ebpf: &mut Ebpf, scope: &LiveScope, mode: u32) -> Result<(), String> {
    let config = match scope {
        LiveScope::Cgroup(cgroup_id) => ScopeConfig {
            cgroup_id: *cgroup_id,
            root_pid: 0,
            mode,
        },
        LiveScope::ProcessTree(root_pid) => ScopeConfig {
            cgroup_id: 0,
            root_pid: *root_pid,
            mode,
        },
    };
    let config_map = ebpf
        .map_mut("APOLYSIS_CONFIG")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONFIG".to_string())?;
    let mut config_array = Array::<_, ScopeConfig>::try_from(config_map)
        .map_err(|error| format!("invalid APOLYSIS_CONFIG map: {error}"))?;
    config_array
        .set(0, config, 0)
        .map_err(|error| format!("failed to configure live observer scope: {error}"))
}

fn seed_process_tree_identities(
    ebpf: &mut Ebpf,
    identities: &[ProcessRuntimeIdentity],
    clock: ProcStartClock,
    replace_existing: bool,
) -> Result<(), String> {
    let tracked_map = ebpf
        .map_mut("APOLYSIS_TRACKED_PIDS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_PIDS".to_string())?;
    let mut tracked = HashMap::<_, u32, TrackedProcessIdentityAbi>::try_from(tracked_map)
        .map_err(|error| format!("invalid APOLYSIS_TRACKED_PIDS map: {error}"))?;
    for identity in identities {
        let window = clock.start_boottime_window(*identity)?;
        let membership = TrackedProcessIdentityAbi::expected(window.lower_ns, window.upper_ns)?;
        if !replace_existing {
            match tracked.get(&identity.pid, 0) {
                Ok(_) => continue,
                Err(MapError::KeyNotFound) => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect process-tree runtime identity pid={}: {error}",
                        identity.pid
                    ));
                }
            }
        }
        let flags = if replace_existing { 0 } else { 1 };
        if let Err(error) = tracked.insert(identity.pid, membership, flags) {
            if !replace_existing && tracked.get(&identity.pid, 0).is_ok() {
                continue;
            }
            return Err(format!(
                "failed to seed process-tree runtime identity pid={}: {error}",
                identity.pid
            ));
        }
    }
    Ok(())
}

fn seed_anchored_process_tree_identities(
    ebpf: &mut Ebpf,
    anchors: &[AnchoredProcessIdentity],
    clock: ProcStartClock,
    replace_existing: bool,
) -> Result<(), String> {
    let identities = anchors
        .iter()
        .map(|anchor| anchor.lineage.runtime)
        .collect::<Vec<_>>();
    with_stable_anchored_process_identities(anchors, || {
        seed_process_tree_identities(ebpf, &identities, clock, replace_existing)
    })
}

fn activate_existing_process_scope(
    ebpf: &mut Ebpf,
    scope: &LiveScope,
    existing: &PreparedExistingProcessAttach,
    current_host_boot_id: &str,
) -> Result<(), String> {
    existing.validate_root(current_host_boot_id)?;
    let before_activation = discover_anchored_process_tree_scope_identities(existing.root_pid())?;
    seed_anchored_process_tree_identities(ebpf, &before_activation, existing.clock, false)?;
    existing.validate_root(current_host_boot_id)?;
    activate_scope(ebpf, scope)?;
    let after_activation = discover_anchored_process_tree_scope_identities(existing.root_pid())?;
    seed_anchored_process_tree_identities(ebpf, &after_activation, existing.clock, false)?;
    existing.validate_root(current_host_boot_id)
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

const SCOPE_DRAIN_POLL_LIMIT: usize = 4_096;
const RING_DRAIN_RECORD_LIMIT: usize = 2_048;

fn track_cgroup_with_observation_counters(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    generation: ScopeGeneration,
) -> Result<(), String> {
    if cgroup_id == 0 {
        return Err("cgroup id must be non-zero".to_string());
    }
    if let Some(scope) = tracked_cgroup_scope(ebpf, cgroup_id)? {
        return Err(format!(
            "cgroup observer scope {cgroup_id} is already generation {} in state {:?}",
            scope.generation(),
            scope.state()?
        ));
    }

    set_network_connect_counters(ebpf, cgroup_id, NetworkConnectCountersAbi::default())?;
    if let Err(error) =
        set_file_operation_counters(ebpf, cgroup_id, FileOperationCountersAbi::default())
    {
        let rollback = remove_network_connect_counters(ebpf, cgroup_id);
        return Err(match rollback {
            Ok(()) => error,
            Err(rollback) => format!("{error}; connect-counter rollback failed: {rollback}"),
        });
    }
    if let Err(error) = set_scope_updates_inflight(ebpf, cgroup_id, 0) {
        let file_rollback = remove_file_operation_counters(ebpf, cgroup_id);
        let connect_rollback = remove_network_connect_counters(ebpf, cgroup_id);
        let mut failures = vec![error];
        if let Err(rollback) = file_rollback {
            failures.push(format!("file-counter rollback failed: {rollback}"));
        }
        if let Err(rollback) = connect_rollback {
            failures.push(format!("connect-counter rollback failed: {rollback}"));
        }
        return Err(failures.join("; "));
    }
    if let Err(error) = set_tracked_cgroup_scope(
        ebpf,
        cgroup_id,
        TrackedCgroupScopeAbi::active(generation.get())?,
    ) {
        let inflight_rollback = remove_scope_updates_inflight(ebpf, cgroup_id);
        let file_rollback = remove_file_operation_counters(ebpf, cgroup_id);
        let connect_rollback = remove_network_connect_counters(ebpf, cgroup_id);
        let mut failures = vec![error];
        if let Err(rollback) = inflight_rollback {
            failures.push(format!("in-flight update rollback failed: {rollback}"));
        }
        if let Err(rollback) = file_rollback {
            failures.push(format!("file-counter rollback failed: {rollback}"));
        }
        if let Err(rollback) = connect_rollback {
            failures.push(format!("connect-counter rollback failed: {rollback}"));
        }
        return Err(failures.join("; "));
    }
    Ok(())
}

fn tracked_cgroup_scope(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
) -> Result<Option<TrackedCgroupScopeAbi>, String> {
    let tracked_map = ebpf
        .map_mut("APOLYSIS_TRACKED_CGROUPS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_CGROUPS".to_string())?;
    let tracked = HashMap::<_, u64, TrackedCgroupScopeAbi>::try_from(tracked_map)
        .map_err(|error| format!("invalid APOLYSIS_TRACKED_CGROUPS map: {error}"))?;
    match tracked.get(&cgroup_id, 0) {
        Ok(scope) => Ok(Some(scope)),
        Err(MapError::KeyNotFound) => Ok(None),
        Err(error) => Err(format!("failed to read cgroup observer scope: {error}")),
    }
}

fn set_tracked_cgroup_scope(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    scope: TrackedCgroupScopeAbi,
) -> Result<(), String> {
    let tracked_map = ebpf
        .map_mut("APOLYSIS_TRACKED_CGROUPS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_CGROUPS".to_string())?;
    let mut tracked = HashMap::<_, u64, TrackedCgroupScopeAbi>::try_from(tracked_map)
        .map_err(|error| format!("invalid APOLYSIS_TRACKED_CGROUPS map: {error}"))?;
    tracked
        .insert(cgroup_id, scope, 0)
        .map_err(|error| format!("failed to update cgroup observer scope: {error}"))
}

fn set_tracked_cgroup_state(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    generation: ScopeGeneration,
    state: TrackedCgroupState,
) -> Result<(), String> {
    let scope = tracked_cgroup_scope(ebpf, cgroup_id)?
        .ok_or_else(|| format!("cgroup observer scope {cgroup_id} is not tracked"))?;
    if scope.generation() != generation.get() {
        return Err(format!(
            "cgroup observer scope {cgroup_id} generation mismatch: expected {}, found {}",
            generation.get(),
            scope.generation()
        ));
    }
    set_tracked_cgroup_scope(ebpf, cgroup_id, scope.with_state(state))
}

fn remove_tracked_cgroup(ebpf: &mut Ebpf, cgroup_id: u64) -> Result<(), String> {
    let tracked_map = ebpf
        .map_mut("APOLYSIS_TRACKED_CGROUPS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_CGROUPS".to_string())?;
    let mut tracked = HashMap::<_, u64, TrackedCgroupScopeAbi>::try_from(tracked_map)
        .map_err(|error| format!("invalid APOLYSIS_TRACKED_CGROUPS map: {error}"))?;
    tracked
        .remove(&cgroup_id)
        .map_err(|error| format!("failed to remove cgroup observer scope: {error}"))
}

fn set_network_connect_counters(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    value: NetworkConnectCountersAbi,
) -> Result<(), String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_CONNECT_COUNTERS_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONNECT_COUNTERS_BY_CGROUP".to_string())?;
    let mut counters = HashMap::<_, u64, NetworkConnectCountersAbi>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_CONNECT_COUNTERS_BY_CGROUP map: {error}"))?;
    counters
        .insert(cgroup_id, value, 0)
        .map_err(|error| format!("failed to update cgroup connect counters: {error}"))
}

fn read_network_connect_counters(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
) -> Result<NetworkConnectCountersAbi, String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_CONNECT_COUNTERS_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONNECT_COUNTERS_BY_CGROUP".to_string())?;
    let counters = HashMap::<_, u64, NetworkConnectCountersAbi>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_CONNECT_COUNTERS_BY_CGROUP map: {error}"))?;
    counters
        .get(&cgroup_id, 0)
        .map_err(|error| format!("failed to read cgroup connect counters: {error}"))
}

fn remove_network_connect_counters(ebpf: &mut Ebpf, cgroup_id: u64) -> Result<(), String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_CONNECT_COUNTERS_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONNECT_COUNTERS_BY_CGROUP".to_string())?;
    let mut counters = HashMap::<_, u64, NetworkConnectCountersAbi>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_CONNECT_COUNTERS_BY_CGROUP map: {error}"))?;
    counters
        .remove(&cgroup_id)
        .map_err(|error| format!("failed to clean up cgroup connect counters: {error}"))
}

fn set_file_operation_counters(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    value: FileOperationCountersAbi,
) -> Result<(), String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_FILE_COUNTERS_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_FILE_COUNTERS_BY_CGROUP".to_string())?;
    let mut counters = HashMap::<_, u64, FileOperationCountersAbi>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_FILE_COUNTERS_BY_CGROUP map: {error}"))?;
    counters
        .insert(cgroup_id, value, 0)
        .map_err(|error| format!("failed to update cgroup file counters: {error}"))
}

fn read_file_operation_counters(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
) -> Result<FileOperationCountersAbi, String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_FILE_COUNTERS_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_FILE_COUNTERS_BY_CGROUP".to_string())?;
    let counters = HashMap::<_, u64, FileOperationCountersAbi>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_FILE_COUNTERS_BY_CGROUP map: {error}"))?;
    counters
        .get(&cgroup_id, 0)
        .map_err(|error| format!("failed to read cgroup file counters: {error}"))
}

fn remove_file_operation_counters(ebpf: &mut Ebpf, cgroup_id: u64) -> Result<(), String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_FILE_COUNTERS_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_FILE_COUNTERS_BY_CGROUP".to_string())?;
    let mut counters = HashMap::<_, u64, FileOperationCountersAbi>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_FILE_COUNTERS_BY_CGROUP map: {error}"))?;
    counters
        .remove(&cgroup_id)
        .map_err(|error| format!("failed to clean up cgroup file counters: {error}"))
}

fn set_scope_updates_inflight(ebpf: &mut Ebpf, cgroup_id: u64, value: u64) -> Result<(), String> {
    let updates_map = ebpf
        .map_mut("APOLYSIS_SCOPE_UPDATES_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_SCOPE_UPDATES_BY_CGROUP".to_string())?;
    let mut updates = HashMap::<_, u64, u64>::try_from(updates_map)
        .map_err(|error| format!("invalid APOLYSIS_SCOPE_UPDATES_BY_CGROUP map: {error}"))?;
    updates
        .insert(cgroup_id, value, 0)
        .map_err(|error| format!("failed to update cgroup in-flight scope counter: {error}"))
}

fn read_scope_updates_inflight(ebpf: &mut Ebpf, cgroup_id: u64) -> Result<u64, String> {
    let updates_map = ebpf
        .map_mut("APOLYSIS_SCOPE_UPDATES_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_SCOPE_UPDATES_BY_CGROUP".to_string())?;
    let updates = HashMap::<_, u64, u64>::try_from(updates_map)
        .map_err(|error| format!("invalid APOLYSIS_SCOPE_UPDATES_BY_CGROUP map: {error}"))?;
    updates
        .get(&cgroup_id, 0)
        .map_err(|error| format!("failed to read cgroup in-flight scope counter: {error}"))
}

fn remove_scope_updates_inflight(ebpf: &mut Ebpf, cgroup_id: u64) -> Result<(), String> {
    let updates_map = ebpf
        .map_mut("APOLYSIS_SCOPE_UPDATES_BY_CGROUP")
        .ok_or_else(|| "missing BPF map: APOLYSIS_SCOPE_UPDATES_BY_CGROUP".to_string())?;
    let mut updates = HashMap::<_, u64, u64>::try_from(updates_map)
        .map_err(|error| format!("invalid APOLYSIS_SCOPE_UPDATES_BY_CGROUP map: {error}"))?;
    updates
        .remove(&cgroup_id)
        .map_err(|error| format!("failed to clean up cgroup in-flight scope counter: {error}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScopeDrainWaitError {
    Read(String),
    Timeout,
}

impl std::fmt::Display for ScopeDrainWaitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => formatter.write_str(error),
            Self::Timeout => write!(
                formatter,
                "cgroup scope updates did not drain after {SCOPE_DRAIN_POLL_LIMIT} polls"
            ),
        }
    }
}

fn wait_for_scope_updates_to_drain<F>(mut read_inflight: F) -> Result<(), ScopeDrainWaitError>
where
    F: FnMut() -> Result<u64, String>,
{
    for _ in 0..SCOPE_DRAIN_POLL_LIMIT {
        if read_inflight().map_err(ScopeDrainWaitError::Read)? == 0 {
            return Ok(());
        }
        std::thread::yield_now();
    }
    Err(ScopeDrainWaitError::Timeout)
}

fn restore_active_scope(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    generation: ScopeGeneration,
    error: String,
) -> String {
    let restore = match tracked_cgroup_scope(ebpf, cgroup_id) {
        Ok(Some(_)) => {
            set_tracked_cgroup_state(ebpf, cgroup_id, generation, TrackedCgroupState::Active)
        }
        Ok(None) => TrackedCgroupScopeAbi::active(generation.get())
            .and_then(|scope| set_tracked_cgroup_scope(ebpf, cgroup_id, scope)),
        Err(read) => Err(read),
    };
    match restore {
        Ok(()) => error,
        Err(rollback) => format!("{error}; cgroup scope rollback failed: {rollback}"),
    }
}

fn restore_scope_with_counters(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    generation: ScopeGeneration,
    network: NetworkConnectCountersAbi,
    files: FileOperationCountersAbi,
    error: String,
) -> String {
    let mut failures = vec![error];
    let mut prerequisites_restored = true;
    if let Err(rollback) = set_network_connect_counters(ebpf, cgroup_id, network) {
        prerequisites_restored = false;
        failures.push(format!("connect-counter rollback failed: {rollback}"));
    }
    if let Err(rollback) = set_file_operation_counters(ebpf, cgroup_id, files) {
        prerequisites_restored = false;
        failures.push(format!("file-counter rollback failed: {rollback}"));
    }
    if let Err(rollback) = set_scope_updates_inflight(ebpf, cgroup_id, 0) {
        prerequisites_restored = false;
        failures.push(format!("in-flight update rollback failed: {rollback}"));
    }
    if !prerequisites_restored {
        failures.push("cgroup scope remains inactive after incomplete rollback".to_string());
        return failures.join("; ");
    }
    restore_active_scope(ebpf, cgroup_id, generation, failures.join("; "))
}

fn drain_tracked_cgroup(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    generation: ScopeGeneration,
) -> Result<ScopeObservationGapCounters, String> {
    if cgroup_id == 0 {
        return Err("cgroup id must be non-zero".to_string());
    }

    match tracked_cgroup_scope(ebpf, cgroup_id)? {
        Some(scope)
            if scope.generation() == generation.get()
                && scope.state()? == TrackedCgroupState::Active => {}
        Some(scope) => {
            return Err(format!(
                "cgroup observer scope {cgroup_id} generation/state mismatch: expected generation {}, found generation {} in state {:?}",
                generation.get(),
                scope.generation(),
                scope.state()?
            ));
        }
        None => return Err(format!("cgroup observer scope {cgroup_id} is not tracked")),
    }
    set_tracked_cgroup_state(ebpf, cgroup_id, generation, TrackedCgroupState::Draining)?;
    match wait_for_scope_updates_to_drain(|| read_scope_updates_inflight(ebpf, cgroup_id)) {
        Ok(()) => {}
        Err(ScopeDrainWaitError::Timeout) => {
            return Err(restore_active_scope(
                ebpf,
                cgroup_id,
                generation,
                ScopeDrainWaitError::Timeout.to_string(),
            ));
        }
        Err(ScopeDrainWaitError::Read(error)) => {
            return Err(format!(
                "{error}; cgroup scope remains draining because its in-flight update barrier could not be read"
            ));
        }
    }
    if let Err(error) = remove_tracked_cgroup(ebpf, cgroup_id) {
        return Err(restore_active_scope(ebpf, cgroup_id, generation, error));
    }

    let network_snapshot = match read_network_connect_counters(ebpf, cgroup_id) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(format!(
                "{error}; cgroup scope remains inactive because its connect counters could not be restored"
            ));
        }
    };
    let file_snapshot = match read_file_operation_counters(ebpf, cgroup_id) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(format!(
                "{error}; cgroup scope remains inactive because its file counters could not be restored"
            ));
        }
    };
    if let Err(error) = remove_network_connect_counters(ebpf, cgroup_id) {
        return Err(restore_scope_with_counters(
            ebpf,
            cgroup_id,
            generation,
            network_snapshot,
            file_snapshot,
            error,
        ));
    }
    if let Err(error) = remove_file_operation_counters(ebpf, cgroup_id) {
        return Err(restore_scope_with_counters(
            ebpf,
            cgroup_id,
            generation,
            network_snapshot,
            file_snapshot,
            error,
        ));
    }
    if let Err(error) = remove_scope_updates_inflight(ebpf, cgroup_id) {
        return Err(restore_scope_with_counters(
            ebpf,
            cgroup_id,
            generation,
            network_snapshot,
            file_snapshot,
            error,
        ));
    }
    Ok(ScopeObservationGapCounters {
        network_connect: network_snapshot.into(),
        file_operations: file_snapshot.into(),
    })
}

fn snapshot_tracked_cgroup(
    ebpf: &mut Ebpf,
    cgroup_id: u64,
    generation: ScopeGeneration,
) -> Result<ScopeObservationGapCounters, String> {
    match tracked_cgroup_scope(ebpf, cgroup_id)? {
        Some(scope)
            if scope.generation() == generation.get()
                && scope.state()? == TrackedCgroupState::Active => {}
        Some(scope) => {
            return Err(format!(
                "cgroup observer checkpoint {cgroup_id} generation/state mismatch: expected generation {}, found generation {} in state {:?}",
                generation.get(),
                scope.generation(),
                scope.state()?
            ));
        }
        None => return Err(format!("cgroup observer scope {cgroup_id} is not tracked")),
    }
    Ok(ScopeObservationGapCounters {
        network_connect: read_network_connect_counters(ebpf, cgroup_id)?.into(),
        file_operations: read_file_operation_counters(ebpf, cgroup_id)?.into(),
    })
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

fn read_observer_counters(ebpf: &mut Ebpf) -> Result<ObserverCountersAbi, String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_COUNTERS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_COUNTERS".to_string())?;
    let counters = Array::<_, ObserverCountersAbi>::try_from(counters_map)
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

fn drain_ring_batch_now(ring: &mut AsyncFd<RingBuf<MapData>>) -> Vec<Vec<u8>> {
    let mut batch = Vec::new();
    let mut idle_polls = 0;
    while batch.len() < RING_DRAIN_RECORD_LIMIT && idle_polls < SCOPE_DRAIN_POLL_LIMIT {
        match ring.get_mut().next() {
            Some(item) => {
                batch.push(item.to_vec());
                idle_polls = 0;
            }
            None => {
                idle_polls += 1;
                std::thread::yield_now();
            }
        }
    }
    batch
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

fn live_collector_lifecycle_counters(
    counters: DaemonObserverCounters,
    abi_mismatches: u64,
    decode_failures: u64,
    truncations: u64,
) -> CollectorLifecycleCounters {
    let file_totals = counters.file_operations.totals();
    CollectorLifecycleCounters {
        global_reserve_failures: counters.reserve_failures,
        global_map_pressure: counters.map_pressure,
        global_abi_mismatches: abi_mismatches,
        global_decode_failures: decode_failures,
        global_truncations: truncations,
        scope_missing_entries: counters
            .connect_missing_entries
            .saturating_add(file_totals.missing_entries),
        scope_missing_exits: counters
            .connect_missing_exits
            .saturating_add(file_totals.missing_exits),
        scope_pending: counters.connect_pending.saturating_add(file_totals.pending),
    }
}

fn qualification_loss_counters(
    counters: CollectorLifecycleCounters,
    dropped_samples: u64,
) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([
        ("ring_buffer_reserve", counters.global_reserve_failures),
        ("map_pressure", counters.global_map_pressure),
        (
            "pairing",
            counters
                .scope_missing_entries
                .saturating_add(counters.scope_missing_exits)
                .saturating_add(counters.scope_pending),
        ),
        (
            "decode",
            counters
                .global_abi_mismatches
                .saturating_add(counters.global_decode_failures)
                .saturating_add(counters.global_truncations),
        ),
        ("queue", dropped_samples),
        ("writer", 0),
        ("lifecycle_gap", 0),
    ])
}

fn live_collector_failure_reason(error: &str) -> CollectorFailureReason {
    let error = error.to_ascii_lowercase();
    if error.contains("collector lifecycle stop") || error.contains("flush live observer timeline")
    {
        CollectorFailureReason::IncompleteTerminalFlush
    } else if error.contains("counter") || error.contains("apolysis_counters") {
        CollectorFailureReason::CounterReadFailure
    } else if error.contains("abi") {
        CollectorFailureReason::AbiMismatch
    } else if error.contains("decode") || error.contains("canonical") {
        CollectorFailureReason::DecodeFailure
    } else if error.contains("write")
        || error.contains("flush")
        || error.contains("persist")
        || error.contains("timeline")
    {
        CollectorFailureReason::StorageFailure
    } else {
        CollectorFailureReason::ObserverFailure
    }
}

fn persist_collector_start_boundary(
    agent_run_id: &str,
    collector_instance_id: &str,
    scope: &LiveScope,
    loader_plan: &AyaLoaderPlan,
    late_attach_detail: Option<&str>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let late_attach = late_attach_detail.map(|detail| {
        ObservationGap::new(
            agent_run_id,
            "collector_lifecycle",
            ObservationGapKind::LateAttach,
            1,
            detail,
        )
    });
    let capability = audit_observer_capability_manifest(agent_run_id, scope, loader_plan);
    let started = CollectorLifecycleRecord::started(agent_run_id, collector_instance_id);
    let mut records = Vec::<&dyn JsonLine>::with_capacity(3);
    if let Some(gap) = late_attach.as_ref() {
        records.push(gap);
    }
    records.push(&capability);
    records.push(&started);
    store.append_batch_and_sync(&records).map_err(|error| {
        format!("failed to persist collector start boundary to stable storage: {error}")
    })
}

fn append_failed_collector_lifecycle(
    agent_run_id: &str,
    collector_instance_id: &str,
    reason: CollectorFailureReason,
    counters: CollectorLifecycleCounters,
    store: &mut JsonlStore,
) -> Result<(), String> {
    store
        .append(&CollectorLifecycleRecord::failed(
            agent_run_id,
            collector_instance_id,
            reason,
            counters,
        ))
        .map_err(|error| format!("failed to write collector failure lifecycle: {error}"))?;
    store
        .flush()
        .map_err(|error| format!("failed to flush collector failure lifecycle: {error}"))
}

fn append_content_off_runtime_event(
    raw: &RawKernelEvent,
    canonical: &CanonicalEvent,
    redactor: &Redactor,
    store: &mut JsonlStore,
) -> Result<CanonicalEvent, String> {
    let (persisted_raw, persisted_canonical) = RuntimeEvidencePersistence::new(redactor)
        .persist_event(
            raw,
            canonical,
            canonical.event_type == apolysis_core::EventType::CredentialRead,
        );
    store
        .append(&persisted_raw)
        .map_err(|error| format!("failed to write live raw event: {error}"))?;
    store
        .append(&persisted_canonical)
        .map_err(|error| format!("failed to write live canonical event: {error}"))?;
    Ok(persisted_canonical)
}

pub struct ObserverBatchDecoder {
    monotonic_ns: u64,
    unix_ms: u128,
    host_boot_id: Option<String>,
}

impl ObserverBatchDecoder {
    pub fn new(monotonic_ns: u64, unix_ms: u128) -> Self {
        Self {
            monotonic_ns,
            unix_ms,
            host_boot_id: None,
        }
    }

    pub fn with_host_boot_id(mut self, host_boot_id: impl Into<String>) -> Self {
        self.host_boot_id = Some(host_boot_id.into());
        self
    }

    fn capture() -> Result<Self, String> {
        let host_boot_id = read_host_boot_id_at("/proc/sys/kernel/random/boot_id")?;
        Self::capture_with_host_boot_id(host_boot_id)
    }

    fn capture_with_host_boot_id(host_boot_id: impl Into<String>) -> Result<Self, String> {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
            .as_millis();
        Ok(Self {
            monotonic_ns: monotonic_now_ns()?,
            unix_ms,
            host_boot_id: Some(host_boot_id.into()),
        })
    }

    pub fn decode(&self, records: Vec<Vec<u8>>) -> DaemonObserverBatch {
        let mut batch = DaemonObserverBatch::default();
        for bytes in records {
            let record = match KernelEventRecord::decode(&bytes) {
                Ok(record) => record,
                Err(error) if error.is_abi_mismatch() => {
                    batch.abi_mismatches += 1;
                    continue;
                }
                Err(_) => {
                    batch.decode_failures += 1;
                    continue;
                }
            };
            if record.flags & (FLAG_RESOURCE_TRUNCATED | FLAG_PAYLOAD_TRUNCATED) != 0 {
                batch.truncations += 1;
            }
            batch.events.push(DaemonKernelEvent {
                timestamp_unix_ms: self.to_unix_ms(record.timestamp_ns),
                host_boot_id: self.host_boot_id.clone(),
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

fn process_cpu_usage() -> Result<(u64, u64), String> {
    // SAFETY: zero is a valid initialization for rusage before getrusage fills it.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    // SAFETY: usage points to valid writable rusage memory.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(format!(
            "failed to read collector CPU usage: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((timeval_ns(usage.ru_utime), timeval_ns(usage.ru_stime)))
}

fn timeval_ns(value: libc::timeval) -> u64 {
    (value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((value.tv_usec as u64).saturating_mul(1_000))
}

fn read_process_memory(path: &Path) -> Result<ProcessMemory, String> {
    let source = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read collector memory {}: {error}",
            path.display()
        )
    })?;
    parse_proc_status_memory(&source)
}

fn parse_proc_status_memory(source: &str) -> Result<ProcessMemory, String> {
    let kib = |name: &str| -> Result<u64, String> {
        let value = source
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| format!("collector process status is missing {name}"))?;
        let mut parts = value.split_whitespace();
        let amount = parts
            .next()
            .ok_or_else(|| format!("collector process status has empty {name}"))?
            .parse::<u64>()
            .map_err(|error| format!("collector process status has invalid {name}: {error}"))?;
        if parts.next() != Some("kB") || parts.next().is_some() {
            return Err(format!("collector process status has invalid {name} unit"));
        }
        Ok(amount.saturating_mul(1024))
    };
    Ok(ProcessMemory {
        rss_bytes: kib("VmRSS:")?,
        peak_rss_bytes: kib("VmHWM:")?,
    })
}

fn read_u64_file(path: &Path) -> Result<u64, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    source
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("{} is not an unsigned integer: {error}", path.display()))
}

fn verify_qualification_cgroup_isolation(
    collector: &Path,
    workload: &Path,
    managed_agent_pid: u32,
) -> Result<(), String> {
    let mount = Path::new("/sys/fs/cgroup")
        .canonicalize()
        .map_err(|error| format!("failed to resolve cgroup v2 mount: {error}"))?;
    let collector = collector
        .canonicalize()
        .map_err(|error| format!("failed to resolve collector cgroup: {error}"))?;
    let workload = workload
        .canonicalize()
        .map_err(|error| format!("failed to resolve managed workload cgroup: {error}"))?;
    if !collector.starts_with(&mount)
        || !workload.starts_with(&mount)
        || collector.parent() != workload.parent()
        || collector == workload
    {
        return Err(
            "qualification collector/workload cgroups are not isolated siblings".to_string(),
        );
    }
    let membership = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("failed to read collector cgroup membership: {error}"))?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "collector has no unified cgroup v2 membership".to_string())?
        .to_string();
    let current = mount
        .join(
            Path::new(&membership)
                .strip_prefix(Path::new("/"))
                .unwrap_or(Path::new(&membership)),
        )
        .canonicalize()
        .map_err(|error| format!("failed to resolve collector cgroup membership: {error}"))?;
    if current != collector {
        return Err("qualification collector is not in the declared collector cgroup".to_string());
    }
    if read_cgroup_pids(&collector)? != vec![std::process::id()]
        || read_cgroup_pids(&workload)? != vec![managed_agent_pid]
    {
        return Err(
            "qualification cgroups contain processes outside the collector/workload pair"
                .to_string(),
        );
    }
    Ok(())
}

fn read_cgroup_pids(cgroup: &Path) -> Result<Vec<u32>, String> {
    let source = fs::read_to_string(cgroup.join("cgroup.procs"))
        .map_err(|error| format!("failed to read {} cgroup.procs: {error}", cgroup.display()))?;
    let mut pids = source
        .lines()
        .map(|line| {
            line.parse::<u32>()
                .map_err(|error| format!("invalid cgroup PID {line}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    pids.sort_unstable();
    Ok(pids)
}

fn bpf_memory_bytes(ebpf: &Ebpf) -> Result<(u64, u64), String> {
    let mut map_ids = BTreeSet::new();
    let mut map_bytes = 0_u64;
    for (name, map) in ebpf.maps() {
        let info =
            map_info(map).map_err(|error| format!("failed to inspect BPF map {name}: {error}"))?;
        if map_ids.insert(info.id()) {
            let fd = info
                .fd()
                .map_err(|error| format!("failed to open BPF map {name} info fd: {error}"))?;
            let path = PathBuf::from(format!("/proc/self/fdinfo/{}", fd.as_fd().as_raw_fd()));
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("failed to read BPF map {name} fdinfo: {error}"))?;
            map_bytes = map_bytes.saturating_add(parse_fdinfo_memlock(&source)?);
        }
    }

    let mut program_ids = BTreeSet::new();
    let mut program_bytes = 0_u64;
    for (name, program) in ebpf.programs() {
        let info = program
            .info()
            .map_err(|error| format!("failed to inspect BPF program {name}: {error}"))?;
        if program_ids.insert(info.id()) {
            program_bytes =
                program_bytes.saturating_add(u64::from(info.memory_locked().map_err(|error| {
                    format!("failed to read BPF program {name} memlock: {error}")
                })?));
        }
    }
    Ok((map_bytes, program_bytes))
}

fn map_info(map: &Map) -> Result<aya::maps::MapInfo, MapError> {
    let data = match map {
        Map::Array(data)
        | Map::BloomFilter(data)
        | Map::CpuMap(data)
        | Map::DevMap(data)
        | Map::DevMapHash(data)
        | Map::HashMap(data)
        | Map::LpmTrie(data)
        | Map::LruHashMap(data)
        | Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data)
        | Map::PerCpuLruHashMap(data)
        | Map::PerfEventArray(data)
        | Map::ProgramArray(data)
        | Map::Queue(data)
        | Map::RingBuf(data)
        | Map::SockHash(data)
        | Map::SockMap(data)
        | Map::Stack(data)
        | Map::StackTraceMap(data)
        | Map::Unsupported(data)
        | Map::XskMap(data) => data,
    };
    data.info()
}

fn parse_fdinfo_memlock(source: &str) -> Result<u64, String> {
    let value = source
        .lines()
        .find_map(|line| line.strip_prefix("memlock:"))
        .ok_or_else(|| "BPF fdinfo is missing memlock".to_string())?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("BPF fdinfo has invalid memlock: {error}"))
}

fn read_host_boot_id_at(path: impl AsRef<Path>) -> Result<String, String> {
    let path = path.as_ref();
    let boot_id = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read host boot identity {}: {error}",
            path.display()
        )
    })?;
    let boot_id = boot_id.trim();
    if !valid_host_boot_id(boot_id) {
        return Err(format!("invalid host boot identity in {}", path.display()));
    }
    Ok(boot_id.to_ascii_lowercase())
}

fn valid_host_boot_id(boot_id: &str) -> bool {
    boot_id.len() == 36
        && boot_id.char_indices().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
}

fn validate_initial_time_namespace_offsets(input: &str) -> Result<(), String> {
    let mut monotonic = false;
    let mut boottime = false;
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let Some(clock) = fields.next() else {
            continue;
        };
        let seconds = fields
            .next()
            .ok_or_else(|| "invalid observer time namespace offsets".to_string())?
            .parse::<i64>()
            .map_err(|_| "invalid observer time namespace offsets".to_string())?;
        let nanoseconds = fields
            .next()
            .ok_or_else(|| "invalid observer time namespace offsets".to_string())?
            .parse::<u32>()
            .map_err(|_| "invalid observer time namespace offsets".to_string())?;
        if fields.next().is_some() {
            return Err("invalid observer time namespace offsets".to_string());
        }
        if seconds != 0 || nanoseconds != 0 {
            return Err(
                "protected existing-process attach requires the initial time namespace".to_string(),
            );
        }
        match clock {
            "monotonic" => monotonic = true,
            "boottime" => boottime = true,
            _ => {}
        }
    }
    if !monotonic || !boottime {
        return Err("observer time namespace offsets are incomplete".to_string());
    }
    Ok(())
}

pub fn raw_event_from_record(
    record: &KernelEventRecord,
    session_id: &str,
    timestamp_unix_ms: u128,
    host_boot_id: &str,
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

    let raw = RawKernelEvent::new(
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
    )
    .with_process_identity(
        Some(host_boot_id.to_string()),
        Some(record.scope_generation),
        Some(record.process_generation),
        Some(record.process_start_time_ns),
        Some(record.exec_generation),
        Some(record.parent_process_generation),
        Some(record.parent_exec_generation),
    );
    Ok(match record.return_value() {
        Some(return_value) => {
            raw.with_operation_result(operation_result_from_syscall_return(kind, return_value))
        }
        None => raw,
    })
}

fn operation_result_from_syscall_return(
    kind: KernelEventKind,
    return_value: i64,
) -> OperationResult {
    if return_value >= 0 {
        return OperationResult::new(OperationOutcome::Succeeded, return_value, None);
    }
    let errno = return_value
        .checked_neg()
        .and_then(|value| i32::try_from(value).ok());
    let outcome = match errno {
        Some(libc::EACCES | libc::EPERM) => OperationOutcome::Denied,
        Some(libc::EINPROGRESS | libc::EALREADY) if kind == KernelEventKind::Connect => {
            OperationOutcome::Pending
        }
        _ => OperationOutcome::Failed,
    };
    OperationResult::new(outcome, return_value, errno)
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
    use std::collections::VecDeque;
    use std::os::unix::fs::symlink;

    #[test]
    fn identity_validation_sandwich_rejects_post_update_churn() {
        let identity_is_stable = std::cell::Cell::new(true);
        let validations = std::cell::Cell::new(0_u32);

        let error = with_identity_validation_sandwich(
            || {
                validations.set(validations.get() + 1);
                if identity_is_stable.get() {
                    Ok(())
                } else {
                    Err("existing process exited before protected attach activation".to_string())
                }
            },
            || {
                identity_is_stable.set(false);
                Ok(())
            },
        )
        .expect_err("post-update validation must reject identity churn");

        assert_eq!(validations.get(), 2);
        assert!(error.contains("exited before protected attach activation"));
    }

    #[test]
    fn standalone_lifecycle_checkpoint_keeps_global_and_scope_loss_explicit() {
        let counters = live_collector_lifecycle_counters(
            DaemonObserverCounters {
                reserve_failures: 2,
                map_pressure: 3,
                connect_missing_entries: 5,
                connect_missing_exits: 7,
                connect_pending: 11,
                file_operations: FileOperationCounters {
                    open: OperationPairCounters {
                        missing_entries: 13,
                        missing_exits: 17,
                        pending: 19,
                    },
                    ..FileOperationCounters::default()
                },
            },
            23,
            29,
            31,
        );

        assert_eq!(counters.global_reserve_failures, 2);
        assert_eq!(counters.global_map_pressure, 3);
        assert_eq!(counters.global_abi_mismatches, 23);
        assert_eq!(counters.global_decode_failures, 29);
        assert_eq!(counters.global_truncations, 31);
        assert_eq!(counters.scope_missing_entries, 18);
        assert_eq!(counters.scope_missing_exits, 24);
        assert_eq!(counters.scope_pending, 30);
        assert!(counters.has_loss());
    }

    #[test]
    fn standalone_lifecycle_failure_reason_preserves_counter_and_storage_boundaries() {
        assert_eq!(
            live_collector_failure_reason("failed to read observer counters"),
            CollectorFailureReason::CounterReadFailure
        );
        assert_eq!(
            live_collector_failure_reason("failed to write live raw event"),
            CollectorFailureReason::StorageFailure
        );
        assert_eq!(
            live_collector_failure_reason("ring-buffer poll failure"),
            CollectorFailureReason::ObserverFailure
        );
        assert_eq!(
            live_collector_failure_reason("failed to flush live observer timeline"),
            CollectorFailureReason::IncompleteTerminalFlush
        );
    }

    #[test]
    fn cgroup_drain_waits_for_inflight_kernel_counter_updates() {
        let mut observed = VecDeque::from([2, 1, 0]);

        wait_for_scope_updates_to_drain(|| {
            Ok(observed.pop_front().expect("bounded poll sequence"))
        })
        .expect("in-flight updates drain");

        assert!(observed.is_empty());
    }

    #[test]
    fn host_boot_identity_is_read_once_from_the_kernel_boundary() {
        let root =
            std::env::temp_dir().join(format!("apolysis-host-boot-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create boot identity fixture");
        let boot_id = root.join("boot_id");
        std::fs::write(&boot_id, "11111111-2222-3333-4444-555555555555\n")
            .expect("write boot identity fixture");

        assert_eq!(
            read_host_boot_id_at(&boot_id).expect("read host boot identity"),
            "11111111-2222-3333-4444-555555555555"
        );

        std::fs::write(&boot_id, "not a boot id\n").expect("write invalid boot identity fixture");
        assert!(read_host_boot_id_at(&boot_id).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn protected_attach_binds_the_root_cwd_to_the_canonical_workspace() {
        let root = temp_proc_root("protected-attach-workspace");
        let _ = std::fs::remove_dir_all(&root);
        let proc_root = root.join("proc");
        let pid_root = proc_root.join("101");
        let workspace = root.join("workspace");
        let workspace_child = workspace.join("src");
        let outside = root.join("outside");
        std::fs::create_dir_all(&pid_root).expect("create fake proc root");
        std::fs::create_dir_all(&workspace_child).expect("create workspace child");
        std::fs::create_dir_all(&outside).expect("create outside directory");
        let canonical_workspace = std::fs::canonicalize(&workspace).expect("canonical workspace");

        symlink(&workspace_child, pid_root.join("cwd")).expect("link in-workspace cwd");
        validate_process_workspace_boundary_at(&proc_root, 101, &canonical_workspace)
            .expect("workspace descendants are inside the boundary");

        std::fs::remove_file(pid_root.join("cwd")).expect("replace fake cwd");
        symlink(&outside, pid_root.join("cwd")).expect("link outside cwd");
        let error = validate_process_workspace_boundary_at(&proc_root, 101, &canonical_workspace)
            .expect_err("an outside cwd must fail closed");
        assert!(error.contains("workspace boundary mismatch"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn protected_attach_rejects_non_initial_time_namespace_offsets() {
        validate_initial_time_namespace_offsets(
            "monotonic           0         0\nboottime            0         0\n",
        )
        .expect("initial time namespace");

        let error = validate_initial_time_namespace_offsets(
            "monotonic           1         0\nboottime            0         0\n",
        )
        .expect_err("non-initial time namespace must fail closed");

        assert!(error.contains("initial time namespace"));
        validate_initial_time_namespace_inode(0xEFFF_FFFA)
            .expect("Linux initial time namespace inode");
        assert!(validate_initial_time_namespace_inode(0xF000_0001).is_err());
    }

    #[test]
    fn protected_attach_requires_the_initial_pid_namespace() {
        validate_initial_pid_namespace_status("Name:\tapolysis\nNSpid:\t101\n")
            .expect("one visible PID is the initial namespace");

        let error = validate_initial_pid_namespace_status("Name:\tapolysis\nNSpid:\t4101\t101\n")
            .expect_err("nested PID namespaces must fail closed");

        assert!(error.contains("initial PID namespace"));
        assert!(validate_initial_pid_namespace_status("Name:\tapolysis\n").is_err());
        validate_initial_pid_namespace_inode(0xEFFF_FFFC)
            .expect("Linux initial PID namespace inode");
        assert!(validate_initial_pid_namespace_inode(0xF000_0001).is_err());
    }

    #[test]
    fn seeded_candidate_namespace_links_fail_closed_on_nested_identity() {
        let root = temp_proc_root("candidate-namespace-links");
        let _ = std::fs::remove_dir_all(&root);
        let observer_pid = root.join("self/ns/pid");
        let candidate_pid = root.join("200/ns/pid");
        let observer_time = root.join("self/ns/time");
        let candidate_time = root.join("200/ns/time");
        std::fs::create_dir_all(observer_pid.parent().expect("observer namespace parent"))
            .expect("create observer namespace parent");
        std::fs::create_dir_all(candidate_pid.parent().expect("candidate namespace parent"))
            .expect("create candidate namespace parent");
        symlink("pid:[4026531836]", &observer_pid).expect("link observer PID namespace");
        symlink("pid:[4026531836]", &candidate_pid).expect("link candidate PID namespace");
        symlink("time:[4026531834]", &observer_time).expect("link observer time namespace");
        symlink("time:[4026531834]", &candidate_time).expect("link candidate time namespace");

        validate_matching_namespace_links(
            &observer_pid,
            &candidate_pid,
            "observer PID unavailable",
            "candidate PID unavailable",
            "PID namespace mismatch",
        )
        .expect("matching PID namespace");
        validate_matching_namespace_links(
            &observer_time,
            &candidate_time,
            "observer time unavailable",
            "candidate time unavailable",
            "time namespace mismatch",
        )
        .expect("matching time namespace");

        std::fs::remove_file(&candidate_pid).expect("replace candidate PID namespace");
        symlink("pid:[5000000001]", &candidate_pid).expect("link nested PID namespace");
        assert!(validate_matching_namespace_links(
            &observer_pid,
            &candidate_pid,
            "observer PID unavailable",
            "candidate PID unavailable",
            "PID namespace mismatch",
        )
        .is_err());

        std::fs::remove_file(&candidate_time).expect("replace candidate time namespace");
        symlink("time:[5000000002]", &candidate_time).expect("link shifted time namespace");
        assert!(validate_matching_namespace_links(
            &observer_time,
            &candidate_time,
            "observer time unavailable",
            "candidate time unavailable",
            "time namespace mismatch",
        )
        .is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn cgroup_drain_does_not_treat_a_barrier_read_failure_as_a_timeout() {
        let error = wait_for_scope_updates_to_drain(|| Err("barrier map missing".to_string()))
            .expect_err("barrier read failure must fail closed");

        assert_eq!(
            error,
            ScopeDrainWaitError::Read("barrier map missing".to_string())
        );
    }

    #[test]
    fn cgroup_scope_generations_are_nonzero_and_monotonic() {
        let mut generations = ScopeGenerationSequence::default();

        let first = generations.allocate().expect("first scope generation");
        let second = generations.allocate().expect("second scope generation");

        assert_eq!(first.get(), 1);
        assert_eq!(second.get(), 2);
        assert!(ScopeGeneration::new(0).is_err());
    }

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

        let mut managed = spawn_managed_agent(&request, Path::new("."), None).unwrap();
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
            RuntimeEvidencePersistence::new(&redactor).persist_event(&raw, &canonical, true);

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
    fn persisted_supervisor_metadata_is_content_off() {
        let path = std::env::temp_dir().join(format!(
            "apolysis-supervisor-content-off-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let mut store = JsonlStore::create(&path).expect("metadata store");
        let metadata = AgentScopeMetadata {
            supervisor_mode: "apolysis_managed_launch".to_string(),
            kind: "codex".to_string(),
            root_pid: 101,
            executable: "/home/alice/private/bin/codex".to_string(),
            workspace_root: "/home/alice/private/workspace".to_string(),
            start_time_ticks: Some(77),
        };

        write_agent_supervisor_metadata("session-a", &metadata, &mut store)
            .expect("persist metadata");
        store.flush().expect("flush metadata");
        let timeline = std::fs::read_to_string(&path).expect("read metadata");

        assert!(timeline.contains("argv_redacted:true,content_off:true"));
        assert!(timeline.contains("executable_ref:codex"));
        assert!(timeline.contains("workspace_ref:redacted"));
        assert!(!timeline.contains("agent-command-fingerprint"));
        assert!(!timeline.contains("sha256:"));
        assert!(!timeline.contains("/home/alice/private"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn standalone_live_writer_is_content_off_before_jsonl_append() {
        let path = std::env::temp_dir().join(format!(
            "apolysis-live-content-off-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
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
            "/home/alice/private/bin/codex",
            "exec",
            None,
            Some("42".to_string()),
            "argv:/home/alice/private/bin/codex write-the-secret sk-live-secret,argv_truncated:true,payload_truncated:true",
        );
        let canonical = CanonicalEvent::new(
            "session-a",
            EventSource::KernelTracepoint,
            EventType::Exec,
            101,
            100,
            "codex",
            "/home/alice/private/bin/codex",
            "exec",
        )
        .with_process_context(
            "/home/alice/private/bin/codex write-the-secret sk-live-secret",
            "/home/alice/private/bin/codex",
            1,
        );
        let redactor = crate::Redactor::new("session-a", "/home/alice/private/workspace");
        let mut store = JsonlStore::create(&path).expect("live store");

        append_content_off_runtime_event(&raw, &canonical, &redactor, &mut store)
            .expect("append runtime event");
        store.flush().expect("flush live store");
        let timeline = std::fs::read_to_string(&path).expect("read live timeline");

        assert!(timeline.contains("argv_redacted:true"));
        assert!(timeline.contains("argv_truncated:true"));
        assert!(timeline.contains("payload_truncated:true"));
        assert!(timeline.contains("executable_ref:codex"));
        assert!(timeline.contains(r#""process_command":null"#));
        for forbidden in [
            "write-the-secret",
            "sk-live-secret",
            "/home/alice/private",
            "agent-command-fingerprint",
        ] {
            assert!(
                !timeline.contains(forbidden),
                "leaked {forbidden}: {timeline}"
            );
        }
        let _ = std::fs::remove_file(path);
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
    fn persisted_exec_payload_removes_all_argv_content() {
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
            RuntimeEvidencePersistence::new(&redactor).persist_event(&raw, &canonical, false);

        assert!(persisted_raw.raw_payload.contains("argv_redacted:true"));
        assert!(persisted_raw.raw_payload.contains("redacted:payload"));
        for forbidden in [
            "/usr/bin/codex exec",
            "--api-key",
            "sk-test-secret",
            "/workspace/.env",
            "/workspace/src/main.rs",
            "127.0.0.1",
        ] {
            assert!(!persisted_raw.raw_payload.contains(forbidden));
        }
    }

    #[test]
    fn persisted_canonical_event_omits_process_command() {
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
            RuntimeEvidencePersistence::new(&redactor).persist_event(&raw, &canonical, false);

        assert_eq!(persisted_canonical.process_command, None);
        assert!(persisted_canonical
            .process_executable
            .as_deref()
            .is_some_and(|value| value.starts_with("executable_ref:")));
    }

    #[test]
    fn process_context_enriches_exec_and_exit_before_cleanup() {
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

        let exec_event = contexts
            .observe(&exec_raw, canonicalize(&exec_raw))
            .expect("observe exec context");

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

        let exit_event = contexts
            .observe(&exit_raw, canonicalize(&exit_raw))
            .expect("observe exit context");

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

        let stale_event = contexts
            .observe(&stale_raw, canonicalize(&stale_raw))
            .expect("observe post-exit event");

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
            host_boot_id: "11111111-2222-3333-4444-555555555555".to_string(),
            workspace_root: PathBuf::from("/workspace/apolysis"),
            executable: "/usr/bin/codex".to_string(),
            command_fingerprint: "sha256:test".to_string(),
            command: None,
        };

        let error = registration
            .validate_runtime_identity(&proc_root, "11111111-2222-3333-4444-555555555555")
            .expect_err("registration with stale start time must fail closed");

        assert!(error.contains("PID reuse"));
        assert!(error.contains("pid=101"));
        assert!(error.contains("expected_start_time_ticks=9999"));
        assert!(error.contains("actual_start_time_ticks=9001"));

        let _ = std::fs::remove_dir_all(&proc_root);
    }

    #[test]
    fn tracked_process_membership_carries_a_bounded_start_identity() {
        let clock = ProcStartClock::new(100).expect("proc clock");
        let identity = ProcessRuntimeIdentity::new(101, 123).expect("process identity");

        let window = clock
            .start_boottime_window(identity)
            .expect("tracked start window");
        let membership = TrackedProcessIdentityAbi::expected(window.lower_ns, window.upper_ns)
            .expect("tracked membership");

        assert_eq!(membership.start_boottime_ns(), 1_230_000_000);
        assert_eq!(membership.start_boottime_upper_ns(), 1_240_000_000);
        assert!(membership.is_expected());
        assert_eq!(std::mem::size_of::<TrackedProcessIdentityAbi>(), 24);
    }

    #[test]
    fn protected_existing_process_only_seeds_after_tracepoint_attach() {
        assert_eq!(SCOPE_MODE_INACTIVE, 0);
        assert_eq!(
            attached_scope_preparation_mode(&LiveScope::ProcessTree(101), true),
            SCOPE_MODE_PID_TREE_SEEDING
        );
        assert_eq!(
            attached_scope_preparation_mode(&LiveScope::ProcessTree(101), false),
            SCOPE_MODE_INACTIVE
        );
        assert_eq!(
            attached_scope_preparation_mode(&LiveScope::Cgroup(202), true),
            SCOPE_MODE_INACTIVE
        );
    }

    #[test]
    fn protected_attach_boundary_is_durable_before_capability_and_start() {
        let output = temp_proc_root("protected-attach-start-boundary").with_extension("jsonl");
        let archive = PathBuf::from(format!("{}.1", output.display()));
        let _ = std::fs::remove_file(&output);
        let _ = std::fs::remove_file(&archive);
        let mut store = JsonlStore::create_with_rotation(
            &output,
            JsonlRotationPolicy {
                max_file_bytes: 1,
                max_archived_files: 1,
            },
        )
        .expect("create rotating boundary timeline");
        write_runtime_metadata_event(
            "agent-run-protected-attach",
            actors::OBSERVER,
            "boundary-preface",
            "present",
            &mut store,
        )
        .expect("write boundary preface");
        let plan = AyaLoaderPlan::audit_observer_default("observer.bpf.o");
        let detail = "collection_boundary:protected_existing_process_attach,history:unknown,provenance:external_registration,root_selection:registration_qualified";

        persist_collector_start_boundary(
            "agent-run-protected-attach",
            "collector-instance-protected-attach",
            &LiveScope::ProcessTree(101),
            &plan,
            Some(detail),
            &mut store,
        )
        .expect("persist protected attach boundary");

        let timeline = std::fs::read_to_string(&output).expect("read boundary timeline");
        let gap = timeline.find(r#""kind":"late_attach""#).expect("late gap");
        let capability = timeline
            .find(r#""record_type":"collector_capability_manifest""#)
            .expect("capability manifest");
        let started = timeline
            .find(r#""state":"started""#)
            .expect("collector start");
        assert!(gap < capability && capability < started);
        assert!(timeline.contains(r#""operation":"collector_lifecycle""#));
        assert!(timeline.contains(r#""count":1"#));
        assert!(timeline.contains(detail));
        assert_eq!(timeline.matches(r#""kind":"late_attach""#).count(), 1);
        let rotated = std::fs::read_to_string(&archive).expect("read rotated preface");
        assert!(rotated.contains("boundary-preface"));

        let _ = std::fs::remove_file(output);
        let _ = std::fs::remove_file(archive);
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
                    executable: "/private/operator/bin/codex",
                    cwd: "/workspace/apolysis",
                    argv: &["codex", "resume", "session-a", "--token", "do-not-persist"],
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
        assert!(!error.contains("/private/operator"));
        assert!(!error.contains("do-not-persist"));

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
            session_id: "session-agent-scope-conflict".to_string(),
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
            qualification_telemetry: None,
        };

        assert_eq!(
            request.validate(),
            Err("--agent-run cannot be combined with --scope-pid or --scope-cgroup".to_string())
        );
    }

    #[test]
    fn qualification_telemetry_is_bounded_and_contains_no_event_content() {
        let mut telemetry = QualificationTelemetryRecorder::empty_for_test(1);
        telemetry.record("openat", 10, 20, 30);
        telemetry.record("connect", 40, 50, 60);

        assert_eq!(telemetry.samples.len(), 1);
        assert_eq!(telemetry.dropped_samples, 1);
        assert_eq!(telemetry.samples[0].event_name, "openat");
        assert_eq!(telemetry.samples[0].kernel_timestamp_ns, 10);
        assert_eq!(telemetry.samples[0].decoded_monotonic_ns, 20);
        assert_eq!(telemetry.samples[0].appended_monotonic_ns, 30);

        let rendered = serde_json::to_string(&telemetry.report()).expect("serialize telemetry");
        assert!(!rendered.contains("payload"));
        assert!(!rendered.contains("action"));
        assert!(!rendered.contains("collector_cgroup_path"));
    }

    #[test]
    fn qualification_telemetry_refuses_a_symlink_output() {
        let root = std::env::temp_dir().join(format!(
            "apolysis-qualification-telemetry-symlink-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create telemetry test root");
        let protected_target = root.join("protected-target.json");
        let output = root.join("telemetry.json");
        std::os::unix::fs::symlink(&protected_target, &output).expect("create telemetry symlink");

        let mut telemetry = QualificationTelemetryRecorder::empty_for_test(1);
        telemetry.record("openat", 10, 20, 30);
        let error = telemetry
            .persist(&output)
            .expect_err("telemetry must reject a symlink output");

        assert!(error.contains("failed to create qualification telemetry"));
        assert!(!protected_target.exists());
        std::fs::remove_file(output).expect("remove telemetry symlink");
        std::fs::remove_dir(root).expect("remove telemetry test root");
    }

    #[test]
    fn qualification_resource_parser_requires_rss_and_peak_rss() {
        let status = "Name:\tapolysis\nVmPeak:\t  9999 kB\nVmRSS:\t  2048 kB\nVmHWM:\t  3072 kB\n";

        let memory = parse_proc_status_memory(status).expect("parse process memory");

        assert_eq!(memory.rss_bytes, 2 * 1024 * 1024);
        assert_eq!(memory.peak_rss_bytes, 3 * 1024 * 1024);
        assert!(parse_proc_status_memory("Name:\tapolysis\nVmRSS:\t1 kB\n").is_err());
    }

    #[test]
    fn qualification_bpf_memlock_parser_is_strict() {
        assert_eq!(
            parse_fdinfo_memlock("pos:\t0\nflags:\t02000002\nmemlock:\t4096\n")
                .expect("parse BPF memlock"),
            4096
        );
        assert!(parse_fdinfo_memlock("pos:\t0\nflags:\t02000002\n").is_err());
        assert!(parse_fdinfo_memlock("memlock:\tnot-a-number\n").is_err());
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

// SPDX-License-Identifier: Apache-2.0

//! Local runtime execution and process attribution for Apolysis.
//!
//! M3 still runs in audit mode: it records local and Docker runtime evidence,
//! but does not claim to enforce kernel-level isolation. This crate keeps
//! runtime adapters behind a thin CLI before Kubernetes and eBPF backends are
//! added.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use apolysis_core::{
    CanonicalEvent, EnforcementBackend, EventSource, EventType, PolicyDecision as CoreDecision,
    PolicyViolation, RuntimeKind, SandboxSession,
};
use apolysis_policy::Policy;
use apolysis_store::JsonlStore;

const POLL_INTERVAL: Duration = Duration::from_millis(25);
const SIGKILL: i32 = 9;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRunRequest {
    pub policy_path: PathBuf,
    pub output_path: PathBuf,
    pub command: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerRunRequest {
    pub policy_path: PathBuf,
    pub output_path: PathBuf,
    pub image: String,
    pub oci_runtime: Option<String>,
    pub command: Vec<String>,
}

impl DockerRunRequest {
    pub fn new(
        policy_path: impl Into<PathBuf>,
        output_path: impl Into<PathBuf>,
        image: impl Into<String>,
        command: Vec<String>,
    ) -> Self {
        Self {
            policy_path: policy_path.into(),
            output_path: output_path.into(),
            image: image.into(),
            oci_runtime: None,
            command,
        }
    }

    pub fn with_oci_runtime(mut self, oci_runtime: Option<String>) -> Self {
        self.oci_runtime = oci_runtime;
        self
    }
}

impl LocalRunRequest {
    pub fn new(
        policy_path: impl Into<PathBuf>,
        output_path: impl Into<PathBuf>,
        command: Vec<String>,
    ) -> Self {
        Self {
            policy_path: policy_path.into(),
            output_path: output_path.into(),
            command,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRunResult {
    pub session_id: String,
    pub exit_code: i32,
    pub attribution_mode: AttributionMode,
    pub discovered_processes: usize,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttributionMode {
    ProcessTree,
    DockerCli,
}

impl AttributionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessTree => "process_tree",
            Self::DockerCli => "docker_cli",
        }
    }
}

pub fn run_local(request: LocalRunRequest) -> Result<LocalRunResult, String> {
    if request.command.is_empty() {
        return Err("local run requires a command".to_string());
    }

    let policy = load_policy(&request.policy_path)?;
    let session_id = format!(
        "local-{}-{}",
        std::process::id(),
        apolysis_core::now_unix_ms()
    );
    let session = SandboxSession::new(
        &session_id,
        RuntimeKind::Local,
        request.policy_path.to_string_lossy(),
    );
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create timeline: {error}"))?;

    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::Manual,
            EventType::SessionStarted,
            std::process::id(),
            0,
            "apolysis",
            "local-session",
            "start",
        ),
    )?;
    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::ProcessTree,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "process_tree",
            "local-attribution",
            "mode:process_tree",
        ),
    )?;

    let mut child = Command::new(&request.command[0])
        .args(&request.command[1..])
        .env("APOLYSIS_SESSION_ID", &session.id)
        .spawn()
        .map_err(|error| format!("failed to start command: {error}"))?;

    let root_pid = child.id();
    let root_actor = request.command.join(" ");
    let mut seen = HashMap::from([(root_pid, root_actor.clone())]);
    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::ProcessTree,
            EventType::Exec,
            root_pid,
            std::process::id(),
            &root_actor,
            "process",
            "exec",
        ),
    )?;

    let started_at = Instant::now();
    let max_duration = policy.runtime.max_seconds.map(Duration::from_secs);
    let mut timed_out = false;

    loop {
        sample_descendants(&session.id, root_pid, &mut seen, &mut store)?;

        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to poll command status: {error}"))?
        {
            let exit_code = status.code().unwrap_or(1);
            append_exit_event(&session.id, root_pid, &root_actor, exit_code, &mut store)?;
            store
                .flush()
                .map_err(|error| format!("failed to flush timeline: {error}"))?;
            return Ok(LocalRunResult {
                session_id: session.id,
                exit_code,
                attribution_mode: AttributionMode::ProcessTree,
                discovered_processes: seen.len(),
                timed_out,
            });
        }

        if max_duration
            .map(|limit| started_at.elapsed() >= limit)
            .unwrap_or(false)
        {
            timed_out = true;
            append_timeout_violation(&session.id, root_pid, &root_actor, &mut store)?;
            kill_process_tree(root_pid);
            let _ = child.wait();
            append_event(
                &mut store,
                CanonicalEvent::new(
                    &session.id,
                    EventSource::ProcessTree,
                    EventType::ProcessExit,
                    root_pid,
                    std::process::id(),
                    &root_actor,
                    "process",
                    "killed:runtime.max_seconds",
                ),
            )?;
            store
                .flush()
                .map_err(|error| format!("failed to flush timeline: {error}"))?;
            return Ok(LocalRunResult {
                session_id: session.id,
                exit_code: 124,
                attribution_mode: AttributionMode::ProcessTree,
                discovered_processes: seen.len(),
                timed_out,
            });
        }

        thread::sleep(POLL_INTERVAL);
    }
}

pub fn run_docker(request: DockerRunRequest) -> Result<LocalRunResult, String> {
    if request.command.is_empty() {
        return Err("docker run requires a command".to_string());
    }

    let policy = load_policy(&request.policy_path)?;
    let session_id = format!(
        "docker-{}-{}",
        std::process::id(),
        apolysis_core::now_unix_ms()
    );
    let session = SandboxSession::new(
        &session_id,
        RuntimeKind::Docker,
        request.policy_path.to_string_lossy(),
    );
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create timeline: {error}"))?;

    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::Manual,
            EventType::SessionStarted,
            std::process::id(),
            0,
            "apolysis",
            "docker-session",
            "start",
        ),
    )?;

    let cidfile = request.output_path.with_extension("cid");
    let _ = fs::remove_file(&cidfile);
    let plan = DockerRunPlan::new(&session.id, &request, &policy, cidfile)?;
    write_docker_plan_metadata(&session.id, &plan, &mut store)?;

    let status = Command::new(docker_bin())
        .args(&plan.args)
        .status()
        .map_err(|error| format!("failed to start docker: {error}"))?;

    let container_id = fs::read_to_string(&plan.cidfile)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "container-id",
            &container_id,
        ),
    )?;
    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "cgroup-path",
            format!("docker://{container_id}"),
        ),
    )?;

    let exit_code = status.code().unwrap_or(1);
    append_event(
        &mut store,
        CanonicalEvent::new(
            &session.id,
            EventSource::RuntimeMetadata,
            EventType::ProcessExit,
            std::process::id(),
            0,
            format!("docker run {} {}", request.image, request.command.join(" ")),
            "container",
            format!("exit:{exit_code}"),
        ),
    )?;
    store
        .flush()
        .map_err(|error| format!("failed to flush timeline: {error}"))?;

    Ok(LocalRunResult {
        session_id: session.id,
        exit_code,
        attribution_mode: AttributionMode::DockerCli,
        discovered_processes: 0,
        timed_out: false,
    })
}

fn write_docker_plan_metadata(
    session_id: &str,
    plan: &DockerRunPlan,
    store: &mut JsonlStore,
) -> Result<(), String> {
    append_event(
        store,
        CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "container-image",
            format!("image:{}", plan.image),
        ),
    )?;
    append_event(
        store,
        CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "network-mode",
            format!("network:{}", plan.network_mode),
        ),
    )?;
    append_event(
        store,
        CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "docker-runtime",
            format!(
                "oci-runtime:{}",
                plan.oci_runtime.as_deref().unwrap_or("default")
            ),
        ),
    )?;
    append_event(
        store,
        CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "mounts",
            plan.mounts
                .iter()
                .map(DockerMount::summary)
                .collect::<Vec<_>>()
                .join(";"),
        ),
    )?;
    append_event(
        store,
        CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "docker",
            "container-labels",
            format!(
                "apolysis.session_id={session_id},apolysis.runtime=docker,apolysis.policy_path={}",
                plan.policy_path
            ),
        ),
    )
}

fn docker_bin() -> String {
    std::env::var("APOLYSIS_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string())
}

struct DockerRunPlan {
    args: Vec<String>,
    cidfile: PathBuf,
    image: String,
    oci_runtime: Option<String>,
    mounts: Vec<DockerMount>,
    network_mode: String,
    policy_path: String,
}

impl DockerRunPlan {
    fn new(
        session_id: &str,
        request: &DockerRunRequest,
        policy: &Policy,
        cidfile: PathBuf,
    ) -> Result<Self, String> {
        let mounts = docker_mounts(policy)?;
        let network_mode = "none".to_string();
        let pids_limit = policy.runtime.max_processes.unwrap_or(256).to_string();
        let policy_path = request.policy_path.to_string_lossy().to_string();
        let container_name = format!("apolysis-{session_id}");
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--cidfile".to_string(),
            cidfile.to_string_lossy().to_string(),
            "--name".to_string(),
            container_name,
            "--label".to_string(),
            format!("apolysis.session_id={session_id}"),
            "--label".to_string(),
            "apolysis.runtime=docker".to_string(),
            "--label".to_string(),
            format!("apolysis.policy_path={policy_path}"),
            "--env".to_string(),
            format!("APOLYSIS_SESSION_ID={session_id}"),
            "--env".to_string(),
            "APOLYSIS_RUNTIME=docker".to_string(),
            "--read-only".to_string(),
            "--network".to_string(),
            network_mode.clone(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--pids-limit".to_string(),
            pids_limit,
            "--cpus".to_string(),
            "1".to_string(),
            "--memory".to_string(),
            "512m".to_string(),
            "--tmpfs".to_string(),
            "/tmp:rw,noexec,nosuid,nodev,size=64m".to_string(),
        ];

        if let Some(oci_runtime) = &request.oci_runtime {
            args.push("--runtime".to_string());
            args.push(oci_runtime.clone());
        }

        for mount in &mounts {
            args.push("--mount".to_string());
            args.push(mount.to_spec());
        }

        args.push(request.image.clone());
        args.extend(request.command.clone());

        Ok(Self {
            args,
            cidfile,
            image: request.image.clone(),
            oci_runtime: request.oci_runtime.clone(),
            mounts,
            network_mode,
            policy_path,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerMount {
    source: PathBuf,
    target: String,
    read_only: bool,
}

impl DockerMount {
    fn to_spec(&self) -> String {
        let mut spec = format!(
            "type=bind,src={},dst={}",
            self.source.to_string_lossy(),
            self.target
        );
        if self.read_only {
            spec.push_str(",readonly");
        }
        spec
    }

    fn summary(&self) -> String {
        let mode = if self.read_only { "ro" } else { "rw" };
        format!("{}->{}:{mode}", self.source.to_string_lossy(), self.target)
    }
}

fn docker_mounts(policy: &Policy) -> Result<Vec<DockerMount>, String> {
    let mut mounts = Vec::new();
    for value in &policy.workspace.allow_read {
        mounts.push(DockerMount {
            source: absolute_path(value)?,
            target: format!("/workspace/read/{}", mount_name(value)),
            read_only: true,
        });
    }
    for value in &policy.workspace.allow_write {
        mounts.push(DockerMount {
            source: absolute_path(value)?,
            target: format!("/workspace/write/{}", mount_name(value)),
            read_only: false,
        });
    }
    Ok(mounts)
}

fn absolute_path(value: &str) -> Result<PathBuf, String> {
    if value.contains(',') {
        return Err(format!("docker mount path cannot contain comma: {value}"));
    }

    let path = PathBuf::from(value);
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("failed to resolve docker mount path: {error}"))?
    };

    Ok(fs::canonicalize(&absolute).unwrap_or(absolute))
}

fn mount_name(value: &str) -> String {
    let trimmed = value.trim_matches('/');
    let mut out = String::new();
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "root".to_string()
    } else {
        out
    }
}

fn load_policy(path: &Path) -> Result<Policy, String> {
    let input =
        fs::read_to_string(path).map_err(|error| format!("failed to read policy: {error}"))?;
    Policy::parse(&input).map_err(|error| format!("failed to parse policy: {error}"))
}

fn append_event(store: &mut JsonlStore, event: CanonicalEvent) -> Result<(), String> {
    store
        .append(&event)
        .map_err(|error| format!("failed to write event: {error}"))
}

fn append_timeout_violation(
    session_id: &str,
    root_pid: u32,
    actor: &str,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let violation = PolicyViolation::new(
        session_id,
        "runtime.max_seconds",
        CoreDecision::Notify,
        "local process exceeded runtime.max_seconds",
        root_pid,
        actor,
        EnforcementBackend::SignalKill,
    );
    store
        .append(&violation)
        .map_err(|error| format!("failed to write timeout violation: {error}"))
}

fn append_exit_event(
    session_id: &str,
    root_pid: u32,
    actor: &str,
    exit_code: i32,
    store: &mut JsonlStore,
) -> Result<(), String> {
    append_event(
        store,
        CanonicalEvent::new(
            session_id,
            EventSource::ProcessTree,
            EventType::ProcessExit,
            root_pid,
            std::process::id(),
            actor,
            "process",
            format!("exit:{exit_code}"),
        ),
    )
}

fn sample_descendants(
    session_id: &str,
    root_pid: u32,
    seen: &mut HashMap<u32, String>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let table = read_process_table();
    let by_pid: HashMap<u32, ProcessInfo> =
        table.into_iter().map(|info| (info.pid, info)).collect();
    let mut attributed: Vec<ProcessInfo> = by_pid
        .values()
        .filter(|info| info.pid == root_pid || is_descendant_of(info.pid, root_pid, &by_pid))
        .cloned()
        .collect();
    attributed.sort_by_key(|info| info.pid);

    for process in attributed {
        let actor_changed = seen
            .get(&process.pid)
            .map(|actor| actor != &process.actor)
            .unwrap_or(true);
        if actor_changed {
            seen.insert(process.pid, process.actor.clone());
            append_event(
                store,
                CanonicalEvent::new(
                    session_id,
                    EventSource::ProcessTree,
                    EventType::Exec,
                    process.pid,
                    process.ppid,
                    process.actor,
                    "process",
                    "exec",
                ),
            )?;
        }
    }

    Ok(())
}

fn kill_process_tree(root_pid: u32) {
    let table = read_process_table();
    let by_pid: HashMap<u32, ProcessInfo> =
        table.into_iter().map(|info| (info.pid, info)).collect();
    let mut targets: Vec<(usize, u32)> = by_pid
        .values()
        .filter_map(|info| {
            if info.pid == root_pid {
                return Some((0, info.pid));
            }
            depth_from_root(info.pid, root_pid, &by_pid).map(|depth| (depth, info.pid))
        })
        .collect();

    // Kill deeper descendants first so they do not survive after the root shell
    // exits and reparents them to init.
    targets.sort_by(|left, right| right.cmp(left));
    for (_, pid) in targets {
        kill_pid(pid);
    }
}

fn depth_from_root(pid: u32, root_pid: u32, by_pid: &HashMap<u32, ProcessInfo>) -> Option<usize> {
    let mut depth = 0;
    let mut current = pid;
    let mut visited = HashSet::new();

    while let Some(info) = by_pid.get(&current) {
        depth += 1;
        if info.ppid == root_pid {
            return Some(depth);
        }
        if info.ppid == 0 || !visited.insert(current) {
            return None;
        }
        current = info.ppid;
    }

    None
}

fn kill_pid(pid: u32) {
    // Ignore ESRCH and EPERM here. The timeout path reports the policy decision
    // in the timeline; M2 does not yet expose per-PID kill diagnostics.
    let _ = unsafe { kill(pid as i32, SIGKILL) };
}

fn is_descendant_of(pid: u32, root_pid: u32, by_pid: &HashMap<u32, ProcessInfo>) -> bool {
    let mut current = pid;
    let mut visited = HashSet::new();

    while let Some(info) = by_pid.get(&current) {
        if info.ppid == root_pid {
            return true;
        }
        if info.ppid == 0 || !visited.insert(current) {
            return false;
        }
        current = info.ppid;
    }

    false
}

fn read_process_table() -> Vec<ProcessInfo> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            read_process_info(pid)
        })
        .collect()
}

fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let ppid = parse_ppid_from_stat(&stat)?;
    let actor = read_cmdline(pid)?;
    Some(ProcessInfo { pid, ppid, actor })
}

fn parse_ppid_from_stat(stat: &str) -> Option<u32> {
    let end = stat.rfind(") ")?;
    let after_name = &stat[(end + 2)..];
    let mut fields = after_name.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

fn read_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect();

    (!parts.is_empty()).then(|| parts.join(" "))
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    actor: String,
}

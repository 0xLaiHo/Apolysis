// SPDX-License-Identifier: Apache-2.0

//! Local runtime execution and process attribution for Apolysis.
//!
//! M2 still runs in audit mode: it does not claim to isolate untrusted code.
//! This crate exists to make the local runner an explicit runtime adapter and
//! to keep the CLI thin before Docker, Kubernetes, and eBPF backends are added.

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
}

impl AttributionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessTree => "process_tree",
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

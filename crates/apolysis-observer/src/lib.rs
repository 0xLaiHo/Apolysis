// SPDX-License-Identifier: Apache-2.0

//! Audit-only observer pipeline for kernel-derived events.
//!
//! M4 establishes the userspace contract that a future Aya loader will feed:
//! raw ring-buffer records are preserved, analyzed into canonical events, and
//! written into the same JSONL session timeline used by the runtime adapters.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use apolysis_core::{CanonicalEvent, EventSource, EventType, RawKernelEvent};
use apolysis_policy::Policy;
use apolysis_store::JsonlStore;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureObserveRequest {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub policy_path: PathBuf,
    pub session_id: String,
}

impl FixtureObserveRequest {
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
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveResult {
    pub raw_events: usize,
    pub canonical_events: usize,
    pub backend: ObserverBackend,
    pub mode: ObserverMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserverBackend {
    FixtureRingBuffer,
    AyaRingBuffer,
}

impl ObserverBackend {
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
    pub fn m4_default() -> Self {
        Self {
            process: true,
            system: true,
            stdio: false,
            ssl_http_uprobe: false,
        }
    }

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
    pub fn m4_default(object_path: impl Into<PathBuf>) -> Self {
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TracepointAttach {
    pub category: String,
    pub name: String,
}

impl TracepointAttach {
    pub fn new(category: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
        }
    }
}

pub fn observe_fixture(request: FixtureObserveRequest) -> Result<ObserveResult, String> {
    let policy = load_policy(&request.policy_path)?;
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create observer timeline: {error}"))?;
    let runner_plan = ObserverRunnerPlan::m4_default();

    write_observer_metadata(&request.session_id, &runner_plan, &mut store)?;

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
    })
}

fn write_observer_metadata(
    session_id: &str,
    runner_plan: &ObserverRunnerPlan,
    store: &mut JsonlStore,
) -> Result<(), String> {
    for (resource, action) in [
        (
            "observer-mode",
            ObserverMode::AuditOnly.as_str().to_string(),
        ),
        (
            "observer-backend",
            ObserverBackend::FixtureRingBuffer.as_str().to_string(),
        ),
        ("observer-runners", runner_plan.summary()),
    ] {
        let event = CanonicalEvent::new(
            session_id,
            EventSource::RuntimeMetadata,
            EventType::RuntimeMetadata,
            std::process::id(),
            0,
            "observer",
            resource,
            action,
        );
        store
            .append(&event)
            .map_err(|error| format!("failed to write observer metadata: {error}"))?;
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
    let fields = parse_key_values(line)?;
    let timestamp = parse_u128(&fields, "timestamp")?;
    let pid = parse_u32(&fields, "pid")?;
    let ppid = parse_u32(&fields, "ppid")?;
    let uid = parse_u32(&fields, "uid")?;
    let gid = parse_u32(&fields, "gid")?;
    let comm = required(&fields, "comm")?;
    let event_name = required(&fields, "event")?;
    let resource = required(&fields, "resource")?;
    let action = required(&fields, "action")?;
    let container_id = fields.get("container_id").cloned();
    let cgroup_id = fields.get("cgroup_id").cloned();
    let raw_payload = fields.get("payload").cloned().unwrap_or_default();

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

fn parse_key_values(line: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for part in line.split('|') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(format!("invalid raw event field: {part}"));
        };
        fields.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(fields)
}

fn required(fields: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    fields
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| format!("missing raw event field: {key}"))
}

fn parse_u32(fields: &BTreeMap<String, String>, key: &str) -> Result<u32, String> {
    required(fields, key)?
        .parse()
        .map_err(|error| format!("invalid {key}: {error}"))
}

fn parse_u128(fields: &BTreeMap<String, String>, key: &str) -> Result<u128, String> {
    required(fields, key)?
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
    fn m4_default_aya_loader_plan_names_tracepoints_and_ring_buffer() {
        let plan = AyaLoaderPlan::m4_default("ebpf/prebuilt/apolysis-observer.bpf.o");

        assert_eq!(plan.ring_buffer_map, "APOLYSIS_EVENTS");
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("sched", "sched_process_exec")));
        assert!(plan
            .tracepoints
            .contains(&TracepointAttach::new("syscalls", "sys_enter_connect")));
    }

    #[test]
    fn m4_default_runner_plan_keeps_optional_runners_disabled() {
        let plan = ObserverRunnerPlan::m4_default();

        assert_eq!(
            plan.summary(),
            "process:enabled,system:enabled,stdio:disabled,ssl-http-uprobe:disabled"
        );
    }
}

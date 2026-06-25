// SPDX-License-Identifier: Apache-2.0

//! Host prerequisite checks for the live eBPF observer.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{AyaLoaderPlan, LiveScope};

const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Validate the kernel interfaces and effective capabilities needed by AuditObserver.
pub fn validate_live_prerequisites(scope: &LiveScope, plan: &AyaLoaderPlan) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("live eBPF requires Linux".to_string());
    }
    if fs::File::open("/sys/kernel/btf/vmlinux").is_err() {
        return Err("readable /sys/kernel/btf/vmlinux is required".to_string());
    }
    if matches!(scope, LiveScope::Cgroup(_))
        && !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
    {
        return Err("cgroup v2 is required for --scope-cgroup".to_string());
    }
    let effective = effective_capabilities()?;
    if !has_required_bpf_capabilities(effective) {
        return Err(
            "CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN) are required for live observation"
                .to_string(),
        );
    }

    let tracefs = tracefs_root().ok_or_else(|| {
        "tracefs events are unavailable; mount tracefs at /sys/kernel/tracing".to_string()
    })?;
    for attach in &plan.tracepoints {
        let id = tracefs
            .join("events")
            .join(&attach.category)
            .join(&attach.name)
            .join("id");
        if !id.is_file() {
            return Err(format!(
                "required tracepoint is unavailable: {}/{}",
                attach.category, attach.name
            ));
        }
    }
    Ok(())
}

fn tracefs_root() -> Option<PathBuf> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join("events").is_dir())
}

fn effective_capabilities() -> Result<u64, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("failed to read effective capabilities: {error}"))?;
    parse_effective_capabilities(&status)
}

fn parse_effective_capabilities(status: &str) -> Result<u64, String> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .ok_or_else(|| "missing CapEff in /proc/self/status".to_string())?;
    u64::from_str_radix(value, 16)
        .map_err(|error| format!("invalid CapEff value '{value}': {error}"))
}

fn has_required_bpf_capabilities(effective: u64) -> bool {
    has_capability(effective, CAP_SYS_ADMIN)
        || (has_capability(effective, CAP_BPF) && has_capability(effective, CAP_PERFMON))
}

fn has_capability(effective: u64, capability: u32) -> bool {
    effective & (1_u64 << capability) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_effective_capabilities_from_proc_status() {
        assert_eq!(
            parse_effective_capabilities("Name:\ttest\nCapEff:\t000000c000000000\n").unwrap(),
            0x000000c000000000
        );
    }

    #[test]
    fn accepts_bpf_and_perfmon_or_sys_admin() {
        let bpf_and_perfmon = (1_u64 << CAP_BPF) | (1_u64 << CAP_PERFMON);
        assert!(has_required_bpf_capabilities(bpf_and_perfmon));
        assert!(has_required_bpf_capabilities(1_u64 << CAP_SYS_ADMIN));
        assert!(!has_required_bpf_capabilities(1_u64 << CAP_BPF));
        assert!(!has_required_bpf_capabilities(0));
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use apolysis_validation::{
    evaluate_f3_bpf_lsm_prototype_prerequisites, F3BlockValidationAction, F3BlockValidationReport,
    F3BlockValidationRuntime, F3BlockValidationSource, F3BpfLsmPrototypeEnvironment,
};
use aya::maps::Array;
use aya::programs::Lsm;
use aya::{Btf, Ebpf};

const TARGET_TGID_MAP: &str = "apolysis_bpf_lsm_target_tgid";
const PROGRAM_NAME: &str = "apolysis_bpf_lsm_file_open";
const LSM_HOOK: &str = "file_open";

fn main() {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => {}
        Err(RunError::PrerequisiteFailed) => std::process::exit(77),
        Err(RunError::Fatal(error)) => {
            eprintln!("apolysis-f3-bpf-lsm-file-read-prototype: {error}");
            std::process::exit(2);
        }
    }
}

fn run(args: Vec<String>) -> Result<(), RunError> {
    let args = parse_args(args).map_err(RunError::Fatal)?;
    let environment = detect_environment(&args.object_path);
    let prereq = evaluate_f3_bpf_lsm_prototype_prerequisites(environment);
    if !prereq.passed {
        print_json(&prereq).map_err(RunError::Fatal)?;
        return Err(RunError::PrerequisiteFailed);
    }

    let mut ebpf = Ebpf::load_file(&args.object_path)
        .map_err(|error| RunError::Fatal(format!("BPF load or verifier failure: {error:#}")))?;
    configure_target_tgid(&mut ebpf, std::process::id())
        .map_err(|error| RunError::Fatal(format!("failed to configure target TGID: {error}")))?;
    let btf = Btf::from_sys_fs()
        .map_err(|error| RunError::Fatal(format!("failed to read kernel BTF: {error}")))?;
    let program: &mut Lsm = ebpf
        .program_mut(PROGRAM_NAME)
        .ok_or_else(|| RunError::Fatal(format!("missing BPF-LSM program: {PROGRAM_NAME}")))?
        .try_into()
        .map_err(|error| RunError::Fatal(format!("invalid BPF-LSM program: {error}")))?;
    program
        .load(LSM_HOOK, &btf)
        .map_err(|error| RunError::Fatal(format!("BPF-LSM load failed: {error:#}")))?;
    let link_id = program
        .attach()
        .map_err(|error| RunError::Fatal(format!("BPF-LSM attach failed: {error:#}")))?;

    let started = Instant::now();
    let open_result = fs::File::open(&args.target_path);
    let decision_latency_ms = started.elapsed().as_millis();
    program
        .detach(link_id)
        .map_err(|error| RunError::Fatal(format!("BPF-LSM detach failed: {error:#}")))?;

    match open_result {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => {
            return Err(RunError::Fatal(format!(
                "expected BPF-LSM to deny {} with EPERM, got {error}",
                args.target_path.display()
            )));
        }
        Ok(_) => {
            return Err(RunError::Fatal(format!(
                "expected BPF-LSM to deny {}, but file open succeeded",
                args.target_path.display()
            )));
        }
    }

    let report = F3BlockValidationReport {
        evidence_id: "live-bpf-lsm-local-file-read".to_string(),
        source: F3BlockValidationSource::LiveHost,
        runtime: F3BlockValidationRuntime::Local,
        action: F3BlockValidationAction::FileRead,
        backend: "bpf_lsm_block".to_string(),
        host_bpf_lsm_available: true,
        seccomp_available: false,
        preoperation_prevention: true,
        decision_latency_ms: Some(decision_latency_ms),
        side_effect_race_window_ms: Some(0),
    };
    print_json(&vec![report]).map_err(RunError::Fatal)
}

#[derive(Debug)]
enum RunError {
    PrerequisiteFailed,
    Fatal(String),
}

#[derive(Debug)]
struct Args {
    object_path: PathBuf,
    target_path: PathBuf,
}

fn parse_args(args: Vec<String>) -> Result<Args, String> {
    let mut object_path = None;
    let mut target_path = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--bpf-object" => {
                index += 1;
                object_path = args.get(index).map(PathBuf::from);
            }
            "--target-path" => {
                index += 1;
                target_path = args.get(index).map(PathBuf::from);
            }
            _ => return Err(usage()),
        }
        index += 1;
    }

    Ok(Args {
        object_path: object_path.ok_or_else(usage)?,
        target_path: target_path.ok_or_else(usage)?,
    })
}

fn usage() -> String {
    "usage: apolysis-f3-bpf-lsm-file-read-prototype --bpf-object <path> --target-path <path>"
        .to_string()
}

fn detect_environment(object_path: &Path) -> F3BpfLsmPrototypeEnvironment {
    let configured = kernel_config_contains("CONFIG_BPF_LSM=y");
    let active_lsm = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();

    F3BpfLsmPrototypeEnvironment {
        linux: std::env::consts::OS == "linux",
        btf_available: fs::metadata("/sys/kernel/btf/vmlinux").is_ok(),
        bpf_lsm_configured: configured,
        bpf_lsm_active: active_lsm.split(',').any(|lsm| lsm.trim() == "bpf"),
        prototype_object_available: object_path.is_file(),
        privileged_for_bpf: has_bpf_privilege(),
    }
}

fn kernel_config_contains(needle: &str) -> bool {
    let candidates = [
        "/proc/config.gz",
        "/boot/config",
        "/boot/config-linux",
        "/boot/config-linux-lts",
    ];
    for candidate in candidates {
        if candidate.ends_with(".gz") {
            if let Ok(output) = std::process::Command::new("zgrep")
                .arg("-q")
                .arg(needle)
                .arg(candidate)
                .status()
            {
                if output.success() {
                    return true;
                }
            }
        } else if fs::read_to_string(candidate)
            .map(|config| config.lines().any(|line| line == needle))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn has_bpf_privilege() -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(status) => status,
        Err(_) => return false,
    };
    let Some(cap_hex) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
    else {
        return false;
    };
    let Ok(caps) = u64::from_str_radix(cap_hex, 16) else {
        return false;
    };
    let cap_sys_admin = 1_u64 << 21;
    let cap_perfmon = 1_u64 << 38;
    let cap_bpf = 1_u64 << 39;

    (caps & cap_sys_admin) != 0 || ((caps & cap_perfmon) != 0 && (caps & cap_bpf) != 0)
}

fn configure_target_tgid(ebpf: &mut Ebpf, target_tgid: u32) -> Result<(), String> {
    let map = ebpf
        .map_mut(TARGET_TGID_MAP)
        .ok_or_else(|| format!("missing BPF map: {TARGET_TGID_MAP}"))?;
    let mut target_map = Array::<_, u32>::try_from(map)
        .map_err(|error| format!("invalid {TARGET_TGID_MAP} map: {error}"))?;
    target_map
        .set(0, target_tgid, 0)
        .map_err(|error| format!("failed to set target TGID: {error}"))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to serialize BPF-LSM prototype output: {error}"))?;
    println!("{output}");
    Ok(())
}

// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::time::Instant;

use apolysis_validation::{
    PolicyGuardrailsBlockValidationAction, PolicyGuardrailsBlockValidationReport,
    PolicyGuardrailsBlockValidationRuntime, PolicyGuardrailsBlockValidationSource,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-policy-guardrails-seccomp-file-read-prototype: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    if !seccomp_available() {
        return Err("seccomp is not available on this host".to_string());
    }

    install_open_block_filter()?;

    let started = Instant::now();
    let blocked = fs::File::open("/etc/passwd")
        .expect_err("seccomp filter should deny opening a readable host file");
    let decision_latency_ms = started.elapsed().as_millis();
    if blocked.kind() != io::ErrorKind::PermissionDenied {
        return Err(format!(
            "expected seccomp to deny file open with EPERM, got {blocked}"
        ));
    }

    let report = PolicyGuardrailsBlockValidationReport {
        evidence_id: "live-seccomp-local-file-read".to_string(),
        source: PolicyGuardrailsBlockValidationSource::LiveHost,
        runtime: PolicyGuardrailsBlockValidationRuntime::Local,
        action: PolicyGuardrailsBlockValidationAction::FileRead,
        backend: "seccomp_block".to_string(),
        host_bpf_lsm_available: false,
        seccomp_available: true,
        preoperation_prevention: true,
        decision_latency_ms: Some(decision_latency_ms),
        side_effect_race_window_ms: Some(0),
    };
    let output = serde_json::to_string_pretty(&vec![report])
        .map_err(|error| format!("failed to serialize seccomp prototype report: {error}"))?;
    println!("{output}");

    Ok(())
}

fn seccomp_available() -> bool {
    fs::metadata("/proc/sys/kernel/seccomp/actions_avail").is_ok()
}

fn install_open_block_filter() -> Result<(), String> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "failed to set no_new_privs: {}",
                io::Error::last_os_error()
            ));
        }

        let mut filter = [
            bpf_stmt((libc::BPF_LD + libc::BPF_W + libc::BPF_ABS) as u16, 0),
            bpf_jump(
                (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
                libc::SYS_open as u32,
                0,
                1,
            ),
            bpf_stmt(
                (libc::BPF_RET + libc::BPF_K) as u16,
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ),
            bpf_jump(
                (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
                libc::SYS_openat as u32,
                0,
                1,
            ),
            bpf_stmt(
                (libc::BPF_RET + libc::BPF_K) as u16,
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ),
            bpf_stmt(
                (libc::BPF_RET + libc::BPF_K) as u16,
                libc::SECCOMP_RET_ALLOW,
            ),
        ];
        let mut program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };

        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        ) != 0
        {
            return Err(format!(
                "failed to install seccomp filter: {}",
                io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

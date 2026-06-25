// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::path::PathBuf;

use apolysis_validation::{
    evaluate_policy_guardrails_local_seccomp_execution_gate,
    PolicyGuardrailsBlockEnablementPolicyReport, PolicyGuardrailsBlockValidationAction,
    PolicyGuardrailsBlockValidationRuntime, PolicyGuardrailsLocalSeccompExecutionFailure,
    PolicyGuardrailsLocalSeccompExecutionReport, PolicyGuardrailsLocalSeccompExecutionRequest,
};

fn main() {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("apolysis-policy-guardrails-local-seccomp-execution: {error}");
            std::process::exit(2);
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let policy_input = fs::read_to_string(&args.enablement_policy).map_err(|error| {
        format!(
            "failed to read enablement policy report {}: {error}",
            args.enablement_policy.display()
        )
    })?;
    let policy: PolicyGuardrailsBlockEnablementPolicyReport =
        serde_json::from_str(&policy_input)
            .map_err(|error| format!("failed to parse enablement policy JSON: {error}"))?;

    let request = PolicyGuardrailsLocalSeccompExecutionRequest {
        evidence_id: args.evidence_id,
        backend: "seccomp_block".to_string(),
        runtime: PolicyGuardrailsBlockValidationRuntime::Local,
        action: PolicyGuardrailsBlockValidationAction::FileRead,
        target_path: args.target_path,
    };
    let mut report = evaluate_policy_guardrails_local_seccomp_execution_gate(&policy, request);
    if !report.passed {
        print_report(&report)?;
        std::process::exit(1);
    }

    if !seccomp_available() {
        report.passed = false;
        report.failures.push(local_seccomp_execution_failure(
            &report,
            "seccomp is not available on this host",
        ));
        print_report(&report)?;
        std::process::exit(1);
    }

    install_open_block_filter()?;

    match fs::File::open(&report.target_path) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            report.blocked_errno = Some(libc::EPERM);
            report.blocked_message = Some(error.to_string());
            print_report(&report)?;
            Ok(())
        }
        Err(error) => Err(format!(
            "expected seccomp to deny {} with EPERM, got {error}",
            report.target_path
        )),
        Ok(_) => Err(format!(
            "expected seccomp to deny {}, but file open succeeded",
            report.target_path
        )),
    }
}

#[derive(Debug)]
struct Args {
    enablement_policy: PathBuf,
    evidence_id: String,
    target_path: String,
}

fn parse_args(args: Vec<String>) -> Result<Args, String> {
    let mut enablement_policy = None;
    let mut evidence_id = None;
    let mut target_path = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--enablement-policy" => {
                index += 1;
                enablement_policy = args.get(index).map(PathBuf::from);
            }
            "--evidence-id" => {
                index += 1;
                evidence_id = args.get(index).cloned();
            }
            "--target-path" => {
                index += 1;
                target_path = args.get(index).cloned();
            }
            _ => return Err(usage()),
        }
        index += 1;
    }

    Ok(Args {
        enablement_policy: enablement_policy.ok_or_else(usage)?,
        evidence_id: evidence_id.ok_or_else(usage)?,
        target_path: target_path.ok_or_else(usage)?,
    })
}

fn usage() -> String {
    "usage: apolysis-policy-guardrails-local-seccomp-execution --enablement-policy <path> --evidence-id <id> --target-path <path>".to_string()
}

fn print_report(report: &PolicyGuardrailsLocalSeccompExecutionReport) -> Result<(), String> {
    let output = serde_json::to_string_pretty(report)
        .map_err(|error| format!("failed to serialize local seccomp execution report: {error}"))?;
    println!("{output}");
    Ok(())
}

fn local_seccomp_execution_failure(
    report: &PolicyGuardrailsLocalSeccompExecutionReport,
    message: impl Into<String>,
) -> PolicyGuardrailsLocalSeccompExecutionFailure {
    PolicyGuardrailsLocalSeccompExecutionFailure {
        evidence_id: if report.evidence_id.is_empty() {
            None
        } else {
            Some(report.evidence_id.clone())
        },
        message: message.into(),
    }
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

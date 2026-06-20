// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{
    evaluate_f3_bpf_lsm_prototype_prerequisites, F3BpfLsmPrototypeEnvironment,
};

#[test]
fn f3_bpf_lsm_prerequisites_accept_live_capable_environment() {
    let report = evaluate_f3_bpf_lsm_prototype_prerequisites(capable_environment());

    assert!(report.passed, "{report:#?}");
    assert!(report.failures.is_empty(), "{report:#?}");
}

#[test]
fn f3_bpf_lsm_prerequisites_fail_closed_without_active_lsm_or_privilege() {
    let mut environment = capable_environment();
    environment.bpf_lsm_active = false;
    environment.privileged_for_bpf = false;

    let report = evaluate_f3_bpf_lsm_prototype_prerequisites(environment);

    assert!(!report.passed, "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("active LSM list must include bpf"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("CAP_BPF and CAP_PERFMON or CAP_SYS_ADMIN are required"),
        "{failure_text}"
    );
}

#[test]
fn f3_bpf_lsm_prerequisites_fail_closed_without_btf_or_object() {
    let mut environment = capable_environment();
    environment.btf_available = false;
    environment.prototype_object_available = false;

    let report = evaluate_f3_bpf_lsm_prototype_prerequisites(environment);

    assert!(!report.passed, "{report:#?}");
    let failure_text = serde_json::to_string(&report.failures).expect("serialize failures");
    assert!(
        failure_text.contains("readable kernel BTF is required"),
        "{failure_text}"
    );
    assert!(
        failure_text.contains("BPF-LSM prototype object is required"),
        "{failure_text}"
    );
}

fn capable_environment() -> F3BpfLsmPrototypeEnvironment {
    F3BpfLsmPrototypeEnvironment {
        linux: true,
        btf_available: true,
        bpf_lsm_configured: true,
        bpf_lsm_active: true,
        prototype_object_available: true,
        privileged_for_bpf: true,
    }
}

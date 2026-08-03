// SPDX-License-Identifier: Apache-2.0

use apolysis_core::OperationOutcome;
use apolysis_observer::{
    audit_observer_capability_manifest, AyaLoaderPlan, LiveScope, TracepointAttach,
};

#[test]
fn audit_observer_manifest_declares_only_its_current_operation_outcomes() {
    let plan = AyaLoaderPlan::audit_observer_default("target/ebpf/apolysis_observer.bpf.o");
    let manifest = audit_observer_capability_manifest(
        "agent-run-manifest",
        &LiveScope::ProcessTree(42),
        &plan,
    );

    assert_eq!(manifest.agent_run_id, "agent-run-manifest");
    assert_eq!(manifest.observation_scope, "process_tree");
    assert_eq!(manifest.capabilities.len(), 10);

    let process_exec = manifest
        .capabilities
        .iter()
        .find(|capability| capability.operation == "process_exec")
        .expect("process exec capability");
    assert_eq!(
        process_exec.event_sources,
        [
            "sched/sched_process_exec",
            "syscalls/sys_enter_execve",
            "syscalls/sys_enter_execveat",
        ]
    );
    assert_eq!(process_exec.outcomes, [OperationOutcome::Succeeded]);

    let connect = manifest
        .capabilities
        .iter()
        .find(|capability| capability.operation == "network_connect")
        .expect("network connect capability");
    assert_eq!(
        connect.event_sources,
        ["syscalls/sys_enter_connect", "syscalls/sys_exit_connect"]
    );
    assert_eq!(
        connect.outcomes,
        [
            OperationOutcome::Succeeded,
            OperationOutcome::Failed,
            OperationOutcome::Denied,
            OperationOutcome::Pending,
        ]
    );
}

#[test]
fn audit_observer_manifest_declares_cgroup_observation_scope_without_host_identity() {
    let plan = AyaLoaderPlan::audit_observer_default("target/ebpf/apolysis_observer.bpf.o");
    let manifest =
        audit_observer_capability_manifest("agent-run-cgroup", &LiveScope::Cgroup(987_654), &plan);

    assert_eq!(manifest.observation_scope, "cgroup");
    assert!(!manifest.to_json_line().contains("987654"));
}

#[test]
fn audit_observer_manifest_omits_exec_when_only_argument_enrichment_is_attached() {
    let plan = AyaLoaderPlan {
        object_path: "target/ebpf/apolysis_observer.bpf.o".into(),
        ring_buffer_map: "EVENTS".to_string(),
        tracepoints: vec![TracepointAttach::new("syscalls", "sys_enter_execve")],
    };

    let manifest =
        audit_observer_capability_manifest("agent-run-partial", &LiveScope::ProcessTree(42), &plan);

    assert!(manifest.capabilities.is_empty());
}

#[test]
fn audit_observer_manifest_omits_connect_without_its_exit_hook() {
    let plan = AyaLoaderPlan {
        object_path: "target/ebpf/apolysis_observer.bpf.o".into(),
        ring_buffer_map: "EVENTS".to_string(),
        tracepoints: vec![TracepointAttach::new("syscalls", "sys_enter_connect")],
    };

    let manifest =
        audit_observer_capability_manifest("agent-run-partial", &LiveScope::ProcessTree(42), &plan);

    assert!(manifest.capabilities.is_empty());
}

// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::time::Duration;

#[test]
fn observe_fixture_ring_buffer_writes_raw_and_canonical_timeline() {
    let output = temp_jsonl("apolysis-observe-fixture");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-host-observer-fixture",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis observe");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    assert_expected_fragments(
        &timeline,
        "tests/fixtures/expected/observer-timeline.contains",
    );
    assert_eq!(
        timeline
            .matches(r#""record_type":"raw_kernel_event""#)
            .count(),
        8,
        "all fixture raw events should be preserved:\n{timeline}"
    );
    assert!(
        timeline
            .lines()
            .filter(|line| line.contains(r#""record_type":"event""#))
            .all(|line| line.contains(r#""session_id":"session-host-observer-fixture""#)),
        "all canonical events should use the requested session id:\n{timeline}"
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn observe_fixture_rotates_timeline_when_output_budget_is_reached() {
    let output = temp_jsonl("apolysis-observe-rotation");
    let archives: Vec<_> = (1..=8).map(|index| archive_jsonl(&output, index)).collect();
    let _ = std::fs::remove_file(&output);
    for archive in &archives {
        let _ = std::fs::remove_file(archive);
    }

    let status = apolysis_command()
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-host-observer-rotation",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--output-max-bytes",
            "4096",
            "--output-max-files",
            "8",
        ])
        .status()
        .expect("run apolysis observe with output rotation");

    assert!(status.success());
    assert!(archives[0].is_file(), "rotation should retain archives");
    let active = std::fs::read_to_string(&output).expect("read active timeline");
    let retained_archives = archives
        .iter()
        .filter(|path| path.is_file())
        .map(|path| std::fs::read_to_string(path).expect("read archived timeline"))
        .collect::<Vec<_>>();
    let combined = format!("{}\n{active}", retained_archives.join("\n"));
    assert!(active.contains(r#""record_type":"event""#));
    assert!(retained_archives
        .iter()
        .any(|archive| archive.contains(r#""record_type":"event""#)));
    assert!(combined.contains(r#""resource":"observer-output-rotation""#));
    assert!(combined.contains("max_file_bytes:4096,max_archived_files:8"));
    assert!(
        std::fs::metadata(&output).expect("active metadata").len() <= 4096,
        "active timeline should respect the configured byte budget"
    );
    for archive in archives.iter().filter(|path| path.is_file()) {
        assert!(
            std::fs::metadata(archive).expect("archive metadata").len() <= 4096,
            "archived timeline should respect the configured byte budget"
        );
    }

    let _ = std::fs::remove_file(&output);
    for archive in &archives {
        let _ = std::fs::remove_file(archive);
    }
}

#[test]
fn observe_output_rotation_requires_complete_positive_budget() {
    for args in [
        vec!["--output-max-bytes", "4096"],
        vec!["--output-max-files", "2"],
        vec!["--output-max-bytes", "0", "--output-max-files", "2"],
        vec!["--output-max-bytes", "4096", "--output-max-files", "0"],
    ] {
        let output = temp_jsonl("apolysis-observe-invalid-rotation");
        let mut command_args = vec![
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-host-observer-invalid-rotation",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ];
        command_args.extend(args);

        let output = apolysis_command()
            .args(command_args)
            .output()
            .expect("run apolysis observe with invalid output rotation");

        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--output-max-bytes") || stderr.contains("--output-max-files"),
            "stderr should identify the invalid output rotation option:\n{stderr}"
        );
    }
}

#[test]
fn observe_fixture_reports_runner_plan_metadata() {
    let output = temp_jsonl("apolysis-observe-runners");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-host-observer-runners",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis observe");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    assert!(timeline.contains(r#""actor":"observer""#));
    assert!(timeline.contains(r#""resource":"observer-mode""#));
    assert!(timeline.contains(r#""action":"audit-only""#));
    assert!(timeline.contains(r#""resource":"observer-runners""#));
    assert!(timeline.contains("process:enabled"));
    assert!(timeline.contains("system:enabled"));
    assert!(timeline.contains("stdio:disabled"));
    assert!(timeline.contains("ssl-http-uprobe:disabled"));

    let _ = std::fs::remove_file(&output);
}

#[test]
fn observe_fixture_emits_policy_violations_and_feedback_file() {
    let output = temp_jsonl("apolysis-observe-policy");
    let feedback_dir = temp_dir("apolysis-feedback");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&feedback_dir);

    let status = apolysis_command()
        .env("APOLYSIS_BPF_LSM_AVAILABLE", "0")
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-policy-feedback-policy",
            "--policy",
            "tests/fixtures/policies/policy-feedback-block-policy.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--feedback-dir",
            feedback_dir.to_str().expect("utf-8 feedback path"),
        ])
        .status()
        .expect("run apolysis observe with policy feedback");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    assert!(timeline.contains(r#""record_type":"policy_violation""#));
    assert!(timeline.contains(r#""rule_id":"credentials.deny_read""#));
    assert!(timeline.contains(r#""rule_id":"network.allow_egress""#));
    assert!(timeline.contains(r#""rule_id":"workspace.allow_write""#));
    assert!(!timeline.contains(r#""rule_id":"workspace.allow_read""#));
    assert!(timeline.contains(r#""decision":"notify""#));
    assert!(timeline.contains(r#""enforcement_backend":"tracepoint_notify""#));
    assert!(timeline.contains(r#""actor":"policy""#));
    assert!(timeline.contains(r#""resource":"bpf-lsm""#));
    assert!(timeline.contains(r#""action":"unavailable:downgrade:block->notify""#));

    let feedback =
        std::fs::read_to_string(feedback_dir.join("last-violation.txt")).expect("read feedback");
    assert!(feedback.contains("session_id: session-policy-feedback-policy"));
    assert!(feedback.contains("rule_id:"));
    assert!(feedback.contains("decision: notify"));
    assert!(feedback.contains("APOLYSIS_VIOLATION"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&feedback_dir);
}

#[test]
fn observe_fixture_links_raw_canonical_and_policy_records_by_event_id() {
    let output = temp_jsonl("apolysis-observe-correlation");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .env("APOLYSIS_BPF_LSM_AVAILABLE", "0")
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-event-correlation",
            "--policy",
            "tests/fixtures/policies/policy-feedback-block-policy.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis observe with correlation schema");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    let raw_connect = timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"raw_kernel_event""#)
                && line.contains(r#""event_name":"connect""#)
        })
        .expect("raw connect event");
    let event_id = json_string_field(raw_connect, "event_id").expect("raw event id");

    let canonical_connect = timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"event""#)
                && line.contains(r#""event_type":"network_connect""#)
                && line.contains(&format!(r#""raw_event_id":"{event_id}""#))
        })
        .expect("canonical network event linked to raw connect");
    assert!(canonical_connect.contains(r#""pid":4101"#));

    let violation = timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"policy_violation""#)
                && line.contains(r#""rule_id":"network.allow_egress""#)
                && line.contains(&format!(r#""observed_event_id":"{event_id}""#))
        })
        .expect("policy violation linked to raw connect");
    assert!(violation.contains(r#""decision":"notify""#));

    let metadata = timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"enforcement_metadata""#)
                && line.contains(r#""rule_id":"network.allow_egress""#)
                && line.contains(&format!(r#""observed_event_id":"{event_id}""#))
        })
        .expect("enforcement metadata linked to raw connect");
    assert!(metadata.contains(r#""observed_event_timestamp_unix_ms":1780328000004"#));

    let _ = std::fs::remove_file(&output);
}

#[test]
fn observe_fixture_keeps_process_identity_without_command_content() {
    let output = temp_jsonl("apolysis-observe-process-context");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-process-context",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis observe with process context");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    let file_event = timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"event""#)
                && line.contains(r#""event_type":"file_open""#)
                && line.contains(r#""pid":4100"#)
                && line.contains(r#""resource":"tests/fixtures/child.py""#)
        })
        .expect("file event from exec-derived process context");

    assert!(file_event.contains(r#""process_command":null"#));
    assert!(file_event.contains(r#""process_executable":"executable_ref:"#));
    assert!(!file_event.contains("bash -lc fixture"));
    assert!(file_event.contains(r#""process_started_at_unix_ms":1780328000001"#));

    let _ = std::fs::remove_file(&output);
}

#[test]
fn observe_fixture_emits_kill_containment_metadata() {
    let output = temp_jsonl("apolysis-observe-kill-metadata");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-policy-guardrails-kill",
            "--policy",
            "tests/fixtures/policies/policy-guardrails-kill-policy.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis observe with kill policy");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    assert!(timeline.contains(r#""record_type":"policy_violation""#));
    assert!(timeline.contains(r#""decision":"kill""#));
    assert!(timeline.contains(r#""enforcement_backend":"signal_kill""#));
    assert!(timeline.contains(r#""record_type":"enforcement_metadata""#));
    assert!(timeline.contains(r#""requested_decision":"kill""#));
    assert!(timeline.contains(r#""effective_decision":"kill""#));
    assert!(timeline.contains(r#""timing":"post_event_containment""#));
    assert!(timeline.contains(r#""preoperation_prevention":false"#));
    assert!(timeline.contains(r#""action":"credential_read""#));
    assert!(timeline.contains(r#""observed_event_timestamp_unix_ms":"#));
    assert!(timeline.contains(r#""decision_latency_ms":"#));
    assert!(timeline.contains(r#""side_effect_race_window_ms":"#));

    let _ = std::fs::remove_file(&output);
}

#[test]
fn observe_fixture_preserves_policy_feedback_with_kubernetes_metadata() {
    let output = temp_jsonl("apolysis-observe-kubernetes");
    let feedback_dir = temp_dir("apolysis-k8s-feedback");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&feedback_dir);

    let status = apolysis_command()
        .env("APOLYSIS_BPF_LSM_AVAILABLE", "0")
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-kubernetes-metadata-k8s",
            "--policy",
            "tests/fixtures/policies/policy-feedback-block-policy.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--feedback-dir",
            feedback_dir.to_str().expect("utf-8 feedback path"),
            "--kubernetes-metadata",
            "tests/fixtures/kubernetes/agent-sandbox-gvisor-pod.yaml",
        ])
        .status()
        .expect("run apolysis observe with kubernetes metadata");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read observer timeline");
    assert!(timeline.contains(r#""actor":"kubernetes""#));
    assert!(timeline.contains(r#""resource":"kubernetes-pod""#));
    assert!(timeline.contains(r#""action":"name:codex-session-7""#));
    assert!(timeline.contains(r#""resource":"kubernetes-namespace""#));
    assert!(timeline.contains(r#""action":"namespace:agents""#));
    assert!(timeline.contains(r#""resource":"kubernetes-service-account""#));
    assert!(timeline.contains(r#""action":"serviceAccount:agent-runner""#));
    assert!(timeline.contains(r#""resource":"kubernetes-runtime-class""#));
    assert!(timeline.contains(r#""action":"runtimeClass:gvisor""#));
    assert!(timeline.contains(r#""resource":"kubernetes-runtime-profile""#));
    assert!(timeline.contains(r#""action":"isolation:gvisor""#));
    assert!(timeline.contains(r#""resource":"kubernetes-node""#));
    assert!(timeline.contains(r#""action":"node:worker-a""#));
    assert!(timeline.contains(r#""resource":"agent-sandbox""#));
    assert!(timeline.contains(r#""action":"sandbox:codex-sandbox""#));
    assert!(timeline.contains(r#""resource":"kubernetes-service-account-token""#));
    assert!(timeline.contains(r#""action":"automount:false""#));
    assert!(timeline.contains(r#""record_type":"policy_violation""#));
    assert!(timeline.contains(r#""rule_id":"credentials.deny_read""#));
    assert!(timeline.contains(r#""rule_id":"network.allow_egress""#));

    let feedback =
        std::fs::read_to_string(feedback_dir.join("last-violation.txt")).expect("read feedback");
    assert!(feedback.contains("session_id: session-kubernetes-metadata-k8s"));
    assert!(feedback.contains("decision: notify"));
    assert!(feedback.contains("APOLYSIS_VIOLATION"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&feedback_dir);
}

#[test]
fn observe_live_requires_exactly_one_session_scope() {
    let output = temp_jsonl("apolysis-observe-live-scope");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-audit-observer-live",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/apolysis_observer.bpf.o",
            "--duration-seconds",
            "1",
        ])
        .output()
        .expect("run apolysis observe live");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains(
            "live observer requires exactly one of --scope-cgroup, --scope-pid, --agent-run, --agent-registration, or --agent-discover"
        ),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn observe_live_rejects_fixture_input() {
    let output = temp_jsonl("apolysis-observe-live-input");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--input",
            "tests/fixtures/raw-kernel-events.txt",
            "--session",
            "session-audit-observer-live",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/apolysis_observer.bpf.o",
            "--scope-cgroup",
            "42",
            "--duration-seconds",
            "1",
        ])
        .output()
        .expect("run apolysis observe live");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--input is only valid with --backend fixture"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn observe_live_validates_the_bpf_object_before_loading() {
    let output = temp_jsonl("apolysis-observe-live-object");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-audit-observer-live",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--scope-pid",
            &std::process::id().to_string(),
            "--duration-seconds",
            "1",
        ])
        .output()
        .expect("run apolysis observe live");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("BPF object does not exist"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn observe_live_accepts_agent_run_without_operator_pid() {
    let output = temp_jsonl("apolysis-observe-agent-run");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-run",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--workspace-root",
            workspace_root().to_str().expect("utf-8 workspace root"),
            "--agent-kind",
            "codex",
            "--agent-run",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("run apolysis observe live with managed agent");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("BPF object does not exist"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("live observer requires exactly one of --scope-cgroup or --scope-pid"),
        "agent-run should supply the live process-tree scope after launch: {stderr}"
    );
}

#[test]
fn observe_live_accepts_agent_registration_without_operator_pid() {
    let output = temp_jsonl("apolysis-observe-agent-registration");
    let registration = temp_jsonl("apolysis-agent-registration");
    write_current_process_registration(&registration);

    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-registration",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--workspace-root",
            workspace_root().to_str().expect("utf-8 workspace root"),
            "--agent-registration",
            registration.to_str().expect("utf-8 registration path"),
        ])
        .output()
        .expect("run apolysis observe live with registered agent");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("BPF object does not exist"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("live observer requires exactly one of"),
        "agent registration should supply the live process-tree scope: {stderr}"
    );

    let _ = std::fs::remove_file(&registration);
}

#[test]
fn observe_live_accepts_agent_discovery_without_operator_pid() {
    let output = temp_jsonl("apolysis-observe-agent-discovery");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-discovery",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--workspace-root",
            workspace_root().to_str().expect("utf-8 workspace root"),
            "--agent-kind",
            "codex",
            "--agent-discover",
        ])
        .output()
        .expect("run apolysis observe live with agent discovery");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("BPF object does not exist"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("live observer requires exactly one of"),
        "agent discovery should supply the live process-tree scope: {stderr}"
    );
}

#[test]
fn observe_live_rejects_agent_run_with_scope_pid() {
    let output = temp_jsonl("apolysis-observe-agent-run-scope-pid");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-run-scope-pid",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--scope-pid",
            &std::process::id().to_string(),
            "--agent-kind",
            "codex",
            "--agent-run",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("run apolysis observe live with conflicting pid scope");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--agent-run cannot be combined with --scope-pid or --scope-cgroup"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn observe_live_rejects_agent_registration_with_scope_pid() {
    let output = temp_jsonl("apolysis-observe-agent-registration-scope-pid");
    let registration = temp_jsonl("apolysis-agent-registration-scope-pid");
    write_current_process_registration(&registration);

    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-registration-scope-pid",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--scope-pid",
            &std::process::id().to_string(),
            "--agent-registration",
            registration.to_str().expect("utf-8 registration path"),
        ])
        .output()
        .expect("run apolysis observe live with conflicting registration scope");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr
            .contains("--agent-registration cannot be combined with --scope-pid or --scope-cgroup"),
        "unexpected stderr: {stderr}"
    );

    let _ = std::fs::remove_file(&registration);
}

#[test]
fn observe_live_rejects_agent_discovery_with_scope_pid() {
    let output = temp_jsonl("apolysis-observe-agent-discovery-scope-pid");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-discovery-scope-pid",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--scope-pid",
            &std::process::id().to_string(),
            "--agent-kind",
            "codex",
            "--agent-discover",
        ])
        .output()
        .expect("run apolysis observe live with conflicting discovery scope");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--agent-discover cannot be combined with --scope-pid or --scope-cgroup"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn observe_live_rejects_agent_run_with_scope_cgroup() {
    let output = temp_jsonl("apolysis-observe-agent-run-scope-cgroup");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-run-scope-cgroup",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--scope-cgroup",
            "42",
            "--agent-kind",
            "codex",
            "--agent-run",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("run apolysis observe live with conflicting cgroup scope");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--agent-run cannot be combined with --scope-pid or --scope-cgroup"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn observe_live_rejects_agent_run_without_command() {
    let output = temp_jsonl("apolysis-observe-agent-run-empty");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-agent-run-empty",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/does-not-exist.bpf.o",
            "--agent-kind",
            "codex",
            "--agent-run",
            "--",
        ])
        .output()
        .expect("run apolysis observe live with empty managed command");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("missing command after --agent-run --"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
#[ignore = "requires Linux BTF, tracepoints, cgroup v2, CAP_BPF, and CAP_PERFMON"]
fn live_observer_records_scoped_events_and_redacts_sensitive_values() {
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::os::unix::fs::MetadataExt as _;

    let output = temp_jsonl("apolysis-observe-live-smoke");
    let fixture_dir = temp_dir("apolysis-live-fixture");
    let credential_path = fixture_dir.join(".env");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&fixture_dir);
    std::fs::create_dir_all(&fixture_dir).expect("create live fixture directory");
    std::fs::File::create(&credential_path)
        .and_then(|mut file| file.write_all(b"APOLYSIS_TEST_SECRET=do-not-persist\n"))
        .expect("write credential fixture");

    let cgroup_path = current_cgroup_path();
    let cgroup_id = std::fs::metadata(&cgroup_path)
        .expect("stat current cgroup")
        .ino()
        .to_string();

    let mut observer = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-audit-observer-live-smoke",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/apolysis_observer.bpf.o",
            "--scope-cgroup",
            &cgroup_id,
            "--workspace-root",
            workspace_root().to_str().expect("utf-8 workspace root"),
            "--duration-seconds",
            "3",
        ])
        .spawn()
        .expect("spawn live observer");

    std::thread::sleep(Duration::from_millis(800));

    let status = Command::new("cat")
        .arg(&credential_path)
        .status()
        .expect("read credential fixture");
    assert!(status.success());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let port = listener.local_addr().expect("listener address").port();
    let accept = std::thread::spawn(move || listener.accept().expect("accept local connection"));
    let status = Command::new("python3")
        .args(["tests/fixtures/connect.py", "127.0.0.1", &port.to_string()])
        .current_dir(workspace_root())
        .status()
        .expect("run network fixture");
    assert!(status.success());
    drop(accept.join().expect("join listener").0);

    let status = observer.wait().expect("wait for live observer");
    assert!(status.success());

    let timeline = std::fs::read_to_string(&output).expect("read live timeline");
    assert!(timeline.contains(r#""action":"aya_ring_buffer""#));
    assert!(timeline.contains(r#""resource":"observer-scope""#));
    assert!(timeline.contains(r#""record_type":"raw_kernel_event""#));
    assert!(timeline.contains(r#""event_type":"exec""#));
    assert!(timeline.contains(r#""event_type":"credential_read""#));
    assert!(timeline.contains(r#""event_type":"network_connect""#));
    assert!(timeline.contains(r#""record_type":"policy_violation""#));
    assert!(timeline.contains(r#""kind":"summary""#));
    assert!(!timeline.contains(credential_path.to_str().expect("utf-8 credential path")));
    assert!(!timeline.contains("APOLYSIS_TEST_SECRET"));
    assert!(!timeline.contains("127.0.0.1"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&fixture_dir);
}

fn apolysis_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
    command.current_dir(workspace_root());
    command
}

fn current_cgroup_path() -> std::path::PathBuf {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").expect("read process cgroup");
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("cgroup v2 entry");
    std::path::Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'))
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn temp_jsonl(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}.jsonl", std::process::id()))
}

fn archive_jsonl(path: &std::path::Path, index: usize) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.{}", path.display(), index))
}

fn json_string_field(line: &str, field: &str) -> Option<String> {
    let needle = format!(r#""{field}":"#);
    let start = line.find(&needle)? + needle.len();
    let rest = line.get(start..)?.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest.get(..end)?.to_string())
}

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()))
}

fn write_current_process_registration(path: &std::path::Path) {
    let start_time_ticks = current_start_time_ticks();
    let executable = std::env::current_exe().expect("current executable");
    let workspace_root = workspace_root();
    let payload = format!(
        r#"{{
  "agent_kind": "codex",
  "pid": {},
  "start_time_ticks": {},
  "workspace_root": "{}",
  "executable": "{}",
  "command_fingerprint": "sha256:test-fixture"
}}"#,
        std::process::id(),
        start_time_ticks,
        workspace_root.display(),
        executable.display()
    );
    std::fs::write(path, payload).expect("write agent registration");
}

fn current_start_time_ticks() -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", std::process::id()))
        .expect("read current proc stat");
    let after_comm = stat.rsplit_once(") ").expect("proc stat comm").1;
    after_comm
        .split_whitespace()
        .nth(19)
        .expect("proc start time")
        .parse()
        .expect("numeric proc start time")
}

fn assert_expected_fragments(timeline: &str, relative_path: &str) {
    let expected = std::fs::read_to_string(workspace_root().join(relative_path))
        .expect("read expected timeline fragments");
    for fragment in expected.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            timeline.contains(fragment),
            "timeline missing expected fragment {fragment:?}:\n{timeline}"
        );
    }
}

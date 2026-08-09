// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

#[test]
fn observe_rejects_removed_control_plane_options() {
    for option in ["--policy", "--feedback-dir"] {
        let output = temp_jsonl("apolysis-observe-removed-option");
        let result = apolysis_command()
            .args([
                "observe",
                "--backend",
                "fixture",
                "--input",
                "tests/fixtures/raw-kernel-events.txt",
                "--session",
                "agent-run-observer-removed-option",
                "--output",
                output.to_str().expect("utf-8 output path"),
                option,
                "removed",
            ])
            .output()
            .expect("run apolysis observe with removed option");

        assert!(!result.status.success(), "{option} must stay removed");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("unknown argument"),
            "unexpected error for {option}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let _ = std::fs::remove_file(output);
    }
}

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
fn observe_fixture_does_not_cross_process_or_exec_generations() {
    let input = temp_jsonl("apolysis-observe-runtime-generations-input");
    let output = temp_jsonl("apolysis-observe-runtime-generations-output");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
    std::fs::write(
        &input,
        concat!(
            "timestamp=1780328000001|pid=44|ppid=40|uid=1000|gid=1000|comm=old-tool|event=exec|resource=/usr/bin/old-tool|action=exec|cgroup_id=901|host_boot_id=boot-test|scope_generation=7|process_generation=100|process_start_time_ns=1000|exec_generation=1|parent_process_generation=90|parent_exec_generation=2|payload=argv=/usr/bin/old-tool\n",
            "timestamp=1780328000002|pid=44|ppid=40|uid=1000|gid=1000|comm=old-tool|event=openat|resource=old.txt|action=read|cgroup_id=901|host_boot_id=boot-test|scope_generation=7|process_generation=100|process_start_time_ns=1000|exec_generation=1|parent_process_generation=90|parent_exec_generation=2\n",
            "timestamp=1780328000003|pid=44|ppid=40|uid=1000|gid=1000|comm=new-tool|event=exec|resource=/usr/bin/new-tool|action=exec|cgroup_id=901|host_boot_id=boot-test|scope_generation=7|process_generation=100|process_start_time_ns=1000|exec_generation=2|parent_process_generation=90|parent_exec_generation=2|payload=argv=/usr/bin/new-tool\n",
            "timestamp=1780328000004|pid=44|ppid=40|uid=1000|gid=1000|comm=new-tool|event=openat|resource=new.txt|action=read|cgroup_id=901|host_boot_id=boot-test|scope_generation=7|process_generation=100|process_start_time_ns=1000|exec_generation=2|parent_process_generation=90|parent_exec_generation=2\n",
            "timestamp=1780328000005|pid=44|ppid=1|uid=1000|gid=1000|comm=reused|event=openat|resource=reused.txt|action=read|cgroup_id=901|host_boot_id=boot-test|scope_generation=8|process_generation=200|process_start_time_ns=2000|exec_generation=0\n",
        ),
    )
    .expect("write runtime-generation fixture");

    let status = apolysis_command()
        .args([
            "observe",
            "--backend",
            "fixture",
            "--input",
            input.to_str().expect("utf-8 fixture path"),
            "--session",
            "session-runtime-generations",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run generation-aware fixture observation");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read generation-aware timeline");
    let old_file = canonical_file_event(&timeline, "old.txt");
    let new_file = canonical_file_event(&timeline, "new.txt");
    let reused_file = canonical_file_event(&timeline, "reused.txt");

    assert!(old_file.contains(r#""process_executable":"executable_ref:old-tool""#));
    assert!(old_file.contains(r#""process_generation":100"#));
    assert!(old_file.contains(r#""exec_generation":1"#));
    assert!(new_file.contains(r#""process_executable":"executable_ref:new-tool""#));
    assert!(new_file.contains(r#""process_generation":100"#));
    assert!(new_file.contains(r#""exec_generation":2"#));
    assert!(reused_file.contains(r#""process_executable":null"#));
    assert!(reused_file.contains(r#""process_generation":200"#));
    assert!(reused_file.contains(r#""exec_generation":0"#));
    assert!(reused_file.contains(r#""relation_status":"exact""#));

    let _ = std::fs::remove_file(input);
    let _ = std::fs::remove_file(output);
}

fn canonical_file_event<'a>(timeline: &'a str, resource: &str) -> &'a str {
    timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"event""#)
                && line.contains(r#""event_type":"file_open""#)
                && line.contains(&format!(r#""resource":"{resource}""#))
        })
        .unwrap_or_else(|| panic!("missing canonical file event for {resource}:\n{timeline}"))
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
            "live observer requires exactly one of --scope-cgroup, --agent-run, --agent-registration, or --agent-discover"
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
fn observe_live_rejects_unprotected_scope_pid() {
    let output = temp_jsonl("apolysis-observe-unprotected-scope-pid");
    let ordinary_file = workspace_root().join("Cargo.toml");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "session-unprotected-scope-pid",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            ordinary_file.to_str().expect("utf-8 ordinary file path"),
            "--scope-pid",
            &std::process::id().to_string(),
            "--duration-seconds",
            "1",
        ])
        .output()
        .expect("run apolysis observe with an unprotected PID scope");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--scope-pid is not a protected existing-process attach"),
        "unexpected stderr: {stderr}"
    );
    let _ = std::fs::remove_file(output);
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
fn observe_live_rejects_a_reused_registration_identity_without_starting_collection() {
    let output = temp_jsonl("apolysis-observe-agent-registration-pid-reuse");
    let registration_path = temp_jsonl("apolysis-agent-registration-pid-reuse");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&registration_path);

    let mut registration = current_process_registration();
    registration.start_time_ticks = registration
        .start_time_ticks
        .checked_add(1)
        .expect("current process start time can advance by one tick");
    write_agent_registration(&registration_path, &registration);

    let existing_non_bpf_file = workspace_root().join("Cargo.toml");
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "agent-run-registration-pid-reuse",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            existing_non_bpf_file
                .to_str()
                .expect("utf-8 ordinary object path"),
            "--workspace-root",
            workspace_root().to_str().expect("utf-8 workspace root"),
            "--agent-registration",
            registration_path.to_str().expect("utf-8 registration path"),
        ])
        .output()
        .expect("run protected attach with a reused registration identity");

    assert!(!result.status.success());
    let stderr = String::from_utf8(result.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("rejected possible PID reuse"),
        "unexpected stderr: {stderr}"
    );

    let timeline = std::fs::read_to_string(&output).expect("read failed attach timeline");
    let attach_failure = timeline
        .lines()
        .find(|line| {
            line.contains(r#""record_type":"observer_diagnostic""#)
                && line.contains(r#""kind":"attach_failure""#)
        })
        .expect("typed attach failure diagnostic");
    assert!(attach_failure.contains(r#""count":1"#));
    assert!(timeline.lines().any(|line| {
        line.contains(r#""record_type":"collector_lifecycle""#)
            && line.contains(r#""state":"failed""#)
            && line.contains(r#""health":"failed""#)
            && line.contains(r#""stop_reason":"attach_failure""#)
    }));
    assert!(!timeline.contains(r#""state":"started""#));
    assert!(!timeline.contains(r#""record_type":"collector_capability_manifest""#));
    assert!(!timeline.contains(r#""record_type":"raw_kernel_event""#));
    assert!(!timeline.lines().any(|line| {
        line.contains(r#""record_type":"event""#)
            && line.contains(r#""event_source":"kernel_tracepoint""#)
    }));

    let private_command = &registration.command;
    for sensitive in [
        registration_path.to_string_lossy().as_ref(),
        private_command,
        &registration.command_fingerprint,
    ] {
        assert!(!stderr.contains(sensitive), "stderr leaked {sensitive:?}");
        assert!(
            !timeline.contains(sensitive),
            "timeline leaked {sensitive:?}:\n{timeline}"
        );
    }

    let _ = std::fs::remove_file(output);
    let _ = std::fs::remove_file(registration_path);
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
fn live_managed_agent_starts_after_the_capability_manifest_is_durable() {
    let output = temp_jsonl("apolysis-live-capability-before-agent");
    let _ = std::fs::remove_file(&output);
    let result = apolysis_command()
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            "agent-run-capability-before-agent",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--bpf-object",
            "target/ebpf/apolysis_observer.bpf.o",
            "--workspace-root",
            workspace_root().to_str().expect("utf-8 workspace root"),
            "--agent-kind",
            "test-agent",
            "--agent-run",
            "--",
            "sh",
            "-c",
            r#"grep -q '"record_type":"collector_capability_manifest"' "$1" && grep -q '"state":"started"' "$1""#,
            "sh",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run managed Agent behind live observer gate");

    let stderr = String::from_utf8_lossy(&result.stderr);
    if stderr.contains("live observer prerequisite failed") {
        eprintln!("skipping live managed Agent gate test: {stderr}");
        let _ = std::fs::remove_file(output);
        return;
    }
    assert!(
        result.status.success(),
        "managed Agent ran before its capability manifest was durable: {}",
        stderr
    );
    let timeline = std::fs::read_to_string(&output).expect("read live timeline");
    let manifest_index = timeline
        .lines()
        .position(|line| line.contains(r#""record_type":"collector_capability_manifest""#))
        .expect("capability manifest record");
    let lifecycle_start_index = timeline
        .lines()
        .position(|line| {
            line.contains(r#""record_type":"collector_lifecycle""#)
                && line.contains(r#""state":"started""#)
        })
        .expect("collector lifecycle start");
    let first_kernel_event_index = timeline
        .lines()
        .position(|line| line.contains(r#""record_type":"raw_kernel_event""#))
        .expect("managed Agent kernel event");
    let summary_index = timeline
        .lines()
        .position(|line| line.contains(r#""kind":"summary""#))
        .expect("observer summary");
    let lifecycle_stop_index = timeline
        .lines()
        .position(|line| {
            line.contains(r#""record_type":"collector_lifecycle""#)
                && line.contains(r#""state":"stopped""#)
                && line.contains(r#""stop_reason":"agent_exited""#)
        })
        .expect("collector lifecycle stop");
    assert!(manifest_index < lifecycle_start_index);
    assert!(lifecycle_start_index < first_kernel_event_index);
    assert!(summary_index < lifecycle_stop_index);

    let _ = std::fs::remove_file(output);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root plus Linux BTF, tracepoints, cgroup v2, CAP_BPF, and CAP_PERFMON"]
fn live_registered_process_records_the_late_boundary_before_observation_starts() {
    use std::io::Write as _;

    assert_eq!(
        // SAFETY: geteuid only reads the calling process credentials.
        unsafe { libc::geteuid() },
        0,
        "the protected existing-process E2E must run as root"
    );

    let workspace = TempDirGuard::create("apolysis-live-registered-process");
    let output = workspace.path().join("timeline.jsonl");
    let registration_path = workspace.path().join("registration.json");
    let trigger_path = workspace.path().join("read-credential.trigger");
    let credential_path = workspace.path().join(".env");
    let secret = "APOLYSIS_L1_SECRET=late-attach-content-must-not-persist\n";
    std::fs::File::create(&credential_path)
        .and_then(|mut file| file.write_all(secret.as_bytes()))
        .expect("write protected-attach credential fixture");

    let process_tree_script = r#"import os
import sys
import time

child = os.fork()
if child == 0:
    while not os.path.exists(sys.argv[1]):
        time.sleep(0.05)
    with open(sys.argv[2], encoding="utf-8") as credential:
        credential.read()
    while True:
        time.sleep(1)
else:
    os.waitpid(child, 0)
"#;
    let mut target_command = Command::new("python3");
    target_command.current_dir(workspace.path());
    target_command.args([
        "-c",
        process_tree_script,
        trigger_path.to_str().expect("utf-8 trigger path"),
        credential_path.to_str().expect("utf-8 credential path"),
    ]);
    let target = ChildGuard::spawn_process_group(target_command, "spawn registered process tree");
    wait_for_process_child(target.id(), Duration::from_secs(5));

    let registration = process_registration(target.id(), workspace.path().to_path_buf());
    write_agent_registration(&registration_path, &registration);

    let mut observer_command = apolysis_command();
    observer_command.args([
        "observe",
        "--backend",
        "live",
        "--session",
        "agent-run-registered-process-e2e",
        "--output",
        output.to_str().expect("utf-8 output path"),
        "--bpf-object",
        "target/ebpf/apolysis_observer.bpf.o",
        "--workspace-root",
        workspace.path().to_str().expect("utf-8 workspace path"),
        "--agent-registration",
        registration_path.to_str().expect("utf-8 registration path"),
        "--duration-seconds",
        "4",
    ]);
    let mut observer = ChildGuard::spawn(observer_command, "spawn protected attach observer");

    wait_for_timeline_fragment(
        &output,
        r#""record_type":"collector_lifecycle","schema_version":1"#,
        Duration::from_secs(10),
    );
    wait_for_timeline_fragment(&output, r#""state":"started""#, Duration::from_secs(2));
    std::fs::File::create(&trigger_path).expect("release credential-read child");

    let status = observer.wait();
    assert!(
        status.success(),
        "protected attach observer failed: {status}"
    );

    let timeline = std::fs::read_to_string(&output).expect("read protected attach timeline");
    let lines = timeline.lines().collect::<Vec<_>>();
    let late_attach = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            line.contains(r#""record_type":"observation_gap""#)
                && line.contains(r#""kind":"late_attach""#)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        late_attach.len(),
        1,
        "protected attach requires exactly one late boundary:\n{timeline}"
    );
    let (late_attach_index, late_attach_record) = late_attach[0];
    assert!(late_attach_record.contains(r#""operation":"collector_lifecycle""#));
    assert!(late_attach_record.contains(r#""count":1"#));
    assert!(late_attach_record.contains(
        r#""detail":"collection_boundary:protected_existing_process_attach,history:unknown,provenance:external_registration,root_selection:registration_qualified""#
    ));

    let capability_index = lines
        .iter()
        .position(|line| line.contains(r#""record_type":"collector_capability_manifest""#))
        .expect("collector capability manifest");
    let started_index = lines
        .iter()
        .position(|line| {
            line.contains(r#""record_type":"collector_lifecycle""#)
                && line.contains(r#""state":"started""#)
        })
        .expect("collector lifecycle start");
    assert!(late_attach_index < capability_index);
    assert!(late_attach_index < started_index);
    assert!(
        lines
            .iter()
            .any(|line| line.contains(r#""event_type":"credential_read""#)),
        "registered descendant credential read was not observed:\n{timeline}"
    );
    assert!(!timeline.contains("late-attach-content-must-not-persist"));
    assert!(!timeline.contains(&registration.command));
    assert!(!timeline.contains(&registration.command_fingerprint));
    assert!(!timeline.contains(registration_path.to_str().expect("utf-8 registration path")));
}

#[test]
#[ignore = "requires Linux BTF, tracepoints, cgroup v2, CAP_BPF, and CAP_PERFMON"]
fn live_observer_records_scoped_events_and_redacts_sensitive_values() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::MetadataExt as _;
    use std::process::Stdio;

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
        .stdout(Stdio::null())
        .status()
        .expect("read credential fixture");
    assert!(status.success());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let port = listener.local_addr().expect("listener address").port();
    let accept = std::thread::spawn(move || listener.accept().expect("accept local connection"));
    let connection = TcpStream::connect(("127.0.0.1", port)).expect("run blocking network fixture");
    drop(accept.join().expect("join listener").0);
    drop(connection);

    let status = observer.wait().expect("wait for live observer");
    assert!(status.success());

    let timeline = std::fs::read_to_string(&output).expect("read live timeline");
    assert!(timeline.contains(r#""action":"aya_ring_buffer""#));
    assert!(timeline.contains(r#""resource":"observer-scope""#));
    assert!(timeline.contains(r#""record_type":"raw_kernel_event""#));
    assert!(timeline.contains(r#""event_type":"exec""#));
    assert!(timeline.contains(r#""event_type":"credential_read""#));
    assert!(timeline.contains(r#""event_type":"network_connect""#));
    let lifecycle_start_index = timeline
        .lines()
        .position(|line| {
            line.contains(r#""record_type":"collector_lifecycle""#)
                && line.contains(r#""state":"started""#)
        })
        .expect("collector lifecycle start");
    let first_kernel_event_index = timeline
        .lines()
        .position(|line| line.contains(r#""record_type":"raw_kernel_event""#))
        .expect("first raw kernel event");
    let credential_read = timeline
        .lines()
        .find(|line| line.contains(r#""event_type":"credential_read""#))
        .expect("credential read event");
    assert!(credential_read.contains(r#""outcome":"succeeded""#));
    assert!(credential_read.contains(r#""return_value":"#));
    assert!(credential_read.contains(r#""errno":null"#));
    assert!(credential_read.contains(r#""host_boot_id":"#));
    assert!(!credential_read.contains(r#""process_generation":null"#));
    assert!(!credential_read.contains(r#""process_start_time_ns":null"#));
    assert!(!credential_read.contains(r#""exec_generation":null"#));
    assert!(credential_read.contains(r#""relation_status":"exact""#));
    let connect = timeline
        .lines()
        .find(|line| line.contains(r#""event_type":"network_connect""#))
        .expect("network connect event");
    assert!(connect.contains(r#""outcome":"succeeded""#));
    assert!(connect.contains(r#""return_value":0"#));
    assert!(connect.contains(r#""errno":null"#));
    assert!(timeline.contains(r#""kind":"summary""#));
    let summary_index = timeline
        .lines()
        .position(|line| line.contains(r#""kind":"summary""#))
        .expect("observer summary");
    let lifecycle_stop_index = timeline
        .lines()
        .position(|line| {
            line.contains(r#""record_type":"collector_lifecycle""#)
                && line.contains(r#""state":"stopped""#)
                && line.contains(r#""stop_reason":"duration_elapsed""#)
        })
        .expect("collector lifecycle stop");
    assert!(lifecycle_start_index < first_kernel_event_index);
    assert!(summary_index < lifecycle_stop_index);
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

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()))
}

struct TempDirGuard {
    path: std::path::PathBuf,
}

impl TempDirGuard {
    fn create(prefix: &str) -> Self {
        let path = temp_dir(prefix);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create guarded temporary directory");
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard {
    child: Option<std::process::Child>,
    process_group: Option<i32>,
}

impl ChildGuard {
    fn spawn(mut command: Command, context: &str) -> Self {
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{context}: {error}"));
        Self {
            child: Some(child),
            process_group: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn spawn_process_group(mut command: Command, context: &str) -> Self {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{context}: {error}"));
        let process_group = i32::try_from(child.id()).expect("child PID fits process group id");
        Self {
            child: Some(child),
            process_group: Some(process_group),
        }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("live child").id()
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        self.child
            .take()
            .expect("live child")
            .wait()
            .expect("wait for child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Some(process_group) = self.process_group {
            // SAFETY: the negative PID targets only the dedicated process group
            // created by spawn_process_group for this test fixture.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        } else {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

#[cfg(target_os = "linux")]
fn wait_for_process_child(parent_pid: u32, timeout: Duration) {
    let children = format!("/proc/{parent_pid}/task/{parent_pid}/children");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(&children)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "registered process did not create its controlled child"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
fn wait_for_timeline_fragment(path: &std::path::Path, fragment: &str, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let timeline = std::fs::read_to_string(path).unwrap_or_default();
        if timeline.contains(fragment) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timeline did not persist {fragment:?}:\n{timeline}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct TestAgentRegistration {
    #[serde(rename = "agent_kind")]
    kind: String,
    pid: u32,
    start_time_ticks: u64,
    host_boot_id: String,
    workspace_root: std::path::PathBuf,
    executable: String,
    command_fingerprint: String,
    command: String,
}

fn write_current_process_registration(path: &std::path::Path) -> TestAgentRegistration {
    let registration = current_process_registration();
    write_agent_registration(path, &registration);
    registration
}

fn current_process_registration() -> TestAgentRegistration {
    process_registration(std::process::id(), workspace_root())
}

fn process_registration(
    pid: u32,
    registration_workspace_root: std::path::PathBuf,
) -> TestAgentRegistration {
    let command_args = process_command_args(pid);
    let fingerprint_input = if command_args.is_empty() {
        process_comm(pid).into_bytes()
    } else {
        command_args.join("\0").into_bytes()
    };

    TestAgentRegistration {
        kind: "codex".to_string(),
        pid,
        start_time_ticks: process_start_time_ticks(pid),
        host_boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .expect("read host boot identity")
            .trim()
            .to_string(),
        workspace_root: registration_workspace_root,
        executable: std::fs::read_link(format!("/proc/{pid}/exe"))
            .expect("read process executable")
            .display()
            .to_string(),
        command_fingerprint: sha256_fingerprint(&fingerprint_input),
        command: command_args.join(" "),
    }
}

fn write_agent_registration(path: &std::path::Path, registration: &TestAgentRegistration) {
    let file = std::fs::File::create(path).expect("create agent registration");
    serde_json::to_writer(file, registration).expect("serialize agent registration");
}

fn process_command_args(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .expect("read process command line")
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| String::from_utf8(value.to_vec()).expect("utf-8 process argument"))
        .collect()
}

fn process_comm(pid: u32) -> String {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .expect("read process stat for command name");
    let start = stat.find(" (").expect("proc stat command start") + 2;
    let end = stat.rfind(") ").expect("proc stat command end");
    stat[start..end].to_string()
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write command digest");
    }
    output
}

fn process_start_time_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read process stat");
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

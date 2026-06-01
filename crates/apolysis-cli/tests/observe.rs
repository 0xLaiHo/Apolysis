// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

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
            "session-m4-fixture",
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
            .all(|line| line.contains(r#""session_id":"session-m4-fixture""#)),
        "all canonical events should use the requested session id:\n{timeline}"
    );

    let _ = std::fs::remove_file(&output);
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
            "session-m4-runners",
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
            "session-m5-policy",
            "--policy",
            "tests/fixtures/policies/m5-block-policy.yaml",
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
    assert!(feedback.contains("session_id: session-m5-policy"));
    assert!(feedback.contains("rule_id:"));
    assert!(feedback.contains("decision: notify"));
    assert!(feedback.contains("APOLYSIS_VIOLATION"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&feedback_dir);
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
            "session-m6-k8s",
            "--policy",
            "tests/fixtures/policies/m5-block-policy.yaml",
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
    assert!(feedback.contains("session_id: session-m6-k8s"));
    assert!(feedback.contains("decision: notify"));
    assert!(feedback.contains("APOLYSIS_VIOLATION"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_dir_all(&feedback_dir);
}

fn apolysis_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
    command.current_dir(workspace_root());
    command
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

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()))
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

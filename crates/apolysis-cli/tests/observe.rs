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

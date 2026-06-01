// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::time::Duration;

#[test]
fn run_command_writes_a_jsonl_timeline() {
    let output =
        std::env::temp_dir().join(format!("apolysis-cli-run-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "run",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "echo",
            "hello",
        ])
        .status()
        .expect("run apolysis CLI");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    assert!(timeline.contains(r#""event_type":"session_started""#));
    assert!(timeline.contains(r#""event_type":"exec""#));
    assert!(timeline.contains(r#""event_type":"process_exit""#));
    assert!(timeline.contains(r#""actor":"echo hello""#));

    let _ = std::fs::remove_file(&output);
}

#[test]
fn run_command_attributes_child_processes_to_the_same_session() {
    let output = temp_jsonl("apolysis-cli-child-tree");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "run",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "bash",
            "-c",
            "python3 tests/fixtures/child.py",
        ])
        .status()
        .expect("run apolysis CLI");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    let session_ids = extract_json_values(&timeline, "session_id");
    assert!(
        !session_ids.is_empty(),
        "timeline should include session ids"
    );
    assert!(
        session_ids.iter().all(|value| value == &session_ids[0]),
        "all process events should share one session id: {session_ids:?}"
    );
    assert!(timeline.contains(r#""event_source":"process_tree""#));
    assert!(timeline.contains(r#""event_type":"runtime_metadata""#));
    assert!(timeline.contains("bash -c python3 tests/fixtures/child.py"));
    assert!(timeline.contains("python3 tests/fixtures/child.py"));
    assert!(
        timeline.matches(r#""event_type":"exec""#).count() >= 2,
        "timeline should include root and child exec events:\n{timeline}"
    );
    assert!(
        !timeline.contains(r#""actor":"python3","resource":"process","action":"exec""#),
        "exiting processes with an empty cmdline should not create synthetic exec noise:\n{timeline}"
    );
    assert_expected_fragments(
        &timeline,
        "tests/fixtures/expected/child-process-tree.contains",
    );

    let _ = std::fs::remove_file(&output);
}

#[test]
fn run_command_records_runtime_timeout_and_exits_non_zero() {
    let output = temp_jsonl("apolysis-cli-timeout");
    let policy = temp_jsonl("apolysis-cli-timeout-policy");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&policy);
    std::fs::write(
        &policy,
        r#"version: 1

runtime:
  max_seconds: 1
  max_processes: 16
"#,
    )
    .expect("write timeout policy");

    let status = apolysis_command()
        .args([
            "run",
            "--policy",
            policy.to_str().expect("utf-8 policy path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "python3",
            "tests/fixtures/sleep.py",
            "5",
        ])
        .status()
        .expect("run apolysis CLI");

    assert!(!status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    assert!(timeline.contains(r#""record_type":"policy_violation""#));
    assert!(timeline.contains(r#""rule_id":"runtime.max_seconds""#));
    assert!(timeline.contains(r#""decision":"notify""#));
    assert!(timeline.contains(r#""event_type":"process_exit""#));
    assert!(timeline.contains("killed:runtime.max_seconds"));
    assert_expected_fragments(
        &timeline,
        "tests/fixtures/expected/runtime-timeout.contains",
    );

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&policy);
}

#[test]
fn runtime_timeout_kills_descendant_processes() {
    let output = temp_jsonl("apolysis-cli-timeout-tree");
    let policy = temp_jsonl("apolysis-cli-timeout-tree-policy");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&policy);
    std::fs::write(
        &policy,
        r#"version: 1

runtime:
  max_seconds: 1
  max_processes: 16
"#,
    )
    .expect("write timeout policy");

    let status = apolysis_command()
        .args([
            "run",
            "--policy",
            policy.to_str().expect("utf-8 policy path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "bash",
            "-c",
            "python3 tests/fixtures/sleep.py 5 & wait",
        ])
        .status()
        .expect("run apolysis CLI");

    assert!(!status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    let session_id = extract_json_values(&timeline, "session_id")
        .into_iter()
        .next()
        .expect("timeline session id");
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !process_with_session_exists(&session_id),
        "timeout should kill descendant processes with APOLYSIS_SESSION_ID={session_id}"
    );

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&policy);
}

fn temp_jsonl(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}.jsonl", std::process::id()))
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

fn extract_json_values(input: &str, key: &str) -> Vec<String> {
    let pattern = format!(r#""{key}":""#);
    input
        .lines()
        .filter_map(|line| {
            let start = line.find(&pattern)? + pattern.len();
            let rest = &line[start..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .collect()
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

fn process_with_session_exists(session_id: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    let needle = format!("APOLYSIS_SESSION_ID={session_id}");

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .any(|pid| {
            let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
                return false;
            };
            environ
                .split(|byte| *byte == 0)
                .any(|entry| entry == needle.as_bytes())
        })
}

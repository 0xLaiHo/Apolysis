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

#[test]
fn docker_runtime_uses_safe_defaults_and_records_metadata() {
    let output = temp_jsonl("apolysis-cli-docker");
    let policy = temp_jsonl("apolysis-cli-docker-policy");
    let docker_log = temp_jsonl("apolysis-cli-docker-args");
    let cid = "apolysis-test-container-123";
    let write_dir =
        std::env::temp_dir().join(format!("apolysis-docker-write-{}", std::process::id()));
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&docker_log);
    let _ = std::fs::create_dir_all(&write_dir);
    std::fs::write(
        &policy,
        format!(
            r#"version: 1

workspace:
  allow_read:
    - tests/fixtures
  allow_write:
    - {}
runtime:
  max_seconds: 60
  max_processes: 32
"#,
            write_dir.display()
        ),
    )
    .expect("write docker policy");

    let status = apolysis_command()
        .env(
            "APOLYSIS_DOCKER_BIN",
            workspace_root().join("tests/fixtures/docker_stub.sh"),
        )
        .env("APOLYSIS_DOCKER_STUB_LOG", &docker_log)
        .env("APOLYSIS_DOCKER_STUB_CID", cid)
        .args([
            "run",
            "--runtime",
            "docker",
            "--image",
            "alpine:3.20",
            "--policy",
            policy.to_str().expect("utf-8 policy path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "echo",
            "hello",
        ])
        .status()
        .expect("run apolysis docker CLI");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    let docker_args = std::fs::read_to_string(&docker_log).expect("read docker args");
    let session_id = extract_json_values(&timeline, "session_id")
        .into_iter()
        .next()
        .expect("timeline session id");

    assert_expected_fragments(&timeline, "tests/fixtures/expected/docker-runtime.contains");
    assert!(timeline.contains(cid));
    assert!(timeline.contains("image:alpine:3.20"));
    assert!(timeline.contains("network:none"));
    assert!(timeline.contains(&format!("docker://{cid}")));
    assert!(docker_args.contains("--read-only\n"));
    assert!(docker_args.contains("--rm\n"));
    assert!(docker_args.contains("--network\nnone\n"));
    assert!(docker_args.contains("--cap-drop\nALL\n"));
    assert!(docker_args.contains("--security-opt\nno-new-privileges\n"));
    assert!(docker_args.contains("--pids-limit\n32\n"));
    assert!(docker_args.contains("--cpus\n1\n"));
    assert!(docker_args.contains("--memory\n512m\n"));
    assert!(docker_args.contains("--tmpfs\n/tmp:rw,noexec,nosuid,nodev,size=64m\n"));
    assert!(docker_args.contains(&format!("--label\napolysis.session_id={session_id}\n")));
    assert!(docker_args.contains(&format!("--env\nAPOLYSIS_SESSION_ID={session_id}\n")));
    assert!(docker_args.contains("type=bind"));
    assert!(docker_args.contains("readonly"));
    assert!(docker_args.contains("tests/fixtures"));
    assert!(docker_args.contains("/workspace/write/"));
    assert!(!docker_args.contains("--privileged"));
    assert!(!docker_args.contains("--network\nhost\n"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&policy);
    let _ = std::fs::remove_file(&docker_log);
    let _ = std::fs::remove_dir_all(&write_dir);
}

#[test]
fn docker_runtime_can_select_an_oci_runtime_backend() {
    let output = temp_jsonl("apolysis-cli-docker-runsc");
    let docker_log = temp_jsonl("apolysis-cli-docker-runsc-args");
    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&docker_log);

    let status = apolysis_command()
        .env(
            "APOLYSIS_DOCKER_BIN",
            workspace_root().join("tests/fixtures/docker_stub.sh"),
        )
        .env("APOLYSIS_DOCKER_STUB_LOG", &docker_log)
        .env("APOLYSIS_DOCKER_STUB_CID", "apolysis-runsc-container")
        .args([
            "run",
            "--runtime",
            "docker",
            "--docker-runtime",
            "runsc",
            "--image",
            "alpine:3.20",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "echo",
            "hello",
        ])
        .status()
        .expect("run apolysis docker CLI");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    let docker_args = std::fs::read_to_string(&docker_log).expect("read docker args");
    assert!(docker_args.contains("--runtime\nrunsc\n"));
    assert!(timeline.contains(r#""resource":"docker-runtime""#));
    assert!(timeline.contains("oci-runtime:runsc"));

    let _ = std::fs::remove_file(&output);
    let _ = std::fs::remove_file(&docker_log);
}

#[test]
fn docker_runtime_requires_an_image() {
    let output = temp_jsonl("apolysis-cli-docker-missing-image");
    let output_result = apolysis_command()
        .args([
            "run",
            "--runtime",
            "docker",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("run apolysis docker CLI");

    assert_eq!(output_result.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output_result.stderr);
    assert!(stderr.contains("missing --image"));
    let _ = std::fs::remove_file(&output);
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

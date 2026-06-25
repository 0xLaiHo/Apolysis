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
        stderr.contains("live observer requires exactly one of --scope-cgroup or --scope-pid"),
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

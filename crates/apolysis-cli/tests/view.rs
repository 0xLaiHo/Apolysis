// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_observer::{audit_observer_capability_manifest, AyaLoaderPlan, LiveScope};
use apolysis_store::MAX_SAVED_RUN_BYTES;
use serde_json::{json, Value};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn run_view_writes_one_private_offline_traceable_report() {
    let root = temp_root("complete");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    let findings = root.join("findings.jsonl");
    let record = root.join("record.json");
    let report = root.join("report.html");
    write_jsonl(&timeline, &complete_run("run-view"));
    write_jsonl(
        &findings,
        &[json!({
            "record_type": "accountability_finding",
            "schema_version": 1,
            "session_id": "run-view",
            "kind": "unknown_egress",
            "decision": "review",
            "reason": "network endpoint is outside the declared egress set",
            "evidence_ref": "event-1",
            "runtime": {
                "runtime": "native",
                "container_id": null,
                "pod_uid": null,
                "cgroup_id": null
            },
            "evidence_boundary": "host_boundary"
        })],
    );
    assert_success(
        apolysis_command()
            .args([
                "run",
                "project",
                "--input",
                timeline.to_str().expect("utf-8 timeline path"),
                "--input",
                findings.to_str().expect("utf-8 findings path"),
                "--output",
                record.to_str().expect("utf-8 record path"),
            ])
            .output()
            .expect("run projection command"),
    );
    let result = apolysis_command()
        .args([
            "run",
            "view",
            "--input",
            record.to_str().expect("utf-8 record path"),
            "--output",
            report.to_str().expect("utf-8 report path"),
        ])
        .output()
        .expect("run viewer command");

    assert_success(result);
    let html = std::fs::read_to_string(&report).expect("read viewer output");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("data-apolysis-viewer-schema=\"1\""));
    assert!(html.contains("Evidence State"));
    assert!(html.contains("Collector Health"));
    assert!(html.contains("Review State"));
    assert!(html.contains("source ordinal 3"));
    assert!(html.contains("network endpoint is outside the declared egress set"));
    assert!(html.contains("event-1"));
    assert!(!html.contains("src=\"http"));
    assert!(!html.contains("href=\"http"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&report)
            .expect("viewer output metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "viewer output must be private");
    }

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_view_rejects_an_inconsistent_record_without_replacing_output_or_leaking_payload() {
    let root = temp_root("inconsistent");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    let projected = root.join("projected.json");
    let inconsistent = root.join("APOLYSIS_VIEW_SECRET_INPUT.json");
    let report = root.join("APOLYSIS_VIEW_SECRET_OUTPUT.html");
    let secret_run_id = "APOLYSIS_VIEW_SECRET_RUN";
    let secret_payload = "APOLYSIS_VIEW_SECRET_PAYLOAD";
    write_jsonl(&timeline, &complete_run(secret_run_id));
    assert_success(
        apolysis_command()
            .args([
                "run",
                "project",
                "--input",
                timeline.to_str().expect("utf-8 timeline path"),
                "--output",
                projected.to_str().expect("utf-8 projection path"),
            ])
            .output()
            .expect("run projection command"),
    );
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&projected).expect("read projection"))
            .expect("parse projection");
    record["summary"]["runtime_observation_count"] = json!(99);
    record["runtime_observations"][0]["resource"] = json!(secret_payload);
    std::fs::write(
        &inconsistent,
        serde_json::to_vec_pretty(&record).expect("serialize inconsistent record"),
    )
    .expect("write inconsistent record");
    std::fs::write(&report, "sentinel\n").expect("write existing viewer output");

    let result = apolysis_command()
        .args([
            "run",
            "view",
            "--input",
            inconsistent.to_str().expect("utf-8 input path"),
            "--output",
            report.to_str().expect("utf-8 report path"),
        ])
        .output()
        .expect("run viewer command");

    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(&report).expect("read existing output"),
        "sentinel\n"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("internally inconsistent"), "{stderr}");
    assert!(!stderr.contains(secret_run_id));
    assert!(!stderr.contains(secret_payload));
    assert!(!stderr.contains("APOLYSIS_VIEW_SECRET_INPUT"));
    assert!(!stderr.contains("APOLYSIS_VIEW_SECRET_OUTPUT"));
    assert!(!stderr.contains(inconsistent.to_str().expect("utf-8 input path")));
    assert!(!stderr.contains(report.to_str().expect("utf-8 output path")));

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_view_refuses_same_path_and_hard_link_outputs_without_mutating_input() {
    assert_view_alias_refused("same-path", false);
    assert_view_alias_refused("hard-link", true);
}

#[test]
fn run_view_rejects_symlink_directory_and_oversized_inputs() {
    use std::os::unix::fs::symlink;

    let root = temp_root("unsafe-input");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let record = project_complete_record(&root, "run-view-unsafe-input");
    let symlink_input = root.join("APOLYSIS_VIEW_SECRET_INPUT_LINK.json");
    symlink(&record, &symlink_input).expect("create input symlink");
    let directory_input = root.join("APOLYSIS_VIEW_SECRET_INPUT_DIRECTORY");
    std::fs::create_dir(&directory_input).expect("create input directory");
    let oversized_input = root.join("APOLYSIS_VIEW_SECRET_OVERSIZED_INPUT.json");
    std::fs::File::create(&oversized_input)
        .and_then(|file| file.set_len(MAX_SAVED_RUN_BYTES + 1))
        .expect("create sparse oversized input");

    for (case, input, expected_error) in [
        ("symlink", &symlink_input, "input is a symlink"),
        ("directory", &directory_input, "input is not a regular file"),
        (
            "oversized",
            &oversized_input,
            "input exceeded the byte limit",
        ),
    ] {
        let report = root.join(format!("{case}.html"));
        let result = run_view(input, &report);
        assert_eq!(result.status.code(), Some(2), "{case}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(expected_error), "{case}: {stderr}");
        assert!(!stderr.contains("APOLYSIS_VIEW_SECRET"), "{case}: {stderr}");
        assert!(!report.exists(), "{case} must not create output");
    }

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_view_rejects_symlink_and_directory_outputs_without_touching_targets() {
    use std::os::unix::fs::symlink;

    let root = temp_root("unsafe-output");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let record = project_complete_record(&root, "run-view-unsafe-output");
    let target = root.join("target.html");
    std::fs::write(&target, "sentinel\n").expect("write symlink target");
    let symlink_output = root.join("APOLYSIS_VIEW_SECRET_OUTPUT_LINK.html");
    symlink(&target, &symlink_output).expect("create output symlink");
    let directory_output = root.join("APOLYSIS_VIEW_SECRET_OUTPUT_DIRECTORY");
    std::fs::create_dir(&directory_output).expect("create output directory");

    for (case, output) in [
        ("symlink", &symlink_output),
        ("directory", &directory_output),
    ] {
        let result = run_view(&record, output);
        assert_eq!(result.status.code(), Some(2), "{case}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.contains("output must be a regular file"),
            "{case}: {stderr}"
        );
        assert!(!stderr.contains("APOLYSIS_VIEW_SECRET"), "{case}: {stderr}");
    }
    assert_eq!(
        std::fs::read_to_string(&target).expect("read symlink target"),
        "sentinel\n"
    );
    assert!(symlink_output.is_symlink());
    assert!(directory_output.is_dir());

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_view_is_byte_deterministic_for_the_same_record() {
    let root = temp_root("deterministic");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let record = project_complete_record(&root, "run-view-deterministic");
    let first = root.join("first.html");
    let second = root.join("second.html");

    assert_success(run_view(&record, &first));
    assert_success(run_view(&record, &second));

    assert_eq!(
        std::fs::read(&first).expect("read first viewer output"),
        std::fs::read(&second).expect("read second viewer output")
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

fn assert_view_alias_refused(name: &str, hard_link: bool) {
    let root = temp_root(name);
    std::fs::create_dir_all(&root).expect("create fixture root");
    let record = project_complete_record(&root, &format!("run-view-{name}"));
    let output = if hard_link {
        let output = root.join("report.html");
        std::fs::hard_link(&record, &output).expect("create hard-link output alias");
        output
    } else {
        record.clone()
    };
    let before = std::fs::read(&record).expect("read input before viewing");

    let result = apolysis_command()
        .args([
            "run",
            "view",
            "--input",
            record.to_str().expect("utf-8 record path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run viewer command");

    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("aliases its input"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(&record).expect("read input after viewing"),
        before
    );
    assert_eq!(
        std::fs::read(&output).expect("read alias after viewing"),
        before
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

fn project_complete_record(root: &std::path::Path, agent_run_id: &str) -> std::path::PathBuf {
    let timeline = root.join("timeline.jsonl");
    let record = root.join("record.json");
    write_jsonl(&timeline, &complete_run(agent_run_id));
    assert_success(
        apolysis_command()
            .args([
                "run",
                "project",
                "--input",
                timeline.to_str().expect("utf-8 timeline path"),
                "--output",
                record.to_str().expect("utf-8 record path"),
            ])
            .output()
            .expect("run projection command"),
    );
    record
}

fn run_view(input: &std::path::Path, output: &std::path::Path) -> std::process::Output {
    apolysis_command()
        .args([
            "run",
            "view",
            "--input",
            input.to_str().expect("utf-8 input path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run viewer command")
}

fn assert_success(result: std::process::Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn complete_run(agent_run_id: &str) -> Vec<Value> {
    vec![
        capability(agent_run_id, 1000),
        lifecycle(agent_run_id, 1001, "started", "healthy", Value::Null),
        network_observation(agent_run_id, 1002),
        lifecycle(
            agent_run_id,
            1003,
            "stopped",
            "healthy",
            json!("agent_exited"),
        ),
    ]
}

fn capability(agent_run_id: &str, timestamp_unix_ms: u64) -> Value {
    let loader_plan = AyaLoaderPlan::audit_observer_default("target/ebpf/apolysis_observer.bpf.o");
    let manifest =
        audit_observer_capability_manifest(agent_run_id, &LiveScope::ProcessTree(42), &loader_plan);
    let mut value: Value =
        serde_json::from_str(&manifest.to_json_line()).expect("parse production manifest");
    value["timestamp_unix_ms"] = json!(timestamp_unix_ms);
    value
}

fn lifecycle(
    agent_run_id: &str,
    timestamp_unix_ms: u64,
    state: &str,
    health: &str,
    stop_reason: Value,
) -> Value {
    json!({
        "record_type": "collector_lifecycle",
        "schema_version": 1,
        "timestamp_unix_ms": timestamp_unix_ms,
        "agent_run_id": agent_run_id,
        "collector": "apolysis_observer",
        "collector_instance_id": "collector-1",
        "state": state,
        "health": health,
        "stop_reason": stop_reason,
        "counters": {
            "global_reserve_failures": 0,
            "global_map_pressure": 0,
            "global_abi_mismatches": 0,
            "global_decode_failures": 0,
            "global_truncations": 0,
            "scope_missing_entries": 0,
            "scope_missing_exits": 0,
            "scope_pending": 0
        }
    })
}

fn network_observation(agent_run_id: &str, timestamp_unix_ms: u64) -> Value {
    json!({
        "record_type": "event",
        "timestamp_unix_ms": timestamp_unix_ms,
        "session_id": agent_run_id,
        "event_source": "kernel_tracepoint",
        "event_type": "network_connect",
        "raw_event_id": "event-1",
        "pid": 42,
        "ppid": 1,
        "actor": "agent",
        "resource": "address_token:0123456789abcdef01234567:port:443",
        "action": "connect",
        "outcome": "succeeded",
        "return_value": 0,
        "errno": null,
        "container_id": null,
        "cgroup_id": null,
        "host_boot_id": "00000000-0000-0000-0000-000000000042",
        "scope_generation": 7,
        "process_generation": 11,
        "process_start_time_ns": 123456,
        "exec_generation": 2,
        "parent_process_generation": 3,
        "parent_exec_generation": 1,
        "relation_status": "exact",
        "relation_reason": "host_boot_scope_process_start_exec_generation",
        "process_command": null,
        "process_executable": "executable_ref:agent",
        "process_started_at_unix_ms": null
    })
}

fn write_jsonl(path: &std::path::Path, records: &[Value]) {
    let mut output = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("serialize fixture"))
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    std::fs::write(path, output).expect("write JSONL fixture");
}

fn apolysis_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command
}

fn temp_root(name: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "apolysis-cli-view-{name}-{}-{id}",
        std::process::id()
    ))
}

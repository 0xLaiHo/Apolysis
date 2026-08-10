// SPDX-License-Identifier: Apache-2.0

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_observer::{audit_observer_capability_manifest, AyaLoaderPlan, LiveScope};
use apolysis_store::HashChainStore;
use serde_json::{json, Value};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn run_project_writes_one_private_queryable_agent_observation_record() {
    let root = temp_root("plain");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    let findings = root.join("findings.jsonl");
    let output = root.join("record.json");
    write_jsonl(&timeline, &complete_run("run-cli"));
    write_jsonl(
        &findings,
        &[json!({
            "record_type": "accountability_finding",
            "schema_version": 1,
            "session_id": "run-cli",
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
    std::fs::write(&output, "stale output\n").expect("write prior output");

    let result = apolysis_command()
        .args([
            "run",
            "project",
            "--input",
            timeline.to_str().expect("utf-8 timeline path"),
            "--input",
            findings.to_str().expect("utf-8 findings path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run projection command");

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let record: Value = serde_json::from_slice(&std::fs::read(&output).expect("read output"))
        .expect("parse output");
    assert_eq!(record["record_type"], "agent_observation_record");
    assert_eq!(record["agent_run_id"], "run-cli");
    assert_eq!(record["summary"]["evidence_state"], "complete");
    assert_eq!(record["summary"]["review_state"], "requires_review");
    assert_eq!(record["summary"]["runtime_observation_count"], 1);
    assert_eq!(record["summary"]["finding_count"], 1);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&output)
            .expect("output metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "projection output must be private");
    }

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_project_verifies_hash_chain_before_projection() {
    let root = temp_root("hash-chain");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    let output = root.join("record.json");
    let mut store = HashChainStore::create_or_recover(&timeline)
        .expect("create chain")
        .store;
    for record in complete_run("run-chain") {
        store
            .append_json(
                1,
                &serde_json::to_string(&record).expect("serialize fixture"),
            )
            .expect("append fixture");
    }
    store.flush().expect("flush chain");
    drop(store);

    let result = apolysis_command()
        .args([
            "run",
            "project",
            "--input",
            timeline.to_str().expect("utf-8 timeline path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run projection command");

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let record: Value = serde_json::from_slice(&std::fs::read(&output).expect("read output"))
        .expect("parse output");
    assert_eq!(record["source_integrity"], "verified_hash_chain");

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_project_failure_preserves_existing_output_and_does_not_leak_payloads() {
    let root = temp_root("mixed-run");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let first = root.join("first.jsonl");
    let second = root.join("second.jsonl");
    let output = root.join("record.json");
    write_jsonl(
        &first,
        &[
            capability("run-expected", 1000),
            lifecycle("run-expected", 1001, "started", "healthy", Value::Null),
        ],
    );
    let secret = "APOLYSIS_CLI_PROJECTION_SECRET";
    write_jsonl(&second, &[network_observation(secret, 1002)]);
    std::fs::write(&output, "sentinel\n").expect("write existing output");

    let result = apolysis_command()
        .args([
            "run",
            "project",
            "--input",
            first.to_str().expect("utf-8 first path"),
            "--input",
            second.to_str().expect("utf-8 second path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run projection command");

    assert_eq!(result.status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(&output).expect("read output"),
        "sentinel\n"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("belongs to a different Agent Run"),
        "{stderr}"
    );
    assert!(!stderr.contains(secret));

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_project_rejects_corrupt_chain_without_creating_output() {
    let root = temp_root("corrupt-chain");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    let output = root.join("record.json");
    let mut store = HashChainStore::create_or_recover(&timeline)
        .expect("create chain")
        .store;
    for record in complete_run("run-corrupt") {
        store
            .append_json(
                1,
                &serde_json::to_string(&record).expect("serialize fixture"),
            )
            .expect("append fixture");
    }
    store.flush().expect("flush chain");
    drop(store);
    let chain = std::fs::read_to_string(&timeline).expect("read chain");
    std::fs::write(&timeline, chain.replacen("event-1", "event-9", 1)).expect("tamper chain");

    let result = apolysis_command()
        .args([
            "run",
            "project",
            "--input",
            timeline.to_str().expect("utf-8 timeline path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .output()
        .expect("run projection command");

    assert_eq!(result.status.code(), Some(2));
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("hash-chain integrity failed"));

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_project_refuses_to_overwrite_any_input_source() {
    let root = temp_root("input-alias");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    write_jsonl(&timeline, &complete_run("run-alias"));
    let before = std::fs::read(&timeline).expect("read source before projection");

    let result = apolysis_command()
        .args([
            "run",
            "project",
            "--input",
            timeline.to_str().expect("utf-8 timeline path"),
            "--output",
            timeline.to_str().expect("utf-8 timeline path"),
        ])
        .output()
        .expect("run projection command");

    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("aliases an input source"));
    assert_eq!(
        std::fs::read(&timeline).expect("read source after projection"),
        before
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn run_project_is_byte_deterministic_for_the_same_saved_run() {
    let root = temp_root("deterministic");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let timeline = root.join("timeline.jsonl");
    let first = root.join("first.json");
    let second = root.join("second.json");
    write_jsonl(&timeline, &complete_run("run-deterministic"));

    for output in [&first, &second] {
        let result = apolysis_command()
            .args([
                "run",
                "project",
                "--input",
                timeline.to_str().expect("utf-8 timeline path"),
                "--output",
                output.to_str().expect("utf-8 output path"),
            ])
            .output()
            .expect("run projection command");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    assert_eq!(
        std::fs::read(&first).expect("read first projection"),
        std::fs::read(&second).expect("read second projection")
    );
    std::fs::remove_dir_all(root).expect("remove fixture root");
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
        "apolysis-cli-project-{name}-{}-{id}",
        std::process::id()
    ))
}

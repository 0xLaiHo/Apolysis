// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn intent_ingest_codex_jsonl_writes_redacted_intent_records() {
    let input = temp_jsonl("apolysis-codex-intent-input");
    let output = temp_jsonl("apolysis-codex-intent-output");
    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);

    std::fs::write(
        &input,
        r#"{"type":"response_item","payload":{"type":"function_call","id":"call-1","name":"exec_command","arguments":"{\"cmd\":\"cat Cargo.toml\"}"}}
{"type":"response_item","payload":{"type":"function_call","id":"call-2","name":"exec_command","arguments":{"cmd":"curl -H 'Authorization: Bearer sk-test-secret' https://example.invalid"}}}
{"type":"message","role":"assistant","content":"not a tool call"}
"#,
    )
    .expect("write codex intent fixture");

    let status = apolysis_command()
        .args([
            "intent",
            "ingest",
            "--adapter",
            "codex-jsonl",
            "--input",
            input.to_str().expect("utf-8 input path"),
            "--session",
            "session-intent-cli",
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis intent ingest");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read intent timeline");
    assert_eq!(
        timeline.matches(r#""record_type":"intent""#).count(),
        2,
        "only Codex tool calls should become intent records:\n{timeline}"
    );
    assert!(timeline.contains(r#""session_id":"session-intent-cli""#));
    assert!(timeline.contains(r#""intent_source":"codex""#));
    assert!(timeline.contains(r#""intent_id":"codex:call-1""#));
    assert!(timeline.contains(r#""source_event_id":"call-1""#));
    assert!(timeline.contains(r#""tool_name":"exec_command""#));
    assert!(timeline.contains(r#""declared_action":"shell.command""#));
    assert!(timeline.contains(r#""command":"cat Cargo.toml""#));
    assert!(timeline.contains("<redacted>"));
    assert!(!timeline.contains("sk-test-secret"));
    assert!(timeline
        .lines()
        .all(|line| line.contains(r#""raw_event_id":null"#)));

    let _ = std::fs::remove_file(&input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn intent_ingest_rejects_unknown_adapter() {
    let output = apolysis_command()
        .args([
            "intent",
            "ingest",
            "--adapter",
            "unknown",
            "--input",
            "missing.jsonl",
            "--session",
            "session-intent-cli",
            "--output",
            "ignored.jsonl",
        ])
        .output()
        .expect("run apolysis intent ingest");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported intent adapter"));
}

#[test]
fn intent_correlate_links_commands_and_reports_mismatches() {
    let intent_input = temp_jsonl("apolysis-intent-correlate-intents");
    let timeline_input = temp_jsonl("apolysis-intent-correlate-timeline");
    let output = temp_jsonl("apolysis-intent-correlate-output");
    let _ = std::fs::remove_file(&intent_input);
    let _ = std::fs::remove_file(&timeline_input);
    let _ = std::fs::remove_file(&output);

    std::fs::write(
        &intent_input,
        r#"{"record_type":"intent","timestamp_unix_ms":1780328100001,"session_id":"session-intent-correlate","intent_source":"codex","intent_id":"codex:call-1","source_event_id":"call-1","intent_type":"tool_call","tool_name":"exec_command","declared_action":"shell.command","target":"workspace","command":"cat Cargo.toml","raw_event_id":null}
{"record_type":"intent","timestamp_unix_ms":1780328100002,"session_id":"session-intent-correlate","intent_source":"codex","intent_id":"codex:call-2","source_event_id":"call-2","intent_type":"tool_call","tool_name":"exec_command","declared_action":"shell.command","target":"workspace","command":"rg TODO README.md","raw_event_id":null}
"#,
    )
    .expect("write intent records");
    std::fs::write(
        &timeline_input,
        r#"{"record_type":"event","timestamp_unix_ms":1780328200001,"session_id":"session-intent-correlate","event_source":"kernel_tracepoint","event_type":"file_open","raw_event_id":"session-intent-correlate:event:0000000000000001","pid":4100,"ppid":1,"actor":"cat","resource":"Cargo.toml","action":"open","container_id":null,"cgroup_id":null,"process_command":"cat Cargo.toml","process_executable":"/usr/bin/cat","process_started_at_unix_ms":1780328199000}
{"record_type":"event","timestamp_unix_ms":1780328200002,"session_id":"session-intent-correlate","event_source":"kernel_tracepoint","event_type":"network_connect","raw_event_id":"session-intent-correlate:event:0000000000000002","pid":4101,"ppid":1,"actor":"curl","resource":"address_token:abc:port:443","action":"connect","container_id":"container-123","cgroup_id":987654321,"pod_uid":"pod-abc","process_command":"curl https://example.invalid","process_executable":"/usr/bin/curl","process_started_at_unix_ms":1780328199500}
"#,
    )
    .expect("write observed timeline");

    let status = apolysis_command()
        .args([
            "intent",
            "correlate",
            "--intent-input",
            intent_input.to_str().expect("utf-8 intent path"),
            "--timeline-input",
            timeline_input.to_str().expect("utf-8 timeline path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis intent correlate");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read correlation output");
    assert_eq!(
        timeline
            .matches(r#""record_type":"intent_correlation""#)
            .count(),
        1,
        "one intent should be linked to observed host evidence:\n{timeline}"
    );
    assert!(timeline.contains(r#""intent_id":"codex:call-1""#));
    assert!(
        timeline.contains(r#""raw_event_id":"session-intent-correlate:event:0000000000000001""#)
    );
    assert!(timeline.contains(r#""match_basis":"process_command_exact""#));
    assert!(timeline.contains(r#""event_type":"file_open""#));

    assert_eq!(
        timeline
            .matches(r#""record_type":"accountability_finding""#)
            .count(),
        2,
        "unmatched observed effects and unobserved intents should both be findings:\n{timeline}"
    );
    assert!(timeline.contains(r#""kind":"missing_intent""#));
    assert!(
        timeline.contains(r#""evidence_ref":"session-intent-correlate:event:0000000000000002""#)
    );
    assert!(timeline.contains(r#""container_id":"container-123""#));
    assert!(timeline.contains(r#""cgroup_id":987654321"#));
    assert!(timeline.contains(r#""pod_uid":"pod-abc""#));
    assert!(timeline.contains(r#""kind":"unobserved_intent""#));
    assert!(timeline.contains(r#""evidence_ref":"codex:call-2""#));

    let _ = std::fs::remove_file(&intent_input);
    let _ = std::fs::remove_file(&timeline_input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn intent_correlate_prefers_raw_event_id_when_present() {
    let intent_input = temp_jsonl("apolysis-intent-correlate-id-intents");
    let timeline_input = temp_jsonl("apolysis-intent-correlate-id-timeline");
    let output = temp_jsonl("apolysis-intent-correlate-id-output");
    let _ = std::fs::remove_file(&intent_input);
    let _ = std::fs::remove_file(&timeline_input);
    let _ = std::fs::remove_file(&output);

    std::fs::write(
        &intent_input,
        r#"{"record_type":"intent","timestamp_unix_ms":1780328300001,"session_id":"session-intent-id-correlate","intent_source":"codex","intent_id":"codex:call-raw","source_event_id":"call-raw","intent_type":"tool_call","tool_name":"exec_command","declared_action":"shell.command","target":"workspace","command":"cat README.md","raw_event_id":"session-intent-id-correlate:event:0000000000000042"}
"#,
    )
    .expect("write intent records");
    std::fs::write(
        &timeline_input,
        r#"{"record_type":"event","timestamp_unix_ms":1780328301001,"session_id":"session-intent-id-correlate","event_source":"kernel_tracepoint","event_type":"file_open","raw_event_id":"session-intent-id-correlate:event:0000000000000042","pid":4200,"ppid":1,"actor":"cat","resource":"README.md","action":"open","container_id":null,"cgroup_id":null,"process_command":"cat README.md","process_executable":"/usr/bin/cat","process_started_at_unix_ms":1780328300000}
"#,
    )
    .expect("write observed timeline");

    let status = apolysis_command()
        .args([
            "intent",
            "correlate",
            "--intent-input",
            intent_input.to_str().expect("utf-8 intent path"),
            "--timeline-input",
            timeline_input.to_str().expect("utf-8 timeline path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis intent correlate");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read correlation output");
    assert_eq!(
        timeline
            .matches(r#""record_type":"intent_correlation""#)
            .count(),
        1,
        "one raw_event_id-backed intent should be linked:\n{timeline}"
    );
    assert!(timeline.contains(r#""match_basis":"raw_event_id""#));
    assert!(!timeline.contains(r#""record_type":"accountability_finding""#));

    let _ = std::fs::remove_file(&intent_input);
    let _ = std::fs::remove_file(&timeline_input);
    let _ = std::fs::remove_file(&output);
}

#[test]
fn intent_correlate_links_truncated_live_exec_by_executable_path() {
    let intent_input = temp_jsonl("apolysis-intent-correlate-executable-intents");
    let timeline_input = temp_jsonl("apolysis-intent-correlate-executable-timeline");
    let output = temp_jsonl("apolysis-intent-correlate-executable-output");
    let _ = std::fs::remove_file(&intent_input);
    let _ = std::fs::remove_file(&timeline_input);
    let _ = std::fs::remove_file(&output);

    std::fs::write(
        &intent_input,
        r#"{"record_type":"intent","timestamp_unix_ms":1780328400001,"session_id":"session-intent-executable-correlate","intent_source":"codex","intent_id":"codex:call-live-script","source_event_id":"call-live-script","intent_type":"tool_call","tool_name":"exec_command","declared_action":"shell.command","target":"workspace","command":"./scripts/run-codex-live-demo-workload.sh","raw_event_id":null}
"#,
    )
    .expect("write intent records");
    std::fs::write(
        &timeline_input,
        r#"{"record_type":"event","timestamp_unix_ms":1780328401001,"session_id":"session-intent-executable-correlate","event_source":"kernel_tracepoint","event_type":"exec","raw_event_id":"session-intent-executable-correlate:event:0000000000000100","pid":4300,"ppid":1,"actor":"run-codex-live-","resource":"./scripts/run-codex-live-demo-workload.sh","action":"exec","container_id":null,"cgroup_id":null,"process_command":"./scripts/run-codex-live-demo-w","process_executable":"./scripts/run-codex-live-demo-workload.sh","process_started_at_unix_ms":1780328401000}
{"record_type":"event","timestamp_unix_ms":1780328401002,"session_id":"session-intent-executable-correlate","event_source":"kernel_tracepoint","event_type":"file_open","raw_event_id":"session-intent-executable-correlate:event:0000000000000101","pid":4301,"ppid":4300,"actor":"python3","resource":"path_token:dccfe6616e57989e18638cd0","action":"read","container_id":null,"cgroup_id":null,"process_command":"python3 path_token:f3d72bc9350a77bf367c9645","process_executable":"/usr/bin/python3","process_started_at_unix_ms":1780328401001}
{"record_type":"event","timestamp_unix_ms":1780328401003,"session_id":"session-intent-executable-correlate","event_source":"kernel_tracepoint","event_type":"credential_read","raw_event_id":"session-intent-executable-correlate:event:0000000000000102","pid":4301,"ppid":4300,"actor":"python3","resource":"path_token:aa11bb22cc33dd44ee55ff66","action":"read","container_id":null,"cgroup_id":null,"process_command":"python3 path_token:f3d72bc9350a77bf367c9645","process_executable":"/usr/bin/python3","process_started_at_unix_ms":1780328401002}
"#,
    )
    .expect("write observed timeline");

    let status = apolysis_command()
        .args([
            "intent",
            "correlate",
            "--intent-input",
            intent_input.to_str().expect("utf-8 intent path"),
            "--timeline-input",
            timeline_input.to_str().expect("utf-8 timeline path"),
            "--output",
            output.to_str().expect("utf-8 output path"),
        ])
        .status()
        .expect("run apolysis intent correlate");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read correlation output");
    assert_eq!(
        timeline
            .matches(r#""record_type":"intent_correlation""#)
            .count(),
        1,
        "truncated live exec should still be linked to its declared intent:\n{timeline}"
    );
    assert!(timeline.contains(r#""intent_id":"codex:call-live-script""#));
    assert!(timeline.contains(r#""match_basis":"process_executable""#));
    assert!(timeline.contains(
        r#""raw_event_id":"session-intent-executable-correlate:event:0000000000000100""#
    ));
    assert_eq!(
        timeline.matches(r#""kind":"missing_intent""#).count(),
        1,
        "only the credential read is an accountable missing_intent; the plain file_open read is not:\n{timeline}"
    );
    assert!(timeline.contains(
        r#""evidence_ref":"session-intent-executable-correlate:event:0000000000000102""#
    ));
    assert!(
        !timeline.contains(
            r#""evidence_ref":"session-intent-executable-correlate:event:0000000000000101""#
        ),
        "a plain file_open read must not become a missing_intent finding:\n{timeline}"
    );

    let _ = std::fs::remove_file(&intent_input);
    let _ = std::fs::remove_file(&timeline_input);
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

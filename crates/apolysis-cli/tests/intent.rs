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

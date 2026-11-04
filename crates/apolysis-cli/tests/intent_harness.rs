// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn codex_jsonl_ingests_local_shell_and_web_search() {
    let input = temp_jsonl("codex-more");
    let output = temp_jsonl("codex-more-out");
    std::fs::write(
        &input,
        concat!(
            r#"{"type":"response_item","payload":{"type":"local_shell_call","call_id":"call_shell_1","action":{"type":"exec","command":"cargo test"}}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"web_search_call","id":"ws_1","action":{"query":"apolysis intent"}}}"#,
            "\n",
        ),
    )
    .unwrap();
    let status = apolysis_command()
        .args([
            "intent",
            "ingest",
            "--adapter",
            "codex-jsonl",
            "--input",
            input.to_str().unwrap(),
            "--session",
            "s",
            "--output",
            output.to_str().unwrap(),
            "--workspace-root",
            std::env::temp_dir().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_id":"codex:call_shell_1""#));
    assert!(body.contains(r#""declared_action":"shell.command""#));
    assert!(body.contains(r#""intent_id":"codex:ws_1""#));
    assert!(body.contains(r#""tool_name":"web_search""#));
    assert!(body.contains(r#""declared_action":"web.search""#));
    assert!(!body.contains("apolysis intent"));
}

#[test]
fn codex_hook_stamps_shell_command_and_redacts_intent() {
    let output = temp_jsonl("codex-hook-out");
    let root = std::env::temp_dir();
    let mut child = apolysis_command()
        .args([
            "intent",
            "hook",
            "--harness",
            "codex",
            "--output",
            output.to_str().unwrap(),
            "--workspace-root",
            root.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    std::io::Write::write_all(
        &mut std::io::BufWriter::new(stdin),
        br#"{"session_id":"sess","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call_9","tool_input":{"command":"cargo test"}}"#,
    )
    .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let response: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        response["hookSpecificOutput"]["updatedInput"]["command"],
        "APOLYSIS_INTENT_ID=codex:call_9 cargo test"
    );
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_source":"codex""#));
    assert!(body.contains("argv_redacted:true"));
    assert!(!body.contains("cargo test"));
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

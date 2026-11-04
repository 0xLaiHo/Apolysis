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

#[test]
fn claude_jsonl_ingests_tool_use_blocks() {
    let input = temp_jsonl("claude-in");
    let output = temp_jsonl("claude-out");
    std::fs::write(
        &input,
        concat!(
            r#"{"type":"assistant","sessionId":"sess","message":{"content":[{"type":"text","text":"looking"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"cargo test"}},{"type":"tool_use","id":"toolu_2","name":"WebSearch","input":{"query":"secret query"}}]}}"#,
            "\n",
        ),
    )
    .unwrap();
    assert!(ingest("claude-jsonl", &input, &output).success());
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_source":"claude""#));
    assert!(body.contains(r#""intent_id":"claude:toolu_1""#));
    assert!(body.contains(r#""declared_action":"shell.command""#));
    assert!(body.contains(r#""intent_id":"claude:toolu_2""#));
    assert!(body.contains(r#""declared_action":"web.search""#));
    assert!(!body.contains("secret query"));
    assert!(!body.contains("cargo test"));
}

#[test]
fn claude_hook_rewrites_bash_and_leaves_web_search_unchanged() {
    let response = hook_stdout(
        "claude",
        r#"{"session_id":"sess","hook_event_name":"PreToolUse","tool_name":"WebSearch","tool_use_id":"toolu_2","tool_input":{"query":"docs"}}"#,
    );
    assert!(response["hookSpecificOutput"].get("updatedInput").is_none());
    let response = hook_stdout(
        "claude",
        r#"{"session_id":"sess","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"toolu_1","tool_input":{"command":"ls"}}"#,
    );
    assert_eq!(
        response["hookSpecificOutput"]["updatedInput"]["command"],
        "APOLYSIS_INTENT_ID=claude:toolu_1 ls"
    );
}

#[test]
fn cursor_jsonl_ingests_hook_payloads_and_tool_use_blocks() {
    let input = temp_jsonl("cursor-in");
    let output = temp_jsonl("cursor-out");
    std::fs::write(
        &input,
        concat!(
            r#"{"hook_event_name":"preToolUse","conversation_id":"conv","tool_name":"Shell","tool_use_id":"tool-1","tool_input":{"command":"pwd"}}"#,
            "\n",
            r#"{"role":"assistant","content":[{"type":"tool_use","id":"tool-2","name":"WebSearch","input":{"query":"hidden"}}]}"#,
            "\n",
        ),
    )
    .unwrap();
    assert!(ingest("cursor-jsonl", &input, &output).success());
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_id":"cursor:tool-1""#));
    assert!(body.contains(r#""intent_id":"cursor:tool-2""#));
    assert!(body.contains(r#""declared_action":"web.search""#));
    assert!(!body.contains("hidden"));
}

#[test]
fn cursor_pre_tool_use_rewrites_shell_and_shell_event_does_not() {
    let pre = hook_stdout(
        "cursor",
        r#"{"conversation_id":"conv","hook_event_name":"preToolUse","tool_name":"Shell","tool_use_id":"tool-1","tool_input":{"command":"pwd"}}"#,
    );
    assert_eq!(pre["permission"], "allow");
    assert_eq!(
        pre["updated_input"]["command"],
        "APOLYSIS_INTENT_ID=cursor:tool-1 pwd"
    );
    let before = hook_stdout(
        "cursor",
        r#"{"conversation_id":"conv","hook_event_name":"beforeShellExecution","command":"pwd","cwd":"/work","sandbox":false,"tool_use_id":"tool-9"}"#,
    );
    assert_eq!(before, serde_json::json!({"permission": "allow"}));
}

fn ingest(
    adapter: &str,
    input: &std::path::Path,
    output: &std::path::Path,
) -> std::process::ExitStatus {
    apolysis_command()
        .args([
            "intent",
            "ingest",
            "--adapter",
            adapter,
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
        .unwrap()
}

fn hook_stdout(harness: &str, body: &str) -> serde_json::Value {
    let output = temp_jsonl(&format!("hook-{harness}"));
    let mut child = apolysis_command()
        .args([
            "intent",
            "hook",
            "--harness",
            harness,
            "--output",
            output.to_str().unwrap(),
            "--workspace-root",
            std::env::temp_dir().to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        &mut std::io::BufWriter::new(child.stdin.take().unwrap()),
        body.as_bytes(),
    )
    .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
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

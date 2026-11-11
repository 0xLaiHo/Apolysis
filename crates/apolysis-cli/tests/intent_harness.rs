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
    let id = assert_stamped(
        &response["hookSpecificOutput"]["updatedInput"]["command"],
        "cargo test",
    );
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_source":"codex""#));
    assert!(body.contains(&format!(r#""intent_id":"{id}""#)));
    assert!(body.contains(r#""observation_mode":"local_shell""#));
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
    assert_stamped(
        &response["hookSpecificOutput"]["updatedInput"]["command"],
        "ls",
    );
    assert!(response["hookSpecificOutput"]
        .get("permissionDecision")
        .is_none());
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
    assert_stamped(&pre["updated_input"]["command"], "pwd");
    let before = hook_stdout(
        "cursor",
        r#"{"conversation_id":"conv","hook_event_name":"beforeShellExecution","command":"pwd","cwd":"/work","sandbox":false}"#,
    );
    assert_eq!(before, serde_json::json!({"permission": "allow"}));
}

#[test]
fn pi_jsonl_ingests_assistant_tool_calls() {
    let input = temp_jsonl("pi-in");
    let output = temp_jsonl("pi-out");
    std::fs::write(
        &input,
        concat!(
            r#"{"type":"session","version":3,"id":"uuid","timestamp":"2024-12-03T14:00:00.000Z","cwd":"/work"}"#,
            "\n",
            r#"{"type":"message","id":"c3","parentId":"b2","timestamp":"2024-12-03T14:00:03.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call_123","name":"bash","arguments":{"command":"cargo test"}}],"timestamp":1733234403000}}"#,
            "\n",
            r#"{"type":"message","id":"c4","parentId":"c3","timestamp":"2024-12-03T14:00:04.000Z","message":{"role":"toolResult","toolCallId":"call_123","toolName":"bash","content":[{"type":"text","text":"ok"}],"isError":false,"timestamp":1733234404000}}"#,
            "\n",
        ),
    )
    .unwrap();
    assert!(ingest("pi-jsonl", &input, &output).success());
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_source":"pi""#));
    assert!(body.contains(r#""intent_id":"pi:call_123""#));
    assert!(body.contains(r#""tool_name":"bash""#));
    assert_eq!(body.matches(r#""record_type":"intent""#).count(), 1);
    assert!(!body.contains("cargo test"));
}

#[test]
fn pi_hook_stamps_bash_command() {
    let response = hook_stdout(
        "pi",
        r#"{"session_id":"uuid","hook_event_name":"tool_call","tool_name":"bash","tool_use_id":"call_123","tool_input":{"command":"cargo test"}}"#,
    );
    assert_stamped(&response["command"], "cargo test");
}

#[test]
fn opencode_jsonl_ingests_tool_parts_and_skips_text() {
    let input = temp_jsonl("opencode-in");
    let output = temp_jsonl("opencode-out");
    std::fs::write(
        &input,
        concat!(
            r#"{"data":{"role":"assistant","parts":[{"type":"text","text":"secret prompt"},{"type":"tool","tool":"bash","callID":"call-1","state":{"input":{"command":"ls"}}},{"type":"tool","tool":"read","callID":"call-2","state":{"input":{"filePath":"/work/Cargo.toml"}}}]}}"#,
            "\n",
        ),
    )
    .unwrap();
    assert!(ingest("opencode-jsonl", &input, &output).success());
    let body = std::fs::read_to_string(output).unwrap();
    assert!(body.contains(r#""intent_id":"opencode:call-1""#));
    assert!(body.contains(r#""declared_action":"shell.command""#));
    assert!(body.contains(r#""intent_id":"opencode:call-2""#));
    assert!(body.contains(r#""declared_action":"file.read""#));
    assert!(!body.contains("secret prompt"));
    assert!(!body.contains("Cargo.toml"));
}

#[test]
fn opencode_hook_stamps_bash_command() {
    let response = hook_stdout(
        "opencode",
        r#"{"session_id":"ses_1","hook_event_name":"tool.execute.before","tool_name":"bash","tool_use_id":"call-1","tool_input":{"command":"ls"}}"#,
    );
    assert_stamped(&response["command"], "ls");
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
    static NEXT_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let number = NEXT_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{number}.jsonl", std::process::id()))
}

fn assert_stamped(value: &serde_json::Value, original: &str) -> String {
    let text = value.as_str().expect("rewritten command");
    let (header, command) = text.split_once('\n').expect("complete marker line");
    let id = header
        .strip_prefix("# APOLYSIS_INTENT_ID=")
        .expect("comment marker");
    assert_eq!(id.len(), 32);
    assert!(id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(command, original);
    id.to_string()
}

fn run_hook(
    harness: &str,
    body: &serde_json::Value,
    output: &std::path::Path,
    session: Option<&str>,
) -> std::process::Output {
    let mut command = apolysis_command();
    command.args([
        "intent",
        "hook",
        "--harness",
        harness,
        "--output",
        output.to_str().unwrap(),
        "--workspace-root",
        std::env::temp_dir().to_str().unwrap(),
    ]);
    if let Some(session) = session {
        command.args(["--session", session]);
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        &mut child.stdin.take().unwrap(),
        body.to_string().as_bytes(),
    )
    .unwrap();
    child.wait_with_output().unwrap()
}

fn parsed_hook(
    harness: &str,
    body: &serde_json::Value,
    session: Option<&str>,
) -> (serde_json::Value, serde_json::Value) {
    let path = temp_jsonl("hook-shape");
    let result = run_hook(harness, body, &path, session);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let response = serde_json::from_slice(&result.stdout).unwrap();
    let record = serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    std::fs::remove_file(path).unwrap();
    (response, record)
}

#[test]
fn live_identity_is_compact_and_scopes_native_and_capture_sessions() {
    let call_id = format!("parent/{}", "调用\"\n".repeat(80));
    let body = serde_json::json!({
        "session_id": "native-a", "tool_name": "bash", "tool_use_id": call_id,
        "tool_input": {"command": "printf safe"},
    });
    let (response, first) = parsed_hook("pi", &body, Some("capture-a"));
    let id = assert_stamped(&response["command"], "printf safe");
    assert_eq!(first["intent_id"], id);
    assert_eq!(first["session_id"], "capture-a");
    assert_eq!(first["harness_session_id"], "native-a");
    assert_eq!(first["source_event_id"], call_id);
    let (_, same) = parsed_hook("pi", &body, Some("capture-a"));
    let (_, other_capture) = parsed_hook("pi", &body, Some("capture-b"));
    let mut other_body = body.clone();
    other_body["session_id"] = "native-b".into();
    let (_, other_native) = parsed_hook("pi", &other_body, Some("capture-a"));
    let (_, other_source) = parsed_hook("opencode", &body, Some("capture-a"));
    assert_eq!(first["intent_id"], same["intent_id"]);
    assert_ne!(first["intent_id"], other_capture["intent_id"]);
    assert_ne!(first["intent_id"], other_native["intent_id"]);
    assert_ne!(first["intent_id"], other_source["intent_id"]);
}

#[test]
fn rewrites_preserve_all_input_fields_and_respect_each_hook_contract() {
    for (harness, tool, field) in [
        ("claude", "Bash", "command"),
        ("codex", "Bash", "command"),
        ("codex", "exec_command", "cmd"),
        ("codex", "shell_command", "command"),
        ("cursor", "Shell", "command"),
    ] {
        let mut input = serde_json::json!({
            "timeout": 1234, "description": "private description", "run_in_background": true,
            "workdir": "/work", "shell": "/bin/bash", "future_field": {"keep": [1, 2]},
        });
        input[field] = "printf safe".into();
        let body = serde_json::json!({
            "session_id": "native", "hook_event_name": "preToolUse", "tool_name": tool,
            "tool_use_id": "call-1", "tool_input": input,
        });
        let (response, record) = parsed_hook(harness, &body, None);
        let mut updated = if harness == "cursor" {
            response["updated_input"].clone()
        } else {
            response["hookSpecificOutput"]["updatedInput"].clone()
        };
        assert_stamped(&updated[field], "printf safe");
        updated[field] = "printf safe".into();
        assert_eq!(updated, input);
        if harness == "codex" {
            assert_eq!(
                response["hookSpecificOutput"]["permissionDecision"],
                "allow"
            );
        } else {
            assert!(response["hookSpecificOutput"]
                .get("permissionDecision")
                .is_none());
        }
        assert!(!record.to_string().contains("private description"));
        assert_eq!(record["observation_mode"], "local_shell");
    }
}

#[test]
fn unsupported_tools_and_shell_shapes_remain_semantic_only() {
    for (harness, tool, input) in [
        (
            "claude",
            "mcp__remote__exec",
            serde_json::json!({"command": "ls"}),
        ),
        (
            "cursor",
            "MCP:execute",
            serde_json::json!({"command": "ls"}),
        ),
        ("pi", "custom_bash", serde_json::json!({"command": "ls"})),
        ("opencode", "read", serde_json::json!({"path": "/private"})),
        (
            "codex",
            "shell",
            serde_json::json!({"command": ["bash", "-c", "ls"]}),
        ),
        (
            "codex",
            "exec_command",
            serde_json::json!({"cmd": "ls", "shell": "/bin/fish"}),
        ),
    ] {
        let body = serde_json::json!({
            "session_id": "native", "hook_event_name": "preToolUse", "tool_name": tool,
            "tool_use_id": "call-1", "tool_input": input,
        });
        let (response, record) = parsed_hook(harness, &body, None);
        assert_eq!(record["observation_mode"], "semantic_only");
        assert!(response.get("command").is_none());
        assert!(response.get("updated_input").is_none());
        assert!(response["hookSpecificOutput"].get("updatedInput").is_none());
        assert!(response["hookSpecificOutput"]
            .get("permissionDecision")
            .is_none());
    }
}

#[test]
fn cursor_supplemental_shell_event_never_invents_a_call_or_duplicates_a_record() {
    for command in [
        "pwd",
        "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\npwd",
    ] {
        let path = temp_jsonl("cursor-supplemental");
        let result = run_hook(
            "cursor",
            &serde_json::json!({
                "conversation_id": "native", "hook_event_name": "beforeShellExecution",
                "command": command, "cwd": "/work", "sandbox": false,
            }),
            &path,
            None,
        );
        assert!(result.status.success());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap(),
            serde_json::json!({"permission": "allow"})
        );
        assert!(!path.exists() || std::fs::read_to_string(path).unwrap().is_empty());
    }
}

#[test]
fn marker_retries_are_idempotent_and_conflicting_headers_are_rejected() {
    let mut body = serde_json::json!({
        "session_id": "native", "tool_name": "bash", "tool_use_id": "call-1",
        "tool_input": {"command": "printf safe"},
    });
    let (first, _) = parsed_hook("pi", &body, None);
    body["tool_input"]["command"] = first["command"].clone();
    let (second, _) = parsed_hook("pi", &body, None);
    assert_eq!(first, second);
    let shared_output = temp_jsonl("hook-retry-dedup");
    for _ in 0..3 {
        let result = run_hook("pi", &body, &shared_output, None);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(
        std::fs::read_to_string(&shared_output)
            .unwrap()
            .lines()
            .count(),
        1
    );
    std::fs::remove_file(shared_output).unwrap();
    for command in [
        "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef\nprintf safe",
        "# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef",
        "# APOLYSIS_INTENT_ID=not-valid\nprintf safe",
    ] {
        body["tool_input"]["command"] = command.into();
        let result = run_hook("pi", &body, &temp_jsonl("bad-stamp"), None);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("printf safe"));
    }
}

#[test]
fn comment_markers_preserve_supported_shell_command_behavior() {
    let cases = [
        "if true; then printf safe; fi",
        "for x in a b; do printf '%s' \"$x\"; done",
        "{ printf a; printf b; }",
        "(printf nested)",
        "f() { printf function; }; f",
        "cat <<'EOF'\nhello $world\nEOF",
        "printf foo | cat",
        "false",
        "printf '%s|%s|%s|%s\\n' \"$?\" \"$_\" \"$0\" \"$1\"",
    ];
    for shell in ["sh", "bash", "zsh"] {
        if Command::new(shell).args(["-c", "exit 0"]).status().is_err() {
            eprintln!("skipping {shell}: executable unavailable");
            continue;
        }
        for original in cases {
            let (response, _) = parsed_hook(
                "claude",
                &serde_json::json!({
                    "session_id": "native", "tool_name": "Bash", "tool_use_id": "call-1",
                    "tool_input": {"command": original},
                }),
                None,
            );
            let rewritten = response["hookSpecificOutput"]["updatedInput"]["command"]
                .as_str()
                .unwrap();
            let before = Command::new(shell)
                .args(["-c", original, "audit", "arg"])
                .output()
                .unwrap();
            let after = Command::new(shell)
                .args(["-c", rewritten, "audit", "arg"])
                .output()
                .unwrap();
            assert_eq!(
                before.status.code(),
                after.status.code(),
                "{shell}: {original}"
            );
            assert_eq!(before.stdout, after.stdout, "{shell}: {original}");
            assert_eq!(before.stderr, after.stderr, "{shell}: {original}");
        }
    }
}

#[test]
fn failed_persistence_never_returns_a_command_marker() {
    let path = temp_jsonl("intent-unwritable-directory");
    std::fs::create_dir(&path).unwrap();
    let result = run_hook(
        "claude",
        &serde_json::json!({
            "session_id": "native", "tool_name": "Bash", "tool_use_id": "call-1",
            "tool_input": {"command": "printf DO_NOT_LOG_COMMAND"},
        }),
        &path,
        None,
    );
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("DO_NOT_LOG_COMMAND"));
    std::fs::remove_dir(path).unwrap();
}

#[test]
fn missing_call_identity_never_creates_a_shared_placeholder_or_marker() {
    for harness in ["codex", "claude", "pi", "opencode"] {
        let path = temp_jsonl("intent-missing-call");
        let result = run_hook(
            harness,
            &serde_json::json!({
                "session_id": "native", "tool_name": "Bash",
                "tool_input": {"command": "printf DO_NOT_LOG_COMMAND"},
            }),
            &path,
            None,
        );
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!path.exists());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("DO_NOT_LOG_COMMAND"));
    }
}

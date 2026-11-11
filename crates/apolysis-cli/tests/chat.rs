// SPDX-License-Identifier: Apache-2.0

//! Public CLI contracts only. No authentication, provider, sudo, or live BPF.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

fn invoke(directory: &Path, args: &[&str], input: &[u8]) -> Output {
    // A blank PATH and environment also catch accidental dependence on a
    // Python executable discovered through PATH, without reading real auth.
    let mut child = Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .args(args)
        .current_dir(directory)
        .env_clear()
        .env("PATH", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn hook(directory: &Path, input: &Value) -> Output {
    let evidence = directory.join("evidence");
    invoke(
        directory,
        &[
            "chat",
            "hook",
            "--workspace-root",
            directory.to_str().unwrap(),
            "--evidence-dir",
            evidence.to_str().unwrap(),
            "--session",
            "capture-test",
        ],
        &serde_json::to_vec(input).unwrap(),
    )
}

fn one_record(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap();
    assert!(text.ends_with('\n'));
    assert_eq!(text.lines().count(), 1);
    serde_json::from_str(&text).unwrap()
}

#[test]
fn chat_help_needs_no_sudo_provider_or_python_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let output = invoke(directory.path(), &["chat", "--help"], b"");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("apolysis chat"));
    assert!(help.contains("No Python runtime is used"));
    assert!(help.contains("/exit or EOF"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn invalid_chat_and_hook_options_fail_before_starting_a_session() {
    let directory = tempfile::tempdir().unwrap();
    for args in [
        vec!["chat", "--unknown-private-option"],
        vec!["chat", "--turn-timeout", "0"],
        vec!["chat", "--turn-timeout"],
        vec!["chat", "--smoke", "--smoke"],
        vec!["chat", "hook"],
        vec!["chat", "hook", "--private-option", "DO_NOT_LOG"],
    ] {
        let output = invoke(directory.path(), &args, b"");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_LOG"));
    }
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn chat_hook_uses_native_stdout_and_stores_only_bound_redacted_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let summary = "验证登录修复是否通过回归检查。";
    let mut input = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "session_id": "native-session",
        "tool_use_id": "native-call",
        "prompt": "DO_NOT_LOG_PROMPT",
        "tool_result": "DO_NOT_LOG_RESULT",
        "transcript_path": "DO_NOT_LOG_TRANSCRIPT",
        "tool_input": {
            "command": "printf '%s' 'DO_NOT_LOG_COMMAND'",
            "description": format!("APOLYSIS_REASON_JSON={}", json!({"reason_code":"verify_change","reason_summary":summary})),
            "timeout": 7,
            "future_argument": "DO_NOT_LOG_ARGUMENT",
        },
    });
    let output = hook(directory.path(), &input);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["hookSpecificOutput"]["hookEventName"],
        "PreToolUse"
    );
    assert!(response["hookSpecificOutput"]
        .get("permissionDecision")
        .is_none());
    let updated = &response["hookSpecificOutput"]["updatedInput"];
    assert_eq!(updated["timeout"], 7);
    assert_eq!(updated["description"], input["tool_input"]["description"]);
    assert_eq!(
        updated["future_argument"],
        input["tool_input"]["future_argument"]
    );
    assert!(updated["command"]
        .as_str()
        .unwrap()
        .starts_with("/bin/bash -c '# APOLYSIS_INTENT_ID="));
    assert!(response.get("prompt").is_none());
    assert!(response.get("tool_result").is_none());

    let evidence = directory.path().join("evidence");
    let intent_path = evidence.join("intent.jsonl");
    let reason_path = evidence.join("intent.jsonl.reasons.jsonl");
    let intent = one_record(&intent_path);
    let reason = one_record(&reason_path);
    assert_eq!(intent["session_id"], "capture-test");
    assert_eq!(intent["observation_mode"], "local_shell");
    for key in [
        "session_id",
        "intent_id",
        "intent_source",
        "harness_session_id",
        "source_event_id",
    ] {
        assert_eq!(reason[key], intent[key]);
    }
    assert_eq!(reason["harness_session_id"], "native-session");
    assert_eq!(reason["source_event_id"], "native-call");
    assert_eq!(reason["reason_source"], "agent_declared");
    assert_eq!(reason["reason_code"], "verify_change");
    assert_eq!(reason["reason_summary"], summary);
    let intent_before = fs::read(&intent_path).unwrap();
    let reason_before = fs::read(&reason_path).unwrap();
    for bytes in [&intent_before, &reason_before] {
        assert!(!String::from_utf8_lossy(bytes).contains("DO_NOT_LOG"));
        assert!(!String::from_utf8_lossy(bytes).contains("APOLYSIS_REASON_JSON="));
    }
    // A normal description cannot be promoted to an explicit declaration. The
    // public hook protocol returns deny with status 0 and leaves evidence alone.
    input["tool_input"]["description"] = "DO_NOT_LOG ordinary description".into();
    let rejected = hook(directory.path(), &input);
    assert!(rejected.status.success());
    let denied: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(denied["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(denied["hookSpecificOutput"].get("updatedInput").is_none());
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("DO_NOT_LOG"));
    assert_eq!(fs::read(&intent_path).unwrap(), intent_before);
    assert_eq!(fs::read(&reason_path).unwrap(), reason_before);
}

#[test]
fn unprivileged_chat_publish_replaces_symlink_without_touching_its_target() {
    // SAFETY: identity queries take no pointers and do not change credentials.
    if unsafe {
        libc::getuid() == 0 || libc::geteuid() == 0 || libc::getgid() == 0 || libc::getegid() == 0
    } {
        eprintln!(
            "SKIP: chat publish requires a non-root user and group; no sudo is used in this test"
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let victim = directory.path().join("unrelated.txt");
    let destination = directory.path().join("result.json");
    fs::write(&victim, b"keep unrelated contents").unwrap();
    symlink(&victim, &destination).unwrap();
    let body = "新证据\0exact bytes\n".as_bytes();
    let output = invoke(
        directory.path(),
        &["chat", "publish", destination.to_str().unwrap()],
        body,
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(!fs::symlink_metadata(&destination)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&destination).unwrap(), body);
    assert_eq!(fs::read(&victim).unwrap(), b"keep unrelated contents");
    let metadata = fs::metadata(&destination).unwrap();
    // SAFETY: the same read-only identity query as the guard above.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

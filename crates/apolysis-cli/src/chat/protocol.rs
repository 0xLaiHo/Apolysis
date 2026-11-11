// SPDX-License-Identifier: Apache-2.0

//! Native chat messages and the explicit, bounded Claude reason carrier.
//! Prompts, thinking blocks, tool results, and raw hook payloads are not stored.

use std::io::{Read, Write};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};

const MAX_HOOK_BYTES: usize = 1024 * 1024;
const REASON_PREFIX: &str = "APOLYSIS_REASON_JSON=";
const DENIAL_REASON: &str = "This chat requires a valid APOLYSIS_REASON_JSON declaration in Bash.description and durable intent recording before execution.";

pub(super) fn user_message(prompt: &str) -> Value {
    json!({
        "type": "user",
        "message": { "role": "user", "content": prompt },
        "parent_tool_use_id": null,
        "session_id": "default",
        "client_composed": true,
    })
}

pub(super) fn assistant_text(value: &Value) -> Vec<&str> {
    if value.get("type").and_then(Value::as_str) != Some("assistant") {
        return Vec::new();
    }
    value
        .pointer("/message/content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect()
}

pub(super) fn turn_succeeded(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("result")
        && value.get("subtype").and_then(Value::as_str) == Some("success")
        && value
            .get("is_error")
            .is_none_or(|error| error.as_bool() == Some(false))
}

pub(super) fn hook(args: &[String]) -> Result<i32, String> {
    let request = HookRequest::parse(args)?;
    respond(&request, std::io::stdin().lock(), std::io::stdout().lock())
}

#[derive(Debug, PartialEq)]
struct HookRequest {
    workspace: PathBuf,
    evidence: PathBuf,
    session: String,
}

impl HookRequest {
    fn parse(args: &[String]) -> Result<Self, String> {
        let (mut workspace, mut evidence, mut session) = (None, None, None);
        let mut options = args.iter();
        while let Some(option) = options.next() {
            let target = match option.as_str() {
                "--workspace-root" => &mut workspace,
                "--evidence-dir" => &mut evidence,
                "--session" => &mut session,
                _ => return Err("unsupported chat hook option".to_string()),
            };
            if target.is_some() {
                return Err("duplicate chat hook option".to_string());
            }
            let value = options
                .next()
                .filter(|value| !value.is_empty() && !value.starts_with("--"))
                .ok_or("chat hook option requires a value")?;
            *target = Some(value.clone());
        }
        Ok(Self {
            workspace: workspace
                .ok_or("chat hook requires --workspace-root")?
                .into(),
            evidence: evidence.ok_or("chat hook requires --evidence-dir")?.into(),
            session: session.ok_or("chat hook requires --session")?,
        })
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Declaration {
    reason_code: String,
    reason_summary: String,
}

fn parse_declaration(description: &str) -> Result<Declaration, String> {
    if description.chars().count() > 2048 {
        return Err("reason declaration is too long".to_string());
    }
    let document = description
        .strip_prefix(REASON_PREFIX)
        .ok_or("explicit reason declaration required")?;
    // Deriving the two-field object also rejects duplicate fields. JSON parsing
    // rejects nonstandard constants and invalid surrogate escapes without echo.
    let declaration: Declaration = serde_json::from_str(document)
        .map_err(|_| "invalid reason declaration JSON".to_string())?;
    if !matches!(
        declaration.reason_code.as_str(),
        "unknown"
            | "inspect_context"
            | "verify_change"
            | "reproduce_issue"
            | "implement_change"
            | "diagnose_failure"
            | "gather_evidence"
    ) {
        return Err("invalid reason declaration code".to_string());
    }
    let summary = &declaration.reason_summary;
    if !(1..=240).contains(&summary.chars().count())
        || summary.trim().is_empty()
        || summary
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err("invalid reason declaration summary".to_string());
    }
    Ok(declaration)
}

fn denial() -> Value {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": DENIAL_REASON,
    }})
}

fn respond(
    request: &HookRequest,
    reader: impl Read,
    mut writer: impl Write,
) -> Result<i32, String> {
    let response = accept(request, reader).unwrap_or_else(|_| denial());
    serde_json::to_writer(&mut writer, &response)
        .map_err(|_| "failed to write chat hook response".to_string())?;
    writer
        .write_all(b"\n")
        .map_err(|_| "failed to write chat hook response".to_string())?;
    Ok(0)
}

fn accept(request: &HookRequest, reader: impl Read) -> Result<Value, String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_HOOK_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "failed to read chat hook input".to_string())?;
    if bytes.len() > MAX_HOOK_BYTES {
        return Err("chat hook input is too large".to_string());
    }
    let mut input: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid chat hook input".to_string())?;
    if input.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse")
        || input.get("tool_name").and_then(Value::as_str) != Some("Bash")
        || !input
            .pointer("/tool_input/command")
            .and_then(Value::as_str)
            .is_some_and(|command| !command.trim().is_empty())
        || !["session_id", "tool_use_id"].iter().all(|field| {
            input
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
        })
    {
        return Err("chat hook requires a native Bash call identity".to_string());
    }
    let description = input
        .pointer("/tool_input/description")
        .and_then(Value::as_str)
        .ok_or("explicit reason declaration required")?;
    let declaration = parse_declaration(description)?;
    input["apolysis_reason"] = json!({
        "reason_code": declaration.reason_code,
        "reason_summary": declaration.reason_summary,
    });
    let output = crate::intent::hook_with_shell_bridge(
        "claude",
        &input,
        &request.workspace,
        Some(&request.session),
        Some("/bin/bash"),
    )?;
    let record = output.record.ok_or("native Bash declaration is missing")?;
    let reason = crate::intent::reason::collect(&input, &record, true)?
        .ok_or("explicit reason declaration is missing")?;
    let intent_path = request.evidence.join("intent.jsonl");
    let reason_path = request.evidence.join("intent.jsonl.reasons.jsonl");
    crate::distinct_output_paths(
        &intent_path.to_string_lossy(),
        &reason_path.to_string_lossy(),
    )?;
    apolysis_store::append_intent(&intent_path, &record)
        .map_err(|_| "chat intent recording failed".to_string())?;
    apolysis_store::append_intent_reason(&reason_path, &reason)
        .map_err(|_| "chat reason recording failed".to_string())?;
    Ok(output.response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn description(code: Value, summary: Value) -> String {
        format!(
            "{REASON_PREFIX}{}",
            json!({"reason_code":code,"reason_summary":summary})
        )
    }

    fn request(root: &std::path::Path) -> HookRequest {
        HookRequest {
            workspace: root.into(),
            evidence: root.join("evidence"),
            session: "capture".into(),
        }
    }

    fn payload() -> Value {
        json!({"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"native",
            "tool_use_id":"call","prompt":"DO_NOT_LOG_PROMPT","tool_result":"DO_NOT_LOG_RESULT",
            "tool_input":{"command":"printf safe","timeout":7,"description":description(json!("verify_change"),json!("验证登录修复是否通过回归检查。"))}})
    }

    fn run(request: &HookRequest, input: &[u8]) -> Value {
        let mut stdout = Vec::new();
        assert_eq!(
            respond(request, Cursor::new(input), &mut stdout).unwrap(),
            0
        );
        serde_json::from_slice(&stdout).unwrap()
    }

    #[test]
    fn user_messages_preserve_the_entire_original_text() {
        for prompt in [
            "你好",
            "  保留空格。  ",
            "第一行\n第二行\t内容",
            "引号 \" \\ ' 😀",
            "APOLYSIS_REASON_JSON= ordinary text",
            "",
        ] {
            assert_eq!(
                user_message(prompt),
                json!({"type":"user","message":{"role":"user","content":prompt},"parent_tool_use_id":null,"session_id":"default","client_composed":true})
            );
        }
    }

    #[test]
    fn assistant_display_only_returns_text_blocks() {
        let value = json!({"type":"assistant","message":{"content":[
            {"type":"thinking","text":"DO_NOT_LOG"},
            {"type":"redacted_thinking","data":"DO_NOT_LOG"},
            {"type":"tool_use","text":"DO_NOT_LOG","input":{"command":"DO_NOT_LOG"}},
            {"type":"tool_result","text":"DO_NOT_LOG"},
            {"type":"text","text":"答复。"},{"type":"text","text":7},
            {"type":"text","text":"第二段。"},null,"DO_NOT_LOG"]}});
        assert_eq!(assistant_text(&value), ["答复。", "第二段。"]);
        for invalid in [
            Value::Null,
            json!([]),
            json!({"type":"result","result":"DO_NOT_LOG"}),
            json!({"type":"assistant","message":null}),
            json!({"type":"assistant","message":[]}),
            json!({"type":"assistant","message":{"content":null}}),
            json!({"type":"assistant","message":{"content":"DO_NOT_LOG"}}),
        ] {
            assert!(assistant_text(&invalid).is_empty());
        }
    }

    #[test]
    fn only_a_successful_native_result_completes_a_turn() {
        assert!(turn_succeeded(
            &json!({"type":"result","subtype":"success"})
        ));
        assert!(turn_succeeded(
            &json!({"type":"result","subtype":"success","is_error":false})
        ));
        for value in [
            Value::Null,
            json!({}),
            json!({"type":"assistant","subtype":"success"}),
            json!({"type":"result","subtype":"error"}),
            json!({"type":"result","subtype":"success","is_error":true}),
            json!({"type":"result","subtype":"success","is_error":null}),
            json!({"type":"result","subtype":"success","is_error":"false"}),
        ] {
            assert!(!turn_succeeded(&value));
        }
    }

    #[test]
    fn declaration_requires_exact_fields_without_duplicate_keys() {
        for input in ["Run tests", "验证修复。", "", " APOLYSIS_REASON_JSON={}",
            "APOLYSIS_REASON_JSON=[]", "APOLYSIS_REASON_JSON=null",
            "APOLYSIS_REASON_JSON={\"reason_code\":\"verify_change\"}",
            "APOLYSIS_REASON_JSON={\"reason_summary\":\"DO_NOT_LOG\"}",
            "APOLYSIS_REASON_JSON={\"reason_code\":\"unknown\",\"reason_code\":\"verify_change\",\"reason_summary\":\"DO_NOT_LOG\"}",
            "APOLYSIS_REASON_JSON={\"reason_code\":\"unknown\",\"reason_summary\":\"a\",\"reason_summary\":\"DO_NOT_LOG\"}",
            "APOLYSIS_REASON_JSON={\"reason_code\":\"unknown\",\"reason_summary\":\"DO_NOT_LOG\",\"reason_source\":\"agent_declared\"}",
            "APOLYSIS_REASON_JSON={\"reason_code\":NaN,\"reason_summary\":\"DO_NOT_LOG\"}",
            "APOLYSIS_REASON_JSON={\"reason_code\":\"unknown\",\"reason_summary\":\"\\ud800\"}",
            "APOLYSIS_REASON_JSON={DO_NOT_LOG}"] {
            assert!(!parse_declaration(input).unwrap_err().contains("DO_NOT_LOG"));
        }
    }

    #[test]
    fn declaration_validates_codes_and_unmodified_unicode_summary_bounds() {
        for code in [
            "unknown",
            "inspect_context",
            "verify_change",
            "reproduce_issue",
            "implement_change",
            "diagnose_failure",
            "gather_evidence",
        ] {
            for summary in [
                "验".to_string(),
                "验".repeat(240),
                "  检查  登录修复。  ".to_string(),
                "e\u{301} 与 é 保持原文。".to_string(),
            ] {
                let declared =
                    parse_declaration(&description(json!(code), json!(summary))).unwrap();
                assert_eq!(declared.reason_code, code);
                assert_eq!(declared.reason_summary, summary);
            }
        }
        for code in [
            Value::Null,
            json!(1),
            json!(true),
            json!([]),
            json!({}),
            json!(""),
            json!("VERIFY_CHANGE"),
            json!(" verify_change"),
            json!("DO_NOT_LOG"),
        ] {
            assert!(parse_declaration(&description(code, json!("验证修复"))).is_err());
        }
        for summary in [
            Value::Null,
            json!(1),
            json!(true),
            json!([]),
            json!({}),
            json!(""),
            json!("   "),
            json!("验".repeat(241)),
            json!(format!("{}验", " ".repeat(240))),
            json!("DO_NOT_LOG\nnext"),
            json!("DO_NOT_LOG\rnext"),
            json!("DO_NOT_LOG\tnext"),
            json!("DO_NOT_LOG\0next"),
            json!("DO_NOT_LOG\u{85}next"),
            json!("DO_NOT_LOG\u{2028}next"),
            json!("DO_NOT_LOG\u{2029}next"),
        ] {
            assert!(!parse_declaration(&description(json!("unknown"), summary))
                .unwrap_err()
                .contains("DO_NOT_LOG"));
        }
        assert!(parse_declaration(&format!("{REASON_PREFIX}{}", "[".repeat(2048))).is_err());
    }

    #[test]
    fn hook_flags_are_required_bounded_to_known_options_and_never_echoed() {
        let args = [
            "--workspace-root",
            "/tmp/work",
            "--evidence-dir",
            "/tmp/evidence",
            "--session",
            "capture",
        ]
        .map(String::from);
        assert_eq!(
            HookRequest::parse(&args).unwrap(),
            HookRequest {
                workspace: "/tmp/work".into(),
                evidence: "/tmp/evidence".into(),
                session: "capture".into()
            }
        );
        for args in [
            vec![],
            vec!["--workspace-root"],
            vec!["--workspace-root", "--evidence-dir"],
            vec!["--session", ""],
            vec!["--session", "one", "--session", "two"],
            vec!["DO_NOT_LOG"],
        ] {
            let error = HookRequest::parse(&args.into_iter().map(String::from).collect::<Vec<_>>())
                .unwrap_err();
            assert!(!error.contains("DO_NOT_LOG"));
        }
    }

    #[test]
    fn invalid_or_oversized_input_returns_static_deny_without_persistence() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        for bytes in [
            b"DO_NOT_LOG".to_vec(),
            vec![b'x'; MAX_HOOK_BYTES + 1],
            b"null".to_vec(),
        ] {
            assert_eq!(run(&request, &bytes), denial());
        }
        for pointer in [
            "/session_id",
            "/tool_use_id",
            "/tool_input/command",
            "/tool_input/description",
        ] {
            let mut input = payload();
            *input.pointer_mut(pointer).unwrap() = json!("");
            assert_eq!(
                run(&request, &serde_json::to_vec(&input).unwrap()),
                denial()
            );
        }
        for (field, value) in [
            ("tool_name", "mcp_remote_exec"),
            ("hook_event_name", "PostToolUse"),
        ] {
            let mut input = payload();
            input[field] = value.into();
            assert_eq!(
                run(&request, &serde_json::to_vec(&input).unwrap()),
                denial()
            );
        }
        assert!(!request.evidence.exists());
    }

    #[test]
    fn accepted_hook_persists_reason_before_rewrite_and_retries_without_duplication() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let mut input = payload();
        let first = run(&request, &serde_json::to_vec(&input).unwrap());
        assert!(first
            .pointer("/hookSpecificOutput/permissionDecision")
            .is_none());
        assert_eq!(
            first.pointer("/hookSpecificOutput/updatedInput/timeout"),
            Some(&json!(7))
        );
        let command = first
            .pointer("/hookSpecificOutput/updatedInput/command")
            .unwrap()
            .clone();
        assert!(command
            .as_str()
            .unwrap()
            .starts_with("/bin/bash -c '# APOLYSIS_INTENT_ID="));
        input["tool_input"]["command"] = command;
        assert_eq!(run(&request, &serde_json::to_vec(&input).unwrap()), first);
        let intent = std::fs::read_to_string(request.evidence.join("intent.jsonl")).unwrap();
        let reason =
            std::fs::read_to_string(request.evidence.join("intent.jsonl.reasons.jsonl")).unwrap();
        assert_eq!(intent.lines().count(), 1);
        assert_eq!(reason.lines().count(), 1);
        assert!(!intent.contains("DO_NOT_LOG"));
        assert!(!reason.contains("DO_NOT_LOG"));
        let intent: Value = serde_json::from_str(intent.trim()).unwrap();
        let reason: Value = serde_json::from_str(reason.trim()).unwrap();
        assert_eq!(reason["intent_id"], intent["intent_id"]);
        assert_eq!(reason["reason_source"], "agent_declared");
        assert_eq!(reason["reason_summary"], "验证登录修复是否通过回归检查。");
        assert_eq!(reason["harness_session_id"], "native");
        assert_eq!(reason["source_event_id"], "call");
        input["tool_use_id"] = "different-call".into();
        assert_eq!(
            run(&request, &serde_json::to_vec(&input).unwrap()),
            denial()
        );
    }

    #[test]
    fn storage_failure_never_returns_an_execution_marker_and_retry_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let request = request(directory.path());
        let reason_path = request.evidence.join("intent.jsonl.reasons.jsonl");
        std::fs::create_dir_all(&reason_path).unwrap();
        let bytes = serde_json::to_vec(&payload()).unwrap();
        assert_eq!(run(&request, &bytes), denial());
        std::fs::remove_dir(&reason_path).unwrap();
        assert_ne!(run(&request, &bytes), denial());
        assert_eq!(
            std::fs::read_to_string(request.evidence.join("intent.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(reason_path)
                .unwrap()
                .lines()
                .count(),
            1
        );
    }
}

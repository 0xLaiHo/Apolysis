// SPDX-License-Identifier: Apache-2.0

mod claude;
mod codex;
mod cursor;
mod pi;

use std::path::Path;

use apolysis_core::SessionIntentRecord;

pub fn declared_action(tool_name: &str) -> &'static str {
    let normalized = tool_name.to_ascii_lowercase();
    if normalized.contains("web_search") || normalized.contains("websearch") {
        "web.search"
    } else if normalized.contains("exec")
        || normalized.contains("shell")
        || normalized.contains("bash")
        || normalized.contains("command")
    {
        "shell.command"
    } else if normalized.contains("read")
        || normalized.contains("grep")
        || normalized.contains("glob")
    {
        "file.read"
    } else if normalized.contains("edit")
        || normalized.contains("write")
        || normalized.contains("patch")
    {
        "file.write"
    } else if normalized.starts_with("mcp") {
        "mcp.tool"
    } else {
        "tool.call"
    }
}

pub fn ingest(
    adapter: &str,
    input: &str,
    session_id: &str,
    workspace_root: Option<&Path>,
) -> Result<Vec<SessionIntentRecord>, String> {
    match adapter {
        "codex-jsonl" => codex::records(input, session_id, workspace_root),
        "claude-jsonl" => claude::records(input, session_id, workspace_root),
        "cursor-jsonl" => cursor::records(input, session_id, workspace_root),
        "pi-jsonl" => pi::records(input, session_id, workspace_root),
        other => Err(format!("unsupported intent adapter '{other}'")),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HookOutput {
    pub record: SessionIntentRecord,
    pub response: serde_json::Value,
}

pub fn hook(
    harness: &str,
    input: &serde_json::Value,
    workspace_root: &Path,
) -> Result<HookOutput, String> {
    match harness {
        "codex" => pre_tool_use_hook("codex", input, workspace_root),
        "claude" => pre_tool_use_hook("claude", input, workspace_root),
        "cursor" => cursor_hook(input, workspace_root),
        "pi" => command_stamp_hook("pi", input, workspace_root),
        other => Err(format!("unsupported intent hook harness '{other}'")),
    }
}

fn pre_tool_use_hook(
    source: &str,
    input: &serde_json::Value,
    workspace_root: &Path,
) -> Result<HookOutput, String> {
    let session_id = required_str(input, "session_id")?;
    let tool_name = required_str(input, "tool_name")?;
    let call_id = required_str(input, "tool_use_id")?;
    let intent_id = format!("{source}:{call_id}");
    validate_stamp(&intent_id)?;
    let command = input
        .pointer("/tool_input/command")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let record = stamped_record(
        session_id,
        source,
        &intent_id,
        call_id,
        tool_name,
        command.as_deref(),
        workspace_root,
    )?;
    let mut response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow"
        }
    });
    if declared_action(tool_name) == "shell.command" {
        let original =
            command.ok_or(format!("{source} shell hook is missing tool_input.command"))?;
        response["hookSpecificOutput"]["updatedInput"] =
            serde_json::json!({ "command": format!("APOLYSIS_INTENT_ID={intent_id} {original}") });
    }
    Ok(HookOutput { record, response })
}

fn command_stamp_hook(
    source: &str,
    input: &serde_json::Value,
    workspace_root: &Path,
) -> Result<HookOutput, String> {
    let session_id = required_str(input, "session_id")?;
    let tool_name = required_str(input, "tool_name")?;
    let call_id = required_str(input, "tool_use_id")?;
    let intent_id = format!("{source}:{call_id}");
    validate_stamp(&intent_id)?;
    let command = input
        .pointer("/tool_input/command")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let record = stamped_record(
        session_id,
        source,
        &intent_id,
        call_id,
        tool_name,
        command.as_deref(),
        workspace_root,
    )?;
    let response = if declared_action(tool_name) == "shell.command" {
        let original =
            command.ok_or(format!("{source} shell hook is missing tool_input.command"))?;
        serde_json::json!({ "command": format!("APOLYSIS_INTENT_ID={intent_id} {original}") })
    } else {
        serde_json::json!({})
    };
    Ok(HookOutput { record, response })
}

fn cursor_hook(input: &serde_json::Value, workspace_root: &Path) -> Result<HookOutput, String> {
    let session_id =
        required_str(input, "session_id").or_else(|_| required_str(input, "conversation_id"))?;
    let event_name = required_str(input, "hook_event_name")?;
    let call_id = required_str(input, "tool_use_id")?;
    let tool_name = required_str(input, "tool_name")
        .or_else(|_| {
            if event_name == "beforeShellExecution" {
                Ok("Shell")
            } else {
                Err("hook input missing tool_name".to_string())
            }
        })?
        .to_string();
    let intent_id = format!("cursor:{call_id}");
    validate_stamp(&intent_id)?;
    let command = input
        .pointer("/tool_input/command")
        .and_then(serde_json::Value::as_str)
        .or_else(|| input.get("command").and_then(serde_json::Value::as_str))
        .map(str::to_string);
    let record = stamped_record(
        session_id,
        "cursor",
        &intent_id,
        call_id,
        &tool_name,
        command.as_deref(),
        workspace_root,
    )?;
    let mut response = serde_json::json!({ "permission": "allow" });
    if event_name == "preToolUse" && declared_action(&tool_name) == "shell.command" {
        let original = command.ok_or("cursor shell hook is missing tool_input.command")?;
        response["updated_input"] =
            serde_json::json!({ "command": format!("APOLYSIS_INTENT_ID={intent_id} {original}") });
    }
    Ok(HookOutput { record, response })
}

fn required_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("hook input missing {field}"))
}

fn validate_stamp(intent_id: &str) -> Result<(), String> {
    let valid = !intent_id.is_empty()
        && intent_id.len() <= 128
        && intent_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '-' | '.'));
    if valid {
        Ok(())
    } else {
        Err(format!("intent id {intent_id} cannot be stamped"))
    }
}

pub(crate) fn stamped_record(
    session_id: &str,
    source: &str,
    intent_id: &str,
    source_event_id: &str,
    tool_name: &str,
    command: Option<&str>,
    workspace_root: &Path,
) -> Result<SessionIntentRecord, String> {
    let mut record =
        SessionIntentRecord::new(session_id, source, intent_id, "tool_call", tool_name)
            .with_source_event_id(source_event_id)
            .with_declared_action(declared_action(tool_name));
    if let Some(command) = command {
        record = record.with_command(
            apolysis_observer::redact_command_text_for_persistence(
                session_id,
                workspace_root,
                command,
            )
            .value,
        );
        record = record.with_target("workspace");
    }
    Ok(record)
}

// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use apolysis_core::SessionIntentRecord;
use apolysis_observer::redact_command_text_for_persistence;

pub(crate) fn records(
    input: &str,
    session_id: &str,
    workspace_root: Option<&Path>,
) -> Result<Vec<SessionIntentRecord>, String> {
    let workspace_root = match workspace_root {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|error| format!("failed to resolve current workspace root: {error}"))?,
    };
    let mut records = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = serde_json::from_str::<serde_json::Value>(line).map_err(|error| {
            format!(
                "failed to parse codex-jsonl intent line {}: {error}",
                index + 1
            )
        })?;
        let Some(tool_call) = codex_tool_call(&value, index + 1) else {
            continue;
        };
        let command = tool_call.command.map(|command| {
            redact_command_text_for_persistence(session_id, &workspace_root, &command).value
        });
        let mut record = SessionIntentRecord::new(
            session_id,
            "codex",
            tool_call.intent_id,
            "tool_call",
            tool_call.tool_name.clone(),
        )
        .with_declared_action(super::declared_action(&tool_call.tool_name));

        if let Some(source_event_id) = tool_call.source_event_id {
            record = record.with_source_event_id(source_event_id);
        }
        if let Some(target) = tool_call.target {
            record = record.with_target(target);
        }
        if let Some(command) = command {
            record = record.with_command(command);
        }
        records.push(record);
    }

    Ok(records)
}

#[derive(Debug, Eq, PartialEq)]
struct CodexToolCall {
    intent_id: String,
    source_event_id: Option<String>,
    tool_name: String,
    target: Option<String>,
    command: Option<String>,
}

fn codex_tool_call(value: &serde_json::Value, line_number: usize) -> Option<CodexToolCall> {
    let payload = value
        .get("payload")
        .or_else(|| value.get("item"))
        .unwrap_or(value);
    let item_type = payload
        .get("type")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("type").and_then(serde_json::Value::as_str))?;
    match item_type {
        "local_shell_call" => return local_shell_call(payload, line_number),
        "web_search_call" => return web_search_call(payload, line_number),
        "function_call" | "tool_call" => {}
        _ => return None,
    }

    let tool_name = payload
        .get("name")
        .or_else(|| payload.get("tool_name"))
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let source_event_id = payload
        .get("id")
        .or_else(|| payload.get("call_id"))
        .or_else(|| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let intent_id = source_event_id
        .as_ref()
        .map(|id| format!("codex:{id}"))
        .unwrap_or_else(|| format!("codex:line:{line_number}"));
    let arguments = payload.get("arguments").or_else(|| payload.get("args"));
    let command = arguments.and_then(command_from_arguments);

    Some(CodexToolCall {
        intent_id,
        source_event_id,
        tool_name,
        target: command.as_ref().map(|_| "workspace".to_string()),
        command,
    })
}

fn local_shell_call(payload: &serde_json::Value, line_number: usize) -> Option<CodexToolCall> {
    let (intent_id, source_event_id) = codex_ids(payload, line_number, &["call_id", "id"]);
    let command = payload
        .get("action")
        .and_then(|action| action.get("command"))
        .and_then(command_text);
    Some(CodexToolCall {
        intent_id,
        source_event_id,
        tool_name: "local_shell".to_string(),
        target: command.as_ref().map(|_| "workspace".to_string()),
        command,
    })
}

fn web_search_call(payload: &serde_json::Value, line_number: usize) -> Option<CodexToolCall> {
    let (intent_id, source_event_id) = codex_ids(payload, line_number, &["id", "call_id"]);
    Some(CodexToolCall {
        intent_id,
        source_event_id,
        tool_name: "web_search".to_string(),
        target: None,
        command: None,
    })
}

fn codex_ids(
    payload: &serde_json::Value,
    line_number: usize,
    keys: &[&str],
) -> (String, Option<String>) {
    let source_event_id = keys.iter().find_map(|key| {
        payload
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
    });
    let intent_id = source_event_id
        .as_ref()
        .map(|id| format!("codex:{id}"))
        .unwrap_or_else(|| format!("codex:line:{line_number}"));
    (intent_id, source_event_id)
}

fn command_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(command) => Some(command.clone()),
        serde_json::Value::Array(parts) => {
            let parts: Vec<&str> = parts.iter().filter_map(serde_json::Value::as_str).collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

fn command_from_arguments(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) => serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|parsed| command_from_arguments(&parsed))
            .or_else(|| Some(raw.clone())),
        serde_json::Value::Object(map) => ["cmd", "command", "command_line", "shell"]
            .iter()
            .find_map(|key| {
                map.get(*key)
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                serde_json::to_string(value)
                    .ok()
                    .filter(|serialized| serialized != "{}")
            }),
        _ => None,
    }
}

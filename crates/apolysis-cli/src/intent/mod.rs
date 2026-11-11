// SPDX-License-Identifier: Apache-2.0

mod claude;
mod codex;
mod cursor;
mod opencode;
mod pi;
pub mod reason;
pub mod reason_binding;
mod shell_bridge;

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
        "opencode-jsonl" => opencode::records(input, session_id, workspace_root),
        other => Err(format!("unsupported intent adapter '{other}'")),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HookOutput {
    pub record: Option<SessionIntentRecord>,
    pub response: serde_json::Value,
    pub diagnostic: Option<&'static str>,
}

const STAMP_PREFIX: &str = "# APOLYSIS_INTENT_ID=";

pub fn hook(
    harness: &str,
    input: &serde_json::Value,
    workspace_root: &Path,
    capture_session: Option<&str>,
) -> Result<HookOutput, String> {
    hook_with_shell_bridge(harness, input, workspace_root, capture_session, None)
}

pub fn hook_with_shell_bridge(
    harness: &str,
    input: &serde_json::Value,
    workspace_root: &Path,
    capture_session: Option<&str>,
    bridge_shell: Option<&str>,
) -> Result<HookOutput, String> {
    if let Some(shell) = bridge_shell {
        shell_bridge::validate(shell)?;
    }
    if !matches!(harness, "codex" | "claude" | "cursor" | "pi" | "opencode") {
        return Err("unsupported intent hook harness".to_string());
    }
    if matches!(
        input
            .get("hook_event_name")
            .and_then(serde_json::Value::as_str),
        Some("UserPromptSubmit" | "beforeSubmitPrompt")
    ) {
        return Ok(HookOutput {
            record: None,
            response: if harness == "cursor" {
                serde_json::json!({ "continue": true })
            } else {
                serde_json::json!({})
            },
            diagnostic: None,
        });
    }
    if harness == "cursor" && required_str(input, "hook_event_name")? == "beforeShellExecution" {
        // This event has no native tool-call id. The preceding preToolUse hook owns
        // the declaration; never invent an identity or append a duplicate here.
        let stamped = input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|command| {
                leading_stamp(command).ok().flatten().is_some()
                    || shell_bridge::has_complete_marker(command)
            });
        return Ok(HookOutput {
            record: None,
            response: serde_json::json!({ "permission": "allow" }),
            diagnostic: (!stamped).then_some(
                "Cursor shell event has no complete intent marker; no tool-call association was recorded",
            ),
        });
    }

    if harness == "cursor" && required_str(input, "hook_event_name")? != "preToolUse" {
        return Err("unsupported Cursor intent hook event".to_string());
    }

    let native_session = if harness == "cursor" {
        required_str(input, "session_id").or_else(|_| required_str(input, "conversation_id"))?
    } else {
        required_str(input, "session_id")?
    };
    let session_id = capture_session.unwrap_or(native_session);
    if session_id.is_empty() {
        return Err("capture session must not be empty".to_string());
    }
    let tool_name = required_str(input, "tool_name")?;
    let call_id = required_str(input, "tool_use_id")?;
    let intent_id = live_intent_id(harness, session_id, native_session, call_id);
    let tool_input = input.get("tool_input");
    if let Some(shell) = bridge_shell {
        if matches!(
            tool_name,
            "Bash" | "Shell" | "bash" | "shell" | "exec_command" | "shell_command"
        ) && tool_input
            .and_then(|input| input.get("shell"))
            .is_some_and(|value| value.as_str() != Some(shell))
        {
            return Err(
                "shell bridge conflicts with the explicitly selected tool shell".to_string(),
            );
        }
    }
    let command_field = shell_command_field(harness, tool_name, tool_input);
    let unwrapped = command_field
        .and_then(|key| tool_input.and_then(|value| value.get(key)))
        .and_then(serde_json::Value::as_str)
        .map(|command| shell_bridge::unwrap(command, &intent_id))
        .transpose()?
        .flatten();
    if unwrapped
        .as_ref()
        .is_some_and(|(_, shell)| Some(*shell) != bridge_shell)
    {
        return Err("shell bridge retry requires the same explicitly selected shell".to_string());
    }
    let command = command_field
        .and_then(|key| tool_input.and_then(|value| value.get(key)))
        .and_then(serde_json::Value::as_str)
        .map(|command| {
            unwrapped
                .as_ref()
                .map_or(command, |(decoded, _)| decoded.as_str())
        })
        .map(|command| unstamped_command(command, &intent_id))
        .transpose()?;
    if bridge_shell.is_some() {
        if let Some(mut command) = command {
            // Reason headers are metadata comments, not a boundary that can
            // hide another call's executable attribution marker.
            loop {
                let body = reason::command_body(command);
                if body.len() == command.len() {
                    break;
                }
                command = body;
            }
            if leading_stamp(command)?.is_some()
                || shell_bridge::unwrap(command, &intent_id)?.is_some()
            {
                return Err("shell bridge command contains nested intent markers".to_string());
            }
        }
    }
    let mut record = stamped_record(
        session_id,
        harness,
        &intent_id,
        call_id,
        tool_name,
        command.map(reason::command_body),
        workspace_root,
    )?
    .with_harness_session_id(native_session)
    .with_observation_mode(if command.is_some() {
        "local_shell"
    } else {
        "semantic_only"
    });
    if command.is_some() {
        record = record.with_declared_action("shell.command");
    }

    let mut response = match harness {
        "codex" | "claude" => serde_json::json!({
            "hookSpecificOutput": { "hookEventName": "PreToolUse" }
        }),
        "cursor" => serde_json::json!({ "permission": "allow" }),
        _ => serde_json::json!({}),
    };
    if let (Some(field), Some(original)) = (command_field, command) {
        let stamped = format!("{STAMP_PREFIX}{intent_id}\n{original}");
        let stamped = bridge_shell.map_or_else(
            || stamped.clone(),
            |shell| shell_bridge::wrap(shell, &stamped),
        );
        if matches!(harness, "codex" | "claude" | "cursor") {
            // updatedInput replaces the entire object in Claude Code. Preserve
            // timeouts, cwd, descriptions, background options, and future fields.
            let mut updated = tool_input.cloned().unwrap_or_default();
            updated[field] = serde_json::Value::String(stamped);
            if harness == "cursor" {
                response["updated_input"] = updated;
            } else {
                response["hookSpecificOutput"]["updatedInput"] = updated;
                // Codex requires allow alongside a PreToolUse input rewrite.
                // Claude accepts a rewrite without making a permission decision.
                if harness == "codex" {
                    response["hookSpecificOutput"]["permissionDecision"] = "allow".into();
                }
            }
        } else {
            response["command"] = serde_json::Value::String(stamped);
        }
    }
    Ok(HookOutput {
        record: Some(record),
        response,
        diagnostic: None,
    })
}

// Tool names with words such as "exec" are not enough to establish a local
// shell execution contract (for example, an HTTP MCP tool can use that name).
fn shell_command_field(
    harness: &str,
    tool_name: &str,
    input: Option<&serde_json::Value>,
) -> Option<&'static str> {
    let key = match (harness, tool_name) {
        ("codex" | "claude", "Bash") | ("cursor", "Shell") => "command",
        ("codex", "exec_command") => "cmd",
        ("codex", "shell_command") => "command",
        ("pi", "bash") | ("opencode", "bash" | "shell") => "command",
        _ => return None,
    };
    let input = input?;
    if let Some(shell) = input.get("shell") {
        let shell = shell.as_str()?;
        if !matches!(
            Path::new(shell).file_name()?.to_str()?,
            "sh" | "bash" | "zsh" | "dash"
        ) {
            return None;
        }
    }
    input.get(key)?.as_str()?;
    Some(key)
}

fn live_intent_id(source: &str, session: &str, native_session: &str, call_id: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    for field in [source, session, native_session, call_id] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    digest.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn leading_stamp(command: &str) -> Result<Option<(&str, &str)>, String> {
    let Some(rest) = command.strip_prefix(STAMP_PREFIX) else {
        return Ok(None);
    };
    let (id, original) = rest
        .split_once('\n')
        .ok_or("intent marker header is incomplete")?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("intent marker header is invalid".to_string());
    }
    Ok(Some((id, original)))
}

fn unstamped_command<'a>(command: &'a str, expected_id: &str) -> Result<&'a str, String> {
    match leading_stamp(command)? {
        None => Ok(command),
        Some((id, original)) if id == expected_id => Ok(original),
        Some(_) => Err("intent marker belongs to a different tool call or session".to_string()),
    }
}

fn required_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("hook input missing {field}"))
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
            .with_declared_action(declared_action(tool_name))
            .with_observation_mode(if declared_action(tool_name) == "shell.command" {
                "historical"
            } else {
                "semantic_only"
            });
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

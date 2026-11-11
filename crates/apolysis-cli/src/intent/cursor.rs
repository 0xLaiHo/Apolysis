// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use apolysis_core::SessionIntentRecord;

pub(crate) fn records(
    input: &str,
    session_id: &str,
    workspace_root: Option<&Path>,
) -> Result<Vec<SessionIntentRecord>, String> {
    let workspace_root = resolve_workspace(workspace_root)?;
    let mut records = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let Some(value) = parse_line(line, index)? else {
            continue;
        };
        if let Some(record) = hook_record(&value, session_id, &workspace_root)? {
            records.push(record);
            continue;
        }
        if value.get("role").and_then(serde_json::Value::as_str) == Some("assistant") {
            records.extend(assistant_tool_uses(
                &value,
                session_id,
                &workspace_root,
                index,
            )?);
        }
    }

    Ok(records)
}

fn hook_record(
    value: &serde_json::Value,
    session_id: &str,
    workspace_root: &Path,
) -> Result<Option<SessionIntentRecord>, String> {
    let (Some(tool_name), Some(call_id)) = (
        value.get("tool_name").and_then(serde_json::Value::as_str),
        value.get("tool_use_id").and_then(serde_json::Value::as_str),
    ) else {
        return Ok(None);
    };
    if tool_name.is_empty() || call_id.is_empty() {
        return Ok(None);
    }
    let command = value
        .pointer("/tool_input/command")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("command").and_then(serde_json::Value::as_str));
    Ok(Some(super::stamped_record(
        session_id,
        "cursor",
        &format!("cursor:{call_id}"),
        call_id,
        tool_name,
        command,
        workspace_root,
    )?))
}

fn assistant_tool_uses(
    value: &serde_json::Value,
    session_id: &str,
    workspace_root: &Path,
    index: usize,
) -> Result<Vec<SessionIntentRecord>, String> {
    let Some(content) = value.get("content").and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for block in content {
        if block.get("type").and_then(serde_json::Value::as_str) != Some("tool_use") {
            continue;
        }
        let id = block
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                format!(
                    "cursor-jsonl line {} tool_use block is missing id",
                    index + 1
                )
            })?;
        let tool_name = block
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                format!(
                    "cursor-jsonl line {} tool_use block is missing name",
                    index + 1
                )
            })?;
        let command = block
            .pointer("/input/command")
            .and_then(serde_json::Value::as_str);
        records.push(super::stamped_record(
            session_id,
            "cursor",
            &format!("cursor:{id}"),
            id,
            tool_name,
            command,
            workspace_root,
        )?);
    }
    Ok(records)
}

fn resolve_workspace(workspace_root: Option<&Path>) -> Result<std::path::PathBuf, String> {
    match workspace_root {
        Some(path) => Ok(path.to_path_buf()),
        None => std::env::current_dir()
            .map_err(|error| format!("failed to resolve current workspace root: {error}")),
    }
}

fn parse_line(line: &str, index: usize) -> Result<Option<serde_json::Value>, String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(line).map(Some).map_err(|error| {
        format!(
            "failed to parse cursor-jsonl intent line {}: {error}",
            index + 1
        )
    })
}

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
        if value.get("type").and_then(serde_json::Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(content) = value
            .pointer("/message/content")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
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
                        "claude-jsonl line {} tool_use block is missing id",
                        index + 1
                    )
                })?;
            let tool_name = block
                .get("name")
                .and_then(serde_json::Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    format!(
                        "claude-jsonl line {} tool_use block is missing name",
                        index + 1
                    )
                })?;
            let command = block
                .pointer("/input/command")
                .and_then(serde_json::Value::as_str);
            records.push(super::stamped_record(
                session_id,
                "claude",
                &format!("claude:{id}"),
                id,
                tool_name,
                command,
                &workspace_root,
            )?);
        }
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
            "failed to parse claude-jsonl intent line {}: {error}",
            index + 1
        )
    })
}

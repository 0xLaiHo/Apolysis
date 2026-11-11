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
        let body = value
            .get("data")
            .filter(|data| data.is_object())
            .unwrap_or(&value);
        let Some(parts) = body.get("parts").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for part in parts {
            if part.get("type").and_then(serde_json::Value::as_str) != Some("tool") {
                continue;
            }
            let tool_name = part
                .get("tool")
                .and_then(serde_json::Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    format!(
                        "opencode-jsonl line {} tool part is missing tool",
                        index + 1
                    )
                })?;
            let call_id = part
                .get("callID")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    format!(
                        "opencode-jsonl line {} tool part is missing callID",
                        index + 1
                    )
                })?;
            let command = part
                .pointer("/state/input/command")
                .and_then(serde_json::Value::as_str);
            records.push(super::stamped_record(
                session_id,
                "opencode",
                &format!("opencode:{call_id}"),
                call_id,
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
            "failed to parse opencode-jsonl intent line {}: {error}",
            index + 1
        )
    })
}

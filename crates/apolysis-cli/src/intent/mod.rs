// SPDX-License-Identifier: Apache-2.0

mod codex;

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
        other => Err(format!("unsupported intent adapter '{other}'")),
    }
}

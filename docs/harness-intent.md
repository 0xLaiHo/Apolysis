# Harness intent

Apolysis records a tool call from Codex, Claude Code, Cursor, Pi, or OpenCode,
then joins a shell syscall to that call when a live hook stamps
`APOLYSIS_INTENT_ID` into the shell command.

File adapters read an existing session export. Live hooks append the same
`intent` JSONL and, for a shell tool, rewrite the command the harness is about
to run. Persisted records stay content-off: prompts, tool results, raw argv,
and secrets are not stored. The field list and match order are in
[JSONL schema v1](jsonl-schema-v1.md).

## Codex

Put this in `~/.codex/hooks.json` or the project `.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "apolysis intent hook --harness codex --output .apolysis/intent.codex.jsonl --workspace-root \"$PWD\""
          }
        ]
      }
    ]
  }
}
```

`codex-jsonl` also reads Codex `response_item` logs, including `function_call`,
`tool_call`, `local_shell_call`, and `web_search_call`.

## Claude Code

Put this in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "apolysis intent hook --harness claude --output .apolysis/intent.claude.jsonl --workspace-root \"$CLAUDE_PROJECT_DIR\""
          }
        ]
      }
    ]
  }
}
```

`claude-jsonl` reads assistant `tool_use` blocks from a Claude Code transcript.

## Cursor

Put this in `.cursor/hooks.json`. Both events use the same command:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "apolysis intent hook --harness cursor --output .apolysis/intent.cursor.jsonl --workspace-root \"$PWD\""
      }
    ],
    "beforeShellExecution": [
      {
        "command": "apolysis intent hook --harness cursor --output .apolysis/intent.cursor.jsonl --workspace-root \"$PWD\""
      }
    ]
  }
}
```

`preToolUse` stamps a shell command through `updated_input`. `beforeShellExecution`
records the call and returns `{"permission":"allow"}` without rewriting the
command. HTTP MCP `preToolUse` ignores `updated_input`, so those calls stay
semantic records.

`cursor-jsonl` reads hook payloads and assistant `tool_use` blocks. File ingest
uses the CLI `--session` value.

## Pi

Copy `hooks/pi/apolysis-intent.ts` into `~/.pi/agent/extensions/`. Set
`APOLYSIS_BIN` when the `apolysis` binary is not on `PATH`. The extension
listens for `tool_call`, appends `.apolysis/intent.pi.jsonl`, and applies a
returned shell command.

`pi-jsonl` reads assistant `toolCall` blocks from a Pi session file.

## OpenCode

Copy `hooks/opencode/apolysis-intent.ts` into `.opencode/plugins/`. The plugin
listens for `tool.execute.before`, appends `.apolysis/intent.opencode.jsonl`,
and applies a returned shell command.

Export an existing database with:

```bash
sqlite3 "${XDG_DATA_HOME:-$HOME/.local/share}/opencode/opencode.db" \
  "SELECT data FROM session_message;" > /tmp/opencode-messages.jsonl
apolysis intent ingest --adapter opencode-jsonl --input /tmp/opencode-messages.jsonl \
  --session opencode-replay --output .apolysis/intent.opencode.jsonl \
  --workspace-root "$PWD"
```

Each exported line is the `data` JSON object. Tool parts are `parts[]` entries
whose `type` is `tool`.

## What joins to a syscall

- A shell syscall joins to a tool call only when the event's `intent_id` equals
  the intent record. That requires the hook rewrite to have been present in the
  transient argv of the shell or an observed parent exec.
- `web.search` and `file.read` records explain the tool name. They do not
  create a syscall correlation by themselves.
- Provider-side web search does not appear as a host connect.
- Historical timelines recorded before this stamp cannot be joined by id.
  Executable-name correlation remains the fallback and is labeled
  `process_executable`.

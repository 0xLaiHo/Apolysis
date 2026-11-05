# Harness intent

[English](harness-intent.md) | [简体中文](harness-intent.zh-CN.md)

Apolysis normalizes declared Tool Calls from Codex, Claude Code, Cursor, Pi,
and OpenCode into local `intent` JSONL records. These are Semantic Evidence;
they do not establish an operation's success, authorization, or complete
execution coverage. File adapters import historical declarations. Live hooks
record a declaration before returning a supported shell-command rewrite.

The hook writer appends under a file lock and deduplicates a repeated call;
it does not truncate previous records. Live IDs are 32 lowercase hexadecimal
characters derived from SHA-256 over length-framed source, capture session,
native harness session, and call ID. Native IDs remain metadata, rather than
being interpolated into shell syntax. Historical file adapters retain their
existing source-prefixed IDs.
Deduplication compares the complete persisted record except ingestion time.
It does not compare original command contents: if a producer reuses a call ID,
differences confined to discarded arguments cannot be detected. Conflicts in
retained metadata are rejected; raw-command fingerprints are not retained.

For a shell Tool Call, the rewrite adds a comment line before the unchanged
command body:

```sh
# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef
cargo test
```

This is a command-text marker, not an environment variable or a shell wrapper.
The hook preserves the rest of the original tool input. Claude Code receives
no `permissionDecision`, so its native permission flow decides approval.
Codex requires `permissionDecision:"allow"` alongside a shell `updatedInput`;
that acknowledgement is emitted only for a supported rewrite, not for every
tool. Pi and OpenCode modify their documented mutable input objects. Cursor
returns its documented continuation response.

Persisted records stay content-off: prompts, tool results, raw argv, and raw
tool arguments are not retained. Executable metadata is allowlisted. The
original command necessarily exists transiently in the hook and is returned
to the product for execution. See [JSONL schema v1](jsonl-schema-v1.md).

## Capture session and visibility

The `session_id` used for correlation is the Apolysis capture-session ID.
`harness_session_id` preserves the product's native session ID separately.
Pass `--session <capture-id>` to the hook when the observer uses a different
ID; otherwise the hook uses the native ID. The observer and hook must use the
same capture ID. Matching only the native call ID does not join two sessions.
The Pi and OpenCode wrappers accept `APOLYSIS_SESSION_ID` as the capture-session
override and otherwise use their native session ID.

Each declaration records `observation_mode`:

| Value | Meaning |
| --- | --- |
| `local_shell` | A local shell command was prepared for marker propagation. |
| `semantic_only` | The tool has a declaration but no supported local shell rewrite. |
| `historical` | The declaration was imported from an existing export. |

`local_shell` describes an intended observation path; it does not confirm that
the product executed the rewrite or that the observer received the marker.
Web search, file-read tools, and remote calls remain `semantic_only` unless a
separate execution integration supplies evidence.

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
Hosted Codex web search does not run through the local `PreToolUse` hook;
its declaration requires file ingestion. Shell hooks use the canonical
`Bash` tool name and `tool_input.command`, including unified exec.

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

`preToolUse` stamps a shell command through `updated_input` while preserving
the other tool-input fields. `beforeShellExecution` is supplementary: its
documented payload has no call ID. It reuses a valid leading marker when one
is present; otherwise it reports a skipped supplementary event and continues
without inventing a call ID or overwriting the intent file. It does not rewrite
the command a second time. Cloud-agent HTTP MCP ignores `updated_input`, so
those calls stay semantic records.

`cursor-jsonl` reads hook payloads and assistant `tool_use` blocks. File ingest
uses the CLI `--session` value.

## Pi

Copy `hooks/pi/apolysis-intent.ts` into `~/.pi/agent/extensions/`. Set
`APOLYSIS_BIN` when the `apolysis` binary is not on `PATH`. The extension
listens for `tool_call`, appends `.apolysis/intent.pi.jsonl`, and applies a
returned shell command.

`pi-jsonl` reads assistant `toolCall` blocks from a Pi session file.
The extension obtains its native session ID from
`ctx.sessionManager.getSessionId()`; the `tool_call` event has no `sessionId`
field.

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

## Verification boundary

Hook fixture tests verify normalized input, safe IDs, append/deduplication,
input preservation, and command syntax without calling a model or a provider.
They do not qualify a product/version's live event delivery or its execution
backend. The JavaScript bridge tests invoke the actual Pi and OpenCode modules
with product-shaped events and a controlled subprocess response. Run the
focused checks with a current Rust toolchain. The locked append API uses
[`File::lock`](https://doc.rust-lang.org/std/fs/struct.File.html#method.lock),
which requires Rust 1.89 or newer; this is an API requirement, not a verified
minimum version for the entire workspace. Bridge tests use native
[TypeScript type stripping](https://nodejs.org/api/typescript.html), requiring
Node.js 22.18+ on the 22.x line, or a newer LTS release with stripping enabled
by default. `make test-harness-hooks` is included in `make test` and CI runs it
with the latest Node.js 22 release:

```bash
cargo test -p apolysis-store --test intent_append
cargo test -p apolysis-cli --test intent_harness
cargo test -p apolysis-cli --test intent --test intent_correlation --test intent_correlation_conflicts
cargo test -p apolysis-observer
make test-harness-hooks
```

`make test-bpf-relocation` is an additional opt-in check requiring readable host
BTF and the eBPF build tools, but no BPF privileges. It parses the built object
and relocates all programs without loading them into the kernel. Native C
helper tests also cover complete shell basenames and malformed marker headers.

Privileged live observer tests are opt-in. Missing privileges or kernel
prerequisites are reported as a skip, not a pass. Rebuild the CLI and eBPF object
together; the current 648-byte event ABI is not compatible with older objects.
`make test-live-harness-intent` runs the explicit local live marker gate on a
prepared host. An authorized privileged invocation has passed on one local
kernel, along with the general observer regression; see
[live validation](harness-intent-live-validation.md) for the exact scope and
retained truncation diagnostics. This does not qualify native product
end-to-end delivery, other kernels, or stress/loss behavior.
The gate attaches audit-only probes to synthetic child process trees, reads
temporary fixture files, and attempts a loopback connection. It contacts no
provider and changes no runtime policy; process exit detaches probes and the
script removes its own temporary directory.

## What relates to an observed attempt

The collector reads only a complete leading marker from a recognized shell's
command-string argument. It captures the marker in a dedicated field rather
than scanning diagnostic argv, so truncating a long command body does not
truncate the marker. Supported shell invocation forms are bounded (`-c`,
`-lc`, or `-cl`, within the first eight arguments); other execution forms may
remain unattributed.

Kernel context checks TGID plus thread-group leader start time, copies the marker at
fork (including children that do not exec), preserves it across same-process
exec only when complete capture establishes no new marker, and replaces it
when a valid new marker is observed. Missing pending capture, unreadable or
malformed headers, or an unresolved shell command slot clear old attribution.
These cases retain `intent_capture_incomplete:true` in the content-off raw
payload and contribute to the existing truncation warning.
File, network, credential, and process events carry that context while it is
known. Context is removed when the last thread exits. A missing live marker
is not reconstructed from an old userspace cache. Loss and map-pressure
diagnostics remain relevant; this is not complete process-tree coverage.

Correlation is a separate command and stays within one capture session:

- A unique `intent_id`, or a unique explicit `raw_event_id` link when no marker
  is present, establishes an Exact Relation within this integration's trust
  boundary. When both exist they must identify the same declaration.
- Unknown, conflicting, or ambiguous identifiers produce an
  `intent_correlation_diagnostic`; they do not fall back to a name match.
- Legacy command equality and exec-only executable matching produce
  `intent_correlation_candidate`, marked `inferred` for one candidate or
  `ambiguous` for several. They do not count as matches or suppress Findings.
- `semantic_only` declarations neither match execution events nor produce
  `unobserved_intent`. Historical imports remain eligible for explicit links;
  a weak candidate alone leaves them unmatched.

File and network events in this implementation describe observed attempts.
One Tool Call can produce many events; a matching ID does not prove that the
declared tool was authorized to perform every observed action. Provider-side
web search is outside a local host's connect visibility. A remote execution
backend needs its own Evidence Source.

All processes writing a live intent file must use the locked append interface.
External rotation and network-filesystem lock behavior are outside this local
contract. A malformed or incomplete existing file is rejected without
truncating it. Direct Codex, Claude Code, and Cursor hook failures exit with
code 2 and emit no rewritten command; the product may block the tool call.
Pi and OpenCode bridge failures instead issue a fixed diagnostic and continue
after removing any complete leading intent-marker headers, preserving the
command body. This prevents a rejected old marker from being executed as a
different call's attribution. These failures are not a successful capture.

References for the native hook contracts:

- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [Pi extensions](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md)
- [OpenCode plugins](https://opencode.ai/docs/plugins/)

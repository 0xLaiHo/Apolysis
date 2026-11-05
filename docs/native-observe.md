# Observe a native agent application

[English](native-observe.md) | [简体中文](native-observe.zh-CN.md)

`apolysis observe --agent` opens the selected application's own interface.
Apolysis adds a temporary tool-declaration hook and a separate eBPF collector,
then writes a readable local report when the application exits. It does not
replace the conversation interface or select Claude implicitly.

This is the native entry point. The older [`apolysis chat`](reason-chat.md)
command remains a separate controlled Claude experiment using stream JSON and
Bash-only tools; it is not required here.

## Start

Use a Linux host with the live eBPF prerequisites, a supported application
installed in `PATH`, and that application's existing provider authentication.
Build the CLI and matching BPF object as your ordinary user:

```bash
cargo build -p apolysis-cli
make build-ebpf
```

From the checkout, choose one application:

```bash
target/debug/apolysis observe --agent claude
target/debug/apolysis observe --agent codex
target/debug/apolysis observe --agent pi
target/debug/apolysis observe --agent opencode
target/debug/apolysis observe --agent cursor
```

Run this as your ordinary user, without putting `sudo` in front. The CLI asks
sudo to start only the collector; the native application retains your identity,
environment, terminal, credentials and normal permission prompts. It does not
disable existing tools, MCP servers, hooks, slash commands or conversation
history. A native trust prompt for the added hook/plugin remains a native trust
decision; Apolysis does not bypass it.

The launch workspace is the current directory; the child's `PWD` is set to the
canonical launch directory so an inherited shell value cannot point the native
application at a different project. To use a separate existing test
directory, specify `--workspace /absolute/path/to/test-directory`. The directory
is not a sandbox and the application keeps its normal host access.

## Keep native arguments native

Place Apolysis options before `--`; everything after it is passed as individual
arguments to the selected application. Values are not joined into a shell
command, evaluated, or reinterpreted as Apolysis flags.

```bash
# Original Claude option, with the native interface still active.
target/debug/apolysis observe --agent claude -- --model sonnet

# Ask the installed applications for their actual supported options.
target/debug/apolysis observe --agent codex -- --help
target/debug/apolysis observe --agent claude -- --help
target/debug/apolysis observe --agent pi -- --help
target/debug/apolysis observe --agent opencode -- --help
target/debug/apolysis observe --agent cursor -- --help
```

Standalone help/version invocations are passed through without sudo, hook
installation or eBPF capture. Model names, provider options, resume IDs, worktree
options and subcommands otherwise retain the selected application's syntax and
validation. Apolysis does not promise that one product understands another
product's flags, or that a locally recognized model is available from your
provider. Quote prompt and path arguments as you normally would in your shell.

Native JSON/stream output remains on stdout; Apolysis status and report-location
messages use stderr. A native `--print`, `exec`, `run`, `--json` or equivalent is
your explicit choice, not an option silently imposed by the observer.

| Apolysis option, before `--` | Meaning |
| --- | --- |
| `--agent codex\|claude\|pi\|opencode\|cursor` | Required application selection; no default. |
| `--workspace <directory>` | Initial launch directory; defaults to current directory. |
| `--output-dir <parent>` | Parent for a new private capture directory. |
| `--bpf-object <path>` | Explicit matching observer object when automatic discovery is unsuitable. |
| `--policy <path>` | Optional audit policy. |
| `--allow-reason-summary` | Explicitly retain bounded, filtered reason/description text when supplied. |
| `--shell-bridge /bin/bash` | Explicitly use the existing supported inner-shell marker bridge. |

Native directory options such as Codex `-C` and Cursor `--workspace` remain
native arguments. Known directory options are also resolved for observation
metadata where possible; dynamic worktree/resume choices can differ from the
initial workspace, which is reported as a coverage note.

## Product-specific integration

| Selection | Executable | Temporary integration |
| --- | --- | --- |
| `claude` | `claude` | An additional runtime plugin containing `PreToolUse`; existing settings and plugins remain loaded. |
| `codex` | `codex` | A session config layer with `PreToolUse`, hooks enabled and `--no-daemon` so local work stays in this process tree. |
| `pi` | `pi` | The checked-in tool-call extension, loaded using the native extension option. |
| `opencode` | `opencode` | The checked-in tool-execution plugin, appended to the existing in-memory `OPENCODE_CONFIG_CONTENT` configuration. |
| `cursor` | `cursor-agent` | An additional runtime plugin with `preToolUse` and `beforeShellExecution`. |

Original argument tokens stay in order. Existing user/project configuration is
not overwritten. Temporary files hold hook/plugin configuration, not copied
credentials or native invocation arguments. Other hooks and native policy can
still reject or modify a Tool Call; a loaded plugin is not proof that every call
was recorded.

Options that disable this hook or move execution outside the local process tree
are rejected explicitly where recognized: Claude bare/safe/cloud/desktop or
background modes, Codex remote mode or competing session hook/daemon overrides,
and OpenCode pure/attach modes. Do not silently remove such options to make a
test pass. Remote, shared-server and detached execution need a different
Evidence Source; this entry does not claim their kernel activity as locally
captured. A product version without the required runtime plugin/config option
is not qualified by the existence of this adapter.

## Try an ordinary conversation

In the native application, enter your own request, for example:

```text
Check the current weather in San Francisco.
```

The application can choose its normal web search or MCP tool. Such declarations
are often `semantic_only`: the observer must not invent an exact local syscall
relation for a remote tool. Codex hosted WebSearch does not pass through its
local `PreToolUse` hook and is a separate declaration-coverage gap.

For local execution you can ask the application to create a small file with its
shell tool and read it back. Default marker-only mode adds no tool shell, but a
product's subsequent `eval` wrapping can hide the marker from exec capture. To
exercise the existing explicit bridge instead, choose it before launching:

```bash
target/debug/apolysis observe --agent claude --shell-bridge /bin/bash
```

This preserves the native interface but adds an inner shell to supported shell
Tool Calls. Its cwd, variables and functions do not propagate back to the
application's outer shell. Exact attribution still requires a real accepted
rewrite and observed marker; bridge selection alone is not evidence.

No reason-generation prompt is injected. Ordinary native descriptions remain
`tool_description` with code `unknown`; absent reasons stay unknown. The
controlled `agent_declared` protocol from the earlier experiment is not silently
applied to ordinary sessions. See [harness intents](harness-intent.md).

## Read the report

Exit through the application's normal exit mechanism and let Apolysis finish
correlation. The location is printed on stderr. By default, captures live under
`$XDG_STATE_HOME/apolysis/captures`, or
`$HOME/.local/state/apolysis/captures` when XDG state is unset or not absolute.
A new private directory is created for each invocation; its `evidence/`
subdirectory contains the files below. Do not concatenate separate captures.

| File | Purpose |
| --- | --- |
| `report.html` | Offline, self-contained call-oriented report; open it in a browser. |
| `report.md` | The same main conclusions as readable Markdown. |
| `result.json` | Structured application state, capture health, call aggregates and diagnostics. |
| `intent.jsonl` | Original tool declarations. |
| `intent.jsonl.reasons.jsonl` | Codes and any explicitly opted-in reason summaries. |
| `timeline.jsonl` | Content-off observed events, metadata and diagnostics. |
| `correlation.jsonl` | Exact Relations, weaker candidates, reason bindings and Findings. |

Each Tool Call shows its declared reason or unknown status, observation mode,
exact event counts, and bounded examples linked by raw event ID. Network and
credential-path attempts remain visible rather than buried among library-file
opens. Raw and canonical records are not counted twice. Unattributed evidence,
ambiguous candidates, identifier conflicts and audit-policy notices remain
separate from exact call attribution.

Application exit, capture completion and task outcome are different fields.
The report leaves task outcome `not_verified`: a successful process exit or
connect attempt does not prove a weather response or other claimed result.
Loss and truncation are separate, and `complete` does not promise exhaustive
syscall coverage. Missing, malformed, foreign-session, stale-correlation or
oversized inputs make the report explicitly incomplete; each source artifact
has a 64 MiB rendering bound.

Controlled native captures use a bounded **8 MiB** ring-buffer capacity override
at load time to tolerate product startup and hook bursts. The eBPF event ABI,
built object default, legacy observer and daemon defaults are unchanged. This
is not a guarantee against event loss: nonzero loss still makes capture
incomplete, and truncation is still reported.

The default audit policy avoids applying repository-directory allow lists to
an unrelated native workspace. Credential-path rules remain visible, but a
path match is not proof of reading a secret or leaking it. No audit-only policy
notice should be presented as a blocked operation.

## Retention and validation boundary

Apolysis does not persist prompts, full command arguments, tool results or raw
provider stdout/stderr. Native application history and other existing hooks
retain their original behavior; this promise does not reconfigure those
systems. Declared summaries, identifiers and observed paths remain retained
data. Reports escape untrusted text and load no external resources, but local
user-owned exports are not a tamper-resistant evidence store.

Tests of argument construction, report rendering and local process control are
different from real product/provider/eBPF qualification. Missing authentication,
provider connectivity failures, skipped live gates and unsupported product
versions cannot be reported as passed. Earlier script results and the separate
current native-entry passes and gaps are recorded in the
[live-validation report](harness-intent-live-validation.md); historical results
do not automatically qualify this native launch path. Current scope and
no-go criteria remain in the [design](design.md) and [roadmap](roadmap.md).

`make test-native-observe` runs the non-provider Rust regressions. The
[native entry validation](harness-intent-live-validation.md#native-entry-validation)
section separately records real TUI checks and reproduction commands for the
explicit provider/eBPF gate.

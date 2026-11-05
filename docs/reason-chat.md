# Try a conversation with declared reasons

[English](reason-chat.md) | [简体中文](reason-chat.zh-CN.md)

[`run-reason-chat.py`](../scripts/run-reason-chat.py) lets you type your own
natural-language tasks and follow-ups into one Claude conversation while
Apolysis observes its local execution with real eBPF. There is no fixed task
in interactive mode. Each run creates a separate workspace; it does not use
your current project as the task directory.

This is an experimental observation runner for Claude Code, using a controlled
reason-declaration protocol and an explicit shell bridge. It is not a default
native reason capability or a hostile-agent sandbox.

## Start

You need Linux with the live BPF prerequisites, a working Claude Code CLI and
existing provider authentication, Bubblewrap, Python 3, and the CLI/BPF objects
built from the same source. It makes real provider requests, which may incur
charges. Use a normal user terminal in the repository, build without sudo,
then explicitly elevate the observer:

```bash
cargo build -p apolysis-cli
make build-ebpf
sudo --preserve-env=PATH,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy \
  env PYTHONDONTWRITEBYTECODE=1 python3 -u ./scripts/run-reason-chat.py
```

Preserve any additional existing provider-auth environment variables by name
if your setup needs them; do not put their values in commands or files. The
runner requires a non-root invoking user, restores that user's real home, and
runs the managed product as that user. Temporary settings and mount masks
leave existing global hooks, instructions, and shell profiles unchanged.
Missing build artifacts or live prerequisites produce an error rather than a
successful demonstration.

The terminal prints the new `workspace` and `evidence` directories under
`target/reason-chat-*`. Type one message per line and wait for the reply. For
example, send these as three separate turns:

```text
Create greeting.txt in the current directory containing hello apolysis, then tell me what you did.
Read the file you just created and tell me how many words it contains.
Thanks. Reply in one sentence without using any tools.
```

These are examples, not required commands. You can ask different tasks and
refer to earlier turns. Only Bash is available; pure conversation needs no
tool. The model chooses its commands and writes each call's declared reason.

- `/exit` or Ctrl+D ends the conversation normally.
- Ctrl+C ends the whole session; it is not a request to cancel only one turn.
- `--turn-timeout 300` changes the per-turn timeout from the default 180 seconds.

Each tool call uses a fresh `/bin/bash`. Files persist between calls, but
shell directory, variable, and function changes do not carry back to the
product's outer shell. Ask for needed directory changes within the same
command. The in-memory conversation lasts only for the current process:
`--no-session-persistence` means it cannot be resumed after exit.

## Read the observations

After each reply, the runner displays every newly declared call's `intent_id`,
declared reason, and current exact-relation count. A turn without a tool call
reports that fact and creates no synthetic intent or reason. The count is the
number of observed events attributed to that call, not the number of tasks
successfully completed. An exact relation identifies an observed attempt;
file contents, test results, or other outcome evidence must establish success.

The model supplies `APOLYSIS_REASON_JSON=` followed by a strict JSON object in
native `Bash.description`. The adapter passes its `reason_code` and
`reason_summary` to the existing hook, preserving the real native session and
call IDs. Invalid declarations are denied. This runner deliberately enables
`--allow-reason-summary` and `--shell-bridge /bin/bash`; it does not infer why
from a command or fill in a missing reason. The summary remains the model's
unverified statement, not hidden thinking or authorization.

The existing privacy filter may replace a free-text summary with `[redacted]`.
That does not invalidate its reason code or intent-ID relation: the interface
can show the code and indicate that the summary was redacted. A readable
summary is not required for an exact execution relation, and redacted text
must not be reconstructed or silently replaced with an invented explanation.

At exit, inspect the printed capture status and `evidence/result.json`:

| Field | Meaning |
| --- | --- |
| `conversation_status` | Whether the conversation finished or was interrupted/failed. |
| `capture_status` | Whether final capture checks passed, including a nonempty matching summary and successful native exit. |
| `correlation_status` | Whether final correlation completed. |
| `smoke_status` | `not_requested` in interactive mode; `passed` or `failed` for the separate smoke assertions. |
| `turns` | Completed turn numbers and their tool-call counts, without prompt text. |
| `kernel_events`, `loss_or_failure_count`, `truncations` | Observed event totals and retained diagnostics. |

These statuses are separate. Forced shutdown, missing final records, or a
failed turn must not be presented as a complete successful run. Truncations
remain visible even when capture checks pass; passing checks does not prove
complete syscall coverage. A zero association count is not proof that no
action occurred.

## What stays on disk

The run keeps both directories for you to inspect:

| Location | Retained data |
| --- | --- |
| `workspace/` | Files created or edited for your tasks, including their contents. |
| `evidence/intent.jsonl` | Tool-call declarations and identity metadata. |
| `evidence/intent.jsonl.reasons.jsonl` | Declared codes and opted-in summaries. |
| `evidence/timeline.jsonl` | Content-off kernel/canonical events and observer diagnostics. |
| `evidence/correlation.jsonl` | Exact relations, candidates, reason bindings, and diagnostics. |
| `evidence/result.json` | Final conversation, capture, and correlation status. |

Prompts, complete tool arguments, and the raw provider stdout/stderr streams
are not written to logs. Assistant text is shown in your terminal. Declared
summaries, identifiers, observed paths, and generated task files **are retained
data**; content-off observation is not a promise that the whole directory is
content-free. Best-effort summary redaction does not guarantee anonymity.
Terminal recording and the provider's own data handling are outside this
local persistence rule.

The generated root is private and Git-ignored. Control files are temporary;
workspace and evidence remain after exit or failure. Remove only the printed
run directory when you no longer need it. No global product configuration is
edited, and the runner does not use Kubernetes.

The mount setup makes the host read-only and permits writes to the temporary
control directory, workspace, and evidence. Read-only mounts do not prevent
host reads or network access, and the agent shares access to writable evidence.
The setup therefore provides neither hostile-agent containment nor
tamper-resistant records. Use non-sensitive tasks for this experiment.

## Validation boundary

`--smoke` runs three real provider-backed turns: create a greeting file, read
and count its words, then chat without a tool. Invoke it with the same sudo
environment above, adding `--smoke`. `make test-reason-chat` runs the local
protocol and shutdown regressions without provider calls.

The final live smoke run on 2026-11-05 with Claude Code 2.1.295 and x86_64 Linux
6.18.55-2-cachyos-lts completed all three turns: **4,209 kernel events, 18
truncations, zero loss/failures**, two calls in the same native session with
67 and 98 exact relations, and no tool call in the final turn. The final result
reports `conversation_status=finished`, `capture_status=complete`,
`correlation_status=complete`, and `smoke_status=passed`. Complete capture here
means normal exit and successful count/diagnostic checks, not zero truncation
or complete syscall coverage.

The first summary was `[redacted]`, with its `implement_change` code retained.
The second call retained the model-written summary:

> 用户要求读取刚创建的问候文件并统计其中单词数量，需要读取文件并用单词统计命令计算

Both calls retained exact relations. Local protocol and cleanup regressions
also passed: `make test-reason-chat` reported 21 and 3 passing tests. The full
Rust suite reported 541 passed, 91 ignored, and no failures; `make lint` passed.
A separate manual terminal run without `--smoke` also passed: a user-entered
directory-listing request caused a real `ls` call with 81 exact relations,
then `/exit` closed normally (3,607 kernel events, 15 truncations, zero
loss/failures; complete capture/correlation, finished conversation, and
`smoke_status=not_requested`).
This bounded result does not qualify arbitrary tasks, product versions,
kernels, or loads. The existing Codex network and Cursor
authentication blockers remain unchanged; see [live validation](harness-intent-live-validation.md),
[design](design.md), and [roadmap](roadmap.md).

# Try a conversation with declared reasons

[English](reason-chat.md) | [简体中文](reason-chat.zh-CN.md)

The Rust `apolysis chat` command lets you type your own
natural-language tasks and follow-ups into one Claude conversation while
Apolysis observes its local execution with real eBPF. There is no fixed task
in interactive mode. Each run creates a separate workspace; it does not use
your current project as the task directory.

This is an experimental observation runner for Claude Code, using a controlled
reason-declaration protocol and an explicit shell bridge. It is not a default
native reason capability or a hostile-agent sandbox.

## Start

You need Linux with the live BPF prerequisites, a working Claude Code CLI and
existing provider authentication, Bubblewrap, and the CLI/BPF objects built
from the same source. The conversation runtime does not require Python. It
makes real provider requests, which may incur
charges. Use a normal user terminal in the repository, build without sudo,
then explicitly elevate the observer:

```bash
cargo build -p apolysis-cli
make build-ebpf
sudo --preserve-env=PATH,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy \
  target/debug/apolysis chat
```

Preserve any additional existing provider-auth environment variables by name
if your setup needs them; do not put their values in commands or files. The
runner requires a non-root invoking user, restores that user's real home, and
runs the managed product as that user. Temporary settings and mount masks
leave existing global hooks, instructions, and shell profiles unchanged.
Missing build artifacts or live prerequisites produce an error rather than a
successful demonstration.

The terminal prints the new `workspace` and `evidence` directories under
`target/reason-chat-rust-*`. Type one message per line and wait for the reply. For
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
- `--turn-timeout 300` changes the per-turn timeout from the default 180 seconds
  (accepted range: 1–3,600 seconds).

The optional paths are `--output-dir <parent>` (default `target`),
`--policy <path>` (default `policies/local-dev.yaml`), and `--bpf-object <path>`
(default `target/ebpf/apolysis_observer.bpf.o`). They resolve from the directory
where you launch the command. The output option selects the parent for a new
run directory, not an existing project to operate on. Use matching CLI and BPF
builds. `apolysis chat --help` does not start a provider or require sudo. The
internal `hook`, `launch`, and `publish` helpers are not manual workflow steps.

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
| `controller_runtime` | `rust`, identifying the conversation implementation used for this run. |
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

The generated run directory is private; the default `target/` location is
Git-ignored. If you select another output parent, keep those captures out of
version control. The root observer writes its capture source only in a
root-owned private temporary directory. Fresh unprivileged Rust helpers
atomically publish the timeline snapshots, correlation, and final result to
the user-owned evidence directory; root does not reopen those mutable output
paths for publication. The authentication helper also runs as the invoking
user and reads the required existing settings into its child environment,
without writing credentials to files.

Control and private capture files are temporary; workspace and published
evidence remain after exit or failure. Remove only the printed run directory
when you no longer need it. No global product configuration is edited, and
the command does not use Kubernetes.

The mount setup makes the host read-only and permits writes to the temporary
control directory, workspace, and evidence. Read-only mounts do not prevent
host reads or network access, and the agent shares access to writable evidence.
The setup therefore provides neither hostile-agent containment nor
tamper-resistant records. Use non-sensitive tasks for this experiment.

## Validation boundary

`--smoke` runs three real provider-backed turns: create a greeting file, read
and count its words, then chat without a tool. Invoke it with the same sudo
environment above, adding `--smoke`. This regression requests ordinary shell
commands so that it can check the Rust conversation path without a Python
interpreter. `make test-reason-chat` runs the Rust unit and CLI integration
regressions without provider calls:

```bash
cargo test -p apolysis-cli chat:: --bin apolysis
cargo test -p apolysis-cli --test chat
```

On 2026-11-05, the Rust runtime passed both paths with Claude Code 2.1.295 on
x86_64 Linux 6.18.55-2-cachyos-lts:

| Rust run | Kernel events | Truncations | Observed result |
| --- | --- | --- | --- |
| Three-turn `--smoke` with outer execution tracing | 3,752 | 16 | Two calls in one native session, with 67 and 66 exact relations; no tool in the third turn. |
| Manual terminal input, then `/exit` | 3,631 | 17 | A user request created and read back a note; its two calls had 35 and 66 exact relations, then the session exited normally. |

Both runs reported zero loss/failures, `controller_runtime=rust`, complete
capture/correlation, and a finished conversation. The smoke status was
`passed` for the three-turn run and `not_requested` for the manual run. The
manual run's first summary was redacted; the second retained the model's
declaration “读回文件内容以确认写入正确”. Exact relations remained valid for both.
Complete capture means normal exit and successful count/diagnostic checks,
not zero truncation or complete syscall coverage.

Local verification passed: 38 chat unit tests, 4 CLI integration tests, and
the full Rust suite with 583 passed, 91 ignored, and no failures. These are
Rust results, not inherited passes from the former Python conversation script.
The retained `test-live-reason-products.py` and `test-live-reason-summary.py`
scripts are independent opt-in validation tools, not dependencies of
`apolysis chat`; their historical results remain in [live validation](harness-intent-live-validation.md).

### Optional execution-tracing gate

[`test-live-reason-chat.sh`](../scripts/test-live-reason-chat.sh), also exposed
as `make test-live-reason-chat`, reruns only the fixed three-turn smoke under
an outer executable tracer. This includes controller publish/correlate helpers
outside the observer's managed-agent scope. It requires a complete Rust smoke
report, usable filename/count evidence, and no observed Python executable.
This is evidence about that run, not proof against renamed or hostile code.

After building, use the same explicit sudo environment:

```bash
sudo --preserve-env=PATH,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy \
  ./scripts/test-live-reason-chat.sh --require-all
```

The gate uses `APOLYSIS_STRACE` when supplied, otherwise an installed `strace`,
and falls back to `bpftrace` when strace is unavailable. To use a separately
verified binary without installing it globally, insert
`env APOLYSIS_STRACE=/absolute/path/to/verified/strace` before the script path
in that command. It also needs `jq`, `setpriv`, `timeout`, and `realpath`, plus
`gawk` for the strace backend. These are optional validation dependencies,
not requirements of `apolysis chat`. `--require-all` turns missing
prerequisites into a failure rather than a successful skip.

Only executable filenames and their attempt counts are exported as
`evidence/executable-counts.json`, atomically published as the invoking user.
The counts include failed PATH-search attempts and are not successful-exec
counts. Filenames remain retained data. The strace backend temporarily records argv
for this fixed synthetic workload in a root-private directory; it does not
expand environment values, and removes raw traces on exit. Do not use this
gate to record ordinary private conversations. It changes neither global
product configuration nor Kubernetes state.

The local bpftrace attempt failed inside its ELF handling and is not passing
evidence. The final outer-trace gate passed using a signature-verified
temporary strace binary without global installation. It observed **18
`apolysis` exec attempts**, including helpers outside the managed-agent scope,
and **no Python exec attempt**. Its Rust smoke result is the 3,752-event row
above. Raw traces were removed on exit; only the filename/count artifact was
retained alongside the ordinary chat evidence.

Even a successful bounded run does not qualify arbitrary tasks, product
versions, kernels, or loads. This Claude-specific experiment does not determine
other applications' current native-entry status; see the dated
[live validation](harness-intent-live-validation.md),
[design](design.md), and [roadmap](roadmap.md).

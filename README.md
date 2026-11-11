# Apolysis

[English](README.md) | [简体中文](README.zh-CN.md) | [Architecture](docs/design.md)

Apolysis is an experimental Linux eBPF runtime observability system for AI agents. It
collects tool declarations and scoped operating-system observations separately,
then relates them through explicit identifiers. The resulting report shows
what the agent declared, which process/file/network attempts were observed,
and where evidence is missing.

The local entry opens the agent's original application. Apolysis supplies
temporary hooks and a separate eBPF collector; the agent keeps its own interface,
tools, configuration and permission prompts. This observation path does not
provide isolation or prove that a task succeeded.

## Current capabilities

- Native launch adapters for Codex, Claude Code, Cursor Agent, Pi and OpenCode,
  with product-specific hook loading and native argument passthrough.
- Process-tree or cgroup-scoped observation, stable process/exec generations,
  outcome-aware selected file/connect operations, and explicit loss and gaps.
- Tool declarations and optional declared reasons (including opt-in sanitized
  user prompt and tool-description summaries), linked to execution through
  `intent_id`. Identifier-based relations remain separate from inferred matches.
- Local JSONL evidence, an on-exit English terminal summary tree, and
  call-oriented HTML, Markdown and JSON reports.
- Protected existing-process attach, durable collector lifecycle, qualified
  Docker/containerd identities and bounded Kubernetes attribution.
- Non-privileged saved-run projection/offline viewing and receipt-owned local
  daemon install/inspect/uninstall operations that preserve saved runs.

See the [architecture](docs/design.md) for module boundaries, record semantics,
privacy rules and the limits of each subsystem.

## Try the fixture without root

With Rust/Cargo and a native build toolchain installed, run from the checkout:

```bash
cargo build -p apolysis-cli
make quickstart
```

This uses checked-in declarations and observed-event fixtures. It requires no
provider, sudo or live eBPF, and writes its results to `target/quickstart/`.
It demonstrates correlation; it does not observe an actual agent.

## Observe a native agent

Live observation requires Linux with kernel BTF, the required tracepoints and
BPF ring-buffer support. The provided live gates also require cgroup v2.
Building the BPF objects requires Clang/LLVM, `bpftool` and libbpf headers.
Install the selected agent in `PATH`, configure its normal authentication, and
have sudo access for the collector.

Build the CLI and matching BPF objects as your ordinary user:

```bash
APOLYSIS_REQUIRE_BPF=1 make build
```

The environment variable makes missing BPF prerequisites a build failure
instead of an optional skip. Then select an application explicitly:

```bash
target/debug/apolysis observe --agent claude
target/debug/apolysis observe --agent codex
target/debug/apolysis observe --agent pi
target/debug/apolysis observe --agent opencode
target/debug/apolysis observe --agent cursor
```

Run these commands without a leading `sudo`. Only the collector requests
elevation; the application runs as you. There is no default agent. Cursor uses
the installed `cursor-agent` executable; the other names select their matching
executables.

Put Apolysis options before `--` and the application's original arguments after
it. Argument boundaries and ordering are preserved:

```bash
target/debug/apolysis observe --agent pi -- --provider deepseek --model deepseek-flash
target/debug/apolysis observe --agent claude -- --help
```

Model availability, resume options and subcommands remain application-specific.
Standalone native help/version queries bypass collection and elevation. Native
stdout remains suitable for piping; Apolysis status messages use stderr.

| Apolysis option | Purpose |
| --- | --- |
| `--workspace <directory>` | Initial working directory; defaults to the current directory. |
| `--output-dir <parent>` | Parent for a new private capture directory. |
| `--bpf-object <path>` | Select the matching observer object explicitly. |
| `--allow-reason-summary` | Opt in to bounded, filtered declared text (user prompt intent and tool description). |
| `--shell-bridge /bin/bash` | Opt in to an inner shell for supported shell-tool attribution. |

The default shell marker may be hidden by an application's later `eval`
wrapping. The optional shell bridge exposes that marker at a supported exec
boundary, but introduces an inner shell: its cwd, variables and functions do
not propagate back to the outer tool shell. Recognized options that disable
hooks or move execution to remote, detached or shared-server processes are
rejected because this collector cannot cover them.

## Read the result

Exit through the application's normal mechanism. Apolysis completes correlation,
prints an English session summary tree on stderr (grouping tool calls by intent
and listing observed `network_connect`, `exec`, file and credential-path events), and
prints the report path. Captures default to
`$XDG_STATE_HOME/apolysis/captures`, or `$HOME/.local/state/apolysis/captures`
when XDG state is unset or not absolute. Each invocation gets a separate
private directory containing `evidence/`:

| File | Contents |
| --- | --- |
| `report.html` / `report.md` | Readable tool calls, reasons, related attempts and coverage gaps. |
| `result.json` | Application exit, capture health and structured report totals. |
| `intent.jsonl` / `intent.jsonl.reasons.jsonl` | Tool declarations and their optional declared reasons. |
| `timeline.jsonl` | Observed events, runtime metadata and diagnostics. |
| `correlation.jsonl` | Exact relations, weaker candidates, reason bindings and findings. |

An exact relation establishes an identifier link within the stated trust
boundary. It does not prove motive, authorization or task outcome. Selected file
and connect events report syscall return values and outcomes; these do not prove
remote effects or task success. Application exit zero is also insufficient.
Search, file-read and remote tools may have only semantic evidence. Missing
reasons remain unknown, and lost events remain visible as incomplete capture.

Native collection leaves full prompts, tool results and exec argument lists out
of exported evidence. Free-text reason summaries require explicit opt-in;
retained paths and declared text still need to be treated as private data.

## Validation and limits

Bounded real-provider/eBPF runs have passed for Claude Code, Codex, Pi and
OpenCode using the explicit shell bridge. Codex's noninteractive test also
explicitly selected workspace-write and hook-trust bypass; the daily launcher
does not add those options. Cursor's adapter and parameter path exist, but its
real tool-call validation remains blocked by unusable authentication. These
results do not qualify every version, default shell wrapping or sustained load.

The opt-in gate checks actual file contents, declaration-to-kernel attribution,
capture health, report generation and privacy assertions:

```bash
scripts/test-live-native-observe.sh --agent claude --require-all
```

It makes real provider requests, starts a privileged collector and uses the
application's noninteractive mode. It keeps generated evidence under `target/`.
Other native options can be supplied after `--`; `--require-all` treats missing
prerequisites as failures. Full kernel-event coverage, remote execution and
hostile-agent or tamper-resistant evidence guarantees remain outside this path.

## Develop

Saved runs can also be projected and viewed without root:

```bash
target/debug/apolysis run project --input <timeline.jsonl> --output <run.json>
target/debug/apolysis run view --input <run.json> --output <run.html>
```

The current qualification contract grants no Supported environment. Linux
6.12/x86_64 native host is Candidate; container/Kubernetes profiles remain
Experimental. Native provider demonstrations do not replace those gates.

```bash
make build
make test
make lint
git diff --check
```

`make test` runs Rust regressions plus hook and adapter tests; Node.js and Python
are used by test tooling. The native observation controller itself is Rust and
does not depend on Python. Live BPF, provider and Kubernetes gates are
explicit opt-ins. `make clean` removes Cargo build artifacts.

The source is organized into local collection/correlation, daemon, storage,
viewer and Kubernetes crates, `ebpf/` programs, `hooks/` adapters and `scripts/`
validation runners. Central Gateway/PostgreSQL/S3 and policy-enforcement planes
are historical code, outside the active workspace. The [architecture](docs/design.md)
maps these components and distinguishes implemented foundations from open work.

Start focused branches from updated `pre-release`, and submit Pull Requests
back to `pre-release` with verification, privilege assumptions, privacy checks
and cleanup notes. Require CI and review before integration; promote to `main`
through a separate release PR. Work is tracked through Pull Requests.

Do not commit credentials, private captures or provider transcripts. Report
security issues through GitHub private vulnerability reporting when available,
with the affected revision and a redacted reproduction. Apolysis's retention
rules do not change an agent application's own conversation history.

User-space code is licensed under [Apache-2.0](LICENSE); eBPF programs are
[GPL-2.0-only](LICENSES/GPL-2.0-only.txt).

# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [Simplified Chinese](README.zh-CN.md)

Apolysis is currently an experimental Linux runtime audit-telemetry and
accountability layer for AI agent workloads. It records a scoped subset of host
observations and syscall attempts, then heuristically correlates process, file,
network, credential, runtime, policy, and declared-intent records into an
ordered audit timeline.

The project is evolving toward an Agent Runtime Evidence & Policy Plane that
joins hook, SDK, OTLP, MCP, A2A, provider-outcome, and optional eBPF runtime
evidence across local, CI, vendor-hosted, container, and Kubernetes agent
environments. It is not a general agent orchestrator, sandbox, MCP gateway, or
SIEM.

![Apolysis live eBPF audit: the agent's declared workload is matched and an undeclared credential-path access attempt is flagged as missing_intent — recorded from a real observe run; the credential path is redacted in the timeline](docs/assets/codex-live-demo/live-ebpf-demo.gif)

Demo assets: [live asciinema cast](docs/assets/codex-live-demo/live-ebpf-demo.cast),
[zero-privilege quickstart cast](docs/assets/codex-live-demo/codex-live-demo.cast),
and [public evidence excerpt](docs/codex-live-demo-public-assets.md).

## Try It In Five Minutes (no root)

```bash
make build && make quickstart
```

This runs the intent-vs-observation accountability flow on a bundled fixture —
no root, no eBPF — and prints where declared intent and the fixture's observed
OS events diverge. See [Quickstart](docs/quickstart.md).

## Audit An Agent In CI (GitHub Action)

```yaml
- uses: 0xLaiHo/Apolysis@c00a84650e306d01b44e2fbd6b80f1395c852f74 # v0.3.0
  with:
    run: 'codex exec --json "run the project tests"'
```

One step records session-scoped kernel observations and syscall attempts for the
command, prints a digest into the job summary, and uploads the JSONL timeline as
an artifact. See [GitHub Action](docs/github-action.md).

## Current Status

`v0.3.0` is the latest public research release with a prebuilt Linux CLI,
bundled CO-RE eBPF object, release manifest, checksum, and AWS KMS-backed
release-artifact signing evidence. It fixes an observer race that could drop
all events for fast commands, adds a correlation summary, and warns when events
are dropped or truncated.

Apolysis is still experimental audit telemetry: current file and network
tracepoints describe syscall attempts unless an outcome is available; CLI
timelines are ordinary JSONL, while daemon mode can use a local hash-chain
envelope. Neither is an independently anchored forensic record.

The 26-week production-MVP direction starts with a versioned Agent Execution
Record, an authenticated Execution Evidence Gateway, durable storage, and
Minimum Console v0 for run inventory, separate coverage, timeline, source
health and findings. Later source integrations culminate in Investigation
Console v1 with Agent Run Graph, cross-run search, and bounded workflow action
before a controlled partner pilot. Every run will expose semantic, execution,
and outcome coverage separately.
These are roadmap targets, not current capabilities. Do not treat the current
Action as safe for untrusted repositories or Pull Requests until the public
path is hardened.

## Core Capabilities

- Live and fixture observation for process, file, network, bounded exec argv,
  and credential-path events, with explicit attempt/outcome limitations.
- Managed local agent launch with process-tree attribution for Codex and other
  command-line agents.
- Intent ingestion and heuristic correlation for declared tool calls versus
  observed host-side events.
- Runtime metadata correlation for local processes, Docker/containerd, and
  Kubernetes workloads.
- Ordered JSONL timelines, output rotation, daemon-local hash-chain
  verification, policy findings, and release-validation gates.

## Current Architecture

```text
Agent / tool runner
  └─ declared intent logs

Apolysis observer
  ├─ live eBPF events
  ├─ process tree attribution
  ├─ runtime metadata
  └─ policy evaluation

Apolysis correlation
  ├─ intent records
  ├─ observed host events
  └─ accountability findings

Recorded timeline
  ├─ JSONL timeline
  ├─ rotated local files
  └─ optional hash-chain verification
```

The design keeps three boundaries separate:

- Intent: what the harness or tool runner declared.
- Isolation: what the runtime allowed the workload to reach.
- Evidence: what the host and runtime actually observed.

Core crates:

- `apolysis-cli`: command-line entry point.
- `apolysis-observer`: fixture and live observer backends.
- `apolysis-core`: shared JSONL records and schema types.
- `apolysis-runtime`: local, Docker, and runtime metadata adapters.
- `apolysis-policy`: policy parser and decision logic.
- `apolysis-store`: append-only JSONL and hash-chain storage.
- `apolysis-daemon`: node-local service for longer-running deployments.

## Build And Test

```bash
make build
make test
make lint
```

Build only the CO-RE eBPF object:

```bash
make build-ebpf
```

Run the capability-aware live observer smoke test on a prepared Linux host:

```bash
make test-live
```

## Example: Audit A Local Agent Command

Input:

- Built binary: `target/debug/apolysis`
- Built BPF object: `target/ebpf/apolysis_observer.bpf.o`
- Policy file: `policies/local-dev.yaml`
- Agent command: `codex exec --json "run the project tests"`

Command:

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-audit \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex exec --json "run the project tests"
```

Key parameters:

- `--backend live`: use the live eBPF observer.
- `--session`: stable session id written into every record.
- `--policy`: policy file used for review and notification findings.
- `--output`: JSONL timeline path.
- `--bpf-object`: CO-RE observer object loaded by the live backend.
- `--workspace-root`: workspace boundary used for path handling.
- `--agent-kind`: agent adapter hint, for example `codex`.
- `--agent-run -- <command>`: let Apolysis start the agent and own the root
  process tree instead of asking the operator to find a PID manually.

Output:

```jsonl
{"record_type":"event","event_type":"exec","resource":"codex"}
{"record_type":"event","event_type":"file_open","resource":"path_token:..."}
{"record_type":"policy_violation","rule_id":"credentials.deny_read","decision":"notify"}
```

## Example: Correlate Declared Intent

Input:

- Codex response-item log: `.apolysis/codex-live/codex-response-items.jsonl`
- Observed timeline: `.apolysis/codex-live/timeline.agent-run.jsonl`
- Session id: `codex-local-audit`

Commands:

```bash
./target/debug/apolysis intent ingest \
  --adapter codex-jsonl \
  --input .apolysis/codex-live/codex-response-items.jsonl \
  --session codex-local-audit \
  --output .apolysis/codex-live/intent.codex.jsonl \
  --workspace-root "$PWD"

./target/debug/apolysis intent correlate \
  --intent-input .apolysis/codex-live/intent.codex.jsonl \
  --timeline-input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/intent-correlation.jsonl
```

Output:

```jsonl
{"record_type":"intent","intent_source":"codex","declared_action":"shell.command"}
{"record_type":"intent_correlation","match_basis":"process_executable"}
{"record_type":"accountability_finding","kind":"missing_intent","decision":"review"}
```

Keep generated timelines, Codex logs, and reports under `.apolysis/` or
`target/`. Do not commit captured workload data or credentials.

## Key Documents

- [Quickstart](docs/quickstart.md)
- [GitHub Action](docs/github-action.md)
- [JSONL schema](docs/jsonl-schema-v1.md)
- [Threat model](docs/threat-model.md)
- [Hash-chain verification](docs/hash-chain-verification.md)
- [Timeline shipping](docs/timeline-shipping.md)
- [Codex live demo runbook](docs/codex-live-demo-runbook.md)
- [Codex live demo launch blog draft](docs/codex-live-demo-launch-blog.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

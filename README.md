# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [Simplified Chinese](README.zh-CN.md)

Apolysis is a Linux runtime accountability layer for AI agent workloads. It
records host-side evidence for what an agent session actually did, then
correlates process, file, network, credential, runtime, policy, and declared
intent records into an append-only audit timeline.

It is not a sandbox, approval UI, MCP gateway, or SIEM. It is the evidence
layer that helps operators review agent side effects independently of the
agent harness.

![Apolysis live eBPF audit: the agent's declared workload is matched and an undeclared credential read is flagged as missing_intent — recorded from a real observe run; the credential path is redacted in the evidence](docs/assets/codex-live-demo/live-ebpf-demo.gif)

Demo assets: [live asciinema cast](docs/assets/codex-live-demo/live-ebpf-demo.cast),
[zero-privilege quickstart cast](docs/assets/codex-live-demo/codex-live-demo.cast),
and [public evidence excerpt](docs/codex-live-demo-public-assets.md).

## Try It In Five Minutes (no root)

```bash
make build && make quickstart
```

This runs the intent-vs-side-effect accountability flow on a bundled fixture —
no root, no eBPF — and prints where an agent's declared intent and its real OS
side effects diverge. See [Quickstart](docs/quickstart.md).

## Audit An Agent In CI (GitHub Action)

```yaml
- uses: 0xLaiHo/Apolysis@main
  with:
    run: 'codex exec --json "run the project tests"'
```

One step records kernel-level evidence of what the command actually did on the
runner, prints a digest into the job summary, and uploads the JSONL timeline as
an artifact. See [GitHub Action](docs/github-action.md).

## Current Status

`v0.2.0` is the first signed public release with a prebuilt Linux CLI, bundled
CO-RE eBPF object, release manifest, checksum, and AWS KMS-backed signing
evidence. Apolysis remains an audit and accountability layer, not a full
sandbox provider or compliance-certified platform.

## Core Capabilities

- Live and fixture observation for process, file, network, bounded exec argv,
  and credential-path events.
- Managed local agent launch with process-tree attribution for Codex and other
  command-line agents.
- Intent ingestion and correlation for declared tool calls versus observed
  host-side side effects.
- Runtime metadata correlation for local processes, Docker/containerd, and
  Kubernetes workloads.
- Append-only JSONL evidence, output rotation, hash-chain verification, policy
  findings, release-validation gates, and signed release-artifact handoff.

## Architecture

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

Append-only evidence
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
- [Starter issues](docs/starter-issues.md)

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
  findings, and release-validation gates.

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

## Minimal Usage

Observe a managed local agent command:

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

Ingest and correlate declared intent:

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

Keep generated timelines, Codex logs, and reports under `.apolysis/` or
`target/`. Do not commit captured workload data or credentials.

## Key Documents

- [JSONL schema](docs/jsonl-schema-v1.md)
- [Threat model](docs/threat-model.md)
- [Release artifact dry run](docs/release-artifact-dry-run.md)
- [Hash-chain verification](docs/hash-chain-verification.md)
- [Codex live demo runbook](docs/codex-live-demo-runbook.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Starter issues](docs/starter-issues.md)

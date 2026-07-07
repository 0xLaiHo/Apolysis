# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [Simplified Chinese](README.zh-CN.md)

**Your AI coding agent says it ran the tests. Did it also read your cloud keys?**

Apolysis is a Linux runtime accountability layer for AI agents. It records
host-side evidence of what an agent session actually did — every process, file,
network connection, and credential path — then flags anything the agent never
declared, in an append-only audit timeline you can review independently of the
agent's own logs.

It is not a sandbox, approval UI, MCP gateway, or SIEM. It is the evidence layer
that helps you review agent side effects independently of the agent harness.

![Codex live demo: Apolysis matches the declared workload and flags a redacted fake credential side effect as missing intent](docs/assets/codex-live-demo/codex-live-demo.gif)

Demo assets: [asciinema cast](docs/assets/codex-live-demo/codex-live-demo.cast)
and [public evidence excerpt](docs/codex-live-demo-public-assets.md).

## Try It In Five Minutes (no root)

```bash
make build && make quickstart
```

On a bundled sample — no root, no eBPF, no kernel setup — you see the whole idea:

```text
Apolysis accountability summary  (session: codex-mismatch-demo)
  1 side effect(s) matched declared intent, 1 finding(s) with no declared intent
  ✓ matched   crates/apolysis-cli/tests/intent.rs
            declared as: cargo test -p apolysis-cli --test intent  [process_command_exact]
  ⚠ missing_intent   credential_read /tmp/apolysis-demo-home/.aws/credentials
            by: python3 scripts/read-demo-credential.py
            observed side effect has no matching declared intent  [review]
```

The agent declared one action — run the tests (`✓ matched`). It also read
`.aws/credentials` (`⚠ missing_intent`), which nothing declared. That gap is the
whole point. Full walkthrough: [Quickstart](docs/quickstart.md).

## Why

- **Harness logs show intent, not behavior.** "Ran the tests" in a tool-call log
  does not capture the `curl`, the `npm postinstall` hook, or the credential read
  a subprocess actually performed.
- **Sandboxes bound what an agent can reach, not what it attempted** — and they do
  not tie a declared tool call to an OS side effect. Apolysis does.
- **You are accountable for a repo, CI runner, or cluster you may not own the
  agent for.** Apolysis gives you evidence you do not have to take the harness's
  word for.

## What It Does

- **Observe** — capture process, file, network, bounded exec argv, and
  credential-path events, live via eBPF or from a fixture, scoped to one session.
- **Correlate** — join the agent's declared intent against the observed timeline
  and surface `missing_intent` and policy findings.
- **Record** — a redacted, append-only JSONL timeline with optional hash-chain
  verification, ready to ship to your existing log stack.

Runtime metadata for local, Docker/containerd, and Kubernetes ties each event to
its container, pod, service account, and cgroup.

## How It Works

Apolysis keeps three boundaries separate and owns the third:

- **Intent** — what the harness or tool runner declared.
- **Isolation** — what the runtime allowed the workload to reach (Docker, gVisor,
  Kata, Kubernetes).
- **Evidence** — what the host and runtime actually observed. **This is Apolysis.**

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

## Current Status

`v0.2.0` is the first signed public release, with a prebuilt Linux CLI and a
bundled CO-RE eBPF object. Apolysis is an audit-and-accountability layer, not a
full sandbox provider or a compliance-certified platform. The
[threat model](docs/threat-model.md) states exactly what it does and does not
prove, including where host-side observation is blind.

## Use It Live On Your Own Agent

Two steps: record a real timeline with the eBPF observer, then correlate it
against the agent's declared intent.

### 1. Record (Linux, root / CAP_BPF)

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

- `--backend live` — use the live eBPF observer.
- `--session` — stable session id written into every record.
- `--policy` — policy file used for review and notification findings.
- `--bpf-object` — CO-RE observer object loaded by the live backend.
- `--agent-run -- <command>` — let Apolysis start the agent and own the root
  process tree instead of asking you to find a PID by hand.

Output:

```jsonl
{"record_type":"event","event_type":"exec","resource":"codex"}
{"record_type":"event","event_type":"file_open","resource":"path_token:..."}
{"record_type":"policy_violation","rule_id":"credentials.deny_read","decision":"notify"}
```

### 2. Correlate

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
  --output .apolysis/codex-live/intent-correlation.jsonl \
  --summary
```

Output:

```jsonl
{"record_type":"intent","intent_source":"codex","declared_action":"shell.command"}
{"record_type":"intent_correlation","match_basis":"process_executable"}
{"record_type":"accountability_finding","kind":"missing_intent","decision":"review"}
```

`--summary` prints the human-readable digest shown in the quickstart. Keep
generated timelines, Codex logs, and reports under `.apolysis/` or `target/`, and
do not commit captured workload data or credentials.

## Build And Test

```bash
make build   # build the CLI and the CO-RE eBPF object
make test
make lint
```

- `make build-ebpf` — build only the CO-RE eBPF object.
- `make test-live` — capability-aware live observer smoke test on a prepared
  Linux host.

## Architecture

Core crates:

- `apolysis-cli` — command-line entry point.
- `apolysis-observer` — fixture and live observer backends.
- `apolysis-core` — shared JSONL records and schema types.
- `apolysis-runtime` — local, Docker, and runtime metadata adapters.
- `apolysis-policy` — policy parser and decision logic.
- `apolysis-store` — append-only JSONL and hash-chain storage.
- `apolysis-daemon` — node-local service for longer-running deployments.

## Key Documents

- [Quickstart](docs/quickstart.md)
- [JSONL schema](docs/jsonl-schema-v1.md)
- [Threat model](docs/threat-model.md)
- [Hash-chain verification](docs/hash-chain-verification.md)
- [Timeline shipping](docs/timeline-shipping.md)
- [Codex live demo runbook](docs/codex-live-demo-runbook.md)
- [Codex live demo launch blog draft](docs/codex-live-demo-launch-blog.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Starter issues](docs/starter-issues.md)

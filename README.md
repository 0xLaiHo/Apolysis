# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [Simplified Chinese](README.zh-CN.md)

Apolysis is an experimental **eBPF Agent Runtime Observability Platform** for
operator-controlled Linux environments. It groups supported process, file,
network, and credential-related runtime observations into an Agent Run,
attributes them to process and workload identities, and makes collector loss,
truncation, and unsupported paths explicit.

The project is resetting its scope around this Linux runtime workflow. eBPF is
the required primary observation source, not an optional add-on to a broader
cross-provider evidence platform. Apolysis is not an Agent orchestrator,
sandbox, policy-enforcement engine, MCP gateway, SIEM, or multi-tenant evidence
SaaS.

![Apolysis live eBPF audit: the declared Agent workload is matched and an undeclared credential-path access attempt is marked missing_intent; credential paths are redacted in the timeline](docs/assets/codex-live-demo/live-ebpf-demo.gif)

Demo assets: [live asciinema cast](docs/assets/codex-live-demo/live-ebpf-demo.cast),
[unprivileged quickstart cast](docs/assets/codex-live-demo/codex-live-demo.cast),
and [public evidence excerpt](docs/codex-live-demo-public-assets.md).

## Five-minute unprivileged tour

```bash
make build && make quickstart
```

The quickstart runs the observation and optional declared-intent comparison
against packaged fixtures. It does not require root or eBPF and is intended to
show the current record and investigation experience. See
[Quickstart](docs/quickstart.md).

## Product question

For a supported Agent Run, Apolysis should let an operator answer:

1. Which processes did the Agent start?
2. Which supported file, network, and credential operations were observed?
3. Which container, cgroup, Pod, or process identity owns each observation?
4. Did the operation succeed, fail, or remain unknown?
5. Was the collector healthy, and where are the observation gaps?

The product does not claim that an unobserved operation did not occur. It only
describes activity inside its declared scope and capability boundary.

## Active product boundary

| In scope | Not in active scope |
| --- | --- |
| Operator-controlled Linux hosts | Vendor-hosted Agent kernels unavailable to the operator |
| Managed Agent launch, PID-tree, and cgroup scope | General Agent orchestration or sandboxing |
| Process, selected file, network, and credential observations | Indiscriminate full-syscall or plaintext capture |
| Local, Docker/containerd, and bounded Kubernetes attribution | Cross-provider Hook, OTLP, MCP, and A2A integration matrix |
| Collector health, loss, truncation, and capability gaps | Remote outcome verification and portable evidence custody |
| Local run storage, query, and operator viewer | Multi-tenant Gateway, PostgreSQL/S3 platform, billing, or HA |
| Review-oriented findings | BPF-LSM blocking, approval workflow, or universal enforcement |

Provider or harness metadata may be added later as optional context. It cannot
replace the eBPF runtime source or silently upgrade an inferred relationship to
an exact one.

## Current capabilities

- CO-RE eBPF observation of fork, exec, exit, outcome-aware selected file
  operations, and outcome-aware network connect operations.
- A versioned kernel/userspace ABI and per-Agent-Run capability manifest that
  states the attached event sources and supported outcome semantics.
- Per-Agent-Run collector lifecycle records with durable starts, periodic
  health/loss checkpoints, explicit normal or failed terminal states, and a
  persisted restart gap when the daemon recovers an unfinished instance.
- Stable in-run runtime identity across PID reuse, exec, and numeric cgroup-ID
  reuse, with exact versus inferred attribution recorded explicitly.
- PID-tree, single-cgroup, and multi-cgroup observation scopes.
- Managed local Agent launch and runtime metadata correlation for local,
  Docker/containerd, and Kubernetes prototypes.
- Content-off persistence for exec arguments and process commands, with
  credential and network redaction.
- Ordered JSONL output, rotation, optional local hash-chain envelopes, and
  typed diagnostics for drops, map pressure, ABI mismatches, decode failures,
  and truncation.
- Agent-Run-scoped Observation Gaps for unmatched or still-pending selected
  file and network-connect entry/exit pairs, including isolated multi-cgroup
  daemon scopes.
- Optional Codex declared-intent ingestion and heuristic mismatch findings.

Selected file operations and network connect use bounded entry/exit matching
and report return value and errno. File outcomes are succeeded, failed, or
denied; connect additionally supports pending. The collector does not observe
every Linux operation path.

## Target shape

```text
Agent command / container / Pod
  -> Observation Scope
  -> eBPF Collector
     - process lifecycle
     - selected file operations
     - network connections
     - collector health and gaps
  -> userspace normalization and redaction
  -> bounded local store
  -> CLI and saved-run viewer
```

The privileged collector and non-privileged operator viewer remain separate
trust boundaries. Remote export and any central multi-tenant evidence plane are
deferred beyond the bounded beta.

## Supported environments

| Environment | Direction |
| --- | --- |
| Local Linux Agent CLI | First stable workflow |
| Docker/containerd on operator-controlled Linux | Stable target after local collector correctness |
| Kubernetes node and Pod attribution | Bounded beta after container identity is stable |
| Linux self-hosted CI runner | Supported through the CLI managed-run boundary; no maintained composite Action |
| macOS, Windows, or vendor-managed Agent runtime | Unsupported for eBPF runtime observation |

## Current repository state

`v0.3.0` remains the latest public research release and demonstrates the live
collector, managed Agent launch, JSONL timeline, privacy redaction, and release
packaging. The active Cargo workspace is now limited to eight crates: core,
observer, accountability findings, local storage, daemon, CLI, Kubernetes
metadata, and visibility assessment. Superseded contracts, central services,
policy actuation, Agent feedback control, sandbox execution, and broad
production-qualification prototypes have left active builds and default gates.

The scope reset is a roadmap decision, not a retroactive production claim.
Apolysis remains experimental until the supported collector, attribution,
failure, performance, and privacy paths pass their new bounded beta gates.
The first qualification contract now names Linux 6.12/x86_64 native host as a
Candidate only; no environment is yet Supported and numeric performance
budgets remain evidence-gated. See the
[Beta qualification envelope](docs/qualification-envelope.md).

## Build and test

```bash
make build
make test
make lint
```

Build only the CO-RE eBPF object:

```bash
make build-ebpf
```

Run the opt-in live observer test on a prepared Linux host:

```bash
make test-live
```

Privileged tests skip cleanly when Linux BTF, cgroup v2, tracepoints, or the
required BPF capabilities are unavailable.

## Live managed Agent example

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-observation \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex exec --json "run the project tests"
```

Do not place secrets in the managed command or arguments. Raw command content
is disabled at the persistence boundary, but privileged in-kernel capture and
third-party workload behavior still require a documented threat model.

## High-level roadmap

1. Keep the active workspace bounded to eBPF collection, Observation Scope,
   attribution, local storage, daemon, CLI, and operator investigation.
2. Qualify collector lifecycle, health/gap reporting, and the local Agent Run
   investigation workflow while preserving outcome-aware semantics and stable
   in-run runtime identity.
3. Qualify container attribution and then a bounded Kubernetes beta before
   considering any central platform expansion.

## Documentation

- [Scope decision](docs/adr/0004-focus-on-ebpf-agent-observability.md)
- [Design](docs/design.md)
- [Roadmap](docs/roadmap.md)
- [Bounded Beta qualification plan](docs/beta-qualification-plan.md)
- [Quickstart](docs/quickstart.md)
- [JSONL schema](docs/jsonl-schema-v1.md)
- [Threat model](docs/threat-model.md)
- [Visibility validation](docs/visibility-validation.md)
- [Live demo runbook](docs/codex-live-demo-runbook.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

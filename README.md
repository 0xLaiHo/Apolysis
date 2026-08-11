# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](https://github.com/0xLaiHo/Apolysis/blob/main/LICENSE)

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

![Apolysis live eBPF audit: the declared Agent workload is matched and an undeclared credential-path access attempt is marked missing_intent; credential paths are redacted in the timeline](https://raw.githubusercontent.com/0xLaiHo/Apolysis/main/docs/assets/codex-live-demo/live-ebpf-demo.gif)

Demo assets: [live asciinema cast](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/live-ebpf-demo.cast),
[unprivileged quickstart cast](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/codex-live-demo.cast),
the [public summary](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/summary.json), and the
[redacted evidence excerpt](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/evidence-excerpt.jsonl).
Raw live timelines are not committed; public assets are curated, bounded, and
redacted before publication.

## Five-minute unprivileged tour

```bash
make build && make quickstart
```

The quickstart runs the observation and optional declared-intent comparison
against packaged fixtures. It does not require root or eBPF. The fixture shows
one declared action matched to an observation and one undeclared credential
read reported as `missing_intent`; it writes generated output only below
`target/quickstart/`.

## Product question

For a supported Agent Run, Apolysis should let an operator answer:

1. Which processes did the Agent start?
2. Which supported file, network, and credential operations were observed?
3. Which container, cgroup, Pod, or process identity owns each observation?
4. Did the operation succeed, fail, or remain unknown?
5. Was the collector healthy, and where are the observation gaps?
6. Which bounded findings require operator review?

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
- Managed local Agent launch plus protected existing-process attach with an
  explicit late-attach Collection Boundary.
- Existing-process admission qualifies the current root; exact in-run event
  identity begins after activation.
- Qualified Docker/containerd runtime binding and bounded source recovery from
  stable, complete inventories. The exact identity, transition, and gap
  contracts are defined in the design document.
- Kubernetes metadata correlation remains a bounded beta target.
- Content-off persistence for exec arguments and process commands, with
  credential and network redaction.
- Ordered JSONL output, rotation, optional local hash-chain envelopes, and
  typed diagnostics for drops, map pressure, ABI mismatches, decode failures,
  and truncation.
- Manifest-v2-verified Linux daemon packaging and bounded `apolysis daemon
  install`, `inspect`, and `uninstall` operations over a fixed managed path
  set with receipt-owned replacement and removal. Staged-root operations never
  activate systemd, interrupted managed changes recover fail closed on reopen,
  and default uninstall preserves saved Agent Run state.
- Deterministic, non-privileged projection of one saved Agent Run into a
  queryable Agent Observation Record with independent evidence, collector
  health, and review states. Plain/rotated JSONL and verified hash-chain input
  are bounded and fail closed on corruption or mixed runs.
- Deterministic, non-privileged viewing of one Agent Observation Record as a
  private, self-contained offline HTML investigation. It keeps the three state
  axes independent and links Findings to source-ordered observations.
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
| Linux self-hosted CI runner | CLI managed-run path only; no maintained composite Action |
| macOS, Windows, or vendor-managed Agent runtime | Unsupported for eBPF runtime observation |

## Current repository state

`v0.3.0` remains the latest public research release and demonstrates the live
collector, managed Agent launch, JSONL timeline, privacy redaction, and release
packaging. The active Cargo workspace is now limited to ten crates: core,
observer, accountability findings, local storage, daemon, CLI, saved-run
viewer, Kubernetes metadata, visibility assessment, and release verification.
Superseded contracts, central services, policy actuation, Agent feedback
control, sandbox execution, and broad production-qualification prototypes have
left active builds and default gates.

The local `apolysis run project` path now writes one private, atomic JSON Agent
Observation Record for a saved run. `apolysis run view` validates exactly one
such v1 record and writes a private, self-contained offline HTML investigation.
The local projection and viewer do not add live tailing, cross-run search, a
central query service, or a change to the experimental support status.

The local daemon operations direction now includes a manifest-verified Linux
bundle and a bounded, state-preserving host lifecycle. Its detailed filesystem,
recovery, and qualification contracts live in the design; this work does not
change the experimental support status by itself.

The D1/D2 runtime-binding implementation, deterministic contracts, and retained
non-destructive qualification are complete for both Docker and an independently
isolated private standalone containerd runtime. The evidence remains
profile-specific: it does not extend Docker claims to containerd or either
runtime's claims to Kubernetes. Destructive runtime-service restart, K1/VKE,
and release qualification remain open. None of these results promotes a
profile.

The scope reset is a roadmap decision, not a retroactive production claim.
Apolysis remains experimental until the supported collector, attribution,
failure, performance, and privacy paths pass their new bounded beta gates.
The qualification contract names Linux 6.12/x86_64 native host as Candidate;
no environment is yet Supported, while container and Kubernetes profiles
remain Experimental. The exact machine-readable authority and promotion rules
are described in the [design](docs/design.md).

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

Project a saved run without root access:

```bash
./target/debug/apolysis run project \
  --input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/agent-observation-record.json
```

Render that record as an offline Saved Run Viewer without root access:

```bash
./target/debug/apolysis run view \
  --input .apolysis/codex-live/agent-observation-record.json \
  --output .apolysis/codex-live/saved-run-view.html
```

Verify a copied hash-chain timeline without modifying it:

```bash
./target/debug/apolysis verify hash-chain \
  --input /var/lib/apolysis/sessions/<agent-run-id>/timeline.jsonl \
  --output target/hash-chain-verification.json
```

Exit `0` is valid, `1` is a written failed-verification report, and `2` means
the command could not run.

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
2. Validate least-privilege K1 node/Pod attribution on the designated,
   runtime- and network-ready VKE test cluster as an explicitly bounded beta.
3. Keep destructive runtime-service restart qualification separate and prepare
   a release without extending Docker evidence to containerd or Kubernetes.
4. Promote a release only after applicable kernel, runtime, privacy,
   performance, packaging, cleanup, and no-silent-gap gates pass.

## Contributing

Use a focused branch and submit changes through the repository's integration
Pull Request workflow. Follow the checked-in automation and Pull Request
template for the applicable validation and operational disclosures. Never
commit secrets, kubeconfigs, signing material, private captures, generated
timelines, or local release artifacts.

## Security reporting

Apolysis is observability, not a sandbox or independent attestation boundary.
Report vulnerabilities through GitHub private vulnerability reporting. If it
is unavailable, open only a minimal public notice and do not include exploit
details, secrets, private logs, paths, argv, socket values, labels, annotations,
or payloads. Reports should identify the affected commit or release,
reproduction boundary, required privileges, and impact on confidentiality,
integrity, availability, or observation accuracy.

## Documentation

- [English design and complete product contract](docs/design.md)
- [Simplified Chinese design and complete product contract](docs/design.zh-CN.md)

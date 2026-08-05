# Bounded Beta Qualification Plan

> English | [Simplified Chinese](beta-qualification-plan.zh-CN.md)
> Authority: [roadmap.md](roadmap.md) and
> [ADR-0004](adr/0004-focus-on-ebpf-agent-observability.md)

This document turns the active roadmap into an executable qualification
program. It does not expand product scope or record per-commit progress. Work
status and detailed acceptance evidence live in focused Pull Requests.

## Destination

The program is complete when Apolysis can be promoted from `pre-release` to
`main` as a bounded eBPF Agent runtime observability Beta with:

- stable local Linux and Docker/containerd Agent Run workflows;
- Kubernetes node and Pod attribution labelled Beta;
- an Agent Observation Record that exposes supported Runtime Observations,
  Runtime Identity, Collector Capability, Collector Health, findings, and
  Observation Gaps without requiring raw JSONL inspection;
- documented and tested kernel, runtime, privacy, performance, retention, and
  failure envelopes; and
- every applicable roadmap no-go criterion closed.

The destination excludes central ingest, multi-tenant storage, provider
semantics, remote outcome verification, and enforcement.

## Program rules

- Each work item starts from the latest `pre-release`, uses one focused branch,
  and is tracked by one Pull Request targeting `pre-release`.
- A Pull Request declares its purpose, non-goals, acceptance criteria,
  dependencies, exact verification, privilege assumptions, privacy checks, and
  rollback behavior.
- Kernel, runtime, Kubernetes, and performance claims require an explicit live
  gate. A skipped gate records a limitation and cannot close the corresponding
  qualification item.
- English and Chinese README, design, and roadmap documents remain synchronized
  when product direction or maturity changes.
- Execution may continue through this program one work item at a time; planning
  artifacts do not count as delivery.

## Work graph

| Work item | Outcome | Depends on |
| --- | --- | --- |
| C1 Per-scope Observation Gaps | Attribute network pairing counters by cgroup and persist honest Agent-Run-scoped gaps in the multi-cgroup daemon | none |
| C2 Remaining operation outcomes | Add bounded entry/exit results and missing-pair gaps for the supported file operation set | none |
| C3 Stable Runtime Identity | Survive PID reuse and exec generation without promoting heuristic matches to Exact Relations | none |
| C4 Collector lifecycle | Persist start, health/loss checkpoints, terminal state, and explicit stop reason; fail loud on incomplete lifecycle | none |
| Q1 Qualification envelope | Freeze the candidate kernel/runtime contract and measurement protocol, then grant support only after retained live evidence freezes CPU, memory, latency, and event-loss budgets | none |
| L1 Protected existing-process attach | Attach with Runtime Identity validation and an explicit late-attach Observation Gap | C3, C4 |
| L2 Agent Observation Record projection | Produce one queryable run aggregate and summary over observation, capability, identity, health, finding, and gap records | C1, C2, C3, C4 |
| L3 Non-privileged saved-run viewer | Complete the representative investigation without raw JSONL or privileged access | L2 |
| L4 Local daemon operations | Qualify install, health, stop, cleanup, permissions, retention, and failure recovery | C4, L2 |
| D1 Container identity | Stabilize Docker/containerd cgroup and container attribution across churn and PID reuse | C3, C4 |
| D2 Runtime recovery | Qualify daemon restart and Docker/containerd runtime socket recovery | D1, C4 |
| K1 Kubernetes attribution and deployment | Bind Pod/runtime identity and deploy a least-privilege node collector with a non-privileged viewer path | D1, D2, L2, L3 |
| K2 VKE qualification | Validate representative workloads, reschedule, sensor loss, runtime boundaries, cleanup, and privacy on the designated VKE cluster | K1, Q1 |
| R1 Beta release | Close all applicable no-go criteria, prepare release metadata, promote `pre-release` to `main`, tag, and publish | C1-C4, Q1, L1-L4, D1-D2, K1-K2 |

Items with no dependencies form the initial frontier. They are ordered C1,
C2, C3, C4, then Q1 so that correctness gaps are closed before UI and
environment breadth.

## Completion gates

### Collector correctness

- Every declared operation/outcome is backed by its actual attached sources
  and tested entry/exit semantics.
- Missing entry, missing exit, unsupported paths, reserve failure, map pressure,
  truncation, decode failure, restart, and incomplete flush cannot yield a
  clean or complete Agent Observation Record.
- Runtime Identity distinguishes PID reuse and exec generations within its
  declared boundary.
- Content-off persistence prevents raw argv, prompt, response, tool payload,
  credential, private path, and private network content from crossing the
  default persistence seam.

### Local product

- Managed launch and protected attach both declare their collection boundary.
- The CLI or viewer answers the six roadmap investigation questions without
  requiring raw JSONL or kernel traces.
- The viewer is non-privileged, and every displayed fact resolves to a typed
  source record.
- Install, shutdown, cleanup, retention, permissions, and corruption recovery
  are bounded and tested.

### Container and Kubernetes

- Container and Pod attribution never relies on PID-only, name-only, or
  timing-only matching.
- Runtime restart, container churn, Pod reschedule, sensor loss, and unsupported
  guest or remote paths remain visible as identity transitions or Observation
  Gaps.
- Kubernetes validation uses the designated VKE cluster without copying,
  printing, or committing credentials or captured private workload data.

### Release

- Local, CI, live-kernel, runtime, Kubernetes, privacy, performance, packaging,
  install, upgrade, uninstall, and rollback evidence is linked from the release
  Pull Request.
- Required CI and human review pass on the `pre-release` to `main` promotion.
- Documentation names only supported or explicitly experimental profiles.

## Decisions still to resolve

The focused work items must settle these details before their dependent items
start:

- the Q1 Candidate contract is Linux 6.12/x86_64 native host and its versioned
  synthetic workloads, paired capture order, monotonic event window, exact
  count reconciliation, isolated collector resource sampling, and pair-level
  bootstrap summary with phase-scoped burst loss are fixed, but exact numeric
  budgets and any Supported promotion remain blocked on enough retained
  privileged live evidence;
- the saved-run viewer interaction and presentation shape after L2 freezes the
  queryable Agent Observation Record; and
- the Kubernetes least-privilege deployment shape after container identity and
  runtime recovery are qualified.

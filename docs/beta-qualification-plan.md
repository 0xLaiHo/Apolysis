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
| L1 Protected existing-process attach | Admit an existing tree only through a registration-qualified current root or unique inferred discovery, reject raw PID scope, activate from seeded identities, and persist one ordered late-attach boundary gap | C3, C4 |
| L2 Agent Observation Record projection | Produce one queryable run aggregate and summary over observation, capability, identity, health, finding, and gap records | C1, C2, C3, C4 |
| L3 Non-privileged saved-run viewer | Investigate exactly one Agent Observation Record v1 through a private, standalone offline view without raw JSONL or privileged access | L2 |
| L4 Local daemon operations | Qualify the exact-five-artifact manifest, fixed-path inspect/plan/apply lifecycle, receipt ownership, staged-root behavior, concrete systemd health/stop, state-preserving uninstall, retention, and failure recovery | C4, L2 |
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
- Protected-attach identity normalizes TGIDs and uses a half-open USER_HZ start
  interval until kernel bookkeeping matches during seeding or later. Only
  post-activation emitted events carrying the matched kernel start time plus
  process/exec generations receive exact event identity within that collector
  run; root-selection confidence remains separate.
- Content-off persistence prevents raw argv, prompt, response, tool payload,
  credential, private path, and private network content from crossing the
  default persistence seam.

### Local product

- Managed launch and protected attach both declare their collection boundary.
- `apolysis run project` produces a deterministic single-run aggregate from a
  plain contiguous rotation set or a fully verified hash chain; chain payloads
  are not exposed before verification. Batch, byte, and record limits cover all
  composed inputs together.
- Malformed or mixed-run input, content-policy violations, illegal lifecycle
  order, and duplicate canonical observations fail closed. Mixed source
  integrity and unknown additive records are indeterminate; gaps, loss, and a
  missing terminal cannot be complete.
- Partial or fictitious capability contracts and unresolved Finding evidence
  references are typed issues and cannot be complete. Exact identity requires
  a canonical post-activation kernel relation and its full stable tuple.
- Projection output is published through a private atomic file, refuses
  symlink, non-regular, or input-alias targets, and preserves source files and
  any existing output on pre-publication failure without echoing payloads.
- Protected attach is available only through explicit registration or unique
  inferred discovery; raw `--scope-pid` is rejected. Qualification covers boot
  ID, start tick, executable, command fingerprint, workspace, zombie exclusion,
  live-root cwd containment, pidfd liveness, and per-candidate initial PID/time
  namespace failures. A registration match
  is recorded as `registration_qualified` for the root visible when its pidfd is
  opened, not as continuity since registration creation.
- Live activation evidence covers inactive scope, tracepoint attachment, root
  and descendant TGID seeding, repeated snapshots, a per-seeded-candidate pidfd
  sandwich plus exit-hook removal, root requalification, then activation.
- Every successful protected attach emits exactly one `late_attach` gap with
  `operation:"collector_lifecycle"` and `count:1` before capability and
  `started`; the count is rendered as one unknown-history boundary, not a
  missing-event estimate. The three-record durable batch survives one rotation
  decision and rolls back on injected write or sync failure.
- Qualification must model and document the residual pre-anchor ambiguity: a
  registration root can be substituted between registration creation and root
  `pidfd_open` by the same PID/tick/executable/command, and a lineage candidate
  can be substituted between snapshot and `pidfd_open` by the same
  PID/tick/lineage. It must not present the post-anchor seeded-candidate race as
  residual or overclaim pre-anchor continuity.
- The CLI or viewer answers the six roadmap investigation questions without
  requiring raw JSONL or kernel traces.
- `apolysis run view` accepts exactly one internally consistent Agent
  Observation Record v1 and publishes deterministic, standalone offline HTML
  through a private atomic mode-`0600` file. It rejects unsafe input/output
  types and aliases without replacing a valid output on pre-publication
  failure.
- The viewer is non-privileged, treats stored text as untrusted data, keeps
  Evidence State, Collector Health, and Review State independent, and makes
  every displayed fact traceable through a record path or `source_ordinal`.
  Findings resolve to supporting Runtime Observations.
- Active, failed, incomplete, mixed-integrity, gap-bearing, or otherwise
  limited records retain those states and never render as clean or complete.
  Because v1 lacks an authoritative parent Runtime Identity link, the viewer
  shows the Exact Runtime Identity roster and reported PID/PPID facts without
  constructing a canonical process tree.
- Release manifest schema v2 contains exactly the `apolysis`, `apolysisd`, and
  `apolysisd-health` binaries, the CO-RE object, and the systemd unit, with the
  required kind, digest, size, and mode. Missing, duplicate, additional, or
  changed bundle content is rejected. Verification also rejects non-canonical
  or extended archive structure and requires libbpf parsing of the real CO-RE
  object through `bpftool gen skeleton`.
- Daemon install, inspect, managed replacement, and uninstall map only that
  closed set to documented fixed paths. Inspect/plan/apply preflights the full
  set and binds a plan to the source and target snapshot. Receipt ownership is
  required for replacement and removal; symlink, non-regular, hard-linked,
  unmanaged, changed, or stale state fails before publication. Identical
  reinstall is a no-op, and default uninstall preserves `/var/lib/apolysis`
  and unrelated files. Owner and full mode proofs, including special bits, are
  part of the receipt boundary.
- A synchronized private operation journal precedes file publication. Reopen
  testing proves rollback of pre-commit interruption and completion of
  committed install or uninstall cleanup; inspection reports that recovery.
  Unknown or changed transaction state fails closed. This gate proves durable
  convergence rather than instantaneous multi-path visibility.
- The deterministic staged-root gate exercises filesystem publication,
  rollback, permissions, and state preservation without activating systemd or
  eBPF. It cannot close the separate opt-in privileged gate, which uses the
  shipped concrete systemd unit, reuses the daemon health protocol, waits for
  eBPF/storage readiness, verifies bounded SIGTERM shutdown and restart
  recovery, and proves cleanup on a real host.
- Destructive retention takes time only from the daemon clock, validates the
  open timeline descriptor and directory identity, blocks late persistence
  with a tombstone, and uses a synchronized staging/committed journal. Startup
  rolls staging back and completes committed cleanup; replacement, unknown
  content, or corrupt/conflicting recovery state fails closed. Hash-chain
  recovery likewise rejects links and path replacement and keeps recoverable
  tail bytes in a private create-new quarantine file. Destructive apply is
  limited to the local default context; non-default requests do not mutate
  state. The independent terminal retention catalog fails closed at its bound
  without consuming active-run capacity.

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

## Adopted local-viewer contract

L3 uses the frozen L2 Agent Observation Record as its only input contract. The
viewer is a deterministic local presentation boundary, not a new evidence
source: it does not reproject raw JSONL, rewrite summary states, infer parent
identity, or contact a live observer. Live tailing, cross-run search, remote
query, external assets, and a central evidence plane are not part of this
contract. The Local product gates above remain the qualification authority for
record consistency, traceability, untrusted-text handling, output privacy, and
failure behavior.

## Decisions still to resolve

The focused work items must settle these details before their dependent items
start:

- the Q1 Candidate contract is Linux 6.12/x86_64 native host and its versioned
  synthetic workloads, paired capture order, monotonic event window, exact
  count reconciliation, isolated collector resource sampling, and pair-level
  bootstrap summary with phase-scoped burst loss are fixed, but exact numeric
  budgets and any Supported promotion remain blocked on enough retained
  privileged live evidence;
- the Kubernetes least-privilege deployment shape after container identity and
  runtime recovery are qualified.

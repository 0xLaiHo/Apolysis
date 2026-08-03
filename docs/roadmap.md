# Apolysis Roadmap

> English | [Simplified Chinese](roadmap.zh-CN.md)
> Companion document: [design.md](design.md)
> Execution plan: [beta-qualification-plan.md](beta-qualification-plan.md)
> Last reviewed: 2026-08-03

This roadmap directs Apolysis toward a bounded eBPF Agent runtime
observability beta. It records sequencing, deferrals, no-go criteria, and the
conditions under which the project may expand. It is not a per-commit progress
log.

## Current decision

Apolysis is no longer pursuing a cross-provider Agent Runtime Evidence &
Policy Plane. The active product is an **eBPF Agent Runtime Observability
Platform** for operator-controlled Linux environments.

The reset establishes these durable boundaries:

- eBPF runtime observation is required, not an optional coverage enhancement;
- the primary aggregate is an Agent Observation Record, not a cross-provider
  Agent Execution Record;
- the first stable workflow is a local Linux Agent Run, followed by container
  attribution and a bounded Kubernetes beta;
- collection, attribution, privacy, health, and operator investigation take
  priority over central storage and provider adapters;
- findings are post-observation review aids and do not claim enforcement;
- a central multi-tenant evidence plane requires new user evidence and a new
  architectural decision.

The active workspace now matches the bounded product: eight crates cover core
records, observer, accountability findings, local storage, daemon, CLI,
Kubernetes metadata, and visibility assessment. Central services, policy
actuation, feedback control, sandbox execution, and broad production
qualification no longer participate in active builds or default tests. The
next priority is collector correctness.

## Beta outcome

The bounded beta should let an operator start or attach to a supported Agent
Run and answer, through a CLI or saved-run viewer:

1. which processes belonged to the run;
2. which supported file, network, and credential operations were observed;
3. how each observation was attributed to process, cgroup, container, or Pod;
4. whether the operation succeeded, failed, or remained unknown;
5. whether collection was healthy and which observations may be missing;
6. which bounded findings require review.

The beta does not require a project-owned cloud service, PostgreSQL, object
storage, provider adapters, or policy enforcement.

## Delivery sequence

### 0. Freeze the product boundary

Purpose: make the scope reset the documented authority before changing code.

Deliverables:

- synchronize the English and Chinese README, design, and roadmap;
- replace cross-provider evidence-plane language in the domain glossary;
- record the scope decision and supersede incompatible ADRs;
- state that broad prototypes remain in history but are not active product
  commitments.

Exit condition: a reviewed PR targeting `pre-release` establishes one
unambiguous product definition and explicit non-goals.

### 1. Reduce the active workspace

Purpose: make build, test, and ownership boundaries match the product.

Keep as active product modules:

- kernel program and userspace observer;
- run scope and runtime identity;
- bounded local store;
- node daemon;
- CLI and future saved-run viewer;
- narrowly required local/container metadata.

Remove from the active workspace and default gates:

- production contracts, Gateway, Gateway server and testkit;
- PostgreSQL Gateway and projections;
- evidence-object storage and lifecycle;
- policy actuation, feedback control, and enforcement prototypes;
- provider, compliance, and production-plane qualification machinery that no
  longer validates the eBPF product.

The change should preserve recoverability through Git history rather than
maintaining archived crates in the default workspace.

Exit conditions:

- `make build`, `make test`, and `make lint` exercise only the active product;
- no active crate depends on Gateway, PostgreSQL, object storage, policy
  actuation, or provider-evidence modules;
- README and package metadata name only supported or explicitly experimental
  capabilities;
- the live observer and privacy regression tests remain intact.

### 2. Qualify collector correctness

Purpose: make the eBPF source reliable enough to support product conclusions
inside its declared capability boundary.

Priorities:

- preserve compatibility for the versioned kernel/userspace ABI and capability
  manifest, and reject incompatible records explicitly;
- preserve bounded entry/exit matching for `network_connect` and the selected
  supported file-operation set;
- preserve return value and errno semantics while distinguishing attempted,
  succeeded, failed, denied, pending, and unknown;
- preserve per-cgroup operation correlation counters and qualify isolated
  Agent-Run gap persistence across scope drain, shutdown, and identity churn;
- preserve stable process identity across PID reuse and exec within one
  collector lifetime;
- preserve generation-qualified cgroup scope and deterministic process
  lineage;
- emit collector start, periodic health, loss checkpoints, terminal state, and
  explicit stop reason;
- fail loud on reserve failure, map pressure, truncation, decode failure,
  attach failure, ABI mismatch, restart, and incomplete flush;
- retain content-off persistence and secret/path redaction.

Initial operation breadth remains process lifecycle, selected file mutations
and opens, built-in credential-class paths, and outbound connect. New hooks require
a user investigation case plus a privacy and performance budget.

Exit conditions:

- every supported operation has tested outcome semantics;
- unsupported paths and missing exit events become explicit gaps;
- PID reuse, collector restart, decode failure, and event-loss tests cannot
  produce a clean or complete result;
- representative live tests pass on the explicitly supported kernel profiles;
- no raw argv, prompt, response, tool payload, credential, or private path
  crosses the default persistence seam.

### 3. Deliver the local Agent Run product

Purpose: turn correct kernel observations into an operator workflow.

Deliverables:

- managed launch that attaches before Agent execution begins;
- protected attach to an existing process tree with an explicit late-attach
  gap;
- one Agent Observation Record per run;
- process tree and ordered process/file/network/credential timeline;
- run summary, collector health, capability, attribution, and gap views;
- bounded findings for credential paths, workspace mutations, unexpected
  executable classes, unapproved network targets, and degraded observation;
- a non-privileged saved-run viewer over bounded local data;
- install, health, stop, cleanup, and retention behavior for the local daemon.

Optional declared-intent correlation may remain experimental. A run must be
useful without Agent-specific logs or provider APIs.

Exit conditions:

- an operator can complete the representative investigation without reading
  raw JSONL or kernel traces;
- every viewer fact resolves to an observation, capability, health, or gap
  record;
- an empty or partial timeline never renders as successful or complete;
- privilege separation, local file permissions, retention, and redaction pass
  their bounded tests;
- the collector meets a workload-specific CPU, memory, latency, and event-loss
  envelope frozen before beta qualification.

### 4. Add container attribution and Kubernetes beta

Purpose: reuse the same collector and record model for deeper operator-owned
runtime boundaries.

Sequence:

1. stabilize Docker/containerd cgroup and container identity;
2. qualify daemon restart and runtime socket recovery;
3. bind Kubernetes Pod UID, container ID, cgroup, namespace, service account,
   node, and RuntimeClass where supported;
4. deploy a least-privilege node collector and non-privileged viewer path;
5. validate representative workloads on the designated VKE test cluster.

Exit conditions:

- container and Pod identity never rely on name-only or PID-only matching;
- runtime restart, container churn, Pod reschedule, PID reuse, and sensor loss
  remain visible as gaps or identity transitions;
- gVisor, Kata, Firecracker, guest, io_uring, and remote-operation boundaries
  are described honestly;
- Kubernetes credentials and captured workload data never enter repository,
  logs, or retained test artifacts;
- Kubernetes support remains labelled Beta until its workload and kernel
  envelope is qualified.

## Cross-cutting rules

- Scope before capture: no supported host-wide default collection.
- Capability before claim: every operation and outcome is tied to a versioned
  capability.
- No silent absence: loss, truncation, unsupported paths, late attach, and
  collector death always create gaps.
- Runtime identity before inference: cgroup/process generation wins over PID,
  time, path, or command correlation.
- Privacy before persistence: sensitive content is off unless a separate,
  reviewed profile authorizes it.
- Observation is not enforcement: findings describe conditions after or while
  they are observed and never claim prevention.
- Viewer is non-privileged: browser or local UI code cannot access BPF maps,
  host PID namespace, runtime sockets, or node credentials.
- Expansion follows repeated use: new event families and environments must
  change a real investigation decision.

## Beta support boundary

Target stable profiles:

- supported Linux distributions and kernels with BTF, cgroup v2, required
  tracepoints, and documented BPF capabilities;
- local managed Agent commands;
- Linux self-hosted CI through the same CLI managed-run boundary;
- Docker/containerd after runtime attribution qualification.

Target experimental profile:

- Kubernetes node and Pod attribution on documented runtime/kernel
  combinations.

Unsupported:

- macOS and Windows runtime collection;
- vendor-managed Agent environments without an operator-controlled kernel;
- remote MCP, SaaS, or cloud effects outside the observed host;
- strong guest semantics without a guest collector.

## Explicitly deferred

- provider Hook, SDK, OTLP, MCP, and A2A adapter families;
- generic remote export and external custody;
- semantic coverage and remote outcome verification;
- cross-run search and organization-wide investigation graph;
- central authenticated ingest, multi-user Query API, and Web Console;
- PostgreSQL, S3-compatible evidence objects, KMS, replay authority, and
  multi-tenant retention/deletion;
- policy denial, approval workflow, BPF-LSM blocking, kill, or containment;
- portable evidence receipts, external anchoring, HSM custody, SCITT, and
  selective disclosure;
- public SaaS, billing, replication, failover, multi-region, and fleet disaster
  recovery.

Deferred work is not kept compiled in the active workspace solely because it
may be useful later. It returns only through a new scoped decision backed by
user demand.

## No-go criteria

The beta cannot be released for a profile when any applicable condition holds:

- the collector can silently drop, truncate, fail, restart, or stop without an
  Observation Gap;
- a syscall-entry event is rendered as a successful operation without a
  supported outcome source;
- PID-only, name-only, or timing-only matching is displayed as exact runtime
  attribution;
- an empty timeline is interpreted as absence of Agent activity;
- raw prompt, response, argv, tool payload, credential, or private path content
  persists by default;
- the viewer requires root, BPF access, host PID namespace, runtime socket, or
  node credential access;
- the supported kernel, runtime, operation, and performance envelope is not
  documented and tested;
- a finding is described as blocking or enforcement;
- local uninstall, retention, or cleanup can delete or modify unrelated host
  data;
- a Kubernetes test prints, copies, or commits kubeconfig or workload secrets.

## Success and stop conditions

Continue toward broader runtime support when:

- representative Agent Runs are automatically scoped and attributed;
- operators repeatedly use the process/file/network investigation workflow;
- collector health and gaps prevent false clean conclusions;
- at least one runtime observation changes a review, security, incident, or
  debugging decision;
- container or Kubernetes attribution adds useful context beyond ordinary
  process logging.

Stop expanding and simplify further when:

- users only need generic process telemetry already supplied by existing
  runtime-security tools;
- eBPF observations do not change an investigation decision;
- privileged deployment cost exceeds the value of Agent-specific scoping;
- most useful activity occurs in vendor-managed or remote environments the
  collector cannot observe;
- the saved-run viewer is not used after initial evaluation;
- adapter or compatibility maintenance consumes more capacity than collector
  correctness and operator workflow.

## Resource assumption

For one engineer, plan approximately 12-16 weeks from scope reset to bounded
container beta. Two engineers can parallelize collector correctness and the
operator workflow and may reach the same beta in roughly 8-10 weeks. These are
planning envelopes, not release commitments; Kubernetes depth follows only
after the local and container gates close.

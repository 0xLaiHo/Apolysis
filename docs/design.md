# Apolysis Design

> English | [Simplified Chinese](design.zh-CN.md)
> Companion document: [roadmap.md](roadmap.md)
> Last reviewed: 2026-08-03

This document is the authority for what Apolysis is, how its target system
works, what exists today, and where its claims stop. Delivery order, deferrals,
and release gates belong in the roadmap.

## 1. Product definition and maturity

Apolysis is an experimental **eBPF Agent Runtime Observability Platform** for
operator-controlled Linux environments. It observes a bounded set of process,
file, network, and credential-related operations, groups them into an Agent
Run, attributes them to runtime identities, and reports collector health and
observation gaps.

The eBPF collector is a required primary source. Provider hooks, Agent logs,
protocol traces, and remote export are deferred; they do not define the active
product and cannot replace runtime observation.

The active target is a bounded beta, not a production evidence plane. Gateway,
PostgreSQL, evidence-object, projection, and cross-provider contract prototypes
have left the active workspace. Policy actuation, Agent feedback control,
sandbox execution, and broad production qualification have also left active
builds; none is an observer-side product dependency.

### Maturity labels

| Label | Meaning |
| --- | --- |
| Implemented today | Exists in the current collector or local workflow with documented limits |
| Beta target | Required by the active eBPF observability roadmap but not yet qualified |
| Deferred | Retained as a possible future extension only after repeated user demand |
| Out of scope | Not part of the product direction |

## 2. User and decision

The primary operator is a platform, runtime-security, AppSec, or engineering
team running Agents on Linux infrastructure it controls. The first supported
workflows are local Agent CLIs, Linux self-hosted CI, and containers; a bounded
Kubernetes node workflow follows after container attribution is stable.

For one Agent Run, the operator needs to answer:

1. Which processes did the Agent start?
2. Which supported file, network, and credential operations were observed?
3. Which runtime identity owns each observation?
4. Did a supported operation succeed, fail, or remain unknown?
5. Was collection healthy, and which activity may be missing or unsupported?
6. Which observations require review because they crossed a configured
   workspace, credential, or network boundary?

More event volume is not itself product value. The product succeeds when an
operator can investigate a real Agent Run without reading kernel traces or raw
storage files and without being misled by missing evidence.

## 3. Domain model

The aggregate is the **Agent Observation Record**:

```text
Agent Run
  |- Observation Scope
  |- Runtime Identity
  |    `- Runtime Observation
  |         `- Operation Outcome
  |- Collector Capability
  |- Collector Health
  |- Observation Gap
  `- Finding
```

An Agent Observation Record is narrower than the earlier Agent Execution
Record. It does not attempt to aggregate provider intent, multi-Agent protocol
semantics, remote outcome verification, approvals, or policy actuation.

Exact relations require a stable runtime identity inside a documented
boundary. Time, command name, path, or PID-only matching is inferred. When
several owners remain plausible, the relationship is ambiguous; it is never
silently promoted to exact.

## 4. Responsibility and trust boundaries

| Boundary | Owner | Apolysis role |
| --- | --- | --- |
| Agent authorization and task intent | Agent harness or operator | Optional descriptive metadata only |
| Workload isolation | Host, container runtime, Kubernetes, or sandbox | Observe supported runtime activity; do not claim isolation |
| Runtime observation | Operator-controlled Linux kernel and Apolysis collector | Collect, scope, normalize, redact, and report health/gaps |
| External result | Git, test, cloud, SaaS, or remote service | Outside the active product contract |

A compromised host root or kernel can forge or suppress host observations.
Apolysis is an operational observability tool, not an independent attestation
authority.

The privileged collector and the non-privileged operator surface are separate
trust domains. The viewer never loads BPF programs or receives host-wide
credentials.

## 5. Target architecture

```text
Agent command / self-hosted CI job / container / Pod
                         |
                  Observation Scope
                         |
              privileged eBPF Collector
                |- process lifecycle
                |- selected file operations
                |- network connections
                |- loss and health counters
                         |
             userspace decode and identity join
                         |
                 privacy/redaction seam
                         |
                  bounded local store
                         |
              CLI and saved-run viewer
```

### 5.1 Agent Run and Observation Scope

Every observation belongs to an explicit run scope. Supported scope modes are:

- a managed Agent command whose process tree is observed from launch;
- an existing process tree with PID-reuse protection;
- one cgroup for a container or workload;
- a bounded set of cgroups managed by the node daemon.

Managed launch is the preferred local workflow because the collector can be
attached before the Agent starts. Attaching to an existing process may miss
earlier activity and must record that gap.

A host-wide default scope is not permitted. The collector may expose an
explicit diagnostic mode for development, but it is not a supported Agent Run
profile.

### 5.2 eBPF Collector

The collector uses a small, versioned set of high-signal hooks. It filters at
event origin where possible, emits fixed and bounded records, and reports map
pressure, reserve failure, truncation, decode failure, attach failure, and
unexpected termination. Each record begins with an ABI version and declared
record size. Userspace rejects an incompatible version or size instead of
decoding it as the current layout.

The beta collector target adds entry/exit matching for each supported
operation. A record distinguishes attempted, succeeded, failed, denied,
pending, and unknown outcomes and preserves return value or errno when that is
part of the capability.

`network_connect` and the selected `file_open`, `file_create`,
`file_truncate`, `file_unlink`, and `file_rename` operations have completed
outcome paths. The collector keeps bounded thread-scoped entry records and
emits Runtime Observations at syscall exit. Linux return values map to
succeeded, failed, or denied; connect additionally supports pending. An
unmatched entry or exit becomes an explicit, operation-specific Observation
Gap.

In multi-cgroup daemon mode, connect and file pairing loss is counted
separately for each cgroup while collector-global counters remain available
for health diagnosis. Draining a scope prevents new entries, snapshots its
missing-entry, missing-exit, and pending counts after a bounded in-flight
collector-update drain, and confirms typed Observation Gaps are durable in the
owning Agent Run before its ownership is discarded. Already-submitted ring
records pass through a bounded drain and are confirmed durable first. Every
scope registration receives a monotonic generation. Pending pairs and emitted
records retain that generation, so a stale pair from a drained scope cannot be
charged to or emitted into a later Agent Run that reuses the same numeric
cgroup ID. A drain, snapshot, queue drop or shedding event, or storage failure
stops the observer runtime and rejects a clean run close.

Every multi-cgroup ring producer, including process fork, exec, and exit,
participates in the same in-flight scope barrier. Barrier-map read failure
leaves the scope draining and fails closed; only a bounded wait timeout may
attempt to restore an otherwise complete ACTIVE scope. ABI-valid records that
cannot be normalized also stop queued ingest or confirmed drain instead of
being skipped.

Full-syscall collection, prompt/response capture, TLS plaintext capture, and
generic kernel enforcement are not targets.

### 5.3 Userspace normalization and identity

Userspace decodes the kernel ABI, assigns deterministic source sequence,
normalizes event types, joins runtime metadata, applies content-off privacy,
and writes the Agent Observation Record.

Kernel ABI v3 carries a bounded scope generation, process generation, kernel
process-start timestamp, exec generation, and parent process/exec generations.
The live userspace boundary attaches the host boot ID read once when the
collector starts. Process context is keyed by host boot, PID, process
generation, and exec generation rather than PID alone; a PID reuse or exec
transition therefore cannot inherit stale executable context. The
process-identity map and userspace context table are bounded and fail loud on
pressure instead of silently reusing or dropping identity state.

Attribution is exact only when host boot, scope generation, process generation,
kernel process-start time, and exec generation are present. A fork identity is
provisional until the child process start is observed; thread-clone candidates
that never become process identities remain inferred and are discarded at task
exit. Missing generations remain inferred with an explicit reason; PID-only,
command, path, and timestamp joins never become exact. Scope generation
protects cgroup ownership within one collector lifetime. Collector restart
remains a visible identity boundary: cross-restart continuity is not claimed
until lifecycle persistence is implemented. PID namespace, container, Pod, and
node identity remain additive attribution where available.

### 5.4 Local store and viewer

The first product remains local-first. The store is bounded, rotates safely,
and retains explicit run start, capability, health checkpoints, terminal state,
and gap records. The current format is append-only JSONL with optional local
hash-chain envelopes. A query index may be added behind the same record model
when the saved-run viewer requires it.

The viewer provides:

- run inventory and summary;
- process tree and runtime identity drill-down;
- ordered process, file, network, and credential timeline;
- supported outcome and attribution status;
- collector health, loss, truncation, and unsupported capability gaps;
- review-oriented findings linked to their observations.

The viewer derives no hidden success verdict from an empty result.

### 5.5 Deferred central boundary

Remote export, custody, organization authorization, object storage, cross-run
search, and high availability are not part of the bounded beta. They return
only after repeated use proves that a central service is needed and a new
architectural decision defines its boundary.

## 6. Observation contract

Each Runtime Observation carries, when supported:

- schema and collector ABI version;
- run and observation identifiers;
- source sequence and observed time;
- runtime identity and scope reference;
- operation family and normalized action;
- bounded, redacted resource identity;
- attempted/succeeded/failed/denied/pending/unknown outcome;
- return value or errno when declared by the capability;
- truncation and decoding state;
- relation status and reason.

Collector lifecycle records carry start, capability manifest, periodic health,
loss counters, terminal state, and stop reason. A missing terminal record is an
Observation Gap.

Consumers ignore unknown additive fields. Incompatible ABI or schema changes
require a new version and an explicit decoder failure rather than best-effort
misinterpretation.

## 7. Supported operation set

| Family | Beta target | Claim boundary |
| --- | --- | --- |
| Process | fork/clone lineage, exec, exit | Process lifecycle, not logical sub-Agent semantics |
| File | selected open/create/truncate/rename/unlink paths | Supported operations and resolved identity only; no universal filesystem history |
| Credential | built-in credential-class path access | Path access finding, not proof that a secret was consumed |
| Network | outbound connect tuple and outcome | Connection attempt/result, not remote mutation or TLS content |
| Health | attach, loss, map pressure, decode, truncation, terminal state | Collector condition, not host integrity attestation |

Operation breadth expands only when a real investigation requires it and the
privacy/performance cost is bounded. Unsupported io_uring, filesystem,
network, guest, or runtime paths become explicit capability gaps.

## 8. Environment model

| Environment | Runtime observation contract |
| --- | --- |
| Local Linux CLI | Managed launch or protected process-tree attach |
| Linux self-hosted CI | Same CLI managed-run boundary; runner isolation remains external |
| Docker/containerd | Host eBPF observation joined to container and cgroup identity |
| Kubernetes | Node eBPF observation joined to Pod/container/cgroup identity; bounded beta |
| gVisor | Host/runtime boundary visibility, not every guest syscall |
| Kata or Firecracker | Host/VMM/shim visibility; guest semantics require a guest collector |
| macOS or Windows | No eBPF runtime observation support |
| Vendor-managed Agent runtime | Out of scope without an operator-controlled Linux kernel |

## 9. Findings and control

Findings are post-observation review aids. The initial bounded set is:

- access to a built-in credential-class path;
- file mutation outside the configured workspace boundary;
- connection to an unapproved address or domain class when resolvable;
- execution of an unexpected binary class;
- degraded collection that violates a required observation profile.

Findings never claim that the operation was prevented. The BPF-LSM and seccomp
blocking prototypes are not part of the active product.

## 10. Privacy and security

- Prompt, response, raw tool payload, and full argv are content-off by default.
- Persisted executable identity is allowlisted and bounded; secret values and
  private paths are redacted before storage.
- Raw kernel payload exists only as a bounded implementation detail and may not
  cross the persistence seam without an explicit, reviewed profile.
- Observation scopes prevent accidental host-wide collection.
- Local files use restrictive permissions and bounded retention.
- The viewer is non-privileged and has no path to BPF maps, host PID namespace,
  container sockets, or node credentials.

## 11. Failure semantics

The following always produce an explicit gap or failed/degraded collector
state:

- ring-buffer reserve failure or map pressure;
- truncated resource or payload;
- kernel/userspace ABI mismatch;
- decode, attach, verifier, or permission failure;
- collector restart or death;
- late attach, PID reuse ambiguity, or missing process lineage;
- unsupported syscall, io_uring, guest, or remote operation path;
- local storage failure or incomplete terminal flush.

A quiet timeline is never proof that the Agent performed no relevant action.

## 12. Current implementation mapping

Implemented today:

- `ebpf/observer` and `apolysis-observer`: CO-RE tracepoints, ring buffer,
  process-tree/cgroup scopes, ABI v3, bounded process/exec and cgroup scope
  generations, outcome-aware selected file operations and network connect,
  per-cgroup operation gap counters, redaction, and health/gap diagnostics;
- `apolysis-cli`: fixture/live observation, managed Agent launch, optional
  Codex intent correlation, visibility, and verification commands;
- `apolysis-core`: current JSONL vocabulary, record types, and versioned
  Collector Capability manifest;
- `apolysis-store`: rotation and optional local hash-chain envelopes;
- `apolysis-accountability`: optional declared-intent comparison and
  review-oriented findings;
- `apolysis-kubernetes` and `apolysis-visibility`: bounded runtime metadata and
  visibility-boundary assessment;
- `apolysis-daemon`: long-lived observer, bounded queue, local socket, and
  runtime registration prototype.

The live collector synchronizes its capability manifest to stable storage after
successful attachment and before releasing a managed Agent gate. Selected
file operations and network connect have bounded entry/exit outcome semantics,
and the daemon persists their pairing gaps to the owning Agent Run at explicit
scope removal and clean shutdown. Stable in-run scope/process generations are
implemented. Complete collector lifecycle records and restart-gap persistence,
the saved-run viewer, and bounded Kubernetes beta remain targets.

The central contracts, Gateway, PostgreSQL projection, evidence-object cluster,
policy/feedback/control planes, sandbox runner, and broad qualification
machinery have been removed from the active workspace. Git history preserves
them as historical implementation input; they do not define this architecture.

## 13. Limitations

- eBPF sees kernel/runtime operations, not logical reasoning or hidden remote
  provider state.
- Relative paths, file-descriptor-relative operations, namespaces, overlays,
  and guest runtimes require explicit resolution and capability limits.
- A successful connect does not prove that a remote operation committed.
- Same-process logical Agents cannot be separated without an additional
  propagated identity; runtime-only attribution remains process-level.
- Connect or file entries still pending when a cgroup scope drains remain in
  bounded pairing maps until syscall or thread exit. Their captured scope
  generation prevents them from crossing into a later Agent Run after numeric
  cgroup-ID reuse, but the generation allocator is observer-lifetime state and
  does not establish identity continuity across collector restart.
- The exit side cannot reconstruct `openat` or `openat2` flags after a missing
  entry, so such an unmatched exit is conservatively attributed to
  `file_open`, not create or truncate.
- A compromised kernel or privileged host can suppress or forge observations.
- Kernel version, BTF, hook availability, verifier behavior, and privileges
  constrain support.

## 14. Non-goals

- Agent orchestration, scheduling, memory, model routing, or sandboxing.
- General Hook, SDK, OTLP, MCP, or A2A observability platform.
- Remote outcome verification and cross-provider Agent evidence graph.
- Synchronous policy denial, approval workflow, BPF-LSM enforcement, or
  automated containment.
- Multi-tenant Gateway, PostgreSQL/S3 custody, evidence-object lifecycle,
  billing, HA, or public SaaS.
- SIEM, prompt evaluation, token-cost analytics, or long-term data lake.
- macOS/Windows kernel sensors, TLS plaintext, default prompt/response capture,
  or indiscriminate full-syscall capture.

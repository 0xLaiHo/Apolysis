# Apolysis Design

> English | [Simplified Chinese](design.zh-CN.md)
> Last reviewed: 2026-08-11

This is the sole detailed product document. It is the authority for what
Apolysis is, how its target system works, its stable record and qualification
contracts, what exists today, future direction, and where its claims stop.

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

The shared vocabulary is:

| Term | Contract |
| --- | --- |
| Agent | The autonomous participant whose runtime activity is observed |
| Agent Run | One bounded period in which an Agent and its attributed process tree pursue one declared task |
| Observation Scope | The runtime boundary whose activity belongs to one Agent Run |
| Protected Attach | Qualified admission of an already-running Agent; it does not claim earlier history or pre-anchor continuity |
| Collection Boundary | The point from which a Collector Capability applies; earlier activity is unknown history represented by a gap |
| Runtime Identity | Stable process or workload identity that distinguishes reuse and coincidental matches |
| Runtime Observation | A supported process, file, network, or credential-related operation reported inside capability and scope |
| Operation Outcome | `attempted`, `succeeded`, `failed`, `denied`, `pending`, or `unknown` within the declared source semantics |
| Collector Capability | Versioned operation/source/outcome declaration for one environment boundary |
| Collector Health | Independent `healthy`, `degraded`, `failed`, or `unknown` collector state |
| Observation Gap | Explicit missing, lost, truncated, unsupported, ambiguous, or out-of-scope evidence boundary |
| Exact / Inferred / Ambiguous Relation | Stable-identity relation, correlation-supported relation, or a relation with multiple plausible targets |
| Unattributed Observation | In-scope observation that cannot responsibly be assigned more specifically |
| Finding | Reviewable condition derived from bounded observations; never an enforcement verdict |
| Saved Run Viewer | Local read-only rendering of one frozen Agent Observation Record; not an evidence source |

New interfaces and documentation use these terms. “Session”, “job”, “tenant”,
process name, or a bare PID must not replace Agent Run, Observation Scope, or
Runtime Identity in a public claim.

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
- a protected existing process tree admitted through explicit Agent
  registration or automatic discovery;
- one cgroup for a container or workload;
- a bounded set of cgroups managed by the node daemon.

Managed launch is the preferred local workflow because the collector can be
attached before the Agent starts. Protected existing-process attach is a closed
admission surface: raw `--scope-pid` is rejected, and the root must come from
`--agent-registration` or `--agent-discover`. An explicit registration is
qualified against the current host boot ID, root start tick, executable,
command fingerprint, and canonical workspace boundary as the collector opens
the root pidfd; the root's live cwd must resolve to that boundary or one of its
descendants. A match records `root_selection:registration_qualified`: it
qualifies the root visible at that anchor, not its continuity since the
registration was created. Discovery derives identity material from live process
state, requires one unique best candidate, and keeps root selection `inferred`.

Every root or lineage candidate admitted to seeding must be a live, non-zombie
thread-group leader. After the snapshot, a pidfd is opened for each candidate
and its liveness, lineage, and initial PID/time namespace membership are checked
on both sides of map insertion: a per-seeded-candidate pidfd sandwich. The exit hook removes a candidate that
exits after insertion. The selected root remains anchored by a pidfd through
activation. The observer and target must share the initial PID namespace and
the same initial, unshifted time namespace. The scope begins inactive,
tracepoints attach, and it then enters process-tree seeding: the
registration-qualified or inferred root is seeded before descendants, repeated
process-tree snapshots add missing TGIDs, and root identity is requalified
around activation. Only then does the scope become active. This closes
post-anchor exit and replacement races for seeded candidates but is not proof
of pre-anchor selection continuity.

Activity before activation is unknown. Every successful protected attach
therefore persists exactly one `late_attach` Observation Gap with
`operation:"collector_lifecycle"` and `count:1` before the capability manifest
and `started` lifecycle record. The count represents one unknown-history
Collection Boundary, not an estimate of missing syscalls or events.

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
pressure instead of silently reusing or dropping identity state. A kernel
identity-map or exec-generation failure sets a preallocated fail-closed latch;
all later records remain inferred until the collector restarts, so pressure
cannot silently restore exact attribution.

Attribution is exact only when host boot, scope generation, process generation,
kernel process-start time, and exec generation are present. A fork identity is
provisional until the child process start is observed; thread-clone candidates
that never become process identities remain inferred and are discarded at task
exit. Missing generations remain inferred with an explicit reason; PID-only,
command, path, and timestamp joins never become exact. Scope generation
protects cgroup ownership within one collector lifetime. Collector restart
remains a visible identity boundary: lifecycle recovery records the unfinished
instance and its restart gap, but does not claim identity continuity across the
boundary. PID namespace, container, Pod, and node identity remain additive
attribution where available.

#### Container runtime binding and recovery

Docker and containerd attribution consumes a successful, complete adapter
inventory rather than interpreting a stream of sightings as authority. One
stable workload identity contains the adapter, full workload/container ID,
runtime start marker, host boot ID, init-process start time in clock ticks, and
cgroup filesystem `(device,inode)` identity. PID, process or container name,
timing, runtime path, and a numeric cgroup ID are never independently Exact.

An identical complete inventory is a no-op. Only a successful complete
inventory may retire an absent binding. The same adapter/workload key with a
different stable identity is an explicit identity transition: the old binding
first receives a `runtime_metadata_unavailable` gap with
`reason=identity_transition`, then is retired, and the replacement is attached
only after qualification. Duplicate workload keys, conflicting cgroup identities,
adapter mismatch, missing or over-limit identity fields, and oversized
inventories fail closed. A socket or decode failure is not an empty inventory
and therefore cannot silently retire or preserve stale Exact attribution.

Runtime-source loss suspends affected active bindings and persists an
Observation Gap before recovery. Daemon restart restores persisted bindings as
dormant rather than Exact; a fresh complete inventory must requalify them.
Socket disconnect, runtime service restart, and daemon restart use bounded
backoff, report adapter health as degraded while unavailable, and return to
ready only after a valid inventory. Docker, containerd, and k3s-containerd use
the same recovery semantics; Kubernetes metadata remains additive and cannot
upgrade an unqualified container binding.

The D1/D2 implementation and deterministic contracts are complete. Retained
non-destructive Docker qualification proves all of the following boundaries:

- complete inventory establishes an active binding, and a restart of the same
  full container ID changes the stable identity rather than inheriting stale
  PID, name, timing, or numeric-cgroup attribution;
- a controlled adapter-socket outage persists a source gap before suspension,
  clears active ownership, and permits only a fresh complete inventory to
  observe the stable binding again;
- a new private daemon/server lifecycle over the same private state root keeps
  replayed bindings dormant and requires the ordered `daemon_restart` gap ->
  retired -> observed recovery before active query attribution returns; and
- a real content-off eBPF file event carries Exact container and cgroup
  identity, with the Agent Run capability manifest and hash chain verified.

The privileged Docker/eBPF boundary is reproducible through
`make qualify-runtime-binding-live`. The runner performs unprivileged BPF and
test compilation, publishes verified root-owned private copies of the single
test executable and CO-RE BPF object, and invokes only the exact opt-in gate
against the fixed local Docker Engine socket. The test itself checks kernel,
Docker, image, service-state, and ownership prerequisites before any Docker
mutation, and performs identity-bound cleanup. A skip is not a pass; running
the test binary with a bare `--ignored` is outside this contract.

Those gates qualify only the retained Docker behaviors. The independent private
standalone-containerd boundary is reproducible through
`make qualify-private-containerd-live`, which invokes the explicit
`scripts/run-private-containerd-live.sh` runner as the unprivileged checkout
owner with pre-authorized `sudo`. The runner pins the official `crictl` v1.36.0
archive and binary hashes, accepts only that verified binary (or downloads and
verifies the official archive), and requires the pinned Alpine image to be
present in the local Docker store. It uses the host's local containerd and runc
binaries, then builds the private workload store offline by saving and
importing that cached image; it never pulls a workload image during
qualification.

The runner enters a create-only delegated user systemd scope, prepares valid
cgroup-v2 nesting by moving scope-root processes into a private `init` child,
and enables only the required available controllers. The privileged gate then
starts a private containerd instance using runc, with private root, state, socket,
plugin, CNI, CDI, NRI, image-verifier, and `opt` paths. Mount, network, UTS, IPC,
and cgroup namespaces are isolated. The outer PID namespace is deliberately
shared so `/proc` can prove every owned process and cgroup generation; each CRI
Pod sandbox and workload PID namespace is still created and isolated by runc.
The gate does not restart a shared service, alter shared CNI configuration or
iptables, or use a shared runtime socket or store.

The retained private-containerd result proves a complete initial inventory, an
identical stable inventory, and a replacement workload with a fresh full
container identity and stable-proof generation while the unchanged workload
retains its identity. A controlled proxy-socket outage persists the source gap,
suspends active ownership, and permits observation again only from a fresh
complete inventory after reconnect. `crictl` may render CRI `startedAt` as
RFC3339Nano in local time with a numeric UTC offset; the adapter strictly
normalizes that value at its boundary to the existing canonical positive
decimal Unix-nanosecond marker. Offset text is not persisted.

Cleanup is proof-bound and fail-closed. The runner deletes only proven private
CRI objects and their process/cgroup generations, stops the private runtime,
removes its namespaces, mounts, delegated scope, and create-new root, and
requires all of them to be absent before reporting success. Before and after,
it binds the shared Docker and containerd service states, PIDs, socket
identities, cached Alpine identity, and Docker container inventory. Uncertain
private cleanup or residue fails the gate and preserves the private root.
Shared-baseline drift also fails the gate, but a separately proven private
cleanup may still remove that root because it is not authority for shared-host
state.

A shared-host CRI discovery gate that reports `RuntimeReady=true` but
`NetworkReady=false` still performs a clean pre-mutation skip, and that skip is
not a pass. The retained private standalone result closes the bounded D1/D2
containerd qualification; it does not qualify Kubernetes or a shared
containerd installation. Docker evidence cannot be extrapolated to containerd,
and private-containerd evidence cannot be extrapolated to Kubernetes. The
containerd and Kubernetes profiles therefore remain Experimental, and no
profile becomes Supported.

Actual Docker/containerd service restarts through systemd remain additional,
destructive opt-in qualification beyond the non-destructive D1/D2 closure.
Those gates and the K1/VKE Kubernetes qualification remain open; their status
does not invalidate the retained Docker or private-containerd evidence.

Protected attach normalizes initial process and thread identifiers to TGIDs and
requires the root to be a live thread-group leader. A `/proc` start tick is
converted to the half-open boot-time interval
`[start_tick * tick_ns, (start_tick + 1) * tick_ns)`. Matching kernel
bookkeeping may promote the internal tracked membership to the exact
group-leader start time during seeding or later; subsequent matches must use
that nanosecond value. Only events emitted after activation receive exact event
identity within the collector run from the matched kernel start time plus
process and exec generations. This is separate from pre-anchor root-selection
confidence: explicit registration is
`registration_qualified`, discovery remains `inferred`, and neither selection
value is an event relation status or a continuity claim.

### 5.4 Local store and viewer

The first product remains local-first. The store is bounded, rotates safely,
and retains explicit run start, capability, health checkpoints, terminal state,
and gap records. The current format is append-only JSONL with optional local
hash-chain envelopes. The L3 Saved Run Viewer consumes the frozen single-run
record directly. A query index remains deferred until repeated use demonstrates
that a bounded single-record view is insufficient.

The v1 saved-run read path opens the active file and contiguous numeric
archives as one stable local snapshot, refuses symlinks and non-regular files,
enforces byte/line/record limits before projection, and verifies a complete
hash chain before exposing payloads. Source order is authoritative; wall-clock
timestamps never repair or reorder a malformed lifecycle. Plain and verified
inputs may be composed explicitly, but mixed integrity is visible and cannot
produce complete evidence. Batch, byte, and record budgets apply to the whole
composed command, not independently to each `--input`.

`apolysis-accountability` folds those typed source records into exactly one
Agent Observation Record. Its Agent Observation Summary keeps evidence state,
Collector Health, and review state independent. Missing lifecycle, unsupported
outcomes, diagnostics, Observation Gaps, unknown records, and source-integrity
findings remain queryable limitations; mixed Agent Runs, corrupt storage,
invalid lifecycle order, duplicate canonical observations, incompatible
schemas, and content-policy violations fail closed. Free-form finding and gap
diagnostics are canonicalized rather than copied into the derived artifact.
Validated runtime-binding lifecycle facts remain in source order in the
projection; validation reconstructs their lifecycle rather than reducing them
to the currently active set.

Complete evidence requires the full current v1 operation/source/outcome
capability contract. A partial or fictitious manifest and an unresolved Finding
reference remain visible as typed issues and cannot be complete. Exact Runtime
Identity is admitted only for post-activation kernel observations carrying the
canonical generation-based relation reason and complete stable tuple.

`apolysis run project --input <path> [--input <path> ...] --output <path>` is
the non-privileged adapter for this projection. It writes deterministic JSON
through a same-directory private temporary file, synchronizes it, and publishes
it atomically. It refuses an output that aliases any active or rotated input.
The command is a saved-run projection, not a live tail, remote query API, or
interactive viewer.

`apolysis run view --input <agent-observation-record.json> --output
<viewer.html>` is the non-privileged Saved Run Viewer adapter. It accepts
exactly one Agent Observation Record v1, validates its type, schema, summary,
identity references, source ordinals, runtime-binding lifecycle, Finding
links, and state consistency, then renders deterministic, self-contained HTML.
A malformed or inconsistent record fails closed without replacing an existing
output. The reader is bounded, refuses symlinks and non-regular files, and the
publisher refuses an output alias before using an exclusive mode-`0600`
same-directory temporary file, file and directory synchronization, and atomic
rename.

The HTML is an offline, read-only artifact with no external assets or network
dependency. A restrictive Content Security Policy disables connections and
external resources, and every stored value is rendered as untrusted text. The
viewer requires neither root nor access to BPF maps, the host PID namespace,
runtime sockets, or node credentials.

The viewer provides:

- one-run summary with Evidence State, Collector Health, and Review State kept
  as three independent axes;
- an Exact Runtime Identity roster and the reported PID/PPID fields retained
  on Runtime Observations;
- the ordered observed, retired, and suspended runtime-binding lifecycle;
- ordered process, file, network, and credential timeline;
- supported outcome and attribution status;
- collector health, loss, truncation, and unsupported capability gaps;
- review-oriented Findings linked to their supporting Runtime Observation or
  earlier exact-matching observed runtime binding;
- source ordinals and record paths that keep displayed facts traceable to the
  frozen record.

Agent Observation Record v1 does not carry an authoritative parent Runtime
Identity link. The viewer therefore does not construct a canonical process
tree from numeric PID/PPID values, which may be reused; it presents the identity
roster and reported PPID as stored facts without inferring parent edges. It
also derives no hidden success verdict from an empty result and never combines
the three summary axes into a clean verdict.

The derived v1 object is one JSON object and is never appended to timeline
JSONL. Its top level is `record_type`, `schema_version`, `agent_run_id`,
`source_integrity`, `summary`, `capability_manifests`, `runtime_identities`,
`runtime_observations`, `runtime_bindings`, `collector_lifecycle`, `findings`,
`observation_gaps`, and `issues`. Every projected source fact carries a
one-based `source_ordinal` from authoritative input order. The summary retains
typed counts and grouping maps without merging Evidence State, Collector
Health, and Review State.

Projection limits are 128 MiB across all inputs, 1 MiB per JSONL line,
1,000,000 source records, 1,024 numeric archives, 1,024 input batches, 4,096
bytes per string, 1,024 items per array, 256 fields per object, and 16 nested
value levels. Publication uses an exclusive mode-`0600` temporary file,
file/parent synchronization, and atomic rename; source aliases and unsafe file
types are rejected before replacement.

`apolysis verify hash-chain` is read-only. Exit `0` means every record and tail
verified, `1` means a failure report was written, and `2` means the command
could not run. Its report retains the verified record count, last sequence and
hash, valid/total bytes, and a bounded failure category. Middle corruption and
a truncated or corrupt tail fail closed without truncating, repairing, or
quarantining the source.

External log shipping preserves each original JSONL line and record body.
Vector, Fluent Bit, or another operator-owned transport may route, buffer,
compress, or encrypt outside the body, but it does not become the schema or
query authority. A copied daemon hash chain is verified before replay, and
local evidence remains authoritative until downstream retention is confirmed.
OTLP and a project-owned exporter remain deferred.

### 5.5 Local daemon operations

A Linux release bundle contains the `apolysis`, `apolysisd`, and
`apolysisd-health` binaries, the CO-RE object, and the systemd unit. Release
manifest schema v2 binds exactly those five installable artifacts to their
kind, SHA-256 digest, byte length, and required mode. Manifest paths do not
become arbitrary destinations: the installer maps the closed artifact set onto
`/usr/local/bin/apolysis`, `/usr/local/bin/apolysisd`,
`/usr/local/bin/apolysisd-health`,
`/usr/local/lib/apolysis/apolysis_observer.bpf.o`, and
`/etc/systemd/system/apolysisd.service`.

The release verifier accepts one bounded, canonical gzip/tar stream, rejects
duplicate or extended archive metadata and non-regular members, checks the
closed manifest and systemd contracts, validates executable ELF structure, and
requires `bpftool gen skeleton` to parse the packaged CO-RE object. Its package
contract tests use the freshly built real object; there is no structural-fixture
switch in the production verifier.

`apolysis daemon install --bundle <dir> --root <root>`, `inspect`, and
`uninstall` are adapters over `LocalDaemonOperations`. That deep module exposes
inspect, plan, and apply while hiding bundle validation, complete-target
preflight, filesystem snapshots, descriptor-anchored staging, synchronization,
crash recovery, and receipt ownership. Root, bundle, parent, and mutation
operations stay anchored to already-open directories with no-follow semantics.
Receipt proofs bind owner, mode including special bits, digest, size, and file
identity. The module rejects linked or non-regular sources and targets,
hard-linked artifacts, malformed or changed bundles, unmanaged conflicts,
changed managed files, and stale plans. A successful install publishes
`/usr/local/lib/apolysis/install-receipt-v1.json`; reinstalling identical managed
content is a no-op. Default uninstall removes only artifacts still proven by
that receipt and always preserves `/var/lib/apolysis` and unrelated host files.

Each mutating apply writes and synchronizes a fixed private mode-`0600`
operation journal before publishing individual files. Reopening the module
rolls a pre-commit transaction back or finishes committed cleanup and exposes
`recovered_interrupted_operation` through inspection. Replacement and removal
use identity-checked descriptor-relative operations; a changed or unknown
journal or transaction sibling fails closed for manual repair. This is durable
interruption recovery, not a claim that all five host paths change with one
instantaneously visible filesystem transaction.

A staged root exercises the same fixed-path filesystem contract without
invoking systemd, group management, or eBPF. The product supports the shipped
systemd unit as one concrete integration, not an abstract service-manager
interface. On a live host, that unit requires an explicitly provisioned
`apolysis` group; systemd owns activation, SIGTERM shutdown, and its bounded
drain deadline, while qualification reuses the daemon's existing health
protocol. Runtime and state directories are mode `0750`, daemon timelines are
mode `0640`, private quarantine and retention journals are mode `0600`, and the
explicitly managed local socket remains mode `0660`. Staged-root qualification
cannot substitute for the opt-in privileged gate that loads the real bundle,
waits for eBPF and storage readiness, stops the unit, and verifies
state-preserving uninstall.

Uninstall is not retention. Destructive retention obtains time from the daemon
clock, qualifies each closed Agent Run against the directory identity and the
already-open single-link timeline descriptor, blocks late writes, and stages
the exact set under a private same-filesystem trash root. A synchronized typed
journal distinguishes staging from committed cleanup. Startup rolls back an
unfinished staging transaction and completes committed cleanup; unsafe target
replacement, unknown content, journal corruption, or conflicting live state
fails closed. A non-mutating preview may use an explicit time for deterministic
tests, but a caller cannot supply the time for destructive apply. Destructive
apply is limited to the local default context; a legacy non-default request is
rejected without mutation, while multi-tenant deletion remains deferred. The
terminal retention catalog has an independent 4,096-Agent-Run bound; saturation
fails closed without evicting retained state or consuming active-run capacity.

Hash-chain recovery opens the timeline once with no-follow semantics and uses
that descriptor for validation, quarantine, truncation, and future append. It
rejects symbolic links, multiply linked files, and path replacement. A
recoverable corrupt tail is retained in a private create-new quarantine file;
middle corruption remains a fail-closed error. Recovery and retention never
turn the resulting integrity or Collector Restart limitation into complete
evidence.

### 5.6 Deferred central boundary

Remote export, custody, organization authorization, object storage, cross-run
search, and high availability are not part of the bounded beta. They return
only after repeated use proves that a central service is needed and a new
architectural decision defines its boundary.

## 6. Observation contract

Timeline schema v1 is newline-delimited JSON: one complete object per line,
one `record_type` string per object, Unix-millisecond timestamps unless named
otherwise, decimal numeric identifiers, and explicit `null` for optional
fields. Compatibility is append-only. Consumers ignore unknown fields and new
additive record types, do not depend on object field order, and join by stable
IDs rather than timestamps. Explicitly closed sub-schemas, including the
runtime-binding lifecycle below, reject unknown fields. Removal, rename, type
change, or semantic change requires a new schema version. Producers redact before persistence and never
write raw secret, argv, prompt, response, socket, path, label, annotation, or
tool-payload content under the default `content_off` profile.

The stable record families are:

| `record_type` | Required contract |
| --- | --- |
| `collector_capability_manifest` | Agent Run, collector/ABI identity, Observation Scope, privacy profile, ordered operation/source/outcome declarations |
| `collector_lifecycle` | Agent Run, opaque collector instance, start/checkpoint/terminal state, health, stop reason, cumulative loss and pending counters |
| `event` | Agent Run, source/type/raw ID, actor/resource/action, outcome/return/errno, runtime identity fields, relation status/reason |
| `raw_kernel_event` | Bounded pre-normalization kernel fact with ABI-qualified identity, redacted resource/payload, outcome and raw event ID |
| `intent` / `intent_correlation` | Optional content-off declared intent and its stable-ID or bounded executable correlation; not required for observation |
| `accountability_finding` | Typed review decision, bounded canonical reason, evidence reference, runtime identity and evidence boundary |
| `observation_gap` | Typed operation, kind, count and bounded detail for evidence that may be absent or unusable |
| `runtime_binding_observed` / `runtime_binding_retired` / `runtime_binding_suspended` | Durable Docker/containerd binding lifecycle over one stable workload identity |
| `observer_diagnostic` | Typed bounded attach, verifier, ABI, decode, truncation, pressure, loss, or summary diagnostic |
| `visibility_assessment` | Runtime profile, host visibility scope, metadata/guest-collector requirements and bounded subjects |

### 6.1 Timeline JSONL wire schema v1

In the tables below, every field is required on the wire. `T|null` means the
field is present and its value may be JSON `null`; no other field is nullable.
`u32`, `u64`, and `u128` are non-negative JSON integers within the named Rust
range, `i32` and `i64` are signed JSON integers, and `map<string,u64>` is a JSON
object whose values are non-negative counts.

`collector_capability_manifest` has this shape:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `record_type` | string | Constant `collector_capability_manifest` |
| `schema_version` | u32 | Constant `1` |
| `timestamp_unix_ms` | u128 | Persistence time |
| `agent_run_id` | string | Owning Agent Run |
| `collector` | string | Constant `apolysis_observer` |
| `collector_version` | string | Userspace package version |
| `kernel_abi_version` | u32 | Current live ABI is `3` |
| `kernel_record_size` | u32 | Current ABI-v3 size is `656` |
| `observation_scope` | enum | `process_tree` or `cgroup` |
| `privacy_profile` | enum | Constant `content_off` |
| `capabilities` | array<object> | Ordered capability objects |

Each capability object contains required string `operation`, required
`event_sources:array<string>`, and required `outcomes:array<enum>`. Outcome
values are `attempted`, `succeeded`, `failed`, `denied`, `pending`, and
`unknown`. A compatible AuditObserver v1 manifest declares the exact operation
contract below; a file capability is valid only with its complete entry/exit
source set.

| Operation | Event sources | Outcomes |
| --- | --- | --- |
| `process_fork` | `sched/sched_process_fork` | `succeeded` |
| `process_exec` | `sched/sched_process_exec`, `syscalls/sys_enter_execve`, `syscalls/sys_enter_execveat` | `succeeded`; the sched source is mandatory |
| `process_exit` | `sched/sched_process_exit` | `unknown` |
| `file_open` | `syscalls/sys_enter_openat`, `syscalls/sys_exit_openat`, `syscalls/sys_enter_openat2`, `syscalls/sys_exit_openat2` | `succeeded`, `failed`, `denied` |
| `file_create` | file-open sources plus `syscalls/sys_enter_creat`, `syscalls/sys_exit_creat` | `succeeded`, `failed`, `denied` |
| `file_truncate` | file-open sources plus `syscalls/sys_enter_truncate`, `syscalls/sys_exit_truncate` | `succeeded`, `failed`, `denied` |
| `file_unlink` | `syscalls/sys_enter_unlinkat`, `syscalls/sys_exit_unlinkat` | `succeeded`, `failed`, `denied` |
| `file_rename` | `syscalls/sys_enter_renameat2`, `syscalls/sys_exit_renameat2` | `succeeded`, `failed`, `denied` |
| `network_connect` | `syscalls/sys_enter_connect`, `syscalls/sys_exit_connect` | `succeeded`, `failed`, `denied`, `pending` |
| `credential_path_access` | `syscalls/sys_enter_openat`, `syscalls/sys_exit_openat`, `syscalls/sys_enter_openat2`, `syscalls/sys_exit_openat2` | `succeeded`, `failed`, `denied` |

`collector_lifecycle` has this shape:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `record_type` | string | Constant `collector_lifecycle` |
| `schema_version` | u32 | Constant `1` |
| `timestamp_unix_ms` | u128 | Lifecycle time |
| `agent_run_id` | string | Owning Agent Run |
| `collector` | string | Constant `apolysis_observer` |
| `collector_instance_id` | string | Opaque UUID shared by the process's run streams |
| `state` | enum | `started`, `checkpoint`, `stopped`, or `failed` |
| `health` | enum | `healthy`, `degraded`, or `failed` |
| `stop_reason` | enum|null | `null` for start/checkpoint; terminal value below |
| `counters` | object | Required cumulative counter object below |

Normal stop reasons are `agent_run_closed`, `daemon_shutdown`,
`duration_elapsed`, `agent_exited`, and `shutdown_signal`. Failure reasons are
`attach_failure`, `verifier_failure`, `abi_mismatch`, `decode_failure`,
`counter_read_failure`, `storage_failure`, `observer_failure`,
`collector_restart`, and `incomplete_terminal_flush`. The counters object has
eight required `u64` fields: `global_reserve_failures`, `global_map_pressure`,
`global_abi_mismatches`, `global_decode_failures`, `global_truncations`,
`scope_missing_entries`, `scope_missing_exits`, and `scope_pending`.
`started` is `healthy`, has a null reason, and has zero counters. `checkpoint`
has a null reason and is `degraded` exactly when a persistent-loss counter is
non-zero. `stopped` uses a normal reason and is degraded for persistent loss or
non-zero pending. `failed` is `failed` and uses a failure reason.

`event` is the canonical Runtime Observation source record:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `record_type` | string | Constant `event` |
| `timestamp_unix_ms` | u128 | Observation time |
| `session_id` | string | Agent Run ID; this is the legacy wire name |
| `event_source` | enum | `manual`, `process_tree`, `kernel_tracepoint`, `uprobe`, or `runtime_metadata` |
| `event_type` | enum | `session_started`, `runtime_metadata`, `exec`, `file_open`, `file_create`, `file_truncate`, `file_unlink`, `file_rename`, `network_connect`, `credential_read`, or `process_exit` |
| `raw_event_id` | string|null | Canonical join to a raw event |
| `pid` | u32 | Reported process ID |
| `ppid` | u32 | Reported parent process ID |
| `actor` | string | Bounded process, observer, runtime, or integration actor |
| `resource` | string | Redacted target/resource identity |
| `action` | string | Normalized action or metadata value |
| `outcome` | enum|null | Capability outcome enum, or `null` when unsupported |
| `return_value` | i64|null | Linux syscall result |
| `errno` | i32|null | Positive errno derived from a negative result |
| `container_id` | string|null | Runtime container identity |
| `cgroup_id` | string|null | Runtime cgroup identity |
| `host_boot_id` | string|null | Collector-captured boot UUID |
| `scope_generation` | u64|null | Observer-lifetime scope generation |
| `process_generation` | u64|null | Collector-assigned process generation |
| `process_start_time_ns` | u64|null | Boot-relative kernel process start time |
| `exec_generation` | u32|null | Process-local exec generation |
| `parent_process_generation` | u64|null | Known parent process generation |
| `parent_exec_generation` | u32|null | Known parent exec generation |
| `relation_status` | enum | `exact`, `inferred`, `ambiguous`, or `unattributed` |
| `relation_reason` | string | Stable bounded attribution reason |
| `process_command` | string|null | Legacy redacted context; current content-off producer emits `null` |
| `process_executable` | string|null | `executable_ref:<basename>` only |
| `process_started_at_unix_ms` | u128|null | Legacy wall-clock context, not `process_start_time_ns` |

`raw_kernel_event` preserves bounded input before canonicalization:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `record_type` | string | Constant `raw_kernel_event` |
| `timestamp_unix_ms` | u128 | Observation time |
| `session_id` | string | Agent Run ID |
| `event_source` | enum | Event-source enum above; normally `kernel_tracepoint` |
| `event_name` | string | Tracepoint or normalized kernel event name |
| `event_id` | string|null | Stable raw-event join ID |
| `pid` | u32 | Process ID |
| `ppid` | u32 | Parent process ID |
| `uid` | u32 | User ID |
| `gid` | u32 | Group ID |
| `comm` | string | Bounded kernel command name |
| `resource` | string | Persistence-redacted resource |
| `action` | string | Raw action label |
| `outcome` | enum|null | Capability outcome enum |
| `return_value` | i64|null | Linux syscall result |
| `errno` | i32|null | Positive errno or `null` |
| `container_id` | string|null | Container identity |
| `cgroup_id` | string|null | Cgroup identity |
| `host_boot_id` | string|null | Boot UUID |
| `scope_generation` | u64|null | Scope generation |
| `process_generation` | u64|null | Process generation |
| `process_start_time_ns` | u64|null | Boot-relative process start |
| `exec_generation` | u32|null | Exec generation |
| `parent_process_generation` | u64|null | Parent process generation |
| `parent_exec_generation` | u32|null | Parent exec generation |
| `relation_status` | enum | Relation enum above |
| `relation_reason` | string | Stable bounded reason |
| `raw_payload` | string | Bounded persistence-redacted payload |

For `network_connect`, non-negative return is `succeeded`; `EACCES`/`EPERM`
is `denied`; `EINPROGRESS`/`EALREADY` is `pending`; other negative return is
`failed`. For the five file operations, non-negative is `succeeded`,
`EACCES`/`EPERM` is `denied`, and every other negative result is `failed`.
On the wire, `succeeded` requires non-negative `return_value` and null `errno`;
`failed`, `denied`, and `pending` require a negative value and its positive
negation as `errno`; null outcome requires both numeric fields to be null.

The optional intent records have these required shapes:

| Record | Field | Type | Value or meaning |
| --- | --- | --- | --- |
| `intent` | `record_type` | string | Constant `intent` |
| `intent` | `timestamp_unix_ms` | u128 | Ingestion time |
| `intent` | `session_id` | string | Agent Run ID |
| `intent` | `intent_source` | string | Adapter, currently `codex` |
| `intent` | `intent_id` | string | Adapter-stable ID |
| `intent` | `source_event_id` | string|null | Source harness event ID |
| `intent` | `intent_type` | string | Normalized type, for example `tool_call` |
| `intent` | `tool_name` | string | Source tool/function name |
| `intent` | `declared_action` | string|null | Normalized action class |
| `intent` | `target` | string|null | Declared target scope/resource |
| `intent` | `command` | string|null | Content-off executable reference and redaction marker |
| `intent` | `raw_event_id` | string|null | Correlated raw-event ID |
| `intent_correlation` | `record_type` | string | Constant `intent_correlation` |
| `intent_correlation` | `timestamp_unix_ms` | u128 | Correlation time |
| `intent_correlation` | `session_id` | string | Agent Run ID |
| `intent_correlation` | `intent_source` | string | Adapter |
| `intent_correlation` | `intent_id` | string | Declared intent ID |
| `intent_correlation` | `match_basis` | enum | `raw_event_id`, `process_command_exact`, or `process_executable` |
| `intent_correlation` | `raw_event_id` | string | Observed raw-event ID |
| `intent_correlation` | `event_type` | string | Canonical observed type |
| `intent_correlation` | `pid` | u32 | Observed PID, or `0` if unavailable |
| `intent_correlation` | `resource` | string | Observed redacted resource |
| `intent_correlation` | `process_command` | string|null | Redacted observed context |
| `intent_correlation` | `process_executable` | string|null | Observed executable reference |
| `intent_correlation` | `command` | string|null | Redacted declared summary |

`accountability_finding` has required fields `record_type:string` (constant
`accountability_finding`),
`schema_version:u32` (`1`), `session_id:string`, `kind:enum`, `decision:enum`,
`reason:string`, `evidence_ref:string`, `runtime:object`, and
`evidence_boundary:enum`. Kind is `missing_intent`, `unobserved_intent`,
`undeclared_action`, `credential_read`, `workspace_boundary`, `unknown_egress`,
`dangerous_command`, or `service_account_token_read`; decision is `notify` or
`review`; evidence boundary is `host_boundary` or `guest_semantic`. Runtime has
required `runtime:string`, `container_id:string|null`, `pod_uid:string|null`,
and `cgroup_id:u64|null`. The AOR discards source `reason` and substitutes the
kind's canonical bounded reason.

| Finding kind | Canonical AOR `reason` |
| --- | --- |
| `missing_intent` | `observed side effect has no matching declared intent` |
| `unobserved_intent` | `declared intent has no matching observed side effect` |
| `undeclared_action` | `observed action class was not declared by intent` |
| `credential_read` | `workload read a credential-classified resource` |
| `workspace_boundary` | `file access crossed the declared workspace boundary` |
| `unknown_egress` | `network endpoint is outside the declared egress set` |
| `dangerous_command` | `command matches the dangerous-command baseline` |
| `service_account_token_read` | `workload read a Kubernetes service account token` |

`observation_gap` has required `record_type:string` (constant
`observation_gap`),
`schema_version:u32` (`1`), `timestamp_unix_ms:u128`, `agent_run_id:string`,
`operation:string`, `kind:enum`, `count:u64`, and `detail:string`. Legal shapes
are:

| Kind | Operation/count | Source detail | AOR detail |
| --- | --- | --- | --- |
| `missing_entry`, `missing_exit` | `network_connect`, `file_open`, `file_create`, `file_truncate`, `file_unlink`, or `file_rename`; positive count | Bounded producer diagnostic | `bounded_loss_counter` |
| `collector_restart` | `collector_lifecycle`, `1` | Opaque unfinished instance only | `unfinished_collector_instance` |
| `late_attach` | `collector_lifecycle`, `1` | `collection_boundary:protected_existing_process_attach,history:unknown,provenance:<external_registration\|proc_discovery>,root_selection:<registration_qualified\|inferred>` | Same bounded detail |
| `runtime_metadata_unavailable` | `runtime_metadata`, `1` | `source=<docker\|containerd\|k3s_containerd>,reason=<socket_unavailable\|daemon_restart\|inventory_invalid>` | `runtime_source_unavailable` |
| `runtime_metadata_unavailable` | `runtime_metadata`, `1` | Same source set and `reason=identity_transition` | `runtime_identity_transition` |

Runtime-metadata details cannot include paths, payloads, socket names, or
backend text. Every gap adds one AOR `observation_gap` issue and prevents
complete evidence. A runtime-metadata gap does not require a collector
`started` record because the adapter may be configured independently.

The runtime-binding lifecycle records have one shared exact shape:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `record_type` | enum | `runtime_binding_observed`, `runtime_binding_retired`, or `runtime_binding_suspended` |
| `schema_version` | u32 | Constant `1` |
| `agent_run_id` | string | Owning canonical Agent Run ID |
| `adapter` | enum | `docker`, `containerd`, or `k3s_containerd` |
| `workload_id` | string | Non-zero 64-byte lowercase-hex Docker container ID, `containerd/<same-id>`, or `k3s_containerd/<same-id>` |
| `start_marker` | string | Docker UTC `YYYY-MM-DDTHH:MM:SS[.1..9 digits]Z` (valid date, year >= 1970) or canonical positive-decimal u64 CRI `startedAt`; strict RFC3339Nano `Z`/numeric-offset CRI text is normalized to decimal Unix nanoseconds at the adapter boundary |
| `host_boot_id` | string | Canonical lowercase, non-zero host boot UUID |
| `init_process_start_time_ticks` | u64 | Positive `/proc/<init>/stat` start tick |
| `cgroup_device` | u64 | Positive cgroup-filesystem device identity |
| `cgroup_id` | u64 | Positive cgroup-filesystem inode identity; not a PID or independently Exact numeric cgroup claim |
| `runtime_handler` | string|null | Bounded opaque non-path runtime-handler name, or `null` |

All fields above are required; only `runtime_handler` is nullable. These records
have no payload timestamp: their authoritative order is the JSONL source order,
or the enclosing hash-chain sequence. They never contain PID, container name,
raw label or annotation, runtime/cgroup/socket path, endpoint, backend error,
payload, or private namespace. `agent_run_id`, `workload_id`, `start_marker`,
and a non-null `runtime_handler` are bounded identifiers, not free-form capture.

Legal lifecycle order is fail-closed. A successful complete inventory may emit
`runtime_binding_observed`; an identical inventory emits nothing, and only a
successful complete inventory may emit `runtime_binding_retired` for absence.
Stable-identity replacement is its prior `reason=identity_transition` gap,
retirement of the old identity, then observation of the replacement. Runtime
source loss is its prior `reason=socket_unavailable` or
`reason=inventory_invalid` gap, then suspension; only a later fresh complete
inventory may observe the binding again. Daemon recovery holds persisted
bindings dormant; its first fresh complete inventory emits the prior
`reason=daemon_restart` gap, retires the dormant identity, then observes the
currently qualified identity when present. Failure is never an empty inventory.
There is no separate transition record: the canonical identity-transition
representation is the ordered gap -> retired -> observed sequence.

The AOR projector strict-decodes these three record types, binds every record
to the projected Agent Run, and tracks active `(adapter,workload_id)` keys. A
duplicate observation or a retirement/suspension whose full identity does not
match the active binding fails closed. Suspension additionally consumes one
earlier, unmatched source-outage gap credit for the same adapter; credits are
counted once and may span unrelated interleaved records. Because v1 has no
inventory transaction ID, the projector does not guess that an identity- or
daemon-restart gap belongs to an arbitrary retirement. Their stronger effect
order remains a producer/coordinator invariant, while every such gap still
makes the projected evidence incomplete.

`observer_diagnostic` has required `record_type:string` (constant
`observer_diagnostic`),
`timestamp_unix_ms:u128`, `session_id:string`, `kind:enum`, `count:u64`, and
`detail:string`. Kind is `ring_buffer_reserve_failure`, `map_pressure`,
`abi_mismatch`, `decode_failure`, `truncation`, `attach_failure`,
`verifier_failure`, or `summary`. `visibility_assessment` has required
`record_type:string` (constant `visibility_assessment`), `session_id:string`, `runtime_profile:enum`,
`host_visibility_scope:enum`, `host_semantics_collapsed:boolean`,
`guest_collector_required:boolean`, `runtime_metadata_required:boolean`,
`host_event_subjects:array<string>`, `pod_name:string|null`,
`namespace:string|null`, `runtime_class_name:string|null`,
`sandbox_name:string|null`, and `notes:string`. Runtime profile is
`docker-default`, `docker-gvisor`, `kubernetes-gvisor`, `kubernetes-kata`, or
`firecracker-prototype`; host scope is `guest_process`, `runtime_boundary`, or
`boundary_only`.

### 6.2 Local Session query schema v1

The local daemon query is not a timeline record. A valid
`{"type":"query","tenant_id":"<tenant>","session_id":"<agent-run>"}`
request returns this `DAEMON_SCHEMA_V1` response:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `type` | string | Constant `session` |
| `schema_version` | u32 | Constant `1` |
| `session` | object|null | Matching `SessionState`, or `null` when absent or not visible to the tenant |
| `runtime_bindings` | array<object> | Active bindings for that visible Agent Run; always present, and empty when `session` is `null` |

Each `runtime_bindings` element has exactly these required nested fields:

| Field path | Type | Value or meaning |
| --- | --- | --- |
| `agent_run_id` | string | Same Agent Run requested and returned in `session` |
| `identity.adapter` | enum | `docker`, `containerd`, or `k3s_containerd` |
| `identity.workload_id` | string | Full stable workload/container ID described above |
| `identity.start_marker` | string | Runtime-native start marker |
| `identity.host_boot_id` | string | Canonical host boot UUID |
| `identity.init_process_start_time_ticks` | u64 | Positive init-process start tick |
| `identity.cgroup.device` | u64 | Positive cgroup-filesystem device identity |
| `identity.cgroup.inode` | u64 | Positive cgroup-filesystem inode identity |
| `runtime_handler` | string|null | Bounded opaque handler name, or `null` |

The array contains active, freshly qualified bindings only; dormant, suspended,
and retired bindings are excluded and entries are ordered by adapter/workload
key. `tenant_id` defaults to `default` when omitted. The daemon first requires
the requested Agent Run's registered tenant to equal the query tenant; only
then does it read bindings. `session` and `runtime_bindings` come from one
tenant-gated atomic snapshot, so concurrent tenant replacement cannot separate
the authorization decision from binding disclosure. An absent or cross-tenant
Agent Run therefore returns `session:null` and `runtime_bindings:[]`, preventing binding identity
from becoming a cross-tenant existence oracle. The query preserves the same
privacy boundary as persistence: it exposes no raw label, namespace, PID,
container name, cgroup/runtime/socket path, endpoint, backend error, or payload.

### 6.3 Agent Observation Record v1

The projection is one deterministic JSON object, never a timeline line.
Inputs remain in command-line and segment order; every projected source fact
uses a one-based `source_ordinal`, and timestamps never reorder records.

| Top-level field | Type | Contract |
| --- | --- | --- |
| `record_type` | string | Constant `agent_observation_record` |
| `schema_version` | u32 | Constant `1` |
| `agent_run_id` | string | One non-empty run shared by all source records |
| `source_integrity` | enum | `unverified_plain_jsonl`, `verified_hash_chain`, or `mixed` |
| `summary` | object | State and deterministic aggregates below |
| `capability_manifests` | array<object> | Projected compatible manifests |
| `runtime_identities` | array<object> | Exact identity aggregates |
| `runtime_observations` | array<object> | Canonical supported observations |
| `runtime_bindings` | array<object> | Ordered validated runtime-binding lifecycle facts; new v1 output always includes it |
| `collector_lifecycle` | array<object> | Ordered lifecycle facts |
| `findings` | array<object> | Typed review findings |
| `observation_gaps` | array<object> | Normalized bounded gaps |
| `issues` | array<object> | Projection limitations |

The required `summary` fields are three enums (`evidence_state`:
`complete|active|incomplete|failed|indeterminate`, `collector_health`:
`healthy|degraded|failed|unknown`, `review_state`:
`requires_review|no_findings_reported|indeterminate`), six `u64` counts
(`runtime_observation_count`, `runtime_identity_count`, `finding_count`,
`observation_gap_record_count`, `known_missing_observation_count`,
`unknown_history_boundary_count`) and five `map<string,u64>` aggregates
(`event_type_counts`, `outcome_counts`, `relation_counts`,
`finding_kind_counts`, `gap_kind_counts`).

Nested array object schemas are:

| Array/object | Required fields and types |
| --- | --- |
| capability manifest | `source_ordinal:u64`, `schema_version:u32`, `timestamp_unix_ms:u128`, `collector:string`, `collector_version:string`, `kernel_abi_version:u32`, `kernel_record_size:u32`, `observation_scope:string`, `privacy_profile:string`, `capabilities:array<object>` |
| capability | `operation:string`, `event_sources:array<string>`, `outcomes:array<string>` |
| runtime identity | `identity_id:string`, `host_boot_id:string`, `scope_generation:u64`, `pid:u32`, `process_generation:u64`, `process_start_time_ns:u64`, `exec_generation:u32`, `first_source_ordinal:u64`, `last_source_ordinal:u64`, `observation_count:u64` |
| runtime observation | `source_ordinal:u64`, `timestamp_unix_ms:u128`, `event_source:string`, `event_type:string`, `raw_event_id:string|null`, `pid:u32`, `ppid:u32`, `actor:string`, `resource:string`, `action:string`, `outcome:string|null`, `return_value:i64|null`, `errno:i32|null`, `container_id:string|null`, `cgroup_id:string|null`, `relation_status:string`, `relation_reason:string`, `process_executable:string|null`, `process_started_at_unix_ms:u128|null`, `runtime_identity_id:string|null`, `parent_process_generation:u64|null`, `parent_exec_generation:u32|null` |
| runtime binding | `source_ordinal:u64`, `record_type:enum`, `schema_version:u32`, `agent_run_id:string`, `adapter:string`, `workload_id:string`, `start_marker:string`, `host_boot_id:string`, `init_process_start_time_ticks:u64`, `cgroup_device:u64`, `cgroup_id:u64`, `runtime_handler:string|null`; the last eleven fields are the exact runtime-binding v1 lifecycle wire shape |
| collector lifecycle | `source_ordinal:u64`, `schema_version:u32`, `timestamp_unix_ms:u128`, `collector:string`, `collector_instance_id:string`, `state:enum`, `health:enum`, `stop_reason:enum|null`, `counters:object` with the same eight `u64` fields as timeline lifecycle |
| finding | `source_ordinal:u64`, `schema_version:u32`, `kind:enum`, `decision:enum`, `reason:string`, `evidence_ref:string`, `runtime:object`, `evidence_boundary:enum`; runtime uses `runtime:string`, `container_id:string|null`, `pod_uid:string|null`, `cgroup_id:u64|null` |
| observation gap | `source_ordinal:u64`, `schema_version:u32`, `timestamp_unix_ms:u128`, `operation:string`, `kind:string`, `count:u64`, `detail:string` using the normalized table above, plus optional `runtime_source:string` and `runtime_reason:string` as defined below |
| issue | `code:enum`, `source_ordinal:u64|null`, `count:u64` |

Version 1 accepts at most one capability manifest; a duplicate manifest is a
structural error rather than a second capability epoch. Enum values in nested
lifecycle, observation, Finding, and Gap objects are the corresponding
timeline enums and canonical projections defined above.

`runtime_bindings` is a default-compatible v1 extension. New projection output
always contains the array, while a legacy v1 AOR that omits it is read as an
empty array. The array preserves every validated `runtime_binding_observed`,
`runtime_binding_retired`, and `runtime_binding_suspended` fact, not only the
binding active at the end of the run. Each element belongs to the projected
Agent Run and remains in authoritative `source_ordinal` order. The projector
and frozen-record validator both reconstruct the active binding state and
enforce the lifecycle identity and sequence rules in Section 6.1.

A Finding whose `evidence_ref` is `runtime_binding:<workload_id>` is resolved
only by a `runtime_binding_observed` fact from the same run that appears before
the Finding and whose `adapter`, `workload_id`, and `cgroup_id` exactly match
the Finding's runtime, container ID, and cgroup ID. A retired or suspended fact
never grants support, even when its fields match. The Saved Run Viewer exposes
each binding fact at its source ordinal and lets a supported Finding jump to
that exact earlier observed fact; unresolved references remain limitations.

For a newly projected `runtime_metadata_unavailable` gap, `runtime_source` and
`runtime_reason` are both present. Source is exactly `docker`, `containerd`, or
`k3s_containerd`; reason is exactly `socket_unavailable`, `inventory_invalid`,
`daemon_restart`, or `identity_transition`. Other gap kinds omit both fields.
The pair is a default-compatible v1 extension: a legacy AOR may omit it, but a
missing or partial pair never authorizes a later `runtime_binding_suspended`.
The frozen-record validator replays gaps and binding facts together in
`source_ordinal` order. Only an earlier, unconsumed gap for the same adapter
with reason `socket_unavailable` or `inventory_invalid` grants one suspension
credit. `daemon_restart` and `identity_transition` do not grant suspension
credit, and every credit is single-use.

Issue code is exactly `missing_capability`, `unsupported_capability`,
`missing_lifecycle_start`, `missing_lifecycle_terminal`, `collector_loss`,
`collector_diagnostic`, `observation_gap`, `unsupported_observation`,
`unsupported_outcome`, `unknown_record_type`, `source_integrity_finding`,
`no_runtime_observations`, or `unresolved_finding_evidence`. A null issue
ordinal denotes a run-wide issue rather than a copied source fact.
`unsupported_capability` counts missing or mismatched contract operations on
its manifest. Source-bound unsupported-observation/outcome, unknown-record,
integrity, and unresolved-Finding issues count one each. `observation_gap` and
`collector_diagnostic` retain the source count. Run-wide missing-capability,
missing-start, no-observation, and mixed-integrity issues count one; a
missing-terminal issue counts unfinished collector instances. `collector_loss`
points to the latest lossy lifecycle record and counts one.

Exact identities are scoped by the active `collector_instance_id` and require
`event_source=kernel_tracepoint`, non-null canonical
`raw_event_id`, relation `exact` with reason
`host_boot_scope_process_start_exec_generation`, and the complete tuple
`(host_boot_id,scope_generation,pid,process_generation,process_start_time_ns,exec_generation)`.
First appearance assigns `identity-1`, `identity-2`, and so on. Non-exact facts
remain unmerged. Complete evidence requires a compatible content-off manifest,
a legal normal lifecycle terminal, at least one supported observation, and no
loss, gap, diagnostic, integrity, capability, or unresolved-evidence issue.
A Finding changes only review state. `no_findings_reported` is not a clean-run
verdict.

For capability checks, projected event types map as follows: `exec` to
`process_exec`, `process_exit` to `process_exit`, each `file_*` event to its
same-named operation, `network_connect` to `network_connect`, and
`credential_read` to `credential_path_access`. Other event types and any
non-`kernel_tracepoint` source add `unsupported_observation`; a missing or
undeclared outcome adds `unsupported_outcome`.

### 6.4 Local hash-chain envelope

A hash-chain timeline is JSONL whose every line has required
`schema_version:u32`, `sequence:u64`, `previous_hash:string`,
`record_hash:string`, and `payload:object`. Sequence starts at `1`; the first
previous hash is 64 lowercase zeroes, and each later `previous_hash` equals the
preceding `record_hash`. The payload is canonicalized by parsing JSON and
recursively serializing it as compact UTF-8 JSON: object keys are sorted
lexicographically, array order is preserved, no insignificant whitespace or
slash escaping is added, strings escape JSON control characters, quote, and
backslash, and numbers use the shortest serde-json representation (timeline
contracts use integers).
The lowercase hexadecimal record digest is:

```text
SHA-256(
  schema_version as 4-byte unsigned big-endian
  || sequence as 8-byte unsigned big-endian
  || UTF-8 bytes of previous_hash
  || UTF-8 bytes of compact canonical payload JSON
)
```

There are no separators or length prefixes between those four byte strings.
Verification checks the expected sequence, link, canonicalized payload digest,
and complete final line. Its report contains `path:string`, `passed:boolean`,
`record_count:integer`, `last_sequence:u64`, `last_record_hash:string`,
`valid_bytes:u64`, `total_bytes:u64`, and `failure:string|null`. Verification is
read-only; middle corruption and a truncated or corrupt tail fail closed.

Canonical joins use raw kernel `event_id`, canonical `raw_event_id`, optional
intent `raw_event_id`, correlation `raw_event_id`, and Finding `evidence_ref`.
For runtime-binding evidence, the bounded Finding reference joins only to the
earlier observed lifecycle source ordinal under the exact rules in Section 6.3;
retired and suspended lifecycle facts are excluded from that support relation.
Timestamp-only matching never creates an Exact relation. Raw exec argv is
replaced by redaction/truncation markers; credential paths and socket addresses
are tokenized before output. Rotation is a storage budget, never a schema
change, and never splits one JSONL record.

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

Collector lifecycle records use one opaque instance ID per collector process
and one record stream per Agent Run. `started` is durable before a managed
Agent is released or a daemon scope registration completes. Periodic
`checkpoint` records carry cumulative loss counters plus the current
`scope_pending` in-flight gauge, and are emitted even for quiet workloads.
Their `global_*` counters describe collector-wide loss and retain that name
when copied into each active run; `scope_*` counters contain only the owning
Observation Scope's entry/exit pairing state. For the daemon, that is the sum
of only the cgroups owned by the Agent Run. A non-zero loss counter degrades a
checkpoint. Pending alone remains healthy while collection is active, but
degrades a terminal because it then represents unmatched work at stop.

For protected existing-process attach, the durable start boundary is appended
and synchronized in this order: the mandatory `late_attach` gap, the Collector
Capability manifest, then `started`. The gap's `count:1` means one
unknown-history Collection Boundary. Its `root_selection` detail describes
`registration_qualified` registration or `inferred` discovery selection; it
does not extend or override the canonical `exact`, `inferred`, `ambiguous`, and
`unattributed` event relation statuses. `registration_qualified` describes only
the root visible when its pidfd is opened, not pre-anchor continuity.
The three records are serialized as one durable batch: rotation is evaluated
once for the complete batch, and a write or synchronization failure truncates
the active file back to its pre-batch length before attach fails.

Daemon checkpoints and terminals first wait on a sequence fence covering every
pipeline record admitted before that boundary. The lifecycle boundary is then
appended directly to the per-run hash chain, so a full bounded queue cannot
drop it and later high-priority traffic cannot make it overtake older evidence.
An ordinary writer failure pauses the affected run and signals scope failure
asynchronously; the single writer never waits for observer untrack or for the
failed terminal that untrack produces.

After confirmed event drain and Observation Gap persistence, a normal path
writes `stopped` with an explicit reason. A fatal attach, verifier, ABI,
decoder, counter, observer, or writable-storage path writes `failed` when the
timeline remains writable. On daemon recovery, a `started` or `checkpoint`
instance without `stopped` or `failed` receives one `collector_restart`
Observation Gap and one recovered failed terminal. The repair is idempotent.
A standalone timeline with a missing terminal is still incomplete, even when
no process remains available to append the gap.

Runtime metadata loss uses one bounded v1 shape:

```json
{"record_type":"observation_gap","schema_version":1,"agent_run_id":"<agent-run>","operation":"runtime_metadata","kind":"runtime_metadata_unavailable","count":1,"detail":"source=docker,reason=socket_unavailable"}
```

`source` is exactly `docker`, `containerd`, or `k3s_containerd`. Source-outage
`reason` is exactly `socket_unavailable`, `daemon_restart`, or
`inventory_invalid`; the same workload key changing stable identity uses
`reason=identity_transition`. Paths, payloads, socket names, and free-form
backend errors are forbidden. The Agent Observation Record normalizes outage
details to `runtime_source_unavailable` and identity changes to
`runtime_identity_transition`, while retaining the bounded source and reason
in `runtime_source` and `runtime_reason`. It adds one `observation_gap` issue
and cannot be complete. This gap does not require an eBPF collector `started`
lifecycle record because a runtime adapter may be configured independently.
For an identity transition, durable effect order is gap, retire, then attach.

The Agent Observation Summary exposes three independent conclusions:

- `evidence_state` is `complete`, `active`, `incomplete`, `failed`, or
  `indeterminate`;
- `collector_health` is `healthy`, `degraded`, `failed`, or `unknown`;
- `review_state` is `requires_review`, `no_findings_reported`, or
  `indeterminate`.

Complete evidence requires one compatible content-off capability manifest, a
legal started-to-normal-terminal lifecycle, at least one supported Runtime
Observation, and no loss, gap, diagnostic, integrity, or capability issue.
Active or failed lifecycle state remains explicit. Mixed source integrity and
unknown additive record types make an otherwise complete-shaped run
indeterminate. A Finding changes review
state but does not rewrite evidence completeness. A `late_attach` count of one
increments the unknown-history-boundary count, never the known-missing-event
count. Mixed Agent Runs, malformed or incompatible records, content-policy
violations, invalid lifecycle order, duplicate canonical observations, and
conflicting Exact Runtime Identity fail closed.

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

The machine-readable qualification authority lives in the source tree at the
[qualification envelope](https://github.com/0xLaiHo/Apolysis/blob/main/qualification/envelope-v1.json),
with its versioned workload definitions under the adjacent `qualification/workloads/`
directory. A release documentation archive is a human-readable snapshot and
does not embed those machine files; consumers that qualify or promote a profile
must use the envelope from the matching source revision. Linux 6.12/x86_64
native host is Candidate, not Supported: it requires cgroup v2, readable target BTF and tracefs, the 19
declared tracepoints with inspected formats, the production verifier/load/full
attach path, and effective `CAP_BPF` plus `CAP_PERFMON`. Other feature-probed
Linux 5.11+ x86_64 kernels, aarch64, Docker, containerd, Kubernetes, and the
legacy `CAP_SYS_ADMIN` fallback remain Experimental. Missing required hooks,
cgroup v1/hybrid scope, rootless host collection, non-Linux, or kernels below
the feature floor without backports are Unsupported.

Qualification uses versioned content-free `idle`, `representative`, and
`burst` workloads. Paired same-boot collector-off/on trials retain workload and
collector CPU separately, process/cgroup/BPF memory separately, monotonic
kernel-to-decode/append latency, exact expected/observed/lost event maps, and
phase-scoped burst loss. The representative profile requires zero known and
unexplained loss. Numeric CPU, memory, latency, repetition, and rated-event
budgets remain unset until sufficient privileged live evidence supports a
reviewed conservative bound. Fixtures test the checker and cannot promote a
profile. Supported promotion requires retained raw live evidence, frozen
budgets and exact tuples in the machine envelope, privacy/overload review, and
the complete applicable release gates.

Visibility claims remain profile-specific. Docker default normally preserves
guest-process host semantics when exact container/cgroup identity exists.
gVisor may collapse observations to the runtime boundary and therefore
requires runtime metadata for correlation. Kata and Firecracker expose
VMM/shim/host boundaries; complete guest process, file, network, or credential
semantics require a guest collector. Kubernetes metadata cannot restore guest
semantics that the host source did not observe.

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
- Registration host/start/executable/command-fingerprint/workspace values are
  qualification inputs. Full executable and workspace paths and the command
  fingerprint do not cross the persistence seam; only bounded identity and
  redacted supervisor metadata are retained.
- Raw kernel payload exists only as a bounded implementation detail and may not
  cross the persistence seam without an explicit, reviewed profile.
- Observation scopes prevent accidental host-wide collection.
- Local files use restrictive permissions and bounded retention. Daemon
  lifecycle changes accept only the manifest/receipt-owned fixed artifact set,
  refuse linked or unmanaged substitution before mutation, and preserve saved
  Agent Runs during default uninstall.
- The viewer is non-privileged and has no path to BPF maps, host PID namespace,
  container sockets, or node credentials.
- The standalone viewer escapes all stored text and uses a restrictive Content
  Security Policy that permits no network connection or external asset. The
  artifact contains projected run facts and therefore retains mode-`0600`
  publication semantics.

## 11. Failure semantics

The following always produce an explicit gap or failed/degraded collector
state:

- ring-buffer reserve failure or map pressure;
- truncated resource or payload;
- kernel/userspace ABI mismatch;
- decode, attach, verifier, or permission failure;
- collector restart or death;
- runtime socket loss, daemon restart, invalid runtime inventory, or stale
  container identity transition;
- late attach, PID reuse ambiguity, or missing process lineage;
- unsupported syscall, io_uring, guest, or remote operation path;
- local storage failure or incomplete terminal flush.

A quiet timeline is never proof that the Agent performed no relevant action.

## 12. Current implementation mapping

Implemented today:

- `ebpf/observer` and `apolysis-observer`: CO-RE tracepoints, ring buffer,
  process-tree/cgroup scopes, ABI v3, bounded process/exec and cgroup scope
  generations, outcome-aware selected file operations and network connect,
  protected existing-process TGID seeding, per-cgroup operation gap counters,
  redaction, lifecycle checkpoints and terminals, and health/gap diagnostics;
- `apolysis-cli`: fixture/live observation, managed Agent launch, protected
  existing-process attach through registration or discovery, non-privileged
  saved-run projection and Saved Run Viewer publication, optional Codex intent
  correlation, visibility, verification, and bounded daemon
  install/inspect/uninstall commands;
- `apolysis-core`: current JSONL vocabulary, record types, versioned Collector
  Capability manifest, and collector lifecycle schema, including the single
  authoritative lifecycle vocabulary and complete AuditObserver v1
  operation/source/outcome contract consumed by both producer and projection;
- `apolysis-store`: rotation, optional local hash-chain envelopes, no-follow
  descriptor-bound recovery, and bounded stable-snapshot readers for
  plain/rotated or verified saved runs;
- `apolysis-accountability`: the pure Agent Observation Record projection,
  independent summary axes, optional declared-intent comparison, and
  review-oriented findings;
- `apolysis-viewer`: strict Agent Observation Record v1 validation and
  deterministic standalone offline HTML presentation with source traceability;
- `apolysis-kubernetes` and `apolysis-visibility`: bounded runtime metadata and
  visibility-boundary assessment;
- `apolysis-daemon`: long-lived observer, bounded queue, local socket, runtime
  registration, complete Docker/containerd inventory qualification, stable
  container/cgroup binding, bounded runtime-source and daemon-restart recovery,
  scoped lifecycle persistence, idempotent unfinished-instance recovery,
  receipt-owned local operations, and identity-bound journaled retention.

The live collector synchronizes its capability manifest and lifecycle start to
stable storage after successful attachment and before releasing a managed
Agent gate. For protected existing-process attach it first persists the single
unknown-history `late_attach` boundary. Selected file operations and network
connect have bounded entry/exit outcome semantics, and the daemon persists
their pairing gaps to the owning Agent Run at explicit scope removal and clean
shutdown. Stable in-run scope/process generations, periodic cumulative
lifecycle checkpoints, explicit terminal reasons, and restart-gap recovery are
implemented together with the queryable saved-run projection and the
non-privileged Saved Run Viewer. Docker/containerd stable identity and runtime
recovery are implemented with typed runtime-metadata gaps. Retained
non-destructive Docker gates cover complete-inventory identity churn,
socket-outage recovery, private daemon-lifecycle recovery, and exact
content-off eBPF container/cgroup attribution with capability and hash-chain
evidence. The independent retained private-containerd gate covers stable and
replacement complete inventories plus socket gap -> suspension -> fresh
observation under the isolation and cleanup contract in section 5.3.
Destructive systemd runtime-service restart and K1/VKE qualification remain
open. Bounded local daemon filesystem operations are implemented; no Supported
live-host profile is granted, and the bounded Kubernetes beta remains a target.

The central contracts, Gateway, PostgreSQL projection, evidence-object cluster,
policy/feedback/control planes, sandbox runner, and broad qualification
machinery have been removed from the active workspace. Git history preserves
them as historical implementation input; they do not define this architecture.

## 13. Limitations

- Local daemon operations target the documented Linux/systemd layout and five
  fixed runtime artifacts. They are not a distribution package manager or a
  general arbitrary-prefix installer. Staged-root qualification proves the
  bounded filesystem behavior, not privileged activation; a live claim
  requires the explicit systemd/eBPF gate. Default uninstall intentionally does
  not purge retained Agent Runs. The transaction profile requires procfs plus
  Linux `O_TMPFILE` and `renameat2` support on the managed filesystem; an
  unsupported host fails before publication.
- L3 renders one bounded, local, frozen Agent Observation Record v1. It is not
  a live tail, cross-run search, remote query surface, or central query plane.
- Agent Observation Record v1 lacks an authoritative parent Runtime Identity
  link. The viewer can show the Exact Runtime Identity roster and each
  observation's reported PID/PPID, but cannot construct a canonical process
  tree without unsafe PID-based inference.
- eBPF sees kernel/runtime operations, not logical reasoning or hidden remote
  provider state.
- Relative paths, file-descriptor-relative operations, namespaces, overlays,
  and guest runtimes require explicit resolution and capability limits.
- A successful connect does not prove that a remote operation committed.
- Same-process logical Agents cannot be separated without an additional
  propagated identity; runtime-only attribution remains process-level.
- Protected existing-process attach supports only the initial PID namespace
  and a shared initial, unshifted time namespace.
- Per-seeded-candidate pidfd sandwiches and the exit hook close exit and
  replacement races after a candidate is anchored. They cannot establish
  pre-anchor selection continuity: an external-registration root can be
  substituted between registration creation and root `pidfd_open` by a process
  with the same PID, USER_HZ tick, executable, and command; a lineage candidate
  can likewise be substituted between its snapshot and `pidfd_open` by one with
  the same PID, tick, and lineage. These bounded same-tick ambiguities limit the
  selection claim even though kernel start time plus process and exec
  generations provide exact event identity after activation within that
  collector run.
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
- The current qualification contract grants no Supported profile. Linux 6.12
  x86_64 native host is Candidate only; other kernels, architectures, and
  container/Kubernetes runtimes remain Experimental until exact retained live
  evidence passes. The deterministic content-free workloads and paired raw
  capture harness freeze expected event counts, monotonic latency samples,
  isolated collector CPU/process/cgroup/BPF memory samples, and pair-level
  bootstrap summaries, with burst loss attributed to separate rate phases.
  Conservative numeric budgets and enough retained privileged repetitions are
  still required for promotion.

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

## 15. Direction and release gates

The local Agent Run workflow, non-privileged projection/viewer, bounded daemon
operations, and the completed D1/D2 implementation with retained independent
Docker and private-containerd qualification form the current foundation. The
next bounded direction is K1 least-privilege Kubernetes node and Pod
attribution, followed by release preparation. Its designated, runtime- and
network-ready VKE validation must cover representative reschedule, sensor loss,
runtime boundary, cleanup, and privacy. Docker evidence cannot be reused as
containerd or Kubernetes evidence, and private-containerd evidence cannot be
reused as Kubernetes evidence. Destructive systemd runtime-service restart
qualification remains an independent, optional claim. No profile advances
beyond Experimental or Candidate until its exact workload/kernel/runtime and
applicable release evidence passes.

Cross-cutting rules are durable: scope before capture, capability before claim,
no silent absence, stable identity before inference, privacy before
persistence, observation rather than enforcement, a non-privileged viewer, and
expansion only when repeated use changes a real investigation decision.

The following remain explicitly deferred: provider Hook/SDK/OTLP/MCP/A2A
families; generic remote export or custody; remote outcome verification; live
tailing and cross-run search; central authenticated ingest, multi-user query,
PostgreSQL/S3/KMS custody and multi-tenant retention; policy denial or
containment; portable evidence receipts; public SaaS, HA and multi-region;
general package-manager abstraction; and automatic purge of retained Agent
Runs during uninstall. They return only with demonstrated demand and a new
architectural decision.

A profile is a release no-go if any applicable condition holds:

- loss, failure, truncation, restart, unavailable runtime metadata, unsupported
  paths, or missing terminal state can produce unmarked complete evidence;
- entry-only, PID/name/time-only, stale container, or ambiguous correlation is
  presented as a successful operation or Exact Runtime Identity;
- protected attach bypasses qualification, omits its ordered unknown-history
  boundary, or overclaims pre-anchor continuity;
- mixed, malformed, corrupt, unsupported, unresolved, or gap-bearing input is
  rendered stronger than its source, or a viewer invents process-tree edges;
- secret, argv, prompt, response, payload, credential, private path, socket,
  label, annotation, kubeconfig, or private workload data crosses the default
  persistence, log, error, test, or repository boundary;
- the viewer needs privileged host access, or a Finding is described as
  blocking or enforcement;
- install, replacement, uninstall, retention, recovery, runtime cleanup, or
  Kubernetes validation can mutate unrelated state or lacks its required live
  evidence; or
- kernel, runtime, operation, privacy, performance, packaging, and cleanup
  envelopes remain undocumented, untested, or budgetless for the claimed
  profile.

Expansion continues only when representative Agent Runs are automatically
scoped and attributed, operators use the process/file/network investigation,
gaps prevent false clean conclusions, and container or Kubernetes context
changes a real review or incident decision. If generic telemetry already
suffices, eBPF evidence does not change decisions, deployment privilege costs
more than the workflow is worth, most activity is remote, or adapter
maintenance displaces collector correctness, the project should simplify
rather than broaden.

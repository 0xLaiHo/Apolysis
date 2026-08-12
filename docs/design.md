# Apolysis Design

> English | [Simplified Chinese](design.zh-CN.md)
> Last reviewed: 2026-08-12

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
workflows are local Agent CLIs, Linux self-hosted CI, and containers. The K1
implementation adds a bounded Kubernetes containerd/K3s node workflow without
promoting that still-unqualified profile beyond Experimental.

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
  |- Kubernetes Workload Claim
  |- Kubernetes Attribution
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
| Kubernetes Workload Claim | Operator-authorized exact cluster/namespace/Pod/container slot for one Agent Run and claim revision |
| Kubernetes Attribution | Qualified lifecycle relation from one exact claim and stable Pod candidate to one active Exact D1 runtime binding |
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
Those gates and the K1/VKE Kubernetes live qualification remain open; their
status does not invalidate the retained Docker or private-containerd evidence.

#### Kubernetes node and Pod attribution (K1)

K1 is deployed as one two-container DaemonSet Pod per node. The root collector
owns eBPF loading, the host `/proc`, cgroup, BPF, trace/BTF, exactly one CRI
runtime socket, and the local state boundary. It has no service-account token.
It is not a privileged container, cannot escalate privileges, uses a read-only
root filesystem, drops all ambient capabilities, and adds exactly `BPF`,
`PERFMON`, `SYS_RESOURCE`, and `DAC_READ_SEARCH`; it does not receive
`SYS_ADMIN`. The Pod does not join the host PID or network namespace.
The metadata-source container runs as UID/GID `65532`, drops all capabilities,
uses a read-only root filesystem, and alone receives a projected, rotating
service-account token. Production startup verifies the exact effective UID and
GID and a zero effective capability set. Its Role permits only Pod `list` and `watch` in
the DaemonSet's own dedicated Agent namespace; automatic token mounting is
disabled. It has no cluster-wide or cross-namespace read path.
The dedicated namespace is an operator-controlled trust domain: untrusted
tenants must not receive Pod `create`, `update`, or `patch` authority there.

The containers share only a bounded memory-backed IPC volume. The source owns a
mode-`0700` directory and a UID/GID-`65532`, mode-`0660` Unix socket; the
source binds under an unpredictable private name and publishes the fully
qualified socket with one no-replace rename. The collector receives shared GID
`65532` under a strict supplemental-group policy and retains `DAC_READ_SEARCH` alongside
its BPF capabilities to traverse that private directory. Both ends validate the
socket type, ownership, mode, pre/post-connect inode identity and peer
credentials around bounded framed I/O. Stale-socket recovery uses a
nonblocking liveness probe and removes only the exact proven inode. The
collector's persistent host directory is a separate operator precondition and
must already exist as root-owned mode `0700`; the DaemonSet never creates a
broad host path. A K1 daemon owns exactly one `containerd` or
`k3s_containerd` inventory domain, and configuration with both sockets is
rejected. The shipped canonical manifest is pinned to the VKE/containerd path
`/run/containerd/containerd.sock`. K3s support is implemented, but an operator
must supply a matching K3s socket manifest or overlay that preserves this
security and ownership contract; the repository does not ship one. A host CRI
socket nevertheless exposes mutating protocol methods, so
the collector remains node-trusted. Removing `SYS_ADMIN`, separating the token,
and mounting host files narrowly are relative privilege reductions, not a
read-only runtime boundary. True read-only CRI access requires a future
allowlist broker rather than direct socket ownership.

Operator authorization enters through `SessionIntent.kubernetes_claims`, not
through discovered Pod metadata. Each claim has one non-zero revision and the
exact tuple `(cluster_id,namespace_ref,pod_uid,container_kind,container_ref)`;
all claims in one intent share the revision and duplicate slots are rejected.
The operator must generate a cross-cluster unique, immutable `cluster_id` for
the deployment. The source validates only canonical, non-zero UUID shape; it
cannot detect accidental reuse or prove cluster identity.

| Claim field | Contract |
| --- | --- |
| `schema_version` | u32 constant `1` |
| `claim_revision` | Non-zero u64 shared by every claim in the intent |
| `cluster_id` | Canonical lowercase non-zero UUID |
| `namespace_ref` | 64-byte lowercase hexadecimal namespace pseudonym |
| `pod_uid` | Canonical lowercase non-zero Pod UUID |
| `container_kind` | `application`, `init`, or `ephemeral` |
| `container_ref` | 64-byte lowercase hexadecimal container-name pseudonym |

An intent carries at most 256 K1 claims. Unknown claim fields, mixed revisions,
duplicate exact slots, malformed references, and an expired or invalid parent
intent fail before daemon state changes.
`apolysisd-control` reads one bounded typed control request from standard input,
validates the local daemon socket and peer, applies one I/O deadline, and
forwards the request without echoing rejected values. It is the intended
operator ingress from `kubectl exec` into the collector container. Source
labels and annotations remain discovery inputs and can never create or widen a
claim.

The Kubernetes node task explicitly enables CRI Pod-sandbox metadata joining.
Standalone containerd keeps its existing direct-container-only behavior, while
K3s retains its existing sandbox-label behavior. In K1 mode, only a READY Pod
sandbox whose label is exactly `apolysis.dev/observe=true` participates;
unmarked sandboxes are ignored before their private metadata is parsed. A
marked sandbox must carry `metadata.namespace`; a different namespace is
ignored even when its session value matches, while the configured namespace
also requires standard label `io.kubernetes.pod.namespace` to match exactly.
The sandbox Agent Run may come from label `apolysis.session_id` or annotation
`apolysis.dev/session-id` and is normalized to inherited
`apolysis.session_id`. A direct container session label remains a valid routing
input for a candidate D1 identity, but it must equal inherited routing when both
exist. Neither direct nor inherited session metadata authorizes D1/scope
attachment. A present empty or
invalid session value, conflicting label/annotation, missing or conflicting
target namespace, duplicate READY target sandbox ID, or direct/inherited
conflict during listing or inspect invalidates the complete CRI inventory.
Diagnostics report only a fixed category and never the rejected metadata. The
adapter's final candidate re-list uses the identical K1 mode and invalidates the
inventory if the canonical set changed.

This fail-closed metadata behavior is also an explicit availability boundary.
A malformed marked sandbox in the operator namespace degrades that node's
K1/runtime cycle. Exact typed claims prevent such metadata from widening
authorization, but K1 does not claim denial-of-service resistance against a
principal that already has Pod write authority in the dedicated namespace.

Qualification is one closed transaction:

```text
complete paginated Pod LIST A
  -> complete containerd/K3s CRI inventory (whole-scan request_timeout)
  -> complete paginated Pod LIST B
  -> exact typed-claim intersection
  -> filter to claim-authorized full D1 identities
  -> D1 reconcile/attach before durable Kubernetes attribution
```

Watch is only a dirty hint; it is never authority. LIST A and LIST B must have
the same source epoch, cluster, namespace, and node identity, strictly
increasing non-zero sequences, and byte-equivalent canonical Pod candidates.
The candidate includes Pod UID, deletion/marker state, runtime-class reference,
every application/init/ephemeral container slot and running container ID, plus
an ephemeral `pod_revision_ref` derived from the Pod resource version. A later
cycle in the same epoch must begin after the prior terminal sequence. Any
pagination, decoding, bound, duplicate, revision, or A/B mismatch invalidates
the whole snapshot; failure is never interpreted as an empty list.

The intersection requires a marked, non-deleting Pod, an exact claim slot, a
running container with a canonical full ID, and a candidate carrying the full
Exact D1 identity for the same Agent Run. Only the resulting exact
`claim -> A/B Pod UID+slot -> runtime container ID -> full D1 identity` key
enters the admitted inventory. D1 reconciliation and scope attachment consume
that filtered inventory; an unclaimed, mismatched, or metadata-only candidate
cannot produce D1 state or scope ownership. Durable effect ordering observes D1
before its K1 attribution. Kubernetes metadata is additive: it cannot
manufacture a runtime identity or upgrade a stale/inferred binding. Raw
namespace, node, container, and runtime-class names are domain-separated SHA-256
references before IPC. `pod_revision_ref`, source epoch, and source sequences
exist only to close qualification races and never cross the persistence seam.
The persisted references are deterministic, unkeyed SHA-256 pseudonyms for the
content-off profile, not anonymization or confidentiality: low-entropy names
can be enumerated offline and identical values are linkable across runs. Pod UID
and the nested D1 full container ID remain explicit.

```text
reference_v1(kind, raw) = lowerhex(SHA-256(
  "apolysis:kubernetes-reference:v1" || 0x00 ||
  kind || 0x00 || UTF-8(raw)
))
pod_revision_ref = lowerhex(SHA-256(
  "apolysis:kubernetes-pod-revision:v1" || 0x00 || UTF-8(resourceVersion)
))
```

`kind` is exactly `namespace`, `node`, `container`, or `runtime_class`.
Namespace/container inputs are canonical lowercase DNS labels; node/runtime
class inputs are bounded canonical lowercase DNS subdomains. The second formula
is qualification-only and never a persisted identifier.

An identical qualified cycle is a no-op. Pod/container absence in a successful
cycle retires the K1 attribution. A same-Pod container restart changes its D1
identity and produces the ordered K1 identity-transition gap, old K1
retirement, fresh D1 qualification, and new K1 observation. A newly appearing
K1 link to a runtime binding that predated the cycle records one
`kubernetes_late_attach` relationship boundary; a D1 binding created in the
same atomic cycle does not. Recovery from a declared outage, identity
transition, or restart is not mislabeled as late attach.

Kubernetes API loss emits an API gap and suspends K1 while leaving independently
healthy D1 collection active. CRI loss first makes K1 runtime metadata
unavailable and suspends K1, then applies the ordinary D1 runtime gap and
suspension. A successful CRI scan that cannot prove the claimed runtime join
(missing, conflicting, duplicate, or invalid runtime identity) follows the same
K1-then-D1 `inventory_invalid` suspension path; source-only Pod A/B churn
suspends K1 but retains an independently exact D1 binding. Both recovery paths
require a fresh complete A/runtime/B cycle before attribution returns. A changed
source epoch or recovered daemon state emits
`kubernetes_daemon_restart`, retires prior active or dormant K1 state, and
re-observes only freshly qualified links. Closing or replacing a claim revision
atomically retires its K1 links and the K1-exclusive containerd/K3s D1 bindings,
and untracks their scopes before acknowledging the replacement; this remains
true while Kubernetes metadata is unavailable. Independent Docker bindings are
not revoked by that K1 transaction. A cross-node reschedule is not continuity:
the old Pod UID retires and a new Pod UID is independently observed after a
bounded handoff; no gap-free ownership claim is made.

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
Validated runtime-binding and Kubernetes-attribution lifecycle facts remain in
source order in the projection; validation reconstructs both lifecycles rather
than reducing them to the currently active set.

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
identity references, source ordinals, runtime-binding and K1 lifecycles,
Finding links, and state consistency, then renders deterministic,
self-contained HTML.
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
- the ordered observed, retired, and suspended K1 lifecycle with exact D1
  source links;
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
`runtime_observations`, `runtime_bindings`, `kubernetes_attributions`,
`collector_lifecycle`, `findings`, `observation_gaps`, and `issues`. Every
projected source fact carries a
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
| `kubernetes_attribution_observed` / `kubernetes_attribution_retired` / `kubernetes_attribution_suspended` | Durable claimed Pod/container attribution lifecycle over one Exact observed containerd/K3s runtime binding |
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
| `kubernetes_metadata_unavailable` | `kubernetes_metadata`, `1` | `cluster=<canonical-nonzero-UUID>,reason=<kubernetes_api_unavailable\|kubernetes_runtime_unavailable\|kubernetes_snapshot_invalid>` | Respectively `kubernetes_source_unavailable`, `kubernetes_runtime_unavailable`, or `kubernetes_snapshot_invalid` |
| `kubernetes_metadata_unavailable` | `kubernetes_metadata`, `1` | Same cluster shape and `reason=<kubernetes_daemon_restart\|kubernetes_identity_transition\|kubernetes_late_attach>` | The same bounded reason |

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

The Kubernetes-attribution lifecycle records have this exact closed shape:

| Field | Type | Value or meaning |
| --- | --- | --- |
| `record_type` | enum | `kubernetes_attribution_observed`, `kubernetes_attribution_retired`, or `kubernetes_attribution_suspended` |
| `schema_version` | u32 | Constant `1` |
| `agent_run_id` | string | Owning canonical Agent Run ID |
| `cluster_id` | string | Canonical lowercase non-zero UUID configured by the operator |
| `namespace_ref` | string | 64-byte lowercase hexadecimal domain-separated privacy reference |
| `pod_uid` | string | Canonical lowercase non-zero Kubernetes Pod UUID |
| `node_ref` | string | 64-byte lowercase hexadecimal domain-separated privacy reference |
| `runtime_class_ref` | string\|null | Same 64-byte privacy reference, or explicit `null` |
| `container_kind` | enum | `application`, `init`, or `ephemeral` |
| `container_ref` | string | 64-byte lowercase hexadecimal domain-separated privacy reference |
| `runtime_binding` | object | Complete valid v1 `runtime_binding_observed` object for the same Agent Run; adapter is exactly `containerd` or `k3s_containerd` |

The lifecycle key is
`(cluster_id,pod_uid,container_kind,container_ref)`. Observation requires the
embedded D1 identity to be active first. Suspension or retirement must match the
entire active K1 identity, and K1 must end before its D1 identity ends. A K1
suspension consumes one earlier unmatched API/runtime/snapshot-unavailable gap
credit for the same cluster and active key. Restart, identity-transition, and
late-attach gaps are visible boundaries but do not authorize suspension.
`claim_revision`, raw names, `pod_revision_ref`, source epoch/sequence, labels,
annotations, paths, PID, endpoint, token, and backend text are not wire fields.

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
| `kubernetes_attributions` | array<object> | Active freshly qualified K1 records for that visible Agent Run; always present, and empty when `session` is `null` |

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

The two arrays contain active, freshly qualified state only; dormant,
suspended, and retired entries are excluded. Runtime bindings are ordered by
adapter/workload key and Kubernetes attributions by their exact lifecycle key.
Every `kubernetes_attributions` element has the closed K1 wire shape above and
references one returned active D1 binding. `tenant_id` defaults to `default`
when omitted. The daemon first requires
the requested Agent Run's registered tenant to equal the query tenant; only
then does it read bindings. `session` and `runtime_bindings` come from one
tenant-gated atomic snapshot, so concurrent tenant replacement cannot separate
the authorization decision from binding disclosure. An absent or cross-tenant
Agent Run therefore returns `session:null`, `runtime_bindings:[]`, and
`kubernetes_attributions:[]`, preventing workload identity from becoming a
cross-tenant existence oracle. The query preserves the same privacy boundary as
persistence: it exposes no raw label, annotation, namespace, node, container
name, PID, cgroup/runtime/socket path, endpoint, backend error, or payload.

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
| `kubernetes_attributions` | array<object> | Ordered validated K1 lifecycle facts; new v1 output always includes it |
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
| Kubernetes attribution | `source_ordinal:u64` plus the exact eleven-field closed K1 lifecycle wire shape above, including its nested runtime-binding object |
| collector lifecycle | `source_ordinal:u64`, `schema_version:u32`, `timestamp_unix_ms:u128`, `collector:string`, `collector_instance_id:string`, `state:enum`, `health:enum`, `stop_reason:enum|null`, `counters:object` with the same eight `u64` fields as timeline lifecycle |
| finding | `source_ordinal:u64`, `schema_version:u32`, `kind:enum`, `decision:enum`, `reason:string`, `evidence_ref:string`, `runtime:object`, `evidence_boundary:enum`; runtime uses `runtime:string`, `container_id:string|null`, `pod_uid:string|null`, `cgroup_id:u64|null` |
| observation gap | `source_ordinal:u64`, `schema_version:u32`, `timestamp_unix_ms:u128`, `operation:string`, `kind:string`, `count:u64`, `detail:string` using the normalized table above, plus the optional paired `runtime_source:string`/`runtime_reason:string` or `kubernetes_cluster_id:string`/`kubernetes_reason:string` fields defined below |
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

`kubernetes_attributions` follows the same default-compatible v1 extension
rule: new projection output always includes it and a legacy v1 record may omit
it as empty. The projector preserves every validated K1 observed, retired, and
suspended fact in source order. It replays runtime and K1 state together,
requires the referenced D1 observation to precede K1 observation, requires K1
retirement/suspension before D1 ends, and consumes K1 suspension credits exactly
once. The frozen-record validator repeats those checks. The Saved Run Viewer
renders a separate K1 lifecycle panel and links each K1 fact to its Exact D1
binding source fact without reconstructing raw Kubernetes names.

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

For `kubernetes_metadata_unavailable`, projection replaces the source detail
with the normalized bounded detail in Section 6.1 and adds required
`kubernetes_cluster_id` and `kubernetes_reason` fields. The reason is exactly
one of the six K1 reasons listed there. Other gaps omit both fields. Every K1
gap adds one `observation_gap` issue and prevents complete evidence; late attach
counts a relationship boundary rather than a number of missing syscalls.

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
| Kubernetes containerd/K3s | Implemented K1 node eBPF observation joined to claimed Pod/container/cgroup identity; Experimental pending designated live qualification |
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
- K1 persists the operator-defined cluster UUID, Pod UID, container kind, and
  domain-separated namespace/node/container/runtime-class references. Raw Pod
  names, namespace and node names, labels, annotations, resource versions,
  tokens, and source error bodies do not cross the persistence or diagnostic
  seam. The projected token is mounted only in the non-root source container;
  the root collector has no Kubernetes API credential.
- K1 privacy references are deterministic unkeyed pseudonyms, not secrets or
  anonymity. Low-entropy identifiers remain enumerable and references remain
  linkable across runs; Pod UID and the full runtime container identity remain
  explicit by contract.
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
- Kubernetes API or CRI loss, invalid/changed A/B Pod snapshot, source epoch or
  daemon restart, K1 identity transition, or K1 late attach;
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
  independent summary axes, optional declared-intent comparison, typed K1 claim
  admission and lifecycle validation, and review-oriented findings;
- `apolysis-viewer`: strict Agent Observation Record v1 validation and
  deterministic standalone offline HTML presentation with runtime/K1 source
  traceability;
- `apolysis-kubernetes`: the pure bounded A/runtime/B qualification coordinator,
  claim intersection, K1 lifecycle, outage/restart recovery, and Exact D1 join;
- `apolysis-kubernetes-source`: the non-root namespace-scoped Pod LIST/watch
  source and strict privacy-safe Unix IPC protocol;
- `apolysis-visibility`: visibility-boundary assessment;
- `apolysis-daemon`: long-lived observer, bounded queue, local socket, runtime
  registration, complete Docker/containerd inventory qualification, stable
  container/cgroup binding, bounded runtime-source and daemon-restart recovery,
  two-phase K1/runtime lifecycle persistence and recovery, tenant-atomic query,
  scoped collector lifecycle, idempotent unfinished-instance recovery,
  receipt-owned local operations, and identity-bound journaled retention;
- `apolysisd-control` and `deploy/kubernetes`: the typed operator ingress and
  least-privilege two-container node DaemonSet contract.

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
The K1 implementation covers typed claims, privacy-safe Pod metadata, complete
A/runtime/B closure, application/init/ephemeral containers, D1 reuse,
observed/retired/suspended lifecycle, explicit API/CRI/snapshot/restart/
transition/late-attach gaps, tenant-gated query, AOR projection, and viewer
navigation. In the combined path, D1 reconciliation receives only the full
identity keys authorized by the exact claim/A/B intersection; raw routing
candidates cannot attach scope. Its deterministic and deployment contracts
pass locally, but its
designated VKE live gate has not run in this workspace because the required
kubeconfig and `kubectl` are absent. That preflight result is a skip, not a
pass, and does not promote Kubernetes. Destructive systemd runtime-service
restart and release qualification remain open. Bounded local daemon filesystem
operations are implemented; no Supported live-host profile is granted.

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
- K1 is limited to one namespace and node per DaemonSet Pod, one explicitly
  configured containerd or K3s runtime domain, READY marked Pod sandboxes, and
  exact typed claims for application, init, or ephemeral container slots. It
  does not observe Docker-backed Kubernetes, arbitrary/unclaimed Pods, multiple
  namespaces from one source token, or runtime/container metadata that cannot
  form an Exact D1 identity.
- The canonical DaemonSet supports only its own dedicated Agent namespace. It
  cannot be copied per workload namespace while sharing the same node runtime:
  one node observer must exclusively own the runtime domain. Cluster-wide or
  cross-namespace attribution needs a newly designed authorization/source seam.
- The dedicated namespace must remain operator-controlled. Exact claims prevent
  a Pod writer from acquiring another run's D1/scope, but a malformed marked
  sandbox deliberately fails the complete scan and can degrade node K1/runtime
  availability; K1 does not resist that authorized-namespace denial of service.
- Direct host CRI socket ownership keeps the collector node-trusted because the
  protocol includes mutating methods. Capability and token separation reduce
  privilege but do not enforce read-only access; that requires a future
  allowlist broker.
- K1 watches only to trigger a fresh capture. Its authority is two complete Pod
  LISTs around one complete CRI inventory, so API pagination or runtime latency
  bounds convergence and churn can repeatedly yield an explicit snapshot gap.
  Node-local state has no gap-free cross-node handoff: a rescheduled Pod has a
  new UID and is independently qualified on its destination node.
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
operations, completed D1/D2 work with retained independent Docker and
private-containerd qualification, and completed deterministic K1 contract form
the current foundation. The next bounded step is the designated, runtime- and
network-ready VKE live qualification, followed by release preparation. That
gate must cover representative same-Pod restart, source loss and recovery,
cross-node new-UID handoff, runtime boundary, cleanup, and privacy. In this
workspace its required kubeconfig and `kubectl` are absent, so it has not run;
the canonical preflight result is a skip and must not be reported as a pass.
Docker evidence cannot be reused as containerd or Kubernetes evidence, and
private-containerd evidence cannot be reused as Kubernetes evidence.
Destructive systemd runtime-service restart qualification remains an
independent, optional claim. No profile advances beyond Experimental or
Candidate until its exact workload/kernel/runtime and applicable release
evidence passes.

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

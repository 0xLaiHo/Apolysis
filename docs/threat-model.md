# Apolysis Threat Model

This document defines the security boundary for the active eBPF Agent runtime
observability product. It covers operator-controlled Linux hosts and the local
collection, storage, and investigation workflow.

## Product boundary

Apolysis observes a bounded set of process, file, network, and
credential-related operations inside an explicit Agent Run scope. It attributes
those observations to runtime identities and reports collector health, loss,
truncation, unsupported paths, and other Observation Gaps.

The eBPF collector is the required primary source. Apolysis does not claim that
an unobserved action did not occur, that a successful syscall proves a remote
effect, or that host observations are independent of a compromised kernel.

## Not a security boundary

Apolysis is not a sandbox, workload isolation mechanism, approval system,
identity provider, kernel enforcement engine, MCP gateway, SIEM, or independent
attestation service. Docker, gVisor, Kata, Firecracker, Kubernetes, host policy,
and cloud runtime configuration remain responsible for isolation.

Findings are review-oriented observations. They do not claim that an operation
was blocked, rolled back, or contained.

## Trust boundaries

- **Agent workload:** untrusted code, tools, and subprocesses whose activity may
  attempt to evade or overload observation.
- **Operator:** trusted to select an appropriate scope, install the collector,
  protect local output, and interpret documented capability limits.
- **Linux kernel and host root:** trusted only as the source of host runtime
  observations. A compromised kernel or privileged host can forge, suppress,
  or modify them.
- **Privileged eBPF collector:** trusted to load the reviewed object, apply the
  declared scope, emit bounded records, and expose health and loss counters.
- **Userspace observer and daemon:** trusted to decode the ABI, join runtime
  identity, redact sensitive content, preserve gaps, and write bounded local
  records.
- **Runtime metadata sources:** trusted only for documented container, cgroup,
  Pod, and process identity fields. They do not prove guest semantics or remote
  effects.
- **Local store:** trusted to protect retained Agent Observation Records with
  restrictive permissions and bounded retention.
- **Saved-run read and projection path:** non-privileged and read-only with
  respect to source evidence. Local files are untrusted structured input;
  hash-chain payloads are unavailable to projection until the entire chain is
  verified.
- **Saved-run viewer:** non-privileged and trusted only to render stored facts.
  It cannot invent outcome, attribution, health, or completeness verdicts.

## Primary assets

- Agent Run and Observation Scope identity.
- Stable process, cgroup, container, Pod, and node attribution.
- Kernel/userspace ABI and Collector Capability declarations.
- Runtime Observations and supported Operation Outcomes.
- Source sequence, collector lifecycle, health, loss, truncation, and gap
  records.
- Content-off persistence and redaction guarantees for argv, paths, socket
  values, labels, annotations, and payloads.
- Local timeline integrity, file permissions, retention, and cleanup behavior.
- Projection source order and integrity plus the independent evidence,
  collector-health, and review-state semantics of the derived record.
- Private atomic publication of the derived Agent Observation Record without
  overwriting any input source.
- Operator credentials and kubeconfigs, which must never be captured, printed,
  copied into the repository, or committed.

## In-scope threats

### Scope and attribution confusion

- A malicious or buggy Agent creates descendants that escape the tracked
  process tree or cgroup.
- PID or thread-ID reuse attaches another workload's events to the run.
- A stale or forged registration, or an ambiguous automatic discovery result,
  selects the wrong existing-process root.
- Before pidfd anchoring, an external-registration root is replaced by a process
  with the same PID, USER_HZ tick, executable, and command, or a lineage
  candidate is replaced after its snapshot by one with the same PID, tick, and
  lineage.
- An admitted root or seeded candidate exits or is replaced after anchoring but
  before protected-attach activation completes.
- A nested PID namespace or shifted time namespace makes host process identity
  and start-time conversion unsafe.
- Container churn, Pod rescheduling, cgroup reuse, or runtime restart preserves
  a stale identity relation.
- Name, command, path, PID, or timing correlation is presented as an exact
  relation.
- Late attach omits earlier workload activity without recording a gap.

### Collector failure and evasion

- Ring-buffer pressure, bounded-map exhaustion, truncation, or decode failure
  silently removes observations.
- ABI mismatch or unavailable hooks cause records to be misdecoded rather than
  rejected.
- The Agent produces enough activity to exhaust CPU, memory, queue, or storage
  budgets.
- Collector startup, attach, restart, death, or incomplete terminal flush is
  omitted from the run record.
- Unsupported io_uring, guest, filesystem, or network paths are mistaken for
  absence of activity.

### Outcome and capability overclaim

- A syscall-entry attempt is rendered as succeeded without a matched supported
  outcome.
- A successful file or network operation is described as a verified remote or
  application-level effect.
- gVisor, Kata, Firecracker, or another boundary is described as providing
  guest process visibility that the host collector cannot supply.
- A quiet or partial timeline is rendered as clean or complete.
- Mixed-run, mixed-integrity, unknown, malformed, diagnostic-bearing, lossy, or
  unterminated input is projected with a stronger completeness conclusion than
  its source supports.
- A finding is described as prevention or enforcement.

### Privacy and data exposure

- Raw argv, prompt, response, tool payload, credential, private path, socket,
  label, annotation, or captured workload data crosses the default persistence
  seam.
- Redaction is applied after an unredacted record has already reached local
  storage, logs, metrics, or an error message.
- Host-wide collection captures unrelated workloads because scope validation
  fails open.
- Viewer content causes script execution, unsafe links, terminal escape
  injection, or misleading status presentation.
- A malformed Finding reason, Gap detail, record identifier, or parser error
  copies private payload or control characters into projection output or
  stderr.
- Projection output aliases an active or rotated source file, is published
  with broad permissions, or replaces an existing valid output before the new
  record is complete.
- Local files, runtime sockets, or cleanup paths expose or modify data outside
  the selected Agent Run.

### Privilege and supply-chain misuse

- Workspace-controlled executable, BPF object, output path, environment, or
  loader configuration crosses into a privileged collector launch.
- The non-privileged viewer gains access to BPF maps, host PID namespace,
  container runtime sockets, node credentials, or privileged output paths.
- A substituted BPF object or binary reports capabilities that do not match the
  loaded implementation.
- A symlink, non-regular file, rotation substitution, source churn, oversized
  record set, or tampered hash chain changes what the non-privileged projection
  reads.
- Install, upgrade, rollback, uninstall, retention, or cleanup modifies
  unrelated host state.

## Default controls

- Require one explicit Observation Scope; do not provide a supported
  host-wide default.
- Prefer managed Agent launch so the collector is attached before workload
  execution begins.
- Limit protected existing-process attach to explicit registration or unique
  automatic discovery. Validate a registration's host boot ID, root start
  tick, executable, command fingerprint, and workspace boundary against the
  root visible when its pidfd is opened, and require its live cwd to resolve
  inside that canonical boundary. Persist that selection as
  `registration_qualified`, not as proof of pre-anchor continuity; keep
  discovery root selection `inferred` and reject ambiguity.
- Require the initial PID namespace and a shared initial, unshifted time
  namespace for protected process-tree attach.
- Keep the scope inactive while attaching tracepoints, then seed the admitted
  TGID root and lineage candidates from repeated snapshots. Require each seeded
  candidate to be a live, non-zombie leader in the initial PID/time namespaces,
  use a per-seeded-candidate pidfd sandwich around map insertion that rechecks
  namespace membership, remove post-insertion exits in the exit hook,
  and hold the root pidfd across activation.
- Match initially seeded TGIDs through a half-open USER_HZ start-time window.
  Allow matching kernel bookkeeping to promote internal membership during
  seeding or later, but assign exact event identity only to emitted
  post-activation events carrying the matched kernel start time and process/exec
  generations; keep this distinct from root-selection confidence.
- After successful protected attach, persist exactly one `late_attach` gap for
  one unknown-history Collection Boundary, followed by the capability manifest
  and `started` lifecycle record. Do not interpret its `count:1` as a missing
  syscall count. Persist all three as one rotation-safe durable batch and roll
  back the active file if writing or synchronization fails.
- Filter at event origin where possible and keep kernel records fixed and
  bounded.
- Embed the kernel/userspace ABI version and record size in every ring-buffer
  record, and reject incompatible records before decoding the current layout.
- Synchronize the attached operation/source/outcome capability manifest to
  stable storage before a managed Agent is released.
- Pair network connect entry and exit by thread identity, preserve its signed
  return value and errno, and emit Observation Gaps for unmatched or pending
  pairs.
- Emit collector start, health/loss checkpoints, terminal state, and stop
  reason; treat missing lifecycle records as gaps.
- Preserve reserve failure, map pressure, truncation, decode failure, attach
  failure, restart, and storage failure as explicit degraded or failed states.
- Keep prompt, response, raw tool payload, and full argv content-off by default.
- Redact credential, private path, and socket values before persistence.
- Use restrictive local permissions, bounded retention, safe rotation, and
  target-specific cleanup.
- Open every saved-run segment without following symlinks, require regular
  files, bind the active file plus contiguous `.N` archives to device/inode and
  timestamp snapshots, read oldest archive through active, and fail if the set
  changes during the read.
- Bound saved-run bytes, line width, record count, rotation files, projection
  batches, value depth, collection size, and copied strings. Verify a complete
  hash chain before exposing any payload to projection. Apply byte and record
  budgets across every input composed by one command.
- Fail closed for mixed Agent Runs, invalid lifecycle order, incompatible or
  malformed records, duplicate canonical observations, and content-policy
  violations. Mixed integrity and unknown additive records cannot be complete.
- Canonicalize free-form Finding reasons and Gap details, and keep error text
  free of record payloads and conflicting run identifiers.
- Require the full current v1 operation/source/outcome capability contract for
  complete evidence, resolve Finding references to projected canonical
  observations, and admit Exact Runtime Identity only from canonical
  post-activation kernel relations with a complete stable tuple.
- Publish projection output through an exclusive mode-`0600` same-directory
  temporary file, sync file and parent, atomically rename it, and reject path or
  inode aliases to every active or rotated input.
- Keep the saved-run viewer non-privileged and render all captured text as
  untrusted data.
- Keep privileged live and Kubernetes gates opt-in and document their kernel,
  capability, runtime, and cleanup assumptions.

## Environment-specific limits

- **Local Linux:** managed launch provides the strongest scope. Protected
  existing-process attach cannot recover prior activity or prove pre-anchor
  selection continuity. An external-registration root can be substituted
  between registration creation and root `pidfd_open` by a process with the
  same PID, USER_HZ tick, executable, and command; a lineage candidate can be
  substituted between its snapshot and `pidfd_open` by one with the same PID,
  tick, and lineage. Pidfd sandwiches and the exit hook close the corresponding
  exit/replacement race after candidates are anchored.
- **Self-hosted CI:** Apolysis observes the managed workload but does not isolate
  the runner control plane or same-UID state.
- **Docker/containerd:** host observations require exact cgroup and container
  identity; runtime socket access is privileged and separate from the Agent.
- **Kubernetes:** node observation requires least-privilege deployment and
  exact Pod/container/cgroup joins. Kubeconfig and workload secrets are never
  evidence artifacts.
- **gVisor:** host observation may expose runtime boundary activity rather than
  each guest syscall.
- **Kata/Firecracker:** host observation covers VMM, shim, and host boundaries;
  guest process semantics require a guest collector.
- **Vendor-managed runtime:** no eBPF claim is made without an
  operator-controlled Linux kernel.

## Out of scope

- Preventing all malicious Agent behavior.
- Proving absence of activity outside the declared capability and scope.
- Proving remote SaaS, cloud, Git, database, or provider mutations from host
  syscalls.
- Replacing Kubernetes policy, network policy, IAM, sandbox configuration, or
  human approval.
- Protecting observations from a compromised host root or kernel.
- Cross-provider semantic ingestion, central multi-tenant custody, remote
  export, and policy enforcement from the superseded evidence-plane direction.

## Release blockers

A supported profile cannot be described as Beta-ready when:

- loss, failure, truncation, restart, unsupported paths, or missing terminal
  state can produce an unmarked clean result;
- operation outcome or runtime attribution is stronger than the source can
  prove;
- sensitive content persists by default;
- the viewer requires privileged host access;
- the kernel, capability, runtime, performance, retention, and cleanup envelope
  is undocumented or untested;
- an unresolved high-severity issue affects collector privilege, scope,
  attribution, privacy, local storage, or viewer isolation.

The detailed product boundary and delivery gates are maintained in
[Design](design.md) and [Roadmap](roadmap.md).

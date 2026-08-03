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
- Operator credentials and kubeconfigs, which must never be captured, printed,
  copied into the repository, or committed.

## In-scope threats

### Scope and attribution confusion

- A malicious or buggy Agent creates descendants that escape the tracked
  process tree or cgroup.
- PID or thread-ID reuse attaches another workload's events to the run.
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
- Local files, runtime sockets, or cleanup paths expose or modify data outside
  the selected Agent Run.

### Privilege and supply-chain misuse

- Workspace-controlled executable, BPF object, output path, environment, or
  loader configuration crosses into a privileged collector launch.
- The non-privileged viewer gains access to BPF maps, host PID namespace,
  container runtime sockets, node credentials, or privileged output paths.
- A substituted BPF object or binary reports capabilities that do not match the
  loaded implementation.
- Install, upgrade, rollback, uninstall, retention, or cleanup modifies
  unrelated host state.

## Default controls

- Require one explicit Observation Scope; do not provide a supported
  host-wide default.
- Prefer managed Agent launch so the collector is attached before workload
  execution begins.
- Protect process attachment against PID reuse with stable start and runtime
  identity where available.
- Filter at event origin where possible and keep kernel records fixed and
  bounded.
- Embed the kernel/userspace ABI version and record size in every ring-buffer
  record, and reject incompatible records before decoding the current layout.
- Flush the attached operation/source/outcome capability manifest before a
  managed Agent is released.
- Emit collector start, health/loss checkpoints, terminal state, and stop
  reason; treat missing lifecycle records as gaps.
- Preserve reserve failure, map pressure, truncation, decode failure, attach
  failure, restart, and storage failure as explicit degraded or failed states.
- Keep prompt, response, raw tool payload, and full argv content-off by default.
- Redact credential, private path, and socket values before persistence.
- Use restrictive local permissions, bounded retention, safe rotation, and
  target-specific cleanup.
- Keep the saved-run viewer non-privileged and render all captured text as
  untrusted data.
- Keep privileged live and Kubernetes gates opt-in and document their kernel,
  capability, runtime, and cleanup assumptions.

## Environment-specific limits

- **Local Linux:** managed launch provides the strongest scope. Manual attach
  may miss prior activity.
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

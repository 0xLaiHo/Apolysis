# Apolysis

🌐 [English](README.md) | [简体中文](README.zh-CN.md)

**Apolysis** is an environment-owned runtime accountability layer for opaque or
semi-trusted AI Agent workloads. It is designed to collect independent
OS/runtime evidence beneath the agent harness, correlate that evidence with the
agent's declared intent and isolation boundary, and provide the policy surface
needed to notify, review, or eventually enforce risky side effects.

## 🧭 What Apolysis Is

Apolysis is not a replacement for Docker, gVisor, Kata Containers,
Firecracker, E2B, Daytona, Modal Sandboxes, or Kubernetes Agent Sandbox.
It is also not an agent harness, MCP gateway, approval UI, or general-purpose
container runtime. Instead, it sits below the harness and above or beside
execution runtimes, focusing on the missing agent-security layer:
**environment-owned side-effect verification**.

The key assumption is that harness logs are not a sufficient source of truth.
Modern agent harnesses include prompt loops, planning/retry logic, tool
routing, MCP clients, permission modes, approval gates, hooks, memory, logs,
credential handling, and sometimes default sandbox settings. When that harness
is opaque, third-party, hosted, or allowed to spawn arbitrary subprocesses, the
environment operator needs OS/runtime facts that do not depend on the harness
reporting honestly or completely.

The long-term architecture has three layers:

1. 🔐 **Intent authorization**: what the agent should do, usually mediated by
   the harness through MCP, tool gateways, OAuth scopes, and approvals.
2. 🧱 **Execution isolation**: what the agent can touch, provided by containers,
   VMs, namespaces, network policy, filesystem mounts, and runtime limits.
3. 🔎 **Side-effect verification**: what actually happened, captured through
   process lineage, file access, network connects, credential reads, policy
   decisions, and feedback.

When all three layers agree, the platform can trust the session with higher
confidence. When they diverge, Apolysis treats OS/runtime evidence as the
starting point for investigation and future enforcement.

F0 (M1-M7) completes the first PoC baseline for the third layer. It records
local sessions, process-tree attribution, Docker runtime metadata, Kubernetes
pod metadata, fixture ring-buffer events, raw kernel-event records, canonical
side-effect events, policy violations, downgrade metadata, feedback files,
visibility assessments, and JSONL timelines. F1 now implements a scoped, live,
audit-only eBPF observer with a CO-RE build, Aya loader, process/file/network
events, loss diagnostics, and persistence-time redaction. Its privileged
live-host validation is complete. F3 keeps production-facing kernel blocking
disabled by default while validating narrow local seccomp and BPF-LSM
pre-operation block prototypes with operator-approved enablement and rollback
audit records. F4 is complete for runtime adapter depth: it separates supported
audit/review/kill paths, local-only block prototypes, metadata-only
strong-isolation claims, boundary-only VM-backed runtimes, and validated
Docker/containerd/Kubernetes adapter evidence. It also adds live gVisor
runsc/sentry/gofer metadata evidence, Kubernetes Agent Sandbox metadata
evidence, Kata boundary-only evidence, and a live-runtime evidence bundle gate
that binds F4 claims to retained F2 runtime adapter matrix artifacts. F5 has
started with a production-hardening baseline for a bounded Kubernetes
DaemonSet/RBAC deployment surface and a live k3s rollout/restore validation
gate for the node-local daemon, including live metrics scrape validation and
live DaemonSet restart, k3s CRI socket outage recovery, queue pressure, and
unwritable-store recovery evidence. It now also includes a local release
supply-chain bundle gate for signed artifacts, SBOM, provenance, and
high/critical vulnerability scan evidence, plus Helm-rendered tenant-isolated
deployment packaging with metrics mTLS handoff annotations and a narrow
metrics NetworkPolicy allowlist, and a local OCI registry/archive gate for
release image publishing, SBOM attachment, and read-only archive evidence. The
Helm packaging now also renders optional Istio strict mTLS and metrics
AuthorizationPolicy resources for service-account-scoped metrics access. The
daemon API now also carries tenant IDs and retention tiers on session intents
and supports tenant-scoped session query/list responses plus local retention
purge dry-run/apply enforcement for retained daemon state. F5 now also includes
a release promotion policy gate and live OCI registry promotion execution for
digest-locked production promotion, retention windows, rollback tags, and
bounded registry access principals, plus a KMS/HSM signing profile gate for
production signer eligibility and an HSM-compatible PKCS#11 signing execution
gate plus opt-in AWS KMS and external HSM live signing gates, an external WORM/object-lock
archive policy gate with live S3-compatible Object Lock API execution, and a
live Istio service-mesh admission/handshake evidence gate, plus live operator/controller
reconciliation validation, live k3s and Vultr VKE managed-Kubernetes
chaos/performance validation, and a
fail-closed external provider qualification bundle gate with live Cloudflare
R2 Bucket Lock WORM evidence and live Docker Hub immutable-tag registry
promotion evidence, plus retained external provider bundle artifact
verification, final external provider bundle assembly, and an opt-in managed
Cloud Service Mesh provider qualification gate, plus a Vultr VKE 3-node
cluster readiness gate for subsequent live Kubernetes validation and a Vultr
VKE Istio live provider qualification path for final-bundle managed
service-mesh evidence, and a final provider readiness audit that fail-closes
when required live-provider evidence is missing and rejects accepted-looking
fixtures without live-provider evidence source, plus a signing-provider
readiness preflight for retained signing evidence, AWS KMS prerequisites, and
external HSM prerequisites, an opt-in AWS KMS signer bootstrap gate for
inspect/ensure handoff to live signing, a manual workflow path that can run
that AWS KMS bootstrap before F5.25 signing, a provider workflow readiness gate
for GitHub secret/variable setup and web/headless-token auth handoff, an AWS
OIDC role/KMS policy inspect/ensure handoff gate, and a final provider
completion gate that binds
that readiness audit to a passing final external provider bundle, a manual
GitHub Actions workflow for running the remaining live provider evidence gates
with repository secrets, and a final provider bundle environment preparation
helper with workflow bundle assembly, retained provider artifact package
handoff, and retained provider workflow alternatives.

## 🚀 Runtime Scenarios

- 🧑‍💻 **Local coding agents**: wrap commands such as Codex, Claude Code, Aider, or
  local automation scripts and emit a JSONL timeline.
- 🧪 **AI-generated code execution**: prepare policy and event schemas before
  running untrusted code inside Docker or stronger runtimes.
- 🔁 **CI/CD audit**: record which process was launched and how policy decisions
  would be represented in an append-only timeline.
- ☁️ **Cloud-native agent platforms**: prepare the schema and runtime adapter
  boundaries needed for future Kubernetes Agent Sandbox, gVisor, and Kata
  integrations.

## 🧩 How Apolysis Differs From Existing Sandboxes

| Product / Runtime | Primary focus | Apolysis difference |
| --- | --- | --- |
| Docker | Reproducible container execution | Docker is treated as a baseline adapter, not a strong security boundary. |
| gVisor | User-space kernel isolation for containers | Apolysis will correlate runtime metadata with agent side effects and policy decisions. |
| Kata Containers | VM-backed Kubernetes pod isolation | Apolysis will document host/guest visibility gaps and decide where guest collectors are needed. |
| Firecracker | Low-overhead microVM primitive | Apolysis reserves a future adapter instead of building a microVM platform in the MVP. |
| E2B / Daytona / Modal | Managed sandbox execution environments | Apolysis focuses on runtime evidence, policy decisions, and agent feedback across environments. |
| Kubernetes Agent Sandbox | Cloud-native agent workload lifecycle | Apolysis can become an observation and policy layer for those workloads. |
| AgentSight / ActPlane | eBPF observability / eBPF enforcement research | Apolysis adapts those ideas into a Rust project with runtime adapters, schemas, and staged enforcement. |

## 🛠️ Build And Run

Requirements for the current F0 baseline and F1 implementation:

- 🦀 Rust stable toolchain
- 📦 Cargo
- 🐧 Linux development shell for process-tree attribution through `/proc`
- 🐳 Docker CLI/daemon for real Docker runs; tests use a local Docker stub
- 🧬 eBPF development uses `clang`, `llvm-strip`, `bpftool`, BTF, and elevated
  capabilities; normal tests use fixture ring-buffer records and do not need root

🔨 Build Rust and the CO-RE object:

```bash
make build
```

✅ Run tests:

```bash
make test
```

🧹 Run Clippy:

```bash
make lint
```

🎨 Format:

```bash
cargo fmt --all
```

▶️ Run the local command wrapper:

```bash
cargo run -p apolysis-cli -- run \
  --policy policies/local-dev.yaml \
  --output .apolysis/timeline.jsonl \
  -- echo hello
```

📄 Inspect the generated JSONL timeline:

```bash
cat .apolysis/timeline.jsonl
```

Expected M2 records include `session_started`, `runtime_metadata`, `exec`, and
`process_exit`. A timeout emits a `policy_violation` with
`runtime.max_seconds` and terminates the local process tree.

🐳 Run through the M3 Docker adapter:

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-timeline.jsonl \
  -- echo hello
```

Use gVisor's `runsc` runtime when it is installed:

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --docker-runtime runsc \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-runsc.jsonl \
  -- echo hello
```

The Docker adapter injects `APOLYSIS_SESSION_ID`, writes Apolysis labels, uses
`--read-only`, `--network none`, `--cap-drop ALL`, `no-new-privileges`,
`--pids-limit`, `--cpus`, and `--memory`, and emits container image, selected
OCI runtime, mounts, network mode, container id, and cgroup mapping metadata.

🔎 Run the M4 audit-only observer pipeline with fixture ring-buffer records:

```bash
cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-m4-demo \
  --policy policies/local-dev.yaml \
  --output .apolysis/observer-timeline.jsonl
```

The observer writes both `raw_kernel_event` records and analyzed canonical
events. The M4 event set covers `exec`, `open/openat/openat2`, `creat`,
`truncate`, `unlink`, `rename`, network `connect`, and credential path reads.
The default runner plan enables process/system runners and keeps stdio plus
SSL/HTTP uprobes disabled until later milestones.

🧬 Run the F1 live audit-only observer on a capable Linux host:

```bash
make build-ebpf
make build
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session session-f1-live \
  --policy policies/local-dev.yaml \
  --output .apolysis/live-timeline.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --scope-pid <root-pid> \
  --workspace-root "$PWD"
```

Use `make test-live` for the capability-aware smoke test. The live backend is
audit-only and does not perform pre-operation blocking.

🛡️ Run the M5 policy-feedback path:

```bash
APOLYSIS_BPF_LSM_AVAILABLE=0 cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-m5-demo \
  --policy tests/fixtures/policies/m5-block-policy.yaml \
  --output .apolysis/policy-timeline.jsonl \
  --feedback-dir .sandbox
```

When a policy requests `block` but BPF-LSM is unavailable, Apolysis writes an
explicit `unavailable:downgrade:block->notify` metadata event, emits
`policy_violation` records with `tracepoint_notify`, and updates
`.sandbox/last-violation.txt` for future Claude/Codex hook integration.

☸️ Add M6 Kubernetes / Agent Sandbox metadata to an observer session:

```bash
APOLYSIS_BPF_LSM_AVAILABLE=0 cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-m6-k8s \
  --policy tests/fixtures/policies/m5-block-policy.yaml \
  --output .apolysis/kubernetes-timeline.jsonl \
  --feedback-dir .sandbox \
  --kubernetes-metadata tests/fixtures/kubernetes/agent-sandbox-gvisor-pod.yaml
```

M6 consumes captured pod metadata, not the live Kubernetes API. It emits Pod,
namespace, service account, RuntimeClass, node, service-account-token, and
Agent Sandbox identity records, then keeps the M5 policy-feedback contract on
the same timeline.

🧪 Run the M7 strong-isolation visibility validator:

```bash
cargo run -p apolysis-cli -- visibility \
  --scenario kubernetes-kata \
  --input tests/fixtures/visibility/kubernetes-kata-host-events.txt \
  --output .apolysis/visibility-kata.jsonl \
  --kubernetes-metadata tests/fixtures/kubernetes/agent-sandbox-kata-pod.yaml
```

The validator compares host-side observer fixtures for Docker default,
Docker+gVisor, Kubernetes+gVisor, Kubernetes+Kata, and Firecracker boundary
scenarios. It records whether host semantics collapsed, whether runtime
metadata is required, and whether a guest-side collector is required.

## 📁 Repository Layout

```text
crates/
  apolysis-accountability/ F2 intent, session, finding, queue, and health contracts.
  apolysis-core/    Shared schema and JSONL records.
  apolysis-daemon/  Node-local `apolysisd` Unix socket service.
  apolysis-feedback/ Agent-facing violation feedback files.
  apolysis-kubernetes/ Kubernetes and Agent Sandbox metadata parser.
  apolysis-observer/ Raw kernel event observer and policy evaluation pipeline.
  apolysis-policy/  YAML/JSON policy parser and decision logic.
  apolysis-runtime/ Local runner and Docker runtime adapter.
  apolysis-store/   Append-only JSONL timeline writer.
  apolysis-visibility/ Strong-isolation visibility assessment model.
  apolysis-cli/     Local `apolysis run` command wrapper.
ebpf/
  include/          Observer ring-buffer ABI shared with userspace.
  observer/         GPL-2.0-only F1 eBPF observer source.
target/ebpf/        Generated CO-RE build output.
deploy/kubernetes/ RuntimeClass, NetworkPolicy, and Agent Sandbox examples.
policies/
  local-dev.yaml    Default audit policy.
  docker-baseline.yaml Docker adapter baseline policy.
tests/fixtures/     Local/Docker command fixtures and expected timeline fragments.
```

## 🗺️ Feature Plan And Progress

Current status: Apolysis is a PoC / audit-first prototype. F0 (M1-M7), F1
Independent Observability MVP, F2 Accountability Beta, F3 Limited Guardrails,
and F4 Runtime Adapter Depth are complete. F5 Production Hardening is in
progress, with a Kubernetes DaemonSet/RBAC deployment baseline, local manifest
hardening gate, live k3s deployment validation gate, and production DaemonSet
metrics, resilience, queue pressure, storage-failure, and release
supply-chain validation, plus Helm production packaging for tenant-isolated
node-local deployments and local OCI registry/archive validation for release
artifacts, plus rendered service-mesh identity policy validation for metrics
access, tenant-scoped query/retention metadata, and local retention purge
enforcement in the daemon API, plus release promotion policy validation for
production registry retention and access controls plus live OCI registry
promotion execution validation, and KMS/HSM signing profile validation plus
HSM-compatible PKCS#11 signing execution, external WORM/object-lock archive
policy validation plus live S3-compatible Object Lock API execution
validation, live Istio service-mesh admission/handshake validation, and live
operator/controller reconciliation validation plus live k3s and Vultr VKE
managed-Kubernetes chaos/performance validation, fail-closed external provider
qualification bundle validation, and
live Cloudflare R2 Bucket Lock WORM evidence plus live Docker Hub immutable-tag
registry promotion evidence and retained external provider bundle artifact
verification, plus opt-in AWS KMS and external HSM live signing gates and final external
provider bundle assembly, and an opt-in managed Cloud Service Mesh provider
qualification gate, plus a Vultr VKE 3-node cluster readiness gate and final
provider readiness audit with live-provider fixture rejection, a Vultr VKE
Istio live provider qualification path for final-bundle managed service-mesh
evidence, a final provider completion gate, a manual final provider evidence
workflow, and a final provider bundle environment preparation helper with
workflow bundle assembly, retained provider artifact package handoff, and
retained provider workflow alternatives, plus signing-provider readiness
preflight for retained signing evidence, AWS KMS prerequisites, and external
HSM prerequisites, and opt-in AWS KMS signer bootstrap for inspect/ensure
handoff to live signing with workflow bootstrap orchestration, plus provider
workflow readiness web/headless-token auth handoff auditing for the remaining
GitHub Actions setup and AWS OIDC role/KMS policy inspect/ensure handoff. The
remaining F5 production-provider gap is real cloud KMS or external hardware HSM
signing evidence.

Implementation milestones:

| Milestone | Scope | Status |
| --- | --- | --- |
| M1 | Rust workspace, core schema, policy parser, JSONL store, local CLI wrapper, README | ✅ **Completed** |
| M2 | Local process session model, process-tree attribution, timeout notify, richer fixtures | ✅ **Completed** |
| M3 | Docker adapter with safe defaults, optional OCI runtime, and container metadata | ✅ **Completed** |
| M4 | Audit-only observer pipeline, raw kernel event schema, eBPF ring-buffer ABI, exec/file/network canonicalization | ✅ **Completed** |
| M5 | Policy engine integration, `Notify`/`Block`/`Kill`/`Review`, feedback hook | ✅ **Completed** |
| M6 | Kubernetes / Agent Sandbox metadata integration | ✅ **Completed** |
| M7 | gVisor/Kata/Firecracker host-visibility validation and guest collector decision model | ✅ **Completed** |

Focused roadmap:

| Phase | Scope | Status |
| --- | --- | --- |
| F0 | PoC baseline: M1-M7 schema, adapters, fixture observer, feedback, Kubernetes metadata, strong-isolation visibility modeling | ✅ **Completed** |
| F1 | Independent Observability MVP: live audit-only eBPF observer, CO-RE/Aya loader, process/file/network/credential timeline, loss accounting, redaction | ✅ **Completed** |
| F2 | Accountability Beta: `apolysisd`, cross-layer comparison, Docker/containerd/Kubernetes metadata correlation, `Notify`/`Review` findings, feedback, metrics, local timeline integrity | ✅ **Completed** |
| F3 | Limited Guardrails: truthful `Notify`/`Review`/`Kill`, narrow BPF-LSM/seccomp `Block` prototypes only where pre-op prevention is proven | ✅ **Completed** |
| F4 | Runtime Adapter Depth: Docker/containerd baseline, gVisor metadata adapter, Kubernetes Agent Sandbox metadata, Kata boundary-only mode, Firecracker research prototype | ✅ **Completed** |
| F5 | Production Hardening: DaemonSet privilege budget, multi-tenant storage/query/retention metadata, mTLS/RBAC, signed artifacts, SBOM/provenance, KMS/HSM signing profile validation, PKCS#11 signing execution, opt-in AWS KMS and external HSM live signing, signing-provider readiness preflight, AWS KMS signer bootstrap and workflow orchestration, provider workflow readiness web/headless-token auth handoff auditing, AWS OIDC role/KMS policy inspect/ensure handoff, Helm, registry/archive/promotion/WORM policy and API execution validation including live OCI promotion, service-mesh identity/live handshake validation, opt-in managed Cloud Service Mesh provider qualification, Vultr VKE Istio live provider qualification for managed service-mesh evidence, live operator/controller reconciliation validation, live k3s and Vultr VKE managed-Kubernetes chaos/performance validation, Vultr VKE 3-node readiness, final provider readiness audit with live-provider fixture rejection, final provider completion gate, manual provider evidence workflow, final provider bundle environment preparation, workflow bundle assembly, retained provider artifact package handoff, retained provider workflow alternatives, fail-closed external provider qualification bundle validation with retained artifact SHA verification and final bundle assembly, live Cloudflare R2 Bucket Lock WORM evidence, live Docker Hub immutable-tag registry promotion evidence, and remaining live execution of external KMS/HSM signing evidence | 🚧 **In Progress** |

## 📜 License

Apolysis userspace components are licensed under Apache-2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

Future kernel-loaded eBPF programs under `ebpf/` are licensed under
GPL-2.0-only where required by Linux kernel BPF licensing rules. See
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).

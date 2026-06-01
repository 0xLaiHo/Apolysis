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

M2 implements the local runner foundation for the third layer using Rust-only
audit-mode components. It records local sessions, process-tree attribution,
runtime metadata, timeout notifications, and JSONL timelines. Kernel eBPF
collection and BPF-LSM enforcement are planned but not enabled yet.

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
| Firecracker | Low-overhead microVM primitive | Apolysis reserves a future adapter instead of building a microVM platform in M1. |
| E2B / Daytona / Modal | Managed sandbox execution environments | Apolysis focuses on runtime evidence, policy decisions, and agent feedback across environments. |
| Kubernetes Agent Sandbox | Cloud-native agent workload lifecycle | Apolysis can become an observation and policy layer for those workloads. |
| AgentSight / ActPlane | eBPF observability / eBPF enforcement research | Apolysis adapts those ideas into a Rust project with runtime adapters, schemas, and staged enforcement. |

## 🛠️ Build And Run

Requirements for M2:

- 🦀 Rust stable toolchain
- 📦 Cargo
- 🐧 Linux development shell for process-tree attribution through `/proc`

🔨 Build:

```bash
cargo build
```

✅ Run tests:

```bash
cargo test
```

🧹 Run Clippy:

```bash
cargo clippy --all-targets --all-features
```

🎨 Format:

```bash
cargo fmt --all
```

▶️ Run the M2 local command wrapper:

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

## 📁 Repository Layout

```text
crates/
  apolysis-core/    Shared schema and JSONL records.
  apolysis-policy/  M1 policy parser and audit-only decisions.
  apolysis-runtime/ M2 local runtime runner and process-tree attribution.
  apolysis-store/   Append-only JSONL timeline writer.
  apolysis-cli/     Local `apolysis run` command wrapper.
policies/
  local-dev.yaml    Default audit policy.
tests/fixtures/     Local command fixtures and expected timeline fragments.
```

## 🗺️ Feature Plan And Progress

| Milestone | Scope | Status |
| --- | --- | --- |
| M1 | Rust workspace, core schema, policy parser, JSONL store, local CLI wrapper, README | ✅ **Completed in this iteration** |
| M2 | Local process session model, process-tree attribution, timeout notify, richer fixtures | ✅ **Completed in this iteration** |
| M3 | Docker adapter with safe defaults and container metadata | 🟡 Planned |
| M4 | eBPF audit-only observer for exec/file/network events | 🟡 Planned |
| M5 | Policy engine integration, `Notify`/`Block`/`Kill`/`Review`, feedback hook | 🟡 Planned |
| M6 | Kubernetes / Agent Sandbox metadata integration | 🟡 Planned |
| M7 | gVisor/Kata/Firecracker visibility validation | 🟡 Planned |

The table above is the repository-local progress summary. Detailed internal
development progress is tracked outside this repository in the surrounding
research workspace.

## 📜 License

Apolysis userspace components are licensed under Apache-2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

Future kernel-loaded eBPF programs under `ebpf/` are licensed under
GPL-2.0-only where required by Linux kernel BPF licensing rules. See
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).

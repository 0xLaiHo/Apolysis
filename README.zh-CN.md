# Apolysis

🌐 [English](README.md) | [简体中文](README.zh-CN.md)

**Apolysis** 是一个由环境拥有者掌握的 AI Agent 运行时问责层，面向不透明或半可信的 AI Agent workload。它的目标是在 agent harness 之下采集独立的 OS/runtime 证据，把这些证据与 agent 的声明意图、执行隔离边界关联起来，并为后续 `Notify`、`Review` 或强制执行高风险副作用提供策略入口。

## 🧭 Apolysis 是什么

Apolysis 不是 Docker、gVisor、Kata Containers、Firecracker、E2B、Daytona、Modal Sandboxes 或 Kubernetes Agent Sandbox 的替代品。它也不是 agent harness、MCP gateway、审批 UI 或通用容器 runtime。它位于 harness 之下，并位于执行 runtime 之上或旁边，补齐 AI Agent 安全中缺失的一层：**由环境拥有者掌握的副作用验证**。

核心假设是：harness 日志不能作为唯一事实来源。现代 agent harness 包含 prompt loop、规划和重试逻辑、工具路由、MCP client、权限模式、审批门控、hooks、memory、日志、凭证处理，有时还包含默认 sandbox 配置。当 harness 不透明、来自第三方、托管运行，或可以启动任意子进程时，环境运营者需要不依赖 harness 诚实且完整上报的 OS/runtime 事实。

长期架构分为三层：

1. 🔐 **意图授权**：回答 agent 应该做什么，通常由 harness 通过 MCP、工具网关、OAuth scope 和审批来调解。
2. 🧱 **执行隔离**：回答 agent 能触及什么，由容器、VM、namespace、network policy、文件系统挂载和 runtime limit 提供。
3. 🔎 **副作用验证**：回答实际发生了什么，通过进程谱系、文件访问、网络连接、凭证读取、策略决策和反馈来记录。

当三层一致时，平台可以对会话建立更高信心。当三层不一致时，Apolysis 将 OS/runtime 证据作为调查和未来执行控制的起点。

F0（M1-M7）完成了第三层的首个 PoC baseline。它会记录本地 session、process-tree 归属、Docker runtime metadata、Kubernetes Pod metadata、fixture ring-buffer 事件、raw kernel event、归一化副作用事件、policy violation、降级 metadata、feedback 文件、visibility assessment 和 JSONL timeline。F1 已实现带 session scope 的 live audit-only eBPF observer，包括 CO-RE build、Aya loader、process/file/network 事件、loss diagnostics 和持久化前脱敏，并已完成特权 live-host 验证。F3 在 production-facing kernel blocking 默认关闭的前提下，完成了 narrow local seccomp 和 BPF-LSM pre-operation block prototype validation，并加入 operator-approved enablement 与 rollback audit record。F4 已完成 runtime adapter depth：它区分已支持的 audit/review/kill 路径、本机 block prototype、metadata-only 强隔离声明、VM-backed runtime 的 boundary-only 能力，以及已验证的 Docker/containerd/Kubernetes adapter evidence；同时新增 live gVisor runsc/sentry/gofer metadata evidence、Kubernetes Agent Sandbox metadata evidence、Kata boundary-only evidence 和 live-runtime evidence bundle gate，用于把 F4 claim 绑定到保留的 F2 runtime adapter matrix artifact。F5 已启动，建立有边界的 Kubernetes DaemonSet/RBAC 生产加固部署基线，并加入 node-local daemon 的 live k3s rollout/restore 验证 gate、live metrics scrape validation、live DaemonSet restart、k3s CRI socket outage recovery、queue pressure、unwritable-store recovery evidence、本地 release supply-chain bundle gate、带 metrics mTLS handoff annotation 和窄 metrics NetworkPolicy allowlist 的 Helm-rendered tenant-isolated deployment packaging、用于 release image publishing、SBOM attachment 和只读归档证据的本地 OCI registry/archive gate，以及可选 Istio strict mTLS 和 metrics AuthorizationPolicy 渲染。Daemon API 现在也会在 session intent 中携带 tenant ID 与 retention tier，支持按 tenant 隔离的 session query/list response，并为保留的 daemon state 提供本地 retention purge dry-run/apply enforcement。F5 现在还包含 release promotion policy gate 和 live OCI registry promotion execution，用于验证 digest-locked production promotion、retention window、rollback tag 和有边界的 registry access principal，并新增 KMS/HSM signing profile gate、HSM-compatible PKCS#11 signing execution gate、opt-in AWS KMS live signing gate、external WORM/object-lock archive policy gate、live S3-compatible Object Lock API execution gate、live Istio service-mesh admission/handshake evidence gate、live operator/controller reconciliation validation、live k3s 与 Vultr VKE managed-Kubernetes chaos/performance validation、带 retained artifact SHA verification 与 final bundle assembly 的 fail-closed external provider qualification bundle gate、live Cloudflare R2 Bucket Lock WORM evidence、live Docker Hub immutable-tag registry promotion evidence、opt-in managed Cloud Service Mesh provider qualification gate、Vultr VKE 3-node cluster readiness gate、缺少 signing 或 managed service-mesh evidence 时 fail-closed 的 final provider readiness audit、使用 repository secrets 运行剩余 live provider evidence gates 的手动 GitHub Actions workflow，以及 final provider bundle environment preparation helper。

## 🚀 运行场景

- 🧑‍💻 **本地 coding agent**：包裹 Codex、Claude Code、Aider 或本地自动化脚本等命令，并输出 JSONL timeline。
- 🧪 **AI 生成代码执行**：在把不可信代码放进 Docker 或更强隔离 runtime 前，先准备好策略和事件 schema。
- 🔁 **CI/CD 审计**：记录启动了哪些进程，以及策略决策会如何写入 append-only timeline。
- ☁️ **云原生 agent 平台**：为后续 Kubernetes Agent Sandbox、gVisor 和 Kata 集成准备 schema 与 runtime adapter 边界。

## 🧩 与已有沙箱的差异

| 产品 / Runtime | 主要关注点 | Apolysis 的差异 |
| --- | --- | --- |
| Docker | 可复现的容器执行环境 | Docker 在 Apolysis 中被视为 baseline adapter，而不是强安全边界。 |
| gVisor | 面向容器的用户态内核隔离 | Apolysis 会把 runtime metadata 与 agent 副作用、策略决策关联起来。 |
| Kata Containers | 基于 VM 的 Kubernetes Pod 隔离 | Apolysis 会记录 host/guest 可观测性差异，并判断是否需要 guest collector。 |
| Firecracker | 低开销 microVM 原语 | Apolysis 在 MVP 阶段只预留未来 adapter，不构建 microVM 平台。 |
| E2B / Daytona / Modal | 托管 sandbox 执行环境 | Apolysis 关注跨环境的运行时证据、策略决策和 agent 反馈。 |
| Kubernetes Agent Sandbox | 云原生 agent workload 生命周期 | Apolysis 可以作为这类 workload 的观测层和策略层。 |
| AgentSight / ActPlane | eBPF 可观测 / eBPF 执行控制研究 | Apolysis 将这些思路适配为带 runtime adapter、schema 和分阶段执行控制的 Rust 项目。 |

## 🛠️ 编译与运行

当前 F0 baseline 和 F1 实现的环境要求：

- 🦀 Rust stable toolchain
- 📦 Cargo
- 🐧 Linux 开发 shell，用于通过 `/proc` 完成 process-tree 归属
- 🐳 真实 Docker 运行需要 Docker CLI/daemon；测试使用本地 Docker stub
- 🧬 eBPF 开发需要 `clang`、`llvm-strip`、`bpftool`、BTF 和更高权限；普通测试使用 fixture ring-buffer 记录，不需要 root

🔨 编译 Rust 与 CO-RE object：

```bash
make build
```

✅ 运行测试：

```bash
make test
```

🧹 运行 Clippy：

```bash
make lint
```

🎨 格式化：

```bash
cargo fmt --all
```

▶️ 运行本地命令 wrapper：

```bash
cargo run -p apolysis-cli -- run \
  --policy policies/local-dev.yaml \
  --output .apolysis/timeline.jsonl \
  -- echo hello
```

📄 查看生成的 JSONL timeline：

```bash
cat .apolysis/timeline.jsonl
```

M2 预期记录包括 `session_started`、`runtime_metadata`、`exec` 和 `process_exit`。超时时会输出带有 `runtime.max_seconds` 的 `policy_violation`，并终止本地进程树。

🐳 通过 M3 Docker adapter 运行：

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-timeline.jsonl \
  -- echo hello
```

如果已安装 gVisor 的 `runsc` runtime，可以指定：

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --docker-runtime runsc \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-runsc.jsonl \
  -- echo hello
```

Docker adapter 会注入 `APOLYSIS_SESSION_ID`，写入 Apolysis labels，使用 `--read-only`、`--network none`、`--cap-drop ALL`、`no-new-privileges`、`--pids-limit`、`--cpus` 和 `--memory`，并输出 container image、选定 OCI runtime、mounts、network mode、container id 和 cgroup mapping metadata。

🔎 使用 fixture ring-buffer 记录运行 M4 audit-only observer pipeline：

```bash
cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-m4-demo \
  --policy policies/local-dev.yaml \
  --output .apolysis/observer-timeline.jsonl
```

Observer 会同时写入 `raw_kernel_event` 和分析后的 canonical event。M4 事件集覆盖 `exec`、`open/openat/openat2`、`creat`、`truncate`、`unlink`、`rename`、network `connect` 和 credential path read。默认 runner plan 启用 process/system runner，并将 stdio 与 SSL/HTTP uprobe 留到后续阶段。

🧬 在具备相应能力的 Linux host 上运行 F1 live audit-only observer：

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

使用 `make test-live` 运行 capability-aware smoke test。Live backend 仅用于
audit，不提供 pre-operation blocking。

🛡️ 运行 M5 policy-feedback 路径：

```bash
APOLYSIS_BPF_LSM_AVAILABLE=0 cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-m5-demo \
  --policy tests/fixtures/policies/m5-block-policy.yaml \
  --output .apolysis/policy-timeline.jsonl \
  --feedback-dir .sandbox
```

当策略请求 `block` 但 BPF-LSM 不可用时，Apolysis 会写入明确的 `unavailable:downgrade:block->notify` metadata event，输出带 `tracepoint_notify` 的 `policy_violation` 记录，并更新 `.sandbox/last-violation.txt`，为后续 Claude/Codex hook 集成预留读取入口。

☸️ 为 observer session 增加 M6 Kubernetes / Agent Sandbox metadata：

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

M6 消费已捕获的 Pod metadata，而不是直接访问实时 Kubernetes API。它会输出 Pod、namespace、service account、RuntimeClass、node、service-account-token 和 Agent Sandbox 身份记录，并在同一条 timeline 上保留 M5 policy-feedback 合约。

🧪 运行 M7 强隔离可观测性验证器：

```bash
cargo run -p apolysis-cli -- visibility \
  --scenario kubernetes-kata \
  --input tests/fixtures/visibility/kubernetes-kata-host-events.txt \
  --output .apolysis/visibility-kata.jsonl \
  --kubernetes-metadata tests/fixtures/kubernetes/agent-sandbox-kata-pod.yaml
```

验证器会对比 Docker default、Docker+gVisor、Kubernetes+gVisor、Kubernetes+Kata 和 Firecracker boundary 场景下的 host-side observer fixture。它会记录 host 语义是否折叠、是否需要 runtime metadata、是否需要 guest-side collector。

## 📁 仓库结构

```text
crates/
  apolysis-accountability/ F2 intent、session、finding、queue 与 health contract。
  apolysis-core/    共享 schema 与 JSONL 记录。
  apolysis-daemon/  节点本地 `apolysisd` Unix socket 服务。
  apolysis-feedback/ 面向 agent 的 violation feedback 文件。
  apolysis-kubernetes/ Kubernetes 与 Agent Sandbox metadata parser。
  apolysis-observer/ raw kernel event observer 与 policy evaluation pipeline。
  apolysis-policy/  YAML/JSON policy parser 与决策逻辑。
  apolysis-runtime/ 本地 runner 与 Docker runtime adapter。
  apolysis-store/   append-only JSONL timeline writer。
  apolysis-visibility/ 强隔离可观测性评估模型。
  apolysis-cli/     本地 `apolysis run` 命令 wrapper。
ebpf/
  include/          与用户态共享的 observer ring-buffer ABI。
  observer/         GPL-2.0-only F1 eBPF observer source。
target/ebpf/        生成的 CO-RE build output。
deploy/kubernetes/ RuntimeClass、NetworkPolicy 与 Agent Sandbox 示例。
policies/
  local-dev.yaml    默认 audit policy。
  docker-baseline.yaml Docker adapter baseline policy。
tests/fixtures/     本地/Docker 命令测试夹具和预期 timeline 片段。
```

## 🗺️ 功能规划与进度

当前状态：Apolysis 是 PoC / audit-first 原型。F0（M1-M7）、F1
Independent Observability MVP、F2 Accountability Beta、F3 Limited Guardrails
和 F4 Runtime Adapter Depth 均已完成。F5 Production Hardening 正在进行中，
已包含 Kubernetes DaemonSet/RBAC deployment baseline、本地 manifest hardening
gate、live k3s deployment validation gate 和 production DaemonSet metrics
validation、resilience validation、queue pressure validation、storage-failure
validation、release supply-chain validation，以及 tenant-isolated node-local
deployment 的 Helm production packaging 和 release artifacts 的本地 OCI
registry/archive validation，以及 metrics access 的 service-mesh identity
policy rendering validation、daemon API 中的 tenant-scoped query/retention
metadata、本地 retention purge enforcement，以及 production registry
retention/access control 的 release promotion policy validation 与 live OCI registry
promotion execution validation、KMS/HSM
signing profile validation 和 HSM-compatible PKCS#11 signing execution，以及
opt-in AWS KMS live signing gate、
external WORM/object-lock archive policy validation、live S3-compatible Object
Lock API execution validation、live Istio service-mesh admission/handshake
validation、live operator/controller reconciliation validation、live k3s 与 Vultr VKE
managed-Kubernetes chaos/performance validation、带 retained artifact SHA verification 的 fail-closed external provider
qualification bundle validation 与 final bundle assembly、live Cloudflare R2 Bucket Lock WORM evidence、
live Docker Hub immutable-tag registry promotion evidence，以及 opt-in managed Cloud Service Mesh provider
qualification gate、Vultr VKE 3-node cluster readiness gate、final provider readiness audit 和手动 final provider evidence workflow。

实现里程碑：

| Milestone | Scope | Status |
| --- | --- | --- |
| M1 | Rust workspace、核心 schema、policy parser、JSONL store、本地 CLI wrapper、README | ✅ **Completed** |
| M2 | 本地进程 session model、process-tree 归属、超时 notify、更丰富的 fixtures | ✅ **Completed** |
| M3 | Docker adapter（安全默认值、可选 OCI runtime、容器元数据） | ✅ **Completed** |
| M4 | Audit-only observer pipeline（raw kernel event schema、eBPF ring-buffer ABI、exec/file/network 归一化） | ✅ **Completed** |
| M5 | 策略引擎集成（`Notify`/`Block`/`Kill`/`Review`、feedback hook） | ✅ **Completed** |
| M6 | Kubernetes / Agent Sandbox metadata 集成 | ✅ **Completed** |
| M7 | gVisor/Kata/Firecracker host-visibility validation 与 guest collector decision model | ✅ **Completed** |

聚焦路线图：

| Phase | Scope | Status |
| --- | --- | --- |
| F0 | PoC baseline：M1-M7 schema、adapter、fixture observer、feedback、Kubernetes metadata、强隔离 visibility modeling | ✅ **Completed** |
| F1 | Independent Observability MVP：live audit-only eBPF observer、CO-RE/Aya loader、process/file/network/credential timeline、loss accounting、redaction | ✅ **已完成** |
| F2 | Accountability Beta：`apolysisd`、cross-layer comparison、Docker/containerd/Kubernetes metadata correlation、`Notify`/`Review` findings、feedback、metrics、本地 timeline integrity | ✅ **已完成** |
| F3 | Limited Guardrails：真实描述 `Notify`/`Review`/`Kill`，只在能证明 pre-op prevention 的窄场景 prototype BPF-LSM/seccomp `Block` | ✅ **已完成** |
| F4 | Runtime Adapter Depth：Docker/containerd baseline、gVisor metadata adapter、Kubernetes Agent Sandbox metadata、Kata boundary-only mode、Firecracker research prototype | ✅ **已完成** |
| F5 | Production Hardening：DaemonSet privilege budget、multi-tenant storage/query/retention metadata、mTLS/RBAC、signed artifacts、SBOM/provenance、KMS/HSM signing profile validation、PKCS#11 signing execution、opt-in AWS KMS live signing、Helm、registry/archive/promotion/WORM policy 与 API execution validation（包含 live OCI promotion）、service-mesh identity/live handshake validation、opt-in managed Cloud Service Mesh provider qualification、live operator/controller reconciliation validation、live k3s 与 Vultr VKE managed-Kubernetes chaos/performance validation、Vultr VKE 3-node readiness、final provider readiness audit、手动 provider evidence workflow、final provider bundle environment preparation、带 retained artifact SHA verification 与 final bundle assembly 的 fail-closed external provider qualification bundle validation、live Cloudflare R2 Bucket Lock WORM evidence、live Docker Hub immutable-tag registry promotion evidence，以及剩余 external KMS/HSM 与 managed service-mesh provider qualification 的 live execution | 🚧 **进行中** |

## 📜 许可证

Apolysis userspace 组件使用 Apache-2.0。详见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。

未来 `ebpf/` 下需要加载进内核的 eBPF 程序，在 Linux kernel BPF 许可规则要求时使用 GPL-2.0-only。详见 [LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)。

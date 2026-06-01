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

M1 阶段实现的是第三层的第一版代码基础，当前只包含 Rust audit-mode 组件。内核 eBPF 采集和 BPF-LSM 执行控制已经纳入计划，但本阶段尚未启用。

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
| Firecracker | 低开销 microVM 原语 | Apolysis 在 M1 只预留未来 adapter，不在当前阶段构建 microVM 平台。 |
| E2B / Daytona / Modal | 托管 sandbox 执行环境 | Apolysis 关注跨环境的运行时证据、策略决策和 agent 反馈。 |
| Kubernetes Agent Sandbox | 云原生 agent workload 生命周期 | Apolysis 可以作为这类 workload 的观测层和策略层。 |
| AgentSight / ActPlane | eBPF 可观测 / eBPF 执行控制研究 | Apolysis 将这些思路适配为带 runtime adapter、schema 和分阶段执行控制的 Rust 项目。 |

## 🛠️ 编译与运行

M1 阶段要求：

- 🦀 Rust stable toolchain
- 📦 Cargo
- 💻 当前 Rust-only 基础能力可在 Linux/macOS 开发 shell 中运行

🔨 编译：

```bash
cargo build
```

✅ 运行测试：

```bash
cargo test
```

🧹 运行 Clippy：

```bash
cargo clippy --all-targets --all-features
```

🎨 格式化：

```bash
cargo fmt --all
```

▶️ 运行 M1 本地命令 wrapper：

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

M1 预期记录包括 `session_started`、`exec` 和 `process_exit`。

## 📁 仓库结构

```text
crates/
  apolysis-core/    共享 schema 与 JSONL 记录。
  apolysis-policy/  M1 policy parser 与 audit-only 决策。
  apolysis-store/   append-only JSONL timeline writer。
  apolysis-cli/     本地 `apolysis run` 命令 wrapper。
policies/
  local-dev.yaml    M1 默认 audit policy。
tests/fixtures/     供后续 M2/M4 复用的本地命令测试夹具。
```

## 🗺️ 功能规划与进度

| Milestone | Scope | Status |
| --- | --- | --- |
| M1 | Rust workspace、核心 schema、policy parser、JSONL store、本地 CLI wrapper、README | ✅ **本轮已完成** |
| M2 | 本地进程 session model、cgroup/process-tree 归属、更丰富的 fixtures | 🟡 计划中 |
| M3 | 带安全默认值和 container metadata 的 Docker adapter | 🟡 计划中 |
| M4 | 面向 exec/file/network 事件的 eBPF audit-only observer | 🟡 计划中 |
| M5 | 策略引擎集成、`Notify`/`Block`/`Kill`/`Review`、feedback hook | 🟡 计划中 |
| M6 | Kubernetes / Agent Sandbox metadata 集成 | 🟡 计划中 |
| M7 | gVisor/Kata/Firecracker 可观测性验证 | 🟡 计划中 |

上表是仓库内的简要进度摘要。详细的内部开发进度记录放在本仓库外层的 research workspace 中。

## 📜 许可证

Apolysis userspace 组件使用 Apache-2.0。详见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。

未来 `ebpf/` 下需要加载进内核的 eBPF 程序，在 Linux kernel BPF 许可规则要求时使用 GPL-2.0-only。详见 [LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)。

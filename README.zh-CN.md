# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [简体中文](README.zh-CN.md)

Apolysis 是面向用户可控 Linux 环境的实验性 **eBPF Agent 运行时观测平台**。它把受支持的
进程、文件、网络和凭证相关运行时观测组织到一次 Agent Run 中，将其归属到进程和工作负载
身份，并明确展示 collector 丢失、截断和不支持的路径。

项目正在围绕这条 Linux runtime workflow 重置范围。eBPF 是必需的主要观测源，不再是更大
跨 provider 证据平台的可选附加项。Apolysis 不是 Agent orchestrator、sandbox、策略执行
引擎、MCP gateway、SIEM 或多租户证据 SaaS。

![Apolysis 实时 eBPF 审计：声明的 Agent workload 被匹配，一次未声明的凭证路径访问尝试被标记为 missing_intent；凭证路径在 timeline 中已脱敏](docs/assets/codex-live-demo/live-ebpf-demo.gif)

演示素材：[实时 asciinema cast](docs/assets/codex-live-demo/live-ebpf-demo.cast)、
[零特权 quickstart cast](docs/assets/codex-live-demo/codex-live-demo.cast) 和
[公开证据摘录](docs/codex-live-demo-public-assets.md)。

## 五分钟零特权试用

```bash
make build && make quickstart
```

Quickstart 使用随包 fixture 运行观测与可选的声明意图对比。它不需要 root 或 eBPF，用于展示
当前 record 和调查体验。参见 [Quickstart](docs/quickstart.md)。

## 产品问题

对于一次受支持的 Agent Run，Apolysis 应帮助操作者回答：

1. Agent 启动了哪些进程？
2. 观测到了哪些受支持的文件、网络和凭证操作？
3. 每条观测属于哪个 container、cgroup、Pod 或进程身份？
4. 操作是成功、失败，还是结果未知？
5. Collector 是否健康，观测缺口在哪里？
6. 哪些有界 Finding 需要操作者复查？

产品不把“没有观测到”解释为“没有发生”。它只描述声明 scope 与 capability 边界内的活动。

## 活跃产品边界

| 属于当前范围 | 不属于活跃范围 |
| --- | --- |
| 用户可控的 Linux 主机 | 用户无法控制 kernel 的厂商托管 Agent |
| 托管 Agent 启动、PID-tree 与 cgroup scope | 通用 Agent orchestration 或 sandbox |
| 进程、选定文件、网络和凭证观测 | 无差别全 syscall 或明文采集 |
| 本地、Docker/containerd 与有界 Kubernetes 归属 | 跨 provider Hook、OTLP、MCP、A2A 集成矩阵 |
| Collector 健康、丢失、截断和 capability gap | 远端 outcome 验证和可移植证据托管 |
| 本地 run 存储、查询和操作者 viewer | 多租户 Gateway、PostgreSQL/S3 平台、计费或 HA |
| 面向复查的 finding | BPF-LSM 阻断、审批 workflow 或通用 enforcement |

未来可以把 provider 或 harness metadata 作为可选上下文，但它不能替代 eBPF runtime source，
也不能把推断关系静默升级为 exact relation。

## 当前能力

- 通过 CO-RE eBPF 观测 fork、exec、exit、outcome-aware 选定文件操作和 network connect。
- 提供版本化 kernel/userspace ABI，并为每次 Agent Run 写入 capability manifest，明确实际挂载的
  event source 与支持的 outcome 语义。
- 为每次 Agent Run 写入 collector lifecycle record，包括持久化 start、周期 health/loss
  checkpoint、明确的正常或失败 terminal state；daemon 恢复未完成实例时会持久化 restart gap。
- 在一次 collector 运行内提供可抵御 PID reuse、exec 与数字 cgroup ID 复用的稳定 runtime
  identity，并显式记录 exact 或 inferred attribution。
- 支持 PID-tree、单 cgroup 与多 cgroup Observation Scope。
- 支持托管本地 Agent 启动，以及带显式 late-attach Collection Boundary 的 protected
  existing-process attach。
- Existing-process admission 只对当前 root 做资格校验；本次 run 的 exact event identity
  从 activation 后开始。
- 支持 local、Docker/containerd 和 Kubernetes 原型的 runtime metadata 关联。
- Exec 参数与 process command 默认 content-off 持久化，并对凭证和网络内容脱敏。
- 提供有序 JSONL、输出轮转、可选本地 hash-chain envelope，以及 drop、map pressure、ABI
  mismatch、decode failure 和 truncation 的类型化诊断。
- 可在非特权环境中把一次 saved Agent Run 确定性投影为可查询的 Agent Observation Record，
  并保持 evidence、collector health 与 review state 相互独立。Plain/rotated JSONL 和经过验证的
  hash-chain 输入都有界，遇到损坏或混合 run 时 fail closed。
- 可在非特权环境中把一份 Agent Observation Record 确定性呈现为私有、self-contained 的离线
  HTML 调查视图；三个状态轴保持独立，Finding 可链接到按 source order 排列的 observation。
- 对无法匹配或 collector 停止时仍 pending 的选定文件与 network connect entry/exit pair
  发出归属于 Agent Run 的 Observation Gap，并隔离 multi-cgroup daemon 中的不同 scope。
- 可选摄取 Codex 声明意图并通过启发式关联生成 mismatch finding。

选定文件操作与 network connect 现使用有界 entry/exit matching，并报告 return value 与
errno。文件 outcome 为 succeeded、failed 或 denied；connect 还支持 pending。Collector
不会观测所有 Linux 操作路径。

## 目标形态

```text
Agent command / container / Pod
  -> Observation Scope
  -> eBPF Collector
     - process lifecycle
     - selected file operations
     - network connections
     - collector health and gaps
  -> userspace normalization and redaction
  -> bounded local store
  -> CLI and saved-run viewer
```

特权 collector 与非特权 operator viewer 保持独立 trust boundary。Remote export 和任何中央
多租户证据平面都后置到有界 Beta 之后。

## 支持环境

| 环境 | 方向 |
| --- | --- |
| 本地 Linux Agent CLI | 首个稳定 workflow |
| 用户可控 Linux 上的 Docker/containerd | 本地 collector 正确性完成后的稳定目标 |
| Kubernetes node 与 Pod 归属 | Container identity 稳定后的有界 Beta |
| Linux self-hosted CI runner | 通过 CLI managed-run boundary 支持；不维护 composite Action |
| macOS、Windows 或厂商托管 Agent runtime | 不支持 eBPF runtime observation |

## 当前仓库状态

`v0.3.0` 仍是最新公开研究版本，展示 live collector、托管 Agent 启动、JSONL timeline、
隐私脱敏和发布打包。活跃 Cargo workspace 现仅包含 9 个 crate：core、observer、
accountability finding、本地 storage、daemon、CLI、saved-run viewer、Kubernetes metadata
与 visibility assessment。被取代的 contracts、中央服务、policy actuation、Agent feedback
control、sandbox execution 与广泛的 production-qualification 原型已移出活跃 build 和默认
门禁。

本地 `apolysis run project` 路径现可为 saved run 原子写入一份私有 JSON Agent Observation
Record。`apolysis run view` 会验证恰好一份这类 v1 record，并写入私有、self-contained 的离线
HTML 调查视图。本地 projection 与 viewer 不会引入 live tail、跨 run 搜索、中央 query
service，也不会改变当前 experimental support 状态。

范围重置是一项路线图决策，不是追溯性的生产声明。在受支持 collector、归属、失败、性能和
隐私路径通过新的有界 Beta 门禁前，Apolysis 仍是实验性项目。
首个资格 contract 现仅把 Linux 6.12/x86_64 原生 host 命名为 Candidate；当前尚无
Supported 环境，数值性能预算仍由证据门禁。仓库已提供版本化、content-free 的 synthetic
workload；显式 collector-off/on 路径现会保留 monotonic latency、隔离的 collector resource
sample、按 phase 归因的 burst loss 与 pair-bootstrap summary，但没有保留的 privileged 证据和
reviewed 数值 budget 时，这些输出不会授予支持。详见
[Beta 资格包络](docs/qualification-envelope.zh-CN.md)。

## 构建与测试

```bash
make build
make test
make lint
```

只构建 CO-RE eBPF 对象：

```bash
make build-ebpf
```

在准备好的 Linux host 上运行 opt-in live observer test：

```bash
make test-live
```

当 Linux BTF、cgroup v2、tracepoint 或所需 BPF capability 不可用时，特权测试会明确跳过。

无需 root 即可投影 saved run：

```bash
./target/debug/apolysis run project \
  --input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/agent-observation-record.json
```

无需 root 即可把这份 record 渲染为离线 Saved Run Viewer：

```bash
./target/debug/apolysis run view \
  --input .apolysis/codex-live/agent-observation-record.json \
  --output .apolysis/codex-live/saved-run-view.html
```

## 托管 Agent 实时观测示例

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-observation \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex exec --json "run the project tests"
```

不要在托管命令或参数中放置 secret。持久化边界默认关闭原始命令内容，但特权 kernel 内采集
与第三方 workload 行为仍需要有文档化的 threat model。

## 高层路线图

1. 保持活跃 workspace 只包含 eBPF collection、Observation Scope、attribution、本地 storage、
   daemon、CLI 与操作者调查能力。
2. 在保持 outcome-aware 语义与单次运行内稳定 runtime identity 的同时，验证 collector
   lifecycle、health/gap 报告和本地 Agent Run 调查 workflow。
3. 先验证 container 归属，再交付有界 Kubernetes Beta；在此之前不扩张中央平台。

## 文档

- [范围决策](docs/adr/0004-focus-on-ebpf-agent-observability.md)
- [设计文档](docs/design.zh-CN.md)
- [路线图](docs/roadmap.zh-CN.md)
- [有界 Beta 验证计划](docs/beta-qualification-plan.zh-CN.md)
- [Quickstart](docs/quickstart.md)
- [JSONL 模式](docs/jsonl-schema-v1.md)
- [Agent Observation Record v1](docs/agent-observation-record-v1.zh-CN.md)
- [威胁模型](docs/threat-model.md)
- [可见性验证](docs/visibility-validation.md)
- [实时演示运行手册](docs/codex-live-demo-runbook.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)

# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [简体中文](README.zh-CN.md)

Apolysis 当前是面向 AI 智能体工作负载的实验性 Linux 运行时审计遥测与问责层。它记录
有 scope 的主机观测和 syscall 尝试子集，并把进程、文件、网络、凭证、运行时、策略和
声明意图记录做启发式关联，形成有序审计时间线。

项目正在演进为 Agent 运行时证据与策略平面，把本地、CI、厂商托管、container 和
Kubernetes Agent 环境中的 hook、SDK、OTLP、MCP、A2A、provider outcome 与可选 eBPF
runtime evidence 关联起来。它不是通用 Agent orchestrator、sandbox、MCP gateway 或 SIEM。

![Apolysis 实时 eBPF 审计：智能体声明的 workload 被匹配，一次未声明的凭证路径访问尝试被标记为 missing_intent——录自真实 observe 运行；凭证路径在 timeline 中已脱敏](docs/assets/codex-live-demo/live-ebpf-demo.gif)

演示素材：[实时 asciinema cast](docs/assets/codex-live-demo/live-ebpf-demo.cast)、
[零特权 quickstart cast](docs/assets/codex-live-demo/codex-live-demo.cast)
和[公开证据摘录](docs/codex-live-demo-public-assets.md)。

## 五分钟试用（无需 root）

```bash
make build && make quickstart
```

在一份随包 fixture 上跑完「声明意图 ↔ 观测事件」问责流程——不需要 root、不需要
eBPF——并打印出声明意图和 fixture 中的 OS 观测事件在哪里出现分歧。见
[Quickstart](docs/quickstart.md)。

## 在 CI 里审计智能体（GitHub Action）

```yaml
- uses: 0xLaiHo/Apolysis@c00a84650e306d01b44e2fbd6b80f1395c852f74 # v0.3.0
  with:
    run: 'codex exec --json "run the project tests"'
```

一个 step 就能在 runner 上记录该命令在 session scope 内的内核观测和 syscall 尝试，
把摘要打进 job summary，并把 JSONL 时间线作为 artifact 上传。见
[GitHub Action](docs/github-action.md)。

## 当前状态

`v0.3.0` 是最新的公开研究版本，包含预构建 Linux CLI、随包 CO-RE eBPF
对象、release manifest、checksum 和 AWS KMS 发布制品签名证据。该版本修复了快命令
可能丢失全部事件的观测器竞态，新增关联摘要，并在事件被丢弃或截断时告警。

Apolysis 仍是实验性审计遥测：当前文件与网络 tracepoint 在没有结果信息时只描述
syscall 尝试；CLI timeline 是普通 JSONL，daemon 模式可以使用本地 hash-chain
envelope。两者都不是已被独立锚定的取证记录。

26 周 production MVP 方向先交付版本化 Agent Execution Record、带认证的 Execution
Evidence Gateway、耐久存储，以及展示 run inventory、独立 coverage、timeline、source
health 和 finding 的 Minimum Console v0；后续 source integration 最终形成带 Agent Run
Graph、跨 run search 与有限 workflow action 的 Investigation Console v1，再进入受控伙伴
pilot。每次 run 将分别显示 semantic、execution 与 outcome coverage。这些都是 roadmap
目标，不是当前能力。在公开路径完成加固前，不要把
当前 Action 用于不可信仓库或 GitHub 拉取请求（PR）。

## 核心能力

- 通过离线数据和实时 eBPF 观测采集进程、文件、网络、受限命令参数和凭证路径事件，
  并显式说明 attempt/outcome 局限。
- 由 Apolysis 托管启动本地智能体命令，并为 Codex 等命令行智能体追踪进程树。
- 摄入智能体声明的工具调用意图，并与主机侧观测事件做启发式关联。
- 关联本地进程、Docker/containerd 和 Kubernetes 工作负载的运行时元数据。
- 提供有序 JSONL timeline、输出轮转、daemon 本地哈希链校验、策略发现和发布验证关卡。

## 当前架构

```text
智能体 / 工具运行器
  └─ 声明意图日志

Apolysis 观测器
  ├─ 实时 eBPF 事件
  ├─ 进程树归属
  ├─ 运行时元数据
  └─ 策略评估

Apolysis 关联层
  ├─ 意图记录
  ├─ 主机侧观测事件
  └─ 问责发现

记录的时间线
  ├─ JSONL 时间线
  ├─ 本地轮转文件
  └─ 可选哈希链校验
```

设计上分开三类边界：

- 意图：智能体框架或工具运行器声明要做什么。
- 隔离：运行时允许工作负载触及什么。
- 证据：主机和运行时实际观测到了什么。

核心模块：

- `apolysis-cli`：命令行入口。
- `apolysis-observer`：离线和实时观测后端。
- `apolysis-core`：共享 JSONL 记录和模式类型。
- `apolysis-runtime`：本地、Docker 和运行时元数据适配。
- `apolysis-policy`：策略解析和决策逻辑。
- `apolysis-store`：追加式 JSONL 和哈希链存储。
- `apolysis-daemon`：面向长期运行场景的节点本地服务。

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

在已准备好 eBPF 能力的 Linux 主机上运行实时观测测试：

```bash
make test-live
```

## 示例：审计本地智能体命令

输入：

- 已构建的二进制：`target/debug/apolysis`
- 已构建的 BPF 对象：`target/ebpf/apolysis_observer.bpf.o`
- 策略文件：`policies/local-dev.yaml`
- 智能体命令：`codex exec --json "run the project tests"`

命令：

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-audit \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex exec --json "run the project tests"
```

参数说明：

- `--backend live`：使用实时 eBPF 观测后端。
- `--session`：写入每条记录的稳定会话标识。
- `--policy`：用于生成复查和通知发现的策略文件。
- `--output`：JSONL 时间线输出路径。
- `--bpf-object`：实时观测后端加载的 CO-RE BPF 对象。
- `--workspace-root`：用于路径处理的工作区边界。
- `--agent-kind`：智能体类型提示，例如 `codex`。
- `--agent-run -- <command>`：由 Apolysis 启动智能体并掌握根进程树，避免让
  使用者手动查找进程号。

输出示例：

```jsonl
{"record_type":"event","event_type":"exec","resource":"codex"}
{"record_type":"event","event_type":"file_open","resource":"path_token:..."}
{"record_type":"policy_violation","rule_id":"credentials.deny_read","decision":"notify"}
```

## 示例：关联声明意图

输入：

- Codex 响应日志：`.apolysis/codex-live/codex-response-items.jsonl`
- 主机观测时间线：`.apolysis/codex-live/timeline.agent-run.jsonl`
- 会话标识：`codex-local-audit`

命令：

```bash
./target/debug/apolysis intent ingest \
  --adapter codex-jsonl \
  --input .apolysis/codex-live/codex-response-items.jsonl \
  --session codex-local-audit \
  --output .apolysis/codex-live/intent.codex.jsonl \
  --workspace-root "$PWD"

./target/debug/apolysis intent correlate \
  --intent-input .apolysis/codex-live/intent.codex.jsonl \
  --timeline-input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/intent-correlation.jsonl
```

输出示例：

```jsonl
{"record_type":"intent","intent_source":"codex","declared_action":"shell.command"}
{"record_type":"intent_correlation","match_basis":"process_executable"}
{"record_type":"accountability_finding","kind":"missing_intent","decision":"review"}
```

生成的时间线、Codex 日志和报告应放在 `.apolysis/` 或 `target/` 下。不要提交
捕获到的工作负载数据或凭证。

## 关键文档

- [Quickstart](docs/quickstart.md)
- [GitHub Action](docs/github-action.md)
- [JSONL 模式](docs/jsonl-schema-v1.md)
- [威胁模型](docs/threat-model.md)
- [哈希链校验](docs/hash-chain-verification.md)
- [时间线外运](docs/timeline-shipping.md)
- [Codex 实时演示运行手册](docs/codex-live-demo-runbook.md)
- [Codex 实时演示 launch blog 草稿](docs/codex-live-demo-launch-blog.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)

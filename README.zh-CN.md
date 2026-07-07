# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [简体中文](README.zh-CN.md)

Apolysis 是面向 AI 智能体工作负载的 Linux 运行时问责层。它记录一次智能体会话在
主机侧实际产生的进程、文件、网络、凭证、运行时、策略和声明意图证据，并将这些证据
关联成追加式审计时间线。

它不是沙箱、审批界面、工具网关或告警平台。它的职责是作为环境侧证据层，帮助
运维者不依赖智能体框架本身，也能复查智能体到底做了什么。

![Codex 实时演示：Apolysis 匹配声明的 workload，并将脱敏后的假凭证副作用标记为 missing intent](docs/assets/codex-live-demo/codex-live-demo.gif)

演示素材：[asciinema cast](docs/assets/codex-live-demo/codex-live-demo.cast)
和[公开证据摘录](docs/codex-live-demo-public-assets.md)。

## 当前状态

`v0.2.0` 是第一个已签名的公开版本，包含预构建 Linux CLI、随包 CO-RE eBPF
对象、release manifest、checksum 和 AWS KMS 签名证据。Apolysis 仍然是审计与
问责层，不是完整沙箱提供方，也不是合规认证平台。

## 核心能力

- 通过离线数据和实时 eBPF 观测采集进程、文件、网络、受限命令参数和凭证路径事件。
- 由 Apolysis 托管启动本地智能体命令，并为 Codex 等命令行智能体追踪进程树。
- 摄入并关联智能体声明的工具调用意图与主机侧实际副作用。
- 关联本地进程、Docker/containerd 和 Kubernetes 工作负载的运行时元数据。
- 提供追加式 JSONL 证据、输出轮转、哈希链校验、策略发现、发布验证关卡，以及
  带签名证据的 release 产物交接。

## 架构设计

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

追加式证据
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

- [JSONL 模式](docs/jsonl-schema-v1.md)
- [威胁模型](docs/threat-model.md)
- [哈希链校验](docs/hash-chain-verification.md)
- [时间线外运](docs/timeline-shipping.md)
- [Codex 实时演示运行手册](docs/codex-live-demo-runbook.md)
- [Codex 实时演示 launch blog 草稿](docs/codex-live-demo-launch-blog.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)
- [入门任务](docs/starter-issues.md)

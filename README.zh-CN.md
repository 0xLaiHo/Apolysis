# Apolysis

[English](README.md) | [简体中文](README.zh-CN.md) | [架构设计](docs/design.zh-CN.md)

Apolysis 是面向 AI agent 的实验性 Linux 审计与证据系统。它分别采集工具声明和
指定范围内的操作系统观测，再通过显式标识符关联。报告展示 agent 声明了什么、
实际观测到了哪些进程、文件和网络操作尝试，以及哪些证据仍然缺失。

本地入口直接打开 agent 原有的应用。Apolysis 配置临时 hook 并启动独立 eBPF
采集器；应用保留自己的界面、工具、配置和权限提示。这条观测路径不提供隔离，
也不能仅凭采集结果证明任务成功。

## 当前能力

- Codex、Claude Code、Cursor Agent、Pi 和 OpenCode 原生启动适配器，分别加载
  产品支持的 hook，并透传原生参数。
- 按进程树或 cgroup 范围观测，补充运行时与容器元数据，输出策略发现，明确报告
  事件丢失和截断。
- 采集工具声明及可选的显式调用理由，通过 `intent_id` 关联执行证据；基于标识符
  的精确关联与推断候选保持分离。
- 保存本地 JSONL 证据，生成按工具调用组织的 HTML、Markdown 和 JSON 报告。
- 独立的服务端基础：版本化执行记录契约、经过认证的 Gateway、PostgreSQL
  持久化、加密证据对象写入及生命周期投影。目前还不是集成的生产服务，也没有
  已交付的网页控制台。

模块边界、记录语义、隐私规则及各子系统限制见[架构设计](docs/design.zh-CN.md)。

## 无需 root 的夹具体验

安装 Rust/Cargo 和本机编译工具链后，在项目目录执行：

```bash
cargo build -p apolysis-cli
make quickstart
```

该命令使用仓库中的工具声明和观测事件夹具，不需要模型服务、sudo 或真实 eBPF，
结果写入 `target/quickstart/`。它展示关联流程，不会实际观测 agent。

## 观测原生 agent

真实观测需要 Linux 内核提供 BTF、所需 tracepoint 和 BPF ring buffer 支持。
仓库中的真实验证脚本还要求 cgroup v2。编译 BPF 对象需要 Clang/LLVM、`bpftool`
和 libbpf 头文件。将选定的 agent 安装到 `PATH`，完成其正常认证，并具备启动
采集器所需的 sudo 权限。

以普通用户编译 CLI 及配套 BPF 对象：

```bash
APOLYSIS_REQUIRE_BPF=1 make build
```

这个环境变量会将 BPF 前置条件缺失视为构建失败，而非可选跳过。然后显式选择应用：

```bash
target/debug/apolysis observe --agent claude
target/debug/apolysis observe --agent codex
target/debug/apolysis observe --agent pi
target/debug/apolysis observe --agent opencode
target/debug/apolysis observe --agent cursor
```

命令前不要加 `sudo`。只有采集器会请求提权，应用仍以当前用户运行。没有默认 agent。
Cursor 使用已安装的 `cursor-agent`，其余名称使用对应的同名可执行文件。

Apolysis 参数放在 `--` 前，应用原有参数放在其后；参数边界和顺序保持不变：

```bash
target/debug/apolysis observe --agent pi -- --provider deepseek --model deepseek-flash
target/debug/apolysis observe --agent claude -- --help
```

模型是否可用、会话恢复选项和子命令仍由各应用决定。单独查询原生帮助或版本时，
不会启动采集或请求提权。原生标准输出可以继续用于管道，Apolysis 状态信息写入
标准错误。

| Apolysis 参数 | 用途 |
| --- | --- |
| `--workspace <directory>` | 初始工作目录，默认当前目录。 |
| `--output-dir <parent>` | 新建私有采集目录的父目录。 |
| `--bpf-object <path>` | 显式指定配套的观测器对象。 |
| `--policy <path>` | 应用审计策略。 |
| `--allow-reason-summary` | 显式允许保留有长度限制并经过过滤的声明文本。 |
| `--shell-bridge /bin/bash` | 显式增加内层 shell，用于受支持的 shell 工具归属。 |

默认 shell 标记可能被应用后续的 `eval` 包装隐藏。可选 shell bridge 会在受支持的
exec 边界暴露标记，但引入了内层 shell：其中的工作目录、变量和函数不会传回外层
工具 shell。对于已识别出的禁用 hook、转移到远程、脱离当前进程树或使用共享服务
的参数，入口会明确拒绝，因为当前采集器无法覆盖这些执行方式。

## 查看结果

通过应用原有方式退出后，Apolysis 完成关联并打印报告路径。采集结果默认位于
`$XDG_STATE_HOME/apolysis/captures`；XDG 状态目录未设置或不是绝对路径时，使用
`$HOME/.local/state/apolysis/captures`。每次调用创建独立私有目录，其中的
`evidence/` 包含：

| 文件 | 内容 |
| --- | --- |
| `report.html` / `report.md` | 可读的工具调用、理由、关联操作尝试和覆盖缺口。 |
| `result.json` | 应用退出状态、采集健康状态和结构化报告统计。 |
| `intent.jsonl` / `intent.jsonl.reasons.jsonl` | 工具声明及可选的显式调用理由。 |
| `timeline.jsonl` | 观测事件、运行时元数据及诊断。 |
| `correlation.jsonl` | 精确关联、较弱候选、理由绑定及发现。 |

精确关联只表示在声明的信任边界内建立了标识符关系，不能证明动机、授权或结果。
文件和网络事件描述的是尝试，应用退出码为零也不代表任务成功。搜索、读文件和远程
工具可能只有语义证据。缺少理由时保持未知，事件丢失会明确体现为采集不完整。

原生采集不会将完整提示词、工具结果和 exec 参数列表写入导出证据。自由文本理由
摘要需要显式启用；保留的路径和声明文本仍应作为私有数据处理。

## 验证与限制

Claude Code、Codex、Pi 和 OpenCode 已在显式启用 shell bridge 的配置下通过有界的
真实模型服务与 eBPF 验证。Codex 的非交互测试还显式选择了工作区写入和跳过 hook
信任确认；日常入口不会添加这两个选项。Cursor 已有适配器和参数路径，但真实工具
调用验证仍受不可用的认证阻塞。这些结果不代表所有版本、默认 shell 包装方式或
持续负载均已通过验证。

可选的真实验证脚本会检查实际文件内容、声明到内核事件的关联、采集健康状态、
报告生成和隐私断言：

```bash
scripts/test-live-native-observe.sh --agent claude --require-all
```

它会请求真实模型服务、启动提权采集器，并使用应用自己的非交互模式，生成的证据
保留在 `target/`。其他原生参数可以放在 `--` 后；`--require-all` 将缺少前置条件
视为失败。完整内核事件覆盖、远程执行、恶意 agent 隔离和防篡改证据保证不属于
当前这条路径的能力范围。

## 开发

```bash
make build
make test
make lint
git diff --check
```

`make test` 执行 Rust 回归以及 hook、适配器测试；测试工具使用 Node.js 和 Python。
原生观测控制器本身由 Rust 实现，不依赖 Python。真实 BPF、模型服务、数据库和
Kubernetes 验证需要显式选择。`make clean` 清理 Cargo 构建产物。

源码分为本地采集与关联 crates、独立 Gateway/存储/投影 crates、`ebpf/` 程序、
`hooks/` 适配器、`schemas/` 契约和 `scripts/` 验证脚本。
[架构设计](docs/design.zh-CN.md)说明组件关系，并区分已有基础与待完成能力。

从更新后的 `pre-release` 创建聚焦分支，将 Pull Request 提交回 `pre-release`，
写明验证结果、权限假设、隐私检查和清理说明。集成前要求 CI 与审查通过，再通过
单独的发布 PR 晋升至 `main`。项目工作通过 Pull Request 跟踪。

不要提交凭证、私有采集记录或模型服务原始对话。发现安全问题时，优先使用 GitHub
私密漏洞报告，提供受影响版本及脱敏复现。Apolysis 的保留规则不会改变 agent 应用
自己的对话历史策略。

用户态代码使用 [Apache-2.0](LICENSE)，eBPF 程序使用
[GPL-2.0-only](LICENSES/GPL-2.0-only.txt)。

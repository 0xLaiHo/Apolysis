# 观测原生 Agent 应用

[English](native-observe.md) | [简体中文](native-observe.zh-CN.md)

`apolysis observe --agent` 打开所选应用自己的界面。Apolysis 增加本次运行的临时工具
声明 hook 和独立 eBPF 采集器，在应用退出后生成可读的本地报告。它不替代聊天界面，
也不默认选择 Claude。

这是原生应用入口。原有 [`apolysis chat`](reason-chat.zh-CN.md) 继续作为使用
stream JSON、只开放 Bash 的受控 Claude 实验，不是这里的依赖。

## 启动

需要满足实时 eBPF 前提条件的 Linux、已安装且位于 `PATH` 的受支持应用，以及该应用
已有的 provider 认证。使用普通用户身份构建 CLI 和匹配的 BPF 对象：

```bash
cargo build -p apolysis-cli
make build-ebpf
```

在源码目录中选择一个应用：

```bash
target/debug/apolysis observe --agent claude
target/debug/apolysis observe --agent codex
target/debug/apolysis observe --agent pi
target/debug/apolysis observe --agent opencode
target/debug/apolysis observe --agent cursor
```

以普通用户运行，不要在前面加 `sudo`。CLI 仅通过 sudo 启动采集器；原生应用仍使用
你的身份、环境、终端、认证与正常权限提示。入口不关闭既有工具、MCP、hook、slash
commands 或聊天历史。新增 hook/插件引起的原生信任提示仍由应用处理，Apolysis 不
绕过它。

默认工作目录是当前目录；子进程的 `PWD` 被设为规范化的启动目录，避免继承的 shell
环境值让原生应用误认项目位置。若要使用独立的已有测试目录，增加
`--workspace /absolute/path/to/test-directory`。这不是沙箱，应用保持其正常主机访问能力。

## 原生参数保持原生

Apolysis 的选项放在 `--` 前，之后的内容作为独立参数交给所选应用。参数值不会拼成
shell 命令、被执行解释，或重新当成 Apolysis 的选项。

```bash
# 使用 Claude 原有参数，仍然保留原生界面。
target/debug/apolysis observe --agent claude -- --model sonnet

# 查看本机各应用实际支持的参数。
target/debug/apolysis observe --agent codex -- --help
target/debug/apolysis observe --agent claude -- --help
target/debug/apolysis observe --agent pi -- --help
target/debug/apolysis observe --agent opencode -- --help
target/debug/apolysis observe --agent cursor -- --help
```

单独查看帮助或版本直接透传，不提权、不安装 hook、不进行 eBPF 采集。模型名、
provider 参数、恢复会话 ID、worktree 选项与子命令遵循所选应用自己的语法与校验。
Apolysis 不保证某个产品理解另一个产品的参数，也不保证本机接受的模型名在你的
provider 上可用。提示词或含空格路径按你平时使用 shell 的方式加引号。

原生 JSON/流输出继续写入 stdout；Apolysis 的状态和报告位置写入 stderr。
`--print`、`exec`、`run`、`--json` 等原生模式由你显式选择，不由观测器悄悄添加。

| Apolysis 选项，放在 `--` 前 | 含义 |
| --- | --- |
| `--agent codex\|claude\|pi\|opencode\|cursor` | 必须显式选择应用，没有默认值。 |
| `--workspace <目录>` | 初始启动目录，默认当前目录。 |
| `--output-dir <父目录>` | 本次私有采集目录的父目录。 |
| `--bpf-object <路径>` | 自动查找不适用时，指定匹配的观测对象。 |
| `--policy <路径>` | 可选审计策略。 |
| `--allow-reason-summary` | 对实际提供的原因或描述显式保留有界、过滤后的正文。 |
| `--shell-bridge /bin/bash` | 显式启用已有受支持的内层 shell 标记桥接。 |

Codex 的 `-C`、Cursor 的 `--workspace` 等目录参数仍作为原生参数传入。已知目录
选项也会在可行时用于解析观测元数据；动态 worktree 或恢复会话选择的目录可能与
初始目录不同，报告会保留这类覆盖说明。

## 各产品的接入方式

| 选择值 | 可执行程序 | 临时接入 |
| --- | --- | --- |
| `claude` | `claude` | 增加包含 `PreToolUse` 的运行时插件，仍加载既有设置与插件。 |
| `codex` | `codex` | 会话配置层增加 `PreToolUse`、启用 hooks，并使用 `--no-daemon` 将本地执行留在本次进程树。 |
| `pi` | `pi` | 通过原生扩展参数加载仓库中的 tool-call 扩展。 |
| `opencode` | `opencode` | 将仓库中的 tool-execution 插件追加到已有的内存配置 `OPENCODE_CONFIG_CONTENT`。 |
| `cursor` | `cursor-agent` | 增加包含 `preToolUse` 与 `beforeShellExecution` 的运行时插件。 |

原始参数 token 顺序保持不变，不覆盖既有用户或项目配置。临时文件保存 hook/插件
配置，不复制认证或原生调用参数。其他 hook 和原生策略仍可能拒绝或修改 Tool Call；
插件成功加载不证明每次调用都被记录。

已识别的冲突模式会明确拒绝，例如 Claude 的 bare/safe/cloud/desktop 和后台模式、
Codex 远程模式或竞争的会话 hook/daemon 覆盖，以及 OpenCode 的 pure/attach 模式。
不能为了让测试通过而静默删除这些选项。远程、共享服务和脱离本地前台进程树的执行
需要不同 Evidence Source；此入口不将其内核活动冒充为本地已采集。某产品版本若
没有所需的运行时插件或配置选项，不能因为适配器存在就被视为通过资格验证。

## 用日常对话测试

在原生应用中输入自己的请求，例如：

```text
帮我查一下旧金山现在的天气。
```

应用可以正常选择网页搜索或 MCP。这些调用常为 `semantic_only`；观测器不能给
远程工具补造精确本地系统调用关系。Codex 托管 WebSearch 不经过本地 `PreToolUse`，
属于单独的声明覆盖缺口。

测试本地执行时，可以让应用用 shell 工具创建一个小文件并读回。默认仅注释标记的
模式不增加工具 shell，但产品后续的 `eval` 包装可能使标记无法被 exec 捕获。如果
本次要测试已有显式桥接模式，在启动前选择：

```bash
target/debug/apolysis observe --agent claude --shell-bridge /bin/bash
```

这保留原生界面，但为受支持的 shell Tool Call 增加内层 shell；cwd、变量和函数
变化不会回传应用外层 shell。精确归属仍要求改写被实际接受、标记被实际观测；选择
bridge 本身不构成证据。

入口不注入生成理由的提示。普通原生描述仍为 `tool_description`、代码为 `unknown`；
缺失理由保持未知。此前实验的受控 `agent_declared` 协议不会被暗中应用到普通会话。
见 [Harness 意图](harness-intent.zh-CN.md)。

## 看报告

通过应用自己的退出方式正常结束，再让 Apolysis 完成关联。报告位置写入 stderr。
默认输出位于 `$XDG_STATE_HOME/apolysis/captures`，未设置 XDG 状态目录或其不是绝对
路径时使用 `$HOME/.local/state/apolysis/captures`。每次启动创建新的私有目录，下面
的文件位于其中的 `evidence/` 子目录；不要混合不同采集。

| 文件 | 用途 |
| --- | --- |
| `report.html` | 离线、独立、按调用组织的报告，可在浏览器打开。 |
| `report.md` | 包含相同主要结论的 Markdown。 |
| `result.json` | 结构化应用状态、采集健康、调用汇总和诊断。 |
| `intent.jsonl` | 原始工具声明。 |
| `intent.jsonl.reasons.jsonl` | 原因代码及显式允许保留的摘要。 |
| `timeline.jsonl` | 默认不保留内容的观测事件、元数据和诊断。 |
| `correlation.jsonl` | Exact Relation、较弱候选、原因绑定与 Findings。 |

每次 Tool Call 展示声明理由或未知状态、观测模式、精确关联的事件计数，以及可用
raw event ID 核对的有限样例。网络与凭证路径尝试保持可见，不埋在大量动态库文件
打开记录中。原始事件与规范化副本不重复计数。未归属证据、歧义候选、标识符冲突
以及审计策略提醒，与精确调用归属分开呈现。

应用退出、采集完成和任务结果是不同字段。报告将任务结果保持为 `not_verified`：
进程成功退出或 connect 尝试不证明天气响应或其他声称的结果。丢失与截断分别显示；
`complete` 不承诺完整 syscall 覆盖。缺失、格式错误、混入其他会话、过期关联或过大
输入会明确令报告不完整；每个源制品的渲染读取上限为 64 MiB。

受控原生采集在加载时使用有界的 **8 MiB** ring-buffer 容量覆盖，以容纳产品启动与
hook 的突发事件。eBPF 事件 ABI、构建对象默认值、旧观测入口与 daemon 默认值不变。
这不保证不会丢失事件：丢失计数非零仍将采集标为不完整，截断也继续显示。

默认审计策略避免将仓库目录允许列表套到无关的原生工作目录。凭证路径规则仍可见，
但路径命中不证明读到了秘密或发生泄露。仅审计的策略提醒不能呈现为已阻止操作。

## 保留内容和验证边界

Apolysis 不持久化提示词、完整命令参数、工具结果或原始 provider stdout/stderr。
原生应用的历史和既有 hook 仍维持原行为；这个承诺不会重配它们。声明摘要、标识符
和观测路径仍属于保留数据。报告会转义不可信文本，不加载外部资源，但本地用户
拥有的导出不是防篡改证据存储。

参数构造、报告渲染与本地进程控制测试，不同于真实产品/provider/eBPF 资格验证。
缺少认证、provider 连接失败、跳过实时门禁和不支持的产品版本都不能报告为通过。
此前脚本结果，以及独立的当前原生入口通过项与缺口，均记录在[实时验证报告](harness-intent-live-validation.zh-CN.md)中；
历史结果不会自动使这条原生启动路径通过资格验证。当前范围与禁止扩大声明的条件仍由
[设计](design.zh-CN.md)和[路线图](roadmap.zh-CN.md)定义。

`make test-native-observe` 运行不调用 provider 的 Rust 回归。[原生入口验证](harness-intent-live-validation.zh-CN.md#原生入口验证)
单独记录真实 TUI 检查，以及显式 provider/eBPF 门禁的复现命令。

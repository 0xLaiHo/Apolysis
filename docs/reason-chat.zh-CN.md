# 用日常对话测试声明原因

[English](reason-chat.md) | [简体中文](reason-chat.zh-CN.md)

Rust `apolysis chat` 命令允许你在同一个 Claude 会话中
输入自己的自然语言任务和后续要求，同时由 Apolysis 使用真实 eBPF 观测本地执行。
交互模式没有固定任务。每次运行创建独立工作目录，不把当前项目作为任务目录。

这是面向 Claude Code 的实验性观测入口，使用受控原因声明协议和显式 shell bridge，
不代表产品默认具有原生原因能力，也不是针对恶意 agent 的安全沙箱。

## 启动

需要具备实时 BPF 前提条件的 Linux、可用的 Claude Code CLI 与既有 provider 认证、
Bubblewrap，以及来自同一源码构建的 CLI/BPF 对象。对话运行时不依赖 Python，入口会实际调用
provider，可能产生费用。在普通用户终端进入仓库，不使用 sudo 构建，然后显式提权
启动观测：

```bash
cargo build -p apolysis-cli
make build-ebpf
sudo --preserve-env=PATH,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy \
  target/debug/apolysis chat
```

如果当前配置还依赖 provider 认证环境变量，也只按变量名保留，不把值写入命令或
文件。入口要求非 root 的原始调用用户，恢复该用户的真实 home，并以该用户身份运行
受管产品。临时配置和挂载遮蔽不修改现有全局 hook、指令或 shell profile。缺少构建
产物或实时前提条件会报错，不会计为演示成功。

终端会显示 `target/reason-chat-rust-*` 下新建的 `workspace` 和 `evidence` 目录。
每行输入一条消息，等回复后再输入下一轮。例如分三轮输入：

```text
请在当前目录创建 greeting.txt，内容为 hello apolysis，然后告诉我完成了什么。
请读取刚才创建的文件，统计其中的单词数量，并用中文告诉我结果。
谢谢。请只用一句话回复，不要调用工具。
```

这些只是示例，不是必须执行的命令。你可以输入不同任务，也可以引用前面的对话。
只开放 Bash；纯聊天不需要工具。模型自行选择命令，并撰写每次调用的声明原因。

- `/exit` 或 Ctrl+D 正常结束对话。
- Ctrl+C 结束整个会话，不是只取消当前一轮。
- `--turn-timeout 300` 将单轮超时从默认的 180 秒改为 300 秒，允许范围为 1–3,600 秒。

可选路径参数包括 `--output-dir <parent>`（默认 `target`）、`--policy <path>`
（默认 `policies/local-dev.yaml`）及 `--bpf-object <path>`（默认
`target/ebpf/apolysis_observer.bpf.o`），相对路径以启动命令时的目录为准。输出参数
指定新运行目录的父目录，不是让 agent 操作已有项目。CLI 与 BPF 构建必须匹配。
`apolysis chat --help` 不调用 provider，也不要求 sudo。内部 `hook`、`launch`、
`publish` 助手不需要手动执行。

每次工具调用使用新的 `/bin/bash`。文件会保留，但 shell 的目录、变量和函数变化
不会传回产品的外层 shell；需要切换目录时，应在同一条命令里完成。对话上下文只在
当前进程内存中保留：启用 `--no-session-persistence` 后，退出便不能恢复会话。

## 查看观测

每轮回复后，入口显示该轮新声明调用的 `intent_id`、声明原因及当前准确关联的事件
数量。没有工具调用时会明确说明，不补造意图或原因。计数表示归属于该调用的观测
事件数，不是成功完成的任务数。准确关联标识已观测的尝试；是否成功仍须由实际文件
内容、测试结果或其他结果证据确认。

模型在原生 `Bash.description` 中提供 `APOLYSIS_REASON_JSON=` 加严格 JSON 对象。
适配器将其中的 `reason_code` 和 `reason_summary` 交给既有 hook，保留真实原生
会话与调用 ID。无效声明会被拒绝。此入口明确开启 `--allow-reason-summary` 和
`--shell-bridge /bin/bash`，不从命令推断原因，也不补填原因。摘要仍是模型未经验证
的声明，不是内部思考或授权依据。

既有隐私过滤器可能把自由文本摘要替换成 `[redacted]`。这不使原因代码或意图 ID
关联失效：界面可以显示代码并标注“摘要已脱敏”。准确执行关联不要求摘要可读，也
不应恢复已脱敏文本或悄悄补造解释。

退出时查看终端显示的采集状态，以及 `evidence/result.json`：

| 字段 | 含义 |
| --- | --- |
| `controller_runtime` | 值为 `rust`，标识本次运行采用的对话实现。 |
| `conversation_status` | 对话正常结束，还是中断或失败。 |
| `capture_status` | 最终采集检查是否通过，包括匹配且非空的 summary 与原生进程成功退出。 |
| `correlation_status` | 最终关联是否完成。 |
| `smoke_status` | 交互模式为 `not_requested`；独立 smoke 断言结果为 `passed` 或 `failed`。 |
| `turns` | 已完成的轮次编号和工具调用数，不含提示词正文。 |
| `kernel_events`、`loss_or_failure_count`、`truncations` | 观测事件总数及保留的诊断计数。 |

这些状态相互独立。强制停止、缺少最终记录或单轮失败，不能被表述为完整成功运行。
即使采集检查通过，截断仍会显示；检查通过不证明完整 syscall 覆盖。关联数为零也
不证明没有发生操作。

## 哪些内容保留在磁盘

运行结束后保留两个目录，供你检查：

| 位置 | 保留内容 |
| --- | --- |
| `workspace/` | 为任务创建或修改的文件，包括文件内容。 |
| `evidence/intent.jsonl` | 工具调用声明和身份元数据。 |
| `evidence/intent.jsonl.reasons.jsonl` | 声明代码及显式启用的摘要。 |
| `evidence/timeline.jsonl` | 默认不保留内容的内核/规范化事件与观测器诊断。 |
| `evidence/correlation.jsonl` | 准确关联、候选、原因绑定及诊断。 |
| `evidence/result.json` | 最终对话、采集与关联状态。 |

提示词、完整工具参数和原始 provider stdout/stderr 不写入日志；助手文本会显示在
终端。声明摘要、标识符、观测路径与生成的任务文件**仍是保留数据**；观测记录默认
不保留内容，不代表整个目录不含内容。尽力脱敏不保证匿名。终端录制与 provider
自身的数据处理不属于这条本地持久化规则的保证范围。

生成的运行目录为私有目录；默认的 `target/` 位置被 Git 忽略。若选择其他输出父目录，
须自行确保采集数据不进入版本控制。root 观测器只在 root 拥有的私有临时目录中写入
采集源文件。新启动的降权 Rust 助手将时间线快照、关联与最终结果原子发布到用户
拥有的证据目录；root 不会为发布而重新打开这些可变输出路径。认证助手同样以原始
调用用户身份运行，只将需要的既有配置读入子进程环境，不把凭证写入文件。

控制文件和私有采集文件是临时的；任务目录与已发布证据在退出或失败后仍保留。不再
需要时，只删除终端打印的本次运行目录。入口不修改全局产品配置，也不使用 Kubernetes。

挂载设置将主机设为只读，允许写入临时控制目录、任务目录和证据目录。只读挂载不
阻止读取主机文件或网络访问，agent 也能访问可写证据。因此它既不提供恶意 agent
隔离，也不提供防篡改记录。请使用不敏感的任务进行这个实验。

## 验证边界

`--smoke` 通过真实 provider 执行三轮：创建问候文件、读取并统计单词，再进行无工具
聊天。在上面的相同 sudo 环境下添加 `--smoke` 即可运行。该回归要求使用常规 shell
命令，以便验证 Rust 对话链路不需要 Python 解释器。`make test-reason-chat` 执行
Rust 单元测试及 CLI 集成回归，不调用 provider：

```bash
cargo test -p apolysis-cli chat:: --bin apolysis
cargo test -p apolysis-cli --test chat
```

2026-11-05，Rust 运行时在 Claude Code 2.1.295、x86_64 Linux
6.18.55-2-cachyos-lts 上通过了两条路径：

| Rust 运行 | 内核事件 | 截断 | 实际结果 |
| --- | --- | --- | --- |
| 带外层执行跟踪的三轮 `--smoke` | 3,752 | 16 | 同一原生会话两次调用分别有 67、66 条准确关联，第三轮没有调用工具。 |
| 手动终端输入，再 `/exit` | 3,631 | 17 | 用户要求创建并读回便条文件，两次调用分别有 35、66 条准确关联，随后正常退出。 |

两次运行均为零丢失/失败，`controller_runtime=rust`，采集与关联 complete，对话
finished。三轮运行的 smoke 状态为 `passed`，手动运行则为 `not_requested`。
手动运行的第一条摘要被脱敏，第二条保留了模型声明“读回文件内容以确认写入正确”，
两次准确关联均保持有效。采集完整表示正常退出并通过计数和诊断检查，不代表没有
截断或完整 syscall 覆盖。

本地验证通过：38 项 chat 单元测试、4 项 CLI 集成测试；全仓 Rust 测试为 583 passed、
91 ignored、无失败。这些是 Rust 的实际结果，没有沿用旧 Python 对话脚本的通过
结论。保留的 `test-live-reason-products.py` 与
`test-live-reason-summary.py` 是独立的显式验证工具，不是 `apolysis chat` 的依赖；
其历史结果仍记录在[实时验证](harness-intent-live-validation.zh-CN.md)中。

### 可选的执行跟踪门禁

[`test-live-reason-chat.sh`](../scripts/test-live-reason-chat.sh)（也可通过
`make test-live-reason-chat` 调用）只在外层可执行文件跟踪器下重跑固定三轮 smoke，
覆盖观测器受管 agent 范围之外的控制器 publish/correlate 助手。它要求完整的 Rust
smoke 报告、有效的文件名/计数证据，以及未观测到 Python 可执行文件。这是对该次
运行的证据，不是针对改名或恶意代码的证明。

构建后，在相同的显式 sudo 环境下运行：

```bash
sudo --preserve-env=PATH,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy \
  ./scripts/test-live-reason-chat.sh --require-all
```

门禁优先使用指定的 `APOLYSIS_STRACE`，否则使用系统 `strace`；没有 strace 时退到
`bpftrace`。若使用另行验证的临时二进制而不全局安装，可在上面命令的脚本路径前
插入 `env APOLYSIS_STRACE=/absolute/path/to/verified/strace`。此外还需 `jq`、
`setpriv`、`timeout`、`realpath`，strace 后端还需 `gawk`。这些都是可选验证依赖，
不是 `apolysis chat` 的运行要求。`--require-all` 让缺少前提条件变为失败，不能把
跳过计为成功。

只将可执行文件名及尝试计数导出为 `evidence/executable-counts.json`，由原始调用
用户身份原子发布。计数包括 PATH 搜索失败的尝试，不等于成功执行次数。文件名仍
属于保留数据。strace 后端会为这个固定合成工作负载临时
记录 argv，文件位于 root 私有目录，不展开环境变量值，退出时删除原始跟踪。
不要将这个门禁用于录制日常私密对话。它不修改全局产品配置或 Kubernetes 状态。

本机 bpftrace 尝试因其内部 ELF 处理错误失败，不能作为通过证据。最终外层跟踪
门禁使用已验证签名的临时 strace 二进制通过，无需全局安装。它观测到 **18 次
`apolysis` exec 尝试**，包括受管 agent 范围之外的助手，**没有 Python exec 尝试**。
其 Rust smoke 结果对应上表的 3,752 条事件。原始跟踪在退出时已删除，只保留文件名/
计数制品及普通对话证据。

即使有界运行通过，也不证明任意任务、产品版本、内核或负载均已通过资格验证。
这个 Claude 专用实验不决定其他应用当前的原生入口资格；见注明日期的
[实时验证](harness-intent-live-validation.zh-CN.md)、
[设计](design.zh-CN.md)和[路线图](roadmap.zh-CN.md)。

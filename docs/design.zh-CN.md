# Apolysis 设计

[English](design.md) | [简体中文](design.zh-CN.md)

本文是当前源码树唯一受版本控制的设计概览。[领域词汇表](../CONTEXT.md)定义产品术语。
[路线图](roadmap.zh-CN.md)负责方向与资格边界；实现历史保留在 Git 中。

## 证据边界

Apolysis 当前提供实验性的本地 Linux 审计遥测与问责。CLI 与 daemon 采集限定范围的
Execution Evidence，结合运行时元数据及声明的 Tool Call，输出默认不保留内容的 JSONL
记录和 Finding。当前实现的文件与网络 tracepoint 在没有独立结果信息时只描述尝试。
观测到调用不代表 Verified Outcome。

Semantic Evidence 表示工具运行器声明了什么；Execution Evidence 表示受控运行时边界
观测到了什么；Outcome Evidence 独立检查声称的外部结果。三种边界保持分离：关联成功、
哈希链或没有 Finding 均不代表覆盖完整或已经实现隔离。

本分支也包含[契约集](contracts/README.md)描述的独立生产 record/Gateway 契约与
存储、传输基础。依照 [ADR-0001](adr/0001-independent-production-contracts.md)，
旧版 JSONL v1 是边缘格式，不是带认证的 Gateway 或 Query 契约。Gateway、
evidence-object、projection 和 transport 的已有限制继续以各自规范契约为准；本地
harness 适配不代表这些部分通过资格验证。

## Harness 声明

文件摄入接受 Codex、Claude Code、Cursor、Pi 和 OpenCode 导出数据。产品实时 hook
将 Tool Call 归一为相同的 `intent` 记录。原生 hook 接口仍有产品差异；支持的输入与
安装方式见 [Harness 接入](harness-intent.zh-CN.md)。

记录把 Apolysis `session_id` 与 `harness_session_id` 分开。显式指定的采集会话必须
与观测器一致。实时 ID 是 32 位小写十六进制值，由带长度边界的来源、采集会话、
原生会话和调用 ID 经 SHA-256 派生；历史导入 ID 保持兼容。实时写入使用带锁追加，
并去重重试，同一次调用不能抹掉此前的声明。
去重比较除摄入时间外的完整持久化记录，不比较已丢弃的参数内容。若复用调用 ID 且
差异仅在已丢弃参数中，系统无法区分，也不会保留命令指纹。

默认 shell 改写在原命令正文前加入 `# APOLYSIS_INTENT_ID=<id>` 注释行，保留其他工具
输入字段。Claude Code 保留原生许可决定；Codex 仅在受支持的 shell 改写时收到契约
要求的 `allow` 确认。Cursor 的补充 shell 事件可以复用已有标记；缺少调用
ID 时不能生成共享占位值。Pi 从扩展上下文获取原生会话；OpenCode 从工具执行事件
获取原生会话和调用 ID。

产品随后可能把改写后的命令嵌入 `eval` 或其他 shell 包装，因此默认注释未必位于
实际 exec 参数开头。Claude Code 2.1.295 原生运行暴露了这一边界：声明与原因均已
记录，但 fixture 文件尝试没有内核标记。采集器不会通过搜索嵌套注释来补齐它。

显式 `--shell-bridge /bin/bash` 则让原命令正文进入选定的受支持 shell，使其命令
参数以严格意图头开头。它不会用 `exec` 替换产品外层 shell。输出和退出状态来自内层
命令，但 cwd、环境和函数的改动不会回传到外层 shell。该模式默认关闭，不能描述为
透明保留原生 shell 语义。Pi/OpenCode 的等价配置为 `APOLYSIS_SHELL_BRIDGE`；
选定 shell 必须与显式工具输入中的 shell 一致。资格验证必须说明测试的是该模式
还是默认注释模式。

`observation_mode` 区分已准备的 `local_shell` 路径、`semantic_only` 声明与
`historical` 导入。准备好标记不代表命令已经执行、产品采用了改写或观测器采集到了
标记。

## 原生应用入口

Rust `apolysis observe --agent <product> -- <原生参数>` 入口要求显式选择 Codex、
Claude Code、Pi、OpenCode 或 Cursor Agent。终端、标准输入输出、认证、配置、工具、
MCP 服务与权限流程仍由原生应用管理。`--` 后的参数作为不变的参数数组交给应用；
Apolysis 只增加对应产品的临时 hook 或插件配置。禁用 hook 或把执行移到当前采集树
之外的冲突模式会明确拒绝，不会悄悄改写。单独查看帮助和版本不提权、不采集。

原生子进程的 cwd 与 `PWD` 使用一致的规范化启动目录；产品自己的目录/worktree
参数保留原生语义。普通用户控制器负责原生启动、临时 hook 配置、关联和报告发布。独立的 sudo 采集器
通过私有控制通道接收请求，在 root 私有临时目录写入源采集数据。应用参数和提示词
不会进入 sudo 命令行元数据或持久化的启动清单。仅采集器提权；Apolysis 的提示写入
stderr，原生 stdout 保持可供管道使用。默认观测策略不设置目录或网络允许列表，
保留审计模式的凭证路径诊断。指定策略也不会将此观测入口变为隔离边界。

受控原生采集加载器将 ring-buffer 容量覆盖为 8 MiB，以容纳启动/hook 突发事件，
不改变事件 ABI、对象默认值及旧观测入口/daemon 默认值；采集丢失仍是明确失败。

原生应用退出后，默认不保留内容的 JSONL 继续作为底层证据；`result.json`、
`report.md` 和独立 `report.html` 按 Tool Call 提供可读视图。报告检查原始与规范化
事件身份、唯一意图、既有关联结果和有效原因绑定，才计入 Exact Relation。只有语义
的调用、候选、冲突、未归属证据与策略提醒分别呈现。应用退出、采集健康和 Outcome
Coverage 相互独立：退出码为零且采集检查通过，也仍将任务结果标为未验证。截断与
丢失分别显示。格式错误、混入其他会话、缺失或过大的报告输入会明确标为不完整。
渲染器每个源制品最多读取 64 MiB，不把完整 argv、提示词、工具结果或 provider 流
复制进报告。

入口不向原生会话注入生成理由的提示。普通工具描述仍为 `tool_description`/`unknown`；
保留摘要与启用 shell bridge 都需要单独选择。默认仅注释标记的模式保留既有 shell
边界，但不能修复产品后续 `eval` 包装导致的标记不可见。原有全局 hook 仍生效，
可能修改或阻止新 hook。原生应用可能保存自己的对话；Apolysis 的 content-off 规则
不重配这些历史设置。用户拥有的导出证据不防篡改。参数、产品差异、执行限制和报告
解读见[原生观测指南](native-observe.zh-CN.md)。

## 声明原因

可选的 `intent_reason` 记录描述生产者为一次 Tool Call 声明的目的。它独立于 `intent`，
通过同一采集会话与意图 ID 引用调用，并保留原生来源身份用于校验。它不揭示模型内部
思考，不验证动机，不授予操作权限，也不产生 Execution Evidence。意图 ID 派生与
内核标记传递保持不变。

显式声明使用封闭的原因代码。受控扩展可提供顶层 `apolysis_reason` 对象；内置 shell
工具则可在已有命令字符串开头携带 `# APOLYSIS_REASON_CODE=<code>` 注释。Hook
仍将意图标记放在第一行。原生工具描述保留为 `tool_description`，代码为 `unknown`，
不根据描述措辞推断 Agent 为什么执行。Schema 保留 `operator_annotation`，当前 CLI
不会生成该来源。

另一项实时验证在 Claude 原生 `Bash.description` 中使用仅供测试的
`APOLYSIS_REASON_JSON` 协议。模型自行选择代码、撰写摘要，严格适配器将这些字段
原封传入 `apolysis_reason`，保留原生会话与调用 ID。显式启用摘要保留及 `/bin/bash`
bridge 后，登录回归实际执行，其文件尝试通过准确的意图 ID 关联附带同一声明摘要。
这验证了受控协议与既有执行链，不代表自动解释普通描述，也不代表五个产品默认具有
原生原因能力。该门禁没有增加生产原因提取逻辑；默认仍不保留摘要。

实验性 Rust [`apolysis chat`](reason-chat.zh-CN.md) 命令把这一显式协议应用到用户在
独立工作目录中输入的任务，运行时不依赖 Python。同一 Claude 进程通过 stream-JSON
接收多轮输入，关闭会话落盘，只开放
Bash。每次真实调用经既有 hook 处理，显式开启摘要保留与 `/bin/bash` bridge；纯
聊天轮次不产生意图。入口显示助手文本与每次调用的准确关联计数，保留任务文件和
默认不保留内容的观测记录。提示词、完整工具输入和原始 provider 输出不写入日志；
声明摘要和观测路径仍属于保留数据。隐私过滤后的 `[redacted]` 摘要不使有效的原因
代码或意图 ID 关联失效。这是观测实验：主机只读挂载，但控制目录、任务
目录和证据目录可写，不构成针对恶意 agent 的隔离边界，也不提供防篡改证据，不修改
全局配置。

root 控制器监督独立的 root 观测器，将采集源文件保存在仅 root 可访问的临时目录。
认证仅由降权后的 Rust 启动助手读取，然后执行 Bubblewrap。快照与最终结果由以原始
调用用户身份启动的新助手进程原子发布，root 不会为发布而重新打开 agent 可控制的
证据路径。`hook`、`launch`、`publish` 是内部助手子命令，不是日常入口。独立 Python
实时验证门禁仍是测试工具；对话执行链不调用它们。

原因记录独立追加、去重重试，并诊断冲突身份。修正使用新原因 ID，通过
`supersedes_reason_id` 指向同一次调用已有的原因，不覆盖历史。关联步骤单独输出
`intent_reason_binding`，只有存在唯一有效原因时才补充 Exact Relation。冲突和未绑定原因
不能建立运行时链接，也不能提升弱候选。`semantic_only` 原因可以只绑定声明，不产生
执行关系。

默认记录保留代码与可选的不透明引用，不保留原因正文。`--allow-reason-summary`
显式允许最多 240 个 Unicode 字符、尽力脱敏的摘要；这不保证任意文本均不含秘密。
`task_ref` 是由 1–64 个 ASCII 字母、数字、下划线或连字符组成的不透明引用，不是任务
内容或待打开的文件。系统不会为
构造原因而读取提示词文件。输入与字段见 [Harness 接入](harness-intent.zh-CN.md)和
[JSONL 契约](jsonl-schema-v1.md)。

## 进程归属与关系

实时采集器把已识别 shell 命令参数中的完整前导注释读入独立的 32 字节字段，不搜索
任意 argv token，也不依赖会截断的诊断命令 payload。识别仅覆盖受支持的 shell 调用
形式，缺失的标记保持缺失。

内核上下文通过 TGID 加线程组首线程启动时间排除已复用的进程标识，在 fork 时传播，即使
子进程不 exec 也能继承。同进程 exec 只有在完整采集确认没有新标记时才保留原值；
合法新标记替换旧值。缺失 pending capture、不可读或格式错误的标记，以及无法确定
shell 命令参数位置时清除旧值，报告 `intent_capture_incomplete:true` 并沿用截断告警。
最后一个线程退出时清理上下文。每个范围内事件都携带内核当前归属，包括其缺失状态；用户态
不会从过期缓存重建缺失的实时标记。这减少了对生命周期事件送达顺序的依赖，但不能
恢复丢失事件、未观测到的进程关系或不受支持的执行后端。

关联仍是同一采集会话内的独立步骤。唯一的显式 `intent_id` 或 `raw_event_id` 链接
在声明的信任边界内建立 Exact Relation。两者同时存在时必须一致。未知、冲突或存在
歧义的标识符产生诊断，不允许回退到更弱匹配。一条声明可关联多次尝试。

旧版命令相等与仅限 exec 的可执行文件名匹配产生候选记录：单个候选是 Inferred
Relation，多个是 Ambiguous Relation。两者都不计为 Exact Relation，也不抑制 Finding。
`semantic_only` 声明不参与执行匹配，不产生 `unobserved_intent`。历史导入保持可读，
可使用显式链接，但仅有弱候选不代表已匹配。

## 隐私与信任

意图持久化保留定宽传递 ID、原生来源标识符、工具元数据和白名单中的可执行文件引用。
原生标识符不受传递 ID 的 32 字符限制。不持久化提示词、
结果、原始参数、raw argv 或重建后的进程命令文本。产品需要执行命令，因此 hook
会瞬时接触原命令。[JSONL 契约](jsonl-schema-v1.md)说明持久化字段。

标记是在协作式本地集成范围内使用的关联键，不是签名、授权令牌，也不能抵御能控制
自身命令文本的工作负载。本地 JSONL 与 daemon 本地哈希链不提供独立证据锚定。
远程工具和 provider 托管搜索需要自己的 Evidence Source；本地观测器无法确认它们
的结果。

## 验证范围

Fixture 测试可验证 hook 契约、追加与去重、标记语法，以及默认不保留内容的持久化。
产品版本兼容性、实际标记送达、进程树传递和内核事件覆盖需要 fixture 以外的独立集成
证据。内核/用户态事件 ABI 是 648 字节，需要来自同一次构建的 CLI 与 BPF 对象；
历史 JSONL 可读不代表兼容旧 BPF 对象。
显式启用的 `make test-bpf-relocation` 门禁把所有已构建观测器程序的 CO-RE relocation
应用到可读的主机 BTF，不加载 BPF 程序。原生回归测试执行共享 C 标记解析器与有界
shell basename 判断。这些检查不能替代内核验证器接受和实时事件断言。

有界合成标记门禁与通用实时观测器回归已在一个本地内核上通过；
[验证详情](harness-intent-live-validation.zh-CN.md)记录环境、断言、诊断和边界。
原生产品资格仅限已测模式：Claude Code 2.1.295、Pi 1.5.0 和 OpenCode 1.18.31 已在
显式 `/bin/bash` bridge 下通过单条合成命令检查，将声明原因关联到准确的 fixture
文件尝试，且持久化记录不含提示词专用 sentinel。较新的原生入口另有 Claude、Pi、
Codex 与 OpenCode 有界通过结果；Codex 显式选择了测试用 sandbox/hook-trust 参数，
OpenCode 显式选择了可用模型。Codex provider 通路在该配置下现已可用；Cursor
仍需要可用认证。缺少前提条件不算通过，也不能据此断定产品本身不受支持。默认注释
送达、更广的产品版本、其他内核与压力/丢失资格仍待验证。特权验证继续显式执行，
缺少前提条件而跳过的运行不能计为实时验证成功。

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

Shell 改写在原命令正文前加入 `# APOLYSIS_INTENT_ID=<id>` 注释行，保留其他工具
输入字段。Claude Code 保留原生许可决定；Codex 仅在受支持的 shell 改写时收到契约
要求的 `allow` 确认。Cursor 的补充 shell 事件可以复用已有标记；缺少调用
ID 时不能生成共享占位值。Pi 从扩展上下文获取原生会话；OpenCode 从工具执行事件
获取原生会话和调用 ID。

`observation_mode` 区分已准备的 `local_shell` 路径、`semantic_only` 声明与
`historical` 导入。准备好标记不代表命令已经执行、产品采用了改写或观测器采集到了
标记。

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
特权实时验证必须显式执行；未执行或跳过的实时测试不能表述为资格验证成功。

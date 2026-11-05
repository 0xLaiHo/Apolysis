# Apolysis 路线图

[English](roadmap.md) | [简体中文](roadmap.zh-CN.md)

本文是当前源码树唯一受版本控制的方向与资格边界，不是阶段日志。
[设计](design.zh-CN.md)说明当前行为；完成历史和验证记录保留在 Git 与对应 Pull Request。

## 产品方向

已有 production MVP 方向继续是 Agent Runtime Evidence & Policy Plane：版本化
Agent Execution Record、带认证的证据摄入、耐久存储、分离的 semantic/execution/outcome
coverage、Minimum Console v0，以及后续 Investigation Console v1 和受控伙伴 pilot。
[契约集](contracts/README.md)负责冻结接口及资格缺口。本地 harness 工作属于边缘集成，
不代表 Gateway、存储、Query 或 Console 已完成。

## 当前 Harness 集成

当前切片建立五个产品的默认不保留内容的声明、追加与去重、分离的采集和原生会话标识、
安全确定性的 ID，以及保留工具输入和原生审批语义的 shell 注释改写。独立内核标记和
进程代际检查跨 fork/exec 传递归属。关联判定区分明确标识符关系、冲突，以及推断或
歧义候选；只有语义的声明不暗示应有本地执行证据。下一步边界是明确产品版本的 hook
资格验证，以及丢失、不受支持的执行形式和较长运行工作负载下的特权内核资格验证。
Fixture 与本地构建不能关闭这些门禁。

资格验证需要覆盖实际产品适配脚本及 Rust 归一化入口。内核 fixture 与特权 Linux
运行是不同证据，两者都不能替代针对明确产品版本的 hook 集成运行。

## 延后范围

- 远程和 provider 托管操作需要额外 Evidence Source；语义声明本身不能确认执行或结果。
- 非 shell 工具、共享长驻工作进程和任意异步委派，需要明确的操作级上下文，不能依赖
  宽泛继承的进程标签。
- 经过密码学认证的关联键、抵御恶意工作负载、独立锚定和完整 syscall 覆盖属于独立工作。
- 生产 admission、更广的恢复与容量验证、授权 Query/object 读取、Console 视图和
  伙伴部署批准，继续受已有规范契约约束。

## 禁止扩大声明的条件

存在以下任一情况时，不得将此切片描述为已通过生产资格验证或完整的 Tool Call 到
syscall 映射：

- Hook 错误、缺失 ID、重复或冲突声明、采集会话不一致被隐藏，或被静默视为成功采集。
- 改写丢失其他工具字段、改变 shell 控制流语法，或授予并未要求该集成授予的许可。
- 缺失进程关系、标记截断、事件丢失或过期进程标识被静默当成明确关联。
- 可执行文件名猜测被报告为明确关联，或标识符冲突被更弱的回退掩盖。
- 只有语义或历史数据的可见性被表述为已验证结果。
- 默认不保留内容的持久化被破坏，或跳过的实时/产品验证被报告为通过。

晋级与发布仍须遵守仓库受保护分支的 review 和验证流程。安装 hook 的说明不会隐式
授权特权主机、Kubernetes 或 provider 操作。

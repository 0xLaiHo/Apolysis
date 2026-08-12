# Apolysis 设计文档

> [English](design.md) | 简体中文
> 最后审查：2026-08-12

本文是唯一的详细产品文档，权威定义 Apolysis 是什么、目标系统如何工作、稳定记录格式与
资格验证约定、当前已经实现什么、未来方向，以及产品声明止步于何处。

## 1. 产品定义与成熟度

Apolysis 是面向用户可控 Linux 环境的实验性 **eBPF 智能体（Agent）运行时观测平台**。它观测有界的
进程、文件、网络和凭证相关操作，把它们组织到一次智能体运行中，归属到运行时身份，
并报告采集器健康和观测缺口。

eBPF 采集器是必需的主要观测源。服务提供方挂钩、智能体日志、协议跟踪和远程导出
都保持暂缓；它们不定义当前产品，也不能替代运行时观测。

当前目标是有界测试版（Beta），而不是生产级证据平面。网关、PostgreSQL、证据对象、
投影与跨服务提供方约定原型已经移出当前工作区。策略执行、智能体反馈控制、
沙箱执行与大范围生产资格验证也已移出当前构建；它们都不是观测端的产品依赖。

### 成熟度标签

| 标签 | 含义 |
| --- | --- |
| 当前已实现 | 当前采集器或本地工作流中已存在，并有文档化限制 |
| 测试版目标 | 活跃 eBPF 观测路线图要求交付，但尚未完成资格验证 |
| 暂缓 | 只有在出现重复用户需求后才可能进入的未来扩展 |
| 范围外 | 不属于产品方向 |

## 2. 用户与决策

主要操作者是在自有 Linux 基础设施上运行智能体的平台团队、运行时安全团队、应用安全
（AppSec）团队或工程团队。首批受支持工作流是本地智能体命令行工具、Linux 自托管 CI
和容器。K1 增加了有界的 Kubernetes containerd/K3s 节点工作流，但不会把尚未完成资格
验证的配置档晋级到实验级（`Experimental`）以上。

对于一次智能体运行，操作者需要回答：

1. 智能体启动了哪些进程？
2. 观测到了哪些受支持的文件、网络和凭证操作？
3. 每条观测属于哪个运行时身份？
4. 受支持操作是成功、失败，还是结果未知？
5. 采集是否健康，哪些活动可能丢失或不受支持？
6. 哪些观测因为跨越已配置的工作区、凭证或网络边界而需要复查？

更多事件数量本身不是产品价值。只有当操作者无需读取内核跟踪或原始存储文件，也不会
被缺失证据误导，就能调查一次真实智能体运行时，产品才成功。

## 3. 领域模型

聚合对象是 **智能体观测记录**：

```text
智能体运行
  |- 观测范围
  |- Kubernetes 工作负载授权声明
  |- Kubernetes 归属
  |- 运行时身份
  |    `- 运行时观测
  |         `- 操作结果
  |- 采集器能力
  |- 采集器健康状态
  |- 观测缺口
  `- 发现项
```

智能体观测记录比此前的智能体执行记录更窄。它不尝试聚合服务提供方意图、多智能体
协议语义、远端结果验证、审批或策略执行。

精确关系（Exact）必须依赖文档化边界内的稳定运行时身份。仅使用时间、命令名、路径或
PID 的匹配属于推断关系（Inferred）。存在多个可能归属对象时，关系为歧义（Ambiguous），
绝不能静默升级为精确关系。

共享词汇如下：

| 术语 | 约定 |
| --- | --- |
| 智能体 | 被观测运行时活动的自主参与者 |
| 智能体运行 | 智能体及其所属进程树为一项声明任务工作的有界时间段 |
| 观测范围 | 属于一次智能体运行的运行时边界 |
| 受保护挂接 | 对已运行智能体的资格化准入；不声明锚定前的历史连续性 |
| 采集边界 | 采集器能力开始适用的位置；更早活动是以缺口表示的未知历史 |
| 运行时身份 | 区分复用与偶然匹配的稳定进程/工作负载身份 |
| Kubernetes 工作负载授权声明 | 操作者为一次智能体运行及其授权声明修订号指定的精确集群、命名空间、Pod 与容器槽位 |
| Kubernetes 归属 | 从精确授权声明和稳定 Pod 候选项，到生效的精确 D1 运行时绑定所形成的、经过资格验证的生命周期关系 |
| 运行时观测 | 在能力与范围内报告的受支持进程、文件、网络和凭证操作 |
| 操作结果 | 在声明来源语义内的 `attempted`、`succeeded`、`failed`、`denied`、`pending` 或 `unknown` |
| 采集器能力 | 某一环境边界的版本化操作/来源/结果声明 |
| 采集器健康状态 | 独立的 `healthy`、`degraded`、`failed` 或 `unknown` 采集器状态 |
| 观测缺口 | 对缺失、丢失、截断、不支持、归属歧义或范围外证据边界的显式记录 |
| 精确／推断／歧义关系 | 稳定身份关系、相关证据支持的关系，或仍有多个合理目标的关系 |
| 未归属观测 | 位于范围内但无法负责任地进一步归属的观测 |
| 发现项 | 从有界观测派生的可复查条件；永远不是执行判定 |
| 已保存运行查看器 | 一份冻结智能体观测记录的本地只读呈现；不是证据来源 |

新接口与文档使用这些术语。旧称“会话”（Session）、“作业”（job）、“租户”（tenant）、
进程名称或裸 PID 不得在公开声明中
替代智能体运行、观测范围或运行时身份。

## 4. 责任与信任边界

| 边界 | 主要归属 | Apolysis 角色 |
| --- | --- | --- |
| 智能体授权与任务意图 | 智能体运行框架或操作者 | 只作为可选描述性元数据 |
| 工作负载隔离 | 主机、容器运行时、Kubernetes 或沙箱 | 观测受支持的运行时活动，不宣称隔离 |
| 运行时观测 | 用户可控 Linux 内核与 Apolysis 采集器 | 采集、限定范围、标准化、脱敏并报告健康状态/缺口 |
| 外部结果 | Git、测试、云平台、SaaS 或远程服务 | 不属于当前产品约定 |

被攻陷的主机 root 或内核可以伪造或省略主机观测。Apolysis 是运行时观测工具，
不是独立的远程证明权威。

特权采集器与非特权操作界面属于不同信任域。查看器永不加载 BPF 程序，
也不接收全主机凭证。

## 5. 目标架构

```text
智能体命令 / 自托管 CI 作业 / 容器 / Pod
                       |
                    观测范围
                       |
                 特权 eBPF 采集器
                  |- 进程生命周期
                  |- 选定文件操作
                  |- 网络连接
                  |- 丢失与健康计数器
                       |
                用户空间解码与身份关联
                       |
                   隐私/脱敏边界
                       |
                   有界本地存储
                       |
                CLI 与已保存运行查看器
```

### 5.1 智能体运行与观测范围

每条观测都属于一个显式运行范围。支持的范围模式包括：

- 从启动前开始观测其进程树的托管智能体命令；
- 仅通过显式智能体注册或自动发现准入的受保护现有进程树；
- 一个容器或工作负载 cgroup；
- 由节点守护进程管理的有界 cgroup 集合。

托管启动是首选本地工作流，因为采集器可以在智能体启动前完成挂接。
受保护的现有进程挂接是封闭的准入面：原始 `--scope-pid` 会被拒绝，根进程必须来自
`--agent-registration` 或 `--agent-discover`。显式注册会对照当前主机启动 ID、根进程
启动时钟滴答、可执行文件、命令指纹与规范工作区边界，在采集器打开根进程 pidfd 时完成
资格校验；根进程的当前工作目录必须解析到该边界或其子目录。匹配成功记录
`root_selection:registration_qualified`：它只限定该
锚点时可见的根进程，不证明从注册创建以来的连续性。自动发现从当前进程状态派生身份材料，
要求存在唯一的最佳候选项，并保持根进程选择结果为 `inferred`。

每个获准加入初始集合的根进程或谱系候选项都必须是存活、非僵尸的线程组主线程。取得快照
后，系统会为每个候选项打开 pidfd，并在写入映射表前后检查其存活状态、谱系以及初始
PID／时间命名空间归属，形成针对每个候选项的 pidfd 双重校验；候选项在写入后退出时由
退出挂钩移除。选定的根进程在激活全过程中继续由 pidfd 锚定。观测器与目标必须共享初始
PID 命名空间，以及同一个未偏移的初始时间命名空间。范围起初处于未激活状态：先挂接
tracepoint，再建立进程树初始集合；先加入注册验证通过或推断得到的根进程，再通过多轮进程树
快照补齐缺失的 TGID，并在激活前后重新核验根进程身份。只有这些步骤全部成功，范围才进入
活跃状态。该流程消除了候选项在锚定后的退出与换代竞态，但不证明锚定前的选择连续性。

激活前的活动属于未知历史。因此每次成功的受保护挂接都必须先持久化
恰好一条 `operation:"collector_lifecycle"`、`count:1` 的 `late_attach` 观测缺口，然后才是
能力清单与 `started` 生命周期记录。这里的计数表示一个“历史未知”的采集边界，
不是对缺失系统调用或事件数量的估计。

不允许默认使用全主机范围。采集器可以为开发提供显式诊断模式，但它不是
受支持的智能体运行配置档。

### 5.2 eBPF 采集器

采集器使用少量、版本化且高信噪比的挂钩。它尽可能在事件产生处过滤，发出固定、有界的
记录，并报告映射表压力、预留失败、截断、解码失败、挂接失败和异常终止。每条记录以 ABI
版本和声明的记录大小开头；用户空间会拒绝不兼容的版本或大小，不会按当前布局勉强解码。

测试版采集器目标为每种受支持操作加入入口与退出配对。记录区分已尝试、成功、失败、拒绝、
待定与未知结果，其传输值分别为 `attempted`、`succeeded`、`failed`、`denied`、`pending`
与 `unknown`；能力声明允许时，还会保留返回值或 errno。

`network_connect` 以及选定的 `file_open`、`file_create`、`file_truncate`、
`file_unlink` 与 `file_rename` 已具备完整结果路径。采集器保存按线程限定的有界入口记录，
并在系统调用退出时发出运行时观测。Linux 返回值映射为成功、失败或拒绝；连接操作还支持
待定结果。无法配对的入口或退出会形成指明具体操作的观测缺口。

在多 cgroup 守护进程模式下，连接与文件配对丢失会按 cgroup 分别计数，同时保留采集器
全局计数器用于健康诊断。排空一个范围时会阻止新的入口，快照其入口缺失、退出缺失与待定
计数；快照前会在有界时间内等待正在执行的采集器更新排空，并在丢弃归属前确认类型化观测
缺口已经持久化到所属智能体运行。已经提交到环形缓冲区的记录会先经过有界排空并确认
持久化。每次范围注册都会获得单调递增的代次；待定配对与发出的记录会保留该代次，因此
已排空范围的陈旧配对无法计入或发送到复用同一数字 cgroup ID 的后续智能体运行。排空、
快照、队列丢弃／削减或存储失败都会停止观测器运行时，并拒绝把该次运行正常关闭。

所有多 cgroup 环形缓冲区生产者（包括进程 fork、exec 与退出）都参与同一个运行中范围屏障。
读取屏障映射表失败时，范围会保持排空状态并默认拒绝；只有有界等待超时，才可以尝试恢复
其他前置条件完整的 `ACTIVE` 范围。通过 ABI 验证但无法规范化的记录也会停止队列摄取或
已确认排空流程，而不会被跳过。

全系统调用采集、提示词／响应、TLS 明文和通用内核强制执行都不是目标。

### 5.3 用户空间规范化与身份

用户空间解码内核 ABI，分配确定性来源序列号，标准化事件类型，关联
运行时元数据，应用原文不落盘（content-off）隐私策略，并写入智能体观测记录。

内核 ABI v3 携带有界的范围代次、进程代次、内核进程启动时间戳、exec 代次以及父进程的
进程／exec 代次。当前用户空间边界会附加采集器启动时读取一次的主机启动 ID。进程上下文
按主机启动 ID、PID、进程代次与 exec 代次键控，而不是只按 PID 键控，因此 PID 复用或
exec 转换不会继承陈旧的可执行文件上下文。进程身份映射表与用户空间上下文表保持有界；
出现压力时会显式失败，而不会静默复用或丢弃身份状态。内核身份映射表或 exec 代次更新
失败会设置预分配的默认拒绝锁存器；此后直到采集器重启，所有记录都保持推断关系，因此
压力消失也不会让归属静默恢复为精确关系。

只有主机启动 ID、范围代次、进程代次、内核进程启动时间与 exec 代次全部存在时，归属才
是精确关系。Fork 身份在观测到子进程启动前保持临时状态；始终未成为进程身份的线程克隆
候选项保持推断关系，并在任务退出时丢弃。代次缺失时保持推断关系并给出明确原因；只依赖
PID、命令、路径或时间戳的关联不会升级为精确关系。范围代次只保护单次采集器生命周期内
的 cgroup 所有权。采集器重启仍是可见的身份边界。生命周期恢复会记录未完成实例及其重启
缺口，但不会跨越该边界声明身份连续性。PID 命名空间、容器、Pod 与节点身份在可用时仍可
作为增量归属信息。

#### 容器运行时绑定与恢复

Docker 与 containerd 归属只消费成功且完整的适配器清单，不会把发现事件流直接当作权威。
稳定的工作负载身份包含适配器、完整工作负载／容器 ID、运行时启动标记、主机启动 ID、
初始进程的时钟滴答启动时间，以及 cgroup 文件系统的 `(device,inode)` 身份。PID、进程／
容器名称、时间接近性、运行时路径与数字 cgroup ID 都不能单独构成精确关系。

相同的完整清单不会产生任何变化。只有成功的完整清单才能退役其中缺失的绑定。
相同适配器／工作负载键若出现不同稳定身份，就是显式身份转换：旧绑定
会先得到一条带 `reason=identity_transition` 的 `runtime_metadata_unavailable` 缺口，然后被
退役；替代项只有通过资格验证后才能挂接。工作负载键重复、cgroup 身份冲突、适配器不匹配、
身份字段缺失或超限，以及清单过大都会触发默认拒绝。套接字故障或解码失败不等于空清单，
因此既不能静默退役绑定，也不能保留陈旧的精确归属。

运行时来源丢失会暂停受影响的生效绑定，并在恢复前持久化观测缺口。守护进程重启只把
持久化绑定恢复为休眠状态，而不是精确关系；必须由新的完整清单重新完成资格验证。套接字
断开、运行时服务重启与守护进程重启使用有界退避；不可用期间适配器健康状态为降级，只有
取得合法清单后才恢复就绪。Docker、
containerd 与 k3s-containerd 使用相同恢复语义；Kubernetes 元数据仍是增量信息，不能
升级未资格化的容器绑定。

D1/D2 实现与确定性约定已完成。保留的非破坏性 Docker 资格验证
证明以下全部边界：

- 完整清单建立生效绑定；同一完整容器 ID 重启后会改变稳定身份，
  不会继承陈旧的 PID、名称、时间或数字 cgroup 归属；
- 受控的适配器套接字中断会先持久化来源缺口，再暂停绑定并清除生效所有权；之后只有
  最新完整清单才能重新观测该稳定绑定；
- 在同一私有状态根目录上创建新的私有守护进程／服务端生命周期时，重放绑定保持休眠；
  恢复生效查询归属前，必须按 `daemon_restart` 缺口 -> 已退役 -> 已观测
  顺序完成恢复；
- 真实的原文不落盘 eBPF 文件事件携带精确容器与 cgroup 身份，同时完成智能体运行能力清单
  与哈希链验证。

特权 Docker/eBPF 边界可通过 `make qualify-runtime-binding-live` 复现。执行器以普通用户身份
构建 BPF 与测试，把唯一的测试可执行文件和 CO-RE BPF 对象发布为经过校验、root 所有的私有
副本，并且只针对固定的本地 Docker Engine 套接字调用这一精确的显式启用门禁。测试会在
任何 Docker 变更前检查内核、Docker、镜像、服务状态与所有权前置条件，并执行身份绑定的
清理。跳过不等于通过；直接对测试二进制使用裸 `--ignored` 不属于该约定。

这些门禁只验证已保留的 Docker 行为。独立的私有 containerd 边界可通过
`make qualify-private-containerd-live` 复现；该目标由具备预授权 `sudo` 的非特权检出目录所有者
显式调用 `scripts/run-private-containerd-live.sh`。执行器固定官方 `crictl` v1.36.0 归档及其
二进制哈希，只接受这一已验证二进制（或下载并校验官方归档），并要求本地 Docker 存储中
已经存在固定版本的 Alpine 镜像。它使用主机本地的 containerd 与 runc 二进制，再通过保存并
导入该缓存镜像，以离线方式构建私有工作负载存储；资格验证期间不会拉取工作负载镜像。

执行器进入仅创建的委托用户 systemd 范围，把范围根进程移入私有 `init` 子进程，并只启用
实际存在的必要控制器，从而准备合法的 cgroup v2 嵌套。随后特权门禁使用 runc，并以私有的
root、状态、套接字、插件、CNI、CDI、NRI、镜像验证器与 `opt` 路径启动 containerd 实例。
挂载、网络、UTS、IPC 与 cgroup 命名空间相互隔离。外层 PID 命名空间有意与主机共享，使
`/proc` 能证明每个自有进程与 cgroup 代次；每个 CRI Pod 沙箱和工作负载的 PID 命名空间仍由
runc 创建并隔离。该门禁不重启共享服务，不修改共享 CNI 配置或 iptables，也不使用共享的
运行时套接字或存储。

保留的私有 containerd 结果证明了完整初始清单、相同稳定清单，以及替代工作负载最新、
完整的容器身份与稳定性证明代次；未变化的工作负载仍保持原身份。受控代理套接字中断会
持久化来源缺口、暂停生效所有权；重新连接后，只有最新完整清单才能再次建立观测。
`crictl` 可能把 CRI `startedAt` 渲染为带数字 UTC 偏移的本地时间 RFC3339Nano；适配器会在
边界严格归一化为既有的十进制正数 Unix 纳秒标记，不持久化偏移文本。

清理由证明约束并默认拒绝。执行器只删除经过证明的私有 CRI 对象及其进程／cgroup 代次，
停止私有运行时，移除其命名空间、挂载、委托范围与新建根目录，并要求这些对象全部不存在
后才报告成功。执行前后都会绑定共享 Docker/containerd 服务状态、PID、套接字身份、缓存的
Alpine 身份与 Docker 容器清单。无法确定的私有清理或残留会使门禁失败并保留私有根目录；
共享基线漂移同样会使门禁失败。不过，如果私有清理已经得到独立证明，仍可删除该根目录，
因为它不是共享主机状态的证据权威。

共享主机 CRI 发现门禁若报告 `RuntimeReady=true` 但 `NetworkReady=false`，仍会在变更前
安全跳过；跳过不算通过。已经保留的私有独立结果完成了有界 D1/D2 containerd 资格验证，
但没有验证 Kubernetes 或共享 containerd 安装。Docker 证据不能外推到 containerd，私有
containerd 证据也不能外推到 Kubernetes。因此 containerd 与 Kubernetes
配置档继续保持实验级（`Experimental`），任何配置档都不会因此获得正式支持（`Supported`）。

通过 systemd 实际重启 Docker/containerd 服务，仍属于非破坏性 D1/D2 闭环之外的额外、破坏性
显式资格验证。这些门禁与 K1/VKE Kubernetes 实机资格验证仍未完成；它们
不会使已保留的 Docker 或私有 containerd 证据失效。

#### Kubernetes 节点与 Pod 归属（K1）

K1 以每个节点一个双容器 DaemonSet Pod 的形态部署。以 root 身份运行的采集器负责加载 eBPF、访问
主机 `/proc`、cgroup、BPF、跟踪设施／BTF、恰好一个 CRI 运行时套接字，以及本地状态边界；它不
持有服务账号令牌。它不是特权容器，禁止权限提升，使用只读根文件系统，清空 Linux 环境能力集，
并且只增加 `BPF`、`PERFMON`、
`SYS_RESOURCE` 与 `DAC_READ_SEARCH`；不会获得 `SYS_ADMIN`。Pod 不加入主机 PID 或网络
命名空间。元数据源容器以 UID/GID `65532` 运行，移除全部能力，使用只读根文件系统，
并且只有它接收投射、轮换的服务账号令牌。生产启动会验证精确的有效 UID/GID，且有效能力集合必须
为空。其 Role 仅允许在 DaemonSet 自身专用智能体命名空间中列举（`list`）与监听（`watch`）
Pod；自动令牌挂载被关闭。它没有全集群或跨命名空间读取路径。该专用命名空间
是操作者控制的信任域：不受信租户不得在其中获得 Pod `create`、`update` 或 `patch` 权限。

两个容器只共享一个容量受限、以内存为后端的 IPC 卷。元数据源进程拥有模式为 `0700` 的目录，以及
UID/GID 为 `65532`、模式为 `0660` 的 Unix 套接字；该进程先以不可预测的私有名称绑定，
完成全部资格校验后，再通过一次禁止覆盖的重命名发布。采集器采用严格的补充组策略，获得
共享 GID `65532`，以及访问并读取该私有目录所需的 `DAC_READ_SEARCH`（另加 BPF 所需能力）。
双方都围绕有界的分帧 I/O 验证套接字类型、所有权、模式、连接前后 inode 身份与对端凭证。
陈旧套接字恢复使用非阻塞存活探测，且只删除已经精确证明的 inode。采集器的持久主机目录
是独立的操作者前置条件，必须预先创建为 root 所有、模式 `0700`；DaemonSet 不会创建宽泛的
主机路径。一个 K1 守护进程恰好拥有一个 `containerd` 或 `k3s_containerd` 清单域；同时配置
两个套接字会被拒绝。随仓库交付的规范清单固定使用 VKE/containerd 路径
`/run/containerd/containerd.sock`。K3s 已有实现支持，但操作者必须提供匹配 K3s 套接字且保持
本文安全与所有权约定的清单或叠加配置；仓库当前不交付该叠加配置。但主机 CRI 套接字在
协议上仍暴露变更方法，因此采集器仍受节点信任。移除 `SYS_ADMIN`、隔离令牌与收窄主机挂载
都只是相对降低权限，而不是真正的只读运行时边界。真正的只读 CRI 访问需要未来增加方法
白名单代理，不能让采集器直接拥有套接字。

操作者授权通过 `SessionIntent.kubernetes_claims` 进入，而不是来自发现的 Pod 元数据。
每条声明具有一个非零修订号与精确元组
`(cluster_id,namespace_ref,pod_uid,container_kind,container_ref)`；同一意图的所有声明
共享修订号，重复槽位会被拒绝。操作者必须为部署生成跨集群唯一且不可变的 `cluster_id`；
来源只验证规范的非零 UUID 结构，无法发现误复用或证明集群身份。

| 声明字段 | 约定 |
| --- | --- |
| `schema_version` | u32 常量 `1` |
| `claim_revision` | 同一意图每条声明共用的非零 u64 |
| `cluster_id` | 规范的小写非零 UUID |
| `namespace_ref` | 64 字节小写十六进制命名空间假名 |
| `pod_uid` | 规范的小写非零 Pod UUID |
| `container_kind` | `application`、`init` 或 `ephemeral` |
| `container_ref` | 64 字节小写十六进制容器名称假名 |

一个意图最多携带 256 条 K1 声明。未知声明字段、混合修订号、重复的精确槽位、格式错误的
引用，以及过期或无效的父意图，都会在守护进程状态变更前触发拒绝。`apolysisd-control`
从标准输入读取一个有界、类型化的控制请求，验证本地守护进程套接字与对端，应用统一的
I/O 截止时间，并在不回显被拒值的情况下转发请求。它是通过 `kubectl exec` 进入采集器容器
的预期操作者入口。来源标签与注解始终只是发现输入，不能创建或扩大声明。

Kubernetes 节点任务显式启用 CRI Pod 沙箱元数据关联。独立 containerd 保留既有的“只接受
直接容器”行为，K3s 保留既有的沙箱标签行为。在 K1 模式中，只有处于 `READY` 状态且标签
精确为 `apolysis.dev/observe=true` 的 Pod 沙箱才参与；未标记沙箱会在解析私有元数据前被
忽略。已标记沙箱必须携带 `metadata.namespace`；不同命名空间即使会话值相同也会被忽略，
而已配置命名空间还要求标准标签 `io.kubernetes.pod.namespace` 精确相同。沙箱的智能体运行
可来自标签 `apolysis.session_id` 或注解 `apolysis.dev/session-id`，并规范化为继承的
`apolysis.session_id`。直接容器会话标签仍可作为候选 D1 身份的有效路由输入；如果同时存在
继承路由，两者必须相同。直接或继承的会话元数据都不能授权 D1 或范围挂接。会话值存在但
为空或无效、标签与注解冲突、目标命名空间缺失或冲突、`READY` 目标沙箱 ID 重复，或者
列举／检查结果中的直接与继承值冲突，都会使整份 CRI 清单非法。诊断只报告固定类别，永不
回显被拒元数据。适配器最终重新列举候选项时使用完全相同的 K1 模式；规范集合发生变化会
使清单非法。

这种默认拒绝的元数据行为也是明确的可用性边界。操作者命名空间内一条格式错误的已标记
沙箱会使该节点的 K1／运行时周期降级。精确的类型化授权声明会阻止这类元数据扩大授权，但 K1
不承诺抵抗已经拥有该专用命名空间 Pod 写权限的主体发起的拒绝服务攻击。

资格验证是一次封闭事务：

```text
完整、分页的 Pod 列表 A
  -> 完整 containerd/K3s CRI 清单（整次扫描受 request_timeout 限制）
  -> 完整、分页的 Pod 列表 B
  -> 与精确的类型化授权声明求交
  -> 只保留授权声明允许的完整 D1 身份
  -> 先协调并挂接 D1，再持久化 Kubernetes 归属
```

变更监听只提供“数据已变脏”的提示，永远不是权威。Pod 列表 A 与列表 B 必须具有相同的来源纪元、
集群、命名空间与节点身份，严格递增的非零序列号，以及字节等价的规范 Pod 候选项。候选项
包含 Pod UID、删除／标记状态、运行时类引用、每个应用／初始化／临时容器槽位及其运行中
容器 ID，以及从 Pod 资源版本派生的临时 `pod_revision_ref`。同一纪元的后续周期必须从上次
终止序列号之后开始。分页、解码、上界、重复项、修订号或 A/B 不匹配中的任何问题都会使
整个快照非法；失败永远不会被解释为空列表。

求交要求 Pod 已标记且未进入删除状态、槽位精确匹配声明、运行中容器具有规范的完整 ID，
并且候选项属于同一智能体运行且携带完整的精确 D1 身份。只有经过“授权声明 → A/B 两次 Pod
快照中的 UID 与容器槽位 → 运行时容器 ID → 完整 D1 身份”逐级匹配后得到的键，才会进入准入清单。
D1 协调与范围挂接只消费这份筛选后清单；未声明、不匹配或只有元数据的候选项不能
产生 D1 状态或范围所有权。持久化生效顺序是先观测 D1，再观测对应的 K1 归属。Kubernetes
元数据只是附加信息：不能制造运行时身份，也不能把陈旧或推断的绑定升级。原始命名空间、
节点、容器与运行时类名称会在进入 IPC 前转换为带域分隔的 SHA-256 引用。
`pod_revision_ref`、来源纪元与来源序列号只用于消除资格验证竞态，绝不跨越持久化边界。
持久化引用面向原文不落盘配置档，是确定性、无密钥的 SHA-256 假名，而不是匿名化或保密
机制：低熵名称可被离线枚举，相同值可跨运行关联。Pod UID 与嵌套的完整 D1 容器 ID 仍然
显式保留。

```text
reference_v1(kind, raw) = lowerhex(SHA-256(
  "apolysis:kubernetes-reference:v1" || 0x00 ||
  kind || 0x00 || UTF-8(raw)
))
pod_revision_ref = lowerhex(SHA-256(
  "apolysis:kubernetes-pod-revision:v1" || 0x00 || UTF-8(resourceVersion)
))
```

`kind` 恰好是 `namespace`、`node`、`container` 或 `runtime_class`。命名空间/容器输入
必须是规范的小写 DNS 标签；节点／运行时类输入必须是有界、规范的小写 DNS 子域名。
第二个公式只用于资格验证，绝不是持久化标识符。

相同的资格验证周期不会产生任何变化。成功周期中缺失的 Pod／容器会使 K1 归属退役。同一
Pod 内容器重启会改变 D1 身份，并依次生成 K1 身份转换缺口、旧 K1 退役、最新 D1 资格验证
与新 K1 观测。新出现的 K1 关联若引用周期前已存在的运行时绑定，
会记录一个 `kubernetes_late_attach` 关系边界；同一原子周期新建的 D1 绑定不会。
已明确记录的中断、身份转换或重启恢复不会被误标为延迟挂接。

Kubernetes API 丢失会发出 API 缺口并暂停 K1，同时让独立、健康的 D1 采集继续生效。CRI
丢失会先把 K1 运行时元数据标记为不可用并暂停 K1，再应用普通 D1 运行时缺口与暂停。若
一次成功的 CRI 扫描无法证明授权声明指定的运行时关联（运行时身份缺失、冲突、重复或非法），
也会走相同的 K1→D1 `inventory_invalid` 暂停路径；仅 Pod A/B 来源变化时只暂停 K1，并保留
独立、精确的 D1 绑定。两类恢复都必须经过最新、完整的 A／运行时／B 周期，才能恢复归属。
来源纪元变化或守护进程状态恢复会发出 `kubernetes_daemon_restart`，退役既有的生效／休眠
K1 状态，并且只重新观测最新、资格验证通过的关联。撤销授权声明或替换其修订号时，会在其
D1 绑定之前，于同一事务中退役 K1 关联与 K1 独占的 containerd/K3s D1 绑定，并在确认替换前
取消跟踪对应范围；即使 Kubernetes 元数据当前不可用，也保持该语义。独立 Docker 绑定不会
被该 K1 事务撤销。跨节点重新调度不代表连续性：旧 Pod UID 退役，新 Pod UID 在有界交接后
独立建立观测；系统不声明无缺口所有权。

受保护挂接会把初始进程与线程标识符规范化为 TGID，并要求 root 是存活的线程组主线程。
一个 `/proc` 启动时钟滴答会转换成相对主机启动时间的半开区间
`[start_tick * tick_ns, (start_tick + 1) * tick_ns)`。匹配的内核记账信息可以在初始集合构建
阶段或之后，把内部跟踪成员提升为精确的线程组主线程启动时间；后续匹配必须使用该纳秒值。
只有激活后实际发出的事件，才由匹配的内核启动时间与进程／exec 代次，在本次采集器运行内
获得精确事件身份。该身份与锚定前的根进程选择置信度相互独立：显式注册为
`registration_qualified`，发现保持 `inferred`；二者都不是事件关系状态，也不证明连续性。

### 5.4 本地存储与查看器

首个产品保持本地优先。存储有界并安全轮转，保留明确的运行起点、能力、健康检查点、终止
状态与缺口记录。当前格式是仅追加 JSONL，以及可选的本地哈希链封装。L3 已保存运行查看器
直接消费冻结的单次运行记录。只有重复使用证明有界的单记录视图不足时，才考虑后置查询索引。

V1 已保存运行读取路径把生效文件与连续编号归档视为同一个稳定本地快照，按最旧归档到生效
文件的顺序读取；它拒绝符号链接、非普通文件、读取期间变化、截断、格式错误和混合封装，
并在暴露载荷前验证完整哈希链。字节、行和记录都有明确上限。来源顺序是权威顺序；墙钟
时间戳不会修复或重排非法生命周期。普通输入与已验证输入可以显式组合，但混合完整性始终
可见，不能产生完整证据。批次、字节与记录预算作用于整个组合命令，而不是分别作用于每个
`--input`。

`apolysis-accountability` 会把这些类型化来源记录纯函数式折叠为恰好一份智能体观测记录。
智能体观测摘要保持证据状态、采集器健康状态与复查状态相互独立。缺失生命周期、不支持的
结果、诊断、观测缺口、未知记录与来源完整性发现项会保留为可查询限制；混合智能体运行、
损坏存储、非法生命周期顺序、重复的规范观测、不兼容模式与内容策略违规会触发默认拒绝。
自由文本的发现项原因与缺口详情会被规范化，而不是复制到派生制品。经过验证的运行时绑定
与 Kubernetes 归属生命周期事实会按来源顺序保留在投影中；验证会重建两种生命周期，而不
只是把它们归约为当前生效集合。

完整证据要求满足当前 v1 的完整操作、来源与结果能力约定。部分或伪造的清单，以及无法
解析的发现项引用，会作为类型化问题保留，不能成为完整证据。只有携带基于代次的规范关系
原因与完整稳定元组的激活后内核观测，才能进入精确运行时身份。

`apolysis run project --input <path> [--input <path> ...] --output <path>` 是该投影
的非特权适配器。它通过同目录私有临时文件写入确定性 JSON，完成同步后原子发布，
并拒绝让输出与任何生效或轮转后的输入互为别名。该命令用于已保存运行投影，不是实时追踪、
远程查询 API 或交互式查看器。

`apolysis run view --input <agent-observation-record.json> --output
<viewer.html>` 是非特权已保存运行查看器适配器。它只接受一份智能体观测记录 v1，验证其
类型、模式、摘要、身份引用、来源序号、发现项链接、运行时绑定／K1 生命周期与状态一致性，
然后渲染确定性的自包含 HTML。格式错误或内部不一致的记录会触发默认拒绝，且不会替换现有
输出。读取器有界并拒绝符号链接与非普通文件；发布器使用独占、模式为 `0600` 的同目录临时
文件，同步文件与目录并执行原子重命名前，会拒绝输出别名。

该 HTML 是离线、只读制品，不依赖外部资源或网络。限制性内容安全策略（Content Security
Policy）禁用网络连接与外部资源，每个存储值都按不可信文本渲染。查看器不需要 root，也不
接触 BPF 映射表、主机 PID 命名空间、运行时套接字或节点凭证。

查看器提供：

- 保持证据状态、采集器健康状态与复查状态三个维度相互独立的单次运行摘要；
- 精确运行时身份清单，以及运行时观测中保留的已报告 PID/PPID 字段；
- 有序的已观测、已退役与已暂停运行时绑定生命周期；
- 带有精确 D1 来源链接的有序 K1 已观测、已退役与已暂停生命周期；
- 有序的进程、文件、网络与凭证时间线；
- 受支持的结果与归属状态；
- 采集器健康状态、丢失、截断与不支持能力缺口；
- 链接到支撑运行时观测或更早、精确匹配的已观测运行时绑定的复查型发现项；
- 使展示事实可追溯到冻结记录的来源序号与记录路径。

智能体观测记录 v1 不携带权威父运行时身份链接。因此查看器不会从可能复用的数字 PID/PPID
构造规范进程树；它只把身份清单与已报告 PPID 作为存储事实展示，不推断父子边。它也不会
从空结果推导隐藏的成功判定，更不会把三个摘要维度合并为“无异常”判定。

派生的 v1 对象是一份 JSON 对象，永远不会追加回时间线 JSONL。顶层字段是
`record_type`、`schema_version`、`agent_run_id`、`source_integrity`、`summary`、
`capability_manifests`、`runtime_identities`、`runtime_observations`、
`runtime_bindings`、`kubernetes_attributions`、`collector_lifecycle`、`findings`、
`observation_gaps` 与 `issues`。每个投影后
的来源事实携带来自权威输入顺序、从 1 开始的 `source_ordinal`。摘要保留类型化计数与分组
映射表，不合并证据状态、采集器健康状态与复查状态。

投影上限为：全部输入合计 128 MiB、每行 JSONL 1 MiB、1,000,000 条来源记录、1,024 个数字
归档、1,024 个输入批次、每个字符串 4,096 字节、每个数组 1,024 项、每个对象 256 个字段，
值最深 16 层。发布使用独占、模式为 `0600` 的临时文件，执行文件／父目录同步与原子重命名；
替换前拒绝来源别名与不安全的文件类型。

`apolysis verify hash-chain` 是只读操作。退出码 `0` 表示所有记录与尾部验证通过，`1` 表示已经
写出失败报告，`2` 表示命令无法运行。报告保留已验证记录数、最后序列号／哈希、有效／总
字节数与有界失败类别。中段损坏、尾部截断或尾部损坏都会触发默认拒绝，不会截断、修复或
隔离源文件。

外部日志传输保留每条原始 JSONL 行与记录正文。Vector、Fluent Bit 或其他操作者传输工具
可以在正文外进行路由、缓冲、压缩或加密，但不会成为模式或查询权威。复制出的守护进程
哈希链在重放前必须验证；确认下游留存前，本地证据仍是权威。OTLP 与项目自有导出器保持暂缓。

### 5.5 本地守护进程运维

Linux 发布包包含 `apolysis`、`apolysisd` 与 `apolysisd-health` 二进制、CO-RE 对象和 systemd
单元。发布清单模式 v2 会把恰好这 5 个可安装制品绑定到各自的种类、SHA-256 摘要、字节长度
与要求模式。清单路径不会成为任意目标位置；安装器只把这一封闭制品集合映射到
`/usr/local/bin/apolysis`、`/usr/local/bin/apolysisd`、
`/usr/local/bin/apolysisd-health`、
`/usr/local/lib/apolysis/apolysis_observer.bpf.o` 与
`/etc/systemd/system/apolysisd.service`。

发布验证器只接受一条有界且规范的 gzip/tar 流，拒绝重复或扩展的归档元数据与非普通成员，
检查封闭清单、systemd 约定及可执行 ELF 结构，并要求 `bpftool gen skeleton` 能解析打包的
CO-RE 对象。打包约定测试使用刚构建的真实对象；生产验证器没有结构夹具开关。

`apolysis daemon install --bundle <dir> --root <root>`、`inspect` 与 `uninstall` 是
`LocalDaemonOperations` 的适配器。这个深层模块只暴露检查、规划与应用，并隐藏发布包验证、
完整目标预检、文件系统快照、描述符锚定暂存、同步、崩溃恢复与收据所有权。root、发布包、
父目录与变更都以已打开目录为锚，并使用禁止跟随链接的语义。收据证明绑定所有者、包含特殊
位的模式、摘要、大小与文件身份。它拒绝有链接或非普通的来源／目标、硬链接制品、非法或
已变化的发布包、非托管冲突、已变化的托管文件和陈旧计划。成功安装会发布
`/usr/local/lib/apolysis/install-receipt-v1.json`；重复安装相同托管内容不会产生变化。默认
卸载只删除仍可由该收据证明所有权的制品，并始终保留 `/var/lib/apolysis` 与无关主机文件。

每次实际应用变更时，都会在发布各个文件前写入并同步一个固定、私有、模式为 `0600` 的操作
日志。重新打开模块时会回滚提交前事务，或完成已经提交的清理，并通过检查暴露
`recovered_interrupted_operation`。替换与删除使用经过身份复核、相对描述符执行的操作；
发生变化或未知的日志／事务同级项会触发默认拒绝，等待人工修复。这提供持久的中断恢复，
但不宣称 5 条主机路径能在一个瞬间可见的文件系统事务中同时变化。

暂存根目录执行相同的固定路径文件系统约定，但不调用 systemd、组管理或 eBPF。产品只支持
随包交付的 systemd 单元这一种具体集成，不提供抽象服务管理器接口。在真实主机上，该单元
要求显式准备 `apolysis` 组；systemd 负责激活、SIGTERM 关闭与有界排空截止时间，资格验证
复用守护进程现有健康协议。运行时／状态目录模式为 `0750`，守护进程时间线为 `0640`，私有
隔离区与留存日志为 `0600`，显式管理的本地套接字保持 `0660`。暂存根目录验证不能替代显式
特权门禁；后者会加载真实发布包、等待 eBPF 与存储就绪、停止单元，并验证保留状态的卸载。

卸载不等于留存管理。破坏性留存从守护进程时钟取得时间，依据目录身份与已经打开的单链接
时间线描述符验证每个已关闭智能体运行，阻止迟到写入，并把精确集合暂存到同一文件系统的
私有回收站根目录。同步的类型化日志区分暂存与已提交清理。启动时会回滚未完成的暂存事务，
并完成已提交清理；不安全的目标替换、未知内容、日志损坏或冲突的当前状态都会触发默认拒绝。
无变更预览可以为确定性测试使用显式时间，但调用方不能为破坏性应用提供时间。破坏性应用
只适用于本地默认上下文；旧模式的非默认请求会在零变更下被拒绝，多租户删除仍保持暂缓。
终止留存目录具有独立的 4,096 次智能体运行上限；达到上限时会触发默认拒绝，既不驱逐已
留存状态，也不占用活跃运行容量。

哈希链恢复以禁止跟随链接的语义只打开时间线一次，并在验证、隔离、截断与后续追加中复用
该描述符。它拒绝符号链接、多链接文件与路径替换。可恢复的损坏尾部会保留在私有、新建的
隔离文件中；中段损坏仍会触发默认拒绝。恢复与留存都不会把由此产生的完整性或采集器重启
限制改写成完整证据。

### 5.6 后置的中央边界

远程导出、托管链、组织授权、对象存储、跨运行搜索与高可用都不属于有界测试版。只有重复
使用证明需要中央服务，并由新的架构决策定义边界后，它们才会重新进入。

## 6. 观测约定

时间线模式 v1 是逐行分隔的 JSON（newline-delimited JSON）：每行一个完整对象，每个对象
包含一个字符串字段 `record_type`；除非字段另有声明，时间戳使用 Unix 毫秒；数字 ID 使用
十进制；可选字段显式输出 `null`。兼容规则是仅追加。消费者忽略未知字段与新增记录类型，
不依赖对象字段顺序，并使用稳定 ID 而不是时间戳进行关联。下文运行时绑定生命周期等显式
封闭子模式会拒绝未知字段。删除字段、重命名、改变类型或改变语义都需要新的模式版本。
生产者在持久化前脱敏；默认 `content_off` 配置档永不写入原始秘密、argv、提示词、响应、
套接字、路径、标签、注解或工具载荷。

稳定记录族如下：

| `record_type` | 必需约定 |
| --- | --- |
| `collector_capability_manifest` | 智能体运行、采集器／ABI 身份、观测范围、隐私配置档、有序操作／来源／结果声明 |
| `collector_lifecycle` | 智能体运行、不透明采集器实例、启动／检查点／终止状态、健康状态、停止原因、累计丢失／待定计数器 |
| `event` | 智能体运行、来源／类型／原始 ID、执行者／资源／动作、结果／返回值／errno、运行时身份字段、关系状态／原因 |
| `raw_kernel_event` | 带 ABI 身份、有界脱敏资源／载荷、结果与原始事件 ID 的规范化前内核事实 |
| `intent` / `intent_correlation` | 可选的原文不落盘声明意图及其稳定 ID 或有界可执行文件关联；不是观测必需输入 |
| `accountability_finding` | 类型化复查决定、有界规范原因、证据引用、运行时身份与证据边界 |
| `observation_gap` | 可能缺失或不可用证据的类型化操作、种类、计数与有界详情 |
| `runtime_binding_observed` / `runtime_binding_retired` / `runtime_binding_suspended` | 围绕单一稳定工作负载身份的持久 Docker/containerd 绑定生命周期 |
| `kubernetes_attribution_observed` / `kubernetes_attribution_retired` / `kubernetes_attribution_suspended` | 围绕一条已观测的精确 containerd/K3s 运行时绑定，形成持久的已授权 Pod／容器归属生命周期 |
| `observer_diagnostic` | 类型化的有界挂接、验证器、ABI、解码、截断、压力、丢失或摘要诊断 |
| `visibility_assessment` | 运行时配置档、主机可见性范围、元数据／客体采集器要求与有界主体 |

### 6.1 时间线 JSONL 传输格式模式 v1

下列表格中的每个字段都是传输格式必需字段。`T|null` 表示字段必须出现，但值可以是
JSON `null`；其他字段都不可为空。`u32`、`u64` 与 `u128` 是对应 Rust 范围内的非负 JSON
整数，`i32` 与 `i64` 是有符号 JSON 整数，`map<string,u64>` 是值为非负计数的 JSON 对象。

`collector_capability_manifest` 的结构是：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `record_type` | 字符串 | 常量 `collector_capability_manifest` |
| `schema_version` | u32 | 常量 `1` |
| `timestamp_unix_ms` | u128 | 持久化时间 |
| `agent_run_id` | 字符串 | 所属智能体运行 |
| `collector` | 字符串 | 常量 `apolysis_observer` |
| `collector_version` | 字符串 | 用户空间软件包版本 |
| `kernel_abi_version` | u32 | 当前 ABI 为 `3` |
| `kernel_record_size` | u32 | 当前 ABI-v3 大小为 `656` |
| `observation_scope` | 枚举 | `process_tree` 或 `cgroup` |
| `privacy_profile` | 枚举 | 常量 `content_off` |
| `capabilities` | 对象数组 | 有序能力对象 |

每个能力对象包含必需的 `operation:string`、
`event_sources:array<string>` 和 `outcomes:array<enum>`。结果值是
`attempted`、`succeeded`、`failed`、`denied`、`pending` 与 `unknown`。兼容的
AuditObserver v1 清单必须声明下列完整操作约定；文件能力只有包含完整
入口与退出来源集合时才有效。

| 操作 | 事件来源 | 结果 |
| --- | --- | --- |
| `process_fork` | `sched/sched_process_fork` | `succeeded` |
| `process_exec` | `sched/sched_process_exec`、`syscalls/sys_enter_execve`、`syscalls/sys_enter_execveat` | `succeeded`；sched 来源必需 |
| `process_exit` | `sched/sched_process_exit` | `unknown` |
| `file_open` | `syscalls/sys_enter_openat`、`syscalls/sys_exit_openat`、`syscalls/sys_enter_openat2`、`syscalls/sys_exit_openat2` | `succeeded`、`failed`、`denied` |
| `file_create` | 文件打开来源加 `syscalls/sys_enter_creat`、`syscalls/sys_exit_creat` | `succeeded`、`failed`、`denied` |
| `file_truncate` | 文件打开来源加 `syscalls/sys_enter_truncate`、`syscalls/sys_exit_truncate` | `succeeded`、`failed`、`denied` |
| `file_unlink` | `syscalls/sys_enter_unlinkat`、`syscalls/sys_exit_unlinkat` | `succeeded`、`failed`、`denied` |
| `file_rename` | `syscalls/sys_enter_renameat2`、`syscalls/sys_exit_renameat2` | `succeeded`、`failed`、`denied` |
| `network_connect` | `syscalls/sys_enter_connect`、`syscalls/sys_exit_connect` | `succeeded`、`failed`、`denied`、`pending` |
| `credential_path_access` | `syscalls/sys_enter_openat`、`syscalls/sys_exit_openat`、`syscalls/sys_enter_openat2`、`syscalls/sys_exit_openat2` | `succeeded`、`failed`、`denied` |

`collector_lifecycle` 的结构是：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `record_type` | 字符串 | 常量 `collector_lifecycle` |
| `schema_version` | u32 | 常量 `1` |
| `timestamp_unix_ms` | u128 | 生命周期时间 |
| `agent_run_id` | 字符串 | 所属智能体运行 |
| `collector` | 字符串 | 常量 `apolysis_observer` |
| `collector_instance_id` | 字符串 | 同一进程各运行流共用的不透明 UUID |
| `state` | 枚举 | `started`、`checkpoint`、`stopped` 或 `failed` |
| `health` | 枚举 | `healthy`、`degraded` 或 `failed` |
| `stop_reason` | 枚举或空值 | 启动/检查点为 `null`；终止值见下文 |
| `counters` | 对象 | 下列必需的累计计数器对象 |

正常停止原因是 `agent_run_closed`、`daemon_shutdown`、
`duration_elapsed`、`agent_exited` 与 `shutdown_signal`。失败原因是
`attach_failure`、`verifier_failure`、`abi_mismatch`、`decode_failure`、
`counter_read_failure`、`storage_failure`、`observer_failure`、
`collector_restart` 与 `incomplete_terminal_flush`。计数器对象有八个必需的 `u64`
字段：`global_reserve_failures`、`global_map_pressure`、
`global_abi_mismatches`、`global_decode_failures`、`global_truncations`、
`scope_missing_entries`、`scope_missing_exits` 与 `scope_pending`。
`started` 必须为 `healthy`，原因为 `null`，计数器为零。`checkpoint` 的原因为 `null`，且
恰好在持久性丢失计数器非零时为 `degraded`。`stopped` 使用正常原因，并在存在持久性丢失
或非零 `pending` 时为 `degraded`。`failed` 的健康状态为 `failed`，并使用失败原因。

`event` 是规范运行时观测来源记录：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `record_type` | 字符串 | 常量 `event` |
| `timestamp_unix_ms` | u128 | 观测时间 |
| `session_id` | 字符串 | 智能体运行 ID；这是旧版传输字段名 |
| `event_source` | 枚举 | `manual`、`process_tree`、`kernel_tracepoint`、`uprobe` 或 `runtime_metadata` |
| `event_type` | 枚举 | `session_started`、`runtime_metadata`、`exec`、`file_open`、`file_create`、`file_truncate`、`file_unlink`、`file_rename`、`network_connect`、`credential_read` 或 `process_exit` |
| `raw_event_id` | 字符串或空值 | 指向原始事件的规范关联 |
| `pid` | u32 | 报告的进程 ID |
| `ppid` | u32 | 报告的父进程 ID |
| `actor` | 字符串 | 有界进程、观测器、运行时或集成执行者 |
| `resource` | 字符串 | 脱敏的目标/资源身份 |
| `action` | 字符串 | 规范化动作或元数据值 |
| `outcome` | 枚举或空值 | 能力结果枚举；不支持时为 `null` |
| `return_value` | `i64` 或空值 | Linux 系统调用结果 |
| `errno` | `i32` 或空值 | 从负结果推导的正 errno |
| `container_id` | 字符串或空值 | 运行时容器身份 |
| `cgroup_id` | 字符串或空值 | 运行时 cgroup 身份 |
| `host_boot_id` | 字符串或空值 | 采集器捕获的启动 UUID |
| `scope_generation` | `u64` 或空值 | 观测器生命周期内的范围代次 |
| `process_generation` | `u64` 或空值 | 采集器分配的进程代次 |
| `process_start_time_ns` | `u64` 或空值 | 相对主机启动时间的内核进程启动时间 |
| `exec_generation` | `u32` 或空值 | 进程本地 exec 代次 |
| `parent_process_generation` | `u64` 或空值 | 已知父进程代次 |
| `parent_exec_generation` | `u32` 或空值 | 已知父进程 exec 代次 |
| `relation_status` | 枚举 | `exact`、`inferred`、`ambiguous` 或 `unattributed` |
| `relation_reason` | 字符串 | 稳定、有界归属原因 |
| `process_command` | 字符串或空值 | 旧版脱敏上下文；当前原文不落盘生产者输出 `null` |
| `process_executable` | 字符串或空值 | 仅允许 `executable_ref:<basename>` |
| `process_started_at_unix_ms` | `u128` 或空值 | 旧版墙钟上下文，不是 `process_start_time_ns` |

`raw_kernel_event` 保留规范化前的有界输入：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `record_type` | 字符串 | 常量 `raw_kernel_event` |
| `timestamp_unix_ms` | u128 | 观测时间 |
| `session_id` | 字符串 | 智能体运行 ID |
| `event_source` | 枚举 | 上述事件来源枚举；通常是 `kernel_tracepoint` |
| `event_name` | 字符串 | tracepoint 或规范化内核事件名称 |
| `event_id` | 字符串或空值 | 稳定的原始事件关联 ID |
| `pid` | u32 | 进程 ID |
| `ppid` | u32 | 父进程 ID |
| `uid` | u32 | 用户 ID |
| `gid` | u32 | 组 ID |
| `comm` | 字符串 | 有界内核命令名称 |
| `resource` | 字符串 | 持久化前脱敏的资源 |
| `action` | 字符串 | 原始动作标签 |
| `outcome` | 枚举或空值 | 能力结果枚举 |
| `return_value` | `i64` 或空值 | Linux 系统调用结果 |
| `errno` | `i32` 或空值 | 正 errno 或 `null` |
| `container_id` | 字符串或空值 | 容器身份 |
| `cgroup_id` | 字符串或空值 | Cgroup 身份 |
| `host_boot_id` | 字符串或空值 | 主机启动 UUID |
| `scope_generation` | `u64` 或空值 | 范围代次 |
| `process_generation` | `u64` 或空值 | 进程代次 |
| `process_start_time_ns` | `u64` 或空值 | 相对主机启动时间的进程启动时间 |
| `exec_generation` | `u32` 或空值 | exec 代次 |
| `parent_process_generation` | `u64` 或空值 | 父进程代次 |
| `parent_exec_generation` | `u32` 或空值 | 父进程 exec 代次 |
| `relation_status` | 枚举 | 上述关系枚举 |
| `relation_reason` | 字符串 | 稳定、有界原因 |
| `raw_payload` | 字符串 | 有界、持久化前脱敏的载荷 |

对于 `network_connect`，非负返回是 `succeeded`；`EACCES`/`EPERM` 是 `denied`；
`EINPROGRESS`/`EALREADY` 是 `pending`；其他负返回是 `failed`。对于五种文件
操作，非负返回是 `succeeded`，`EACCES`/`EPERM` 是 `denied`，其他所有负结果
都是 `failed`。
在传输格式上，`succeeded` 要求非负 `return_value` 与 `null` 的 `errno`；`failed`、`denied`
和 `pending` 要求负值，且 `errno` 是该值取反后的正数；`null` 结果要求两个数值字段都为
`null`。

可选意图记录具有下列必需结构：

| 记录 | 字段 | 类型 | 值或含义 |
| --- | --- | --- | --- |
| `intent` | `record_type` | 字符串 | 常量 `intent` |
| `intent` | `timestamp_unix_ms` | u128 | 摄取时间 |
| `intent` | `session_id` | 字符串 | 智能体运行 ID |
| `intent` | `intent_source` | 字符串 | 适配器，目前为 `codex` |
| `intent` | `intent_id` | 字符串 | 适配器稳定 ID |
| `intent` | `source_event_id` | 字符串或空值 | 来源运行框架事件 ID |
| `intent` | `intent_type` | 字符串 | 规范化类型，例如 `tool_call` |
| `intent` | `tool_name` | 字符串 | 来源工具/函数名称 |
| `intent` | `declared_action` | 字符串或空值 | 规范化动作类别 |
| `intent` | `target` | 字符串或空值 | 声明的目标范围/资源 |
| `intent` | `command` | 字符串或空值 | 原文不落盘的可执行文件引用与脱敏标记 |
| `intent` | `raw_event_id` | 字符串或空值 | 已关联的原始事件 ID |
| `intent_correlation` | `record_type` | 字符串 | 常量 `intent_correlation` |
| `intent_correlation` | `timestamp_unix_ms` | u128 | 关联时间 |
| `intent_correlation` | `session_id` | 字符串 | 智能体运行 ID |
| `intent_correlation` | `intent_source` | 字符串 | 适配器 |
| `intent_correlation` | `intent_id` | 字符串 | 已声明意图 ID |
| `intent_correlation` | `match_basis` | 枚举 | `raw_event_id`、`process_command_exact` 或 `process_executable` |
| `intent_correlation` | `raw_event_id` | 字符串 | 已观测原始事件 ID |
| `intent_correlation` | `event_type` | 字符串 | 规范的已观测类型 |
| `intent_correlation` | `pid` | u32 | 已观测 PID；不可用时为 `0` |
| `intent_correlation` | `resource` | 字符串 | 已观测的脱敏资源 |
| `intent_correlation` | `process_command` | 字符串或空值 | 脱敏的已观测上下文 |
| `intent_correlation` | `process_executable` | 字符串或空值 | 已观测的可执行文件引用 |
| `intent_correlation` | `command` | 字符串或空值 | 脱敏的声明摘要 |

`accountability_finding` 有必需字段 `record_type:string`（常量
`accountability_finding`）、
`schema_version:u32`（`1`）、`session_id:string`、`kind:enum`、`decision:enum`、
`reason:string`、`evidence_ref:string`、`runtime:object` 与
`evidence_boundary:enum`。种类是 `missing_intent`、`unobserved_intent`、
`undeclared_action`、`credential_read`、`workspace_boundary`、`unknown_egress`、
`dangerous_command` 或 `service_account_token_read`；决定是 `notify` 或 `review`；
证据边界是 `host_boundary` 或 `guest_semantic`。运行时有必需字段
`runtime:string`、`container_id:string|null`、`pod_uid:string|null` 与
`cgroup_id:u64|null`。AOR 丢弃来源 `reason`，并替换为与种类对应的规范有界
原因。

| 发现项种类 | AOR 规范 `reason` |
| --- | --- |
| `missing_intent` | `observed side effect has no matching declared intent` |
| `unobserved_intent` | `declared intent has no matching observed side effect` |
| `undeclared_action` | `observed action class was not declared by intent` |
| `credential_read` | `workload read a credential-classified resource` |
| `workspace_boundary` | `file access crossed the declared workspace boundary` |
| `unknown_egress` | `network endpoint is outside the declared egress set` |
| `dangerous_command` | `command matches the dangerous-command baseline` |
| `service_account_token_read` | `workload read a Kubernetes service account token` |

`observation_gap` 有必需字段 `record_type:string`（常量 `observation_gap`）、
`schema_version:u32`（`1`）、`timestamp_unix_ms:u128`、`agent_run_id:string`、
`operation:string`、`kind:enum`、`count:u64` 与 `detail:string`。合法结构是：

| 种类 | 操作/计数 | 来源详情 | AOR 详情 |
| --- | --- | --- | --- |
| `missing_entry`、`missing_exit` | `network_connect`、`file_open`、`file_create`、`file_truncate`、`file_unlink` 或 `file_rename`；正计数 | 有界生产者诊断 | `bounded_loss_counter` |
| `collector_restart` | `collector_lifecycle`、`1` | 只含不透明的未完成实例 | `unfinished_collector_instance` |
| `late_attach` | `collector_lifecycle`、`1` | `collection_boundary:protected_existing_process_attach,history:unknown,provenance:<external_registration\|proc_discovery>,root_selection:<registration_qualified\|inferred>` | 相同有界详情 |
| `runtime_metadata_unavailable` | `runtime_metadata`、`1` | `source=<docker\|containerd\|k3s_containerd>,reason=<socket_unavailable\|daemon_restart\|inventory_invalid>` | `runtime_source_unavailable` |
| `runtime_metadata_unavailable` | `runtime_metadata`、`1` | 相同来源集合加 `reason=identity_transition` | `runtime_identity_transition` |
| `kubernetes_metadata_unavailable` | `kubernetes_metadata`、`1` | `cluster=<canonical-nonzero-UUID>,reason=<kubernetes_api_unavailable\|kubernetes_runtime_unavailable\|kubernetes_snapshot_invalid>` | 分别为 `kubernetes_source_unavailable`、`kubernetes_runtime_unavailable` 或 `kubernetes_snapshot_invalid` |
| `kubernetes_metadata_unavailable` | `kubernetes_metadata`、`1` | 相同集群结构加 `reason=<kubernetes_daemon_restart\|kubernetes_identity_transition\|kubernetes_late_attach>` | 相同有界原因 |

运行时元数据详情不得包含路径、载荷、套接字名称或后端文本。每条缺口都增加一条 AOR
`observation_gap` 问题，并阻止证据成为完整。运行时适配器可以独立配置，因此运行时元数据
缺口不要求采集器已有 `started` 记录。

运行时绑定生命周期记录共用同一个精确结构：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `record_type` | 枚举 | `runtime_binding_observed`、`runtime_binding_retired` 或 `runtime_binding_suspended` |
| `schema_version` | u32 | 常量 `1` |
| `agent_run_id` | 字符串 | 所属规范智能体运行 ID |
| `adapter` | 枚举 | `docker`、`containerd` 或 `k3s_containerd` |
| `workload_id` | 字符串 | 非零、64 字节小写十六进制 Docker 容器 ID、`containerd/<same-id>` 或 `k3s_containerd/<same-id>` |
| `start_marker` | 字符串 | Docker UTC `YYYY-MM-DDTHH:MM:SS[.1..9 digits]Z`（有效日期且年份 >= 1970），或规范的十进制正数 u64 CRI `startedAt`；严格 RFC3339Nano `Z`／数字偏移 CRI 文本会在适配器边界归一化为十进制 Unix 纳秒 |
| `host_boot_id` | 字符串 | 规范小写、非零的主机启动 UUID |
| `init_process_start_time_ticks` | u64 | 正数 `/proc/<init>/stat` 启动时钟滴答 |
| `cgroup_device` | u64 | 正数 cgroup 文件系统设备身份 |
| `cgroup_id` | u64 | 正数 cgroup 文件系统 inode 身份；不是 PID，也不是可独立作为精确的数字 cgroup 声明 |
| `runtime_handler` | 字符串或空值 | 有界、不含路径的不透明运行时处理器名称，或 `null` |

上表所有字段都是必需字段，只有 `runtime_handler` 可为空。这些记录没有载荷
时间戳；权威顺序来自 JSONL 来源顺序或外层哈希链序列号。它们绝不包含 PID、
容器名称、原始标签／注解、运行时／cgroup／套接字路径、端点、后端错误、载荷
或私有命名空间。`agent_run_id`、`workload_id`、`start_marker` 与非空
`runtime_handler` 都是有界标识符，不是自由文本采集结果。

合法生命周期顺序会默认拒绝。成功的完整清单可以产生
`runtime_binding_observed`；相同清单不产生记录，且只有成功的完整清单才能
因缺席产生 `runtime_binding_retired`。稳定身份替代项的顺序是先写
`reason=identity_transition` 缺口，再退役旧身份，最后观测替代项。运行时来源丢失
先写 `reason=socket_unavailable` 或 `reason=inventory_invalid` 缺口，再暂停；只有后续最新
完整清单才能再次观测该绑定。守护进程恢复将持久绑定保持休眠；首次
最新完整清单先写 `reason=daemon_restart` 缺口，再退役休眠身份，并在当前
身份存在时写入已观测记录。失败永远不等于空清单。不存在独立的转换记录；规范身份转换
表示法就是有序的“缺口 -> 已退役 -> 已观测”序列。

Kubernetes 归属生命周期记录具有下列精确封闭结构：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `record_type` | 枚举 | `kubernetes_attribution_observed`、`kubernetes_attribution_retired` 或 `kubernetes_attribution_suspended` |
| `schema_version` | u32 | 常量 `1` |
| `agent_run_id` | 字符串 | 所属规范智能体运行 ID |
| `cluster_id` | 字符串 | 操作者配置的规范小写非零 UUID |
| `namespace_ref` | 字符串 | 64 字节小写十六进制、带域分隔的隐私引用 |
| `pod_uid` | 字符串 | 规范小写非零 Kubernetes Pod UUID |
| `node_ref` | 字符串 | 64 字节小写十六进制、带域分隔的隐私引用 |
| `runtime_class_ref` | 字符串或空值 | 相同的 64 字节隐私引用，或显式 `null` |
| `container_kind` | 枚举 | `application`、`init` 或 `ephemeral` |
| `container_ref` | 字符串 | 64 字节小写十六进制、带域分隔的隐私引用 |
| `runtime_binding` | 对象 | 属于同一智能体运行的完整有效 v1 `runtime_binding_observed` 对象；适配器恰好为 `containerd` 或 `k3s_containerd` |

生命周期键是 `(cluster_id,pod_uid,container_kind,container_ref)`。观测要求嵌入的 D1 身份
已经生效。暂停或退役必须匹配完整的生效 K1 身份，并且 K1 必须在其
D1 身份结束前先结束。K1 暂停会消费同集群与生效键之前一条尚未匹配的
API／运行时／快照不可用缺口的授权额度。重启、身份转换与延迟挂接缺口都是
可见边界，但不授权暂停。`claim_revision`、原始名称、`pod_revision_ref`、来源
纪元／序列号、标签、注解、路径、PID、端点、令牌与后端文本都不是传输格式字段。

AOR 投影器会严格解码这三种记录类型，把每条记录绑定到投影中的智能体运行，并
跟踪生效 `(adapter,workload_id)` 键。重复观测，或完整身份与生效绑定
不匹配的退役／暂停都会触发默认拒绝。暂停还必须消费同一适配器之前一条
尚未匹配的来源中断缺口授权额度；授权额度只能消费一次，但允许跨越无关的交错记录。由于
v1 没有清单事务 ID，投影器不会猜测身份或守护进程重启缺口属于哪一次退役。更强的生效
顺序仍由生产者／协调器保证，而每条此类缺口仍会使投影证据不完整。

`observer_diagnostic` 有必需字段 `record_type:string`（常量 `observer_diagnostic`）、
`timestamp_unix_ms:u128`、`session_id:string`、`kind:enum`、`count:u64` 与
`detail:string`。种类是 `ring_buffer_reserve_failure`、`map_pressure`、
`abi_mismatch`、`decode_failure`、`truncation`、`attach_failure`、
`verifier_failure` 或 `summary`。`visibility_assessment` 有必需字段
`record_type:string`（常量 `visibility_assessment`）、`session_id:string`、`runtime_profile:enum`、
`host_visibility_scope:enum`、`host_semantics_collapsed:boolean`、
`guest_collector_required:boolean`、`runtime_metadata_required:boolean`、
`host_event_subjects:array<string>`、`pod_name:string|null`、
`namespace:string|null`、`runtime_class_name:string|null`、
`sandbox_name:string|null` 与 `notes:string`。运行时配置档是
`docker-default`、`docker-gvisor`、`kubernetes-gvisor`、`kubernetes-kata` 或
`firecracker-prototype`；主机范围是 `guest_process`、`runtime_boundary` 或
`boundary_only`。

### 6.2 本地会话（Session）查询模式 v1

本地守护进程查询不是时间线记录。合法的
`{"type":"query","tenant_id":"<tenant>","session_id":"<agent-run>"}` 请求返回下列
`DAEMON_SCHEMA_V1` 响应：

| 字段 | 类型 | 值或含义 |
| --- | --- | --- |
| `type` | 字符串 | 常量 `session` |
| `schema_version` | u32 | 常量 `1` |
| `session` | 对象或空值 | 匹配的 `SessionState`；不存在或对该租户不可见时为 `null` |
| `runtime_bindings` | 对象数组 | 该可见智能体运行的生效绑定；始终存在，`session` 为 `null` 时为空数组 |
| `kubernetes_attributions` | 对象数组 | 该可见智能体运行中生效且刚完成资格验证的 K1 记录；始终存在，`session` 为 `null` 时为空数组 |

每个 `runtime_bindings` 元素恰好包含下列必需嵌套字段：

| 字段路径 | 类型 | 值或含义 |
| --- | --- | --- |
| `agent_run_id` | 字符串 | 与请求及返回 `session` 相同的智能体运行 |
| `identity.adapter` | 枚举 | `docker`、`containerd` 或 `k3s_containerd` |
| `identity.workload_id` | 字符串 | 上述完整稳定工作负载／容器 ID |
| `identity.start_marker` | 字符串 | 运行时原生启动标记 |
| `identity.host_boot_id` | 字符串 | 规范的主机启动 UUID |
| `identity.init_process_start_time_ticks` | u64 | 正数初始进程启动时钟滴答 |
| `identity.cgroup.device` | u64 | 正数 cgroup 文件系统设备身份 |
| `identity.cgroup.inode` | u64 | 正数 cgroup 文件系统 inode 身份 |
| `runtime_handler` | 字符串或空值 | 有界不透明处理器名称，或 `null` |

两个数组都只包含生效且刚完成资格验证的状态；休眠、已暂停与已退役条目不会返回。运行时
绑定按适配器／工作负载键排序，Kubernetes 归属按其精确
生命周期键排序。每个 `kubernetes_attributions` 元素都具有上文封闭 K1 传输格式结构，并
引用一条返回的生效 D1 绑定。省略 `tenant_id` 时默认为 `default`。守护进程会先
要求请求租户等于目标智能体运行的注册租户，之后才读取绑定。`session`、
`runtime_bindings` 与 `kubernetes_attributions` 来自同一个受租户隔离约束的原子快照，因此并发租户
替代不能把授权判断与工作负载披露分离。不存在或跨租户的智能体运行会返回 `session:null`、
`runtime_bindings:[]` 与 `kubernetes_attributions:[]`，避免工作负载身份成为跨租户存在性
探测信号。查询保持与持久化相同的隐私边界：它不暴露原始标签、注解、命名空间、节点、
容器名称、PID、cgroup／运行时／套接字路径、端点、后端错误或载荷。

### 6.3 智能体观测记录（Agent Observation Record）v1

投影是一份确定性 JSON 对象，绝不是时间线中的一行。输入保持命令行与分段顺序；每条投影
来源事实使用从 1 开始的 `source_ordinal`，时间戳不会重排记录。

| 顶层字段 | 类型 | 约定 |
| --- | --- | --- |
| `record_type` | 字符串 | 常量 `agent_observation_record` |
| `schema_version` | u32 | 常量 `1` |
| `agent_run_id` | 字符串 | 所有来源记录共用的非空运行 |
| `source_integrity` | 枚举 | `unverified_plain_jsonl`、`verified_hash_chain` 或 `mixed` |
| `summary` | 对象 | 下列状态与确定性聚合 |
| `capability_manifests` | 对象数组 | 投影后的兼容清单 |
| `runtime_identities` | 对象数组 | 精确身份聚合 |
| `runtime_observations` | 对象数组 | 规范的受支持观测 |
| `runtime_bindings` | 对象数组 | 有序、经过验证的运行时绑定生命周期事实；新的 v1 输出始终包含该字段 |
| `kubernetes_attributions` | 对象数组 | 有序、经过验证的 K1 生命周期事实；新的 v1 输出始终包含该字段 |
| `collector_lifecycle` | 对象数组 | 有序生命周期事实 |
| `findings` | 对象数组 | 类型化复查发现项 |
| `observation_gaps` | 对象数组 | 规范化有界缺口 |
| `issues` | 对象数组 | 投影限制 |

必需的 `summary` 字段包含三个枚举（`evidence_state`：
`complete|active|incomplete|failed|indeterminate`，`collector_health`：
`healthy|degraded|failed|unknown`，`review_state`：
`requires_review|no_findings_reported|indeterminate`）、六个 `u64` 计数
（`runtime_observation_count`、`runtime_identity_count`、`finding_count`、
`observation_gap_record_count`、`known_missing_observation_count`、
`unknown_history_boundary_count`）以及五个 `map<string,u64>` 聚合
（`event_type_counts`、`outcome_counts`、`relation_counts`、
`finding_kind_counts`、`gap_kind_counts`）。

嵌套数组对象模式如下：

| 数组／对象 | 必需字段与类型 |
| --- | --- |
| 能力清单 | `source_ordinal:u64`、`schema_version:u32`、`timestamp_unix_ms:u128`、`collector:string`、`collector_version:string`、`kernel_abi_version:u32`、`kernel_record_size:u32`、`observation_scope:string`、`privacy_profile:string`、`capabilities:array<object>` |
| 能力 | `operation:string`、`event_sources:array<string>`、`outcomes:array<string>` |
| 运行时身份 | `identity_id:string`、`host_boot_id:string`、`scope_generation:u64`、`pid:u32`、`process_generation:u64`、`process_start_time_ns:u64`、`exec_generation:u32`、`first_source_ordinal:u64`、`last_source_ordinal:u64`、`observation_count:u64` |
| 运行时观测 | `source_ordinal:u64`、`timestamp_unix_ms:u128`、`event_source:string`、`event_type:string`、`raw_event_id:string|null`、`pid:u32`、`ppid:u32`、`actor:string`、`resource:string`、`action:string`、`outcome:string|null`、`return_value:i64|null`、`errno:i32|null`、`container_id:string|null`、`cgroup_id:string|null`、`relation_status:string`、`relation_reason:string`、`process_executable:string|null`、`process_started_at_unix_ms:u128|null`、`runtime_identity_id:string|null`、`parent_process_generation:u64|null`、`parent_exec_generation:u32|null` |
| 运行时绑定 | `source_ordinal:u64`、`record_type:enum`、`schema_version:u32`、`agent_run_id:string`、`adapter:string`、`workload_id:string`、`start_marker:string`、`host_boot_id:string`、`init_process_start_time_ticks:u64`、`cgroup_device:u64`、`cgroup_id:u64`、`runtime_handler:string|null`；后十一个字段是精确的运行时绑定 v1 生命周期传输格式结构 |
| Kubernetes 归属 | `source_ordinal:u64` 加上文精确、封闭的十一字段 K1 生命周期传输格式结构，包括嵌套运行时绑定对象 |
| 采集器生命周期 | `source_ordinal:u64`、`schema_version:u32`、`timestamp_unix_ms:u128`、`collector:string`、`collector_instance_id:string`、`state:enum`、`health:enum`、`stop_reason:enum|null`、`counters:object`；计数器与时间线生命周期使用相同八个 `u64` 字段 |
| 发现项 | `source_ordinal:u64`、`schema_version:u32`、`kind:enum`、`decision:enum`、`reason:string`、`evidence_ref:string`、`runtime:object`、`evidence_boundary:enum`；运行时使用 `runtime:string`、`container_id:string|null`、`pod_uid:string|null`、`cgroup_id:u64|null` |
| 观测缺口 | `source_ordinal:u64`、`schema_version:u32`、`timestamp_unix_ms:u128`、`operation:string`、`kind:string`、`count:u64`、`detail:string`；使用上表规范化值，并包含下文定义的可选成对 `runtime_source:string`/`runtime_reason:string` 或 `kubernetes_cluster_id:string`/`kubernetes_reason:string` 字段 |
| 问题 | `code:enum`、`source_ordinal:u64|null`、`count:u64` |

版本 1 最多接受一份能力清单；重复清单属于结构错误，不会创建第二个能力纪元。嵌套的生命
周期、观测、发现项与缺口对象使用上文对应的时间线枚举值和规范投影。

`runtime_bindings` 是默认兼容的 v1 扩展。新的投影输出始终包含该数组；缺少该字段的旧版
v1 AOR 会按空数组读取。该数组保留每条经过验证的
`runtime_binding_observed`、`runtime_binding_retired` 与 `runtime_binding_suspended` 事实，而不只
保留运行结束时生效的绑定。每个元素都属于投影中的智能体运行，并保持权威
`source_ordinal` 顺序。投影器与冻结记录验证器都会重建生效绑定状态，并执行 6.1 节的生命
周期身份与序列规则。

`kubernetes_attributions` 使用相同的默认兼容 v1 扩展规则：新的投影输出始终包含该数组，
旧版 v1 记录可以把缺失字段读取为空。投影器按来源顺序保留每条经过验证的 K1 已观测、
已退役与已暂停事实，共同重放运行时／K1 状态，要求被引用的 D1 观测先于 K1 观测，K1
退役／暂停先于 D1 结束，并且每个 K1 暂停授权额度只消费一次。冻结记录验证器会重复这些
检查。已保存运行查看器渲染独立的 K1 生命周期面板，并把每条 K1 事实链接到其精确 D1
绑定来源事实，而不重建原始 Kubernetes 名称。

当发现项的 `evidence_ref` 为 `runtime_binding:<workload_id>` 时，只有同一运行中先于该
发现项出现，且 `adapter`、`workload_id`、`cgroup_id` 与发现项的运行时、容器 ID、
cgroup ID 精确匹配的 `runtime_binding_observed` 事实才能解析该引用。已退役或已暂停事实
即使字段匹配也绝不提供支撑。已保存运行查看器会在每个绑定事实的来源序号处提供跳转目标，
并允许受支持的发现项跳转到那条更早、精确匹配的已观测事实；无法解析的引用继续作为限制
保留。

新投影的 `runtime_metadata_unavailable` 缺口会同时包含 `runtime_source` 与
`runtime_reason`。来源只能是 `docker`、`containerd` 或 `k3s_containerd`；原因只能是
`socket_unavailable`、`inventory_invalid`、`daemon_restart` 或 `identity_transition`。其他缺口
种类会省略这两个字段。这对字段属于默认兼容的 v1 扩展：旧版 AOR 可以省略，但缺失或只
出现一项时，绝不能授权后续 `runtime_binding_suspended`。冻结记录验证器
会按 `source_ordinal` 顺序共同重放缺口与绑定事实。只有同适配器、更早且尚未消费、
原因为 `socket_unavailable` 或 `inventory_invalid` 的缺口才授予一次暂停授权额度；
`daemon_restart` 与 `identity_transition` 不授予暂停授权额度，每个授权额度只能消费一次。

对 `kubernetes_metadata_unavailable`，投影会把来源详情替换为 6.1 节的规范化
有界详情，并增加必需的 `kubernetes_cluster_id` 与 `kubernetes_reason` 字段。原因恰好是
该节列出的六种 K1 原因之一。其他缺口会省略这两个字段。每条 K1 缺口都增加一个
`observation_gap` 问题并阻止完整证据；延迟挂接表示一个关系边界，不是
缺失系统调用数量。

问题代码恰好是 `missing_capability`、`unsupported_capability`、
`missing_lifecycle_start`、`missing_lifecycle_terminal`、`collector_loss`、
`collector_diagnostic`、`observation_gap`、`unsupported_observation`、
`unsupported_outcome`、`unknown_record_type`、`source_integrity_finding`、
`no_runtime_observations` 或 `unresolved_finding_evidence`。空问题序号表示整次运行问题，
不是复制的来源事实。
`unsupported_capability` 计数等于其清单中缺失或不匹配的约定操作数。
绑定来源的不支持观测／结果、未知记录、完整性与未解析发现项问题各计数 1。
`observation_gap` 与 `collector_diagnostic` 保留来源计数。整次运行的缺失能力、缺失启动、
无观测与混合完整性问题计数为 1；缺失终止问题计数等于未完成采集器实例数。
`collector_loss` 指向最新的有丢失生命周期记录，计数为 1。

精确身份由生效 `collector_instance_id` 限定，并要求
`event_source=kernel_tracepoint`、非空的规范 `raw_event_id`、
关系 `exact` 且原因为 `host_boot_scope_process_start_exec_generation`，并具有完整元组
`(host_boot_id,scope_generation,pid,process_generation,process_start_time_ns,exec_generation)`。
首次出现依次分配 `identity-1`、`identity-2`。非精确事实保持不合并。完整证据要求兼容的
原文不落盘清单、合法的正常生命周期终止、至少一条受支持观测，且不存在丢失、缺口、诊断、
完整性、能力或未解析证据问题。发现项只改变复查状态；`no_findings_reported` 不是“运行
无异常”的判定。

执行能力检查时，投影后的事件类型按如下方式映射：`exec` 到 `process_exec`，
`process_exit` 到 `process_exit`，各 `file_*` 事件到同名操作，`network_connect` 到
`network_connect`，`credential_read` 到 `credential_path_access`。其他事件类型以及任何
非 `kernel_tracepoint` 来源都增加 `unsupported_observation`；缺失或未声明的结果增加
`unsupported_outcome`。

### 6.4 本地哈希链封装

哈希链时间线是 JSONL，每行都有必需的 `schema_version:u32`、`sequence:u64`、
`previous_hash:string`、`record_hash:string` 与 `payload:object`。序列号从 `1` 开始；首条
前序哈希是 64 个小写零字符，之后每条 `previous_hash` 等于前一条 `record_hash`。载荷在解析
JSON 后递归序列化为紧凑 UTF-8 JSON，以完成规范化：对象键按字典序排序，数组顺序保留，
不添加无意义空白或斜杠转义；字符串转义 JSON 控制字符、引号与反斜杠；数字使用最短的
serde-json 表示形式（时间线约定只使用整数）。小写十六进制记录摘要是：

```text
SHA-256(
  schema_version 的 4 字节无符号大端表示
  || sequence 的 8 字节无符号大端表示
  || previous_hash 的 UTF-8 字节
  || 紧凑规范载荷 JSON 的 UTF-8 字节
)
```

这四段字节串之间没有分隔符或长度前缀。验证会检查预期序列号、链接、规范化载荷摘要与
完整末行。报告包含 `path:string`、`passed:boolean`、
`record_count:integer`、`last_sequence:u64`、`last_record_hash:string`、
`valid_bytes:u64`、`total_bytes:u64` 与 `failure:string|null`。验证只读；中段损坏、
截断或损坏尾部都会默认拒绝。

规范关联使用原始内核 `event_id`、规范 `raw_event_id`、可选意图
`raw_event_id`、关联的 `raw_event_id` 与发现项 `evidence_ref`。
对于运行时绑定证据，有界发现项引用只会按 6.3 节的精确规则连接到更早的
已观测生命周期来源序号；已退役与已暂停生命周期事实不属于该支撑
关系。只依赖时间戳的匹配永远不会创建精确关系。原始 exec argv 会替换为脱敏／截断标记；
凭证路径与套接字地址在输出前会被标记化。轮转属于存储预算，不是模式变更，
并且永远不会拆分一条 JSONL 记录。

每条运行时观测在受支持时携带：

- 模式与采集器 ABI 版本；
- 运行与观测标识符；
- 来源序列号与观测时间；
- 运行时身份与范围引用；
- 操作族与规范化动作；
- 有界、脱敏的资源身份；
- 已尝试／成功／失败／拒绝／待定／未知结果；
- 能力声明支持时的返回值或 errno；
- 截断与解码状态；
- 关系状态与原因。

采集器生命周期记录为每个采集器进程使用一个不透明实例 ID，并为每次智能体运行维护一条
记录流。`started` 会在放行托管智能体或完成守护进程范围注册前持久化。周期 `checkpoint`
携带累计丢失计数器与当前 `scope_pending` 运行中度量值，即使
工作负载安静也会发出。`global_*` 计数器描述采集器全局丢失；复制到每个活跃运行
时仍保留该命名。`scope_*` 计数器只包含所属观测范围的入口与退出配对状态；对
守护进程而言，它只汇总属于该智能体运行的 cgroup。非零丢失计数器会让检查点标记为
`degraded`。采集仍活跃时，只有待定项仍可保持健康；到终止时，它代表停止时未匹配的工作，
因此会使终止状态降级。

对受保护的现有进程挂接，持久启动边界按以下顺序追加并同步：强制的
`late_attach` 缺口、采集器能力清单、`started`。缺口的 `count:1` 表示一个
历史未知采集边界。其 `root_selection` 详情描述 `registration_qualified` 注册或 `inferred`
发现选择；它不会扩展或覆盖事件
规范中的 `exact`、`inferred`、`ambiguous` 与 `unattributed` 关系状态。
`registration_qualified` 只描述打开 pidfd 时可见的 root，不证明锚定前连续性。这三条记录
会作为一个持久批次序列化：轮转对整个批次只评估一次；写入或同步失败时，生效文件会先
截断回批次写入前的长度，然后挂接才失败。

守护进程检查点与终止会先等待序列号屏障；该屏障覆盖边界之前所有已被处理流水线接纳的
记录。随后生命周期边界直接追加到每个智能体运行的哈希链，因此有界队列即使已满也不能
丢弃它，后来的高优先级流量也不能让它越过旧证据。普通写入器失败会暂停受影响的智能体
运行，并异步发送范围失败；唯一写入器不会同步等待观测器取消跟踪，也不会等待这次取消
跟踪产生的失败终止记录。

正常路径会先确认事件排空与观测缺口已持久化，再写入带明确原因的 `stopped`。致命挂接、
验证器、ABI、解码器、计数器、观测器或可写存储路径故障会在
时间线仍可写时记录 `failed`。守护进程恢复时，缺少 `stopped` 或 `failed` 的 `started` /
`checkpoint` 实例会得到一次 `collector_restart` 观测缺口和一个恢复生成的失败
终止；重复恢复不会重复写入。独立时间线缺少终止时仍是不完整证据，即使
原进程已无法补写缺口。

运行时元数据丢失使用一种有界 v1 结构：

```json
{"record_type":"observation_gap","schema_version":1,"agent_run_id":"<agent-run>","operation":"runtime_metadata","kind":"runtime_metadata_unavailable","count":1,"detail":"source=docker,reason=socket_unavailable"}
```

`source` 只能是 `docker`、`containerd` 或 `k3s_containerd`。来源中断 `reason` 只能是
`socket_unavailable`、`daemon_restart` 或 `inventory_invalid`；相同工作负载键的稳定身份
变化使用 `reason=identity_transition`。禁止路径、载荷、套接字名称与自由文本后端错误。
智能体观测记录会把中断详情规范化为 `runtime_source_unavailable`，把身份变化规范化为
`runtime_identity_transition`，同时将有界来源与原因保留在 `runtime_source` 与
`runtime_reason`。它会增加一条 `observation_gap` 问题，并且不能成为完整。由于运行时
适配器可以独立配置，这种缺口不要求 eBPF 采集器已有 `started` 生命周期记录。
身份转换的持久生效顺序是缺口、退役、挂接。

智能体观测摘要暴露三条相互独立的结论：

- `evidence_state` 为 `complete`、`active`、`incomplete`、`failed` 或 `indeterminate`；
- `collector_health` 为 `healthy`、`degraded`、`failed` 或 `unknown`；
- `review_state` 为 `requires_review`、`no_findings_reported` 或 `indeterminate`。

完整证据要求存在一份兼容的原文不落盘能力清单、从合法 `started` 到正常终止的生命周期、
至少一条受支持运行时观测，并且没有丢失、缺口、诊断、完整性或能力问题。生效或失败的
生命周期状态必须显式保留。混合来源完整性与未知增量记录类型会让其他方面呈完整结构的
运行成为 `indeterminate`。发现项只改变复查状态，不改写证据完整性。`late_attach` 的计数 1
只增加历史未知边界计数，不增加已知缺失事件计数。混合智能体运行、格式错误或不兼容记录、
内容策略违规、
非法生命周期顺序、重复规范观测与冲突的精确运行时身份都默认拒绝。

消费者忽略未知的增量字段。不兼容的 ABI 或模式变更必须使用新版本并显式报告解码失败，
不能尽力猜测其含义。

## 7. 受支持操作集合

| 类别 | 测试版目标 | 声明边界 |
| --- | --- | --- |
| 进程 | fork／clone 谱系、exec、退出 | 进程生命周期，不是逻辑子智能体语义 |
| 文件 | 选定的打开／创建／截断／重命名／删除路径 | 只覆盖受支持操作与已解析身份，不是通用文件系统历史 |
| 凭证 | 内置凭证类别的路径访问 | 路径访问发现项，不证明秘密已被使用 |
| 网络 | 出站连接元组与结果 | 连接尝试／结果，不证明远端变更或 TLS 内容 |
| 健康状态 | 挂接、丢失、映射表压力、解码、截断、终止状态 | 采集器状态，不是主机完整性证明 |

只有真实调查需要，且隐私与性能成本有界时，才扩大操作广度。不受支持的 io_uring、
文件系统、网络、客体或运行时路径会形成显式能力缺口。

## 8. 环境模型

| 环境 | 运行时观测约定 |
| --- | --- |
| 本地 Linux CLI | 托管启动或受保护的进程树挂接 |
| Linux 自托管 CI | 使用相同 CLI 托管运行边界；执行器隔离由外部提供 |
| Docker/containerd | 主机 eBPF 观测关联容器与 cgroup 身份 |
| Kubernetes containerd/K3s | 已实现 K1 节点 eBPF 观测与已授权 Pod／容器／cgroup 身份的关联；完成指定实机资格验证前仍为实验级（`Experimental`） |
| gVisor | 主机／运行时边界可见性，不是每个客体系统调用 |
| Kata 或 Firecracker | 主机／VMM／shim 可见性；客体语义需要客体采集器 |
| macOS 或 Windows | 不支持 eBPF 运行时观测 |
| 厂商托管智能体运行时 | 没有用户可控 Linux 内核时不属于范围 |

机器可读资格权威位于源码树的
[资格验证封装](https://github.com/0xLaiHo/Apolysis/blob/main/qualification/envelope-v1.json)，
其版本化工作负载定义位于相邻的 `qualification/workloads/` 目录。发布文档
归档只是人类可读快照，不内嵌这些机器文件；执行配置档资格验证或晋级的
消费者必须使用匹配来源修订号中的封装。Linux 6.12/x86_64 原生主机仅为
候选级（`Candidate`），尚非正式支持（`Supported`）：它要求 cgroup v2、可读目标 BTF/tracefs、19 个声明
tracepoint 及其经过检查的格式、生产验证器／加载／完整挂接路径，以及有效
`CAP_BPF` + `CAP_PERFMON`。其他经过功能探测的 Linux 5.11+ x86_64 内核、aarch64、Docker、
containerd、Kubernetes 与旧版 `CAP_SYS_ADMIN` 回退保持实验级（`Experimental`）。缺少必要挂钩、
cgroup v1／混合范围、无 root 主机采集、非 Linux，或低于功能下限且无向后移植
的内核为不支持。

资格验证使用版本化无内容的 `idle`、`representative` 与 `burst` 工作负载。同一次主机启动中
配对的采集器关闭／开启试验分别保留工作负载／采集器 CPU、进程／cgroup／BPF 内存、单调的
内核到解码／追加延迟、完整的预期／已观测／丢失事件映射表，以及按阶段归属的突发丢失。
代表性配置档要求已知与无法解释的丢失都为 0。CPU、内存、延迟、重复次数与额定事件数值
预算，在足量特权实机证据支持经过复查的保守边界前保持未设置。夹具只测试检查器，不能
晋级配置档。晋级正式支持（`Supported`）需要保留原始实机证据、在机器封装中冻结预算与精确元组、通过
隐私／过载复查，
并关闭全部适用发布门禁。

可见性声明按配置档区分。具备精确容器／cgroup 身份时，Docker 默认配置通常保留客体进程
的主机语义。gVisor 可能把观测收缩到运行时边界，
因此关联需要运行时元数据。Kata 与 Firecracker 只暴露 VMM／shim／主机边界；完整的客体
进程、文件、网络或凭证语义需要客体采集器。Kubernetes 元数据无法恢复主机来源没有观测
到的客体语义。

## 9. 发现项与控制

发现项是观测后的复查辅助信息。首个有界集合包括：

- 访问内置凭证类别路径；
- 在配置的工作区边界外修改文件；
- 在可以解析时连接未批准的地址或域类别；
- 执行非预期二进制类别；
- 采集退化并违反本次运行所要求的观测配置档。

发现项永不宣称操作已经被阻止。BPF-LSM 与 seccomp 阻止原型不属于当前产品。

## 10. 隐私与安全

- 提示词、响应、原始工具载荷与完整 argv 默认原文不落盘。
- 持久化的可执行文件身份经过允许列表约束且有界；秘密值与私有路径在存储前
  脱敏。
- 注册的主机／启动／可执行文件／命令指纹／工作区值是资格校验输入。完整可执行文件路径、
  工作区路径与命令指纹不跨越持久化边界；只保留有界身份与脱敏监督器元数据。
- K1 持久化操作者定义的集群 UUID、Pod UID、容器种类，以及带域分隔的命名空间／节点／
  容器／运行时类引用。原始 Pod 名称、命名空间／节点名称、标签、注解、资源版本、令牌与
  来源错误正文都不跨越持久化或诊断边界。投射令牌只挂载到非 root 来源容器；root 采集器
  没有 Kubernetes API
  凭证。
- K1 隐私引用是确定性的无密钥假名，不是秘密或匿名机制。低熵
  标识符仍可枚举，引用仍可跨运行链接；Pod UID 与完整运行时容器身份按
  约定保持显式。
- 原始内核载荷只是有界实现细节，没有显式复查配置档时不得跨越持久化边界。
- 观测范围防止意外的全主机采集。
- 本地文件使用限制性权限与有界留存。守护进程生命周期变更只接受由清单／收据证明所有权
  的固定制品集合，在变更前拒绝有链接项或非托管替换，并在默认卸载中保留已保存智能体运行。
- 查看器是非特权组件，无法接触 BPF 映射表、主机 PID 命名空间、容器套接字或节点
  凭证。
- 独立查看器会转义所有存储文本，并使用禁止网络连接与外部资源的限制性内容安全策略。
  该制品包含投影后的运行事实，因此保留模式为 `0600` 的发布语义。

## 11. 失败语义

下列情况始终产生显式缺口，或使采集器进入失败／降级状态：

- 环形缓冲区预留失败或映射表压力；
- 资源或载荷截断；
- 内核／用户空间 ABI 不匹配；
- 解码、挂接、验证器或权限失败；
- 采集器重启或终止；
- 运行时套接字丢失、守护进程重启、非法运行时清单或陈旧容器身份
  转换；
- Kubernetes API/CRI 丢失、非法或变化的 A/B Pod 快照、来源纪元/守护进程重启、K1
  身份转换或 K1 延迟挂接；
- 延迟挂接、PID 复用歧义或缺失进程谱系；
- 不支持的系统调用、io_uring、客体或远程操作路径；
- 本地存储失败或终止刷新不完整。

安静的时间线永远不能证明智能体没有执行相关动作。

## 12. 当前实现映射

当前已实现：

- `ebpf/observer` 与 `apolysis-observer`：CO-RE tracepoint、环形缓冲区、
  进程树/cgroup 范围、ABI v3、有界进程/exec 与 cgroup 范围代次、
  结果感知的选定文件操作与网络连接、受保护现有进程的 TGID 初始集合、按 cgroup 统计的
  操作缺口计数器、脱敏、生命周期检查点／终止以及健康状态／缺口
  诊断；
- `apolysis-cli`：夹具／实时观测、托管智能体启动、通过注册或发现
  完成的受保护的现有进程挂接、非特权已保存运行投影与已保存运行查看器
  发布、可选 Codex 意图关联、可见性、验证与有界守护进程安装／检查／卸载命令；
- `apolysis-core`：当前 JSONL 词汇表、记录类型、版本化采集器能力
  清单与采集器生命周期模式，包括由生产者与投影共同消费的唯一
  生命周期词汇表和完整 AuditObserver v1 操作／来源／结果约定；
- `apolysis-store`：轮转、可选本地哈希链封装、禁止跟随链接且绑定描述符的恢复，以及读取
  普通／轮转或已验证的已保存运行时所用的有界稳定快照读取器；
- `apolysis-accountability`：智能体观测记录的纯函数式投影、相互独立的摘要维度、可选声明意图对比、
  类型化 K1 授权声明准入／生命周期验证与面向复查的发现项；
- `apolysis-viewer`：严格验证智能体观测记录 v1，并提供带运行时／K1 来源可追溯性的确定性
  独立离线 HTML 展示；
- `apolysis-kubernetes`：纯函数式、有界的 A／运行时／B 资格验证协调器、声明求交、K1 生命周期、
  中断／重启恢复与精确 D1 关联；
- `apolysis-kubernetes-source`：非 root、限定命名空间的 Pod 列表查询／变更监听来源，以及严格、
  符合隐私约束的 Unix IPC 协议；
- `apolysis-visibility`：可见性边界评估；
- `apolysis-daemon`：长期运行的观测器、有界队列、本地套接字、运行时注册、
  完整 Docker/containerd 清单资格验证、稳定容器/cgroup 绑定、有界
  运行时来源与守护进程重启恢复、两阶段 K1／运行时生命周期持久化与恢复、租户隔离查询、
  限定范围的采集器生命周期、幂等的未完成实例恢复、由收据证明归属的本地运维，以及基于身份
  校验并记录事务日志的留存；
- `apolysisd-control` 与 `deploy/kubernetes`：类型化操作者入口与最小权限双容器
  节点 DaemonSet 约定。

实时采集器会在成功挂接后、释放托管智能体门禁前把能力清单与生命周期启动同步到稳定存储；
对受保护的现有进程挂接，它会先持久化唯一的历史未知
`late_attach` 边界。选定文件操作与网络连接已具备有界入口与退出结果语义，守护进程会在
显式移除范围与正常关闭时把这些配对缺口持久化到所属智能体运行。单次运行内
稳定的范围/进程代次、周期累计生命周期检查点、显式终止原因与
重启缺口恢复、可查询已保存运行投影与非特权已保存运行查看器已经实现。Docker/containerd
稳定身份与运行时恢复已通过类型化运行时元数据缺口实现。保留的非破坏性 Docker 门禁覆盖
完整清单身份变化、套接字中断恢复、私有守护进程生命周期恢复，以及具备能力与哈希链证据
的原文不落盘 eBPF 精确容器／cgroup 归属。独立、保留的私有 containerd 门禁按 5.3 节的
隔离与清理约定，覆盖稳定／替代项完整清单以及“套接字缺口 -> 暂停 -> 最新观测”。K1 实现
已覆盖类型化授权声明、符合隐私约束的 Pod 元数据、完整 A／运行时／B 闭合、应用／初始化／临时容器、
D1 复用、已观测／已退役／已暂停生命周期、显式 API／CRI／快照／重启／转换／延迟挂接
缺口、租户隔离查询、AOR 投影与查看器导航。在组合路径中，D1 协调只接收由精确授权声明与 A/B
求交授权的完整身份键；原始路由候选项不能挂接范围。确定性与部署约定已在本地通过，但本
工作区因缺少所需 kubeconfig 与 `kubectl`，尚未运行指定 VKE 实机资格验证。预检结果是跳过，
不是通过，也不会晋级 Kubernetes。破坏性 systemd 运行时服务重启与发布资格验证仍未完成。
本地有界守护进程文件系统操作已实现；当前没有授予任何正式支持（`Supported`）的实机主机配置档。

中央约定、网关、PostgreSQL 投影、证据对象集群、策略／反馈／控制平面、沙箱执行器与
大范围资格验证机制已移出当前工作区。Git 历史保留它们作为历史实现输入；它们不定义本文
架构。

## 13. 限制

- 本地守护进程运维只面向文档化的 Linux/systemd 布局与 5 个固定运行时制品；它不是发行版
  软件包管理器，也不是可安装到任意前缀的通用安装器。暂存根目录验证证明有界文件系统
  行为，不证明特权激活；实机声明需要显式 systemd/eBPF 门禁。默认卸载有意不清除已保留的
  智能体运行。事务配置档要求 procfs 可用，且托管文件系统支持 Linux `O_TMPFILE` 与
  `renameat2`；不支持的主机会在发布前失败。
- L3 渲染一份有界、本地、冻结的智能体观测记录 v1。它不是实时追踪、跨运行搜索、远程
  查询界面或中央查询平面。
- 智能体观测记录 v1 缺少权威父运行时身份链接。查看器可以展示精确运行时身份清单，以及
  每条观测报告的 PID/PPID，但不能依赖不安全的基于 PID 推断来构造规范进程树。
- K1 限于每个 DaemonSet Pod 一个命名空间／节点、一个显式配置的 containerd 或 K3s 运行时
  域、处于 `READY` 状态且已标记的 Pod 沙箱，以及针对应用／初始化／临时容器槽位的精确
  类型化授权声明。它不观测以 Docker 为后端的 Kubernetes、任何未获授权声明覆盖的 Pod、一个来源令牌下的
  多个命名空间，或无法形成精确 D1 身份的运行时／容器元数据。
- 规范 DaemonSet 只支持自身专用智能体命名空间。不能针对每个工作负载命名空间复制并共享
  同一节点运行时：一个节点观测器必须独占运行时域。全集群或跨命名空间归属需要重新设计
  授权与来源边界。
- 专用命名空间必须由操作者控制。精确授权声明会阻止 Pod 写入器获得其他运行的 D1／范围，但
  格式错误的已标记沙箱会按设计使完整扫描失败，并可降低节点 K1／运行时可用性；K1 不抵抗
  这种已获命名空间权限的拒绝服务攻击。
- 直接拥有主机 CRI 套接字会使采集器受节点信任，因为协议包含变更方法。能力与令牌隔离会
  收敛权限，但不强制只读访问；这需要未来的允许列表代理。
- K1 变更监听只触发最新采集。权威来源是围绕一次完整 CRI 清单的两次完整 Pod 列表，因此 API
  分页或运行时延迟会限制收敛速度，持续变化可能重复产生显式快照缺口。节点本地状态不提供
  无缺口的跨节点交接：重新调度的 Pod 使用新 UID，并在目标节点上独立完成资格验证。
- eBPF 看到内核/运行时操作，看不到逻辑推理或隐藏的远程服务提供方状态。
- 相对路径、fd 相对操作、命名空间、叠加层与客体运行时需要显式解析和能力限制。
- 成功连接不证明远端操作已经提交。
- 没有额外传播身份时，无法区分同进程中的逻辑智能体；仅依赖运行时的归属保持在进程级别。
- 受保护的现有进程挂接只支持初始 PID 命名空间，以及共享、未偏移的初始时间命名空间。
- 针对每个初始候选项的 pidfd 双重校验与退出挂钩会消除候选项锚定后的退出与换代竞态，
  但不能建立锚定前的选择连续性：外部注册的 root 可能在注册创建到 root `pidfd_open` 之间，
  被具有相同 PID、USER_HZ 时钟滴答、可执行文件与命令的进程替换；谱系候选项也可能在快照
  到 `pidfd_open` 之间，被具有相同 PID、时钟滴答与谱系的进程替换。这些有界的同一时钟滴答
  歧义限制选择声明；但激活后的内核启动时间、进程代次与 exec 代次，仍能在本次采集器运行
  内提供精确事件身份。
- cgroup 范围排空时仍处于待定状态的连接或文件入口，会保留在有界配对映射表中，直到系统
  调用返回或线程退出。它们捕获的范围代次会阻止其在数字 cgroup ID 复用后跨入后续智能体
  运行；但代次分配器属于观测器生命周期状态，不能建立跨采集器重启的身份连续性。
- 入口缺失后，退出侧无法重建 `openat` 或 `openat2` 标志，因此这类未配对退出会保守归因到
  `file_open`，而不是创建或截断。
- 被攻陷的内核或特权主机可以省略或伪造观测。
- 内核版本、BTF、挂钩可用性、验证器行为与权限会限制支持范围。
- 当前资格约定没有授予任何正式支持（`Supported`）的配置档。Linux 6.12 x86_64 原生主机仅为
  候选级（`Candidate`）；其他内核、架构与容器／Kubernetes 运行时在准确、保留的实机证据通过前都保持
  实验级（`Experimental`）。确定性的无内容工作负载与配对原始采集框架已经冻结预期事件计数、单调延迟
  样本、隔离的采集器 CPU／进程／cgroup／BPF 内存样本与配对级自举摘要，并把突发丢失归因
  到独立速率阶段；晋级仍需要保守数值预算和足量、保留的特权重复证据。

## 14. 非目标

- 智能体编排、调度、记忆、模型路由或沙箱。
- 通用钩子、SDK、OTLP、MCP 或 A2A 可观测平台。
- 远程结果验证与跨服务提供方智能体证据图。
- 同步策略拒绝、审批工作流、BPF-LSM 强制执行或自动遏制。
- 多租户网关、PostgreSQL/S3 托管链、证据对象生命周期、计费、高可用或公共 SaaS。
- SIEM、提示词评估、令牌成本分析或长期数据湖。
- macOS/Windows 内核传感器、TLS 明文、默认提示词／响应或无差别全系统调用采集。

## 15. 方向与发布门禁

本地智能体运行工作流、非特权投影／查看器、有界守护进程运维、完成的 D1/D2 工作与分别
保留的 Docker／私有 containerd 资格验证，以及完成的确定性 K1 约定，共同构成当前基础。
下一项有界工作是在指定的运行时就绪、网络就绪 VKE 上完成实机资格验证，随后进行发布准备。
该门禁必须覆盖代表性的同一 Pod 重启、来源丢失／恢复、跨节点新 UID 交接、运行时边界、
清理与隐私。本工作区缺少必需的 kubeconfig 与 `kubectl`，因此尚未运行；规范预检结果是跳过，
不能报告为通过。Docker 证据不能复用为 containerd 或 Kubernetes 证据，私有 containerd 证据
也不能复用为 Kubernetes 证据。破坏性 systemd 运行时服务重启资格验证保持独立、可选声明。
在相应的精确工作负载／内核／运行时与适用发布证据通过前，任何配置档都不会超越
实验级（`Experimental`）或候选级（`Candidate`）。

跨领域规则长期有效：先限定范围再采集、先声明能力再作结论、不静默忽略缺失、先建立稳定
身份再推断、先处理隐私再持久化、只做观测而非强制执行、查看器保持非特权，以及只有重复
使用能够改变真实调查决策时才扩展。

以下能力明确暂缓：服务提供方钩子／SDK／OTLP／MCP／A2A 系列；通用远程导出／托管链；
远程结果验证；实时追踪与跨运行搜索；中央认证摄取、多用户查询、PostgreSQL／S3／KMS
托管链与多租户留存；策略拒绝／遏制；可移植证据收据；公共 SaaS、高可用与多区域；通用
软件包管理器抽象；卸载时自动清除已保留智能体运行。只有出现明确需求并做出新架构决策后，
它们才能返回。

存在任一适用条件时，配置档都不得发布：

- 丢失、失败、截断、重启、运行时元数据不可用、不支持路径或缺失
  终止可以产生未标记的完整证据；
- 只有入口、只依赖 PID／名称／时间、陈旧容器或歧义关联被展示为成功操作
  或精确运行时身份；
- 受保护挂接绕过资格校验、遗漏有序的历史未知边界或夸大锚定前连续性；
- 混合、格式错误、损坏、不支持、未解析或带缺口的输入被呈现得比来源更强，或查看器构造
  进程树边；
- 秘密、argv、提示词、响应、载荷、凭证、私有路径、套接字、标签、注解、kubeconfig 或
  私有工作负载数据跨越默认持久化、日志、错误、测试或仓库边界；
- 查看器需要特权主机访问，或发现项被描述为阻止／强制执行；
- 安装、替换、卸载、留存、恢复、运行时清理或 Kubernetes 验证
  可以修改无关状态，或缺少必需实机证据；
- 所声明配置档的内核、运行时、操作、隐私、性能、打包与清理封装尚未文档化、测试或冻结
  预算。

只有代表性智能体运行能够自动限定范围／归属、操作者实际使用进程／文件／网络调查、缺口
能够阻止错误的“无异常”结论，并且容器／Kubernetes 上下文能够改变真实复查或事件响应决定
时，项目才继续扩展。如果通用遥测已经足够、eBPF 证据不改变决策、部署权限成本高于工作流
价值、大多数活动发生在远端，或适配器维护挤压采集器正确性，项目应进一步简化而不是扩张。

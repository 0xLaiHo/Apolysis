# Apolysis 路线图

> [English](roadmap.md) | 简体中文
> 配套文档：[design.zh-CN.md](design.zh-CN.md)
> 最后审查：2026-08-03

本路线图把 Apolysis 引向一个有界的 eBPF Agent 运行时观测 Beta。它记录交付顺序、后置项、
no-go 条件和允许项目扩张的条件，不是逐 commit 的进度日志。

## 当前决策

Apolysis 不再推进跨 provider 的 Agent Runtime Evidence & Policy Plane。活跃产品是面向
用户可控 Linux 环境的 **eBPF Agent 运行时观测平台**。

这次重置建立以下持久边界：

- eBPF runtime observation 是必需能力，不是可选 coverage enhancement；
- 主要聚合对象是 Agent Observation Record，不是跨 provider Agent Execution Record；
- 首个稳定 workflow 是本地 Linux Agent Run，随后是 container attribution 和有界
  Kubernetes Beta；
- collection、attribution、privacy、health 与 operator investigation 优先于中央存储和
  provider adapter；
- finding 是 post-observation review aid，不宣称 enforcement；
- 中央多租户证据平面需要新的用户证据和新的架构决策。

活跃 workspace 现在与有界产品一致：8 个 crate 覆盖 core record、observer、
accountability finding、本地 storage、daemon、CLI、Kubernetes metadata 与 visibility
assessment。中央服务、policy actuation、feedback control、sandbox execution 与广泛的
production qualification 不再参与活跃 build 或默认 test。下一优先级是 collector 正确性。

## Beta 结果

有界 Beta 应让操作者启动或 attach 到一次受支持 Agent Run，并通过 CLI 或 saved-run viewer
回答：

1. 哪些进程属于本次 run；
2. 观测到了哪些受支持的文件、网络和凭证操作；
3. 每条观测如何归属到 process、cgroup、container 或 Pod；
4. 操作是成功、失败，还是结果未知；
5. 采集是否健康，哪些观测可能缺失；
6. 哪些有界 finding 需要复查。

Beta 不要求项目自建 cloud service、PostgreSQL、object storage、provider adapter 或 policy
enforcement。

## 交付顺序

### 0. 冻结产品边界

目的：在修改代码前，让范围重置成为文档权威。

交付物：

- 同步中英文 README、design 与 roadmap；
- 替换领域 glossary 中的跨 provider evidence-plane 语言；
- 记录范围决策并 supersede 冲突 ADR；
- 说明广泛 prototype 保留在历史中，但不再是活跃产品承诺。

退出条件：一个经过 review、面向 `pre-release` 的 PR 建立唯一明确的产品定义与显式非目标。

### 1. 收敛活跃 Workspace

目的：让 build、test 与 ownership boundary 匹配产品。

保留为活跃产品模块：

- kernel program 与 userspace observer；
- run scope 与 runtime identity；
- 有界本地 store；
- node daemon；
- CLI 与未来 saved-run viewer；
- 严格必要的 local/container metadata。

移出活跃 workspace 与默认门禁：

- production contract、Gateway、Gateway server 与 testkit；
- PostgreSQL Gateway 与 projection；
- evidence-object storage 与 lifecycle；
- policy actuation、feedback control 与 enforcement prototype；
- 不再验证 eBPF 产品的 provider、compliance 与 production-plane qualification machinery。

通过 Git 历史保持可恢复，而不是在默认 workspace 中继续维护 archive crate。

退出条件：

- `make build`、`make test` 与 `make lint` 只验证活跃产品；
- 活跃 crate 不再依赖 Gateway、PostgreSQL、object storage、policy actuation 或
  provider-evidence 模块；
- README 与 package metadata 只命名受支持或明确 experimental 的能力；
- live observer 与 privacy regression test 保持完整。

### 2. 验证 Collector 正确性

目的：让 eBPF source 足以在其声明 capability boundary 内支撑产品结论。

优先级：

- 维护版本化 kernel/userspace ABI 与 capability manifest 的兼容性，并显式拒绝不兼容
  record；
- 把有界 `network_connect` entry/exit 模式扩展到其余受支持 operation set；
- 保持 return value 与 errno 语义，并区分 attempted、succeeded、failed、denied、pending
  和 unknown；
- 在 multi-cgroup daemon 持久化 Agent-Run-scoped Observation Gap 前，按 cgroup 归属
  network correlation counter；
- 建立抵御 PID reuse 与 exec 的稳定 process identity；
- 保留 cgroup scope 与 deterministic process lineage；
- 发出 collector start、周期 health、loss checkpoint、terminal state 和显式 stop reason；
- 对 reserve failure、map pressure、truncation、decode failure、attach failure、ABI
  mismatch、restart 与 incomplete flush fail loud；
- 保持 content-off persistence 与 secret/path redaction。

首批 operation breadth 保持 process lifecycle、选定 file mutation/open、内置 credential
类别 path 与 outbound connect。新 hook 必须有真实用户调查场景，以及隐私和性能预算。

退出条件：

- 每种受支持 operation 都有经过测试的 outcome semantics；
- unsupported path 与 missing exit event 形成显式 gap；
- PID reuse、collector restart、decode failure 与 event-loss test 不会产生 clean 或 complete
  result；
- 代表性 live test 在明确支持的 kernel profile 上通过；
- raw argv、prompt、response、tool payload、credential 或 private path 不会跨过默认
  persistence seam。

### 3. 交付本地 Agent Run 产品

目的：把正确的 kernel observation 转化为 operator workflow。

交付物：

- 在 Agent 执行前完成 attach 的 managed launch；
- 对现有 process tree 的受保护 attach，并记录显式 late-attach gap；
- 每次 run 一份 Agent Observation Record；
- process tree 与有序 process/file/network/credential timeline；
- run summary、collector health、capability、attribution 与 gap view；
- credential path、workspace mutation、unexpected executable class、unapproved network
  target 与 degraded observation 的有界 finding；
- 基于有界本地数据的非特权 saved-run viewer；
- local daemon 的 install、health、stop、cleanup 与 retention 行为。

可选 declared-intent correlation 可以保持 experimental。没有 Agent-specific log 或 provider
API 时，run 仍必须有用。

退出条件：

- operator 无需读取 raw JSONL 或 kernel trace 即可完成代表性调查；
- 每个 viewer fact 都能解析到 observation、capability、health 或 gap record；
- 空或不完整 timeline 永远不渲染成 successful 或 complete；
- privilege separation、本地文件权限、retention 与 redaction 通过有界测试；
- collector 满足在 Beta qualification 前冻结的 workload-specific CPU、memory、latency 和
  event-loss envelope。

### 4. 加入 Container Attribution 与 Kubernetes Beta

目的：在更深的用户自有 runtime boundary 中复用同一 collector 与 record model。

顺序：

1. 稳定 Docker/containerd cgroup 与 container identity；
2. 验证 daemon restart 与 runtime socket recovery；
3. 在受支持时绑定 Kubernetes Pod UID、container ID、cgroup、namespace、service account、
   node 与 RuntimeClass；
4. 部署 least-privilege node collector 和非特权 viewer path；
5. 在指定 VKE test cluster 验证代表性 workload。

退出条件：

- container 与 Pod identity 不依赖 name-only 或 PID-only matching；
- runtime restart、container churn、Pod reschedule、PID reuse 与 sensor loss 保持为显式 gap
  或 identity transition；
- gVisor、Kata、Firecracker、guest、io_uring 与 remote-operation boundary 被诚实描述；
- Kubernetes credential 与捕获的 workload data 不进入 repository、log 或 retained test
  artifact；
- 在 workload 与 kernel envelope 通过资格验证前，Kubernetes support 始终标为 Beta。

## 跨阶段规则

- 先 scope 再 capture：不提供受支持的默认 host-wide collection。
- 先 capability 再 claim：每个 operation 和 outcome 都绑定版本化 capability。
- 不静默表达 absence：loss、truncation、unsupported path、late attach 与 collector death
  始终产生 gap。
- Runtime identity 优先于 inference：cgroup/process generation 优先于 PID、time、path 或
  command correlation。
- Privacy 先于 persistence：除非独立 review profile 授权，否则敏感内容关闭。
- Observation 不是 enforcement：finding 只描述正在或已经观测到的条件，不宣称阻止。
- Viewer 非特权：browser 或 local UI 不能接触 BPF map、host PID namespace、runtime
  socket 或 node credential。
- 重复使用驱动扩张：新的 event family 与环境必须能改变真实调查决策。

## Beta 支持边界

目标稳定 profile：

- 具有 BTF、cgroup v2、所需 tracepoint 与文档化 BPF capability 的受支持 Linux 发行版和
  kernel；
- 本地 managed Agent command；
- 通过同一 CLI managed-run boundary 的 Linux self-hosted CI；
- 完成 runtime attribution qualification 后的 Docker/containerd。

目标 experimental profile：

- 文档化 runtime/kernel 组合上的 Kubernetes node 与 Pod attribution。

不支持：

- macOS 与 Windows runtime collection；
- 没有用户可控 kernel 的 vendor-managed Agent environment；
- 被观测 host 之外的 remote MCP、SaaS 或 cloud effect；
- 没有 guest collector 时的强 guest semantics。

## 明确后置

- Provider Hook、SDK、OTLP、MCP 与 A2A adapter family；
- 通用 remote export 与 external custody；
- semantic coverage 与 remote outcome verification；
- 跨 run search 与 organization-wide investigation graph；
- 中央 authenticated ingest、多用户 Query API 与 Web Console；
- PostgreSQL、S3-compatible evidence object、KMS、replay authority 与多租户
  retention/deletion；
- policy denial、approval workflow、BPF-LSM blocking、kill 或 containment；
- portable evidence receipt、external anchoring、HSM custody、SCITT 与 selective
  disclosure；
- 公共 SaaS、billing、replication、failover、multi-region 与 fleet disaster recovery。

Deferred work 不会只因为未来可能有用就继续在活跃 workspace 中编译。它必须由新的、有用户
需求支撑的范围决策重新引入。

## No-go 条件

存在任何适用条件时，不得发布对应 Beta profile：

- collector 可以在没有 Observation Gap 的情况下静默 drop、truncate、fail、restart 或
  stop；
- syscall-entry event 在没有受支持 outcome source 时被渲染为成功操作；
- PID-only、name-only 或 timing-only matching 被显示为 exact runtime attribution；
- 空 timeline 被解释为 Agent 没有活动；
- raw prompt、response、argv、tool payload、credential 或 private path 默认落盘；
- viewer 需要 root、BPF access、host PID namespace、runtime socket 或 node credential；
- 受支持 kernel、runtime、operation 与 performance envelope 没有文档和测试；
- finding 被描述为 blocking 或 enforcement；
- local uninstall、retention 或 cleanup 可能删除或修改无关 host data；
- Kubernetes test 打印、复制或提交 kubeconfig 或 workload secret。

## 成功与停止条件

满足以下条件时继续扩大 runtime support：

- 代表性 Agent Run 能自动限定 scope 并完成归属；
- operator 重复使用 process/file/network investigation workflow；
- collector health 与 gap 防止错误 clean conclusion；
- 至少一条 runtime observation 改变 review、security、incident 或 debugging decision；
- container 或 Kubernetes attribution 提供普通 process log 之外的有用 context。

出现以下情况时停止扩张并继续简化：

- 用户只需要现有 runtime-security tool 已提供的通用 process telemetry；
- eBPF observation 不改变调查决策；
- 特权部署成本超过 Agent-specific scope 的价值；
- 多数有用活动发生在 collector 无法观测的 vendor-managed 或 remote environment；
- saved-run viewer 在首次评估后不再使用；
- adapter 或 compatibility maintenance 占用的能力超过 collector correctness 和 operator
  workflow。

## 资源假设

一名工程师从 scope reset 到有界 container Beta 预计需要约 12–16 周。两名工程师可以并行
推进 collector correctness 与 operator workflow，约 8–10 周达到相同 Beta。这些是规划区间，
不是发布承诺；只有 local 与 container gate 关闭后才进入 Kubernetes 深度工作。

# Apolysis 路线图

> [English](roadmap.md) | 简体中文
> 配套文档：[design.zh-CN.md](design.zh-CN.md)
> 执行计划：[beta-qualification-plan.zh-CN.md](beta-qualification-plan.zh-CN.md)
> 最后审查：2026-08-10

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

有界产品由 core record、observer、accountability finding、本地 storage、daemon、CLI、
Saved Run Viewer、Kubernetes metadata 与 visibility assessment 组成。中央服务、policy
actuation、feedback control、sandbox execution 与广泛的 production qualification 不参与
活跃 build 或默认 test。本地产品方向是在扩大 runtime breadth 前，基于 single-run
projection contract 支持非特权 saved-run investigation 与 daemon operations。

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
- CLI 与 Saved Run Viewer；
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
- 保持 `network_connect` 与选定受支持文件 operation set 的有界 entry/exit matching；
- 保持 return value 与 errno 语义，并区分 attempted、succeeded、failed、denied、pending
  和 unknown；
- 保持 per-cgroup operation correlation counter，并验证 scope drain、shutdown 与 identity
  churn 下隔离的 Agent-Run gap 持久化；
- 保持单次 collector 生命周期内抵御 PID reuse 与 exec 的稳定 process identity；
- 保留带 generation 限定的 cgroup scope 与 deterministic process lineage；
- 保持持久化 collector start、周期累计 health/loss checkpoint、显式 terminal reason 与幂等
  restart-gap recovery；
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
- 仅通过 registration-qualified current root 或唯一 inferred discovery 准入现有 process
  tree 的 protected attach，并拒绝原始 PID scope；
- 每次成功 protected attach 都必须在 capability 与 lifecycle start 前记录一条 late-attach
  gap；
- 每次 run 一份确定性的 single-run Agent Observation Record projection；
- Exact Runtime Identity roster、reported PID/PPID fact 与有序
  process/file/network/credential timeline；schema v1 不支持 canonical process tree，viewer
  不会推断 parent edge；
- 可查询的 capability、identity、observation、lifecycle/health、finding、gap、issue array，
  以及相互独立的 evidence/health/review summary；
- credential path、workspace mutation、unexpected executable class、unapproved network
  target 与 degraded observation 的有界 finding；
- 基于有界本地数据的非特权 saved-run viewer；
- 基于 manifest 验证一个固定 artifact 集合的 install 与 inspect，包括 receipt-owned
  replacement、interruption recovery 和保留 state 的 uninstall；
- 复用 socket protocol 的 health、有界 systemd stop、针对明确 target 的 cleanup，以及面向
  local daemon 单一 default context、带 crash recovery 的 identity-bound retention。

可选 declared-intent correlation 可以保持 experimental。没有 Agent-specific log 或 provider
API 时，run 仍必须有用。

退出条件：

- operator 无需读取 raw JSONL 或 kernel trace 即可完成代表性调查；
- 每个 viewer fact 都能解析到 observation、capability、health 或 gap record；
- mixed-run、malformed、active、failed、missing-capability/terminal、包含 loss/gap、
  mixed-integrity 或 unknown-record 的输入永远不渲染成 clean 或 complete；
- Protected attach 对 zombie、ambiguous 或 namespace-incompatible candidate fail closed，
  把显式 registration selection 标为 `registration_qualified`，且绝不把该标记呈现为
  pre-anchor continuity；
- 每次成功 protected attach 都展示恰好一个有序的 unknown-history boundary，其 `count:1` 不会
  被呈现为 missing-event estimate，并与 capability 和 start 一起作为 rotation-safe、可回滚的
  durable batch 持久化；同时记录 admitted root 或 lineage candidate 的有界 same-tick pre-anchor
  ambiguity；
- Exact event identity 仅在 activation 后，由本次 collector run 内的 kernel start time、process
  generation 与 exec generation 建立；
- privilege separation、本地文件权限、retention 与 redaction 通过有界测试；
- local lifecycle change 只作用于文档化 artifact 集合，在 mutation 前拒绝 symlink、
  non-regular、hard-linked、unmanaged、已变化或 stale 的输入，并默认保留 retained Agent Run
  与无关文件；
- 资格证据来自版本化 synthetic workload、同一 boot 上交替的 collector-off/on trial、
  monotonic 原始 latency 与隔离 collector-resource sample、配对 bootstrap summary，以及准确
  event-count reconciliation 和按 phase 归因的 burst loss；
- collector 满足由保留 live 证据冻结的 workload-specific CPU、memory、latency 与
  event-loss budget；未设置的 Candidate envelope 是显式 no-go，绝不视作隐式通过。

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
- 不静默表达 absence：loss、truncation、unsupported path、collector death，以及 protected
  attach 之前的 unknown history 始终产生 gap。
- Runtime identity 优先于 inference：cgroup/process generation 优先于 PID、time、path 或
  command correlation；root-selection confidence 不是 event identity 或 pre-anchor continuity。
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
- live tail 或 streaming viewer；
- 跨 run search 与 organization-wide investigation graph；
- 中央 authenticated ingest、多用户 Query API 与 Web Console；
- PostgreSQL、S3-compatible evidence object、KMS、replay authority 与多租户
  retention/deletion；
- policy denial、approval workflow、BPF-LSM blocking、kill 或 containment；
- portable evidence receipt、external anchoring、HSM custody、SCITT 与 selective
  disclosure；
- 公共 SaaS、billing、replication、failover、multi-region 与 fleet disaster recovery；
- 发行版原生 package repository，以及通用 package-manager 或 service-manager abstraction；
- 自动迁移或清除 local uninstall 所保留的 Agent Run。

Deferred work 不会只因为未来可能有用就继续在活跃 workspace 中编译。它必须由新的、有用户
需求支撑的范围决策重新引入。

## No-go 条件

存在任何适用条件时，不得发布对应 Beta profile：

- collector 可以在没有 Observation Gap 的情况下静默 drop、truncate、fail、restart 或
  stop；
- syscall-entry event 在没有受支持 outcome source 时被渲染为成功操作；
- PID-only、name-only 或 timing-only matching 被显示为 exact runtime attribution；
- Existing-process attach 接受原始 PID、绕过 root identity 或 namespace 资格校验、接纳
  ambiguous discovery，或把 inferred root selection 当作 exact event attribution；
- 把 `registration_qualified` 呈现为从 registration 创建以来的 continuity，或在缺少 kernel
  start time 与 process/exec generation 时宣称 post-activation exact event identity；
- 成功的 protected attach 没有在 capability 与 `started` record 前恰好写入一条
  `late_attach` gap，或把该 gap 的 `count:1` 呈现为 missing-syscall count；
- 空 timeline 被解释为 Agent 没有活动；
- saved-run projection 接纳 mixed Agent Run、在完整验证前暴露 hash-chain payload、把 mixed
  integrity 或 unknown record 标为 complete、把 per-input limit 误当作 combined-input bound、
  接受 partial 或伪造 capability 为 complete、保留无法解析的 Finding evidence link、能够覆盖
  input source，或在错误中包含 raw payload；
- raw prompt、response、argv、tool payload、credential 或 private path 默认落盘；
- v1 viewer 从数字 PID/PPID 构造 canonical process-tree edge，而不是只展示已存储的 identity
  roster 与 reported parent identifier；
- viewer 需要 root、BPF access、host PID namespace、runtime socket 或 node credential；
- 受支持 kernel、runtime、operation 与 performance envelope 没有文档和测试；
- finding 被描述为 blocking 或 enforcement；
- local install、managed replacement、uninstall、retention、recovery 或 cleanup 能逃逸固定
  artifact/state 集合、跟随 link、仅以 pathname 证明 ownership、默认删除 retained Agent Run，
  或删除、修改无关 host data；
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

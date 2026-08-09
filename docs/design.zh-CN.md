# Apolysis 设计文档

> [English](design.md) | 简体中文
> 配套文档：[roadmap.zh-CN.md](roadmap.zh-CN.md)
> 最后审查：2026-08-10

本文是 Apolysis 做什么、目标系统如何工作、当前已经实现什么以及产品声明止步于何处的
唯一权威说明。交付顺序、后置项和发布门禁属于 roadmap。

## 1. 产品定义与成熟度

Apolysis 是面向用户可控 Linux 环境的实验性 **eBPF Agent 运行时观测平台**。它观测有界的
进程、文件、网络和凭证相关操作，把它们组织到一次 Agent Run 中，归属到 runtime identity，
并报告 collector 健康和 Observation Gap。

eBPF collector 是必需的主要观测源。Provider hook、Agent log、protocol trace 和 remote
export 都保持 deferred；它们不定义活跃产品，也不能替代 runtime observation。

当前活跃目标是有界 Beta，而不是生产证据平面。Gateway、PostgreSQL、evidence-object、
projection 与跨 provider contract 原型已经移出活跃 workspace。Policy actuation、Agent
feedback control、sandbox execution 与广泛的 production qualification 也已移出活跃
build；它们都不是 observer-side 产品依赖。

### 成熟度标签

| 标签 | 含义 |
| --- | --- |
| Implemented today | 当前 collector 或本地 workflow 中已存在，并有文档化限制 |
| Beta target | 活跃 eBPF 观测路线图要求交付，但尚未完成资格验证 |
| Deferred | 只有在出现重复用户需求后才可能进入的未来扩展 |
| Out of scope | 不属于产品方向 |

## 2. 用户与决策

主要操作者是在自有 Linux 基础设施上运行 Agent 的 platform、runtime-security、AppSec 或
工程团队。首批受支持 workflow 是本地 Agent CLI、Linux self-hosted CI 和 container；
container 归属稳定后再进入有界 Kubernetes node workflow。

对于一次 Agent Run，操作者需要回答：

1. Agent 启动了哪些进程？
2. 观测到了哪些受支持的文件、网络和凭证操作？
3. 每条观测属于哪个 runtime identity？
4. 受支持操作是成功、失败，还是结果未知？
5. 采集是否健康，哪些活动可能丢失或不受支持？
6. 哪些观测因为跨越配置的 workspace、credential 或 network boundary 而需要复查？

更多 event 数量本身不是产品价值。只有当操作者无需读取 kernel trace 或原始存储文件，也不会
被缺失 evidence 误导，就能调查一次真实 Agent Run 时，产品才成功。

## 3. 领域模型

聚合对象是 **Agent Observation Record**：

```text
Agent Run
  |- Observation Scope
  |- Runtime Identity
  |    `- Runtime Observation
  |         `- Operation Outcome
  |- Collector Capability
  |- Collector Health
  |- Observation Gap
  `- Finding
```

Agent Observation Record 比此前的 Agent Execution Record 更窄。它不尝试聚合 provider
intent、多 Agent protocol 语义、远端 outcome 验证、approval 或 policy actuation。

Exact relation 必须依赖文档化 boundary 内的稳定 runtime identity。仅使用时间、命令名、
路径或 PID 的匹配属于 inferred。存在多个可能 owner 时关系为 ambiguous，绝不能静默升级为
exact。

## 4. 责任与信任边界

| 边界 | 主要归属 | Apolysis 角色 |
| --- | --- | --- |
| Agent 授权与任务意图 | Agent harness 或 operator | 只作为可选描述性 metadata |
| Workload 隔离 | Host、container runtime、Kubernetes 或 sandbox | 观测受支持 runtime activity，不宣称隔离 |
| Runtime observation | 用户可控 Linux kernel 与 Apolysis collector | 采集、限定 scope、标准化、脱敏并报告 health/gap |
| 外部结果 | Git、test、cloud、SaaS 或 remote service | 不属于活跃产品 contract |

被攻陷的 host root 或 kernel 可以伪造或省略 host observation。Apolysis 是运行时观测工具，
不是独立 attestation authority。

特权 collector 与非特权 operator surface 属于不同 trust domain。Viewer 永不加载 BPF 程序，
也不接收 host-wide credential。

## 5. 目标架构

```text
Agent command / self-hosted CI job / container / Pod
                         |
                  Observation Scope
                         |
              privileged eBPF Collector
                |- process lifecycle
                |- selected file operations
                |- network connections
                |- loss and health counters
                         |
             userspace decode and identity join
                         |
                 privacy/redaction seam
                         |
                  bounded local store
                         |
              CLI and saved-run viewer
```

### 5.1 Agent Run 与 Observation Scope

每条观测都属于一个显式 run scope。受支持的 scope mode 是：

- 从启动前开始观测其 process tree 的托管 Agent command；
- 仅通过显式 Agent registration 或自动 discovery 准入的受保护现有 process tree；
- 一个 container 或 workload cgroup；
- 由 node daemon 管理的有界 cgroup 集合。

Managed launch 是首选本地 workflow，因为 collector 可以在 Agent 启动前完成 attach。
Protected existing-process attach 是封闭的准入面：原始 `--scope-pid` 会被拒绝，root 必须来自
`--agent-registration` 或 `--agent-discover`。显式 registration 会对照当前 host boot ID、root
start tick、executable、command fingerprint 与 canonical workspace boundary，在 collector 打开
root pidfd 时完成资格校验；root 的 live cwd 必须解析到该 boundary 或其子目录。匹配成功记录
`root_selection:registration_qualified`：它只限定该
anchor 时可见的 root，不证明从 registration 创建以来的连续性。Discovery 从 live process state
派生 identity material，要求唯一最佳 candidate，并保持 root selection 为 `inferred`。

每个获准 seed 的 root 或 lineage candidate 都必须是活着的 non-zombie thread-group leader。
Snapshot 后会为每个 candidate 打开 pidfd，并在 map insertion 前后检查其 liveness、lineage
以及 initial PID/time namespace membership，
形成 per-seeded-candidate pidfd sandwich；candidate 在插入后退出时由 exit hook 移除。选定 root
在 activation 全程继续由 pidfd 锚定。Observer 与 target 必须共享 initial PID namespace，以及
同一个 initial、unshifted time namespace。Scope 从 inactive 开始，先 attach tracepoint，再进入
process-tree seeding：先 seed registration-qualified 或 inferred root，再通过多轮 process-tree
snapshot 补充缺失 TGID，并在 activation 前后重新限定 root identity。只有这些步骤成功后 scope
才进入 active。该流程关闭 seeded candidate 在 anchor 后的退出与换代竞态，但不证明
pre-anchor selection continuity。

Activation 之前的活动属于 unknown history。因此每次成功的 protected attach 都必须先持久化
恰好一条 `operation:"collector_lifecycle"`、`count:1` 的 `late_attach` Observation Gap，然后才是
capability manifest 与 `started` lifecycle record。这里的 count 表示一个 unknown-history
Collection Boundary，不是缺失 syscall 或 event 数量的估计。

不允许默认使用 host-wide scope。Collector 可以为开发提供显式 diagnostic mode，但它不是
受支持的 Agent Run profile。

### 5.2 eBPF Collector

Collector 使用少量、版本化、高信噪比 hook。它尽可能在 event origin 过滤，发出固定有界
record，并报告 map pressure、reserve failure、truncation、decode failure、attach failure
和异常终止。每条 record 以 ABI version 和声明的 record size 开头；userspace 会拒绝不兼容
version 或 size，不会按当前 layout 勉强解码。

Beta collector target 为每种受支持 operation 加入 entry/exit matching。Record 区分
attempted、succeeded、failed、denied、pending 与 unknown outcome，并在 capability 声明
包含时保留 return value 或 errno。

`network_connect` 以及选定的 `file_open`、`file_create`、`file_truncate`、
`file_unlink` 与 `file_rename` 已具备完整 outcome 路径。Collector 保存有界、
thread-scoped entry record，并在 syscall exit 发出 Runtime Observation。Linux return value
映射为 succeeded、failed 或 denied；connect 还支持 pending。无法匹配的 entry 或 exit 会
成为显式、operation-specific Observation Gap。

在 multi-cgroup daemon 模式下，connect 与文件配对丢失会按 cgroup 分别计数，同时保留
collector-global counter 用于健康诊断。Drain 一个 scope 时会阻止新的 entry，快照其
missing-entry、missing-exit 与 pending 计数；快照前会有界等待正在执行的 collector update
排空，并在丢弃归属前确认类型化 Observation Gap 已持久化到所属 Agent Run。已提交的 ring
record 会先经过有界排空并确认持久化。每次 scope 注册都会获得单调递增 generation；pending
pair 与发出 record 会保留该 generation，因此 drained scope 的 stale pair 无法计入或发到复用
同一数字 cgroup ID 的后续 Agent Run。Drain、快照、queue drop/shedding 或 storage 失败会
停止 observer runtime，并拒绝把该 run 干净关闭。

所有 multi-cgroup ring producer（包括 process fork、exec 与 exit）都参与同一个 in-flight
scope barrier。Barrier map 读取失败时 scope 会保持 draining 并 fail closed；只有有界等待超时
才可以尝试恢复其他前置条件完整的 ACTIVE scope。通过 ABI 验证但无法 normalize 的 record 也会
停止 queued ingest 或 confirmed drain，而不会被跳过。

全 syscall 采集、prompt/response、TLS plaintext 和通用 kernel enforcement 都不是目标。

### 5.3 Userspace normalization 与 identity

Userspace 解码 kernel ABI，分配 deterministic source sequence，标准化 event type，关联
runtime metadata，应用 content-off privacy，并写入 Agent Observation Record。

Kernel ABI v3 携带有界的 scope generation、process generation、kernel process-start
timestamp、exec generation 以及 parent process/exec generation。Live userspace boundary 会
附加 collector 启动时读取一次的 host boot ID。Process context 按 host boot、PID、process
generation 与 exec generation 键控，而不是只按 PID 键控，因此 PID reuse 或 exec transition
不会继承陈旧 executable context。Process-identity map 与 userspace context table 保持有界；
出现 pressure 时会 fail loud，而不会静默复用或丢弃 identity state。Kernel identity-map 或
exec-generation 失败会设置预分配的 fail-closed latch；此后直到 collector 重启，所有 record
都保持 inferred，因此 pressure 不会静默恢复 exact attribution。

只有 host boot、scope generation、process generation、kernel process-start time 与 exec
generation 都存在时 attribution 才是 exact。Fork identity 在观测到 child process start 前保持
provisional；始终未成为 process identity 的 thread-clone candidate 保持 inferred，并在 task exit
时丢弃。Generation 缺失时保持 inferred 并给出显式 reason；PID-only、command、path 与
timestamp join 不会升级为 exact。Scope generation 只保护单次 collector 生命周期内的 cgroup
ownership。Collector restart 仍是可见 identity boundary。Lifecycle recovery 会记录未完成
实例及其 restart gap，但不会跨越该边界声明 identity continuity。PID namespace、container、
Pod 与 node identity 在可用时仍作为增量 attribution。

Protected attach 会把初始 process 与 thread identifier 归一化为 TGID，并要求 root 是活着的
thread-group leader。一个 `/proc` start tick 会转换成 boot-time 半开区间
`[start_tick * tick_ns, (start_tick + 1) * tick_ns)`。匹配的 kernel bookkeeping 可以在 seeding
阶段或之后，把内部 tracked membership 提升为 exact group-leader start time；后续匹配必须使用该
nanosecond value。只有 activation 后实际发出的 event，才由匹配的 kernel start time 与
process、exec generation 在本次 collector run 内获得 exact event identity。该 identity 与
pre-anchor root-selection confidence 相互独立：显式 registration 为
`registration_qualified`，discovery 保持 `inferred`；二者都不是 event relation status，也不
证明连续性。

### 5.4 本地 Store 与 Viewer

首个产品保持 local-first。Store 有界、安全轮转，并保留显式 run start、capability、health
checkpoint、terminal state 与 gap record。当前格式是 append-only JSONL 和可选本地
hash-chain envelope。Saved-run viewer 需要时，可以在同一 record model 后加入 query index。

V1 saved-run 读取路径会把 active file 与连续数字 archive 作为同一个稳定本地 snapshot，按
最旧 archive 到 active 的顺序读取；它拒绝 symlink、非普通文件、读取期间变化、截断、格式错误
和混合 envelope，并在暴露 payload 前验证完整 hash chain。Byte、line 与 record 都有明确上限。
Source order 是权威顺序；wall-clock timestamp 不会修复或重排非法 lifecycle。Plain 与 verified
输入可以显式组合，但 mixed integrity 始终可见，不能产生 complete evidence。

`apolysis-accountability` 会把这些 typed source record 纯函数式折叠为恰好一份 Agent
Observation Record。Agent Observation Summary 保持 Evidence State、Collector Health 与
Review State 相互独立。缺失 lifecycle、不支持的 outcome、diagnostic、Observation Gap、未知
record 与 source-integrity finding 会保留为可查询限制；mixed Agent Run、损坏 storage、非法
lifecycle 顺序、重复 canonical observation、不兼容 schema 与 content-policy violation 会
fail closed。自由文本 Finding reason 与 Gap detail 会 canonicalize，而不是复制到派生 artifact。

`apolysis run project --input <path> [--input <path> ...] --output <path>` 是该 projection
的非特权 adapter。它通过同目录私有 temporary file 写入确定性 JSON，完成 sync 后原子发布，
并拒绝 output alias 任何 active 或 rotated input。该命令是 saved-run projection，不是 live
tail、remote query API 或交互式 viewer。

Viewer 提供：

- run inventory 与 summary；
- process tree 与 runtime identity drill-down；
- 有序 process、file、network 与 credential timeline；
- 受支持的 outcome 与 attribution status；
- collector health、loss、truncation 与 unsupported capability gap；
- 链接到原始观测的 review-oriented finding。

Viewer 不从空结果推导隐藏的 success verdict。

### 5.5 后置的中央边界

Remote export、custody、organization authorization、object storage、跨 run search 与 HA
都不属于有界 Beta。只有当重复使用证明需要中央服务，并由新的架构决策定义边界后，它们才会
重新进入。

## 6. Observation contract

每条 Runtime Observation 在受支持时携带：

- schema 与 collector ABI version；
- run 与 observation identifier；
- source sequence 与 observed time；
- runtime identity 与 scope reference；
- operation family 与 normalized action；
- 有界、脱敏的 resource identity；
- attempted/succeeded/failed/denied/pending/unknown outcome；
- capability 声明支持时的 return value 或 errno；
- truncation 与 decoding state；
- relation status 与 reason。

Collector lifecycle record 为每个 collector process 使用一个不透明 instance ID，并为每次
Agent Run 维护一条 record stream。`started` 会在放行托管 Agent 或完成 daemon scope 注册前
持久化。周期 `checkpoint` 携带累计 loss counter 与当前 `scope_pending` in-flight gauge，即使
workload 安静也会发出。`global_*` counter 描述 collector 全局丢失；复制到每个 active run
时仍保留该命名。`scope_*` counter 只包含所属 Observation Scope 的 entry/exit 配对状态；对
daemon 而言，它只汇总属于该 Agent Run 的 cgroup。非零 loss counter 会让 checkpoint 标记为
`degraded`。采集仍活跃时，只有 pending 仍保持 healthy；到 terminal 时，它代表停止时未匹配的
工作，因此会使 terminal degraded。

对 protected existing-process attach，durable start boundary 按以下顺序追加并同步：mandatory
`late_attach` gap、Collector Capability manifest、`started`。Gap 的 `count:1` 表示一个
unknown-history Collection Boundary。其 `root_selection` detail 描述
`registration_qualified` registration 或 `inferred` discovery selection；它不会扩展或覆盖 event
规范中的 `exact`、`inferred`、`ambiguous` 与 `unattributed` relation status。
`registration_qualified` 只描述打开 pidfd 时可见的 root，不证明 pre-anchor continuity。
这三条 record 会作为一个 durable batch 序列化：rotation 对整个 batch 只评估一次；write 或
sync 失败时，active file 会先截断回 batch 写入前的长度，然后 attach 才失败。

Daemon checkpoint 与 terminal 会先等待 sequence fence；该 fence 覆盖 boundary 之前所有已被
pipeline 接纳的 record。随后 lifecycle boundary 直接追加到每个 Agent Run 的 hash chain，因此
bounded queue 即使已满也不能丢弃它，后来的高优先级流量也不能让它越过旧 evidence。普通 writer
失败会暂停受影响的 Agent Run，并异步发送 scope failure；唯一 writer 不会同步等待 observer
untrack，也不会等待该 untrack 产生的 failed terminal。

正常路径会先确认 event drain 与 Observation Gap 已持久化，再写入带显式 reason 的
`stopped`。致命 attach、verifier、ABI、decoder、counter、observer 或可写 storage 路径会在
timeline 仍可写时记录 `failed`。Daemon 恢复时，缺少 `stopped` 或 `failed` 的 `started` /
`checkpoint` 实例会得到一次 `collector_restart` Observation Gap 和一个恢复生成的 failed
terminal；重复恢复不会重复写入。Standalone timeline 缺少 terminal 时仍是不完整证据，即使
原进程已无法补写 gap。

Agent Observation Summary 暴露三条相互独立的结论：

- `evidence_state` 为 `complete`、`active`、`incomplete`、`failed` 或 `indeterminate`；
- `collector_health` 为 `healthy`、`degraded`、`failed` 或 `unknown`；
- `review_state` 为 `requires_review`、`no_findings_reported` 或 `indeterminate`。

Complete evidence 要求存在一份兼容的 content-off capability manifest、合法的 started 到正常
terminal lifecycle、至少一条受支持 Runtime Observation，并且没有 loss、gap、diagnostic、
integrity 或 capability issue。Active 或 failed lifecycle state 必须显式保留。Mixed source
integrity 与未知增量 record type 为 indeterminate。Finding 只改变 review state，不改写
evidence completeness。`late_attach` 的 count 1 只增加 unknown-history-boundary count，不增加
known-missing-event count。Mixed Agent Run、格式错误或不兼容 record、content-policy violation、
非法 lifecycle 顺序、重复 canonical observation 与冲突的 Exact Runtime Identity 都 fail closed。

Consumer 忽略未知的增量 field。不兼容的 ABI 或 schema change 必须使用新版本并显式 decode
failure，不能 best-effort 误解。

## 7. 受支持操作集合

| 类别 | Beta target | 声明边界 |
| --- | --- | --- |
| Process | fork/clone lineage、exec、exit | Process lifecycle，不是逻辑 sub-Agent 语义 |
| File | 选定 open/create/truncate/rename/unlink path | 只覆盖受支持 operation 与 resolved identity，不是通用 filesystem history |
| Credential | 内置 credential 类别 path access | Path access finding，不证明 secret 被使用 |
| Network | Outbound connect tuple 与 outcome | Connection attempt/result，不证明远端 mutation 或 TLS content |
| Health | Attach、loss、map pressure、decode、truncation、terminal state | Collector condition，不是 host integrity attestation |

只有真实调查需要、且隐私与性能成本有界时才扩大 operation breadth。不受支持的 io_uring、
filesystem、network、guest 或 runtime path 成为显式 capability gap。

## 8. 环境模型

| 环境 | Runtime observation contract |
| --- | --- |
| 本地 Linux CLI | Managed launch 或受保护的 process-tree attach |
| Linux self-hosted CI | 使用相同 CLI managed-run boundary；runner isolation 由外部提供 |
| Docker/containerd | Host eBPF observation 关联 container 与 cgroup identity |
| Kubernetes | Node eBPF observation 关联 Pod/container/cgroup identity；有界 Beta |
| gVisor | Host/runtime boundary visibility，不是每个 guest syscall |
| Kata 或 Firecracker | Host/VMM/shim visibility；guest semantics 需要 guest collector |
| macOS 或 Windows | 不支持 eBPF runtime observation |
| 厂商托管 Agent runtime | 没有用户可控 Linux kernel 时不属于范围 |

## 9. Finding 与控制

Finding 是 post-observation review aid。首个有界集合是：

- 访问内置 credential 类别 path；
- 在配置的 workspace boundary 外修改文件；
- 在可以解析时连接未批准 address 或 domain class；
- 执行非预期 binary class；
- 采集退化并违反本次 run 的 required observation profile。

Finding 永不宣称操作已经被阻止。BPF-LSM 与 seccomp block prototype 不属于活跃产品。

## 10. 隐私与安全

- Prompt、response、raw tool payload 与完整 argv 默认 content-off。
- 持久化 executable identity 经过 allowlist 且有界；secret value 与 private path 在存储前
  脱敏。
- Registration 的 host/start/executable/command-fingerprint/workspace value 是资格校验输入。
  完整 executable path、workspace path 与 command fingerprint 不跨越 persistence seam；只保留
  有界 identity 与脱敏 supervisor metadata。
- Raw kernel payload 只是有界实现细节，没有显式 review profile 时不得跨越 persistence
  seam。
- Observation Scope 防止意外 host-wide collection。
- 本地文件使用限制性权限与有界 retention。
- Viewer 是非特权组件，无法接触 BPF map、host PID namespace、container socket 或 node
  credential。

## 11. 失败语义

下列情况始终产生显式 gap 或 failed/degraded collector state：

- ring-buffer reserve failure 或 map pressure；
- resource 或 payload truncation；
- kernel/userspace ABI mismatch；
- decode、attach、verifier 或 permission failure；
- collector restart 或 death；
- late attach、PID reuse ambiguity 或 missing process lineage；
- unsupported syscall、io_uring、guest 或 remote operation path；
- local storage failure 或 incomplete terminal flush。

安静的 timeline 永远不能证明 Agent 没有执行相关动作。

## 12. 当前实现映射

Implemented today：

- `ebpf/observer` 与 `apolysis-observer`：CO-RE tracepoint、ring buffer、
  process-tree/cgroup scope、ABI v3、有界 process/exec 与 cgroup scope generation、
  outcome-aware 选定文件操作与 network connect、protected existing-process TGID seeding、
  per-cgroup operation gap counter、脱敏、lifecycle checkpoint/terminal 以及 health/gap
  diagnostic；
- `apolysis-cli`：fixture/live observation、托管 Agent launch、通过 registration 或 discovery
  完成的 protected existing-process attach、非特权 saved-run projection、可选 Codex intent
  correlation、visibility 与 verification command；
- `apolysis-core`：当前 JSONL vocabulary、record type、版本化 Collector Capability
  manifest 与 collector lifecycle schema；
- `apolysis-store`：rotation、可选本地 hash-chain envelope，以及读取 plain/rotated 或 verified
  saved run 的有界 stable-snapshot reader；
- `apolysis-accountability`：纯 Agent Observation Record projection、相互独立的 summary
  axis、可选声明意图对比与面向复查的 finding；
- `apolysis-kubernetes` 与 `apolysis-visibility`：有界 runtime metadata 与 visibility
  boundary assessment；
- `apolysis-daemon`：long-lived observer、有界 queue、本地 socket、runtime registration
  prototype、scoped lifecycle persistence 与幂等的未完成实例恢复。

Live collector 会在成功 attach 后、释放托管 Agent gate 前把 capability manifest 与 lifecycle
start 同步到稳定存储；对 protected existing-process attach，它会先持久化唯一的 unknown-history
`late_attach` boundary。选定文件操作与 network connect 已具备有界 entry/exit outcome 语义，
daemon 会在显式移除 scope 与正常关闭时把这些配对 gap 持久化到所属 Agent Run。单次运行内
稳定的 scope/process generation、周期累计 lifecycle checkpoint、显式 terminal reason 与
restart-gap recovery 与可查询 saved-run projection 已实现。交互式 saved-run viewer 和有界
Kubernetes Beta 仍是 target。

中央 contracts、Gateway、PostgreSQL projection、evidence-object 集群、
policy/feedback/control plane、sandbox runner 与广泛 qualification machinery 已移出活跃
workspace。Git 历史保留它们作为历史实现输入；它们不定义本文架构。

## 13. 限制

- L2 是有界、本地、single-Agent-Run JSON projection，不是 L3 交互式 viewer、live tail、
  cross-run search 或中央 query plane。
- eBPF 看到 kernel/runtime operation，看不到逻辑推理或隐藏的 remote provider state。
- Relative path、fd-relative operation、namespace、overlay 与 guest runtime 需要显式解析和
  capability limit。
- 成功 connect 不证明远端 operation 已 commit。
- 没有额外传播 identity 时，无法区分同进程中的逻辑 Agent；runtime-only attribution 保持
  process-level。
- Protected existing-process attach 只支持 initial PID namespace，以及共享的 initial、
  unshifted time namespace。
- Per-seeded-candidate pidfd sandwich 与 exit hook 会关闭 candidate 锚定后的退出与换代竞态，
  但不能建立 pre-anchor selection continuity：external-registration root 可能在 registration
  创建到 root `pidfd_open` 之间，被具有相同 PID、USER_HZ tick、executable 与 command 的进程
  替换；lineage candidate 也可能在 snapshot 到 `pidfd_open` 之间，被具有相同 PID、tick 与
  lineage 的进程替换。这些有界 same-tick ambiguity 限制 selection claim；但 activation 后的
  kernel start time、process generation 与 exec generation 仍在本次 collector run 内提供 exact
  event identity。
- Cgroup scope drain 时仍 pending 的 connect 或 file entry 会保留在有界配对 map 中，直到
  syscall 返回或 thread 退出。它们捕获的 scope generation 会阻止其在数字 cgroup ID 复用后
  跨入后续 Agent Run；但 generation allocator 属于 observer-lifetime state，不能建立跨
  collector restart 的 identity continuity。
- Entry 缺失后，exit 侧无法重建 `openat` 或 `openat2` flags，因此这类 unmatched exit 会
  保守归因到 `file_open`，而不是 create 或 truncate。
- 被攻陷的 kernel 或 privileged host 可以省略或伪造 observation。
- Kernel version、BTF、hook availability、verifier behavior 与 privilege 限制支持范围。
- 当前资格 contract 没有授予任何 Supported profile。Linux 6.12 x86_64 原生 host 仅为
  Candidate；其他 kernel、architecture 与 container/Kubernetes runtime 在准确、保留的 live
  证据通过前都保持 Experimental。确定性的 content-free workload 与配对原始采集 harness 已
  冻结 expected event count、monotonic latency sample、隔离的 collector
  CPU/process/cgroup/BPF memory sample 与 pair-level bootstrap summary，并把 burst loss
  归因到独立 rate phase；晋级仍需要保守数值 budget 和足量、保留的 privileged 重复证据。

## 14. 非目标

- Agent orchestration、scheduling、memory、model routing 或 sandbox。
- 通用 Hook、SDK、OTLP、MCP 或 A2A observability platform。
- Remote outcome verification 与跨 provider Agent evidence graph。
- 同步 policy denial、approval workflow、BPF-LSM enforcement 或自动 containment。
- 多租户 Gateway、PostgreSQL/S3 custody、evidence-object lifecycle、billing、HA 或公共 SaaS。
- SIEM、prompt evaluation、token-cost analytics 或长期 data lake。
- macOS/Windows kernel sensor、TLS plaintext、默认 prompt/response 或无差别全 syscall 采集。

# Apolysis 设计文档

> [English](design.md) | 简体中文
> 配套文档：[roadmap.zh-CN.md](roadmap.zh-CN.md)
> 最后审查：2026-08-03

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
- 带 PID reuse 防护的现有 process tree；
- 一个 container 或 workload cgroup；
- 由 node daemon 管理的有界 cgroup 集合。

Managed launch 是首选本地 workflow，因为 collector 可以在 Agent 启动前完成 attach。Attach
到已运行进程可能错过之前的活动，必须记录这一 gap。

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
ownership。Collector restart 仍是可见 identity boundary：在 lifecycle persistence 实现前，
不声明跨重启 continuity。PID namespace、container、Pod 与 node identity 在可用时仍作为
增量 attribution。

### 5.4 本地 Store 与 Viewer

首个产品保持 local-first。Store 有界、安全轮转，并保留显式 run start、capability、health
checkpoint、terminal state 与 gap record。当前格式是 append-only JSONL 和可选本地
hash-chain envelope。Saved-run viewer 需要时，可以在同一 record model 后加入 query index。

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

Collector lifecycle record 携带 start、capability manifest、周期 health、loss counter、
terminal state 与 stop reason。缺少 terminal record 本身就是 Observation Gap。

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
  outcome-aware 选定文件操作与 network connect、per-cgroup operation gap counter、脱敏和
  health/gap diagnostic；
- `apolysis-cli`：fixture/live observation、托管 Agent launch、可选 Codex intent
  correlation、visibility 与 verification command；
- `apolysis-core`：当前 JSONL vocabulary、record type 与版本化 Collector Capability
  manifest；
- `apolysis-store`：rotation 与可选本地 hash-chain envelope；
- `apolysis-accountability`：可选声明意图对比与面向复查的 finding；
- `apolysis-kubernetes` 与 `apolysis-visibility`：有界 runtime metadata 与 visibility
  boundary assessment；
- `apolysis-daemon`：long-lived observer、有界 queue、本地 socket 与 runtime registration
  prototype。

Live collector 会在成功 attach 后、释放托管 Agent gate 前把 capability manifest 同步到稳定
存储。选定文件操作与 network connect 已具备有界 entry/exit outcome 语义，daemon 会在显式
移除 scope 与正常关闭时把这些配对 gap 持久化到所属 Agent Run。单次运行内稳定的
scope/process generation 已实现。完整 collector lifecycle record 与 restart-gap persistence、
saved-run viewer 和有界 Kubernetes Beta 仍是 target。

中央 contracts、Gateway、PostgreSQL projection、evidence-object 集群、
policy/feedback/control plane、sandbox runner 与广泛 qualification machinery 已移出活跃
workspace。Git 历史保留它们作为历史实现输入；它们不定义本文架构。

## 13. 限制

- eBPF 看到 kernel/runtime operation，看不到逻辑推理或隐藏的 remote provider state。
- Relative path、fd-relative operation、namespace、overlay 与 guest runtime 需要显式解析和
  capability limit。
- 成功 connect 不证明远端 operation 已 commit。
- 没有额外传播 identity 时，无法区分同进程中的逻辑 Agent；runtime-only attribution 保持
  process-level。
- Cgroup scope drain 时仍 pending 的 connect 或 file entry 会保留在有界配对 map 中，直到
  syscall 返回或 thread 退出。它们捕获的 scope generation 会阻止其在数字 cgroup ID 复用后
  跨入后续 Agent Run；但 generation allocator 属于 observer-lifetime state，不能建立跨
  collector restart 的 identity continuity。
- Entry 缺失后，exit 侧无法重建 `openat` 或 `openat2` flags，因此这类 unmatched exit 会
  保守归因到 `file_open`，而不是 create 或 truncate。
- 被攻陷的 kernel 或 privileged host 可以省略或伪造 observation。
- Kernel version、BTF、hook availability、verifier behavior 与 privilege 限制支持范围。

## 14. 非目标

- Agent orchestration、scheduling、memory、model routing 或 sandbox。
- 通用 Hook、SDK、OTLP、MCP 或 A2A observability platform。
- Remote outcome verification 与跨 provider Agent evidence graph。
- 同步 policy denial、approval workflow、BPF-LSM enforcement 或自动 containment。
- 多租户 Gateway、PostgreSQL/S3 custody、evidence-object lifecycle、billing、HA 或公共 SaaS。
- SIEM、prompt evaluation、token-cost analytics 或长期 data lake。
- macOS/Windows kernel sensor、TLS plaintext、默认 prompt/response 或无差别全 syscall 采集。

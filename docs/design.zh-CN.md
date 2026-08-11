# Apolysis 设计文档

> [English](design.md) | 简体中文
> 最后审查：2026-08-12

本文是唯一的详细产品文档，权威定义 Apolysis 是什么、目标系统如何工作、稳定 record 与资格
contract、当前已经实现什么、未来方向，以及产品声明止步于何处。

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
工程团队。首批受支持 workflow 是本地 Agent CLI、Linux self-hosted CI 和 container。K1
implementation 增加了有界 Kubernetes containerd/K3s node workflow，但不会把仍未完成资格
验证的 profile 晋级到 Experimental 以上。

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
  |- Kubernetes Workload Claim
  |- Kubernetes Attribution
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

共享词汇如下：

| 术语 | Contract |
| --- | --- |
| Agent | 被观测运行时活动的自主参与者 |
| Agent Run | Agent 及其归属 process tree 为一项声明任务工作的有界时间段 |
| Observation Scope | 属于一次 Agent Run 的 runtime boundary |
| Protected Attach | 对已运行 Agent 的资格化准入；不声明更早历史或 pre-anchor continuity |
| Collection Boundary | Collector Capability 开始适用的位置；更早活动是以 gap 表示的未知历史 |
| Runtime Identity | 区分复用与偶然匹配的稳定 process/workload identity |
| Kubernetes Workload Claim | Operator 为一次 Agent Run 与 claim revision 授权的 exact cluster/namespace/Pod/container slot |
| Kubernetes Attribution | 从一条 exact claim 与稳定 Pod candidate 到一条 active Exact D1 runtime binding 的 qualified lifecycle relation |
| Runtime Observation | 在 capability 与 scope 内报告的受支持 process/file/network/credential operation |
| Operation Outcome | 在声明 source 语义内的 `attempted`、`succeeded`、`failed`、`denied`、`pending` 或 `unknown` |
| Collector Capability | 某一环境 boundary 的版本化 operation/source/outcome 声明 |
| Collector Health | 独立的 `healthy`、`degraded`、`failed` 或 `unknown` collector 状态 |
| Observation Gap | 对 missing、lost、truncated、unsupported、ambiguous 或 scope 外证据边界的显式记录 |
| Exact / Inferred / Ambiguous Relation | 稳定身份关系、相关证据支持的关系，或仍有多个合理目标的关系 |
| Unattributed Observation | 位于 scope 内但无法负责任地进一步归属的 observation |
| Finding | 从有界 observation 派生的可复查条件；永远不是 enforcement verdict |
| Saved Run Viewer | 一份冻结 Agent Observation Record 的本地只读呈现；不是 evidence source |

新接口与文档使用这些术语。“Session”“job”“tenant”、process name 或裸 PID 不得在公开声明中
替代 Agent Run、Observation Scope 或 Runtime Identity。

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

#### Container runtime binding 与 recovery

Docker 与 containerd attribution 消费成功、完整的 adapter inventory，而不会把 sighting stream
直接当作权威。一个稳定 workload identity 包含 adapter、完整 workload/container ID、runtime
start marker、host boot ID、init-process clock tick start time，以及 cgroup filesystem
`(device,inode)` identity。PID、process/container name、timing、runtime path 与数字 cgroup ID
都不能独立成为 Exact。

相同 complete inventory 是 no-op。只有成功的 complete inventory 才能 retire 缺失 binding。
相同 adapter/workload key 若出现不同 stable identity，就是显式 identity transition：旧 binding
会先得到一条带 `reason=identity_transition` 的 `runtime_metadata_unavailable` gap，然后被
retire；replacement 只有通过资格化后才能 attach。Duplicate workload key、
冲突 cgroup identity、adapter mismatch、缺失或超限 identity field、过大 inventory 都会 fail
closed。Socket 或 decode failure 不是 empty inventory，因此不能静默 retire，也不能保留陈旧
Exact attribution。

Runtime source 丢失会 suspend 受影响的 active binding，并在恢复前持久化 Observation Gap。
Daemon restart 只把持久化 binding 恢复为 dormant，而不是 Exact；必须由新的 complete inventory
重新资格化。Socket disconnect、runtime service restart 与 daemon restart 使用有界 backoff，
不可用期间 adapter health 为 degraded，只有取得合法 inventory 后才恢复 ready。Docker、
containerd 与 k3s-containerd 使用相同 recovery 语义；Kubernetes metadata 仍是增量信息，不能
升级未资格化的 container binding。

D1/D2 implementation 与 deterministic contract 已完成。保留的非破坏性 Docker qualification
证明以下全部边界：

- complete inventory 建立 active binding；同一完整 container ID 重启后会改变 stable identity，
  不会继承陈旧的 PID、名称、时间或数字 cgroup attribution；
- 受控 adapter-socket outage 会先持久化 source gap，再 suspend binding 并清除 active
  ownership；之后只有 fresh complete inventory 才能重新 observe 该 stable binding；
- 在同一 private state root 上创建新的私有 daemon/server lifecycle 时，replay binding 保持
  dormant；active query attribution 恢复前必须按 `daemon_restart` gap -> retired -> observed
  顺序完成 recovery；
- 真实 content-off eBPF file event 携带 Exact container 与 cgroup identity，同时完成 Agent Run
  capability manifest 与 hash chain 验证。

特权 Docker/eBPF boundary 可通过 `make qualify-runtime-binding-live` 复现。Runner 以普通用户
身份构建 BPF 与测试，把唯一测试可执行文件和 CO-RE BPF object 发布为经过校验、root-owned 的
私有副本，并且只针对固定的本地 Docker Engine socket 调用该 exact opt-in gate。测试本身会在
任何 Docker mutation 前检查 kernel、Docker、image、service state 与 ownership prerequisite，
并执行 identity-bound cleanup。Skip 不等于 pass；直接对测试 binary 使用裸 `--ignored` 不属于
该 contract。

这些 gate 只资格化已保留的 Docker 行为。独立的私有 standalone-containerd boundary 可通过
`make qualify-private-containerd-live` 复现；该目标由具备预授权 `sudo` 的非特权 checkout owner
显式调用 `scripts/run-private-containerd-live.sh`。Runner 固定 official `crictl` v1.36.0 archive
与 binary hash，只接受该 verified binary（或下载并校验 official archive），并要求本地 Docker
store 已存在 pinned Alpine image。它使用 host 本地的 containerd 与 runc binary，再通过保存并
导入该 cached image，以离线方式构建私有 workload store；资格验证期间不会拉取 workload image。

Runner 进入 create-only 的 delegated user systemd scope，把 scope root process 移入私有 `init`
child，并只启用实际存在的必需 controller，从而准备合法的 cgroup-v2 nesting。之后特权 gate
使用 runc，并以私有 root、state、socket、plugin、CNI、CDI、NRI、image-verifier 与 `opt` path
启动私有 containerd instance。Mount、network、UTS、IPC 与 cgroup namespace 相互隔离。Outer PID
namespace 有意与 host 共享，使 `/proc` 能证明每个 owned process 与 cgroup generation；每个 CRI
Pod sandbox 和 workload 的 PID namespace 仍由 runc 创建并隔离。Gate 不重启 shared service，
不修改 shared CNI configuration 或 iptables，也不使用 shared runtime socket 或 store。

保留的 private-containerd 结果证明 complete initial inventory、相同的 stable inventory，以及
replacement workload 的 fresh full container identity 与 stable-proof generation；未变化 workload
仍保持原 identity。受控 proxy-socket outage 会持久化 source gap、suspend active ownership，且
reconnect 后只有 fresh complete inventory 才能再次 observe。`crictl` 可能把 CRI `startedAt`
渲染为带 numeric UTC offset 的 local-time RFC3339Nano；adapter 会在边界严格归一化为既有
canonical positive-decimal Unix-nanosecond marker，不持久化 offset text。

Cleanup 由 proof 约束并 fail closed。Runner 只删除经过证明的私有 CRI object 及其 process/cgroup
generation，停止私有 runtime，移除其 namespace、mount、delegated scope 与 create-new root，并
要求这些对象全部不存在后才报告成功。执行前后都会绑定 shared Docker/containerd service state、
PID、socket identity、cached Alpine identity 与 Docker container inventory。无法确定的私有
cleanup 或 residue 会使 gate 失败并保留 private root；shared baseline drift 同样使 gate 失败，
但若私有 cleanup 已被独立证明，该 root 仍可删除，因为它不是 shared-host state 的证据权威。

Shared-host CRI discovery gate 若报告 `RuntimeReady=true` 但 `NetworkReady=false`，仍会在 mutation
前 clean skip；该 skip 不算 pass。已保留的 private standalone 结果关闭了有界 D1/D2 containerd
qualification，但不资格化 Kubernetes 或 shared containerd installation。Docker 证据不能外推到
containerd，private-containerd 证据也不能外推到 Kubernetes。因此 containerd 与 Kubernetes
profile 继续保持 Experimental，任何 profile 都不会因此成为 Supported。

通过 systemd 实际重启 Docker/containerd service 仍属于非破坏性 D1/D2 闭环之外的额外、破坏性
opt-in qualification。这些 gate 与 K1/VKE Kubernetes live qualification 仍保持 open；它们
不会使已保留的 Docker 或 private-containerd 证据失效。

#### Kubernetes node 与 Pod 归属（K1）

K1 以每个 node 一个双容器 DaemonSet Pod 的形态部署。Root collector 负责加载 eBPF、访问
host `/proc`、cgroup、BPF、trace/BTF、恰好一个 CRI runtime socket，以及本地状态边界；它不
持有 service-account token。它不是 privileged container，不能 privilege escalation，使用
read-only root filesystem，drop 全部 ambient capability，并且只增加 `BPF`、`PERFMON`、
`SYS_RESOURCE` 与 `DAC_READ_SEARCH`；不会获得 `SYS_ADMIN`。Pod 不加入 host PID 或 network
namespace。Metadata-source container 以
UID/GID `65532` 运行，drop 全部
capability，使用 read-only root filesystem，并且只有它接收 projected、轮换的
service-account token。生产启动会验证精确 effective UID/GID，且 effective capability 集合必须
为空。其 Role 仅允许在 DaemonSet 自身专用 Agent namespace 中对 Pod 执行
`list`、`watch`；automatic token mounting 被关闭。它没有 cluster-wide 或
cross-namespace read path。
该专用 namespace 是 operator-controlled trust domain：不受信 tenant 不得在其中获得 Pod
`create`、`update` 或 `patch` authority。

两个容器只共享一个有界 memory-backed IPC volume。Source 拥有 mode `0700` directory 与
UID/GID `65532`、mode `0660` Unix socket；source 先以不可预测的 private name bind，完成全部
资格校验后再用一次 no-replace rename 发布。collector 在 strict supplemental-group policy 下获得
shared GID `65532`，以及穿越/读取该
private directory 所需的 `DAC_READ_SEARCH`（以及 BPF 所需 capability）。双方都会围绕有界
framed I/O 验证 socket type、ownership、mode、
connect 前后 inode identity 与 peer credential。Stale-socket recovery 使用 nonblocking
liveness probe，且只删除精确证明的 inode。Collector 的持久 host directory 是独立 operator 前置条件，必须
预先创建为 root 所有、mode `0700`；DaemonSet 不创建宽泛 host path。一个 K1 daemon 恰好拥有
一个 `containerd` 或 `k3s_containerd` inventory domain；同时配置两个 socket 会被拒绝。
随仓库交付的 canonical manifest 固定使用 VKE/containerd path
`/run/containerd/containerd.sock`。K3s 已有实现支持，但 operator 必须提供匹配 K3s socket 且保持
本文 security/ownership contract 的 manifest 或 overlay；仓库当前不交付该 overlay。但 host CRI
socket 在协议上仍暴露 mutating method，因此 collector 仍是 node-trusted。移除
`SYS_ADMIN`、隔离 token 与收窄 host mount 都是相对的 privilege reduction，而不是真正 read-only
runtime boundary。真正的 read-only CRI access 需要未来增加 allowlist broker，不能直接拥有 socket。

Operator authorization 通过 `SessionIntent.kubernetes_claims` 进入，而不是来自发现的 Pod
metadata。每条 claim 具有一个非零 revision 与精确 tuple
`(cluster_id,namespace_ref,pod_uid,container_kind,container_ref)`；同一 intent 的所有 claim
共享 revision，duplicate slot 会被拒绝。Operator 必须为 deployment 生成跨 cluster 唯一且
immutable 的 `cluster_id`；source 只验证 canonical non-zero UUID shape，无法发现误复用或证明
cluster identity。

| Claim field | Contract |
| --- | --- |
| `schema_version` | u32 常量 `1` |
| `claim_revision` | 同一 intent 每条 claim 共用的非零 u64 |
| `cluster_id` | Canonical lowercase non-zero UUID |
| `namespace_ref` | 64-byte lowercase hexadecimal namespace pseudonym |
| `pod_uid` | Canonical lowercase non-zero Pod UUID |
| `container_kind` | `application`、`init` 或 `ephemeral` |
| `container_ref` | 64-byte lowercase hexadecimal container-name pseudonym |

一个 intent 最多携带 256 条 K1 claim。Unknown claim field、mixed revision、duplicate exact slot、
malformed reference，以及 expired/invalid parent intent 都会在 daemon state mutation 前 fail。
`apolysisd-control` 从 standard input 读取一个有界、类型化 control request，验证本地 daemon
socket 与 peer，应用单一 I/O deadline，并在不回显被拒
value 的情况下转发 request。它是通过 `kubectl exec` 进入 collector container 的预期 operator
ingress。Source label 与 annotation 始终只是 discovery input，不能创建或扩大 claim。

Kubernetes node task 显式启用 CRI Pod-sandbox metadata join。Standalone containerd 保留既有
direct-container-only 行为，K3s 保留既有 sandbox-label 行为。在 K1 mode 中，只有 READY 且 label
精确为 `apolysis.dev/observe=true` 的 Pod sandbox 才参与；unmarked sandbox 会在 private metadata
解析前被忽略。Marked sandbox 必须携带 `metadata.namespace`；不同 namespace 即使 session value
相同也会被忽略，而 configured namespace 还要求标准 label `io.kubernetes.pod.namespace` 精确相同。
Sandbox Agent Run 可来自 label `apolysis.session_id` 或 annotation
`apolysis.dev/session-id`，并归一化为 inherited `apolysis.session_id`。Direct container session
label 仍是 candidate D1 identity 的有效 routing input，但同时存在 inherited routing 时必须相同。
Direct 与 inherited session metadata 都不能授权 D1/scope attach。Present empty/invalid session
value、label/annotation 冲突、target namespace 缺失/冲突、READY target sandbox ID duplicate，或在
list/inspect 中出现 direct/inherited conflict，都会使 complete CRI inventory 整体非法。
Diagnostic 只报告固定 category，永不回显被拒 metadata。Adapter 的 final candidate re-list 使用
完全相同的 K1 mode；canonical set 变化会使 inventory 非法。

该 fail-closed metadata 行为也是显式 availability boundary。Operator namespace 内一条 malformed
marked sandbox 会使该 node 的 K1/runtime cycle degraded。Exact typed claim 会阻止这类 metadata
扩大 authorization，但 K1 不承诺抵抗已经拥有该专用 namespace Pod 写权限的 principal 发起的 DoS。

资格化是一次 closed transaction：

```text
complete paginated Pod LIST A
  -> complete containerd/K3s CRI inventory (whole-scan request_timeout)
  -> complete paginated Pod LIST B
  -> exact typed-claim intersection
  -> filter to claim-authorized full D1 identities
  -> D1 reconcile/attach before durable Kubernetes attribution
```

Watch 只提供 dirty hint，永远不是权威。LIST A 与 LIST B 必须具有相同 source epoch、cluster、
namespace 与 node identity，严格递增的非零 sequence，以及 byte-equivalent canonical Pod
candidate。Candidate 包含 Pod UID、deletion/marker state、runtime-class reference、每个
application/init/ephemeral container slot 与 running container ID，以及从 Pod resource version
派生的 ephemeral `pod_revision_ref`。同一 epoch 的后续 cycle 必须从上次 terminal sequence 之后
开始。任何 pagination、decoding、bound、duplicate、revision 或 A/B mismatch 都使整个 snapshot
非法；failure 永远不会被解释为空 list。

Intersection 要求 marked 且非 deleting 的 Pod、精确 claim slot、具有 canonical full ID 的 running
container，以及属于同一 Agent Run、携带完整 Exact D1 identity 的 candidate。只有最终精确的
`claim -> A/B Pod UID+slot -> runtime container ID -> full D1 identity` key 才进入 admitted
inventory。D1 reconciliation 与 scope attach 只消费该 filtered inventory；unclaimed、mismatched 或
metadata-only candidate 不能产生 D1 state 或 scope ownership。Durable effect ordering 会先 observe
D1，再 observe 对应 K1 attribution。Kubernetes metadata 只是 additive：不能制造 runtime identity，
也不能升级 stale/inferred binding。Raw namespace、
node、container 与 runtime-class name 会在 IPC 前转换为 domain-separated SHA-256 reference。
`pod_revision_ref`、source epoch 与 source sequence 只用于关闭资格竞态，绝不跨越 persistence seam。
持久化 reference 是面向 content-off profile、deterministic 且 unkeyed 的 SHA-256 pseudonym，不是
anonymization 或 confidentiality：低 entropy name 可被离线枚举，相同 value 可跨 run 链接。Pod UID
与 nested D1 full container ID 仍然显式。

```text
reference_v1(kind, raw) = lowerhex(SHA-256(
  "apolysis:kubernetes-reference:v1" || 0x00 ||
  kind || 0x00 || UTF-8(raw)
))
pod_revision_ref = lowerhex(SHA-256(
  "apolysis:kubernetes-pod-revision:v1" || 0x00 || UTF-8(resourceVersion)
))
```

`kind` 恰好是 `namespace`、`node`、`container` 或 `runtime_class`。Namespace/container input
必须是 canonical lowercase DNS label；node/runtime class input 必须是有界 canonical lowercase
DNS subdomain。第二个公式只用于 qualification，绝不是持久化 identifier。

相同 qualified cycle 是 no-op。成功 cycle 中缺失 Pod/container 会 retire K1 attribution。同一 Pod
内 container restart 会改变 D1 identity，并生成有序 K1 identity-transition gap、旧 K1 retire、
fresh D1 qualification 与新 K1 observe。新出现的 K1 link 若引用 cycle 前已存在的 runtime binding，
会记录一个 `kubernetes_late_attach` relation boundary；同一 atomic cycle 新建的 D1 binding 不会。
Declared outage、identity transition 或 restart 的 recovery 不会被误标为 late attach。

Kubernetes API 丢失会发出 API gap 并 suspend K1，同时保持独立健康的 D1 collection active。CRI
丢失会先使 K1 runtime metadata unavailable 并 suspend K1，再应用普通 D1 runtime gap 与
suspension。若一次成功 CRI scan 无法证明 claimed runtime join（runtime identity 缺失、冲突、重复
或非法），也会走相同的 K1→D1 `inventory_invalid` suspension；仅 Pod A/B source churn 时只
suspend K1，并保留独立 exact 的 D1 binding。两类恢复都必须经过 fresh complete A/runtime/B cycle
才恢复 attribution。Source epoch 变化或 daemon state recovery 会发出 `kubernetes_daemon_restart`，retire 既有 active/dormant
K1 state，并只 re-observe fresh qualified link。关闭 claim 或替换 claim revision 时，会在其 D1
binding 前，以同一事务 retire K1 link 与 K1 独占的 containerd/K3s D1 binding，并在确认替换前
untrack 对应 scope；即使 Kubernetes metadata 当前 unavailable 也保持该语义。独立 Docker binding
不会被该 K1 transaction 撤销。Cross-node reschedule 不是 continuity：旧 Pod UID retire，新 Pod
UID 在有界 handoff 后独立 observe；系统不声明 gap-free ownership。

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
hash-chain envelope。L3 Saved Run Viewer 直接消费冻结的 single-run record。只有重复使用证明
有界 single-record 视图不足时，才考虑后置的 query index。

V1 saved-run 读取路径会把 active file 与连续数字 archive 作为同一个稳定本地 snapshot，按
最旧 archive 到 active 的顺序读取；它拒绝 symlink、非普通文件、读取期间变化、截断、格式错误
和混合 envelope，并在暴露 payload 前验证完整 hash chain。Byte、line 与 record 都有明确上限。
Source order 是权威顺序；wall-clock timestamp 不会修复或重排非法 lifecycle。Plain 与 verified
输入可以显式组合，但 mixed integrity 始终可见，不能产生 complete evidence。Batch、byte 与
record budget 作用于整个组合命令，而不是分别作用于每个 `--input`。

`apolysis-accountability` 会把这些 typed source record 纯函数式折叠为恰好一份 Agent
Observation Record。Agent Observation Summary 保持 Evidence State、Collector Health 与
Review State 相互独立。缺失 lifecycle、不支持的 outcome、diagnostic、Observation Gap、未知
record 与 source-integrity finding 会保留为可查询限制；mixed Agent Run、损坏 storage、非法
lifecycle 顺序、重复 canonical observation、不兼容 schema 与 content-policy violation 会
fail closed。自由文本 Finding reason 与 Gap detail 会 canonicalize，而不是复制到派生 artifact。
经过验证的 runtime-binding 与 Kubernetes-attribution lifecycle fact 会按 source order 保留在
projection 中；验证会重建两种 lifecycle，而不是把它们归约为当前 active set。

Complete evidence 要求完整的当前 v1 operation/source/outcome capability contract。Partial 或
伪造 manifest 与无法解析的 Finding reference 会作为 typed issue 保留，不能成为 complete。
只有携带 canonical generation-based relation reason 与完整稳定 tuple 的 post-activation kernel
observation 才能进入 Exact Runtime Identity。

`apolysis run project --input <path> [--input <path> ...] --output <path>` 是该 projection
的非特权 adapter。它通过同目录私有 temporary file 写入确定性 JSON，完成 sync 后原子发布，
并拒绝 output alias 任何 active 或 rotated input。该命令是 saved-run projection，不是 live
tail、remote query API 或交互式 viewer。

`apolysis run view --input <agent-observation-record.json> --output
<viewer.html>` 是非特权 Saved Run Viewer adapter。它只接受一份 Agent Observation Record
v1，验证其类型、schema、summary、identity reference、source ordinal、Finding link、
runtime-binding/K1 lifecycle 与状态一致性，然后渲染确定性的 self-contained HTML。格式错误或
内部不一致的 record 会 fail closed，且不会替换现有 output。Reader 有界并拒绝 symlink 与非
普通文件；publisher 在使用独占、mode 为 `0600` 的同目录 temporary file、同步文件与目录并
原子 rename 前，会拒绝 output alias。

该 HTML 是离线、只读 artifact，不依赖外部 asset 或网络。限制性 Content Security Policy
禁用 connection 与外部 resource，每个存储值都按不可信文本渲染。Viewer 不需要 root，也不
接触 BPF map、host PID namespace、runtime socket 或 node credential。

Viewer 提供：

- 保持 Evidence State、Collector Health 与 Review State 三个状态轴相互独立的单次 run
  summary；
- Exact Runtime Identity roster，以及 Runtime Observation 中保留的 reported PID/PPID field；
- 有序的 observed、retired 与 suspended runtime-binding lifecycle；
- 带 Exact D1 source link 的有序 observed、retired 与 suspended K1 lifecycle；
- 有序 process、file、network 与 credential timeline；
- 受支持的 outcome 与 attribution status；
- collector health、loss、truncation 与 unsupported capability gap；
- 链接到 supporting Runtime Observation 或更早、精确匹配的 observed runtime binding 的
  review-oriented Finding；
- 使展示事实可追溯到冻结 record 的 source ordinal 与 record path。

Agent Observation Record v1 不携带权威 parent Runtime Identity link。因此 viewer 不会从可能
复用的数字 PID/PPID 构造 canonical process tree；它只把 identity roster 与 reported PPID
作为已存储事实展示，不推断 parent edge。它也不会从空结果推导隐藏的 success verdict，更
不会把三个 summary axis 合并为 clean verdict。

派生的 v1 对象是一份 JSON object，永远不会追加回 timeline JSONL。Top level 是
`record_type`、`schema_version`、`agent_run_id`、`source_integrity`、`summary`、
`capability_manifests`、`runtime_identities`、`runtime_observations`、
`runtime_bindings`、`kubernetes_attributions`、`collector_lifecycle`、`findings`、
`observation_gaps` 与 `issues`。每个投影后
的 source fact 携带来自权威输入顺序、从 1 开始的 `source_ordinal`。Summary 保留 typed count
与 grouping map，不合并 Evidence State、Collector Health 与 Review State。

Projection limit 为：全部 input 合计 128 MiB、每行 JSONL 1 MiB、1,000,000 条 source record、
1,024 个数字 archive、1,024 个 input batch、每个 string 4,096 bytes、每个 array 1,024 items、
每个 object 256 fields、value 最深 16 层。发布使用独占 mode-`0600` temporary file、file/parent
sync 与 atomic rename；替换前拒绝 source alias 与不安全 file type。

`apolysis verify hash-chain` 是只读操作。退出码 `0` 表示所有 record 与 tail 验证通过，`1`
表示已经写出失败报告，`2` 表示命令无法运行。报告保留 verified record count、last sequence/
hash、valid/total bytes 与有界 failure category。Middle corruption、truncated 或 corrupt tail
都会 fail closed，不会 truncate、repair 或 quarantine 源文件。

外部 log shipping 保留每条原始 JSONL line 与 record body。Vector、Fluent Bit 或其他 operator
transport 可以在 body 外 route、buffer、compress 或 encrypt，但不会成为 schema 或 query
authority。复制出的 daemon hash chain 在 replay 前必须验证；确认 downstream retention 前，
本地 evidence 仍是权威。OTLP 与项目自有 exporter 保持 deferred。

### 5.5 本地 daemon 运维

Linux release bundle 包含 `apolysis`、`apolysisd` 与 `apolysisd-health`
binary、CO-RE object 和 systemd unit。Release manifest schema v2 会把恰好这 5 个可安装
artifact 绑定到各自的 kind、SHA-256 digest、byte length 与要求的 mode。Manifest path 不会
成为任意 destination；installer 只把这一封闭 artifact 集合映射到
`/usr/local/bin/apolysis`、`/usr/local/bin/apolysisd`、
`/usr/local/bin/apolysisd-health`、
`/usr/local/lib/apolysis/apolysis_observer.bpf.o` 与
`/etc/systemd/system/apolysisd.service`。

Release verifier 只接受一条有界且 canonical 的 gzip/tar stream，拒绝重复或扩展 archive metadata
与非普通 member，检查封闭 manifest 和 systemd contract、可执行 ELF 结构，并要求
`bpftool gen skeleton` 能解析打包的 CO-RE object。Package contract test 使用刚构建的真实
object；production verifier 没有 structural fixture 开关。

`apolysis daemon install --bundle <dir> --root <root>`、`inspect` 与 `uninstall` 是
`LocalDaemonOperations` 的 adapter。这个 deep module 只暴露 inspect、plan 与 apply，并隐藏
bundle validation、完整 target preflight、filesystem snapshot、descriptor-anchored staging、
sync、crash recovery 与 receipt ownership。Root、bundle、parent 与 mutation 都以已打开的
directory 为锚，并使用 no-follow 语义。Receipt proof 会绑定 owner、包含 special bit 的 mode、
digest、size 与 file identity。它会拒绝 linked 或非普通 source/target、hard-linked artifact、
非法或已变化的 bundle、非托管 conflict、已变化的 managed file 和 stale plan。成功安装会发布
`/usr/local/lib/apolysis/install-receipt-v1.json`；重复安装相同托管内容是 no-op。默认卸载只会
删除仍可由该 receipt 证明 ownership 的 artifact，并始终保留 `/var/lib/apolysis` 与无关 host
file。

每次有 mutation 的 apply 都会在发布各个文件前写入并同步一个固定、私有、mode `0600` 的
operation journal。重新打开 module 时会回滚 pre-commit transaction，或完成已经 committed 的
cleanup，并通过 inspection 暴露 `recovered_interrupted_operation`。Replacement 与 removal
使用经 identity 复核的 descriptor-relative operation；发生变化或未知的 journal/transaction
sibling 会 fail closed，等待人工修复。这提供 durable interruption recovery，但不宣称 5 条
host path 能在一个瞬间可见的 filesystem transaction 中同时变化。

Staged root 会执行相同的固定路径 filesystem contract，但不调用 systemd、group management
或 eBPF。产品支持随包 systemd unit 这一种具体 integration，不提供抽象 service-manager
interface。在真实 host 上，该 unit 要求显式 provision `apolysis` group；systemd 负责
activation、SIGTERM shutdown 与有界 drain deadline，资格验证复用 daemon 现有 health
protocol。Runtime/state directory 为 mode `0750`，daemon timeline 为 `0640`，私有
quarantine 与 retention journal 为 `0600`，显式管理的本地 socket 保持 `0660`。Staged-root
验证不能替代 opt-in privileged gate；后者会加载真实 bundle、等待 eBPF 与 storage readiness、
停止 unit，并验证保留 state 的卸载。

Uninstall 不是 retention。破坏性 retention 从 daemon clock 取得时间，依据 directory identity
与已经打开的 single-link timeline descriptor 验证每个 closed Agent Run，阻止 late write，并把
准确集合 staged 到私有的同 filesystem trash root。同步的 typed journal 区分 staging 与已提交
cleanup。Startup 会回滚未完成的 staging transaction，并完成已提交 cleanup；unsafe target
replacement、未知内容、journal corruption 或冲突 live state 都会 fail closed。非 mutation 的
preview 可以为确定性测试使用显式时间，但 caller 不能为破坏性 apply 提供时间。破坏性 apply
只适用于本地 default context；旧 schema 的非 default 请求会在零 mutation 下被拒绝，多租户
删除仍保持 deferred。Terminal retention catalog 具有独立的 4,096 Agent Run 上界；达到上界
时会 fail closed，既不驱逐 retained state，也不占用 active-run capacity。

Hash-chain recovery 会以 no-follow 语义只打开 timeline 一次，并在 validation、quarantine、
truncate 与后续 append 中复用该 descriptor。它拒绝 symbolic link、multiply linked file 与
path replacement。可恢复的 corrupt tail 会保留在私有 create-new quarantine file 中；middle
corruption 仍会 fail closed。Recovery 与 retention 都不会把由此产生的 integrity 或 Collector
Restart 限制改写成 complete evidence。

### 5.6 后置的中央边界

Remote export、custody、organization authorization、object storage、跨 run search 与 HA
都不属于有界 Beta。只有当重复使用证明需要中央服务，并由新的架构决策定义边界后，它们才会
重新进入。

## 6. Observation contract

Timeline schema v1 是 newline-delimited JSON：每行一个完整 object，每个 object 一个
`record_type` string；除非 field name 另行声明，timestamp 使用 Unix milliseconds；数字 ID
使用十进制；optional field 显式输出 `null`。兼容规则是 append-only。Consumer 忽略未知 field
与新增 record type，不依赖 object field 顺序，并使用稳定 ID 而不是 timestamp 做 join。下文
runtime-binding lifecycle 等显式 closed sub-schema 会拒绝未知 field。删除、rename、type 或
semantic change 需要新 schema version。Producer 在持久化前脱敏；默认
`content_off` profile 永不写入 raw secret、argv、prompt、response、socket、path、label、
annotation 或 tool payload。

稳定 record family 是：

| `record_type` | 必需 contract |
| --- | --- |
| `collector_capability_manifest` | Agent Run、collector/ABI identity、Observation Scope、privacy profile、有序 operation/source/outcome 声明 |
| `collector_lifecycle` | Agent Run、不透明 collector instance、start/checkpoint/terminal state、health、stop reason、累计 loss/pending counter |
| `event` | Agent Run、source/type/raw ID、actor/resource/action、outcome/return/errno、runtime identity field、relation status/reason |
| `raw_kernel_event` | 带 ABI identity、有界 redacted resource/payload、outcome 与 raw event ID 的 normalization 前 kernel fact |
| `intent` / `intent_correlation` | 可选 content-off declared intent 及其 stable-ID 或有界 executable correlation；不是 observation 必需输入 |
| `accountability_finding` | Typed review decision、有界 canonical reason、evidence reference、runtime identity 与 evidence boundary |
| `observation_gap` | 可能缺失或不可用证据的 typed operation、kind、count 与 bounded detail |
| `runtime_binding_observed` / `runtime_binding_retired` / `runtime_binding_suspended` | 围绕单一 stable workload identity 的持久 Docker/containerd binding lifecycle |
| `kubernetes_attribution_observed` / `kubernetes_attribution_retired` / `kubernetes_attribution_suspended` | 围绕一条 Exact observed containerd/K3s runtime binding 的持久 claimed Pod/container attribution lifecycle |
| `observer_diagnostic` | Typed bounded attach、verifier、ABI、decode、truncation、pressure、loss 或 summary diagnostic |
| `visibility_assessment` | Runtime profile、host visibility scope、metadata/guest-collector requirement 与 bounded subject |

### 6.1 Timeline JSONL wire schema v1

下列表格中的每个 field 都是 wire 必需 field。`T|null` 表示 field 必须出现，但 value 可以是
JSON `null`；其他 field 都不可为空。`u32`、`u64` 与 `u128` 是处于对应 Rust range 内的非负
JSON integer，`i32` 与 `i64` 是有符号 JSON integer，`map<string,u64>` 是 value 为非负
count 的 JSON object。

`collector_capability_manifest` 的 shape 是：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `record_type` | string | 常量 `collector_capability_manifest` |
| `schema_version` | u32 | 常量 `1` |
| `timestamp_unix_ms` | u128 | 持久化时间 |
| `agent_run_id` | string | 所属 Agent Run |
| `collector` | string | 常量 `apolysis_observer` |
| `collector_version` | string | Userspace package version |
| `kernel_abi_version` | u32 | 当前 live ABI 为 `3` |
| `kernel_record_size` | u32 | 当前 ABI-v3 size 为 `656` |
| `observation_scope` | enum | `process_tree` 或 `cgroup` |
| `privacy_profile` | enum | 常量 `content_off` |
| `capabilities` | array<object> | 有序 capability object |

每个 capability object 包含必需的 `operation:string`、
`event_sources:array<string>` 和 `outcomes:array<enum>`。Outcome value 是
`attempted`、`succeeded`、`failed`、`denied`、`pending` 与 `unknown`。兼容的
AuditObserver v1 manifest 必须声明下列完整 operation contract；file capability 只有包含完整
entry/exit source set 时才有效。

| Operation | Event source | Outcome |
| --- | --- | --- |
| `process_fork` | `sched/sched_process_fork` | `succeeded` |
| `process_exec` | `sched/sched_process_exec`、`syscalls/sys_enter_execve`、`syscalls/sys_enter_execveat` | `succeeded`；sched source 必需 |
| `process_exit` | `sched/sched_process_exit` | `unknown` |
| `file_open` | `syscalls/sys_enter_openat`、`syscalls/sys_exit_openat`、`syscalls/sys_enter_openat2`、`syscalls/sys_exit_openat2` | `succeeded`、`failed`、`denied` |
| `file_create` | file-open source 加 `syscalls/sys_enter_creat`、`syscalls/sys_exit_creat` | `succeeded`、`failed`、`denied` |
| `file_truncate` | file-open source 加 `syscalls/sys_enter_truncate`、`syscalls/sys_exit_truncate` | `succeeded`、`failed`、`denied` |
| `file_unlink` | `syscalls/sys_enter_unlinkat`、`syscalls/sys_exit_unlinkat` | `succeeded`、`failed`、`denied` |
| `file_rename` | `syscalls/sys_enter_renameat2`、`syscalls/sys_exit_renameat2` | `succeeded`、`failed`、`denied` |
| `network_connect` | `syscalls/sys_enter_connect`、`syscalls/sys_exit_connect` | `succeeded`、`failed`、`denied`、`pending` |
| `credential_path_access` | `syscalls/sys_enter_openat`、`syscalls/sys_exit_openat`、`syscalls/sys_enter_openat2`、`syscalls/sys_exit_openat2` | `succeeded`、`failed`、`denied` |

`collector_lifecycle` 的 shape 是：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `record_type` | string | 常量 `collector_lifecycle` |
| `schema_version` | u32 | 常量 `1` |
| `timestamp_unix_ms` | u128 | Lifecycle 时间 |
| `agent_run_id` | string | 所属 Agent Run |
| `collector` | string | 常量 `apolysis_observer` |
| `collector_instance_id` | string | 同一 process 各 run stream 共用的不透明 UUID |
| `state` | enum | `started`、`checkpoint`、`stopped` 或 `failed` |
| `health` | enum | `healthy`、`degraded` 或 `failed` |
| `stop_reason` | enum|null | Start/checkpoint 为 `null`；terminal value 见下文 |
| `counters` | object | 下列必需的累计 counter object |

正常 stop reason 是 `agent_run_closed`、`daemon_shutdown`、
`duration_elapsed`、`agent_exited` 与 `shutdown_signal`。失败 reason 是
`attach_failure`、`verifier_failure`、`abi_mismatch`、`decode_failure`、
`counter_read_failure`、`storage_failure`、`observer_failure`、
`collector_restart` 与 `incomplete_terminal_flush`。Counters object 有八个必需 `u64`
field：`global_reserve_failures`、`global_map_pressure`、
`global_abi_mismatches`、`global_decode_failures`、`global_truncations`、
`scope_missing_entries`、`scope_missing_exits` 与 `scope_pending`。
`started` 必须为 `healthy`，reason 为 null，counter 为零。`checkpoint` 的 reason 为 null，且
恰好在 persistent-loss counter 非零时为 `degraded`。`stopped` 使用正常 reason，并在存在
persistent loss 或非零 pending 时 degraded。`failed` 的 health 为 `failed`，并使用 failure
reason。

`event` 是 canonical Runtime Observation source record：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `record_type` | string | 常量 `event` |
| `timestamp_unix_ms` | u128 | 观测时间 |
| `session_id` | string | Agent Run ID；这是 legacy wire name |
| `event_source` | enum | `manual`、`process_tree`、`kernel_tracepoint`、`uprobe` 或 `runtime_metadata` |
| `event_type` | enum | `session_started`、`runtime_metadata`、`exec`、`file_open`、`file_create`、`file_truncate`、`file_unlink`、`file_rename`、`network_connect`、`credential_read` 或 `process_exit` |
| `raw_event_id` | string|null | 指向 raw event 的 canonical join |
| `pid` | u32 | 报告的 process ID |
| `ppid` | u32 | 报告的 parent process ID |
| `actor` | string | 有界 process、observer、runtime 或 integration actor |
| `resource` | string | 脱敏的 target/resource identity |
| `action` | string | Normalized action 或 metadata value |
| `outcome` | enum|null | Capability outcome enum；不支持时为 `null` |
| `return_value` | i64|null | Linux syscall result |
| `errno` | i32|null | 从负 result 推导的正 errno |
| `container_id` | string|null | Runtime container identity |
| `cgroup_id` | string|null | Runtime cgroup identity |
| `host_boot_id` | string|null | Collector 捕获的 boot UUID |
| `scope_generation` | u64|null | Observer-lifetime scope generation |
| `process_generation` | u64|null | Collector 分配的 process generation |
| `process_start_time_ns` | u64|null | Boot-relative kernel process start time |
| `exec_generation` | u32|null | Process-local exec generation |
| `parent_process_generation` | u64|null | 已知 parent process generation |
| `parent_exec_generation` | u32|null | 已知 parent exec generation |
| `relation_status` | enum | `exact`、`inferred`、`ambiguous` 或 `unattributed` |
| `relation_reason` | string | 稳定、有界 attribution reason |
| `process_command` | string|null | Legacy redacted context；当前 content-off producer 输出 `null` |
| `process_executable` | string|null | 仅允许 `executable_ref:<basename>` |
| `process_started_at_unix_ms` | u128|null | Legacy wall-clock context，不是 `process_start_time_ns` |

`raw_kernel_event` 保留 canonicalization 前的有界输入：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `record_type` | string | 常量 `raw_kernel_event` |
| `timestamp_unix_ms` | u128 | 观测时间 |
| `session_id` | string | Agent Run ID |
| `event_source` | enum | 上述 event-source enum；通常是 `kernel_tracepoint` |
| `event_name` | string | Tracepoint 或 normalized kernel event name |
| `event_id` | string|null | 稳定 raw-event join ID |
| `pid` | u32 | Process ID |
| `ppid` | u32 | Parent process ID |
| `uid` | u32 | User ID |
| `gid` | u32 | Group ID |
| `comm` | string | 有界 kernel command name |
| `resource` | string | 持久化前脱敏的 resource |
| `action` | string | Raw action label |
| `outcome` | enum|null | Capability outcome enum |
| `return_value` | i64|null | Linux syscall result |
| `errno` | i32|null | 正 errno 或 `null` |
| `container_id` | string|null | Container identity |
| `cgroup_id` | string|null | Cgroup identity |
| `host_boot_id` | string|null | Boot UUID |
| `scope_generation` | u64|null | Scope generation |
| `process_generation` | u64|null | Process generation |
| `process_start_time_ns` | u64|null | Boot-relative process start |
| `exec_generation` | u32|null | Exec generation |
| `parent_process_generation` | u64|null | Parent process generation |
| `parent_exec_generation` | u32|null | Parent exec generation |
| `relation_status` | enum | 上述 relation enum |
| `relation_reason` | string | 稳定、有界 reason |
| `raw_payload` | string | 有界、持久化前脱敏的 payload |

对于 `network_connect`，非负 return 是 `succeeded`；`EACCES`/`EPERM` 是 `denied`；
`EINPROGRESS`/`EALREADY` 是 `pending`；其他负 return 是 `failed`。对于五种 file
operation，非负 return 是 `succeeded`，`EACCES`/`EPERM` 是 `denied`，其他所有负 result
都是 `failed`。
在 wire 上，`succeeded` 要求非负 `return_value` 与 null `errno`；`failed`、`denied` 和
`pending` 要求负 value，且 `errno` 是该 value 取反后的正数；null outcome 要求两个数值 field
都为 null。

可选 intent record 具有下列必需 shape：

| Record | Field | Type | Value 或含义 |
| --- | --- | --- | --- |
| `intent` | `record_type` | string | 常量 `intent` |
| `intent` | `timestamp_unix_ms` | u128 | 摄取时间 |
| `intent` | `session_id` | string | Agent Run ID |
| `intent` | `intent_source` | string | Adapter，目前为 `codex` |
| `intent` | `intent_id` | string | Adapter-stable ID |
| `intent` | `source_event_id` | string|null | Source harness event ID |
| `intent` | `intent_type` | string | Normalized type，例如 `tool_call` |
| `intent` | `tool_name` | string | Source tool/function name |
| `intent` | `declared_action` | string|null | Normalized action class |
| `intent` | `target` | string|null | 声明的 target scope/resource |
| `intent` | `command` | string|null | Content-off executable reference 与 redaction marker |
| `intent` | `raw_event_id` | string|null | Correlated raw-event ID |
| `intent_correlation` | `record_type` | string | 常量 `intent_correlation` |
| `intent_correlation` | `timestamp_unix_ms` | u128 | Correlation 时间 |
| `intent_correlation` | `session_id` | string | Agent Run ID |
| `intent_correlation` | `intent_source` | string | Adapter |
| `intent_correlation` | `intent_id` | string | Declared intent ID |
| `intent_correlation` | `match_basis` | enum | `raw_event_id`、`process_command_exact` 或 `process_executable` |
| `intent_correlation` | `raw_event_id` | string | Observed raw-event ID |
| `intent_correlation` | `event_type` | string | Canonical observed type |
| `intent_correlation` | `pid` | u32 | Observed PID；不可用时为 `0` |
| `intent_correlation` | `resource` | string | Observed redacted resource |
| `intent_correlation` | `process_command` | string|null | Redacted observed context |
| `intent_correlation` | `process_executable` | string|null | Observed executable reference |
| `intent_correlation` | `command` | string|null | Redacted declared summary |

`accountability_finding` 有必需 field `record_type:string`（常量
`accountability_finding`）、
`schema_version:u32`（`1`）、`session_id:string`、`kind:enum`、`decision:enum`、
`reason:string`、`evidence_ref:string`、`runtime:object` 与
`evidence_boundary:enum`。Kind 是 `missing_intent`、`unobserved_intent`、
`undeclared_action`、`credential_read`、`workspace_boundary`、`unknown_egress`、
`dangerous_command` 或 `service_account_token_read`；decision 是 `notify` 或 `review`；
evidence boundary 是 `host_boundary` 或 `guest_semantic`。Runtime 有必需 field
`runtime:string`、`container_id:string|null`、`pod_uid:string|null` 与
`cgroup_id:u64|null`。AOR 丢弃 source `reason`，并替换为与 kind 对应的 canonical bounded
reason。

| Finding kind | Canonical AOR `reason` |
| --- | --- |
| `missing_intent` | `observed side effect has no matching declared intent` |
| `unobserved_intent` | `declared intent has no matching observed side effect` |
| `undeclared_action` | `observed action class was not declared by intent` |
| `credential_read` | `workload read a credential-classified resource` |
| `workspace_boundary` | `file access crossed the declared workspace boundary` |
| `unknown_egress` | `network endpoint is outside the declared egress set` |
| `dangerous_command` | `command matches the dangerous-command baseline` |
| `service_account_token_read` | `workload read a Kubernetes service account token` |

`observation_gap` 有必需 field `record_type:string`（常量 `observation_gap`）、
`schema_version:u32`（`1`）、`timestamp_unix_ms:u128`、`agent_run_id:string`、
`operation:string`、`kind:enum`、`count:u64` 与 `detail:string`。合法 shape 是：

| Kind | Operation/count | Source detail | AOR detail |
| --- | --- | --- | --- |
| `missing_entry`、`missing_exit` | `network_connect`、`file_open`、`file_create`、`file_truncate`、`file_unlink` 或 `file_rename`；正 count | 有界 producer diagnostic | `bounded_loss_counter` |
| `collector_restart` | `collector_lifecycle`、`1` | 只含不透明 unfinished instance | `unfinished_collector_instance` |
| `late_attach` | `collector_lifecycle`、`1` | `collection_boundary:protected_existing_process_attach,history:unknown,provenance:<external_registration\|proc_discovery>,root_selection:<registration_qualified\|inferred>` | 相同 bounded detail |
| `runtime_metadata_unavailable` | `runtime_metadata`、`1` | `source=<docker\|containerd\|k3s_containerd>,reason=<socket_unavailable\|daemon_restart\|inventory_invalid>` | `runtime_source_unavailable` |
| `runtime_metadata_unavailable` | `runtime_metadata`、`1` | 相同 source set 加 `reason=identity_transition` | `runtime_identity_transition` |
| `kubernetes_metadata_unavailable` | `kubernetes_metadata`、`1` | `cluster=<canonical-nonzero-UUID>,reason=<kubernetes_api_unavailable\|kubernetes_runtime_unavailable\|kubernetes_snapshot_invalid>` | 分别为 `kubernetes_source_unavailable`、`kubernetes_runtime_unavailable` 或 `kubernetes_snapshot_invalid` |
| `kubernetes_metadata_unavailable` | `kubernetes_metadata`、`1` | 相同 cluster shape 加 `reason=<kubernetes_daemon_restart\|kubernetes_identity_transition\|kubernetes_late_attach>` | 相同 bounded reason |

Runtime-metadata detail 不得包含 path、payload、socket name 或 backend text。每条 gap 都增加
一条 AOR `observation_gap` issue，并阻止 evidence 成为 complete。Runtime adapter 可以独立
配置，因此 runtime-metadata gap 不要求 collector `started` record。

Runtime-binding lifecycle record 共用同一个精确 shape：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `record_type` | enum | `runtime_binding_observed`、`runtime_binding_retired` 或 `runtime_binding_suspended` |
| `schema_version` | u32 | 常量 `1` |
| `agent_run_id` | string | 所属 canonical Agent Run ID |
| `adapter` | enum | `docker`、`containerd` 或 `k3s_containerd` |
| `workload_id` | string | 非零、64-byte lowercase-hex Docker container ID、`containerd/<same-id>` 或 `k3s_containerd/<same-id>` |
| `start_marker` | string | Docker UTC `YYYY-MM-DDTHH:MM:SS[.1..9 digits]Z`（有效日期且 year >= 1970），或 canonical positive-decimal u64 CRI `startedAt`；strict RFC3339Nano `Z`/numeric-offset CRI text 会在 adapter boundary 归一化为 decimal Unix nanoseconds |
| `host_boot_id` | string | Canonical lowercase、非零 host boot UUID |
| `init_process_start_time_ticks` | u64 | 正数 `/proc/<init>/stat` start tick |
| `cgroup_device` | u64 | 正数 cgroup-filesystem device identity |
| `cgroup_id` | u64 | 正数 cgroup-filesystem inode identity；不是 PID，也不是可独立作为 Exact 的数字 cgroup claim |
| `runtime_handler` | string|null | 有界、不含 path 的 opaque runtime-handler name，或 `null` |

上表所有 field 都是必需 field，只有 `runtime_handler` 可为空。这些 record 没有 payload
timestamp；权威顺序来自 JSONL source order 或外层 hash-chain sequence。它们绝不包含 PID、
container name、raw label/annotation、runtime/cgroup/socket path、endpoint、backend error、payload
或 private namespace。`agent_run_id`、`workload_id`、`start_marker` 与非空
`runtime_handler` 都是有界 identifier，不是自由文本 capture。

合法 lifecycle order 会 fail closed。成功的 complete inventory 可以产生
`runtime_binding_observed`；相同 inventory 不产生 record，且只有成功的 complete inventory 才能
因缺席产生 `runtime_binding_retired`。Stable-identity replacement 的顺序是先写
`reason=identity_transition` gap，再退役旧 identity，最后观测 replacement。Runtime source 丢失
先写 `reason=socket_unavailable` 或 `reason=inventory_invalid` gap，再 suspension；只有后续 fresh
complete inventory 才能再次观测该 binding。Daemon recovery 将持久 binding 保持 dormant；首次
fresh complete inventory 先写 `reason=daemon_restart` gap，再退役 dormant identity，并在当前
identity 存在时写 observed。Failure 永远不是 empty inventory。不存在独立 transition record；
canonical identity-transition representation 就是有序的 gap -> retired -> observed sequence。

Kubernetes-attribution lifecycle record 具有下列精确 closed shape：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `record_type` | enum | `kubernetes_attribution_observed`、`kubernetes_attribution_retired` 或 `kubernetes_attribution_suspended` |
| `schema_version` | u32 | 常量 `1` |
| `agent_run_id` | string | 所属 canonical Agent Run ID |
| `cluster_id` | string | Operator 配置的 canonical lowercase non-zero UUID |
| `namespace_ref` | string | 64-byte lowercase hexadecimal domain-separated privacy reference |
| `pod_uid` | string | Canonical lowercase non-zero Kubernetes Pod UUID |
| `node_ref` | string | 64-byte lowercase hexadecimal domain-separated privacy reference |
| `runtime_class_ref` | string\|null | 相同 64-byte privacy reference，或显式 `null` |
| `container_kind` | enum | `application`、`init` 或 `ephemeral` |
| `container_ref` | string | 64-byte lowercase hexadecimal domain-separated privacy reference |
| `runtime_binding` | object | 属于同一 Agent Run 的完整有效 v1 `runtime_binding_observed` object；adapter 恰好为 `containerd` 或 `k3s_containerd` |

Lifecycle key 是 `(cluster_id,pod_uid,container_kind,container_ref)`。Observation 要求 embedded D1
identity 已先 active。Suspension 或 retirement 必须匹配完整 active K1 identity，并且 K1 必须在其
D1 identity 结束前先结束。K1 suspension 会消费同 cluster 与 active key 之前一条尚未匹配的
API/runtime/snapshot-unavailable gap credit。Restart、identity-transition 与 late-attach gap 都是
可见 boundary，但不授权 suspension。`claim_revision`、raw name、`pod_revision_ref`、source
epoch/sequence、label、annotation、path、PID、endpoint、token 与 backend text 都不是 wire field。

AOR projector 会 strict-decode 这三种 record type，把每条 record 绑定到投影中的 Agent Run，并
跟踪 active `(adapter,workload_id)` key。重复 observation，或 full identity 与 active binding
不匹配的 retirement/suspension 都会 fail closed。Suspension 还必须消费同一 adapter 之前一条
尚未匹配的 source-outage gap credit；credit 只能消费一次，但允许跨越无关的交错 record。由于
v1 没有 inventory transaction ID，projector 不会猜测 identity 或 daemon-restart gap 属于任意
retirement。其更强的 effect order 仍由 producer/coordinator 保证，而每条此类 gap 仍会使投影
evidence 成为 incomplete。

`observer_diagnostic` 有必需 field `record_type:string`（常量 `observer_diagnostic`）、
`timestamp_unix_ms:u128`、`session_id:string`、`kind:enum`、`count:u64` 与
`detail:string`。Kind 是 `ring_buffer_reserve_failure`、`map_pressure`、
`abi_mismatch`、`decode_failure`、`truncation`、`attach_failure`、
`verifier_failure` 或 `summary`。`visibility_assessment` 有必需 field
`record_type:string`（常量 `visibility_assessment`）、`session_id:string`、`runtime_profile:enum`、
`host_visibility_scope:enum`、`host_semantics_collapsed:boolean`、
`guest_collector_required:boolean`、`runtime_metadata_required:boolean`、
`host_event_subjects:array<string>`、`pod_name:string|null`、
`namespace:string|null`、`runtime_class_name:string|null`、
`sandbox_name:string|null` 与 `notes:string`。Runtime profile 是
`docker-default`、`docker-gvisor`、`kubernetes-gvisor`、`kubernetes-kata` 或
`firecracker-prototype`；host scope 是 `guest_process`、`runtime_boundary` 或
`boundary_only`。

### 6.2 本地 Session query schema v1

本地 daemon query 不是 timeline record。合法的
`{"type":"query","tenant_id":"<tenant>","session_id":"<agent-run>"}` request 返回下列
`DAEMON_SCHEMA_V1` response：

| Field | Type | Value 或含义 |
| --- | --- | --- |
| `type` | string | 常量 `session` |
| `schema_version` | u32 | 常量 `1` |
| `session` | object|null | 匹配的 `SessionState`；不存在或对该 tenant 不可见时为 `null` |
| `runtime_bindings` | array<object> | 该可见 Agent Run 的 active binding；始终存在，`session` 为 `null` 时为空数组 |
| `kubernetes_attributions` | array<object> | 该可见 Agent Run 的 active、fresh qualified K1 record；始终存在，`session` 为 `null` 时为空数组 |

每个 `runtime_bindings` element 恰好包含下列必需 nested field：

| Field path | Type | Value 或含义 |
| --- | --- | --- |
| `agent_run_id` | string | 与 request 及返回 `session` 相同的 Agent Run |
| `identity.adapter` | enum | `docker`、`containerd` 或 `k3s_containerd` |
| `identity.workload_id` | string | 上述完整 stable workload/container ID |
| `identity.start_marker` | string | Runtime-native start marker |
| `identity.host_boot_id` | string | Canonical host boot UUID |
| `identity.init_process_start_time_ticks` | u64 | 正数 init-process start tick |
| `identity.cgroup.device` | u64 | 正数 cgroup-filesystem device identity |
| `identity.cgroup.inode` | u64 | 正数 cgroup-filesystem inode identity |
| `runtime_handler` | string|null | 有界 opaque handler name，或 `null` |

两个 array 都只包含 active、经过 fresh qualification 的 state；dormant、suspended 与 retired
entry 不会返回。Runtime binding 按 adapter/workload key 排序，Kubernetes attribution 按其 exact
lifecycle key 排序。每个 `kubernetes_attributions` element 都具有上文 closed K1 wire shape，并
引用一条返回的 active D1 binding。省略 `tenant_id` 时默认为 `default`。Daemon 会先
要求 request tenant 等于目标 Agent Run 的 registered tenant，之后才读取 binding。`session` 与
`runtime_bindings` 与 `kubernetes_attributions` 来自同一个 tenant-gated atomic snapshot，因此
并发 tenant replacement 不能把授权判断与 workload disclosure 分离。不存在或 cross-tenant 的
Agent Run 因而返回 `session:null`、`runtime_bindings:[]` 与
`kubernetes_attributions:[]`，避免 workload identity 成为跨 tenant existence oracle。Query 保持
与 persistence 相同的 privacy boundary：它不暴露 raw label、annotation、namespace、node、
container name、PID、cgroup/runtime/socket path、endpoint、backend error 或 payload。

### 6.3 Agent Observation Record v1

Projection 是一份 deterministic JSON object，绝不是 timeline line。Input 保持 command-line
与 segment 顺序；每条投影 source fact 使用从一开始的 `source_ordinal`，timestamp 不会重排
record。

| Top-level field | Type | Contract |
| --- | --- | --- |
| `record_type` | string | 常量 `agent_observation_record` |
| `schema_version` | u32 | 常量 `1` |
| `agent_run_id` | string | 所有 source record 共用的非空 run |
| `source_integrity` | enum | `unverified_plain_jsonl`、`verified_hash_chain` 或 `mixed` |
| `summary` | object | 下列 state 与 deterministic aggregate |
| `capability_manifests` | array<object> | 投影后的兼容 manifest |
| `runtime_identities` | array<object> | Exact identity aggregate |
| `runtime_observations` | array<object> | Canonical supported observation |
| `runtime_bindings` | array<object> | 有序、经过验证的 runtime-binding lifecycle fact；新的 v1 output 始终包含该 field |
| `kubernetes_attributions` | array<object> | 有序、经过验证的 K1 lifecycle fact；新的 v1 output 始终包含该 field |
| `collector_lifecycle` | array<object> | 有序 lifecycle fact |
| `findings` | array<object> | Typed review finding |
| `observation_gaps` | array<object> | Normalized bounded gap |
| `issues` | array<object> | Projection limitation |

必需 `summary` field 包含三个 enum（`evidence_state`：
`complete|active|incomplete|failed|indeterminate`，`collector_health`：
`healthy|degraded|failed|unknown`，`review_state`：
`requires_review|no_findings_reported|indeterminate`）、六个 `u64` count
（`runtime_observation_count`、`runtime_identity_count`、`finding_count`、
`observation_gap_record_count`、`known_missing_observation_count`、
`unknown_history_boundary_count`）以及五个 `map<string,u64>` aggregate
（`event_type_counts`、`outcome_counts`、`relation_counts`、
`finding_kind_counts`、`gap_kind_counts`）。

Nested array object schema 是：

| Array/object | 必需 field 与 type |
| --- | --- |
| capability manifest | `source_ordinal:u64`、`schema_version:u32`、`timestamp_unix_ms:u128`、`collector:string`、`collector_version:string`、`kernel_abi_version:u32`、`kernel_record_size:u32`、`observation_scope:string`、`privacy_profile:string`、`capabilities:array<object>` |
| capability | `operation:string`、`event_sources:array<string>`、`outcomes:array<string>` |
| runtime identity | `identity_id:string`、`host_boot_id:string`、`scope_generation:u64`、`pid:u32`、`process_generation:u64`、`process_start_time_ns:u64`、`exec_generation:u32`、`first_source_ordinal:u64`、`last_source_ordinal:u64`、`observation_count:u64` |
| runtime observation | `source_ordinal:u64`、`timestamp_unix_ms:u128`、`event_source:string`、`event_type:string`、`raw_event_id:string|null`、`pid:u32`、`ppid:u32`、`actor:string`、`resource:string`、`action:string`、`outcome:string|null`、`return_value:i64|null`、`errno:i32|null`、`container_id:string|null`、`cgroup_id:string|null`、`relation_status:string`、`relation_reason:string`、`process_executable:string|null`、`process_started_at_unix_ms:u128|null`、`runtime_identity_id:string|null`、`parent_process_generation:u64|null`、`parent_exec_generation:u32|null` |
| runtime binding | `source_ordinal:u64`、`record_type:enum`、`schema_version:u32`、`agent_run_id:string`、`adapter:string`、`workload_id:string`、`start_marker:string`、`host_boot_id:string`、`init_process_start_time_ticks:u64`、`cgroup_device:u64`、`cgroup_id:u64`、`runtime_handler:string|null`；后十一个 field 是精确的 runtime-binding v1 lifecycle wire shape |
| Kubernetes attribution | `source_ordinal:u64` 加上文精确、closed 的十一 field K1 lifecycle wire shape，包括 nested runtime-binding object |
| collector lifecycle | `source_ordinal:u64`、`schema_version:u32`、`timestamp_unix_ms:u128`、`collector:string`、`collector_instance_id:string`、`state:enum`、`health:enum`、`stop_reason:enum|null`、`counters:object`；counter 与 timeline lifecycle 使用相同八个 `u64` field |
| finding | `source_ordinal:u64`、`schema_version:u32`、`kind:enum`、`decision:enum`、`reason:string`、`evidence_ref:string`、`runtime:object`、`evidence_boundary:enum`；runtime 使用 `runtime:string`、`container_id:string|null`、`pod_uid:string|null`、`cgroup_id:u64|null` |
| observation gap | `source_ordinal:u64`、`schema_version:u32`、`timestamp_unix_ms:u128`、`operation:string`、`kind:string`、`count:u64`、`detail:string`；使用上表 normalized value，并包含下文定义的可选成对 `runtime_source:string`/`runtime_reason:string` 或 `kubernetes_cluster_id:string`/`kubernetes_reason:string` field |
| issue | `code:enum`、`source_ordinal:u64|null`、`count:u64` |

Version 1 最多接受一份 capability manifest；重复 manifest 是 structural error，不会创建第二个
capability epoch。Nested lifecycle、observation、Finding 与 Gap object 的 enum value 使用
上文对应 timeline enum 与 canonical projection。

`runtime_bindings` 是 default-compatible 的 v1 extension。新的 projection output 始终包含该
array；缺少该 field 的旧 v1 AOR 会按空数组读取。该数组保留每条经过验证的
`runtime_binding_observed`、`runtime_binding_retired` 与 `runtime_binding_suspended` fact，而不只
保留 run 结束时 active 的 binding。每个 element 都属于投影中的 Agent Run，并保持权威
`source_ordinal` 顺序。Projector 与 frozen-record validator 都会重建 active binding state，并
执行 6.1 节的 lifecycle identity 与 sequence rule。

`kubernetes_attributions` 使用相同 default-compatible v1 extension 规则：新的 projection output
始终包含该 array，legacy v1 record 可以把缺失 field 读取为空。Projector 按 source order 保留每条
经过验证的 K1 observed、retired 与 suspended fact，共同 replay runtime/K1 state，要求 referenced
D1 observation 先于 K1 observation、K1 retirement/suspension 先于 D1 结束，并且每个 K1
suspension credit 只消费一次。Frozen-record validator 会重复这些检查。Saved Run Viewer 渲染独立
K1 lifecycle panel，并把每条 K1 fact 链接到其 Exact D1 binding source fact，而不重建 raw
Kubernetes name。

当 Finding 的 `evidence_ref` 为 `runtime_binding:<workload_id>` 时，只有同一 run 中先于该
Finding 出现，且 `adapter`、`workload_id`、`cgroup_id` 与 Finding 的 runtime、container ID、
cgroup ID 精确匹配的 `runtime_binding_observed` fact 才能解析该引用。Retired 或 suspended fact
即使字段匹配也绝不授予 support。Saved Run Viewer 会在每个 binding fact 的 source ordinal
提供目标，并允许受支持的 Finding 跳转到那条更早、精确匹配的 observed fact；无法解析的引用
继续作为 limitation 保留。

新投影的 `runtime_metadata_unavailable` gap 会同时包含 `runtime_source` 与
`runtime_reason`。Source 只能是 `docker`、`containerd` 或 `k3s_containerd`；reason 只能是
`socket_unavailable`、`inventory_invalid`、`daemon_restart` 或 `identity_transition`。其他 gap
kind 会省略这两个 field。该字段对是 default-compatible 的 v1 extension：旧 AOR 可以省略，
但缺失或只出现一项时，绝不能授权后续 `runtime_binding_suspended`。Frozen-record validator
会按 `source_ordinal` 顺序共同重放 gap 与 binding fact。只有同 adapter、更早且尚未消费、
reason 为 `socket_unavailable` 或 `inventory_invalid` 的 gap 才授予一次 suspension credit；
`daemon_restart` 与 `identity_transition` 不授予 suspension credit，每个 credit 只能消费一次。

对 `kubernetes_metadata_unavailable`，projection 会把 source detail 替换为 6.1 节的 normalized
bounded detail，并增加必需的 `kubernetes_cluster_id` 与 `kubernetes_reason` field。Reason 恰好是
该节列出的六种 K1 reason 之一。其他 gap 会省略这两个 field。每条 K1 gap 都增加一个
`observation_gap` issue 并阻止 complete evidence；late attach 表示一个 relation boundary，不是
missing syscall 数量。

Issue code 恰好是 `missing_capability`、`unsupported_capability`、
`missing_lifecycle_start`、`missing_lifecycle_terminal`、`collector_loss`、
`collector_diagnostic`、`observation_gap`、`unsupported_observation`、
`unsupported_outcome`、`unknown_record_type`、`source_integrity_finding`、
`no_runtime_observations` 或 `unresolved_finding_evidence`。Null issue ordinal 表示 run-wide
issue，不是复制的 source fact。
`unsupported_capability` count 等于其 manifest 中缺失或不匹配的 contract operation 数。
Source-bound unsupported-observation/outcome、unknown-record、integrity 与 unresolved-Finding
issue 各 count 1。`observation_gap` 与 `collector_diagnostic` 保留 source count。Run-wide
missing-capability、missing-start、no-observation 与 mixed-integrity issue count 1；
missing-terminal issue count 等于未完成 collector instance 数。`collector_loss` 指向最新
lossy lifecycle record 且 count 1。

Exact identity 由 active `collector_instance_id` 限定，并要求
`event_source=kernel_tracepoint`、非 null canonical `raw_event_id`、
relation `exact` 且 reason 为 `host_boot_scope_process_start_exec_generation`，并具有完整 tuple
`(host_boot_id,scope_generation,pid,process_generation,process_start_time_ns,exec_generation)`。
首次出现依次分配 `identity-1`、`identity-2`。Non-exact fact 保持不合并。Complete evidence
要求兼容 content-off manifest、合法正常 lifecycle terminal、至少一条 supported observation，
且不存在 loss、gap、diagnostic、integrity、capability 或 unresolved-evidence issue。Finding 只
改变 review state；`no_findings_reported` 不是 clean-run verdict。

执行 capability check 时，projected event type 按如下方式映射：`exec` 到 `process_exec`，
`process_exit` 到 `process_exit`，各 `file_*` event 到同名 operation，`network_connect` 到
`network_connect`，`credential_read` 到 `credential_path_access`。其他 event type 以及任何
非 `kernel_tracepoint` source 都增加 `unsupported_observation`；缺失或未声明的 outcome 增加
`unsupported_outcome`。

### 6.4 本地 hash-chain envelope

Hash-chain timeline 是 JSONL，每行都有必需的 `schema_version:u32`、`sequence:u64`、
`previous_hash:string`、`record_hash:string` 与 `payload:object`。Sequence 从 `1` 开始；首条
previous hash 是 64 个小写零字符，之后每条 `previous_hash` 等于前一条 `record_hash`。Payload
通过 parse JSON 后递归序列化为 compact UTF-8 JSON 完成 canonicalization：object key 按
lexicographic order 排序，array order 保留，不添加无意义 whitespace 或 slash escape；string
escape JSON control character、quote 与 backslash；number 使用最短 serde-json representation
（timeline contract 只使用 integer）。小写十六进制 record digest 是：

```text
SHA-256(
  schema_version 的 4-byte unsigned big-endian
  || sequence 的 8-byte unsigned big-endian
  || previous_hash 的 UTF-8 byte
  || compact canonical payload JSON 的 UTF-8 byte
)
```

这四段 byte string 之间没有 separator 或 length prefix。验证会检查 expected sequence、link、
canonicalized payload digest 与完整 final line。Report 包含 `path:string`、`passed:boolean`、
`record_count:integer`、`last_sequence:u64`、`last_record_hash:string`、
`valid_bytes:u64`、`total_bytes:u64` 与 `failure:string|null`。验证只读；middle corruption、
truncated 或 corrupt tail 都会 fail closed。

Canonical join 使用 raw kernel `event_id`、canonical `raw_event_id`、可选 intent
`raw_event_id`、correlation `raw_event_id` 与 Finding `evidence_ref`。
对于 runtime-binding evidence，有界 Finding reference 只会按 6.3 节的精确规则连接到更早的
observed lifecycle source ordinal；retired 与 suspended lifecycle fact 不属于该 support
relation。Timestamp-only matching 永远不会创建 Exact relation。Raw exec argv 会替换为
redaction/truncation marker；credential path 与 socket address 在输出前 tokenized。Rotation 是
storage budget，不是 schema change，
并且永远不会拆分一条 JSONL record。

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

Runtime metadata 丢失使用一种有界 v1 shape：

```json
{"record_type":"observation_gap","schema_version":1,"agent_run_id":"<agent-run>","operation":"runtime_metadata","kind":"runtime_metadata_unavailable","count":1,"detail":"source=docker,reason=socket_unavailable"}
```

`source` 只能是 `docker`、`containerd` 或 `k3s_containerd`。Source-outage `reason` 只能是
`socket_unavailable`、`daemon_restart` 或 `inventory_invalid`；相同 workload key 的 stable
identity 变化使用 `reason=identity_transition`。禁止 path、payload、socket name 与自由文本
backend error。Agent Observation Record 会把 outage detail canonicalize 为
`runtime_source_unavailable`，把 identity change canonicalize 为
`runtime_identity_transition`，同时将有界 source 与 reason 保留在 `runtime_source` 与
`runtime_reason`。它会增加一条 `observation_gap` issue，并且不能成为 complete。由于 runtime
adapter 可以独立配置，这种 gap 不要求 eBPF collector 已有 `started` lifecycle record。
Identity transition 的 durable effect order 是 gap、retire、attach。

Agent Observation Summary 暴露三条相互独立的结论：

- `evidence_state` 为 `complete`、`active`、`incomplete`、`failed` 或 `indeterminate`；
- `collector_health` 为 `healthy`、`degraded`、`failed` 或 `unknown`；
- `review_state` 为 `requires_review`、`no_findings_reported` 或 `indeterminate`。

Complete evidence 要求存在一份兼容的 content-off capability manifest、合法的 started 到正常
terminal lifecycle、至少一条受支持 Runtime Observation，并且没有 loss、gap、diagnostic、
integrity 或 capability issue。Active 或 failed lifecycle state 必须显式保留。Mixed source
integrity 与未知增量 record type 会让其他方面呈 complete shape 的 run 成为 indeterminate。
Finding 只改变 review state，不改写
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
| Kubernetes containerd/K3s | 已实现 K1 node eBPF observation 与 claimed Pod/container/cgroup identity 的 join；指定 live qualification 前仍为 Experimental |
| gVisor | Host/runtime boundary visibility，不是每个 guest syscall |
| Kata 或 Firecracker | Host/VMM/shim visibility；guest semantics 需要 guest collector |
| macOS 或 Windows | 不支持 eBPF runtime observation |
| 厂商托管 Agent runtime | 没有用户可控 Linux kernel 时不属于范围 |

Machine-readable 资格权威位于源码树的
[qualification envelope](https://github.com/0xLaiHo/Apolysis/blob/main/qualification/envelope-v1.json)，
其版本化 workload definition 位于相邻的 `qualification/workloads/` directory。Release 文档
archive 只是 human-readable snapshot，不内嵌这些 machine file；执行 profile 资格验证或晋级的
consumer 必须使用匹配 source revision 中的 envelope。Linux 6.12/x86_64 原生 host 只是
Candidate，不是 Supported：它要求 cgroup v2、可读 target BTF/tracefs、19 个声明
tracepoint 及其经过检查的 format、production verifier/load/full attach 路径，以及有效
`CAP_BPF` + `CAP_PERFMON`。其他 feature-probed Linux 5.11+ x86_64 kernel、aarch64、Docker、
containerd、Kubernetes 与 legacy `CAP_SYS_ADMIN` fallback 保持 Experimental。缺少必需 hook、
cgroup v1/hybrid scope、rootless host collection、非 Linux，或低于 feature floor 且无 backport
的 kernel 为 Unsupported。

资格验证使用版本化 content-free `idle`、`representative` 与 `burst` workload。同一 boot 上
配对的 collector-off/on trial 分别保留 workload/collector CPU、process/cgroup/BPF memory、
monotonic kernel-to-decode/append latency、完整 expected/observed/lost event map，以及按 phase
归属的 burst loss。Representative profile 要求 known 与 unexplained loss 都为 0。CPU、memory、
latency、repetition 与 rated-event 数值 budget 在足量 privileged live evidence 支持 reviewed
保守边界前保持 unset。Fixture 只测试 checker，不能晋级 profile。晋级 Supported 需要保留 raw
live evidence、在 machine envelope 冻结 budget 与 exact tuple、通过 privacy/overload review，
并关闭全部适用 release gate。

Visibility 声明保持 profile-specific。具备 exact container/cgroup identity 时，Docker default
通常保留 guest-process host semantic。gVisor 可能把 observation 收缩到 runtime boundary，
因此关联需要 runtime metadata。Kata 与 Firecracker 只暴露 VMM/shim/host boundary；完整 guest
process、file、network 或 credential semantic 需要 guest collector。Kubernetes metadata 无法
恢复 host source 没有观测到的 guest semantic。

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
- K1 持久化 operator 定义的 cluster UUID、Pod UID、container kind，以及 domain-separated
  namespace/node/container/runtime-class reference。Raw Pod name、namespace/node name、label、
  annotation、resource version、token 与 source error body 都不跨越 persistence 或 diagnostic
  seam。Projected token 只挂载到 non-root source container；root collector 没有 Kubernetes API
  credential。
- K1 privacy reference 是 deterministic unkeyed pseudonym，不是 secret 或 anonymity。低 entropy
  identifier 仍可枚举，reference 仍可跨 run 链接；Pod UID 与完整 runtime container identity 按
  contract 保持显式。
- Raw kernel payload 只是有界实现细节，没有显式 review profile 时不得跨越 persistence
  seam。
- Observation Scope 防止意外 host-wide collection。
- 本地文件使用限制性权限与有界 retention。Daemon lifecycle change 只接受由
  manifest/receipt 证明 ownership 的固定 artifact 集合，在 mutation 前拒绝 linked 或非托管
  substitution，并在默认卸载中保留 saved Agent Run。
- Viewer 是非特权组件，无法接触 BPF map、host PID namespace、container socket 或 node
  credential。
- Standalone viewer 会转义所有存储文本，并使用禁止网络连接与外部 asset 的限制性 Content
  Security Policy。该 artifact 包含投影后的 run fact，因此保留 mode-`0600` 发布语义。

## 11. 失败语义

下列情况始终产生显式 gap 或 failed/degraded collector state：

- ring-buffer reserve failure 或 map pressure；
- resource 或 payload truncation；
- kernel/userspace ABI mismatch；
- decode、attach、verifier 或 permission failure；
- collector restart 或 death；
- runtime socket 丢失、daemon restart、非法 runtime inventory 或陈旧 container identity
  transition；
- Kubernetes API/CRI 丢失、非法或变化的 A/B Pod snapshot、source epoch/daemon restart、K1
  identity transition 或 K1 late attach；
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
  完成的 protected existing-process attach、非特权 saved-run projection 与 Saved Run Viewer
  发布、可选 Codex intent correlation、visibility、verification 与有界 daemon
  install/inspect/uninstall command；
- `apolysis-core`：当前 JSONL vocabulary、record type、版本化 Collector Capability
  manifest 与 collector lifecycle schema，包括由 producer 与 projection 共同消费的唯一
  lifecycle vocabulary 和完整 AuditObserver v1 operation/source/outcome contract；
- `apolysis-store`：rotation、可选本地 hash-chain envelope、no-follow descriptor-bound
  recovery，以及读取 plain/rotated 或 verified saved run 的有界 stable-snapshot reader；
- `apolysis-accountability`：纯 Agent Observation Record projection、相互独立的 summary
  axis、可选声明意图对比、typed K1 claim admission/lifecycle validation 与面向复查的 finding；
- `apolysis-viewer`：严格验证 Agent Observation Record v1，并提供带 runtime/K1 source
  traceability 的确定性 standalone 离线 HTML 展示；
- `apolysis-kubernetes`：纯、有界 A/runtime/B qualification coordinator、claim intersection、
  K1 lifecycle、outage/restart recovery 与 Exact D1 join；
- `apolysis-kubernetes-source`：non-root namespace-scoped Pod LIST/watch source 与严格、
  privacy-safe Unix IPC protocol；
- `apolysis-visibility`：visibility boundary assessment；
- `apolysis-daemon`：long-lived observer、有界 queue、本地 socket、runtime registration、
  完整 Docker/containerd inventory qualification、稳定 container/cgroup binding、有界
  runtime-source 与 daemon-restart recovery、two-phase K1/runtime lifecycle persistence 与
  recovery、tenant-atomic query、scoped collector lifecycle、幂等的未完成实例恢复、
  receipt-owned local operation 与 identity-bound journaled retention；
- `apolysisd-control` 与 `deploy/kubernetes`：typed operator ingress 与 least-privilege 双容器
  node DaemonSet contract。

Live collector 会在成功 attach 后、释放托管 Agent gate 前把 capability manifest 与 lifecycle
start 同步到稳定存储；对 protected existing-process attach，它会先持久化唯一的 unknown-history
`late_attach` boundary。选定文件操作与 network connect 已具备有界 entry/exit outcome 语义，
daemon 会在显式移除 scope 与正常关闭时把这些配对 gap 持久化到所属 Agent Run。单次运行内
稳定的 scope/process generation、周期累计 lifecycle checkpoint、显式 terminal reason 与
restart-gap recovery、可查询 saved-run projection 与非特权 Saved Run Viewer 已实现。
Docker/containerd stable identity 与 runtime recovery 已通过 typed runtime-metadata gap 实现。
保留的非破坏性 Docker gate 覆盖 complete-inventory identity churn、socket-outage recovery、
私有 daemon-lifecycle recovery，以及具备 capability 与 hash-chain 证据的 content-off eBPF
exact container/cgroup 归属。独立、保留的 private-containerd gate 按 section 5.3 的隔离与
cleanup contract，覆盖 stable/replacement complete inventory 以及 socket gap -> suspension ->
fresh observation。K1 implementation 已覆盖 typed claim、privacy-safe Pod metadata、complete
A/runtime/B closure、application/init/ephemeral container、D1 reuse、observed/retired/suspended
lifecycle、显式 API/CRI/snapshot/restart/transition/late-attach gap、tenant-gated query、AOR
projection 与 viewer navigation。在 combined path 中，D1 reconciliation 只接收由 exact
claim/A/B intersection 授权的 full identity key；raw routing candidate 不能 attach scope。其
deterministic/deployment contract 已在本地通过，但本
workspace 因缺少所需 kubeconfig 与 `kubectl`，尚未运行指定 VKE live gate。该 preflight 结果是
skip，不是 pass，也不会晋级 Kubernetes。破坏性 systemd runtime-service restart 与 release
qualification 仍保持 open。本地有界 daemon filesystem operation 已实现；当前没有授予任何
Supported live-host profile。

中央 contracts、Gateway、PostgreSQL projection、evidence-object 集群、
policy/feedback/control plane、sandbox runner 与广泛 qualification machinery 已移出活跃
workspace。Git 历史保留它们作为历史实现输入；它们不定义本文架构。

## 13. 限制

- 本地 daemon 运维只面向文档化的 Linux/systemd layout 与 5 个固定 runtime artifact；它不是
  发行版 package manager，也不是通用任意 prefix installer。Staged-root 验证证明有界
  filesystem 行为，不证明 privileged activation；live claim 需要显式 systemd/eBPF gate。
  默认卸载有意不清除已保留的 Agent Run。Transaction profile 要求 procfs 可用，且 managed
  filesystem 支持 Linux `O_TMPFILE` 与 `renameat2`；不支持的 host 会在 publication 前失败。
- L3 渲染一份有界、本地、冻结的 Agent Observation Record v1。它不是 live tail、跨 run
  search、remote query surface 或中央 query plane。
- Agent Observation Record v1 缺少权威 parent Runtime Identity link。Viewer 可以展示 Exact
  Runtime Identity roster 与每条 observation 的 reported PID/PPID，但不能依赖不安全的
  PID-based inference 构造 canonical process tree。
- K1 限于每个 DaemonSet Pod 一个 namespace/node、一个显式配置的 containerd 或 K3s runtime
  domain、READY marked Pod sandbox，以及针对 application/init/ephemeral container slot 的 exact
  typed claim。它不观测 Docker-backed Kubernetes、任意/unclaimed Pod、一个 source token 下的
  multiple namespace，或无法形成 Exact D1 identity 的 runtime/container metadata。
- Canonical DaemonSet 只支持自身专用 Agent namespace。不能针对每个 workload namespace 复制并
  共享同一 node runtime：一个 node observer 必须独占 runtime domain。Cluster-wide 或
  cross-namespace attribution 需要重新设计 authorization/source seam。
- 专用 namespace 必须保持 operator-controlled。Exact claim 会阻止 Pod writer 获得其他 run 的
  D1/scope，但 malformed marked sandbox 会按设计使 complete scan fail，并可降低 node
  K1/runtime availability；K1 不抵抗这种 authorized-namespace DoS。
- 直接拥有 host CRI socket 会使 collector 保持 node-trusted，因为协议包含 mutating method。
  Capability 与 token 隔离会收敛 privilege，但不强制 read-only access；这需要未来的 allowlist
  broker。
- K1 watch 只触发 fresh capture。权威来源是围绕一次 complete CRI inventory 的两次 complete Pod
  LIST，因此 API pagination 或 runtime latency 会限制 convergence，持续 churn 可能重复产生显式
  snapshot gap。Node-local state 不提供 gap-free cross-node handoff：rescheduled Pod 使用新 UID，
  并在 destination node 上独立资格化。
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

## 15. 方向与 release gate

本地 Agent Run workflow、非特权 projection/viewer、有界 daemon 运维、完成的 D1/D2 工作与
分别保留的 Docker/private-containerd qualification，以及完成的 deterministic K1 contract 构成
当前基础。下一项有界工作是在指定 runtime-ready、network-ready VKE 上完成 live qualification，
随后进行 release 准备。该 gate 必须覆盖代表性 same-Pod restart、source loss/recovery、cross-node
new-UID handoff、runtime boundary、cleanup 与 privacy。本 workspace 缺少其必需 kubeconfig 与
`kubectl`，因此尚未运行；规范 preflight 结果是 skip，不能报告为 pass。Docker 证据不能复用成
containerd 或 Kubernetes 证据，private-containerd 证据也不能复用成 Kubernetes 证据。破坏性
systemd runtime-service restart qualification 保持独立、可选声明。在相应 exact
workload/kernel/runtime 与适用 release 证据通过前，任何 profile 都不会超越 Experimental 或
Candidate。

跨领域规则长期有效：scope before capture、capability before claim、no silent absence、stable
identity before inference、privacy before persistence、observation 而非 enforcement、viewer
非特权，以及只有重复使用能改变真实调查决策时才扩展。

以下能力明确 deferred：provider Hook/SDK/OTLP/MCP/A2A family；通用 remote export/custody；
remote outcome verification；live tail 与跨 run search；中央 authenticated ingest、multi-user
query、PostgreSQL/S3/KMS custody 与 multi-tenant retention；policy denial/containment；portable
evidence receipt；public SaaS、HA 与 multi-region；通用 package-manager abstraction；卸载时自动
purge 已保留 Agent Run。只有出现明确需求并做出新架构决策后，它们才能返回。

存在任一适用条件时，profile 都属于 release no-go：

- loss、failure、truncation、restart、runtime metadata unavailable、unsupported path 或 missing
  terminal 可以产生未标记的 complete evidence；
- entry-only、PID/name/time-only、陈旧 container 或 ambiguous correlation 被展示为成功 operation
  或 Exact Runtime Identity；
- protected attach 绕过资格校验、遗漏有序 unknown-history boundary 或夸大 pre-anchor continuity；
- mixed、malformed、corrupt、unsupported、unresolved 或带 gap input 被呈现得比 source 更强，
  或 viewer 构造 process-tree edge；
- secret、argv、prompt、response、payload、credential、private path、socket、label、annotation、
  kubeconfig 或 private workload data 跨越默认 persistence、log、error、test 或 repository boundary；
- viewer 需要 privileged host access，或 Finding 被描述为 blocking/enforcement；
- install、replacement、uninstall、retention、recovery、runtime cleanup 或 Kubernetes validation
  可以修改无关状态，或缺少必需 live evidence；
- claimed profile 的 kernel、runtime、operation、privacy、performance、packaging 与 cleanup
  envelope 尚未文档化、测试或冻结 budget。

只有 representative Agent Run 能自动限定 scope/attribution、operator 实际使用
process/file/network investigation、gap 能阻止 false clean conclusion，并且 container/Kubernetes
context 能改变真实 review 或 incident decision 时，项目才继续扩展。如果通用 telemetry 已足够、
eBPF evidence 不改变决策、deployment privilege 成本高于 workflow 价值、大多数活动发生在远端，
或 adapter maintenance 挤压 collector correctness，项目应进一步简化而不是扩张。

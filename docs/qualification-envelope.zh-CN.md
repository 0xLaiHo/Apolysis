# Beta 资格包络

> [English](qualification-envelope.md) | 简体中文
> 状态：候选 contract；没有 Supported profile
> 最后审查：2026-08-04

本文冻结 Apolysis eBPF collector 的首个有界资格 contract，但不会授予 support claim。在可
重复的 live 测量产生并随 release 保留之前，数值限制保持未设置。

机器可读权威是
[`qualification/envelope-v1.json`](../qualification/envelope-v1.json)。Candidate profile、
未设置预算、精确环境不匹配、畸形证据、采样不足、超预算或 event loss 都必须被 checker
拒绝。

## 状态矩阵

| 状态 | 环境 | 边界 |
| --- | --- | --- |
| Candidate | 原生 host、Linux 6.12 系列、x86_64、cgroup v2、可读 target BTF 与 tracefs、完整 19 个 tracepoint、production object verifier/load/attach、有效 `CAP_BPF` + `CAP_PERFMON` | 只有保留的正确性、lifecycle、性能、丢失、过载和隐私证据全部通过后才能成为 Supported |
| Experimental | 其他通过 feature probe 的 Linux 5.11+ x86_64 kernel；aarch64；Docker；containerd；Kubernetes；`CAP_SYS_ADMIN` legacy fallback | 不承诺兼容性或性能；runtime 扩展由 D1/D2 与 K1/K2 负责 |
| Unsupported | 未回移必需能力的 Linux 5.11 之前版本；cgroup v1/hybrid Agent Run scope；缺少 BTF 或必需 hook；非特权/rootless host collector；非 Linux | 需要不同实现或产品 profile，不能豁免门禁 |

Linux 5.11 只是当前 upstream feature floor：eBPF 程序除了 BPF ring buffer 与 CO-RE，还使用
`bpf_get_current_task_btf`。这不是笼统的 `Linux >= 5.11` 支持声明。首个 6.12 系列只是
收敛后的产品候选；每个受支持 release tuple 都必须命名并保留准确 kernel build 与 artifact
证据。

## 必需证据

每个准确 tuple 只记录非敏感资格 metadata：

- 完整 kernel release 与 architecture；
- target BTF 与 production BPF object 的 SHA-256 fingerprint；
- cgroup v2 探测结果与有效 capability mode；
- 版本化的 19 个必需 tracepoint 清单及每个 event format fingerprint；
- verifier、load 与完整 attach 结果；
- source commit、workload manifest、重复次数与 synthetic-workload 隐私声明。

Shell preflight 与 Rust regression test 共用 tracepoint manifest；后者把它与
`AyaLoaderPlan::audit_observer_default` 比较。CO-RE 不会让 tracepoint 成为稳定 ABI，因此
版本检查不能替代 format inspection 和真实 attach。

## Workload 与指标 contract

资格测试分开三种模式：

1. `idle` 测量 collector attach 后、没有受跟踪 Agent 活动时的成本。
2. `representative` 运行版本化、确定性的 process、选定文件与网络操作组合，预期 event
   数量已知。
3. `burst` 逐级提高 event rate，直至首次出现可检测 loss、pressure、storage failure 或
   latency violation；它只用于发现容量边界，不能凭带 loss 的结果通过 rated workload。

Version 1 manifest 被嵌入 qualification-only binary，并保留在
`qualification/workloads/`。`idle` 保持一秒空窗口；`representative` 执行 25 轮
`openat`、`creat`、`truncate`、`renameat2`、`unlinkat`、loopback `connect` 与
fork/exit，共预期 200 个 event；`burst` 分别提供每秒 100、500 与 2,000 个 `openat`
event，共预期 1,300 个 event。每个 burst rate 都有独立 monotonic window，并在其后保留
150 毫秒 settle gap；event rate、latency 与 loss-counter delta 按 phase 归因，不与整个 run
混合。Summary 会报告首次检测到 loss 的 phase，并拒绝任何偏离嵌入 manifest 的 rate、顺序、
event count 或 phase-window 计划。只有位于 workload monotonic start/end window 内的 kernel
timestamp 才参与 reconciliation，从而排除 loader 与原始文件写入活动。

Collector-off/on 配对 trial 必须保留原始样本，并至少报告：

- collector userspace CPU 以及 workload CPU/wall-time delta，因为 BPF 也在触发 syscall 的
  task 路径执行；原始 workload CPU 同时包含 `RUSAGE_SELF` 与已 wait 的
  `RUSAGE_CHILDREN`；
- process RSS/peak RSS、collector-cgroup memory 与 BPF map/program memory，三者分开；
- workload overhead，以及 kernel-to-decode 和 kernel-to-append 的 p50、p95、p99、最大值、
  样本数与区间方法；append latency 不是 durable latency；
- 每类 event 的 expected、observed 和 lost count，包括 reserve、map pressure、pairing、
  decode、queue、writer 与 lifecycle-gap counter。

Qualification harness 每 25 毫秒采样 collector `RUSAGE_SELF`、`VmRSS`/`VmHWM` 与
collector-cgroup `memory.current`/`memory.peak`，并保留首尾 bracket sample；production
object 完成 load 与 attach 后，BPF map/program `memlock` 单独采集一次。Harness 在调用者当前
cgroup 下创建临时 subtree，把 collector 与 synthetic workload 放入兄弟 cgroup；绝不会把
二者混合的父 cgroup memory 报成 collector memory。
外层 supervisor 会先把全新的 collector process 移入其 cgroup，再执行 exec，因此 runtime
和 BPF allocation 不会早于 measurement cgroup。内层 collector 会在记录 isolation 前验证
自己的 `/proc/self/cgroup` membership，以及准确的 collector/workload `cgroup.procs`
membership。缺少可写 cgroup-v2 delegation、memory controller、`memory.peak`、process
status field、BPF `memlock`、workload window 任一侧没有 sample，或 sampling gap 超过四个
interval（100 毫秒），都会使 trial 失败。Burst phase boundary 也必须在相同 gap limit 内被
前后 bracket。两个 process 离开后，精确删除该 subtree。采样本身的工作计入 collector CPU，
因此是保守的 harness cost。

每个 pair 保留带符号的 workload CPU 与 wall-time delta。发布的一侧 overhead estimate 只把
负的聚合边界截为零；summary 中仍保留带符号 paired sample。
`workload_latency_overhead` 指配对 workload wall-time delta。Event rate 取 pair 中位数；CPU
与 overhead metric 对 pair 使用 nearest-rank p95；RSS、cgroup 与 BPF memory 取最大值；lag
p50/p95/p99 先汇总每个 collector-on trial，再对 pair 使用相同的 nearest-rank percentile；
最大 lag 取各 trial 最大值中的最大值。

Version 1 固定 nearest-rank percentile，以及 10,000 次重采样的确定性 95%
percentile-bootstrap interval。重采样单位是完整 off/on pair，不是单个 eBPF event。Trial 在
同一次 boot 上交替 collector-off/on 顺序并使用 `CLOCK_MONOTONIC`。通过比较
`CLOCK_BOOTTIME` 与 `CLOCK_MONOTONIC`，每个 raw workload、off/on pair 和完整 evidence
bundle 都会拒绝 suspend drift。每个 workload manifest 冻结预期 event-class count；evidence
必须先匹配该 map，再核对 observed count。

Rated representative envelope 要求 known 与 unexplained event loss 都为零。CPU、memory、
latency、重复次数和 rated event rate 在 version 1 中保持 `null`，直到 privileged 6.12 host
产生足够 trial，并通过显式 safety margin 选择保守边界。
`tests/fixtures/qualification/` 中的数字只测试 checker，不是产品预算。

## 命令与晋级

无需 privilege 即可运行确定性 contract test：

```bash
make test-qualification
```

在 clean commit 与准备好的 privileged host 上，显式捕获真实 production object 的前置条件
与 attach 证据：

```bash
APOLYSIS_CONFIRM_QUALIFICATION=1 make qualify-live
```

该命令只写入 `target/qualification/<UTC timestamp>/`。缺少前置条件会显式失败，不会变成
通过的 skip。Capture 会按同一 boot 内交替的 collector-off/on 顺序运行三个版本化 workload
（默认三对），保留 content-free workload、timeline、lifecycle、kernel-to-decode/append
纳秒样本，以及彼此分离的 collector process/cgroup/BPF resource sample。它会写入带
pair-level measurement 与 bootstrap interval 的 `measurement-summary.json`；profile 仍为
Candidate 时，再写入 failed decision 并返回非零。可以把
`APOLYSIS_QUALIFICATION_SAMPLES` 设为 1 到 100 以改变原始重复次数，但这不会豁免 reviewed
sample-size 或 budget 决策。当前 bundle 会计算 aggregate，但有意不设置数值 budget，因此
它只是证据输入，不是支持证书。

写入 preflight bundle 前，harness 会重新计算每个 workload 的 canonical JSON tree digest，
要求 summary 包含相同的 raw digest 与 workload-manifest digest，并把 summary 文件 SHA-256
记录到 preflight provenance；Supported checker 要求该 provenance field 是有效 SHA-256。
因此 summary 无法静默引用另一份 raw evidence。

Production `apolysis` CLI 不暴露 qualification timing option。独立 harness 通过 observer
library 启用有界内存 timing recorder 与有界 qualification-only resource sampler。Timing
data 只持久化 event name 与 monotonic timestamp；resource data 只持久化数值 CPU/memory
sample 和 cgroup isolation 是否生效。Raw-trial assembly 会拒绝 synthetic workload window
之外的 latency sample、不能前后 bracket 该 window 的 resource sample、超过固定限制的
sampling gap、发生回退的累计 loss counter，以及无法准确归因到各 phase 的 burst counter；
跨 suspend 的 run 会失败而不会进入 bundle。在 `sudo` 下，off/on workload 都恢复为同一个
调用者 UID/GID；privileged trial root 保持 root-owned，只委托专用 synthetic workload/result
子目录。Privileged 原始文件使用 exclusive、no-symlink 创建。Workload 与 summary 文件不
包含 resource path、cgroup path、payload 或 command content。

晋级到 Supported 必须通过 reviewed change 链接保留的 live 原始结果，在机器包络中冻结
数值预算并修改 profile status，对每个声明 tuple 重新运行 checker，同时确认隐私与过载行为。
Fixture、被跳过的 live test、kernel-version 匹配或 `CAP_SYS_ADMIN` fallback 都不能完成晋级。

# 有界 Beta 验证计划

> [English](beta-qualification-plan.md) | 简体中文
> 权威来源：[roadmap.zh-CN.md](roadmap.zh-CN.md) 与
> [ADR-0004](adr/0004-focus-on-ebpf-agent-observability.md)

本文把活跃 roadmap 转化为可执行的验证计划。它不扩大产品范围，也不记录逐 commit 进度；
工作状态与详细验收证据保存在聚焦的 Pull Request 中。

## 终点

当 Apolysis 能以有界 eBPF Agent runtime observability Beta 从 `pre-release` 推进到
`main`，且满足以下条件时，本计划完成：

- 本地 Linux 与 Docker/containerd Agent Run workflow 达到 stable；
- Kubernetes node 与 Pod attribution 保持 Beta 标签；
- Agent Observation Record 能展示受支持的 Runtime Observation、Runtime Identity、
  Collector Capability、Collector Health、finding 与 Observation Gap，而不要求读取原始
  JSONL；
- kernel、runtime、隐私、性能、retention 与故障边界均有文档和测试；
- roadmap 中所有适用的 no-go 条件均已关闭。

终点不包含 central ingest、多租户存储、provider semantics、remote outcome verification
或 enforcement。

## 执行规则

- 每个工作项从最新 `pre-release` 开始，使用一个聚焦分支，并通过一个目标为
  `pre-release` 的 Pull Request 跟踪。
- Pull Request 必须声明目的、非目标、验收标准、依赖、准确验证命令、权限假设、隐私检查
  和 rollback 行为。
- Kernel、runtime、Kubernetes 与性能声明需要显式 live gate。跳过的 gate 必须记录限制，
  且不能关闭对应验证项。
- 当产品方向或成熟度变化时，英文与中文 README、design 和 roadmap 必须保持同步。
- 本计划允许一次推进一个工作项；规划产物不算实际交付。

## 工作图

| 工作项 | 结果 | 依赖 |
| --- | --- | --- |
| C1 按 scope 的 Observation Gap | 按 cgroup 归属 network pairing counter，并在 multi-cgroup daemon 中持久化可信的 Agent-Run-scoped gap | 无 |
| C2 其余 operation outcome | 为受支持 file operation set 增加有界 entry/exit result 与 missing-pair gap | 无 |
| C3 稳定 Runtime Identity | 抵御 PID reuse 与 exec generation，且不把 heuristic match 提升为 Exact Relation | 无 |
| C4 Collector lifecycle | 持久化 start、health/loss checkpoint、terminal state 与显式 stop reason；incomplete lifecycle 必须 fail loud | 无 |
| Q1 验证边界 | 冻结候选 kernel/runtime contract 与测量协议；只有保留的 live 证据冻结 CPU、memory、latency 与 event-loss budget 后才授予支持 | 无 |
| L1 受保护的 existing-process attach | 通过 Runtime Identity 验证 attach，并发出显式 late-attach Observation Gap | C3、C4 |
| L2 Agent Observation Record projection | 为 observation、capability、identity、health、finding 与 gap record 生成单次 run 的可查询 aggregate 和 summary | C1、C2、C3、C4 |
| L3 非特权 saved-run viewer | 无需原始 JSONL 或 privileged access 即可完成代表性调查 | L2 |
| L4 本地 daemon 运维 | 验证 install、health、stop、cleanup、permission、retention 与 failure recovery | C4、L2 |
| D1 Container identity | 稳定 Docker/containerd cgroup 与 container attribution，并抵御 churn 与 PID reuse | C3、C4 |
| D2 Runtime recovery | 验证 daemon restart 与 Docker/containerd runtime socket recovery | D1、C4 |
| K1 Kubernetes attribution 与部署 | 绑定 Pod/runtime identity，并部署 least-privilege node collector 与 non-privileged viewer path | D1、D2、L2、L3 |
| K2 VKE 验证 | 在指定 VKE cluster 验证代表 workload、reschedule、sensor loss、runtime boundary、cleanup 与隐私 | K1、Q1 |
| R1 Beta release | 关闭所有适用 no-go 条件，准备 release metadata，把 `pre-release` 推进到 `main`，tag 并发布 | C1-C4、Q1、L1-L4、D1-D2、K1-K2 |

无依赖项构成初始 frontier。执行顺序为 C1、C2、C3、C4、Q1，使 correctness gap 在 UI
与环境扩张之前关闭。

## 完成门禁

### Collector correctness

- 每个声明的 operation/outcome 都由实际 attached source 与经过测试的 entry/exit semantics
  支撑。
- Missing entry、missing exit、unsupported path、reserve failure、map pressure、truncation、
  decode failure、restart 与 incomplete flush 不能产生 clean 或 complete Agent Observation
  Record。
- Runtime Identity 在其声明边界内区分 PID reuse 与 exec generation。
- Content-off persistence 阻止 raw argv、prompt、response、tool payload、credential、private
  path 与 private network content 穿过默认 persistence seam。

### 本地产品

- Managed launch 与 protected attach 都声明其 collection boundary。
- CLI 或 viewer 无需读取原始 JSONL 或 kernel trace，即可回答 roadmap 中六个调查问题。
- Viewer 为 non-privileged，且每个显示事实都能解析到 typed source record。
- Install、shutdown、cleanup、retention、permission 与 corruption recovery 均有边界并通过
  测试。

### Container 与 Kubernetes

- Container 与 Pod attribution 不依赖 PID-only、name-only 或 timing-only matching。
- Runtime restart、container churn、Pod reschedule、sensor loss，以及 unsupported guest 或
  remote path 始终表现为 identity transition 或 Observation Gap。
- Kubernetes 验证使用指定 VKE cluster，且不会复制、打印或提交 credential 或捕获的私有
  workload data。

### Release

- Release Pull Request 链接 local、CI、live-kernel、runtime、Kubernetes、privacy、
  performance、packaging、install、upgrade、uninstall 与 rollback 证据。
- `pre-release` 到 `main` 的 promotion 通过 required CI 与人工 review。
- 文档只命名 supported 或显式 experimental profile。

## 尚待解决的决策

以下细节必须由相应聚焦工作项解决，之后才能开始其依赖项：

- Q1 Candidate contract 已收敛为 Linux 6.12/x86_64 原生 host，但准确数值 performance
  budget 与任何 Supported 晋级仍受保留的 privileged live 证据阻塞；
- L2 冻结可查询 Agent Observation Record 后，saved-run viewer 的 interaction 与展示形态；
- container identity 与 runtime recovery 验证后，Kubernetes least-privilege deployment
  形态。

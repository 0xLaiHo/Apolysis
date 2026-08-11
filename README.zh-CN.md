# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](https://github.com/0xLaiHo/Apolysis/blob/main/LICENSE)

[English](README.md) | [简体中文](README.zh-CN.md)

Apolysis 是面向用户可控 Linux 环境的实验性 **eBPF Agent 运行时观测平台**。它把受支持的
进程、文件、网络和凭证相关运行时观测组织到一次 Agent Run 中，将其归属到进程和工作负载
身份，并明确展示 collector 丢失、截断和不支持的路径。

项目正在围绕这条 Linux runtime workflow 重置范围。eBPF 是必需的主要观测源，不再是更大
跨 provider 证据平台的可选附加项。Apolysis 不是 Agent orchestrator、sandbox、策略执行
引擎、MCP gateway、SIEM 或多租户证据 SaaS。

![Apolysis 实时 eBPF 审计：声明的 Agent workload 被匹配，一次未声明的凭证路径访问尝试被标记为 missing_intent；凭证路径在 timeline 中已脱敏](https://raw.githubusercontent.com/0xLaiHo/Apolysis/main/docs/assets/codex-live-demo/live-ebpf-demo.gif)

演示素材：[实时 asciinema cast](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/live-ebpf-demo.cast)、
[零特权 quickstart cast](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/codex-live-demo.cast)、
[公开 summary](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/summary.json) 和
[脱敏证据摘录](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/evidence-excerpt.jsonl)。Raw live timeline 不会提交；
公开素材会在发布前完成筛选、限界与脱敏。

## 五分钟零特权试用

```bash
make build && make quickstart
```

Quickstart 使用随包 fixture 运行观测与可选的声明意图对比。它不需要 root 或 eBPF。Fixture
会展示一条与观测匹配的声明 action，以及一次被报告为 `missing_intent` 的未声明凭证读取；
生成输出只写入 `target/quickstart/`。

## 产品问题

对于一次受支持的 Agent Run，Apolysis 应帮助操作者回答：

1. Agent 启动了哪些进程？
2. 观测到了哪些受支持的文件、网络和凭证操作？
3. 每条观测属于哪个 container、cgroup、Pod 或进程身份？
4. 操作是成功、失败，还是结果未知？
5. Collector 是否健康，观测缺口在哪里？
6. 哪些有界 Finding 需要操作者复查？

产品不把“没有观测到”解释为“没有发生”。它只描述声明 scope 与 capability 边界内的活动。

## 活跃产品边界

| 属于当前范围 | 不属于活跃范围 |
| --- | --- |
| 用户可控的 Linux 主机 | 用户无法控制 kernel 的厂商托管 Agent |
| 托管 Agent 启动、PID-tree 与 cgroup scope | 通用 Agent orchestration 或 sandbox |
| 进程、选定文件、网络和凭证观测 | 无差别全 syscall 或明文采集 |
| 本地、Docker/containerd 与有界 Kubernetes 归属 | 跨 provider Hook、OTLP、MCP、A2A 集成矩阵 |
| Collector 健康、丢失、截断和 capability gap | 远端 outcome 验证和可移植证据托管 |
| 本地 run 存储、查询和操作者 viewer | 多租户 Gateway、PostgreSQL/S3 平台、计费或 HA |
| 面向复查的 finding | BPF-LSM 阻断、审批 workflow 或通用 enforcement |

未来可以把 provider 或 harness metadata 作为可选上下文，但它不能替代 eBPF runtime source，
也不能把推断关系静默升级为 exact relation。

## 当前能力

- 通过 CO-RE eBPF 观测 fork、exec、exit、outcome-aware 选定文件操作和 network connect。
- 提供版本化 kernel/userspace ABI，并为每次 Agent Run 写入 capability manifest，明确实际挂载的
  event source 与支持的 outcome 语义。
- 为每次 Agent Run 写入 collector lifecycle record，包括持久化 start、周期 health/loss
  checkpoint、明确的正常或失败 terminal state；daemon 恢复未完成实例时会持久化 restart gap。
- 在一次 collector 运行内提供可抵御 PID reuse、exec 与数字 cgroup ID 复用的稳定 runtime
  identity，并显式记录 exact 或 inferred attribution。
- 支持 PID-tree、单 cgroup 与多 cgroup Observation Scope。
- 支持托管本地 Agent 启动，以及带显式 late-attach Collection Boundary 的 protected
  existing-process attach。
- Existing-process admission 只对当前 root 做资格校验；本次 run 的 exact event identity
  从 activation 后开始。
- 已完成基于稳定 complete inventory 的 Docker/containerd runtime binding 与有界 source
  recovery 资格验证；精确 identity、transition 与 gap 合同由设计文档定义。
- Kubernetes metadata 关联仍是有界 Beta 目标。
- Exec 参数与 process command 默认 content-off 持久化，并对凭证和网络内容脱敏。
- 提供有序 JSONL、输出轮转、可选本地 hash-chain envelope，以及 drop、map pressure、ABI
  mismatch、decode failure 和 truncation 的类型化诊断。
- 提供经过 manifest v2 验证的 Linux daemon 打包，以及只作用于固定托管路径集合、由 receipt
  证明 replacement/removal ownership 的 `apolysis daemon install`、`inspect` 与 `uninstall`
  运维能力。Staged-root 运维不会激活 systemd；托管变更中断后会在 reopen 时 fail-closed 地恢复，
  默认卸载会保留已保存的 Agent Run 状态。
- 可在非特权环境中把一次 saved Agent Run 确定性投影为可查询的 Agent Observation Record，
  并保持 evidence、collector health 与 review state 相互独立。Plain/rotated JSONL 和经过验证的
  hash-chain 输入都有界，遇到损坏或混合 run 时 fail closed。
- 可在非特权环境中把一份 Agent Observation Record 确定性呈现为私有、self-contained 的离线
  HTML 调查视图；三个状态轴保持独立，Finding 可链接到按 source order 排列的 observation。
- 对无法匹配或 collector 停止时仍 pending 的选定文件与 network connect entry/exit pair
  发出归属于 Agent Run 的 Observation Gap，并隔离 multi-cgroup daemon 中的不同 scope。
- 可选摄取 Codex 声明意图并通过启发式关联生成 mismatch finding。

选定文件操作与 network connect 现使用有界 entry/exit matching，并报告 return value 与
errno。文件 outcome 为 succeeded、failed 或 denied；connect 还支持 pending。Collector
不会观测所有 Linux 操作路径。

## 目标形态

```text
Agent command / container / Pod
  -> Observation Scope
  -> eBPF Collector
     - process lifecycle
     - selected file operations
     - network connections
     - collector health and gaps
  -> userspace normalization and redaction
  -> bounded local store
  -> CLI and saved-run viewer
```

特权 collector 与非特权 operator viewer 保持独立 trust boundary。Remote export 和任何中央
多租户证据平面都后置到有界 Beta 之后。

## 支持环境

| 环境 | 方向 |
| --- | --- |
| 本地 Linux Agent CLI | 首个稳定 workflow |
| 用户可控 Linux 上的 Docker/containerd | 本地 collector 正确性完成后的稳定目标 |
| Kubernetes node 与 Pod 归属 | Container identity 稳定后的有界 Beta |
| Linux self-hosted CI runner | 仅提供 CLI managed-run path；不维护 composite Action |
| macOS、Windows 或厂商托管 Agent runtime | 不支持 eBPF runtime observation |

## 当前仓库状态

`v0.3.0` 仍是最新公开研究版本，展示 live collector、托管 Agent 启动、JSONL timeline、
隐私脱敏和发布打包。活跃 Cargo workspace 现仅包含 10 个 crate：core、observer、
accountability finding、本地 storage、daemon、CLI、saved-run viewer、Kubernetes metadata、
visibility assessment 与 release verification。被取代的 contracts、中央服务、policy
actuation、Agent feedback control、sandbox execution 与广泛的 production-qualification
原型已移出活跃 build 和默认门禁。

本地 `apolysis run project` 路径现可为 saved run 原子写入一份私有 JSON Agent Observation
Record。`apolysis run view` 会验证恰好一份这类 v1 record，并写入私有、self-contained 的离线
HTML 调查视图。本地 projection 与 viewer 不会引入 live tail、跨 run 搜索、中央 query
service，也不会改变当前 experimental support 状态。

本地 daemon operations 方向现包含经过 manifest 验证的 Linux bundle，以及有界、保留状态的
host lifecycle。具体的文件系统、恢复与资格 contract 统一记录在 design 中；这项工作本身
不会改变 experimental support 状态。

D1/D2 runtime-binding implementation、deterministic contract 与保留的非破坏性资格验证已经完成，
并分别覆盖 Docker 和独立隔离的私有 standalone containerd runtime。这些证据保持 profile-specific：
不能把 Docker 声明外推到 containerd，也不能把任一 runtime 的声明外推到 Kubernetes。破坏性的
runtime-service restart、K1/VKE 与 release qualification 仍保持 open。这些结果都不会晋级任何
profile。

范围重置是一项路线图决策，不是追溯性的生产声明。在受支持 collector、归属、失败、性能和
隐私路径通过新的有界 Beta 门禁前，Apolysis 仍是实验性项目。资格 contract 将 Linux
6.12/x86_64 原生 host 定义为 Candidate；目前没有任何
Supported 环境，container 与 Kubernetes profile 仍是 Experimental。确切的机器可读权威与晋级
规则见[设计文档](docs/design.zh-CN.md)。

## 构建与测试

```bash
make build
make test
make lint
```

只构建 CO-RE eBPF 对象：

```bash
make build-ebpf
```

在准备好的 Linux host 上运行 opt-in live observer test：

```bash
make test-live
```

当 Linux BTF、cgroup v2、tracepoint 或所需 BPF capability 不可用时，特权测试会明确跳过。

无需 root 即可投影 saved run：

```bash
./target/debug/apolysis run project \
  --input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/agent-observation-record.json
```

无需 root 即可把这份 record 渲染为离线 Saved Run Viewer：

```bash
./target/debug/apolysis run view \
  --input .apolysis/codex-live/agent-observation-record.json \
  --output .apolysis/codex-live/saved-run-view.html
```

验证复制出的 hash-chain timeline，且不修改源文件：

```bash
./target/debug/apolysis verify hash-chain \
  --input /var/lib/apolysis/sessions/<agent-run-id>/timeline.jsonl \
  --output target/hash-chain-verification.json
```

退出码 `0` 表示有效，`1` 表示已写出验证失败报告，`2` 表示命令无法运行。

## 托管 Agent 实时观测示例

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-observation \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex exec --json "run the project tests"
```

不要在托管命令或参数中放置 secret。持久化边界默认关闭原始命令内容，但特权 kernel 内采集
与第三方 workload 行为仍需要有文档化的 threat model。

## 高层路线图

1. 保持活跃 workspace 只包含 eBPF collection、Observation Scope、attribution、本地 storage、
   daemon、CLI 与操作者调查能力。
2. 在指定的 runtime-ready 且 network-ready VKE 测试集群上验证 least-privilege K1 node/Pod
   归属这一明确有界的 Beta。
3. 将破坏性 runtime-service restart qualification 保持独立，并在不把 Docker 证据外推到
   containerd 或 Kubernetes 的前提下准备 release。
4. 只有适用的 kernel、runtime、privacy、performance、packaging、cleanup 与 no-silent-gap
   gate 全部通过后才晋级 release。

## 贡献

使用聚焦 branch，并通过仓库的 integration Pull Request workflow 提交变更。适用验证与运维
披露以仓库内自动化和 Pull Request template 为准。禁止提交 secret、kubeconfig、签名材料、
私有 capture、生成的 timeline 或本地 release artifact。

## 安全报告

Apolysis 是观测工具，不是 sandbox 或独立 attestation boundary。请使用 GitHub private
vulnerability reporting 报告漏洞。若该功能不可用，只能公开一个最小通知，不能包含 exploit
细节、secret、私有 log、path、argv、socket value、label、annotation 或 payload。报告应说明
受影响 commit/release、复现边界、所需权限，以及对 confidentiality、integrity、availability
或 observation accuracy 的影响。

## 文档

- [英文设计与完整产品 contract](docs/design.md)
- [简体中文设计与完整产品 contract](docs/design.zh-CN.md)

# Apolysis

[![发布验证](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![最新发布](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![许可证](https://img.shields.io/github/license/0xLaiHo/Apolysis)](https://github.com/0xLaiHo/Apolysis/blob/main/LICENSE)

[English](README.md) | [简体中文](README.zh-CN.md)

Apolysis 是面向用户可控 Linux 环境的实验性 **eBPF 智能体运行时观测平台**。它把受支持的
进程、文件、网络和凭证相关运行时观测组织到一次智能体运行（Agent Run）中，将其归属到进程
和工作负载身份，并明确展示采集器丢失、截断和不支持的路径。

项目正在围绕这条 Linux 运行时工作流重新界定范围。eBPF 是必需的主要观测来源，不再是更大
跨提供方证据平台的可选附加项。Apolysis 不是智能体编排器、沙箱、策略执行
引擎、MCP 网关、SIEM 或多租户证据 SaaS。

![Apolysis 实时 eBPF 审计：声明的智能体工作负载已匹配，一次未声明的凭证路径访问尝试被标记为 missing_intent；凭证路径在时间线中已脱敏](https://raw.githubusercontent.com/0xLaiHo/Apolysis/main/docs/assets/codex-live-demo/live-ebpf-demo.gif)

演示素材：[实时 asciinema 录屏](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/live-ebpf-demo.cast)、
[零特权快速试用录屏](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/codex-live-demo.cast)、
[公开摘要](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/summary.json) 和
[脱敏证据摘录](https://github.com/0xLaiHo/Apolysis/blob/main/docs/assets/codex-live-demo/evidence-excerpt.jsonl)。
原始实时事件时间线不会提交；公开素材会在发布前完成筛选、限界与脱敏。

## 五分钟零特权试用

```bash
make build && make quickstart
```

快速试用会使用随包测试夹具运行观测与可选的声明意图对比。它不需要 root 权限或 eBPF。测试夹具
会展示一条与观测匹配的声明操作，以及一次被报告为 `missing_intent` 的未声明凭证读取；
生成输出只写入 `target/quickstart/`。

## 产品问题

对于一次受支持的智能体运行，Apolysis 应帮助操作者回答：

1. 智能体启动了哪些进程？
2. 观测到了哪些受支持的文件、网络和凭证操作？
3. 每条观测属于哪个容器、cgroup、Pod 或进程身份？
4. 操作是成功、失败，还是结果未知？
5. 采集器是否健康，观测缺口在哪里？
6. 哪些有界发现项（Finding）需要操作者复查？

产品不把“没有观测到”解释为“没有发生”。它只描述声明范围与能力边界内的活动。

## 活跃产品边界

| 属于当前范围 | 不属于活跃范围 |
| --- | --- |
| 用户可控的 Linux 主机 | 用户无法控制内核的厂商托管智能体 |
| 托管智能体启动、PID 树与 cgroup 范围 | 通用智能体编排或沙箱 |
| 进程、选定文件、网络和凭证观测 | 无差别采集全部系统调用或明文内容 |
| 本地、Docker/containerd 与有界 Kubernetes 归属 | 跨提供方钩子、OTLP、MCP、A2A 集成矩阵 |
| 采集器健康、丢失、截断和能力缺口 | 远端结果验证和可移植证据托管 |
| 本地运行存储、查询和操作者查看器 | 多租户网关、PostgreSQL/S3 平台、计费或高可用 |
| 面向复查的发现项 | BPF-LSM 阻断、审批工作流或通用强制执行 |

未来可以把提供方或测试框架元数据作为可选上下文，但它不能替代 eBPF 运行时来源，
也不能把推断关系静默升级为精确关系。

## 当前能力

- 通过 CO-RE eBPF 观测 `fork`、`exec`、`exit`、能感知结果的选定文件操作和网络连接。
- 提供版本化内核/用户空间 ABI，并为每次智能体运行写入能力清单，明确实际挂载的
  事件来源与支持的结果语义。
- 为每次智能体运行写入采集器生命周期记录，包括持久化的启动记录、周期性健康/丢失
  检查点，以及明确的正常或失败终态；守护进程恢复未完成实例时会持久化重启缺口。
- 在一次采集器运行内提供可抵御 PID 复用、`exec` 与数字 cgroup ID 复用的稳定运行时
  身份，并显式记录精确归属或推断归属。
- 支持 PID 树、单 cgroup 与多 cgroup 观测范围（Observation Scope）。
- 支持托管本地智能体启动，以及明确标记延迟挂接采集边界（Collection Boundary）的受保护
  现有进程挂接。
- 现有进程准入只对当前根进程做资格校验；本次运行的精确事件身份
  从激活后开始。
- 已完成基于稳定完整清单的 Docker/containerd 运行时绑定与有界来源
  恢复资格验证；精确身份、状态转换与缺口契约由设计文档定义。
- 已为 containerd 与 K3s 节点实现确定性的 K1 Kubernetes 归属契约：它使用类型化的操作者
  授权声明，对 Pod 和运行时身份进行资格校验，记录明确的归属生命周期与缺口，并提供租户隔离
  查询、已保存运行投影和离线查看。指定的 VKE 实机资格验证通过前，Kubernetes 环境仍处于
  实验级（`Experimental`）。
- `exec` 参数与进程命令默认不持久化内容，并对凭证和网络内容脱敏。
- 提供有序 JSONL、输出轮转、可选本地哈希链封装，以及丢弃、映射表压力、ABI
  不匹配、解码失败和截断的类型化诊断。
- 提供经过清单 v2 验证的 Linux 守护进程打包，以及只作用于固定托管路径集合、由回执
  证明替换/删除归属权的 `apolysis daemon install`、`inspect` 与 `uninstall`
  运维能力。暂存根目录（staged root）运维不会激活 systemd；托管变更中断后会在重新打开时
  执行恢复，恢复失败则拒绝继续运行。默认卸载会保留已保存的智能体运行状态。
- 可在非特权环境中把一次已保存的智能体运行确定性投影为可查询的智能体观测记录
  （Agent Observation Record），
  并保持证据、采集器健康状态与复查状态相互独立。普通/轮转 JSONL 和经过验证的
  哈希链输入都有界，遇到损坏或混合运行数据时会拒绝继续处理。
- 可在非特权环境中把一份智能体观测记录确定性呈现为私有、自包含的离线
  HTML 调查视图；三个状态轴保持独立，发现项可链接到按来源顺序排列的观测项。
- 对无法匹配或采集器停止时仍处于挂起状态的选定文件与网络连接进入/退出事件对
  发出归属于智能体运行的观测缺口（Observation Gap），并隔离多 cgroup 守护进程中的不同范围。
- 可选摄取 Codex 声明意图并通过启发式关联生成不匹配发现项。

选定文件操作与网络连接现使用有界的进入/退出事件匹配，并报告返回值与
`errno`。文件结果为成功、失败或拒绝；连接还支持挂起状态。采集器
不会观测所有 Linux 操作路径。

## 目标形态

```text
智能体命令 / 容器 / Pod
  -> 观测范围
  -> eBPF 采集器
     - 进程生命周期
     - 选定文件操作
     - 网络连接
     - 采集器健康状态与缺口
  -> 用户空间规范化与脱敏
  -> 有界本地存储
  -> CLI 与已保存运行查看器
```

特权采集器与非特权操作者查看器保持独立信任边界。远程导出和任何中央
多租户证据平面都后置到有界测试版（Beta）阶段之后。

在 Kubernetes 中，目标部署形态是每个节点一个双容器 DaemonSet Pod。具有 root 权限的采集器负责
eBPF、主机运行时访问与本地状态，但不持有 Kubernetes API 令牌；非 root 元数据源
仅具有命名空间范围的 Pod 列举（`list`）与监听（`watch`）权限，并通过组共享 Unix 套接字发送有界
快照。操作者通过本地 `apolysisd-control` 边界注册精确、类型化的工作负载授权声明。主机
状态目录必须预先创建、归 root 所有，权限模式为 `0700`。

随仓库交付的标准清单只覆盖自身专用的智能体命名空间与 VKE/containerd 套接字，
不提供集群范围观测。K3s 已有实现支持，但需要操作者提供匹配 K3s 套接字且保持相同
信任控制的清单或叠加配置。该命名空间必须由操作者控制；不可信租户不得在
其中创建或修改 Pod。类型化授权声明会阻止元数据扩大授权范围，但不能阻止具有
命名空间写权限的主体用格式异常且带标记的元数据降低 K1 可用性。主机 CRI 套接字
允许调用会改变运行时状态的协议方法，因此采集器仍须作为节点级受信组件。令牌隔离、收敛后的
权限与能力集合，以及不记录内容的假名化标识，只能缩小
暴露面，不能使采集器变成真正的只读组件，也不能使元数据匿名。

## 支持环境

| 环境 | 方向 |
| --- | --- |
| 本地 Linux 智能体 CLI | 首个稳定工作流 |
| 用户可控 Linux 上的 Docker/containerd | 本地采集器正确性完成后的稳定目标 |
| Kubernetes containerd/K3s 节点与 Pod 归属 | 已有确定性 K1 实现；指定 VKE 实机资格验证前仍为实验级（`Experimental`） |
| Linux 自托管 CI 执行器 | 仅提供 CLI 托管运行路径；不维护复合 Action |
| macOS、Windows 或厂商托管智能体运行时 | 不支持 eBPF 运行时观测 |

## 当前仓库状态

`v0.3.0` 仍是最新公开研究版本，展示实时采集器、托管智能体启动、JSONL 时间线、
隐私脱敏和发布打包。活跃的 Cargo 工作区现仅包含 11 个 Rust 软件包（crate）：核心库、观测器、
问责发现项、本地存储、守护进程、CLI、已保存运行查看器、Kubernetes 归属、
隔离的 Kubernetes 元数据源、可见性评估与发布验证。被取代的契约、中央服务、策略
执行、智能体反馈控制、沙箱执行与广泛的生产资格验证
原型已移出活跃构建和默认门禁。

本地 `apolysis run project` 路径现可为已保存运行原子写入一份私有 JSON 智能体观测
记录。`apolysis run view` 会验证恰好一份这类 v1 记录，并写入私有、自包含的离线
HTML 调查视图。本地投影与查看器不会引入实时追踪、跨运行搜索、中央查询
服务，也不会改变当前的实验级支持状态。

本地守护进程运维现已包含经过清单验证的 Linux 组件包，以及有界且保留状态的
主机生命周期管理。具体的文件系统、恢复与资格契约统一记录在设计文档中；这项工作本身
不会改变实验级支持状态。

D1/D2 运行时绑定实现、确定性契约与保留的非破坏性资格验证已经完成，
并分别覆盖 Docker 和独立隔离的私有 containerd 运行时服务。K1 契约与实现也已
覆盖有界 containerd/K3s Kubernetes 工作流，但不会因此晋级支持等级。证据按
环境严格区分：Docker 与私有 containerd 结果不能用于资格化 Kubernetes。当前工作区因缺少
指定 kubeconfig 与 `kubectl`，尚未运行指定 VKE 实机门禁；其规范结果是“跳过”，不是“通过”。
破坏性的运行时服务重启资格验证与发布资格验证也仍未完成。

范围重置是一项路线图决策，不是追溯性的生产声明。在采集器、归属、失败、性能和
隐私路径通过新的有界测试版门禁前，Apolysis 仍是实验性项目。资格契约将 Linux
6.12/x86_64 原生主机定义为候选级（`Candidate`）；目前没有任何
正式支持（`Supported`）的环境，容器与 Kubernetes 环境仍为实验级（`Experimental`）。
确切的机器可读权威与晋级规则见[设计文档](docs/design.zh-CN.md)。

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

在准备好的 Linux 主机上运行需显式启用的实时观测器测试：

```bash
make test-live
```

当 Linux BTF、cgroup v2、跟踪点（tracepoint）或所需 BPF 能力不可用时，特权测试会明确跳过。

无需 root 权限即可投影已保存运行：

```bash
./target/debug/apolysis run project \
  --input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/agent-observation-record.json
```

无需 root 权限即可把这份记录渲染为离线的已保存运行查看器：

```bash
./target/debug/apolysis run view \
  --input .apolysis/codex-live/agent-observation-record.json \
  --output .apolysis/codex-live/saved-run-view.html
```

验证复制出的哈希链时间线，且不修改源文件：

```bash
./target/debug/apolysis verify hash-chain \
  --input /var/lib/apolysis/sessions/<agent-run-id>/timeline.jsonl \
  --output target/hash-chain-verification.json
```

退出码 `0` 表示有效，`1` 表示已写出验证失败报告，`2` 表示命令无法运行。

## 托管智能体实时观测示例

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

不要在托管命令或参数中放置敏感信息。持久化边界默认关闭原始命令内容，但特权内核采集
与第三方工作负载行为仍需要有文档记录的威胁模型。

## 高层路线图

1. 将已实现的 K1 契约限定在显式操作者授权声明、containerd/K3s 身份、节点本地
   采集与不记录内容的元数据内。
2. 在显式前置条件可用后，于指定的运行时和网络均就绪的 VKE 集群运行
   最小权限 K1 实机门禁。
3. 将破坏性的运行时服务重启资格验证保持独立，并在不把 Docker 证据外推到
   containerd 或 Kubernetes 的前提下准备发布。
4. 只有适用的内核、运行时、隐私、性能、打包、清理与无静默缺口
   门禁全部通过后才晋级发布。

## 贡献

使用范围聚焦的分支，并通过仓库的集成拉取请求（Pull Request）工作流提交变更。适用验证与运维
披露以仓库内自动化和拉取请求模板为准。禁止提交敏感信息、kubeconfig、签名材料、
私有采集数据、生成的时间线或本地发布制品。

## 安全报告

Apolysis 是观测工具，不是沙箱或独立证明边界。请使用 GitHub 私密漏洞报告功能报告漏洞。
若该功能不可用，只能公开一个最小通知，不能包含漏洞利用细节、敏感信息、私有日志、路径、
`argv`、套接字值、标签、注解或载荷。报告应说明受影响的提交/发布版本、复现边界、所需权限，
以及对机密性、完整性、可用性或观测准确性的影响。

## 文档

- [英文设计与完整产品契约](docs/design.md)
- [简体中文设计与完整产品契约](docs/design.zh-CN.md)

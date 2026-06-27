# Apolysis

[English](README.md) | [简体中文](README.zh-CN.md)

Apolysis 是一个面向 AI Agent workload 的 Linux 运行时问责层。它在 agent
harness 之下采集由环境拥有者掌握的证据，将这些证据与声明意图和 runtime metadata
关联起来，并写入可独立审计的 audit records。

Apolysis 适合运行 coding agent、自动化 agent 或不可信生成代码的团队。它要回答的问题很直接：
这个 session 在主机或 runtime 上实际做了什么？

## 为什么需要 Apolysis

Agent harness 日志有价值，但不能作为完整事实来源。Harness 可能隐藏重试、启动子进程、通过插件路由工具、处理凭证，或者在较宽松的文件系统和网络权限下运行。Apolysis 将证据边界放在 harness 之外。

Apolysis 聚焦三类职责：

- 将进程、文件、网络、runtime 和 policy evidence 记录到 append-only JSONL timeline。
- 将本地进程、Docker container、Kubernetes metadata 和 runtime isolation signal 关联到同一个 agent session。
- 提供 policy decision 和 operator feedback，同时不夸大 runtime 实际能够执行的控制能力。

Apolysis 不是 Docker、gVisor、Kata Containers、Firecracker、Kubernetes、MCP gateway
或审批 UI 的替代品。它补充这些系统，从环境视角记录 side effects 和 runtime context。

## 核心能力

- 本地命令 wrapper，跟踪 session 从进程启动到退出的完整过程。
- Docker runtime adapter，包含保守默认值、labels、resource limits 和 container metadata capture。
- Fixture 和 live eBPF observer backend，用于 process、file、network 和 credential-related events。
- Policy evaluation，支持 `Notify`、`Review`、`Kill`，并在 kernel support 不可用时显式降级 `Block` 行为。
- Kubernetes 和 Agent Sandbox metadata parsing，覆盖 Pod、namespace、RuntimeClass、service account 和 node context。
- Strong-isolation visibility assessment，用于 host-side evidence 无法覆盖 guest semantics 的 runtime。
- Node-local daemon、health model、metrics、recovery checks 和 Kubernetes deployment assets。
- 面向 regulated environment 的 evidence packaging、retention、signing、registry 和 release-readiness validation scripts。

## 架构

Apolysis 将 intent、isolation 和 evidence 分成三层：

- Intent authorization：agent 或 operator 声明应该发生什么。
- Execution isolation：runtime 允许 workload 触及什么。
- Side-effect verification：OS 和 runtime 显示实际发生了什么。

仓库拆分为多个职责清晰的 Rust crates：

- `apolysis-cli`：运行和观测 session 的命令行入口。
- `apolysis-core`：共享 schema 和 JSONL record 类型。
- `apolysis-runtime`：本地和 Docker runtime adapters。
- `apolysis-observer`：fixture 和 live observer backends。
- `apolysis-policy`：policy parser 和 decision logic。
- `apolysis-store`：append-only JSONL writer 和 hash-chain support。
- `apolysis-kubernetes`：Kubernetes 和 Agent Sandbox metadata parsing。
- `apolysis-visibility`：strong-isolation visibility assessment。
- `apolysis-accountability`：session、finding、queue 和 health contracts。
- `apolysis-daemon`：node-local Unix socket service。
- `apolysis-feedback`：面向 agent 的 feedback files。

## 环境要求

- Linux development host。
- Rust stable toolchain 和 Cargo。
- Docker runtime execution 需要 Docker CLI 和 daemon。
- Live eBPF observation 需要 `clang`、`llvm-strip`、`bpftool`、kernel BTF，以及所需 Linux capabilities 或 root 权限。

大多数 unit 和 fixture tests 不需要 root。

## 编译

编译整个 workspace 和 eBPF object：

```bash
make build
```

只编译 eBPF object：

```bash
make build-ebpf
```

格式化和 lint：

```bash
cargo fmt --all
make lint
```

## 测试

运行默认 Rust test suite：

```bash
make test
```

在已准备好 eBPF 能力的主机上运行 live observer smoke test：

```bash
make test-live
```

Production 和 release validation scripts 通过 Make targets 暴露，适合需要显式 evidence gates 的 operator workflow 和 CI job。无密钥 handoff gate 会检查 release-validation runbook 和 roadmap 状态是否仍保持一致；preflight fixture gate 会检查 retained evidence readiness report 和 evidence index 生成路径；CI contract gate 会检查 release-validation GitHub Actions workflow 保持 repo-local 且不需要 credentials：

```bash
make test-release-validation-handoff
make test-release-validation-preflight
make test-release-validation-ci
```

## 运行本地 Session

运行一个命令并写出 JSONL timeline：

```bash
cargo run -p apolysis-cli -- run \
  --policy policies/local-dev.yaml \
  --output .apolysis/timeline.jsonl \
  -- echo hello
```

查看结果：

```bash
cat .apolysis/timeline.jsonl
```

Timeline 会包含 session lifecycle records、runtime metadata、执行过的进程、policy decisions 和 process exit status。

## 使用 Docker 运行

在 Docker 中运行同一个命令：

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-timeline.jsonl \
  -- echo hello
```

如果已安装 gVisor `runsc`，可以指定替代 OCI runtime：

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --docker-runtime runsc \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-runsc.jsonl \
  -- echo hello
```

Docker adapter 会注入 `APOLYSIS_SESSION_ID`，写入 Apolysis labels，使用只读文件系统和默认禁用网络的配置，drop capabilities，应用 resource limits，并记录 container image、OCI runtime、mounts、network mode、container ID 和 cgroup mapping metadata。

## 观测 Fixture Events

在不需要 privileged kernel access 的情况下，可以使用 fixture input 开发 policy、schema 或 timeline processing：

```bash
cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session demo-fixture \
  --policy policies/local-dev.yaml \
  --output .apolysis/observer-timeline.jsonl
```

Observer 会写出 raw kernel-event records 和 canonical side-effect events。Fixture set 覆盖 process execution、file operations、network connects 和 credential-path reads。

## 观测 Live Host Activity

在具备条件的 Linux host 上，先编译 eBPF object，再运行 live observer：

```bash
make build-ebpf
make build
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session demo-live \
  --policy policies/local-dev.yaml \
  --output .apolysis/live-timeline.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --scope-pid <root-pid> \
  --workspace-root "$PWD"
```

Live backend 面向 audit。Pre-operation blocking 只存在于窄范围、显式启用的 prototype 中，不应被描述为通用 production enforcement guarantee。

## Kubernetes 部署资产

Kubernetes manifests 和 Helm assets 位于 `deploy/`：

```text
deploy/kubernetes/
deploy/helm/apolysis/
deploy/container/
deploy/systemd/
```

Kubernetes deployment assets 包括 RBAC、NetworkPolicy、DaemonSet、RuntimeClass examples、service mesh policy examples 和 production-oriented container hardening checks。

## 发布验证

仓库包含面向 regulated environment 的验证脚本，用于生成外部签名、不可变归档留存、registry promotion 和 managed service-mesh evidence。这些脚本将本地 evidence 写入 `target/`，运行时应使用明确限定权限范围的 provider credentials。Release-validation handoff gate 不需要 provider credentials，可检查 runbook、可重复输入和隐私约束。Release-validation preflight gate 会验证 retained evidence 输入，并为 operator handoff 写出 evidence index。

## 仓库结构

```text
crates/              Rust workspace crates。
ebpf/                eBPF source 和共享 observer ABI。
deploy/              Kubernetes、Helm、container 和 systemd assets。
policies/            示例 audit policies。
scripts/             Build、validation、release 和 evidence gates。
tests/fixtures/      Fixture events、policies、metadata 和 expected output。
docs/                聚焦的技术说明。
```

Generated build artifacts 和本地 evidence output 应放在 `target/` 或 `.apolysis/` 下，不应提交。

## 安全模型

Apolysis 记录 evidence。它不会单独把不安全的 runtime 变安全。Runtime isolation 仍由已配置的 container、VM、Kubernetes 或 host policy boundary 负责。

重要默认值和约束：

- 将 Docker 视为 baseline runtime adapter，而不是强隔离声明。
- 不要用 host-only evidence 声称 VM-backed runtime 的 guest-level visibility。
- 不要声称 broad pre-operation blocking，除非精确 kernel path 和 rollback behavior 已验证。
- 不要提交 credentials、kubeconfigs、provider tokens、signing material 或可能包含 private workload data 的 captured artifacts。

## 文档

- `docs/visibility-validation.md` 说明 host 和 guest visibility limits。
- `docs/release-validation-handoff.md` 说明 regulated-release validation
  handoff 和可重复 evidence-package 输入。
- `deploy/kubernetes/README.md` 说明 Kubernetes deployment assets。
- `ebpf/observer/README.md` 说明 observer eBPF program。

详细 roadmap、research notes、validation history 和 release-readiness records 不放在顶层 README 中，以便 README 保持面向使用和运维的核心内容。

## 许可证

Apolysis userspace components 使用 Apache-2.0。详见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。

在 Linux kernel BPF licensing rules 要求时，`ebpf/` 下需要加载进内核的 eBPF programs 使用 GPL-2.0-only。详见 [LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt)。

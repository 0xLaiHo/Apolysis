# Harness 意图：有界实时验证

[English](harness-intent-live-validation.md) | [简体中文](harness-intent-live-validation.zh-CN.md)

2026-11-05，合成 harness 标记门禁与通用实时观测器回归在 **x86_64 Linux
6.18.55-2-cachyos-lts** 上通过。这只验证该内核上的本地 fixture 路径。原生 Codex、
Claude Code、Cursor、Pi、OpenCode 端到端运行、其他内核及压力/丢失资格验证仍待完成。
工作由 [PR #87](https://github.com/0xLaiHo/Apolysis/pull/87) 跟踪。

## 变更原因

真实加载暴露了普通 Rust 测试没有覆盖的两个缺陷：

- CO-RE relocation 在 raw tracepoint context 的零长度 `args` 数组上失败。
  改为不依赖该数组重定位的 raw tracepoint 参数读取，修复 Aya 越界错误。
  显式主机 BTF 回归在修复前可复现失败，修复后通过。
- 扫描完整可执行文件路径导致内核验证器状态增长。定长 basename 尾部检查保留准确
  shell 名称识别，去掉完整路径扫描循环。内核代码与原生回归共享 C helper，覆盖合法
  shell 路径、相似名称和边界。

`make test-bpf-relocation` 构建对象，并把所有观测器 CO-RE relocation 应用到可读的
主机 BTF，不需要 BPF 权限，也不加载内核程序。通过
`cargo test -p apolysis-observer --test intent_header` 执行原生 helper 测试。
两者均不能替代内核验证器接受和实时断言。

## 观测结果

| 门禁 | 结果 |
| --- | --- |
| 主机 BTF 重定位回归 | 已复现修复前失败，修复后对象通过。 |
| 合成实时标记门禁 | 6 次完整采集、220 条 raw kernel event。每次都包含受管目标 exec、工作负载成功退出，以及与 raw event 数量一致且非空的 summary。 |
| 正例标记 | 同 PID exec、不 exec 的 fork、leader 退出后由剩余线程 fork、三个不同进程身份的文件尝试，以及 loopback connect 归属均通过。正例采集中没有 `intent_capture_incomplete:true`。 |
| 五类反例 | 普通 argv、脚本参数、后置注释、短 token 和大写 token 均不产生意图归属。 |
| 采集健康 | drop/map-pressure/decode/load/attach 失败计数为零。按采集顺序的截断计数为 **2、1、1、1、1、1**。 |
| 通用实时观测器回归 | 1 passed、0 ignored；3.78 秒；丢失事件为零，截断为 1。 |
| 最终本地门禁 | `cargo test`：490 passed、91 ignored；上方显式 BTF 与实时测试另行执行通过。桥接测试 7 passed。格式、Clippy、quickstart 与差异检查通过。 |

截断诊断被保留，涉及有界诊断 argv 和格式错误的标记反例，不代表覆盖完整。正例单独
明确检查标记采集完整性。测试通过 `pthread_join` 确认 leader 已退出，再观察剩余
线程的操作，不依赖时间延迟猜测退出顺序。

这些检查验证尝试与关联，不证明网络连接成功或某个操作已获授权。输入是交给 Apolysis
的合成 Claude 形状 hook payload，不是实际 Claude Code 会话。

## 复现与清理边界

特权门禁将仅审计探针限定到合成工作负载 scope，只读取临时 fixture 文件并尝试
loopback 连接。它要求 BPF/perf 能力（或 `CAP_SYS_ADMIN`）、可读主机 BTF、tracing
前提条件和 eBPF 构建工具。它不访问 provider 或 Kubernetes，不修改策略、不 pin map、
不挂载文件系统。CLI 与采用 648 字节 ABI 的 eBPF 对象须来自同一源码构建。

成功的标记运行使用独立临时 systemd scope：

```bash
cargo build -p apolysis-cli
sudo env APOLYSIS_REQUIRE_BPF=1 systemd-run --scope --quiet \
  --unit=apolysis-intent-validation-20261105 \
  ./scripts/test-live-harness-intent.sh
```

`APOLYSIS_REQUIRE_BPF=1` 让缺失前提条件变为失败而不是跳过。无特权命令
`APOLYSIS_REQUIRE_BPF=1 make test-bpf-relocation` 也已通过；其纳入版本控制的入口
在构建和测试前检查前提条件。调用者已经具备所需
能力和工具链访问权限时，正常的显式执行入口为 `make test-live-harness-intent`。

通用回归先由普通用户执行 `cargo test -p apolysis-cli --test observe --no-run`，
再在独立特权 scope 内执行生成的 `observe` 测试制品，参数为
`live_observer --ignored --nocapture`。Cargo 会报告制品路径；随构建变化的文件名
不是稳定接口。特权环境可以访问 Rust 工具链时，已纳入版本控制的
[`test-live-observer.sh`](../scripts/test-live-observer.sh) 提供等价执行入口。

退出后两个 scope 均不存在且不活动。清理检查确认三类 fixture 目录和 JSONL 没有残留，
也没有残留的 Apolysis BPF program 或 map。由 root 构建的两个 BPF 对象已恢复为
调用用户所有、权限 `0644`。不提交原始采集、验证器地址或临时复现文件。

该有界门禁通过不代表所有进程形式、内核、负载、事件丢失或产品版本均已验证，也不
解决与受保护 `pre-release` 分支的集成冲突。合并前仍须 CI 和 review。见
[设计](design.zh-CN.md)、[路线图](roadmap.zh-CN.md)和[Harness 接入](harness-intent.zh-CN.md)。

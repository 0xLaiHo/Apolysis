# Harness 意图：有界实时验证

[English](harness-intent-live-validation.md) | [简体中文](harness-intent-live-validation.zh-CN.md)

2026-11-05，合成 harness 标记/理由门禁与通用实时观测器回归在 **x86_64 Linux
6.18.55-2-cachyos-lts** 上通过，使用了下述受管门控描述符修复和最终 bridge 变更。
扩展后的 fixture 门禁已完成七次采集。原生 Claude Code、Pi、OpenCode 已在显式
shell bridge 下通过；Codex 仍受 provider 连通性阻断，Cursor 仍受认证过期阻断，
本报告不认定这两项通过。这些结果只验证
列出的本地路径、产品版本和 provider 配置。其他内核及压力/丢失资格验证仍待完成。
工作由
[PR #87](https://github.com/0xLaiHo/Apolysis/pull/87) 跟踪。

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

后续观测器回归暴露了受管启动的描述符缺陷：`dup2(3, 3)` 保留 `FD_CLOEXEC`，
导致 exec 后的 shell wrapper 丢失门控读取端，以 `Bad file descriptor`/退出码 127
失败。隔离子进程在创建 Tokio 前占用描述符 3，然后只释放自己持有的描述符，再调用
实际受管启动函数。该测试在修复前连续两次复现失败，显式清除 `FD_CLOEXEC` 后通过。
另一项回归复现了 spawn 失败时读取端泄漏；现在两个管道端均由 `OwnedFd` 持有，
错误路径会自动关闭。测试不关闭其他测试线程持有的描述符，也不需要 BPF 权限。
两项回归及原有门控释放测试均通过。

## 观测结果

| 门禁 | 结果 |
| --- | --- |
| 主机 BTF 重定位回归 | 已复现修复前失败，修复后对象通过：1 passed。 |
| 合成实时标记门禁 | 描述符和 bridge 修复后完成 7 次完整采集、303 条 raw kernel event。每次都包含受管目标 exec、工作负载成功退出，以及与 raw event 数量一致且非空的 summary。 |
| 正例标记 | 同 PID exec、不 exec 的 fork、leader 退出后由剩余线程 fork、三个不同进程身份的文件尝试，以及 loopback connect 归属均通过。正例采集中没有 `intent_capture_incomplete:true`。 |
| 理由关联与修订 | 声明理由附加到准确的文件和网络尝试关联；迟到修订改变当前理由，但不改变 raw event 或执行关联边。提示词、工具结果和原生描述的哨兵值未出现在持久化 intent/reason 记录中。 |
| 五类反例 | 普通 argv、脚本参数、后置注释、短 token 和大写 token 均不产生意图归属。 |
| 采集健康 | drop/map-pressure/decode/load/attach 失败计数为零。按采集顺序的截断计数为 **2、3、1、1、1、1、1**。 |
| 通用实时观测器回归 | 修复后运行：1 passed、0 ignored；3.84 秒；丢失事件为零，截断为 1。 |
| 受管门控描述符回归 | 描述符 3 启动与 spawn 错误清理均在各自修复前复现失败，修复后通过。 |
| 本地门禁 | `cargo test`：541 passed、91 ignored。observer crate：59 passed、1 ignored。CLI `observe`：20 passed、1 ignored。Node 桥接测试：14 passed。格式、Clippy、quickstart 与差异检查通过。显式 BTF 与实时结果在上方单列。 |
| 原生产品门禁 | Claude Code、Pi、OpenCode 在显式 `/bin/bash` bridge 下通过，计数和版本见下文；Codex 连通性与 Cursor 认证问题尚未解决。 |
| 扩展合成门禁 | 真实执行的 `eval` 包装 bridge 用例已通过，覆盖三个文件尝试进程身份及网络尝试归属，计入七次采集总数。 |

截断诊断被保留，涉及有界诊断 argv 和格式错误的标记反例，不代表覆盖完整。正例单独
明确检查标记采集完整性。测试通过 `pthread_join` 确认 leader 已退出，再观察剩余
线程的操作，不依赖时间延迟猜测退出顺序。

这些检查验证尝试与关联，不证明网络连接成功或某个操作已获授权。理由是声明元数据，
不是对操作的独立解释。七次采集门禁使用交给 Apolysis 的合成 Claude 形状 hook
payload，不是实际 Claude Code 会话。

## 复现与清理边界

合成特权门禁将仅审计探针限定到 fixture scope，只读取临时 fixture 文件并尝试
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

已完成的标记/观测器运行退出后，其 scope 均不存在且不活动。清理确认没有原生产品
测试进程、fixture 目录或 Apolysis BPF program/map 残留。显式保留用于诊断的 12 个
失败 fixture 已删除；成功 fixture 由脚本自动删除。由 root 构建的两个 BPF 对象已恢复为
调用用户所有、权限 `0644`。不提交原始采集、验证器地址或临时复现文件。

## 原生产品门禁：三项通过，两项待完成

三项已完成运行均显式选择 `--shell-bridge /bin/bash`（脚本接入使用
`APOLYSIS_SHELL_BRIDGE=/bin/bash`）。每项均通过零丢失/失败诊断检查，将原生声明
理由准确关联到合成 `cat` 的 fixture 文件尝试，并确认持久化 JSONL 输出中没有提示词
哨兵值。
最终复跑同时临时遮蔽已有用户 shell profile 和全局 hook。所选三个产品全部通过，
没有跳过前置条件。

| 产品 | 测试版本/配置 | Raw kernel event | 截断 | 结果 |
| --- | --- | --- | --- | --- |
| Claude Code | 2.1.295，本次安装环境的 Claude 配置 | 2593 | 12 | 显式 bridge 下通过 |
| Pi | 1.5.0，DeepSeek flash | 551 | 6 | 显式 bridge 下通过 |
| OpenCode | 1.18.31，DeepSeek v4 flash | 690 | 5 | 显式 bridge 下通过 |
| Codex | 0.162.0，既有 ChatGPT 认证 | — | — | Provider 连通性阻断，待复跑 |
| Cursor | 2026.07.20，access 与 refresh 认证均已过期 | — | — | 待更新认证并复跑 |

Codex 隔离认证绑定与原生安装指向同一个底层文件，token 尚未过期，但这不证明
provider 请求能够成功：在 harness 外以普通用户进行的 HTTP HEAD 探测同样失败。
通过既有代理访问 ChatGPT/OpenAI API 端点时发生 TLS unexpected EOF，没有 HTTP
响应；直连 ChatGPT 超时，直连 API 无法建立连接。因此当前证据不能把阻断归因为
Apolysis hook 故障。本报告不包含代理地址、环境变量值或认证内容。

Cursor 的 access token 和 refresh token 均已过期。缓存的 `logged_in` 状态不代表
当前 API 认证有效。门禁尚未验证可用的 Codex provider 通路或更新后的 Cursor 会话。

这些是对应测试版本和 provider 配置的部分原生产品结果，不是五产品整体资格验证。
Bridge 不是默认行为，它创建子 shell，cwd、环境和函数变化不会传回产品的外层 shell。
因此这些通过结果不代表默认模式能透明归属，也不代表普遍兼容有状态 shell。此前
Claude 默认注释模式虽持久化了声明和理由，但由于命令被嵌入产品的 `eval` wrapper，
没有形成准确执行关联。

纳入版本控制的 [`test-live-reason-products.py`](../scripts/test-live-reason-products.py)
和 `make test-live-reason-products` 运行实际原生产品并调用 provider。先构建 CLI
和 eBPF 对象。该入口要求显式通过 sudo 执行并保留调用用户的 `PATH`、非 root 的
原始调用用户、实时 BPF 前提条件、已安装的产品 CLI、Bubblewrap，以及可用的现有
产品认证。Provider 请求可能产生费用。Make 目标显式选择 `--shell-bridge /bin/bash`，
并使用 `--require-all`，因此缺少前提条件不能形成整体通过。

工作负载只读取临时合成文件，并携带首行理由代码。在 Bubblewrap mount namespace
内使用私有临时 hook 配置：除 fixture 目录外主机只读，现有全局 hook/指令通过挂载
遮蔽，不修改其主机文件。认证文件保留原位；隔离产品目录需要认证文件时，以只读绑定
方式使用既有文件，不复制内容。这是有界集成测试约束，不是针对恶意 agent 的安全
沙箱。门禁不使用 Kubernetes，也不修改全局产品配置。

入口检查原生产品成功退出、完整且非空的内核采集、一次原生工具调用声明及 content-off
理由，以及该理由到 fixture 文件尝试的 Exact Relation。输出仅含计数和固定错误
类别，不打印原始产品输出或凭证。正常退出和错误退出默认均清理临时采集与私有产品
日志；仅显式使用 `--keep-failed-private` 才保留失败 fixture 供本地诊断。声明整个
只有 Codex 和 Cursor 的剩余验证也通过后，才能宣称五产品验证全部通过。

该有界门禁通过不代表所有进程形式、内核、负载、事件丢失或产品版本均已验证，也不
解决与受保护 `pre-release` 分支的集成冲突。合并前仍须 CI 和 review。见
[设计](design.zh-CN.md)、[路线图](roadmap.zh-CN.md)和[Harness 接入](harness-intent.zh-CN.md)。

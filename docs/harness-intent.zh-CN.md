# Harness 意图

[English](harness-intent.md) | [简体中文](harness-intent.zh-CN.md)

Apolysis 把 Codex、Claude Code、Cursor、Pi 和 OpenCode 声明的 Tool Call 归一为本地
`intent` JSONL 记录。这些记录是 Semantic Evidence，不证明操作成功、已获授权或执行
覆盖完整。文件适配器导入历史声明；实时 hook 先记录声明，再返回受支持的 shell 命令改写。

Hook 写入器通过文件锁追加，并去重同一次调用的重复事件，不会清空此前的记录。实时 ID
是 32 位小写十六进制值，由带长度边界的来源、采集会话、原生会话和调用 ID 经 SHA-256
派生。原生 ID 保留为元数据，不直接插入 shell 语法。历史文件适配器继续使用原有的
来源前缀 ID。
去重比较除摄入时间外的完整持久化记录，不比较原始命令内容：若生产者复用调用 ID，
只存在于已丢弃参数中的差异无法检测。保留的元数据有冲突时会拒绝，不保存原命令指纹。

对于 shell Tool Call，改写在原命令正文前加入注释行：

```sh
# APOLYSIS_INTENT_ID=0123456789abcdef0123456789abcdef
cargo test
```

默认模式下，这是命令文本标记，不是环境变量，也不增加 shell 包装层。Hook 保留其他原始工具输入
字段。Claude Code 不收到 `permissionDecision`，由其原生许可流程决定是否批准。
Codex 契约要求 shell `updatedInput` 同时带有 `permissionDecision:"allow"`，因此只
对受支持的改写返回该确认，不对所有工具统一返回。Pi 与 OpenCode 修改文档规定的可变
输入对象；Cursor 返回其文档规定的继续响应。

持久化默认不保留内容：不保存提示词、工具结果、raw argv 或原始工具参数；可执行文件
元数据使用白名单。原命令会瞬时存在于 hook 中，并返回给产品执行。字段见
[JSONL schema v1](jsonl-schema-v1.md)。

## 采集会话与可见性

用于关联的 `session_id` 是 Apolysis 采集会话 ID；`harness_session_id` 单独保留产品
原生会话 ID。如果观测器使用不同 ID，应向 hook 传入 `--session <capture-id>`；否则
hook 默认采用原生 ID。观测器与 hook 必须使用相同采集 ID，仅原生调用 ID 相同不能
跨会话关联。Pi 与 OpenCode 包装脚本接受 `APOLYSIS_SESSION_ID` 作为采集会话覆盖值，
未设置时采用原生会话 ID。

每条声明都有 `observation_mode`：

| 值 | 含义 |
| --- | --- |
| `local_shell` | 已准备本地 shell 命令的标记传递。 |
| `semantic_only` | 有工具声明，但没有受支持的本地 shell 改写。 |
| `historical` | 从已有导出数据导入的声明。 |

`local_shell` 描述预期观测路径，不保证产品执行了改写，也不保证观测器收到标记。
网页搜索、读文件工具和远程调用保持 `semantic_only`，除非另一个执行集成提供证据。

## 可选 shell bridge

原生产品可能把改写后的命令放入环境准备脚本或 `eval` 中。工具输入中的前导注释不
保证出现在实际 exec 命令参数的开头。Claude Code 2.1.295 原生运行在默认注释模式下
记录了声明和原因，却未将 fixture 文件尝试归属到该意图。内核解析器继续严格限定
前导位置，不搜索任意嵌套注释。

在直接 hook 调用中追加 `--shell-bridge /bin/bash`，即可显式选择用独立 shell 执行
原正文，并让意图头位于该 shell 命令参数开头。Pi 和 OpenCode 设置
`APOLYSIS_SHELL_BRIDGE=/bin/bash`。支持 `/bin/sh`、`/bin/bash`、`/bin/zsh`、
`/bin/dash` 及对应的 `/usr/bin/` 路径，且可执行文件必须存在。工具输入若显式指定
shell，必须与该选择一致。`observation_mode` 仍为 `local_shell`。

该模式创建内层 shell，不用 `exec` 替换外层 shell。它保留原命令正文、输出与退出
状态，但 cwd、环境改动和函数不会回传给产品外层 shell。选择与命令语言兼容的 shell。
Bridge 默认关闭；在该模式下通过资格验证，不证明默认模式透明保留行为，也不证明
与有状态 shell 会话兼容。

## 声明原因

可选原因记录生产者声称一次 Tool Call 的用途。它是未经验证的 Semantic Evidence，
不是模型内部思考、推断的动机、授权或执行证明。原因保存在独立的 `intent_reason`
记录中，引用已有 `session_id` 与 `intent_id`，并保留 `intent_source`、
`harness_session_id` 和 `source_event_id` 用于身份校验。它不改变意图哈希、shell
意图标记或 eBPF 传递机制。

原因代码是封闭集合：

| 代码 | 声明的目的 |
| --- | --- |
| `unknown` | 没有声明分类目的。 |
| `inspect_context` | 查看相关上下文。 |
| `verify_change` | 验证改动。 |
| `reproduce_issue` | 复现问题。 |
| `implement_change` | 实现改动。 |
| `diagnose_failure` | 诊断失败。 |
| `gather_evidence` | 收集证据。 |

五个产品的内置 shell 工具都可以在已有命令字符串开头加入原因代码注释：

```sh
# APOLYSIS_REASON_CODE=verify_change
cargo test
```

默认注释模式下，hook 会在最前面加上已有的意图头，因此工具命令先是
`# APOLYSIS_INTENT_ID=<id>`，再是原因注释和命令正文。
启用可选 bridge 后，这些行位于内层 shell 命令参数的开头。该接口不增加产品原生工具
schema 字段。注释必须由生产者提供；Apolysis 不会根据 `cargo test` 或其他命令文本
推断原因。

受控扩展也可以在归一化 hook 输入中提供顶层 `apolysis_reason` 对象。这是 Apolysis
封装，不是产品内置工具的额外参数：

```json
{
  "session_id": "native-session-1",
  "tool_use_id": "call-1",
  "tool_name": "Bash",
  "tool_input": {"command": "cargo test"},
  "apolysis_reason": {
    "reason_code": "verify_change",
    "task_ref": "task-42"
  }
}
```

封装还接受可选的 `reason_summary`、`reason_id` 和 `supersedes_reason_id`，拒绝
未知字段。封装与注释同时存在时，原因代码必须一致。
显式声明来源为 `agent_declared`。只有原生工具描述时，来源为 `tool_description`、
代码为 `unknown`，不根据正文分类原因。`operator_annotation` 是保留来源，当前
不是受支持的输入模式。

Hook 可选参数 `--reason-output` 指定原因 JSONL 文件，默认为
`<intent-output>.reasons.jsonl`，现有 hook 配置采用该默认值。
Pi 和 OpenCode 桥接也接受 `APOLYSIS_REASON_OUTPUT`，只有
`APOLYSIS_REASON_SUMMARY=1` 才启用摘要。原因记录具有稳定 ID，
追加而不替换历史记录，重试去重，冲突 ID 产生诊断。修正使用新的 `reason_id`，
通过 `supersedes_reason_id` 引用同一次 Tool Call 已有的原因；跨调用引用不是修正。

默认只保留代码与标识符。`--allow-reason-summary` 允许保留最多 240 个 Unicode
字符、尽力脱敏的摘要。显式启用不代表任意文本都适合保留，请勿在原因中放入秘密。
`task_ref`、显式 `reason_id` 和 `supersedes_reason_id` 由 1–64 个 ASCII 字母、
数字、下划线或连字符组成。任务引用不是提示词、待读路径或任务文档。CLI 不会
读取完整提示词文件来重建原因。

若要晚到补充声明或修正，将上面的归一化调用 JSON 保存为 `reason-call.json`，保留
原调用的原生会话与调用身份，并使用与 hook 相同的采集会话覆盖值：

```bash
apolysis intent reason --harness codex --session capture-1 \
  --output .apolysis/intent.codex.jsonl.reasons.jsonl < reason-call.json
```

`intent reason` 还接受 `--workspace-root`、`--shell-bridge` 和
`--allow-reason-summary`；它追加
原因，不执行工具，也不改写命令。在关联时显式传入原因文件：

```bash
apolysis intent correlate \
  --intent-input .apolysis/intent.codex.jsonl \
  --reason-input .apolysis/intent.codex.jsonl.reasons.jsonl \
  --timeline-input .apolysis/timeline.jsonl \
  --output .apolysis/intent-correlation.jsonl
```

关联单独输出 `intent_reason_binding`。唯一有效原因可以补充已有 Exact Relation，不能建立
Exact Relation。冲突或未绑定原因产生诊断，不制造运行时链接，也不提升可执行文件名
候选。`semantic_only` 调用的原因可以只绑定声明。缺失原因保持未知，不从提示词、
命令名或已观测 syscall 重建。
即使来源不同，多个活跃原因也会产生歧义；应通过显式修正取代此前原因。成功绑定和
补充后的明确关联携带 `declared_reason` 对象；解析失败单独输出
`intent_reason_diagnostic`。

## Codex

在 `~/.codex/hooks.json` 或项目 `.codex/hooks.json` 中配置：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "apolysis intent hook --harness codex --output .apolysis/intent.codex.jsonl --workspace-root \"$PWD\""
          }
        ]
      }
    ]
  }
}
```

`codex-jsonl` 也支持 Codex `response_item` 日志，包括 `function_call`、`tool_call`、
`local_shell_call` 和 `web_search_call`。Codex 托管网页搜索不经过本地 `PreToolUse`
hook，需要通过文件摄入声明。Shell hook 使用规范名称 `Bash` 与 `tool_input.command`，
unified exec 也走这一形式。

## Claude Code

在 `.claude/settings.json` 中配置：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "apolysis intent hook --harness claude --output .apolysis/intent.claude.jsonl --workspace-root \"$CLAUDE_PROJECT_DIR\""
          }
        ]
      }
    ]
  }
}
```

`claude-jsonl` 读取 Claude Code transcript 中 assistant 的 `tool_use` block。

## Cursor

在 `.cursor/hooks.json` 中配置，两个事件使用相同命令：

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "apolysis intent hook --harness cursor --output .apolysis/intent.cursor.jsonl --workspace-root \"$PWD\""
      }
    ],
    "beforeShellExecution": [
      {
        "command": "apolysis intent hook --harness cursor --output .apolysis/intent.cursor.jsonl --workspace-root \"$PWD\""
      }
    ]
  }
}
```

`preToolUse` 通过 `updated_input` 给 shell 命令加标记，并保留其他工具输入字段。
`beforeShellExecution` 是补充事件，其文档定义的输入没有调用 ID：存在合法前导标记时
复用标记，否则报告跳过补充事件并继续，不编造调用 ID，也不覆盖意图文件。它不会再次
改写命令。云端 Agent 的 HTTP MCP 忽略 `updated_input`，这些调用保持为语义记录。

`cursor-jsonl` 读取 hook payload 和 assistant 的 `tool_use` block。文件摄入使用 CLI
`--session` 值。

## Pi

把 `hooks/pi/apolysis-intent.ts` 复制到 `~/.pi/agent/extensions/`。如果 `apolysis`
不在 `PATH` 中，设置 `APOLYSIS_BIN`。扩展监听 `tool_call`，追加
`.apolysis/intent.pi.jsonl` 并应用返回的 shell 命令。

`pi-jsonl` 读取 Pi 会话文件中 assistant 的 `toolCall` block。扩展通过
`ctx.sessionManager.getSessionId()` 获取原生会话 ID；`tool_call` 事件没有
`sessionId` 字段。

## OpenCode

把 `hooks/opencode/apolysis-intent.ts` 复制到 `.opencode/plugins/`。插件监听
`tool.execute.before`，追加 `.apolysis/intent.opencode.jsonl` 并应用返回的 shell 命令。

导出现有数据库：

```bash
sqlite3 "${XDG_DATA_HOME:-$HOME/.local/share}/opencode/opencode.db" \
  "SELECT data FROM session_message;" > /tmp/opencode-messages.jsonl
apolysis intent ingest --adapter opencode-jsonl --input /tmp/opencode-messages.jsonl \
  --session opencode-replay --output .apolysis/intent.opencode.jsonl \
  --workspace-root "$PWD"
```

每行是 `data` JSON 对象，工具部分是 `parts[]` 中 `type` 为 `tool` 的条目。

## 验证边界

Hook fixture 测试验证输入归一化、安全 ID、追加与去重、输入保留和命令语法，不调用
模型或 provider。这些测试不代表具体产品版本的实时事件送达或执行后端已通过资格
验证。JavaScript 桥接测试以产品形状的事件和受控子进程响应调用实际的 Pi 与 OpenCode
模块。使用当前 Rust 工具链运行聚焦检查。带锁追加接口使用
[`File::lock`](https://doc.rust-lang.org/std/fs/struct.File.html#method.lock)，
该 API 要求 Rust 1.89 或更新版本；这不代表整个 workspace 的最低 Rust 版本已验证。
桥接测试使用原生 [TypeScript 类型剥离](https://nodejs.org/api/typescript.html)，
要求 Node.js 22.x 分支中的 22.18+，或默认启用类型剥离的更新 LTS 版本。
`make test` 包含 `make test-harness-hooks`，CI 使用最新 Node.js 22 版本运行该目标：

```bash
cargo test -p apolysis-store --test intent_append
cargo test -p apolysis-cli --test intent_harness
cargo test -p apolysis-cli --test intent --test intent_correlation --test intent_correlation_conflicts
cargo test -p apolysis-observer
make test-harness-hooks
```

独立门禁 `scripts/test-live-reason-products.py` 使用合成提示词调用已安装产品 CLI
及其配置的 provider。它要求显式特权执行、已有认证的用户、当前 CLI 和 BPF 对象，
以及 Bubblewrap。`--products codex,claude,cursor,pi,opencode` 选择产品；
`--require-all` 将前提条件缺失导致的跳过视为门禁失败。
运行时显式传入 `--shell-bridge /bin/bash` 才验证 bridge 送达；省略则测试默认注释
路径。提权启动观测器时应保留原用户已有 proxy 与 provider 环境，但不打印其值。
例如按需保留已有 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 及对应小写变量，
以及选定 provider 已有的认证变量名。不要把凭证值写入命令参数、纳入版本控制的
配置或日志。CLI 已安装、状态命令显示存有登录数据，都不能证明当前 provider 可访问。
它使用临时项目 hook，在私有
mount namespace 中屏蔽全局 hook 与用户 shell 启动文件。原认证保留在已有位置或只读绑定；Claude 已有的
认证环境仅在内存中传递。门禁将原生声明与原因对应到准确的 fixture 文件尝试，并
拒绝提示词专用 sentinel 出现在持久化结果中。这是独立资格运行，不代表安装适配器
就已通过。产品输出和采集保存在私有目录，默认删除。
`--keep-failed-private` 显式保留失败的临时目录供本地诊断；检查后删除报告的目录，
不要提交其中内容。该门禁会发起真实 provider 请求，可能产生费用。
2026-11-05 的脚本原生 bridge 门禁已在 Claude Code 2.1.295、Pi 1.5.0 和
OpenCode 1.18.31 通过。当时 Codex 虽存有认证但 provider 连通性失败，Cursor
凭证过期。较新的[原生入口验证](harness-intent-live-validation.zh-CN.md#原生入口验证)
现已在显式测试权限参数下完成 Codex 验证；这不抹去此前失败，也不证明仍待完成的
Cursor 路径通过。前述三项结果仅覆盖单条合成原因注释、显式 `/bin/bash` bridge、
准确的 fixture 文件尝试，以及提示词 sentinel 隐私断言，不代表默认注释传递或任意
原生工具调用均已验证。

`make test-bpf-relocation` 是额外的显式门禁，需要可读的主机 BTF 和 eBPF 构建工具，
不需要 BPF 权限。它解析已构建对象并重定位所有程序，不将其加载进内核。原生 C helper
测试也覆盖完整 shell basename 与格式错误的标记。

特权实时观测器测试需要显式启用。缺少权限或内核条件应报告跳过，不能报告通过。CLI
与 eBPF 对象必须一起重建；当前 648 字节事件 ABI 不兼容旧对象。
`make test-live-harness-intent` 在准备好的主机上执行显式本地实时标记门禁。经授权的
特权运行现已在一个本地内核上通过，通用观测器回归也通过；准确范围和保留的截断诊断
见[实时验证](harness-intent-live-validation.zh-CN.md)。该合成门禁本身不代表原生产品端到端送达、
其他内核或压力/丢失行为通过资格验证。
门禁把仅审计的探针限定到合成子进程树，读取临时 fixture 文件并尝试连接 loopback。
它不访问 provider，也不修改运行时策略；进程退出会卸载探针，脚本删除自己创建的临时目录。

## 如何关联观测到的尝试

采集器只从已识别 shell 的命令字符串参数中读取完整前导标记。标记使用独立字段采集，
不扫描诊断 argv，因此长命令正文被截断不会截断标记。支持的 shell 调用形式是有界的：
前八个参数内的 `-c`、`-lc` 或 `-cl`；其他执行形式可能保持无归属。

内核上下文检查 TGID 加线程组首线程启动时间，在 fork 时复制标记（包括不 exec 的子进程），
同进程 exec 只有在完整采集确认没有新标记时保留原标记，观察到合法新标记时替换。
缺失 pending capture、不可读或格式错误的标记，以及无法确定 shell 命令参数位置时，
清除旧归属。这些情况在默认不保留内容的 raw payload 中留下
`intent_capture_incomplete:true`，并计入已有截断告警。文件、网络、凭证和
进程事件在上下文已知时携带该标记，最后一个线程退出时清理上下文。缺失的实时标记不会从旧
用户态缓存重建。丢失与 map-pressure 诊断仍然适用，这不代表完整进程树覆盖。

关联是独立命令，只在同一采集会话内进行：

- 唯一 `intent_id`，或无标记时唯一显式 `raw_event_id` 链接，可在该集成的信任边界内
  建立 Exact Relation。两者同时存在时必须指向同一声明。
- 未知、冲突或存在歧义的标识符产生 `intent_correlation_diagnostic`，不会回退到名称
  匹配。
- 旧版命令相等和仅限 exec 的可执行文件匹配产生 `intent_correlation_candidate`：
  一个候选标为 `inferred`，多个标为 `ambiguous`。它们不计为匹配，也不抑制 Finding。
- `semantic_only` 声明既不匹配执行事件，也不产生 `unobserved_intent`。历史导入仍可
  使用显式链接；只有弱候选时仍然视为未匹配。

当前文件与网络事件描述观测到的尝试。一次 Tool Call 可以产生多个事件；编号匹配不
证明该工具被授权执行所有观测到的行为。Provider 端网页搜索不属于本地主机 connect
可见范围。远程执行后端需要自己的 Evidence Source。

所有写入实时意图文件的进程必须使用带锁追加接口。外部轮转和网络文件系统的锁行为
不在此本地契约内。现有文件损坏或尾行不完整时会被拒绝，不会清空原文件。Codex、
Claude Code 和 Cursor 的直接 hook 失败时以退出码 2 结束，不输出改写命令，产品可能
阻止工具调用。Pi 与 OpenCode 桥接失败时则报告固定诊断，移除所有完整的前导意图
标记头后继续执行，保留命令正文，避免被拒绝的旧标记把当前执行归到其他调用。
这些失败不能视为成功采集。

原生 hook 契约参考：

- [Codex hooks](https://learn.chatgpt.com/docs/hooks)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [Pi extensions](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md)
- [OpenCode plugins](https://opencode.ai/docs/plugins/)

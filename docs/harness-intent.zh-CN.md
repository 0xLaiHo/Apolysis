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

这是命令文本标记，不是环境变量，也不增加 shell 包装层。Hook 保留其他原始工具输入
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

特权实时观测器测试需要显式启用。缺少权限或内核条件应报告跳过，不能报告通过。CLI
与 eBPF 对象必须一起重建；当前 648 字节事件 ABI 不兼容旧对象。
`make test-live-harness-intent` 在准备好的主机上执行显式本地实时标记门禁；当前无特权
调用因缺少 BPF/perf 能力而跳过，不代表实时内核行为通过资格验证。
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

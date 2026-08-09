# Agent Observation Record v1

> [English](agent-observation-record-v1.md) | 简体中文

Agent Observation Record 是一次 saved Agent Run 的确定性、可查询投影。它是单个
JSON 对象，不是 timeline JSONL record，也不得追加回源 timeline。

## 命令

```bash
apolysis run project \
  --input <timeline.jsonl> [--input <additional.jsonl> ...] \
  --output <agent-observation-record.json>
```

输入按命令行顺序消费。对于带 rotation 的 plain input，源顺序从最旧的连续 `.N`
archive 到 `.1`，最后是 active file。Hash-chain input 必须先完整验证，之后才会暴露
payload，且不能使用 rotation set。时间戳不会改变源记录顺序。

## 顶层对象

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `record_type` | string | 固定为 `agent_observation_record` |
| `schema_version` | integer | 固定为 `1` |
| `agent_run_id` | string | 所有输入记录共享的唯一 Agent Run |
| `source_integrity` | enum | `unverified_plain_jsonl`、`verified_hash_chain` 或 `mixed` |
| `summary` | object | 相互独立的 evidence、health、review、计数和分组字段 |
| `capability_manifests` | array | 已验证且执行 content-off 的 Collector Capability 源记录 |
| `runtime_identities` | array | 精确 Runtime Identity 聚合 |
| `runtime_observations` | array | 规范化的受支持或明确受限 observation |
| `collector_lifecycle` | array | 按序排列的 start、checkpoint 和 terminal 源记录 |
| `findings` | array | 面向 review 的类型化 finding |
| `observation_gaps` | array | 类型化、有界的 gap 和采集边界 |
| `issues` | array | 带源 ordinal 和计数的类型化投影限制 |

每个投影出来的源事实都带有 `source_ordinal`。它从一开始按权威输入顺序分配，
不是时间戳排序键。

## Summary

`summary` 包含：

- `evidence_state`：`complete`、`active`、`incomplete`、`failed` 或
  `indeterminate`；
- `collector_health`：`healthy`、`degraded`、`failed` 或 `unknown`；
- `review_state`：`requires_review`、`no_findings_reported` 或
  `indeterminate`；
- `runtime_observation_count`、`runtime_identity_count`、`finding_count` 和
  `observation_gap_record_count`；
- `known_missing_observation_count`：对 `missing_entry` 和 `missing_exit` record
  计数；
- `unknown_history_boundary_count`：对 `late_attach` 计数；其中的 `count:1` 表示一个
  boundary，并非缺失事件数量的估算；
- 确定性的 `event_type_counts`、`outcome_counts`、`relation_counts`、
  `finding_kind_counts` 和 `gap_kind_counts` map。

三个 state 字段相互独立。Finding 会要求 review，但不会让原本完整的 evidence 变得
incomplete。`no_findings_reported` 仅适用于完整且非空的 evidence，它不是 clean
verdict。即使存在其他 issue，active 或 failed lifecycle 仍然可见。

Complete evidence 要求一个兼容的 content-off capability manifest、合法且正常结束的
lifecycle、至少一个受支持的 Runtime Observation，并且不存在 loss、gap、diagnostic、
integrity 或 capability issue。缺少 lifecycle、不受支持或缺失的 outcome、collector
loss、gap、integrity finding 和非零 failure diagnostic 均不能被判为 complete。Mixed
integrity 和未知的 additive record 会使原本形似完整的 run 变为 indeterminate。

## Identity 与隐私

在一个 collector instance 内，精确 identity 由 host boot ID、scope generation、PID、
process generation、kernel process-start time 和 exec generation 组成。相同的精确 tuple
会折叠为按首次出现稳定分配的 `identity-1`、`identity-2` 等 ID。Inferred、ambiguous
和 unattributed observation 不会被提升或合并为精确 identity。

投影只接受 `content_off` capability manifest，并拒绝非 null 的旧版
`process_command`。Finding kind、decision 和 evidence boundary 都经过类型约束。
Finding reason 与普通 Gap detail 从有界词汇派生，不复制自由格式源文本。未知 record
和 integrity record 的 payload 不会复制到投影或错误信息中。

## 失败边界

对于空 record set、混合 Agent Run、格式错误或不兼容 record、非法 lifecycle 顺序、
破损的 late-attach durable boundary、重复的规范 `raw_event_id`、冲突的精确 identity、
违反 content policy 或超过输入限制，projector 会 fail closed。发生这些结构性失败时，
不会返回局部 aggregate。

本地 reader 还会拒绝 symlink、非普通文件、不连续 archive、读取期间变化的 source、
截断的尾行、畸形 JSON、混合 envelope format 和 hash-chain 损坏。错误只标识有界位置
或类别，不包含 path、record payload 或冲突的 run ID。

## 限制与发布

- saved-run input 总量不超过 128 MiB；
- 每行 JSONL 不超过 1 MiB；
- 源 record 不超过 1,000,000 条；
- numeric rotation archive 不超过 1,024 个；
- projection input batch 不超过 1,024 个；
- projection 边界内，每个 string 不超过 4,096 bytes，每个 array 不超过 1,024 items，
  每个 object 不超过 256 fields，value 嵌套不超过 16 层。

CLI 序列化一个确定性的 pretty-JSON 对象，并追加换行。它在 output directory 中创建
独占、mode 为 `0600` 的临时文件，完成同步后原子 rename，再同步 parent；如果 output
path 或 inode 与任一 active 或 rotated input 重合，则拒绝写入。

## 最小查询示例

```bash
jq '.summary' agent-observation-record.json
jq '.runtime_identities[]' agent-observation-record.json
jq '.runtime_observations[] | {source_ordinal,event_type,outcome,relation_status}' agent-observation-record.json
jq '.observation_gaps[], .issues[]' agent-observation-record.json
jq '.findings[] | {kind,decision,evidence_ref}' agent-observation-record.json
```

L3 saved-run viewer 将消费这份 record。Live tailing、跨 run 搜索、remote query 和 central
evidence plane 均不属于该 schema。

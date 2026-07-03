# Apolysis JSONL Schema v1

Schema version: v1

This document is the stable consumer contract for Apolysis JSONL records emitted
by the CLI observer, runtime metadata adapters, policy feedback path, and
visibility validator. It covers append-only audit records intended for
operators, tests, and downstream log or SIEM pipelines.

Generated validation reports, provider evidence bundles, release manifests, and
hash-chain package metadata are separate artifacts. They may contain JSON, but
they are not timeline JSONL records covered by this schema.

## Format

- Files are newline-delimited JSON.
- Each line is one complete JSON object.
- Every object has a `record_type` string.
- Timestamps are Unix milliseconds unless a field name states another unit.
- Numeric process identifiers are decimal JSON numbers.
- Optional fields are emitted as `null`, not omitted.
- Consumers must ignore unknown fields.
- Producers must not write raw secret material. Path, argv, socket, payload, and
  command fields may contain redacted tokens.

## Append-only compatibility rules

The v1 compatibility contract is append-only:

- Existing field names and meanings are stable.
- Existing `record_type` values remain readable.
- New nullable fields may be added to an existing record.
- New `record_type` values may be added.
- New enum string values may be added when a feature introduces a new runtime,
  event source, event type, policy decision, enforcement backend, or diagnostic
  kind.
- Consumers must not rely on object field ordering.
- Consumers that need exact joins should use `event_id`, `raw_event_id`, and
  `observed_event_id`, not timestamp-only matching.
- Backward-incompatible removal, renaming, type changes, or semantic changes
  require a new schema version.

## Record Types

### `session`

Session records describe a supervised runtime session.

Fields:

- `record_type`: always `session`
- `id`: session identifier
- `runtime`: `local`, `docker`, `kubernetes`, or `firecracker`
- `root`: runtime root or `null`
- `policy_path`: policy file path used for the run
- `started_at_unix_ms`: session start timestamp

### `event`

Canonical event records describe normalized runtime, metadata, process, file,
network, credential, or policy-visible activity.

Fields:

- `record_type`: always `event`
- `timestamp_unix_ms`: event timestamp
- `session_id`: session identifier
- `event_source`: `manual`, `process_tree`, `kernel_tracepoint`, `bpf_lsm`,
  `uprobe`, `runtime_metadata`, or `agent_feedback`
- `event_type`: `session_started`, `runtime_metadata`, `exec`, `file_open`,
  `file_create`, `file_truncate`, `file_unlink`, `file_rename`,
  `network_connect`, `credential_read`, or `process_exit`
- `raw_event_id`: matching raw kernel `event_id`, or `null`
- `pid`: process ID
- `ppid`: parent process ID
- `actor`: process, observer, policy, runtime, or integration actor
- `resource`: target resource, metadata resource, path token, executable, or
  socket token
- `action`: action or metadata value
- `container_id`: container identifier or `null`
- `cgroup_id`: cgroup identifier or `null`
- `process_command`: redacted command context known for the PID, or `null`
- `process_executable`: executable path known for the PID, or `null`
- `process_started_at_unix_ms`: command-context start timestamp, or `null`

Runtime metadata records are canonical `event` records with
`event_type:"runtime_metadata"`. Agent supervisor metadata uses resources such
as `agent-supervisor-mode`, `agent-kind`, `agent-root-pid`, `agent-command`,
`agent-command-fingerprint`, `agent-executable`, `agent-workspace-root`,
`agent-start-time`, and `agent-exit-status`.

### `raw_kernel_event`

Raw kernel event records preserve observer input before canonicalization.

Fields:

- `record_type`: always `raw_kernel_event`
- `timestamp_unix_ms`: event timestamp
- `session_id`: session identifier
- `event_source`: normally `kernel_tracepoint`
- `event_name`: kernel event or tracepoint name, for example
  `sched_process_exec`, `sched_process_exit`, `sched_process_fork`, `openat`,
  `creat`, `truncate`, `unlinkat`, `renameat2`, or `connect`
- `event_id`: stable per-session raw event identifier, or `null`
- `pid`: process ID
- `ppid`: parent process ID
- `uid`: user ID
- `gid`: group ID
- `comm`: kernel command name
- `resource`: raw resource after persistence-time redaction
- `action`: raw action label
- `container_id`: container identifier or `null`
- `cgroup_id`: cgroup identifier or `null`
- `raw_payload`: bounded raw payload after persistence-time redaction

Exec payloads may include redacted argv evidence. Truncation is explicit through
markers such as `argv_truncated:true`, `payload_truncated:true`, and
`resource_truncated:true`.

### `intent`

Intent records preserve declared harness or tool-call intent as append-only
timeline records. They are optional: Apolysis can still record host-side
evidence without harness logs, but consumers need `intent` records when they
want to compare declared work with observed side effects.

Fields:

- `record_type`: always `intent`
- `timestamp_unix_ms`: intent ingestion timestamp
- `session_id`: session identifier
- `intent_source`: harness or adapter name, for example `codex`
- `intent_id`: stable intent identifier assigned by the adapter
- `source_event_id`: source harness event ID or `null`
- `intent_type`: normalized intent category, for example `tool_call`
- `tool_name`: source tool/function name
- `declared_action`: normalized action class such as `shell.command`, or
  `null`
- `target`: declared target scope, resource class, or `null`
- `command`: redacted command or tool payload summary, or `null`
- `raw_event_id`: observed raw kernel event ID after correlation, or `null`

The first adapter is `codex-jsonl`. It consumes Codex JSONL `response_item`
function/tool-call records and writes `intent` records with source
`intent_source:"codex"`. Payload redaction reuses command redaction rules for
secret-looking argv values and credential-looking paths.

Example ingestion:

```bash
apolysis intent ingest \
  --adapter codex-jsonl \
  --input .apolysis/codex-live/codex-response-items.jsonl \
  --session codex-local-audit \
  --output .apolysis/codex-live/intent.codex.jsonl \
  --workspace-root "$PWD"
```

### `intent_correlation`

Intent correlation records link declared harness intent to observed host-side
timeline evidence. Correlation prefers stable `raw_event_id` matches when an
intent record already carries one. If no event ID is available, the first
implementation can fall back to exact redacted command-context matching through
`process_command_exact`. For live eBPF traces where argv can be truncated,
`exec` events may also match a declared command by the observed
`process_executable` or exec `resource` path.

Fields:

- `record_type`: always `intent_correlation`
- `timestamp_unix_ms`: correlation timestamp
- `session_id`: session identifier
- `intent_source`: harness or adapter name, for example `codex`
- `intent_id`: declared intent identifier
- `match_basis`: `raw_event_id`, `process_command_exact`, or
  `process_executable`
- `raw_event_id`: observed raw kernel event ID linked to the canonical event
- `event_type`: observed canonical event type
- `pid`: process ID on the observed event, or `0` if unavailable
- `resource`: observed resource string
- `process_command`: redacted observed command context, or `null`
- `process_executable`: observed executable path, or `null`
- `command`: redacted declared command or tool payload summary, or `null`

Example correlation:

```bash
apolysis intent correlate \
  --intent-input .apolysis/codex-live/intent.codex.jsonl \
  --timeline-input .apolysis/codex-live/timeline.jsonl \
  --output .apolysis/codex-live/intent-correlation.jsonl
```

### `accountability_finding`

Accountability findings generated by the intent correlation pass identify
declared-versus-observed mismatches that require review. They are append-only
records; consumers should treat `evidence_ref` as a reference to either a
canonical event's `raw_event_id` or an `intent_id`.

Fields:

- `record_type`: always `accountability_finding`
- `schema_version`: finding schema version, currently `1`
- `session_id`: session identifier
- `kind`: `missing_intent` or `unobserved_intent`
- `decision`: currently `review`
- `reason`: human-readable explanation
- `evidence_ref`: `raw_event_id` for observed side effects, or `intent_id` for
  declared intent without host evidence
- `runtime`: runtime metadata object when available
- `evidence_boundary`: boundary label, currently `host_boundary`

### `policy_violation`

Policy violation records describe policy decisions derived from observed events.

Fields:

- `record_type`: always `policy_violation`
- `timestamp_unix_ms`: decision timestamp
- `session_id`: session identifier
- `observed_event_id`: raw kernel `event_id` that caused the decision, or `null`
- `rule_id`: policy rule identifier
- `decision`: `allow`, `notify`, `block`, `kill`, or `review`
- `reason`: human-readable policy reason
- `pid`: process ID
- `target`: resource or target that matched the rule
- `enforcement_backend`: `audit_only`, `tracepoint_notify`, `bpf_lsm_block`,
  `seccomp_block`, or `signal_kill`

### `enforcement_metadata`

Enforcement metadata records explain how a requested policy decision was handled
by the available runtime backend.

Fields:

- `record_type`: always `enforcement_metadata`
- `timestamp_unix_ms`: metadata timestamp
- `session_id`: session identifier
- `rule_id`: policy rule identifier or `null`
- `observed_event_id`: raw kernel `event_id` that caused the decision, or `null`
- `requested_decision`: requested policy decision
- `effective_decision`: effective policy decision after downgrade or backend
  selection
- `enforcement_backend`: backend used or selected
- `timing`: enforcement timing label
- `runtime`: runtime label
- `action`: observed or policy action
- `preoperation_prevention`: boolean, true only for pre-operation blocking paths
- `observed_event_timestamp_unix_ms`: observed event timestamp or `null`
- `decision_latency_ms`: decision latency or `null`
- `side_effect_race_window_ms`: post-event race window or `null`
- `downgrade_reason`: downgrade reason or `null`

### `observer_diagnostic`

Observer diagnostic records describe observer health, loss, truncation, attach
failures, verifier failures, and run summaries.

Fields:

- `record_type`: always `observer_diagnostic`
- `timestamp_unix_ms`: diagnostic timestamp
- `session_id`: session identifier
- `kind`: `ring_buffer_reserve_failure`, `map_pressure`, `decode_failure`,
  `truncation`, `attach_failure`, `verifier_failure`, or `summary`
- `count`: diagnostic count
- `detail`: diagnostic detail string

### `visibility_assessment`

Visibility assessment records describe what host-side evidence can prove for a
runtime profile.

Fields:

- `record_type`: always `visibility_assessment`
- `session_id`: session identifier
- `runtime_profile`: `docker-default`, `docker-gvisor`,
  `kubernetes-gvisor`, `kubernetes-kata`, or `firecracker-prototype`
- `host_visibility_scope`: `guest_process`, `runtime_boundary`, or
  `boundary_only`
- `host_semantics_collapsed`: boolean
- `guest_collector_required`: boolean
- `runtime_metadata_required`: boolean
- `host_event_subjects`: array of observed host event subjects
- `pod_name`: Kubernetes pod name or `null`
- `namespace`: Kubernetes namespace or `null`
- `runtime_class_name`: RuntimeClass name or `null`
- `sandbox_name`: Agent Sandbox name or `null`
- `notes`: human-readable assessment notes

## Join Model

Use these fields for deterministic joins:

- `raw_kernel_event.event_id` is the raw event identifier.
- `event.raw_event_id` links a canonical event to the raw kernel event that
  produced it.
- `intent.raw_event_id` is `null` at ingestion time and may later link declared
  intent to an observed raw kernel event when a correlation pass has enough
  evidence.
- `intent_correlation.raw_event_id` links a declared intent to the canonical
  event and raw kernel event that proved the observed side effect.
- `accountability_finding.evidence_ref` links a mismatch finding to either an
  observed `raw_event_id` or an unmatched `intent_id`.
- `policy_violation.observed_event_id` links a policy decision to the observed
  raw event.
- `enforcement_metadata.observed_event_id` links enforcement metadata to the
  observed raw event.

Process context is a separate enrichment model. When available,
`process_command`, `process_executable`, and `process_started_at_unix_ms` attach
the latest successful exec context known for the PID at observation time. Intent
correlation treats `exec` records as matchable command evidence, but unmatched
`exec` records do not by themselves produce `missing_intent` findings; those
findings are reserved for observed file, network, credential, and similar side
effects.

## Redaction And Truncation

Persistence-time redaction applies before JSONL output:

- Secret-looking argv values are replaced with `<redacted>`.
- Credential-looking paths outside the allowed workspace may become
  `path_token:<digest>` values.
- Socket addresses may be tokenized while retaining non-sensitive routing
  detail such as port where needed.
- Raw payload redaction adds explicit markers, for example `redacted:payload`.
- Resource redaction adds `redacted:resource` to the raw payload when relevant.
- Bounded capture truncation is explicit through markers such as
  `argv_truncated:true`, `payload_truncated:true`, and
  `resource_truncated:true`.

## Local Output Rotation

Local output rotation is a storage budget, not a schema change. Operators can
bound local observer files with `--output-max-bytes <bytes>` and
`--output-max-files <n>` on `apolysis observe`. When the active JSONL file would
exceed `max_file_bytes`, Apolysis rotates `timeline.jsonl` to
`timeline.jsonl.1`, shifts older archives, and keeps at most
`max_archived_files` local archives. A single JSONL record is never split across
files; an oversized record is written as one line and the next append rotates.

When rotation is enabled, observer metadata includes
`resource:"observer-output-rotation"` with an action containing
`max_file_bytes:<bytes>,max_archived_files:<n>`.

## Minimal Consumer Queries

```bash
jq -c 'select(.record_type=="raw_kernel_event" and .event_id!=null)' timeline.jsonl

jq -c 'select(.record_type=="event" and .raw_event_id!=null) | {raw_event_id,event_type,pid,resource}' timeline.jsonl

jq -c 'select(.record_type=="event" and .process_command!=null) | {event_type,pid,process_command,process_executable,process_started_at_unix_ms,raw_event_id}' timeline.jsonl

jq -c 'select(.record_type=="intent") | {intent_source,intent_id,tool_name,declared_action,command,raw_event_id}' timeline.jsonl

jq -c 'select(.record_type=="intent_correlation") | {intent_source,intent_id,match_basis,raw_event_id,event_type,pid,resource}' intent-correlation.jsonl

jq -c 'select(.record_type=="accountability_finding") | {kind,decision,evidence_ref,reason}' intent-correlation.jsonl

jq -c 'select((.record_type=="policy_violation" or .record_type=="enforcement_metadata") and .observed_event_id!=null)' timeline.jsonl
```

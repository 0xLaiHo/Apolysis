# Apolysis JSONL Schema v1

Schema version: v1

This document is the stable consumer contract for Apolysis JSONL records emitted
by the CLI observer, runtime metadata adapters, accountability analyzer, and
visibility assessor. It covers append-only observation records intended for
operators, tests, and downstream log pipelines.

Release manifests and hash-chain package metadata are separate artifacts. They
may contain JSON, but they are not timeline JSONL records covered by this schema.

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
  event source, event type, or diagnostic kind.
- Consumers must not rely on object field ordering.
- Consumers that need exact joins should use `event_id`, `raw_event_id`, and
  `evidence_ref`, not timestamp-only matching.
- Backward-incompatible removal, renaming, type changes, or semantic changes
  require a new schema version.

## Record Types

### `collector_capability_manifest`

Collector capability manifests declare the observation boundary used for one
Agent Run. The live collector writes and synchronizes this record to stable
storage after successful attachment and before releasing a managed Agent.
Consumers must use it to distinguish supported observation semantics from
unsupported paths.

Fields:

- `record_type`: always `collector_capability_manifest`
- `schema_version`: capability manifest schema version, currently `1`
- `timestamp_unix_ms`: manifest persistence timestamp
- `agent_run_id`: Agent Run identifier
- `collector`: collector identifier, currently `apolysis_observer`
- `collector_version`: userspace collector package version
- `kernel_abi_version`: supported kernel/userspace event ABI version, currently
  `3`
- `kernel_record_size`: event record size for ABI v3, currently `656`
- `observation_scope`: `process_tree` or `cgroup`; the manifest does not persist
  the host PID or cgroup ID
- `privacy_profile`: persistence privacy profile, currently `content_off`
- `capabilities`: ordered operation declarations. Each entry contains an
  `operation`, the attached `event_sources` used to produce that observation,
  and supported `outcomes`. Outcome values are `attempted`, `succeeded`,
  `failed`, `denied`, `pending`, or `unknown`.

The current AuditObserver declaration includes only capabilities backed by its
actual attachment plan. Selected file operations declare `succeeded`,
`failed`, and `denied` only when their complete supported entry/exit hook set
is attached. Network connect declares those outcomes plus `pending` only when
both entry and exit hooks are attached. Exec declares `succeeded` only when
the observation-producing `sched/sched_process_exec` hook is attached.

### `event`

Canonical event records describe normalized runtime, metadata, process, file,
network, or credential activity.

Fields:

- `record_type`: always `event`
- `timestamp_unix_ms`: event timestamp
- `session_id`: session identifier
- `event_source`: `manual`, `process_tree`, `kernel_tracepoint`, `uprobe`, or
  `runtime_metadata`
- `event_type`: `session_started`, `runtime_metadata`, `exec`, `file_open`,
  `file_create`, `file_truncate`, `file_unlink`, `file_rename`,
  `network_connect`, `credential_read`, or `process_exit`
- `raw_event_id`: matching raw kernel `event_id`, or `null`
- `pid`: process ID
- `ppid`: parent process ID
- `actor`: process, observer, runtime, or integration actor
- `resource`: target resource, metadata resource, path token, executable, or
  socket token
- `action`: action or metadata value
- `outcome`: `attempted`, `succeeded`, `failed`, `denied`, `pending`,
  `unknown`, or `null` when the active capability does not supply an outcome
- `return_value`: signed Linux syscall return value, or `null`
- `errno`: positive Linux errno derived from a negative return value, or `null`
- `container_id`: container identifier or `null`
- `cgroup_id`: cgroup identifier or `null`
- `host_boot_id`: boot UUID captured once by the live userspace collector, or
  `null` for legacy/fixture sources
- `scope_generation`: observer-lifetime generation for one cgroup scope, or
  `null`
- `process_generation`: bounded collector-assigned process generation, or
  `null`
- `process_start_time_ns`: kernel process start time in boot-relative
  nanoseconds, or `null`
- `exec_generation`: process-local exec generation, or `null`
- `parent_process_generation`: parent process generation when known, or `null`
- `parent_exec_generation`: parent exec generation when known, or `null`
- `relation_status`: `exact`, `inferred`, `ambiguous`, or `unattributed`
- `relation_reason`: stable reason describing the attribution status
- `process_command`: legacy redacted command context, or `null`; current
  content-off observer producers emit `null`
- `process_executable`: allowlisted `executable_ref:<basename>` known for the
  PID, or `null`; paths and small-space executable hashes are not persisted
- `process_started_at_unix_ms`: legacy command-context start timestamp, or
  `null`; this is distinct from the boot-relative kernel
  `process_start_time_ns`

Runtime attribution is `exact` only when `host_boot_id`, `scope_generation`,
`process_generation`, `process_start_time_ns`, and `exec_generation` are
present. A fork identity without a confirmed process-start time remains
`inferred`. Missing generation data remains `inferred` with a reason; PID-only
matching is never exact. Scope generation prevents numeric cgroup-ID reuse from
crossing Agent Runs within one observer lifetime, but does not claim continuity
across collector restart.

Runtime metadata records are canonical `event` records with
`event_type:"runtime_metadata"`. Agent supervisor metadata uses resources such
as `agent-supervisor-mode`, `agent-kind`, `agent-root-pid`, `agent-command`,
`agent-executable`, `agent-workspace-root`, `agent-start-time`, and
`agent-exit-status`. The current writer records `agent-command` as a fixed
content-off marker and does not emit `agent-command-fingerprint`.

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
- `outcome`: supported operation outcome, or `null`
- `return_value`: signed Linux syscall return value, or `null`
- `errno`: positive Linux errno derived from a negative return value, or `null`
- `container_id`: container identifier or `null`
- `cgroup_id`: cgroup identifier or `null`
- `host_boot_id`: boot UUID attached by the live userspace collector, or `null`
- `scope_generation`: observer-lifetime cgroup-scope generation, or `null`
- `process_generation`: bounded collector-assigned process generation, or
  `null`
- `process_start_time_ns`: kernel process start time in boot-relative
  nanoseconds, or `null`
- `exec_generation`: process-local exec generation, or `null`
- `parent_process_generation`: parent process generation when known, or `null`
- `parent_exec_generation`: parent exec generation when known, or `null`
- `relation_status`: `exact`, `inferred`, `ambiguous`, or `unattributed`
- `relation_reason`: stable reason describing the attribution status
- `raw_payload`: bounded raw payload after persistence-time redaction

Persisted exec payloads never contain argv. They contain
`argv_redacted:true`, `redacted:payload`, and applicable truncation markers such
as `argv_truncated:true`, `payload_truncated:true`, and
`resource_truncated:true`.

For `network_connect`, return values greater than or equal to zero map to
`succeeded`; `EACCES` and `EPERM` map to `denied`; `EINPROGRESS` and `EALREADY`
map to `pending`; and other negative return values map to `failed`.

For `file_open`, `file_create`, `file_truncate`, `file_unlink`, and
`file_rename`, return values greater than or equal to zero map to `succeeded`;
`EACCES` and `EPERM` map to `denied`; and every other negative return value,
including `EINPROGRESS` and `EALREADY`, maps to `failed` because these supported
file syscalls are synchronous.

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
- `command`: content-off executable reference plus `argv_redacted:true`, or
  `null`
- `raw_event_id`: observed raw kernel event ID after correlation, or `null`

The first adapter is `codex-jsonl`. It consumes Codex JSONL `response_item`
function/tool-call records and writes `intent` records with source
`intent_source:"codex"`. Content-off persistence retains an executable
reference but omits the supplied command, arguments, and tool payload.

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
- `kind`: one of `missing_intent`, `unobserved_intent`, `undeclared_action`,
  `credential_read`, `workspace_boundary`, `unknown_egress`,
  `dangerous_command`, or `service_account_token_read`. The intent correlation
  command currently emits the first two; the shared accountability analyzer
  can emit the remaining kinds.
- `decision`: `notify` or `review`; intent correlation currently emits `review`
- `reason`: human-readable explanation
- `evidence_ref`: `raw_event_id` for observed side effects, or `intent_id` for
  declared intent without host evidence
- `runtime`: runtime metadata object when available
- `evidence_boundary`: `host_boundary` or `guest_semantic`; intent correlation
  currently emits `host_boundary`

### `observation_gap`

Observation Gap records explicitly report runtime observations that may be
missing or cannot be correlated. Consumers must include their counts when
deciding whether an Agent Run is complete.

Fields:

- `record_type`: always `observation_gap`
- `schema_version`: Observation Gap schema version, currently `1`
- `timestamp_unix_ms`: gap reporting timestamp
- `agent_run_id`: Agent Run identifier
- `operation`: affected operation: `network_connect`, `file_open`,
  `file_create`, `file_truncate`, `file_unlink`, or `file_rename`
- `kind`: `missing_entry` or `missing_exit`
- `count`: affected operation count
- `detail`: bounded diagnostic context. Missing-exit details distinguish
  kernel-reported losses from entries still pending when the collector stops.

The managed single-Agent-Run live observer persists these records directly.
The multi-cgroup daemon snapshots connect and file gap counters per cgroup and
first drains already-submitted ring records with confirmed writes. It then
persists gaps to only the owning Agent Run before explicit scope removal or
clean observer shutdown completes. Any queue drop or shedding fails the
observer runtime. Collector-global counters remain available for diagnostics
and are not reassigned to an Agent Run.

### `observer_diagnostic`

Observer diagnostic records describe observer health, loss, truncation, attach
failures, verifier failures, and run summaries.

Fields:

- `record_type`: always `observer_diagnostic`
- `timestamp_unix_ms`: diagnostic timestamp
- `session_id`: session identifier
- `kind`: `ring_buffer_reserve_failure`, `map_pressure`, `abi_mismatch`,
  `decode_failure`, `truncation`, `attach_failure`, `verifier_failure`, or
  `summary`
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

Process context is a separate enrichment model. Current observer producers keep
an allowlisted `process_executable` basename reference and
`process_started_at_unix_ms`, but set `process_command` to `null`. Intent
correlation can still use the normalized executable reference; unmatched
`exec` records do not by themselves produce `missing_intent` findings, which
remain reserved for observed file, network, credential, and similar side
effects.

## Redaction And Truncation

Persistence-time redaction applies before JSONL output:

- Exec argv is removed as a whole and replaced with `argv_redacted:true`.
- Credential-class paths may become
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

jq -c 'select(.record_type=="event" and .process_executable!=null) | {event_type,pid,process_executable,process_started_at_unix_ms,raw_event_id}' timeline.jsonl

jq -c 'select(.record_type=="intent") | {intent_source,intent_id,tool_name,declared_action,command,raw_event_id}' timeline.jsonl

jq -c 'select(.record_type=="intent_correlation") | {intent_source,intent_id,match_basis,raw_event_id,event_type,pid,resource}' intent-correlation.jsonl

jq -c 'select(.record_type=="accountability_finding") | {kind,decision,evidence_ref,reason}' intent-correlation.jsonl
```

Legacy `v0.3.0` research timelines may contain `session`, `policy_violation`,
or `enforcement_metadata` records. Active producers no longer emit them; v1
consumers should handle them as unknown historical record types.

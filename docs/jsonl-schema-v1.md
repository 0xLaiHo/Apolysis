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
- Optional base fields are emitted as `null`; optional extension fields may
  be omitted by older or inapplicable producers.
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
- `process_command`: legacy redacted command context, or `null`; current
  content-off observer producers emit `null`
- `process_executable`: allowlisted `executable_ref:<basename>` known for the
  PID, or `null`; paths and small-space executable hashes are not persisted
- `process_started_at_unix_ms`: command-context start timestamp, or `null`
- `intent_id`: valid 32-character lowercase hexadecimal marker from dedicated
  kernel attribution, or omitted when attribution is unavailable. A leading
  `# APOLYSIS_INTENT_ID=<id>` shell-command comment supplies the marker;
  in-scope fork/exec descendants can inherit it. Persistence still leaves
  `process_command` null.

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
- `container_id`: container identifier or `null`
- `cgroup_id`: cgroup identifier or `null`
- `raw_payload`: bounded raw payload after persistence-time redaction
- `intent_id`: optional dedicated marker, with the same validity rules as the
  canonical event field; this is not extracted from persisted argv
- `process_start_time_ns`: optional thread-group leader start time in boot-relative
  nanoseconds, used with PID to distinguish process generations
- `parent_start_time_ns`: optional parent thread-group leader start time in the same
  clock domain; these are not Unix timestamps

Persisted exec payloads never contain argv. They contain
`argv_redacted:true`, `redacted:payload`, and applicable truncation markers such
as `argv_truncated:true`, `payload_truncated:true`, and
`resource_truncated:true`.
`intent_capture_incomplete:true` reports uncertain marker capture. It is
retained after content-off redaction and also contributes to truncation
diagnostics; prior attribution is cleared rather than guessed at successful
exec.

### `intent`

Intent records preserve declared harness or tool-call intent as append-only
timeline records. They are optional: Apolysis can still record host-side
evidence without harness logs, but consumers need `intent` records when they
want to compare declared work with observed side effects.

Fields:

- `record_type`: always `intent`
- `timestamp_unix_ms`: intent ingestion timestamp
- `session_id`: session identifier
- `harness_session_id`: native product session identifier, or `null` for
  historical records whose native session is unavailable; `session_id` is the
  Apolysis capture-session identifier used for correlation
- `intent_source`: harness or adapter name, for example `codex`
- `intent_id`: stable intent identifier assigned by the adapter; live hooks use
  32 lowercase hexadecimal characters derived from SHA-256 over length-framed
  source, capture session, native session, and call ID; file adapters retain
  their historical source-prefixed identifiers
- `source_event_id`: source harness event ID or `null`
- `intent_type`: normalized intent category, for example `tool_call`
- `tool_name`: source tool/function name
- `declared_action`: normalized action class such as `shell.command`, or
  `null`
- `target`: declared target scope, resource class, or `null`
- `command`: content-off executable reference plus `argv_redacted:true`, or
  `null`
- `raw_event_id`: observed raw kernel event ID after correlation, or `null`
- `observation_mode`: `local_shell`, `semantic_only`, or `historical`; older
  records may omit the field. This declares the available observation path,
  not successful execution or actual observer coverage.

Adapters are `codex-jsonl`, `claude-jsonl`, `cursor-jsonl`, `pi-jsonl`, and
`opencode-jsonl`. They write `intent` records with `intent_source` `codex`,
`claude`, `cursor`, `pi`, or `opencode`. Content-off persistence retains an
executable reference but omits prompts, tool results, raw argv, and secrets.
Live hook writes use locked append and deduplicate repeated calls. A shell
rewrite adds `# APOLYSIS_INTENT_ID=<id>` as the first comment line, followed by
the original command body. It does not interpolate the native call ID into
shell syntax. `--session` selects a capture session separately from the native
session. A product-specific file name does not itself isolate sessions.

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

Current intent correlation records establish an Exact Relation through a
unique explicit identifier inside one capture session. This is a relation
within the local integration's trust boundary, not causal or authorization
proof. Declarations whose complete persisted JSON objects are identical apart
from ingestion timestamp are deduplicated before matching; differences in
retained action, target, native session, or future fields remain conflicts.
`semantic_only` declarations cannot establish execution matches, but remain
visible during identifier conflict detection.

When an event has `intent_id`, that ID must resolve uniquely. If an explicit
`raw_event_id` link also exists, both links must identify the same declaration;
the recorded basis is then `raw_event_id`. Unknown, conflicting, or ambiguous
IDs produce a diagnostic and never fall back to command or executable text.
Without `intent_id`, a unique `raw_event_id` link can establish the relation.
If neither explicit link is available, text/name matches become candidates
as described below. One declaration may relate to many observed attempts.

Fields:

- `record_type`: always `intent_correlation`
- `timestamp_unix_ms`: correlation timestamp
- `session_id`: session identifier
- `intent_source`: harness or adapter name, for example `codex`
- `intent_id`: declared intent identifier
- `tool_name`: source tool or function name
- `match_basis`: current writers use `raw_event_id` or `intent_id`; historical
  records with `process_command_exact` or `process_executable` remain readable
  but are heuristic evidence, not newly established Exact Relations
- `relation_status`: `exact` for current records; absent in historical records
- `raw_event_id`: observed raw kernel event ID linked to the canonical event
- `event_type`: observed canonical event type
- `pid`: process ID on the observed event, or `0` if unavailable
- `resource`: observed resource string
- `process_command`: redacted observed command context, or `null`
- `process_executable`: observed executable path, or `null`
- `command`: redacted declared command or tool payload summary, or `null`

### `intent_correlation_candidate`

Candidate records keep possible Inferred or Ambiguous Relations visible
without marking a declaration as matched. Their fields are the same as
`intent_correlation`, with these differences:

- `record_type`: always `intent_correlation_candidate`
- `match_basis`: `process_command_exact`, or `process_executable` for `exec`
  events only
- `relation_status`: `inferred` when one candidate remains, or `ambiguous`
  when several remain
- `candidate_count`: number of candidates under this basis for this event

Legacy redacted command equality is considered before executable-name
comparison. Every candidate is emitted; the first record is never chosen as a
winner. Even one candidate does not satisfy an Exact Relation or suppress a
`missing_intent`/`unobserved_intent` Finding. Current content-off observer
records have no `process_command`, so command equality is primarily a legacy
input path. Candidate matching is only attempted when no explicit identifier
is unresolved, conflicting, or ambiguous.

### `intent_correlation_diagnostic`

These records expose failed explicit-identifier resolution:

- `record_type`: always `intent_correlation_diagnostic`
- `session_id`: capture-session identifier
- `raw_event_id`: observed event reference
- `intent_id`: observed marker, or `null`
- `reason`: `unrecognized_intent_id`, `conflicting_identifiers`,
  `ambiguous_intent_id`, `ambiguous_raw_event_id`, or
  `semantic_only_runtime_event` when a runtime link points at a semantic-only
  declaration

A diagnostic does not turn an event into a match. The applicable accountability
Finding is still emitted.

Deduplication compares persisted metadata, not original command contents.
Commands that differ only in discarded arguments cannot be distinguished if
a producer reuses the same call identity. No raw-command fingerprint is added
to bypass the content-off boundary.

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
`semantic_only` declarations do not produce `unobserved_intent`: no local
execution evidence was promised. `historical` and legacy declarations can
still produce it. A missing relation describes an evidence gap, not proof of
malice, failed execution, or an independently verified unauthorized action.
Unmatched file mutations, network-connect attempts, and credential-path
accesses produce `missing_intent`; ordinary file-open and exec events alone
do not, to avoid treating routine process initialization as a Finding.

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
- `event.intent_id`, when present, must resolve uniquely to `intent.intent_id`
  in the same capture session and agree with any explicit raw-event link.
- `intent_correlation.raw_event_id` links a declared intent to the canonical
  event and raw kernel event that reported the observed attempt.
- `accountability_finding.evidence_ref` links a mismatch finding to either an
  observed `raw_event_id` or an unmatched `intent_id`.
- `policy_violation.observed_event_id` links a policy decision to the observed
  raw event.
- `enforcement_metadata.observed_event_id` links enforcement metadata to the
  observed raw event.

Process context is a separate enrichment model. Current observer producers keep
an allowlisted `process_executable` basename reference and
`process_started_at_unix_ms`, but set `process_command` to `null`. Intent
candidate matching can still use the normalized executable reference; unmatched
`exec` records do not by themselves produce `missing_intent` findings, which
remain reserved for observed file, network, credential, and similar side
effects. These weak candidates do not count as identifier matches.

The live collector reads the complete marker header directly from the command
argument of a recognized shell invocation. It does not scan arbitrary argv
tokens or rely on the bounded diagnostic argv payload. Kernel process context
is keyed by TGID and checked against thread-group leader start time, propagates at
fork, survives same-process exec when complete capture establishes no new
marker, and accepts a valid newer marker on exec. Missing pending capture,
unreadable or malformed headers, and unresolved shell-command slots clear old
attribution and report `intent_capture_incomplete:true`. In-scope events carry
that context independently of userspace
event ordering. Userspace does not restore a missing live marker from an old
cached process context. Missing visibility remains unattributed.

The updated kernel/userspace event ABI is 648 bytes; use an eBPF object and CLI
built together. This is not a promise of compatibility with old release BPF
objects. Optional JSONL fields preserve readability of historical timelines.

## Redaction And Truncation

Persistence-time redaction applies before JSONL output:

- Exec argv is removed as a whole and replaced with `argv_redacted:true`.
- Credential-looking paths outside the allowed workspace may become
  `path_token:<digest>` values.
- Socket addresses may be tokenized while retaining non-sensitive routing
  detail such as port where needed.
- Raw payload redaction adds explicit markers, for example `redacted:payload`.
- Resource redaction adds `redacted:resource` to the raw payload when relevant.
- Bounded capture truncation is explicit through markers such as
  `argv_truncated:true`, `payload_truncated:true`, and
  `resource_truncated:true`.
- Uncertain intent capture retains `intent_capture_incomplete:true`, clears
  prior intent attribution on exec, and contributes to the truncation warning.

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

jq -c 'select(.record_type=="intent_correlation_candidate") | {intent_id,match_basis,relation_status,candidate_count,raw_event_id}' intent-correlation.jsonl

jq -c 'select(.record_type=="intent_correlation_diagnostic")' intent-correlation.jsonl

jq -c 'select(.record_type=="accountability_finding") | {kind,decision,evidence_ref,reason}' intent-correlation.jsonl

jq -c 'select((.record_type=="policy_violation" or .record_type=="enforcement_metadata") and .observed_event_id!=null)' timeline.jsonl
```

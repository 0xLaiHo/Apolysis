# Agent Observation Record v1

> English | [Simplified Chinese](agent-observation-record-v1.zh-CN.md)

An Agent Observation Record is the deterministic, queryable projection of one
saved Agent Run. It is one JSON object, not a timeline JSONL record, and must
not be appended back into the source timeline.

## Command

```bash
apolysis run project \
  --input <timeline.jsonl> [--input <additional.jsonl> ...] \
  --output <agent-observation-record.json>
```

Inputs are consumed in command-line order. Within a plain rotated input,
source order is the oldest contiguous `.N` archive through `.1`, followed by
the active file. Hash-chain input is fully verified before its payloads are
exposed and cannot use a rotation set. Timestamps do not reorder source
records.

## Top-level object

| Field | Type | Meaning |
| --- | --- | --- |
| `record_type` | string | Always `agent_observation_record` |
| `schema_version` | integer | Always `1` |
| `agent_run_id` | string | The single Agent Run shared by every input record |
| `source_integrity` | enum | `unverified_plain_jsonl`, `verified_hash_chain`, or `mixed` |
| `summary` | object | Independent evidence, health, review, count, and grouping fields |
| `capability_manifests` | array | Validated content-off Collector Capability source records |
| `runtime_identities` | array | Exact Runtime Identity aggregates |
| `runtime_observations` | array | Canonical supported or explicitly limited observations |
| `collector_lifecycle` | array | Ordered start/checkpoint/terminal source records |
| `findings` | array | Typed review-oriented findings |
| `observation_gaps` | array | Typed, bounded gaps and collection boundaries |
| `issues` | array | Typed projection limitations with source ordinals and counts |

Every projected source fact carries `source_ordinal`. It is assigned from the
authoritative input order beginning at one. It is not a timestamp sort key.

## Summary

`summary` contains:

- `evidence_state`: `complete`, `active`, `incomplete`, `failed`, or
  `indeterminate`;
- `collector_health`: `healthy`, `degraded`, `failed`, or `unknown`;
- `review_state`: `requires_review`, `no_findings_reported`, or
  `indeterminate`;
- `runtime_observation_count`, `runtime_identity_count`, `finding_count`, and
  `observation_gap_record_count`;
- `known_missing_observation_count` for counted `missing_entry` and
  `missing_exit` records;
- `unknown_history_boundary_count` for `late_attach`; its `count:1` is one
  boundary, not an estimate of missing events;
- deterministic `event_type_counts`, `outcome_counts`, `relation_counts`,
  `finding_kind_counts`, and `gap_kind_counts` maps.

The three state fields are independent. A Finding makes review required but
does not make otherwise complete evidence incomplete. `no_findings_reported`
is available only for complete, non-empty evidence and is not a clean verdict.
An active or failed lifecycle remains visible even when other issues exist.

Complete evidence requires one compatible content-off capability manifest, a
legal lifecycle with a normal terminal, at least one supported Runtime
Observation, and no loss, gap, diagnostic, integrity, or capability issue.
For v1, compatible means the complete current `apolysis_observer`
operation/source/outcome contract; a missing operation or mismatched source or
outcome set produces `unsupported_capability`. A Finding whose `evidence_ref`
does not resolve to a projected canonical observation produces
`unresolved_finding_evidence`.
Missing lifecycle, unsupported or missing outcomes, collector loss, gaps,
integrity findings, and non-zero failure diagnostics cannot be complete. Mixed
integrity and unknown additive records make an otherwise complete-shaped run
indeterminate.

## Identity and privacy

An exact identity is keyed within one collector instance by host boot ID,
scope generation, PID, process generation, kernel process-start time, and exec
generation. Identical exact tuples are folded into the stable first-seen IDs
`identity-1`, `identity-2`, and so on. Inferred, ambiguous, and unattributed
observations are never upgraded or merged into an exact identity.
Exact projection additionally requires `event_source:kernel_tracepoint`, a
non-empty canonical `raw_event_id`, and relation reason
`host_boot_scope_process_start_exec_generation`. Unsupported or heuristic
relations cannot create an exact identity.

The projection accepts only a `content_off` capability manifest and rejects a
non-null legacy `process_command`. Finding kinds, decisions, and evidence
boundaries are typed. Finding reasons and ordinary Gap details are derived
from bounded vocabulary instead of copying free-form source text. Unknown and
integrity record payloads are not copied into the projection or its errors.

## Failure boundary

The projector fails closed for an empty record set, mixed Agent Runs,
malformed or incompatible records, invalid lifecycle order, a broken
late-attach durable boundary, duplicate canonical `raw_event_id`, conflicting
exact identity, content-policy violations, or an exceeded input limit. It does
not return a partial aggregate for these structural failures.

The local reader additionally rejects symlinks, non-regular files,
non-contiguous archives, source churn, truncated tails, malformed JSON, mixed
envelope formats, and hash-chain corruption. Errors identify only bounded
locations or categories; they do not include paths, record payloads, or
conflicting run IDs.

## Limits and publication

- 128 MiB total saved-run input across all `--input` values;
- 1 MiB per JSONL line;
- 1,000,000 source records;
- at most 1,024 numeric rotation archives;
- at most 1,024 projection input batches;
- at most 4,096 bytes per string, 1,024 items per array, 256 fields per object,
  and 16 nested value levels at the projection boundary.

The CLI serializes one deterministic pretty-JSON object plus a trailing
newline. It writes an exclusive mode-`0600` temporary file in the output
directory, synchronizes it, atomically renames it, synchronizes the parent, and
refuses any output path or inode that aliases an active or rotated input.

## Minimal queries

```bash
jq '.summary' agent-observation-record.json
jq '.runtime_identities[]' agent-observation-record.json
jq '.runtime_observations[] | {source_ordinal,event_type,outcome,relation_status}' agent-observation-record.json
jq '.observation_gaps[], .issues[]' agent-observation-record.json
jq '.findings[] | {kind,decision,evidence_ref}' agent-observation-record.json
```

## Saved Run Viewer consumer

The completed L3 Saved Run Viewer consumes exactly one record through:

```bash
apolysis run view \
  --input <agent-observation-record.json> \
  --output <saved-run-view.html>
```

It validates v1 consistency, preserves Evidence State, Collector Health, and
Review State as independent axes, follows `source_ordinal` as authoritative
order, and resolves Finding links to supporting Runtime Observations. It does
not reinterpret incomplete, active, failed, mixed-integrity, or gap-bearing
records as clean or complete.

Version 1 retains an Exact Runtime Identity roster and reported PID/PPID fields
but no authoritative parent Runtime Identity link. The viewer therefore shows
those facts without constructing or implying a canonical process tree. Live
tailing, cross-run search, remote query, and a central evidence plane remain
outside this schema.

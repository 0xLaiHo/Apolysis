# Apolysis design

[English](design.md) | [简体中文](design.zh-CN.md)

This is the canonical design overview for this source tree. The
[domain glossary](../CONTEXT.md) defines the product's terms. The
[roadmap](roadmap.md) owns direction and qualification boundaries; implementation
history belongs in Git.

## Evidence boundaries

Apolysis currently provides experimental local Linux audit telemetry and
accountability. The CLI and daemon collect scoped Execution Evidence, combine
it with runtime metadata and declared Tool Calls, and produce content-off
JSONL records and Findings. File and network tracepoints in this implementation
describe attempts unless a separate outcome is available. An observed call
does not establish a Verified Outcome.

Semantic Evidence says what a tool runner declared. Execution Evidence says
what a controlled runtime boundary observed. Outcome Evidence independently
checks a claimed external result. These boundaries remain distinct: no match,
hash chain, or lack of Findings establishes complete coverage or isolation.

The branch also contains the independent production record/Gateway contract
and storage/transport foundations described in the [contract set](contracts/README.md).
Per [ADR-0001](adr/0001-independent-production-contracts.md), legacy JSONL v1
is an edge format, not the authenticated Gateway or Query contract. Existing
Gateway, evidence-object, projection, and transport limitations remain those
of their normative contracts; the local harness adapter does not qualify them.

## Harness declarations

File ingestion accepts Codex, Claude Code, Cursor, Pi, and OpenCode exports.
Live product hooks normalize a Tool Call into the same `intent` record. Native
hook interfaces remain product-specific; supported input and installation are
documented in [harness integration](harness-intent.md).

The record keeps Apolysis `session_id` separate from `harness_session_id`.
An explicit capture-session override must agree with the observer. Live IDs
are deterministic 32-character lowercase hexadecimal SHA-256-derived values
over length-framed source, capture session, native session, and call ID.
Historical import identifiers stay compatible. The live writer uses locked
append and deduplicates retries, so one call cannot erase earlier declarations.
Deduplication compares the entire persisted record except ingestion time, not
discarded argument content. Reused call IDs with differences confined to
discarded arguments are not distinguishable; no command fingerprint is kept.

Shell rewrites insert a leading `# APOLYSIS_INTENT_ID=<id>` comment followed
by the original command body. Remaining tool-input fields are preserved.
Claude Code keeps its native permission decision; Codex receives the required
`allow` acknowledgement only with a supported shell rewrite. Cursor's
supplementary shell event can reuse an existing
marker; a missing call ID does not justify synthesizing a shared placeholder.
Pi reads its native session from extension context. OpenCode reads the native
session and call ID from its tool-execution event.

`observation_mode` distinguishes a prepared `local_shell` path from
`semantic_only` declarations and `historical` imports. A prepared marker does
not establish that the command ran, the product honored the rewrite, or the
observer captured it.

## Process attribution and relations

The live collector reads a complete leading comment from a recognized shell's
command argument into a dedicated 32-byte field. It does not search arbitrary
argv tokens or depend on the truncated diagnostic command payload. Recognition
is bounded to supported shell invocation forms; missing markers remain missing.

Kernel context uses TGID with thread-group leader start time to reject reused process
identity and propagates at fork even when the child does not exec. Same-process
exec retains the token only when complete capture establishes that there is no
new marker; a valid new marker replaces it. Missing pending capture, unreadable
or malformed headers, or an unresolved shell command slot clear the previous
token and report `intent_capture_incomplete:true` with the existing truncation
warning. Context is removed when the last thread exits. Each in-scope event carries
the kernel's current attribution, including its absence; userspace does not
reconstruct a missing live marker from a stale cache. This reduces dependence
on lifecycle delivery order, but does not recover lost events, unobserved
lineage, or unsupported execution backends.

Correlation remains a separate pass within one capture session. Unique
explicit `intent_id` or `raw_event_id` links establish Exact Relations within
the declared trust boundary. If both exist they must agree. Unknown,
conflicting, or ambiguous identifiers produce a diagnostic and cannot fall
back to a weaker match. A declaration can relate to multiple attempts.

Legacy command equality and exec-only executable-name matching produce
candidate records: one candidate is an Inferred Relation, several are
Ambiguous Relations. Neither counts as an Exact Relation nor suppresses a
Finding. `semantic_only` declarations are excluded from execution matching and
`unobserved_intent`. Historical imports stay readable and can use explicit
links, but a weak candidate alone does not make them matched.

## Privacy and trust

Intent persistence retains fixed-width transport IDs, native source
identifiers, tool metadata, and an allowlisted executable reference. Native
identifiers are not subject to the transport ID's 32-character limit.
Prompts, results, original arguments, raw
argv, and reconstructed process-command text are not persisted. The command
is transiently available to the hook because the product must execute it.
The [JSONL contract](jsonl-schema-v1.md) describes persistence fields.

A marker is a relation key within a cooperative local integration. It is not
a signature, authorization token, or defense against a workload that controls
its own command text. Local JSONL and daemon-local hash chains do not provide
independent evidence anchoring. Remote tools and provider-hosted search need
their own Evidence Sources; a local observer cannot establish their outcomes.

## Verification scope

Fixture tests can validate hook contracts, append/deduplication, marker
syntax, and content-off persistence. Product-version compatibility, actual
marker delivery, process-tree propagation, and kernel event coverage require
separate integration evidence beyond fixtures. The kernel/userspace event
ABI is 648 bytes and requires a CLI and BPF object from the same build;
historical JSONL readability does not imply old BPF-object compatibility.
Privileged live validation remains explicit;
unrun or skipped live tests must not be presented as successful qualification.

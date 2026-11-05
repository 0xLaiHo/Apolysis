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

Default shell rewrites insert a leading `# APOLYSIS_INTENT_ID=<id>` comment followed
by the original command body. Remaining tool-input fields are preserved.
Claude Code keeps its native permission decision; Codex receives the required
`allow` acknowledgement only with a supported shell rewrite. Cursor's
supplementary shell event can reuse an existing
marker; a missing call ID does not justify synthesizing a shared placeholder.
Pi reads its native session from extension context. OpenCode reads the native
session and call ID from its tool-execution event.

A product can subsequently embed that updated command in an `eval` or other
shell wrapper. The default comment then need not start an actual exec argument.
The native Claude Code 2.1.295 run exposed this boundary: its declaration and
reason were recorded, while the fixture file attempt had no kernel marker.
The collector deliberately does not scan embedded comments to repair this.

Explicit `--shell-bridge /bin/bash` instead executes the unchanged command body
inside a selected supported shell whose command argument starts with the strict
intent header. It does not replace the product's outer shell with `exec`.
Output and exit status follow the inner command, but changes to cwd,
environment, and functions do not propagate back to the outer shell. It is
disabled by default and cannot be presented as transparent native shell
semantics. The Pi/OpenCode equivalent is `APOLYSIS_SHELL_BRIDGE`; the selected
shell must agree with an explicit tool-input shell. Qualification must identify
whether it tested this mode or the default comment mode.

`observation_mode` distinguishes a prepared `local_shell` path from
`semantic_only` declarations and `historical` imports. A prepared marker does
not establish that the command ran, the product honored the rewrite, or the
observer captured it.

## Declared reasons

An optional `intent_reason` record describes the producer's stated purpose for
one Tool Call. It is independent of `intent`, keyed to the same capture session
and intent ID, with native source identity retained for validation. It does not
expose hidden model reasoning, verify a motive, authorize an operation, or
create Execution Evidence. Intent ID derivation and kernel marker transport
are unchanged.

Explicit declarations use a closed reason code. A controlled extension can
provide a top-level `apolysis_reason` object; builtin shell tools can instead
carry a leading `# APOLYSIS_REASON_CODE=<code>` comment in their existing
command string. The hook still places the intent marker first. Native tool
descriptions remain `tool_description` with code `unknown`: their wording is
not used to infer why the Agent acted. `operator_annotation` is reserved in
the schema; the CLI does not currently produce that source.

A separate live validation uses a test-only `APOLYSIS_REASON_JSON` protocol in
Claude's native `Bash.description`. The model selects the code and writes the
summary; a strict adapter passes those fields unchanged into `apolysis_reason`
while preserving the native session and call ID. With summary retention and
the `/bin/bash` bridge explicitly enabled, the login regression ran and its
file attempt received the same declared summary through an exact intent-ID
relation. This validates the controlled protocol and existing execution path,
not automatic interpretation of ordinary descriptions or a default native
reason capability across the five products. The gate adds no production
reason-extraction logic; default summaries remain absent.

The experimental Rust [`apolysis chat`](reason-chat.md) command applies that
explicit protocol to user-entered tasks in a separate workspace, without a
Python runtime. One Claude process
accepts successive stream-JSON user turns with session persistence disabled;
only Bash is available. Each real call passes through the existing hook with
summary retention and the `/bin/bash` bridge enabled. A conversation-only turn
creates no intent. The runner displays assistant text and per-call exact
relation counts, then preserves task files and content-off observation records.
Prompts, full tool inputs, and raw provider streams are not written to logs;
declared summaries and observed paths are retained data. A privacy-filtered
`[redacted]` summary does not invalidate an otherwise valid reason code or
intent-ID relation. This is an observation experiment: the host is mounted
read-only, but the control, workspace, and evidence directories are writable.
It provides neither a hostile-agent boundary nor tamper-resistant evidence,
and does not change global settings.

The root controller supervises a separate root observer and retains the
capture source in a root-only temporary directory. Authentication is read
only by an unprivileged Rust launch helper before it executes Bubblewrap.
Snapshots and final results are atomically published by fresh helpers running
as the invoking user, so root does not reopen agent-controlled evidence paths
for publication. The `hook`, `launch`, and `publish` subcommands are internal
helpers, not the daily interface. The independent Python live-validation
gates remain test tooling; the conversation path does not call them.

Reason records append independently, deduplicate retries, and diagnose
conflicting identities. A correction uses a new reason ID and
`supersedes_reason_id` pointing to an existing reason for that same call;
it does not overwrite history. Correlation emits separate `intent_reason_binding`
records and enriches an Exact Relation only when one valid reason remains.
Conflicts and unbound reasons cannot create runtime links or promote a weak
candidate. A `semantic_only` reason can bind its declaration without an
execution relation.

The default record retains codes and optional opaque references, not reason
prose. `--allow-reason-summary` explicitly permits a best-effort-redacted
summary of at most 240 Unicode characters; it is not a guarantee that arbitrary
text is free of secrets. `task_ref` is an opaque reference of 1–64 ASCII
letters, digits, underscores, or hyphens, not task content or a file to open. No prompt file is read to
construct a reason. See [harness integration](harness-intent.md) and the
[JSONL contract](jsonl-schema-v1.md) for inputs and fields.

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
The opt-in `make test-bpf-relocation` gate checks every built observer program's
CO-RE relocations against readable host BTF without loading a BPF program.
Native regression tests exercise the shared C marker parser and bounded shell
basename checks. These checks do not substitute for kernel verifier acceptance
and live event assertions.

A bounded synthetic marker gate and the general live observer regression have
passed on one local kernel; [validation details](harness-intent-live-validation.md)
record the environment, assertions, diagnostics, and limits. Product-native
qualification is limited to the tested mode: native Claude Code 2.1.295,
Pi 1.5.0, and OpenCode 1.18.31 have passed a single synthetic command with the
explicit `/bin/bash` bridge, connecting its declared reason to an exact
fixture-file attempt and keeping its prompt-only sentinel out of persisted
records. Codex is blocked by provider-network connectivity in the validation
environment despite valid authentication; Cursor is blocked by expired access
and refresh credentials. Neither blocked run is a pass or a claim that the
product itself is unsupported. Default comment delivery,
broader product versions, other kernels, and stress/loss qualification remain open.
Privileged validation stays explicit, and prerequisite skips never count as
successful live qualification.

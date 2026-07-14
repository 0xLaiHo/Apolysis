# Execution Evidence Gateway Lifecycle v0.1

Status: normative W1–W2 target contract. An application core, non-durable
reference adapter, and initial PostgreSQL write-adapter prototype are
implemented on the `pre-release` development line; the production Execution
Evidence Gateway is not.

## Boundary

The Gateway is an authenticated write plane for Agent Execution Record source
envelopes. It is not the browser Query API, a public event bucket, an agent
orchestrator, or a general tool proxy. Privileged collectors never serve a
browser endpoint.

The canonical operations are `open_run`, `bind_runtime`, `ingest`, and
`finish_run`. Their machine types belong to the independent contracts boundary;
legacy JSONL v1 is an edge adapter input, not a Gateway schema.

## Current implementation status

The Gateway foundation slice currently implements:

- an application service for all four canonical operations, with an
  authenticated context injected by its caller;
- organization, source-registration, source-policy, and scoped hashed-lease
  authorization checks;
- server-side join grants and registration policies rather than trusting a
  client-supplied join assertion;
- immutable run-policy and source-registration facts, with trust and policy
  revision frozen for each server-assigned stream;
- RFC 8785 canonical request, inline-payload, and source-manifest digests, with
  committed golden vectors for requests and inline payloads;
- an in-memory reference adapter that commits record append, deduplication,
  ingest sequence, and projection-outbox intent atomically, including batches
  containing exact duplicates and novel envelopes;
- a migration-managed PostgreSQL adapter for the same atomic-command seam,
  with normalized ledger/outbox state, hashed lease and join references,
  encrypted exact-operation replay, and bounded retry for serialization or
  deadlock failures;
- a run-wide admission cap of 256 source streams plus bounded,
  transaction-local PostgreSQL lock and statement deadlines; and
- bounded finishing declarations and deadlines, sealing a reconciled run as
  `finished`, and lazy command-boundary reconciliation that seals an active or
  finishing run after its last lease or finalization deadline expires.

The 28 shared repository scenarios run against both adapters, including the
256-stream admission boundary and atomic rejection of the 257th stream. The
explicit real-PostgreSQL gate also has eleven targeted tests for repository/pool
reconstruction, post-commit/pre-ack retry, two identical-operation concurrent
tasks, distinct operation IDs racing on one client run key, plaintext lease
absence, and contiguous organization sequence with one outbox row per ledger
record, plus replay expiry that remains a durable idempotency tombstone after
reconstruction. The concurrency checks use independent repositories and
connection pools. The distinct-operation race produces one deterministic
winner and one idempotency conflict. State inspection for conformance is test-only; the
PostgreSQL repository exposes no public snapshot/read API. The added
range-reservation cases prove one sequence-row update for a maximum novel
batch, zero allocation for exact replay or all-duplicate input, novel-only
allocation for mixed input, disjoint concurrent ranges, and rollback without a
ledger hole after a real database rejection.

A separate real recovery gate drives the production PostgreSQL repository
through the application core with `SystemClock`, `OsRandomIdGenerator`, and
runtime-generated operations. Against a pinned PostgreSQL 16 persistent volume
with data checksums, `fsync`, synchronous commit, and full-page writes enabled,
it proves exact replay after graceful database restart and PostgreSQL `SIGKILL`
with WAL redo. Deterministic application-process `SIGKILL` before commit proves
complete rollback followed by one novel retry; `SIGKILL` after the atomic
commit while a distinct client-acknowledgement file remains absent proves one
exact replay, then kills that retry at the same pre-ack boundary before a third
process converges. The gate also runs
catalog-discovered plaintext scanning, `pg_amcheck`, `pg_dump`, generated-secret
scans, private-file checks, and dedicated-resource cleanup. It exercises an
application/repository process seam, not recovery of an HTTPS Gateway server.

Current PostgreSQL gap discovery evaluates a window over the full persisted
history for one source stream; its SQL limit bounds returned gaps rather than
scan work. Novel envelopes reserve one contiguous organization sequence range
with one row update, but record, outbox, and evidence inserts remain row-wise
while organization sequencing is held. Incremental watermark/gap state, bulk
insertion, and load/capacity qualification are required before the W3–W6
storage exit gate.

The slice is a conformance foundation, not a production service, and does not
complete W3–W6. In particular, it has:

- no HTTPS Gateway-server crash recovery, complete multiprocess/lifecycle race
  matrix, sustained or capacity load, replication/failover, backup/restore, or
  high-availability qualification; the narrower graceful PostgreSQL restart,
  PostgreSQL SIGKILL/WAL redo, and application-process pre-commit,
  post-commit/pre-ack, and replay/pre-ack crash slice is covered by the explicit
  recovery gate, while HTTPS trace and error-body secret handling remains part
  of the server gate;
- no production KMS/envelope-data-key integration, database role model, or RLS
  deployment; the built-in AES-256-GCM protector is a direct-key in-process
  keyring;
- no HTTP or gRPC transport, transport-level mTLS/JWT verification, or live
  credential-revocation integration;
- no object-store resolver for referenced payloads;
- no background deadline or encrypted-replay cleanup reaper—run expiration is
  reconciled only when a later novel lifecycle command reaches the application
  core, while an expired replay is rejected but not deleted;
- no production rate, batch-byte, request-byte, or organization limit
  enforcement beyond the run-wide stream cap; and
- no durable projectors, Query service, or Web Console.

The following sections remain the normative production behavior even where the
reference adapter cannot yet demonstrate the associated durability or
availability claim.

## Authentication and authority

The transport injects an authenticated source principal from a registered
workload identity, mTLS identity, or comparably bound credential. The Gateway
derives the organization, permitted source roles, operations, and environment
profiles from that principal.

A request-supplied `organization_id`, `tenant_id`, run identifier, source name,
or provider identity is an assertion to validate, never authority. A mismatch
is rejected before idempotency or existence information is disclosed.

Every accepted `open_run` requires:

- a registered source principal bound to one organization;
- operation permission and a compatible `SourceManifest`;
- a client operation identifier and canonical request digest for idempotency.

`open_run` creates a lease. Every accepted `bind_runtime`, `ingest`, or
`finish_run` also requires an unexpired lease scoped to organization, run,
source registration, source stream, and allowed operations.

Credentials for Gateway writes cannot authorize Query API, Console, object, or
export reads.

## `open_run`

`open_run` has two explicit modes. Implementations must not overload “open” to
silently create a duplicate run when a source intended to join.

### Create mode

Create mode establishes a new Agent Run. The authorized initiating source
provides a client run key, environment profile, authority/principal references,
privacy and retention profiles, expected source roles, and its `SourceManifest`.
The Gateway assigns the canonical `run_id`, source registration binding, source
stream, and initial lease.

Repeating create mode with the same principal, client operation identifier, and
canonical digest returns the same run and lease outcome. Reusing the identifier
with different content is an idempotency conflict. A client run key collision
never causes an implicit join.

### Join mode

Join mode lets an additional semantic, eBPF Runtime Witness, provider, or
outcome-verifier source contribute to an existing run. It requires the target
`run_id`, the joining source's `SourceManifest`, and a time-bounded join grant
or registration policy scoped to that organization, run, and source role.

The Gateway checks both the transport principal and join authorization. It
creates a distinct source stream and lease; it does not share the initiating
source's credentials, sequence space, or trust profile. Join mode cannot change
the run's authority, organization, privacy ceiling, or retention ceiling.
When a required source joins a run that is already `finishing`, its lease is
bounded by the run's immutable finalization deadline. At or after that deadline
the Gateway rejects novel joins while preserving an already committed exact
operation replay.

The response to either mode identifies whether the run was `created`, `joined`,
or returned from an idempotent retry. It never reveals a cross-organization run.

## `bind_runtime`

`bind_runtime` attaches a versioned `RuntimeBinding` to the run, for example a
process scope, cgroup, container, Pod, VM, runner, or provider workload. The
binding records the asserting source, runtime identity type and value, validity
window, evidence basis, and relation representation.

- An explicitly propagated, independently validated runtime identifier may be
  `exact` within its trust boundary.
- PID, time, working-directory, argument, or name matching remains `inferred`
  or `ambiguous` and records typed reasons, bounded confidence, evidence basis,
  and every scored alternative rather than only a selected best match.
- A conflicting exclusive runtime identity is rejected or represented as an
  explicit conflict; it is never silently reassigned between active runs.
- Repeating the same binding identifier and digest is idempotent. Reusing it
  with different content is a conflict.
- Binding authorization cannot broaden the source's registered capability or
  the run's privacy policy.

## `ingest`

`ingest` accepts a bounded batch of versioned `SourceEnvelope` values from the
lease's source stream. The Gateway validates the entire batch's authentication,
scope, schema, capability, privacy classification, size, and integrity before
committing any novel envelope. A validation failure does not partially commit
the batch. Exact duplicates may be acknowledged alongside newly committed
envelopes. Repeated instances of the same exact source event within one batch
are coalesced to one acknowledgement; reusing that event identity with a
different sequence or envelope content rejects the whole batch as
`source_event_conflict` without consuming the operation identity.

For each novel accepted envelope, the Gateway atomically persists the envelope,
deduplication digest, server ingest sequence, and projection-outbox intent. A
successful acknowledgement contains only newly committed and exact duplicate
inputs, and reports the durable watermark and any known source-sequence gaps.
Schema, capability, privacy, or integrity rejection is an operation-level error
for the whole batch. Transient persistence or admitted-write-capacity
backpressure is also operation-level and commits no novel envelope; neither
case returns a mixed per-envelope result. Clients follow the `retryable` field
and bounded-retry rules defined below.

An acknowledgement means durable acceptance, not projection visibility,
verified outcome, or successful execution.

## `finish_run`

`finish_run` is authorized only for the initiating coordinator or a principal
explicitly delegated finalization permission. It declares the run's expected
terminal source streams, their final sequence positions, and claimed terminal
outcomes. The Gateway assigns or bounds the finalization deadline under the
organization policy; request content cannot extend it beyond that ceiling.

The first valid call moves an active run to `finishing`. During that bounded
state, registered sources may fill declared sequence gaps or send required
terminal envelopes under their existing leases. Projection can revise coverage
as those inputs commit. A requested deadline at or before acceptance time is
invalid rather than silently replaced with a later policy deadline. At or after
the accepted deadline, novel join and ingest are rejected; an exact operation
retry may still return its previously committed result. A duplicate envelope
under a new operation requires a lease that is still valid.

When the first declaration is already reconciled, one atomic command records
the accepted cumulative finalization declaration, both `active -> finishing`
and `finishing -> finished`, and returns `finished`;
the client does not need a second operation identifier for the normal complete
path. An unresolved declaration remains in bounded `finishing`.

The Gateway seals the run as:

- `finished` when all required terminal declarations and sequence positions are
  reconciled without an unresolved required-source gap; or
- `incomplete` when the run has no unexpired lease, a required source or
  terminal declaration is missing, a required gap remains, or the finalization
  deadline passes.

The same operation identifier and digest returns the same result. A conflicting
retry is rejected. After sealing, exact stored operation retries may receive
their original result; exact duplicate envelopes under a still-valid lease may
receive their prior acknowledgement while novel envelopes are rejected with
`invalid_lifecycle_transition`. A future correction mechanism must create an
audited revision; it cannot reopen the run through these lifecycle operations.

Before admitting a novel lifecycle mutation, the Gateway reconciles run-level
expiry. An `active` or `finishing` run with no unexpired lease is atomically
sealed `incomplete`; an elapsed finishing deadline has the same result. A
reusable join policy cannot revive that run. Exact stored operation replay is
resolved before this dynamic reconciliation so lost-response recovery remains
stable. A rejected ingest still commits no envelope, although the same command
may commit the independent lifecycle transition that the expiry check made due.

`finished` is not a success verdict and `incomplete` is not a failed execution
verdict.

## Ordering, clocks, gaps, and replay

### Ordering

- Each source stream has a monotonically increasing `source_sequence` beginning
  at one. A source restart or credential rotation opens a new stream rather
  than resetting a sequence.
- The Gateway assigns an immutable `ingest_sequence` in durable commit order.
- Ordering across source streams is not implied. Observed timestamps and ingest
  order are not silently converted into causal order.
- Every observed timestamp carries its time basis and known clock uncertainty.
  Missing uncertainty is represented as unknown, not zero.

### Gaps

- Receiving a sequence above the next expected value records a gap and may
  accept the envelope; it does not fabricate the missing entries.
- A later envelope may fill an open gap during the active or finishing state.
  The gap history remains auditable even when current coverage improves.
- Sampling, truncation, source loss, batch rejection, and expired leases create
  typed Coverage Gaps.
- A required unresolved gap prevents `complete`, `host_verified`, or `verified`
  coverage as applicable and prevents a clean terminal summary.

### Replay and idempotency

- Envelope identity is scoped by organization, run, source registration, source
  stream, and event identifier. Sequence alone is not an idempotency key.
- Replaying an identity with the same canonical digest returns the original
  acknowledgement. Different content for the same identity is rejected and
  audited as a conflict.
- Dedupe state is retained at least as long as the retained run record. When
  dedupe proof has expired, a replay is rejected rather than accepted as novel.
- Repeated binding and lifecycle operations follow the same
  identifier-plus-digest rule.

### Canonical digest profile

Gateway protocol digests use RFC 8785 JSON Canonicalization Scheme (JCS) and
SHA-256 with explicit domain separation. Conceptually, the byte input is:

```text
SHA-256(UTF8(domain) || 0x00 || UTF8(discriminator) || 0x00 || JCS(value))
```

The request domain is `apolysis.gateway.request/v1`; its discriminator is the
canonical operation name, and the root `request_digest` member is removed from
the value before canonicalization. The inline-payload domain is
`apolysis.evidence.inline-payload/v1` and uses `evidence_type` as its
discriminator. The source-manifest domain is
`apolysis.evidence.source-manifest/v1` and uses `source_id` as its
discriminator. Server-side source-envelope deduplication uses
`apolysis.evidence.source-envelope/v1` with `payload_type`; runtime-binding
conflict detection uses `apolysis.gateway.runtime-binding/v1` with
`runtime_binding`. The primary lease lookup key is SHA-256 of
`apolysis.gateway.lease-id/v1 || 0x00 || UTF8(lease_id)`. Because an exact
`open_run` retry must reproduce its original lease, a durable adapter may also
retain the response's bearer material only in a separately KMS or
envelope-encrypted replay record with strict TTL, access control, and audit;
the bearer value is never plaintext in database indexes or logs. Integers
outside the exact interoperable range `[-(2^53-1), 2^53-1]` are rejected before
JCS.

The current PostgreSQL prototype stores AES-256-GCM ciphertext using an
in-process direct-key keyring and rejects replay after its configured TTL. Its
schema reserves an optional wrapped-data-key field for a future
envelope-encryption implementation, but the built-in protector does not create
or wrap data keys and no cleanup reaper is implemented.

The committed Gateway fixtures and `crates/apolysis-gateway/tests/digest_vectors.rs`
lock request and inline-payload digest outputs as interoperability inputs. Any
change to field omission, domain separation, canonicalization, or expected
digest values is a protocol change that requires fixture and contract review.

## Backpressure and availability

The Gateway enforces bounded request, batch, source, and organization limits.
`backpressure` means that the Gateway durable-persistence path or admitted
write capacity is temporarily unavailable. It does not represent authentication,
authorization, validation, rate limiting, or projection lag; those conditions
retain their dedicated v0.1 codes.

The response's `retryable` field is authoritative. The frozen v0.1
`backpressure` code remains reserved for a transient condition in which nothing
novel committed. This implementation emits it with `retryable: true` and a
bounded server-selected `retry_after_ms` from 1 through 60,000 milliseconds.
For v0.1 compatibility, readers must also accept a missing or `null` hint and
then apply a bounded local backoff. A source may retry only the exact operation,
preserving its operation identifier and digest. Its retry policy must also
bound total attempts or elapsed time and apply backoff or jitter.

Configured run-scoped admission limits are not reported as `backpressure` in
v0.1; they fail through the existing non-retryable lifecycle code. Generic
internal repository faults cannot be safely described by any permanent v0.1
machine code, so the current implementation preserves bounded v0.1
`backpressure` and records the actual invariant only in protected audit
metadata. This compatibility fallback is not a claim that an invariant will
self-heal; a future contract version requires a dedicated internal-unavailable
code and transport mapping. Clients never retry without a total-attempt or
elapsed-time bound, and always handle `retryable: false` conservatively.
Sources use bounded, encrypted local buffers according to their privacy policy
and report loss when the buffer cannot retain an item. Silent dropping is
forbidden.

Authentication, organization binding, content-policy validation, and
idempotency integrity fail closed. An unavailable projector does not invalidate
durably accepted writes; it makes projection lag and query watermark visible.

## Retention and deletion

The Gateway enforces [privacy and retention](privacy-boundary.md) at acceptance.
Expired, revoked, or deletion-pending runs reject novel ingest. Deletion first
revokes reads and write leases, then propagates a tombstone through write,
projection, index, cache, object, export, and stream components. The system must
not claim deletion completion before every registered component acknowledges
it.

## Minimum error classes

Machine contracts distinguish at least:

- `unauthenticated`, `forbidden`, and enumeration-safe `not_found`;
- `unsupported_contract_version`, `unsupported_source_version`, and
  `invalid_contract`;
- `invalid_lifecycle_transition`, `lease_expired`, `lease_revoked`, and
  `lease_scope_mismatch`;
- `idempotency_conflict`, `source_event_conflict`, and `sequence_conflict`;
- `capability_mismatch`, `redaction_required`, `content_not_authorized`, and
  `retention_not_authorized`;
- `batch_too_large`, `backpressure`, and `rate_limited`.

A cross-organization lookup returns the same external `not_found` response as a
missing resource, while the internal audit record retains the true rejection
reason. Safe error text never discloses another organization's run or source.

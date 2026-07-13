# Execution Evidence Gateway Lifecycle v0.1

Status: normative W1–W2 target contract. The Execution Evidence Gateway is not
implemented in the current release.

## Boundary

The Gateway is an authenticated write plane for Agent Execution Record source
envelopes. It is not the browser Query API, a public event bucket, an agent
orchestrator, or a general tool proxy. Privileged collectors never serve a
browser endpoint.

The canonical operations are `open_run`, `bind_runtime`, `ingest`, and
`finish_run`. Their machine types belong to the independent contracts boundary;
legacy JSONL v1 is an edge adapter input, not a Gateway schema.

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
envelopes.

For each novel accepted envelope, the Gateway atomically persists the envelope,
deduplication digest, server ingest sequence, and projection-outbox intent. A
successful acknowledgement contains only newly committed and exact duplicate
inputs, and reports the durable watermark and any known source-sequence gaps.
Schema, capability, privacy, or integrity rejection is an operation-level error
for the whole batch. Backpressure is also an operation-level retryable error and
commits no novel envelope; neither case returns a mixed per-envelope result.

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
as those inputs commit.

The Gateway seals the run as:

- `finished` when all required terminal declarations and sequence positions are
  reconciled without an unresolved required-source gap; or
- `incomplete` when a lease expires, a required source or terminal declaration
  is missing, a required gap remains, or the finalization deadline passes.

The same operation identifier and digest returns the same result. A conflicting
retry is rejected. After sealing, exact duplicate envelopes and finish retries
may receive their original acknowledgement while novel envelopes are rejected
with `invalid_lifecycle_transition`. A future correction mechanism must create
an audited revision; it cannot reopen the run through these lifecycle
operations.

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

## Backpressure and availability

The Gateway enforces bounded request, batch, source, and organization limits.
When capacity is unavailable it returns an explicit retryable response with a
retry delay and commits nothing from the rejected batch. Sources use bounded,
encrypted local buffers according to their privacy policy and report loss when
the buffer cannot retain an item. Silent dropping is forbidden.

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

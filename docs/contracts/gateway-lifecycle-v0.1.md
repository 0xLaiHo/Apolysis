# Execution Evidence Gateway Lifecycle v0.1

Status: normative W1–W2 target contract. An application core, non-durable
reference adapter, PostgreSQL write adapter, and direct-mTLS lifecycle tracer
are implemented on the `pre-release` development line; the production
Execution Evidence Gateway is not.

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
- an `AuthenticationSnapshot` that binds credential identifier, credential
  epoch, and policy revision without exposing those server-only authority
  inputs on the public wire;
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
- transaction-time PostgreSQL current-authority revalidation: after locking the
  operation identity and before materializing replay, every transaction attempt
  locks and revalidates the current organization, source registration, and
  transport credential; novel work revalidates that same locked authority again
  at its final transaction time after acquiring the applicable dynamic locks;
- explicit policy and credential rotation, with authority history and atomic
  invalidation of live leases and pending join authorization; initial
  registration cannot implicitly rotate existing authority;
- a direct-mTLS HTTP tracer for all four lifecycle operations, with current
  PostgreSQL credential authority, revocation on every route, bounded request
  bodies, content-free errors, and durable replay across graceful Gateway
  process restarts;
- a deployment role model with a NOLOGIN schema owner and separate Gateway
  runtime/control, evidence runtime/control, and deletion-acknowledgement
  capabilities; served Gateway sessions use only the runtime capability;
- novel-ingest admission for authorized, available evidence-object references,
  bound transactionally to organization, run, source, capability, payload,
  digest, size, retention, and object policy;
- a run-wide admission cap of 256 source streams plus bounded,
  transaction-local PostgreSQL lock and statement deadlines; and
- bounded finishing declarations and deadlines, sealing a reconciled run as
  `finished`, and lazy command-boundary reconciliation that seals an active or
  finishing run after its last lease or finalization deadline expires.

The 43 shared repository scenarios run against both adapters, including
credential-epoch/policy rotation, stale lease and replay rejection, the
256-stream admission boundary, and atomic rejection of the 257th stream. The
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

A sibling real direct-mTLS HTTPS recovery gate reuses the production listener,
application core, and PostgreSQL repository for two bounded crash columns on
each of `open_run`, `bind_runtime`, `ingest`, and `finish_run`. The
late-precommit column sends an accepted novel request through the normal
production binary. A qualification-owned ordinary, non-deferred `AFTER INSERT`
trigger targets that client's final `operation_replays` write, advances a
nontransactional sequence, and waits on an advisory lock. The driver requires
`pg_stat_activity` to show the runtime session blocked by the known holder
while the client remains response-silent. A separate session must see no target
operation/replay. External `SIGKILL` must leave loopback `curl` at HTTP `000`
with no header or body. After every runtime session closes, the logical
organization-scoped repository-state fingerprint must match its pre-request
baseline and the separately committed mTLS admission audit count must be
exactly one above its baseline.

The same signed request then enters the post-commit column. A feature-gated
response barrier in a separate qualification-only binary stops both the novel
success and its exact replay after the database commit and complete response
construction, but before the handler returns that response to Axum. A static
mode-`0600` marker in a private local directory signals that boundary; the gate
then sends external `SIGKILL` to the Gateway. The waiting loopback `curl` must
observe HTTP `000` with no response header or body. PostgreSQL inspection proves
one operation, one encrypted replay, and the route's expected ledger/outbox
effects, while the encrypted replay fingerprint remains unchanged across the
replay crash. A third, normal production server then returns the exact durable
result and lets the lifecycle proceed. The late-precommit database objects are
disposable qualification state, not migrations or production controls. The
post-commit barrier exists only in an explicit feature build, requires an
ephemeral loopback listener, and cannot be armed by the production CLI or any
remote request, header, or body. Neither the production CLI nor remote input can
install or configure the late-precommit database objects.

A separate bounded multiprocess gate starts two qualification-only Gateway
processes with independent loopback mTLS listeners and PostgreSQL pools. After
current-authority resolution and request decoding, both requests create static
private `ready` markers and remain response-silent and free of lifecycle
mutations until the driver atomically publishes one static private `release`
file. Current-authority audit writes may precede the marker; the oracle requires
both client operation identities to remain absent from lifecycle state. The
driver next holds an exclusive qualification lock on the operation table,
releases the HTTP barrier, proves both runtime transactions are waiting on
database locks, and then releases the blocker. It qualifies identical-operation
replay, competing client-run identities, one-use join-grant consumption,
cross-run exact runtime identity exclusion, concurrent event deduplication and
cross-run organization sequencing, identical and competing finalization, and
rejection of novel bind/ingest/finish operations after the terminal state. The
join grant is seeded by a feature-gated local helper through
`PostgresGatewayRepository::register_join_grant`; this adds no remote control
endpoint. Database evidence requires one encrypted replay per accepted
operation, record/outbox 1:1, contiguous organization sequences, one consumed
grant, one active-identity winner, and no terminal-state resurrection.

A bounded split-clock sibling uses the same independent processes, pools,
private pre-operation release, and observed database-lock overlap to qualify
exact replay against novel lifecycle work when a transaction wait crosses an
inclusive join-grant expiry, an accepted finalization deadline, or last-lease
expiry. The transaction-wait overlap is established at the
qualification-owned operation-table blocker; it is not evidence of a wait on
a particular run or join-authorization row. Qualification-owned
late-write fault injection raises SQLSTATE `40001` once for the target novel
operation to qualify the same boundaries through one real internal retry.
Seven operation/boundary scenarios run through both modes, for fourteen live
matrix cells: one-use join-grant expiry, join with a valid one-use grant at the
requested last-lease expiry, join at the finalization deadline, bind at the
requested last-lease expiry, ingest at the finalization deadline, ingest at the
requested last-lease expiry, and finish at the requested last-lease expiry. A
focused fifteenth cell repeats
finish at last-lease expiry with a one-shot
SQLSTATE `40P01` fault. It proves retry parity when PostgreSQL returns that
code; it does not claim that PostgreSQL's deadlock detector observed a naturally
formed multi-session wait-for cycle. Join attempts lock the operation
identity, current authority, exact stored-operation replay, run, and join
authorization before reading fresh transaction time and reconciling expiry.
Bind, ingest, and finish use the same order with the run and requested lease
locked instead of the join authorization. At that final time, novel work
revalidates the same locked registration/credential authority and
authentication-snapshot expiry before reconciliation or mutation. Exact replay
performs only the initial current-authority check. Every bounded serialization
or deadlock retry repeats the complete two-check order for novel work and
obtains fresh transaction time.

For object-reference ingest, PostgreSQL `clock_timestamp()` through the
schema-owned database-time function is authoritative. Content-off join, bind,
ingest, and finish use the trusted Gateway clock passed through the repository
port. A join authorization that expires at the fresh decision time is rejected
first as enumeration-safe `404 not_found`. The live one-use-grant cases prove
that this inclusive rejection leaves lifecycle state unchanged. Their
qualification recovery reruns the identical request with the qualification
clock at `T−1`, where `T` is the inclusive grant-expiry instant, and succeeds.
For otherwise eligible work at or after the accepted finalization deadline, novel join, bind, or
ingest is rejected with non-retryable `409 invalid_lifecycle_transition`; that
deadline takes precedence when a lease expires at the same instant. Without an
elapsed deadline, a join carrying a valid one-use grant at the last-lease
expiry also returns `409` and commits exactly one `active -> incomplete`
transition; bind or ingest at the relevant lease expiry returns non-retryable
`401 lease_expired`. Finish at last-lease expiry instead durably returns HTTP
`200` with state `incomplete`, accepts no finalization declaration, and commits
exactly one `active -> incomplete` transition. Exact replay of the accepted
join remains byte-stable across the new expiry cells. Two identical waiting
finish requests converge on one novel result and one exact replay; after one
late SQLSTATE `40001` or focused `40P01`, a restarted finish attempt reaches
the same durable result at the inclusive expiry and retains a stable exact
replay.
After deadline
reconciliation seals the run, later novel lifecycle work remains a `409`
lifecycle rejection rather than degrading to a lease error; the first
last-lease reconciliation by bind or ingest on an active run without a
deadline remains `401`.
A rejected join/bind/ingest operation creates no operation, encrypted replay,
stream, lease, runtime binding, or novel evidence event. A lifecycle-boundary
decision may commit only the single lazy transition to `incomplete` and its
matching record/outbox pair; competing requests cannot create a second
transition. A retained exact operation replay returns its unchanged stored
result after current-authority revalidation but before that dynamic
reconciliation.

A real-PostgreSQL repository test and a sibling direct-mTLS HTTPS qualification
cover exact replay for `open_run`, `bind_runtime`, `ingest`, and `finish_run`
while the exact operation row is locked. Each live route first proves two
byte-stable positive exact replays at expiry minus one millisecond, with replay
expiry still inside the current registration and credential validity windows.
The qualification corrupts only retained replay ciphertext, proves the runtime
transaction is blocked on the exact holder, advances its private transaction
clock only after that waiter exists, and releases the holder at inclusive
replay-TTL expiry. Expiry is therefore decided before decryption: every route
produces non-retryable `409` `idempotency_conflict`, with
`Cache-Control: no-store`, no retry hint, and no response bytes before release.
The 20-table lifecycle fingerprint and operation/replay cardinality remain
unchanged, while the transport attempt adds exactly one admission-audit row.
The v0.1 HTTP adapter samples transaction time once after the lock wait. The
loopback, same-UID, `0600` time-advance file exists only in the qualification
build; production configuration rejects that control surface. The monotonic
interval from pre-operation release through confirmed holder termination must
remain below 1.2 seconds, preserving explicit margin under the production
two-second lock timeout.

Operations and encrypted replay records carry credential identifier,
credential epoch, and policy revision. Leases and join authorization carry the
same current-authority binding, including both target and issuer binding for a
join. Policy rotation advances the policy revision without silently replacing
the credential. Credential rotation advances the credential epoch, retires the
old certificate, and may either retain the policy or advance it once. Both
cutovers atomically revoke live leases and pending join authorization for the
affected source. A stored successful result bound to superseded authority is an
idempotency tombstone, not continuing authority, and fails closed before replay
material is opened.

The shared real-PostgreSQL authority cases prove that a novel operation waiting
on policy rotation observes the new authority, exact replay waiting on
credential rotation never opens the old replay, and a transaction restarted
after SQLSTATE `40001` rechecks authority before mutation. A deferred
authority-denial commit returning SQLSTATE `40001` also restarts the complete
transaction rather than returning backpressure or committing a partial
capability. Join-grant issuance waiting on its run lock resamples final
transaction time, rechecks both issuer and target authority before mutation,
requires expiry after that time, and stores that time as
`issued_at_unix_ms`. The direct-mTLS rotation gate additionally proves policy
and certificate cutover behavior with real old/new client certificates, stale
lease/replay rejection, and a new source stream under current authority.

Current PostgreSQL gap discovery evaluates a window over the full persisted
history for one source stream; its SQL limit bounds returned gaps rather than
scan work. Novel envelopes reserve one contiguous organization sequence range
with one row update, but record, outbox, and evidence inserts remain row-wise
while organization sequencing is held. Incremental watermark/gap state, bulk
insertion, and load/capacity qualification are required before the W3–W6
storage exit gate.

A durable PostgreSQL lifecycle projector now consumes strict Gateway ingest
order, maintains organization-qualified generations and exact watermarks,
publishes the active outbox, and supports from-zero rebuild with atomic
cutover. Its bounded lifecycle membership cursor is internal: it is not public
Query authorization, an external cursor, or a Console surface.

The authorized evidence-object write lifecycle now reserves bounded metadata,
performs encrypted S3-compatible upload and full authenticated read-back,
binds novel Gateway events to available objects, and propagates deletion
through a fenced reaper and consumer acknowledgements. It exposes no
source-authorized or browser object-read API. Its fixed PostgreSQL capability
roles are process-plane separation, not tenant RLS.

The slice is a conformance foundation, not a production service, and does not
complete W3–W6. In particular, it has:

- the repository recovery gate remains a non-HTTPS application/repository seam;
  the sibling HTTPS gate qualifies one accepted-novel late-precommit rollback
  seam plus post-commit/pre-ack process death for novel success and exact replay
  on all four routes, and the two-process gate qualifies the bounded
  writer/lifecycle matrix above. The split-clock transaction-boundary slices
  qualify the listed join, bind, ingest, and finish cases. The sibling
  direct-mTLS HTTPS qualification covers the four-route replay-TTL
  operation-lock race. The direct-mTLS split-clock matrix and shared
  real-PostgreSQL conformance now both cover join-grant expiry and join at
  last-lease expiry; shared conformance additionally covers invalid transaction
  time and one staggered requested-lease bind case. They do not qualify the remaining
  earlier or arbitrary network pre-commit/process-death timings, pre-commit
  exact-replay or rejection branches, completion of the final `INSERT`
  statement, entry into `COMMIT`, physical or WAL commit timing, the remaining
  mixed lifecycle/retry matrix, registration-policy parity for the two new live
  one-use-grant cells, broader staggered combinations beyond the current
  focused two-lease shape, additional retry depths or operations beyond the
  focused one-shot `40P01` finish parity cell,
  sustained or capacity load,
  replication/failover, backup/restore, or high availability;
- no production KMS/envelope-data-key custody or tenant RLS deployment; the
  built-in replay protector and evidence-object wrapping key are direct-key
  in-process inputs, and the fixed database roles are not a shared-cluster
  tenant-isolation profile;
- a real direct-mTLS HTTP tracer covers all four lifecycle routes, live
  credential revocation, cross-organization rejection, and graceful
  Gateway-process restart; the sibling gate also covers the bounded HTTPS
  accepted-novel late-precommit rollback and post-commit/pre-ack crash seams,
  and the current PostgreSQL/direct-mTLS slice covers transaction-time authority
  revalidation plus credential/policy rotation, but JWT/workload-identity
  profiles, production admission, and the broader network fault/race matrix
  remain open;
- no authorized Query/object-read resolver for referenced payloads;
- no background deadline or encrypted-replay cleanup reaper—run expiration is
  reconciled only when a later novel lifecycle command reaches the application
  core, while an expired replay is rejected but not deleted;
- no production Gateway request-rate, batch-byte, or organization limit
  enforcement beyond the run-wide stream cap and the transport's one-MiB
  request-body ceiling; evidence objects have a separate bounded policy; and
- no public projector-backed Query authorization, external cursor or SSE,
  evidence-object read projection, coverage/findings/source-health views, or
  Web Console.

The following sections remain the normative production behavior even where the
reference adapter cannot yet demonstrate the associated durability or
availability claim.

## Authentication and authority

The transport injects an authenticated source principal from a registered
workload identity, mTLS identity, or comparably bound credential. The Gateway
derives the organization, permitted source roles, operations, and environment
profiles from that principal.

The injected authentication snapshot includes the transport credential
identifier and epoch as well as the policy revision. It records what the
transport authenticated; it is not a lease or continuing authority. Before
returning an exact replay or performing novel PostgreSQL lifecycle work, the
same transaction must lock current organization, registration, and credential
state and prove at initial transaction time that the snapshot still matches. A
retry starts this check again. Exact replay may return after that check. Novel
work must revalidate the same locked state at its final transaction time after
waiting on run, lease,
client-run, or join locks; this second check includes registration/credential
validity and authentication-snapshot expiry. Stale policy is authorization
failure; inactive, revoked, expired, identity-mismatched, or stale
credential/epoch state fails authentication, without revealing
cross-organization existence or replay material.

A request-supplied `organization_id`, `tenant_id`, run identifier, source name,
or provider identity is an assertion to validate, never authority. A mismatch
is rejected before idempotency or existence information is disclosed.

Every accepted `open_run` requires:

- a registered source principal bound to one organization;
- operation permission and a compatible `SourceManifest`;
- a client operation identifier and canonical request digest for idempotency.

`open_run` creates a lease. Every accepted `bind_runtime` or `ingest` mutation,
and every accepted `finish_run` finalization declaration, requires an unexpired
lease scoped to organization, run, source registration, source stream, and
allowed operations. A `finish_run` request that first observes last-lease
expiry may durably report the run it reconciled to `incomplete` without
accepting the requested finalization declaration.

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
canonical digest returns the same run and lease outcome only while the
operation's credential/epoch/policy binding remains current. Reusing the
identifier with different content is an idempotency conflict. A client run key
collision never causes an implicit join.

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
operation replay whose credential/epoch/policy binding remains current.

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
their original result only while their credential/policy binding remains
current; exact duplicate envelopes under a still-valid, authority-bound lease
may receive their prior acknowledgement while novel envelopes are rejected
with `invalid_lifecycle_transition`. A future correction mechanism must create
an audited revision; it cannot reopen the run through these lifecycle
operations.

Before admitting a novel lifecycle mutation, the Gateway reconciles run-level
expiry. An `active` or `finishing` run with no unexpired lease is atomically
sealed `incomplete`; an elapsed finishing deadline has the same result. A
reusable join policy cannot revive that run. Exact stored operation replay is
resolved after transaction-time current-authority revalidation and before this
dynamic reconciliation so lost-response recovery remains stable without
turning stale replay into continuing authority. A rejected ingest still commits
no envelope, although the same command may commit the independent lifecycle
transition that the expiry check made due.

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

### Clocks and transaction admission

HTTP arrival, transport-authority resolution, request decoding, application
entry, and transaction begin are not lifecycle acceptance points.
Object-reference ingest is the sole precondition exception to the
operation-first Gateway lock order. To preserve the evidence-object
cross-plane ancestor lock order, it first acquires the evidence-object
organization shared-ancestor lock. Within the Gateway plane it then follows
the same order as every other lifecycle attempt. Each PostgreSQL repository
transaction attempt must:

1. resolve and lock the operation identity;
2. lock the current organization, source registration, and transport
   credential;
3. read initial trusted transaction time and revalidate those rows against the
   authentication snapshot, including all authority and snapshot validity;
4. materialize and return an unexpired, matching, authority-bound exact
   operation replay before dynamic lifecycle reconciliation;
5. for novel work, acquire its applicable run, lease, client-run, and/or join
   authorization locks;
6. read final trusted transaction time;
7. revalidate the same locked current authority at that final time, including
   registration/credential validity and authentication-snapshot expiry;
8. reconcile deadline or last-lease expiry; and
9. only then admit a novel mutation.

A PostgreSQL serialization or deadlock restart is a new attempt and must repeat
that sequence, including both authority checks for novel work and the
fresh-time read. For ingest containing an evidence object reference, the
repository reads PostgreSQL `clock_timestamp()` through the schema-owned
database-time function. Content-off
join, bind, ingest, and finish read the trusted Gateway clock through the
repository port. A zero or regressed trusted Gateway time fails closed rather
than admitting work under a stale timestamp.

The join-grant, finalization-deadline, and lease-expiry checks use inclusive
boundaries. If a one-use join authorization has expired at fresh transaction
time, the request first fails enumeration-safe as HTTP `404`, `not_found`,
without consuming that authorization. The live split-clock cases require no
lifecycle delta after that rejection. Their recovery control reruns the
identical request with the qualification clock at `T−1`, where `T` is the
inclusive grant-expiry instant, and succeeds. For otherwise eligible work, if
the fresh transaction time is at or after the
accepted finalization deadline, a novel join, bind, or ingest is rejected as
HTTP `409`, `invalid_lifecycle_transition`, with `retryable: false`; this
result takes precedence if a lease expires at the same instant. Without an
elapsed deadline, a novel join carrying a valid one-use grant at inclusive
last-lease expiry is also rejected as `409` and lazily seals the run
`incomplete`; bind or ingest at the relevant lease expiry is rejected as HTTP
`401`, `lease_expired`, with `retryable: false`. A run already sealed by
deadline reconciliation continues to reject later novel lifecycle work as
`409`; clearing its active deadline metadata must not downgrade that result to
`401`. The first last-lease reconciliation by bind or ingest on an active run
with no elapsed deadline remains `401`. None of these responses carries a
retry delay. The rejection consumes no novel operation identity and creates no
encrypted replay, stream, lease, runtime binding, or evidence event. A
lifecycle-boundary transaction lazily seals the run `incomplete`; across
competing requests, reconciliation commits exactly one state-transition record
and its matching outbox row. An accepted join's exact replay remains unchanged
and is resolved before either expiry decision.

A novel `finish_run` that first observes last-lease expiry is the qualified
exception to that rejection result. It atomically reconciles
`active -> incomplete`, accepts no finalization declaration, persists one
operation and encrypted replay for the durable HTTP `200` `incomplete` result,
and returns that same result on an exact retry.

This rule defines the qualified lifecycle decision point; it does not claim
that the database commit's wall-clock instant precedes the deadline or expiry.
A real-PostgreSQL repository gate and its direct-mTLS HTTPS sibling qualify all
four routes at inclusive replay-TTL expiry after an exact operation-row lock
wait, including expiry-before-decryption and unchanged-lifecycle-state oracles.
The direct-mTLS split-clock matrix separately qualifies one-use join-grant
expiry and valid one-use-grant join at last-lease expiry through both its
operation-table transaction wait and one-shot SQLSTATE `40001` retry modes. It
does not qualify registration-policy parity, broader staggered combinations
beyond the current focused two-lease shape, additional retry depths, or
operations beyond the focused one-shot `40P01` finish parity cell.

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
  acknowledgement only while its credential/epoch/policy binding remains
  current. Different content for the same identity is rejected and audited as
  a conflict.
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

The adapter's bounded internal transaction restart is distinct from a client
retry. A serialization or deadlock restart that has not committed repeats the
complete transaction-admission order and samples fresh transaction time. If
the new attempt reaches a deadline or lease-expiry decision, it returns the
applicable non-retryable lifecycle result—or the qualified durable
`finish_run` convergence on `incomplete`—rather than `backpressure`. Exhausted
retries or an unavailable persistence path retain the bounded external
`backpressure` behavior.

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

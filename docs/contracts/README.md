# W1–W2 Contract Set

Status: normative W1–W2 contract. The active Gateway foundation slice includes
an application core, a non-durable reference adapter, and an initial PostgreSQL
write-adapter prototype, not a production Gateway service.

These documents freeze the W1–W2 product and evidence contract. The independent
machine types, schemas, and fixtures live in `apolysis-contracts`. The
current `pre-release` implementation now applies the Gateway types in an
authenticated application core, an in-memory reference adapter, and a
migration-managed PostgreSQL write adapter. The remaining contracts describe
what the production Gateway transport, storage qualification, projection,
Query API, and Console implementations must do without claiming those runtime
components exist.

Read the contracts in this order:

1. [Scope and environment profiles](w1-w2-scope.md)
2. [Privacy boundary and defaults](privacy-boundary.md)
3. [Agent Execution Record v0.1 semantics](agent-execution-record-v0.1.md)
4. [Execution Evidence Gateway lifecycle v0.1](gateway-lifecycle-v0.1.md)
5. [Minimum Console v0 information architecture](console-v0.md)
6. [Design-partner validation and approval template](design-partner-validation.md)

The repository [domain glossary](../../CONTEXT.md) defines canonical terms.
The [production-contract boundary ADR](../adr/0001-independent-production-contracts.md)
records why these types are independent from legacy JSONL.
The independent `apolysis-contracts` crate owns shared machine types and
versioned schemas; legacy JSONL v1 remains an edge adapter format rather than a
Gateway or Query schema. Schemas and fixtures are authoritative for machine
validation; this set is authoritative for product meaning and claim boundaries.
A schema that permits a state forbidden here is a contract defect, not
permission to make the broader claim.

Gateway clients treat the error response's `retryable` field, not its `code`,
as the authority for automatic retry. Frozen v0.1 `backpressure` remains a
transient persistence/capacity signal; this implementation emits a bounded
retry hint, while compatible readers still accept the old missing or `null`
hint shape. A run-scoped admission limit uses the existing non-retryable
lifecycle code, where that machine meaning remains accurate. Generic internal
repository faults retain bounded v0.1
backpressure for wire compatibility and are distinguished in protected audit
metadata; a future version needs a dedicated internal-unavailable code. Clients
must never retry indefinitely from the code alone.

## Machine artifacts

- Rust wire types: `crates/apolysis-contracts/src/`
- Gateway application core and non-durable reference adapter:
  `crates/apolysis-gateway/src/`
- Shared Gateway repository conformance scenarios:
  `crates/apolysis-gateway-testkit/`
- Initial PostgreSQL Gateway write adapter and migration:
  `crates/apolysis-gateway-postgres/`
- Application-core conformance invocation and RFC 8785 golden-vector tests:
  `crates/apolysis-gateway/tests/`
- Generated JSON Schema: `schemas/contracts/v0.1/`
- Positive and negative compatibility fixtures:
  `crates/apolysis-contracts/tests/fixtures/`

Regenerate schemas after an intentional contract change:

```bash
cargo run -p apolysis-contracts --bin export_schemas
cargo test -p apolysis-contracts --test schema_snapshots
```

The snapshot test fails when committed schemas drift from the Rust roots. It
also locks critical source-envelope exclusivity, source ordering, integrity,
and bounded ingest constraints.

## Compatibility rule

The `v0.1` record and lifecycle contracts may be refined during W1–W2, but a
merged incompatible change must update all affected schemas, fixtures, and
contract documents in the same Pull Request. After the W1–W2 exit gate, an
incompatible wire change requires a new version.

## Current implementation boundary

The current code provides local CLI, daemon, JSONL, Codex intent,
accountability, runtime metadata, and Linux observation paths. The
`pre-release` implementation line also provides the four-operation Gateway
application core, server-side join grant/policy checks, RFC 8785 request and
inline-payload golden vectors, bounded lifecycle reconciliation, and a
non-durable memory adapter. An initial PostgreSQL adapter applies the same
atomic-command seam to normalized ledger/outbox state, hashed lease and join
references, encrypted exact-operation replay, a 256-stream-per-run admission
cap, and bounded transaction-local lock/statement deadlines. The shared
43-scenario suite runs against both adapters and verifies atomic rejection at
the stream boundary plus credential/policy rotation and stale-capability
rejection; an explicit real-PostgreSQL gate
adds eleven targeted transaction, reconstruction, range-allocation, two-shape cross-pool
concurrency, plaintext-absence, sequencing, and replay-expiry checks. The
second concurrency shape races distinct operation IDs on one client run key
and requires one winner plus one idempotency conflict. Expired replay remains
a durable idempotency tombstone after repository reconstruction. Database
inspection used by conformance is test-only; the production repository exposes
no snapshot/read API.

A separate real crash-recovery gate drives that production repository through
the application core with `SystemClock`, `OsRandomIdGenerator`, and
runtime-generated operations. On a pinned PostgreSQL 16 persistent volume with
data checksums and durable write settings enabled, it proves exact replay across
graceful database restart and PostgreSQL `SIGKILL`/WAL redo, complete rollback
after application-process death before commit, and exact replay after
application-process death post-commit/pre-ack. It withholds a distinct client
acknowledgement, kills the first retry at the same pre-ack boundary, and uses a
third process to prove exact convergence. Catalog-discovered plaintext
scanning, `pg_amcheck`, `pg_dump`, generated-secret scans, private-file checks,
and dedicated-resource cleanup are part of the gate. This qualifies the
application/repository process seam, not HTTPS Gateway-server recovery.
A sibling real direct-mTLS HTTPS gate now covers all four lifecycle routes at
one accepted-novel late-precommit rollback seam and at the
post-commit/pre-ack server-death seam. The late-precommit column uses the normal
production binary and a qualification-owned ordinary, non-deferred
`AFTER INSERT` trigger on the final `operation_replays` write. A
nontransactional sequence and an advisory-lock wait prove that the target
request reached the seam and that its runtime session is blocked by the known
holder. While the client remains response-silent, a separate session must see
no target operation/replay. External `SIGKILL` must leave loopback `curl` at
HTTP `000` with no header or body. After every runtime session closes, the
logical organization-scoped repository-state fingerprint must match its
pre-request baseline and the separately committed mTLS admission audit count
must be exactly one above its baseline.

The same signed request then enters the existing post-commit column. For both
the novel result and exact replay, a feature-gated qualification-only binary
writes a static private mode-`0600` marker after commit and complete response
construction but before returning the response to Axum; external `SIGKILL`
must leave loopback `curl` at HTTP `000` with no headers or body. The database
must retain one operation/replay and the expected ledger/outbox effects without
changing the encrypted replay fingerprint, after which a third normal
production server returns the exact result. The late-precommit database objects
are disposable qualification state, not migrations or production controls. The
post-commit qualification binary accepts only an ephemeral loopback listener;
neither the production CLI nor remote HTTP input can install or configure the
late-precommit objects or arm the response barrier.

A bounded two-process gate additionally qualifies the reviewed writer and
lifecycle races. Its split-clock sibling qualifies five operation/boundary
scenarios through both a transaction wait and one qualification-injected, real
SQLSTATE `40001` internal retry, for ten cells: join at the finalization
deadline, bind at last-lease expiry, ingest at the finalization deadline,
ingest at last-lease expiry, and finish at last-lease expiry. A focused
eleventh cell repeats finish at last-lease expiry with a one-shot SQLSTATE
`40P01` fault, proving retry parity when PostgreSQL returns that code without
claiming a naturally detected multi-session deadlock. The
transaction-boundary implementation orders each covered lifecycle attempt as
operation-identity lock, current organization/registration/credential locks
and revalidation, exact stored replay, applicable run/lease/client-run/join
locks, fresh transaction time, final revalidation of the same locked authority,
expiry reconciliation, then novel mutation. The final check includes
registration/credential and authentication-snapshot expiry after the dynamic
lock wait. Exact replay performs only the initial current-authority check.
Every internal serialization or deadlock retry repeats that order and both
authority checks for novel work.
Object-reference ingest uses
PostgreSQL `clock_timestamp()` through the schema-owned database-time function;
content-off join, bind, ingest, and finish use the trusted Gateway clock.

A real-PostgreSQL repository test and a sibling direct-mTLS HTTPS qualification
cover exact replay for `open_run`, `bind_runtime`, `ingest`, and `finish_run`
while the exact operation row is locked. Each live route first proves two
byte-stable positive exact replays at expiry minus one millisecond, with replay
expiry still inside the current registration and credential validity windows.
The qualification then corrupts only the retained replay ciphertext, proves the
runtime transaction is waiting on the exact holder, advances its private
transaction clock only after that waiter exists, and releases the holder at the
inclusive replay-TTL expiry. Expiry is therefore decided before decryption:
each route produces a non-retryable `409` `idempotency_conflict`, with
`Cache-Control: no-store`, no HTTP or body retry hint, no response bytes before
lock release, an unchanged 20-table lifecycle fingerprint and operation/replay
cardinality, and exactly one additional admission-audit row. The v0.1 adapter
samples transaction time once after the wait. The loopback, same-UID, `0600`
time-advance file is available only in the qualification build; production
configuration rejects that control surface. The monotonic interval from
pre-operation release through confirmed holder termination must remain below
1.2 seconds, preserving explicit margin under the production two-second lock
timeout.

`AuthenticationSnapshot` binds credential identifier, credential epoch, and
policy revision. PostgreSQL operations, encrypted replay records, leases, and
join authorization retain the matching authority binding. Explicit policy or
credential rotation updates current authority and atomically revokes live
leases plus pending join authorization; replay bound to superseded authority
fails closed before decryption. Initial registration cannot implicitly update
or rotate an existing source. Shared real-PostgreSQL cases include a novel
request waiting on policy rotation, exact replay waiting on credential
rotation, authority revalidation after one SQLSTATE `40001` transaction
restart, and complete restart after a deferred authority-denial commit returns
SQLSTATE `40001`. Join-grant issuance also rechecks issuer and target authority
after its run-lock wait, rejects expiry at final transaction time, and records
that time as the grant issue time. The live direct-mTLS gate also exercises
old/new certificate, policy, lease, replay, and new-stream behavior across both
cutovers.

For the covered novel join/bind/ingest cases, deadline crossing returns
non-retryable `409 invalid_lifecycle_transition` and last-lease crossing
returns non-retryable `401 lease_expired`. A rejected novel request creates no
operation, encrypted replay, or evidence event. Finish at last-lease expiry
instead durably returns HTTP `200` with state `incomplete`, accepts no
finalization declaration, records exactly one `active -> incomplete`
transition, and retains a stable exact replay. Across competing requests, lazy
reconciliation creates exactly one `incomplete` transition and its matching
record/outbox pair. A retained exact operation replay remains unchanged and is
resolved after current-authority revalidation but before dynamic lifecycle
reconciliation.

Current PostgreSQL ingest still uses a full per-stream history window for gap
discovery—the SQL limit bounds returned gaps, not scan work. A novel batch now
reserves one contiguous organization sequence range with one row update, but
record, outbox, and evidence inserts remain row-wise while holding organization
sequencing. Incremental watermark/gap state, bulk insertion, and load/capacity
qualification remain W3–W6 storage work.

This is not a production Gateway and does not complete W3–W6. The remaining
earlier or arbitrary network pre-commit/process-death timings, pre-commit
exact-replay or rejection branches, completion of the final `INSERT` statement,
entry into `COMMIT`, physical or WAL commit timing, and the remaining mixed
lifecycle/retry matrices, sustained or capacity load, replication/failover,
backup/restore, and HA are not qualified. The bounded lifecycle decision is not
a claim about the database commit's wall-clock instant. Live join-grant expiry,
live join at last-lease expiry, remaining novel join/bind cases, broader
staggered multi-lease combinations, and additional retry depths and operations
beyond the focused one-shot `40P01` finish parity cell also remain open.
Production KMS/envelope-key integration,
database RLS deployment, the authorized object-read resolver and downstream
deletion propagation, background deadline/replay cleanup, and production rate and
request-size enforcement beyond the implemented stream cap are likewise
unqualified. JWT/workload-identity transport profiles also remain open. The
organization-scoped Query API, complete Console-v0 read-model projectors, and
Web Console specified here are also not implemented.

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
28-scenario suite runs against both adapters and verifies atomic rejection at
the stream boundary; an explicit real-PostgreSQL gate
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
HTTPS trace and error-body secret handling therefore remains part of the
server-recovery gate.

Current PostgreSQL ingest still uses a full per-stream history window for gap
discovery—the SQL limit bounds returned gaps, not scan work. A novel batch now
reserves one contiguous organization sequence range with one row update, but
record, outbox, and evidence inserts remain row-wise while holding organization
sequencing. Incremental watermark/gap state, bulk insertion, and load/capacity
qualification remain W3–W6 storage work.

This is not a production Gateway and does not complete W3–W6. The broader
multiprocess/lifecycle race matrix, sustained or capacity load,
replication/failover, backup/restore, HA, and HTTPS Gateway-server recovery are
not qualified; nor are production KMS/envelope-key integration or database RLS
deployment; network transport or live credential revocation; object-store
resolver; background deadline/replay cleanup; or production rate and
request-size enforcement beyond the implemented stream cap. The
organization-scoped Query API, versioned
projectors, and Web Console specified here are also not implemented.

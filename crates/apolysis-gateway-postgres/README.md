# `apolysis-gateway-postgres`

`apolysis-gateway-postgres` is the initial PostgreSQL write adapter for the
transport-independent Execution Evidence Gateway application core. It
implements the same `GatewayRepository` atomic-command seam as the in-memory
reference adapter and owns its migration-managed `apolysis_gateway` schema.

## Implemented boundary

The adapter currently persists the four canonical Gateway operations and their
normalized run, source, stream, lease, runtime-binding, evidence, finalization,
operation, and append-fact state. Its transaction boundary includes:

- organization-scoped ingest-sequence allocation;
- record-item and projection-outbox insertion with an exact 1:1 database
  invariant;
- event and operation deduplication/idempotency state;
- hashed lease and join-authorization lookup references;
- a run-wide admission cap of 256 source streams;
- exact runtime-identity exclusion for active runs;
- run/lease locking, bounded retry for PostgreSQL serialization/deadlock
  failures, and transaction-local lock/statement deadlines (2 seconds and 15
  seconds by default, configurable within a bounded range); and
- transient/permanent database-failure classification for transaction control
  and protected diagnostics limited to the operation stage, error kind,
  SQLSTATE, and constraint name; the frozen v0.1 external response keeps generic
  internal faults on bounded backpressure until a dedicated wire code exists;
  and
- AES-256-GCM protected exact-operation replay with authenticated associated
  data and an expiry timestamp.

An expired encrypted replay is rejected; there is no cleanup worker that
deletes expired replay rows. Lazy lifecycle reconciliation also requires a
later novel command and is not a background deadline reaper.

`Aes256GcmReplayProtector` is an in-process direct-key keyring. Deployments are
responsible for sourcing key bytes and coordinating rotation outside this
crate. The schema can hold an optional `wrapped_data_key` for a future
envelope-encryption implementation, but the built-in protector has no KMS
integration and does not generate or wrap data keys.

## Explicit PostgreSQL gate

Unit tests and the PostgreSQL integration tests are intentionally separate.
The detailed real-database gate runs the 28 shared repository-conformance
scenarios, including the 256-stream admission boundary, plus seven targeted
checks for pool/repository reconstruction,
post-commit/pre-ack retry, identical-operation concurrent tasks, distinct
operation IDs racing on one client run key, plaintext lease absence,
contiguous ledger/outbox sequencing, and replay expiry that remains a durable
idempotency tombstone after reconstruction. The concurrency checks use
independent repositories and connection pools. The distinct-operation race
requires one winner and one deterministic idempotency conflict:

```bash
make test-gateway-postgres
```

The script requires an accessible Docker daemon. It starts a pinned PostgreSQL
16 image on a random loopback port with generated credentials, runs ignored
tests single-threaded, and removes the container and temporary credential file
on exit. It does not print the database URL or password. The pinned image is
left in the normal Docker cache.

A separate crash-recovery gate drives the production
`PostgresGatewayRepository` through `ExecutionEvidenceGateway` with
`SystemClock` and `OsRandomIdGenerator`; it does not substitute a fixed clock,
fixed identifiers, an in-memory repository, or checked-in request data. It
starts the pinned PostgreSQL 16 image on a dedicated persistent volume with data
checksums, `fsync`, synchronous commit, and full-page writes enabled, then
proves:

- exact replay after a graceful PostgreSQL stop/start;
- committed-state recovery after PostgreSQL receives `SIGKILL`, including an
  advanced WAL position and PostgreSQL log evidence that WAL redo ran;
- complete rollback and a successful novel retry after the application driver
  receives `SIGKILL` while its transaction is deterministically blocked before
  commit; and
- one exact idempotent result after the application driver receives `SIGKILL`
  after the atomic run/operation/replay/lease/three-record/three-outbox commit
  while a distinct client-acknowledgement file is still absent; the first retry
  process is killed at the same pre-ack boundary, and a third process converges
  on the same exact result.

The gate scans database catalog-discovered text, JSON, and byte columns, the
database dump, process logs, and private control artifacts for plaintext bearer
leases and generated secrets. It also runs `pg_amcheck` and `pg_dump`, verifies
private files are mode `0600`, and removes its dedicated container, persistent
volume, and control directory:

```bash
make test-gateway-postgres-crash-recovery
```

This is an application/repository process seam. It does not start or kill the
HTTPS Gateway server and therefore does not qualify network-listener recovery,
trace secret handling, or HTTP error-body secret handling.

To compile and run only non-database tests:

```bash
cargo test -p apolysis-gateway-postgres
```

## Known ingest scaling limits

Current gap discovery computes a window over the full persisted history for one
source stream. The SQL `LIMIT` bounds the number of returned gap ranges, not the
amount of history scanned. Novel batch items are also assigned organization
sequences and inserted row by row while the organization sequence row remains
locked. Before storage qualification, this must become incremental
watermark/gap state with bounded scan work, sequence-range reservation, and
bulk insertion, followed by load and capacity testing.

## Non-claims

This crate is a write-path prototype, not a production Gateway service and not
completion of W3–W6. The dedicated gate qualifies graceful PostgreSQL restart,
PostgreSQL SIGKILL/WAL redo, and application-process death on both sides of the
commit boundary for one runtime-generated `open_run` shape. It does not qualify
HTTPS Gateway-server recovery, the full multiprocess or lifecycle race matrix,
sustained or capacity load, replication, failover, backup/restore, or high
availability. Production KMS/envelope-key integration, database roles and
row-level-security deployment, complete network authority/revocation, object
storage, background reapers, admission controls beyond the 256-stream cap,
durable projectors, Query API, and Console remain outside this crate.

Conformance-state inspection is implemented by the test harness through a
separate database pool. `PostgresGatewayRepository` exposes no public snapshot
or product read API; production reads remain the responsibility of future
projectors and the Query service.

See [SCHEMA.md](SCHEMA.md) for storage invariants and
[`docs/contracts/gateway-lifecycle-v0.1.md`](../../docs/contracts/gateway-lifecycle-v0.1.md)
for the normative lifecycle contract.

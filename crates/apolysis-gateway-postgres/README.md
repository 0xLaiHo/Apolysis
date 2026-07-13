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
completion of W3–W6. The current tests reconstruct the repository and client
pool; they do not restart the PostgreSQL server or prove WAL/crash recovery,
multiprocess races, sustained load, replication, failover, backup/restore, or
high availability. Production KMS/envelope-key integration, database roles and
row-level-security deployment, network authentication/revocation, background
reapers, object storage, admission controls beyond the 256-stream cap, durable
projectors, Query API, and Console remain outside this crate. The seven targeted
tests do not close the full multiprocess or lifecycle race matrix.

Conformance-state inspection is implemented by the test harness through a
separate database pool. `PostgresGatewayRepository` exposes no public snapshot
or product read API; production reads remain the responsibility of future
projectors and the Query service.

See [SCHEMA.md](SCHEMA.md) for storage invariants and
[`docs/contracts/gateway-lifecycle-v0.1.md`](../../docs/contracts/gateway-lifecycle-v0.1.md)
for the normative lifecycle contract.

# PostgreSQL schema notes

`migrations/0001_gateway_ledger.sql` is the initial PostgreSQL Gateway ledger
schema. Run it only through the crate's migration runner. The SQL deliberately
does not use blanket `IF NOT EXISTS`: the runner's version/checksum table is the
repeat-execution guard, and unexpected pre-existing objects must surface as
drift.

The migration creates only the dedicated `apolysis_gateway` schema. Every
tenant-owned key and foreign key carries `organization_id`; callers must also
set database roles and row-level access policy before claiming tenant
isolation. `organization_sequences.next_ingest_sequence` is the row-lock seam
for assigning the per-organization append order.

Security invariants:

- `leases` stores only the domain-separated SHA-256 lease digest.
- `join_authorizations` stores only the domain-separated SHA-256 proof digest.
- `operation_replays` stores an encrypted response, algorithm/cipher version,
  nonce, tag, AAD digest, key reference, optional wrapped data key for envelope
  encryption, and mandatory expiry. A direct KMS or secret-manager key
  reference leaves the wrapped-data-key column null. It has no plaintext
  response or bearer column. The current built-in AES-256-GCM protector is a
  direct-key in-process keyring and does not populate or wrap a data key; the
  optional column is schema capacity for a future envelope-encryption
  implementation.
- `gateway_operations` remains after replay ciphertext expires so an old
  operation identifier cannot become novel again. Expired replay is rejected,
  but no background cleanup reaper is implemented yet.

`record_items` and `projection_outbox` use deferred mutual foreign keys. A
transaction therefore cannot commit one without the other, preserving the
ledger-to-outbox 1:1 invariant while allowing either insert order.
`active_runtime_identities` uses the binding's complete identity tuple and a
database-fixed `exact` attribution in its foreign key, so an unrelated or
non-exact binding cannot claim the exclusive active slot.

PostgreSQL `BIGINT` is signed, while the Rust contracts expose unsigned
integers. Wire-visible counters and millisecond values use domains capped at
`2^53 - 1`, matching the exact interoperable I-JSON/JCS range. JSONB is not an
RFC 8785 serialization: the adapter must validate canonical digests and reject
unsafe JSON numbers before writing the JSONB snapshots. Shared contract
vocabularies are also domains so source, environment, principal, trust,
operation, lifecycle, and runtime-identity variants cannot drift between
tables.

The adapter transactions currently implement sequential/cumulative
finalization revisions, normalized-row/ledger-fact writes, organization
sequence allocation, operation and event deduplication, lease/join state, and
the record/outbox commit boundary. The application adapter also caps a run at
256 source streams and installs bounded transaction-local PostgreSQL lock and
statement deadlines. Other child-table cardinalities and production admission
limits remain application responsibilities rather than trigger logic.

Current ingest gap discovery runs a window over the full event history for the
source stream; `LIMIT 257` bounds returned ranges but not scanned history. Novel
events are appended and inserted row by row while the organization sequence
row is locked. Incremental watermark/gap state, bounded scan work,
sequence-range reservation, bulk insertion, and load/capacity qualification
remain required before this schema path can leave the W3–W6 storage gate.

The explicit real-PostgreSQL gate runs 28 shared conformance scenarios,
including the 256-stream admission boundary, and seven targeted tests. Those
targeted tests cover repository/pool reconstruction,
post-commit/pre-ack retry, two identical-operation concurrent tasks, distinct
operation IDs racing on the same client run key with one winner and one
idempotency conflict, plaintext lease scanning, and contiguous organization
sequence plus 1:1 outbox state, and replay expiry that remains a durable
idempotency tombstone after reconstruction. The concurrency checks use
independent repositories and connection pools.

The separate real crash-recovery gate uses the production repository with
`SystemClock` and `OsRandomIdGenerator` against the pinned PostgreSQL 16 image
on one persistent volume. Data checksums, `fsync`, synchronous commit, and
full-page writes are required. The gate proves exact replay across graceful
database restart and PostgreSQL `SIGKILL` with observed WAL redo. It also kills
the application driver while a transaction is blocked before the outbox insert
can commit and after an exact run/operation/replay/lease/three-record/
three-outbox commit while a distinct client acknowledgement remains absent; the
former leaves zero scenario rows and retries as novel. The first replay process
is killed at the same pre-ack boundary, and a third process then converges on
the one committed result.
Catalog-discovered plaintext scanning, `pg_amcheck`, `pg_dump`, generated-secret
scanning, private-file mode checks, and cleanup of the dedicated container,
volume, and control directory are part of the gate.

This is not HTTPS Gateway-server recovery and does not qualify trace or HTTP
error-body secret handling. The full multiprocess/lifecycle race
matrix, sustained or capacity load, replication/failover, backup/restore, HA
behavior, production KMS integration, database roles, and RLS remain
unqualified. A successful migration or recovery-gate run is therefore still
not a production claim.

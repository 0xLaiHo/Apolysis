# PostgreSQL schema notes

`migrations/0001_gateway_ledger.sql` is the initial durable Gateway ledger
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
  response or bearer column.
- `gateway_operations` remains after replay ciphertext expires so an old
  operation identifier cannot become novel again.

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

Cross-row semantic checks that remain transaction-adapter responsibilities
rather than trigger logic include sequential/cumulative finalization revisions,
matching normalized rows to the corresponding ledger fact kind, and keeping
child-table cardinalities within the wire-contract limits. These behaviors
require the PostgreSQL conformance and concurrent-writer gates; a successful
migration alone is not a production claim.

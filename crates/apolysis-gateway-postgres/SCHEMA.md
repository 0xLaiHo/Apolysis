# PostgreSQL schema notes

`migrations/0001_gateway_ledger.sql` is the initial PostgreSQL Gateway ledger
schema. Run it only through the crate's migration runner. The SQL deliberately
does not use blanket `IF NOT EXISTS`: the runner's version/checksum table is the
repeat-execution guard, and unexpected pre-existing objects must surface as
drift.

The migration creates only the dedicated `apolysis_gateway` schema. Every
tenant-owned key and foreign key carries `organization_id`.
`deploy/bootstrap_roles.sql` and `deploy/privileges.sql` provide the reviewed
owner/runtime/control role split, but they do not provide row-level security;
organization isolation still depends on the authenticated application scope
and therefore is not a database-enforced tenant boundary.
`organization_sequences.next_ingest_sequence` is the row-lock seam for
assigning the per-organization append order.

Use a dedicated Apolysis PostgreSQL cluster and apply schema changes in this
order:

1. run `deploy/bootstrap_roles.sql` as a PostgreSQL superuser;
2. grant the migration login membership in the NOLOGIN
   `apolysis_schema_owner` role through deployment secret automation;
3. run the explicit Gateway authority `migrate` command, which uses one
   connection and `SET ROLE apolysis_schema_owner`;
4. run `deploy/privileges.sql` before starting or restarting any served
   process; and
5. grant each application login only its required NOLOGIN capability role.

Re-run `deploy/bootstrap_roles.sql` after assigning login memberships. Its
audit rejects capability combinations or delegation, indirect distribution
groups, unrelated memberships, direct or out-of-surface object authority,
served database/schema owners or DDL authority, non-origin replication-role
defaults or parameter grants, and served roles with role-management,
replication, or RLS-bypass authority. Both deployment artifacts pin their
catalog search path; served connections and transactions independently require
`session_replication_role = origin` before mutable work.

The role names are deliberately fixed. Bootstrap records the owning database
in each cluster-global role comment and rejects reuse from another database,
rather than silently sharing authority. Re-run `deploy/privileges.sql` after
every migration. The runtime repository and server connection paths never run
migrations.

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

`migrations/0003_evidence_object_lifecycle.sql` adds the separately bounded
evidence-object write registry. It binds every object to the complete
organization/run/profile/source-stream/capability/payload scope and binds an
event reference back to both the exact event and the exact object metadata.
Object integrity and lifecycle facts are separate from the S3 locator and
encrypted-key material so a completed deletion can retain a non-sensitive
tombstone without retaining recovery material. Deferred reverse foreign keys
require every lifecycle revision to commit with exactly one current outbox and
audit fact.

Database triggers use PostgreSQL wall time to enforce the active policy's
upload deadline and retention ceiling, serialize organization quota and rate
reservations, reject metadata rewrites and illegal lifecycle transitions,
snapshot registered deletion consumers, require storage-material absence and
consumer acknowledgements before deletion, and release quota only at the
terminal transition. These invariants do not replace least-privilege database
roles: a schema owner or superuser can disable enforcement and is outside the
application trust boundary.

The runtime reaper helper skips locked organizations before its bounded limit
and returns them in oldest-attempt order. The application takes one eligible
object per returned organization, preserving organization-before-object lock
order and preventing one tenant from consuming every claim slot. Failed
provider attempts remain fenced by their database-stamped attempt time; fully
purged objects with outstanding deletion acknowledgements are not candidates.

Current ingest gap discovery runs a window over the full event history for the
source stream; `LIMIT 257` bounds returned ranges but not scanned history. Novel
events reserve one contiguous organization sequence range with one row update,
then record, outbox, and evidence rows are still inserted individually while
the transaction retains the sequencing lock. Incremental watermark/gap state,
bounded scan work, bulk insertion, and load/capacity qualification remain
required before this schema path can leave the W3–W6 storage gate.

The explicit real-PostgreSQL gate runs 28 shared conformance scenarios,
including the 256-stream admission boundary, and eleven targeted tests. Those
targeted tests cover repository/pool reconstruction,
post-commit/pre-ack retry, two identical-operation concurrent tasks, distinct
operation IDs racing on the same client run key with one winner and one
idempotency conflict, plaintext lease scanning, and contiguous organization
sequence plus 1:1 outbox state, and replay expiry that remains a durable
idempotency tombstone after reconstruction. The concurrency checks use
independent repositories and connection pools.

Four additional range scenarios prove one update for a maximum batch, no
allocation for exact replay or an all-duplicate operation, novel-only allocation
for a mixed batch, disjoint contiguous concurrent reservations, and full
rollback/reuse after a real database rejection.

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

The separate two-process mTLS lifecycle-race gate now drives independent
Gateway processes and pools through a qualification-only pre-operation
barrier. It proves identical-operation replay, one winner for a shared client
run key and one-use join grant, exact runtime-identity exclusion, duplicate
event convergence, contiguous cross-run organization sequencing, finalization
convergence, terminal irreversibility, operation/replay alignment, and
record/outbox 1:1. A qualification-owned exclusive table lock is held across
the HTTP release until both runtime transactions are observed in concurrent
lock waits, so the gate does not rely only on scheduler timing. The join-grant
fixture is created through the production repository validation path rather
than direct SQL. This qualifies the bounded writer/lifecycle matrix, not
arbitrary process death or network timing.

The separate evidence-object provider gate additionally proves schema-owner
separation with distinct SCRAM logins, no startup migration,
migration-history ownership, runtime/control allowlists, and denial of owner
assumption, trigger disabling, credential reads, and direct deletion
acknowledgements. This qualifies the evidence-object served paths' process-plane
roles; it does not establish database-enforced tenant isolation.

The repository crash gate alone is not HTTPS Gateway-server recovery and does
not qualify trace or HTTP error-body secret handling. The sibling HTTPS gates
cover bounded post-commit death and two-process writer/lifecycle races, but the
broader network pre-commit/process-death matrix, mixed lifecycle/deadline
races, sustained or capacity load, replication/failover, backup/restore or
point-in-time recovery, HA behavior, production KMS integration, and tenant
RLS remain unqualified. A successful migration or gate run is therefore still
not a production claim.

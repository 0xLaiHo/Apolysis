# PostgreSQL schema notes

`migrations/0001_gateway_ledger.sql` is the initial PostgreSQL Gateway ledger
schema. Run it only through the crate's migration runner. The SQL deliberately
does not use blanket `IF NOT EXISTS`: the runner's version/checksum table is the
repeat-execution guard, and unexpected pre-existing objects must surface as
drift.

`migrations/0004_transaction_authority_binding.sql` adds append-only source
authority revision history plus credential-identifier, credential-epoch, and
policy-revision binding for lifecycle capabilities and replay. Its upgrade
path fails legacy leases and join grants closed, removes legacy replay
ciphertext while retaining operation tombstones, and grants only the reviewed
runtime/control surfaces.

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

- `leases` stores only the domain-separated SHA-256 lease digest and binds it
  to credential identifier, credential epoch, and policy revision.
- `join_authorizations` stores only the domain-separated SHA-256 proof digest
  and binds both target and issuer current authority.
- `source_authority_revisions` is append-only authority history. Initial
  registration cannot use an upsert as implicit policy or credential rotation;
  explicit rotation advances the revision/epoch and atomically invalidates live
  leases plus pending join authorization.
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

A novel lifecycle transaction follows one lock and decision order: operation
identity, current organization/registration/credential authority at initial transaction
time, retained exact operation replay, applicable
run/lease/client-run/join locks, final transaction time, second validation of
the same locked authority, expiry reconciliation, then novel mutation. The
second check includes registration/credential and authentication-snapshot
expiry after the dynamic lock wait. Exact replay exits after the initial check.
Each bounded serialization or deadlock retry starts a new transaction and
repeats both checks for novel work.

Object-reference ingest is the sole precondition exception to this
operation-first Gateway order. It first acquires the evidence-object
organization shared-ancestor lock to preserve the evidence-object cross-plane
ancestor order, then follows operation identity, current authority, and dynamic
resource locking within the Gateway plane.

Object-reference ingest reads PostgreSQL `clock_timestamp()` through
`apolysis_gateway.evidence_object_db_now_unix_ms()`; content-off ingest reads
the trusted Gateway clock passed through the repository port.

At the fresh decision point, an accepted finalization deadline is an inclusive
boundary and returns non-retryable `409 invalid_lifecycle_transition` for novel
ingest. Last-lease expiry is also inclusive and returns non-retryable
`401 lease_expired` for novel bind or ingest. The rejected operation creates no
operation row, encrypted replay, or evidence event. Finish at last-lease expiry
instead durably returns HTTP `200` with state `incomplete`, accepts no
finalization declaration, and persists one operation and replay. For either
qualified boundary outcome, expiry reconciliation commits exactly one
`incomplete` transition record and its deferred 1:1 outbox partner across
competing requests; it cannot create a second transition. A retained matching
exact operation replay is returned unchanged after the initial
current-authority check but before run and lease reconciliation.

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

The explicit real-PostgreSQL gate runs 43 shared conformance scenarios,
including the 256-stream admission boundary, and targeted tests. Those
targeted tests cover repository/pool reconstruction,
post-commit/pre-ack retry, two identical-operation concurrent tasks, distinct
operation IDs racing on the same client run key with one winner and one
idempotency conflict, plaintext lease scanning, and contiguous organization
sequence plus 1:1 outbox state, and replay expiry that remains a durable
idempotency tombstone after reconstruction. The concurrency checks use
independent repositories and connection pools.

The same disposable real-PostgreSQL gate also checks fresh and upgraded
transaction-authority schema state and covers shared-database cases including a
novel operation waiting on policy rotation, exact replay waiting on credential
rotation, authority revalidation after one SQLSTATE `40001` transaction
restart, and complete transaction restart when a deferred authority-denial
commit returns SQLSTATE `40001`. A real run-lock case proves join-grant
issuance rechecks issuer and target authority at final transaction time before
mutation, requires the grant expiry to remain in the future, and stores that
final time as `issued_at_unix_ms`. A separate control-plane gate qualifies
monotonic atomic policy/credential cutovers; the direct-mTLS gate qualifies
old/new certificate, lease, replay, and stream behavior.

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

The sibling real direct-mTLS HTTPS crash gate adds one bounded late-precommit
column for accepted novel `open_run`, `bind_runtime`, `ingest`, and `finish_run`
requests. It installs a disposable ordinary, non-deferred `AFTER INSERT`
trigger on `operation_replays`, the final repository write. For only the target
client operation, the trigger advances a nontransactional sequence and waits on
a held advisory lock. The driver proves the runtime session is blocked by that
known holder, the client remains response-silent, and a separate database
session sees neither the target operation nor replay. The captured
logical organization-scoped repository-state fingerprint is checked after
Gateway `SIGKILL` and runtime-session closure and must match its pre-request
baseline. The killed client must observe HTTP `000` without a header or body.
The independently committed mTLS admission audit is outside that transaction
fingerprint and must advance by exactly one from its baseline count. The
trigger, helper schema, and sequence are qualification-owned objects removed
after each route, not migration state.
The same signed request then enters the sibling post-commit/pre-ack novel and
exact-replay crash column before a normal server proves exact convergence.

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

The split-clock mixed lifecycle sibling uses the same independent Gateway
processes, pools, private release, and observed database-lock overlap for
transaction-wait cases. A qualification-owned late-write trigger raises
SQLSTATE `40001` once for the target novel operation to exercise a real
internal retry. Five operation/boundary scenarios run through both the
transaction-wait and internal-retry modes, for ten qualified cells: join at the
finalization deadline, bind at last-lease expiry, ingest at the finalization
deadline, ingest at last-lease expiry, and finish at last-lease expiry. For the
four join/bind/ingest scenarios, the oracle requires one unchanged stored
replay result, no state for the rejected novel operation, and exactly one
`incomplete` record/outbox pair. Finish instead converges on a durable HTTP
`200` result with state `incomplete`: two identical requests produce one novel
result and one exact replay, while the retry variant raises one late SQLSTATE
`40001`, restarts at the inclusive expiry, and retains a stable exact replay.
Both finish modes leave finalization declarations, terminal positions, and
outcome claims absent and commit exactly one `active -> incomplete` transition.
Exact replay performs the initial authority check only; novel work revalidates
the same locked authority at final transaction time after its dynamic lock
wait.

A real-PostgreSQL repository test and a sibling direct-mTLS HTTPS qualification
cover exact replay for `open_run`, `bind_runtime`, `ingest`, and `finish_run`
across replay-TTL expiry while waiting for the exact operation row lock. Each
live route first has two byte-stable positive controls at expiry minus one
millisecond, with replay expiry inside current registration and credential
validity. The qualification then corrupts only retained replay ciphertext,
holds that route's exact operation row, proves the runtime transaction is
blocked by the exact holder, advances its private transaction clock only after
the waiter exists, and releases the holder at inclusive TTL expiry. Expiry is
therefore evaluated before decryption: every route produces a non-retryable
`409` `idempotency_conflict`, with `Cache-Control: no-store`, no retry hint, and
no response bytes before release. The 20-table lifecycle fingerprint and
operation/replay cardinality remain unchanged; the transport attempt adds
exactly one admission-audit row. The v0.1 adapter samples transaction time once
after the wait. The loopback, same-UID, `0600` time-advance file is
qualification-only and production configuration rejects it.
The monotonic interval from pre-operation release through confirmed holder
termination must remain below 1.2 seconds against the production two-second
lock timeout.

The separate evidence-object provider gate additionally proves schema-owner
separation with distinct SCRAM logins, no startup migration,
migration-history ownership, runtime/control allowlists, and denial of owner
assumption, trigger disabling, credential reads, and direct deletion
acknowledgements. This qualifies the evidence-object served paths' process-plane
roles; it does not establish database-enforced tenant isolation.

The repository crash gate alone is not HTTPS Gateway-server recovery and does
not qualify trace or HTTP error-body secret handling. The sibling HTTPS
qualifications cover one accepted-novel late-precommit rollback seam, bounded
post-commit death, two-process writer/lifecycle races, and the listed
join/bind/ingest/finish deadline/expiry transaction decisions. The sibling
direct-mTLS HTTPS qualification covers the four-route replay-TTL operation-lock
race above. These gates also do not qualify the remaining earlier or arbitrary
network pre-commit/process-death timings, pre-commit exact-replay or rejection branches,
completion of the final `INSERT` statement, entry into `COMMIT`, physical or
WAL commit timing, the remaining mixed lifecycle/retry matrix,
commit-wall-clock enforcement, live join-grant expiry or join at last-lease
expiry, broader staggered multi-lease behavior, additional retry depths or live
SQLSTATE `40P01` fault coverage, sustained or capacity load,
replication/failover, backup/restore or point-in-time recovery, HA behavior,
production KMS integration, or tenant RLS.
The separate authority gates qualify only the bounded current-authority and
rotation slice described above. A successful migration or gate run is
therefore still not a production claim.

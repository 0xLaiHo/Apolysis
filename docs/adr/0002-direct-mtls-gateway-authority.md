# Require direct mTLS and current PostgreSQL authority for Gateway writes

Status: accepted

The Gateway write listener requires a client certificate issued by its
configured CA. It derives a domain-separated SHA-256 fingerprint from the
verified leaf DER certificate and resolves the current organization,
principal, source registration, policy revision, credential epoch, validity,
and revocation state from PostgreSQL for every recognized lifecycle HTTP
request. Certificate
subjects and SANs are descriptive only; request bodies and headers cannot
assert authority. Authority-looking headers are rejected, and the resulting
`AuthenticatedSourceContext` remains a server-only input with no wire
serialization.

Its `AuthenticationSnapshot` binds the credential identifier, credential
epoch, and policy revision. The snapshot records the transport decision; it is
not a lease and cannot by itself authorize later database work.

The listener terminates TLS itself, has no browser CORS or cookie surface, and
is separate from the future Query API. A deployment that terminates TLS at a
proxy will require a later, explicitly authenticated proxy-hop profile; plain
forwarded-certificate headers are not trusted. Gateway responses are
`no-store`, and raw request or response bodies are not access-log material
because the frozen v0.1 contract carries bearer lease material in JSON.

This decision establishes direct mTLS as the first production transport
profile without making it the only future credential profile. Sender-bound
JWT or workload identity may be added behind the same current-authority seam.
All PostgreSQL Gateway migrations remain in one ordered migration set so
restart validation cannot observe split migration histories.

The first implementation now exposes all four frozen lifecycle routes:
`open-run`, `bind-runtime`, `ingest`, and `finish-run`. Its real tracer proves
TLS identity, current PostgreSQL lookup, cross-organization rejection,
credential revocation on every route, durable exact replay, and continuation
across Gateway-process restarts. The same live gate now also exercises explicit
policy and credential rotation with old and replacement client certificates,
stale leases and replay, and the required new source stream.

A sibling real direct-mTLS HTTPS qualification gate now fixes two bounded
server-death columns for all four routes. First, it sends each accepted novel
request through the normal production listener, authority, application, and
repository paths. A qualification-owned ordinary, non-deferred `AFTER INSERT`
trigger targets only that client's `operation_replays` insertion, the
repository's final write. The trigger advances a nontransactional sequence and
then waits on an advisory lock. `pg_stat_activity` must show the runtime session
blocked by the known holder while loopback `curl` remains response-silent. A
separate session must see no target operation/replay. External `SIGKILL` must
leave loopback `curl` at HTTP `000` with no header or body. After every runtime
database session closes, the logical organization-scoped repository-state
fingerprint must match its pre-request baseline. The independently committed
mTLS admission audit is excluded from that fingerprint and its count must be
exactly one above the baseline.

The gate then reuses the same signed request at the existing
post-commit/pre-ack boundary. It exercises each novel success and exact replay
through the same production paths. After the database commit and complete HTTP
response construction, but before the handler returns the response to Axum, a
feature-gated qualification-only binary writes one static marker to a private
mode-`0600` file and waits. The gate externally sends `SIGKILL`; loopback
`curl` must report HTTP `000` and receive no header or body. Database inspection
then proves the operation, encrypted replay, and expected ledger/outbox effects
exist exactly once. It also records an encrypted replay fingerprint and
requires it to remain unchanged when the exact-replay server is killed at the
same boundary. A third normal production server must return the exact durable
result and allow the lifecycle to continue.

Neither seam is a production control surface. The late-precommit trigger,
helper schema, and sequence are disposable qualification objects installed in
and removed from the dedicated database; they are not migrations. The response
barrier is compiled only for the separate qualification binary, accepts only an
ephemeral loopback listener and a private local marker, and has no request,
header, environment, or normal production-CLI input capable of arming it. The
production CLI rejects the qualification options. Neither the production CLI
nor remote input can install or configure the late-precommit database objects.

A second qualification-only mode places a bounded barrier after mTLS authority
resolution and request decoding but before the application call. Two
independent Gateway processes, listeners, and PostgreSQL pools each write a
private static marker, remain response-silent and free of lifecycle mutations,
and proceed only after the driver atomically publishes one private static
release file. Current-authority audit writes may already have committed before
the marker; the pre-release oracle is specifically the absence of both client
operation identities from lifecycle state.

The driver then holds a qualification-owned exclusive operation-table lock,
releases both HTTP barriers, observes both runtime transactions waiting on
database locks, and only then releases the blocker. The real gate qualifies
identical and competing run creation, one-use join-grant consumption,
cross-run exact runtime-identity exclusion, duplicate and cross-run ingest
sequencing, identical and competing finalization, and terminal irreversibility.
A separate feature-gated local helper seeds the join grant through the
production repository validation path; no remote management endpoint is added.
Stale, symlinked, non-private, modified, or missing release files fail closed,
and the normal production binary rejects every qualification option.

The bounded mixed lifecycle/deadline qualification composes that pre-operation
barrier with one feature-gated split clock shared by the Gateway application
and its current-authority lookup. It separates the driver-selected,
I-JSON-safe admission instant from the fresh lifecycle-decision instant and
can advance the latter only after the first transaction attempt. The clock is
accepted only by the qualification binary on an ephemeral `127.0.0.1:0`
listener. The production CLI rejects the option, and no remote request,
header, or body can arm the barrier or select the clock. This is a
qualification determinism seam, not a production clock override.

`make test-gateway-mixed-lifecycle-deadline-races` starts two independent
Gateway processes, listeners, and PostgreSQL pools for each scenario. It holds
the same qualification-owned exclusive operation-table lock while releasing
both private barriers, and uses `pg_stat_activity` to prove both transactions
overlap in database lock waits before releasing the blocker. A
qualification-owned late write trigger raises SQLSTATE `40001` exactly once
for the internal-retry variants. The database oracle covers five
operation/boundary cases, each through a transaction wait and one real
internal retry, for ten matrix cells:

1. At an accepted finalization deadline, an exact replay of a join accepted
   before the deadline returns its unchanged stored result, while a novel join
   returns `409 invalid_lifecycle_transition`, leaves its independent grant
   reusable, and lazily commits the single `finishing -> incomplete`
   transition.
2. At the requested last lease's expiry, an exact replay of a bind accepted
   before expiry returns its unchanged stored result, while a novel bind
   returns `401 lease_expired` and lazily commits the single
   `active -> incomplete` transition.
3. At an accepted finalization deadline, an exact replay of an ingest accepted
   before the deadline returns its unchanged stored result, while a novel
   ingest returns `409 invalid_lifecycle_transition` and lazily commits the
   single `finishing -> incomplete` transition.
4. At the requested last lease's expiry, an exact replay of an ingest accepted
   before expiry returns its unchanged stored result, while a novel ingest
   returns `401 lease_expired` and lazily commits the single
   `active -> incomplete` transition.
5. At the requested last lease's expiry, finish converges on a durable HTTP
   `200` result with state `incomplete`, no finalization declaration, and one
   `active -> incomplete` transition. Two identical waiting requests produce
   one novel result and one exact replay. The retry variant raises one late
   SQLSTATE `40001`, restarts at the inclusive expiry, returns the novel
   durable result, and preserves a stable exact replay.

For the first four cases, the accepted operation and encrypted replay remain
exactly once and unchanged, while the rejected novel operation creates no
operation, replay, stream, lease, binding, or evidence-event effect. In the
finish case, the novel result creates exactly one operation and encrypted
replay, and the exact retry returns that stored result. Across all five cases,
the lifecycle transition and its outbox effect occur exactly once, and neither
competing request can revive the run. Finish additionally leaves finalization
terminal positions and outcome claims absent.

The transaction-boundary extension makes request arrival and transaction begin
explicitly non-authoritative for every lifecycle operation. Each transaction
attempt locks the operation identity, then locks the current organization,
source registration, and transport credential and revalidates them at an
initial transaction time. Only after that check may it materialize and return
matching exact replay. Novel join then
locks the run and join authorization; novel bind, ingest, and finish lock the
run and requested lease, while create mode may wait on the client-run identity.
After those dynamic lock waits, the adapter samples final transaction time and
revalidates the same locked organization, registration, and credential,
including registration/credential validity and authentication-snapshot expiry.
Only then may it reconcile deadline or last-lease expiry and admit novel work.
Exact replay performs only the initial current-authority check. An internal
PostgreSQL serialization or deadlock retry repeats the full two-check order for
novel work and reads time again.

Object-reference ingest is the sole precondition exception to this
operation-first Gateway order: it first takes the evidence-object organization
shared-ancestor lock to preserve the evidence-object cross-plane ancestor
order, then resumes the same operation-identity, current-authority, and dynamic
resource order inside the Gateway plane.

Object-reference ingest uses PostgreSQL `clock_timestamp()` through the
schema-owned database-time function; content-off ingest, join, bind, and finish
use the trusted Gateway clock passed to the repository.

Join-authorization freshness is evaluated before lifecycle reconciliation; an
authorization that expires at the fresh decision time returns
`404 not_found` without being consumed. For otherwise eligible novel
join/bind/ingest work, crossing an accepted finalization deadline returns
`409 invalid_lifecycle_transition`; novel bind or ingest crossing the requested
lease's expiry without an elapsed deadline returns `401 lease_expired`. Both
lifecycle errors are non-retryable. Finish at last-lease expiry instead follows
the durable `200`/`incomplete` convergence described above. Once deadline
reconciliation seals a run, later novel lifecycle work remains a `409`
lifecycle rejection rather than degrading to a lease error after the deadline
field is cleared. The first last-lease reconciliation of an active run without
an elapsed deadline remains `401` for bind or ingest. Those rejection paths
create no novel operation, encrypted replay, stream, lease, binding, or
evidence event. Finish creates one operation and replay but no finalization
declaration. The only durable lifecycle-reconciliation effect is exactly one
transition to `incomplete` and its matching record/outbox pair across competing
requests. Exact stored-operation replay remains prior to dynamic reconciliation
but after initial current-authority revalidation, and returns the unchanged
result. Shared memory and real-PostgreSQL conformance
additionally cover join-grant expiry, join at last-lease expiry, zero or
regressed transaction time, and one staggered requested-lease bind while
another lease remains live.

Operations, encrypted replay records, leases, and join authorization retain
the credential-identifier, credential-epoch, and policy-revision binding. Join
authorization binds both the target source and its issuer. A superseded
successful operation remains an idempotency tombstone, but its encrypted replay
cannot be opened and returned under stale authority.

Registration is initial enrollment or exact idempotent confirmation, not an
implicit update path. Explicit `rotate-policy` and `rotate-credential`
operations serialize organization, registration, and credential changes,
append authority history, update current authority, revoke live leases and
pending join authorization, and record content-free audit evidence in one
transaction. Policy rotation advances the policy revision. Credential rotation
advances the epoch, retires the old certificate, and may retain the policy or
advance it once.

Shared real-PostgreSQL qualification covers a novel request blocked behind
policy rotation, exact replay blocked behind credential rotation,
current-authority revalidation after one SQLSTATE `40001` transaction restart,
and complete transaction restart when a deferred authority-denial commit
returns SQLSTATE `40001`. Join-grant issuance waiting on a run lock resamples
final transaction time, rechecks issuer and target authority before mutation,
requires expiry after that time, and records that time as
`issued_at_unix_ms`. The direct-mTLS gate covers live policy and certificate
cutover, rejection of old leases and replay, rejection of the old certificate,
admission of the replacement certificate at the new epoch, and creation of a
new stream.

A real-PostgreSQL repository test and a sibling direct-mTLS HTTPS qualification
cover all four lifecycle routes when exact replay waits for its exact operation
row lock across replay-TTL expiry. Each live route first proves two byte-stable
positive controls at expiry minus one millisecond while the replay remains
inside current registration and credential validity. The qualification corrupts
only retained replay ciphertext, proves the runtime transaction is waiting on
the exact holder, advances a private transaction clock only after that waiter
exists, and releases the holder at inclusive expiry. Expiry is therefore
evaluated before decryption: every route produces a non-retryable `409`
`idempotency_conflict`, `Cache-Control: no-store`, no retry hint, and no
response bytes before release. The 20-table lifecycle fingerprint and
operation/replay cardinality remain unchanged; the accepted transport attempt
adds exactly one admission-audit row. The v0.1 adapter samples time once after
the lock wait. The loopback, same-UID, `0600` time control exists only in the
qualification build; production configuration rejects it.
The monotonic interval from pre-operation release through confirmed holder
termination must remain below 1.2 seconds, preserving explicit margin under the
production two-second lock timeout.

This still does not close the W3–W6 transport gate. Sender-bound JWT/workload
identity profiles, the remaining earlier or arbitrary network
pre-commit/process-death fault timings, pre-commit exact-replay or rejection
branches, completion of the final `INSERT` statement, entry into `COMMIT`,
physical or WAL commit timing, commit-wall-clock boundary enforcement, live
join-grant-expiry and join-at-last-lease-expiry cases,
broader staggered multi-lease combinations, additional retry depths and live
SQLSTATE `40P01` fault coverage, the remaining mixed lifecycle/retry matrix,
load/capacity qualification, authorized object-read resolution and downstream
deletion propagation, production KMS and tenant RLS integration,
replication/failover/recovery, HA, quotas, and rate limits remain required.

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
across Gateway-process restarts.

A sibling real direct-mTLS HTTPS qualification gate now fixes the
post-commit/pre-ack server-death boundary for all four routes. It exercises each
novel success and exact replay through the production listener, authority,
application, and repository paths. After the database commit and complete HTTP
response construction, but before the handler returns the response to Axum, a
feature-gated qualification-only binary writes one static marker to a private
mode-`0600` file and waits. The gate externally sends `SIGKILL`; loopback
`curl` must report HTTP `000` and receive no header or body. Database inspection
then proves the operation, encrypted replay, and expected ledger/outbox effects
exist exactly once. It also records an encrypted replay fingerprint and
requires it to remain unchanged when the exact-replay server is killed at the
same boundary. A third normal production server must return
the exact durable result and allow the lifecycle to continue.

The response barrier is not a production control surface. It is compiled only
for the separate qualification binary, accepts only an ephemeral loopback
listener and a private local marker, and has no request, header, environment, or
normal production-CLI input capable of arming it. The production CLI rejects
the qualification options.

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
for the internal-retry variants. The database oracle covers four
operation/boundary cases, each through a transaction wait and one real
internal retry:

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

For each case, the accepted operation and encrypted replay remain exactly once
and unchanged; the rejected novel operation creates no operation, replay,
stream, lease, binding, or evidence-event effect; the lifecycle transition and
its outbox effect occur exactly once; and neither competing request can revive
the run.

The transaction-boundary extension makes request arrival and transaction begin
explicitly non-authoritative for novel join, bind, and ingest admission. Each
transaction attempt locks the operation identity and returns a retained
matching exact replay when present. Novel join then locks the run and join
authorization; novel bind and ingest lock the run and requested lease. Only
after those reads does the adapter sample fresh transaction time, reconcile
deadline or last-lease expiry, and admit novel work. An internal PostgreSQL
serialization or deadlock retry repeats the full order and reads time again.
Object-reference ingest uses PostgreSQL `clock_timestamp()` through the
schema-owned database-time function; content-off ingest, join, and bind use the
trusted Gateway clock passed to the repository.

Join-authorization freshness is evaluated before lifecycle reconciliation; an
authorization that expires at the fresh decision time returns
`404 not_found` without being consumed. For otherwise eligible work, crossing
an accepted finalization deadline returns
`409 invalid_lifecycle_transition`; crossing the requested lease's expiry
without an elapsed deadline returns `401 lease_expired`. Both lifecycle errors
are non-retryable. Once deadline reconciliation seals a run, later novel
lifecycle work remains a `409` lifecycle rejection rather than degrading to a
lease error after the deadline field is cleared. The first last-lease
reconciliation of an active run without an elapsed deadline remains `401`.
Neither path creates a novel operation, encrypted replay, stream, lease,
binding, or evidence event. The only durable rejection effect is exactly one
transition to `incomplete` and its matching record/outbox pair across competing
requests. Exact stored-operation replay remains prior to dynamic reconciliation
and returns the unchanged result. Shared memory and real-PostgreSQL conformance
additionally cover join-grant expiry, join at last-lease expiry, zero or
regressed transaction time, and one staggered requested-lease bind while
another lease remains live.

This still does not close the W3–W6 transport gate. Transaction-time authority
revalidation, credential-epoch binding in leases and replay records,
policy/credential rotation, the broader network pre-commit/process-death fault
matrix, commit-wall-clock boundary enforcement, replay-TTL expiry during an
operation-lock wait, live join-grant-expiry and join-at-last-lease-expiry
cases, broader staggered multi-lease combinations and retry depths, the
remaining mixed lifecycle/retry matrix, load/capacity qualification, authorized
object-read resolution and downstream deletion propagation, production KMS and
tenant RLS integration, replication/failover/recovery, HA, quotas, and rate
limits remain required.

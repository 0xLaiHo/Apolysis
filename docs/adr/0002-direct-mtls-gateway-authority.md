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

This still does not close the W3–W6 transport gate. Transaction-time authority
revalidation, credential-epoch binding in leases and replay records,
policy/credential rotation, the broader network pre-commit/process-death fault
matrix, mixed lifecycle/deadline races, load/capacity qualification, authorized
object-read resolution and downstream deletion propagation, production KMS and
tenant RLS integration, replication/failover/recovery, HA, quotas, and rate
limits remain required.

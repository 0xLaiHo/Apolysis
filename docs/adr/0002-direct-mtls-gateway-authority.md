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
across Gateway-process restarts. It still does not close the W3–W6 transport
gate. Transaction-time authority revalidation, credential-epoch binding in
leases and replay records, policy/credential rotation, post-commit/pre-ack
crash qualification, quotas, and rate limits remain required.

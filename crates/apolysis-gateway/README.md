# `apolysis-gateway`

`apolysis-gateway` is the transport-independent application core for the
Execution Evidence Gateway contract. It accepts a caller-injected
`AuthenticatedSourceContext` and implements `open_run`, `bind_runtime`,
`ingest`, and `finish_run` over the narrow `GatewayRepository` transaction
port.

The crate currently includes:

- authorization against organization and source-registration policy, scoped
  hashed leases, and server-side join grants or registration policies;
- immutable run-policy and source-registration append facts, with effective
  trust, authenticated principal, and policy revision frozen per source
  stream, plus server-accepted runtime-binding provenance;
- RFC 8785 request, inline-payload, and source-manifest digest construction;
- bounded run finishing with immutable terminal declarations and explicit
  `finished` or `incomplete` sealing;
- a repository clock port that distinguishes request admission time from fresh
  ingest transaction-decision time; and
- `MemoryGatewayRepository`, a non-durable conformance adapter that models
  atomic record append, deduplication, ingest sequencing, and projection-outbox
  mutation.

`MemoryGatewayRepository` is not a deployable production Gateway. It provides
no persistence or cross-process guarantees. The sibling
`apolysis-gateway-postgres` crate is an initial PostgreSQL write-adapter
prototype for the same transaction seam; see its README for its narrower
verified boundary.

The application contract and both adapters enforce a run-wide cap of 256
source streams. The PostgreSQL adapter additionally installs bounded,
transaction-local lock and statement deadlines.

For production PostgreSQL ingest, each transaction attempt locks the operation
identity, returns a retained exact operation replay before dynamic
reconciliation, locks the run and lease, reads fresh trusted transaction time,
reconciles deadline or last-lease expiry, and only then admits a novel
mutation. Every internal serialization or deadlock retry repeats that order and
reads time again. Content-off ingest uses the trusted Gateway clock; the
PostgreSQL object-reference path uses database `clock_timestamp()`.

At that decision point, crossing an accepted finalization deadline produces
non-retryable `409 invalid_lifecycle_transition`; crossing the last lease's
expiry produces non-retryable `401 lease_expired`. A rejected novel request
creates no operation, encrypted replay, or evidence event. Lazy reconciliation
commits exactly one `incomplete` transition and its matching record/outbox pair
across competing requests. A retained exact operation replay returns its
unchanged result first.

Neither adapter supplies network transport, transport-level authentication,
live credential revocation, object-store resolution, background deadline or
replay cleanup, broader production admission limits, durable projection, or a
Query service. Expired active or finishing runs are reconciled only when a
later novel lifecycle command reaches the application core. The qualified
ingest decision does not claim commit-wall-clock enforcement, replay-TTL
expiry across an operation-lock wait, novel join/bind behavior, staggered
multi-lease behavior, or transaction-time authority freshness and rotation.

Run the crate gates with:

```bash
cargo test -p apolysis-gateway
cargo test -p apolysis-gateway --test gateway_conformance
cargo test -p apolysis-gateway --test digest_vectors
```

Run the shared suite plus the targeted real-PostgreSQL checks with the explicit
Docker-backed gate documented by `apolysis-gateway-postgres`.

The normative lifecycle and claim boundaries live in
[`docs/contracts/gateway-lifecycle-v0.1.md`](../../docs/contracts/gateway-lifecycle-v0.1.md).

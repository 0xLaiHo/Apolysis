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
  `finished` or `incomplete` sealing; and
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

Neither adapter supplies network transport, transport-level authentication,
live credential revocation, object-store resolution, background deadline or
replay cleanup, broader production admission limits, durable projection, or a
Query service. Expired active or finishing runs are reconciled only when a
later novel lifecycle command reaches the application core.

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

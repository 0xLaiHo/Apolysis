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

The memory adapter is not a deployable production Gateway. It provides no
PostgreSQL durability, restart recovery, crash or concurrent-writer guarantees,
network transport, transport-level authentication, live credential revocation,
object-store resolution, background deadline reaping, or production rate and
request-size enforcement. Expired active or finishing runs are reconciled only
when a later novel lifecycle command reaches the application core. Its
exact-replay lease response exists only in process memory; the PostgreSQL
adapter must use a hashed lookup key and separately KMS or envelope-encrypted,
TTL-bound replay material instead of plaintext bearer values.

Run the crate gates with:

```bash
cargo test -p apolysis-gateway
cargo test -p apolysis-gateway --test gateway_conformance
cargo test -p apolysis-gateway --test digest_vectors
```

The normative lifecycle and claim boundaries live in
[`docs/contracts/gateway-lifecycle-v0.1.md`](../../docs/contracts/gateway-lifecycle-v0.1.md).

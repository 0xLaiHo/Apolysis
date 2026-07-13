# W1–W2 Contract Set

Status: normative W1–W2 contract. The active Gateway foundation slice includes
an application core and a non-durable reference adapter, not a production
Gateway service.

These documents freeze the W1–W2 product and evidence contract. The independent
machine types, schemas, and fixtures live in `apolysis-contracts`. The
current `pre-release` implementation now applies the Gateway types in an
authenticated application core and an in-memory conformance adapter. The
remaining contracts describe what durable Gateway storage, projection, Query
API, and Console implementations must do without claiming those production
runtime components exist.

Read the contracts in this order:

1. [Scope and environment profiles](w1-w2-scope.md)
2. [Privacy boundary and defaults](privacy-boundary.md)
3. [Agent Execution Record v0.1 semantics](agent-execution-record-v0.1.md)
4. [Execution Evidence Gateway lifecycle v0.1](gateway-lifecycle-v0.1.md)
5. [Minimum Console v0 information architecture](console-v0.md)
6. [Design-partner validation and approval template](design-partner-validation.md)

The repository [domain glossary](../../CONTEXT.md) defines canonical terms.
The [production-contract boundary ADR](../adr/0001-independent-production-contracts.md)
records why these types are independent from legacy JSONL.
The independent `apolysis-contracts` crate owns shared machine types and
versioned schemas; legacy JSONL v1 remains an edge adapter format rather than a
Gateway or Query schema. Schemas and fixtures are authoritative for machine
validation; this set is authoritative for product meaning and claim boundaries.
A schema that permits a state forbidden here is a contract defect, not
permission to make the broader claim.

## Machine artifacts

- Rust wire types: `crates/apolysis-contracts/src/`
- Gateway application core and non-durable reference adapter:
  `crates/apolysis-gateway/src/`
- Gateway conformance and RFC 8785 golden-vector tests:
  `crates/apolysis-gateway/tests/`
- Generated JSON Schema: `schemas/contracts/v0.1/`
- Positive and negative compatibility fixtures:
  `crates/apolysis-contracts/tests/fixtures/`

Regenerate schemas after an intentional contract change:

```bash
cargo run -p apolysis-contracts --bin export_schemas
cargo test -p apolysis-contracts --test schema_snapshots
```

The snapshot test fails when committed schemas drift from the Rust roots. It
also locks critical source-envelope exclusivity, source ordering, integrity,
and bounded ingest constraints.

## Compatibility rule

The `v0.1` record and lifecycle contracts may be refined during W1–W2, but a
merged incompatible change must update all affected schemas, fixtures, and
contract documents in the same Pull Request. After the W1–W2 exit gate, an
incompatible wire change requires a new version.

## Current implementation boundary

The current code provides local CLI, daemon, JSONL, Codex intent,
accountability, runtime metadata, and Linux observation paths. The
`pre-release` implementation line also provides the four-operation Gateway
application core, server-side join grant/policy checks, RFC 8785 request and
inline-payload golden vectors, bounded lifecycle reconciliation, and a
non-durable memory adapter. The adapter models atomic record append,
deduplication, ingest sequencing, and projection-outbox mutation for conformance
testing.

This is not a production Gateway and does not complete W3–W6. There is no
PostgreSQL durability, restart recovery, or concurrency validation; network
transport or live credential revocation; object-store resolver; background
deadline reaper; or production rate and request-size enforcement. The
organization-scoped Query API, versioned projectors, and Web Console specified
here are also not implemented.

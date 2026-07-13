<!-- SPDX-License-Identifier: Apache-2.0 -->

# PostgreSQL run projection

`apolysis-projection-postgres` is the durable, rebuildable PostgreSQL
projection foundation for the Agent Run lifecycle. It consumes the ordered
`apolysis_gateway.record_items` ledger and its exactly paired
`projection_outbox` rows, then maintains an organization-scoped internal read
model.

This crate is intentionally narrower than a Query service or Console backend.
Its read model contains only the run header and lifecycle state needed to prove
ordered projection, durable restart, bounded traversal, and generation
cutover. See [SCHEMA.md](SCHEMA.md) for the database invariants.

## What it does

`PostgresRunProjection` owns the following operations:

- initialize one active generation for an organization;
- project the next strictly contiguous, bounded input batch;
- record an exact commit chain and checkpoint without advancing past invalid
  or missing input;
- publish an active generation's matching Gateway outbox rows in the same
  transaction as its projection commit;
- rebuild a new organization-local generation from input zero while the old
  generation remains active;
- atomically retire the old generation and activate a caught-up rebuild;
- load one active lifecycle row, list active lifecycle membership with a
  bounded internal keyset cursor, and inspect projection status.

Every generation is qualified by `(organization_id, generation_id)`. A
generation identifier alone is not a tenant identity. PostgreSQL constraints
permit at most one active and one building generation per organization.

The lifecycle read model currently contains:

- authority, principal, objective, environment, and policy-profile references;
- current lifecycle state and lifecycle revision;
- opening, latest state-change, and terminal timestamps;
- the opening and latest lifecycle ingest sequences;
- generation and computation-version provenance.

Non-lifecycle facts are validated and consumed in order, but they only require
that the run already exists. They do not create coverage, finding, source
health, or evidence-object views.

## Input integrity and ordering

Projection order comes from the Gateway's organization-local
`ingest_sequence`, not from wall-clock timestamps. A wall clock may move
backward: the projector accepts a valid lifecycle transition whose
`recorded_at_unix_ms` is earlier than a prior timestamp and still applies it in
ingest order. Timestamps describe recorded wall time; they are not the causal
ordering key.

Before applying a row, the projector:

1. requires the expected record/outbox identity and exact next sequence;
2. measures PostgreSQL's logical JSON text length and rejects a value above the
   one-MiB projection bound before returning that JSON to the Rust client; this
   deliberately does not trust TOAST-compressed physical storage size;
3. checks I-JSON-compatible numeric bounds and canonicalizes the JSON value
   with the JSON Canonicalization Scheme (JCS);
4. recomputes SHA-256 and compares it with the stored fact digest;
5. deserializes the value into `AgentExecutionRecordItem`, serializes that typed
   value canonically again, and requires byte-for-byte equality;
6. checks redundant organization, run, sequence, time, schema, fact-kind,
   topic, and typed lifecycle metadata.

Unknown fields, invalid typed contracts, metadata drift, digest mismatches,
missing input, illegal lifecycle transitions, and incompatible outbox state
block only that generation's checkpoint. The failure class and failed sequence
are persisted without copying fact content into the public error.

The stored fact digest and per-batch digest are unkeyed SHA-256 values. They
support deterministic reconstruction and corruption detection, but they are
not signatures, MACs, or tamper-proof anchors against an actor that can rewrite
the database and recompute digests.

## Active projection, rebuild, and outbox publication

An active generation accepts only `pending` outbox input. It updates the read
model, inserts the projection commit, advances the checkpoint and visible
watermark, and changes the exact outbox range to `published` in one
transaction. A failed transaction exposes none of those partial changes.
Transient failures before commit may be retried within the configured bound.
A transport/protocol loss, connection-class SQLSTATE, or explicit statement-
completion-unknown result while awaiting batch or cutover `COMMIT` returns the
content-free, non-retryable `CommitOutcomeUnknown` class. A received definitive
database rejection remains an ordinary rolled-back database failure. After an
unknown result, the worker must reload the durable generation status and
reconcile its checkpoint or active head before scheduling another operation;
the same call never blindly advances a second batch.

A building generation replays the immutable record/outbox identity join while
ignoring mutable delivery state. This lets it rebuild from rows already marked
`published`; it neither republishes those rows nor changes the active query
head while building. Cutover requires the candidate to be healthy and caught
up to a locked organization source watermark. It then publishes any still
pending rows through that watermark, retires the previous generation,
activates the candidate, and moves the organization head atomically.

## Internal cursor semantics

`LifecycleCursor` is an in-process, generation-bound keyset position. It is not
an encoded, authenticated, or externally stable Query API token.

- Page size is limited to 200 rows.
- Ordering is `opened_at_unix_ms DESC, run_id ASC`.
- The cursor records the organization, active generation, visible input
  watermark, and last keyset position.
- The watermark freezes membership by requiring
  `opened_ingest_sequence <= visible_input_watermark`. Runs opened later do not
  enter an existing traversal.
- The cursor does **not** freeze every field of an already included run. A later
  lifecycle transition may be visible on a subsequent page. A future Query
  layer needs row versioning to promise a full as-of snapshot.
- A cursor from another organization returns `NotFound`; a cursor from a
  retired generation expires at cutover.

## RLS trust boundary

The migration enables and forces organization-scoped row-level security on
the projection data tables. Each repository transaction sets the
transaction-local `apolysis.organization_id` setting before accessing them.
With an ordinary `NOBYPASSRLS` runtime role, an unset setting exposes no rows
and a set value limits rows to that organization.

RLS here is defense in depth for a trusted application, not authorization. A
caller that can execute arbitrary SQL can set the same GUC to another
organization. The migration deliberately creates no production roles and
grants no runtime privileges. Deployment of constrained roles, connection
separation, and caller authorization in the Query service remain required.

## Verification

The Rust unit suite covers bounded identifiers/configuration and stored-row
validation without a database:

```bash
cargo test -p apolysis-projection-postgres
```

The real PostgreSQL integration tests are ignored by the default suite because
they migrate and truncate their database. They fail closed unless a private
`0600` URL file identifies the loopback database created by the repository
gate and that database contains the matching gate-owned sentinel. Supplying an
arbitrary PostgreSQL URL is intentionally unsupported. Run them only through:

```bash
make test-projection-postgres
```

That gate uses a disposable, digest-pinned real PostgreSQL server, runs the
ignored tests against genuine Gateway writes produced with the production
system clock and operating-system CSPRNG identity source, exercises two
organizations, concurrent independent pools, poison-input isolation, bounded
pagination, RLS scoping, from-zero rebuild and cutover, suppressed durable
commit responses, TOAST-compressed oversized input, and deterministic lock
races. The included process driver verifies death before commit and after
commit but before acknowledgement, four-process convergence, graceful restart,
`SIGKILL`/WAL redo, a real post-recovery write with WAL-position advance,
`pg_amcheck`, clean dump/restore with another write, and raw plus bytea-hex
bearer scans. The gate binds random loopback ports, generates test-only
credentials without printing them, and removes its exact containers, volumes,
and temporary files. The current branch passed this gate on 2026-07-14. That
branch result does not replace CI for a later revision or expand the explicit
nonclaims below.

## Explicit nonclaims

This crate does **not** provide:

- a full Console or Run Explorer;
- Query authorization, an external pagination token, or SSE/change streaming;
- coverage, findings, evidence inventory, or source-health projections;
- evidence-object storage, resolution, retention, deletion, or reaping;
- production RLS role/grant deployment or an authorization boundary;
- PostgreSQL replication, failover, multiprocess service orchestration, or HA
  qualification.

Those capabilities must build on this foundation without weakening its
organization, generation, input-integrity, and exact-commit invariants.

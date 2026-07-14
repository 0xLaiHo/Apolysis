<!-- SPDX-License-Identifier: Apache-2.0 -->

# Projection schema and invariants

The crate owns the `apolysis_projection` schema. It depends on the Gateway
schema for the immutable input ledger, organization sequence, and exact
record/outbox identity. Gateway migration must therefore run first.

The schema is an internal lifecycle projection, not the public Query or
Console data model.

## Migration ownership

`migrate_projection_schema` takes a transaction-scoped advisory lock, installs
the schema in one transaction, and records the migration SHA-256 in
`apolysis_projection.schema_migrations`. The Gateway adapter already owns the
default SQLx migration ledger, so this crate keeps an independent ledger.

If the schema exists, the runner requires exactly the expected version,
description, and checksum. Unexpected history or edited migration bytes fail
closed. The migration intentionally avoids `IF NOT EXISTS`, role creation, and
grants so unexpected objects and deployment authority are not hidden.

## Numeric and text domains

Projection identifiers are bounded printable contract identifiers. References
are bounded and reject control characters. Persisted contract integers are
limited to the exact-in-JSON range `0..=2^53-1`, with positive variants where
zero is invalid. SHA-256 columns require exactly 32 bytes.

These SQL domains complement, rather than replace, Rust typed-contract and JCS
validation at the input boundary.

## Tables

### `generations`

One row describes one organization-local computation generation:

- composite primary key `(organization_id, generation_id)`;
- computation version and state (`building`, `active`, or `retired`);
- optional same-organization `rebuild_of_generation_id`;
- source watermark captured at creation and lifecycle timestamps;
- a foreign key to the Gateway organization sequence row.

Partial unique indexes allow at most one active generation and one building
generation per organization. The state/timestamp check requires building rows
to be unactivated, active rows to be activated but unretired, and retired rows
to carry both timestamps. The initial generation is active; a building
generation must identify the generation it rebuilds.

First initialization serializes on the organization sequence row. Existing
initialization and rebuild creation observe the active head, lock the referenced
generation/checkpoint pair before the head, and then revalidate that observation.
This matches the active projector and cutover order and prevents a
generation-to-head/head-to-generation deadlock cycle.

### `commits`

A commit identifies one non-empty, contiguous projection batch. Its primary
key is `(organization_id, generation_id, commit_revision)`.

The chain is exact, not merely ordered:

- revision 1 has no predecessor and starts at input watermark 0;
- every later revision names `commit_revision - 1`;
- the deferred predecessor foreign key matches both the prior revision and its
  `through_input_watermark` to this commit's `from_input_watermark`;
- `through_input_watermark = from_input_watermark + record_count`;
- `(generation, through_input_watermark)` is unique;
- `record_count` is between 1 and 200.

`batch_digest` is a domain-separated, deterministic SHA-256 over organization,
input range, ordered ingest sequences, and stored fact digests. It is
generation-independent so rebuilds can be compared. It is unkeyed and is not a
signature or tamper-proof database anchor.

### `checkpoints`

There is exactly one checkpoint per organization-qualified generation. It
stores the input watermark, last commit revision, update time, and either a
ready state or a bounded failure code plus failed ingest sequence.

The deferred checkpoint foreign key matches both
`last_commit_revision` **and** `input_watermark` to the exact commit revision
and through-watermark pair. Therefore a non-zero checkpoint cannot point at a
different position in the same chain. A zero checkpoint has no commit.

Projection uses a row lock and a compare-and-swap on the old watermark. Poison
input records the failure without advancing that watermark.

### `run_lifecycle`

This is the only materialized read model in the crate. Its primary key is
`(organization_id, generation_id, run_id)`. It stores the immutable run header,
current lifecycle state, lifecycle timestamps/revision, and input provenance.

Foreign keys require:

- the owning organization-qualified generation;
- the exact Gateway record that opened the run;
- the exact latest lifecycle Gateway record;
- the exact projection commit revision and through-watermark that last changed
  the row.

Opening and latest lifecycle sequences cannot be beyond the modifying commit's
watermark. Terminal timestamps exist exactly for `finished` and `incomplete`
states.

Lifecycle causality is defined by ingest sequence and legal `from -> to`
transitions. The table intentionally does not require wall-clock timestamps to
be monotonic. A server clock rollback can make a later transition timestamp
earlier than the opening or prior transition while the ingest/commit order
remains authoritative.

The inventory index supports bounded keyset traversal ordered by opening time
descending and run identifier ascending.

### `organization_heads`

One row selects the active generation and query-visible watermark for an
organization. Deferred foreign keys require:

- the selected generation to exist in that organization and have the exact
  `active` state; and
- the visible watermark to match that active generation's exact checkpoint
  watermark.

Cutover changes the old/new generation states and the head in one transaction,
so readers see either the old generation or the fully caught-up replacement.
Generation-bound cursors expire when the head changes.

## Input relation and publication

The projector reads a contiguous organization range by joining
`apolysis_gateway.record_items` to
`apolysis_gateway.projection_outbox` on organization and ingest sequence. The
Gateway schema already enforces a deferred, exact 1:1 record/outbox relation.
The projector additionally requires the expected topic and redundant typed
metadata.

For an active generation, every input outbox row must still be `pending`. In
the same transaction, the projector applies lifecycle changes, inserts the
commit, advances the checkpoint and organization head, and marks the exact
range `published`. This is the active publication path, not a passive read of
an independently delivered outbox.

The bounded internal retry loop applies only while a rollback is known. A
received definitive database rejection at `COMMIT` is classified as rolled
back. Transport/protocol loss, connection-class SQLSTATE, and explicit
statement-completion-unknown results are surfaced as `CommitOutcomeUnknown`
without an internal retry. This rule applies to both batch commits and
cutover. A worker must reconcile the durable checkpoint, commit chain, and
active head before scheduling another operation, because the server may have
committed even when its response did not arrive.

For a building generation, delivery state is deliberately ignored after the
identity join. This makes a rebuild independent of whether the active
generation already published each row. Building does not change delivery state
or the organization head. At cutover, rows through the locked source watermark
must be `pending` or `published`; any remaining pending rows are published in
the cutover transaction.

## Stored-row validation

SQL constraints alone cannot establish that JSONB is the expected typed fact.
Before applying a row, Rust validation performs all of the following:

- bounds the logical PostgreSQL JSON text length to one MiB before returning
  the value to the Rust client; physical `pg_column_size` is not used because
  TOAST compression can make a much larger logical value appear small;
- rejects integers outside the exact I-JSON range and non-finite numbers;
- JCS-canonicalizes the stored JSON value and verifies its SHA-256 digest with
  a constant-time byte comparison;
- deserializes to `AgentExecutionRecordItem`, re-canonicalizes the typed value,
  and requires identical canonical bytes, which rejects unknown or
  non-round-tripping input;
- matches organization, run, ingest sequence, ingest time, schema version,
  fact kind, and outbox topic to the redundant relational columns;
- applies lifecycle facts only in valid state order and requires every other
  fact to reference an already opened run.

A valid unkeyed digest proves consistency with the stored bytes, not authorship
or protection from a database administrator capable of rewriting both value
and digest.

## Cursor membership boundary

The internal `LifecycleCursor` binds organization, generation, visible input
watermark, opening timestamp, and run identifier. The SQL predicate limits
membership to rows whose `opened_ingest_sequence` is at or below the captured
watermark, then advances by the immutable keyset order.

This prevents newly opened runs from appearing mid-traversal and prevents a
cursor from crossing an organization or generation cutover. It is only a
membership snapshot. Lifecycle fields on a member row are not versioned as of
the cursor watermark, so the cursor is not a full repeatable-read snapshot or
a public Query pagination contract.

## Row-level security

RLS is enabled and forced on `generations`, `commits`, `checkpoints`,
`run_lifecycle`, and `organization_heads`. Their policies compare
`organization_id` with the transaction-local
`current_setting('apolysis.organization_id', true)`. The migration ledger is
administrative and is not covered by those tenant policies.

Repository methods set the organization GUC at transaction start together with
bounded lock and statement timeouts. Tests can verify that an ordinary
`NOBYPASSRLS` role sees no rows without the setting and only matching rows when
the trusted application sets it.

This is defense in depth, not caller authorization: PostgreSQL permits a
session able to execute arbitrary SQL to set a custom GUC itself. Production
role creation, grants, connection topology, Query authentication and
organization authorization are outside this migration and remain deferred.

## Outside this schema

No tables or guarantees are provided here for a full Console, Query auth,
external cursor encoding, SSE, coverage, findings, source health,
evidence-object lifecycle, production RLS deployment, replication, failover,
or HA. Those are separate layers and qualification gates.

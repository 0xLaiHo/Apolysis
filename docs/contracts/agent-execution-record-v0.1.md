# Agent Execution Record v0.1 Semantics

Status: normative semantic contract for W1–W2. The current JSONL records are an
implementation baseline, not an implementation of this aggregate.

## Aggregate boundary

An Agent Execution Record is the versioned aggregate for one Agent Run. It is
not a flat event and must not require consumers to infer product truth from raw
JSONL or storage tables. Durable representation is append-oriented contract
items that rebuild the aggregate; it is not one unbounded serialized timeline.

The aggregate contains:

- authority and authenticated principal references;
- run identity, declared objective reference, environment profile, and
  lifecycle;
- agents, turns, delegates, tool calls, MCP calls, and A2A tasks;
- policy decisions, approvals, and separately reported actuation;
- runtime bindings and observed effects;
- claimed outcomes, independent outcome checks, and disagreements;
- Evidence Sources, capability and trust profiles, source health, and Coverage
  Gaps;
- three independent coverage dimensions, relations, and Findings.

The canonical shared types are the bounded `AgentExecutionRecordItem`,
`SourceEnvelope`, `TypedEvidencePayload`, `SourceManifest`, `RuntimeBinding`,
and `CoverageSummary`. Query-facing projections include `RunOverview` and
`TimelinePage`. These types belong to the independent `apolysis-contracts`
boundary so collectors, Gateway, projectors, Query API, and fixtures do not
redefine product semantics. There is deliberately no public whole-run wire
snapshot. Legacy JSONL v1 is an adapter input and output for current local
paths, not this aggregate's wire schema.

Identifiers are opaque strings and are unique only inside their stated scope.
The record preserves organization, run, source, source stream, event, trace,
span, turn, tool-call, task, repository, provider, Pod, container, and cgroup
identifiers when a source legitimately supplies them. It does not invent an
identifier to make a missing relation look exact.

## Run lifecycle

The target lifecycle is:

```text
opening -> active -> finishing -> finished
    |         |          |
    +---------+----------+-> incomplete
```

- `opening`: identity, authority, environment, expected sources, and privacy
  policy are being validated; evidence ingest is not yet authorized.
- `active`: at least one valid run lease exists and registered sources may bind
  runtimes or ingest evidence.
- `finishing`: the coordinator declared completion; expected terminal source
  positions and outstanding gaps are being reconciled.
- `finished`: the run is sealed and all required terminal declarations were
  received without an unresolved required-source gap.
- `incomplete`: the run is sealed with an expired lease, missing terminal
  declaration, required source gap, source failure, or finalization timeout.

`finished` describes lifecycle closure, not success, cleanliness, complete
execution visibility, or verified outcome. Terminal records retain all gaps and
may still contain Findings. Repeating a terminal operation cannot move a run
back to an active state.

## Source envelope

Every source contribution has a versioned envelope that carries, directly or
by immutable reference:

| Group | Required semantics |
| --- | --- |
| Scope | schema version, run, source registration, source stream, event identity |
| Source | adapter/source version, `SourceManifest` reference, declared boundary, redaction profile |
| Order | source sequence within the source stream |
| Time | observed time, clock source, and uncertainty when known |
| Correlation | explicitly supplied trace, span, turn, tool-call, task, provider, workload, and artifact identifiers |
| Payload | typed payload name and version, privacy classification, inline redacted value or authorized object reference |
| Integrity | payload digest |

The source envelope does not supply authoritative organization, ingest
sequence, ingested time, effective trust, or authentication context. On durable
acceptance, the Gateway adds those server facts, including the effective trust
profile, to the append-oriented `AgentExecutionRecord` item and binds it to the
accepted `SourceEnvelope` and `SourceManifest` digest.

The `RunOpened` fact retains the server-approved privacy profile, retention
profile, and expected source kinds so a projector does not depend on a mutable
policy table to rebuild the run. Each `SourceRegistered` fact retains the
server-resolved source registration, assigned stream, frozen policy revision,
authenticated principal, manifest, and effective trust. Each accepted envelope
repeats the authoritative registration, stream, and frozen policy revision and
validates that its stream matches the unchanged source envelope. A
`RuntimeBound` fact similarly wraps the source binding with its authoritative
registration, stream, manifest digest, effective trust, and policy revision. A
policy revision change revokes the old stream lease; it cannot silently raise
the trust assigned to later evidence.
Each accepted `finish_run` also appends the complete cumulative terminal
positions and outcome references, authenticated declarer registration,
lease-bound source stream and principal, frozen policy revision, and
server-bounded deadline before any resulting state transition.
The terminal lifecycle can therefore be replayed without consulting mutable
run side tables.

A `SourceManifest` declares what a source can emit, its evidence boundary,
stream-ordering guarantee, expected lifecycle, sampling behavior, redaction
profile, and structure-only or separately authorized object-reference privacy
capability. It cannot set its effective trust profile and is not a claim that
every declared capability was present in a particular run.

An Evidence Source restart opens a new source stream. Source sequence is
strictly increasing within one stream and never creates a global causal order.
Observed time is display and correlation evidence; ingest sequence is durable
acceptance order. Neither alone proves causality.

## Evidence truth levels

The record preserves source meaning:

- a hook, SDK, protocol, or provider event is Semantic Evidence or a provider
  claim within its declared trust boundary;
- a runtime entry observation is an attempted operation;
- a matched operation return may establish `succeeded`, `failed`, `denied`,
  `pending`, or `unknown` only according to that operation's contract;
- a tool result is a Claimed Outcome, not proof that a remote mutation committed;
- a Git, test, Kubernetes, cloud, database, or SaaS verifier may produce a
  Verified Outcome for the specific state it checked;
- disagreement is retained as evidence and may produce a Finding; one source
  does not overwrite another.

## Coverage dimensions

Coverage is computed server-side from the run's environment, registered source
capabilities, expected lifecycle, loss state, and verifier requirements. The
browser displays the result and reasons; it does not recompute them.

### Semantic Coverage

| State | Meaning |
| --- | --- |
| `complete` | all semantic lifecycle evidence required by the run profile was observed without a known gap |
| `partial` | useful semantic evidence exists, but at least one required lifecycle source or record is missing, sampled, truncated, or failed |
| `opaque` | the environment does not expose enough semantic lifecycle to the customer to assess the required activity |
| `unavailable` | a semantic source required by the run profile was expected but produced no usable evidence |

### Execution Coverage

| State | Meaning |
| --- | --- |
| `host_verified` | the configured Runtime Witness met its declared process, file, network, and workload capability for the controlled boundary without a known required gap |
| `partial` | execution evidence exists but capability, scope, sampling, loss, or isolation leaves a known gap |
| `opaque` | no customer-controlled execution source can observe the execution boundary |
| `not_applicable` | no execution assertion is required by the run profile |
| `incomplete` | execution evidence was expected, but source failure, loss, missing terminal state, or finalization prevented the configured profile from completing |

### Outcome Coverage

| State | Meaning |
| --- | --- |
| `verified` | every outcome required by the run profile was independently checked, regardless of whether the check agreed with the claim |
| `unconfirmed` | an outcome was claimed but was not independently checked |
| `unknown` | no reliable claim/check relationship can be established |
| `not_applicable` | the run profile requires no external outcome |

Outcome coverage never carries agreement. Each claimed-versus-checked outcome
has a separate `OutcomeComparisonState`:

| State | Meaning |
| --- | --- |
| `match` | the independent check agrees with the specific claim |
| `mismatch` | the independent check disagrees with the specific claim |
| `unresolved` | available evidence cannot establish a stable comparison |

No coverage state is an overall confidence score. Semantic `complete`,
execution `host_verified`, and outcome `verified` remain separate. A provider
run can legitimately be semantic `complete`, execution `opaque`, and outcome
`verified`.

Each computed coverage value includes a computation version, projection
revision, input watermark, reason codes, contributing source references, and
Coverage Gap references. Semantic `partial`, `opaque`, and `unavailable`;
execution `partial`, `opaque`, and `incomplete`; outcome `unconfirmed` and
`unknown`; and comparison `mismatch` and `unresolved` cannot be styled or
summarized as success.

## Attribution

Every relationship has one of four representations:

- `exact`: established by an explicitly propagated identifier inside its trust
  boundary;
- `inferred`: one plausible relation supported by recorded match reasons and a
  bounded confidence value;
- `ambiguous`: multiple plausible candidates retained with their reasons and
  scores;
- `unattributed`: evidence belongs to the run but cannot be responsibly assigned
  below the run.

PID, timestamp, working directory, argument, and resource matching are fallback
evidence only. An inferred or ambiguous relation never becomes exact through
display, export, or projection. Exact means identity match, not proof of
causality or source honesty.

## Findings

A Finding has a stable identifier, canonical kind, rule version, severity,
state, affected entities, evidence references, relevant coverage state, and
creation/update times. Deduplication must be deterministic within its declared
scope. Console v0 and legacy JSONL v1 share the same eight finding kinds,
locked by the accountability golden fixture. Coverage gaps, outcome mismatch,
and ambiguous attribution remain typed read-model states rather than silently
expanding that vocabulary.

For Console v0, Findings are read-only investigation results. Acknowledgement,
assignment, resolution, suppression, and other workflow transitions belong to
Investigation Console v1 and require an operator audit trail.

## Compatibility and projection

Stored source envelopes are append-oriented. Corrections and late accepted
evidence create a new revision rather than rewriting accepted history. Derived
views are versioned and rebuildable. Each view reports its computation version,
projection revision, and input watermark so stale or migrating views are
distinguishable from current ones.

The exact machine shape belongs to versioned schemas and fixtures. The existing
`docs/jsonl-schema-v1.md` remains the contract for current local JSONL and must
not be interpreted as the complete Agent Execution Record v0.1 wire format.

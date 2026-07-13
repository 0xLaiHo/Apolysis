# Minimum Console v0 Contract

Status: frozen W1–W2 information architecture and visual semantics. The Query
API, versioned projectors, and Web Console are not implemented in the current
release.

## Operator question

Minimum Console v0 answers: “What happened in this Agent Run, what evidence
supports that account, and what remains incomplete or opaque?” It is an
investigation surface, not a raw event viewer or policy administration console.

## Trust boundary

The browser communicates only with the non-privileged, organization-scoped
Query API. It cannot connect to the write Gateway, privileged daemon, Runtime
Witness, host socket, `hostPath`, database, object bucket, or storage credential.

The server derives coverage, source health, outcome comparisons, Finding state,
and attribution. The browser renders versioned values and reason codes; it does
not infer a verdict from events, colors, missing rows, or client clock.

## Versioned read models

The Console consumes `apolysis-contracts` read models, including `RunOverview`,
`CoverageSummary`, and `TimelinePage`, rather than raw JSONL or internal
database tables. A response identifies its view version, computation version
where applicable, projection revision, and query-visible input watermark.

Minimum read surfaces are:

| Surface | Required content |
| --- | --- |
| Run inventory | organization-authorized runs, lifecycle, environment, primary agent, observed/ingested range, coverage summary, current Findings, and projection freshness |
| Run overview | authority/principal references, objective reference, environment, lifecycle, source summary, claimed and verified outcome summary, coverage, gaps, and Findings |
| Coverage summary | independent semantic, execution, and outcome states with reason codes, contributing sources, and Coverage Gap references |
| Timeline page | layered semantic, execution, and outcome items with observed and ingested time, clock uncertainty, source, attribution, and stable page order |
| Source health | expected and joined sources, capability/trust profiles, last durable position, terminal position, loss, sampling, redaction, gaps, and staleness |
| Finding summary | stable identity, kind, severity, read-only current state, affected entities, coverage context, and authorized evidence references |
| Evidence reference | redacted metadata plus a separately authorized dereference action when raw-object capture was explicitly enabled |

Inventory and timeline queries use opaque cursor and bounded time-window
pagination with server-side organization, environment, source, coverage,
Finding, and outcome filters. An unbounded run snapshot is not a supported
browser contract. Large timelines require row virtualization or comparable
bounded rendering.

Live status uses resumable SSE from a projection-commit cursor. Delivery is at
least once; clients deduplicate by event identity, reconnect with the last
cursor, display a gap/reset state when the cursor expires, and use bounded
polling as the explicit fallback. An SSE event is sent only after its view
revision commits. Reauthorization, heartbeat, connection limits, and revocation
apply to streams.

## Information architecture

### Run Explorer

- search and filter authorized runs;
- compare lifecycle and the three independent coverage dimensions;
- show active Findings and source-health degradation without opening a run;
- make stale projection or unknown state visible.

### Run Overview

- identify authority, principal, agent, environment, and lifecycle;
- present Claimed Outcome beside Verified Outcome and disagreement;
- present semantic, execution, and outcome coverage independently;
- summarize joined/expected Evidence Sources and Coverage Gaps;
- list current Findings and authorized evidence references.

### Layered Timeline

- separate semantic, execution, and outcome lanes;
- show both observed and ingested time plus clock uncertainty;
- retain source and trust boundary on every item;
- label exact, inferred, ambiguous, and unattributed relations;
- expose loss, redaction, sampling, gaps, and correction revisions in context;
- paginate and stream in projection order without claiming that display order is
  causal order.

### Source Health and Gaps

- distinguish `healthy`, `degraded`, `gapped`, `stalled`, `failed`, `opaque`,
  and `not_applicable` with server-provided reasons;
- show expected capability versus observed lifecycle;
- show source stream and durable/terminal sequence positions without exposing
  credentials;
- make an unresolved required gap visible in the Run Overview.

### Findings

Console v0 shows current Findings and evidence but does not implement
acknowledgement, assignment, suppression, resolution, or policy editing. Those
audited workflow actions belong to Investigation Console v1.

## Visual semantics

Color may reinforce meaning but cannot be the only encoding. Every state has a
stable text label, icon/shape or pattern, and accessible description.

### Coverage

- Semantic `complete`, execution `host_verified`, and outcome `verified` use
  dimension-specific labels. `verified` means the outcome was independently
  checked; the separate comparison may still be `mismatch`.
- Semantic `partial`, `opaque`, and `unavailable`; execution `partial`, `opaque`,
  and `incomplete`; and outcome `unconfirmed` and `unknown` use a limitation or
  indeterminate treatment and show the reason/gap count.
- Outcome comparison `mismatch` uses a disagreement label and links both the
  claim and verifier; `unresolved` uses a neutral unresolved treatment.
- Unknown, unavailable, and incomplete treatments never use green, a check
  mark, zero-findings wording, or success copy.
- Execution/outcome `not_applicable` uses a neutral “not applicable” treatment
  and is not included in completeness totals.

### Claimed and verified outcomes

Claim, verification coverage, and comparison are always separate fields.
Matching values may be visually paired but retain both sources. Unconfirmed,
unknown, mismatch, and unresolved cannot collapse into a generic failure or
success. Absence of a verifier is `unconfirmed` or `unknown` according to the
contract, not “no change.”

### Finding state

The current server-owned state, severity, rule version, affected entities, and
evidence count are visible. “No Findings” is allowed only when projection is
current and the applicable coverage profile has no unresolved gap; otherwise
the summary says that the result is incomplete or unknown.

### Attribution

- `exact`: solid connector and explicit “exact identity” label;
- `inferred`: dashed connector and match reason/confidence disclosure;
- `ambiguous`: branched connector or candidate list with all retained options;
- `unattributed`: run-level lane/card with no fabricated actor node.

Exact identity does not receive a “caused by” label unless a separate causal
contract establishes it. Inferred and ambiguous representations remain so in
tooltips, filters, exports, and accessibility text.

## Deterministic fixture scenarios

The frontend/read-model contract must include at least:

1. a normal Codex run with semantic lifecycle, optional host evidence, verified
   Git/test outcome, and no unresolved required gap;
2. a run with partial semantic or execution coverage;
3. a run with source loss, a sequence gap, clock uncertainty, and stale
   projection state;
4. a tool success claim that disagrees with Git, test, Kubernetes, or provider
   read-back;
5. authorization failure and a cross-organization identifier probe;
6. redacted/unauthorized/deleted evidence object behavior;
7. exact, inferred, ambiguous, and unattributed relations;
8. an unknown outcome and incomplete finalization.

Fixtures contain synthetic identifiers and redacted values only. A test passes
only if unknown/incomplete states remain visible and unauthorized raw content
is absent from the read model, stream, and browser output.

## Deferred from Console v0

Agent Run Graph, cross-run search, investigation-task workflow, Finding
disposition, policy editing, organization administration, fleet views, and
general evidence export are Investigation Console v1 or later scope.

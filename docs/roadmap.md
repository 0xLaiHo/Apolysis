# Apolysis roadmap

[English](roadmap.md) | [简体中文](roadmap.zh-CN.md)

This is the canonical direction and qualification boundary for this source
tree. It is not a phase log. The [design](design.md) describes current behavior;
Git and the focused Pull Request retain completion and validation history.

## Product direction

The existing production-MVP direction remains an Agent Runtime Evidence &
Policy Plane: versioned Agent Execution Records, authenticated evidence
ingestion, durable storage, separate semantic/execution/outcome coverage,
Minimum Console v0, and later Investigation Console v1 and a controlled
partner pilot. The [contract set](contracts/README.md) owns the frozen
interfaces and their qualification gaps. Local harness work is an edge
integration and does not complete the Gateway, storage, Query, or Console work.

## Active harness integration

The current slice establishes content-off declarations for five products,
append/deduplication, separate capture and native session identity, safe
deterministic IDs, and shell-comment rewrites that preserve tool input and
native approval semantics. Dedicated kernel markers and process-generation
checks carry attribution across fork and exec. Correlation keeps explicit
identifier relations, conflicts, and inferred or ambiguous candidates distinct;
semantic-only declarations do not imply expected local execution evidence.
A bounded synthetic live regression now establishes the local marker path on
one Linux kernel. Bounded native bridge runs cover Claude Code, Pi, and
OpenCode; Codex is blocked on provider-network connectivity and Cursor on
renewed authentication. These are open qualification gates, not product
support conclusions. The next boundary includes default
comment delivery, broader versioned product-hook qualification, multiple
kernels, and stress/loss or longer-running workloads.
The local gate does not close those broader qualification gaps; its evidence
is recorded in [live validation](harness-intent-live-validation.md).

Qualification must exercise the actual product adapters as well as the Rust
normalizer. Kernel fixtures and privileged Linux runs are separate evidence;
neither substitutes for a versioned product-hook integration run.

Declared reasons remain optional, unverified Semantic Evidence. Codes,
explicit corrections, and bounded opt-in summaries extend the local Tool Call
context; they do not expand kernel coverage or qualify product-native delivery.
An explicit shell bridge supplies a recognizable exec boundary for wrapping
backends, with documented loss of outer-shell state propagation. Default
comment delivery and opt-in bridge delivery require separate qualification;
neither mode establishes generic compatibility with long-lived shell workers.

## Deferred scope

- Operator-origin annotations, authenticated reason authorship, and external
  task-content retrieval remain deferred.
- Remote and provider-hosted operations require additional Evidence Sources;
  semantic declarations alone cannot confirm their execution or outcomes.
- Non-shell tools, shared long-lived workers, and arbitrary asynchronous
  delegation need explicit action-level context rather than a broad inherited
  process label.
- Cryptographically authenticated relation keys, hostile-workload resistance,
  independent anchoring, and complete syscall coverage are separate work.
- Production admission, broader recovery/capacity qualification, authorized
  Query/object reads, Console views, and partner deployment approval remain
  subject to the existing normative contracts.

## No-go criteria

Do not describe this slice as production-qualified or as a complete Tool Call
to syscall mapping while any of these conditions holds:

- Hook errors, missing IDs, duplicate/conflicting declarations, or mismatched
  capture-session IDs are hidden or silently treated as successful capture.
- A rewrite drops unrelated tool fields, changes shell control-flow syntax,
  or grants approval the integration was not asked to grant.
- A shell bridge is enabled without explicit choice or is described as
  preserving outer-shell cwd, environment, or functions.
- Missing process lineage, marker truncation, event loss, or stale process
  identity is silently treated as an exact relation.
- An executable-name guess is reported as an exact relation, or an identifier
  conflict is resolved by a weaker fallback.
- Semantic-only or historical visibility is presented as a verified outcome.
- A declared reason is presented as verified motive or hidden model reasoning,
  ambiguous reasons enrich an execution relation, or free-text reasons are
  retained without explicit opt-in.
- Content-off persistence is violated, or a skipped live/product validation
  is reported as passed.

Promotion and release still require the repository's protected-branch review
and validation workflow. No hook-install instructions authorize a privileged
host, Kubernetes, or provider operation implicitly.

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
The next boundary is versioned product-hook qualification and privileged
kernel qualification under loss, unsupported execution shapes, and longer
running workloads. Fixtures and local builds do not close those gates.

Qualification must exercise the actual product adapters as well as the Rust
normalizer. Kernel fixtures and privileged Linux runs are separate evidence;
neither substitutes for a versioned product-hook integration run.

## Deferred scope

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
- Missing process lineage, marker truncation, event loss, or stale process
  identity is silently treated as an exact relation.
- An executable-name guess is reported as an exact relation, or an identifier
  conflict is resolved by a weaker fallback.
- Semantic-only or historical visibility is presented as a verified outcome.
- Content-off persistence is violated, or a skipped live/product validation
  is reported as passed.

Promotion and release still require the repository's protected-branch review
and validation workflow. No hook-install instructions authorize a privileged
host, Kubernetes, or provider operation implicitly.

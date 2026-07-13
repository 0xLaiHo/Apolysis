# Privacy Boundary and Defaults

Status: normative W1–W2 target contract; remote collection and centralized
retention are not implemented in the current release.

## Principles

1. Collect the minimum evidence needed to answer a declared investigation or
   policy question.
2. Redact before evidence crosses a host or provider boundary whenever the
   source can do so.
3. Treat identifiers and metadata as potentially sensitive even when content
   capture is disabled.
4. A reference to an evidence object is never authorization to read it.
5. Missing or redacted content lowers what Apolysis may claim; it does not
   authorize broader capture.

## Content-off defaults

The following content is disabled unless an organization administrator enables
it for a named source and purpose:

- prompts, model responses, conversation transcripts, and memory contents;
- raw tool arguments and tool results;
- raw command lines and environment values;
- file contents, patches, standard input, and standard output;
- request or response bodies, headers, credentials, tokens, and cookies;
- raw evidence bundles, screenshots, core dumps, and packet payloads.

The default record keeps allowlisted structure and privacy-preserving values:
event type, declared actor and resource identifiers, timestamps, outcome state,
coverage state, loss markers, lengths, hashes where safe, and redacted or
tokenized path, command, socket, repository, and workload values. A hash must
not be used when a small input space makes reversal practical; use an
organization-scoped keyed token instead.

The current local observer enforces this boundary at one shared persistence
seam used by fixture, standalone live, and daemon paths. Exec argv is replaced
with `argv_redacted:true` plus allowlisted truncation markers, canonical
`process_command` is omitted, and executable identity is represented by a
session-scoped reference normalized across path forms. Managed-agent metadata
records a content-off marker and does not persist its command fingerprint.
Kernel-side argv capture is still transiently available for process-context
resolution; disabling capture at the kernel boundary is a separate hardening
gate and no captured argv may reach JSONL, hash-chain, or future Gateway writes.

Secrets, credential values, authorization headers, kubeconfig contents, and
provider API keys must never enter an evidence payload or object. Detection of
a secret path records the category and a redacted reference, not the secret.

## Capture authorization

An opt-in content policy must state:

- organization, source, environment, and data categories;
- investigation purpose and authorized operator roles;
- redaction profile and any fields that remain plaintext;
- retention tier and object-specific maximum lifetime;
- geographic or provider restrictions;
- effective time, approver, review time, and revocation procedure.

The Gateway must reject content outside the registered source capability or
active capture policy. Source-side redaction is mandatory where supported;
Gateway validation and redaction are a second boundary, not a substitute for
edge minimization.

## Organization and access boundary

- The authenticated source registration determines `organization_id`; payloads
  cannot choose or override it.
- Run leases, event identifiers, object references, query cursors, export jobs,
  and finding actions are organization-scoped and non-transferable.
- Browser operators use a separate read identity and role check. Source write
  credentials never authorize Console access.
- Raw-object reads require a fresh authorization decision for the object,
  category, run, organization, and purpose. Storage location or possession of a
  reference is insufficient.
- Every object read, export, retention change, redaction override, and finding
  disposition is auditable without recording the sensitive content itself.

The production MVP validates isolation with at least two synthetic
organizations. This is an isolation gate, not a public multi-tenant product
claim.

## Retention and deletion

The contract preserves the current named retention tiers:

| Tier | Default maximum | Intended use |
| --- | ---: | --- |
| `short` | 7 days | transient development or higher-sensitivity evidence |
| `standard` | 30 days | default run metadata and redacted evidence indexes |
| `extended` | 365 days | explicitly approved audit requirements |

`standard` is the default for record metadata. Raw objects are not collected by
default; when enabled, their maximum lifetime must be explicit and may not
exceed the run's tier. An organization may configure a shorter lifetime.
Extending a lifetime is an audited policy change and cannot revive deleted
content.

Deletion, revocation, or a stricter redaction policy must immediately deny new
reads and propagate to source records, projections, search indexes, caches,
object grants, exports, and live streams. Physical purge may be asynchronous,
but its state must be visible and completion must not be claimed until every
registered storage and derived-data component has acknowledged it. Hash-chain
or audit continuity may retain a non-sensitive tombstone and digest, never the
deleted content.

## Failure behavior

- If redaction cannot complete, content is rejected or retained only in an
  explicitly authorized edge buffer; it is not transmitted unredacted.
- If authorization becomes unavailable, reads and content-bearing writes fail
  closed. Non-content health signals may continue only under a pre-authorized
  degraded-mode policy.
- If deletion propagation, object authorization, or organization binding is
  uncertain, the affected content is unavailable.
- Truncation, sampling, rejection, and redaction are represented as Coverage
  Gaps. They are never rendered as a clean run.

## Non-goals

This contract does not make Apolysis a data-loss-prevention product, secrets
manager, legal-hold system, or durable owner of customer prompts and responses.
Organizations remain responsible for obtaining required consent and defining
their lawful retention policy.

# Quickstart — try Apolysis in five minutes, no root

This compares declared Tool Calls with a bundled, pre-captured sample —
**no root, no eBPF, no special kernel**. It shows evidence gaps without treating
a missing relation as proof of an agent's motive or an operation's outcome.

## Run it

```bash
make build      # builds the CLI (first run only)
make quickstart
```

## What you'll see

The sample contains a Codex declaration to run project tests, an ordinary
file-open event, and a fake credential-path access event. It predates live
intent markers and has no explicit raw-event link. Current correlation reports
zero Exact Relations and two Findings:

- `missing_intent` for the credential-path attempt with no explicit relation.
- `unobserved_intent` for the historical declaration with no explicit relation
  to an observed event.

This does not mean the tests never ran or that a secret was successfully read.
The fixture lacks the identifiers needed to establish those relationships.
The ordinary file-open event does not itself produce `missing_intent`.

Other historical inputs can produce `intent_correlation_candidate` records
from legacy command equality or exec-only executable names. One candidate is
`inferred`; several are `ambiguous`. Candidates do not count as exact matches
or suppress Findings. This particular fixture has no such candidate after
content-off ingestion. See the [JSONL schema](jsonl-schema-v1.md).

## What just happened

`make quickstart` ran two commands against checked-in fixtures under
`tests/fixtures/codex-mismatch/`:

1. `apolysis intent ingest` — normalize the Codex tool-call log into intent
   records.
2. `apolysis intent correlate --summary` — join declared intent against the
   observed timeline, print the digest, and write the resulting JSONL records
   to `target/quickstart/correlation.jsonl`.

Nothing here needs privileges, because the observed timeline is a **fixture**.

## Do it live on your own agent

To record a real timeline from your own agent at the kernel level (Linux,
root / `CAP_BPF`, a CO-RE eBPF object), see the "Audit A Local Agent Command"
example in the [README](../README.md). Install the matching
[harness hook](harness-intent.md) and align its capture-session ID with the
observer before expecting marker-based relations. Merely replacing a fixture
with a live timeline does not supply missing Tool Call identity. Build the CLI
and eBPF object together; inspect loss and truncation diagnostics separately.

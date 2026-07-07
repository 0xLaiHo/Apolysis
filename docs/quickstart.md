# Quickstart — try Apolysis in five minutes, no root

This runs the whole intent-vs-side-effect accountability flow against a bundled,
pre-captured sample — **no root, no eBPF, no special kernel**. It shows the one
thing Apolysis exists to catch: an agent that did something it never declared.

## Run it

```bash
make build      # builds the CLI (first run only)
make quickstart
```

## What you'll see

The sample is a Codex session that declared a single action — "run the project
tests" — captured next to the host-side timeline of what actually happened:

```text
Apolysis accountability summary  (session: codex-mismatch-demo)
  1 side effect(s) matched declared intent, 1 finding(s) with no declared intent
  ✓ matched   crates/apolysis-cli/tests/intent.rs
            declared as: cargo test -p apolysis-cli --test intent  [process_command_exact]
  ⚠ missing_intent   credential_read /tmp/apolysis-demo-home/.aws/credentials
            by: python3 scripts/read-demo-credential.py
            observed side effect has no matching declared intent  [review]
```

The agent said it ran the tests (`✓ matched`). It **also** read
`.aws/credentials` (`⚠ missing_intent`) — a side effect no declared intent
covers. The harness's own tool-call log would not show that; the OS-level
timeline does. That gap is the whole point.

## What just happened

`make quickstart` ran two commands against checked-in fixtures under
`tests/fixtures/codex-mismatch/`:

1. `apolysis intent ingest` — normalize the Codex tool-call log into intent
   records.
2. `apolysis intent correlate --summary` — join declared intent against the
   observed timeline, print the digest above, and write the full JSONL evidence
   to `target/quickstart/correlation.jsonl`.

Nothing here needs privileges, because the observed timeline is a **fixture**.

## Do it live on your own agent

To record a real timeline from your own agent at the kernel level (Linux,
root / `CAP_BPF`, a CO-RE eBPF object), see the "Audit A Local Agent Command"
example in the [README](../README.md). The correlation step is identical — only
the source of the timeline changes from a fixture to the live eBPF observer.

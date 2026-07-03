# Codex Intent Mismatch Demo

This demo is the first P1 launch asset starter. It shows the public story
Apolysis should make easy to reproduce:

> The agent declared one command, but host-side evidence showed another side
> effect.

The checked-in fixture is intentionally offline and safe. It does not contain
real credentials, does not read the current user's home directory, and does not
require privileged eBPF access. The later public launch recording should replace
this fixture with a real `apolysis observe --agent-run -- codex ...` run.

## What The Fixture Shows

- Codex declares a shell command intent: `cargo test -p apolysis-cli --test intent`.
- The observed timeline contains a matching file-open event from that test
  command.
- The same observed timeline also contains an unexpected `credential_read`
  event for `/tmp/apolysis-demo-home/.aws/credentials`.
- `apolysis intent correlate` emits:
  - one `intent_correlation` record for the declared test command;
  - one `accountability_finding` with `kind:"missing_intent"` for the
    credential read.

Fixtures live under `tests/fixtures/codex-mismatch/`:

- `codex-response-items.jsonl`: minimal Codex JSONL response-item input.
- `observed-timeline.jsonl`: canonical host-side timeline events.
- `expected-findings.contains`: stable output fragments used by the demo gate.

## Reproduce Locally

Run the contract gate:

```bash
make test-codex-mismatch-demo
```

Or run the same commands manually:

```bash
mkdir -p target/codex-mismatch-demo

cargo run -q -p apolysis-cli -- intent ingest \
  --adapter codex-jsonl \
  --input tests/fixtures/codex-mismatch/codex-response-items.jsonl \
  --session codex-mismatch-demo \
  --output target/codex-mismatch-demo/intent.codex.jsonl \
  --workspace-root "$PWD"

cargo run -q -p apolysis-cli -- intent correlate \
  --intent-input target/codex-mismatch-demo/intent.codex.jsonl \
  --timeline-input tests/fixtures/codex-mismatch/observed-timeline.jsonl \
  --output target/codex-mismatch-demo/intent-correlation.jsonl
```

Inspect the relevant records:

```bash
grep -F '"record_type":"intent_correlation"' \
  target/codex-mismatch-demo/intent-correlation.jsonl

grep -F '"kind":"missing_intent"' \
  target/codex-mismatch-demo/intent-correlation.jsonl
```

The finding's `evidence_ref` points back to
`codex-mismatch-demo:event:0000000000000002`, which is the `credential_read`
event in the observed timeline fixture.

## Live Recording Target

The public P1 recording should use the same story with real host evidence:

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-mismatch-demo \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-mismatch-demo/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --agent-kind codex \
  --agent-run -- codex "run the apolysis intent tests"
```

In shorthand, this is the `apolysis observe --agent-run -- codex ...` path.
After observation, ingest the retained Codex response-item JSONL with
`apolysis intent ingest`, then run `apolysis intent correlate` against the live
timeline. Use only fake credential fixtures for the demo; never point the agent
at a real `~/.aws/credentials` file.

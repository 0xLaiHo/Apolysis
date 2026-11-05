# Codex Intent Mismatch Demo

This historical launch fixture predates marker-based relations. Current
content-off ingestion produces no Exact Relation for this fixture; it reports
both a missing event relation and an unobserved historical declaration. See
[Quickstart](quickstart.md) for current output. A live marker can relate all
observed descendant attempts to a Tool Call, including credential-path access;
that relation alone does not decide whether an action was authorized.

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
- The observed timeline contains a file-open event with legacy test-command
  context, without an explicit marker or raw-event link to the declaration.
- The same observed timeline also contains an unexpected `credential_read`
  event for `/tmp/apolysis-demo-home/.aws/credentials`.
- `apolysis intent correlate` emits:
  - one `accountability_finding` with `kind:"missing_intent"` for the
    credential-path attempt;
  - one `accountability_finding` with `kind:"unobserved_intent"` for the
    historical declaration, and no Exact Relation.

Fixtures live under `tests/fixtures/codex-mismatch/`:

- `codex-response-items.jsonl`: minimal Codex JSONL response-item input.
- `observed-timeline.jsonl`: canonical host-side timeline events.
- `expected-findings.contains`: stable output fragments used by the demo gate.

## Reproduce Locally

Run the quickstart:

```bash
make quickstart
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
rg -F '"kind":"unobserved_intent"' \
  target/codex-mismatch-demo/intent-correlation.jsonl

rg -F '"kind":"missing_intent"' \
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

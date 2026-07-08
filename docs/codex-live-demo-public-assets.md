# Codex Live Demo Public Assets

This page is the curated public asset boundary for the P1 Codex live demo.
The underlying local run was validated with the privileged live observer, but
the raw `.apolysis/` evidence stays out of git.

No raw live evidence is committed. The checked-in assets under
`docs/assets/codex-live-demo/` are bounded, redacted excerpts that preserve the
launch story without publishing host paths, private chat text, tokens, or fake
credential material.

## Source Run

- Demo status: `validated_local_live`
- Source session: `codex-live-demo`
- Agent: Codex
- Observer backend: live eBPF
- Timeline size: 79,949 JSONL records
- Public evidence boundary: `curated_public_excerpt`

The live run used `apolysis observe --agent-run -- codex exec --json ...`.
Codex was asked to run `./scripts/run-codex-live-demo-workload.sh`. The
observer captured the declared workload as executable evidence and the
correlation step matched it with `match_basis:"process_executable"`.

The workload intentionally read a fake credential fixture after the declared
test command. That credential side effect was not part of the Codex tool-call
intent, so `apolysis intent correlate` emitted a `missing_intent` finding. The
credential finding target is represented only as a redacted `path_token:*`.

## Checked-In Files

- `docs/assets/codex-live-demo/summary.json`: compact public metadata for the
  validated local live run.
- `docs/assets/codex-live-demo/evidence-excerpt.jsonl`: the smallest useful
  JSONL story showing runtime metadata, the declared workload exec,
  credential policy evidence, intent correlation, and the `missing_intent`
  finding.
- `docs/assets/codex-live-demo/live-ebpf-demo.gif` / `.cast`: the README hero — a
  real `apolysis observe --backend live` run that records a workload, matches its
  declared intent, and flags an undeclared credential read as `missing_intent`.
  Recorded on a host with root / `CAP_BPF` (see the runbook); the credential path
  is redacted to a `path_token` in the evidence.
- `docs/assets/codex-live-demo/codex-live-demo.gif` / `.cast`: the zero-privilege
  quickstart recording, reproducible on any host by
  `scripts/record-quickstart-demo.sh` (no root, bundled fixture).

## Redaction Rules

The public asset gate rejects common private data patterns before these files
can pass release validation:

- absolute `/home/...` host paths;
- fake credential marker values such as `APOLYSIS_FAKE_KEY` or
  `APOLYSIS_FAKE_SECRET`;
- AWS-style access key identifiers;
- OpenAI-style `sk-...` tokens;
- `aws_access_key_id` or `aws_secret_access_key` field names;
- `password=` or `password:` fragments;
- oversized public assets.

## Launch Use

Use these assets as the first public README/demo material. The README demo GIF
and cast are a real recording of `make quickstart`, which shows the core
mismatch on the bundled fixture:

1. The agent's declared action — running the tests — is matched to observed host
   evidence by `process_command`.
2. An undeclared credential read becomes a `missing_intent` finding.

The `evidence-excerpt.jsonl` retains the smaller live-run story: a Codex-declared
workload correlated by `process_executable`, and a redacted `path_token`
credential finding from the live eBPF observer. Do not replace these excerpts
with raw live timelines; if a new one is captured, curate it with the same
scrubbing.

## Regenerate The Public Demo

The GIF and cast are a real recording of `make quickstart` — every line of
output comes from the real binary, not a hand-authored transcript:

```bash
./scripts/record-quickstart-demo.sh
```

The recorder requires `asciinema` and `agg`. It warms the build, records the
zero-privilege quickstart, and renders the GIF.

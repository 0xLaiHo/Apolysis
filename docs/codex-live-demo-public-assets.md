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
- `docs/assets/codex-live-demo/terminal-transcript.txt`: a scrubbed terminal
  transcript for README screenshot, GIF, or asciinema planning.
- `docs/assets/codex-live-demo/codex-live-demo.cast`: final public asciinema
  v2 cast generated from the scrubbed transcript.
- `docs/assets/codex-live-demo/codex-live-demo.gif`: final README demo GIF
  generated from the scrubbed transcript.

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

Use these assets as the first public README/demo material. The final README
demo GIF and asciinema cast show the same sequence:

1. Codex declares the workload command.
2. Apolysis records host-side live evidence.
3. Intent correlation matches the declared workload by `process_executable`.
4. A fake credential side effect becomes a `missing_intent` finding with a
   redacted `path_token` target.

Do not replace these excerpts with raw live timelines. If a new recording is
captured, curate a new public excerpt with the same scrubbing.

## Regenerate The Public Demo

The GIF and cast are generated from the scrubbed transcript, not from raw
`.apolysis/` evidence:

```bash
python3 scripts/render-codex-live-demo-assets.py
```

The render script requires Python with Pillow available.

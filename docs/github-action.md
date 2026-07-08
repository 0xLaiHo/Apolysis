# GitHub Action — Audit An Agent In CI

The Apolysis action wraps one workflow command with the live eBPF observer and
answers, per run: **what did this agent (or script) actually do on the runner?**
It records every process, file, network, and credential-path side effect into a
JSONL timeline, prints a digest into the job's step summary, and uploads the
full evidence as a workflow artifact.

## Minimal usage

```yaml
jobs:
  agent-task:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run the agent under audit
        uses: 0xLaiHo/Apolysis@main
        with:
          run: 'codex exec --json "run the project tests"'
```

That is the whole integration. The step summary gains a table like:

| Observed events | Policy findings | Credential reads | Network connects |
| --- | --- | --- | --- |
| 412 | 3 | 1 | 17 |

and the `apolysis-evidence-<session>` artifact holds the raw JSONL timeline for
review or replay.

The action exits with the observed command's own exit code, so a failing test
run still fails your job.

## Correlate declared intent

If the agent writes a Codex response-items log, pass it to get the
"declared X, observed Y" verdict in the same summary:

```yaml
      - uses: 0xLaiHo/Apolysis@main
        with:
          run: 'codex exec --json "run the project tests" > codex-log.jsonl'
          intent-log: codex-log.jsonl
```

The summary then reports how many side effects matched declared intent and how
many `missing_intent` findings had no declared cover. The full
`intent-correlation.jsonl` lands in the same artifact.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `run` | (required) | Command to observe, executed with `bash -c`. |
| `intent-log` | — | Codex response-items JSONL to correlate. |
| `policy` | generated | Your policy file; a minimal audit-only policy (credential deny-list, workspace `./`) is generated when omitted. |
| `session` | `apolysis-<run id>-<attempt>` | Session id written into every record. |
| `agent-kind` | `ci-agent` | Agent adapter hint label. |
| `version` | `v0.2.0` | Release to download (binary + CO-RE object, checksum-verified). |
| `binary` / `bpf-object` | — | Use pre-built artifacts instead of downloading. |
| `output-dir` | `.apolysis-action` | Where the timeline and reports are written. |

Outputs: `timeline` (path to the JSONL) and `exit-code` (observed command's
exit code).

## Requirements and honest limits

- Linux x86_64 runner with sudo and kernel BTF — standard `ubuntu-latest` works.
  Container jobs need a privileged container and host BTF.
- Audit-only: the action records and reports; it does not block anything.
- Evidence has known blind spots (for example `io_uring`-based I/O); see the
  [threat model](threat-model.md) before treating a quiet timeline as proof of
  absence.
- Everything persisted outside the workspace root is redacted to session-salted
  tokens before it is written; the artifact still deserves the same handling as
  any CI log.

The action is self-tested on every pull request by
`.github/workflows/action-self-test.yml`, which plants a fake credential,
audits a command that reads it, and asserts the timeline records the
credential read with the raw path redacted.

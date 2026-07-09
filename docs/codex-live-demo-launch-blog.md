# Apolysis: A Flight Recorder For AI Coding Agents

AI coding agents are usually reviewed through the logs their harness chooses to
keep: prompts, tool calls, terminal snippets, and final messages. Those logs
are useful, but they are not independent evidence. The harness is inside the
same trust boundary as the agent, and it normally sees only the commands it
asked the agent to run. If an operator needs to answer what a session actually
did on a Linux host, harness logs are only one side of the story.

Apolysis is the other side. It is a Linux runtime accountability layer for AI
agent workloads. It records host-side process, file, network, credential,
runtime, policy, and declared-intent evidence into append-only JSONL timelines,
then correlates those records after the session. The goal is not to replace a
sandbox, approval UI, MCP gateway, or SIEM. The goal is to give the environment
owner a flight recorder that can be reviewed independently of the agent
harness.

The first public demo focuses on a simple mismatch:

```text
The agent declared one workload command.
The host-side observer saw that command run.
The same session also read a fake credential fixture.
Apolysis reported that side effect as missing declared intent.
```

That is the shape of the problem Apolysis is designed for. The question is not
"did the agent claim the tests passed?" The question is "what host-side effects
can the operator verify after the run?"

## Three Boundaries

Agent security discussions often compress three different boundaries into one
word: sandbox. Apolysis keeps them separate.

The intent boundary is what the agent framework or tool runner declared. For a
Codex session, that can come from Codex response-item JSONL: the shell command
the agent asked to execute, the working directory, and the declared tool-call
shape.

The isolation boundary is what the runtime allowed. That might be a local
process, Docker, containerd, Kubernetes with gVisor, or a stronger runtime
later. Isolation decides what the workload can reach.

The evidence boundary is what the environment observed. This is where Apolysis
lives today. The live observer uses eBPF to collect host-side events and joins
them with runtime metadata, policy findings, and declared intent. The result is
not a claim that the workload was safe. It is a durable record of what the
workload did, where the evidence came from, and which side effects were not
covered by declared intent.

Those boundaries are independent. A harness log can be honest and still
incomplete. A sandbox can block many actions and still leave operators needing
post-session evidence. A host observer can capture useful facts without being
an enforcement engine. Apolysis deliberately starts with the evidence layer
because it is the part environment owners can deploy and audit without trusting
the agent framework to describe itself.

## The Demo

The demo uses Codex because its declared intent can be retained and parsed. The
operator runs Codex through managed launch:

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-live-demo \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-live-demo/timeline.agent-run.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --agent-kind codex \
  --agent-run -- codex exec --json \
    -C "$PWD" \
    --sandbox workspace-write \
    -c 'approval_policy="never"' \
    "Run ./scripts/run-codex-live-demo-workload.sh and report whether the Apolysis intent tests passed."
```

Managed launch matters because Apolysis owns the root process tree. The user
does not need to find a PID after the agent has already started. The observer
can attribute child processes to the session from the beginning.

In the validated local run, Codex declared the demo workload command:

```text
./scripts/run-codex-live-demo-workload.sh
```

That workload ran the Apolysis intent tests, then invoked a helper that read a
marked fake credential fixture under the demo directory. The helper refuses
unmarked files and prints only a byte count and SHA-256. The demo never reads
real credentials, and the public assets do not include raw timeline files.

The public excerpt shows the important records:

```jsonl
{"record_type":"intent_correlation","match_basis":"process_executable","command":"./scripts/run-codex-live-demo-workload.sh"}
{"record_type":"accountability_finding","kind":"missing_intent","decision":"review","evidence_boundary":"host_boundary"}
```

There are two facts in those lines. First, the declared workload did run, and
the correlation step matched it with host-side executable evidence. Second, a
credential-side effect also occurred, and no declared Codex tool-call intent
covered that side effect. Apolysis does not need to accuse the agent or infer a
hidden motive. It reports the accountable mismatch: observed side effect,
missing declared intent, review required.

## Why Harness Logs Are Not Enough

Harness logs are necessary. They tell the reviewer what the agent was asked to
do and what tool calls it requested. But they are not a complete audit plane.

First, harness logs usually sit above the operating system. They may know that
the agent asked for a shell command, but they do not naturally know every file
open, child process, runtime identity, or policy-relevant credential path seen
by the host.

Second, harness logs are formatted for interaction, not evidence retention.
They change as products change. They often include private chat text. They may
be difficult to share with a security team without exposing more than the team
needs.

Third, the important question in incident review is often comparative. Did the
declared intent cover the observed side effects? If the answer is no, the
reviewer needs the intent record and the host-side evidence record linked by a
stable session id, event id, runtime metadata, and policy context.

Apolysis is built around that comparison. It keeps append-only timelines,
redacts sensitive paths into `path_token:*` values for public material, and
separates raw evidence from curated excerpts. The public demo assets are
checked in only after a gate rejects common secret patterns, absolute host
paths, oversized excerpts, and unredacted credential markers.

## Reproduce The Demo

The safe offline starter requires no privileged eBPF access:

```bash
make quickstart
```

That command ingests a minimal Codex fixture and correlates it with a fixture
timeline containing an unexpected credential read.

For continuous integration, one step records the same host-side evidence for
whatever an agent — or any command — does on the runner, and posts a digest to
the job summary:

```yaml
- uses: 0xLaiHo/Apolysis@main
  with:
    run: 'codex exec --json "run the project tests"'
```

The action downloads the signed release, runs the command under the live
observer, correlates optional declared intent, and uploads the JSONL timeline as
an artifact. See `docs/github-action.md`.

The live recording path is documented in:

```text
docs/codex-live-demo-runbook.md
```

The live path builds the CLI and CO-RE eBPF object, prepares a marked fake
credential fixture, runs `apolysis observe --agent-run -- codex exec --json`,
retains the Codex response-item JSONL, and runs:

```bash
apolysis intent ingest ...
apolysis intent correlate ...
```

The run is launch-ready only if it produces all of these:

- an `intent_correlation` for the declared workload;
- a `missing_intent` finding for the fake credential read;
- a live timeline event for the helper that read the fake fixture;
- no real credential material in the timeline, correlation output, transcript,
  or recording.

The current public excerpt is documented in:

```text
docs/codex-live-demo-public-assets.md
```

It summarizes a validated local live run with 79,949 JSONL records, one
declared workload correlation using `process_executable`, and a redacted
`path_token:*` credential finding. The raw `.apolysis/` evidence stays out of
git.

## No Build Required

The `v0.3.0` release ships a prebuilt Linux CLI and the bundled CO-RE eBPF
object, so you can wrap a local agent command — or drop the GitHub Action into a
workflow — without compiling every piece yourself.

This release does not turn Apolysis into a complete sandbox provider or a
compliance-certified platform. It makes the accountability layer easy to try:
wrap an agent command, retain host-side evidence, ingest declared intent,
correlate the two, and review the mismatches.

## Try It

- **Five minutes, no root:** `make quickstart` shows the mismatch on a bundled
  fixture.
- **On your own agent:** follow `docs/codex-live-demo-runbook.md` (Linux,
  root / `CAP_BPF`).
- **In CI:** add the GitHub Action to a workflow.

If Apolysis surfaces a side effect you did not expect, that is exactly the
report it is built to produce. Tell us what it found.

## Where This Goes Next

The product direction is intentionally constrained. Apolysis improves the shared
evidence spine first: stable schema, managed agent launch, intent correlation,
runtime metadata, policy findings, and evidence verification. Stronger isolation
and richer deployment surfaces can consume that spine later, when real use asks
for them.

For now, the core promise is simple: when an AI coding agent says what it did,
the environment owner should have an independent way to check.

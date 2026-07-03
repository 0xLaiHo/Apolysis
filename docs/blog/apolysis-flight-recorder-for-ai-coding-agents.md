# Apolysis: A Flight Recorder For AI Coding Agents

AI coding agents are starting to look less like chatbots and more like local
automation systems. A useful agent can inspect a repository, run tests, install
tools, call shells, edit files, and coordinate subprocesses. That is exactly
why the audit boundary matters. The interesting security question is no longer
only what the agent said it would do. The question is what actually happened on
the host after the harness started running work.

Apolysis is a Linux runtime accountability layer for that question. It is not
a replacement for a sandbox, an MCP gateway, a tool approval UI, or Kubernetes.
It is a flight recorder owned by the environment. It observes process, file,
network, credential, runtime, and declared-intent evidence from outside the
agent harness, then writes audit records that can be reviewed after the run.

The short version is simple: the agent declared one action, but host-side
evidence showed another side effect.

## Why Harness Logs Are Not Enough

Harness logs are useful. They show prompts, model responses, tool calls, and
the application-level view of a session. But harness logs are insufficient as a
single source of truth for runtime accountability.

A harness can omit retries. It can wrap a command in a shell. It can spawn a
helper process. A plugin can touch files that are not obvious from the top-level
tool call. A command can read a credential path as a side effect. A sandbox can
change what host-side process evidence looks like. A local agent can also run
with a broader filesystem or network boundary than the operator expected.

None of those cases mean the harness is malicious. They mean the harness is not
the operating system. For incident review, policy feedback, and platform
debugging, the environment needs an evidence stream that is not produced by the
same component being audited.

Apolysis keeps that distinction explicit. The harness can still declare intent.
The runtime still enforces reachability. Apolysis records what the host or
runtime observed.

## The Three-Layer Model

Apolysis follows a practical three-layer model for agent security:

1. Intent authorization asks what the agent should do. This is usually owned by
   the agent harness, MCP server, tool gateway, OAuth scopes, or approval flow.
   Apolysis can ingest declared intent records, but it does not replace this
   layer.

2. Execution isolation asks what the agent can reach. This is usually owned by
   Docker, gVisor, Kata Containers, Firecracker, Kubernetes, or a managed
   sandbox provider. Apolysis records runtime metadata and visibility limits,
   but it does not claim to be a full sandbox.

3. Side-effect verification asks what actually happened. This is the layer
   Apolysis owns. It observes host-side and runtime-side evidence, correlates
   it with declared intent and policy, and writes append-only records that an
   operator can inspect.

That separation matters because different teams own different layers. A model
provider or agent framework may own the harness. A platform team may own the
runtime. The environment operator still needs an independent record of side
effects.

## The Codex Demo

The first public demo uses Codex because Apolysis already has a Codex intent
adapter. The recording path is:

```bash
apolysis observe --agent-run -- codex exec --json ...
```

Codex is asked to run one workload command:

```bash
./scripts/run-codex-live-demo-workload.sh
```

The live observer records the Codex-managed process tree. The intent ingest
step reads the Codex response-item JSONL and emits append-only intent records.
The correlation step compares those declared intents with the observed
timeline.

The important linked record is an `intent_correlation` for the declared
workload. In the live run, argv capture was truncated, so Apolysis did not rely
only on exact command text. It matched the declared workload through
`process_executable`, which is the stable executable evidence emitted by the
live observer.

Then the workload intentionally reads a fake credential fixture. The fixture is
marked as fake, the helper refuses unmarked credential files, and the public
asset never includes credential material. The point is to create a realistic
side effect without touching a real secret. That side effect is not part of the
Codex tool-call intent, so Apolysis emits an `accountability_finding` with
`kind:"missing_intent"`. The sensitive target is represented only as a redacted
`path_token`.

That is the story Apolysis is trying to make reviewable:

```text
Codex declared: run ./scripts/run-codex-live-demo-workload.sh
Apolysis saw:   declared workload exec matched by process_executable
Apolysis also saw: fake credential side effect
Finding:        missing_intent, target=path_token:*
```

## What Is Committed

No raw live evidence is committed. The public repository contains only a
curated boundary under `docs/assets/codex-live-demo/`:

- `summary.json` records compact public metadata for the validated local live
  run.
- `evidence-excerpt.jsonl` keeps the minimum JSONL story: runtime metadata, the
  declared exec event, the credential policy evidence, the intent correlation,
  and the finding.
- `terminal-transcript.txt` is a scrubbed transcript for screenshots and launch
  material.
- `terminal-demo.svg` is a static README-first visual derived from the scrubbed
  transcript.

The gate for those assets is:

```bash
make test-codex-live-demo-public-assets
```

For this launch write-up and visual material, the additional gate is:

```bash
make test-p1-launch-materials
```

Those gates reject common private data patterns, including absolute operator
home paths, credential marker values, AWS-style key identifiers, OpenAI-style
tokens, AWS credential field names, password fragments, and oversized public
files. They also require the demo story to preserve the important terms:
`validated_local_live`, `process_executable`, `missing_intent`, and
`path_token`.

## Reproduce The Safe Path

Start with the offline fixture if you only want to understand the correlation
model:

```bash
make test-codex-mismatch-demo
```

That fixture does not require privileged eBPF. It shows a declared Codex
command, an observed host-side timeline, and the resulting correlation output.

Use the live runbook when you want to record real host evidence:

```bash
docs/codex-live-demo-runbook.md
```

The live path builds the CLI and CO-RE BPF object, prepares a marked fake
credential fixture, starts the observer with `--agent-run`, ingests retained
Codex intent records, and correlates intent with the live timeline. The raw
recording belongs under `.apolysis/` or `target/`, not in source control.

## What This Proves And What It Does Not

This demo proves that Apolysis can connect a real local agent run to host-side
evidence, then explain where declared intent and observed side effects diverge.
It also proves that public launch material can be derived from a live run
without publishing raw logs.

It does not prove that Apolysis prevents the read. The current public path is
audit and review. Narrow enforcement work exists elsewhere in the roadmap, but
the launch story is intentionally smaller: build a durable, environment-owned
record of what happened first.

That is the product boundary. Apolysis is the flight recorder for AI agent
workloads. It makes the runtime evidence reviewable when the harness story is
not enough.

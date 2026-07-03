# Apolysis

[![Release Validation](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml/badge.svg)](https://github.com/0xLaiHo/Apolysis/actions/workflows/release-validation.yml)
[![Latest Release](https://img.shields.io/github/v/release/0xLaiHo/Apolysis?sort=semver)](https://github.com/0xLaiHo/Apolysis/releases)
[![License](https://img.shields.io/github/license/0xLaiHo/Apolysis)](LICENSE)

[English](README.md) | [Simplified Chinese](README.zh-CN.md)

**30-second summary:** Apolysis is an environment-owned flight recorder for AI
agent workloads. It records what an agent session actually did on Linux, then
correlates host-side process, file, network, credential, runtime, and declared
intent evidence into audit records that can be reviewed independently of the
agent harness.

**Demo status:** P1 demo starter assets are available in
[`docs/codex-intent-mismatch-demo.md`](docs/codex-intent-mismatch-demo.md).
They replay a Codex run where declared intent is compared with host-side
evidence and an unexpected fake credential read becomes a `missing_intent`
finding. The live recording procedure is staged in
[`docs/codex-live-demo-runbook.md`](docs/codex-live-demo-runbook.md). The
privileged live path has been validated locally; the final public asciinema/GIF
is still planned after the captured evidence is curated and scrubbed.

Apolysis is a Linux runtime accountability layer for AI agent workloads. It
collects environment-owned evidence below the agent harness, correlates that
evidence with declared intent and runtime metadata, and writes audit records
that can be reviewed independently of the agent or tool runner.

Apolysis is designed for teams that run coding agents, automation agents, or
untrusted generated code and need a durable answer to a simple question:
what did this session actually do on the host or runtime?

## Why Apolysis

Agent harness logs are useful, but they are not a complete source of truth. A
harness may hide retries, spawn subprocesses, route tools through plugins,
handle credentials, or run with broad filesystem and network access. Apolysis
keeps the evidence boundary outside that harness.

Apolysis focuses on three responsibilities:

- Record process, file, network, runtime, and policy evidence in an append-only
  JSONL timeline.
- Correlate local processes, Docker containers, Kubernetes metadata, and
  runtime isolation signals with a single agent session.
- Provide policy decisions and operator feedback without overstating what the
  runtime can enforce.

It is not a replacement for Docker, gVisor, Kata Containers, Firecracker,
Kubernetes, an MCP gateway, or an approval UI. It complements those systems by
recording side effects and runtime context from the environment's point of
view.

## Capabilities

- Local command wrapper that tracks a session from process start to exit.
- Docker runtime adapter with conservative defaults, labels, resource limits,
  and container metadata capture.
- Fixture and live eBPF observer backends for process, bounded exec argv, file,
  network, and credential-related events.
- Policy evaluation with `Notify`, `Review`, `Kill`, and explicitly downgraded
  `Block` behavior when kernel support is unavailable.
- Kubernetes and Agent Sandbox metadata parsing for Pod, namespace,
  RuntimeClass, service account, and node context.
- Strong-isolation visibility assessment for runtimes where host-side evidence
  does not capture guest semantics.
- Node-local daemon, health model, metrics, recovery checks, and Kubernetes
  deployment assets.
- Evidence packaging, retention, signing, registry, and release-readiness
  validation scripts for regulated environments.

## Architecture

Apolysis keeps intent, isolation, and evidence as separate layers:

- Intent authorization: what the agent or operator says should happen.
- Execution isolation: what the runtime allows the workload to touch.
- Side-effect verification: what the operating system and runtime show actually
  happened.

The repository is split into small Rust crates:

- `apolysis-cli`: command-line entry point for running and observing sessions.
- `apolysis-core`: shared schemas and JSONL record types.
- `apolysis-runtime`: local and Docker runtime adapters.
- `apolysis-observer`: fixture and live observer backends.
- `apolysis-policy`: policy parser and decision logic.
- `apolysis-store`: append-only JSONL writer and hash-chain support.
- `apolysis-kubernetes`: Kubernetes and Agent Sandbox metadata parsing.
- `apolysis-visibility`: strong-isolation visibility assessment.
- `apolysis-accountability`: session, finding, queue, and health contracts.
- `apolysis-daemon`: node-local Unix socket service.
- `apolysis-feedback`: agent-facing feedback files.

The versioned JSONL record contract is documented in
[`docs/jsonl-schema-v1.md`](docs/jsonl-schema-v1.md).

## Requirements

- Linux development host.
- Rust stable toolchain and Cargo.
- Docker CLI and daemon for Docker runtime execution.
- For live eBPF observation: `clang`, `llvm-strip`, `bpftool`, kernel BTF, and
  the required Linux capabilities or root privileges.

Most unit and fixture tests do not require root.

## Release Artifacts

Tagged releases attach a Linux artifact bundle that contains the `apolysis`
CLI, the CO-RE `apolysis_observer.bpf.o` object, a release manifest, a detached
SHA-256 checksum, and release-signing evidence produced from retained F6
signing evidence:

Before publishing a new demo or release, run the
[`Release Artifact Dry Run`](docs/release-artifact-dry-run.md) to prove the
workflow can build and upload the artifact bundle without mutating a public
GitHub Release.

```bash
version=v0.2.0
target=x86_64-unknown-linux-gnu
asset="apolysis-${version}-${target}.tar.gz"

gh release download "$version" \
  --repo 0xLaiHo/Apolysis \
  --pattern "$asset*" \
  --pattern apolysis-release-manifest.json \
  --pattern apolysis-release-signing-manifest.json \
  --pattern apolysis-release-signing-evidence.json \
  --pattern apolysis-regulated-release-signing-evidence-report.json

sha256sum -c "$asset.sha256"
sha256sum apolysis-release-manifest.json
tar -xzf "$asset"
```

`apolysis-release-signing-manifest.json` records the SHA-256 of
`apolysis-release-manifest.json` that was covered by retained regulated-release
signing evidence. Treat a missing signing manifest, a hash mismatch, or
`release_signing_ready:false` as an unsigned release.

After extraction, use the bundled BPF object with live observation:

```bash
sudo -E "./apolysis-${version}-${target}/bin/apolysis" observe \
  --backend live \
  --session codex-local-audit \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --bpf-object "./apolysis-${version}-${target}/ebpf/apolysis_observer.bpf.o" \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex resume <codex-session-id>
```

## Build

Build the workspace and eBPF object:

```bash
make build
```

Build only the eBPF object:

```bash
make build-ebpf
```

Format and lint:

```bash
cargo fmt --all
make lint
```

## Test

Run the default Rust test suite:

```bash
make test
```

Run the capability-aware live observer smoke test on a host prepared for eBPF:

```bash
make test-live
```

Production and release validation scripts are exposed as Make targets. They are
intended for operator workflows and CI jobs that need explicit evidence gates.
The no-secret handoff gate checks that release-validation runbooks and roadmap
status remain aligned, and the preflight fixture gate checks the retained
evidence readiness report plus evidence index generation path. The CI contract
gate checks that the release-validation GitHub Actions workflow stays
repo-local, credential-free, and retains stable evidence artifacts:

```bash
make test-release-validation-handoff
make test-release-validation-preflight
make test-release-validation-ci
```

## Production Usage Examples

Use these examples when you want to run Apolysis as an operator-owned evidence
layer around real agent work. They keep generated timelines and validation
reports in ignored `.apolysis/` or `target/` paths. Do not commit those outputs,
kubeconfigs, provider credentials, signing material, or captured private
workload data.

### Audit a local agent command

Use this live-observer pattern when you want Apolysis to launch a local coding
agent and own the observed root PID. The operator no longer has to run `ps` or
choose among multiple Codex processes; `--agent-run -- <command>` starts the
agent under the live observer and records supervisor metadata in the timeline.
Managed launch seeds the process-tree scope from the agent root, its threads,
and discoverable descendants before attach.
For managed launch, `--duration-seconds` is an upper bound: the observer drains
and records agent exit metadata when the agent finishes earlier.

```bash
mkdir -p .apolysis/codex-live

sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-audit \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-live/timeline.agent-run.jsonl \
  --output-max-bytes 104857600 \
  --output-max-files 8 \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind codex \
  --agent-run -- codex resume <codex-session-id>
```

`--output-max-bytes` and `--output-max-files` bound local JSONL growth. When
the active timeline would exceed the byte budget, Apolysis rotates
`timeline.agent-run.jsonl` to `timeline.agent-run.jsonl.1`, shifts older
archives, and records `observer-output-rotation` metadata with
`max_file_bytes` and `max_archived_files`. A single JSONL record is never split
across files.

### Verify a Shipped Daemon Timeline

After copying a daemon session timeline out of a node, verify the hash-chain
without mutating the evidence:

```bash
./target/debug/apolysis verify hash-chain \
  --input /var/lib/apolysis/sessions/<session-id>/timeline.jsonl \
  --output target/hash-chain-verification/<session-id>.report.json
```

The command exits `0` for a valid timeline, `1` when verification fails and a
report is written, and `2` when the command cannot run. The report includes
`record_count`, `last_sequence`, `last_record_hash`, `valid_bytes`,
`total_bytes`, and `failure`.

If another trusted supervisor has already started the agent, have that
supervisor write an explicit registration file instead of asking the operator
to choose a PID by process name:

```json
{
  "agent_kind": "codex",
  "pid": 12345,
  "start_time_ticks": 987654321,
  "workspace_root": "/srv/agents/repo",
  "executable": "/home/agent/.nvm/versions/node/bin/codex",
  "command_fingerprint": "sha256:<hex>",
  "command": "codex resume <codex-session-id>"
}
```

Then attach with the registration file. Apolysis compares the recorded
`start_time_ticks` with `/proc/<pid>/stat` before attach and fails closed if
the PID has been reused:

```bash
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session codex-local-audit \
  --policy policies/local-dev.yaml \
  --output .apolysis/codex-live/timeline.agent-registration.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-registration .apolysis/codex-live/agent-registration.json
```

A diagnostic-only discovery fallback is available for local troubleshooting:
`--agent-kind codex --agent-discover`. It scores candidates by kind, workspace,
session id, executable path, command line, and parent chain, and refuses to
attach when more than one candidate remains.

Review the resulting timeline:

```bash
wc -l .apolysis/codex-live/timeline.agent-run.jsonl

jq -c 'select(.resource=="agent-supervisor-mode" or .resource=="agent-kind" or .resource=="agent-root-pid" or .resource=="agent-command" or .resource=="agent-command-fingerprint" or .resource=="observer-scope")' \
  .apolysis/codex-live/timeline.agent-run.jsonl

jq -r '.event_type // .event_name // .kind // .record_type' \
  .apolysis/codex-live/timeline.agent-run.jsonl | sort | uniq -c

jq -c 'select(.event_type=="network_connect" or .event_type=="process_exit" or .event_name=="connect")' \
  .apolysis/codex-live/timeline.agent-run.jsonl

jq -c 'select(.event_type=="exec" or .event_name=="sched_process_exec") | {record_type,event_name,event_type,pid,actor,resource,raw_payload}' \
  .apolysis/codex-live/timeline.agent-run.jsonl

jq -c 'select(.record_type=="raw_kernel_event" and .event_id!=null) | {event_id,event_name,pid,resource,raw_payload}' \
  .apolysis/codex-live/timeline.agent-run.jsonl | head

jq -c 'select(.record_type=="event" and .raw_event_id!=null) | {raw_event_id,event_type,pid,resource}' \
  .apolysis/codex-live/timeline.agent-run.jsonl | head

jq -c 'select(.record_type=="event" and .process_command!=null) | {event_type,pid,resource,process_command,process_executable,process_started_at_unix_ms,raw_event_id}' \
  .apolysis/codex-live/timeline.agent-run.jsonl | head

jq -c 'select((.record_type=="policy_violation" or .record_type=="enforcement_metadata") and .observed_event_id!=null) | {record_type,rule_id,observed_event_id,decision,effective_decision}' \
  .apolysis/codex-live/timeline.agent-run.jsonl | head
```

Live exec records keep the executable path as the canonical `resource` and
store bounded, redacted argv evidence on the matching raw `sched_process_exec`
record. Sensitive argv values and credential-looking paths are redacted before
persistence; truncation is marked with `argv_truncated:true` or
`payload_truncated:true` when limits are reached. Raw kernel records include
`event_id`; canonical records include `raw_event_id`; policy and enforcement
records include `observed_event_id` when they are generated from a specific
observed event. When a successful exec has been observed for a PID, later
canonical exec, file, network, and process-exit records can include the
redacted `process_command`, `process_executable`, and
`process_started_at_unix_ms` context for that process.

Manual `--scope-pid` remains available as a low-level diagnostic fallback for
already-running processes, but production examples should prefer managed launch
or an explicit agent registration file.

### Import Codex intent records

If you retain a Codex JSONL harness log for the same session, ingest its
tool-call records into append-only `intent` records. This is the first
correlation input: it records what the harness declared, while the live
timeline records what the host observed.
With an installed binary, the command is `apolysis intent ingest`.

```bash
cargo run -p apolysis-cli -- intent ingest \
  --adapter codex-jsonl \
  --input .apolysis/codex-live/codex-response-items.jsonl \
  --session codex-local-audit \
  --output .apolysis/codex-live/intent.codex.jsonl \
  --workspace-root "$PWD"

jq -c 'select(.record_type=="intent") | {intent_source,intent_id,tool_name,declared_action,command,raw_event_id}' \
  .apolysis/codex-live/intent.codex.jsonl
```

`raw_event_id` is `null` at ingestion time unless the source log already
contains a stable event link. Correlate the imported intent records with the
live timeline after observation has finished. With an installed binary, the
correlation command is `apolysis intent correlate`.

```bash
cargo run -p apolysis-cli -- intent correlate \
  --intent-input .apolysis/codex-live/intent.codex.jsonl \
  --timeline-input .apolysis/codex-live/timeline.agent-run.jsonl \
  --output .apolysis/codex-live/intent-correlation.jsonl

jq -c 'select(.record_type=="intent_correlation") | {intent_source,intent_id,match_basis,raw_event_id,event_type,pid,resource}' \
  .apolysis/codex-live/intent-correlation.jsonl

jq -c 'select(.record_type=="accountability_finding") | {kind,decision,evidence_ref,reason}' \
  .apolysis/codex-live/intent-correlation.jsonl
```

Correlation prefers `raw_event_id` matches when present and otherwise uses
exact redacted process-command context as a conservative fallback. Side effects
without plausible intent are emitted as `missing_intent`; declared intent with
no observed side effect is emitted as `unobserved_intent`. Secret-looking
command values and credential-looking paths are redacted before persistence.

### Run an agent in Docker or gVisor

Use Docker when you want Apolysis to start the workload with conservative
container defaults and record the resulting runtime metadata:

```bash
mkdir -p .apolysis/prod-docker

cargo run -p apolysis-cli -- run \
  --runtime docker \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/prod-docker/timeline.jsonl \
  -- sh -lc 'echo "agent-session:$APOLYSIS_SESSION_ID"'

jq -c 'select(.event_type=="runtime_metadata" or .event_type=="process_exit")' \
  .apolysis/prod-docker/timeline.jsonl
```

If gVisor `runsc` is installed, keep the same policy and select the OCI runtime
explicitly:

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --docker-runtime runsc \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/prod-docker/runsc-timeline.jsonl \
  -- sh -lc 'echo "agent-session:$APOLYSIS_SESSION_ID"'
```

Apolysis records the container image, OCI runtime, cgroup mapping, network
mode, mounts, resource limits, and Apolysis session labels. Treat Docker as a
baseline runtime adapter; use gVisor, Kata, Firecracker, Kubernetes, or another
runtime boundary for stronger isolation claims.

### Attach Kubernetes or Agent Sandbox metadata

Apolysis does not yet ship a Kubernetes controller or admission webhook. In
production, capture the pod metadata owned by your platform and attach it to
the observed session so the timeline includes pod, namespace, service account,
RuntimeClass, node, and Agent Sandbox identity:

```bash
mkdir -p .apolysis/prod-kubernetes

kubectl get pod <agent-pod> -n <namespace> -o yaml \
  > .apolysis/prod-kubernetes/pod.yaml

cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session prod-kubernetes-agent \
  --policy tests/fixtures/policies/policy-feedback-block-policy.yaml \
  --output .apolysis/prod-kubernetes/timeline.jsonl \
  --feedback-dir .sandbox \
  --kubernetes-metadata .apolysis/prod-kubernetes/pod.yaml

jq -c 'select(.actor=="kubernetes" or .resource=="agent-sandbox" or .record_type=="policy_violation")' \
  .apolysis/prod-kubernetes/timeline.jsonl
```

For agent pods, prefer `runtimeClassName: gvisor` or `runtimeClassName:
kata-qemu`, disable service-account token automount unless the agent needs API
access, and pair the pod with a default-deny `NetworkPolicy` plus narrow allow
rules.

### Deploy the node-local daemon with Helm

Use the Helm chart when the cluster should run `apolysisd` as a node-local
DaemonSet with bounded capabilities, read-only runtime socket mounts,
tenant-scoped state paths, health probes, low-cardinality metrics, NetworkPolicy
defaults, and optional Istio mTLS handoff annotations:

```bash
helm lint deploy/helm/apolysis \
  --set tenant.id=platform-prod \
  --set namespace.name=apolysis-system

helm template apolysis deploy/helm/apolysis \
  --namespace apolysis-system \
  --set tenant.id=platform-prod \
  --set namespace.name=apolysis-system \
  --set image.repository=ghcr.io/0xlaiho/apolysis \
  --set image.tag=0.1.0 \
  --set mesh.istio.enabled=true \
  --set 'mesh.istio.metricsAuthorizationPolicy.allowedPrincipals[0]=cluster.local/ns/monitoring/sa/prometheus' \
  | kubectl apply --dry-run=client --validate=false -f -

helm upgrade --install apolysis deploy/helm/apolysis \
  --namespace apolysis-system \
  --create-namespace \
  --set tenant.id=platform-prod \
  --set namespace.name=apolysis-system \
  --set image.repository=ghcr.io/0xlaiho/apolysis \
  --set image.tag=0.1.0

kubectl -n apolysis-system rollout status daemonset/apolysis
kubectl -n apolysis-system port-forward svc/apolysis-metrics 9909:9909
curl -s http://127.0.0.1:9909/metrics | grep '^apolysis_'
```

Run `make test-production-hardening-helm-production` before changing chart
defaults. Run live Kubernetes gates only in a validation cluster that you are
prepared to mutate.

### Validate a regulated release handoff

Use the release-validation gates when a release operator needs retained
evidence for signing, immutable archive retention, registry promotion,
managed service mesh, and final sign-off:

```bash
make test-release-validation-handoff
make test-release-validation-ci

APOLYSIS_REQUIRE_RELEASE_VALIDATION_PREFLIGHT=1 \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_PROVIDER_ROOT=<provider-root> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_AGGREGATE_REPORT=<aggregate-report.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_EXTERNAL_RETENTION_READBACK_EVIDENCE=<external-readback.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_IMMUTABLE_REGISTRY_READBACK_EVIDENCE=<registry-readback.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_FINAL_SIGNOFF=<final-signoff.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_INDEX=target/release-validation/operator-evidence-index.json \
  ./scripts/release-validation-preflight.sh
```

Required-mode preflight fails closed until every retained input, provider
readback, final sign-off field, and secret-scan expectation is present.

## Run A Local Session

Run a command and write a JSONL timeline:

```bash
cargo run -p apolysis-cli -- run \
  --policy policies/local-dev.yaml \
  --output .apolysis/timeline.jsonl \
  -- echo hello
```

Inspect the result:

```bash
cat .apolysis/timeline.jsonl
```

The timeline includes session lifecycle records, runtime metadata, executed
processes, policy decisions, and process exit status.

## Run With Docker

Run the same command inside Docker:

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-timeline.jsonl \
  -- echo hello
```

Use an alternate OCI runtime, such as gVisor `runsc`, when it is installed:

```bash
cargo run -p apolysis-cli -- run \
  --runtime docker \
  --docker-runtime runsc \
  --image alpine:3.20 \
  --policy policies/docker-baseline.yaml \
  --output .apolysis/docker-runsc.jsonl \
  -- echo hello
```

The Docker adapter injects `APOLYSIS_SESSION_ID`, writes Apolysis labels, uses
read-only filesystem and network-deny defaults, drops capabilities, applies
resource limits, and records container image, OCI runtime, mounts, network mode,
container ID, and cgroup mapping metadata.

## Observe Fixture Events

Use fixture input when developing policies, schemas, or timeline processing
without requiring privileged kernel access:

```bash
cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session demo-fixture \
  --policy policies/local-dev.yaml \
  --output .apolysis/observer-timeline.jsonl
```

The observer writes raw kernel-event records and canonical side-effect events.
The fixture set covers process execution, file operations, network connects,
and credential-path reads.

## Observe Live Host Activity

On a capable Linux host, build the eBPF object and run the live observer:

```bash
make build-ebpf
make build
sudo -E ./target/debug/apolysis observe \
  --backend live \
  --session demo-live \
  --policy policies/local-dev.yaml \
  --output .apolysis/live-timeline.jsonl \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --scope-pid <root-pid> \
  --workspace-root "$PWD"
```

The live backend is audit-oriented. Pre-operation blocking is only available in
narrow, explicitly enabled prototypes and should not be represented as a
general production enforcement guarantee.

## Kubernetes Deployment Assets

Kubernetes manifests and Helm assets live under `deploy/`:

```text
deploy/kubernetes/
deploy/helm/apolysis/
deploy/container/
deploy/systemd/
```

The Kubernetes deployment assets include RBAC, NetworkPolicy, DaemonSet,
RuntimeClass examples, service mesh policy examples, and production-oriented
container hardening checks.

## Release Validation

The repository includes validation scripts for regulated environments that need
external signing, immutable archive retention, registry promotion, and managed
service-mesh evidence. These scripts write local evidence under `target/` and
are intended to be run with explicitly scoped provider credentials. The
release-validation handoff gate is safe to run without provider credentials and
checks the runbook, reproducibility inputs, and privacy expectations. The
release-validation preflight gate validates retained evidence inputs and writes
an evidence index for operator handoff.

## Repository Layout

```text
crates/              Rust workspace crates.
ebpf/                eBPF source and shared observer ABI.
deploy/              Kubernetes, Helm, container, and systemd assets.
policies/            Example audit policies.
scripts/             Build, validation, release, and evidence gates.
tests/fixtures/      Fixture events, policies, metadata, and expected output.
docs/                Focused technical notes.
```

Generated build artifacts and local evidence output belong under `target/` or
`.apolysis/` and should not be committed.

## Security Model

Apolysis records evidence. It does not make an unsafe runtime safe by itself.
Runtime isolation remains the responsibility of the configured container, VM,
Kubernetes, or host policy boundary.

Important defaults and constraints:

- Treat Docker as a baseline runtime adapter, not as a strong isolation claim.
- Do not claim guest-level visibility for VM-backed runtimes from host-only
  evidence.
- Do not claim broad pre-operation blocking unless the exact kernel path and
  rollback behavior have been validated.
- Keep credentials, kubeconfigs, provider tokens, signing material, and captured
  private workload data out of committed artifacts.

## Documentation

- `docs/visibility-validation.md` explains host and guest visibility limits.
- `docs/release-validation-handoff.md` documents regulated-release validation
  handoff and reproducible evidence-package inputs.
- `docs/threat-model.md` summarizes the project security boundary.
- `docs/starter-issues.md` lists small labeled starter issues for first
  contributors.
- `deploy/kubernetes/README.md` documents Kubernetes deployment assets.
- `ebpf/observer/README.md` documents the observer eBPF program.

## Community

- `CONTRIBUTING.md` documents the development workflow, verification gates, and
  privacy rules for pull requests.
- `SECURITY.md` documents supported versions, vulnerability reporting, and the
  security scope.

Detailed roadmap, research notes, validation history, and release-readiness
records are maintained outside the top-level README so this file can stay
focused on using and operating the project.

## Direction

Apolysis positions itself as a flight recorder for AI agent workloads:
installed by the environment owner, independent of harness logs. The current
direction, in dependency order, is attribution closure and adoptable release
packaging, then harness intent correlation, then scale hardening, then a
single narrow validated enforcement path. Details live in the roadmap
documents maintained alongside this repository.

## License

Apolysis userspace components are licensed under Apache-2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

Kernel-loaded eBPF programs under `ebpf/` are licensed under GPL-2.0-only where
required by Linux kernel BPF licensing rules. See
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).

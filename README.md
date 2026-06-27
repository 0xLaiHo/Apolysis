# Apolysis

[English](README.md) | [Simplified Chinese](README.zh-CN.md)

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
- Fixture and live eBPF observer backends for process, file, network, and
  credential-related events.
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

## Requirements

- Linux development host.
- Rust stable toolchain and Cargo.
- Docker CLI and daemon for Docker runtime execution.
- For live eBPF observation: `clang`, `llvm-strip`, `bpftool`, kernel BTF, and
  the required Linux capabilities or root privileges.

Most unit and fixture tests do not require root.

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
- `deploy/kubernetes/README.md` documents Kubernetes deployment assets.
- `ebpf/observer/README.md` documents the observer eBPF program.

Detailed roadmap, research notes, validation history, and release-readiness
records are maintained outside the top-level README so this file can stay
focused on using and operating the project.

## License

Apolysis userspace components are licensed under Apache-2.0. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

Kernel-loaded eBPF programs under `ebpf/` are licensed under GPL-2.0-only where
required by Linux kernel BPF licensing rules. See
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).

# Contributing To Apolysis

Thanks for helping improve Apolysis. Keep contributions focused on the project
scope: an operator-owned Linux runtime accountability layer for AI agent
workloads. Apolysis records evidence; it is not a sandbox provider, approval UI,
or central security platform.

## Development Workflow

Do not develop directly on main. Start each change from the latest `main` and
use a focused branch:

```bash
git switch main
git pull --ff-only origin main
git switch -c feat/<short-name>
```

Use these branch prefixes:

- `feat/<short-name>` for features.
- `fix/<short-name>` for bug fixes.
- `docs/<short-name>` for documentation-only updates.
- `test/<short-name>` for validation or test-only work.
- `release/<version-or-scope>` for release preparation.

Keep each branch narrow. Do not mix unrelated feature work, release work,
roadmap edits, and cleanup refactors in one pull request.

## Verification

Run the smallest relevant gate for the change first, then run the broader gates
before opening a pull request.

Default local gates:

```bash
cargo fmt --all -- --check
cargo test --workspace
make lint
git diff --check
```

Live eBPF, Kubernetes, provider, signing, or release-validation changes must
state the exact privileged or external gate that was run. If a gate is skipped
because credentials, kernel features, or cluster access are unavailable, say so
in the pull request.

## Privacy And Captured Data

Do not commit secrets, kubeconfigs, provider credentials, signing material,
private workload data, generated timelines, retained evidence bundles, or local
release artifacts. Generated outputs belong under `target/` or `.apolysis/`.

When adding examples, prefer redacted values and fixture paths. When adding
observer behavior, preserve persistence-time redaction and explicit truncation
markers.

## Pull Requests

Pull requests should include:

- Purpose and scope.
- Files or modules changed.
- Verification commands and results.
- Privileged, live, provider, Kubernetes, or kernel assumptions.
- Privacy and secret-leak checks performed.
- Rollback or cleanup notes when host, runtime, provider, or release state may
  be affected.

All pull requests must pass required CI and review before merging to `main`.

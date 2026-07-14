# GitHub Action — Audit An Agent In CI

The Apolysis Action wraps one workflow command with the live eBPF observer. It
records process, file, network, and credential-path activity in a JSONL
timeline, writes an advisory digest to the job summary, and uploads the sealed
timeline as a workflow artifact.

## Availability

The hardened wrapper documented here is a pre-release candidate. It downloads
the immutable v0.3.0 executable bundle, but the v0.3.0 commit itself contains
the older Action interface with caller-selected paths; do not cite that public
wrapper as providing this privilege boundary. The bundle also predates the
current-source content-off persistence seam. The candidate keeps the top-level
`run` text out of observer launch metadata by staging it in a root-owned file,
but v0.3.0 can still persist arguments and reconstructed process-command
content for child processes executed by that script. Do not put secrets in
`run` or child argv. Publication is blocked until
an immutable post-content-off bundle replaces v0.3.0. For evaluation after this
change reaches the protected integration branch:

```yaml
jobs:
  agent-task:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run the agent under audit
        # Evaluation only. Pin the next hardened immutable release commit for
        # any production use.
        uses: 0xLaiHo/Apolysis@pre-release
        with:
          run: 'codex exec --json "run the project tests"'
          session: agent-task
```

The artifact is named
`apolysis-evidence-<run-id>-<attempt>-<session>`. The Action step uses the
observed command's runner-recorded success or failure; it deliberately exposes
no numeric exit-code or filesystem-path output through GitHub workflow command
files.

## Correlate declared intent

An optional Codex response-items log adds an advisory declared-versus-observed
summary:

```yaml
        with:
          run: 'codex exec --json "run the project tests" > codex-log.jsonl'
          session: agent-task
          intent-log: codex-log.jsonl
```

Intent input is supplied by the workflow and is not upgraded to kernel-evidence
trust. Derived correlation files are temporary; only the root-sealed timeline
is uploaded.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `run` | (required) | Non-empty command staged root-owned and executed by non-root Bash with `-p`. |
| `session` | (required) | Unique per job; 1–128 safe identifier characters. |
| `agent-kind` | `ci-agent` | Bounded agent adapter label. |
| `policy` | generated | Regular, single-link, non-symlink file inside the workspace, limited to 1 MiB. |
| `intent-log` | — | Optional Codex response-items JSONL for an advisory summary. |

Repeated Action invocations in one job must use distinct sessions. A collision
fails closed instead of reusing an existing privileged path.

## Privilege boundary

The wrapper rejects an already-root runner or one whose primary group is root,
and requires non-interactive sudo. It derives fixed paths only from GitHub's
numeric run identity and the validated session, beneath sticky root-owned
`/var/tmp`.

The install step downloads the fixed v0.3.0 bundle and checks the SHA-256 digest
embedded in the Action. Root extracts only the expected executable and CO-RE
object with archive ownership and permissions disabled, then asserts root
ownership, regular-file type, single-link count, and exact read/execute modes
before use. Curl starts with configuration disabled and both curl and tar run
under a minimal root environment. The workspace cannot select these privileged
inputs.

A custom policy is opened component by component without following symlinks,
validated from that same descriptor, bounded to 1 MiB, and streamed into the
root-only stage. The non-empty command is staged separately as a root-owned,
single-link file; immediately before launch it becomes group-readable but not
writable by the runner. Every control-plane Bash starts in Bash `-p` mode,
and shell-startup plus dynamic-loader variables are neutralized. The observer
is execed through a root-owned isolated environment sanitizer rather than a
root shell; that sanitizer removes exported Bash functions before v0.3.0's
fixed gate shell starts. Its timeline is
pre-reserved root-owned, single-link, and mode `0600`, while workflow
command-file and startup variables are removed from the managed environment.
Benign runner environment such as HOME, PATH, and provider configuration is
preserved deliberately.

The wrapper supplies the absolute invoking UID and GID as the pinned observer's
trusted run-as values. After the observer's fixed gate shell, the non-root
managed Bash/workload runs behind `setpriv --no-new-privs`, so an ordinary
setuid sudo call cannot regain root. Rust's managed-process launch clears
inherited supplementary groups when it applies the non-root UID; the live gate
verifies that only the non-root primary group remains. The live timeline stays
inside the root-controlled directory.

After capture, root copies only the expected regular timeline into a second
Action-owned directory. The sealed file remains root-owned and mode `0440`; the
runner group receives read/traverse access but cannot replace the file. The
Action verifies that boundary, uploads the exact static path through a
full-commit-pinned uploader that errors if the file is absent, then removes only
paths carrying the expected root-owned scope marker. It performs no recursive
ownership change and never writes as root to a caller-selected destination.

## Requirements and honest limits

- Linux x86_64, kernel BTF, a non-root user and non-root primary group, a
  root-owned mode-`1777` `/var/tmp`, `/usr/bin/bash`, `/usr/bin/curl`,
  `/usr/bin/gzip`, `/usr/bin/python3`, GNU userland, `/usr/bin/setpriv`, and passwordless sudo
  that permits `--preserve-env`. Outbound HTTPS access to the pinned GitHub
  release and artifact service is required. Standard `ubuntu-latest` is the
  validated environment. Already-root container jobs or already-root
  self-hosted runners fail closed.
- This is audit telemetry, not containment. `no_new_privs` blocks direct
  exec-based privilege gain, but the managed command still shares the runner
  UID, workspace, temporary files, and action cache with later steps. Deliberate
  modification of runner-owned workflow-command files, step scripts, cached
  actions, or other same-UID state is outside the artifact-integrity claim. Use
  a real sandbox and a separate trusted upload plane when the command is
  actively hostile.
- Detached same-UID children are not a process-isolation boundary. The live gate
  proves a non-sudo child cannot replace the root-owned local timeline through
  a direct filesystem write, but it may still affect other runner state until
  the job or sandbox ends.
- Use only ephemeral, trusted workflow definitions. Do not expose secrets to
  untrusted Pull Requests or `pull_request_target`, and do not infer that an
  arbitrary self-hosted runner is isolated by this wrapper.
- Evidence has known blind spots, including `io_uring`-based I/O. A quiet
  timeline is not proof of absence; see the [threat model](threat-model.md).
- The pinned v0.3.0 bundle is a documented privacy exception: although the
  wrapper prevents the top-level `run` string from entering launch metadata,
  redacts the tested credential path, and does not persist the fixture value,
  v0.3.0 can persist child exec arguments and reconstructed process-command
  content. Never place secrets in
  the command or argv, and handle the artifact as sensitive CI data. A
  post-content-off immutable bundle is a release no-go criterion, not deferred
  hardening.
- Hard cancellation can bypass finalizers on any CI system. Ephemeral hosted
  runners disappear with the job; operators of persistent runners must inspect
  and remove only correctly marked paths for canceled runs. Those paths can
  include the normally deleted root-owned `managed-command.sh`, another reason
  never to place secrets in command text.

The live self-test in `.github/workflows/action-self-test.yml` uses the real
pinned release on a GitHub-hosted eBPF runner. It asserts root-owned extracted
inputs, hostile shell/function/dynamic-loader startup suppression, preserved
benign runner environment, supplementary-group removal, `no_new_privs` with
sudo rejection, credential-path redaction, staged top-level command privacy,
the explicit v0.3.0 child-argv privacy exception, nonzero-command failure
propagation with retained evidence, collision isolation, rejection of empty or
unsafe inputs and a symlinked policy, direct-write resistance against a
surviving same-UID process, preservation of a root-owned legacy-path sentinel,
verified non-empty evidence before the pinned upload, and exact cleanup. The
local boundary test separately requires missing-file upload behavior to be
fail-closed.

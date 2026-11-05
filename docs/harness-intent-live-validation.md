# Harness intent: bounded live validation

[English](harness-intent-live-validation.md) | [简体中文](harness-intent-live-validation.zh-CN.md)

On 2026-11-05, the synthetic harness marker/reason gate and general live
observer regression passed on **x86_64 Linux 6.18.55-2-cachyos-lts** after the
managed-gate descriptor fix and final bridge changes described below. The
expanded fixture gate completed seven captures.
Native Claude Code, Pi, and OpenCode runs have now passed with the explicit
shell bridge. Codex remains blocked by provider connectivity and Cursor by
expired authentication; neither is qualified by this report.
These results qualify only the listed local paths, product versions, and
provider configurations. Other kernels and stress/loss qualification remain open. Work is
tracked in [PR #87](https://github.com/0xLaiHo/Apolysis/pull/87).

## What changed

Live loading exposed two defects that ordinary Rust tests did not exercise:

- CO-RE relocation failed on the raw-tracepoint context's zero-length `args`
  array. Reading the raw-tracepoint arguments without that array relocation
  fixes the Aya bounds failure. The opt-in host-BTF regression reproduces the
  failure before the fix and passes after it.
- Scanning the complete executable path caused kernel-verifier state growth.
  Fixed-length basename-tail checks preserve exact shell-name recognition
  without the path-scanning loop. The kernel code and native regression share
  the C helper, covering valid shell paths, lookalike names, and bounds.

`make test-bpf-relocation` builds the object and applies all observer CO-RE
relocations to readable host BTF without BPF privileges or kernel loading.
Native helper tests run with `cargo test -p apolysis-observer --test intent_header`.
Neither check substitutes for kernel-verifier acceptance and live assertions.

A later observer regression exposed a managed-launch descriptor defect:
`dup2(3, 3)` preserves `FD_CLOEXEC`, so the exec'd shell wrapper could lose its
gate and exit with `Bad file descriptor`/status 127. An isolated subprocess
reserves descriptor 3 before creating Tokio, then releases only that owned
descriptor and calls the actual managed-launch function. This reproduced the
failure twice before the fix; explicitly clearing `FD_CLOEXEC` made it pass.
A separate regression reproduced a leaked read descriptor when spawning
failed. Owning both pipe ends with `OwnedFd` now closes them on that error path.
Neither test closes descriptors owned by other test threads or requires BPF
privileges. Both regressions and the original gate-release test pass.

## Observed results

| Gate | Result |
| --- | --- |
| Host-BTF relocation regression | Pre-fix failure reproduced; fixed object passes: 1 passed. |
| Synthetic live marker gate | 7 complete captures, 303 raw kernel events after the descriptor and bridge fixes. Every capture includes its managed target exec, successful workload exit, and a nonempty summary consistent with the raw-event count. |
| Positive marker case | Same-PID exec, fork without exec, fork from a remaining thread after leader exit, three distinct file-attempt process identities, and loopback-connect attribution passed. `intent_capture_incomplete:true` is absent from the positive capture. |
| Reason relation and correction | A declared reason annotates the exact file and network attempt relations. A late correction changes the active reason without changing raw events or execution-relation edges. Prompt, tool-result, and native-description sentinels are absent from persisted intent/reason records. |
| Five negative marker cases | Ordinary argv, a script argument, a later comment, a short token, and an uppercase token produce no attributed intent. |
| Capture health | Drop/map-pressure/decode/load/attach failure counters are zero. Truncation counts in capture order are **2, 3, 1, 1, 1, 1, 1**. |
| General live observer regression | Post-fix run: 1 passed, 0 ignored; 3.84 seconds; zero dropped events and 1 truncation. |
| Managed-gate descriptor regressions | Descriptor-3 launch and spawn-error cleanup both reproduced failures before their respective fixes and passed afterward. |
| Local gates | `cargo test`: 541 passed, 91 ignored. Observer crate: 59 passed, 1 ignored. CLI `observe`: 20 passed, 1 ignored. Node bridge tests: 14 passed. Formatting, Clippy, quickstart, and diff checks passed. Opt-in BTF and live results are reported separately above. |
| Native-product gate | Claude Code, Pi, and OpenCode passed with the explicit `/bin/bash` bridge; counts and versions appear below. Codex connectivity and Cursor authentication remain unresolved. |
| Expanded synthetic gate | The real `eval`-wrapped bridge case passed, including three file-attempt process identities and network-attempt attribution. It is included in the seven-capture total. |

Truncation diagnostics are retained. They cover bounded diagnostic argv and
malformed-header negative cases; they do not establish complete coverage.
The positive case explicitly checks marker-capture completeness separately.
The test uses `pthread_join` to establish that the leader exited before the
remaining thread's observations, rather than relying on a timing delay.

These are attempts and relation checks, not proof that a network connection
succeeded or that any observed action was authorized. A reason is declared
metadata, not an independent explanation of an action. The seven-capture gate
uses a synthetic Claude-shaped hook payload passed to Apolysis, not a live
Claude Code session.

## Reproduction and cleanup boundary

The privileged synthetic gate attaches audit-only probes to fixture scopes,
reads only temporary fixture files, and attempts a loopback connection. It
requires BPF/perf capabilities (or `CAP_SYS_ADMIN`), readable host BTF, tracing
prerequisites, and the eBPF build tools. It does not contact a provider or
Kubernetes, change policies, pin maps, or mount filesystems. Build the CLI and
the 648-byte-ABI eBPF object from the same source.

The successful marker invocation used an independent transient systemd scope:

```bash
cargo build -p apolysis-cli
sudo env APOLYSIS_REQUIRE_BPF=1 systemd-run --scope --quiet \
  --unit=apolysis-intent-validation-20261105 \
  ./scripts/test-live-harness-intent.sh
```

`APOLYSIS_REQUIRE_BPF=1` makes missing prerequisites fail instead of skipping.
The nonprivileged `APOLYSIS_REQUIRE_BPF=1 make test-bpf-relocation` also passed;
its checked-in runner performs prerequisite checks before building and testing.
`make test-live-harness-intent` is the normal opt-in runner when the caller
already has the required capabilities and toolchain access.

For the general regression, compile as the ordinary user with
`cargo test -p apolysis-cli --test observe --no-run`, then execute the resulting
`observe` test artifact in a separate privileged scope with arguments
`live_observer --ignored --nocapture`. Cargo reports the artifact path; its
build-dependent filename is not a stable interface. The checked-in
[`test-live-observer.sh`](../scripts/test-live-observer.sh) is the equivalent
runner when the privileged environment has Rust toolchain access.

The completed marker/observer scopes were absent/inactive after exit. Cleanup
found no remaining native-product test processes, fixture directories, or
Apolysis BPF programs/maps. Twelve explicitly retained failed native fixtures
were removed after diagnosis; successful fixtures were removed automatically. The two root-built BPF objects were
restored to the invoking user's ownership and mode `0644`. Raw captures,
verifier addresses, and temporary reproduction files are not committed.

## Native-product gate: three passes, two pending

All three completed runs explicitly selected `--shell-bridge /bin/bash`
(`APOLYSIS_SHELL_BRIDGE=/bin/bash` for the script integrations). Each passed
the zero-drop/failure diagnostic checks, linked the native declared reason
exactly to the synthetic `cat` fixture-file attempt, and retained no prompt
sentinel in the persisted JSONL outputs.
The final rerun used temporary masks for existing user shell profiles as well
as global hooks. All three selected products passed; no prerequisite was skipped.

| Product | Tested version/configuration | Raw kernel events | Truncations | Result |
| --- | --- | --- | --- | --- |
| Claude Code | 2.1.295, tested installed Claude configuration | 2593 | 12 | Passed with explicit bridge |
| Pi | 1.5.0, DeepSeek flash | 551 | 6 | Passed with explicit bridge |
| OpenCode | 1.18.31, DeepSeek v4 flash | 690 | 5 | Passed with explicit bridge |
| Codex | 0.162.0, existing ChatGPT authentication | — | — | Blocked by provider connectivity; rerun pending |
| Cursor | 2026.07.20, expired access and refresh authentication | — | — | Authentication renewal and rerun pending |

Codex's isolated authentication binding refers to the same underlying file as
the native installation, and its token was not expired. This does not prove a
successful provider request: ordinary-user HTTP HEAD probes outside the harness
also failed. The configured proxy returned a TLS unexpected EOF with no HTTP
response for the ChatGPT/OpenAI API endpoints; direct ChatGPT access timed out
and direct API access could not connect. The observed blocker is therefore not
established as an Apolysis hook failure. No proxy addresses, environment values,
or authentication contents are included here.

Cursor's access and refresh tokens were both expired. Its cached `logged_in`
status does not establish current API authentication. Neither a working Codex
provider path nor a renewed Cursor session has yet been validated by this gate.

These are partial native-product results for the tested versions and provider
configurations, not a five-product qualification. The bridge is non-default
and creates a subshell: cwd changes, environment changes, and functions do not
propagate back to the product's outer shell. These passes therefore do not
establish transparent default-mode attribution or general stateful-shell
compatibility. The earlier Claude default-comment run persisted its declaration
and reason but failed exact execution attribution because the command was
embedded in the product's `eval` wrapper.

The checked-in [`test-live-reason-products.py`](../scripts/test-live-reason-products.py)
and `make test-live-reason-products` exercise actual native products and provider
calls. Build the CLI and eBPF object first. The runner requires explicit sudo
execution with the invoking user's `PATH` preserved, a non-root invoking user,
live BPF prerequisites, installed product CLIs, Bubblewrap, and usable existing
product authentication. Provider requests may incur charges. The Make target
explicitly selects `--shell-bridge /bin/bash` and uses `--require-all`, so missing
prerequisites cannot produce an overall pass.

The workload is a temporary synthetic file read with a leading reason code.
Private temporary hook configuration is used inside a Bubblewrap mount
namespace: the host is read-only except for the fixture directory, and existing
global hooks/instructions are masked without modifying their host files.
Authentication remains in place; where an isolated product directory needs an
authentication file, the existing file is bound read-only without copying its
contents. This is a bounded integration-test guard, not a hostile-agent sandbox.
The gate does not use Kubernetes or modify global product configuration.

The runner checks a successful native exit, a complete nonempty kernel capture,
one native Tool Call declaration and content-off reason, and an exact relation
from that reason to the fixture file attempt. It prints counts and fixed error
categories, not raw product output or credentials. Temporary captures and
private product logs are removed on normal and error exits by default;
`--keep-failed-private` explicitly retains failed fixtures for local diagnosis.
The remaining Codex and Cursor results must pass before claiming five-product
qualification.

Passing this bounded gate does not qualify all process shapes, kernels, load,
event loss, or product versions, and does not resolve integration conflicts
with the protected `pre-release` branch. CI and review remain required before
merge. See [design](design.md), [roadmap](roadmap.md), and
[harness integration](harness-intent.md).

# Harness intent: bounded live validation

[English](harness-intent-live-validation.md) | [简体中文](harness-intent-live-validation.zh-CN.md)

On 2026-11-05, the synthetic harness marker gate and general live observer
regression passed on **x86_64 Linux 6.18.55-2-cachyos-lts**. This qualifies the
tested local fixture path on that kernel. Native Codex, Claude Code, Cursor,
Pi, and OpenCode end-to-end runs, other kernels, and stress/loss qualification
remain open. Work is tracked in [PR #87](https://github.com/0xLaiHo/Apolysis/pull/87).

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

## Observed results

| Gate | Result |
| --- | --- |
| Host-BTF relocation regression | Pre-fix failure reproduced; fixed object passes. |
| Synthetic live marker gate | 6 complete captures, 220 raw kernel events. Every capture includes its managed target exec, successful workload exit, and a nonempty summary consistent with the raw-event count. |
| Positive marker case | Same-PID exec, fork without exec, fork from a remaining thread after leader exit, three distinct file-attempt process identities, and loopback-connect attribution passed. `intent_capture_incomplete:true` is absent from the positive capture. |
| Five negative marker cases | Ordinary argv, a script argument, a later comment, a short token, and an uppercase token produce no attributed intent. |
| Capture health | Drop/map-pressure/decode/load/attach failure counters are zero. Truncation counts in capture order are **2, 1, 1, 1, 1, 1**. |
| General live observer regression | 1 passed, 0 ignored; 3.78 seconds; zero dropped events and 1 truncation. |
| Final local gates | `cargo test`: 490 passed, 91 ignored. The opt-in BTF and live tests above were also run explicitly. Bridge tests: 7 passed. Formatting, Clippy, quickstart, and diff checks passed. |

Truncation diagnostics are retained. They cover bounded diagnostic argv and
malformed-header negative cases; they do not establish complete coverage.
The positive case explicitly checks marker-capture completeness separately.
The test uses `pthread_join` to establish that the leader exited before the
remaining thread's observations, rather than relying on a timing delay.

These are attempts and relation checks, not proof that a network connection
succeeded or that any observed action was authorized. The input is a synthetic
Claude-shaped hook payload passed to Apolysis, not a live Claude Code session.

## Reproduction and cleanup boundary

The privileged gate attaches audit-only probes to synthetic workload scopes,
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

Both scopes were absent/inactive after exit. Cleanup checks found no fixture
directory or JSONL residue in the three checked fixture categories and no
remaining Apolysis BPF programs or maps. The two root-built BPF objects were
restored to the invoking user's ownership and mode `0644`. Raw captures,
verifier addresses, and temporary reproduction files are not committed.

Passing this bounded gate does not qualify all process shapes, kernels, load,
event loss, or product versions, and does not resolve integration conflicts
with the protected `pre-release` branch. CI and review remain required before
merge. See [design](design.md), [roadmap](roadmap.md), and
[harness integration](harness-intent.md).

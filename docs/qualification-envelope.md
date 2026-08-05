# Beta Qualification Envelope

> English | [Simplified Chinese](qualification-envelope.zh-CN.md)
> Status: candidate contract; no Supported profile
> Last reviewed: 2026-08-04

This document fixes the first bounded qualification contract for the Apolysis
eBPF collector. It deliberately does not grant a support claim. Numeric limits
remain unset until repeatable live measurements exist and are retained with the
release.

The machine-readable authority is
[`qualification/envelope-v1.json`](../qualification/envelope-v1.json). The
checker must reject a Candidate profile, an unset budget, a mismatched exact
environment, malformed evidence, under-sampling, a budget violation, or event
loss.

## Status matrix

| Status | Environment | Boundary |
| --- | --- | --- |
| Candidate | Native host, Linux 6.12 line, x86_64, cgroup v2, readable target BTF and tracefs, all 19 tracepoints, production object verifier/load/attach, effective `CAP_BPF` + `CAP_PERFMON` | Becomes Supported only after retained correctness, lifecycle, performance, loss, overload, and privacy evidence passes |
| Experimental | Other feature-probed Linux 5.11+ x86_64 kernels; aarch64; Docker; containerd; Kubernetes; `CAP_SYS_ADMIN` legacy fallback | No compatibility or performance promise; D1/D2 and K1/K2 own runtime breadth |
| Unsupported | Linux below 5.11 without the required backports; cgroup v1/hybrid Agent Run scope; missing BTF or required hooks; unprivileged/rootless host collector; non-Linux | Requires a different implementation or product profile, not a waived gate |

Linux 5.11 is only the current upstream feature floor: the eBPF program uses
`bpf_get_current_task_btf`, in addition to a BPF ring buffer and CO-RE. It is
not a blanket `Linux >= 5.11` support claim. The initial 6.12 line is a narrow
product candidate, and every supported release tuple must name and retain its
exact kernel build and artifact evidence.

## Required evidence

Each exact tuple records only non-secret qualification metadata:

- full kernel release and architecture;
- target BTF and production BPF-object SHA-256 fingerprints;
- cgroup v2 detection and the effective capability mode;
- the versioned list of 19 required tracepoints and every event-format
  fingerprint;
- verifier, load, and complete attach result; and
- source commit, workload manifest, repetition count, and synthetic-workload
  privacy declaration.

The tracepoint manifest is shared by the shell preflight and a Rust regression
test that compares it with `AyaLoaderPlan::audit_observer_default`. CO-RE does
not make tracepoints a stable ABI, so a version check never substitutes for
format inspection and real attachment.

## Workloads and metric contract

Qualification separates three modes:

1. `idle` measures the attached collector with no tracked Agent activity.
2. `representative` runs a versioned deterministic process, selected-file, and
   network mix with known expected event counts.
3. `burst` sweeps the offered event rate until the first detected loss,
   pressure, storage failure, or latency violation. It discovers a capacity
   boundary and cannot itself qualify a loss-free rated workload.

The version 1 manifests are embedded in the qualification-only binary and
retained under `qualification/workloads/`. `idle` holds a one-second empty
window. `representative` performs 25 rounds of `openat`, `creat`, `truncate`,
`renameat2`, `unlinkat`, loopback `connect`, and fork/exit, for 200 expected
events. `burst` offers 100, 500, and 2,000 `openat` events per second, for 1,300
expected events. Each burst rate has its own monotonic window, followed by a
150-millisecond settling gap; event rate, latency, and loss-counter deltas are
attributed to that phase instead of a blended run total. The summary reports
the first phase with detected loss and rejects any rate, order, event-count, or
phase-window plan that differs from the embedded manifest. Only kernel
timestamps inside the workload's monotonic start/end window participate in
reconciliation, excluding loader and raw-file write activity.

For paired collector-off/on trials, retain raw samples and report at least:

- collector userspace CPU and the workload CPU/wall-time delta, because BPF
  execution also runs on the triggering task's syscall path; raw workload CPU
  includes both `RUSAGE_SELF` and waited `RUSAGE_CHILDREN`;
- process RSS/peak RSS, collector-cgroup memory, and BPF map/program memory as
  separate values;
- workload overhead plus kernel-to-decode and kernel-to-append p50, p95, p99,
  maximum, sample count, and interval method; append latency is not durable
  latency; and
- expected, observed, and lost counts for every event class, including reserve,
  map-pressure, pairing, decode, queue, writer, and lifecycle-gap counters.

The qualification harness samples collector `RUSAGE_SELF`, `VmRSS`/`VmHWM`, and
collector-cgroup `memory.current`/`memory.peak` every 25 milliseconds, with an
initial and terminal bracket sample. It captures BPF map/program `memlock` once
after the production object is loaded and attached. The harness creates
an ephemeral subtree below the caller's current cgroup and places the collector
and synthetic workload in sibling cgroups; it never reports their mixed parent
memory as collector memory. An outer supervisor moves a fresh collector process
into its cgroup before exec, so runtime and BPF allocations do not predate the
measurement cgroup. The inner collector verifies its `/proc/self/cgroup`
membership and the exact collector/workload `cgroup.procs` membership before it
records isolation. Missing writable cgroup-v2 delegation, the memory controller,
`memory.peak`, process status fields, BPF `memlock`, a sample on either side of
the workload window, or a sampling gap above four intervals (100 milliseconds)
fails the trial. Burst phase boundaries must be bracketed within the same gap
limit. The exact subtree is removed after both processes leave it. Sampling work
is included in collector CPU and is therefore a conservative harness cost.

Each pair retains signed workload CPU and wall-time deltas. The published
one-sided overhead estimate clamps only a negative aggregate bound to zero; the
signed paired samples remain in the summary. `workload_latency_overhead` is the
paired workload wall-time delta. Event rate uses the pair median; CPU and
overhead metrics use nearest-rank p95 across pairs; RSS, cgroup, and BPF memory
use the maximum; lag p50/p95/p99 values first summarize each collector-on trial
and then use the matching nearest-rank percentile across pairs. Maximum lag is
the maximum of the per-trial maxima.

Version 1 fixes nearest-rank percentiles and a deterministic 95%
percentile-bootstrap interval with 10,000 resamples. The resampling unit is the
whole off/on pair, not individual eBPF events. Trials alternate collector-off
and collector-on order on the same boot and use `CLOCK_MONOTONIC`. Comparing
`CLOCK_BOOTTIME` with `CLOCK_MONOTONIC` rejects suspend drift for every raw
workload, off/on pair, and complete evidence bundle. Each workload manifest
freezes its expected event-class counts; evidence must match that map before
observed counts are reconciled.

At the rated representative envelope, known and unexplained event loss must
both be zero. CPU, memory, latency, repetition count, and the rated event rate
remain `null` in version 1 until a privileged 6.12 host produces enough trials
to select a conservative bound with an explicit safety margin. Fixture numbers
under `tests/fixtures/qualification/` test the checker only and are not product
budgets.

## Commands and promotion

Run the deterministic contract tests without privilege:

```bash
make test-qualification
```

On a clean commit and prepared privileged host, capture the real production
object's prerequisite and attach evidence explicitly:

```bash
APOLYSIS_CONFIRM_QUALIFICATION=1 make qualify-live
```

The command writes only below `target/qualification/<UTC timestamp>/`. A
missing prerequisite fails visibly; it does not turn into a passing skip. The
capture runs the three versioned workloads in alternating same-boot
collector-off/on order (three pairs by default), retains content-free workload,
timeline, lifecycle, kernel-to-decode/append nanosecond samples, and separated
collector process/cgroup/BPF resource samples. It writes
`measurement-summary.json` with pair-level measurements and bootstrap intervals,
then writes a failed decision and returns non-zero while the profile is
Candidate. Set
`APOLYSIS_QUALIFICATION_SAMPLES` from 1 through 100 to change the raw repetition
count; this does not waive the reviewed sample-size or budget decision. The
current bundle computes aggregates but intentionally leaves numeric budgets
unset, so it is evidence input rather than a support certificate.

Before writing the preflight bundle, the harness recomputes the canonical JSON
tree digest for every workload, requires the summary to contain that same raw
digest and workload-manifest digest, and records the summary file SHA-256 in
preflight provenance. The Supported checker requires that provenance field to
be a valid SHA-256. A summary therefore cannot silently refer to different raw
evidence.

The production `apolysis` CLI exposes no qualification timing option. The
separate harness enables a bounded in-memory timing recorder through the
observer library and a bounded qualification-only resource sampler. Timing data
persists only event names and monotonic timestamps; resource data persists only
numeric CPU/memory samples and whether cgroup isolation was active. Raw-trial
assembly rejects latency samples outside the synthetic workload window and
resource samples that do not bracket it, sampling gaps above the fixed limit,
decreasing cumulative loss counters, and burst counters that cannot be
attributed exactly to their phases. Runs spanning suspend fail rather than
entering the bundle. Under `sudo`, off/on workloads both restore the same
invoking UID/GID; the privileged trial root stays root-owned, while only a
dedicated synthetic workload/result subdirectory is delegated. Privileged raw
files use exclusive, no-symlink creation. Workload and summary files contain no
resource path, cgroup path, payload, or command content.

Promotion to Supported requires a reviewed change that links retained raw live
results, freezes numeric budgets in the machine envelope, changes the profile
status, reruns the checker against every advertised tuple, and confirms privacy
and overload behavior. No fixture, skipped live test, kernel-version match, or
`CAP_SYS_ADMIN` fallback can perform that promotion.

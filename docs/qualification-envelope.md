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

For paired collector-off/on trials, retain raw samples and report at least:

- collector userspace CPU and the workload CPU/wall-time delta, because BPF
  execution also runs on the triggering task's syscall path;
- process RSS/peak RSS, collector-cgroup memory, and BPF map/program memory as
  separate values;
- workload overhead plus kernel-to-decode and kernel-to-append p50, p95, p99,
  maximum, sample count, and interval method; append latency is not durable
  latency; and
- expected, observed, and lost counts for every event class, including reserve,
  map-pressure, pairing, decode, queue, writer, and lifecycle-gap counters.

Version 1 fixes nearest-rank percentiles, a 95% percentile-bootstrap interval
with 10,000 resamples, alternating collector-off/on trials on the same boot,
`CLOCK_MONOTONIC`, and rejection of runs that span suspend. Each workload
manifest freezes its expected event-class counts; evidence must match that map
before observed counts are reconciled.

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
capture intentionally leaves measurements unset, writes a failed decision, and
returns non-zero while the profile is Candidate. It is an input to the
subsequent deterministic performance run, not a support certificate.

Promotion to Supported requires a reviewed change that links retained raw live
results, freezes numeric budgets in the machine envelope, changes the profile
status, reruns the checker against every advertised tuple, and confirms privacy
and overload behavior. No fixture, skipped live test, kernel-version match, or
`CAP_SYS_ADMIN` fallback can perform that promotion.

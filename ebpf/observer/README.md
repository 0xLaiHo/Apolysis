# Apolysis Observer eBPF

This directory holds the F1 audit-only observer program. The runtime path is:

1. build a CO-RE object from `apolysis_observer.bpf.c`;
2. load it from Rust with the Aya-backed loader plan;
3. attach tracepoints for process, file, and network events;
4. read `APOLYSIS_EVENTS` as a ring buffer;
5. preserve redacted raw records and analyze them into canonical JSONL timeline
   events;
6. emit typed diagnostics for loss, truncation, decode, verifier, attach, and
   map-pressure failures.

Normal tests use fixture and ABI records, so they do not require root,
`CAP_BPF`, or `CAP_PERFMON`. `make test-live` runs the ignored live smoke test
when the host has the required capabilities and otherwise prints a specific
skip reason.

The live program filters by cgroup v2 identity or a tracked PID tree before
submitting records to `APOLYSIS_EVENTS`. It remains audit-only and does not
perform pre-operation blocking.

The eBPF source is GPL-2.0-only because it is intended to be loaded into the
Linux kernel.

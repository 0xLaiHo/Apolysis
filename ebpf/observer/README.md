# Apolysis Observer eBPF

This directory holds the audit-only observer programs for M4. The intended
runtime path is:

1. build a CO-RE object from `apolysis_observer.bpf.c`;
2. load it from Rust with the Aya-backed loader plan;
3. attach tracepoints for process, file, and network events;
4. read `APOLYSIS_EVENTS` as a ring buffer;
5. preserve raw records and analyze them into canonical JSONL timeline events.

M4 tests use fixture ring-buffer records instead of loading the kernel program,
so normal development does not require root, `CAP_BPF`, or `CAP_PERFMON`.
The eBPF source is GPL-2.0-only because it is intended to be loaded into the
Linux kernel.

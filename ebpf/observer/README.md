# Apolysis Observer eBPF

This directory holds the AuditObserver audit-only observer program. The runtime path is:

1. build a CO-RE object from `apolysis_observer.bpf.c`;
2. load it from Rust with the Aya-backed loader plan;
3. attach tracepoints for process and file events plus paired network-connect
   entry and exit;
4. read `APOLYSIS_EVENTS` as a ring buffer;
5. preserve redacted raw records and analyze them into canonical JSONL timeline
   events;
6. reject incompatible kernel/userspace ABI records and emit typed diagnostics
   or Observation Gaps for loss, unmatched network operations, truncation,
   decode, verifier, attach, ABI, and map-pressure failures;
7. synchronize a capability manifest to stable storage after attachment and
   before a managed Agent is released.

Normal tests use fixture and ABI records, so they do not require root,
`CAP_BPF`, or `CAP_PERFMON`. `make test-live` runs the ignored live smoke test
when the host has the required capabilities and otherwise prints a specific
skip reason.

The live program filters by cgroup v2 identity or a tracked PID tree before
submitting records to `APOLYSIS_EVENTS`. ABI v2 carries an optional signed
syscall return value. Network connect uses a thread-scoped pending map and emits
only after `sys_exit_connect`; unmatched pairs are reported as Observation
Gaps. The program remains audit-only and does not perform pre-operation
blocking.

The eBPF source is GPL-2.0-only because it is intended to be loaded into the
Linux kernel.

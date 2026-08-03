# Apolysis Observer eBPF

This directory holds the AuditObserver audit-only observer program. The runtime path is:

1. build a CO-RE object from `apolysis_observer.bpf.c`;
2. load it from Rust with the Aya-backed loader plan;
3. attach tracepoints for process events plus paired selected-file and
   network-connect entry and exit;
4. read `APOLYSIS_EVENTS` as a ring buffer;
5. preserve redacted raw records and analyze them into canonical JSONL timeline
   events;
6. reject incompatible kernel/userspace ABI records and emit typed diagnostics
   or operation-specific Observation Gaps for loss, unmatched file/network
   operations, truncation, decode, verifier, attach, ABI, and map-pressure
   failures;
7. synchronize a capability manifest to stable storage after attachment and
   before a managed Agent is released.

Normal tests use fixture and ABI records, so they do not require root,
`CAP_BPF`, or `CAP_PERFMON`. `make test-live` runs the ignored live smoke test
when the host has the required capabilities and otherwise prints a specific
skip reason.

The live program filters by cgroup v2 identity or a tracked PID tree before
submitting records to `APOLYSIS_EVENTS`. ABI v2 carries an optional signed
syscall return value. Network connect and the selected file operations use
bounded thread-scoped pending maps and emit only at syscall exit; unmatched
pairs are reported as operation-specific Observation Gaps. The daemon drains
already-submitted ring records before completing scope removal and rejects a
drained numeric cgroup ID for the rest of that observer lifetime until stable
scope generations are implemented. Process fork, exec, and exit ring producers
join the same multi-cgroup in-flight drain barrier as paired operation exits.
The program remains audit-only and does not perform pre-operation blocking.

The eBPF source is GPL-2.0-only because it is intended to be loaded into the
Linux kernel.

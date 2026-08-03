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
submitting records to `APOLYSIS_EVENTS`. ABI v3 carries an optional signed
syscall return value plus scope, process, exec, process-start, and parent
generations. A bounded process-identity map detects PID reuse and exec
transitions; userspace attaches the host boot ID and records exact versus
inferred attribution. Fork identities remain provisional until the child
process start is observed, final cleanup follows the thread group's
`group_dead` boundary, and any identity-map or exec-generation failure latches
identity attribution as unavailable for the rest of that collector lifetime
instead of allowing a later event to become Exact. Network
connect and the selected file operations use
bounded thread-scoped pending maps and emit only at syscall exit; unmatched
pairs are reported as operation-specific Observation Gaps. The daemon drains
already-submitted ring records before completing scope removal. Monotonic
scope generations allow safe numeric cgroup-ID reuse while rejecting stale
pending pairs from the drained Agent Run. Process fork, exec, and exit ring
producers join the same multi-cgroup in-flight drain barrier as paired
operation exits. Generations are observer-lifetime state and do not claim
identity continuity across collector restart. The program remains audit-only
and does not perform pre-operation blocking.

The eBPF source is GPL-2.0-only because it is intended to be loaded into the
Linux kernel.

# Strong-Isolation Visibility Validation

VisibilityValidation validates what Apolysis can prove from host-side observations when agent
workloads run behind stronger isolation backends. The current implementation is
fixture-driven: it does not start production gVisor, Kata, or Firecracker
instances. Instead, it records a repeatable decision model for how much
side-effect detail host eBPF can preserve.

## Runtime Findings

| Scenario | Host-side visibility | Required metadata | Guest collector decision |
| --- | --- | --- | --- |
| Docker default | Guest process semantics are usually visible as process, file, and network events. | Container id, image, cgroup, and network mode improve correlation. | Not required for MVP. |
| Docker + gVisor | Host events collapse toward `runsc`, Sentry, and Gofer boundary activity. | Runtime metadata or gVisor-specific metadata is required to map events back to the session. | Not required for MVP, but a gVisor metadata adapter may be needed. |
| Kubernetes + gVisor | Same runtime-boundary collapse as Docker + gVisor, plus Kubernetes scheduling indirection. | Pod, namespace, service account, RuntimeClass, node, and Agent Sandbox identity are required. | Not required for MVP if metadata correlation is sufficient. |
| Kubernetes + Kata | Host eBPF usually sees shim, VMM, virtio, and host network/storage boundaries rather than guest process actions. | Kubernetes metadata is required but cannot restore guest process/file/network semantics by itself. | Required for full side-effect semantics. |
| Firecracker prototype | Host eBPF sees VMM, tap, block, and vsock boundary events. | MicroVM id, rootfs, tap, cgroup, and vsock channel metadata are required. | Required through a guest collector or vsock event channel. |

## CLI Validation

Use the `visibility` command to emit a JSONL assessment:

```bash
cargo run -p apolysis-cli -- visibility \
  --scenario kubernetes-kata \
  --input tests/fixtures/visibility/kubernetes-kata-host-events.txt \
  --output .apolysis/visibility-kata.jsonl \
  --kubernetes-metadata tests/fixtures/kubernetes/agent-sandbox-kata-pod.yaml
```

Each assessment records the runtime profile, observed host subjects, visibility
scope, whether host semantics collapsed, whether runtime metadata is required,
and whether a guest collector is required.

## VisibilityValidation Decision

Apolysis should not treat host-only events from Kata or Firecracker as complete
agent side-effect evidence. For those backends, VisibilityValidation marks guest-side collection
as required before claiming full process, file, network, or credential-read
semantics. For gVisor, VisibilityValidation keeps the initial path metadata-first: host events are
useful for boundary accountability, while runtime metadata is required for
session correlation.

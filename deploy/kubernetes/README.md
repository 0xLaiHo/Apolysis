# Kubernetes / Agent Sandbox Examples

These manifests document the M6 integration target. They are examples for
platform teams that already run Kubernetes Agent Sandbox or RuntimeClass-backed
sandboxes. Adjust API versions and handlers to the Agent Sandbox release and
node runtime installed in your cluster.

M6 is metadata-only: Apolysis does not yet include a controller, admission
webhook, or live Kubernetes client. Capture a pod snapshot and pass it to the
observer:

```bash
kubectl get pod <pod> -n <namespace> -o yaml > .apolysis/k8s-pod.yaml

APOLYSIS_BPF_LSM_AVAILABLE=0 cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-m6-k8s \
  --policy tests/fixtures/policies/m5-block-policy.yaml \
  --output .apolysis/kubernetes-timeline.jsonl \
  --feedback-dir .sandbox \
  --kubernetes-metadata .apolysis/k8s-pod.yaml
```

Recommended baseline:

- Use `runtimeClassName: gvisor` or `runtimeClassName: kata-qemu` for agent pods.
- Set `automountServiceAccountToken: false` unless the agent explicitly needs
  Kubernetes API access.
- Attach a default-deny `NetworkPolicy` and add narrow allow rules per tool.
- Label pods with the Agent Sandbox name so Apolysis can correlate timeline
  events to the higher-level sandbox identity.

## F5 Production-Hardening Baseline

`apolysisd-production-baseline.yaml` is the first F5 production-hardening
deployment baseline for running `apolysisd` as a node-local DaemonSet. It keeps
production-facing kernel blocking disabled, uses explicit Linux capabilities
instead of `privileged: true`, mounts runtime sockets read-only, sets bounded
CPU/memory requests and limits, installs a default-deny `NetworkPolicy`, and
uses semantic health probes for liveness and readiness.

Validate the manifest before live deployment:

```bash
make test-f5-production-hardening
kubectl apply --dry-run=client --validate=false \
  -f deploy/kubernetes/apolysisd-production-baseline.yaml
```

Run the live k3s deployment gate only on a validation host:

```bash
APOLYSIS_CONFIRM_F5_LIVE_DEPLOYMENT=1 make test-f5-live-deployment
```

The live gate builds a local image, imports it into k3s containerd, deploys the
DaemonSet, creates a marked workload for runtime adapter evidence, captures
health/log/Kubernetes artifacts, and removes the validation namespace and
temporary state path before exiting.

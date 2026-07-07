# Kubernetes / Agent Sandbox Examples

These manifests document the KubernetesMetadata integration target. They are examples for
platform teams that already run Kubernetes Agent Sandbox or RuntimeClass-backed
sandboxes. Adjust API versions and handlers to the Agent Sandbox release and
node runtime installed in your cluster.

KubernetesMetadata is metadata-only: Apolysis does not yet include a controller, admission
webhook, or live Kubernetes client. Capture a pod snapshot and pass it to the
observer:

```bash
kubectl get pod <pod> -n <namespace> -o yaml > .apolysis/k8s-pod.yaml

APOLYSIS_BPF_LSM_AVAILABLE=0 cargo run -p apolysis-cli -- observe \
  --backend fixture \
  --input tests/fixtures/raw-kernel-events.txt \
  --session session-kubernetes-metadata-k8s \
  --policy tests/fixtures/policies/policy-feedback-block-policy.yaml \
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

## Production Deployment Baseline

`apolysisd-production-baseline.yaml` is the deployment baseline for running
`apolysisd` as a node-local DaemonSet. It keeps
production-facing kernel blocking disabled, uses explicit Linux capabilities
instead of `privileged: true`, mounts runtime sockets read-only, sets bounded
CPU/memory requests and limits, installs a default-deny `NetworkPolicy`, uses
semantic health probes for liveness and readiness, and exposes low-cardinality
Prometheus metrics on the pod-local metrics port.

Validate the manifest before applying it:

```bash
kubectl apply --dry-run=client --validate=false \
  -f deploy/kubernetes/apolysisd-production-baseline.yaml
```

`deploy/helm/apolysis` packages the same node-local daemon shape as a
tenant-isolated production chart. It renders tenant labels, tenant-specific
state hostPaths under `/var/lib/apolysis/tenants/<tenant-id>`, read-only
runtime metadata RBAC, a default-deny NetworkPolicy, a metrics Service with
mTLS handoff annotations, and a narrow metrics ingress allowlist.

```bash
helm lint deploy/helm/apolysis
```

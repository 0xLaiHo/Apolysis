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

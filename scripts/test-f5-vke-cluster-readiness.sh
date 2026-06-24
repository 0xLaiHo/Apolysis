#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_F5_VKE_CLUSTER_READINESS:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-f5: Vultr VKE cluster readiness is opt-in.
Set APOLYSIS_CONFIRM_F5_VKE_CLUSTER_READINESS=1 after confirming the kubeconfig
points at the intended live Vultr VKE test cluster. This gate performs read-only
checks and retains machine-readable evidence.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in kubectl jq python3; do
    require_command "$command"
done

expected_nodes="${APOLYSIS_F5_VKE_EXPECTED_NODES:-3}"
provider="${APOLYSIS_F5_VKE_PROVIDER:-vultr_vke}"
cluster_name="${APOLYSIS_F5_VKE_CLUSTER_NAME:-vultr-vke}"
expected_runtime_prefix="${APOLYSIS_F5_VKE_EXPECTED_RUNTIME_PREFIX:-containerd://}"

if [[ "$provider" != "vultr_vke" ]]; then
    echo "apolysis-f5: F5.28 VKE readiness provider must be vultr_vke" >&2
    exit 2
fi

if ! [[ "$expected_nodes" =~ ^[0-9]+$ ]] || [[ "$expected_nodes" -lt 1 ]]; then
    echo "apolysis-f5: APOLYSIS_F5_VKE_EXPECTED_NODES must be a positive integer" >&2
    exit 2
fi

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_VKE_CLUSTER_READINESS_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-vke-cluster-readiness.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

context="$output_dir/kubectl-current-context.txt"
nodes="$output_dir/kubectl-get-nodes.json"
version="$output_dir/kubectl-version.json"
namespaces="$output_dir/kubectl-get-namespaces.json"
top_nodes="$output_dir/kubectl-top-nodes.txt"
top_nodes_error="$output_dir/kubectl-top-nodes.err"
can_create_namespaces="$output_dir/kubectl-auth-can-i-create-namespaces.txt"
can_delete_namespaces="$output_dir/kubectl-auth-can-i-delete-namespaces.txt"
can_create_deployments="$output_dir/kubectl-auth-can-i-create-deployments.txt"
can_create_daemonsets="$output_dir/kubectl-auth-can-i-create-daemonsets.txt"
can_create_networkpolicies="$output_dir/kubectl-auth-can-i-create-networkpolicies.txt"
evidence="$output_dir/apolysis-f5-vke-cluster-readiness-evidence.json"
report="$output_dir/apolysis-f5-vke-cluster-readiness-report.json"

kubectl config current-context >"$context"
kubectl get nodes -o json >"$nodes"
kubectl version -o json >"$version"
kubectl get namespaces -o json >"$namespaces"

kubectl auth can-i create namespaces >"$can_create_namespaces" 2>"$can_create_namespaces.err"
kubectl auth can-i delete namespaces >"$can_delete_namespaces" 2>"$can_delete_namespaces.err"
kubectl auth can-i create deployments.apps --all-namespaces >"$can_create_deployments" 2>"$can_create_deployments.err"
kubectl auth can-i create daemonsets.apps --all-namespaces >"$can_create_daemonsets" 2>"$can_create_daemonsets.err"
kubectl auth can-i create networkpolicies.networking.k8s.io --all-namespaces >"$can_create_networkpolicies" 2>"$can_create_networkpolicies.err"

if ! kubectl top nodes >"$top_nodes" 2>"$top_nodes_error"; then
    echo "apolysis-f5: metrics-server is required for Vultr VKE F5 readiness evidence" >&2
    cat "$top_nodes_error" >&2 || true
    exit 1
fi

python3 - "$evidence" "$report" \
    "$provider" "$cluster_name" "$expected_nodes" "$expected_runtime_prefix" \
    "$context" "$nodes" "$version" "$namespaces" "$top_nodes" \
    "$can_create_namespaces" "$can_delete_namespaces" "$can_create_deployments" \
    "$can_create_daemonsets" "$can_create_networkpolicies" <<'PY'
import json
import sys
import time
from pathlib import Path

(
    evidence_path,
    report_path,
    provider,
    cluster_name,
    expected_nodes,
    expected_runtime_prefix,
    context_path,
    nodes_path,
    version_path,
    namespaces_path,
    top_nodes_path,
    can_create_namespaces_path,
    can_delete_namespaces_path,
    can_create_deployments_path,
    can_create_daemonsets_path,
    can_create_networkpolicies_path,
) = sys.argv[1:]

expected_nodes = int(expected_nodes)
nodes_doc = json.loads(Path(nodes_path).read_text(encoding="utf-8"))
version_doc = json.loads(Path(version_path).read_text(encoding="utf-8"))
namespaces_doc = json.loads(Path(namespaces_path).read_text(encoding="utf-8"))
context = Path(context_path).read_text(encoding="utf-8").strip()
top_lines = [
    line
    for line in Path(top_nodes_path).read_text(encoding="utf-8").splitlines()
    if line.strip()
]

node_items = nodes_doc.get("items", [])
failures = []
if len(node_items) != expected_nodes:
    failures.append(f"node count {len(node_items)} != expected {expected_nodes}")

ready_nodes = []
not_ready_nodes = []
runtime_versions = {}
node_summaries = []
for node in node_items:
    metadata = node.get("metadata", {})
    status = node.get("status", {})
    info = status.get("nodeInfo", {})
    name = metadata.get("name", "")
    conditions = status.get("conditions", [])
    ready = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in conditions
    )
    if ready:
        ready_nodes.append(name)
    else:
        not_ready_nodes.append(name)
    runtime = info.get("containerRuntimeVersion", "")
    runtime_versions[name] = runtime
    if not runtime.startswith(expected_runtime_prefix):
        failures.append(f"node {name} runtime {runtime!r} does not start with {expected_runtime_prefix!r}")
    node_summaries.append(
        {
            "name": name,
            "ready": ready,
            "unschedulable": bool(node.get("spec", {}).get("unschedulable", False)),
            "kubelet_version": info.get("kubeletVersion", ""),
            "container_runtime_version": runtime,
            "os_image": info.get("osImage", ""),
            "kernel_version": info.get("kernelVersion", ""),
            "architecture": info.get("architecture", ""),
            "capacity_cpu": status.get("capacity", {}).get("cpu", ""),
            "capacity_memory": status.get("capacity", {}).get("memory", ""),
            "allocatable_cpu": status.get("allocatable", {}).get("cpu", ""),
            "allocatable_memory": status.get("allocatable", {}).get("memory", ""),
        }
    )

if not_ready_nodes:
    failures.append(f"not ready nodes: {', '.join(not_ready_nodes)}")
if len(top_lines) < expected_nodes + 1:
    failures.append(f"kubectl top nodes returned {len(top_lines)} lines, expected header plus {expected_nodes} nodes")

authz_paths = {
    "create_namespaces": can_create_namespaces_path,
    "delete_namespaces": can_delete_namespaces_path,
    "create_deployments_all_namespaces": can_create_deployments_path,
    "create_daemonsets_all_namespaces": can_create_daemonsets_path,
    "create_networkpolicies_all_namespaces": can_create_networkpolicies_path,
}
authz = {}
for key, path in authz_paths.items():
    value = Path(path).read_text(encoding="utf-8").strip().lower()
    authz[key] = value
    if value != "yes":
        failures.append(f"kubectl auth can-i {key} returned {value!r}")

observed_at_unix_ms = int(time.time() * 1000)
evidence = {
    "schema_version": 1,
    "evidence_id": f"f5-vke-cluster-readiness-{observed_at_unix_ms}",
    "phase": "F5.28",
    "source": "live_cluster",
    "provider": provider,
    "cluster_name": cluster_name,
    "kubectl_context": context,
    "expected_nodes": expected_nodes,
    "observed_nodes": len(node_items),
    "ready_nodes": ready_nodes,
    "node_summaries": node_summaries,
    "runtime_requirement": expected_runtime_prefix,
    "runtime_versions": runtime_versions,
    "server_version": version_doc.get("serverVersion", {}),
    "namespace_count": len(namespaces_doc.get("items", [])),
    "metrics_server_evidence_ref": "kubectl-top-nodes.txt",
    "authorization": authz,
    "live_cluster": True,
    "external_cluster": True,
    "observed_at_unix_ms": observed_at_unix_ms,
}
report = {
    "schema_version": 1,
    "passed": not failures,
    "approval": {
        "provider": provider,
        "cluster_name": cluster_name,
        "qualified_requirement": "vke_cluster_readiness",
        "expected_nodes": expected_nodes,
        "observed_nodes": len(node_items),
        "ready_node_count": len(ready_nodes),
        "runtime_requirement": expected_runtime_prefix,
        "metrics_server_available": len(top_lines) >= expected_nodes + 1,
        "observed_at_unix_ms": observed_at_unix_ms,
    },
    "failures": failures,
}
Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if failures:
    raise SystemExit("; ".join(failures))
PY

jq -e '
  .source == "live_cluster"
  and .provider == "vultr_vke"
  and .external_cluster == true
  and .live_cluster == true
  and .observed_nodes == .expected_nodes
' "$evidence" >/dev/null

jq -e '
  .passed == true
  and .approval.provider == "vultr_vke"
  and .approval.qualified_requirement == "vke_cluster_readiness"
' "$report" >/dev/null

cat <<EOF
apolysis-f5: Vultr VKE cluster readiness passed ($output_dir)
APOLYSIS_F5_VKE_CLUSTER_READINESS_EVIDENCE=$evidence
APOLYSIS_F5_VKE_CLUSTER_READINESS_REPORT=$report
EOF

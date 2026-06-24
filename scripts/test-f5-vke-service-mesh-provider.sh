#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_F5_VKE_SERVICE_MESH_PROVIDER:-0}"
default_kubeconfig="/home/mactavish/vultr-k8s/vke-a88389c3-f720-412d-9579-c83d3c21eabb.yaml"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<EOF
apolysis-f5: Vultr VKE service-mesh provider qualification is opt-in.
Set APOLYSIS_CONFIRM_F5_VKE_SERVICE_MESH_PROVIDER=1 after confirming the
VKE kubeconfig, Istio installation/cleanup behavior, temporary validation
workloads, and retained provider artifacts are acceptable.
Default kubeconfig: $default_kubeconfig
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in cargo helm jq kubectl python3; do
    require_command "$command"
done

export KUBECONFIG="${KUBECONFIG:-$default_kubeconfig}"
if [[ ! -f "$KUBECONFIG" ]]; then
    echo "apolysis-f5: KUBECONFIG does not exist: $KUBECONFIG" >&2
    exit 2
fi

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_VKE_SERVICE_MESH_PROVIDER_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-vke-service-mesh-provider.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

vke_readiness_dir="$output_dir/vke-cluster-readiness"
istio_live_dir="$output_dir/istio-live"
mkdir -p "$vke_readiness_dir" "$istio_live_dir"

APOLYSIS_CONFIRM_F5_VKE_CLUSTER_READINESS=1 \
APOLYSIS_F5_VKE_CLUSTER_READINESS_OUTPUT_DIR="$vke_readiness_dir" \
    "$repo_root/scripts/test-f5-vke-cluster-readiness.sh" >/dev/null

APOLYSIS_CONFIRM_F5_SERVICE_MESH_LIVE=1 \
APOLYSIS_F5_SERVICE_MESH_LIVE_OUTPUT_DIR="$istio_live_dir" \
    "$repo_root/scripts/test-f5-service-mesh-live-istio.sh" >/dev/null

vke_evidence="$vke_readiness_dir/apolysis-f5-vke-cluster-readiness-evidence.json"
vke_report="$vke_readiness_dir/apolysis-f5-vke-cluster-readiness-report.json"
istio_evidence="$istio_live_dir/apolysis-f5-istio-live-evidence.json"
istio_report="$istio_live_dir/apolysis-f5-istio-live-evidence-report.json"
evidence="$output_dir/apolysis-f5-vke-service-mesh-provider-evidence.json"
report="$output_dir/apolysis-f5-vke-service-mesh-provider-report.json"

jq -e '.passed == true and .approval.provider == "vultr_vke"' "$vke_report" >/dev/null
jq -e '.passed == true and .approval.provider == "istio"' "$istio_report" >/dev/null

python3 - "$evidence" "$report" "$vke_evidence" "$vke_report" "$istio_evidence" "$istio_report" <<'PY'
import json
import sys
import time
from pathlib import Path

(
    evidence_path,
    report_path,
    vke_evidence_path,
    vke_report_path,
    istio_evidence_path,
    istio_report_path,
) = map(Path, sys.argv[1:])

vke_evidence = json.loads(vke_evidence_path.read_text(encoding="utf-8"))
vke_report = json.loads(vke_report_path.read_text(encoding="utf-8"))
istio_evidence = json.loads(istio_evidence_path.read_text(encoding="utf-8"))
istio_report = json.loads(istio_report_path.read_text(encoding="utf-8"))

observed_at_unix_ms = int(time.time() * 1000)
cluster_name = str(vke_evidence.get("cluster_name") or vke_report.get("approval", {}).get("cluster_name") or "vultr-vke")
context = str(vke_evidence.get("kubectl_context") or "vultr-vke")
namespace = str(istio_evidence.get("namespace") or "istio")
provider_control_plane = f"vke:{cluster_name}:{context}:istio:{namespace}"

evidence = {
    "schema_version": 1,
    "evidence_id": f"f5-vke-service-mesh-provider-{observed_at_unix_ms}",
    "phase": "F5.39",
    "source": "live_provider",
    "provider": "vultr_vke_istio",
    "provider_control_plane": provider_control_plane,
    "cluster_provider": "vultr_vke",
    "cluster_name": cluster_name,
    "kubectl_context": context,
    "observed_nodes": vke_evidence.get("observed_nodes", 0),
    "ready_nodes": vke_evidence.get("ready_nodes", []),
    "server_version": vke_evidence.get("server_version", {}),
    "service_mesh_provider": "istio",
    "service_mesh_namespace": namespace,
    "mtls_mode": istio_evidence.get("mtls_mode", ""),
    "observed_traffic_security": istio_evidence.get("observed_traffic_security", ""),
    "authorized_principal": istio_evidence.get("authorized_principal", ""),
    "server_principal": istio_evidence.get("server_principal", ""),
    "authorized_handshake_succeeded": istio_evidence.get("authorized_handshake_succeeded") is True,
    "unauthorized_handshake_denied": istio_evidence.get("unauthorized_handshake_denied") is True,
    "plaintext_handshake_denied": istio_evidence.get("plaintext_handshake_denied") is True,
    "vke_cluster_readiness_evidence_ref": "vke-cluster-readiness/apolysis-f5-vke-cluster-readiness-evidence.json",
    "vke_cluster_readiness_report_ref": "vke-cluster-readiness/apolysis-f5-vke-cluster-readiness-report.json",
    "istio_live_evidence_ref": "istio-live/apolysis-f5-istio-live-evidence.json",
    "istio_live_report_ref": "istio-live/apolysis-f5-istio-live-evidence-report.json",
    "live_provider": True,
    "external_provider": True,
    "observed_at_unix_ms": observed_at_unix_ms,
}

failures = []
if vke_report.get("passed") is not True:
    failures.append("VKE readiness report must pass")
if istio_report.get("passed") is not True:
    failures.append("Istio live service-mesh report must pass")
if istio_evidence.get("source") != "live_cluster":
    failures.append("Istio evidence must come from a live cluster")
if istio_evidence.get("provider") != "istio":
    failures.append("Istio provider evidence is required")
if istio_evidence.get("mtls_mode") != "strict":
    failures.append("strict mTLS is required")
for field in (
    "authorized_handshake_succeeded",
    "unauthorized_handshake_denied",
    "plaintext_handshake_denied",
):
    if istio_evidence.get(field) is not True:
        failures.append(f"{field} must be true")

report = {
    "schema_version": 1,
    "passed": not failures,
    "approval": {
        "provider": "vultr_vke_istio",
        "provider_control_plane": provider_control_plane,
        "qualified_requirement": "managed_service_mesh",
        "cluster_provider": "vultr_vke",
        "service_mesh_provider": "istio",
        "observed_at_unix_ms": observed_at_unix_ms,
    },
    "failures": failures,
}

evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if failures:
    raise SystemExit("; ".join(failures))
PY

jq -e '
  .source == "live_provider"
  and .provider == "vultr_vke_istio"
  and .external_provider == true
  and .live_provider == true
  and .mtls_mode == "strict"
  and .authorized_handshake_succeeded == true
  and .unauthorized_handshake_denied == true
  and .plaintext_handshake_denied == true
' "$evidence" >/dev/null

jq -e '
  .passed == true
  and .approval.provider == "vultr_vke_istio"
  and .approval.qualified_requirement == "managed_service_mesh"
' "$report" >/dev/null

cat <<EOF
apolysis-f5: Vultr VKE service-mesh provider qualification passed ($output_dir)
APOLYSIS_F5_MANAGED_MESH_PROVIDER=vultr_vke_istio
APOLYSIS_F5_MANAGED_MESH_CONTROL_PLANE=$(jq -r '.provider_control_plane' "$evidence")
APOLYSIS_F5_MANAGED_MESH_EVIDENCE=$evidence
APOLYSIS_F5_MANAGED_MESH_REPORT=$report
EOF

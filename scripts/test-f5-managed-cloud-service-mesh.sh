#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_F5_MANAGED_CLOUD_SERVICE_MESH:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-f5: managed Cloud Service Mesh qualification is opt-in.
Set APOLYSIS_CONFIRM_F5_MANAGED_CLOUD_SERVICE_MESH=1 after confirming the GKE
fleet, membership, kube context, managed mesh control plane, and retained
evidence artifacts are acceptable.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

require_env() {
    local name="$1"
    local value="${!name:-}"
    if [[ -z "$value" ]]; then
        echo "apolysis-f5: $name is required" >&2
        exit 2
    fi
    printf '%s' "$value"
}

for command in gcloud jq kubectl python3; do
    require_command "$command"
done

fleet_project="$(require_env APOLYSIS_F5_GKE_MESH_FLEET_PROJECT)"
membership="$(require_env APOLYSIS_F5_GKE_MESH_MEMBERSHIP)"
membership_location="${APOLYSIS_F5_GKE_MESH_MEMBERSHIP_LOCATION:-global}"
cluster_name="${APOLYSIS_F5_GKE_MESH_CLUSTER_NAME:-$membership}"
revision="${APOLYSIS_F5_GKE_MESH_REVISION:-asm-managed}"

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_MANAGED_CLOUD_SERVICE_MESH_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-managed-cloud-service-mesh.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

mesh_describe="$output_dir/gcloud-container-fleet-mesh-describe.json"
membership_describe="$output_dir/gcloud-container-fleet-membership-describe.json"
crds="$output_dir/istio-security-crds.json"
control_plane_revision="$output_dir/controlplanerevision.json"
namespaces="$output_dir/namespaces.json"
evidence="$output_dir/apolysis-f5-managed-cloud-service-mesh-evidence.json"
report="$output_dir/apolysis-f5-managed-cloud-service-mesh-report.json"

gcloud container fleet mesh describe \
    --project "$fleet_project" \
    --format=json >"$mesh_describe"

gcloud container fleet memberships describe "$membership" \
    --project "$fleet_project" \
    --location "$membership_location" \
    --format=json >"$membership_describe"

state_json="$(jq -c --arg membership "$membership" '
  .membershipStates
  | to_entries[]
  | select(.key | endswith("/memberships/" + $membership))
  | .value
' "$mesh_describe")"
spec_json="$(jq -c --arg membership "$membership" '
  .membershipSpecs
  | to_entries[]
  | select(.key | endswith("/memberships/" + $membership))
  | .value
' "$mesh_describe")"

if [[ -z "$state_json" || "$state_json" == "null" ]]; then
    echo "apolysis-f5: membership state was not found in fleet mesh describe output" >&2
    exit 1
fi
if [[ -z "$spec_json" || "$spec_json" == "null" ]]; then
    echo "apolysis-f5: membership spec was not found in fleet mesh describe output" >&2
    exit 1
fi

control_plane_state="$(jq -r '.servicemesh.controlPlaneManagement.state // empty' <<<"$state_json")"
control_plane_implementation="$(jq -r '.servicemesh.controlPlaneManagement.implementation // empty' <<<"$state_json")"
data_plane_state="$(jq -r '.servicemesh.dataPlaneManagement.state // "UNREPORTED"' <<<"$state_json")"
management="$(jq -r '.mesh.management // empty' <<<"$spec_json")"

if [[ "$management" != "MANAGEMENT_AUTOMATIC" ]]; then
    echo "apolysis-f5: managed Cloud Service Mesh must use MANAGEMENT_AUTOMATIC" >&2
    exit 1
fi
if [[ "$control_plane_state" != "ACTIVE" ]]; then
    echo "apolysis-f5: managed Cloud Service Mesh controlPlaneManagement must be ACTIVE" >&2
    exit 1
fi
if [[ "$control_plane_implementation" != "ISTIOD" && "$control_plane_implementation" != "TRAFFIC_DIRECTOR" ]]; then
    echo "apolysis-f5: managed Cloud Service Mesh implementation must be ISTIOD or TRAFFIC_DIRECTOR" >&2
    exit 1
fi
if [[ "$data_plane_state" == "NEEDS_ATTENTION" || "$data_plane_state" == "STALLED" || "$data_plane_state" == "FAILED_PRECONDITION" ]]; then
    echo "apolysis-f5: managed Cloud Service Mesh data plane is not healthy: $data_plane_state" >&2
    exit 1
fi

kubectl get crd \
    peerauthentications.security.istio.io \
    authorizationpolicies.security.istio.io \
    --output=json >"$crds"

if kubectl -n istio-system get controlplanerevision "$revision" --output=json >"$control_plane_revision" 2>/dev/null; then
    :
else
    kubectl -n istio-system get controlplanerevision \
        asm-managed asm-managed-stable asm-managed-rapid \
        --ignore-not-found \
        --output=json >"$control_plane_revision"
fi

jq -e '
  if .kind == "ControlPlaneRevisionList" then
    (.items | length) > 0
  else
    .kind == "ControlPlaneRevision"
  end
' "$control_plane_revision" >/dev/null || {
    echo "apolysis-f5: no managed Cloud Service Mesh controlplanerevision evidence found" >&2
    exit 1
}

kubectl get namespace \
    --selector istio.io/rev \
    --output=json >"$namespaces"

managed_namespace_count="$(jq '.items | length' "$namespaces")"
if [[ "$managed_namespace_count" -lt 1 && "${APOLYSIS_F5_GKE_MESH_ALLOW_EMPTY_NAMESPACE_SET:-0}" != "1" ]]; then
    echo "apolysis-f5: no namespaces are labeled for managed Cloud Service Mesh injection" >&2
    exit 1
fi

observed_at_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

python3 - "$evidence" "$report" \
    "$fleet_project" "$membership" "$membership_location" "$cluster_name" \
    "$management" "$control_plane_state" "$control_plane_implementation" "$data_plane_state" \
    "$revision" "$managed_namespace_count" "$observed_at_unix_ms" <<'PY'
import json
import sys
from pathlib import Path

(
    evidence_path,
    report_path,
    fleet_project,
    membership,
    membership_location,
    cluster_name,
    management,
    control_plane_state,
    control_plane_implementation,
    data_plane_state,
    revision,
    managed_namespace_count,
    observed_at_unix_ms,
) = sys.argv[1:]

provider_control_plane = (
    f"gke:{fleet_project}:{membership_location}:{membership}:"
    f"{control_plane_implementation.lower()}"
)
evidence = {
    "evidence_id": f"f5-managed-cloud-service-mesh-{observed_at_unix_ms}",
    "source": "live_provider",
    "provider": "gke_anthos_service_mesh",
    "provider_control_plane": provider_control_plane,
    "fleet_project": fleet_project,
    "membership": membership,
    "membership_location": membership_location,
    "cluster_name": cluster_name,
    "management": management,
    "control_plane_management_state": control_plane_state,
    "control_plane_implementation": control_plane_implementation,
    "data_plane_management_state": data_plane_state,
    "managed_revision": revision,
    "managed_namespace_count": int(managed_namespace_count),
    "fleet_mesh_describe_ref": "gcloud-container-fleet-mesh-describe.json",
    "fleet_membership_ref": "gcloud-container-fleet-membership-describe.json",
    "istio_security_crds_ref": "istio-security-crds.json",
    "control_plane_revision_ref": "controlplanerevision.json",
    "namespaces_ref": "namespaces.json",
    "live_provider": True,
    "external_provider": True,
    "observed_at_unix_ms": int(observed_at_unix_ms),
}
report = {
    "schema_version": 1,
    "passed": True,
    "approval": {
        "provider": "gke_anthos_service_mesh",
        "provider_control_plane": provider_control_plane,
        "qualified_requirement": "managed_service_mesh",
        "control_plane_management_state": control_plane_state,
        "control_plane_implementation": control_plane_implementation,
        "data_plane_management_state": data_plane_state,
        "observed_at_unix_ms": int(observed_at_unix_ms),
    },
    "failures": [],
}
Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

jq -e '
  .source == "live_provider"
  and .provider == "gke_anthos_service_mesh"
  and .external_provider == true
  and .live_provider == true
  and .management == "MANAGEMENT_AUTOMATIC"
  and .control_plane_management_state == "ACTIVE"
  and (.control_plane_implementation == "ISTIOD" or .control_plane_implementation == "TRAFFIC_DIRECTOR")
' "$evidence" >/dev/null

jq -e '
  .passed == true
  and .approval.provider == "gke_anthos_service_mesh"
  and .approval.qualified_requirement == "managed_service_mesh"
' "$report" >/dev/null

cat <<EOF
apolysis-f5: managed Cloud Service Mesh qualification passed ($output_dir)
APOLYSIS_F5_MANAGED_MESH_PROVIDER=gke_anthos_service_mesh
APOLYSIS_F5_MANAGED_MESH_CONTROL_PLANE=$(jq -r '.provider_control_plane' "$evidence")
APOLYSIS_F5_MANAGED_MESH_EVIDENCE=$evidence
APOLYSIS_F5_MANAGED_MESH_REPORT=$report
EOF

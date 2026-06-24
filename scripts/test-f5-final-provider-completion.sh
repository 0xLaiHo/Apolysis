#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_F5_FINAL_PROVIDER_COMPLETION_TEST_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-final-provider-completion-test.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in jq python3; do
    require_command "$command"
done

completion_gate="$repo_root/scripts/verify-f5-final-provider-completion.sh"
if [[ ! -s "$completion_gate" ]]; then
    echo "apolysis-f5: missing F5.38 final provider completion verifier: $completion_gate" >&2
    exit 1
fi

artifact_dir="$output_dir/retained-live-provider-artifacts"
success_dir="$output_dir/success"
failure_dir="$output_dir/failure"
mkdir -p "$artifact_dir" "$success_dir" "$failure_dir"

write_evidence() {
    local path="$1"
    local provider="$2"
    local control_plane_field="$3"
    local control_plane_value="$4"
    cat >"$path" <<JSON
{
  "source": "live_provider",
  "provider": "$provider",
  "$control_plane_field": "$control_plane_value",
  "observed_at_unix_ms": 1782259200000
}
JSON
}

write_report() {
    local path="$1"
    local provider="$2"
    cat >"$path" <<JSON
{
  "passed": true,
  "approval": {
    "provider": "$provider",
    "observed_at_unix_ms": 1782259200000
  }
}
JSON
}

signing_evidence="$artifact_dir/signing-evidence.json"
signing_report="$artifact_dir/signing-report.json"
worm_evidence="$artifact_dir/worm-evidence.json"
worm_report="$artifact_dir/worm-report.json"
registry_evidence="$artifact_dir/registry-evidence.json"
registry_report="$artifact_dir/registry-report.json"
managed_mesh_evidence="$artifact_dir/managed-mesh-evidence.json"
managed_mesh_report="$artifact_dir/managed-mesh-report.json"

write_evidence "$signing_evidence" "cloud_kms" "key_uri" "awskms://arn:aws:kms:us-west-2:111122223333:key/apolysis-f5"
write_report "$signing_report" "cloud_kms"
write_evidence "$worm_evidence" "cloudflare_r2_bucket_lock" "bucket_uri" "cloudflare-r2:e85b6fa3634dc882cfbd2188361fb37e:apolysis-f5-worm"
write_report "$worm_report" "cloudflare_r2_bucket_lock"
write_evidence "$registry_evidence" "docker_hub" "registry_uri" "docker-hub:devlaiho:apolysis-f5-registry"
write_report "$registry_report" "docker_hub"
write_evidence "$managed_mesh_evidence" "gke_anthos_service_mesh" "provider_control_plane" "gke:prod-us-central1:anthos-service-mesh"
write_report "$managed_mesh_report" "gke_anthos_service_mesh"

APOLYSIS_F5_FINAL_PROVIDER_COMPLETION_OUTPUT_DIR="$success_dir" \
APOLYSIS_F5_SIGNING_PROVIDER="aws_kms" \
APOLYSIS_F5_SIGNING_CONTROL_PLANE="awskms://arn:aws:kms:us-west-2:111122223333:key/apolysis-f5" \
APOLYSIS_F5_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_F5_SIGNING_REPORT="$signing_report" \
APOLYSIS_F5_WORM_PROVIDER="cloudflare_r2_bucket_lock" \
APOLYSIS_F5_WORM_CONTROL_PLANE="cloudflare-r2:e85b6fa3634dc882cfbd2188361fb37e:apolysis-f5-worm" \
APOLYSIS_F5_WORM_EVIDENCE="$worm_evidence" \
APOLYSIS_F5_WORM_REPORT="$worm_report" \
APOLYSIS_F5_REGISTRY_PROVIDER="docker_hub" \
APOLYSIS_F5_REGISTRY_CONTROL_PLANE="docker-hub:devlaiho:apolysis-f5-registry" \
APOLYSIS_F5_REGISTRY_EVIDENCE="$registry_evidence" \
APOLYSIS_F5_REGISTRY_REPORT="$registry_report" \
APOLYSIS_F5_MANAGED_MESH_PROVIDER="gke_anthos_service_mesh" \
APOLYSIS_F5_MANAGED_MESH_CONTROL_PLANE="gke:prod-us-central1:anthos-service-mesh" \
APOLYSIS_F5_MANAGED_MESH_EVIDENCE="$managed_mesh_evidence" \
APOLYSIS_F5_MANAGED_MESH_REPORT="$managed_mesh_report" \
    "$completion_gate"

completion_report="$success_dir/apolysis-f5-final-provider-completion-report.json"
jq -e '
  .passed == true
  and .final_provider_ready == true
  and .final_bundle_passed == true
  and (.qualified_requirements | length) == 4
  and (.qualified_requirements | index("cloud_kms_or_external_hsm_signing"))
  and (.qualified_requirements | index("managed_service_mesh"))
  and (.final_bundle_report | test("apolysis-f5-final-external-provider-bundle-report.json$"))
' "$completion_report" >/dev/null

set +e
APOLYSIS_F5_FINAL_PROVIDER_COMPLETION_OUTPUT_DIR="$failure_dir" \
APOLYSIS_F5_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_F5_SIGNING_REPORT="$signing_report" \
APOLYSIS_F5_WORM_EVIDENCE="$worm_evidence" \
APOLYSIS_F5_WORM_REPORT="$worm_report" \
APOLYSIS_F5_REGISTRY_EVIDENCE="$registry_evidence" \
APOLYSIS_F5_REGISTRY_REPORT="$registry_report" \
APOLYSIS_F5_MANAGED_MESH_REPORT="$managed_mesh_report" \
    "$completion_gate" >"$failure_dir/completion.out" 2>"$failure_dir/completion.err"
completion_rc=$?
set -e

if [[ "$completion_rc" -eq 0 ]]; then
    echo "apolysis-f5: final provider completion unexpectedly passed without managed mesh evidence" >&2
    exit 1
fi

jq -e '
  .passed == false
  and .failed_stage == "final_provider_readiness"
  and (.missing_requirements | index("managed_service_mesh"))
' "$failure_dir/apolysis-f5-final-provider-completion-report.json" >/dev/null

printf 'apolysis-f5: final provider completion gate contract passed (%s)\n' "$output_dir"

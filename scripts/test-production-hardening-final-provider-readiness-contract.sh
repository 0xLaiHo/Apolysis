#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS_CONTRACT_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-final-provider-readiness-contract.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in jq python3; do
    require_command "$command"
done

artifact_dir="$output_dir/accepted-looking-fixtures"
run_dir="$output_dir/readiness-run"
mkdir -p "$artifact_dir" "$run_dir"

write_evidence() {
    local path="$1"
    local provider="$2"
    local control_plane_field="$3"
    cat >"$path" <<JSON
{
  "provider": "$provider",
  "$control_plane_field": "$provider-control-plane",
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

write_evidence "$signing_evidence" "cloud_kms" "key_uri"
write_report "$signing_report" "cloud_kms"
write_evidence "$worm_evidence" "cloudflare_r2_bucket_lock" "bucket_uri"
write_report "$worm_report" "cloudflare_r2_bucket_lock"
write_evidence "$registry_evidence" "docker_hub" "registry_uri"
write_report "$registry_report" "docker_hub"
write_evidence "$managed_mesh_evidence" "gke_anthos_service_mesh" "provider_control_plane"
write_report "$managed_mesh_report" "gke_anthos_service_mesh"

set +e
APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS=1 \
APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS_OUTPUT_DIR="$run_dir" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT="$signing_report" \
APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE="$worm_evidence" \
APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT="$worm_report" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE="$registry_evidence" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT="$registry_report" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE="$managed_mesh_evidence" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT="$managed_mesh_report" \
    "$repo_root/scripts/test-production-hardening-final-provider-readiness.sh" \
    >"$output_dir/readiness.out" 2>"$output_dir/readiness.err"
readiness_rc=$?
set -e

if [[ "$readiness_rc" -eq 0 ]]; then
    echo "apolysis-production-hardening: final provider readiness accepted fixture artifacts without live_provider evidence source" >&2
    cat "$output_dir/readiness.out" >&2
    cat "$output_dir/readiness.err" >&2
    exit 1
fi

report="$run_dir/apolysis-production-hardening-final-provider-readiness-report.json"
jq -e '
  .final_provider_ready == false
  and (.missing_requirements | index("cloud_kms_or_external_hsm_signing"))
  and (.missing_requirements | index("cloud_worm_object_lock_archive"))
  and (.missing_requirements | index("cloud_registry_promotion_retention"))
  and (.missing_requirements | index("managed_service_mesh"))
  and .artifact_inputs.APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE.live_provider_evidence == false
  and .artifact_inputs.APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE.live_provider_evidence == false
' "$report" >/dev/null

printf 'apolysis-production-hardening: final provider readiness fixture rejection contract passed (%s)\n' "$output_dir"

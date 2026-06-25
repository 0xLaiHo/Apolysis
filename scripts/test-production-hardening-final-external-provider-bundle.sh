#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_TEST_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-final-external-provider-bundle-test.XXXXXX")}"
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

artifact_dir="$output_dir/retained-artifacts"
success_dir="$output_dir/success"
failure_dir="$output_dir/failure"
mkdir -p "$artifact_dir" "$success_dir" "$failure_dir"

write_json_artifact() {
    local path="$1"
    local provider="$2"
    local body_field="$3"
    cat >"$path" <<JSON
{
  "provider": "$provider",
  "$body_field": "$provider-control-plane",
  "observed_at_unix_ms": 1782259200000
}
JSON
}

write_report_artifact() {
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

write_json_artifact "$signing_evidence" "cloud_kms" "key_uri"
write_report_artifact "$signing_report" "cloud_kms"
write_json_artifact "$worm_evidence" "cloudflare_r2_bucket_lock" "bucket_uri"
write_report_artifact "$worm_report" "cloudflare_r2_bucket_lock"
write_json_artifact "$registry_evidence" "docker_hub" "registry_uri"
write_report_artifact "$registry_report" "docker_hub"
write_json_artifact "$managed_mesh_evidence" "gke_anthos_service_mesh" "mesh_uri"
write_report_artifact "$managed_mesh_report" "gke_anthos_service_mesh"

APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_OUTPUT_DIR="$success_dir" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER="aws_kms" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_CONTROL_PLANE="awskms://arn:aws:kms:us-west-2:111122223333:key/apolysis-production-hardening" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT="$signing_report" \
APOLYSIS_PRODUCTION_HARDENING_WORM_PROVIDER="cloudflare_r2_bucket_lock" \
APOLYSIS_PRODUCTION_HARDENING_WORM_CONTROL_PLANE="cloudflare-r2:e85b6fa3634dc882cfbd2188361fb37e:apolysis-production-hardening-worm" \
APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE="$worm_evidence" \
APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT="$worm_report" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_PROVIDER="docker_hub" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_CONTROL_PLANE="docker-hub:devlaiho:apolysis-production-hardening-registry" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE="$registry_evidence" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT="$registry_report" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_PROVIDER="gke_anthos_service_mesh" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_CONTROL_PLANE="gke:prod-us-central1:anthos-service-mesh" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE="$managed_mesh_evidence" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT="$managed_mesh_report" \
    "$repo_root/scripts/build-production-hardening-final-external-provider-bundle.sh"

report="$success_dir/apolysis-production-hardening-final-external-provider-bundle-report.json"
bundle="$success_dir/bundle-root/apolysis-production-hardening-final-external-provider-bundle.json"
jq -e '
  .passed == true
  and (.approval.qualified_requirements | length) == 4
  and (.approval.providers | index("aws_kms"))
  and (.approval.providers | index("cloudflare_r2_bucket_lock"))
  and (.approval.providers | index("docker_hub"))
  and (.approval.providers | index("gke_anthos_service_mesh"))
' "$report" >/dev/null

jq -e '
  .source == "evidence_bundle"
  and (.entries | length) == 4
  and ([.entries[].requirement] | index("cloud_kms_or_external_hsm_signing"))
  and ([.entries[].requirement] | index("managed_service_mesh"))
  and ([.entries[].evidence_sha256] | all(startswith("sha256:")))
' "$bundle" >/dev/null

if APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_OUTPUT_DIR="$failure_dir" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER="aws_kms" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_CONTROL_PLANE="awskms://arn:aws:kms:us-west-2:111122223333:key/apolysis-production-hardening" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT="$signing_report" \
APOLYSIS_PRODUCTION_HARDENING_WORM_PROVIDER="cloudflare_r2_bucket_lock" \
APOLYSIS_PRODUCTION_HARDENING_WORM_CONTROL_PLANE="cloudflare-r2:e85b6fa3634dc882cfbd2188361fb37e:apolysis-production-hardening-worm" \
APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE="$worm_evidence" \
APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT="$worm_report" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_PROVIDER="docker_hub" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_CONTROL_PLANE="docker-hub:devlaiho:apolysis-production-hardening-registry" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE="$registry_evidence" \
APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT="$registry_report" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_PROVIDER="gke_anthos_service_mesh" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_CONTROL_PLANE="gke:prod-us-central1:anthos-service-mesh" \
APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT="$managed_mesh_report" \
    "$repo_root/scripts/build-production-hardening-final-external-provider-bundle.sh" >"$failure_dir/missing-managed-mesh.out" 2>"$failure_dir/missing-managed-mesh.err"; then
    echo "apolysis-production-hardening: final external bundle unexpectedly passed without managed mesh evidence" >&2
    exit 1
fi

grep -q 'APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE is required' "$failure_dir/missing-managed-mesh.err" || {
    echo "apolysis-production-hardening: final external bundle did not fail closed on missing managed mesh evidence" >&2
    exit 1
}

printf 'apolysis-production-hardening: final external provider bundle assembly gate passed (%s)\n' "$output_dir"

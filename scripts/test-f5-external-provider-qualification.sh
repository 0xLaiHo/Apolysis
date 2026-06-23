#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_F5_EXTERNAL_PROVIDER_QUALIFICATION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-external-provider-qualification.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in cargo jq python3; do
    require_command "$command"
done

contract_bundle="$output_dir/apolysis-f5-external-provider-qualification-contract.json"
contract_report="$output_dir/apolysis-f5-external-provider-qualification-contract-report.json"
local_bundle="$output_dir/apolysis-f5-external-provider-qualification-local-rejection.json"
local_report="$output_dir/apolysis-f5-external-provider-qualification-local-rejection-report.json"
live_bundle="${APOLYSIS_F5_EXTERNAL_PROVIDER_BUNDLE:-}"
live_report="$output_dir/apolysis-f5-external-provider-qualification-live-report.json"

cat >"$contract_bundle" <<'JSON'
{
  "bundle_id": "f5-external-provider-qualification-contract",
  "source": "evidence_bundle",
  "operator_approved": true,
  "generated_at_unix_ms": 1782259200000,
  "entries": [
    {
      "requirement": "cloud_kms_or_external_hsm_signing",
      "provider": "aws_kms",
      "provider_control_plane": "aws-kms:us-west-2:alias/apolysis-f5-release",
      "evidence_ref": "evidence/aws-kms-signing.json",
      "evidence_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "report_ref": "reports/aws-kms-signing.json",
      "report_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "live_provider": true,
      "external_provider": true,
      "observed_at_unix_ms": 1782259200000
    },
    {
      "requirement": "cloud_worm_object_lock_archive",
      "provider": "cloudflare_r2_bucket_lock",
      "provider_control_plane": "cloudflare-r2:e85b6fa3634dc882cfbd2188361fb37e:apolysis-f5-worm-1782254413912",
      "evidence_ref": "evidence/cloudflare-r2-bucket-lock.json",
      "evidence_sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "report_ref": "reports/cloudflare-r2-bucket-lock.json",
      "report_sha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "live_provider": true,
      "external_provider": true,
      "observed_at_unix_ms": 1782259200000
    },
    {
      "requirement": "cloud_registry_promotion_retention",
      "provider": "docker_hub",
      "provider_control_plane": "docker-hub:devlaiho:apolysis-f5-registry",
      "evidence_ref": "target/f5-dockerhub-registry-promotion.aByXvA/apolysis-f5-dockerhub-registry-promotion-evidence.json",
      "evidence_sha256": "sha256:7f934c70a1fe8a589030d0470a653841f7f05ff4a1d591c2e9c1cea70c6f38ef",
      "report_ref": "target/f5-dockerhub-registry-promotion.aByXvA/apolysis-f5-dockerhub-registry-promotion-report.json",
      "report_sha256": "sha256:78e8e8d4d0f89e862ca05aa9032f9716198775ad8135880dd51b4d82af307641",
      "live_provider": true,
      "external_provider": true,
      "observed_at_unix_ms": 1782259200000
    },
    {
      "requirement": "managed_service_mesh",
      "provider": "gke_anthos_service_mesh",
      "provider_control_plane": "gke:prod-us-central1:anthos-service-mesh",
      "evidence_ref": "evidence/gke-anthos-service-mesh.json",
      "evidence_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "report_ref": "reports/gke-anthos-service-mesh.json",
      "report_sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "live_provider": true,
      "external_provider": true,
      "observed_at_unix_ms": 1782259200000
    }
  ]
}
JSON

cargo run -q -p apolysis-validation --bin apolysis-f5-external-provider-qualification -- \
    --bundle "$contract_bundle" >"$contract_report"

jq -e '
  .schema_version == 1
  and .passed == true
  and (.approval.qualified_requirements | length) == 4
  and (.approval.providers | index("aws_kms"))
  and (.approval.providers | index("cloudflare_r2_bucket_lock"))
  and (.approval.providers | index("docker_hub"))
  and (.approval.providers | index("gke_anthos_service_mesh"))
' "$contract_report" >/dev/null

cat >"$local_bundle" <<'JSON'
{
  "bundle_id": "f5-local-provider-qualification-must-fail",
  "source": "evidence_bundle",
  "operator_approved": true,
  "generated_at_unix_ms": 1782259200000,
  "entries": [
    {
      "requirement": "cloud_kms_or_external_hsm_signing",
      "provider": "softhsm",
      "provider_control_plane": "local workstation",
      "evidence_ref": "target/f5-signing-execution/local.json",
      "evidence_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "report_ref": "target/f5-signing-execution/report.json",
      "report_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "live_provider": true,
      "external_provider": false,
      "observed_at_unix_ms": 1782259200000
    },
    {
      "requirement": "cloud_worm_object_lock_archive",
      "provider": "minio",
      "provider_control_plane": "local docker",
      "evidence_ref": "target/f5-worm-archive-execution/local.json",
      "evidence_sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "report_ref": "target/f5-worm-archive-execution/report.json",
      "report_sha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "live_provider": true,
      "external_provider": false,
      "observed_at_unix_ms": 1782259200000
    },
    {
      "requirement": "cloud_registry_promotion_retention",
      "provider": "oci_distribution_registry",
      "provider_control_plane": "local docker registry:2",
      "evidence_ref": "target/f5-registry-promotion-execution/local.json",
      "evidence_sha256": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      "report_ref": "target/f5-registry-promotion-execution/report.json",
      "report_sha256": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "live_provider": true,
      "external_provider": false,
      "observed_at_unix_ms": 1782259200000
    },
    {
      "requirement": "managed_service_mesh",
      "provider": "istio",
      "provider_control_plane": "local k3s",
      "evidence_ref": "target/f5-service-mesh-live-evidence/local.json",
      "evidence_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "report_ref": "target/f5-service-mesh-live-evidence/report.json",
      "report_sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "live_provider": true,
      "external_provider": false,
      "observed_at_unix_ms": 1782259200000
    }
  ]
}
JSON

if cargo run -q -p apolysis-validation --bin apolysis-f5-external-provider-qualification -- \
    --bundle "$local_bundle" >"$local_report"; then
    echo "apolysis-f5: local provider qualification unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("external provider evidence is required"))
  and (.failures | map(.message) | index("provider must be an accepted external provider for this requirement"))
' "$local_report" >/dev/null

if [[ "${APOLYSIS_REQUIRE_F5_EXTERNAL_PROVIDER_QUALIFICATION:-0}" == "1" && -z "$live_bundle" ]]; then
    cat >&2 <<'EOF'
apolysis-f5: external provider qualification is required but no bundle was supplied.
Set APOLYSIS_F5_EXTERNAL_PROVIDER_BUNDLE to a JSON bundle containing real
cloud KMS/external HSM, cloud WORM/object-lock, cloud registry, and managed
service-mesh evidence, and set APOLYSIS_CONFIRM_F5_EXTERNAL_PROVIDER_QUALIFICATION=1.
EOF
    exit 2
fi

if [[ -n "$live_bundle" ]]; then
    if [[ "${APOLYSIS_CONFIRM_F5_EXTERNAL_PROVIDER_QUALIFICATION:-0}" != "1" ]]; then
        echo "apolysis-f5: refusing to validate external provider bundle without APOLYSIS_CONFIRM_F5_EXTERNAL_PROVIDER_QUALIFICATION=1" >&2
        exit 2
    fi
    cargo run -q -p apolysis-validation --bin apolysis-f5-external-provider-qualification -- \
        --bundle "$live_bundle" >"$live_report"
    jq -e '.passed == true and (.approval.qualified_requirements | length) == 4' "$live_report" >/dev/null
    printf 'apolysis-f5: external provider qualification live bundle passed (%s)\n' "$live_report"
else
    printf 'apolysis-f5: external provider qualification contract and local-provider rejection gates passed (%s)\n' "$output_dir"
fi

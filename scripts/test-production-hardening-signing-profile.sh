#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROFILE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-signing-profile.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in cargo jq python3; do
    require_command "$command"
done

kms_profile="$output_dir/apolysis-production-hardening-kms-signing-profile.json"
hsm_profile="$output_dir/apolysis-production-hardening-hsm-signing-profile.json"
local_profile="$output_dir/apolysis-production-hardening-local-signing-profile.json"
kms_report="$output_dir/apolysis-production-hardening-kms-signing-profile-report.json"
hsm_report="$output_dir/apolysis-production-hardening-hsm-signing-profile-report.json"
local_report="$output_dir/apolysis-production-hardening-local-signing-profile-report.json"

cat >"$kms_profile" <<'JSON'
{
  "profile_id": "production-hardening-kms-release-signer",
  "provider": "kms",
  "key_uri": "awskms://alias/apolysis-production-hardening-release",
  "public_key_ref": "kms://alias/apolysis-production-hardening-release/public-key",
  "certificate_chain_ref": "kms://alias/apolysis-production-hardening-release/cert-chain",
  "attestation_ref": "kms://alias/apolysis-production-hardening-release/key-policy",
  "non_exportable": true,
  "hardware_or_service_backed": true,
  "operator_approved": true,
  "rotation_period_days": 90,
  "allowed_release_channels": ["staging", "production"]
}
JSON

cat >"$hsm_profile" <<'JSON'
{
  "profile_id": "production-hardening-hsm-release-signer",
  "provider": "hsm",
  "key_uri": "pkcs11:token=apolysis;object=production-hardening-release;type=private",
  "public_key_ref": "pkcs11:token=apolysis;object=production-hardening-release;type=public",
  "certificate_chain_ref": "pkcs11:token=apolysis;object=production-hardening-release-chain;type=cert",
  "attestation_ref": "hsm://apolysis/production-hardening-release/key-attestation",
  "non_exportable": true,
  "hardware_or_service_backed": true,
  "operator_approved": true,
  "rotation_period_days": 90,
  "allowed_release_channels": ["production"]
}
JSON

cat >"$local_profile" <<'JSON'
{
  "profile_id": "production-hardening-local-release-signer",
  "provider": "local_file",
  "key_uri": "/var/lib/apolysis/release.key",
  "public_key_ref": "",
  "certificate_chain_ref": "",
  "attestation_ref": "",
  "non_exportable": false,
  "hardware_or_service_backed": false,
  "operator_approved": false,
  "rotation_period_days": 365,
  "allowed_release_channels": ["staging"]
}
JSON

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-signing-profile -- \
    --profile "$kms_profile" >"$kms_report"
cargo run -q -p apolysis-validation --bin apolysis-production-hardening-signing-profile -- \
    --profile "$hsm_profile" >"$hsm_report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "kms"
  and .approval.key_uri == "awskms://alias/apolysis-production-hardening-release"
  and .approval.max_rotation_period_days == 90
' "$kms_report" >/dev/null

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "hsm"
  and (.approval.key_uri | startswith("pkcs11:"))
' "$hsm_report" >/dev/null

if cargo run -q -p apolysis-validation --bin apolysis-production-hardening-signing-profile -- \
    --profile "$local_profile" >"$local_report"; then
    echo "apolysis-production-hardening: local/exportable production signing profile unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("production release signing requires KMS or HSM provider"))
  and (.failures | map(.message) | index("production signing key must be non-exportable"))
  and (.failures | map(.message) | index("file paths are not valid production signing key URIs"))
' "$local_report" >/dev/null

printf 'apolysis-production-hardening: KMS/HSM signing profile gate passed (%s)\n' "$output_dir"

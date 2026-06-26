#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-final-external-provider-bundle.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

bundle_root="$output_dir/bundle-root"
bundle="$bundle_root/apolysis-production-hardening-final-external-provider-bundle.json"
report="$output_dir/apolysis-production-hardening-final-external-provider-bundle-report.json"
mkdir -p "$bundle_root/evidence" "$bundle_root/reports"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_env() {
    local name="$1"
    local value="${!name:-}"
    if [[ -z "$value" ]]; then
        echo "apolysis-production-hardening: $name is required for the final external provider bundle" >&2
        exit 2
    fi
    printf '%s' "$value"
}

require_file() {
    local path="$1"
    local label="$2"
    if [[ ! -f "$path" ]]; then
        echo "apolysis-production-hardening: missing retained $label artifact: $path" >&2
        exit 2
    fi
}

for command in cargo jq python3 sha256sum; do
    require_command "$command"
done

signing_evidence="$(require_env APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE)"
signing_report="$(require_env APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT)"
worm_evidence="$(require_env APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE)"
worm_report="$(require_env APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT)"
registry_evidence="$(require_env APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE)"
registry_report="$(require_env APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT)"
managed_mesh_evidence="$(require_env APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE)"
managed_mesh_report="$(require_env APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT)"

require_file "$signing_evidence" "signing evidence"
require_file "$signing_report" "signing report"
require_file "$worm_evidence" "WORM evidence"
require_file "$worm_report" "WORM report"
require_file "$registry_evidence" "registry evidence"
require_file "$registry_report" "registry report"
require_file "$managed_mesh_evidence" "managed mesh evidence"
require_file "$managed_mesh_report" "managed mesh report"

copy_artifact() {
    local source="$1"
    local relative="$2"
    cp "$source" "$bundle_root/$relative"
    sha256sum "$bundle_root/$relative" | awk '{print "sha256:" $1}'
}

signing_evidence_ref="evidence/signing.json"
signing_report_ref="reports/signing-report.json"
worm_evidence_ref="evidence/worm.json"
worm_report_ref="reports/worm-report.json"
registry_evidence_ref="evidence/registry.json"
registry_report_ref="reports/registry-report.json"
managed_mesh_evidence_ref="evidence/managed-mesh.json"
managed_mesh_report_ref="reports/managed-mesh-report.json"

signing_evidence_sha="$(copy_artifact "$signing_evidence" "$signing_evidence_ref")"
signing_report_sha="$(copy_artifact "$signing_report" "$signing_report_ref")"
worm_evidence_sha="$(copy_artifact "$worm_evidence" "$worm_evidence_ref")"
worm_report_sha="$(copy_artifact "$worm_report" "$worm_report_ref")"
registry_evidence_sha="$(copy_artifact "$registry_evidence" "$registry_evidence_ref")"
registry_report_sha="$(copy_artifact "$registry_report" "$registry_report_ref")"
managed_mesh_evidence_sha="$(copy_artifact "$managed_mesh_evidence" "$managed_mesh_evidence_ref")"
managed_mesh_report_sha="$(copy_artifact "$managed_mesh_report" "$managed_mesh_report_ref")"

generated_at_unix_ms="$(python3 - <<'PY'
import os
import time

for name in (
    "APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_TIMESTAMP_UNIX_MS",
    "APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_TIMESTAMP_UNIX_MS",
):
    value = os.environ.get(name, "")
    if value:
        timestamp = int(value)
        if timestamp <= 0:
            raise SystemExit(f"{name} must be a positive Unix timestamp in milliseconds")
        print(timestamp)
        raise SystemExit(0)

source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
if source_date_epoch:
    timestamp = int(source_date_epoch) * 1000
    if timestamp <= 0:
        raise SystemExit("SOURCE_DATE_EPOCH must be a positive Unix timestamp in seconds")
    print(timestamp)
else:
    print(int(time.time() * 1000))
PY
)"

python3 - "$bundle" \
    "$generated_at_unix_ms" \
    "${APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER:-aws_kms}" \
    "${APOLYSIS_PRODUCTION_HARDENING_SIGNING_CONTROL_PLANE:-$(jq -r '.key_uri // .approval.key_uri // empty' "$signing_evidence")}" \
    "$signing_evidence_ref" "$signing_evidence_sha" "$signing_report_ref" "$signing_report_sha" \
    "${APOLYSIS_PRODUCTION_HARDENING_WORM_PROVIDER:-$(jq -r '.provider // .approval.provider // empty' "$worm_evidence")}" \
    "${APOLYSIS_PRODUCTION_HARDENING_WORM_CONTROL_PLANE:-$(jq -r '.bucket_uri // .approval.bucket_uri // .endpoint_uri // empty' "$worm_evidence")}" \
    "$worm_evidence_ref" "$worm_evidence_sha" "$worm_report_ref" "$worm_report_sha" \
    "${APOLYSIS_PRODUCTION_HARDENING_REGISTRY_PROVIDER:-$(jq -r '.provider // .approval.provider // empty' "$registry_evidence")}" \
    "${APOLYSIS_PRODUCTION_HARDENING_REGISTRY_CONTROL_PLANE:-$(jq -r '.registry_uri // .approval.registry_uri // empty' "$registry_evidence")}" \
    "$registry_evidence_ref" "$registry_evidence_sha" "$registry_report_ref" "$registry_report_sha" \
    "$(require_env APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_PROVIDER)" \
    "$(require_env APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_CONTROL_PLANE)" \
    "$managed_mesh_evidence_ref" "$managed_mesh_evidence_sha" "$managed_mesh_report_ref" "$managed_mesh_report_sha" \
    "$(jq -r '.observed_at_unix_ms // .approval.observed_at_unix_ms // empty' "$signing_evidence")" \
    "$(jq -r '.observed_at_unix_ms // .approval.observed_at_unix_ms // empty' "$worm_evidence")" \
    "$(jq -r '.observed_at_unix_ms // .approval.observed_at_unix_ms // empty' "$registry_evidence")" \
    "$(jq -r '.observed_at_unix_ms // .approval.observed_at_unix_ms // empty' "$managed_mesh_evidence")" <<'PY'
import json
import sys
from pathlib import Path

(
    bundle_path,
    generated_at_unix_ms,
    signing_provider,
    signing_control_plane,
    signing_evidence_ref,
    signing_evidence_sha,
    signing_report_ref,
    signing_report_sha,
    worm_provider,
    worm_control_plane,
    worm_evidence_ref,
    worm_evidence_sha,
    worm_report_ref,
    worm_report_sha,
    registry_provider,
    registry_control_plane,
    registry_evidence_ref,
    registry_evidence_sha,
    registry_report_ref,
    registry_report_sha,
    managed_mesh_provider,
    managed_mesh_control_plane,
    managed_mesh_evidence_ref,
    managed_mesh_evidence_sha,
    managed_mesh_report_ref,
    managed_mesh_report_sha,
    signing_observed,
    worm_observed,
    registry_observed,
    managed_mesh_observed,
) = sys.argv[1:]

entries = [
    (
        "cloud_kms_or_external_hsm_signing",
        signing_provider,
        signing_control_plane,
        signing_evidence_ref,
        signing_evidence_sha,
        signing_report_ref,
        signing_report_sha,
        signing_observed,
    ),
    (
        "cloud_worm_object_lock_archive",
        worm_provider,
        worm_control_plane,
        worm_evidence_ref,
        worm_evidence_sha,
        worm_report_ref,
        worm_report_sha,
        worm_observed,
    ),
    (
        "cloud_registry_promotion_retention",
        registry_provider,
        registry_control_plane,
        registry_evidence_ref,
        registry_evidence_sha,
        registry_report_ref,
        registry_report_sha,
        registry_observed,
    ),
    (
        "managed_service_mesh",
        managed_mesh_provider,
        managed_mesh_control_plane,
        managed_mesh_evidence_ref,
        managed_mesh_evidence_sha,
        managed_mesh_report_ref,
        managed_mesh_report_sha,
        managed_mesh_observed,
    ),
]

bundle_entries = []
for (
    requirement,
    provider,
    control_plane,
    evidence_ref,
    evidence_sha,
    report_ref,
    report_sha,
    observed,
) in entries:
    if not provider.strip():
        raise SystemExit(f"missing provider for {requirement}")
    if not control_plane.strip():
        raise SystemExit(f"missing provider control plane for {requirement}")
    if not observed.strip() or int(observed) <= 0:
        raise SystemExit(f"missing observed timestamp for {requirement}")
    bundle_entries.append(
        {
            "requirement": requirement,
            "provider": provider,
            "provider_control_plane": control_plane,
            "evidence_ref": evidence_ref,
            "evidence_sha256": evidence_sha,
            "report_ref": report_ref,
            "report_sha256": report_sha,
            "live_provider": True,
            "external_provider": True,
            "observed_at_unix_ms": int(observed),
        }
    )

bundle = {
    "bundle_id": f"production-hardening-final-external-provider-bundle-{generated_at_unix_ms}",
    "source": "evidence_bundle",
    "entries": bundle_entries,
    "operator_approved": True,
    "generated_at_unix_ms": int(generated_at_unix_ms),
}
Path(bundle_path).write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-external-provider-qualification -- \
    --bundle "$bundle" \
    --bundle-root "$bundle_root" >"$report"

jq -e '.passed == true and (.approval.qualified_requirements | length) == 4' "$report" >/dev/null

printf 'apolysis-production-hardening: final external provider bundle passed (%s)\n' "$output_dir"

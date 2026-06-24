#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_RETAINED_PROVIDER_PACKAGE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-retained-provider-artifact-package.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

env_output_dir="$output_dir/env"
package_root="$output_dir/package-root"
evidence_dir="$package_root/evidence"
reports_dir="$package_root/reports"
manifest="$package_root/apolysis-f5-retained-provider-artifacts-manifest.json"
archive="$output_dir/apolysis-f5-retained-provider-artifacts.tar.gz"
archive_sha="$output_dir/apolysis-f5-retained-provider-artifacts.tar.gz.sha256"
report="$output_dir/apolysis-f5-retained-provider-artifact-package-report.json"

require_ready="${APOLYSIS_REQUIRE_F5_RETAINED_PROVIDER_PACKAGE:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in jq python3 sha256sum tar; do
    require_command "$command"
done

mkdir -p "$env_output_dir" "$evidence_dir" "$reports_dir"

APOLYSIS_F5_FINAL_PROVIDER_BUNDLE_ENV_OUTPUT_DIR="$env_output_dir" \
    "$repo_root/scripts/prepare-f5-final-provider-bundle-env.sh" >/dev/null

env_file="$env_output_dir/apolysis-f5-final-provider-bundle.env"
env_report="$env_output_dir/apolysis-f5-final-provider-bundle-env-report.json"
if [[ ! -s "$env_file" || ! -s "$env_report" ]]; then
    echo "apolysis-f5: F5.31 env gate did not produce retained provider paths" >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$env_file"

python3 - "$manifest" "$report" "$archive" "$archive_sha" "$require_ready" "$env_report" \
    "${APOLYSIS_F5_SIGNING_EVIDENCE:-}" "${APOLYSIS_F5_SIGNING_REPORT:-}" \
    "${APOLYSIS_F5_WORM_EVIDENCE:-}" "${APOLYSIS_F5_WORM_REPORT:-}" \
    "${APOLYSIS_F5_REGISTRY_EVIDENCE:-}" "${APOLYSIS_F5_REGISTRY_REPORT:-}" \
    "${APOLYSIS_F5_MANAGED_MESH_EVIDENCE:-}" "${APOLYSIS_F5_MANAGED_MESH_REPORT:-}" <<'PY'
import json
import shutil
import sys
import time
from pathlib import Path

(
    manifest_path,
    report_path,
    archive_path,
    archive_sha_path,
    require_ready,
    env_report_path,
    signing_evidence,
    signing_report,
    worm_evidence,
    worm_report,
    registry_evidence,
    registry_report,
    managed_mesh_evidence,
    managed_mesh_report,
) = sys.argv[1:]

manifest_path = Path(manifest_path)
report_path = Path(report_path)
archive_path = Path(archive_path)
archive_sha_path = Path(archive_sha_path)
package_root = manifest_path.parent
evidence_dir = package_root / "evidence"
reports_dir = package_root / "reports"

classes = {
    "cloud_kms_or_external_hsm_signing": (
        signing_evidence,
        signing_report,
        "aws-kms-signing-evidence.json",
        "aws-kms-signing-report.json",
    ),
    "cloud_worm_object_lock_archive": (
        worm_evidence,
        worm_report,
        "cloudflare-r2-worm-evidence.json",
        "cloudflare-r2-worm-report.json",
    ),
    "cloud_registry_promotion_retention": (
        registry_evidence,
        registry_report,
        "dockerhub-registry-evidence.json",
        "dockerhub-registry-report.json",
    ),
    "managed_service_mesh": (
        managed_mesh_evidence,
        managed_mesh_report,
        "managed-cloud-service-mesh-evidence.json",
        "managed-cloud-service-mesh-report.json",
    ),
}

def copy_if_present(source: str, destination: Path) -> bool:
    if not source:
        return False
    path = Path(source)
    if not path.is_file():
        return False
    shutil.copy2(path, destination)
    return True

entries = []
missing = []
for requirement, (evidence, report, evidence_name, report_name) in classes.items():
    evidence_ref = f"evidence/{evidence_name}"
    report_ref = f"reports/{report_name}"
    evidence_copied = copy_if_present(evidence, package_root / evidence_ref)
    report_copied = copy_if_present(report, package_root / report_ref)
    if evidence_copied and report_copied:
        entries.append(
            {
                "requirement": requirement,
                "evidence_ref": evidence_ref,
                "report_ref": report_ref,
                "source_evidence": evidence,
                "source_report": report,
            }
        )
    else:
        missing.append(requirement)

observed_at_unix_ms = int(time.time() * 1000)
manifest = {
    "schema_version": 1,
    "package_id": f"f5-retained-provider-artifacts-{observed_at_unix_ms}",
    "source": "retained_provider_artifact_package",
    "entries": entries,
    "missing_requirements": missing,
    "env_report_ref": "reports/final-provider-bundle-env-report.json",
    "observed_at_unix_ms": observed_at_unix_ms,
}
shutil.copy2(env_report_path, reports_dir / "final-provider-bundle-env-report.json")
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

package_report = {
    "schema_version": 1,
    "passed": bool(entries) and (not missing or require_ready != "1"),
    "fail_closed_required": require_ready == "1",
    "packaged_requirements": [entry["requirement"] for entry in entries],
    "missing_requirements": missing,
    "manifest": str(manifest_path),
    "archive": str(archive_path),
    "archive_sha256_file": str(archive_sha_path),
    "observed_at_unix_ms": observed_at_unix_ms,
}
report_path.write_text(json.dumps(package_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if require_ready == "1" and missing:
    raise SystemExit("missing requirements: " + ", ".join(missing))
if not entries:
    raise SystemExit("no retained provider artifacts were packaged")
PY

tar -C "$package_root" -czf "$archive" .
sha256sum "$archive" >"$archive_sha"

jq -e '.passed == true and (.packaged_requirements | length) >= 1' "$report" >/dev/null

cat <<EOF
apolysis-f5: retained provider artifact package written ($output_dir)
APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE=$archive
APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256=$(awk '{print $1}' "$archive_sha")
APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE_MANIFEST=$manifest
APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE_REPORT=$report
EOF

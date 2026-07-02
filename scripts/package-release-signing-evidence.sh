#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'apolysis-release-signing: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

truthy() {
    case "${1:-}" in
        1 | true | TRUE | yes | YES) return 0 ;;
        *) return 1 ;;
    esac
}

discover_file() {
    local root="$1"
    local include_a="$2"
    local include_b="$3"
    local exclude="${4:-}"
    [[ -d "$root" ]] || return 0
    find "$root" -type f -name '*.json' | while IFS= read -r path; do
        base="$(basename "$path")"
        [[ "$base" == *"$include_a"* && "$base" == *"$include_b"* ]] || continue
        [[ -n "$exclude" && "$base" == *"$exclude"* ]] && continue
        printf '%s\n' "$path"
    done | sort | head -n 1
}

require_command python3
require_command sha256sum

artifact_dir="${APOLYSIS_RELEASE_ARTIFACT_DIR:-target/release-artifacts}"
signing_input_dir="${APOLYSIS_RELEASE_SIGNING_INPUT_DIR:-}"
require_signing="${APOLYSIS_REQUIRE_RELEASE_SIGNING:-0}"
release_manifest="$artifact_dir/apolysis-release-manifest.json"
signing_manifest="$artifact_dir/apolysis-release-signing-manifest.json"
release_signing_evidence="$artifact_dir/apolysis-release-signing-evidence.json"
release_signing_report="$artifact_dir/apolysis-release-signing-report.json"
regulated_output_dir="$artifact_dir/release-signing-validation"
regulated_report="$artifact_dir/apolysis-regulated-release-signing-evidence-report.json"

[[ -f "$release_manifest" ]] || fail "missing release manifest: $release_manifest"
mkdir -p "$artifact_dir" "$regulated_output_dir"
artifact_dir="$(cd "$artifact_dir" && pwd)"
regulated_output_dir="$(cd "$regulated_output_dir" && pwd)"

signing_evidence="${APOLYSIS_RELEASE_SIGNING_EVIDENCE:-}"
signing_report="${APOLYSIS_RELEASE_SIGNING_REPORT:-}"

if [[ -z "$signing_evidence" && -n "$signing_input_dir" ]]; then
    signing_evidence="$(discover_file "$signing_input_dir" signing evidence report || true)"
fi
if [[ -z "$signing_report" && -n "$signing_input_dir" ]]; then
    signing_report="$(discover_file "$signing_input_dir" signing report || true)"
fi

release_manifest_sha256="$(sha256 "$release_manifest")"

if [[ -z "$signing_evidence" || -z "$signing_report" ]]; then
    python3 - "$signing_manifest" "$release_manifest" "$release_manifest_sha256" "$require_signing" <<'PY'
import json
import sys
import time
from pathlib import Path

manifest_path = Path(sys.argv[1])
release_manifest_path = Path(sys.argv[2])
release_manifest_sha256 = sys.argv[3]
require_signing = sys.argv[4] in {"1", "true", "TRUE", "yes", "YES"}
doc = {
    "schema_version": 1,
    "release_signing_ready": False,
    "release_manifest": release_manifest_path.name,
    "release_manifest_sha256": release_manifest_sha256,
    "missing_requirements": [
        "retained_release_signing_evidence",
        "retained_release_signing_report",
    ],
    "fail_closed_required": require_signing,
    "notes": [
        "No secret values are recorded in this manifest.",
        "Apolysis release signing reuses retained regulated-release/F6 signing evidence.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}
manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    if truthy "$require_signing"; then
        fail "release signing evidence is required"
    fi
    printf 'apolysis-release-signing: unsigned release manifest written (%s)\n' "$signing_manifest"
    exit 0
fi

[[ -f "$signing_evidence" ]] || fail "missing release signing evidence: $signing_evidence"
[[ -f "$signing_report" ]] || fail "missing release signing report: $signing_report"

APOLYSIS_REQUIRE_REGULATED_RELEASE_SIGNING_EVIDENCE=1 \
APOLYSIS_REGULATED_RELEASE_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_REGULATED_RELEASE_SIGNING_REPORT="$signing_report" \
APOLYSIS_REGULATED_RELEASE_SIGNING_EVIDENCE_OUTPUT_DIR="$regulated_output_dir" \
    ./scripts/test-regulated-release-signing-evidence.sh >/dev/null

regulated_source_report="$regulated_output_dir/apolysis-regulated-release-signing-evidence-report.json"
[[ -f "$regulated_source_report" ]] || fail "missing regulated-release signing report: $regulated_source_report"

cp "$signing_evidence" "$release_signing_evidence"
cp "$signing_report" "$release_signing_report"
cp "$regulated_source_report" "$regulated_report"

python3 - \
    "$signing_manifest" \
    "$release_manifest" \
    "$release_manifest_sha256" \
    "$release_signing_evidence" \
    "$release_signing_report" \
    "$regulated_report" \
    "${APOLYSIS_RELEASE_VERSION:-}" \
    "${APOLYSIS_RELEASE_TARGET:-}" <<'PY'
import hashlib
import json
import sys
import time
from pathlib import Path

(
    manifest_path,
    release_manifest_path,
    release_manifest_sha256,
    evidence_path,
    report_path,
    regulated_report_path,
    release_version,
    target,
) = sys.argv[1:]

manifest_path = Path(manifest_path)
release_manifest_path = Path(release_manifest_path)
evidence_path = Path(evidence_path)
report_path = Path(report_path)
regulated_report_path = Path(regulated_report_path)

release_doc = json.loads(release_manifest_path.read_text(encoding="utf-8"))
evidence_doc = json.loads(evidence_path.read_text(encoding="utf-8"))
regulated_doc = json.loads(regulated_report_path.read_text(encoding="utf-8"))

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

evidence_manifest_sha = str(
    evidence_doc.get("release_manifest_sha256")
    or evidence_doc.get("approval", {}).get("release_manifest_sha256")
    or ""
)
if evidence_manifest_sha != release_manifest_sha256:
    raise SystemExit(
        "release signing evidence does not match apolysis-release-manifest.json sha256"
    )

provider = str(
    evidence_doc.get("provider")
    or evidence_doc.get("approval", {}).get("provider")
    or regulated_doc.get("selected_signing_provider")
    or ""
)
if not provider:
    raise SystemExit("release signing evidence is missing provider")

doc = {
    "schema_version": 1,
    "release_version": release_version or release_doc.get("release_version", ""),
    "target": target or release_doc.get("target", ""),
    "release_signing_ready": True,
    "provider": provider,
    "release_manifest": release_manifest_path.name,
    "release_manifest_sha256": release_manifest_sha256,
    "regulated_release_signing_evidence_ready": bool(
        regulated_doc.get("signing_evidence_ready")
    ),
    "selected_signing_provider": regulated_doc.get("selected_signing_provider", ""),
    "artifacts": {
        "signing_evidence": {
            "path": evidence_path.name,
            "sha256": sha256(evidence_path),
        },
        "signing_report": {
            "path": report_path.name,
            "sha256": sha256(report_path),
        },
        "regulated_release_report": {
            "path": regulated_report_path.name,
            "sha256": sha256(regulated_report_path),
        },
    },
    "notes": [
        "No secret values are recorded in this manifest.",
        "Apolysis release signing reuses retained regulated-release/F6 signing evidence.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}
manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf 'apolysis-release-signing: signing manifest=%s\n' "$signing_manifest"
printf 'apolysis-release-signing: evidence=%s\n' "$release_signing_evidence"
printf 'apolysis-release-signing: report=%s\n' "$release_signing_report"
printf 'apolysis-release-signing: regulated-report=%s\n' "$regulated_report"

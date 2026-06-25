#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-retained-evidence-package.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-retained-evidence-package-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-regulated_release: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$output_dir" "$report" "$require_ready" <<'PY'
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

output_dir = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

def env_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return ""

def load_json(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def normalize_sha(value: str) -> str:
    value = value.strip()
    if value.startswith("sha256:"):
        value = value.removeprefix("sha256:")
    return value.split()[0] if value else ""

def first_sha_from_file(path: Path | None) -> str:
    if path is None or not path.is_file():
        return ""
    return normalize_sha(path.read_text(encoding="utf-8", errors="replace"))

def copy_required(source: Path, destination: Path) -> bool:
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination.is_file()

source_report_value = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_REPORT")
source_manifest_value = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_MANIFEST")
source_archive_value = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_ARCHIVE")
source_sha_value = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_SHA256")
retention_root_value = env_value("APOLYSIS_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE_ROOT")

source_report = Path(source_report_value) if source_report_value else None
source_report_doc = load_json(source_report)

source_manifest = Path(source_manifest_value) if source_manifest_value else None
if source_manifest is None and isinstance(source_report_doc.get("manifest"), str) and source_report_doc.get("manifest"):
    source_manifest = Path(source_report_doc["manifest"])
source_manifest_doc = load_json(source_manifest)

source_archive = Path(source_archive_value) if source_archive_value else None
if source_archive is None and isinstance(source_report_doc.get("archive"), str) and source_report_doc.get("archive"):
    source_archive = Path(source_report_doc["archive"])
if source_archive is None and isinstance(source_manifest_doc.get("archive"), str) and source_manifest_doc.get("archive"):
    source_archive = Path(source_manifest_doc["archive"])

source_sha_file = Path(source_sha_value) if source_sha_value else None
if source_sha_file is None and source_archive is not None:
    candidate = Path(str(source_archive) + ".sha256")
    source_sha_file = candidate if candidate.is_file() else None

missing_requirements: list[str] = []
if source_report is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_REPORT")
elif not source_report.is_file():
    missing_requirements.append("evidence_package_report")

if source_manifest is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_MANIFEST")
elif not source_manifest.is_file():
    missing_requirements.append("evidence_package_manifest")

if source_archive is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_ARCHIVE")
elif not source_archive.is_file():
    missing_requirements.append("evidence_package_archive")

if source_sha_file is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_SHA256")
elif not source_sha_file.is_file():
    missing_requirements.append("evidence_package_sha256")

if not retention_root_value:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE_ROOT")

evidence_package_ready = source_report_doc.get("evidence_package_ready") is True
if source_report is not None and source_report.is_file() and not evidence_package_ready:
    missing_requirements.append("source_evidence_package_ready")

report_secret_findings = source_report_doc.get("secret_scan_findings") or []
manifest_secret_findings = (
    source_manifest_doc.get("secret_scan", {}).get("findings")
    if isinstance(source_manifest_doc.get("secret_scan"), dict)
    else []
)
if report_secret_findings or manifest_secret_findings:
    missing_requirements.append("source_evidence_package_has_no_secret_findings")

required_entry_count = int(source_report_doc.get("required_entry_count") or 0)
packaged_entry_count = int(source_report_doc.get("packaged_entry_count") or 0)
if source_report is not None and source_report.is_file() and (
    required_entry_count != 4 or packaged_entry_count != required_entry_count
):
    missing_requirements.append("source_evidence_package_entry_count")

archive_sha = sha256_file(source_archive) if source_archive is not None and source_archive.is_file() else ""
report_archive_sha = normalize_sha(str(source_report_doc.get("archive_sha256", "")))
manifest_archive_sha = normalize_sha(str(source_manifest_doc.get("archive_sha256", "")))
sidecar_archive_sha = first_sha_from_file(source_sha_file)

for label, expected in {
    "report_archive_sha256": report_archive_sha,
    "manifest_archive_sha256": manifest_archive_sha,
    "sidecar_archive_sha256": sidecar_archive_sha,
}.items():
    if archive_sha and expected and expected != archive_sha:
        missing_requirements.append(label)
    elif archive_sha and not expected:
        missing_requirements.append(label)

retention_provider = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_RETENTION_PROVIDER") or "local_filesystem"
retention_mode = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_RETENTION_MODE") or "local_copy"
retention_uri = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_RETENTION_URI")
retention_control_plane = env_value("APOLYSIS_REGULATED_RELEASE_EVIDENCE_RETENTION_CONTROL_PLANE")

retention_root = Path(retention_root_value) if retention_root_value else None
raw_package_id = source_manifest_doc.get("package_id") or source_report_doc.get("package_id") or "regulated-release-evidence-package"
package_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(raw_package_id)) or "regulated-release-evidence-package"
retained_dir = retention_root / str(package_id) if retention_root is not None else output_dir / "retained-package"
retained_archive = retained_dir / "apolysis-regulated-release-evidence-package.tar.gz"
retained_sha = retained_dir / "apolysis-regulated-release-evidence-package.tar.gz.sha256"
retained_report = retained_dir / "apolysis-regulated-release-evidence-package-report.json"
retained_manifest = retained_dir / "apolysis-regulated-release-evidence-package-manifest.json"
retention_manifest = retained_dir / "apolysis-regulated-release-retained-evidence-package-manifest.json"

retained_secret_findings: list[dict] = []
retained_files: list[dict] = []
retention_copy_completed = False

if retention_root is not None and not missing_requirements:
    retained_dir.mkdir(parents=True, exist_ok=True)
    copied = [
        copy_required(source_archive, retained_archive),
        copy_required(source_sha_file, retained_sha),
        copy_required(source_report, retained_report),
        copy_required(source_manifest, retained_manifest),
    ]
    retention_copy_completed = all(copied)
    if not retention_copy_completed:
        missing_requirements.append("retained_evidence_package_copy")

    retained_archive_sha = sha256_file(retained_archive) if retained_archive.is_file() else ""
    if retained_archive_sha != archive_sha:
        missing_requirements.append("retained_archive_sha256")

    retained_sidecar_sha = first_sha_from_file(retained_sha)
    if retained_sidecar_sha != archive_sha:
        missing_requirements.append("retained_archive_sha256_sidecar")

    generated_at_unix_ms = int(time.time() * 1000)
    retention_doc = {
        "schema_version": 1,
        "phase": "regulated-release.retained-evidence-package",
        "package_id": package_id,
        "source": "regulated_release_retained_evidence_package",
        "retention_provider": retention_provider,
        "retention_mode": retention_mode,
        "retention_uri": retention_uri or f"file://{retained_dir}",
        "retention_control_plane": retention_control_plane,
        "source_archive_sha256": f"sha256:{archive_sha}",
        "retained_archive": str(retained_archive),
        "retained_archive_sha256": f"sha256:{retained_archive_sha}" if retained_archive_sha else "",
        "retained_report": str(retained_report),
        "retained_manifest": str(retained_manifest),
        "retained_sha256": str(retained_sha),
        "generated_at_unix_ms": generated_at_unix_ms,
    }
    retention_manifest.write_text(json.dumps(retention_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for path in [retained_archive, retained_sha, retained_report, retained_manifest, retention_manifest]:
        retained_files.append(
            {
                "path": str(path),
                "sha256": f"sha256:{sha256_file(path)}" if path.is_file() else "",
            }
        )

    secret_patterns = [
        ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        (
            "aws_secret_access_key_value",
            re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{20,}"),
        ),
        (
            "aws_session_token_value",
            re.compile(r"(?i)\baws_session_token\b\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{20,}"),
        ),
        ("generic_secret_value", re.compile(r"(?i)[\"'](?:secret|token|password)[\"']\s*:\s*[\"'][^\"']{8,}")),
        ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ]
    for path in [retained_sha, retained_report, retained_manifest, retention_manifest]:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern_name, pattern in secret_patterns:
            if pattern.search(text):
                retained_secret_findings.append({"pattern": pattern_name, "artifact": str(path)})

if retained_secret_findings:
    missing_requirements.append("no_secret_material_in_retained_evidence_package")

retained_evidence_package_ready = (
    not missing_requirements
    and evidence_package_ready
    and retention_copy_completed
    and bool(archive_sha)
    and retained_archive.is_file()
    and retained_report.is_file()
    and retained_manifest.is_file()
    and retained_sha.is_file()
    and retention_manifest.is_file()
    and not retained_secret_findings
)
passed = retained_evidence_package_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "regulated-release.retained-evidence-package",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "retained_evidence_package_ready": retained_evidence_package_ready,
    "evidence_package_ready": evidence_package_ready,
    "retention_provider": retention_provider,
    "retention_mode": retention_mode,
    "retention_uri": retention_uri or (f"file://{retained_dir}" if retention_copy_completed else ""),
    "retention_control_plane": retention_control_plane,
    "source_report": str(source_report) if source_report is not None else "",
    "source_manifest": str(source_manifest) if source_manifest is not None else "",
    "source_archive": str(source_archive) if source_archive is not None else "",
    "source_archive_sha256": f"sha256:{archive_sha}" if archive_sha else "",
    "retained_directory": str(retained_dir) if retention_copy_completed else "",
    "retention_manifest": str(retention_manifest) if retention_manifest.is_file() else "",
    "retained_files": retained_files,
    "secret_scan_findings": retained_secret_findings,
    "missing_requirements": [] if retained_evidence_package_ready else list(dict.fromkeys(missing_requirements)),
    "notes": [
        "No secret values are recorded in this report.",
        "The regulated-release.retained-evidence-package gate validates a previously generated regulated-release.evidence-package evidence package before copying it into a retained package directory.",
        "The default retention provider is local_filesystem; external WORM or object-lock metadata can be supplied with APOLYSIS_REGULATED_RELEASE_EVIDENCE_RETENTION_* variables.",
        "The retained package archive and manifests are generated under target/ or the configured retention root and are not intended to be committed.",
    ],
    "next_commands": {
        "audit": "./scripts/test-regulated-release-retained-evidence-package.sh",
        "required_local_retention": "APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_REPORT=<package-report> APOLYSIS_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE_ROOT=<retention-root> APOLYSIS_REQUIRE_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE=1 ./scripts/test-regulated-release-retained-evidence-package.sh",
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not retained_evidence_package_ready:
    print(f"apolysis-regulated_release: retained evidence package failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: retained evidence package audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE_REPORT=$report
EOF

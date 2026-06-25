#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F6_EXTERNAL_RETENTION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f6-external-retention.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f6-external-retention-report.json"
require_ready="${APOLYSIS_REQUIRE_F6_EXTERNAL_RETENTION:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f6: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$output_dir" "$report" "$require_ready" <<'PY'
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

output_dir = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

manifest_path = output_dir / "apolysis-f6-external-retention-manifest.json"

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

def first_text_value(doc: dict, *keys: str) -> str:
    for key in keys:
        value = doc.get(key, "")
        if isinstance(value, str) and value:
            return value
    return ""

def parse_time(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

retained_report_value = env_value("APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_REPORT")
external_evidence_value = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_EVIDENCE")

retained_report = Path(retained_report_value) if retained_report_value else None
external_evidence = Path(external_evidence_value) if external_evidence_value else None

retained_doc = load_json(retained_report)
external_doc = load_json(external_evidence)

missing_requirements: list[str] = []
if retained_report is None:
    missing_requirements.append("APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_REPORT")
elif not retained_report.is_file():
    missing_requirements.append("retained_evidence_package_report")

if external_evidence is not None and not external_evidence.is_file():
    missing_requirements.append("external_retention_evidence")

retained_ready = retained_doc.get("retained_evidence_package_ready") is True
if retained_report is not None and retained_report.is_file() and not retained_ready:
    missing_requirements.append("retained_evidence_package_ready")

retained_secret_findings = retained_doc.get("secret_scan_findings") or []
if retained_secret_findings:
    missing_requirements.append("retained_evidence_package_has_no_secret_findings")

source_archive_sha = normalize_sha(str(retained_doc.get("source_archive_sha256", "")))
retained_files = retained_doc.get("retained_files") if isinstance(retained_doc.get("retained_files"), list) else []
retained_archive_sha = ""
for entry in retained_files:
    path_value = str(entry.get("path", "")) if isinstance(entry, dict) else ""
    sha_value = normalize_sha(str(entry.get("sha256", ""))) if isinstance(entry, dict) else ""
    if path_value.endswith("apolysis-f6-evidence-package.tar.gz"):
        retained_archive_sha = sha_value
        break

if source_archive_sha and retained_archive_sha and retained_archive_sha != source_archive_sha:
    missing_requirements.append("retained_archive_sha256")
elif not source_archive_sha:
    missing_requirements.append("source_archive_sha256")
elif not retained_archive_sha:
    missing_requirements.append("retained_archive_sha256")

provider = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_PROVIDER") or first_text_value(
    external_doc, "provider", "retention_provider"
)
retention_mode = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_MODE") or first_text_value(
    external_doc, "retention_mode", "object_lock_mode"
)
object_uri = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_URI") or first_text_value(
    external_doc, "object_uri", "retention_uri", "archive_uri"
)
object_version_id = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_VERSION_ID") or first_text_value(
    external_doc, "object_version_id", "version_id", "generation"
)
retention_until = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_UNTIL") or first_text_value(
    external_doc, "retention_until", "retain_until", "retain_until_date"
)
control_plane = env_value("APOLYSIS_F6_EXTERNAL_RETENTION_CONTROL_PLANE") or first_text_value(
    external_doc, "provider_control_plane", "retention_control_plane", "bucket_uri"
)
archive_sha = normalize_sha(
    env_value("APOLYSIS_F6_EXTERNAL_RETENTION_ARCHIVE_SHA256")
    or first_text_value(external_doc, "archive_sha256", "source_archive_sha256", "object_sha256")
)
observed_at = external_doc.get("observed_at_unix_ms") if isinstance(external_doc, dict) else None

allowed_provider_tokens = (
    "object_lock",
    "worm",
    "immutable",
    "bucket_lock",
    "s3",
    "r2",
    "gcs",
    "azure",
)
local_provider_tokens = ("local", "filesystem", "file")
provider_lower = provider.lower()
if not provider:
    missing_requirements.append("external_retention_provider")
elif any(token in provider_lower for token in local_provider_tokens) and not any(
    token in provider_lower for token in ("object_lock", "worm", "immutable")
):
    missing_requirements.append("external_retention_provider_non_local")
elif not any(token in provider_lower for token in allowed_provider_tokens):
    missing_requirements.append("external_retention_provider_kind")

mode_lower = retention_mode.lower()
allowed_modes = {"compliance", "governance", "bucket_lock", "object_lock", "worm", "immutable", "legal_hold"}
if not retention_mode:
    missing_requirements.append("external_retention_mode")
elif mode_lower not in allowed_modes:
    missing_requirements.append("external_retention_mode_kind")

if not object_uri:
    missing_requirements.append("external_retention_uri")
elif object_uri.startswith("file://"):
    missing_requirements.append("external_retention_uri_non_file")
elif "://" not in object_uri:
    missing_requirements.append("external_retention_uri_scheme")

if not object_version_id:
    missing_requirements.append("external_retention_version_id")

retain_until_dt = parse_time(retention_until)
if retain_until_dt is None:
    missing_requirements.append("external_retention_until")
elif retain_until_dt <= datetime.now(timezone.utc):
    missing_requirements.append("external_retention_until_future")

if not control_plane:
    missing_requirements.append("external_retention_control_plane")

if not archive_sha:
    missing_requirements.append("external_retention_archive_sha256")
elif archive_sha != source_archive_sha:
    missing_requirements.append("external_retention_archive_sha256_match")

if observed_at is not None and (not isinstance(observed_at, int) or observed_at <= 0):
    missing_requirements.append("external_retention_observed_at_unix_ms")

generated_at_unix_ms = int(time.time() * 1000)
manifest = {
    "schema_version": 1,
    "phase": "F6.8",
    "source": "f6_external_retention",
    "provider": provider,
    "retention_mode": retention_mode,
    "object_uri": object_uri,
    "object_version_id": object_version_id,
    "retention_until": retention_until,
    "provider_control_plane": control_plane,
    "archive_sha256": f"sha256:{archive_sha}" if archive_sha else "",
    "retained_package_report": str(retained_report) if retained_report is not None else "",
    "external_retention_evidence": str(external_evidence) if external_evidence is not None else "",
    "generated_at_unix_ms": generated_at_unix_ms,
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

secret_findings: list[dict] = []
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
for path in [external_evidence, manifest_path]:
    if path is None or not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern_name, pattern in secret_patterns:
        if pattern.search(text):
            secret_findings.append({"pattern": pattern_name, "artifact": str(path)})

if secret_findings:
    missing_requirements.append("no_secret_material_in_external_retention_metadata")

external_retention_ready = (
    not missing_requirements
    and retained_ready
    and bool(source_archive_sha)
    and archive_sha == source_archive_sha
    and not secret_findings
)
passed = external_retention_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "F6.8",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "external_retention_ready": external_retention_ready,
    "retained_evidence_package_ready": retained_ready,
    "provider": provider,
    "retention_mode": retention_mode,
    "object_uri": object_uri,
    "object_version_id": object_version_id,
    "retention_until": retention_until,
    "provider_control_plane": control_plane,
    "source_archive_sha256": f"sha256:{source_archive_sha}" if source_archive_sha else "",
    "external_archive_sha256": f"sha256:{archive_sha}" if archive_sha else "",
    "manifest": str(manifest_path),
    "external_retention_evidence": str(external_evidence) if external_evidence is not None else "",
    "secret_scan_findings": secret_findings,
    "missing_requirements": [] if external_retention_ready else list(dict.fromkeys(missing_requirements)),
    "notes": [
        "No secret values are recorded in this report.",
        "The F6.8 gate validates external WORM/object-lock retention metadata for an already retained F6 evidence package.",
        "This gate does not create cloud resources and does not call provider APIs; live provider readback can be layered on top of this metadata contract.",
        "The object URI must be non-file and the archive SHA-256 must match the retained evidence package source archive.",
    ],
    "next_commands": {
        "audit": "./scripts/test-f6-external-retention.sh",
        "required_metadata": "APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_REPORT=<retained-report> APOLYSIS_F6_EXTERNAL_RETENTION_EVIDENCE=<external-retention.json> APOLYSIS_REQUIRE_F6_EXTERNAL_RETENTION=1 ./scripts/test-f6-external-retention.sh",
    },
    "observed_at_unix_ms": generated_at_unix_ms,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not external_retention_ready:
    print(f"apolysis-f6: external retention failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-f6: external retention audit written ($output_dir)
APOLYSIS_F6_EXTERNAL_RETENTION_REPORT=$report
EOF

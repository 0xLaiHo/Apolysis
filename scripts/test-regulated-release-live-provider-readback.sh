#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_LIVE_PROVIDER_READBACK_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-live-provider-readback.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-live-provider-readback-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_LIVE_PROVIDER_READBACK:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-regulated_release: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$output_dir" "$report" "$require_ready" <<'PY'
import json
import os
import re
import sys
import time
from pathlib import Path

output_dir = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

manifest_path = output_dir / "apolysis-regulated-release-live-provider-readback-manifest.json"

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

def first_text_value(doc: dict, *keys: str) -> str:
    for key in keys:
        value = doc.get(key, "")
        if isinstance(value, str) and value:
            return value
    readback = doc.get("readback")
    if isinstance(readback, dict):
        for key in keys:
            value = readback.get(key, "")
            if isinstance(value, str) and value:
                return value
    provider = doc.get("provider")
    if isinstance(provider, dict):
        for key in keys:
            value = provider.get(key, "")
            if isinstance(value, str) and value:
                return value
    return ""

def first_bool_value(doc: dict, *keys: str) -> bool | None:
    for key in keys:
        value = doc.get(key)
        if isinstance(value, bool):
            return value
    readback = doc.get("readback")
    if isinstance(readback, dict):
        for key in keys:
            value = readback.get(key)
            if isinstance(value, bool):
                return value
    return None

def normalize_sha(value: str) -> str:
    value = value.strip()
    if value.startswith("sha256:"):
        value = value.removeprefix("sha256:")
    return value.split()[0].lower() if value else ""

def normalize_digest(value: str) -> str:
    value = value.strip()
    if value.startswith("sha256:"):
        return f"sha256:{value.removeprefix('sha256:').lower()}"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return f"sha256:{value.lower()}"
    return value

def bool_env(name: str) -> bool | None:
    value = os.environ.get(name, "")
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None

external_report_value = env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_REPORT")
registry_report_value = env_value(
    "APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION_REPORT",
    "APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_REPORT",
)
external_readback_value = env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_READBACK_EVIDENCE")
registry_readback_value = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_READBACK_EVIDENCE")

external_report_path = Path(external_report_value) if external_report_value else None
registry_report_path = Path(registry_report_value) if registry_report_value else None
external_readback_path = Path(external_readback_value) if external_readback_value else None
registry_readback_path = Path(registry_readback_value) if registry_readback_value else None

external_report_doc = load_json(external_report_path)
registry_report_doc = load_json(registry_report_path)
external_readback_doc = load_json(external_readback_path)
registry_readback_doc = load_json(registry_readback_path)

missing_requirements: list[str] = []

if external_report_path is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_REPORT")
elif not external_report_path.is_file():
    missing_requirements.append("external_retention_report")
elif external_report_doc.get("external_retention_ready") is not True:
    missing_requirements.append("external_retention_ready")

if registry_report_path is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION_REPORT")
elif not registry_report_path.is_file():
    missing_requirements.append("immutable_registry_report")
elif registry_report_doc.get("immutable_registry_ready") is not True:
    missing_requirements.append("immutable_registry_ready")

if external_readback_path is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_READBACK_EVIDENCE")
elif not external_readback_path.is_file():
    missing_requirements.append("external_retention_readback_evidence")

if registry_readback_path is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_READBACK_EVIDENCE")
elif not registry_readback_path.is_file():
    missing_requirements.append("immutable_registry_readback_evidence")

expected_external = {
    "provider": str(external_report_doc.get("provider", "")),
    "object_uri": str(external_report_doc.get("object_uri", "")),
    "object_version_id": str(external_report_doc.get("object_version_id", "")),
    "archive_sha256": normalize_sha(
        str(external_report_doc.get("external_archive_sha256") or external_report_doc.get("source_archive_sha256") or "")
    ),
    "retention_mode": str(external_report_doc.get("retention_mode", "")),
    "retention_until": str(external_report_doc.get("retention_until", "")),
    "provider_control_plane": str(external_report_doc.get("provider_control_plane", "")),
}
external_readback = {
    "provider": env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_PROVIDER")
    or first_text_value(external_readback_doc, "provider", "retention_provider"),
    "object_uri": env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_URI")
    or first_text_value(external_readback_doc, "object_uri", "retention_uri", "archive_uri"),
    "object_version_id": env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_VERSION_ID")
    or first_text_value(external_readback_doc, "object_version_id", "version_id", "generation"),
    "archive_sha256": normalize_sha(
        env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_ARCHIVE_SHA256")
        or first_text_value(external_readback_doc, "archive_sha256", "object_sha256", "readback_sha256")
    ),
    "retention_mode": env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_RETENTION_MODE")
    or first_text_value(external_readback_doc, "retention_mode", "object_lock_mode"),
    "retention_until": env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_RETENTION_UNTIL")
    or first_text_value(external_readback_doc, "retention_until", "retain_until", "retain_until_date"),
    "provider_control_plane": env_value("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_CONTROL_PLANE")
    or first_text_value(external_readback_doc, "provider_control_plane", "retention_control_plane", "bucket_uri"),
}
external_readback_verified = bool_env("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_VERIFIED")
if external_readback_verified is None:
    external_readback_verified = first_bool_value(
        external_readback_doc, "readback_verified", "object_readback_verified"
    )
external_policy_verified = bool_env("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_RETENTION_VERIFIED")
if external_policy_verified is None:
    external_policy_verified = first_bool_value(
        external_readback_doc, "retention_policy_verified", "object_lock_verified", "metadata_readback_verified"
    )
external_delete_denied = bool_env("APOLYSIS_REGULATED_RELEASE_EXTERNAL_READBACK_DELETE_DENIED")
if external_delete_denied is None:
    external_delete_denied = first_bool_value(
        external_readback_doc, "delete_denied", "delete_without_bypass_denied", "delete_protection_verified"
    )
external_observed_at = external_readback_doc.get("observed_at_unix_ms") if isinstance(external_readback_doc, dict) else None
external_source = first_text_value(external_readback_doc, "source")

if external_readback_path is not None and external_readback_path.is_file():
    if external_source and external_source not in {"live_provider_readback", "provider_api_readback", "retained_live_provider_readback"}:
        missing_requirements.append("external_readback_source")
    if external_readback["provider"] != expected_external["provider"]:
        missing_requirements.append("external_readback_provider_match")
    if external_readback["object_uri"] != expected_external["object_uri"]:
        missing_requirements.append("external_readback_object_uri_match")
    if external_readback["object_version_id"] != expected_external["object_version_id"]:
        missing_requirements.append("external_readback_version_id_match")
    if external_readback["archive_sha256"] != expected_external["archive_sha256"]:
        missing_requirements.append("external_readback_archive_sha256_match")
    if external_readback["retention_mode"] != expected_external["retention_mode"]:
        missing_requirements.append("external_readback_retention_mode_match")
    if external_readback["retention_until"] != expected_external["retention_until"]:
        missing_requirements.append("external_readback_retention_until_match")
    if external_readback["provider_control_plane"] != expected_external["provider_control_plane"]:
        missing_requirements.append("external_readback_control_plane_match")
    if external_readback_verified is not True:
        missing_requirements.append("external_readback_verified")
    if external_policy_verified is not True:
        missing_requirements.append("external_readback_retention_policy_verified")
    if external_delete_denied is not True:
        missing_requirements.append("external_readback_delete_denied")
    if external_observed_at is not None and (not isinstance(external_observed_at, int) or external_observed_at <= 0):
        missing_requirements.append("external_readback_observed_at_unix_ms")

expected_registry = {
    "provider": str(registry_report_doc.get("provider", "")),
    "registry_uri": str(registry_report_doc.get("registry_uri", "")),
    "image_ref": str(registry_report_doc.get("image_ref", "")),
    "image_digest": normalize_digest(str(registry_report_doc.get("image_digest", ""))),
    "policy_id": str(registry_report_doc.get("policy_id", "")),
    "provider_control_plane": str(registry_report_doc.get("provider_control_plane", "")),
}
registry_readback = {
    "provider": env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_PROVIDER")
    or first_text_value(registry_readback_doc, "provider", "registry_provider"),
    "registry_uri": env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_URI")
    or first_text_value(registry_readback_doc, "registry_uri", "repository_uri", "registry"),
    "image_ref": env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_IMAGE_REF")
    or first_text_value(registry_readback_doc, "image_ref", "image", "artifact_ref"),
    "image_digest": normalize_digest(
        env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_IMAGE_DIGEST")
        or first_text_value(registry_readback_doc, "image_digest", "digest", "manifest_digest", "resolved_digest")
    ),
    "policy_id": env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_POLICY_ID")
    or first_text_value(registry_readback_doc, "policy_id", "immutability_policy_id", "retention_policy_id"),
    "provider_control_plane": env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_CONTROL_PLANE")
    or first_text_value(registry_readback_doc, "provider_control_plane", "registry_control_plane", "control_plane"),
}
registry_digest_verified = bool_env("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_DIGEST_VERIFIED")
if registry_digest_verified is None:
    registry_digest_verified = first_bool_value(
        registry_readback_doc, "digest_readback_verified", "manifest_digest_verified", "image_digest_verified"
    )
registry_policy_verified = bool_env("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_IMMUTABILITY_VERIFIED")
if registry_policy_verified is None:
    registry_policy_verified = first_bool_value(
        registry_readback_doc, "immutability_policy_verified", "immutable_policy_verified", "policy_readback_verified"
    )
registry_mutation_denied = bool_env("APOLYSIS_REGULATED_RELEASE_REGISTRY_READBACK_MUTATION_DENIED")
if registry_mutation_denied is None:
    registry_mutation_denied = first_bool_value(
        registry_readback_doc, "mutation_denied", "tag_mutation_denied", "write_protection_verified"
    )
registry_observed_at = registry_readback_doc.get("observed_at_unix_ms") if isinstance(registry_readback_doc, dict) else None
registry_source = first_text_value(registry_readback_doc, "source")

if registry_readback_path is not None and registry_readback_path.is_file():
    if registry_source and registry_source not in {"live_provider_readback", "provider_api_readback", "retained_live_provider_readback"}:
        missing_requirements.append("registry_readback_source")
    if registry_readback["provider"] != expected_registry["provider"]:
        missing_requirements.append("registry_readback_provider_match")
    if registry_readback["registry_uri"] != expected_registry["registry_uri"]:
        missing_requirements.append("registry_readback_uri_match")
    if registry_readback["image_ref"] != expected_registry["image_ref"]:
        missing_requirements.append("registry_readback_image_ref_match")
    if registry_readback["image_digest"] != expected_registry["image_digest"]:
        missing_requirements.append("registry_readback_image_digest_match")
    if registry_readback["policy_id"] != expected_registry["policy_id"]:
        missing_requirements.append("registry_readback_policy_id_match")
    if registry_readback["provider_control_plane"] != expected_registry["provider_control_plane"]:
        missing_requirements.append("registry_readback_control_plane_match")
    if registry_digest_verified is not True:
        missing_requirements.append("registry_readback_digest_verified")
    if registry_policy_verified is not True:
        missing_requirements.append("registry_readback_immutability_verified")
    if registry_mutation_denied is not True:
        missing_requirements.append("registry_readback_mutation_denied")
    if registry_observed_at is not None and (not isinstance(registry_observed_at, int) or registry_observed_at <= 0):
        missing_requirements.append("registry_readback_observed_at_unix_ms")

generated_at_unix_ms = int(time.time() * 1000)
manifest = {
    "schema_version": 1,
    "phase": "regulated-release.live-provider-readback",
    "source": "regulated_release_live_provider_readback",
    "external_retention": {
        "report": str(external_report_path) if external_report_path is not None else "",
        "readback_evidence": str(external_readback_path) if external_readback_path is not None else "",
        "expected": expected_external,
        "observed": external_readback,
    },
    "immutable_registry": {
        "report": str(registry_report_path) if registry_report_path is not None else "",
        "readback_evidence": str(registry_readback_path) if registry_readback_path is not None else "",
        "expected": expected_registry,
        "observed": registry_readback,
    },
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
for path in [external_readback_path, registry_readback_path, manifest_path]:
    if path is None or not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern_name, pattern in secret_patterns:
        if pattern.search(text):
            secret_findings.append({"pattern": pattern_name, "artifact": str(path)})

if secret_findings:
    missing_requirements.append("no_secret_material_in_live_provider_readback")

external_readback_ready = (
    external_report_doc.get("external_retention_ready") is True
    and external_readback_path is not None
    and external_readback_path.is_file()
    and external_readback_verified is True
    and external_policy_verified is True
    and external_delete_denied is True
    and "external_readback_provider_match" not in missing_requirements
    and "external_readback_object_uri_match" not in missing_requirements
    and "external_readback_version_id_match" not in missing_requirements
    and "external_readback_archive_sha256_match" not in missing_requirements
    and "external_readback_retention_mode_match" not in missing_requirements
    and "external_readback_retention_until_match" not in missing_requirements
    and "external_readback_control_plane_match" not in missing_requirements
)
registry_readback_ready = (
    registry_report_doc.get("immutable_registry_ready") is True
    and registry_readback_path is not None
    and registry_readback_path.is_file()
    and registry_digest_verified is True
    and registry_policy_verified is True
    and registry_mutation_denied is True
    and "registry_readback_provider_match" not in missing_requirements
    and "registry_readback_uri_match" not in missing_requirements
    and "registry_readback_image_ref_match" not in missing_requirements
    and "registry_readback_image_digest_match" not in missing_requirements
    and "registry_readback_policy_id_match" not in missing_requirements
    and "registry_readback_control_plane_match" not in missing_requirements
)
live_provider_readback_ready = (
    external_readback_ready
    and registry_readback_ready
    and not secret_findings
    and not missing_requirements
)
passed = live_provider_readback_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "regulated-release.live-provider-readback",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "live_provider_readback_ready": live_provider_readback_ready,
    "external_retention_readback_ready": external_readback_ready,
    "immutable_registry_readback_ready": registry_readback_ready,
    "external_retention": {
        "provider": external_readback["provider"],
        "object_uri": external_readback["object_uri"],
        "object_version_id": external_readback["object_version_id"],
        "archive_sha256": f"sha256:{external_readback['archive_sha256']}" if external_readback["archive_sha256"] else "",
        "readback_verified": external_readback_verified is True,
        "retention_policy_verified": external_policy_verified is True,
        "delete_denied": external_delete_denied is True,
    },
    "immutable_registry": {
        "provider": registry_readback["provider"],
        "registry_uri": registry_readback["registry_uri"],
        "image_ref": registry_readback["image_ref"],
        "image_digest": registry_readback["image_digest"],
        "digest_readback_verified": registry_digest_verified is True,
        "immutability_policy_verified": registry_policy_verified is True,
        "mutation_denied": registry_mutation_denied is True,
    },
    "manifest": str(manifest_path),
    "external_retention_report": str(external_report_path) if external_report_path is not None else "",
    "immutable_registry_report": str(registry_report_path) if registry_report_path is not None else "",
    "external_retention_readback_evidence": str(external_readback_path) if external_readback_path is not None else "",
    "immutable_registry_readback_evidence": str(registry_readback_path) if registry_readback_path is not None else "",
    "secret_scan_findings": secret_findings,
    "missing_requirements": [] if live_provider_readback_ready else list(dict.fromkeys(missing_requirements)),
    "notes": [
        "No secret values are recorded in this report.",
        "The regulated-release.live-provider-readback gate validates retained provider-side readback evidence for external retention and immutable registry controls.",
        "This gate does not call provider APIs; it verifies explicit readback evidence captured by an operator or provider workflow.",
        "Required mode fails closed unless both external retention and immutable registry readback evidence match the RegulatedRelease reports.",
    ],
    "next_commands": {
        "audit": "./scripts/test-regulated-release-live-provider-readback.sh",
        "required_metadata": "APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_REPORT=<external-retention-report> APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION_REPORT=<immutable-registry-report> APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_READBACK_EVIDENCE=<external-readback.json> APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_READBACK_EVIDENCE=<registry-readback.json> APOLYSIS_REQUIRE_REGULATED_RELEASE_LIVE_PROVIDER_READBACK=1 ./scripts/test-regulated-release-live-provider-readback.sh",
    },
    "observed_at_unix_ms": generated_at_unix_ms,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not live_provider_readback_ready:
    print(f"apolysis-regulated_release: live provider readback failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: live provider readback audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_LIVE_PROVIDER_READBACK_REPORT=$report
EOF

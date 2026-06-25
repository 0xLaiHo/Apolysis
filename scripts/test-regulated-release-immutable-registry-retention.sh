#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-immutable-registry-retention.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-immutable-registry-retention-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION:-0}"

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
from datetime import datetime, timezone
from pathlib import Path

output_dir = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

manifest_path = output_dir / "apolysis-regulated-release-immutable-registry-retention-manifest.json"

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
    policy = doc.get("policy")
    if isinstance(policy, dict):
        for key in keys:
            value = policy.get(key, "")
            if isinstance(value, str) and value:
                return value
    return ""

def first_bool_value(doc: dict, *keys: str) -> bool | None:
    for key in keys:
        value = doc.get(key)
        if isinstance(value, bool):
            return value
    policy = doc.get("policy")
    if isinstance(policy, dict):
        for key in keys:
            value = policy.get(key)
            if isinstance(value, bool):
                return value
    return None

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

def normalize_digest(value: str) -> str:
    value = value.strip()
    if value.startswith("sha256:"):
        return value
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return f"sha256:{value.lower()}"
    return value

evidence_value = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_EVIDENCE")
evidence_path = Path(evidence_value) if evidence_value else None
evidence_doc = load_json(evidence_path)

missing_requirements: list[str] = []
if evidence_path is not None and not evidence_path.is_file():
    missing_requirements.append("immutable_registry_evidence")

provider = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_PROVIDER") or first_text_value(
    evidence_doc, "provider", "registry_provider"
)
registry_uri = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_URI") or first_text_value(
    evidence_doc, "registry_uri", "repository_uri", "registry"
)
image_ref = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_IMAGE_REF") or first_text_value(
    evidence_doc, "image_ref", "image", "artifact_ref"
)
image_digest = normalize_digest(
    env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_IMAGE_DIGEST")
    or first_text_value(evidence_doc, "image_digest", "digest", "manifest_digest")
)
policy_id = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_POLICY_ID") or first_text_value(
    evidence_doc, "policy_id", "retention_policy_id", "immutability_policy_id"
)
immutability_mode = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_MODE") or first_text_value(
    evidence_doc, "immutability_mode", "retention_mode", "policy_mode"
)
control_plane = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_CONTROL_PLANE") or first_text_value(
    evidence_doc, "provider_control_plane", "registry_control_plane", "control_plane"
)
retention_until = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION_UNTIL") or first_text_value(
    evidence_doc, "retention_until", "retain_until", "retain_until_date"
)
observed_at = evidence_doc.get("observed_at_unix_ms") if isinstance(evidence_doc, dict) else None

enabled_value = env_value("APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_ENABLED")
if enabled_value:
    immutability_enabled = enabled_value.lower() in {"1", "true", "yes", "on"}
else:
    bool_value = first_bool_value(evidence_doc, "immutability_enabled", "immutable_tags", "retention_enabled")
    immutability_enabled = bool_value if bool_value is not None else False

provider_lower = provider.lower()
allowed_provider_tokens = (
    "docker_hub",
    "dockerhub",
    "ecr",
    "ghcr",
    "gcr",
    "artifact_registry",
    "acr",
    "azure",
    "harbor",
    "quay",
    "registry",
    "immutable",
)
local_provider_tokens = ("local", "filesystem", "file")
if not provider:
    missing_requirements.append("immutable_registry_provider")
elif any(token in provider_lower for token in local_provider_tokens):
    missing_requirements.append("immutable_registry_provider_non_local")
elif not any(token in provider_lower for token in allowed_provider_tokens):
    missing_requirements.append("immutable_registry_provider_kind")

registry_uri_lower = registry_uri.lower()
if not registry_uri:
    missing_requirements.append("immutable_registry_uri")
elif registry_uri_lower.startswith("file://"):
    missing_requirements.append("immutable_registry_uri_non_file")
elif (
    registry_uri_lower.startswith(("localhost", "127.", "0.0.0.0"))
    or "://localhost" in registry_uri_lower
    or "://127." in registry_uri_lower
    or "://0.0.0.0" in registry_uri_lower
):
    missing_requirements.append("immutable_registry_uri_non_local")
elif "://" not in registry_uri and "." not in registry_uri and "/" not in registry_uri:
    missing_requirements.append("immutable_registry_uri_shape")

digest_pattern = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
if not image_digest:
    missing_requirements.append("immutable_registry_image_digest")
elif not digest_pattern.fullmatch(image_digest):
    missing_requirements.append("immutable_registry_image_digest_sha256")

if not image_ref:
    missing_requirements.append("immutable_registry_image_ref")
else:
    if image_ref.endswith(":latest") or ":latest@" in image_ref:
        missing_requirements.append("immutable_registry_image_ref_not_latest")
    if "@sha256:" in image_ref:
        ref_digest = normalize_digest(image_ref.rsplit("@", 1)[1])
        if image_digest and ref_digest != image_digest:
            missing_requirements.append("immutable_registry_image_ref_digest_match")

allowed_modes = {
    "immutable_tag",
    "immutable_tags",
    "tag_immutability",
    "digest_pinned",
    "retention_policy",
    "protected_tag",
    "immutable_repository",
    "repository_immutability",
}
mode_lower = immutability_mode.lower()
if not immutability_mode:
    missing_requirements.append("immutable_registry_mode")
elif mode_lower not in allowed_modes:
    missing_requirements.append("immutable_registry_mode_kind")

if not immutability_enabled:
    missing_requirements.append("immutable_registry_policy_enabled")

if not policy_id:
    missing_requirements.append("immutable_registry_policy_id")

if not control_plane:
    missing_requirements.append("immutable_registry_control_plane")

if retention_until:
    retention_dt = parse_time(retention_until)
    if retention_dt is None:
        missing_requirements.append("immutable_registry_retention_until")
    elif retention_dt <= datetime.now(timezone.utc):
        missing_requirements.append("immutable_registry_retention_until_future")

if observed_at is not None and (not isinstance(observed_at, int) or observed_at <= 0):
    missing_requirements.append("immutable_registry_observed_at_unix_ms")

generated_at_unix_ms = int(time.time() * 1000)
manifest = {
    "schema_version": 1,
    "phase": "regulated-release.immutable-registry-retention",
    "source": "regulated_release_immutable_registry_retention",
    "provider": provider,
    "registry_uri": registry_uri,
    "image_ref": image_ref,
    "image_digest": image_digest,
    "immutability_enabled": immutability_enabled,
    "immutability_mode": immutability_mode,
    "policy_id": policy_id,
    "retention_until": retention_until,
    "provider_control_plane": control_plane,
    "immutable_registry_evidence": str(evidence_path) if evidence_path is not None else "",
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
for path in [evidence_path, manifest_path]:
    if path is None or not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern_name, pattern in secret_patterns:
        if pattern.search(text):
            secret_findings.append({"pattern": pattern_name, "artifact": str(path)})

if secret_findings:
    missing_requirements.append("no_secret_material_in_immutable_registry_metadata")

immutable_registry_ready = (
    not missing_requirements
    and bool(provider)
    and bool(registry_uri)
    and bool(image_ref)
    and bool(image_digest)
    and immutability_enabled
    and bool(policy_id)
    and bool(control_plane)
    and not secret_findings
)
passed = immutable_registry_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "regulated-release.immutable-registry-retention",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "immutable_registry_ready": immutable_registry_ready,
    "provider": provider,
    "registry_uri": registry_uri,
    "image_ref": image_ref,
    "image_digest": image_digest,
    "immutability_enabled": immutability_enabled,
    "immutability_mode": immutability_mode,
    "policy_id": policy_id,
    "retention_until": retention_until,
    "provider_control_plane": control_plane,
    "manifest": str(manifest_path),
    "immutable_registry_evidence": str(evidence_path) if evidence_path is not None else "",
    "secret_scan_findings": secret_findings,
    "missing_requirements": [] if immutable_registry_ready else list(dict.fromkeys(missing_requirements)),
    "notes": [
        "No secret values are recorded in this report.",
        "The regulated-release.immutable-registry-retention gate validates immutable or retention-protected registry metadata for a digest-pinned release image.",
        "This gate does not call registry APIs; live registry readback can be layered on top of this metadata contract.",
        "The image reference must not use latest, and a digest in the image reference must match the supplied image digest.",
    ],
    "next_commands": {
        "audit": "./scripts/test-regulated-release-immutable-registry-retention.sh",
        "required_metadata": "APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_EVIDENCE=<immutable-registry.json> APOLYSIS_REQUIRE_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION=1 ./scripts/test-regulated-release-immutable-registry-retention.sh",
    },
    "observed_at_unix_ms": generated_at_unix_ms,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not immutable_registry_ready:
    print(f"apolysis-regulated_release: immutable registry retention failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: immutable registry retention audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_RETENTION_REPORT=$report
EOF

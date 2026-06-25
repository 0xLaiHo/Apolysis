#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F6_FINAL_RELEASE_SIGNOFF_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f6-final-release-signoff.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f6-final-release-signoff-report.json"
require_ready="${APOLYSIS_REQUIRE_F6_FINAL_RELEASE_SIGNOFF:-0}"

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
from pathlib import Path

output_dir = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

manifest_path = output_dir / "apolysis-f6-final-release-signoff-manifest.json"
generated_signoff_path = output_dir / "apolysis-f6-final-release-signoff.json"


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


def first_text_value(doc: dict, *keys: str) -> str:
    for key in keys:
        value = doc.get(key, "")
        if isinstance(value, str) and value:
            return value
    for section_name in ("signoff", "approval", "release_signoff"):
        section = doc.get(section_name)
        if isinstance(section, dict):
            for key in keys:
                value = section.get(key, "")
                if isinstance(value, str) and value:
                    return value
    return ""


def first_bool_value(doc: dict, *keys: str) -> bool | None:
    for key in keys:
        value = doc.get(key)
        if isinstance(value, bool):
            return value
    for section_name in ("signoff", "approval", "release_signoff"):
        section = doc.get(section_name)
        if isinstance(section, dict):
            for key in keys:
                value = section.get(key)
                if isinstance(value, bool):
                    return value
    return None


def bool_from_text(value: str) -> bool | None:
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None


def nested_list_values(doc: dict, key: str) -> list:
    values = []
    direct = doc.get(key)
    if isinstance(direct, list):
        values.extend(direct)
    steps = doc.get("steps")
    if isinstance(steps, dict):
        for step in steps.values():
            if isinstance(step, dict) and isinstance(step.get(key), list):
                values.extend(step[key])
    return values


source_report_value = env_value(
    "APOLYSIS_F6_REGULATED_RELEASE_SOURCE_REPORT",
    "APOLYSIS_F6_REGULATED_RELEASE_REPORT",
)
signoff_value = env_value(
    "APOLYSIS_F6_FINAL_RELEASE_SIGNOFF",
    "APOLYSIS_F6_FINAL_SIGNOFF_ARTIFACT",
)

source_report_path = Path(source_report_value) if source_report_value else None
provided_signoff_path = Path(signoff_value) if signoff_value else None
source_doc = load_json(source_report_path)

missing_requirements: list[str] = []
if source_report_path is None:
    missing_requirements.append("APOLYSIS_F6_REGULATED_RELEASE_REPORT")
elif not source_report_path.is_file():
    missing_requirements.append("regulated_release_source_report")

source_report_sha256 = sha256_file(source_report_path) if source_report_path is not None and source_report_path.is_file() else ""
source_phase = str(source_doc.get("phase", ""))
if source_report_path is not None and source_report_path.is_file():
    if source_phase not in {"F6.11", "F6.12"}:
        missing_requirements.append("regulated_release_source_phase")
    if source_doc.get("regulated_release_ready") is not True:
        missing_requirements.append("regulated_release_source_ready")
    if source_doc.get("passed") is not True:
        missing_requirements.append("regulated_release_source_passed")
    if source_doc.get("missing_requirements") not in ([], None):
        missing_requirements.append("regulated_release_source_missing_requirements_empty")

readiness_fields = [
    "provider_execution_plan_ready",
    "signing_evidence_ready",
    "provider_artifact_import_ready",
    "provider_workflow_artifact_import_ready",
    "bundle_env_ready",
    "final_provider_closure_ready",
    "evidence_package_ready",
    "retained_evidence_package_ready",
    "external_retention_ready",
    "immutable_registry_ready",
    "managed_mesh_decision_ready",
    "live_provider_readback_ready",
]
readiness_summary = {field: bool(source_doc.get(field)) for field in readiness_fields}
for field, ready in readiness_summary.items():
    if not ready and source_report_path is not None and source_report_path.is_file():
        missing_requirements.append(f"source_{field}")

run_final_provider_closure = bool(source_doc.get("run_final_provider_closure"))
completion_passed = bool(source_doc.get("completion_passed"))
if source_report_path is not None and source_report_path.is_file() and not run_final_provider_closure:
    missing_requirements.append("source_run_final_provider_closure")
if source_report_path is not None and source_report_path.is_file() and not completion_passed:
    missing_requirements.append("source_completion_passed")

source_secret_findings = nested_list_values(source_doc, "secret_scan_findings")
if source_secret_findings:
    missing_requirements.append("regulated_release_source_has_no_secret_findings")

signoff_doc: dict
if provided_signoff_path is not None:
    if not provided_signoff_path.is_file():
        missing_requirements.append("final_release_signoff_artifact")
    signoff_doc = load_json(provided_signoff_path)
    signoff_path = provided_signoff_path
else:
    approver = env_value("APOLYSIS_F6_FINAL_SIGNOFF_APPROVER", "APOLYSIS_F6_FINAL_RELEASE_APPROVER")
    decision = env_value("APOLYSIS_F6_FINAL_SIGNOFF_DECISION", "APOLYSIS_F6_FINAL_RELEASE_DECISION")
    rationale = env_value("APOLYSIS_F6_FINAL_SIGNOFF_RATIONALE", "APOLYSIS_F6_FINAL_RELEASE_RATIONALE")
    approved_at = env_value("APOLYSIS_F6_FINAL_SIGNOFF_APPROVED_AT", "APOLYSIS_F6_FINAL_RELEASE_APPROVED_AT")
    no_secret_material_recorded = bool_from_text(
        env_value(
            "APOLYSIS_F6_FINAL_SIGNOFF_NO_SECRET_MATERIAL_RECORDED",
            "APOLYSIS_F6_FINAL_RELEASE_NO_SECRET_MATERIAL_RECORDED",
        )
    )
    signoff_doc = {
        "schema_version": 1,
        "source": "generated_final_release_signoff",
        "phase": "F6.12",
        "release_scope": "regulated_release",
        "decision": decision,
        "approver": approver,
        "approved_at": approved_at,
        "rationale": rationale,
        "regulated_release_ready": source_doc.get("regulated_release_ready") is True,
        "source_regulated_release_report": str(source_report_path) if source_report_path is not None else "",
        "source_report_sha256": source_report_sha256,
        "readiness_summary": readiness_summary,
        "no_secret_material_recorded": no_secret_material_recorded,
        "missing_requirements": list(source_doc.get("missing_requirements") or []),
        "generated_at_unix_ms": int(time.time() * 1000),
    }
    generated_signoff_path.write_text(json.dumps(signoff_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    signoff_path = generated_signoff_path

source = first_text_value(signoff_doc, "source")
phase = first_text_value(signoff_doc, "phase")
release_scope = first_text_value(signoff_doc, "release_scope", "scope")
decision = first_text_value(signoff_doc, "decision", "final_decision")
approver = first_text_value(signoff_doc, "approver", "approved_by", "signer")
approved_at = first_text_value(signoff_doc, "approved_at", "signed_at")
if not approved_at and isinstance(signoff_doc.get("approved_at_unix_ms"), int):
    approved_at = str(signoff_doc["approved_at_unix_ms"])
rationale = first_text_value(signoff_doc, "rationale", "approval_rationale", "release_rationale")
artifact_source_sha = first_text_value(signoff_doc, "source_report_sha256", "regulated_release_report_sha256")
artifact_ready = first_bool_value(signoff_doc, "regulated_release_ready")
no_secret_material_recorded = first_bool_value(signoff_doc, "no_secret_material_recorded", "no_secrets_recorded")
artifact_missing_requirements = signoff_doc.get("missing_requirements")

allowed_sources = {
    "final_release_signoff",
    "operator_final_release_signoff",
    "retained_final_release_signoff",
    "generated_final_release_signoff",
}
if not source:
    missing_requirements.append("final_release_signoff_source")
elif source not in allowed_sources:
    missing_requirements.append("final_release_signoff_source_kind")

if phase and phase != "F6.12":
    missing_requirements.append("final_release_signoff_phase")
elif not phase:
    missing_requirements.append("final_release_signoff_phase")

if release_scope and release_scope not in {"regulated_release", "f6_regulated_release"}:
    missing_requirements.append("final_release_signoff_scope")
elif not release_scope:
    missing_requirements.append("final_release_signoff_scope")

if decision != "approve_regulated_release":
    missing_requirements.append("final_release_signoff_decision")
if not approver:
    missing_requirements.append("final_release_signoff_approver")
if not approved_at:
    missing_requirements.append("final_release_signoff_approved_at")
if not rationale or len(rationale.strip()) < 16:
    missing_requirements.append("final_release_signoff_rationale")
if artifact_ready is not True:
    missing_requirements.append("final_release_signoff_regulated_release_ready")
if no_secret_material_recorded is not True:
    missing_requirements.append("final_release_signoff_no_secret_material_recorded")
if artifact_missing_requirements not in ([], None):
    missing_requirements.append("final_release_signoff_missing_requirements_empty")
if not artifact_source_sha:
    missing_requirements.append("final_release_signoff_source_report_sha256")
elif source_report_sha256 and artifact_source_sha != source_report_sha256:
    missing_requirements.append("final_release_signoff_source_report_sha256_match")

artifact_readiness = signoff_doc.get("readiness_summary")
if isinstance(artifact_readiness, dict):
    for field, expected_ready in readiness_summary.items():
        if bool(artifact_readiness.get(field)) != expected_ready:
            missing_requirements.append(f"final_release_signoff_{field}_match")

generated_at_unix_ms = int(time.time() * 1000)
manifest = {
    "schema_version": 1,
    "phase": "F6.12",
    "source": "f6_final_release_signoff",
    "regulated_release_source_report": str(source_report_path) if source_report_path is not None else "",
    "regulated_release_source_sha256": source_report_sha256,
    "final_release_signoff": str(signoff_path),
    "decision": decision,
    "approver": approver,
    "approved_at": approved_at,
    "release_scope": release_scope,
    "readiness_summary": readiness_summary,
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
for path in [source_report_path, signoff_path, manifest_path]:
    if path is None or not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern_name, pattern in secret_patterns:
        if pattern.search(text):
            secret_findings.append({"pattern": pattern_name, "artifact": str(path)})

if secret_findings:
    missing_requirements.append("no_secret_material_in_final_release_signoff")

missing_requirements = list(dict.fromkeys(missing_requirements))
source_ready = (
    source_report_path is not None
    and source_report_path.is_file()
    and source_doc.get("regulated_release_ready") is True
    and source_doc.get("passed") is True
    and source_doc.get("missing_requirements") in ([], None)
    and all(readiness_summary.values())
    and run_final_provider_closure
    and completion_passed
    and not source_secret_findings
)
final_release_signoff_ready = (
    source_ready
    and not missing_requirements
    and decision == "approve_regulated_release"
    and bool(approver)
    and bool(approved_at)
    and bool(rationale)
    and artifact_ready is True
    and no_secret_material_recorded is True
    and artifact_source_sha == source_report_sha256
    and not secret_findings
)
passed = final_release_signoff_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "F6.12",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "final_release_signoff_ready": final_release_signoff_ready,
    "regulated_release_source_ready": source_ready,
    "source_phase": source_phase,
    "source_regulated_release_report": str(source_report_path) if source_report_path is not None else "",
    "source_report_sha256": source_report_sha256,
    "final_release_signoff": str(signoff_path),
    "manifest": str(manifest_path),
    "decision": decision,
    "approver": approver,
    "approved_at": approved_at,
    "release_scope": release_scope,
    "readiness_summary": readiness_summary,
    "secret_scan_findings": secret_findings,
    "missing_requirements": [] if final_release_signoff_ready else missing_requirements,
    "notes": [
        "No secret values are recorded in this report.",
        "F6.12 validates the final regulated-release sign-off artifact against the retained F6 aggregate evidence.",
        "Default audit mode writes a report without calling provider APIs.",
        "Required mode fails closed until the source aggregate is ready and the final sign-off artifact is complete.",
    ],
    "observed_at_unix_ms": generated_at_unix_ms,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not final_release_signoff_ready:
    print(f"apolysis-f6: final release sign-off failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-f6: final release sign-off audit written ($output_dir)
APOLYSIS_F6_FINAL_RELEASE_SIGNOFF_REPORT=$report
EOF

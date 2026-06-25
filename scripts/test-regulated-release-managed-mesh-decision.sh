#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_DECISION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-managed-mesh-decision.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-managed-mesh-decision-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_MANAGED_MESH_DECISION:-0}"

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

manifest_path = output_dir / "apolysis-regulated-release-managed-mesh-decision-manifest.json"

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
    approval = doc.get("approval")
    if isinstance(approval, dict):
        for key in keys:
            value = approval.get(key, "")
            if isinstance(value, str) and value:
                return value
    return ""

def first_bool_value(doc: dict, *keys: str) -> bool | None:
    for key in keys:
        value = doc.get(key)
        if isinstance(value, bool):
            return value
    approval = doc.get("approval")
    if isinstance(approval, dict):
        for key in keys:
            value = approval.get(key)
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

evidence_value = env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_EVIDENCE", "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE")
report_value = env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_REPORT", "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT")

evidence_path = Path(evidence_value) if evidence_value else None
mesh_report_path = Path(report_value) if report_value else None
evidence_doc = load_json(evidence_path)
mesh_report_doc = load_json(mesh_report_path)

missing_requirements: list[str] = []
if evidence_path is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_EVIDENCE")
elif not evidence_path.is_file():
    missing_requirements.append("managed_mesh_evidence")

if mesh_report_path is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_REPORT")
elif not mesh_report_path.is_file():
    missing_requirements.append("managed_mesh_report")

provider = env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_PROVIDER", "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_PROVIDER") or first_text_value(
    evidence_doc, "provider", "mesh_provider", "service_mesh_provider"
)
provider_control_plane = env_value(
    "APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_CONTROL_PLANE",
    "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_CONTROL_PLANE",
) or first_text_value(evidence_doc, "provider_control_plane", "mesh_uri", "cluster_name")
decision = env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_DECISION") or first_text_value(
    evidence_doc, "managed_mesh_decision", "decision"
)
rationale = env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_DECISION_RATIONALE") or first_text_value(
    evidence_doc, "decision_rationale", "rationale"
)
observed_at = evidence_doc.get("observed_at_unix_ms") if isinstance(evidence_doc, dict) else None

additional_required_value = env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_ADDITIONAL_PROVIDER_REQUIRED")
if additional_required_value:
    additional_provider_required = bool_from_text(additional_required_value)
else:
    additional_provider_required = first_bool_value(
        evidence_doc,
        "additional_provider_required",
        "additional_provider_specific_mesh_required",
    )
if additional_provider_required is None:
    additional_provider_required = False

accepted_providers = {
    "vultr_vke_istio",
    "gke_anthos_service_mesh",
    "aks_istio_addon",
    "eks_app_mesh",
    "openshift_service_mesh",
    "linkerd_buoyant_cloud",
    "consul_cloud",
}
accepted_decisions = {
    "accept_retained_provider_evidence",
    "accept_retained_vke_istio",
    "accept_managed_cloud_service_mesh",
}
local_provider_tokens = ("local", "fixture", "mock", "kind", "k3d", "minikube")

provider_lower = provider.lower()
if not provider:
    missing_requirements.append("managed_mesh_provider")
elif provider_lower not in accepted_providers:
    missing_requirements.append("managed_mesh_provider_kind")
elif any(token in provider_lower for token in local_provider_tokens):
    missing_requirements.append("managed_mesh_provider_non_local")

if not provider_control_plane:
    missing_requirements.append("managed_mesh_control_plane")

if not decision:
    missing_requirements.append("managed_mesh_decision")
elif decision not in accepted_decisions:
    missing_requirements.append("managed_mesh_decision_kind")

if not rationale:
    missing_requirements.append("managed_mesh_decision_rationale")

if additional_provider_required:
    missing_requirements.append("managed_mesh_additional_provider_required")

source = first_text_value(evidence_doc, "source")
live_provider = first_bool_value(evidence_doc, "live_provider")
external_provider = first_bool_value(evidence_doc, "external_provider")
if source and source not in {"live_provider", "retained_live_provider", "provider_artifact"}:
    missing_requirements.append("managed_mesh_evidence_source")
if live_provider is not True and source not in {"live_provider", "retained_live_provider"}:
    missing_requirements.append("managed_mesh_live_provider_evidence")
if external_provider is not True:
    missing_requirements.append("managed_mesh_external_provider_evidence")

if observed_at is not None and (not isinstance(observed_at, int) or observed_at <= 0):
    missing_requirements.append("managed_mesh_observed_at_unix_ms")

report_provider = first_text_value(mesh_report_doc, "provider")
qualified_requirement = first_text_value(mesh_report_doc, "qualified_requirement")
if mesh_report_path is not None and mesh_report_path.is_file():
    if mesh_report_doc.get("passed") is not True:
        missing_requirements.append("managed_mesh_report_passed")
    if report_provider and provider and report_provider != provider:
        missing_requirements.append("managed_mesh_report_provider_match")
    if qualified_requirement and qualified_requirement != "managed_service_mesh":
        missing_requirements.append("managed_mesh_report_qualified_requirement")
    elif not qualified_requirement:
        missing_requirements.append("managed_mesh_report_qualified_requirement")

generated_at_unix_ms = int(time.time() * 1000)
manifest = {
    "schema_version": 1,
    "phase": "regulated-release.managed-mesh-decision",
    "source": "regulated_release_managed_mesh_decision",
    "provider": provider,
    "provider_control_plane": provider_control_plane,
    "decision": decision,
    "decision_rationale": rationale,
    "additional_provider_required": additional_provider_required,
    "managed_mesh_evidence": str(evidence_path) if evidence_path is not None else "",
    "managed_mesh_report": str(mesh_report_path) if mesh_report_path is not None else "",
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
for path in [evidence_path, mesh_report_path, manifest_path]:
    if path is None or not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern_name, pattern in secret_patterns:
        if pattern.search(text):
            secret_findings.append({"pattern": pattern_name, "artifact": str(path)})

if secret_findings:
    missing_requirements.append("no_secret_material_in_managed_mesh_decision")

managed_mesh_decision_ready = (
    not missing_requirements
    and bool(provider)
    and provider in accepted_providers
    and bool(provider_control_plane)
    and decision in accepted_decisions
    and not additional_provider_required
    and not secret_findings
)
passed = managed_mesh_decision_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "regulated-release.managed-mesh-decision",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "managed_mesh_decision_ready": managed_mesh_decision_ready,
    "provider": provider,
    "provider_control_plane": provider_control_plane,
    "decision": decision,
    "decision_rationale": rationale,
    "additional_provider_required": additional_provider_required,
    "manifest": str(manifest_path),
    "managed_mesh_evidence": str(evidence_path) if evidence_path is not None else "",
    "managed_mesh_report": str(mesh_report_path) if mesh_report_path is not None else "",
    "secret_scan_findings": secret_findings,
    "missing_requirements": [] if managed_mesh_decision_ready else list(dict.fromkeys(missing_requirements)),
    "notes": [
        "No secret values are recorded in this report.",
        "The regulated-release.managed-mesh-decision gate records the regulated-release decision for managed mesh evidence.",
        "This gate does not call Kubernetes, service-mesh, or cloud-provider APIs.",
        "Vultr VKE Istio evidence is accepted only when the operator records an explicit RegulatedRelease decision.",
    ],
    "next_commands": {
        "audit": "./scripts/test-regulated-release-managed-mesh-decision.sh",
        "required_metadata": "APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_EVIDENCE=<managed-mesh-evidence.json> APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_REPORT=<managed-mesh-report.json> APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_DECISION=<decision> APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_DECISION_RATIONALE=<rationale> APOLYSIS_REQUIRE_REGULATED_RELEASE_MANAGED_MESH_DECISION=1 ./scripts/test-regulated-release-managed-mesh-decision.sh",
    },
    "observed_at_unix_ms": generated_at_unix_ms,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not managed_mesh_decision_ready:
    print(f"apolysis-regulated_release: managed mesh decision failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: managed mesh decision audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_DECISION_REPORT=$report
EOF

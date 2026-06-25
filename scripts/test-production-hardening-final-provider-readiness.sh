#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-final-provider-readiness.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-final-provider-readiness-report.json"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" <<'PY'
import json
import os
import shutil
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = os.environ.get("APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS", "0") == "1"

tool_names = [
    "aws",
    "gcloud",
    "kubectl",
    "helm",
    "jq",
    "python3",
    "cargo",
    "openssl",
    "sha256sum",
    "hcp",
    "consul",
    "linkerd",
]
tools = {
    name: {
        "available": shutil.which(name) is not None,
        "path": shutil.which(name) or "",
    }
    for name in tool_names
}

known_defaults = {
    "APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE": repo_root / "target/production-hardening-cloudflare-r2-worm/apolysis-production-hardening-cloudflare-r2-worm-evidence.json",
    "APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT": repo_root / "target/production-hardening-cloudflare-r2-worm/apolysis-production-hardening-cloudflare-r2-worm-report.json",
    "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE": repo_root / "target/production-hardening-dockerhub-registry-promotion.aByXvA/apolysis-production-hardening-dockerhub-registry-promotion-evidence.json",
    "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT": repo_root / "target/production-hardening-dockerhub-registry-promotion.aByXvA/apolysis-production-hardening-dockerhub-registry-promotion-report.json",
}

artifact_envs = [
    "APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE",
    "APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT",
    "APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE",
    "APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT",
    "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE",
    "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT",
    "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE",
    "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT",
]

def path_from_env(name: str) -> tuple[Path | None, str]:
    value = os.environ.get(name, "")
    if value:
        return Path(value), "environment"
    default = known_defaults.get(name)
    if default is not None:
        return default, "known_retained_default"
    return None, "missing"

def load_json(path: Path | None) -> tuple[dict, str]:
    if path is None:
        return {}, "missing_path"
    if not path.is_file():
        return {}, "missing_file"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "loaded"
    except json.JSONDecodeError as exc:
        return {}, f"invalid_json:{exc}"

artifacts = {}
for name in artifact_envs:
    path, source = path_from_env(name)
    document, status = load_json(path)
    artifacts[name] = {
        "configured": path is not None,
        "exists": bool(path and path.is_file()),
        "path": str(path) if path is not None else "",
        "source": source,
        "evidence_source": document.get("source", ""),
        "live_provider_evidence": document.get("source") == "live_provider",
        "json_status": status,
        "report_passed": document.get("passed") is True,
        "provider": document.get("provider") or document.get("approval", {}).get("provider", ""),
        "observed_at_unix_ms": document.get("observed_at_unix_ms")
        or document.get("approval", {}).get("observed_at_unix_ms")
        or 0,
    }

def pair_ready(evidence_env: str, report_env: str, accepted_providers: set[str]) -> bool:
    evidence = artifacts[evidence_env]
    report = artifacts[report_env]
    return (
        evidence["exists"]
        and report["exists"]
        and evidence["live_provider_evidence"]
        and report["report_passed"]
        and evidence["provider"] in accepted_providers
        and int(evidence["observed_at_unix_ms"] or 0) > 0
    )

readiness = {
    "cloud_kms_or_external_hsm_signing": pair_ready(
        "APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE",
        "APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT",
        {"cloud_kms", "aws_kms", "gcp_cloud_kms", "azure_key_vault", "aws_cloudhsm", "external_hsm"},
    ),
    "cloud_worm_object_lock_archive": pair_ready(
        "APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE",
        "APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT",
        {"cloudflare_r2_bucket_lock", "aws_s3_object_lock", "gcs_bucket_lock", "azure_immutable_blob"},
    ),
    "cloud_registry_promotion_retention": pair_ready(
        "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE",
        "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT",
        {"docker_hub", "aws_ecr", "gcp_artifact_registry", "azure_container_registry", "ghcr", "quay"},
    ),
    "managed_service_mesh": pair_ready(
        "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE",
        "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT",
        {
            "gke_anthos_service_mesh",
            "vultr_vke_istio",
            "vultr_vke_service_mesh",
            "aks_istio_addon",
            "eks_app_mesh",
            "openshift_service_mesh",
            "linkerd_buoyant_cloud",
            "consul_cloud",
        },
    ),
}

live_prerequisites = {
    "aws_kms": {
        "tool_aws": tools["aws"]["available"],
        "APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID": bool(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID")),
        "region": bool(
            os.environ.get("APOLYSIS_PRODUCTION_HARDENING_AWS_REGION")
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
        ),
        "credential_hint_present": any(
            bool(os.environ.get(name))
            for name in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE")
        )
        or (Path.home() / ".aws").is_dir(),
    },
    "gke_anthos_service_mesh": {
        "tool_gcloud": tools["gcloud"]["available"],
        "tool_kubectl": tools["kubectl"]["available"],
        "APOLYSIS_PRODUCTION_HARDENING_GKE_MESH_FLEET_PROJECT": bool(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_GKE_MESH_FLEET_PROJECT")),
        "APOLYSIS_PRODUCTION_HARDENING_GKE_MESH_MEMBERSHIP": bool(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_GKE_MESH_MEMBERSHIP")),
        "gcloud_config_hint_present": (Path.home() / ".config/gcloud").is_dir(),
    },
}

missing_requirements = [name for name, ready in readiness.items() if not ready]
final_provider_ready = not missing_requirements

missing_live_prerequisites = {
    provider: [key for key, present in checks.items() if not present]
    for provider, checks in live_prerequisites.items()
}

report = {
    "schema_version": 1,
    "audit_completed": True,
    "passed": final_provider_ready or not require_ready,
    "fail_closed_required": require_ready,
    "final_provider_ready": final_provider_ready,
    "readiness": readiness,
    "missing_requirements": missing_requirements,
    "tools": tools,
    "artifact_inputs": artifacts,
    "live_prerequisites": live_prerequisites,
    "missing_live_prerequisites": missing_live_prerequisites,
    "notes": [
        "No secret values are recorded in this report.",
        "Default mode is an audit. Set APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS=1 to fail closed until all final provider evidence is present.",
        "ProductionHardening completion still requires real provider signing evidence, real managed service-mesh provider evidence, and a passing final external provider bundle.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not final_provider_ready:
    print(f"apolysis-production-hardening: final provider readiness failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing_requirements), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: final provider readiness audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_READINESS_REPORT=$report
EOF

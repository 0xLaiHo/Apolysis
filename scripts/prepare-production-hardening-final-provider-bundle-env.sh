#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_BUNDLE_ENV_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-final-provider-bundle-env.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-final-provider-bundle-env-report.json"
env_file="$output_dir/apolysis-production-hardening-final-provider-bundle.env"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in python3 jq; do
    require_command "$command"
done

python3 - "$repo_root" "$report" "$env_file" <<'PY'
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
env_path = Path(sys.argv[3])
artifact_root_value = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_ARTIFACT_ROOT", "")
explicit_artifact_roots = []
if artifact_root_value:
    explicit_artifact_roots.extend(Path(part) for part in artifact_root_value.split(":") if part)

require_ready = os.environ.get("APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_BUNDLE_ENV", "0") == "1"
run_final_bundle = os.environ.get("APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_BUNDLE", "0") == "1"

known_defaults = {
    "worm_evidence": repo_root / "target/production-hardening-cloudflare-r2-worm/apolysis-production-hardening-cloudflare-r2-worm-evidence.json",
    "worm_report": repo_root / "target/production-hardening-cloudflare-r2-worm/apolysis-production-hardening-cloudflare-r2-worm-report.json",
    "registry_evidence": repo_root / "target/production-hardening-dockerhub-registry-promotion.aByXvA/apolysis-production-hardening-dockerhub-registry-promotion-evidence.json",
    "registry_report": repo_root / "target/production-hardening-dockerhub-registry-promotion.aByXvA/apolysis-production-hardening-dockerhub-registry-promotion-report.json",
}

accepted_providers = {
    "signing": {"cloud_kms", "aws_kms", "gcp_cloud_kms", "azure_key_vault", "aws_cloudhsm", "external_hsm"},
    "worm": {"cloudflare_r2_bucket_lock", "aws_s3_object_lock", "gcs_bucket_lock", "azure_immutable_blob"},
    "registry": {"docker_hub", "aws_ecr", "gcp_artifact_registry", "azure_container_registry", "ghcr", "quay"},
    "managed_mesh": {
        "gke_anthos_service_mesh",
        "vultr_vke_istio",
        "vultr_vke_service_mesh",
        "aks_istio_addon",
        "eks_app_mesh",
        "openshift_service_mesh",
        "linkerd_buoyant_cloud",
        "consul_cloud",
    },
}

candidate_patterns = {
    "signing_evidence": ["*aws-kms*evidence*.json", "*signing*evidence*.json"],
    "signing_report": ["*aws-kms*report*.json", "*signing*report*.json"],
    "managed_mesh_evidence": ["*managed-cloud-service-mesh*evidence*.json", "*managed*mesh*evidence*.json"],
    "managed_mesh_report": ["*managed-cloud-service-mesh*report*.json", "*managed*mesh*report*.json"],
    "worm_evidence": ["*cloudflare-r2-worm*evidence*.json", "*worm*evidence*.json"],
    "worm_report": ["*cloudflare-r2-worm*report*.json", "*worm*report*.json"],
    "registry_evidence": ["*dockerhub*registry*evidence*.json", "*registry*promotion*evidence*.json"],
    "registry_report": ["*dockerhub*registry*report*.json", "*registry*promotion*report*.json"],
}

env_names = {
    "signing_evidence": "APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE",
    "signing_report": "APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT",
    "worm_evidence": "APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE",
    "worm_report": "APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT",
    "registry_evidence": "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE",
    "registry_report": "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT",
    "managed_mesh_evidence": "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE",
    "managed_mesh_report": "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT",
}

def json_doc(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def provider_of(path: Path) -> str:
    doc = json_doc(path)
    return str(doc.get("provider") or doc.get("approval", {}).get("provider", ""))

def observed_at(path: Path) -> int:
    doc = json_doc(path)
    value = doc.get("observed_at_unix_ms") or doc.get("approval", {}).get("observed_at_unix_ms") or 0
    try:
        return int(value)
    except Exception:
        return 0

def report_passed(path: Path) -> bool:
    return json_doc(path).get("passed") is True

def latest_existing(paths: list[Path]) -> Path | None:
    existing = [path for path in paths if path.is_file()]
    if not existing:
        return None
    return max(existing, key=lambda path: path.stat().st_mtime_ns)

def find_candidate(key: str, provider_class: str | None = None, report: bool = False) -> Path | None:
    explicit = os.environ.get(env_names[key], "")
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else path
    # Signing and managed-mesh artifacts close the final production-readiness gap.
    # Do not discover them from the repo's default target/ tree because local
    # contract tests intentionally create accepted-looking fixture artifacts.
    roots = explicit_artifact_roots
    candidates: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in candidate_patterns[key]:
            candidates.extend(root.rglob(pattern))
    if provider_class:
        filtered = []
        for path in candidates:
            if report:
                if report_passed(path):
                    filtered.append(path)
            elif provider_of(path) in accepted_providers[provider_class] and observed_at(path) > 0:
                filtered.append(path)
        candidates = filtered
    candidate = latest_existing(candidates)
    if candidate is not None:
        return candidate
    default = known_defaults.get(key)
    if default is not None and default.is_file():
        return default
    return None

paths = {
    "signing_evidence": find_candidate("signing_evidence", "signing"),
    "signing_report": find_candidate("signing_report", "signing", report=True),
    "worm_evidence": find_candidate("worm_evidence", "worm"),
    "worm_report": find_candidate("worm_report", "worm", report=True),
    "registry_evidence": find_candidate("registry_evidence", "registry"),
    "registry_report": find_candidate("registry_report", "registry", report=True),
    "managed_mesh_evidence": find_candidate("managed_mesh_evidence", "managed_mesh"),
    "managed_mesh_report": find_candidate("managed_mesh_report", "managed_mesh", report=True),
}

classes = {
    "cloud_kms_or_external_hsm_signing": ("signing_evidence", "signing_report", "signing"),
    "cloud_worm_object_lock_archive": ("worm_evidence", "worm_report", "worm"),
    "cloud_registry_promotion_retention": ("registry_evidence", "registry_report", "registry"),
    "managed_service_mesh": ("managed_mesh_evidence", "managed_mesh_report", "managed_mesh"),
}

readiness = {}
artifact_details = {}
for requirement, (evidence_key, report_key, provider_class) in classes.items():
    evidence_path = paths[evidence_key]
    report_file = paths[report_key]
    evidence_ready = (
        evidence_path is not None
        and evidence_path.is_file()
        and provider_of(evidence_path) in accepted_providers[provider_class]
        and observed_at(evidence_path) > 0
    )
    report_ready = report_file is not None and report_file.is_file() and report_passed(report_file)
    readiness[requirement] = evidence_ready and report_ready
    artifact_details[requirement] = {
        "evidence_path": str(evidence_path) if evidence_path else "",
        "report_path": str(report_file) if report_file else "",
        "provider": provider_of(evidence_path) if evidence_path and evidence_path.is_file() else "",
        "observed_at_unix_ms": observed_at(evidence_path) if evidence_path and evidence_path.is_file() else 0,
        "report_passed": report_passed(report_file) if report_file and report_file.is_file() else False,
    }

missing = [requirement for requirement, ready in readiness.items() if not ready]
all_ready = not missing

managed_mesh_provider = provider_of(paths["managed_mesh_evidence"]) if paths["managed_mesh_evidence"] and paths["managed_mesh_evidence"].is_file() else ""
managed_mesh_doc = json_doc(paths["managed_mesh_evidence"]) if paths["managed_mesh_evidence"] and paths["managed_mesh_evidence"].is_file() else {}
managed_mesh_control_plane = str(
    managed_mesh_doc.get("provider_control_plane")
    or managed_mesh_doc.get("mesh_uri")
    or managed_mesh_doc.get("approval", {}).get("provider_control_plane", "")
    or managed_mesh_doc.get("approval", {}).get("mesh_uri", "")
)

signing_provider = provider_of(paths["signing_evidence"]) if paths["signing_evidence"] and paths["signing_evidence"].is_file() else ""
if signing_provider == "cloud_kms":
    signing_provider = "aws_kms"
signing_doc = json_doc(paths["signing_evidence"]) if paths["signing_evidence"] and paths["signing_evidence"].is_file() else {}
signing_control_plane = str(signing_doc.get("key_uri") or signing_doc.get("approval", {}).get("key_uri", ""))

exports = {}
for key, env_name in env_names.items():
    path = paths[key]
    if path and path.is_file():
        exports[env_name] = str(path.resolve())
if managed_mesh_provider:
    exports["APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_PROVIDER"] = managed_mesh_provider
if managed_mesh_control_plane:
    exports["APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_CONTROL_PLANE"] = managed_mesh_control_plane
if signing_provider:
    exports["APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER"] = signing_provider
if signing_control_plane:
    exports["APOLYSIS_PRODUCTION_HARDENING_SIGNING_CONTROL_PLANE"] = signing_control_plane

env_lines = [
    "# Source this file before running scripts/build-production-hardening-final-external-provider-bundle.sh.",
]
for name in sorted(exports):
    env_lines.append(f"export {name}={shlex.quote(exports[name])}")
env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")

final_bundle = None
final_bundle_status = "not_requested"
if run_final_bundle:
    if not all_ready:
        final_bundle_status = "missing_provider_artifacts"
    else:
        env = os.environ.copy()
        env.update(exports)
        process = subprocess.run(
            [str(repo_root / "scripts/build-production-hardening-final-external-provider-bundle.sh")],
            cwd=repo_root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        final_bundle_status = "passed" if process.returncode == 0 else "failed"
        final_bundle = {
            "exit_code": process.returncode,
            "output": process.stdout,
        }

report = {
    "schema_version": 1,
    "passed": all_ready or not require_ready,
    "all_provider_artifacts_ready": all_ready,
    "fail_closed_required": require_ready,
    "artifact_roots": [str(path) for path in explicit_artifact_roots],
    "readiness": readiness,
    "missing_requirements": missing,
    "artifact_details": artifact_details,
    "env_file": str(env_path),
    "exports": sorted(exports),
    "final_bundle_status": final_bundle_status,
    "final_bundle": final_bundle,
    "observed_at_unix_ms": int(time.time() * 1000),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not all_ready:
    print(f"apolysis-production-hardening: final provider bundle env failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
if run_final_bundle and final_bundle_status != "passed":
    print(f"apolysis-production-hardening: final bundle builder did not pass ({report_path})", file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: final provider bundle env audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_BUNDLE_ENV=$env_file
APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_BUNDLE_ENV_REPORT=$report
EOF

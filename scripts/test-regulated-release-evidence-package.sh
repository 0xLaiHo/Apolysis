#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-evidence-package.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-evidence-package-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_EVIDENCE_PACKAGE:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-regulated_release: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$output_dir" "$report" "$require_ready" <<'PY'
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
report_path = Path(sys.argv[3])
require_ready = sys.argv[4] == "1"

production_hardening_builder = repo_root / "scripts/build-production-hardening-final-external-provider-bundle.sh"
downstream_dir = output_dir / "production-hardening-final-external-provider-bundle"
downstream_report_path = downstream_dir / "apolysis-production-hardening-final-external-provider-bundle-report.json"
downstream_bundle_path = downstream_dir / "bundle-root/apolysis-production-hardening-final-external-provider-bundle.json"
package_manifest_path = output_dir / "apolysis-regulated-release-evidence-package-manifest.json"
archive_path = output_dir / "apolysis-regulated-release-evidence-package.tar.gz"
archive_sha_path = output_dir / "apolysis-regulated-release-evidence-package.tar.gz.sha256"

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

def rel_ref(path: Path, root: Path) -> str:
    return str(path.relative_to(root))

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

provider_root_value = env_value(
    "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT",
    "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT",
)
provider_root = Path(provider_root_value) if provider_root_value else None

signing_evidence_value = env_value("APOLYSIS_REGULATED_RELEASE_SIGNING_EVIDENCE", "APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE")
signing_report_value = env_value("APOLYSIS_REGULATED_RELEASE_SIGNING_REPORT", "APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT")

def artifact_from_root(name: str) -> str:
    if provider_root is None:
        return ""
    return str(provider_root / name)

signing_evidence = Path(signing_evidence_value or artifact_from_root("signing-evidence.json"))
signing_report = Path(signing_report_value or artifact_from_root("signing-report.json"))
worm_evidence = Path(env_value("APOLYSIS_REGULATED_RELEASE_WORM_EVIDENCE", "APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE") or artifact_from_root("worm-evidence.json"))
worm_report = Path(env_value("APOLYSIS_REGULATED_RELEASE_WORM_REPORT", "APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT") or artifact_from_root("worm-report.json"))
registry_evidence = Path(env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_EVIDENCE", "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE") or artifact_from_root("registry-evidence.json"))
registry_report = Path(env_value("APOLYSIS_REGULATED_RELEASE_REGISTRY_REPORT", "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT") or artifact_from_root("registry-report.json"))
managed_mesh_evidence = Path(
    env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_EVIDENCE", "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE")
    or artifact_from_root("managed-mesh-evidence.json")
)
managed_mesh_report = Path(
    env_value("APOLYSIS_REGULATED_RELEASE_MANAGED_MESH_REPORT", "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT")
    or artifact_from_root("managed-mesh-report.json")
)

required_artifacts = {
    "signing_evidence": signing_evidence,
    "signing_report": signing_report,
    "worm_evidence": worm_evidence,
    "worm_report": worm_report,
    "registry_evidence": registry_evidence,
    "registry_report": registry_report,
    "managed_mesh_evidence": managed_mesh_evidence,
    "managed_mesh_report": managed_mesh_report,
}

missing_requirements: list[str] = []
if provider_root is None:
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT")
elif not provider_root.is_dir():
    missing_requirements.append("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT_exists")

for label, path in required_artifacts.items():
    if not str(path):
        missing_requirements.append(f"{label}_path")
    elif not path.is_file():
        missing_requirements.append(label)

signing_doc = load_json(signing_evidence if signing_evidence.is_file() else None)
worm_doc = load_json(worm_evidence if worm_evidence.is_file() else None)
registry_doc = load_json(registry_evidence if registry_evidence.is_file() else None)
managed_mesh_doc = load_json(managed_mesh_evidence if managed_mesh_evidence.is_file() else None)

signing_provider_raw = first_text_value(signing_doc, "provider")
signing_provider = "aws_kms" if signing_provider_raw in {"cloud_kms", "aws_kms"} else signing_provider_raw
signing_control_plane = first_text_value(signing_doc, "key_uri")
worm_provider = first_text_value(worm_doc, "provider")
worm_control_plane = first_text_value(worm_doc, "bucket_uri", "endpoint_uri")
registry_provider = first_text_value(registry_doc, "provider")
registry_control_plane = first_text_value(registry_doc, "registry_uri")
managed_mesh_provider = first_text_value(managed_mesh_doc, "provider")
managed_mesh_control_plane = first_text_value(managed_mesh_doc, "provider_control_plane", "mesh_uri", "cluster_name")

control_fields = {
    "signing_provider": signing_provider,
    "signing_control_plane": signing_control_plane,
    "worm_provider": worm_provider,
    "worm_control_plane": worm_control_plane,
    "registry_provider": registry_provider,
    "registry_control_plane": registry_control_plane,
    "managed_mesh_provider": managed_mesh_provider,
    "managed_mesh_control_plane": managed_mesh_control_plane,
}
for label, value in control_fields.items():
    if not value:
        missing_requirements.append(label)

downstream_output_path = output_dir / "production-hardening-final-external-provider-bundle.out"
downstream_exit_code = 0
downstream_doc: dict = {}
secret_findings: list[dict] = []
package_entries: list[dict] = []

if not missing_requirements:
    env = os.environ.copy()
    env.update(
        {
            "APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_OUTPUT_DIR": str(downstream_dir),
            "APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER": signing_provider,
            "APOLYSIS_PRODUCTION_HARDENING_SIGNING_CONTROL_PLANE": signing_control_plane,
            "APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE": str(signing_evidence),
            "APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT": str(signing_report),
            "APOLYSIS_PRODUCTION_HARDENING_WORM_PROVIDER": worm_provider,
            "APOLYSIS_PRODUCTION_HARDENING_WORM_CONTROL_PLANE": worm_control_plane,
            "APOLYSIS_PRODUCTION_HARDENING_WORM_EVIDENCE": str(worm_evidence),
            "APOLYSIS_PRODUCTION_HARDENING_WORM_REPORT": str(worm_report),
            "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_PROVIDER": registry_provider,
            "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_CONTROL_PLANE": registry_control_plane,
            "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_EVIDENCE": str(registry_evidence),
            "APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPORT": str(registry_report),
            "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_PROVIDER": managed_mesh_provider,
            "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_CONTROL_PLANE": managed_mesh_control_plane,
            "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_EVIDENCE": str(managed_mesh_evidence),
            "APOLYSIS_PRODUCTION_HARDENING_MANAGED_MESH_REPORT": str(managed_mesh_report),
        }
    )
    process = subprocess.run(
        [str(production_hardening_builder)],
        cwd=repo_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    downstream_exit_code = process.returncode
    downstream_output_path.write_text(process.stdout, encoding="utf-8")
    downstream_doc = load_json(downstream_report_path)

    if downstream_exit_code != 0:
        missing_requirements.append("production_hardening_final_external_provider_bundle_succeeded")
    if downstream_doc.get("passed") is not True:
        missing_requirements.append("production_hardening_final_external_provider_bundle_passed")

    bundle_root = downstream_dir / "bundle-root"
    if downstream_bundle_path.is_file():
        bundle_doc = load_json(downstream_bundle_path)
        for entry in bundle_doc.get("entries") or []:
            evidence_ref = entry.get("evidence_ref", "")
            report_ref = entry.get("report_ref", "")
            evidence_path = bundle_root / evidence_ref
            report_artifact_path = bundle_root / report_ref
            if not evidence_path.is_file():
                missing_requirements.append(f"{entry.get('requirement', 'unknown')}_evidence_ref")
            if not report_artifact_path.is_file():
                missing_requirements.append(f"{entry.get('requirement', 'unknown')}_report_ref")
            package_entries.append(
                {
                    "requirement": entry.get("requirement", ""),
                    "provider": entry.get("provider", ""),
                    "provider_control_plane": entry.get("provider_control_plane", ""),
                    "evidence_ref": evidence_ref,
                    "evidence_sha256": f"sha256:{sha256_file(evidence_path)}" if evidence_path.is_file() else "",
                    "report_ref": report_ref,
                    "report_sha256": f"sha256:{sha256_file(report_artifact_path)}" if report_artifact_path.is_file() else "",
                    "observed_at_unix_ms": int(entry.get("observed_at_unix_ms") or 0),
                }
            )
    else:
        missing_requirements.append("production_hardening_final_external_provider_bundle_manifest")

    secret_patterns = [
        ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("aws_secret_access_key_name", re.compile(r"(?i)aws_secret_access_key")),
        ("aws_session_token_name", re.compile(r"(?i)aws_session_token")),
        ("generic_secret_assignment", re.compile(r"(?i)[\"'](?:secret|token|password)[\"']\s*:")),
        ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ]
    if bundle_root.is_dir():
        for path in sorted(bundle_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".json", ".txt", ".env", ".pem"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern_name, pattern in secret_patterns:
                if pattern.search(text):
                    secret_findings.append(
                        {
                            "pattern": pattern_name,
                            "artifact_ref": rel_ref(path, bundle_root),
                        }
                    )

        with tarfile.open(archive_path, "w:gz") as archive:
            for path in sorted(bundle_root.rglob("*")):
                archive.add(path, arcname=rel_ref(path, bundle_root))
        archive_sha = sha256_file(archive_path)
        archive_sha_path.write_text(f"{archive_sha}  {archive_path.name}\n", encoding="utf-8")
    else:
        archive_sha = ""
        missing_requirements.append("regulated_release_evidence_package_bundle_root")
else:
    downstream_exit_code = 0
    archive_sha = ""

if secret_findings:
    missing_requirements.append("no_secret_material_in_evidence_package")

generated_at_unix_ms = int(time.time() * 1000)
package_manifest = {
    "schema_version": 1,
    "phase": "regulated-release.evidence-package",
    "package_id": f"regulated-release-evidence-package-{generated_at_unix_ms}",
    "source": "regulated_release_evidence_package",
    "downstream_bundle": str(downstream_bundle_path) if downstream_bundle_path.is_file() else "",
    "entries": package_entries,
    "archive": str(archive_path) if archive_path.is_file() else "",
    "archive_sha256": f"sha256:{archive_sha}" if archive_sha else "",
    "secret_scan": {
        "patterns_checked": [
            "aws_access_key_id",
            "aws_secret_access_key_name",
            "aws_session_token_name",
            "generic_secret_assignment",
            "private_key_block",
        ],
        "findings": secret_findings,
    },
    "generated_at_unix_ms": generated_at_unix_ms,
}
package_manifest_path.write_text(json.dumps(package_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

evidence_package_ready = (
    not missing_requirements
    and len(package_entries) == 4
    and bool(archive_sha)
    and not secret_findings
    and downstream_doc.get("passed") is True
)
passed = evidence_package_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "regulated-release.evidence-package",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "evidence_package_ready": evidence_package_ready,
    "required_entry_count": 4,
    "packaged_entry_count": len(package_entries),
    "provider_artifact_root_present": bool(provider_root_value),
    "provider_artifact_root_exists": bool(provider_root and provider_root.is_dir()),
    "signing_evidence_path_present": bool(signing_evidence_value),
    "archive": str(archive_path) if archive_path.is_file() else "",
    "archive_sha256": f"sha256:{archive_sha}" if archive_sha else "",
    "manifest": str(package_manifest_path),
    "secret_scan_findings": secret_findings,
    "downstream": {
        "gate": str(production_hardening_builder),
        "exit_code": downstream_exit_code,
        "output_file": str(downstream_output_path),
        "report": str(downstream_report_path) if downstream_report_path.is_file() else "",
        "bundle": str(downstream_bundle_path) if downstream_bundle_path.is_file() else "",
    },
    "missing_requirements": [] if evidence_package_ready else list(dict.fromkeys(missing_requirements)),
    "notes": [
        "No secret values are recorded in this report.",
        "The regulated-release.evidence-package package gate wraps the historical ProductionHardening final external-provider bundle builder.",
        "The package archive is generated under target/ and is not intended to be committed.",
        "Secret scanning checks common AWS access key, AWS secret/session token, generic secret assignment, and private-key block patterns in packaged text artifacts.",
    ],
    "observed_at_unix_ms": generated_at_unix_ms,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not evidence_package_ready:
    print(f"apolysis-regulated_release: evidence package failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: evidence package audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_REPORT=$report
EOF

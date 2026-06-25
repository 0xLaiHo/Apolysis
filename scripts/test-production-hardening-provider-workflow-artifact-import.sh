#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-provider-workflow-artifact-import.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-provider-workflow-artifact-import-report.json"
import_root="$output_dir/provider-artifacts"
bundle_env_dir="$output_dir/final-provider-bundle-env"
require_ready="${APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" "$import_root" "$bundle_env_dir" "$require_ready" <<'PY'
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
import_root = Path(sys.argv[3])
bundle_env_dir = Path(sys.argv[4])
require_ready = sys.argv[5] == "1"
workflow_file = repo_root / ".github" / "workflows" / "production-hardening-final-provider-evidence.yml"

def run(command: list[str], env: dict[str, str] | None = None) -> tuple[int, str]:
    process = subprocess.run(
        command,
        cwd=repo_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return process.returncode, process.stdout

def origin_repo() -> str:
    configured = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_GITHUB_REPO", "")
    if configured:
        return configured
    rc, output = run(["git", "remote", "get-url", "origin"])
    if rc != 0:
        return ""
    value = output.strip()
    patterns = [
        r"git@github\.com:([^/]+/[^/.]+)(?:\.git)?$",
        r"https://github\.com/([^/]+/[^/.]+)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, value)
        if match:
            return match.group(1)
    return ""

def valid_repo(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value))

def valid_run_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d+", value))

def valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))

def safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
    destination_resolved = destination.resolve()
    for member in tar.getmembers():
        if member.issym() or member.islnk():
            raise ValueError(f"retained_provider_artifact_package_no_links:{member.name}")
        target = (destination / member.name).resolve()
        if not str(target).startswith(str(destination_resolved) + os.sep) and target != destination_resolved:
            raise ValueError(f"tar member escapes destination: {member.name}")
    tar.extractall(destination)

def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def provider_json_count(root: Path) -> int:
    if not root.is_dir():
        return 0
    count = 0
    for pattern in ("*evidence*.json", "*report*.json", "*bundle*.json", "*manifest*.json"):
        count += sum(1 for _ in root.rglob(pattern))
    return count

mode = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_MODE", "audit")
download_confirmed = os.environ.get("APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD", "0") == "1"
repo = origin_repo()
run_id = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID", "")
local_artifact_root = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT", "")
retained_package = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE", "")
retained_package_sha256 = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256", "")
run_final_bundle = os.environ.get("APOLYSIS_RUN_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_FINAL_BUNDLE", "0") == "1"

tools = {
    name: {"available": bool(path := shutil.which(name)), "path": path or ""}
    for name in ("gh", "git", "python3")
}

workflow_text = workflow_file.read_text(encoding="utf-8") if workflow_file.is_file() else ""
workflow_contract = {
    "exists": workflow_file.is_file(),
    "workflow_dispatch": "workflow_dispatch:" in workflow_text,
    "aws_kms_artifact": "production-hardening-aws-kms-signing-evidence" in workflow_text,
    "final_bundle_artifact": "production-hardening-final-external-provider-bundle" in workflow_text,
}
workflow_contract_ready = all(workflow_contract.values())

github_token_environment_present = any(bool(os.environ.get(name)) for name in ("GH_TOKEN", "GITHUB_TOKEN"))
gh_authenticated = False
gh_error_hint = ""
if tools["gh"]["available"]:
    rc, output = run(["gh", "auth", "status", "--hostname", "github.com"])
    gh_authenticated = rc == 0 or github_token_environment_present
    if rc != 0 and not github_token_environment_present:
        gh_error_hint = output[:4000]

import_root.mkdir(parents=True, exist_ok=True)
artifact_roots: list[Path] = []
import_actions: list[dict[str, str | bool | int]] = []
missing_requirements: list[str] = []

if mode not in {"audit", "download"}:
    missing_requirements.append("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_MODE_audit_or_download")
if not valid_repo(repo):
    missing_requirements.append("github_repository")
if not workflow_contract_ready:
    missing_requirements.append("workflow_contract")

if local_artifact_root:
    local_root = Path(local_artifact_root)
    if local_root.is_dir():
        artifact_roots.append(local_root.resolve())
        import_actions.append(
            {
                "kind": "local_artifact_root",
                "path": str(local_root.resolve()),
                "provider_json_count": provider_json_count(local_root),
            }
        )
    else:
        missing_requirements.append("local_provider_artifact_root_exists")

if retained_package:
    package_path = Path(retained_package)
    if not package_path.is_file():
        missing_requirements.append("retained_provider_artifact_package_exists")
    if not valid_sha256(retained_package_sha256):
        missing_requirements.append("retained_provider_artifact_package_sha256")
    if package_path.is_file() and valid_sha256(retained_package_sha256):
        actual = file_sha256(package_path)
        if actual.lower() != retained_package_sha256.lower():
            missing_requirements.append("retained_provider_artifact_package_sha256_match")
        else:
            extract_dir = import_root / "retained-package"
            extract_dir.mkdir(parents=True, exist_ok=True)
            try:
                with tarfile.open(package_path, "r:gz") as archive:
                    safe_extract(archive, extract_dir)
                artifact_roots.append(extract_dir.resolve())
                import_actions.append(
                    {
                        "kind": "retained_provider_artifact_package",
                        "path": str(package_path.resolve()),
                        "extract_dir": str(extract_dir.resolve()),
                        "provider_json_count": provider_json_count(extract_dir),
                    }
                )
            except Exception as error:
                if str(error).startswith("retained_provider_artifact_package_no_links:"):
                    missing_requirements.append("retained_provider_artifact_package_no_links")
                else:
                    missing_requirements.append("retained_provider_artifact_package_extractable")
                gh_error_hint = str(error)[:4000]
elif retained_package_sha256:
    missing_requirements.append("retained_provider_artifact_package")

download_command = [
    "gh",
    "run",
    "download",
    run_id or "<run-id>",
    "--repo",
    repo or "<owner>/<repo>",
    "--dir",
    str((import_root / "downloaded").resolve()),
]
download_attempted = False
download_succeeded = False
download_output_hint = ""
if mode == "download":
    if not valid_run_id(run_id):
        missing_requirements.append("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID")
    if not download_confirmed:
        missing_requirements.append("APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD")
    if not tools["gh"]["available"]:
        missing_requirements.append("gh_cli")
    if tools["gh"]["available"] and not gh_authenticated:
        missing_requirements.append("gh_authenticated_session")
    if valid_run_id(run_id) and download_confirmed and tools["gh"]["available"] and gh_authenticated and valid_repo(repo):
        download_attempted = True
        download_root = import_root / "downloaded"
        download_root.mkdir(parents=True, exist_ok=True)
        rc, output = run(download_command)
        download_output_hint = output[:4000]
        if rc == 0:
            download_succeeded = True
            artifact_roots.append(download_root.resolve())
            import_actions.append(
                {
                    "kind": "gh_run_download",
                    "run_id": run_id,
                    "path": str(download_root.resolve()),
                    "provider_json_count": provider_json_count(download_root),
                }
            )
        else:
            missing_requirements.append("gh_run_download_succeeded")
            gh_error_hint = output[:4000]

artifact_json_count = sum(provider_json_count(root) for root in artifact_roots)
if not artifact_roots:
    missing_requirements.append("provider_artifact_source")
elif artifact_json_count == 0:
    missing_requirements.append("provider_artifact_json")

bundle_env_report = ""
bundle_env_exit_code = 0
bundle_env_output_hint = ""
bundle_env_ready = False
bundle_env_missing: list[str] = []
if artifact_roots:
    env = os.environ.copy()
    env["APOLYSIS_PRODUCTION_HARDENING_PROVIDER_ARTIFACT_ROOT"] = ":".join(str(root) for root in artifact_roots)
    env["APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_BUNDLE_ENV_OUTPUT_DIR"] = str(bundle_env_dir)
    env["APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_BUNDLE"] = "1" if run_final_bundle else "0"
    rc, output = run([str(repo_root / "scripts/prepare-production-hardening-final-provider-bundle-env.sh")], env=env)
    bundle_env_exit_code = rc
    bundle_env_output_hint = output[:4000]
    bundle_env_report_path = bundle_env_dir / "apolysis-production-hardening-final-provider-bundle-env-report.json"
    if bundle_env_report_path.is_file():
        bundle_env_report = str(bundle_env_report_path)
        try:
            bundle_env_doc = json.loads(bundle_env_report_path.read_text(encoding="utf-8"))
            bundle_env_ready = bool(bundle_env_doc.get("all_provider_artifacts_ready"))
            bundle_env_missing = list(bundle_env_doc.get("missing_requirements") or [])
        except Exception:
            bundle_env_missing = ["final_provider_bundle_env_report_json"]
    if rc != 0 and run_final_bundle:
        missing_requirements.append("final_bundle_env_audit_succeeded")

missing_requirements = list(dict.fromkeys(missing_requirements))
ready = not missing_requirements
report = {
    "schema_version": 1,
    "phase": "production-hardening.provider-workflow-artifact-import",
    "audit_completed": True,
    "passed": ready or not require_ready,
    "fail_closed_required": require_ready,
    "provider_workflow_artifact_import_ready": ready,
    "mode": mode,
    "download_confirmed": download_confirmed,
    "download_attempted": download_attempted,
    "download_succeeded": download_succeeded,
    "repository": repo,
    "workflow_file": str(workflow_file),
    "workflow_contract_ready": workflow_contract_ready,
    "workflow_contract": workflow_contract,
    "run_id": run_id,
    "artifact_roots": [str(root) for root in artifact_roots],
    "artifact_json_count": artifact_json_count,
    "import_actions": import_actions,
    "bundle_env_report": bundle_env_report,
    "bundle_env_exit_code": bundle_env_exit_code,
    "bundle_env_ready": bundle_env_ready,
    "bundle_env_missing_requirements": bundle_env_missing,
    "run_final_bundle": run_final_bundle,
    "download_command": " ".join(download_command),
    "missing_requirements": missing_requirements,
    "tools": tools,
    "gh_authenticated": gh_authenticated,
    "github_token_environment_present": github_token_environment_present,
    "gh_error_hint": gh_error_hint,
    "download_output_hint": download_output_hint,
    "bundle_env_output_hint": bundle_env_output_hint,
    "notes": [
        "No secret values are recorded in this report.",
        "Default audit mode imports local artifact roots or retained provider packages without downloading from GitHub.",
        "Download mode requires APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD=1 before gh run download is executed.",
        "Imported artifacts are handed to scripts/prepare-production-hardening-final-provider-bundle-env.sh through APOLYSIS_PRODUCTION_HARDENING_PROVIDER_ARTIFACT_ROOT.",
        "This gate does not create signing evidence; it only imports and audits artifacts produced by the final-provider workflow or retained provider package.",
    ],
    "next_commands": {
        "list_workflow_runs": f"gh run list --repo {repo or '<owner>/<repo>'} --workflow production-hardening-final-provider-evidence.yml",
        "download_workflow_artifacts": f"APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_MODE=download APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD=1 APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID=<run-id> APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT=1 ./scripts/test-production-hardening-provider-workflow-artifact-import.sh",
        "audit_local_artifacts": "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT=<artifact-root> APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT=1 ./scripts/test-production-hardening-provider-workflow-artifact-import.sh",
        "audit_retained_package": "APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE=<tar.gz> APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256=<sha256> APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT=1 ./scripts/test-production-hardening-provider-workflow-artifact-import.sh",
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not ready:
    print(f"apolysis-production-hardening: provider workflow artifact import failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing_requirements), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: provider workflow artifact import audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_REPORT=$report
EOF

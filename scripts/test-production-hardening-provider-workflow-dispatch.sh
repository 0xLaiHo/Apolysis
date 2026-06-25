#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-provider-workflow-dispatch.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-provider-workflow-dispatch-report.json"
dispatch_command_file="$output_dir/gh-workflow-dispatch-command.sh"
require_ready="${APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" "$dispatch_command_file" "$require_ready" <<'PY'
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
dispatch_command_path = Path(sys.argv[3])
require_ready = sys.argv[4] == "1"
workflow_file = repo_root / ".github" / "workflows" / "production-hardening-final-provider-evidence.yml"

def run(command: list[str]) -> tuple[int, str]:
    process = subprocess.run(
        command,
        cwd=repo_root,
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

def bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}

def valid_repo(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value))

def valid_ref(value: str) -> bool:
    return bool(value) and not value.startswith("-") and "\n" not in value

def valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))

def valid_run_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d+", value))

def valid_url(value: str) -> bool:
    return bool(re.fullmatch(r"https://[^\s?#]+", value))

mode = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_MODE", "dry-run")
dispatch_confirmed = os.environ.get("APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH", "0") == "1"
repo = origin_repo()
github_ref = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_GITHUB_REF", "production-hardening")

run_aws_kms = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_RUN_AWS_KMS", True)
run_aws_kms_bootstrap = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_RUN_AWS_KMS_BOOTSTRAP", True)
aws_kms_bootstrap_mode = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_AWS_KMS_BOOTSTRAP_MODE", "inspect")
confirm_aws_kms_key_creation = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_CONFIRM_AWS_KMS_KEY_CREATION", False)
run_gke_mesh = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_RUN_GKE_MESH", False)
retained_signing_provider_artifact = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_RETAINED_SIGNING_PROVIDER_ARTIFACT", False)
retained_managed_mesh_provider_artifact = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_RETAINED_MANAGED_MESH_PROVIDER_ARTIFACT", True)
assemble_final_bundle = bool_env("APOLYSIS_PRODUCTION_HARDENING_DISPATCH_ASSEMBLE_FINAL_BUNDLE", True)
retained_provider_artifact_run_id = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_RUN_ID", "")
retained_provider_artifact_url = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_URL", "")
retained_provider_artifact_sha256 = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_SHA256", "")

workflow_text = workflow_file.read_text(encoding="utf-8") if workflow_file.is_file() else ""
workflow_contract = {
    "exists": workflow_file.is_file(),
    "workflow_dispatch": "workflow_dispatch:" in workflow_text,
    "run_aws_kms": "run_aws_kms:" in workflow_text,
    "run_aws_kms_bootstrap": "run_aws_kms_bootstrap:" in workflow_text,
    "aws_kms_bootstrap_mode": "aws_kms_bootstrap_mode:" in workflow_text,
    "confirm_aws_kms_key_creation": "confirm_aws_kms_key_creation:" in workflow_text,
    "retained_signing_provider_artifact": "retained_signing_provider_artifact:" in workflow_text,
    "retained_managed_mesh_provider_artifact": "retained_managed_mesh_provider_artifact:" in workflow_text,
    "retained_provider_artifact_run_id": "retained_provider_artifact_run_id:" in workflow_text,
    "retained_provider_artifact_url": "retained_provider_artifact_url:" in workflow_text,
    "retained_provider_artifact_sha256": "retained_provider_artifact_sha256:" in workflow_text,
    "assemble_final_bundle": "assemble_final_bundle:" in workflow_text,
}
workflow_contract_ready = all(workflow_contract.values())

tools = {
    name: {"available": bool(path := shutil.which(name)), "path": path or ""}
    for name in ("gh", "git", "python3")
}

github_token_environment_present = any(bool(os.environ.get(name)) for name in ("GH_TOKEN", "GITHUB_TOKEN"))
gh_authenticated = False
gh_error_hint = ""
if tools["gh"]["available"]:
    rc, output = run(["gh", "auth", "status", "--hostname", "github.com"])
    gh_authenticated = rc == 0 or github_token_environment_present
    if rc != 0 and not github_token_environment_present:
        gh_error_hint = output[:4000]

workflow_inputs = {
    "run_aws_kms": run_aws_kms,
    "run_aws_kms_bootstrap": run_aws_kms_bootstrap,
    "aws_kms_bootstrap_mode": aws_kms_bootstrap_mode,
    "confirm_aws_kms_key_creation": confirm_aws_kms_key_creation,
    "run_gke_mesh": run_gke_mesh,
    "retained_signing_provider_artifact": retained_signing_provider_artifact,
    "retained_managed_mesh_provider_artifact": retained_managed_mesh_provider_artifact,
    "retained_provider_artifact_run_id": retained_provider_artifact_run_id,
    "retained_provider_artifact_url": retained_provider_artifact_url,
    "retained_provider_artifact_sha256_present": bool(retained_provider_artifact_sha256),
    "assemble_final_bundle": assemble_final_bundle,
}

missing_requirements: list[str] = []
if mode not in {"dry-run", "dispatch"}:
    missing_requirements.append("APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_MODE_dry-run_or_dispatch")
if not valid_repo(repo):
    missing_requirements.append("github_repository")
if not valid_ref(github_ref):
    missing_requirements.append("github_ref")
if not workflow_contract_ready:
    missing_requirements.append("workflow_contract")
if aws_kms_bootstrap_mode not in {"inspect", "ensure"}:
    missing_requirements.append("aws_kms_bootstrap_mode_inspect_or_ensure")
if retained_provider_artifact_url and not valid_url(retained_provider_artifact_url):
    missing_requirements.append("retained_provider_artifact_url_public_https_without_query_or_fragment")
if retained_provider_artifact_url and not valid_sha256(retained_provider_artifact_sha256):
    missing_requirements.append("retained_provider_artifact_sha256")
if retained_provider_artifact_sha256 and not retained_provider_artifact_url:
    missing_requirements.append("retained_provider_artifact_url")
if retained_provider_artifact_run_id and not valid_run_id(retained_provider_artifact_run_id):
    missing_requirements.append("retained_provider_artifact_run_id")
if assemble_final_bundle and not (retained_provider_artifact_run_id or retained_provider_artifact_url):
    missing_requirements.append("retained_provider_artifact_source_for_final_bundle")
if not (run_aws_kms or retained_signing_provider_artifact):
    missing_requirements.append("signing_provider_evidence_path")
if not (run_gke_mesh or retained_managed_mesh_provider_artifact):
    missing_requirements.append("managed_mesh_provider_evidence_path")
if mode == "dispatch":
    if not dispatch_confirmed:
        missing_requirements.append("APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH")
    if not tools["gh"]["available"]:
        missing_requirements.append("gh_cli")
    if tools["gh"]["available"] and not gh_authenticated:
        missing_requirements.append("gh_authenticated_session")

command = [
    "gh",
    "workflow",
    "run",
    "production-hardening-final-provider-evidence.yml",
    "--repo",
    repo or "<owner>/<repo>",
    "--ref",
    github_ref or "production-hardening",
    "-f",
    f"run_aws_kms={str(run_aws_kms).lower()}",
    "-f",
    f"run_aws_kms_bootstrap={str(run_aws_kms_bootstrap).lower()}",
    "-f",
    f"aws_kms_bootstrap_mode={aws_kms_bootstrap_mode}",
    "-f",
    f"confirm_aws_kms_key_creation={str(confirm_aws_kms_key_creation).lower()}",
    "-f",
    f"run_gke_mesh={str(run_gke_mesh).lower()}",
    "-f",
    f"retained_signing_provider_artifact={str(retained_signing_provider_artifact).lower()}",
    "-f",
    f"retained_managed_mesh_provider_artifact={str(retained_managed_mesh_provider_artifact).lower()}",
    "-f",
    f"assemble_final_bundle={str(assemble_final_bundle).lower()}",
]
if retained_provider_artifact_run_id:
    command.extend(["-f", f"retained_provider_artifact_run_id={retained_provider_artifact_run_id}"])
if retained_provider_artifact_url:
    command.extend(["-f", f"retained_provider_artifact_url={retained_provider_artifact_url}"])
    command.extend(["-f", f"retained_provider_artifact_sha256={retained_provider_artifact_sha256}"])

dispatch_command = " ".join(shlex.quote(part) for part in command)
dispatch_command_path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + dispatch_command + "\n", encoding="utf-8")
dispatch_command_path.chmod(0o700)

missing_requirements = list(dict.fromkeys(missing_requirements))
dispatch_plan_ready = not missing_requirements or (
    mode == "dispatch" and missing_requirements == ["APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH"]
)

workflow_dispatch_attempted = False
workflow_dispatched = False
dispatch_output = ""
if mode == "dispatch" and not missing_requirements:
    workflow_dispatch_attempted = True
    rc, dispatch_output = run(command)
    if rc == 0:
        workflow_dispatched = True
    else:
        missing_requirements.append("gh_workflow_run_succeeded")
        gh_error_hint = dispatch_output[:4000]

ready = not missing_requirements
report = {
    "schema_version": 1,
    "phase": "production-hardening.provider-workflow-dispatch",
    "audit_completed": True,
    "passed": ready or not require_ready,
    "fail_closed_required": require_ready,
    "provider_workflow_dispatch_ready": ready,
    "dispatch_plan_ready": dispatch_plan_ready,
    "workflow_dispatch_attempted": workflow_dispatch_attempted,
    "workflow_dispatched": workflow_dispatched,
    "mode": mode,
    "dispatch_confirmed": dispatch_confirmed,
    "repository": repo,
    "github_ref": github_ref,
    "workflow_file": str(workflow_file),
    "workflow_contract_ready": workflow_contract_ready,
    "workflow_contract": workflow_contract,
    "workflow_inputs": workflow_inputs,
    "dispatch_command_path": str(dispatch_command_path),
    "dispatch_command": dispatch_command,
    "missing_requirements": missing_requirements,
    "tools": tools,
    "gh_authenticated": gh_authenticated,
    "github_token_environment_present": github_token_environment_present,
    "gh_error_hint": gh_error_hint,
    "dispatch_output_hint": dispatch_output[:4000],
    "notes": [
        "No secret values are recorded in this report.",
        "The default dry-run mode only renders and validates the workflow dispatch command.",
        "Set APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_MODE=dispatch and APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH=1 before gh workflow run is executed.",
        "Retained provider package dispatch requires retained_provider_artifact_sha256 whenever retained_provider_artifact_url is set.",
        "Retained provider artifact URLs must be public HTTPS URLs without query strings or fragments so signed URL secrets are not recorded.",
        "This gate does not create signing evidence; the dispatched workflow must still run production-hardening.aws-kms-signing or consume retained external HSM evidence.",
    ],
    "next_commands": {
        "authenticate_gh": "gh auth login --hostname github.com --git-protocol ssh --scopes repo,workflow --skip-ssh-key --web",
        "authenticate_gh_with_token": "printf '%s\\n' \"$GH_TOKEN\" | gh auth login --with-token --hostname github.com --git-protocol ssh",
        "dispatch_dry_run_required": "APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH=1 ./scripts/test-production-hardening-provider-workflow-dispatch.sh",
        "dispatch_confirmed": "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_MODE=dispatch APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH=1 APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH=1 ./scripts/test-production-hardening-provider-workflow-dispatch.sh",
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not ready:
    print(f"apolysis-production-hardening: provider workflow dispatch failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing_requirements), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: provider workflow dispatch audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_REPORT=$report
EOF

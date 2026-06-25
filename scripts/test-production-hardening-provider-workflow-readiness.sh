#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_READINESS_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-provider-workflow-readiness.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-provider-workflow-readiness-report.json"
secret_list="$output_dir/github-secret-names.txt"
variable_list="$output_dir/github-variable-names.txt"
workflow_file="$repo_root/.github/workflows/production-hardening-final-provider-evidence.yml"
require_ready="${APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_READINESS:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" "$secret_list" "$variable_list" "$workflow_file" "$require_ready" <<'PY'
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
secret_list_path = Path(sys.argv[3])
variable_list_path = Path(sys.argv[4])
workflow_file = Path(sys.argv[5])
require_ready = sys.argv[6] == "1"

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

repo = origin_repo()
gh_path = shutil.which("gh") or ""
git_path = shutil.which("git") or ""
python_path = shutil.which("python3") or ""
tools = {
    "gh": {"available": bool(gh_path), "path": gh_path},
    "git": {"available": bool(git_path), "path": git_path},
    "python3": {"available": bool(python_path), "path": python_path},
}

workflow_text = workflow_file.read_text(encoding="utf-8") if workflow_file.is_file() else ""
workflow_contract = {
    "exists": workflow_file.is_file(),
    "workflow_dispatch": "workflow_dispatch:" in workflow_text,
    "run_aws_kms": "run_aws_kms:" in workflow_text,
    "run_aws_kms_bootstrap": "run_aws_kms_bootstrap:" in workflow_text,
    "aws_kms_bootstrap_mode": "aws_kms_bootstrap_mode:" in workflow_text,
    "confirm_aws_kms_key_creation": "confirm_aws_kms_key_creation:" in workflow_text,
    "production_hardening_aws_kms_signing": "scripts/test-production-hardening-aws-kms-signing.sh" in workflow_text,
    "production_hardening_aws_kms_bootstrap": "scripts/test-production-hardening-aws-kms-signer-bootstrap.sh" in workflow_text,
    "retained_provider_artifact_url": "retained_provider_artifact_url:" in workflow_text,
    "retained_provider_artifact_sha256": "retained_provider_artifact_sha256:" in workflow_text,
}
workflow_contract_ready = all(workflow_contract.values())

github_token_environment_present = any(
    bool(os.environ.get(name))
    for name in ("GH_TOKEN", "GITHUB_TOKEN")
)
gh_stored_auth = False
gh_authenticated = False
inspected_repository_settings = False
secret_inventory_read = False
variable_inventory_read = False
secret_names: set[str] = set()
variable_names: set[str] = set()
gh_error = ""

if gh_path and repo:
    rc, _ = run(["gh", "auth", "status", "--hostname", "github.com"])
    gh_stored_auth = rc == 0
    if gh_stored_auth or github_token_environment_present:
        rc, output = run(["gh", "secret", "list", "--repo", repo])
        if rc == 0:
            secret_inventory_read = True
            secret_names = {line.split()[0] for line in output.splitlines() if line.strip()}
            secret_list_path.write_text("\n".join(sorted(secret_names)) + "\n", encoding="utf-8")
        else:
            gh_error = output[:4000]
        rc_vars, output_vars = run(["gh", "variable", "list", "--repo", repo])
        if rc_vars == 0:
            variable_inventory_read = True
            variable_names = {line.split()[0] for line in output_vars.splitlines() if line.strip()}
            variable_list_path.write_text("\n".join(sorted(variable_names)) + "\n", encoding="utf-8")
        else:
            gh_error = (gh_error + "\n" + output_vars)[:4000]
        inspected_repository_settings = secret_inventory_read and variable_inventory_read
    gh_authenticated = gh_stored_auth or (github_token_environment_present and inspected_repository_settings)

required_secrets = {
    "ProductionHardening_AWS_ROLE_TO_ASSUME": "AWS OIDC role assumed by the production-hardening.aws-kms-signing signing job",
}
optional_key_secret = "ProductionHardening_AWS_KMS_KEY_ID"
required_variables = {
    "ProductionHardening_AWS_REGION": "AWS region for KMS and credential configuration",
}
optional_key_variable = "ProductionHardening_AWS_KMS_ALIAS"

secret_status = {
    name: name in secret_names
    for name in [*required_secrets.keys(), optional_key_secret]
}
variable_status = {
    name: name in variable_names
    for name in [*required_variables.keys(), optional_key_variable]
}

aws_oidc_ready = secret_status["ProductionHardening_AWS_ROLE_TO_ASSUME"]
aws_region_ready = variable_status["ProductionHardening_AWS_REGION"]
aws_key_reference_ready = secret_status[optional_key_secret] or variable_status[optional_key_variable]
repo_settings_ready = inspected_repository_settings and aws_oidc_ready and aws_region_ready and aws_key_reference_ready
provider_workflow_ready = workflow_contract_ready and repo_settings_ready

missing_requirements: list[str] = []
if not repo:
    missing_requirements.append("github_repository")
if not gh_path:
    missing_requirements.append("gh_cli")
if gh_path and not gh_authenticated:
    missing_requirements.append("gh_authenticated_session")
if gh_path and gh_authenticated and not inspected_repository_settings:
    missing_requirements.append("github_repository_settings_read")
if not workflow_contract_ready:
    missing_requirements.append("workflow_contract")
if inspected_repository_settings and not aws_oidc_ready:
    missing_requirements.append("secret:ProductionHardening_AWS_ROLE_TO_ASSUME")
if inspected_repository_settings and not aws_region_ready:
    missing_requirements.append("variable:ProductionHardening_AWS_REGION")
if inspected_repository_settings and not aws_key_reference_ready:
    missing_requirements.append("secret:ProductionHardening_AWS_KMS_KEY_ID_or_variable:ProductionHardening_AWS_KMS_ALIAS")

dispatch_command = ""
if repo:
    dispatch_command = (
        "gh workflow run production-hardening-final-provider-evidence.yml "
        f"--repo {repo} "
        "--ref production-hardening "
        "-f run_aws_kms=true "
        "-f run_aws_kms_bootstrap=true "
        "-f aws_kms_bootstrap_mode=inspect "
        "-f confirm_aws_kms_key_creation=false "
        "-f run_gke_mesh=false "
        "-f retained_managed_mesh_provider_artifact=true "
        "-f assemble_final_bundle=true "
        "-f retained_provider_artifact_url=<retained-provider-artifacts-url> "
        "-f retained_provider_artifact_sha256=<sha256>"
    )

report = {
    "schema_version": 1,
    "phase": "production-hardening.provider-workflow-readiness",
    "audit_completed": True,
    "passed": provider_workflow_ready or not require_ready,
    "fail_closed_required": require_ready,
    "provider_workflow_ready": provider_workflow_ready,
    "repository": repo,
    "workflow_file": str(workflow_file),
    "workflow_contract_ready": workflow_contract_ready,
    "workflow_contract": workflow_contract,
    "inspected_repository_settings": inspected_repository_settings,
    "secret_status": secret_status,
    "variable_status": variable_status,
    "aws_oidc_ready": aws_oidc_ready,
    "aws_region_ready": aws_region_ready,
    "aws_key_reference_ready": aws_key_reference_ready,
    "missing_requirements": missing_requirements,
    "tools": tools,
    "gh_authenticated": gh_authenticated,
    "gh_stored_auth": gh_stored_auth,
    "github_token_environment_present": github_token_environment_present,
    "secret_inventory_read": secret_inventory_read,
    "variable_inventory_read": variable_inventory_read,
    "gh_error_hint": gh_error,
    "next_commands": {
        "authenticate_gh": "gh auth login --hostname github.com --git-protocol ssh --scopes repo,workflow --skip-ssh-key --web",
        "authenticate_gh_with_token": "printf '%s\\n' \"$GH_TOKEN\" | gh auth login --with-token --hostname github.com --git-protocol ssh",
        "set_aws_oidc_role_secret": f"gh secret set ProductionHardening_AWS_ROLE_TO_ASSUME --repo {repo}",
        "set_aws_region_variable": f"gh variable set ProductionHardening_AWS_REGION --repo {repo} --body <aws-region>",
        "set_existing_kms_key_secret": f"gh secret set ProductionHardening_AWS_KMS_KEY_ID --repo {repo}",
        "set_bootstrap_alias_variable": f"gh variable set ProductionHardening_AWS_KMS_ALIAS --repo {repo} --body alias/apolysis/production-hardening-release-signing",
        "dispatch_workflow": dispatch_command,
    },
    "notes": [
        "No secret values are recorded in this report.",
        "GitHub secret and variable inventories contain names only.",
        "This gate does not create signing evidence; production-hardening.aws-kms-signing still has to run aws kms sign.",
        "For headless use, set GH_TOKEN in the shell and use next_commands.authenticate_gh_with_token; do not store token values in this report.",
        "Use retained managed-mesh and retained WORM/registry artifacts when only the signing evidence remains.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not provider_workflow_ready:
    print(f"apolysis-production-hardening: provider workflow readiness failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing_requirements), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: provider workflow readiness audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_READINESS_REPORT=$report
EOF

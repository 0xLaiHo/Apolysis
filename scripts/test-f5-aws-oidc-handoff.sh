#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_AWS_OIDC_HANDOFF_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-aws-oidc-handoff.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f5-aws-oidc-handoff-report.json"
trust_policy="$output_dir/aws-github-oidc-trust-policy.json"
kms_policy="$output_dir/aws-kms-signing-policy.json"
require_ready="${APOLYSIS_REQUIRE_F5_AWS_OIDC_HANDOFF:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" "$trust_policy" "$kms_policy" "$require_ready" <<'PY'
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
trust_policy_path = Path(sys.argv[3])
kms_policy_path = Path(sys.argv[4])
require_ready = sys.argv[5] == "1"

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
    configured = os.environ.get("APOLYSIS_F5_GITHUB_REPO", "")
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

def valid_account_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d{12}", value))

def key_arn_from_env(region: str, account_id: str) -> str:
    key_arn = os.environ.get("APOLYSIS_F5_AWS_KMS_KEY_ARN", "")
    if key_arn:
        return key_arn
    key_id = os.environ.get("APOLYSIS_F5_AWS_KMS_KEY_ID", "")
    if key_id.startswith("arn:aws:kms:"):
        return key_id
    if region and account_id and re.fullmatch(r"[0-9a-fA-F-]{36}", key_id):
        return f"arn:aws:kms:{region}:{account_id}:key/{key_id}"
    return ""

repo = origin_repo()
github_ref = os.environ.get("APOLYSIS_F5_GITHUB_REF", "refs/heads/f5-production-hardening")
account_id = os.environ.get("APOLYSIS_F5_AWS_ACCOUNT_ID", "")
region = (
    os.environ.get("APOLYSIS_F5_AWS_REGION")
    or os.environ.get("AWS_REGION")
    or os.environ.get("AWS_DEFAULT_REGION")
    or ""
)
role_name = os.environ.get("APOLYSIS_F5_AWS_ROLE_NAME", "apolysis-f5-provider-evidence")
policy_name = os.environ.get("APOLYSIS_F5_AWS_POLICY_NAME", "ApolysisF5KmsSigning")
algorithm = os.environ.get("APOLYSIS_F5_AWS_KMS_SIGNING_ALGORITHM", "RSASSA_PKCS1_V1_5_SHA_256")
kms_key_arn = key_arn_from_env(region, account_id)

role_arn = f"arn:aws:iam::{account_id}:role/{role_name}" if valid_account_id(account_id) else ""
oidc_provider_arn = (
    f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
    if valid_account_id(account_id)
    else "arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com"
)
github_subject = f"repo:{repo}:ref:{github_ref}" if repo and github_ref else ""

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Federated": oidc_provider_arn},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": github_subject or "repo:<owner>/<repo>:ref:refs/heads/f5-production-hardening",
                }
            },
        }
    ],
}

kms_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ApolysisF5KmsPublicKeyRead",
            "Effect": "Allow",
            "Action": ["kms:DescribeKey", "kms:GetPublicKey"],
            "Resource": kms_key_arn or "arn:aws:kms:<region>:<account-id>:key/<key-id>",
        },
        {
            "Sid": "ApolysisF5KmsSign",
            "Effect": "Allow",
            "Action": ["kms:Sign"],
            "Resource": kms_key_arn or "arn:aws:kms:<region>:<account-id>:key/<key-id>",
            "Condition": {"StringEquals": {"kms:SigningAlgorithm": algorithm}},
        },
    ],
}

trust_policy_path.write_text(json.dumps(trust_policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")
kms_policy_path.write_text(json.dumps(kms_policy, indent=2, sort_keys=True) + "\n", encoding="utf-8")

missing_requirements: list[str] = []
if not valid_repo(repo):
    missing_requirements.append("github_repository")
if not github_ref.startswith("refs/"):
    missing_requirements.append("github_ref")
if not valid_account_id(account_id):
    missing_requirements.append("APOLYSIS_F5_AWS_ACCOUNT_ID")
if not region:
    missing_requirements.append("APOLYSIS_F5_AWS_REGION")
if not role_name:
    missing_requirements.append("APOLYSIS_F5_AWS_ROLE_NAME")
if not kms_key_arn:
    missing_requirements.append("APOLYSIS_F5_AWS_KMS_KEY_ARN_or_arn_APOLYSIS_F5_AWS_KMS_KEY_ID")
if algorithm != "RSASSA_PKCS1_V1_5_SHA_256":
    missing_requirements.append("RSASSA_PKCS1_V1_5_SHA_256")

ready = not missing_requirements
tools = {
    name: {"available": bool(path := shutil.which(name)), "path": path or ""}
    for name in ("aws", "gh", "git", "python3")
}

next_commands = {
    "create_oidc_provider_if_missing": (
        "aws iam create-open-id-connect-provider "
        "--url https://token.actions.githubusercontent.com "
        "--client-id-list sts.amazonaws.com "
        "--thumbprint-list <github-actions-oidc-thumbprint>"
    ),
    "create_role": f"aws iam create-role --role-name {role_name} --assume-role-policy-document file://{trust_policy_path}",
    "put_role_policy": f"aws iam put-role-policy --role-name {role_name} --policy-name {policy_name} --policy-document file://{kms_policy_path}",
    "set_github_role_secret": f"gh secret set F5_AWS_ROLE_TO_ASSUME --repo {repo} --body {role_arn or '<role-arn>'}",
    "set_github_region_variable": f"gh variable set F5_AWS_REGION --repo {repo} --body {region or '<aws-region>'}",
    "set_github_kms_key_secret": f"gh secret set F5_AWS_KMS_KEY_ID --repo {repo} --body {kms_key_arn or '<kms-key-arn>'}",
}

report = {
    "schema_version": 1,
    "phase": "F5.44",
    "audit_completed": True,
    "passed": ready or not require_ready,
    "fail_closed_required": require_ready,
    "aws_oidc_handoff_ready": ready,
    "repository": repo,
    "github_ref": github_ref,
    "aws_region": region,
    "aws_account_id_present": bool(account_id),
    "role_name": role_name,
    "role_arn": role_arn,
    "oidc_provider_arn": oidc_provider_arn,
    "kms_key_arn_present": bool(kms_key_arn),
    "kms_signing_algorithm": algorithm,
    "trust_policy_path": str(trust_policy_path),
    "kms_policy_path": str(kms_policy_path),
    "missing_requirements": missing_requirements,
    "tools": tools,
    "next_commands": next_commands,
    "notes": [
        "No secret values are recorded in this report.",
        "This gate prepares AWS IAM and GitHub repository handoff material; it does not authenticate AWS, create IAM roles, or produce signing evidence.",
        "Use the resulting F5_AWS_ROLE_TO_ASSUME, F5_AWS_REGION, and F5_AWS_KMS_KEY_ID repository settings before running the F5 final-provider workflow.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not ready:
    print(f"apolysis-f5: AWS OIDC handoff failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing_requirements), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-f5: AWS OIDC handoff audit written ($output_dir)
APOLYSIS_F5_AWS_OIDC_HANDOFF_REPORT=$report
EOF

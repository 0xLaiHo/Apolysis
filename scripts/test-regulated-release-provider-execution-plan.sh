#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_PROVIDER_EXECUTION_PLAN_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-provider-execution-plan.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-provider-execution-plan-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_PROVIDER_EXECUTION_PLAN:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-regulated_release: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" "$require_ready" <<'PY'
import json
import os
import shutil
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

signing_provider = os.environ.get("APOLYSIS_REGULATED_RELEASE_SIGNING_PROVIDER", "auto")
artifact_source = (
    os.environ.get("APOLYSIS_REGULATED_RELEASE_ARTIFACT_SOURCE")
    or os.environ.get("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_SOURCE")
    or "auto"
)
closure_mode = os.environ.get("APOLYSIS_REGULATED_RELEASE_CLOSURE_MODE", "audit")

allowed_signing = {"auto", "aws_kms", "external_hsm", "retained_signing"}
allowed_artifacts = {"auto", "local_artifact_root", "workflow_download", "retained_package"}
allowed_closure = {"audit", "final_provider_closure"}

def bool_env(name: str) -> bool:
    return bool(os.environ.get(name, ""))

def env_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return ""

def tool(name: str) -> dict:
    path = shutil.which(name) or ""
    return {"available": bool(path), "path": path}

errors: list[str] = []
if signing_provider not in allowed_signing:
    errors.append("APOLYSIS_REGULATED_RELEASE_SIGNING_PROVIDER")
if artifact_source not in allowed_artifacts:
    errors.append("APOLYSIS_REGULATED_RELEASE_ARTIFACT_SOURCE")
if closure_mode not in allowed_closure:
    errors.append("APOLYSIS_REGULATED_RELEASE_CLOSURE_MODE")

aws_region = (
    os.environ.get("APOLYSIS_PRODUCTION_HARDENING_AWS_REGION")
    or os.environ.get("AWS_REGION")
    or os.environ.get("AWS_DEFAULT_REGION")
    or ""
)
aws_kms_key = bool_env("APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID") or bool_env("APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_ALIAS")
aws_role_or_credential_hint = (
    bool_env("APOLYSIS_PRODUCTION_HARDENING_AWS_ROLE_TO_ASSUME")
    or bool_env("AWS_ACCESS_KEY_ID")
    or bool_env("AWS_PROFILE")
    or bool_env("AWS_WEB_IDENTITY_TOKEN_FILE")
    or (Path.home() / ".aws").is_dir()
)
aws_kms_ready = tool("aws")["available"] and bool(aws_region) and aws_kms_key and aws_role_or_credential_hint

external_hsm_ready = (
    tool("pkcs11-tool")["available"]
    and bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE")
    and (bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL") or bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_SLOT"))
    and bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL")
    and (
        bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE")
        or bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN")
        or os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_ALLOW_INTERACTIVE_PIN", "0") == "1"
    )
)

retained_signing_evidence = env_value("APOLYSIS_REGULATED_RELEASE_SIGNING_EVIDENCE", "APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE")
retained_signing_report = env_value("APOLYSIS_REGULATED_RELEASE_SIGNING_REPORT", "APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT")
retained_signing_ready = (
    bool(retained_signing_evidence)
    and bool(retained_signing_report)
    and Path(retained_signing_evidence).is_file()
    and Path(retained_signing_report).is_file()
)

signing_candidates = {
    "aws_kms": aws_kms_ready,
    "external_hsm": external_hsm_ready,
    "retained_signing": retained_signing_ready,
}
if signing_provider == "auto":
    selected_signing_provider = next((name for name, ready in signing_candidates.items() if ready), "aws_kms")
else:
    selected_signing_provider = signing_provider
signing_plan_ready = signing_candidates.get(selected_signing_provider, False)

local_artifact_root = os.environ.get("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT") or os.environ.get(
    "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT", ""
)
workflow_run_id = os.environ.get("APOLYSIS_REGULATED_RELEASE_PROVIDER_WORKFLOW_RUN_ID") or os.environ.get(
    "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID", ""
)
retained_package = os.environ.get("APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE") or os.environ.get(
    "APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE", ""
)
retained_package_sha256 = os.environ.get("APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256") or os.environ.get(
    "APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256", ""
)

local_artifact_ready = bool(local_artifact_root) and Path(local_artifact_root).is_dir()
workflow_download_ready = bool(workflow_run_id)
retained_package_ready = (
    bool(retained_package)
    and bool(retained_package_sha256)
    and Path(retained_package).is_file()
)

artifact_candidates = {
    "local_artifact_root": local_artifact_ready,
    "workflow_download": workflow_download_ready,
    "retained_package": retained_package_ready,
}
if artifact_source == "auto":
    selected_artifact_source = next((name for name, ready in artifact_candidates.items() if ready), "workflow_download")
else:
    selected_artifact_source = artifact_source
artifact_source_ready = artifact_candidates.get(selected_artifact_source, False)

closure_plan_ready = closure_mode == "final_provider_closure" or os.environ.get(
    "APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE", "0"
) == "1"

missing_requirements: list[str] = []
if errors:
    missing_requirements.extend(errors)
if not signing_plan_ready:
    missing_requirements.append(f"{selected_signing_provider}_signing_plan")
if not artifact_source_ready:
    missing_requirements.append(f"{selected_artifact_source}_artifact_source")
if not closure_plan_ready:
    missing_requirements.append("APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE")

provider_execution_plan_ready = not missing_requirements
passed = provider_execution_plan_ready or not require_ready

command_templates = {
    "aws_kms_signing": (
        "APOLYSIS_REGULATED_RELEASE_SIGNING_PROVIDER=aws_kms APOLYSIS_PRODUCTION_HARDENING_AWS_REGION=<region> "
        "APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID=<key-or-arn> APOLYSIS_PRODUCTION_HARDENING_AWS_ROLE_TO_ASSUME=<role-arn> "
        "./scripts/test-regulated-release-provider-execution-plan.sh"
    ),
    "external_hsm_signing": (
        "APOLYSIS_REGULATED_RELEASE_SIGNING_PROVIDER=external_hsm "
        "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE=<module> "
        "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL=<token> "
        "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL=<key> "
        "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE=<pin-file> ./scripts/test-regulated-release-provider-execution-plan.sh"
    ),
    "local_artifact_root": (
        "APOLYSIS_REGULATED_RELEASE_ARTIFACT_SOURCE=local_artifact_root "
        "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT=<artifact-root> "
        "./scripts/test-regulated-release-provider-execution-plan.sh"
    ),
    "workflow_download": (
        "APOLYSIS_REGULATED_RELEASE_ARTIFACT_SOURCE=workflow_download "
        "APOLYSIS_REGULATED_RELEASE_PROVIDER_WORKFLOW_RUN_ID=<run-id> "
        "APOLYSIS_CONFIRM_REGULATED_RELEASE_PROVIDER_ARTIFACT_DOWNLOAD=1 ./scripts/test-regulated-release-provider-execution-plan.sh"
    ),
    "retained_package": (
        "APOLYSIS_REGULATED_RELEASE_ARTIFACT_SOURCE=retained_package "
        "APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE=<tar.gz> "
        "APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256=<sha256> "
        "./scripts/test-regulated-release-provider-execution-plan.sh"
    ),
    "execute_regulated_release": (
        "APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 "
        "APOLYSIS_REQUIRE_REGULATED_RELEASE=1 ./scripts/test-regulated-release.sh"
    ),
}

report = {
    "schema_version": 1,
    "phase": "regulated-release.provider-execution-plan",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "provider_execution_plan_ready": provider_execution_plan_ready,
    "selected_signing_provider": selected_signing_provider,
    "selected_artifact_source": selected_artifact_source,
    "selected_closure_mode": "final_provider_closure" if closure_plan_ready else closure_mode,
    "signing_provider_plan": {
        "requested": signing_provider,
        "selected": selected_signing_provider,
        "ready": signing_plan_ready,
        "aws_kms": {
            "tool_available": tool("aws")["available"],
            "region_present": bool(aws_region),
            "kms_key_or_alias_present": aws_kms_key,
            "role_or_credential_hint_present": aws_role_or_credential_hint,
        },
        "external_hsm": {
            "tool_available": tool("pkcs11-tool")["available"],
            "module_present": bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE"),
            "token_or_slot_present": bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL")
            or bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_SLOT"),
            "key_label_present": bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL"),
            "pin_source_or_interactive_present": bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE")
            or bool_env("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN")
            or os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_ALLOW_INTERACTIVE_PIN", "0") == "1",
        },
        "retained_signing": {
            "evidence_path_present": bool(retained_signing_evidence),
            "report_path_present": bool(retained_signing_report),
            "evidence_files_exist": retained_signing_ready,
        },
    },
    "artifact_source_plan": {
        "requested": artifact_source,
        "selected": selected_artifact_source,
        "ready": artifact_source_ready,
        "local_artifact_root": {
            "path_present": bool(local_artifact_root),
            "path_exists": local_artifact_ready,
        },
        "workflow_download": {
            "run_id_present": bool(workflow_run_id),
            "download_confirmation_required": "APOLYSIS_CONFIRM_REGULATED_RELEASE_PROVIDER_ARTIFACT_DOWNLOAD=1",
        },
        "retained_package": {
            "package_present": bool(retained_package),
            "sha256_present": bool(retained_package_sha256),
            "package_exists": retained_package_ready,
        },
    },
    "closure_plan": {
        "requested": closure_mode,
        "ready": closure_plan_ready,
        "requires": "APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1",
    },
    "missing_requirements": [] if provider_execution_plan_ready else missing_requirements,
    "command_templates": command_templates,
    "notes": [
        "No secret values are recorded in this report.",
        "This gate creates a RegulatedRelease-native execution plan over historical ProductionHardening provider artifact contracts.",
        "Use the command templates as handoff commands; replace placeholders outside retained reports.",
        "Default audit mode only plans provider execution and does not call AWS, HSM, GitHub, or Kubernetes APIs.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not provider_execution_plan_ready:
    print(f"apolysis-regulated_release: provider execution plan failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: provider execution plan audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_PROVIDER_EXECUTION_PLAN_REPORT=$report
EOF

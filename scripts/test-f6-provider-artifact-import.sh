#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F6_PROVIDER_ARTIFACT_IMPORT_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f6-provider-artifact-import.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f6-provider-artifact-import-report.json"
require_ready="${APOLYSIS_REQUIRE_F6_PROVIDER_ARTIFACT_IMPORT:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f6: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$output_dir" "$report" "$require_ready" <<'PY'
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
report_path = Path(sys.argv[3])
require_ready = sys.argv[4] == "1"

f5_gate = repo_root / "scripts/test-f5-provider-workflow-artifact-import.sh"
downstream_dir = output_dir / "f5-provider-workflow-artifact-import"
downstream_report_path = downstream_dir / "apolysis-f5-provider-workflow-artifact-import-report.json"

allowed_sources = {"auto", "local_artifact_root", "workflow_download", "retained_package"}

def env_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return ""

def bool_env(name: str) -> bool:
    return os.environ.get(name, "0") == "1"

def valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))

requested_source = env_value("APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE", "APOLYSIS_F6_ARTIFACT_SOURCE") or "auto"
local_artifact_root = env_value(
    "APOLYSIS_F6_PROVIDER_ARTIFACT_ROOT",
    "APOLYSIS_F5_PROVIDER_WORKFLOW_ARTIFACT_ROOT",
)
workflow_run_id = env_value(
    "APOLYSIS_F6_PROVIDER_WORKFLOW_RUN_ID",
    "APOLYSIS_F5_PROVIDER_WORKFLOW_RUN_ID",
)
retained_package = env_value(
    "APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE",
    "APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE",
)
retained_package_sha256 = env_value(
    "APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256",
    "APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256",
)
download_confirmed = bool_env("APOLYSIS_CONFIRM_F6_PROVIDER_ARTIFACT_DOWNLOAD") or bool_env(
    "APOLYSIS_CONFIRM_F5_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD"
)

source_errors: list[str] = []
if requested_source not in allowed_sources:
    source_errors.append("APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE")

source_candidates = {
    "local_artifact_root": bool(local_artifact_root) and Path(local_artifact_root).is_dir(),
    "retained_package": (
        bool(retained_package)
        and bool(retained_package_sha256)
        and Path(retained_package).is_file()
        and valid_sha256(retained_package_sha256)
    ),
    "workflow_download": bool(workflow_run_id) and download_confirmed,
}

if requested_source == "auto":
    selected_source = next((name for name, ready in source_candidates.items() if ready), "workflow_download")
elif requested_source in allowed_sources:
    selected_source = requested_source
else:
    selected_source = "workflow_download"

source_missing: list[str] = []
if selected_source == "local_artifact_root":
    if not local_artifact_root:
        source_missing.append("APOLYSIS_F6_PROVIDER_ARTIFACT_ROOT")
    elif not Path(local_artifact_root).is_dir():
        source_missing.append("APOLYSIS_F6_PROVIDER_ARTIFACT_ROOT_exists")
elif selected_source == "workflow_download":
    if not workflow_run_id:
        source_missing.append("APOLYSIS_F6_PROVIDER_WORKFLOW_RUN_ID")
    if not download_confirmed:
        source_missing.append("APOLYSIS_CONFIRM_F6_PROVIDER_ARTIFACT_DOWNLOAD")
elif selected_source == "retained_package":
    if not retained_package:
        source_missing.append("APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE")
    elif not Path(retained_package).is_file():
        source_missing.append("APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE_exists")
    if not retained_package_sha256:
        source_missing.append("APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256")
    elif not valid_sha256(retained_package_sha256):
        source_missing.append("APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256_valid")

env = os.environ.copy()
env["APOLYSIS_F5_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_OUTPUT_DIR"] = str(downstream_dir)
env["APOLYSIS_REQUIRE_F5_PROVIDER_WORKFLOW_ARTIFACT_IMPORT"] = "0"

if selected_source == "local_artifact_root" and local_artifact_root:
    env["APOLYSIS_F5_PROVIDER_WORKFLOW_ARTIFACT_ROOT"] = local_artifact_root
elif selected_source == "workflow_download":
    env["APOLYSIS_F5_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_MODE"] = "download"
    if workflow_run_id:
        env["APOLYSIS_F5_PROVIDER_WORKFLOW_RUN_ID"] = workflow_run_id
    if download_confirmed:
        env["APOLYSIS_CONFIRM_F5_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD"] = "1"
elif selected_source == "retained_package":
    if retained_package:
        env["APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE"] = retained_package
    if retained_package_sha256:
        env["APOLYSIS_F5_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256"] = retained_package_sha256

downstream_dir.mkdir(parents=True, exist_ok=True)
process = subprocess.run(
    [str(f5_gate)],
    cwd=repo_root,
    env=env,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
)
downstream_output_path = output_dir / "f5-provider-workflow-artifact-import.out"
downstream_output_path.write_text(process.stdout, encoding="utf-8")

downstream_doc: dict = {}
if downstream_report_path.is_file():
    try:
        downstream_doc = json.loads(downstream_report_path.read_text(encoding="utf-8"))
    except Exception:
        downstream_doc = {}

provider_workflow_artifact_import_ready = bool(
    downstream_doc.get("provider_workflow_artifact_import_ready")
)
bundle_env_ready = bool(downstream_doc.get("bundle_env_ready"))
provider_artifact_import_ready = (
    process.returncode == 0
    and not source_errors
    and not source_missing
    and provider_workflow_artifact_import_ready
    and bundle_env_ready
)

missing_requirements: list[str] = []
missing_requirements.extend(source_errors)
missing_requirements.extend(source_missing)
if process.returncode != 0:
    missing_requirements.append("f5_provider_workflow_artifact_import_audit_succeeded")
if not provider_workflow_artifact_import_ready:
    missing_requirements.append("provider_workflow_artifact_import")
if not bundle_env_ready:
    missing_requirements.append("final_provider_bundle_env")
missing_requirements.extend(str(value) for value in downstream_doc.get("missing_requirements") or [])
missing_requirements.extend(
    f"final_provider_bundle_env:{value}"
    for value in downstream_doc.get("bundle_env_missing_requirements") or []
)
missing_requirements = list(dict.fromkeys(missing_requirements))

passed = provider_artifact_import_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "F6.3",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "provider_artifact_import_ready": provider_artifact_import_ready,
    "provider_workflow_artifact_import_ready": provider_workflow_artifact_import_ready,
    "bundle_env_ready": bundle_env_ready,
    "requested_artifact_source": requested_source,
    "selected_artifact_source": selected_source,
    "source_plan": {
        "local_artifact_root": {
            "path_present": bool(local_artifact_root),
            "path_exists": bool(local_artifact_root) and Path(local_artifact_root).is_dir(),
        },
        "workflow_download": {
            "run_id_present": bool(workflow_run_id),
            "download_confirmed": download_confirmed,
        },
        "retained_package": {
            "package_present": bool(retained_package),
            "package_exists": bool(retained_package) and Path(retained_package).is_file(),
            "sha256_present": bool(retained_package_sha256),
            "sha256_valid": valid_sha256(retained_package_sha256) if retained_package_sha256 else False,
        },
    },
    "downstream": {
        "gate": str(f5_gate),
        "exit_code": process.returncode,
        "output_file": str(downstream_output_path),
        "report": str(downstream_report_path) if downstream_report_path.is_file() else "",
        "provider_workflow_artifact_import_ready": provider_workflow_artifact_import_ready,
        "bundle_env_report": downstream_doc.get("bundle_env_report", ""),
        "bundle_env_exit_code": downstream_doc.get("bundle_env_exit_code", 0),
        "download_attempted": bool(downstream_doc.get("download_attempted")),
        "download_succeeded": bool(downstream_doc.get("download_succeeded")),
    },
    "artifact_roots": downstream_doc.get("artifact_roots") or [],
    "artifact_json_count": int(downstream_doc.get("artifact_json_count") or 0),
    "import_actions": downstream_doc.get("import_actions") or [],
    "bundle_env_missing_requirements": downstream_doc.get("bundle_env_missing_requirements") or [],
    "missing_requirements": [] if provider_artifact_import_ready else missing_requirements,
    "notes": [
        "No secret values are recorded in this report.",
        "F6.3 maps F6 provider artifact source controls to historical F5.46 import contracts.",
        "The downstream gate is scripts/test-f5-provider-workflow-artifact-import.sh.",
        "Default audit mode does not download workflow artifacts unless APOLYSIS_CONFIRM_F6_PROVIDER_ARTIFACT_DOWNLOAD=1 is set.",
        "Provider artifact import readiness requires both imported provider artifacts and a ready final-provider bundle environment.",
    ],
    "next_commands": {
        "audit": "./scripts/test-f6-provider-artifact-import.sh",
        "audit_local_artifacts": (
            "APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE=local_artifact_root "
            "APOLYSIS_F6_PROVIDER_ARTIFACT_ROOT=<artifact-root> "
            "APOLYSIS_REQUIRE_F6_PROVIDER_ARTIFACT_IMPORT=1 ./scripts/test-f6-provider-artifact-import.sh"
        ),
        "download_workflow_artifacts": (
            "APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE=workflow_download "
            "APOLYSIS_F6_PROVIDER_WORKFLOW_RUN_ID=<run-id> "
            "APOLYSIS_CONFIRM_F6_PROVIDER_ARTIFACT_DOWNLOAD=1 "
            "APOLYSIS_REQUIRE_F6_PROVIDER_ARTIFACT_IMPORT=1 ./scripts/test-f6-provider-artifact-import.sh"
        ),
        "audit_retained_package": (
            "APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE=retained_package "
            "APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE=<tar.gz> "
            "APOLYSIS_F6_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256=<sha256> "
            "APOLYSIS_REQUIRE_F6_PROVIDER_ARTIFACT_IMPORT=1 ./scripts/test-f6-provider-artifact-import.sh"
        ),
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not provider_artifact_import_ready:
    print(f"apolysis-f6: provider artifact import failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-f6: provider artifact import audit written ($output_dir)
APOLYSIS_F6_PROVIDER_ARTIFACT_IMPORT_REPORT=$report
EOF

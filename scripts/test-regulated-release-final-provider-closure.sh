#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/regulated-release-final-provider-closure.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-regulated-release-final-provider-closure-report.json"
require_ready="${APOLYSIS_REQUIRE_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE:-0}"
run_final_closure="${APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE:-${APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION:-0}}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-regulated_release: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$output_dir" "$report" "$require_ready" "$run_final_closure" <<'PY'
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
run_final_closure = sys.argv[5] == "1"

production_hardening_gate = repo_root / "scripts/test-production-hardening-final-provider-closure.sh"
downstream_dir = output_dir / "production-hardening-final-provider-closure"
downstream_report_path = downstream_dir / "apolysis-production-hardening-final-provider-closure-report.json"

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

requested_source = (
    env_value("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_SOURCE", "APOLYSIS_REGULATED_RELEASE_ARTIFACT_SOURCE") or "auto"
)
local_artifact_root = env_value(
    "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT",
    "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT",
)
workflow_run_id = env_value(
    "APOLYSIS_REGULATED_RELEASE_PROVIDER_WORKFLOW_RUN_ID",
    "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID",
)
retained_package = env_value(
    "APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE",
    "APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE",
)
retained_package_sha256 = env_value(
    "APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256",
    "APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256",
)
download_confirmed = bool_env("APOLYSIS_CONFIRM_REGULATED_RELEASE_PROVIDER_ARTIFACT_DOWNLOAD") or bool_env(
    "APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD"
)

source_errors: list[str] = []
if requested_source not in allowed_sources:
    source_errors.append("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_SOURCE")

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
        source_missing.append("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT")
    elif not Path(local_artifact_root).is_dir():
        source_missing.append("APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT_exists")
elif selected_source == "workflow_download":
    if not workflow_run_id:
        source_missing.append("APOLYSIS_REGULATED_RELEASE_PROVIDER_WORKFLOW_RUN_ID")
    if not download_confirmed:
        source_missing.append("APOLYSIS_CONFIRM_REGULATED_RELEASE_PROVIDER_ARTIFACT_DOWNLOAD")
elif selected_source == "retained_package":
    if not retained_package:
        source_missing.append("APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE")
    elif not Path(retained_package).is_file():
        source_missing.append("APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE_exists")
    if not retained_package_sha256:
        source_missing.append("APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256")
    elif not valid_sha256(retained_package_sha256):
        source_missing.append("APOLYSIS_REGULATED_RELEASE_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256_valid")

env = os.environ.copy()
env["APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE_OUTPUT_DIR"] = str(downstream_dir)
env["APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE"] = "0"
env["APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION"] = "1" if run_final_closure else "0"

if selected_source == "local_artifact_root" and local_artifact_root:
    env["APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT"] = local_artifact_root
elif selected_source == "workflow_download":
    env["APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_MODE"] = "download"
    if workflow_run_id:
        env["APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID"] = workflow_run_id
    if download_confirmed:
        env["APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD"] = "1"
elif selected_source == "retained_package":
    if retained_package:
        env["APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE"] = retained_package
    if retained_package_sha256:
        env["APOLYSIS_PRODUCTION_HARDENING_RETAINED_PROVIDER_ARTIFACT_PACKAGE_SHA256"] = retained_package_sha256

downstream_dir.mkdir(parents=True, exist_ok=True)
process = subprocess.run(
    [str(production_hardening_gate)],
    cwd=repo_root,
    env=env,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
)
downstream_output_path = output_dir / "production-hardening-final-provider-closure.out"
downstream_output_path.write_text(process.stdout, encoding="utf-8")

downstream_doc: dict = {}
if downstream_report_path.is_file():
    try:
        downstream_doc = json.loads(downstream_report_path.read_text(encoding="utf-8"))
    except Exception:
        downstream_doc = {}

downstream_closure_ready = bool(downstream_doc.get("final_provider_closure_ready"))
artifact_import_ready = bool(downstream_doc.get("artifact_import_ready"))
bundle_env_ready = bool(downstream_doc.get("bundle_env_ready"))
completion_passed = bool(downstream_doc.get("completion_passed"))
artifact_handoff_ready = process.returncode == 0 and artifact_import_ready and bundle_env_ready
final_provider_closure_ready = (
    process.returncode == 0
    and not source_errors
    and not source_missing
    and artifact_handoff_ready
    and run_final_closure
    and completion_passed
    and downstream_closure_ready
)

missing_requirements: list[str] = []
missing_requirements.extend(source_errors)
missing_requirements.extend(source_missing)
if process.returncode != 0:
    missing_requirements.append("production_hardening_final_provider_closure_audit_succeeded")
if not artifact_import_ready:
    missing_requirements.append("provider_artifact_import")
if not bundle_env_ready:
    missing_requirements.append("final_provider_bundle_env")
if not run_final_closure:
    missing_requirements.append("APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE")
if run_final_closure and not completion_passed:
    missing_requirements.append("final_provider_completion")
if not downstream_closure_ready:
    missing_requirements.append("final_provider_closure")
missing_requirements.extend(str(value) for value in downstream_doc.get("missing_requirements") or [])
missing_requirements = list(dict.fromkeys(missing_requirements))

passed = final_provider_closure_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "regulated-release.final-provider-closure",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "final_provider_closure_ready": final_provider_closure_ready,
    "artifact_handoff_ready": artifact_handoff_ready,
    "artifact_import_ready": artifact_import_ready,
    "bundle_env_ready": bundle_env_ready,
    "run_final_provider_closure": run_final_closure,
    "completion_passed": completion_passed,
    "downstream_final_provider_closure_ready": downstream_closure_ready,
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
        "gate": str(production_hardening_gate),
        "exit_code": process.returncode,
        "output_file": str(downstream_output_path),
        "report": str(downstream_report_path) if downstream_report_path.is_file() else "",
        "workflow_handoff_ready": bool(downstream_doc.get("workflow_handoff_ready")),
        "completion_env_file": downstream_doc.get("completion_env_file", ""),
        "completion_env_exports": downstream_doc.get("completion_env_exports") or [],
    },
    "steps": downstream_doc.get("steps") or {},
    "missing_requirements": [] if final_provider_closure_ready else missing_requirements,
    "notes": [
        "No secret values are recorded in this report.",
        "regulated-release.final-provider-closure maps RegulatedRelease provider artifact source controls and final-closure execution controls to the historical production-hardening.final-provider-closure closure gate.",
        "Default audit mode does not dispatch GitHub workflows and does not run final provider completion unless APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 is set.",
        "Final provider closure readiness requires imported provider artifacts, a ready final-provider bundle environment, and a passing downstream final completion.",
    ],
    "next_commands": {
        "audit": "./scripts/test-regulated-release-final-provider-closure.sh",
        "required_from_local_artifacts": (
            "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_SOURCE=local_artifact_root "
            "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT=<artifact-root> "
            "APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 "
            "APOLYSIS_REQUIRE_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 ./scripts/test-regulated-release-final-provider-closure.sh"
        ),
        "download_then_close": (
            "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_SOURCE=workflow_download "
            "APOLYSIS_REGULATED_RELEASE_PROVIDER_WORKFLOW_RUN_ID=<run-id> "
            "APOLYSIS_CONFIRM_REGULATED_RELEASE_PROVIDER_ARTIFACT_DOWNLOAD=1 "
            "APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 "
            "APOLYSIS_REQUIRE_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 ./scripts/test-regulated-release-final-provider-closure.sh"
        ),
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not final_provider_closure_ready:
    print(f"apolysis-regulated_release: final provider closure failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-regulated_release: final provider closure audit written ($output_dir)
APOLYSIS_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE_REPORT=$report
EOF

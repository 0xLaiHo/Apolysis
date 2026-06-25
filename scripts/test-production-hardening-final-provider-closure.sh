#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-final-provider-closure.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-final-provider-closure-report.json"
require_ready="${APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE:-0}"
run_completion="${APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$output_dir" "$report" "$require_ready" "$run_completion" <<'PY'
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
report_path = Path(sys.argv[3])
require_ready = sys.argv[4] == "1"
run_completion = sys.argv[5] == "1"

def run_step(
    name: str,
    command: list[str],
    env_updates: dict[str, str],
    report_name: str,
) -> dict:
    step_dir = output_dir / name
    step_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(env_updates)
    process = subprocess.run(
        command,
        cwd=repo_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output_path = step_dir / f"{name}.out"
    output_path.write_text(process.stdout, encoding="utf-8")
    report_file = step_dir / report_name
    return {
        "name": name,
        "exit_code": process.returncode,
        "output_file": str(output_path),
        "report": str(report_file) if report_file.is_file() else "",
        "report_file": report_file,
    }

def load_json(path: Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def load_env_file(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    exports: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("export ") or "=" not in stripped:
            continue
        assignment = stripped[len("export ") :]
        try:
            parts = shlex.split(assignment, posix=True)
        except ValueError:
            continue
        if len(parts) != 1 or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        if name.startswith("APOLYSIS_PRODUCTION_HARDENING_"):
            exports[name] = value
    return exports

readiness_step = run_step(
    "provider-workflow-readiness",
    [str(repo_root / "scripts/test-production-hardening-provider-workflow-readiness.sh")],
    {
        "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_READINESS_OUTPUT_DIR": str(output_dir / "provider-workflow-readiness"),
        "APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_READINESS": "0",
    },
    "apolysis-production-hardening-provider-workflow-readiness-report.json",
)
readiness_doc = load_json(readiness_step["report_file"])

dispatch_step = run_step(
    "provider-workflow-dispatch",
    [str(repo_root / "scripts/test-production-hardening-provider-workflow-dispatch.sh")],
    {
        "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH_OUTPUT_DIR": str(output_dir / "provider-workflow-dispatch"),
        "APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_DISPATCH": "0",
    },
    "apolysis-production-hardening-provider-workflow-dispatch-report.json",
)
dispatch_doc = load_json(dispatch_step["report_file"])

artifact_import_step = run_step(
    "provider-workflow-artifact-import",
    [str(repo_root / "scripts/test-production-hardening-provider-workflow-artifact-import.sh")],
    {
        "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_OUTPUT_DIR": str(output_dir / "provider-workflow-artifact-import"),
        "APOLYSIS_REQUIRE_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT": "0",
    },
    "apolysis-production-hardening-provider-workflow-artifact-import-report.json",
)
artifact_import_doc = load_json(artifact_import_step["report_file"])

bundle_env_report = Path(str(artifact_import_doc.get("bundle_env_report") or ""))
bundle_env_doc = load_json(bundle_env_report)
bundle_env_file = Path(str(bundle_env_doc.get("env_file") or ""))
completion_env_exports = load_env_file(bundle_env_file)

completion_step = {
    "name": "final-provider-completion",
    "exit_code": 0,
    "output_file": "",
    "report": "",
    "report_file": None,
}
completion_doc: dict = {}
if run_completion:
    completion_step = run_step(
        "final-provider-completion",
        [str(repo_root / "scripts/verify-production-hardening-final-provider-completion.sh")],
        {
            **completion_env_exports,
            "APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION_OUTPUT_DIR": str(output_dir / "final-provider-completion"),
        },
        "apolysis-production-hardening-final-provider-completion-report.json",
    )
    completion_doc = load_json(completion_step["report_file"])

steps = {
    "provider_workflow_readiness": {
        "exit_code": readiness_step["exit_code"],
        "report": readiness_step["report"],
        "provider_workflow_ready": bool(readiness_doc.get("provider_workflow_ready")),
        "missing_requirements": readiness_doc.get("missing_requirements") or [],
    },
    "provider_workflow_dispatch": {
        "exit_code": dispatch_step["exit_code"],
        "report": dispatch_step["report"],
        "provider_workflow_dispatch_ready": bool(dispatch_doc.get("provider_workflow_dispatch_ready")),
        "dispatch_plan_ready": bool(dispatch_doc.get("dispatch_plan_ready")),
        "workflow_dispatch_attempted": bool(dispatch_doc.get("workflow_dispatch_attempted")),
        "workflow_dispatched": bool(dispatch_doc.get("workflow_dispatched")),
        "mode": dispatch_doc.get("mode", ""),
        "missing_requirements": dispatch_doc.get("missing_requirements") or [],
    },
    "provider_workflow_artifact_import": {
        "exit_code": artifact_import_step["exit_code"],
        "report": artifact_import_step["report"],
        "provider_workflow_artifact_import_ready": bool(
            artifact_import_doc.get("provider_workflow_artifact_import_ready")
        ),
        "bundle_env_ready": bool(artifact_import_doc.get("bundle_env_ready")),
        "artifact_roots": artifact_import_doc.get("artifact_roots") or [],
        "artifact_json_count": int(artifact_import_doc.get("artifact_json_count") or 0),
        "bundle_env_report": str(bundle_env_report) if bundle_env_report.is_file() else "",
        "bundle_env_file": str(bundle_env_file) if bundle_env_file.is_file() else "",
        "bundle_env_missing_requirements": artifact_import_doc.get("bundle_env_missing_requirements") or [],
        "missing_requirements": artifact_import_doc.get("missing_requirements") or [],
    },
    "final_provider_completion": {
        "exit_code": completion_step["exit_code"],
        "report": completion_step["report"],
        "requested": run_completion,
        "passed": bool(completion_doc.get("passed")) if run_completion else False,
        "final_provider_ready": bool(completion_doc.get("final_provider_ready")) if run_completion else False,
        "final_bundle_passed": bool(completion_doc.get("final_bundle_passed")) if run_completion else False,
        "missing_requirements": completion_doc.get("missing_requirements") or [],
    },
}

workflow_handoff_ready = (
    steps["provider_workflow_readiness"]["provider_workflow_ready"]
    and steps["provider_workflow_dispatch"]["dispatch_plan_ready"]
)
artifact_import_ready = steps["provider_workflow_artifact_import"]["provider_workflow_artifact_import_ready"]
bundle_env_ready = steps["provider_workflow_artifact_import"]["bundle_env_ready"]
completion_passed = steps["final_provider_completion"]["passed"]

missing_requirements: list[str] = []
for key, step in steps.items():
    if int(step["exit_code"]) != 0 and key != "final_provider_completion":
        missing_requirements.append(f"{key}_audit_succeeded")
if not artifact_import_ready:
    missing_requirements.append("provider_workflow_artifact_import")
if not bundle_env_ready:
    missing_requirements.append("final_provider_bundle_env")
if require_ready and not run_completion:
    missing_requirements.append("APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION")
if run_completion and not completion_passed:
    missing_requirements.append("final_provider_completion")

missing_requirements = list(dict.fromkeys(missing_requirements))
closure_ready = completion_passed if run_completion else artifact_import_ready and bundle_env_ready
passed = closure_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "production-hardening.final-provider-closure",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "final_provider_closure_ready": closure_ready,
    "workflow_handoff_ready": workflow_handoff_ready,
    "artifact_import_ready": artifact_import_ready,
    "bundle_env_ready": bundle_env_ready,
    "run_final_provider_completion": run_completion,
    "completion_passed": completion_passed,
    "completion_env_file": str(bundle_env_file) if bundle_env_file.is_file() else "",
    "completion_env_exports": sorted(completion_env_exports),
    "missing_requirements": missing_requirements,
    "steps": steps,
    "notes": [
        "No secret values are recorded in this report.",
        "Default mode audits workflow readiness, dispatch planning, and artifact import without calling GitHub workflow dispatch or AWS APIs.",
        "Set APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION=1 to run scripts/verify-production-hardening-final-provider-completion.sh with provider artifact exports from the production-hardening.provider-workflow-artifact-import/production-hardening.final-provider-bundle-env env file.",
        "A ready closure still requires real AWS KMS or external hardware HSM signing evidence; local fixture artifacts are rejected by the downstream gates.",
    ],
    "next_commands": {
        "audit_closure": "./scripts/test-production-hardening-final-provider-closure.sh",
        "required_completion_from_local_artifacts": "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_ROOT=<artifact-root> APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION=1 APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE=1 ./scripts/test-production-hardening-final-provider-closure.sh",
        "download_then_complete": "APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_IMPORT_MODE=download APOLYSIS_CONFIRM_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_ARTIFACT_DOWNLOAD=1 APOLYSIS_PRODUCTION_HARDENING_PROVIDER_WORKFLOW_RUN_ID=<run-id> APOLYSIS_RUN_PRODUCTION_HARDENING_FINAL_PROVIDER_COMPLETION=1 APOLYSIS_REQUIRE_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE=1 ./scripts/test-production-hardening-final-provider-closure.sh",
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not closure_ready:
    print(f"apolysis-production-hardening: final provider closure failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing_requirements), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: final provider closure audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_FINAL_PROVIDER_CLOSURE_REPORT=$report
EOF

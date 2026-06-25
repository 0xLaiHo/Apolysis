#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F6_REGULATED_RELEASE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f6-regulated-release.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f6-regulated-release-report.json"
require_ready="${APOLYSIS_REQUIRE_F6_REGULATED_RELEASE:-0}"
run_final_closure="${APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE:-${APOLYSIS_RUN_F5_FINAL_PROVIDER_COMPLETION:-0}}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f6: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$output_dir" "$report" "$require_ready" "$run_final_closure" <<'PY'
import json
import os
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
report_path = Path(sys.argv[3])
require_ready = sys.argv[4] == "1"
run_final_closure = sys.argv[5] == "1"

def run_step(name: str, command: list[str], env_updates: dict[str, str], report_name: str) -> dict:
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

plan_step = run_step(
    "provider-execution-plan",
    [str(repo_root / "scripts/test-f6-provider-execution-plan.sh")],
    {
        "APOLYSIS_F6_PROVIDER_EXECUTION_PLAN_OUTPUT_DIR": str(output_dir / "provider-execution-plan"),
        "APOLYSIS_REQUIRE_F6_PROVIDER_EXECUTION_PLAN": "0",
    },
    "apolysis-f6-provider-execution-plan-report.json",
)
plan_doc = load_json(plan_step["report_file"])

signing_step = run_step(
    "signing-evidence",
    [str(repo_root / "scripts/test-f6-signing-evidence.sh")],
    {
        "APOLYSIS_F6_SIGNING_EVIDENCE_OUTPUT_DIR": str(output_dir / "signing-evidence"),
        "APOLYSIS_REQUIRE_F6_SIGNING_EVIDENCE": "0",
    },
    "apolysis-f6-signing-evidence-report.json",
)
signing_doc = load_json(signing_step["report_file"])

artifact_import_step = run_step(
    "provider-artifact-import",
    [str(repo_root / "scripts/test-f6-provider-artifact-import.sh")],
    {
        "APOLYSIS_F6_PROVIDER_ARTIFACT_IMPORT_OUTPUT_DIR": str(output_dir / "provider-artifact-import"),
        "APOLYSIS_REQUIRE_F6_PROVIDER_ARTIFACT_IMPORT": "0",
    },
    "apolysis-f6-provider-artifact-import-report.json",
)
artifact_import_doc = load_json(artifact_import_step["report_file"])

closure_step = run_step(
    "final-provider-closure",
    [str(repo_root / "scripts/test-f6-final-provider-closure.sh")],
    {
        "APOLYSIS_F6_FINAL_PROVIDER_CLOSURE_OUTPUT_DIR": str(output_dir / "final-provider-closure"),
        "APOLYSIS_REQUIRE_F6_FINAL_PROVIDER_CLOSURE": "0",
        "APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE": "1" if run_final_closure else "0",
    },
    "apolysis-f6-final-provider-closure-report.json",
)
closure_doc = load_json(closure_step["report_file"])

package_step = run_step(
    "evidence-package",
    [str(repo_root / "scripts/test-f6-evidence-package.sh")],
    {
        "APOLYSIS_F6_EVIDENCE_PACKAGE_OUTPUT_DIR": str(output_dir / "evidence-package"),
        "APOLYSIS_REQUIRE_F6_EVIDENCE_PACKAGE": "0",
    },
    "apolysis-f6-evidence-package-report.json",
)
package_doc = load_json(package_step["report_file"])

steps = {
    "provider_execution_plan": {
        "exit_code": plan_step["exit_code"],
        "report": plan_step["report"],
        "provider_execution_plan_ready": bool(plan_doc.get("provider_execution_plan_ready")),
        "selected_signing_provider": plan_doc.get("selected_signing_provider", ""),
        "selected_artifact_source": plan_doc.get("selected_artifact_source", ""),
        "missing_requirements": plan_doc.get("missing_requirements") or [],
    },
    "signing_evidence": {
        "exit_code": signing_step["exit_code"],
        "report": signing_step["report"],
        "signing_evidence_ready": bool(signing_doc.get("signing_evidence_ready")),
        "signing_provider_ready": bool(signing_doc.get("signing_provider_ready")),
        "retained_signing_evidence_ready": bool(signing_doc.get("retained_signing_evidence_ready")),
        "ready_to_execute_live_signing": bool(signing_doc.get("ready_to_execute_live_signing")),
        "selected_signing_provider": signing_doc.get("selected_signing_provider", ""),
        "missing_requirements": signing_doc.get("missing_requirements") or [],
    },
    "provider_artifact_import": {
        "exit_code": artifact_import_step["exit_code"],
        "report": artifact_import_step["report"],
        "provider_artifact_import_ready": bool(artifact_import_doc.get("provider_artifact_import_ready")),
        "provider_workflow_artifact_import_ready": bool(
            artifact_import_doc.get("provider_workflow_artifact_import_ready")
        ),
        "bundle_env_ready": bool(artifact_import_doc.get("bundle_env_ready")),
        "artifact_json_count": int(artifact_import_doc.get("artifact_json_count") or 0),
        "selected_artifact_source": artifact_import_doc.get("selected_artifact_source", ""),
        "missing_requirements": artifact_import_doc.get("missing_requirements") or [],
        "bundle_env_missing_requirements": artifact_import_doc.get("bundle_env_missing_requirements") or [],
    },
    "final_provider_closure": {
        "exit_code": closure_step["exit_code"],
        "report": closure_step["report"],
        "final_provider_closure_ready": bool(closure_doc.get("final_provider_closure_ready")),
        "artifact_handoff_ready": bool(closure_doc.get("artifact_handoff_ready")),
        "run_final_provider_completion": bool(
            closure_doc.get("run_final_provider_closure") or closure_doc.get("run_final_provider_completion")
        ),
        "completion_passed": bool(closure_doc.get("completion_passed")),
        "selected_artifact_source": closure_doc.get("selected_artifact_source", ""),
        "missing_requirements": closure_doc.get("missing_requirements") or [],
    },
    "evidence_package": {
        "exit_code": package_step["exit_code"],
        "report": package_step["report"],
        "evidence_package_ready": bool(package_doc.get("evidence_package_ready")),
        "packaged_entry_count": int(package_doc.get("packaged_entry_count") or 0),
        "archive": package_doc.get("archive", ""),
        "archive_sha256": package_doc.get("archive_sha256", ""),
        "secret_scan_findings": package_doc.get("secret_scan_findings") or [],
        "missing_requirements": package_doc.get("missing_requirements") or [],
    },
}

provider_execution_plan_ready = steps["provider_execution_plan"]["provider_execution_plan_ready"]
signing_ready = steps["signing_evidence"]["signing_evidence_ready"]
artifact_import_ready = steps["provider_artifact_import"]["provider_artifact_import_ready"]
workflow_artifact_import_ready = steps["provider_artifact_import"]["provider_workflow_artifact_import_ready"]
bundle_env_ready = steps["provider_artifact_import"]["bundle_env_ready"]
closure_ready = steps["final_provider_closure"]["final_provider_closure_ready"]
closure_completion_requested = steps["final_provider_closure"]["run_final_provider_completion"]
closure_completion_passed = steps["final_provider_closure"]["completion_passed"]
evidence_package_ready = steps["evidence_package"]["evidence_package_ready"]

missing_requirements: list[str] = []
for name, step in steps.items():
    if int(step["exit_code"]) != 0:
        missing_requirements.append(f"{name}_audit_succeeded")
if not provider_execution_plan_ready:
    missing_requirements.append("provider_execution_plan")
if not signing_ready:
    missing_requirements.append("retained_live_kms_or_external_hsm_signing_evidence")
if not artifact_import_ready:
    missing_requirements.append("provider_artifact_import")
if not workflow_artifact_import_ready:
    missing_requirements.append("provider_workflow_artifact_import")
if not bundle_env_ready:
    missing_requirements.append("final_provider_bundle_env")
if not run_final_closure:
    missing_requirements.append("APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE")
if run_final_closure and not closure_completion_requested:
    missing_requirements.append("final_provider_completion_requested")
if run_final_closure and not closure_completion_passed:
    missing_requirements.append("final_provider_completion")
if not closure_ready:
    missing_requirements.append("final_provider_closure")
if not evidence_package_ready:
    missing_requirements.append("evidence_package")

missing_requirements = list(dict.fromkeys(missing_requirements))
regulated_release_ready = (
    provider_execution_plan_ready
    and signing_ready
    and artifact_import_ready
    and bundle_env_ready
    and run_final_closure
    and closure_completion_requested
    and closure_completion_passed
    and closure_ready
    and evidence_package_ready
)
passed = regulated_release_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "F6.6",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "regulated_release_ready": regulated_release_ready,
    "provider_execution_plan_ready": provider_execution_plan_ready,
    "signing_evidence_ready": signing_ready,
    "signing_provider_ready": bool(signing_doc.get("signing_provider_ready")),
    "provider_artifact_import_ready": artifact_import_ready,
    "provider_workflow_artifact_import_ready": workflow_artifact_import_ready,
    "bundle_env_ready": bundle_env_ready,
    "final_provider_closure_ready": closure_ready,
    "evidence_package_ready": evidence_package_ready,
    "run_final_provider_closure": run_final_closure,
    "completion_passed": closure_completion_passed,
    "missing_requirements": [] if regulated_release_ready else missing_requirements,
    "steps": steps,
    "notes": [
        "No secret values are recorded in this report.",
        "F6 regulated release reuses historical F5 provider gates without renaming their artifact contracts.",
        "The F6 provider execution plan gate records provider and artifact-source choices before required execution.",
        "The F6 signing evidence gate maps F6 signing controls to scripts/test-f5-signing-provider-readiness.sh and requires retained live-provider evidence for regulated release readiness.",
        "The F6 provider artifact import gate maps F6 source selection to scripts/test-f5-provider-workflow-artifact-import.sh before final closure.",
        "The F6 final provider closure gate maps F6 closure execution controls to scripts/test-f5-final-provider-closure.sh.",
        "The F6 evidence package gate wraps the historical F5 final external-provider bundle builder and requires a no-secret package scan.",
        "Default audit mode does not dispatch GitHub workflows and does not call AWS or HSM signing APIs unless downstream gates are explicitly configured to do so.",
        "Required mode fails closed until retained live KMS or external hardware HSM signing evidence, imported provider artifacts, final closure, and a passing evidence package are present.",
    ],
    "next_commands": {
        "audit": "./scripts/test-f6-regulated-release.sh",
        "required_from_imported_artifacts": "APOLYSIS_F6_SIGNING_EVIDENCE=<signing-evidence> APOLYSIS_F6_SIGNING_REPORT=<signing-report> APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE=local_artifact_root APOLYSIS_F6_PROVIDER_ARTIFACT_ROOT=<artifact-root> APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE=1 APOLYSIS_REQUIRE_F6_REGULATED_RELEASE=1 ./scripts/test-f6-regulated-release.sh",
        "download_then_close": "APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE=workflow_download APOLYSIS_CONFIRM_F6_PROVIDER_ARTIFACT_DOWNLOAD=1 APOLYSIS_F6_PROVIDER_WORKFLOW_RUN_ID=<run-id> APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE=1 APOLYSIS_REQUIRE_F6_REGULATED_RELEASE=1 ./scripts/test-f6-regulated-release.sh",
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not regulated_release_ready:
    print(f"apolysis-f6: regulated release failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-f6: regulated release audit written ($output_dir)
APOLYSIS_F6_REGULATED_RELEASE_REPORT=$report
EOF

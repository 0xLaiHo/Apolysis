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

package_archive = str(package_doc.get("archive", ""))
retained_package_step = run_step(
    "retained-evidence-package",
    [str(repo_root / "scripts/test-f6-retained-evidence-package.sh")],
    {
        "APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_OUTPUT_DIR": str(output_dir / "retained-evidence-package"),
        "APOLYSIS_REQUIRE_F6_RETAINED_EVIDENCE_PACKAGE": "0",
        "APOLYSIS_F6_EVIDENCE_PACKAGE_REPORT": str(package_step["report"]),
        "APOLYSIS_F6_EVIDENCE_PACKAGE_ARCHIVE": package_archive,
        "APOLYSIS_F6_EVIDENCE_PACKAGE_MANIFEST": str(package_doc.get("manifest", "")),
        "APOLYSIS_F6_EVIDENCE_PACKAGE_SHA256": f"{package_archive}.sha256" if package_archive else "",
        "APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_ROOT": os.environ.get(
            "APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_ROOT", ""
        ),
        "APOLYSIS_F6_EVIDENCE_RETENTION_PROVIDER": os.environ.get(
            "APOLYSIS_F6_EVIDENCE_RETENTION_PROVIDER", ""
        ),
        "APOLYSIS_F6_EVIDENCE_RETENTION_MODE": os.environ.get("APOLYSIS_F6_EVIDENCE_RETENTION_MODE", ""),
        "APOLYSIS_F6_EVIDENCE_RETENTION_URI": os.environ.get("APOLYSIS_F6_EVIDENCE_RETENTION_URI", ""),
        "APOLYSIS_F6_EVIDENCE_RETENTION_CONTROL_PLANE": os.environ.get(
            "APOLYSIS_F6_EVIDENCE_RETENTION_CONTROL_PLANE", ""
        ),
    },
    "apolysis-f6-retained-evidence-package-report.json",
)
retained_package_doc = load_json(retained_package_step["report_file"])
external_retention_archive_sha = os.environ.get("APOLYSIS_F6_EXTERNAL_RETENTION_ARCHIVE_SHA256", "") or str(
    retained_package_doc.get("source_archive_sha256", "")
)

external_retention_step = run_step(
    "external-retention",
    [str(repo_root / "scripts/test-f6-external-retention.sh")],
    {
        "APOLYSIS_F6_EXTERNAL_RETENTION_OUTPUT_DIR": str(output_dir / "external-retention"),
        "APOLYSIS_REQUIRE_F6_EXTERNAL_RETENTION": "0",
        "APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_REPORT": str(retained_package_step["report"]),
        "APOLYSIS_F6_EXTERNAL_RETENTION_EVIDENCE": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_RETENTION_EVIDENCE", ""
        ),
        "APOLYSIS_F6_EXTERNAL_RETENTION_PROVIDER": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_RETENTION_PROVIDER", ""
        ),
        "APOLYSIS_F6_EXTERNAL_RETENTION_MODE": os.environ.get("APOLYSIS_F6_EXTERNAL_RETENTION_MODE", ""),
        "APOLYSIS_F6_EXTERNAL_RETENTION_URI": os.environ.get("APOLYSIS_F6_EXTERNAL_RETENTION_URI", ""),
        "APOLYSIS_F6_EXTERNAL_RETENTION_VERSION_ID": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_RETENTION_VERSION_ID", ""
        ),
        "APOLYSIS_F6_EXTERNAL_RETENTION_UNTIL": os.environ.get("APOLYSIS_F6_EXTERNAL_RETENTION_UNTIL", ""),
        "APOLYSIS_F6_EXTERNAL_RETENTION_CONTROL_PLANE": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_RETENTION_CONTROL_PLANE", ""
        ),
        "APOLYSIS_F6_EXTERNAL_RETENTION_ARCHIVE_SHA256": external_retention_archive_sha,
    },
    "apolysis-f6-external-retention-report.json",
)
external_retention_doc = load_json(external_retention_step["report_file"])

immutable_registry_step = run_step(
    "immutable-registry-retention",
    [str(repo_root / "scripts/test-f6-immutable-registry-retention.sh")],
    {
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_RETENTION_OUTPUT_DIR": str(
            output_dir / "immutable-registry-retention"
        ),
        "APOLYSIS_REQUIRE_F6_IMMUTABLE_REGISTRY_RETENTION": "0",
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_EVIDENCE": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_EVIDENCE", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_PROVIDER": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_PROVIDER", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_URI": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_URI", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_IMAGE_REF": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_IMAGE_REF", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_IMAGE_DIGEST": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_IMAGE_DIGEST", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_ENABLED": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_ENABLED", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_MODE": os.environ.get("APOLYSIS_F6_IMMUTABLE_REGISTRY_MODE", ""),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_POLICY_ID": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_POLICY_ID", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_RETENTION_UNTIL": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_RETENTION_UNTIL", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_CONTROL_PLANE": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_CONTROL_PLANE", ""
        ),
    },
    "apolysis-f6-immutable-registry-retention-report.json",
)
immutable_registry_doc = load_json(immutable_registry_step["report_file"])

managed_mesh_decision_step = run_step(
    "managed-mesh-decision",
    [str(repo_root / "scripts/test-f6-managed-mesh-decision.sh")],
    {
        "APOLYSIS_F6_MANAGED_MESH_DECISION_OUTPUT_DIR": str(output_dir / "managed-mesh-decision"),
        "APOLYSIS_REQUIRE_F6_MANAGED_MESH_DECISION": "0",
        "APOLYSIS_F6_MANAGED_MESH_EVIDENCE": os.environ.get(
            "APOLYSIS_F6_MANAGED_MESH_EVIDENCE", ""
        ),
        "APOLYSIS_F6_MANAGED_MESH_REPORT": os.environ.get("APOLYSIS_F6_MANAGED_MESH_REPORT", ""),
        "APOLYSIS_F6_MANAGED_MESH_PROVIDER": os.environ.get(
            "APOLYSIS_F6_MANAGED_MESH_PROVIDER", ""
        ),
        "APOLYSIS_F6_MANAGED_MESH_CONTROL_PLANE": os.environ.get(
            "APOLYSIS_F6_MANAGED_MESH_CONTROL_PLANE", ""
        ),
        "APOLYSIS_F6_MANAGED_MESH_DECISION": os.environ.get(
            "APOLYSIS_F6_MANAGED_MESH_DECISION", ""
        ),
        "APOLYSIS_F6_MANAGED_MESH_DECISION_RATIONALE": os.environ.get(
            "APOLYSIS_F6_MANAGED_MESH_DECISION_RATIONALE", ""
        ),
        "APOLYSIS_F6_MANAGED_MESH_ADDITIONAL_PROVIDER_REQUIRED": os.environ.get(
            "APOLYSIS_F6_MANAGED_MESH_ADDITIONAL_PROVIDER_REQUIRED", ""
        ),
    },
    "apolysis-f6-managed-mesh-decision-report.json",
)
managed_mesh_decision_doc = load_json(managed_mesh_decision_step["report_file"])

live_provider_readback_step = run_step(
    "live-provider-readback",
    [str(repo_root / "scripts/test-f6-live-provider-readback.sh")],
    {
        "APOLYSIS_F6_LIVE_PROVIDER_READBACK_OUTPUT_DIR": str(output_dir / "live-provider-readback"),
        "APOLYSIS_REQUIRE_F6_LIVE_PROVIDER_READBACK": "0",
        "APOLYSIS_F6_EXTERNAL_RETENTION_REPORT": str(external_retention_step["report"]),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_RETENTION_REPORT": str(immutable_registry_step["report"]),
        "APOLYSIS_F6_EXTERNAL_RETENTION_READBACK_EVIDENCE": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_RETENTION_READBACK_EVIDENCE", ""
        ),
        "APOLYSIS_F6_IMMUTABLE_REGISTRY_READBACK_EVIDENCE": os.environ.get(
            "APOLYSIS_F6_IMMUTABLE_REGISTRY_READBACK_EVIDENCE", ""
        ),
        "APOLYSIS_F6_EXTERNAL_READBACK_PROVIDER": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_PROVIDER", ""
        )
        or str(external_retention_doc.get("provider", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_URI": os.environ.get("APOLYSIS_F6_EXTERNAL_READBACK_URI", "")
        or str(external_retention_doc.get("object_uri", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_VERSION_ID": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_VERSION_ID", ""
        )
        or str(external_retention_doc.get("object_version_id", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_ARCHIVE_SHA256": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_ARCHIVE_SHA256", ""
        )
        or str(external_retention_doc.get("external_archive_sha256", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_RETENTION_MODE": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_RETENTION_MODE", ""
        )
        or str(external_retention_doc.get("retention_mode", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_RETENTION_UNTIL": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_RETENTION_UNTIL", ""
        )
        or str(external_retention_doc.get("retention_until", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_CONTROL_PLANE": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_CONTROL_PLANE", ""
        )
        or str(external_retention_doc.get("provider_control_plane", "")),
        "APOLYSIS_F6_REGISTRY_READBACK_PROVIDER": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_PROVIDER", ""
        )
        or str(immutable_registry_doc.get("provider", "")),
        "APOLYSIS_F6_REGISTRY_READBACK_URI": os.environ.get("APOLYSIS_F6_REGISTRY_READBACK_URI", "")
        or str(immutable_registry_doc.get("registry_uri", "")),
        "APOLYSIS_F6_REGISTRY_READBACK_IMAGE_REF": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_IMAGE_REF", ""
        )
        or str(immutable_registry_doc.get("image_ref", "")),
        "APOLYSIS_F6_REGISTRY_READBACK_IMAGE_DIGEST": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_IMAGE_DIGEST", ""
        )
        or str(immutable_registry_doc.get("image_digest", "")),
        "APOLYSIS_F6_REGISTRY_READBACK_POLICY_ID": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_POLICY_ID", ""
        )
        or str(immutable_registry_doc.get("policy_id", "")),
        "APOLYSIS_F6_REGISTRY_READBACK_CONTROL_PLANE": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_CONTROL_PLANE", ""
        )
        or str(immutable_registry_doc.get("provider_control_plane", "")),
        "APOLYSIS_F6_EXTERNAL_READBACK_VERIFIED": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_VERIFIED", ""
        ),
        "APOLYSIS_F6_EXTERNAL_READBACK_RETENTION_VERIFIED": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_RETENTION_VERIFIED", ""
        ),
        "APOLYSIS_F6_EXTERNAL_READBACK_DELETE_DENIED": os.environ.get(
            "APOLYSIS_F6_EXTERNAL_READBACK_DELETE_DENIED", ""
        ),
        "APOLYSIS_F6_REGISTRY_READBACK_DIGEST_VERIFIED": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_DIGEST_VERIFIED", ""
        ),
        "APOLYSIS_F6_REGISTRY_READBACK_IMMUTABILITY_VERIFIED": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_IMMUTABILITY_VERIFIED", ""
        ),
        "APOLYSIS_F6_REGISTRY_READBACK_MUTATION_DENIED": os.environ.get(
            "APOLYSIS_F6_REGISTRY_READBACK_MUTATION_DENIED", ""
        ),
    },
    "apolysis-f6-live-provider-readback-report.json",
)
live_provider_readback_doc = load_json(live_provider_readback_step["report_file"])

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
    "retained_evidence_package": {
        "exit_code": retained_package_step["exit_code"],
        "report": retained_package_step["report"],
        "retained_evidence_package_ready": bool(retained_package_doc.get("retained_evidence_package_ready")),
        "retention_provider": retained_package_doc.get("retention_provider", ""),
        "retention_mode": retained_package_doc.get("retention_mode", ""),
        "retention_uri": retained_package_doc.get("retention_uri", ""),
        "retained_directory": retained_package_doc.get("retained_directory", ""),
        "source_archive_sha256": retained_package_doc.get("source_archive_sha256", ""),
        "retention_manifest": retained_package_doc.get("retention_manifest", ""),
        "secret_scan_findings": retained_package_doc.get("secret_scan_findings") or [],
        "missing_requirements": retained_package_doc.get("missing_requirements") or [],
    },
    "external_retention": {
        "exit_code": external_retention_step["exit_code"],
        "report": external_retention_step["report"],
        "external_retention_ready": bool(external_retention_doc.get("external_retention_ready")),
        "provider": external_retention_doc.get("provider", ""),
        "retention_mode": external_retention_doc.get("retention_mode", ""),
        "object_uri": external_retention_doc.get("object_uri", ""),
        "object_version_id": external_retention_doc.get("object_version_id", ""),
        "retention_until": external_retention_doc.get("retention_until", ""),
        "source_archive_sha256": external_retention_doc.get("source_archive_sha256", ""),
        "external_archive_sha256": external_retention_doc.get("external_archive_sha256", ""),
        "manifest": external_retention_doc.get("manifest", ""),
        "secret_scan_findings": external_retention_doc.get("secret_scan_findings") or [],
        "missing_requirements": external_retention_doc.get("missing_requirements") or [],
    },
    "immutable_registry": {
        "exit_code": immutable_registry_step["exit_code"],
        "report": immutable_registry_step["report"],
        "immutable_registry_ready": bool(immutable_registry_doc.get("immutable_registry_ready")),
        "provider": immutable_registry_doc.get("provider", ""),
        "registry_uri": immutable_registry_doc.get("registry_uri", ""),
        "image_ref": immutable_registry_doc.get("image_ref", ""),
        "image_digest": immutable_registry_doc.get("image_digest", ""),
        "immutability_enabled": bool(immutable_registry_doc.get("immutability_enabled")),
        "immutability_mode": immutable_registry_doc.get("immutability_mode", ""),
        "policy_id": immutable_registry_doc.get("policy_id", ""),
        "retention_until": immutable_registry_doc.get("retention_until", ""),
        "manifest": immutable_registry_doc.get("manifest", ""),
        "secret_scan_findings": immutable_registry_doc.get("secret_scan_findings") or [],
        "missing_requirements": immutable_registry_doc.get("missing_requirements") or [],
    },
    "managed_mesh_decision": {
        "exit_code": managed_mesh_decision_step["exit_code"],
        "report": managed_mesh_decision_step["report"],
        "managed_mesh_decision_ready": bool(
            managed_mesh_decision_doc.get("managed_mesh_decision_ready")
        ),
        "provider": managed_mesh_decision_doc.get("provider", ""),
        "provider_control_plane": managed_mesh_decision_doc.get("provider_control_plane", ""),
        "decision": managed_mesh_decision_doc.get("decision", ""),
        "additional_provider_required": bool(
            managed_mesh_decision_doc.get("additional_provider_required")
        ),
        "manifest": managed_mesh_decision_doc.get("manifest", ""),
        "secret_scan_findings": managed_mesh_decision_doc.get("secret_scan_findings") or [],
        "missing_requirements": managed_mesh_decision_doc.get("missing_requirements") or [],
    },
    "live_provider_readback": {
        "exit_code": live_provider_readback_step["exit_code"],
        "report": live_provider_readback_step["report"],
        "live_provider_readback_ready": bool(
            live_provider_readback_doc.get("live_provider_readback_ready")
        ),
        "external_retention_readback_ready": bool(
            live_provider_readback_doc.get("external_retention_readback_ready")
        ),
        "immutable_registry_readback_ready": bool(
            live_provider_readback_doc.get("immutable_registry_readback_ready")
        ),
        "external_retention": live_provider_readback_doc.get("external_retention") or {},
        "immutable_registry": live_provider_readback_doc.get("immutable_registry") or {},
        "manifest": live_provider_readback_doc.get("manifest", ""),
        "secret_scan_findings": live_provider_readback_doc.get("secret_scan_findings") or [],
        "missing_requirements": live_provider_readback_doc.get("missing_requirements") or [],
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
retained_evidence_package_ready = steps["retained_evidence_package"]["retained_evidence_package_ready"]
external_retention_ready = steps["external_retention"]["external_retention_ready"]
immutable_registry_ready = steps["immutable_registry"]["immutable_registry_ready"]
managed_mesh_decision_ready = steps["managed_mesh_decision"]["managed_mesh_decision_ready"]
live_provider_readback_ready = steps["live_provider_readback"]["live_provider_readback_ready"]

source_missing_requirements: list[str] = []
for name, step in steps.items():
    if int(step["exit_code"]) != 0:
        source_missing_requirements.append(f"{name}_audit_succeeded")
if not provider_execution_plan_ready:
    source_missing_requirements.append("provider_execution_plan")
if not signing_ready:
    source_missing_requirements.append("retained_live_kms_or_external_hsm_signing_evidence")
if not artifact_import_ready:
    source_missing_requirements.append("provider_artifact_import")
if not workflow_artifact_import_ready:
    source_missing_requirements.append("provider_workflow_artifact_import")
if not bundle_env_ready:
    source_missing_requirements.append("final_provider_bundle_env")
if not run_final_closure:
    source_missing_requirements.append("APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE")
if run_final_closure and not closure_completion_requested:
    source_missing_requirements.append("final_provider_completion_requested")
if run_final_closure and not closure_completion_passed:
    source_missing_requirements.append("final_provider_completion")
if not closure_ready:
    source_missing_requirements.append("final_provider_closure")
if not evidence_package_ready:
    source_missing_requirements.append("evidence_package")
if not retained_evidence_package_ready:
    source_missing_requirements.append("retained_evidence_package")
if not external_retention_ready:
    source_missing_requirements.append("external_retention")
if not immutable_registry_ready:
    source_missing_requirements.append("immutable_registry")
if not managed_mesh_decision_ready:
    source_missing_requirements.append("managed_mesh_decision")
if not live_provider_readback_ready:
    source_missing_requirements.append("live_provider_readback")

source_missing_requirements = list(dict.fromkeys(source_missing_requirements))
pre_signoff_regulated_release_ready = (
    provider_execution_plan_ready
    and signing_ready
    and artifact_import_ready
    and workflow_artifact_import_ready
    and bundle_env_ready
    and run_final_closure
    and closure_completion_requested
    and closure_completion_passed
    and closure_ready
    and evidence_package_ready
    and retained_evidence_package_ready
    and external_retention_ready
    and immutable_registry_ready
    and managed_mesh_decision_ready
    and live_provider_readback_ready
)

source_report_path = output_dir / "apolysis-f6-regulated-release-source-report.json"
source_report = {
    "schema_version": 1,
    "phase": "F6.11",
    "audit_completed": True,
    "passed": pre_signoff_regulated_release_ready or not require_ready,
    "fail_closed_required": require_ready,
    "regulated_release_ready": pre_signoff_regulated_release_ready,
    "provider_execution_plan_ready": provider_execution_plan_ready,
    "signing_evidence_ready": signing_ready,
    "signing_provider_ready": bool(signing_doc.get("signing_provider_ready")),
    "provider_artifact_import_ready": artifact_import_ready,
    "provider_workflow_artifact_import_ready": workflow_artifact_import_ready,
    "bundle_env_ready": bundle_env_ready,
    "final_provider_closure_ready": closure_ready,
    "evidence_package_ready": evidence_package_ready,
    "retained_evidence_package_ready": retained_evidence_package_ready,
    "external_retention_ready": external_retention_ready,
    "immutable_registry_ready": immutable_registry_ready,
    "managed_mesh_decision_ready": managed_mesh_decision_ready,
    "live_provider_readback_ready": live_provider_readback_ready,
    "run_final_provider_closure": run_final_closure,
    "completion_passed": closure_completion_passed,
    "missing_requirements": [] if pre_signoff_regulated_release_ready else source_missing_requirements,
    "steps": steps,
    "notes": [
        "No secret values are recorded in this source report.",
        "This F6.11 source report is used by the F6.12 final release sign-off gate.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}
source_report_path.write_text(json.dumps(source_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

final_signoff_step = run_step(
    "final-release-signoff",
    [str(repo_root / "scripts/test-f6-final-release-signoff.sh")],
    {
        "APOLYSIS_F6_FINAL_RELEASE_SIGNOFF_OUTPUT_DIR": str(output_dir / "final-release-signoff"),
        "APOLYSIS_REQUIRE_F6_FINAL_RELEASE_SIGNOFF": "0",
        "APOLYSIS_F6_REGULATED_RELEASE_SOURCE_REPORT": str(source_report_path),
        "APOLYSIS_F6_FINAL_RELEASE_SIGNOFF": os.environ.get("APOLYSIS_F6_FINAL_RELEASE_SIGNOFF", ""),
        "APOLYSIS_F6_FINAL_SIGNOFF_ARTIFACT": os.environ.get("APOLYSIS_F6_FINAL_SIGNOFF_ARTIFACT", ""),
        "APOLYSIS_F6_FINAL_SIGNOFF_APPROVER": os.environ.get("APOLYSIS_F6_FINAL_SIGNOFF_APPROVER", ""),
        "APOLYSIS_F6_FINAL_RELEASE_APPROVER": os.environ.get("APOLYSIS_F6_FINAL_RELEASE_APPROVER", ""),
        "APOLYSIS_F6_FINAL_SIGNOFF_DECISION": os.environ.get("APOLYSIS_F6_FINAL_SIGNOFF_DECISION", ""),
        "APOLYSIS_F6_FINAL_RELEASE_DECISION": os.environ.get("APOLYSIS_F6_FINAL_RELEASE_DECISION", ""),
        "APOLYSIS_F6_FINAL_SIGNOFF_RATIONALE": os.environ.get("APOLYSIS_F6_FINAL_SIGNOFF_RATIONALE", ""),
        "APOLYSIS_F6_FINAL_RELEASE_RATIONALE": os.environ.get("APOLYSIS_F6_FINAL_RELEASE_RATIONALE", ""),
        "APOLYSIS_F6_FINAL_SIGNOFF_APPROVED_AT": os.environ.get("APOLYSIS_F6_FINAL_SIGNOFF_APPROVED_AT", ""),
        "APOLYSIS_F6_FINAL_RELEASE_APPROVED_AT": os.environ.get("APOLYSIS_F6_FINAL_RELEASE_APPROVED_AT", ""),
        "APOLYSIS_F6_FINAL_SIGNOFF_NO_SECRET_MATERIAL_RECORDED": os.environ.get(
            "APOLYSIS_F6_FINAL_SIGNOFF_NO_SECRET_MATERIAL_RECORDED", ""
        ),
        "APOLYSIS_F6_FINAL_RELEASE_NO_SECRET_MATERIAL_RECORDED": os.environ.get(
            "APOLYSIS_F6_FINAL_RELEASE_NO_SECRET_MATERIAL_RECORDED", ""
        ),
    },
    "apolysis-f6-final-release-signoff-report.json",
)
final_signoff_doc = load_json(final_signoff_step["report_file"])
steps["final_release_signoff"] = {
    "exit_code": final_signoff_step["exit_code"],
    "report": final_signoff_step["report"],
    "final_release_signoff_ready": bool(final_signoff_doc.get("final_release_signoff_ready")),
    "decision": final_signoff_doc.get("decision", ""),
    "approver": final_signoff_doc.get("approver", ""),
    "approved_at": final_signoff_doc.get("approved_at", ""),
    "source_regulated_release_report": final_signoff_doc.get("source_regulated_release_report", ""),
    "source_report_sha256": final_signoff_doc.get("source_report_sha256", ""),
    "manifest": final_signoff_doc.get("manifest", ""),
    "secret_scan_findings": final_signoff_doc.get("secret_scan_findings") or [],
    "missing_requirements": final_signoff_doc.get("missing_requirements") or [],
}
final_release_signoff_ready = steps["final_release_signoff"]["final_release_signoff_ready"]

missing_requirements = list(source_missing_requirements)
if int(final_signoff_step["exit_code"]) != 0:
    missing_requirements.append("final_release_signoff_audit_succeeded")
if not final_release_signoff_ready:
    missing_requirements.append("final_release_signoff")

missing_requirements = list(dict.fromkeys(missing_requirements))
regulated_release_ready = pre_signoff_regulated_release_ready and final_release_signoff_ready
passed = regulated_release_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "F6.12",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "regulated_release_ready": regulated_release_ready,
    "pre_signoff_regulated_release_ready": pre_signoff_regulated_release_ready,
    "provider_execution_plan_ready": provider_execution_plan_ready,
    "signing_evidence_ready": signing_ready,
    "signing_provider_ready": bool(signing_doc.get("signing_provider_ready")),
    "provider_artifact_import_ready": artifact_import_ready,
    "provider_workflow_artifact_import_ready": workflow_artifact_import_ready,
    "bundle_env_ready": bundle_env_ready,
    "final_provider_closure_ready": closure_ready,
    "evidence_package_ready": evidence_package_ready,
    "retained_evidence_package_ready": retained_evidence_package_ready,
    "external_retention_ready": external_retention_ready,
    "immutable_registry_ready": immutable_registry_ready,
    "managed_mesh_decision_ready": managed_mesh_decision_ready,
    "live_provider_readback_ready": live_provider_readback_ready,
    "final_release_signoff_ready": final_release_signoff_ready,
    "run_final_provider_closure": run_final_closure,
    "completion_passed": closure_completion_passed,
    "regulated_release_source_report": str(source_report_path),
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
        "The F6 retained evidence package gate validates archive checksums and copies the evidence package into the configured retention root.",
        "The F6 external retention gate validates non-local WORM/object-lock retention metadata for the retained evidence package.",
        "The F6 immutable registry retention gate validates digest-pinned immutable registry metadata for release images.",
        "The F6 managed mesh decision gate records whether retained provider-backed mesh evidence is accepted for regulated release.",
        "The F6 live provider readback gate validates retained provider-side readback evidence for external retention and immutable registry controls.",
        "The F6 final release sign-off gate validates the final regulated-release closure summary against the aggregate evidence.",
        "Default audit mode does not dispatch GitHub workflows and does not call AWS or HSM signing APIs unless downstream gates are explicitly configured to do so.",
        "Required mode fails closed until retained live KMS or external hardware HSM signing evidence, imported provider artifacts, final closure, a passing evidence package, retained evidence package handoff, external WORM/object-lock retention metadata, immutable registry metadata, managed mesh decision evidence, live provider readback evidence, and final release sign-off are present.",
    ],
    "next_commands": {
        "audit": "./scripts/test-f6-regulated-release.sh",
        "required_from_imported_artifacts": "APOLYSIS_F6_SIGNING_EVIDENCE=<signing-evidence> APOLYSIS_F6_SIGNING_REPORT=<signing-report> APOLYSIS_F6_PROVIDER_ARTIFACT_SOURCE=local_artifact_root APOLYSIS_F6_PROVIDER_ARTIFACT_ROOT=<artifact-root> APOLYSIS_F6_RETAINED_EVIDENCE_PACKAGE_ROOT=<retention-root> APOLYSIS_F6_EXTERNAL_RETENTION_EVIDENCE=<external-retention.json> APOLYSIS_F6_IMMUTABLE_REGISTRY_EVIDENCE=<immutable-registry.json> APOLYSIS_F6_MANAGED_MESH_EVIDENCE=<managed-mesh-evidence.json> APOLYSIS_F6_MANAGED_MESH_REPORT=<managed-mesh-report.json> APOLYSIS_F6_MANAGED_MESH_DECISION=<decision> APOLYSIS_F6_MANAGED_MESH_DECISION_RATIONALE=<rationale> APOLYSIS_F6_EXTERNAL_RETENTION_READBACK_EVIDENCE=<external-readback.json> APOLYSIS_F6_IMMUTABLE_REGISTRY_READBACK_EVIDENCE=<registry-readback.json> APOLYSIS_F6_FINAL_SIGNOFF_APPROVER=<approver> APOLYSIS_F6_FINAL_SIGNOFF_DECISION=approve_regulated_release APOLYSIS_F6_FINAL_SIGNOFF_APPROVED_AT=<timestamp> APOLYSIS_F6_FINAL_SIGNOFF_RATIONALE=<rationale> APOLYSIS_F6_FINAL_SIGNOFF_NO_SECRET_MATERIAL_RECORDED=1 APOLYSIS_RUN_F6_FINAL_PROVIDER_CLOSURE=1 APOLYSIS_REQUIRE_F6_REGULATED_RELEASE=1 ./scripts/test-f6-regulated-release.sh",
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

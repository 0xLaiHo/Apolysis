#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

matrix_artifacts="${APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR:-}"
if [[ -z "$matrix_artifacts" || ! -d "$matrix_artifacts" ]]; then
    cat >&2 <<'EOF'
apolysis-runtime_guardrails: live runtime evidence bundle requires a retained runtime adapter
matrix artifact directory. Set APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR to
the output directory from scripts/test-runtime-foundation-runtime-adapter-matrix.sh.
EOF
    exit 2
fi

output_dir="${APOLYSIS_RUNTIME_GUARDRAILS_LIVE_RUNTIME_EVIDENCE_OUTPUT_DIR:-$matrix_artifacts}"
visibility_output_dir="${APOLYSIS_RUNTIME_FOUNDATION_VISIBILITY_OUTPUT_DIR:-$output_dir/runtime-foundation-visibility}"
request_fixture="${APOLYSIS_RUNTIME_GUARDRAILS_RUNTIME_GUARDRAIL_REQUEST:-$repo_root/tests/fixtures/validation/runtime-guardrails-runtime-guardrail-request.json}"
adapter_evidence_output="${APOLYSIS_RUNTIME_GUARDRAILS_RUNTIME_ADAPTER_EVIDENCE_OUTPUT:-$matrix_artifacts/runtime-guardrails-runtime-adapter-evidence.jsonl}"
gvisor_metadata_evidence_output="${APOLYSIS_RUNTIME_GUARDRAILS_GVISOR_METADATA_EVIDENCE_OUTPUT:-$matrix_artifacts/runtime-guardrails-gvisor-metadata-evidence.jsonl}"
kubernetes_agent_sandbox_evidence_output="${APOLYSIS_RUNTIME_GUARDRAILS_KUBERNETES_AGENT_SANDBOX_EVIDENCE_OUTPUT:-$matrix_artifacts/runtime-guardrails-kubernetes-agent-sandbox-evidence.jsonl}"
kata_boundary_evidence_output="${APOLYSIS_RUNTIME_GUARDRAILS_KATA_BOUNDARY_EVIDENCE_OUTPUT:-$matrix_artifacts/runtime-guardrails-kata-boundary-evidence.jsonl}"
request_path="$output_dir/runtime-guardrails-live-runtime-evidence-request.json"
report_path="$output_dir/runtime-guardrails-live-runtime-evidence-report.json"

mkdir -p "$output_dir" "$visibility_output_dir"

APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$matrix_artifacts" \
APOLYSIS_RUNTIME_FOUNDATION_VISIBILITY_OUTPUT_DIR="$visibility_output_dir" \
    ./scripts/test-runtime-foundation-visibility-reports.sh

cargo build -p apolysis-validation --bin apolysis-runtime-guardrails-live-runtime-evidence

python3 - \
    "$request_fixture" \
    "$matrix_artifacts" \
    "$visibility_output_dir/visibility-reports.json" \
    "$adapter_evidence_output" \
    "$gvisor_metadata_evidence_output" \
    "$kubernetes_agent_sandbox_evidence_output" \
    "$kata_boundary_evidence_output" \
    >"$request_path" <<'PY'
import json
import sys
from pathlib import Path

request = json.loads(Path(sys.argv[1]).read_text())
request["artifact_dir"] = sys.argv[2]
request["visibility_reports"] = json.loads(Path(sys.argv[3]).read_text())

def read_jsonl(path):
    evidence_path = Path(path)
    if not evidence_path.exists() or evidence_path.stat().st_size == 0:
        return None
    return [
        json.loads(line)
        for line in evidence_path.read_text().splitlines()
        if line.strip()
    ]

adapter_evidence = read_jsonl(sys.argv[4])
if adapter_evidence is not None:
    request["runtime_adapter_evidence_reports"] = adapter_evidence
gvisor_metadata_evidence = read_jsonl(sys.argv[5])
if gvisor_metadata_evidence is not None:
    request["gvisor_metadata_evidence_reports"] = gvisor_metadata_evidence
kubernetes_agent_sandbox_evidence = read_jsonl(sys.argv[6])
if kubernetes_agent_sandbox_evidence is not None:
    request["kubernetes_agent_sandbox_evidence_reports"] = kubernetes_agent_sandbox_evidence
kata_boundary_evidence = read_jsonl(sys.argv[7])
if kata_boundary_evidence is not None:
    request["kata_boundary_evidence_reports"] = kata_boundary_evidence
print(json.dumps(request, indent=2, sort_keys=True))
PY

"$repo_root/target/debug/apolysis-runtime-guardrails-live-runtime-evidence" \
    <"$request_path" \
    >"$report_path"

echo "apolysis-runtime_guardrails: live runtime evidence bundle report written to $report_path"

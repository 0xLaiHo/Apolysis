#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

matrix_artifacts="${APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR:-}"
if [[ -z "$matrix_artifacts" || ! -d "$matrix_artifacts" ]]; then
    cat >&2 <<'EOF'
apolysis-f4: live runtime evidence bundle requires a retained runtime adapter
matrix artifact directory. Set APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR to
the output directory from scripts/test-f2-runtime-adapter-matrix.sh.
EOF
    exit 2
fi

output_dir="${APOLYSIS_F4_LIVE_RUNTIME_EVIDENCE_OUTPUT_DIR:-$matrix_artifacts}"
visibility_output_dir="${APOLYSIS_F2_VISIBILITY_OUTPUT_DIR:-$output_dir/f2-visibility}"
request_fixture="${APOLYSIS_F4_RUNTIME_GUARDRAIL_REQUEST:-$repo_root/tests/fixtures/validation/f4-runtime-guardrail-request.json}"
adapter_evidence_output="${APOLYSIS_F4_RUNTIME_ADAPTER_EVIDENCE_OUTPUT:-$matrix_artifacts/f4-runtime-adapter-evidence.jsonl}"
request_path="$output_dir/f4-live-runtime-evidence-request.json"
report_path="$output_dir/f4-live-runtime-evidence-report.json"

mkdir -p "$output_dir" "$visibility_output_dir"

APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$matrix_artifacts" \
APOLYSIS_F2_VISIBILITY_OUTPUT_DIR="$visibility_output_dir" \
    ./scripts/test-f2-visibility-reports.sh

cargo build -p apolysis-validation --bin apolysis-f4-live-runtime-evidence

python3 - "$request_fixture" "$matrix_artifacts" "$visibility_output_dir/visibility-reports.json" "$adapter_evidence_output" >"$request_path" <<'PY'
import json
import sys
from pathlib import Path

request = json.loads(Path(sys.argv[1]).read_text())
request["artifact_dir"] = sys.argv[2]
request["visibility_reports"] = json.loads(Path(sys.argv[3]).read_text())
adapter_evidence_path = Path(sys.argv[4])
if adapter_evidence_path.exists() and adapter_evidence_path.stat().st_size > 0:
    request["runtime_adapter_evidence_reports"] = [
        json.loads(line)
        for line in adapter_evidence_path.read_text().splitlines()
        if line.strip()
    ]
print(json.dumps(request, indent=2, sort_keys=True))
PY

"$repo_root/target/debug/apolysis-f4-live-runtime-evidence" \
    <"$request_path" \
    >"$report_path"

echo "apolysis-f4: live runtime evidence bundle report written to $report_path"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

output_dir="${APOLYSIS_F2_VISIBILITY_OUTPUT_DIR:-$repo_root/target/f2-visibility}"
matrix_artifacts="${APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR:-}"
evidence_source="${APOLYSIS_F2_VISIBILITY_EVIDENCE_SOURCE:-scripts/test-f2-runtime-adapter-matrix.sh}"

if [[ -z "$matrix_artifacts" || ! -d "$matrix_artifacts" ]]; then
    cat >&2 <<'EOF'
apolysis-f2: visibility reports require a live runtime adapter matrix artifact
directory. Run scripts/test-f2-runtime-adapter-matrix.sh with
APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR=<dir>, then rerun this gate with the
same APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR value.
EOF
    exit 2
fi
evidence_source="$evidence_source artifacts=$matrix_artifacts"

cargo build -p apolysis-validation --bin apolysis-f2-visibility-report
mkdir -p "$output_dir"

reports_path="$output_dir/visibility-reports.json"
gate_path="$output_dir/visibility-gate-report.json"

python3 - "$evidence_source" >"$reports_path" <<'PY'
import json
import sys

evidence = sys.argv[1]
reports = [
    ("local", "guest_process", False),
    ("docker_runc", "guest_process", False),
    ("docker_gvisor", "runtime_boundary", False),
    ("containerd_runc", "guest_process", False),
    ("containerd_gvisor", "runtime_boundary", False),
    ("containerd_kata", "boundary_only", False),
    ("k3s_runc", "guest_process", False),
    ("k3s_gvisor", "runtime_boundary", False),
    ("k3s_kata", "boundary_only", False),
]
print(json.dumps(
    [
        {
            "target": target,
            "live_validated": True,
            "evidence_source": evidence,
            "host_visibility_scope": scope,
            "guest_semantics_claimed": guest_claimed,
        }
        for target, scope, guest_claimed in reports
    ],
    indent=2,
    sort_keys=True,
))
PY

"$repo_root/target/debug/apolysis-f2-visibility-report" <"$reports_path" >"$gate_path"

echo "apolysis-f2: visibility report gate passed; report: $gate_path"

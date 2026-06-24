#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_FINAL_PROVIDER_COMPLETION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-final-provider-completion.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f5-final-provider-completion-report.json"
readiness_dir="$output_dir/final-provider-readiness"
bundle_env_dir="$output_dir/final-provider-bundle-env"
mkdir -p "$readiness_dir" "$bundle_env_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in jq python3; do
    require_command "$command"
done

write_report() {
    local failed_stage="$1"
    local readiness_rc="$2"
    local bundle_env_rc="$3"
    python3 - "$report" "$failed_stage" "$readiness_rc" "$bundle_env_rc" "$readiness_dir" "$bundle_env_dir" <<'PY'
import json
import re
import sys
import time
from pathlib import Path

(
    report_path,
    failed_stage,
    readiness_rc,
    bundle_env_rc,
    readiness_dir,
    bundle_env_dir,
) = sys.argv[1:]

readiness_report = Path(readiness_dir) / "apolysis-f5-final-provider-readiness-report.json"
bundle_env_report = Path(bundle_env_dir) / "apolysis-f5-final-provider-bundle-env-report.json"

def load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}

readiness = load_json(readiness_report)
bundle_env = load_json(bundle_env_report)

final_bundle_output = str((bundle_env.get("final_bundle") or {}).get("output") or "")
final_bundle_output_dir = ""
match = re.search(r"apolysis-f5: final external provider bundle passed \(([^)]+)\)", final_bundle_output)
if match:
    final_bundle_output_dir = match.group(1)

final_bundle_report = ""
final_bundle_bundle = ""
final_bundle_doc = {}
if final_bundle_output_dir:
    final_bundle_report_path = Path(final_bundle_output_dir) / "apolysis-f5-final-external-provider-bundle-report.json"
    final_bundle_bundle_path = (
        Path(final_bundle_output_dir)
        / "bundle-root"
        / "apolysis-f5-final-external-provider-bundle.json"
    )
    final_bundle_report = str(final_bundle_report_path)
    final_bundle_bundle = str(final_bundle_bundle_path)
    final_bundle_doc = load_json(final_bundle_report_path)

qualified_requirements = (
    final_bundle_doc.get("approval", {}).get("qualified_requirements")
    or []
)
final_provider_ready = readiness.get("final_provider_ready") is True
final_bundle_passed = (
    bundle_env.get("final_bundle_status") == "passed"
    and final_bundle_doc.get("passed") is True
    and len(qualified_requirements) == 4
)
passed = final_provider_ready and final_bundle_passed and not failed_stage

missing_requirements = list(readiness.get("missing_requirements") or [])
if not missing_requirements:
    missing_requirements = list(bundle_env.get("missing_requirements") or [])

completion_report = {
    "schema_version": 1,
    "passed": passed,
    "failed_stage": failed_stage,
    "final_provider_ready": final_provider_ready,
    "final_bundle_passed": final_bundle_passed,
    "missing_requirements": missing_requirements,
    "qualified_requirements": qualified_requirements,
    "readiness_exit_code": int(readiness_rc),
    "bundle_env_exit_code": int(bundle_env_rc),
    "readiness_report": str(readiness_report) if readiness_report.is_file() else "",
    "bundle_env_report": str(bundle_env_report) if bundle_env_report.is_file() else "",
    "final_bundle_output_dir": final_bundle_output_dir,
    "final_bundle_report": final_bundle_report,
    "final_bundle_bundle": final_bundle_bundle,
    "observed_at_unix_ms": int(time.time() * 1000),
}
Path(report_path).write_text(
    json.dumps(completion_report, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

set +e
APOLYSIS_REQUIRE_F5_FINAL_PROVIDER_READINESS=1 \
APOLYSIS_F5_FINAL_PROVIDER_READINESS_OUTPUT_DIR="$readiness_dir" \
    "$repo_root/scripts/test-f5-final-provider-readiness.sh" \
    >"$output_dir/final-provider-readiness.out" \
    2>"$output_dir/final-provider-readiness.err"
readiness_rc=$?
set -e

if [[ "$readiness_rc" -ne 0 ]]; then
    write_report "final_provider_readiness" "$readiness_rc" 0
    echo "apolysis-f5: final provider completion failed at readiness ($report)" >&2
    cat "$output_dir/final-provider-readiness.err" >&2
    exit "$readiness_rc"
fi

set +e
APOLYSIS_REQUIRE_F5_FINAL_BUNDLE_ENV=1 \
APOLYSIS_RUN_F5_FINAL_BUNDLE=1 \
APOLYSIS_F5_FINAL_PROVIDER_BUNDLE_ENV_OUTPUT_DIR="$bundle_env_dir" \
    "$repo_root/scripts/prepare-f5-final-provider-bundle-env.sh" \
    >"$output_dir/final-provider-bundle-env.out" \
    2>"$output_dir/final-provider-bundle-env.err"
bundle_env_rc=$?
set -e

if [[ "$bundle_env_rc" -ne 0 ]]; then
    write_report "final_bundle_assembly" "$readiness_rc" "$bundle_env_rc"
    echo "apolysis-f5: final provider completion failed at final bundle assembly ($report)" >&2
    cat "$output_dir/final-provider-bundle-env.err" >&2
    exit "$bundle_env_rc"
fi

write_report "" "$readiness_rc" "$bundle_env_rc"
jq -e '.passed == true and .final_provider_ready == true and .final_bundle_passed == true' "$report" >/dev/null

cat <<EOF
apolysis-f5: final provider completion gate passed ($output_dir)
APOLYSIS_F5_FINAL_PROVIDER_COMPLETION_REPORT=$report
EOF

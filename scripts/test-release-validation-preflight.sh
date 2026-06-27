#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
preflight_script="$repo_root/scripts/release-validation-preflight.sh"
mkdir -p "$repo_root/target"
output_root="${APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_TEST_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/release-validation-preflight-test.XXXXXX")}"
mkdir -p "$output_root"
output_root="$(cd "$output_root" && pwd)"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-release-validation: missing command: $1" >&2
        exit 1
    }
}

require_command python3

missing_dir="$output_root/missing"
mkdir -p "$missing_dir"
set +e
APOLYSIS_REQUIRE_RELEASE_VALIDATION_PREFLIGHT=1 \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_OUTPUT_DIR="$missing_dir" \
    "$preflight_script" >"$missing_dir/preflight.out" 2>&1
missing_status=$?
set -e
if [[ "$missing_status" -eq 0 ]]; then
    echo "apolysis-release-validation: required-mode preflight must fail without inputs" >&2
    exit 1
fi

python3 - "$output_root" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
fixture = root / "fixture"
provider = fixture / "provider-root"
readback = fixture / "readback"
signoff = fixture / "signoff"
for path in (provider, readback, signoff):
    path.mkdir(parents=True, exist_ok=True)

def write_json(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

for name in (
    "signing-evidence.json",
    "signing-report.json",
    "worm-evidence.json",
    "worm-report.json",
    "registry-evidence.json",
    "registry-report.json",
    "dockerhub-registry-promotion-evidence.json",
    "dockerhub-registry-promotion-report.json",
    "managed-mesh-evidence.json",
    "managed-mesh-report.json",
):
    write_json(provider / name, {"source": "release_validation_preflight_fixture", "name": name})

aggregate = fixture / "apolysis-regulated-release-report.json"
write_json(
    aggregate,
    {
        "schema_version": 1,
        "phase": "regulated-release.final-release-signoff",
        "passed": True,
        "regulated_release_ready": True,
        "pre_signoff_regulated_release_ready": True,
        "final_release_signoff_ready": True,
        "missing_requirements": [],
        "steps": {
            "live_provider_readback": {"secret_scan_findings": []},
            "final_release_signoff": {"secret_scan_findings": []},
        },
    },
)

external_readback = readback / "external-readback.json"
write_json(
    external_readback,
    {
        "source": "live_provider_readback",
        "provider": "cloudflare_r2_bucket_lock",
        "readback_verified": True,
        "retention_policy_verified": True,
        "delete_denied": True,
        "observed_at_unix_ms": 1782399000000,
    },
)

registry_readback = readback / "registry-readback.json"
write_json(
    registry_readback,
    {
        "source": "live_provider_readback",
        "provider": "docker_hub_registry",
        "digest_readback_verified": True,
        "immutability_policy_verified": True,
        "mutation_denied": True,
        "observed_at_unix_ms": 1782399000000,
    },
)

signoff_artifact = signoff / "final-signoff.json"
write_json(
    signoff_artifact,
    {
        "source": "operator_final_release_signoff",
        "phase": "regulated-release.final-release-signoff",
        "release_scope": "regulated_release",
        "decision": "approve_regulated_release",
        "approver": "release-validation-test",
        "approved_at": "2026-06-27T00:00:00Z",
        "rationale": "fixture proves preflight validation and evidence index generation",
        "regulated_release_ready": True,
        "no_secret_material_recorded": True,
        "missing_requirements": [],
    },
)
PY

fixture_paths="$(python3 - "$output_root" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
fixture = root / "fixture"
print(json.dumps({
    "provider_root": str(fixture / "provider-root"),
    "aggregate": str(fixture / "apolysis-regulated-release-report.json"),
    "external_readback": str(fixture / "readback" / "external-readback.json"),
    "registry_readback": str(fixture / "readback" / "registry-readback.json"),
    "signoff": str(fixture / "signoff" / "final-signoff.json"),
}))
PY
)"

green_dir="$output_root/green"
mkdir -p "$green_dir"
eval "$(
    python3 - "$fixture_paths" <<'PY'
import json
import shlex
import sys
paths = json.loads(sys.argv[1])
for key, value in paths.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

APOLYSIS_REQUIRE_RELEASE_VALIDATION_PREFLIGHT=1 \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_OUTPUT_DIR="$green_dir" \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_PROVIDER_ROOT="$provider_root" \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_AGGREGATE_REPORT="$aggregate" \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_EXTERNAL_RETENTION_READBACK_EVIDENCE="$external_readback" \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_IMMUTABLE_REGISTRY_READBACK_EVIDENCE="$registry_readback" \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_FINAL_SIGNOFF="$signoff" \
    "$preflight_script"

python3 - "$green_dir/apolysis-release-validation-preflight-report.json" "$green_dir/apolysis-release-validation-evidence-index.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
index = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if report.get("release_validation_preflight_ready") is not True:
    raise SystemExit("preflight report did not declare readiness")
if report.get("missing_requirements") != []:
    raise SystemExit(f"preflight report has missing requirements: {report.get('missing_requirements')}")
if report.get("evidence_index") != str(Path(sys.argv[2])):
    raise SystemExit("preflight report does not point at evidence index")
items = index.get("items")
if not isinstance(items, list) or len(items) < 8:
    raise SystemExit("evidence index did not include expected retained artifacts")
for item in items:
    if not item.get("sha256") or not item.get("path") or not item.get("kind"):
        raise SystemExit(f"malformed evidence index item: {item}")
if index.get("secret_scan_findings") != []:
    raise SystemExit("evidence index must report empty secret_scan_findings")
PY

printf 'apolysis-release-validation: preflight gate test passed (%s)\n' "$green_dir"

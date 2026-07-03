#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

workflow=".github/workflows/release-artifacts.yml"
packager="scripts/package-release-artifacts.sh"
signer="scripts/package-release-signing-evidence.sh"
makefile="Makefile"

fail() {
    printf 'release signing check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing $1"
}

require_contains() {
    local file="$1"
    local needle="$2"
    grep -Fq -- "$needle" "$file" || fail "$file missing required text: $needle"
}

require_file "$workflow"
require_file "$packager"
require_file "$signer"
require_contains "$makefile" "test-release-signing:"

for needle in \
    "signing_evidence_run_id" \
    "APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID" \
    "vars.APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID" \
    "require_signing_evidence" \
    "actions/download-artifact@v4" \
    "env.APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID" \
    "./scripts/package-release-signing-evidence.sh" \
    "apolysis-release-signing-manifest.json" \
    "apolysis-release-signing-evidence.json" \
    "apolysis-regulated-release-signing-evidence-report.json"; do
    require_contains "$workflow" "$needle"
done

for needle in \
    "APOLYSIS_RELEASE_ARTIFACT_DIR" \
    "APOLYSIS_RELEASE_SIGNING_EVIDENCE" \
    "APOLYSIS_RELEASE_SIGNING_REPORT" \
    "APOLYSIS_REQUIRE_RELEASE_SIGNING" \
    "APOLYSIS_REGULATED_RELEASE_SIGNING_EVIDENCE" \
    "test-regulated-release-signing-evidence.sh" \
    "apolysis-release-signing-manifest.json" \
    "release_manifest_sha256"; do
    require_contains "$signer" "$needle"
done

tmpdir="$(mktemp -d "$repo_root/target/release-signing-test.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

fixture_bin="$tmpdir/apolysis"
fixture_bpf="$tmpdir/apolysis_observer.bpf.o"
artifact_dir="$tmpdir/artifacts"
signing_dir="$tmpdir/signing"

printf '#!/usr/bin/env bash\nprintf "apolysis fixture\\n"\n' >"$fixture_bin"
chmod +x "$fixture_bin"
printf 'fixture bpf object\n' >"$fixture_bpf"

APOLYSIS_RELEASE_VERSION="v0.2.0-test" \
APOLYSIS_RELEASE_TARGET="x86_64-unknown-linux-gnu" \
APOLYSIS_RELEASE_BINARY="$fixture_bin" \
APOLYSIS_RELEASE_BPF_OBJECT="$fixture_bpf" \
APOLYSIS_RELEASE_OUTPUT_DIR="$artifact_dir" \
    "$packager"

release_manifest="$artifact_dir/apolysis-release-manifest.json"
release_manifest_sha="$(sha256sum "$release_manifest" | awk '{print $1}')"
signing_evidence="$signing_dir/signing-evidence.json"
signing_report="$signing_dir/signing-report.json"
mkdir -p "$signing_dir"

APOLYSIS_RELEASE_VERSION="v0.2.0-test" \
APOLYSIS_RELEASE_TARGET="x86_64-unknown-linux-gnu" \
APOLYSIS_RELEASE_ARTIFACT_DIR="$artifact_dir" \
APOLYSIS_REQUIRE_RELEASE_SIGNING=0 \
    "$signer"

python3 - "$artifact_dir/apolysis-release-signing-manifest.json" "$release_manifest_sha" <<'PY'
import json
import sys
from pathlib import Path

doc = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert doc["release_signing_ready"] is False
assert doc["release_manifest_sha256"] == sys.argv[2]
assert "retained_release_signing_evidence" in doc["missing_requirements"]
assert doc["fail_closed_required"] is False
PY

python3 - "$signing_evidence" "$signing_report" "$release_manifest_sha" <<'PY'
import json
import sys
import time
from pathlib import Path

evidence_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
release_manifest_sha = sys.argv[3]
now = int(time.time() * 1000)
evidence = {
    "evidence_id": "release-signing-fixture",
    "source": "live_provider",
    "provider": "aws_kms",
    "key_uri": "awskms://alias/apolysis-release-signing",
    "algorithm": "rsa_pkcs1_sha256",
    "release_manifest_sha256": release_manifest_sha,
    "signature_sha256": "0" * 64,
    "public_key_sha256": "1" * 64,
    "signature_verified": True,
    "private_key_non_extractable": True,
    "private_key_sensitive": True,
    "key_generated_in_provider": True,
    "operator_approved": True,
    "cleanup_confirmed": True,
    "observed_at_unix_ms": now,
}
report = {
    "schema_version": 1,
    "phase": "production-hardening.signing-execution",
    "passed": True,
    "approval": {
        "provider": "aws_kms",
        "release_manifest_sha256": release_manifest_sha,
        "observed_at_unix_ms": now,
    },
}
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

APOLYSIS_RELEASE_VERSION="v0.2.0-test" \
APOLYSIS_RELEASE_TARGET="x86_64-unknown-linux-gnu" \
APOLYSIS_RELEASE_ARTIFACT_DIR="$artifact_dir" \
APOLYSIS_RELEASE_SIGNING_EVIDENCE="$signing_evidence" \
APOLYSIS_RELEASE_SIGNING_REPORT="$signing_report" \
APOLYSIS_REQUIRE_RELEASE_SIGNING=1 \
    "$signer"

signing_manifest="$artifact_dir/apolysis-release-signing-manifest.json"
release_signing_evidence="$artifact_dir/apolysis-release-signing-evidence.json"
release_signing_report="$artifact_dir/apolysis-release-signing-report.json"
regulated_report="$artifact_dir/apolysis-regulated-release-signing-evidence-report.json"

[[ -s "$signing_manifest" ]] || fail "missing release signing manifest"
[[ -s "$release_signing_evidence" ]] || fail "missing copied signing evidence"
[[ -s "$release_signing_report" ]] || fail "missing copied signing report"
[[ -s "$regulated_report" ]] || fail "missing regulated-release signing report"

python3 - "$signing_manifest" "$release_manifest_sha" "$release_signing_evidence" "$release_signing_report" "$regulated_report" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
release_manifest_sha = sys.argv[2]
evidence_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
regulated_report_path = Path(sys.argv[5])

doc = json.loads(manifest_path.read_text(encoding="utf-8"))

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

assert doc["schema_version"] == 1
assert doc["release_version"] == "v0.2.0-test"
assert doc["target"] == "x86_64-unknown-linux-gnu"
assert doc["release_signing_ready"] is True
assert doc["provider"] == "aws_kms"
assert doc["release_manifest_sha256"] == release_manifest_sha
assert doc["artifacts"]["signing_evidence"]["path"] == evidence_path.name
assert doc["artifacts"]["signing_evidence"]["sha256"] == sha256(evidence_path)
assert doc["artifacts"]["signing_report"]["path"] == report_path.name
assert doc["artifacts"]["signing_report"]["sha256"] == sha256(report_path)
assert doc["artifacts"]["regulated_release_report"]["path"] == regulated_report_path.name
assert doc["artifacts"]["regulated_release_report"]["sha256"] == sha256(regulated_report_path)
PY

bad_evidence="$signing_dir/signing-evidence-bad.json"
python3 - "$signing_evidence" "$bad_evidence" <<'PY'
import json
import sys
from pathlib import Path

source, dest = map(Path, sys.argv[1:])
doc = json.loads(source.read_text(encoding="utf-8"))
doc["release_manifest_sha256"] = "f" * 64
dest.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if APOLYSIS_RELEASE_VERSION="v0.2.0-test" \
    APOLYSIS_RELEASE_TARGET="x86_64-unknown-linux-gnu" \
    APOLYSIS_RELEASE_ARTIFACT_DIR="$artifact_dir" \
    APOLYSIS_RELEASE_SIGNING_EVIDENCE="$bad_evidence" \
    APOLYSIS_RELEASE_SIGNING_REPORT="$signing_report" \
    APOLYSIS_REQUIRE_RELEASE_SIGNING=1 \
        "$signer" >/dev/null 2>&1; then
    fail "release signing accepted mismatched release_manifest_sha256"
fi

printf 'release signing check passed\n'

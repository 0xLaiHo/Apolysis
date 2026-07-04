#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'signed release artifact dry-run check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing required file: $1"
}

require_contains() {
    local file="$1"
    local needle="$2"
    grep -Fq -- "$needle" "$file" || fail "$file missing required text: $needle"
}

doc="docs/signed-release-artifact-dry-run.md"
unsigned_doc="docs/release-artifact-dry-run.md"
workflow=".github/workflows/release-artifacts.yml"
release_validation_workflow=".github/workflows/release-validation.yml"
release_validation_gate="scripts/test-release-validation-ci.sh"
makefile="Makefile"

for file in \
    "$doc" \
    "$unsigned_doc" \
    "$workflow" \
    "$release_validation_workflow" \
    "$release_validation_gate" \
    "$makefile" \
    README.md \
    README.zh-CN.md; do
    require_file "$file"
done

for needle in \
    "Signed Release Artifact Dry Run" \
    "gh workflow run release-artifacts.yml" \
    "require_signing_evidence=true" \
    "ProductionHardening_AWS_ROLE_TO_ASSUME" \
    "ProductionHardening_AWS_KMS_KEY_ID" \
    "ProductionHardening_AWS_REGION" \
    "APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID" \
    "apolysis-release-signing-evidence.json" \
    "apolysis-release-signing-report.json" \
    "apolysis-regulated-release-signing-evidence-report.json" \
    "release_signing_ready" \
    "cloud_kms" \
    "awskms://" \
    "signature_verified" \
    "apolysis-\${version}-x86_64-unknown-linux-gnu/bin/apolysis" \
    "does not create a GitHub Release" \
    "28694166781"; do
    require_contains "$doc" "$needle"
done

require_contains "$unsigned_doc" "signed-release-artifact-dry-run.md"
require_contains "$workflow" "require_signing_evidence"
require_contains "$workflow" "Sign release manifest with AWS KMS"
require_contains "$workflow" "apolysis-release-signing-evidence.json"
require_contains "$makefile" "test-signed-release-artifact-dry-run:"
require_contains "$release_validation_workflow" "make test-signed-release-artifact-dry-run"
require_contains "$release_validation_gate" "test-signed-release-artifact-dry-run:"
require_contains "$release_validation_gate" "make test-signed-release-artifact-dry-run"
require_contains README.md "docs/signed-release-artifact-dry-run.md"
require_contains README.zh-CN.md "docs/signed-release-artifact-dry-run.md"

printf 'signed release artifact dry-run check passed\n'

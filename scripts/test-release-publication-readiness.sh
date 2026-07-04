#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'release publication readiness check failed: %s\n' "$*" >&2
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

doc="docs/v0.2.0-release-publication.md"
signed_dry_run_doc="docs/signed-release-artifact-dry-run.md"
release_workflow=".github/workflows/release-artifacts.yml"
release_validation_workflow=".github/workflows/release-validation.yml"
release_validation_gate="scripts/test-release-validation-ci.sh"
makefile="Makefile"

for file in \
    "$doc" \
    "$signed_dry_run_doc" \
    "$release_workflow" \
    "$release_validation_workflow" \
    "$release_validation_gate" \
    "$makefile" \
    README.md \
    README.zh-CN.md; do
    require_file "$file"
done

for needle in \
    "v0.2.0 Release Publication" \
    "release/v0.2.0" \
    "v0.2.0-signed-dry-run.20260704035609" \
    "28694166781" \
    "APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID" \
    "ProductionHardening_AWS_ROLE_TO_ASSUME" \
    "ProductionHardening_AWS_KMS_KEY_ID" \
    "ProductionHardening_AWS_REGION" \
    "gh pr create" \
    "git tag -a v0.2.0" \
    "git push origin v0.2.0" \
    "gh run watch" \
    "gh release view v0.2.0" \
    "sha256sum -c" \
    "apolysis-release-signing-evidence.json" \
    "apolysis-release-signing-report.json" \
    "apolysis-regulated-release-signing-evidence-report.json" \
    "signature_verified" \
    "Do not push the final tag before release branch review passes"; do
    require_contains "$doc" "$needle"
done

require_contains "$signed_dry_run_doc" "docs/v0.2.0-release-publication.md"
require_contains "$release_workflow" "push:"
require_contains "$release_workflow" "tags:"
require_contains "$release_workflow" "'v*'"
require_contains "$release_workflow" "gh release upload"
require_contains "$release_workflow" "apolysis-release-signing-evidence.json"
require_contains "$makefile" "test-release-publication-readiness:"
require_contains "$makefile" "./scripts/test-release-publication-readiness.sh"
require_contains "$release_validation_workflow" "make test-release-publication-readiness"
require_contains "$release_validation_gate" "test-release-publication-readiness:"
require_contains "$release_validation_gate" "make test-release-publication-readiness"
require_contains README.md "docs/v0.2.0-release-publication.md"
require_contains README.zh-CN.md "docs/v0.2.0-release-publication.md"

printf 'release publication readiness check passed\n'

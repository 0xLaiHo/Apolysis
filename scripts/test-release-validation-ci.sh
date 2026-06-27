#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="$repo_root/.github/workflows/release-validation.yml"
makefile="$repo_root/Makefile"
mkdir -p "$repo_root/target"
output_root="${APOLYSIS_RELEASE_VALIDATION_CI_TEST_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/release-validation-ci-test.XXXXXX")}"
mkdir -p "$output_root"
output_root="$(cd "$output_root" && pwd)"

fail() {
    printf 'release validation CI check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    local path="$1"
    [[ -f "$path" ]] || fail "missing required file: $path"
}

require_contains() {
    local path="$1"
    local needle="$2"
    grep -Fq "$needle" "$path" || fail "$path must contain: $needle"
}

require_not_contains() {
    local path="$1"
    local needle="$2"
    if grep -Fq "$needle" "$path"; then
        fail "$path must not contain: $needle"
    fi
}

require_file "$workflow"
require_file "$makefile"

require_contains "$makefile" "test-release-validation-ci:"
require_contains "$workflow" "name: Release Validation"
require_contains "$workflow" "pull_request:"
require_contains "$workflow" "push:"
require_contains "$workflow" "workflow_dispatch:"
require_contains "$workflow" "contents: read"
require_contains "$workflow" "make test-release-validation-ci"
require_contains "$workflow" "make test-release-validation-handoff"
require_contains "$workflow" "make test-release-validation-preflight"
require_contains "$workflow" "make test-regulated-release-final-release-signoff"
require_contains "$workflow" "make test-production-hardening"
require_contains "$workflow" "APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_APPROVER: ci-release-validation"
require_contains "$workflow" "APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_DECISION: approve_regulated_release"
require_contains "$workflow" "APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_NO_SECRET_MATERIAL_RECORDED: \"1\""
require_not_contains "$workflow" "KUBECONFIG="
require_not_contains "$workflow" "secrets."
require_not_contains "$workflow" "ProductionHardening_"

isolated_repo="$output_root/isolated/Apolysis"
mkdir -p "$isolated_repo/scripts" "$isolated_repo/docs" "$isolated_repo/.github/workflows"
cp "$repo_root/Makefile" "$isolated_repo/Makefile"
cp "$repo_root/docs/release-validation-handoff.md" "$isolated_repo/docs/release-validation-handoff.md"
cp "$repo_root/scripts/test-release-validation-handoff.sh" "$isolated_repo/scripts/test-release-validation-handoff.sh"
cp "$repo_root/.github/workflows/release-validation.yml" "$isolated_repo/.github/workflows/release-validation.yml"
chmod +x "$isolated_repo/scripts/test-release-validation-handoff.sh"

(
    cd "$isolated_repo"
    ./scripts/test-release-validation-handoff.sh
)

printf 'release validation CI check passed\n'

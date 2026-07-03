#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'release artifact dry-run check failed: %s\n' "$*" >&2
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

doc="docs/release-artifact-dry-run.md"
workflow=".github/workflows/release-artifacts.yml"
makefile="Makefile"

for file in "$doc" "$workflow" "$makefile" README.md README.zh-CN.md; do
    require_file "$file"
done

for needle in \
    "Release Artifact Dry Run" \
    "gh workflow run release-artifacts.yml" \
    "require_signing_evidence=false" \
    "gh run watch" \
    "gh run download" \
    "sha256sum -c" \
    "apolysis-release-manifest.json" \
    "apolysis-release-signing-manifest.json" \
    "release_signing_ready:false" \
    "not a published GitHub Release" \
    "tag push" \
    "retained signing evidence"; do
    require_contains "$doc" "$needle"
done

require_contains "$workflow" "workflow_dispatch:"
require_contains "$workflow" "require_signing_evidence"
require_contains "$workflow" "actions/upload-artifact@v4"
require_contains "$workflow" "gh release upload"
require_contains "$makefile" "test-release-artifact-dry-run:"
require_contains README.md "docs/release-artifact-dry-run.md"
require_contains README.zh-CN.md "docs/release-artifact-dry-run.md"

printf 'release artifact dry-run check passed\n'

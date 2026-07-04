#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

doc="docs/timeline-shipping.md"
workflow=".github/workflows/release-validation.yml"
makefile="Makefile"
ci_contract="scripts/test-release-validation-ci.sh"

fail() {
    printf 'timeline shipping check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing required file: $1"
}

require_contains() {
    local path="$1"
    local needle="$2"
    grep -Fq -- "$needle" "$path" || fail "$path must contain: $needle"
}

require_not_contains() {
    local path="$1"
    local needle="$2"
    if grep -Fq -- "$needle" "$path"; then
        fail "$path must not contain: $needle"
    fi
}

require_file "$doc"
require_file "$workflow"
require_file "$makefile"
require_file "$ci_contract"

for term in \
    "JSONL remains the shipping contract" \
    "Vector" \
    "Fluent Bit" \
    "/var/lib/apolysis/sessions/*/timeline.jsonl" \
    "apolysis verify hash-chain" \
    "Do not rewrite record payloads" \
    "OTLP is intentionally deferred"; do
    require_contains "$doc" "$term"
done

for term in \
    "type = \"file\"" \
    "multiline.mode = \"halt_before\"" \
    "[INPUT]" \
    "Name tail" \
    "Parser json"; do
    require_contains "$doc" "$term"
done

require_not_contains "$doc" "OTLP exporter"
require_not_contains "$doc" "central query plane"

require_contains README.md "docs/timeline-shipping.md"
require_contains README.zh-CN.md "docs/timeline-shipping.md"
require_contains "$makefile" "test-timeline-shipping:"
require_contains "$workflow" "make test-timeline-shipping"
require_contains "$ci_contract" "test-timeline-shipping:"
require_contains "$ci_contract" "make test-timeline-shipping"

printf 'timeline shipping check passed\n'

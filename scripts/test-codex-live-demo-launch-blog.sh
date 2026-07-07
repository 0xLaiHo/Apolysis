#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'codex live demo launch blog check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing required file: $1"
}

require_contains() {
    local path="$1"
    local needle="$2"
    grep -Fq -- "$needle" "$path" || fail "$path missing required text: $needle"
}

require_not_matches() {
    local path="$1"
    local pattern="$2"
    if grep -Eq -- "$pattern" "$path"; then
        fail "$path must not match: $pattern"
    fi
}

blog="docs/codex-live-demo-launch-blog.md"
public_assets_doc="docs/codex-live-demo-public-assets.md"
runbook="docs/codex-live-demo-runbook.md"
summary="docs/assets/codex-live-demo/summary.json"
excerpt="docs/assets/codex-live-demo/evidence-excerpt.jsonl"

require_file "$blog"
require_file "$public_assets_doc"
require_file "$runbook"
require_file "$summary"
require_file "$excerpt"

for needle in \
    "Draft status: P1 launch blog draft" \
    "Apolysis: A Flight Recorder For AI Coding Agents" \
    "Why Harness Logs Are Not Enough" \
    "not independent evidence" \
    "The intent boundary" \
    "The isolation boundary" \
    "The evidence boundary" \
    "apolysis observe" \
    "--agent-run -- codex exec --json" \
    "match_basis" \
    "process_executable" \
    "missing_intent" \
    "path_token:*" \
    "Reproduce The Demo" \
    "docs/codex-live-demo-runbook.md" \
    "docs/codex-live-demo-public-assets.md" \
    "v0.2.0" \
    "AWS KMS-backed signing evidence" \
    "final README demo GIF and asciinema cast"; do
    require_contains "$blog" "$needle"
done

require_contains "$repo_root/Makefile" "test-codex-live-demo-launch-blog:"

require_contains "$repo_root/.github/workflows/release-validation.yml" "make test-codex-live-demo-launch-blog"
require_contains "$repo_root/README.md" "docs/codex-live-demo-launch-blog.md"
require_contains "$repo_root/README.zh-CN.md" "docs/codex-live-demo-launch-blog.md"

require_not_matches "$blog" '/home/[^[:space:]"'\'']+'
require_not_matches "$blog" 'APOLYSIS_FAKE_(KEY|SECRET)'
require_not_matches "$blog" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
require_not_matches "$blog" 'sk-[A-Za-z0-9_-]{20,}'
require_not_matches "$blog" 'aws_secret_access_key|aws_access_key_id'
require_not_matches "$blog" 'password[[:space:]]*[:=]'

word_count="$(wc -w <"$blog")"
(( word_count >= 1200 )) || fail "$blog is too short for the approximately 1,500-word launch draft"
(( word_count <= 2200 )) || fail "$blog is too long for a focused launch draft"

printf 'codex live demo launch blog check passed\n'

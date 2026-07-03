#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'P1 launch materials check failed: %s\n' "$*" >&2
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

require_not_matches() {
    local file="$1"
    local pattern="$2"
    if grep -Eq -- "$pattern" "$file"; then
        fail "$file must not match: $pattern"
    fi
}

blog="docs/blog/apolysis-flight-recorder-for-ai-coding-agents.md"
visual="docs/assets/codex-live-demo/terminal-demo.svg"

require_file "$blog"
require_file "$visual"

for needle in \
    "Apolysis: A Flight Recorder For AI Coding Agents" \
    "Intent authorization" \
    "Execution isolation" \
    "Side-effect verification" \
    "harness logs are insufficient" \
    "apolysis observe --agent-run -- codex" \
    "make test-codex-live-demo-public-assets" \
    "process_executable" \
    "missing_intent" \
    "path_token" \
    "No raw live evidence is committed"; do
    require_contains "$blog" "$needle"
done

word_count="$(wc -w <"$blog")"
(( word_count >= 1100 )) || fail "$blog is too short for the launch narrative"
(( word_count <= 1900 )) || fail "$blog is too long for the launch narrative"

for needle in \
    "<svg" \
    "role=\"img\"" \
    "Codex declares" \
    "Apolysis observes" \
    "process_executable" \
    "missing_intent" \
    "path_token"; do
    require_contains "$visual" "$needle"
done

for path in "$blog" "$visual"; do
    require_not_matches "$path" '/home/[^[:space:]"'\'']+'
    require_not_matches "$path" 'APOLYSIS_FAKE_(KEY|SECRET)'
    require_not_matches "$path" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
    require_not_matches "$path" 'sk-[A-Za-z0-9_-]{20,}'
    require_not_matches "$path" 'aws_secret_access_key|aws_access_key_id'
    require_not_matches "$path" 'password[[:space:]]*[:=]'
done

visual_bytes="$(wc -c <"$visual")"
(( visual_bytes <= 30000 )) || fail "$visual is too large for a README-first visual"

require_contains README.md "docs/assets/codex-live-demo/terminal-demo.svg"
require_contains README.md "docs/blog/apolysis-flight-recorder-for-ai-coding-agents.md"
require_contains README.zh-CN.md "docs/assets/codex-live-demo/terminal-demo.svg"
require_contains README.zh-CN.md "docs/blog/apolysis-flight-recorder-for-ai-coding-agents.md"
require_contains "$repo_root/.github/workflows/release-validation.yml" "make test-p1-launch-materials"
require_contains "$repo_root/scripts/test-release-validation-ci.sh" "test-p1-launch-materials:"

printf 'P1 launch materials check passed\n'

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'codex live demo public assets check failed: %s\n' "$*" >&2
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

doc="docs/codex-live-demo-public-assets.md"
asset_dir="docs/assets/codex-live-demo"
summary="$asset_dir/summary.json"
excerpt="$asset_dir/evidence-excerpt.jsonl"
transcript="$asset_dir/terminal-transcript.txt"

require_file "$doc"
require_file "$summary"
require_file "$excerpt"
require_file "$transcript"

for needle in \
    "validated_local_live" \
    "process_executable" \
    "missing_intent" \
    "fake credential" \
    "path_token" \
    "No raw live evidence is committed"; do
    require_contains "$doc" "$needle"
done

for path in "$summary" "$excerpt" "$transcript"; do
    require_not_matches "$path" '/home/[^[:space:]"'\'']+'
    require_not_matches "$path" 'APOLYSIS_FAKE_(KEY|SECRET)'
    require_not_matches "$path" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
    require_not_matches "$path" 'sk-[A-Za-z0-9_-]{20,}'
    require_not_matches "$path" 'aws_secret_access_key|aws_access_key_id'
    require_not_matches "$path" 'password[[:space:]]*[:=]'
done

summary_bytes="$(wc -c <"$summary")"
excerpt_bytes="$(wc -c <"$excerpt")"
transcript_bytes="$(wc -c <"$transcript")"
(( summary_bytes <= 4096 )) || fail "$summary is too large for a curated public asset"
(( excerpt_bytes <= 20000 )) || fail "$excerpt is too large for a curated public asset"
(( transcript_bytes <= 12000 )) || fail "$transcript is too large for a curated public asset"

jq -e '
  .demo_status == "validated_local_live" and
  .source_session == "codex-live-demo" and
  .timeline_lines == 79949 and
  .intent_correlation_count == 1 and
  .redaction_boundary == "curated_public_excerpt"
' "$summary" >/dev/null

jq -e 'select(.record_type=="intent_correlation" and .match_basis=="process_executable" and .command=="./scripts/run-codex-live-demo-workload.sh")' \
  "$excerpt" >/dev/null
jq -e 'select(.record_type=="accountability_finding" and .kind=="missing_intent" and .decision=="review")' \
  "$excerpt" >/dev/null
jq -e 'select(.record_type=="policy_violation" and .rule_id=="credentials.deny_read" and (.target|startswith("path_token:")))' \
  "$excerpt" >/dev/null

require_contains "$repo_root/.github/workflows/release-validation.yml" "make test-codex-live-demo-public-assets"

printf 'codex live demo public assets check passed\n'

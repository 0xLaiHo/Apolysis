#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'codex mismatch demo check failed: %s\n' "$*" >&2
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

demo_doc="docs/codex-intent-mismatch-demo.md"
codex_log="tests/fixtures/codex-mismatch/codex-response-items.jsonl"
observed_timeline="tests/fixtures/codex-mismatch/observed-timeline.jsonl"
expected_findings="tests/fixtures/codex-mismatch/expected-findings.contains"

for file in "$demo_doc" "$codex_log" "$observed_timeline" "$expected_findings"; do
    require_file "$file"
done

for needle in \
    "apolysis observe --agent-run -- codex" \
    "apolysis intent ingest" \
    "apolysis intent correlate" \
    "tests/fixtures/codex-mismatch" \
    "credential_read" \
    "missing_intent"; do
    require_contains "$demo_doc" "$needle"
done

require_contains "$codex_log" '"type":"response_item"'
require_contains "$codex_log" '"type":"function_call"'
require_contains "$codex_log" 'cargo test -p apolysis-cli --test intent'

require_contains "$observed_timeline" '"record_type":"event"'
require_contains "$observed_timeline" '"event_type":"credential_read"'
require_contains "$observed_timeline" '.aws/credentials'
require_contains "$observed_timeline" '"process_command":"cargo test -p apolysis-cli --test intent"'

mkdir -p "$repo_root/target"
output_root="${APOLYSIS_CODEX_MISMATCH_DEMO_TEST_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/codex-mismatch-demo.XXXXXX")}"
mkdir -p "$output_root"
intent_output="$output_root/intent.codex.jsonl"
correlation_output="$output_root/intent-correlation.jsonl"

cargo run -q -p apolysis-cli -- intent ingest \
    --adapter codex-jsonl \
    --input "$codex_log" \
    --session codex-mismatch-demo \
    --output "$intent_output" \
    --workspace-root "$repo_root"

cargo run -q -p apolysis-cli -- intent correlate \
    --intent-input "$intent_output" \
    --timeline-input "$observed_timeline" \
    --output "$correlation_output"

require_contains "$intent_output" '"record_type":"intent"'
require_contains "$intent_output" '"intent_source":"codex"'
require_contains "$intent_output" '"declared_action":"shell.command"'
require_contains "$intent_output" '"command":"cargo test -p apolysis-cli --test intent"'

require_contains "$correlation_output" '"record_type":"intent_correlation"'
require_contains "$correlation_output" '"match_basis":"process_command_exact"'
require_contains "$correlation_output" '"record_type":"accountability_finding"'
require_contains "$correlation_output" '"kind":"missing_intent"'

while IFS= read -r expected; do
    [[ -z "$expected" ]] && continue
    require_contains "$correlation_output" "$expected"
done < "$expected_findings"

printf 'codex mismatch demo check passed\n'

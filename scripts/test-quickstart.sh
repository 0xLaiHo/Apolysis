#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verifies the zero-privilege quickstart: `make quickstart` must reproduce the
# intent/side-effect accountability verdict on the bundled fixture without root
# or eBPF. This is the trial front door, so it must stay working.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

output="$(make quickstart 2>&1)"

require_contains() {
    if ! printf '%s' "$output" | grep -qF -- "$1"; then
        echo "quickstart check failed: expected output to contain: $1" >&2
        echo "--- actual output ---" >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
}

# The readable summary and both sides of the verdict must be present.
require_contains "Apolysis accountability summary"
require_contains "linked by explicit identifier"
require_contains "inferred/ambiguous candidate(s)"
require_contains "missing_intent"
require_contains "unobserved_intent"
require_contains "codex:call-run-tests"
require_contains "credential_read"
require_contains ".aws/credentials"

# The correlation JSONL must be written for anyone who wants the raw evidence.
if [[ ! -s target/quickstart/correlation.jsonl ]]; then
    echo "quickstart check failed: target/quickstart/correlation.jsonl was not written" >&2
    exit 1
fi

while IFS= read -r expected; do
    if ! grep -qF -- "$expected" target/quickstart/correlation.jsonl; then
        printf 'quickstart check failed: expected evidence field is missing\n' >&2
        exit 1
    fi
done < tests/fixtures/codex-mismatch/expected-findings.contains

# This historical fixture has no propagated identifier. It must not claim an
# Exact Relation after the correlation hardening.
if grep -qF '"record_type":"intent_correlation"' target/quickstart/correlation.jsonl; then
    printf 'quickstart check failed: legacy fixture produced an exact relation\n' >&2
    exit 1
fi

# Content-off persistence must not regress by exposing the declared argv in
# either the human summary or the durable correlation evidence.
forbidden_command="cargo test -p apolysis-cli --test intent"
if printf '%s' "$output" | grep -qF -- "$forbidden_command" ||
    grep -qF -- "$forbidden_command" target/quickstart/correlation.jsonl; then
    echo "quickstart check failed: command content crossed the persistence boundary" >&2
    exit 1
fi

echo "quickstart check passed"

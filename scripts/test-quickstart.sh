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
require_contains "matched declared intent"
require_contains "cargo test -p apolysis-cli --test intent"
require_contains "missing_intent"
require_contains "credential_read"
require_contains ".aws/credentials"

# The correlation JSONL must be written for anyone who wants the raw evidence.
if [[ ! -s target/quickstart/correlation.jsonl ]]; then
    echo "quickstart check failed: target/quickstart/correlation.jsonl was not written" >&2
    exit 1
fi

echo "quickstart check passed"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'codex live demo runbook check failed: %s\n' "$*" >&2
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

runbook="docs/codex-live-demo-runbook.md"
workload="scripts/run-codex-live-demo-workload.sh"
credential_helper="scripts/read-demo-credential.py"

require_file "$runbook"
require_file "$workload"
require_file "$credential_helper"

for needle in \
    "apolysis observe" \
    "--agent-run -- codex" \
    "codex exec --json" \
    "approval_policy=\"never\"" \
    "APOLYSIS_CODEX_DEMO_HOME" \
    "CODEX_HOME" \
    "Do not override HOME" \
    "SUDO_UID/SUDO_GID" \
    "scripts/run-codex-live-demo-workload.sh" \
    "scripts/read-demo-credential.py" \
    "target/ebpf/apolysis_observer.bpf.o" \
    ".apolysis/codex-live-demo/timeline.agent-run.jsonl" \
    ".apolysis/codex-live-demo/intent.codex.jsonl" \
    ".apolysis/codex-live-demo/intent-correlation.jsonl" \
    'find "$HOME/.codex/sessions"' \
    "apolysis intent ingest" \
    "apolysis intent correlate" \
    "missing_intent" \
    "fake credential" \
    "Do not use real credentials" \
    "sha256sum" \
    "asciinema"; do
    require_contains "$runbook" "$needle"
done

require_not_matches "$runbook" '(^|[[:space:]])HOME="\$APOLYSIS_CODEX_DEMO_HOME"'
require_not_matches "$runbook" '--ask-for-approval'

require_contains README.md "docs/codex-live-demo-runbook.md"
require_contains README.zh-CN.md "docs/codex-live-demo-runbook.md"
require_contains "$repo_root/.github/workflows/release-validation.yml" "make test-codex-live-demo-runbook"
require_contains "$repo_root/scripts/test-release-validation-ci.sh" "test-codex-live-demo-runbook"

require_contains "$workload" "cargo test -p apolysis-cli --test intent"
require_contains "$workload" "scripts/read-demo-credential.py"
require_contains "$credential_helper" "APOLYSIS_CODEX_DEMO_HOME"
require_contains "$credential_helper" "fake credential fixture"

tmp_home="$repo_root/target/codex-live-demo-runbook-test/home"
rm -rf "$repo_root/target/codex-live-demo-runbook-test"
mkdir -p "$tmp_home/.aws"
printf 'apolysis_fake_access = APOLYSIS_FAKE_KEY\napolysis_fake_secret = APOLYSIS_FAKE_SECRET\n' \
    >"$tmp_home/.aws/credentials"

helper_output="$repo_root/target/codex-live-demo-runbook-test/helper-output.txt"
APOLYSIS_CODEX_DEMO_HOME="$tmp_home" python3 "$credential_helper" >"$helper_output"
require_contains "$helper_output" "fake credential fixture read"
if grep -Fq "APOLYSIS_FAKE_SECRET" "$helper_output"; then
    fail "credential helper printed fake secret contents"
fi

printf 'codex live demo runbook check passed\n'

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_exact_test() {
    local package="$1"
    local test_target="$2"
    local test_name="$3"

    if ! cargo test -p "$package" --test "$test_target" "$test_name" \
        -- --exact --list | grep -Fqx "$test_name: test"; then
        echo "apolysis-f2: recovery test not found: $package/$test_target::$test_name" >&2
        exit 1
    fi

    cargo test -p "$package" --test "$test_target" "$test_name" \
        -- --exact --nocapture
}

run_exact_test \
    apolysis-daemon \
    socket_api \
    restart_quarantines_corrupt_tail_and_keeps_valid_session_recoverable
run_exact_test \
    apolysis-daemon \
    socket_api \
    restart_restores_active_session_and_continues_hash_chain
run_exact_test \
    apolysis-daemon \
    scope_coordination \
    restart_restores_persisted_cgroup_ownership
cargo test -p apolysis-store --test hash_chain
./scripts/test-f2-apolysisd-systemd.sh

echo "apolysis-f2: recovery qualification passed"

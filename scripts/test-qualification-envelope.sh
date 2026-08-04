#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-qualification-envelope.sh"
test_envelope="$repo_root/tests/fixtures/qualification/supported-envelope.json"
passing="$repo_root/tests/fixtures/qualification/host-managed-pass.json"
malformed="$repo_root/tests/fixtures/qualification/malformed.json"
live_runner="$repo_root/scripts/capture-qualification-preflight.sh"

pass_output="$($checker --envelope "$test_envelope" --evidence "$passing")"
if ! grep -q '"decision":"pass"' <<<"$pass_output"; then
    printf 'qualification envelope test failed: expected passing bundle\n' >&2
    exit 1
fi

cargo test --quiet -p apolysis-cli --bin apolysis-qualification

set +e
malformed_output="$($checker --envelope "$test_envelope" --evidence "$malformed")"
malformed_status=$?
set -e
if [[ "$malformed_status" -ne 2 ]] || ! grep -q 'invalid_input:' <<<"$malformed_output"; then
    printf 'qualification envelope test failed: malformed input must exit 2\n' >&2
    exit 1
fi

set +e
confirmation_output="$($live_runner 2>&1)"
confirmation_status=$?
set -e
if [[ "$confirmation_status" -ne 2 ]] ||
    ! grep -q 'APOLYSIS_CONFIRM_QUALIFICATION=1' <<<"$confirmation_output"; then
    printf 'qualification envelope test failed: live capture must require confirmation\n' >&2
    exit 1
fi

printf 'qualification envelope tests passed\n'

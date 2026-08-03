#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-qualification-envelope.sh"
envelope="$repo_root/qualification/envelope-v1.json"
passing="$repo_root/tests/fixtures/qualification/host-managed-pass.json"
failing="$repo_root/tests/fixtures/qualification/host-managed-event-loss.json"

pass_output="$($checker --envelope "$envelope" --evidence "$passing")"
if ! grep -q '"decision":"pass"' <<<"$pass_output"; then
    printf 'qualification envelope test failed: expected passing evidence\n' >&2
    exit 1
fi

set +e
fail_output="$($checker --envelope "$envelope" --evidence "$failing")"
fail_status=$?
set -e
if [[ "$fail_status" -eq 0 ]]; then
    printf 'qualification envelope test failed: event loss must reject the profile\n' >&2
    exit 1
fi
if ! grep -q '"decision":"fail"' <<<"$fail_output" ||
    ! grep -q 'event_loss_count' <<<"$fail_output"; then
    printf 'qualification envelope test failed: expected an explicit event-loss reason\n' >&2
    exit 1
fi

printf 'qualification envelope tests passed\n'

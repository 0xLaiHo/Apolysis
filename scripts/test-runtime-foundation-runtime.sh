#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set +e
"$repo_root/scripts/check-bpf-prereqs.sh" live
status=$?
set -e
[[ "$status" == "77" ]] && exit 0
[[ "$status" == "0" ]] || exit "$status"

cd "$repo_root"
cargo test -p apolysis-daemon --test live_runtime \
    live_daemon_observer_tracks_two_cgroups_and_excludes_untracked_work \
    -- --ignored --exact --nocapture

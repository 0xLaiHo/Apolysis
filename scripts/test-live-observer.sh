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

cargo test -p apolysis-cli --test observe live_observer -- --ignored --nocapture

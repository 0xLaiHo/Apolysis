#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" != "--envelope" || -z "${2:-}" ||
      "${3:-}" != "--evidence" || -z "${4:-}" || $# -ne 4 ]]; then
    printf 'usage: %s --envelope <path> --evidence <path>\n' "$0" >&2
    exit 2
fi

command -v cargo >/dev/null 2>&1 || {
    printf 'qualification envelope check requires cargo\n' >&2
    exit 2
}
[[ -r "$2" ]] || {
    printf 'qualification envelope is not readable: %s\n' "$2" >&2
    exit 2
}
[[ -r "$4" ]] || {
    printf 'qualification evidence is not readable: %s\n' "$4" >&2
    exit 2
}

exec cargo run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p apolysis-cli --bin apolysis-qualification -- check "$2" "$4"

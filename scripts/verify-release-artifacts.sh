#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-target/release-artifacts}"
verifier="$repo_root/target/release/apolysis-release-verifier"

command -v systemd-analyze >/dev/null 2>&1 || {
    printf 'release artifact verification: missing systemd-analyze\n' >&2
    exit 1
}
command -v bpftool >/dev/null 2>&1 || {
    printf 'release artifact verification: missing bpftool\n' >&2
    exit 1
}
[[ -x "$verifier" ]] || {
    printf 'release artifact verification: missing Rust verifier; run make build-release-verifier\n' >&2
    exit 1
}

verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-release-verify.XXXXXX")"
cleanup() {
    case "$verify_dir" in
        "${TMPDIR:-/tmp}"/apolysis-release-verify.*)
            rm -rf -- "$verify_dir"
            ;;
    esac
}
trap cleanup EXIT

"$verifier" "$output_dir" "$verify_dir"
systemd-analyze verify "$verify_dir/apolysisd.service"
bpftool gen skeleton "$verify_dir/apolysis_observer.bpf.o" >/dev/null

cleanup
trap - EXIT
printf 'release artifact verification: PASS\n'

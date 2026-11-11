#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Opt-in host-BTF regression. Compiles and relocates ELF only; no BPF loading.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set +e
"$repo_root/scripts/check-bpf-prereqs.sh" build
status=$?
set -e
[[ "$status" == 77 ]] && exit 0
[[ "$status" == 0 ]] || exit "$status"
"$repo_root/scripts/build-ebpf.sh"
cd "$repo_root"
cargo test -p apolysis-observer --test btf_relocation -- --ignored

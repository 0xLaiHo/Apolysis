#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$repo_root/target/ebpf"
vmlinux_header="$output_dir/vmlinux.h"
object="$output_dir/apolysis_observer.bpf.o"
bpf_lsm_object="$output_dir/apolysis_bpf_lsm_file_read.bpf.o"

set +e
"$repo_root/scripts/check-bpf-prereqs.sh" build
status=$?
set -e
[[ "$status" == "77" ]] && exit 0
[[ "$status" == "0" ]] || exit "$status"

case "$(uname -m)" in
    x86_64) target_arch=x86 ;;
    aarch64) target_arch=arm64 ;;
    armv7l) target_arch=arm ;;
    ppc64le) target_arch=powerpc ;;
    s390x) target_arch=s390 ;;
    riscv64) target_arch=riscv ;;
    *)
        printf 'apolysis-bpf: unsupported architecture: %s\n' "$(uname -m)" >&2
        exit 1
        ;;
esac

mkdir -p "$output_dir"
bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$vmlinux_header"

clang \
    -g \
    -O2 \
    -target bpf \
    -D"__TARGET_ARCH_${target_arch}" \
    -I"$output_dir" \
    -I"$repo_root/ebpf/include" \
    -c "$repo_root/ebpf/observer/apolysis_observer.bpf.c" \
    -o "$object"

llvm-strip -g "$object"
printf 'apolysis-bpf: built %s\n' "$object"

clang \
    -g \
    -O2 \
    -target bpf \
    -D"__TARGET_ARCH_${target_arch}" \
    -I"$output_dir" \
    -I"$repo_root/ebpf/include" \
    -c "$repo_root/ebpf/observer/apolysis_bpf_lsm_file_read.bpf.c" \
    -o "$bpf_lsm_object"

llvm-strip -g "$bpf_lsm_object"
printf 'apolysis-bpf: built %s\n' "$bpf_lsm_object"

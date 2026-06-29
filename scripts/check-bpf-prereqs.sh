#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mode="${1:-build}"
require_bpf="${APOLYSIS_REQUIRE_BPF:-0}"

skip_or_fail() {
    local reason="$1"
    if [[ "$require_bpf" == "1" ]]; then
        printf 'apolysis-bpf: prerequisite failed: %s\n' "$reason" >&2
        exit 1
    fi
    printf 'apolysis-bpf: SKIP: %s\n' "$reason"
    exit 77
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || skip_or_fail "missing command: $1"
}

require_command bpftool
require_command clang
require_command llvm-strip

[[ "$(uname -s)" == "Linux" ]] || skip_or_fail "live eBPF requires Linux"
[[ -r /sys/kernel/btf/vmlinux ]] || skip_or_fail "readable /sys/kernel/btf/vmlinux is required"
[[ -r /usr/include/bpf/bpf_helpers.h ]] || skip_or_fail "libbpf headers are required"
[[ -r /usr/include/bpf/bpf_tracing.h ]] || skip_or_fail "libbpf tracing headers are required"

if [[ "$mode" == "live" ]]; then
    [[ -e /sys/fs/cgroup/cgroup.controllers ]] ||
        skip_or_fail "cgroup v2 is required for the default live scope"

    cap_hex="$(awk '/^CapEff:/ { print $2 }' /proc/self/status)"
    [[ -n "$cap_hex" ]] || skip_or_fail "cannot read CapEff from /proc/self/status"
    effective_caps=$((16#$cap_hex))
    cap_sys_admin=$((1 << 21))
    cap_perfmon=$((1 << 38))
    cap_bpf=$((1 << 39))

    if (( (effective_caps & cap_sys_admin) == 0 )) &&
        (( (effective_caps & cap_perfmon) == 0 ||
           (effective_caps & cap_bpf) == 0 )); then
        skip_or_fail "CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN) are required"
    fi

    tracefs=
    for candidate in /sys/kernel/tracing /sys/kernel/debug/tracing; do
        if [[ -d "$candidate/events" ]]; then
            tracefs="$candidate"
            break
        fi
    done
    [[ -n "$tracefs" ]] ||
        skip_or_fail "tracefs events are unavailable; mount tracefs at /sys/kernel/tracing"

    while IFS=/ read -r category name; do
        [[ -r "$tracefs/events/$category/$name/id" ]] ||
            skip_or_fail "required tracepoint is unavailable: $category/$name"
    done <<'EOF'
sched/sched_process_fork
sched/sched_process_exec
sched/sched_process_exit
syscalls/sys_enter_execve
syscalls/sys_enter_execveat
syscalls/sys_enter_openat
syscalls/sys_enter_openat2
syscalls/sys_enter_creat
syscalls/sys_enter_truncate
syscalls/sys_enter_unlinkat
syscalls/sys_enter_renameat2
syscalls/sys_enter_connect
EOF
fi

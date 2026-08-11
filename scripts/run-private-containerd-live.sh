#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly opt_in=APOLYSIS_PRIVATE_CONTAINERD_LIVE
readonly test_name=live_private_containerd_cri_qualifies_inventory_identity_and_socket_recovery
readonly crictl_version=v1.36.0
readonly crictl_archive=crictl-v1.36.0-linux-amd64.tar.gz
readonly crictl_sha256=83855e114566a8a8c44c548d515670f51de3a5e1da8b2effb59870e2f10c25a3
readonly crictl_binary_sha256=1899856526fde27f54ff4568ba5b0db00a182b6e7ff129efb1c0bb4950652a69
readonly crictl_url="https://github.com/kubernetes-sigs/cri-tools/releases/download/${crictl_version}/${crictl_archive}"
readonly alpine_image_id=sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
readonly -a private_unshare_args=(
    --mount
    --uts
    --ipc
    --net
    --cgroup
    --propagation
    private
)

fail() {
    printf 'private containerd qualification: FAIL (%s)\n' "$1" >&2
    exit 1
}

run_bounded() {
    local task_deadline_seconds=$1
    local task_stdout_cap=$2
    local task_stderr_cap=$3
    shift 3
    local task_stdin_fd=-1
    local task_same_session=0
    while :; do
        case "${1:-}" in
            --stdin-fd)
                [[ "${2:-}" =~ ^[0-9]+$ ]] || return 125
                task_stdin_fd=$2
                shift 2
                ;;
            --same-session)
                task_same_session=1
                shift
                ;;
            *) break ;;
        esac
    done
    python3 -I - "$task_deadline_seconds" "$task_stdout_cap" "$task_stderr_cap" \
        "$task_stdin_fd" "$task_same_session" "$@" <<'PY'
import os
import selectors
import signal
import subprocess
import sys
import time

deadline_seconds = float(sys.argv[1])
stdout_cap = int(sys.argv[2])
stderr_cap = int(sys.argv[3])
stdin_fd = int(sys.argv[4])
same_session = int(sys.argv[5])
command = sys.argv[6:]
if not (0 < deadline_seconds <= 600):
    raise SystemExit(125)
if not (0 <= stdout_cap <= 8 * 1024 * 1024 and 0 <= stderr_cap <= 8 * 1024 * 1024):
    raise SystemExit(125)
if not command:
    raise SystemExit(125)

popen_group = {"process_group": 0} if same_session else {"start_new_session": True}
child = subprocess.Popen(
    command,
    stdin=subprocess.DEVNULL if stdin_fd < 0 else stdin_fd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    close_fds=True,
    **popen_group,
)

def stop_group(first_signal):
    try:
        os.killpg(child.pid, first_signal)
    except ProcessLookupError:
        pass
    # Do not poll/wait during the grace period: an exited leader must remain
    # unreaped so its process-group ID cannot be reused while descendants live.
    time.sleep(1)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()

def interrupted(signum, _frame):
    stop_group(signum)
    raise SystemExit(128 + signum)

signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)
selector = selectors.DefaultSelector()
streams = ((child.stdout, bytearray(), stdout_cap), (child.stderr, bytearray(), stderr_cap))
for stream, _buffer, _cap in streams:
    os.set_blocking(stream.fileno(), False)
    selector.register(stream, selectors.EVENT_READ)
end = time.monotonic() + deadline_seconds
failure = None
while selector.get_map():
    remaining = end - time.monotonic()
    if remaining <= 0:
        failure = 124
        break
    for key, _events in selector.select(min(remaining, 0.1)):
        stream = key.fileobj
        try:
            chunk = os.read(stream.fileno(), 65536)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(stream)
            continue
        for registered, buffer, cap in streams:
            if registered is stream:
                if len(buffer) + len(chunk) > cap:
                    failure = 125
                else:
                    buffer.extend(chunk)
                break
        if failure is not None:
            break
    if failure is not None:
        break

if failure is not None:
    stop_group(signal.SIGTERM)
else:
    remaining = max(0.0, end - time.monotonic())
    try:
        child.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        failure = 124
        stop_group(signal.SIGTERM)

sys.stdout.buffer.write(streams[0][1])
sys.stderr.buffer.write(streams[1][1])
if failure is not None:
    raise SystemExit(failure)
raise SystemExit(child.returncode)
PY
}

bounded_sha256() {
    local task_digest
    task_digest="$(run_bounded 15 4096 65536 sha256sum -- "$1")" || return 1
    printf '%s\n' "${task_digest%% *}"
}

bounded_file_size() {
    run_bounded 5 4096 65536 stat -c '%s' -- "$1"
}

root_bounded() {
    local task_deadline_seconds=$1
    local task_stdout_cap=$2
    local task_stderr_cap=$3
    shift 3
    [[ "${task_root_supervisor_ready:-0}" == "1" \
        && -n "${task_private_root:-}" ]] \
        || return 125
    sudo -n -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \
        "$task_private_root/bin/runner" --supervise \
        "$task_deadline_seconds" "$task_stdout_cap" "$task_stderr_cap" "$@"
}

bootstrap_root_bounded() {
    local task_deadline_seconds=$1
    shift
    sudo -n -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \
        /usr/bin/timeout --signal=TERM --kill-after=1s "${task_deadline_seconds}s" "$@"
}

unprivileged_path_state() {
    run_bounded 5 1024 65536 python3 -I -c '
import os, sys
try:
    os.lstat(sys.argv[1])
except FileNotFoundError:
    print("absent")
except OSError:
    raise SystemExit(2)
else:
    print("present")
' "$1"
}

valid_delegated_unit() {
    [[ "$1" =~ ^apolysis-private-containerd-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.scope$ ]]
}

delegated_unit_property() {
    local task_unit=$1
    local task_property=$2
    valid_delegated_unit "$task_unit" || return 1
    run_bounded 5 4096 65536 systemctl --user show "$task_unit" \
        --property="$task_property" --value
}

delegated_unit_state() {
    delegated_unit_property "$1" LoadState
}

wait_for_delegated_unit_absent() {
    local task_unit=$1
    local task_attempt task_state
    for ((task_attempt = 0; task_attempt < 50; task_attempt += 1)); do
        task_state="$(delegated_unit_state "$task_unit")" || return 1
        if [[ "$task_state" == "not-found" ]]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

read_delegated_cgroup_file() {
    local task_path=$1
    run_bounded 5 65536 65536 python3 -I -c '
import os, stat, sys
path = sys.argv[1]
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(1)
    contents = os.read(descriptor, 65537)
    if len(contents) > 65536 or os.read(descriptor, 1):
        raise SystemExit(1)
finally:
    os.close(descriptor)
sys.stdout.buffer.write(contents)
' "$task_path"
}

canonical_required_controllers() {
    local task_controllers=$1
    local task_controller
    local task_cpuset=0 task_cpu=0 task_io=0 task_memory=0 task_pids=0 task_count=0
    [[ "$task_controllers" != *$'\n'* && "$task_controllers" != *$'\r'* ]] || return 1
    for task_controller in $task_controllers; do
        task_count=$((task_count + 1))
        case "$task_controller" in
            cpuset) [[ "$task_cpuset" == "0" ]] || return 1; task_cpuset=1 ;;
            cpu) [[ "$task_cpu" == "0" ]] || return 1; task_cpu=1 ;;
            io) [[ "$task_io" == "0" ]] || return 1; task_io=1 ;;
            memory) [[ "$task_memory" == "0" ]] || return 1; task_memory=1 ;;
            pids) [[ "$task_pids" == "0" ]] || return 1; task_pids=1 ;;
            *) return 1 ;;
        esac
    done
    [[ "$task_count" == "5" && "$task_cpuset" == "1" && "$task_cpu" == "1" \
        && "$task_io" == "1" && "$task_memory" == "1" && "$task_pids" == "1" ]]
}

current_unified_cgroup() {
    run_bounded 5 4096 65536 python3 -I -c '
matches = []
with open("/proc/self/cgroup", "r", encoding="ascii") as source:
    for line in source:
        fields = line.rstrip("\n").split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            matches.append(fields[2])
if len(matches) != 1:
    raise SystemExit(1)
print(matches[0])
'
}

valid_cgroup_nesting_root() {
    local task_root=$1
    local task_mode=$2
    local task_expected_group=$3
    [[ "$task_expected_group" == /* \
        && "$task_expected_group" != *'..'* \
        && "$task_expected_group" != *$'\n'* ]] || return 1
    case "$task_mode" in
        private)
            [[ "$task_root" == "/sys/fs/cgroup" && "$task_expected_group" == "/" ]]
            ;;
        contract)
            [[ "$task_expected_group" != "/" \
                && "$task_root" == "/sys/fs/cgroup$task_expected_group" ]]
            ;;
        *) return 1 ;;
    esac
}

cgroup_nesting_fail() {
    local task_step=${1:-}
    case "$task_step" in
        path|fs|self-group|type|controllers|subtree-initial|init-create|init-type|move|root-empty|enable|readback|self-init) ;;
        *) task_step=path ;;
    esac
    printf 'cgroup nesting step=%s\n' "$task_step" >&2
    return 1
}

prepare_cgroup_v2_nesting() {
    local task_root=$1
    local task_mode=$2
    local task_expected_group=$3
    local task_init="$task_root/init"
    local task_type task_controllers task_subtree task_pid task_remaining task_self_group
    local task_resolved_root task_fs_type task_move_failed task_round
    local task_total_pids=0 task_empty_snapshot=0
    local task_round_limit=16 task_per_round_limit=256 task_total_limit=1024
    local -a task_pids=()
    valid_cgroup_nesting_root "$task_root" "$task_mode" "$task_expected_group" \
        || { cgroup_nesting_fail path; return 1; }
    [[ -d "$task_root" && ! -L "$task_root" ]] \
        || { cgroup_nesting_fail path; return 1; }
    task_resolved_root="$(
        run_bounded 5 4096 65536 readlink -f -- "$task_root" 2>/dev/null
    )" || { cgroup_nesting_fail path; return 1; }
    [[ "$task_resolved_root" == "$task_root" ]] \
        || { cgroup_nesting_fail path; return 1; }
    task_fs_type="$(
        run_bounded 5 4096 65536 stat -f -c '%T' -- "$task_root" 2>/dev/null
    )" || { cgroup_nesting_fail fs; return 1; }
    [[ "$task_fs_type" == "cgroup2fs" ]] \
        || { cgroup_nesting_fail fs; return 1; }
    task_self_group="$(current_unified_cgroup 2>/dev/null)" \
        || { cgroup_nesting_fail self-group; return 1; }
    [[ "$task_self_group" == "$task_expected_group" ]] \
        || { cgroup_nesting_fail self-group; return 1; }
    task_type="$(read_delegated_cgroup_file "$task_root/cgroup.type" 2>/dev/null)" \
        || { cgroup_nesting_fail type; return 1; }
    [[ "$task_type" == "domain" ]] || { cgroup_nesting_fail type; return 1; }
    task_controllers="$(
        read_delegated_cgroup_file "$task_root/cgroup.controllers" 2>/dev/null
    )" || { cgroup_nesting_fail controllers; return 1; }
    canonical_required_controllers "$task_controllers" \
        || { cgroup_nesting_fail controllers; return 1; }
    task_subtree="$(
        read_delegated_cgroup_file "$task_root/cgroup.subtree_control" 2>/dev/null
    )" || { cgroup_nesting_fail subtree-initial; return 1; }
    [[ -z "$task_subtree" ]] || { cgroup_nesting_fail subtree-initial; return 1; }
    [[ ! -e "$task_init" && ! -L "$task_init" ]] \
        || { cgroup_nesting_fail init-create; return 1; }
    run_bounded 5 65536 65536 mkdir -- "$task_init" >/dev/null 2>&1 \
        || { cgroup_nesting_fail init-create; return 1; }
    [[ -d "$task_init" && ! -L "$task_init" ]] \
        || { cgroup_nesting_fail init-create; return 1; }
    task_resolved_root="$(
        run_bounded 5 4096 65536 readlink -f -- "$task_init" 2>/dev/null
    )" || { cgroup_nesting_fail init-create; return 1; }
    [[ "$task_resolved_root" == "$task_init" ]] \
        || { cgroup_nesting_fail init-create; return 1; }
    task_type="$(read_delegated_cgroup_file "$task_init/cgroup.type" 2>/dev/null)" \
        || { cgroup_nesting_fail init-type; return 1; }
    [[ "$task_type" == "domain" ]] || { cgroup_nesting_fail init-type; return 1; }
    for ((task_round = 0; task_round < task_round_limit; task_round += 1)); do
        task_pids=()
        if ! mapfile -t task_pids 2>/dev/null < "$task_root/cgroup.procs"; then
            cgroup_nesting_fail move
            return 1
        fi
        if [[ "${#task_pids[@]}" == "0" ]]; then
            task_empty_snapshot=1
            break
        fi
        if [[ "${#task_pids[@]}" -gt "$task_per_round_limit" ]]; then
            cgroup_nesting_fail move
            return 1
        fi
        task_total_pids=$((task_total_pids + ${#task_pids[@]}))
        if [[ "$task_total_pids" -gt "$task_total_limit" ]]; then
            cgroup_nesting_fail move
            return 1
        fi
        task_move_failed=0
        for task_pid in "${task_pids[@]}"; do
            if [[ ! "$task_pid" =~ ^[1-9][0-9]*$ ]]; then
                task_move_failed=1
                break
            fi
            if ! { printf '%s\n' "$task_pid" > "$task_init/cgroup.procs"; } \
                2>/dev/null; then
                task_move_failed=1
                break
            fi
        done
        if [[ "$task_move_failed" != "0" ]]; then
            cgroup_nesting_fail move
            return 1
        fi
    done
    [[ "$task_empty_snapshot" == "1" ]] \
        || { cgroup_nesting_fail root-empty; return 1; }
    task_remaining="$(
        read_delegated_cgroup_file "$task_root/cgroup.procs" 2>/dev/null
    )" || { cgroup_nesting_fail root-empty; return 1; }
    [[ -z "$task_remaining" ]] || { cgroup_nesting_fail root-empty; return 1; }
    if ! { printf '%s\n' '+cpuset +cpu +io +memory +pids' \
        > "$task_root/cgroup.subtree_control"; } 2>/dev/null; then
        cgroup_nesting_fail enable
        return 1
    fi
    task_subtree="$(
        read_delegated_cgroup_file "$task_root/cgroup.subtree_control" 2>/dev/null
    )" || { cgroup_nesting_fail readback; return 1; }
    canonical_required_controllers "$task_subtree" \
        || { cgroup_nesting_fail readback; return 1; }
    task_self_group="$(current_unified_cgroup 2>/dev/null)" \
        || { cgroup_nesting_fail self-init; return 1; }
    case "$task_mode" in
        private)
            [[ "$task_self_group" == "/init" ]] \
                || { cgroup_nesting_fail self-init; return 1; }
            ;;
        contract)
            [[ "$task_self_group" == "$task_expected_group/init" ]] \
                || { cgroup_nesting_fail self-init; return 1; }
            ;;
        *) cgroup_nesting_fail self-init; return 1 ;;
    esac
}

prepare_private_cgroup_v2_nesting() {
    prepare_cgroup_v2_nesting /sys/fs/cgroup private /
}

prepare_delegated_contract_cgroup_nesting() {
    local task_unit=$1
    local task_control_group
    valid_delegated_unit "$task_unit" || return 1
    task_control_group="$(delegated_unit_property "$task_unit" ControlGroup)" || return 1
    prepare_cgroup_v2_nesting "/sys/fs/cgroup$task_control_group" \
        contract "$task_control_group"
}

verify_delegated_environment() {
    run_bounded 5 1024 65536 python3 -I -c '
import os
allowed = {
    "PATH", "HOME", "USER", "LOGNAME", "LC_ALL", "PWD", "SHLVL", "_",
    "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
    "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_SCOPE",
    "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT",
    "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID",
    "APOLYSIS_PRIVATE_CONTAINERD_LIVE", "APOLYSIS_CRICTL",
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
    "https_proxy", "http_proxy", "all_proxy", "no_proxy",
}
if set(os.environ) - allowed:
    raise SystemExit(1)
' >/dev/null
}

verify_delegated_scope() {
    local task_unit=$1
    local task_expected_uid=$2
    local task_uid task_load_state task_delegate task_control_group task_self_group
    local task_type task_controllers task_required
    [[ "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_SCOPE:-}" == "1" \
        && "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" == "$task_unit" \
        && "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID:-}" == "$task_expected_uid" ]] \
        || return 1
    verify_delegated_environment || return 1
    valid_delegated_unit "$task_unit" || return 1
    [[ "$task_expected_uid" =~ ^[0-9]+$ ]] || return 1
    task_uid="$(run_bounded 5 1024 65536 id -u)" || return 1
    [[ "$task_uid" == "$task_expected_uid" && "$task_uid" != "0" ]] || return 1
    task_load_state="$(delegated_unit_state "$task_unit")" || return 1
    [[ "$task_load_state" == "loaded" ]] || return 1
    task_delegate="$(delegated_unit_property "$task_unit" Delegate)" || return 1
    [[ "$task_delegate" == "yes" ]] || return 1
    task_control_group="$(delegated_unit_property "$task_unit" ControlGroup)" || return 1
    valid_delegated_control_group "$task_unit" "$task_expected_uid" "$task_control_group" \
        || return 1
    task_self_group="$(run_bounded 5 4096 65536 python3 -I -c '
import sys
matches = []
with open("/proc/self/cgroup", "r", encoding="ascii") as source:
    for line in source:
        fields = line.rstrip("\n").split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            matches.append(fields[2])
if len(matches) != 1:
    raise SystemExit(1)
print(matches[0])
')" || return 1
    [[ "$task_self_group" == "$task_control_group" ]] || return 1
    task_type="$(read_delegated_cgroup_file "/sys/fs/cgroup$task_control_group/cgroup.type")" \
        || return 1
    [[ "$task_type" == "domain" ]] || return 1
    task_controllers="$(read_delegated_cgroup_file \
        "/sys/fs/cgroup$task_control_group/cgroup.controllers")" || return 1
    [[ "$task_controllers" != *$'\n'* ]] || return 1
    for task_required in cpuset cpu io memory pids; do
        [[ " $task_controllers " == *" $task_required "* ]] || return 1
    done
}

valid_delegated_control_group() {
    local task_unit=$1
    local task_expected_uid=$2
    local task_control_group=$3
    valid_delegated_unit "$task_unit" || return 1
    [[ "$task_expected_uid" =~ ^[0-9]+$ && "$task_expected_uid" != "0" ]] || return 1
    [[ "$task_control_group" == \
        "/user.slice/user-$task_expected_uid.slice/user@$task_expected_uid.service/app.slice/$task_unit" ]]
}

prove_delegated_cgroup_kill_target() {
    local task_path=$1
    local task_expected_uid=$2
    local task_expected_gid=$3
    local task_resolved task_type task_identity
    [[ "$task_expected_uid" =~ ^[0-9]+$ && "$task_expected_uid" != "0" \
        && "$task_expected_gid" =~ ^[0-9]+$ ]] || return 1
    [[ "$task_path" == /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/\
apolysis-private-containerd-*.scope/cgroup.kill \
        && "$task_path" != *'..'* && "$task_path" != *$'\n'* ]] || return 1
    [[ -d /sys/fs/cgroup && ! -L /sys/fs/cgroup ]] || return 1
    task_resolved="$(run_bounded 5 4096 65536 readlink -f -- /sys/fs/cgroup)" || return 1
    [[ "$task_resolved" == "/sys/fs/cgroup" ]] || return 1
    task_type="$(run_bounded 5 4096 65536 stat -f -c '%T' -- /sys/fs/cgroup)" || return 1
    [[ "$task_type" == "cgroup2fs" ]] || return 1
    [[ -f "$task_path" && ! -L "$task_path" ]] || return 1
    task_resolved="$(run_bounded 5 4096 65536 readlink -f -- "$task_path")" || return 1
    [[ "$task_resolved" == "$task_path" ]] || return 1
    task_identity="$(run_bounded 5 4096 65536 stat -Lc '%u:%g:%h:%F' -- "$task_path")" \
        || return 1
    [[ "$task_identity" == "$task_expected_uid:$task_expected_gid:1:regular empty file" \
        || "$task_identity" == "$task_expected_uid:$task_expected_gid:1:regular file" ]]
}

kill_residual_delegated_scope_cgroup() {
    local task_unit=$1
    local task_expected_uid=$2
    local task_expected_gid=$3
    local task_control_group task_outer_group task_kill_path
    [[ "$task_expected_gid" =~ ^[0-9]+$ ]] || return 1
    task_control_group="$(delegated_unit_property "$task_unit" ControlGroup)" || return 1
    valid_delegated_control_group "$task_unit" "$task_expected_uid" "$task_control_group" \
        || return 1
    task_outer_group="$(current_unified_cgroup)" || return 1
    [[ "$task_outer_group" == /* && "$task_outer_group" != *'..'* \
        && "$task_outer_group" != *$'\n'* && "$task_outer_group" != *$'\r'* \
        && "$task_outer_group" != "$task_control_group" \
        && "$task_outer_group" != "$task_control_group/"* ]] || return 1
    task_kill_path="/sys/fs/cgroup$task_control_group/cgroup.kill"
    prove_delegated_cgroup_kill_target \
        "$task_kill_path" "$task_expected_uid" "$task_expected_gid" || return 1
    bootstrap_root_bounded 5 /usr/bin/python3 -I -c '
import os
import stat
import sys

descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    metadata = os.fstat(descriptor)
    expected_uid = int(sys.argv[2])
    expected_gid = int(sys.argv[3])
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid or metadata.st_gid != expected_gid):
        raise SystemExit(1)
    if os.write(descriptor, b"1") != 1:
        raise SystemExit(1)
finally:
    os.close(descriptor)
' "$task_kill_path" "$task_expected_uid" "$task_expected_gid" >/dev/null 2>&1
}

run_in_delegated_scope() {
    local task_deadline=$1
    local task_runner=$2
    shift 2
    local task_uid task_gid task_user task_uuid task_unit task_status=0 task_state task_name
    local task_cleanup_status
    local task_scope_path task_home
    local -a task_child_environment
    task_uid="$(run_bounded 5 1024 65536 id -u)" || return 1
    task_gid="$(run_bounded 5 1024 65536 id -g)" || return 1
    task_user="$(run_bounded 5 4096 65536 id -un)" || return 1
    task_home=${HOME:-}
    [[ "$task_uid" =~ ^[0-9]+$ && "$task_uid" != "0" \
        && "$task_gid" =~ ^[0-9]+$ \
        && "$task_user" != *:* && "$task_user" != *$'\n'* \
        && "$task_home" == /* && "$task_home" != *:* && "$task_home" != *$'\n'* ]] \
        || return 1
    IFS= read -r task_uuid < /proc/sys/kernel/random/uuid || return 1
    [[ "$task_uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || return 1
    task_unit="apolysis-private-containerd-$task_uuid.scope"
    valid_delegated_unit "$task_unit" || return 1
    task_state="$(delegated_unit_state "$task_unit")" || return 1
    [[ "$task_state" == "not-found" ]] || return 1
    task_scope_path="$task_home/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    task_child_environment=(
        env -i
        "PATH=$task_scope_path"
        "HOME=$task_home"
        "USER=$task_user"
        "LOGNAME=$task_user"
        LC_ALL=C
        "XDG_RUNTIME_DIR=/run/user/$task_uid"
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$task_uid/bus"
        APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_SCOPE=1
        "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT=$task_unit"
        "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID=$task_uid"
    )
    for task_name in APOLYSIS_PRIVATE_CONTAINERD_LIVE APOLYSIS_CRICTL \
        HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY https_proxy http_proxy all_proxy no_proxy; do
        if [[ -v "$task_name" ]]; then
            task_child_environment+=("$task_name=${!task_name}")
        fi
    done
    if run_bounded "$task_deadline" 4194304 4194304 --same-session \
        systemd-run --user --scope --collect --quiet \
        --unit="$task_unit" --property=Delegate=yes \
        "${task_child_environment[@]}" "$task_runner" "$@"; then
        task_status=0
    else
        task_status=$?
    fi
    task_state="$(delegated_unit_state "$task_unit")" || return 1
    if [[ "$task_state" != "not-found" ]]; then
        if wait_for_delegated_unit_absent "$task_unit"; then
            return "$task_status"
        fi
        task_state="$(delegated_unit_state "$task_unit")" || return 1
        [[ "$task_state" != "not-found" ]] || return "$task_status"
        task_cleanup_status=0
        kill_residual_delegated_scope_cgroup "$task_unit" "$task_uid" "$task_gid" \
            || task_cleanup_status=1
        if ! run_bounded 10 65536 65536 systemctl --user stop "$task_unit" \
            >/dev/null 2>&1; then
            task_state="$(delegated_unit_state "$task_unit")" || task_cleanup_status=1
            [[ "$task_state" == "not-found" ]] || task_cleanup_status=1
        fi
        wait_for_delegated_unit_absent "$task_unit" || task_cleanup_status=1
        [[ "$task_cleanup_status" == "0" ]] || return 1
    fi
    return "$task_status"
}

run_delegated_scope_contract() {
    run_in_delegated_scope 30 "${BASH_SOURCE[0]}" --delegated-contract-child
}

run_delegated_cgroup_nesting_contract_child() {
    local task_status=0 task_index task_pid
    local -a task_wait_pids=()
    verify_delegated_scope \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID:-}" \
        || return 1
    for ((task_index = 0; task_index < 16; task_index += 1)); do
        /usr/bin/sleep 20 &
        task_wait_pids+=("$!")
    done
    prepare_delegated_contract_cgroup_nesting \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" \
        || task_status=$?
    for task_pid in "${task_wait_pids[@]}"; do
        kill -TERM "$task_pid" 2>/dev/null || true
    done
    for task_pid in "${task_wait_pids[@]}"; do
        wait "$task_pid" 2>/dev/null || true
    done
    return "$task_status"
}

bounded_contract() {
    local task_case=$1
    local task_status
    case "$task_case" in
        success)
            [[ "$(run_bounded 2 16 16 /usr/bin/printf ok)" == "ok" ]]
            ;;
        timeout)
            if run_bounded 0.1 16 16 /bin/sh -c 'trap "" TERM; while :; do :; done'; then
                return 1
            else
                task_status=$?
            fi
            [[ "$task_status" == "124" ]]
            ;;
        overflow)
            if run_bounded 2 64 16 /usr/bin/yes x >/dev/null; then
                return 1
            else
                task_status=$?
            fi
            [[ "$task_status" == "125" ]]
            ;;
        leader-exit)
            local task_pid_file task_grandchild_pid
            task_pid_file="$(mktemp /tmp/apolysis-bounded-grandchild.XXXXXX)"
            if run_bounded 0.1 64 64 /bin/sh -c \
                '(trap "" TERM; while :; do :; done) & printf "%s\n" "$!" > "$1"; exit 0' \
                bounded-contract "$task_pid_file"; then
                rm -- "$task_pid_file"
                return 1
            else
                task_status=$?
            fi
            task_grandchild_pid="$(<"$task_pid_file")"
            rm -- "$task_pid_file"
            [[ "$task_status" == "124" ]]
            local task_attempt
            for ((task_attempt = 0; task_attempt < 20; task_attempt += 1)); do
                if ! kill -0 "$task_grandchild_pid" 2>/dev/null; then
                    return 0
                fi
                sleep 0.05
            done
            return 1
            ;;
        session-group)
            local task_leader
            setsid timeout --signal=TERM --kill-after=1s 10s \
                /bin/sh -c 'trap "" TERM; while :; do :; done' &
            task_leader=$!
            if ! run_bounded 2 64 64 python3 -I -c \
                'import os,sys; p=int(sys.argv[1]); raise SystemExit(0 if os.getpgid(p) == p else 1)' \
                "$task_leader"; then
                kill -KILL -- "-$task_leader" 2>/dev/null || true
                wait "$task_leader" 2>/dev/null || true
                return 1
            fi
            kill -TERM -- "-$task_leader" 2>/dev/null || true
            sleep 1
            kill -KILL -- "-$task_leader" 2>/dev/null || true
            wait "$task_leader" 2>/dev/null || true
            ! kill -0 -- "-$task_leader" 2>/dev/null
            ;;
        same-session-group)
            [[ "$(run_bounded 2 16 64 --same-session python3 -I -c '
import os
print("ok" if os.getpgrp() == os.getpid() and os.getsid(0) == os.getsid(os.getppid()) else "bad")
')" == "ok" ]]
            ;;
        stdin)
            local task_stdin_fd
            exec {task_stdin_fd}<<<'{"bounded":true}'
            run_bounded 2 16 64 --stdin-fd "$task_stdin_fd" python3 -I -c \
                'import json,sys; value=json.load(sys.stdin); print("ok" if value == {"bounded": True} else "bad")' \
                | grep -Fx ok >/dev/null
            local task_result=$?
            exec {task_stdin_fd}<&-
            return "$task_result"
            ;;
        sweep-list-failure)
            local task_fixture_root task_status
            task_fixture_root="$(mktemp -d /tmp/apolysis-sweep-list-failure.XXXXXX)"
            mkdir "$task_fixture_root/bin"
            printf '%s\n' '#!/bin/sh' 'exit 97' > "$task_fixture_root/bin/crictl"
            chmod 0500 "$task_fixture_root/bin/crictl"
            task_private_root=$task_fixture_root
            if private_cri_ids /missing/containerd.sock container >/dev/null; then
                task_status=0
            else
                task_status=$?
            fi
            rm -- "$task_fixture_root/bin/crictl"
            rmdir -- "$task_fixture_root/bin" "$task_fixture_root"
            task_private_root=
            [[ "$task_status" != "0" ]]
            ;;
        private-config)
            local task_fixture_root task_socket task_directory task_effective task_effective_fd
            task_fixture_root="$(mktemp -d /tmp/apolysis-private-config.XXXXXX)"
            while IFS= read -r task_directory; do
                mkdir -p -- "$task_directory"
            done < <(private_containerd_directories "$task_fixture_root")
            task_socket="$task_fixture_root/run/containerd.sock"
            write_private_containerd_config "$task_fixture_root" "$task_socket"
            run_bounded 5 1024 1048576 python3 -I -c '
import os, stat, sys, tomllib
root, path = sys.argv[1:]
with open(path, "rb") as source:
    document = source.read()
    value = tomllib.loads(document.decode("utf-8"))
plugins = value["plugins"]
nri = plugins["io.containerd.nri.v1.nri"]
assert nri == {
    "disable": True,
    "disable_connections": True,
    "socket_path": root + "/nri/run/nri.sock",
    "plugin_path": root + "/nri/plugins",
    "plugin_config_path": root + "/nri/conf.d",
}
runtime = plugins["io.containerd.cri.v1.runtime"]
assert runtime["enable_cdi"] is False
assert runtime["cdi_spec_dirs"] == [root + "/empty-cdi-specs"]
assert plugins["io.containerd.image-verifier.v1.bindir"]["bin_dir"] == root + "/empty-image-verifiers"
assert plugins["io.containerd.internal.v1.opt"]["path"] == root + "/opt"
for path in (
    root + "/nri/run", root + "/nri/plugins", root + "/nri/conf.d",
    root + "/empty-cdi-specs", root + "/empty-image-verifiers", root + "/opt",
):
    assert os.path.isdir(path)
for forbidden in (b"/var/run/nri", b"/opt/nri", b"/etc/nri", b"/etc/cdi", b"/var/run/cdi", b"/opt/containerd"):
    assert forbidden not in document
assert stat.S_IMODE(os.stat(path := sys.argv[2]).st_mode) == 0o400
' "$task_fixture_root" "$task_fixture_root/config.toml"
            local task_status=$?
            if [[ "$task_status" == "0" ]]; then
                task_effective="$(run_bounded 10 1048576 1048576 \
                    containerd --config "$task_fixture_root/config.toml" config dump)" \
                    || task_status=$?
            fi
            if [[ "$task_status" == "0" ]]; then
                exec {task_effective_fd}<<<"$task_effective"
                run_bounded 5 1024 1048576 --stdin-fd "$task_effective_fd" \
                    python3 -I -c '
import sys, tomllib
root = sys.argv[1]
value = tomllib.load(sys.stdin.buffer)
plugins = value["plugins"]
nri = plugins["io.containerd.nri.v1.nri"]
assert nri["disable"] is True and nri["disable_connections"] is True
assert nri["socket_path"] == root + "/nri/run/nri.sock"
assert nri["plugin_path"] == root + "/nri/plugins"
assert nri["plugin_config_path"] == root + "/nri/conf.d"
runtime = plugins["io.containerd.cri.v1.runtime"]
assert runtime["enable_cdi"] is False
assert runtime["cdi_spec_dirs"] == [root + "/empty-cdi-specs"]
assert plugins["io.containerd.image-verifier.v1.bindir"]["bin_dir"] == root + "/empty-image-verifiers"
assert plugins["io.containerd.internal.v1.opt"]["path"] == root + "/opt"
' "$task_fixture_root" || task_status=$?
                exec {task_effective_fd}<&-
            fi
            find "$task_fixture_root" -depth -delete
            return "$task_status"
            ;;
        cleanup-scope)
            local task_fixture_root task_status
            task_fixture_root="$(mktemp -d /tmp/apolysis-cleanup-scope.XXXXXX)"
            if (
                task_private_root=$task_fixture_root
                task_inner_socket="$task_fixture_root/missing.sock"
                task_inner_containerd_pid=
                task_inner_containerd_stopped=0
                task_inner_sweep_complete=0
                set +e
                false
                inner_cleanup
            ); then
                task_status=0
            else
                task_status=$?
            fi
            rmdir -- "$task_fixture_root"
            [[ "$task_status" == "1" ]]
            ;;
        delegated-recursion)
            local task_status task_fake_unit task_fake_path task_uid
            task_fake_unit=apolysis-private-containerd-00000000-0000-4000-8000-000000000000.scope
            task_uid="$(id -u)"
            task_fake_path="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            if run_bounded 5 1024 1048576 env -i \
                "PATH=$task_fake_path" HOME="$HOME" LC_ALL=C \
                "XDG_RUNTIME_DIR=/run/user/$task_uid" \
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$task_uid/bus" \
                APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_SCOPE=1 \
                "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT=$task_fake_unit" \
                "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID=$task_uid" \
                "${BASH_SOURCE[0]}" --delegated-contract-child >/dev/null 2>&1; then
                task_status=0
            else
                task_status=$?
            fi
            [[ "$task_status" != "0" ]] || return 1
            if run_bounded 5 1024 1048576 env -i \
                "PATH=$task_fake_path" HOME="$HOME" USER="$(id -un)" LOGNAME="$(id -un)" \
                LC_ALL=C "XDG_RUNTIME_DIR=/run/user/$task_uid" \
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$task_uid/bus" \
                APOLYSIS_PRIVATE_CONTAINERD_LIVE=1 \
                APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_SCOPE=1 \
                "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT=$task_fake_unit" \
                "APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID=$task_uid" \
                "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
                task_status=0
            else
                task_status=$?
            fi
            [[ "$task_status" != "0" ]]
            ;;
        delegated-scope)
            run_delegated_scope_contract
            ;;
        delegated-main-proof)
            run_in_delegated_scope 30 "${BASH_SOURCE[0]}" --delegated-main-proof-child
            ;;
        unshare-namespace-contract)
            [[ "${#private_unshare_args[@]}" == "7" \
                && "${private_unshare_args[0]}" == "--mount" \
                && "${private_unshare_args[1]}" == "--uts" \
                && "${private_unshare_args[2]}" == "--ipc" \
                && "${private_unshare_args[3]}" == "--net" \
                && "${private_unshare_args[4]}" == "--cgroup" \
                && "${private_unshare_args[5]}" == "--propagation" \
                && "${private_unshare_args[6]}" == "private" ]] || return 1
            local task_fake_pid=pid:[303]
            namespace_identity() {
                case "$1" in
                    mnt) printf '%s\n' 'mnt:[101]' ;;
                    net) printf '%s\n' 'net:[102]' ;;
                    uts) printf '%s\n' 'uts:[103]' ;;
                    ipc) printf '%s\n' 'ipc:[104]' ;;
                    cgroup) printf '%s\n' 'cgroup:[105]' ;;
                    pid) printf '%s\n' "$task_fake_pid" ;;
                    *) return 1 ;;
                esac
            }
            APOLYSIS_PRIVATE_CONTAINERD_HOST_MNT_NS=mnt:[201]
            APOLYSIS_PRIVATE_CONTAINERD_HOST_NET_NS=net:[202]
            APOLYSIS_PRIVATE_CONTAINERD_HOST_UTS_NS=uts:[203]
            APOLYSIS_PRIVATE_CONTAINERD_HOST_IPC_NS=ipc:[204]
            APOLYSIS_PRIVATE_CONTAINERD_HOST_CGROUP_NS=cgroup:[205]
            APOLYSIS_PRIVATE_CONTAINERD_HOST_PID_NS=pid:[303]
            verify_inner_namespace_contract || return 1
            task_fake_pid=pid:[304]
            if verify_inner_namespace_contract; then
                return 1
            fi
            task_fake_pid=pid:[303]
            APOLYSIS_PRIVATE_CONTAINERD_HOST_MNT_NS=mnt:[101]
            if verify_inner_namespace_contract; then
                return 1
            fi
            ;;
        delegated-residual-cleanup)
            local task_fake_unit task_fake_uid task_fake_gid task_fake_group task_fake_outer
            local task_fake_kill_path task_fake_kill_called=0
            task_fake_unit=apolysis-private-containerd-00000000-0000-4000-8000-000000000002.scope
            task_fake_uid="$(id -u)"
            task_fake_gid="$(id -g)"
            task_fake_group="/user.slice/user-$task_fake_uid.slice/user@$task_fake_uid.service/app.slice/$task_fake_unit"
            task_fake_outer="/user.slice/user-$task_fake_uid.slice/user@$task_fake_uid.service/app.slice/outer.scope"
            task_fake_kill_path="/sys/fs/cgroup$task_fake_group/cgroup.kill"
            delegated_unit_property() {
                [[ "$1" == "$task_fake_unit" && "$2" == "ControlGroup" ]] || return 1
                printf '%s\n' "$task_fake_group"
            }
            current_unified_cgroup() {
                printf '%s\n' "$task_fake_outer"
            }
            prove_delegated_cgroup_kill_target() {
                [[ "$1" == "$task_fake_kill_path" \
                    && "$2" == "$task_fake_uid" && "$3" == "$task_fake_gid" ]]
            }
            bootstrap_root_bounded() {
                [[ "$#" == "8" && "$1" == "5" \
                    && "$2" == "/usr/bin/python3" && "$3" == "-I" \
                    && "$4" == "-c" && "$5" == *'os.O_NOFOLLOW'* \
                    && "$5" == *'os.write(descriptor, b"1")'* \
                    && "$6" == "$task_fake_kill_path" \
                    && "$7" == "$task_fake_uid" && "$8" == "$task_fake_gid" ]] || return 1
                task_fake_kill_called=$((task_fake_kill_called + 1))
            }
            kill_residual_delegated_scope_cgroup \
                "$task_fake_unit" "$task_fake_uid" "$task_fake_gid" \
                || return 1
            [[ "$task_fake_kill_called" == "1" ]] || return 1
            task_fake_kill_called=0
            task_fake_outer="$task_fake_group/init"
            if kill_residual_delegated_scope_cgroup \
                "$task_fake_unit" "$task_fake_uid" "$task_fake_gid"; then
                return 1
            fi
            [[ "$task_fake_kill_called" == "0" ]] || return 1
            task_fake_outer="/outside.scope"
            task_fake_group="/unexpected/$task_fake_unit"
            if kill_residual_delegated_scope_cgroup \
                "$task_fake_unit" "$task_fake_uid" "$task_fake_gid"; then
                return 1
            fi
            [[ "$task_fake_kill_called" == "0" ]]
            ;;
        delegated-cgroup-guards)
            canonical_required_controllers 'cpuset cpu io memory pids' || return 1
            if canonical_required_controllers 'cpuset cpu io memory pids hostile'; then
                return 1
            fi
            if valid_cgroup_nesting_root /tmp/hostile-cgroup contract /expected/control/group; then
                return 1
            fi
            ;;
        cgroup-nesting-diagnostics)
            local task_output task_status
            if task_output="$(prepare_cgroup_v2_nesting \
                /tmp/hostile-private-value contract /expected/control/group 2>&1)"; then
                task_status=0
            else
                task_status=$?
            fi
            [[ "$task_status" != "0" \
                && "$task_output" == 'cgroup nesting step=path' \
                && "$task_output" != *hostile* \
                && "$task_output" != *expected* ]]
            ;;
        delegated-cgroup-nesting)
            local task_output
            task_output="$(run_in_delegated_scope 30 \
                "${BASH_SOURCE[0]}" --delegated-cgroup-nesting-child)" || return 1
            [[ "$task_output" == 'private containerd delegated cgroup nesting child: PASS' ]]
            ;;
        *) return 2 ;;
    esac
}

root_identity() {
    if [[ "${task_root_supervisor_ready:-0}" == "1" ]]; then
        root_bounded 5 1024 65536 stat -c '%d:%i:%u:%g:%a:%F' -- "$1"
    else
        bootstrap_root_bounded 5 /usr/bin/stat -c '%d:%i:%u:%g:%a:%F' -- "$1"
    fi
}

root_path_state() {
    local -a task_command=(python3 -I -c '
import os, sys
try:
    os.lstat(sys.argv[1])
except FileNotFoundError:
    print("absent")
except OSError:
    raise SystemExit(2)
else:
    print("present")
' "$1")
    if [[ "${task_root_supervisor_ready:-0}" == "1" ]]; then
        root_bounded 5 1024 65536 "${task_command[@]}"
    else
        bootstrap_root_bounded 5 "${task_command[@]}"
    fi
}

prove_source_artifact() {
    local task_artifact=$1
    local task_expected_uid=$2
    python3 -I - "$task_artifact" "$task_expected_uid" <<'PY'
import os
import stat
import sys

candidate = os.path.abspath(sys.argv[1])
expected_uid = int(sys.argv[2])
current = "/"
for component in candidate.split("/")[1:]:
    current = os.path.join(current, component)
    metadata = os.lstat(current)
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("source artifact path contains a symlink")

metadata = os.lstat(candidate)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("source artifact is not a regular file")
if metadata.st_nlink != 1 or metadata.st_uid != expected_uid:
    raise SystemExit("source artifact ownership is unsafe")
if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
    raise SystemExit("source artifact has special mode bits")
if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
    raise SystemExit("source artifact is group/world writable")
PY
}

namespace_identity() {
    run_bounded 5 1024 65536 readlink -- "/proc/self/ns/$1"
}

verify_inner_namespace_contract() {
    local task_namespace task_current task_host task_host_variable
    for task_namespace in mnt net uts ipc cgroup; do
        task_host_variable="APOLYSIS_PRIVATE_CONTAINERD_HOST_${task_namespace^^}_NS"
        task_host="${!task_host_variable:-}"
        task_current="$(namespace_identity "$task_namespace")" || return 1
        [[ "$task_host" =~ ^${task_namespace}:\[[0-9]+\]$ \
            && "$task_current" =~ ^${task_namespace}:\[[0-9]+\]$ \
            && "$task_current" != "$task_host" ]] || return 1
    done

    task_host=${APOLYSIS_PRIVATE_CONTAINERD_HOST_PID_NS:-}
    task_current="$(namespace_identity pid)" || return 1
    [[ "$task_host" =~ ^pid:\[[0-9]+\]$ \
        && "$task_current" =~ ^pid:\[[0-9]+\]$ \
        && "$task_current" == "$task_host" ]]
}

prove_inner_context() {
    local task_root=$1
    local task_runner="$task_root/bin/runner"
    local task_runner_hash
    [[ "${APOLYSIS_PRIVATE_CONTAINERD_LIVE:-}" == "1" ]] \
        || fail 'inner live opt-in is absent'
    [[ "${APOLYSIS_PRIVATE_CONTAINERD_INNER:-}" == "1" ]] \
        || fail 'inner namespace handshake is absent'
    [[ "$(run_bounded 5 1024 65536 id -u)" == "0" ]] || fail 'inner gate is not root'
    [[ "$(run_bounded 5 4096 65536 readlink -f -- "${BASH_SOURCE[0]}")" == "$task_runner" ]] \
        || fail 'inner runner is not the root-owned private copy'
    [[ "$(run_bounded 5 4096 65536 stat -Lc '%u:%g:%a:%h:%F' -- "$task_runner")" \
        == '0:0:700:1:regular file' ]] \
        || fail 'inner runner metadata proof failed'
    task_runner_hash="$(run_bounded 10 4096 65536 sha256sum -- "$task_runner")"
    task_runner_hash=${task_runner_hash%% *}
    [[ "$task_runner_hash" == "${APOLYSIS_PRIVATE_CONTAINERD_RUNNER_SHA256:-}" ]] \
        || fail 'inner runner hash proof failed'
    [[ "$(run_bounded 5 4096 65536 stat -Lc '%d:%i:%u:%g:%a:%F' -- "$task_root")" \
        == "${APOLYSIS_PRIVATE_CONTAINERD_ROOT_IDENTITY:-}" ]] \
        || fail 'inner private root identity proof failed'

    verify_inner_namespace_contract || fail 'inner namespace contract proof failed'
}

capture_shared_containerd_service() {
    run_bounded 10 65536 65536 systemctl show containerd.service --no-pager \
        --property=ActiveState --property=SubState --property=MainPID
}

capture_shared_containerd_socket() {
    [[ -S /run/containerd/containerd.sock && ! -L /run/containerd/containerd.sock ]] \
        || return 1
    run_bounded 5 1024 65536 \
        stat -Lc '%d:%i:%u:%g:%a:%F' -- /run/containerd/containerd.sock
}

verify_shared_containerd_unchanged() {
    if [[ -z "${task_shared_containerd_service_before:-}" ]]; then
        return 0
    fi
    local task_service_after task_socket_after
    task_service_after="$(capture_shared_containerd_service)" || return 1
    task_socket_after="$(capture_shared_containerd_socket)" || return 1
    if [[ "$task_service_after" != "$task_shared_containerd_service_before" \
        || "$task_socket_after" != "$task_shared_containerd_socket_before" ]]; then
        printf '%s\n' \
            'private containerd qualification: shared containerd state changed during the gate' >&2
        return 1
    fi
}

capture_docker_containers() {
    run_bounded 15 1048576 1048576 \
        docker --host=unix:///var/run/docker.sock ps -a --no-trunc --format '{{.ID}}'
}

capture_docker_alpine_id() {
    run_bounded 15 1024 1048576 \
        docker --host=unix:///var/run/docker.sock image inspect alpine:3.20 --format '{{.Id}}'
}

capture_docker_service() {
    run_bounded 10 65536 65536 systemctl show docker.service --no-pager \
        --property=ActiveState --property=SubState --property=MainPID
}

capture_docker_socket() {
    [[ -S /var/run/docker.sock && ! -L /var/run/docker.sock ]] || return 1
    run_bounded 5 1024 65536 stat -Lc '%d:%i:%u:%g:%a:%F' -- /var/run/docker.sock
}

verify_docker_unchanged() {
    if [[ "${task_docker_baseline_ready:-0}" != "1" ]]; then
        return 0
    fi
    local task_containers_after task_alpine_after task_service_after task_socket_after
    task_containers_after="$(capture_docker_containers)" || return 1
    task_alpine_after="$(capture_docker_alpine_id)" || return 1
    task_service_after="$(capture_docker_service)" || return 1
    task_socket_after="$(capture_docker_socket)" || return 1
    if [[ "$task_containers_after" != "$task_docker_containers_before" \
        || "$task_alpine_after" != "$task_docker_alpine_before" \
        || "$task_service_after" != "$task_docker_service_before" \
        || "$task_socket_after" != "$task_docker_socket_before" ]]; then
        printf '%s\n' 'private containerd qualification: shared Docker state changed' >&2
        return 1
    fi
}

private_container_residue_clear() {
    local task_required_ids=${1:-}
    local -a task_command=(
        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C
        APOLYSIS_PRIVATE_CONTAINERD_RESIDUE_CHECK=1
        "APOLYSIS_PRIVATE_CONTAINERD_ROOT=$task_private_root"
    )
    if [[ -n "$task_required_ids" ]]; then
        task_command+=("APOLYSIS_PRIVATE_CONTAINERD_REQUIRE_IDS=$task_required_ids")
    fi
    task_command+=(
        "$task_private_root/bin/runtime_adapters"
        --ignored --exact private_container_residue_check_helper --nocapture
    )
    if [[ "$(id -u)" == "0" ]]; then
        run_bounded 30 1048576 1048576 "${task_command[@]}" >/dev/null
    else
        root_bounded 30 1048576 1048576 "${task_command[@]}" >/dev/null
    fi
}

cleanup_user_download() {
    if [[ -z "${task_download_root:-}" ]]; then
        return 0
    fi
    local task_current_identity
    task_current_identity="$(stat -Lc '%d:%i:%u:%g:%a:%F' -- "$task_download_root")" || return 1
    if [[ "$task_current_identity" != "$task_download_identity" ]]; then
        printf '%s\n' 'private containerd qualification: download root identity changed; refusing cleanup' >&2
        return 1
    fi
    if [[ -e "$task_download_root/crictl" ]]; then
        rm -- "$task_download_root/crictl" || return 1
    fi
    if [[ -e "$task_download_root/$crictl_archive" ]]; then
        rm -- "$task_download_root/$crictl_archive" || return 1
    fi
    rmdir -- "$task_download_root" || return 1
    task_download_root=
}

private_root_mount_state() {
    local task_mount_targets task_mount_target
    task_mount_targets="$(root_bounded 10 1048576 1048576 findmnt -rn -o TARGET)" \
        || return 1
    while IFS= read -r task_mount_target; do
        case "$task_mount_target" in
            "$task_private_root"|"$task_private_root"/*)
                printf '%s\n' present
                return 0
                ;;
        esac
    done <<< "$task_mount_targets"
    printf '%s\n' absent
}

private_root_process_state() {
    root_bounded 10 1024 1048576 python3 -I -c '
import os
import sys

needle = os.fsencode(sys.argv[1])
excluded = set()
current = os.getpid()
while current > 1 and current not in excluded:
    excluded.add(current)
    try:
        raw = open(f"/proc/{current}/stat", "r", encoding="ascii").read()
        fields = raw[raw.rfind(")") + 2:].split()
    except (FileNotFoundError, ProcessLookupError):
        break
    current = int(fields[1])
for entry in os.scandir("/proc"):
    if not entry.name.isdigit():
        continue
    if int(entry.name) in excluded:
        continue
    try:
        command_line = open(f"/proc/{entry.name}/cmdline", "rb").read()
    except (FileNotFoundError, ProcessLookupError):
        continue
    if needle in command_line:
        print("present")
        break
else:
    print("absent")
' "$task_private_root"
}

cleanup_private_root_bootstrap() {
    [[ -n "${task_private_identity:-}" ]] || return 1
    bootstrap_root_bounded 15 /usr/bin/python3 -I -c '
import os, re, stat, sys
root, expected_identity = sys.argv[1:]
if os.path.dirname(root) != "/tmp" or re.fullmatch(r"apolysis-private-containerd-live\.[A-Za-z0-9]{6}", os.path.basename(root)) is None:
    raise SystemExit(1)
metadata = os.lstat(root)
identity = f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_uid}:{metadata.st_gid}:{stat.S_IMODE(metadata.st_mode):o}:directory"
if identity != expected_identity or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(1)
needle = os.fsencode(root)
excluded = set()
current = os.getpid()
while current > 1 and current not in excluded:
    excluded.add(current)
    try:
        raw = open(f"/proc/{current}/stat", "r", encoding="ascii").read()
        current = int(raw[raw.rfind(")") + 2:].split()[1])
    except (FileNotFoundError, ProcessLookupError):
        break
for entry in os.scandir("/proc"):
    if not entry.name.isdigit() or int(entry.name) in excluded:
        continue
    try:
        command_line = open(f"/proc/{entry.name}/cmdline", "rb").read()
    except (FileNotFoundError, ProcessLookupError):
        continue
    if needle in command_line:
        raise SystemExit(1)
with open("/proc/self/mountinfo", "r", encoding="utf-8") as mounts:
    for line in mounts:
        target = line.split(" - ", 1)[0].split()[4]
        if target == root or target.startswith(root + "/"):
            raise SystemExit(1)
entries = list(os.scandir(root))
if any(entry.name != "bin" or not entry.is_dir(follow_symlinks=False) for entry in entries):
    raise SystemExit(1)
bin_path = os.path.join(root, "bin")
if os.path.isdir(bin_path):
    allowed = {"runner", "runtime_adapters", "crictl"}
    for entry in os.scandir(bin_path):
        item = entry.stat(follow_symlinks=False)
        if (entry.name not in allowed or not stat.S_ISREG(item.st_mode)
                or item.st_uid != 0 or item.st_gid != 0 or item.st_nlink != 1
                or stat.S_IMODE(item.st_mode) != 0o700):
            raise SystemExit(1)
    for entry in os.scandir(bin_path):
        os.unlink(entry.path)
    os.rmdir(bin_path)
os.rmdir(root)
' "$task_private_root" "$task_private_identity" || return 1
    [[ "$(unprivileged_path_state "$task_private_root")" == "absent" ]] || return 1
    task_private_root=
}

cleanup_private_root() {
    if [[ -z "${task_private_root:-}" ]]; then
        return 0
    fi
    if [[ "${task_root_supervisor_ready:-0}" != "1" ]]; then
        cleanup_private_root_bootstrap
        return $?
    fi
    local task_current_identity task_final_state task_mount_state task_process_state
    task_current_identity="$(root_identity "$task_private_root")" || return 1
    if [[ "$task_current_identity" != "$task_private_identity" ]]; then
        printf '%s\n' 'private containerd qualification: private root identity changed; refusing cleanup' >&2
        return 1
    fi
    task_process_state="$(private_root_process_state)" || {
        printf '%s\n' \
            'private containerd qualification: process inspection failed; preserving private root' >&2
        return 1
    }
    if [[ "$task_process_state" == "present" ]]; then
        printf '%s\n' 'private containerd qualification: owned process remains; preserving private root' >&2
        return 1
    fi
    [[ "$task_process_state" == "absent" ]] || return 1
    task_mount_state="$(private_root_mount_state)" || {
        printf '%s\n' \
            'private containerd qualification: mount inspection failed; preserving private root' >&2
        return 1
    }
    if [[ "$task_mount_state" == "present" ]]; then
        printf '%s\n' 'private containerd qualification: mount remains; preserving private root' >&2
        return 1
    fi
    [[ "$task_mount_state" == "absent" ]] || return 1
    local task_mutation_state
    task_mutation_state="$(root_path_state "$task_private_root/qualification-mutation-started")" \
        || return 1
    case "$task_mutation_state" in
        absent) ;;
        present)
            if ! private_container_residue_clear; then
                printf '%s\n' \
                    'private containerd qualification: container-residue inspection failed; preserving private root' >&2
                return 1
            fi
            ;;
        *) return 1 ;;
    esac
    root_bounded 30 65536 1048576 /usr/bin/python3 -I -c '
import os, shutil, stat, sys
root, expected_identity = sys.argv[1:]
metadata = os.lstat(root)
identity = f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_uid}:{metadata.st_gid}:{stat.S_IMODE(metadata.st_mode):o}:directory"
if identity != expected_identity or not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit(1)
shutil.rmtree(root)
if os.path.lexists(root):
    raise SystemExit(1)
' "$task_private_root" "$task_private_identity" || return 1
    task_final_state="$(unprivileged_path_state "$task_private_root")" || return 1
    if [[ "$task_final_state" != "absent" ]]; then
        printf '%s\n' 'private containerd qualification: private root remains after cleanup' >&2
        return 1
    fi
    task_private_root=
}

cleanup_on_exit() {
    local task_status=$?
    trap - EXIT
    if ! cleanup_private_root; then
        task_status=1
    fi
    if ! cleanup_user_download; then
        task_status=1
    fi
    if ! verify_shared_containerd_unchanged; then
        task_status=1
    fi
    if ! verify_docker_unchanged; then
        task_status=1
    fi
    exit "$task_status"
}

wait_for_containerd() {
    local task_socket=$1
    local task_pid=$2
    local task_attempt
    for ((task_attempt = 0; task_attempt < 200; task_attempt += 1)); do
        if ! kill -0 "$task_pid" 2>/dev/null; then
            return 1
        fi
        if [[ -S "$task_socket" ]] \
            && run_bounded 3 65536 65536 ctr --address "$task_socket" version >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

private_containerd_process_state() {
    local task_pid=$1
    local task_root=$2
    run_bounded 5 65536 65536 python3 -I -c '
import os, sys
leader = int(sys.argv[1])
root = sys.argv[2]
expected = os.path.realpath("/usr/bin/containerd")
found = []
for entry in os.scandir("/proc"):
    if not entry.name.isdigit():
        continue
    try:
        fields = open(f"/proc/{entry.name}/stat", "r", encoding="ascii").read()
        close = fields.rfind(")")
        process_group = int(fields[close + 2:].split()[2])
        executable = os.path.realpath(f"/proc/{entry.name}/exe")
        command_line = open(f"/proc/{entry.name}/cmdline", "rb").read()
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        continue
    if executable == expected and os.fsencode(root + "/config.toml") in command_line:
        found.append(process_group)
if not found:
    print("absent")
elif all(process_group == leader for process_group in found):
    print("present")
else:
    raise SystemExit("private containerd escaped its proven process group")
' "$task_pid" "$task_root"
}

stop_private_containerd() {
    local task_pid=$1
    local task_root=$2
    local task_state
    task_state="$(private_containerd_process_state "$task_pid" "$task_root")" || return 1
    if [[ "$task_state" == "absent" ]]; then
        wait "$task_pid" 2>/dev/null || true
        return 0
    fi
    [[ "$task_state" == "present" ]] || return 1
    kill -TERM -- "-$task_pid" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$task_pid" 2>/dev/null || true
    wait "$task_pid" 2>/dev/null || true
    task_state="$(private_containerd_process_state "$task_pid" "$task_root")" || return 1
    [[ "$task_state" == "absent" ]]
}

build_pause_oci() {
    local task_root=$1
    local task_assets="$task_root/assets"
    local task_layout="$task_assets/pause-oci"
    local task_layer_root="$task_assets/pause-rootfs"
    local task_source="$task_assets/pause.c"
    local task_layer_tar="$task_assets/pause-layer.tar"
    local task_config="$task_assets/pause-config.json"
    local task_manifest="$task_assets/pause-manifest.json"
    local task_layer_digest task_layer_size task_config_digest task_config_size
    local task_manifest_digest task_manifest_size

    run_bounded 10 65536 65536 install -d -o root -g root -m 0700 -- \
        "$task_layout/blobs/sha256" "$task_layer_root"
    printf '%s\n' \
        '#include <signal.h>' \
        '#include <unistd.h>' \
        'static volatile sig_atomic_t stopped;' \
        'static void stop(int signal) { (void)signal; stopped = 1; }' \
        'int main(void) {' \
        '  signal(SIGINT, stop); signal(SIGTERM, stop);' \
        '  while (!stopped) pause();' \
        '  return 0;' \
        '}' > "$task_source"
    run_bounded 30 65536 1048576 cc -static -Os -s -Wl,--build-id=none \
        -o "$task_layer_root/pause" "$task_source"
    run_bounded 5 65536 65536 chmod 0555 "$task_layer_root/pause"
    run_bounded 30 65536 1048576 tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --format=gnu --create --file "$task_layer_tar" --directory "$task_layer_root" pause
    task_layer_digest="$(bounded_sha256 "$task_layer_tar")"
    task_layer_size="$(bounded_file_size "$task_layer_tar")"

    printf '%s' \
        '{"created":"1970-01-01T00:00:00Z","architecture":"amd64","os":"linux",' \
        '"config":{"Entrypoint":["/pause"],"WorkingDir":"/","StopSignal":"SIGTERM"},' \
        '"rootfs":{"type":"layers","diff_ids":["sha256:'"$task_layer_digest"'"]},"history":[]}' \
        > "$task_config"
    task_config_digest="$(bounded_sha256 "$task_config")"
    task_config_size="$(bounded_file_size "$task_config")"

    printf '%s' \
        '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",' \
        '"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:'"$task_config_digest"'","size":'"$task_config_size"'},' \
        '"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:'"$task_layer_digest"'","size":'"$task_layer_size"'}]}' \
        > "$task_manifest"
    task_manifest_digest="$(bounded_sha256 "$task_manifest")"
    task_manifest_size="$(bounded_file_size "$task_manifest")"

    run_bounded 10 65536 65536 install -o root -g root -m 0400 -- \
        "$task_layer_tar" "$task_layout/blobs/sha256/$task_layer_digest"
    run_bounded 10 65536 65536 install -o root -g root -m 0400 -- \
        "$task_config" "$task_layout/blobs/sha256/$task_config_digest"
    run_bounded 10 65536 65536 install -o root -g root -m 0400 -- \
        "$task_manifest" "$task_layout/blobs/sha256/$task_manifest_digest"
    printf '%s' '{"imageLayoutVersion":"1.0.0"}' > "$task_layout/oci-layout"
    printf '%s' \
        '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[' \
        '{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:'"$task_manifest_digest"'","size":'"$task_manifest_size"',' \
        '"platform":{"architecture":"amd64","os":"linux"},"annotations":{"org.opencontainers.image.ref.name":"registry.k8s.io/pause:3.10.2"}}]}' \
        > "$task_layout/index.json"
    run_bounded 5 65536 65536 chmod 0400 "$task_layout/oci-layout" "$task_layout/index.json"
    run_bounded 30 65536 1048576 tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        --format=gnu --create --file "$task_assets/pause-oci.tar" \
        --directory "$task_layout" oci-layout index.json blobs
}

private_containerd_directories() {
    local task_root=$1
    printf '%s\n' \
        "$task_root/assets" \
        "$task_root/containerd-root" \
        "$task_root/containerd-state" \
        "$task_root/empty-cdi-specs" \
        "$task_root/empty-cni-bin" \
        "$task_root/empty-cni-conf" \
        "$task_root/empty-docker-config" \
        "$task_root/empty-image-verifiers" \
        "$task_root/empty-registry" \
        "$task_root/nri/conf.d" \
        "$task_root/nri/plugins" \
        "$task_root/nri/run" \
        "$task_root/opt" \
        "$task_root/run" \
        "$task_root/tmp"
}

write_private_containerd_config() {
    local task_root=$1
    local task_socket=$2
    local task_config="$task_root/config.toml"
    [[ ! -e "$task_config" && ! -L "$task_config" ]] || return 1
    run_bounded 5 65536 65536 install -m 0600 /dev/null "$task_config"
    printf '%s\n' \
        'version = 4' \
        'imports = []' \
        "root = '$task_root/containerd-root'" \
        "state = '$task_root/containerd-state'" \
        "temp = '$task_root/tmp'" \
        "[plugins.'io.containerd.cri.v1.images']" \
        "  snapshotter = 'overlayfs'" \
        "  [plugins.'io.containerd.cri.v1.images'.pinned_images]" \
        "    sandbox = 'registry.k8s.io/pause:3.10.2'" \
        "  [plugins.'io.containerd.cri.v1.images'.registry]" \
        "    config_path = '$task_root/empty-registry'" \
        "[plugins.'io.containerd.cri.v1.runtime']" \
        '  disable_apparmor = true' \
        '  enable_cdi = false' \
        "  cdi_spec_dirs = ['$task_root/empty-cdi-specs']" \
        "  [plugins.'io.containerd.cri.v1.runtime'.containerd]" \
        "    default_runtime_name = 'runc'" \
        "    [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]" \
        "      runtime_type = 'io.containerd.runc.v2'" \
        "      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]" \
        "        BinaryName = '/usr/bin/runc'" \
        '        SystemdCgroup = false' \
        "  [plugins.'io.containerd.cri.v1.runtime'.cni]" \
        "    bin_dirs = ['$task_root/empty-cni-bin']" \
        "    conf_dir = '$task_root/empty-cni-conf'" \
        '    max_conf_num = 0' \
        "[plugins.'io.containerd.grpc.v1.cri']" \
        '  disable_tcp_service = true' \
        "[plugins.'io.containerd.image-verifier.v1.bindir']" \
        "  bin_dir = '$task_root/empty-image-verifiers'" \
        "[plugins.'io.containerd.internal.v1.opt']" \
        "  path = '$task_root/opt'" \
        "[plugins.'io.containerd.nri.v1.nri']" \
        '  disable = true' \
        '  disable_connections = true' \
        "  socket_path = '$task_root/nri/run/nri.sock'" \
        "  plugin_path = '$task_root/nri/plugins'" \
        "  plugin_config_path = '$task_root/nri/conf.d'" \
        "[plugins.'io.containerd.server.v1.grpc']" \
        "  address = '$task_socket'" \
        '  uid = 0' \
        '  gid = 0' \
        "[plugins.'io.containerd.server.v1.ttrpc']" \
        "  address = '$task_root/run/containerd.sock.ttrpc'" \
        '  uid = 0' \
        '  gid = 0' \
        > "$task_config"
    run_bounded 5 65536 65536 chmod 0400 "$task_config"
}

private_crictl() {
    local task_socket=$1
    shift
    run_bounded 30 1048576 1048576 \
        "$task_private_root/bin/crictl" --config /dev/null \
        --runtime-endpoint "unix://$task_socket" --timeout 10s "$@"
}

private_cri_ids() {
    local task_socket=$1
    local task_kind=$2
    local task_ids
    case "$task_kind" in
        container) task_ids="$(private_crictl "$task_socket" ps -a -q)" || return 1 ;;
        pod) task_ids="$(private_crictl "$task_socket" pods -q)" || return 1 ;;
        *) return 1 ;;
    esac
    run_bounded 5 1048576 65536 python3 -I -c '
import re, sys
lines = [line for line in sys.argv[1].splitlines() if line]
if len(lines) > 16 or len(lines) != len(set(lines)):
    raise SystemExit(1)
if any(re.fullmatch(r"[0-9a-f]{64}", line) is None for line in lines):
    raise SystemExit(1)
print("\n".join(lines))
' "$task_ids"
}

persist_swept_private_id() {
    local task_id=$1
    run_bounded 5 1024 1048576 python3 -I -c '
import os, re, stat, sys
root, object_id = sys.argv[1:]
if re.fullmatch(r"[0-9a-f]{64}", object_id) is None:
    raise SystemExit(1)
root_metadata = os.lstat(root)
if (not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_uid != 0
        or root_metadata.st_gid != 0 or stat.S_IMODE(root_metadata.st_mode) != 0o700):
    raise SystemExit(1)
marker = os.path.join(root, "qualification-mutation-started")
marker_metadata = os.lstat(marker)
if (not stat.S_ISREG(marker_metadata.st_mode) or marker_metadata.st_uid != 0
        or marker_metadata.st_gid != 0 or marker_metadata.st_nlink != 1
        or stat.S_IMODE(marker_metadata.st_mode) != 0o600):
    raise SystemExit(1)
proof = os.path.join(root, "qualification-container-ids")
existing = []
try:
    descriptor = os.open(proof, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
except FileNotFoundError:
    pass
else:
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_gid != 0 or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise SystemExit(1)
        document = b""
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            document += chunk
            if len(document) > 1024:
                raise SystemExit(1)
        existing = document.decode("ascii").splitlines()
    finally:
        os.close(descriptor)
if (len(existing) != len(set(existing)) or len(existing) > 6
        or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in existing)):
    raise SystemExit(1)
if object_id in existing:
    raise SystemExit(0)
if len(existing) >= 6:
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
descriptor = os.open(proof, flags, 0o600)
try:
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != 0 or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise SystemExit(1)
    payload = (object_id + "\n").encode("ascii")
    if os.write(descriptor, payload) != len(payload):
        raise SystemExit(1)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
' "$task_private_root" "$task_id"
}

private_proven_residue_state() {
    run_bounded 10 1024 1048576 python3 -I -c '
import os, re, stat, sys
root = sys.argv[1]
proof = os.path.join(root, "qualification-container-ids")
try:
    descriptor = os.open(proof, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
except FileNotFoundError:
    ids = []
else:
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_gid != 0 or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise SystemExit(1)
        document = os.read(descriptor, 4096)
        if os.read(descriptor, 1):
            raise SystemExit(1)
    finally:
        os.close(descriptor)
    ids = document.decode("ascii").splitlines()
if (len(ids) > 6 or len(ids) != len(set(ids))
        or any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in ids)):
    raise SystemExit(1)
needles = [item.encode("ascii") for item in ids]
for entry in os.scandir("/proc"):
    if not entry.name.isdigit():
        continue
    for leaf in ("cmdline", "cgroup"):
        try:
            with open(os.path.join(entry.path, leaf), "rb") as source:
                contents = source.read(1024 * 1024 + 1)
        except (FileNotFoundError, ProcessLookupError):
            continue
        if len(contents) > 1024 * 1024:
            raise SystemExit(1)
        if any(needle in contents for needle in needles):
            print("residue")
            raise SystemExit(0)
inspected = 0
for directory, subdirectories, _files in os.walk("/sys/fs/cgroup", followlinks=False):
    inspected += len(subdirectories)
    if inspected > 100000:
        raise SystemExit(1)
    for name in subdirectories:
        path = os.path.join(directory, name)
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemExit(1)
        encoded = os.fsencode(name)
        if any(needle in encoded for needle in needles):
            print("residue")
            raise SystemExit(0)
print("clear")
' "$task_private_root"
}

prove_private_cri_object_for_sweep() {
    local task_socket=$1
    local task_kind=$2
    local task_id=$3
    local task_inspect task_inspect_fd task_status=0
    case "$task_kind" in
        container)
            task_inspect="$(private_crictl "$task_socket" inspect -o json "$task_id")" \
                || return 1
            ;;
        pod)
            task_inspect="$(private_crictl "$task_socket" inspectp -o json "$task_id")" \
                || return 1
            ;;
        *) return 1 ;;
    esac
    exec {task_inspect_fd}<<<"$task_inspect"
    run_bounded 5 1024 1048576 --stdin-fd "$task_inspect_fd" python3 -I -c '
import json, re, sys
kind, expected_id = sys.argv[1:]
value = json.load(sys.stdin)
status = value.get("status")
if not isinstance(status, dict) or status.get("id") != expected_id:
    raise SystemExit(1)
labels = status.get("labels")
if not isinstance(labels, dict):
    raise SystemExit(1)
uuid = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
fixture_uid = labels.get("apolysis.fixture_uid")
owner = labels.get("apolysis.fixture_owner")
session = labels.get("apolysis.session_id")
if not isinstance(fixture_uid, str) or uuid.fullmatch(fixture_uid) is None:
    raise SystemExit(1)
if not isinstance(owner, str) or uuid.fullmatch(owner) is None:
    raise SystemExit(1)
prefixes = ("live-private-containerd-first-", "live-private-containerd-second-")
if not isinstance(session, str) or not any(
        session.startswith(prefix) and uuid.fullmatch(session[len(prefix):])
        for prefix in prefixes):
    raise SystemExit(1)
if kind == "pod":
    metadata = status.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("uid") != fixture_uid:
        raise SystemExit(1)
' "$task_kind" "$task_id" || task_status=$?
    exec {task_inspect_fd}<&-
    return "$task_status"
}

publish_authoritative_sweep() {
    run_bounded 5 1024 1048576 python3 -I -c '
import os, stat, sys
root = sys.argv[1]
root_stat = os.lstat(root)
if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != 0 or stat.S_IMODE(root_stat.st_mode) != 0o700:
    raise SystemExit(1)
marker = os.path.join(root, "qualification-mutation-started")
marker_stat = os.lstat(marker)
if (not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_uid != 0
        or marker_stat.st_gid != 0 or marker_stat.st_nlink != 1
        or stat.S_IMODE(marker_stat.st_mode) != 0o600):
    raise SystemExit(1)
marker_descriptor = os.open(marker, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    if os.read(marker_descriptor, 16) != b"started\n" or os.read(marker_descriptor, 1):
        raise SystemExit(1)
finally:
    os.close(marker_descriptor)
proof = os.path.join(root, "qualification-authoritative-sweep")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
descriptor = os.open(proof, flags, 0o600)
try:
    os.write(descriptor, b"complete\n")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    os.fsync(directory)
finally:
    os.close(directory)
' "$task_private_root"
}

authoritative_private_runtime_sweep() {
    local task_socket=$1
    local task_ids task_id task_attempt task_empty_samples=0 task_residue_state
    [[ -f "$task_private_root/qualification-mutation-started" ]] || return 0
    [[ -S "$task_socket" ]] || return 1

    for ((task_attempt = 0; task_attempt < 30; task_attempt += 1)); do
        task_ids="$(private_cri_ids "$task_socket" container)" || return 1
        while IFS= read -r task_id; do
            [[ -n "$task_id" ]] || continue
            persist_swept_private_id "$task_id" || return 1
            prove_private_cri_object_for_sweep "$task_socket" container "$task_id" || return 1
            private_crictl "$task_socket" stop --timeout 10 "$task_id" >/dev/null || return 1
            private_crictl "$task_socket" rm -f "$task_id" >/dev/null || return 1
        done <<< "$task_ids"

        task_ids="$(private_cri_ids "$task_socket" pod)" || return 1
        while IFS= read -r task_id; do
            [[ -n "$task_id" ]] || continue
            persist_swept_private_id "$task_id" || return 1
            prove_private_cri_object_for_sweep "$task_socket" pod "$task_id" || return 1
            private_crictl "$task_socket" stopp "$task_id" >/dev/null || return 1
            private_crictl "$task_socket" rmp "$task_id" >/dev/null || return 1
        done <<< "$task_ids"

        task_ids="$(private_cri_ids "$task_socket" container)" || return 1
        if [[ -n "$task_ids" ]]; then
            task_empty_samples=0
            continue
        fi
        task_ids="$(private_cri_ids "$task_socket" pod)" || return 1
        if [[ -n "$task_ids" ]]; then
            task_empty_samples=0
            continue
        fi
        task_empty_samples=$((task_empty_samples + 1))
        if [[ "$task_empty_samples" -ge "12" ]]; then
            task_residue_state="$(private_proven_residue_state)" || return 1
            if [[ "$task_residue_state" == "clear" ]]; then
                publish_authoritative_sweep
                return $?
            fi
            [[ "$task_residue_state" == "residue" ]] || return 1
        fi
        sleep 1
    done
    return 1
}

inner_cleanup() {
    local task_status=$?
    trap - EXIT
    if [[ -f "$task_private_root/qualification-mutation-started" \
        && "${task_inner_sweep_complete:-0}" != "1" ]]; then
        if authoritative_private_runtime_sweep "$task_inner_socket"; then
            task_inner_sweep_complete=1
        else
            task_status=1
        fi
    fi
    if [[ -n "${task_inner_containerd_pid:-}" \
        && "${task_inner_containerd_stopped:-0}" != "1" ]]; then
        if ! stop_private_containerd "$task_inner_containerd_pid" "$task_private_root"; then
            task_status=1
        fi
    fi
    exit "$task_status"
}

inner_gate() {
    local task_root=$1
    task_private_root=$task_root
    prove_inner_context "$task_root"
    umask 077

    local task_socket="$task_root/run/containerd.sock"
    task_inner_socket=$task_socket
    task_inner_containerd_pid=
    task_inner_containerd_stopped=0
    task_inner_sweep_complete=0
    local task_docker_before task_docker_after task_alpine_id_before task_alpine_id_after
    local -a task_directories

    trap inner_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    mapfile -t task_directories < <(private_containerd_directories "$task_root")
    [[ "${#task_directories[@]}" == "15" ]] \
        || fail 'private containerd directory contract is incomplete'
    run_bounded 15 65536 65536 install -d -o root -g root -m 0700 -- \
        "${task_directories[@]}"
    run_bounded 10 65536 65536 mount --make-rprivate /
    run_bounded 10 65536 65536 mount -t cgroup2 -o nsdelegate none /sys/fs/cgroup
    prepare_private_cgroup_v2_nesting \
        || fail 'private cgroup v2 nesting preparation failed'
    task_docker_before="$(
        run_bounded 15 1048576 1048576 \
            docker --host=unix:///var/run/docker.sock ps -a --no-trunc --format '{{.ID}}'
    )"
    task_alpine_id_before="$(
        run_bounded 15 1024 1048576 \
            docker --host=unix:///var/run/docker.sock image inspect alpine:3.20 --format '{{.Id}}'
    )" || fail 'cached alpine:3.20 is required; the runner never pulls images'
    [[ "$task_alpine_id_before" == "$alpine_image_id" ]] \
        || fail 'cached alpine:3.20 identity does not match the pinned offline fixture'
    build_pause_oci "$task_root"
    run_bounded 60 65536 1048576 docker --host=unix:///var/run/docker.sock image save \
        --output "$task_root/assets/alpine.tar" alpine:3.20
    run_bounded 5 65536 65536 chmod 0400 "$task_root/assets/alpine.tar"

    write_private_containerd_config "$task_root" "$task_socket" \
        || fail 'private containerd config publication failed'

    setsid timeout --signal=TERM --kill-after=2s 540s \
        containerd --config "$task_root/config.toml" --log-level error \
        > /dev/null 2>&1 &
    task_inner_containerd_pid=$!
    wait_for_containerd "$task_socket" "$task_inner_containerd_pid" \
        || fail 'private containerd did not become ready'

    ctr --address "$task_socket" --namespace k8s.io images import \
        --platform linux/amd64 "$task_root/assets/pause-oci.tar" >/dev/null
    ctr --address "$task_socket" --namespace k8s.io images import \
        --platform linux/amd64 "$task_root/assets/alpine.tar" >/dev/null
    ctr --address "$task_socket" --namespace k8s.io images list -q \
        | grep -Fx 'registry.k8s.io/pause:3.10.2' >/dev/null \
        || fail 'private pause image import was not observable'
    ctr --address "$task_socket" --namespace k8s.io images list -q \
        | grep -Fx 'docker.io/library/alpine:3.20' >/dev/null \
        || fail 'private Alpine image import was not observable'

    APOLYSIS_PRIVATE_CONTAINERD_LIVE=1 \
    APOLYSIS_PRIVATE_CONTAINERD_DIAGNOSTIC=1 \
    APOLYSIS_PRIVATE_CONTAINERD_ROOT="$task_root" \
    APOLYSIS_CRICTL="$task_root/bin/crictl" \
    TMPDIR="$task_root/tmp" \
        "$task_root/bin/runtime_adapters" \
        --ignored --exact "$test_name" --nocapture

    authoritative_private_runtime_sweep "$task_socket" \
        || fail 'authoritative private CRI cleanup sweep failed'
    task_inner_sweep_complete=1
    private_container_residue_clear 6 \
        || fail 'private container residue remained after the exact test'

    stop_private_containerd "$task_inner_containerd_pid" "$task_root" \
        || fail 'private containerd did not stop cleanly'
    task_inner_containerd_stopped=1
    private_container_residue_clear 6 \
        || fail 'private container residue remained after runtime stop'
    task_docker_after="$(run_bounded 15 1048576 1048576 \
        docker --host=unix:///var/run/docker.sock ps -a --no-trunc --format '{{.ID}}')"
    task_alpine_id_after="$(
        run_bounded 15 1024 1048576 \
            docker --host=unix:///var/run/docker.sock image inspect alpine:3.20 --format '{{.Id}}'
    )"
    [[ "$task_docker_after" == "$task_docker_before" ]] \
        || fail 'Docker container inventory changed during read-only image export'
    [[ "$task_alpine_id_after" == "$task_alpine_id_before" ]] \
        || fail 'cached Alpine image identity changed'
    trap - EXIT
    printf '%s\n' 'private containerd qualification inner gate: PASS'
}

if [[ "${1:-}" == "--delegated-contract-child" ]]; then
    [[ $# == 1 && "$(id -u)" != "0" ]] \
        || fail 'invalid delegated contract child invocation'
    verify_delegated_scope \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID:-}" \
        || fail 'delegated contract child scope proof failed'
    printf '%s\n' 'private containerd delegated scope child: PASS'
    exit 0
fi

if [[ "${1:-}" == "--delegated-cgroup-nesting-child" ]]; then
    [[ $# == 1 && "$(id -u)" != "0" ]] \
        || fail 'invalid delegated cgroup nesting child invocation'
    run_delegated_cgroup_nesting_contract_child \
        || fail 'delegated cgroup nesting preparation failed'
    printf '%s\n' 'private containerd delegated cgroup nesting child: PASS'
    exit 0
fi

if [[ "${1:-}" == "--supervise" ]]; then
    [[ "$(id -u)" == "0" && $# -ge 5 ]] || fail 'invalid root supervisor invocation'
    shift
    run_bounded "$@"
    exit $?
fi

if [[ "${1:-}" == "--bounded-contract" ]]; then
    [[ $# == 2 && "$(id -u)" != "0" ]] || fail 'invalid bounded contract invocation'
    bounded_contract "$2" || fail "bounded contract failed: $2"
    printf 'private containerd bounded contract %s: PASS\n' "$2"
    exit 0
fi

if [[ "${1:-}" == "--inner" ]]; then
    [[ $# == 2 ]] || fail 'invalid inner arguments'
    inner_gate "$2"
    exit 0
fi

task_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$task_repo_root"
unset OLDPWD

if [[ "${1:-}" == "--delegated-main-proof-child" ]]; then
    [[ $# == 1 && "$(id -u)" != "0" ]] \
        || fail 'invalid delegated main proof child invocation'
    verify_delegated_scope \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" \
        "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID:-}" \
        || fail 'delegated main child scope proof failed'
    printf '%s\n' 'private containerd delegated main child: PASS'
    exit 0
fi

if [[ "${APOLYSIS_PRIVATE_CONTAINERD_LIVE:-0}" != "1" ]]; then
    printf 'private containerd qualification: SKIP (set %s=1)\n' "$opt_in"
    exit 0
fi
if [[ "$(id -u)" == "0" ]]; then
    fail 'run as the unprivileged checkout owner with sudo access'
fi
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] \
    || fail 'this runner currently qualifies Linux amd64 only'

for task_command in awk cargo cc chmod containerd ctr curl docker find findmnt grep id install \
    mkdir mktemp mount python3 readlink rm rmdir setsid sha256sum sleep sort stat sudo sync systemctl \
    systemd-run tar timeout tr uname unshare; do
    command -v "$task_command" >/dev/null 2>&1 \
        || fail "missing required command: $task_command"
done

task_scope_runner="$(readlink -f -- "${BASH_SOURCE[0]}")"
case "$task_scope_runner" in
    "$task_repo_root"/scripts/run-private-containerd-live.sh) ;;
    *) fail 'delegated scope runner path escaped the repository' ;;
esac
prove_source_artifact "$task_scope_runner" "$(id -u)"
case "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_SCOPE:-}" in
    '')
        [[ -z "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" \
            && -z "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID:-}" ]] \
            || fail 'partial delegated scope handshake is forbidden'
        sudo -v || fail 'root authorization unavailable'
        task_scope_status=0
        run_in_delegated_scope 600 "$task_scope_runner" || task_scope_status=$?
        exit "$task_scope_status"
        ;;
    1)
        verify_delegated_scope \
            "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UNIT:-}" \
            "${APOLYSIS_PRIVATE_CONTAINERD_DELEGATED_UID:-}" \
            || fail 'delegated scope proof failed before private mutation'
        sudo -n -v || fail 'pre-authorized root access was not retained in delegated scope'
        ;;
    *) fail 'invalid delegated scope handshake' ;;
esac

task_source_uid="$(id -u)"
task_download_root=
task_download_identity=
task_private_root=
task_private_identity=
task_shared_containerd_service_before=
task_shared_containerd_socket_before=
task_docker_baseline_ready=0
task_docker_containers_before=
task_docker_alpine_before=
task_docker_service_before=
task_docker_socket_before=
task_root_supervisor_ready=0
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -n "${APOLYSIS_CRICTL:-}" ]]; then
    [[ "$APOLYSIS_CRICTL" == /* ]] || fail 'APOLYSIS_CRICTL must be absolute'
    task_source_crictl="$(readlink -f -- "$APOLYSIS_CRICTL")"
    [[ "$task_source_crictl" == "$APOLYSIS_CRICTL" ]] \
        || fail 'APOLYSIS_CRICTL must not traverse symlinks'
else
    task_download_root="$(mktemp -d /tmp/apolysis-crictl-v1.36.0.XXXXXX)"
    case "$task_download_root" in
        /tmp/apolysis-crictl-v1.36.0.*) ;;
        *) fail 'unsafe crictl download root' ;;
    esac
    chmod 0700 "$task_download_root"
    task_download_identity="$(stat -Lc '%d:%i:%u:%g:%a:%F' -- "$task_download_root")"
    [[ "$task_download_identity" == *":$task_source_uid:"*':700:directory' ]] \
        || fail 'unsafe crictl download root identity'
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "$task_download_root/$crictl_archive" "$crictl_url"
    printf '%s  %s\n' "$crictl_sha256" "$task_download_root/$crictl_archive" \
        | sha256sum --check --strict
    [[ "$(tar --list --gzip --file "$task_download_root/$crictl_archive")" == 'crictl' ]] \
        || fail 'official crictl archive contained unexpected entries'
    tar --extract --gzip --file "$task_download_root/$crictl_archive" \
        --directory "$task_download_root" --no-same-owner --no-same-permissions crictl
    chmod 0500 "$task_download_root/crictl"
    task_source_crictl="$task_download_root/crictl"
fi

prove_source_artifact "$task_source_crictl" "$task_source_uid"
[[ "$(sha256sum -- "$task_source_crictl" | awk '{print $1}')" == "$crictl_binary_sha256" ]] \
    || fail 'crictl binary hash does not match the pinned official release'
"$task_source_crictl" --version | grep -Fx "crictl version $crictl_version" >/dev/null \
    || fail "crictl must be $crictl_version"

task_source_runner="$(readlink -f -- "${BASH_SOURCE[0]}")"
case "$task_source_runner" in
    "$task_repo_root"/scripts/run-private-containerd-live.sh) ;;
    *) fail 'runner source path escaped the repository' ;;
esac
prove_source_artifact "$task_source_runner" "$task_source_uid"

task_source_test="$(
    cargo test -p apolysis-daemon --test runtime_adapters --no-run --message-format=json |
        python3 -I -c '
import json
import sys

executables = []
for line in sys.stdin:
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        continue
    target = message.get("target", {})
    executable = message.get("executable")
    if (message.get("reason") == "compiler-artifact"
            and target.get("name") == "runtime_adapters"
            and executable):
        executables.append(executable)
if len(executables) != 1:
    raise SystemExit("expected exactly one runtime_adapters test executable")
print(executables[0])
'
)"
task_source_test="$(readlink -f -- "$task_source_test")"
case "$task_source_test" in
    "$task_repo_root"/target/*) ;;
    *) fail 'test executable escaped target/' ;;
esac
prove_source_artifact "$task_source_test" "$task_source_uid"

task_source_runner_hash="$(sha256sum -- "$task_source_runner" | awk '{print $1}')"
task_source_test_hash="$(sha256sum -- "$task_source_test" | awk '{print $1}')"
task_source_crictl_hash="$(sha256sum -- "$task_source_crictl" | awk '{print $1}')"

task_private_root="$(bootstrap_root_bounded 5 \
    /usr/bin/mktemp -d /tmp/apolysis-private-containerd-live.XXXXXX)"
case "$task_private_root" in
    /tmp/apolysis-private-containerd-live.??????) ;;
    *) fail 'unsafe private containerd root path' ;;
esac
task_private_identity="$(root_identity "$task_private_root")"
[[ "$task_private_identity" == *':0:0:700:directory' ]] \
    || fail 'unsafe private containerd root identity'
bootstrap_root_bounded 10 /usr/bin/install -d -o root -g root -m 0700 -- \
    "$task_private_root/bin"
bootstrap_root_bounded 10 /usr/bin/install -o root -g root -m 0700 -- \
    "$task_source_runner" "$task_private_root/bin/runner"
[[ "$(bootstrap_root_bounded 5 /usr/bin/stat -c '%u:%g:%a:%h:%F' -- \
    "$task_private_root/bin/runner")" == '0:0:700:1:regular file' ]] \
    || fail 'unsafe root-owned runner identity'
task_published_hash="$(bootstrap_root_bounded 10 /usr/bin/sha256sum -- \
    "$task_private_root/bin/runner")"
[[ "${task_published_hash%% *}" == "$task_source_runner_hash" ]] \
    || fail 'root-owned runner hash mismatch'
task_root_supervisor_ready=1

root_bounded 10 65536 1048576 install -o root -g root -m 0700 -- \
    "$task_source_test" "$task_private_root/bin/runtime_adapters"
root_bounded 10 65536 1048576 install -o root -g root -m 0700 -- \
    "$task_source_crictl" "$task_private_root/bin/crictl"

for task_pair in \
    "$task_private_root/bin/runner:$task_source_runner_hash" \
    "$task_private_root/bin/runtime_adapters:$task_source_test_hash" \
    "$task_private_root/bin/crictl:$task_source_crictl_hash"; do
    task_published=${task_pair%%:*}
    task_expected_hash=${task_pair##*:}
    [[ "$(root_bounded 5 1024 65536 stat -c '%u:%g:%a:%h:%F' -- \
        "$task_published")" == '0:0:700:1:regular file' ]] \
        || fail 'unsafe root-owned artifact identity'
    task_published_hash="$(root_bounded 10 4096 65536 sha256sum -- "$task_published")"
    [[ "${task_published_hash%% *}" == "$task_expected_hash" ]] \
        || fail 'root-owned artifact hash mismatch'
done
[[ "$(sha256sum -- "$task_source_runner" | awk '{print $1}')" == "$task_source_runner_hash" \
    && "$(sha256sum -- "$task_source_test" | awk '{print $1}')" == "$task_source_test_hash" \
    && "$(sha256sum -- "$task_source_crictl" | awk '{print $1}')" == "$task_source_crictl_hash" ]] \
    || fail 'source artifact changed during root publication'

task_host_mnt_ns="$(namespace_identity mnt)"
task_host_net_ns="$(namespace_identity net)"
task_host_uts_ns="$(namespace_identity uts)"
task_host_ipc_ns="$(namespace_identity ipc)"
task_host_pid_ns="$(namespace_identity pid)"
task_host_cgroup_ns="$(namespace_identity cgroup)"
task_shared_containerd_service_before="$(capture_shared_containerd_service)" \
    || fail 'cannot capture shared containerd.service state'
task_shared_containerd_socket_before="$(capture_shared_containerd_socket)" \
    || fail 'cannot capture shared containerd socket identity'
task_docker_containers_before="$(capture_docker_containers)" \
    || fail 'cannot capture shared Docker container inventory'
task_docker_alpine_before="$(capture_docker_alpine_id)" \
    || fail 'cannot capture cached Alpine identity'
task_docker_service_before="$(capture_docker_service)" \
    || fail 'cannot capture shared docker.service state'
task_docker_socket_before="$(capture_docker_socket)" \
    || fail 'cannot capture shared Docker socket identity'
[[ "$task_docker_alpine_before" == "$alpine_image_id" ]] \
    || fail 'cached Alpine identity does not match the pinned fixture'
task_docker_baseline_ready=1

root_bounded 600 4194304 4194304 \
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \
    DOCKER_CONFIG="$task_private_root/empty-docker-config" \
    APOLYSIS_PRIVATE_CONTAINERD_LIVE=1 \
    APOLYSIS_PRIVATE_CONTAINERD_INNER=1 \
    APOLYSIS_PRIVATE_CONTAINERD_ROOT_IDENTITY="$task_private_identity" \
    APOLYSIS_PRIVATE_CONTAINERD_RUNNER_SHA256="$task_source_runner_hash" \
    APOLYSIS_PRIVATE_CONTAINERD_HOST_MNT_NS="$task_host_mnt_ns" \
    APOLYSIS_PRIVATE_CONTAINERD_HOST_NET_NS="$task_host_net_ns" \
    APOLYSIS_PRIVATE_CONTAINERD_HOST_UTS_NS="$task_host_uts_ns" \
    APOLYSIS_PRIVATE_CONTAINERD_HOST_IPC_NS="$task_host_ipc_ns" \
    APOLYSIS_PRIVATE_CONTAINERD_HOST_PID_NS="$task_host_pid_ns" \
    APOLYSIS_PRIVATE_CONTAINERD_HOST_CGROUP_NS="$task_host_cgroup_ns" \
    unshare "${private_unshare_args[@]}" \
    "$task_private_root/bin/runner" --inner "$task_private_root"

verify_shared_containerd_unchanged \
    || fail 'shared containerd postcondition failed'
verify_docker_unchanged \
    || fail 'shared Docker postcondition failed'
cleanup_private_root
cleanup_user_download
trap - EXIT
printf '%s\n' 'private containerd qualification: PASS'

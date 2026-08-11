#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

opt_in=APOLYSIS_LIVE_DOCKER_EBPF
test_name=live_daemon_ebpf_attributes_a_docker_file_event_to_the_exact_runtime_binding

if [[ "${APOLYSIS_LIVE_DOCKER_EBPF:-0}" != "1" ]]; then
    printf 'runtime binding Docker/eBPF qualification: SKIP (set %s=1)\n' "$opt_in"
    exit 0
fi

if [[ "$(id -u)" == "0" ]]; then
    printf '%s\n' \
        'runtime binding Docker/eBPF qualification: run this script as an unprivileged checkout owner with sudo access' >&2
    exit 2
fi

for command in awk cargo id install make mktemp python3 readlink rm rmdir sha256sum stat sudo; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'runtime binding Docker/eBPF qualification: SKIP (missing %s)\n' "$command"
        exit 0
    }
done

if ! cargo --version >/dev/null 2>&1; then
    printf '%s\n' 'runtime binding Docker/eBPF qualification: SKIP (Rust toolchain unavailable)'
    exit 0
fi

if ! sudo -v; then
    printf '%s\n' 'runtime binding Docker/eBPF qualification: SKIP (root authorization unavailable)'
    exit 0
fi

# Build as the checkout owner. Root never invokes Cargo or executes a binary
# directly from the user-writable target directory.
APOLYSIS_REQUIRE_BPF=1 make build-ebpf
test_binary="$(
    cargo test -p apolysis-daemon --test runtime_binding_live --no-run \
        --message-format=json |
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
            and target.get("name") == "runtime_binding_live"
            and executable):
        executables.append(executable)

if len(executables) != 1:
    print("expected exactly one runtime_binding_live test executable", file=sys.stderr)
    raise SystemExit(1)
print(executables[0])
'
)"
test_binary="$(readlink -f -- "$test_binary")"

case "$test_binary" in
    "$repo_root"/target/*) ;;
    *)
        printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe test executable path' >&2
        exit 1
        ;;
esac

source_bpf="$(readlink -f -- "$repo_root/target/ebpf/apolysis_observer.bpf.o")"
case "$source_bpf" in
    "$repo_root"/target/ebpf/*) ;;
    *)
        printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe BPF object path' >&2
        exit 1
        ;;
esac

python3 -I - "$test_binary" "$source_bpf" "$(id -u)" <<'PY'
import os
import stat
import sys

expected_uid = int(sys.argv[3])
for path in sys.argv[1:3]:
    metadata = os.lstat(path)
    unsafe = (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )
    if unsafe:
        raise SystemExit("unsafe live qualification source artifact metadata")
PY

source_binary_hash="$(sha256sum -- "$test_binary" | awk '{print $1}')"
source_bpf_hash="$(sha256sum -- "$source_bpf" | awk '{print $1}')"
root_dir=
root_binary=
root_bpf=
root_dir_identity=
root_binary_identity=
root_bpf_identity=

root_path_state() {
    sudo -- python3 -I - "$1" <<'PY'
import os
import sys

try:
    os.lstat(sys.argv[1])
except FileNotFoundError:
    print("absent")
except OSError:
    raise SystemExit(2)
else:
    print("present")
PY
}

strict_cleanup() {
    if [[ -z "$root_dir" ]]; then
        return 0
    fi
    local state current_root_identity current_binary_identity current_binary_hash
    local current_bpf_identity current_bpf_hash binary_state bpf_state
    local -a removal_paths=()
    if ! state="$(root_path_state "$root_dir")"; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private-root state check failed' >&2
        return 1
    fi
    if [[ "$state" != "present" ]]; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private root disappeared before cleanup' >&2
        return 1
    fi
    current_root_identity="$(sudo -- stat -c '%d:%i:%u:%g:%a:%F' -- "$root_dir")" || return 1
    if [[ -z "$root_dir_identity" || "$current_root_identity" != "$root_dir_identity" ]]; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private root identity changed; refusing cleanup' >&2
        return 1
    fi
    if ! sudo -- python3 -I - "$root_dir" <<'PY'
import os
import sys

if not set(os.listdir(sys.argv[1])).issubset(
        {"runtime_binding_live", "apolysis_observer.bpf.o"}):
    raise SystemExit(1)
PY
    then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private root contains unknown entries; refusing cleanup' >&2
        return 1
    fi
    if ! binary_state="$(root_path_state "$root_binary")" \
        || ! bpf_state="$(root_path_state "$root_bpf")"; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private artifact state check failed' >&2
        return 1
    fi
    if [[ "$binary_state" == "present" ]]; then
        current_binary_identity="$(sudo -- stat -c '%d:%i:%u:%g:%a:%h:%F' -- "$root_binary")" || return 1
        current_binary_hash="$(sudo -- sha256sum -- "$root_binary" | awk '{print $1}')" || return 1
        case "$current_binary_identity" in
            *:0:0:700:1:'regular file') ;;
            *)
                printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe partial test binary; refusing cleanup' >&2
                return 1
                ;;
        esac
        if [[ "$current_binary_hash" != "$source_binary_hash" \
            || ( -n "$root_binary_identity" \
                && "$current_binary_identity" != "$root_binary_identity" ) ]]; then
            printf '%s\n' 'runtime binding Docker/eBPF qualification: private artifact identity changed; refusing cleanup' >&2
            return 1
        fi
        removal_paths+=("$root_binary")
    elif [[ -n "$root_binary_identity" ]]; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private test binary disappeared; refusing cleanup' >&2
        return 1
    fi
    if [[ "$bpf_state" == "present" ]]; then
        current_bpf_identity="$(sudo -- stat -c '%d:%i:%u:%g:%a:%h:%F' -- "$root_bpf")" || return 1
        current_bpf_hash="$(sudo -- sha256sum -- "$root_bpf" | awk '{print $1}')" || return 1
        case "$current_bpf_identity" in
            *:0:0:400:1:'regular file') ;;
            *)
                printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe partial BPF object; refusing cleanup' >&2
                return 1
                ;;
        esac
        if [[ "$current_bpf_hash" != "$source_bpf_hash" \
            || ( -n "$root_bpf_identity" \
                && "$current_bpf_identity" != "$root_bpf_identity" ) ]]; then
            printf '%s\n' 'runtime binding Docker/eBPF qualification: private artifact identity changed; refusing cleanup' >&2
            return 1
        fi
        removal_paths+=("$root_bpf")
    elif [[ -n "$root_bpf_identity" ]]; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private BPF object disappeared; refusing cleanup' >&2
        return 1
    fi
    if (( ${#removal_paths[@]} > 0 )); then
        sudo -- rm -- "${removal_paths[@]}" || return 1
    fi
    sudo -- rmdir -- "$root_dir" || return 1
    if ! state="$(root_path_state "$root_dir")" || [[ "$state" != "absent" ]]; then
        printf '%s\n' 'runtime binding Docker/eBPF qualification: private root remains after cleanup' >&2
        return 1
    fi
    root_dir=
    return 0
}

cleanup_on_exit() {
    status=$?
    trap - EXIT
    if [[ -n "$root_dir" ]] && ! strict_cleanup; then
        status=1
    fi
    exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

root_dir="$(sudo -- mktemp -d /tmp/apolysis-runtime-binding-live.XXXXXXXX)"
root_binary="$root_dir/runtime_binding_live"
root_bpf="$root_dir/apolysis_observer.bpf.o"
case "$root_dir" in
    /tmp/apolysis-runtime-binding-live.*) ;;
    *)
        printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe private root path' >&2
        exit 1
        ;;
esac
root_dir_identity="$(sudo -- stat -c '%d:%i:%u:%g:%a:%F' -- "$root_dir")"
case "$root_dir_identity" in
    *:0:0:700:directory) ;;
    *)
        printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe private root identity' >&2
        exit 1
        ;;
esac

sudo -- install -o root -g root -m 0700 -- "$test_binary" "$root_binary"
root_binary_identity="$(sudo -- stat -c '%d:%i:%u:%g:%a:%h:%F' -- "$root_binary")"
case "$root_binary_identity" in
    *:0:0:700:1:'regular file') ;;
    *)
        printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe private test binary identity' >&2
        exit 1
        ;;
esac
sudo -- install -o root -g root -m 0400 -- "$source_bpf" "$root_bpf"
root_bpf_identity="$(sudo -- stat -c '%d:%i:%u:%g:%a:%h:%F' -- "$root_bpf")"
case "$root_bpf_identity" in
    *:0:0:400:1:'regular file') ;;
    *)
        printf '%s\n' 'runtime binding Docker/eBPF qualification: unsafe private BPF object identity' >&2
        exit 1
        ;;
esac

if [[ "$(sha256sum -- "$test_binary" | awk '{print $1}')" != "$source_binary_hash" \
    || "$(sha256sum -- "$source_bpf" | awk '{print $1}')" != "$source_bpf_hash" \
    || "$(sudo -- sha256sum -- "$root_binary" | awk '{print $1}')" != "$source_binary_hash" \
    || "$(sudo -- sha256sum -- "$root_bpf" | awk '{print $1}')" != "$source_bpf_hash" ]]; then
    printf '%s\n' 'runtime binding Docker/eBPF qualification: source artifact changed during publication' >&2
    exit 1
fi

sudo -- env -i PATH=/usr/bin:/bin TMPDIR=/tmp \
    "$opt_in=1" "APOLYSIS_LIVE_BPF_OBJECT=$root_bpf" "$root_binary" \
    --ignored --exact "$test_name" --nocapture

strict_cleanup
trap - EXIT
printf '%s\n' 'runtime binding Docker/eBPF qualification: PASS'

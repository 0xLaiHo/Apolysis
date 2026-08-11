#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${APOLYSIS_LIVE_SYSTEM_INSTALL:-0}" != "1" ]]; then
    printf 'local daemon system install qualification: SKIP (set APOLYSIS_LIVE_SYSTEM_INSTALL=1)\n'
    exit 0
fi

for command in \
    awk cargo chmod date env find getent git groupadd groupdel id install journalctl make \
    mkdir mktemp python3 rm rmdir rustc seq sha256sum sleep stat systemctl \
    systemd-analyze tar uname; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'local daemon system install qualification: SKIP (missing %s)\n' "$command"
        exit 0
    }
done

if ! cargo --version >/dev/null 2>&1 || ! rustc --version >/dev/null 2>&1; then
    printf 'local daemon system install qualification: SKIP (Rust toolchain is unavailable)\n'
    exit 0
fi
rust_target_libdir="$(rustc --print target-libdir 2>/dev/null || true)"
if [[ -z "$rust_target_libdir" || ! -d "$rust_target_libdir" ]]; then
    printf 'local daemon system install qualification: SKIP (host Rust target is unavailable)\n'
    exit 0
fi

if [[ "$(id -u)" == "0" ]]; then
    root_command=()
elif sudo -n true >/dev/null 2>&1; then
    root_command=(sudo -n)
else
    printf 'local daemon system install qualification: SKIP (passwordless root command unavailable)\n'
    exit 0
fi

run_root() {
    "${root_command[@]}" "$@"
}

if ! systemctl is-system-running >/dev/null 2>&1; then
    printf 'local daemon system install qualification: SKIP (systemd is not running)\n'
    exit 0
fi

set +e
bpf_build_prerequisite="$(
    APOLYSIS_REQUIRE_BPF=0 "$repo_root/scripts/check-bpf-prereqs.sh" build 2>&1
)"
bpf_build_prerequisite_status=$?
set -e
if [[ "$bpf_build_prerequisite_status" == "77" ]]; then
    printf 'local daemon system install qualification: SKIP (%s)\n' "$bpf_build_prerequisite"
    exit 0
fi
if [[ "$bpf_build_prerequisite_status" != "0" ]]; then
    printf 'local daemon system install qualification: prerequisite check failed: %s\n' \
        "$bpf_build_prerequisite" >&2
    exit 1
fi

set +e
bpf_live_prerequisite="$(
    run_root env APOLYSIS_REQUIRE_BPF=0 \
        "$repo_root/scripts/check-bpf-prereqs.sh" live 2>&1
)"
bpf_live_prerequisite_status=$?
set -e
if [[ "$bpf_live_prerequisite_status" == "77" ]]; then
    printf 'local daemon system install qualification: SKIP (%s)\n' "$bpf_live_prerequisite"
    exit 0
fi
if [[ "$bpf_live_prerequisite_status" != "0" ]]; then
    printf 'local daemon system install qualification: prerequisite check failed: %s\n' \
        "$bpf_live_prerequisite" >&2
    exit 1
fi

unit_name=apolysisd.service
library_dir=/usr/local/lib/apolysis
managed_paths=(
    /usr/local/bin/apolysis
    /usr/local/bin/apolysisd
    /usr/local/bin/apolysisd-health
    /usr/local/lib/apolysis/apolysis_observer.bpf.o
    /usr/local/lib/apolysis/install-receipt-v1.json
    /etc/systemd/system/apolysisd.service
)
unit_search_roots=(
    /etc/systemd/system.control
    /run/systemd/system.control
    /run/systemd/transient
    /run/systemd/generator.early
    /etc/systemd/system
    /etc/systemd/system.attached
    /run/systemd/system
    /run/systemd/system.attached
    /run/systemd/generator
    /usr/local/lib/systemd/system
    /usr/lib/systemd/system
    /lib/systemd/system
    /run/systemd/generator.late
)

# One bounded privileged filesystem seam for the gate's fixed paths. It uses
# lstat or descriptor-relative O_NOFOLLOW operations and never recursively
# removes host state.
host_fs_guard() {
    run_root python3 -I - "$@" <<'PY'
import os
import stat
import sys

action, *args = sys.argv[1:]
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def identity(metadata):
    return (
        f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_uid}:"
        f"{metadata.st_gid}:{stat.S_IMODE(metadata.st_mode):o}"
    )


def open_parent(path):
    parts = [part for part in path.split("/") if part]
    directory_fd = os.open("/", DIR_FLAGS)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, DIR_FLAGS, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd, parts[-1]


if action == "path-state":
    try:
        os.lstat(args[0])
    except FileNotFoundError:
        raise SystemExit(10)
    raise SystemExit(0)

if action == "directory-identity":
    try:
        metadata = os.lstat(args[0])
    except FileNotFoundError:
        print("absent")
        raise SystemExit(0)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("path is not a real directory")
    print(identity(metadata))
    raise SystemExit(0)

if action == "assert-metadata":
    path, expected_kind, expected_mode, expected_uid, expected_gid = args
    parent_fd, name = open_parent(path)
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    kinds = {
        "file": stat.S_ISREG(metadata.st_mode),
        "directory": stat.S_ISDIR(metadata.st_mode),
        "socket": stat.S_ISSOCK(metadata.st_mode),
    }
    if (not kinds[expected_kind]
            or (expected_kind != "directory" and metadata.st_nlink != 1)
            or stat.S_IMODE(metadata.st_mode) != int(expected_mode, 8)
            or metadata.st_uid != int(expected_uid)
            or metadata.st_gid != int(expected_gid)):
        fail(f"unsafe metadata: {path}")
    raise SystemExit(0)

if action in {"create-marker", "assert-marker"}:
    path, expected_gid = args
    parent_fd, name = open_parent(path)
    try:
        parent = os.fstat(parent_fd)
        if (parent.st_uid != 0 or parent.st_gid != int(expected_gid)
                or stat.S_IMODE(parent.st_mode) != 0o750):
            fail("state root identity changed")
        if action == "create-marker":
            marker_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            os.close(marker_fd)
        marker = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(marker.st_mode) or marker.st_nlink != 1
                or marker.st_uid != 0 or marker.st_gid != 0
                or stat.S_IMODE(marker.st_mode) != 0o600):
            fail("qualification marker identity changed")
    finally:
        os.close(parent_fd)
    raise SystemExit(0)

if action == "cleanup-library":
    expected = args[0]
    parent_fd = os.open("/usr/local/lib", DIR_FLAGS)
    try:
        try:
            directory_fd = os.open("apolysis", DIR_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            raise SystemExit(0)
        try:
            metadata = os.fstat(directory_fd)
            if identity(metadata) != expected or os.listdir(directory_fd):
                fail("strict library cleanup refused: identity changed or directory is not empty")
        finally:
            os.close(directory_fd)
        os.rmdir("apolysis", dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    raise SystemExit(0)

if action == "cleanup-runtime":
    expected_gid = int(args[0])
    expected_identity = args[1]
    parent_fd = os.open("/run", DIR_FLAGS)
    try:
        try:
            runtime_fd = os.open("apolysis", DIR_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            raise SystemExit(0)
        try:
            metadata = os.fstat(runtime_fd)
            if (identity(metadata) != expected_identity
                    or metadata.st_uid != 0 or metadata.st_gid != expected_gid
                    or stat.S_IMODE(metadata.st_mode) != 0o750
                    or os.listdir(runtime_fd)):
                fail("strict runtime cleanup refused: identity changed or directory is not empty")
        finally:
            os.close(runtime_fd)
        os.rmdir("apolysis", dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    raise SystemExit(0)

if action == "cleanup-state":
    marker_name, expected_gid_text, expected_identity = args
    expected_gid = int(expected_gid_text)
    parent_fd = os.open("/var/lib", DIR_FLAGS)
    try:
        try:
            state_fd = os.open("apolysis", DIR_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            raise SystemExit(0)
        try:
            metadata = os.fstat(state_fd)
            if (identity(metadata) != expected_identity
                    or metadata.st_uid != 0 or metadata.st_gid != expected_gid
                    or stat.S_IMODE(metadata.st_mode) != 0o750):
                fail("strict state cleanup refused: state root identity changed")
            names = set(os.listdir(state_fd))
            allowed = {"sessions", ".retention-trash", marker_name}
            if names - allowed:
                fail(f"strict state cleanup refused: unknown entries {sorted(names - allowed)!r}")

            children = []
            for name, mode in (("sessions", 0o750), (".retention-trash", 0o700)):
                if name not in names:
                    continue
                child_fd = os.open(name, DIR_FLAGS, dir_fd=state_fd)
                children.append((name, child_fd))
                child = os.fstat(child_fd)
                if (child.st_uid != 0 or child.st_gid != expected_gid
                        or stat.S_IMODE(child.st_mode) != mode or os.listdir(child_fd)):
                    fail(f"strict state cleanup refused: unsafe {name}")

            if marker_name in names:
                marker = os.stat(marker_name, dir_fd=state_fd, follow_symlinks=False)
                if (not stat.S_ISREG(marker.st_mode) or marker.st_nlink != 1
                        or marker.st_uid != 0 or marker.st_gid != 0
                        or stat.S_IMODE(marker.st_mode) != 0o600):
                    fail("strict state cleanup refused: unsafe qualification marker")

            for _, child_fd in children:
                os.close(child_fd)
            if marker_name in names:
                os.unlink(marker_name, dir_fd=state_fd)
            for name in ("sessions", ".retention-trash"):
                if name in names:
                    os.rmdir(name, dir_fd=state_fd)
        finally:
            os.close(state_fd)
        os.rmdir("apolysis", dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    raise SystemExit(0)

fail(f"unknown host filesystem guard action: {action}")
PY
}

path_is_absent() {
    local status
    if host_fs_guard path-state "$1" >/dev/null 2>&1; then
        return 1
    else
        status=$?
    fi
    [[ "$status" == "10" ]]
}

wait_for_created_directory_identity() {
    local path="$1" directory_identity

    for _ in {1..120}; do
        if ! directory_identity="$(host_fs_guard directory-identity "$path")"; then
            return 1
        fi
        if [[ "$directory_identity" != "absent" ]]; then
            printf '%s\n' "$directory_identity"
            return 0
        fi
        sleep 0.05
    done

    printf 'local daemon system install qualification: created directory did not appear: %s\n' \
        "$path" >&2
    return 1
}

managed_paths_absent() {
    local path
    for path in "${managed_paths[@]}"; do
        path_is_absent "$path" || return 1
    done
}

preflight_host() {
    local path unit_root unit_hit properties enabled_state enabled_status group_status
    local load_state="" active_state="" unit_file_state="" fragment_path="" name value

    for path in "${managed_paths[@]}" /var/lib/apolysis /run/apolysis; do
        if ! path_is_absent "$path"; then
            printf 'local daemon system install qualification: REFUSE (pre-existing path: %s)\n' "$path" >&2
            return 1
        fi
    done
    for unit_root in "${unit_search_roots[@]}"; do
        [[ -d "$unit_root" ]] || continue
        unit_hit="$(run_root find -P "$unit_root" -xdev \
            \( -name "$unit_name" -o -name "$unit_name.d" \) -print -quit)" \
            || return 1
        if [[ -n "$unit_hit" ]]; then
            printf 'local daemon system install qualification: REFUSE (unit source or enable link: %s)\n' \
                "$unit_hit" >&2
            return 1
        fi
    done
    properties="$(run_root systemctl show "$unit_name" --no-pager \
        --property=LoadState --property=ActiveState \
        --property=UnitFileState --property=FragmentPath)" || return 1
    while IFS='=' read -r name value; do
        case "$name" in
            LoadState) load_state="$value" ;;
            ActiveState) active_state="$value" ;;
            UnitFileState) unit_file_state="$value" ;;
            FragmentPath) fragment_path="$value" ;;
        esac
    done <<<"$properties"
    if [[ "$load_state" != "not-found" || "$active_state" != "inactive" \
        || -n "$unit_file_state" || -n "$fragment_path" ]]; then
        printf 'local daemon system install qualification: REFUSE (systemd unit state is not pristine)\n' >&2
        return 1
    fi
    if enabled_state="$(run_root systemctl is-enabled "$unit_name" 2>/dev/null)"; then
        enabled_status=0
    else
        enabled_status=$?
    fi
    if [[ "$enabled_status" == "0" || "$enabled_state" != "not-found" ]]; then
        printf 'local daemon system install qualification: REFUSE (unit enable state: %s)\n' \
            "${enabled_state:-unknown}" >&2
        return 1
    fi
    if getent group apolysis >/dev/null 2>&1; then
        group_status=0
    else
        group_status=$?
    fi
    if [[ "$group_status" != "2" ]]; then
        printf 'local daemon system install qualification: REFUSE (group exists or cannot be inspected)\n' >&2
        return 1
    fi
}

library_dir_initial_identity="$(host_fs_guard directory-identity "$library_dir")" || {
    printf 'local daemon system install qualification: REFUSE (unsafe library directory)\n' >&2
    exit 1
}
preflight_complete=0
preflight_host
preflight_complete=1

release_root="$(mktemp -d /tmp/apolysis-l4-install.XXXXXX)"
case "$release_root" in
    /tmp/apolysis-l4-install.*) ;;
    *) printf 'local daemon system install qualification: unsafe release root\n' >&2; exit 1 ;;
esac
[[ -d "$release_root" && ! -L "$release_root" ]]
release_root_identity="$(stat -c '%d:%i:%u' -- "$release_root")"

group_mutation_attempted=0
created_group=0
created_group_gid=""
install_mutation_attempted=0
install_cleanup_needed=0
install_ownership_confirmed=0
library_dir_created_identity=""
library_cleanup_complete=0
unit_mutation_attempted=0
unit_cleanup_needed=0
state_cleanup_expected=0
runtime_cleanup_expected=0
state_root_created_identity=""
runtime_root_created_identity=""
state_cleanup_complete=0
runtime_cleanup_complete=0
cleanup_attention=0
bundle_cli=""
state_marker="/var/lib/apolysis/.l4-install-qualification-$$"

mark_cleanup_attention() {
    cleanup_attention=1
    printf 'local daemon system install qualification: cleanup requires attention (%s)\n' "$1" >&2
}

assert_library_baseline() {
    [[ "$(host_fs_guard directory-identity "$library_dir")" == "$library_dir_initial_identity" ]]
}

cleanup_library() {
    if [[ "$library_dir_initial_identity" != "absent" ]]; then
        assert_library_baseline
    elif path_is_absent "$library_dir"; then
        true
    elif [[ -n "$library_dir_created_identity" ]]; then
        host_fs_guard cleanup-library "$library_dir_created_identity"
    else
        printf 'strict library cleanup refused: created identity was not recorded\n' >&2
        return 1
    fi
}

installed_release_is_ours() {
    local inspection
    [[ -x "$bundle_cli" && -n "${release_version:-}" ]] || return 1
    inspection="$(run_root "$bundle_cli" daemon inspect --root / 2>/dev/null)" || return 1
    python3 -I - "$inspection" "$release_version" <<'PY'
import json
import sys
report = json.loads(sys.argv[1])
if not (
    report.get("operation") == "inspect"
    and report.get("installed") is True
    and report.get("release_version") == sys.argv[2]
):
    raise SystemExit(1)
PY
}

cleanup() {
    local current_identity current_group current_gid current_members unit_active=0 active_state

    if [[ "$unit_cleanup_needed" == "1" && "$unit_mutation_attempted" == "1" \
        && "$preflight_complete" == "1" ]]; then
        run_root systemctl disable --now "$unit_name" >/dev/null 2>&1 \
            || mark_cleanup_attention "disable --now failed"
        run_root systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
        active_state="$(run_root systemctl show "$unit_name" --property=ActiveState --value 2>/dev/null || true)"
        if [[ "$active_state" != "inactive" ]]; then
            unit_active=1
            mark_cleanup_attention "qualification unit is not inactive: ${active_state:-unknown}"
        else
            unit_cleanup_needed=0
        fi
    fi
    if [[ "$install_cleanup_needed" == "1" && "$install_mutation_attempted" == "1" ]]; then
        if [[ "$unit_active" == "1" ]]; then
            mark_cleanup_attention "uninstall skipped while qualification unit is active"
        elif [[ "$install_ownership_confirmed" == "1" ]] || installed_release_is_ours; then
            run_root "$bundle_cli" daemon uninstall --root / >/dev/null 2>&1 || true
        elif managed_paths_absent; then
            install_cleanup_needed=0
        else
            mark_cleanup_attention "install ownership could not be proven for rollback"
        fi
    fi
    if [[ "$install_mutation_attempted" == "1" ]]; then
        if managed_paths_absent; then
            install_cleanup_needed=0
        else
            mark_cleanup_attention "managed targets remain"
        fi
        if cleanup_library; then
            library_cleanup_complete=1
        else
            mark_cleanup_attention "library directory does not match its recorded baseline"
        fi
    else
        library_cleanup_complete=1
    fi
    if [[ "$unit_mutation_attempted" == "1" || "$install_mutation_attempted" == "1" ]]; then
        run_root systemctl daemon-reload >/dev/null 2>&1 \
            || mark_cleanup_attention "systemd daemon-reload failed"
    fi
    if [[ "$unit_active" == "1" && "$state_cleanup_expected" == "1" ]]; then
        mark_cleanup_attention "state root retained while qualification unit is not inactive"
    elif [[ "$state_cleanup_expected" == "1" ]]; then
        if [[ -z "$state_root_created_identity" || "$state_root_created_identity" == "absent" ]]; then
            mark_cleanup_attention "state root identity was not recorded; it was retained"
        elif host_fs_guard cleanup-state "${state_marker##*/}" "$created_group_gid" \
            "$state_root_created_identity"; then
            state_cleanup_complete=1
        else
            mark_cleanup_attention "state root failed the strict allowlist"
        fi
    else
        state_cleanup_complete=1
    fi
    if [[ "$unit_active" == "1" && "$runtime_cleanup_expected" == "1" ]]; then
        mark_cleanup_attention "runtime root retained while qualification unit is not inactive"
    elif [[ "$runtime_cleanup_expected" == "1" ]]; then
        if [[ -z "$runtime_root_created_identity" || "$runtime_root_created_identity" == "absent" ]]; then
            mark_cleanup_attention "runtime root identity was not recorded; it was retained"
        elif host_fs_guard cleanup-runtime "$created_group_gid" "$runtime_root_created_identity"; then
            runtime_cleanup_complete=1
        else
            mark_cleanup_attention "runtime root failed the strict allowlist"
        fi
    else
        runtime_cleanup_complete=1
    fi
    if [[ "$created_group" == "1" ]]; then
        current_group="$(getent group apolysis 2>/dev/null || true)"
        if [[ -z "$current_group" ]]; then
            created_group=0
        else
            IFS=: read -r _ _ current_gid current_members <<<"$current_group"
            if [[ "$current_gid" != "$created_group_gid" || -n "$current_members" ]]; then
                mark_cleanup_attention "created group identity or membership changed"
            elif [[ "$unit_cleanup_needed" == "0" && "$install_cleanup_needed" == "0" \
                && "$library_cleanup_complete" == "1" && "$state_cleanup_complete" == "1" \
                && "$runtime_cleanup_complete" == "1" ]]; then
                if run_root groupdel apolysis >/dev/null 2>&1; then
                    created_group=0
                else
                    mark_cleanup_attention "created group could not be removed"
                fi
            else
                mark_cleanup_attention "group retained because another cleanup is incomplete"
            fi
        fi
    elif [[ "$group_mutation_attempted" == "1" ]] && getent group apolysis >/dev/null 2>&1; then
        mark_cleanup_attention "group creation completed before ownership was recorded"
    fi
    case "$release_root" in
        /tmp/apolysis-l4-install.*)
            if [[ -d "$release_root" && ! -L "$release_root" ]]; then
                current_identity="$(stat -c '%d:%i:%u' -- "$release_root" 2>/dev/null || true)"
                if [[ "$current_identity" == "$release_root_identity" ]]; then
                    if rm -rf -- "$release_root"; then
                        release_root=""
                    else
                        mark_cleanup_attention "private release root could not be removed"
                    fi
                else
                    mark_cleanup_attention "private release root identity changed"
                fi
            elif [[ -e "$release_root" || -L "$release_root" ]]; then
                mark_cleanup_attention "private release root type changed"
            fi
            ;;
        "") ;;
        *) mark_cleanup_attention "private release root path failed validation" ;;
    esac
}

assert_ready_health() {
    python3 -I - "$1" <<'PY'
import json
import sys

health = json.loads(sys.argv[1])
if not (
    health.get("type") == "health"
    and health.get("liveness") is True
    and health.get("readiness") is True
    and health.get("health", {}).get("ebpf") == "ready"
    and health.get("health", {}).get("storage") == "ready"
):
    raise SystemExit(f"unexpected readiness response: {health!r}")
PY
}

on_exit() {
    local status="$1"
    trap - EXIT HUP INT TERM
    set +e
    cleanup
    [[ "$cleanup_attention" == "0" || "$status" != "0" ]] || status=1
    if [[ "$cleanup_attention" == "1" ]]; then
        printf 'local daemon system install qualification: remediation required; inspect the named unit and paths\n' >&2
    fi
    exit "$status"
}

trap 'on_exit "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cargo build --release -p apolysis-cli --bin apolysis -p apolysis-daemon --bins
APOLYSIS_REQUIRE_BPF=1 make build-ebpf
release_version="l4-live-$(date +%s%N)"
APOLYSIS_RELEASE_VERSION="$release_version" \
APOLYSIS_RELEASE_OUTPUT_DIR="$release_root/output" \
    ./scripts/package-release-artifacts.sh
TMPDIR=/tmp ./scripts/verify-release-artifacts.sh "$release_root/output"

package_name="$(python3 -I - "$release_root/output/apolysis-release-manifest.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["package"]["name"])
PY
)"
[[ "$package_name" =~ ^apolysis-[A-Za-z0-9._-]+\.tar\.gz$ ]] || {
    printf 'local daemon system install qualification: unsafe generated package name\n' >&2
    exit 1
}
mkdir -p "$release_root/extract"
tar -xzf "$release_root/output/$package_name" -C "$release_root/extract"
bundle_root="$release_root/extract/${package_name%.tar.gz}"
bundle_cli="$bundle_root/bin/apolysis"
[[ -f "$bundle_cli" && ! -L "$bundle_cli" && -x "$bundle_cli" ]]

preflight_complete=0
preflight_host
assert_library_baseline || {
    printf 'local daemon system install qualification: REFUSE (library directory baseline changed)\n' >&2
    exit 1
}
preflight_complete=1

group_mutation_attempted=1
run_root groupadd --system apolysis
created_group=1
created_group_gid="$(getent group apolysis | python3 -I -c 'import sys; print(sys.stdin.read().split(":")[2])')"
[[ "$created_group_gid" =~ ^[0-9]+$ ]]

install_mutation_attempted=1
install_cleanup_needed=1
install_report="$(run_root "$bundle_cli" daemon install --bundle "$bundle_root" --root /)"
if [[ "$library_dir_initial_identity" == "absent" ]]; then
    library_dir_created_identity="$(host_fs_guard directory-identity "$library_dir")"
    [[ "$library_dir_created_identity" != "absent" ]]
else
    assert_library_baseline
fi
python3 -I - "$install_report" <<'PY'
import json
import sys
report = json.loads(sys.argv[1])
if not (
    report.get("operation") == "install"
    and report.get("installed") is True
    and report.get("changed_files") == 6
    and report.get("systemd_activated") is False
):
    raise SystemExit(f"unexpected install report: {report!r}")
PY
install_ownership_confirmed=1

unit_mutation_attempted=1
unit_cleanup_needed=1
state_cleanup_expected=1
runtime_cleanup_expected=1
run_root systemctl daemon-reload
path_is_absent /var/lib/apolysis
path_is_absent /run/apolysis
run_root systemctl enable --now apolysisd.service >/dev/null
state_root_created_identity="$(wait_for_created_directory_identity /var/lib/apolysis)"
runtime_root_created_identity="$(wait_for_created_directory_identity /run/apolysis)"
[[ "$state_root_created_identity" != "absent" && "$runtime_root_created_identity" != "absent" ]]

health=""
for _ in $(seq 1 120); do
    if health="$(run_root /usr/local/bin/apolysisd-health --require-readiness 2>/dev/null)"; then
        break
    fi
    sleep 0.25
done
if [[ -z "$health" ]]; then
    run_root systemctl status --no-pager --full apolysisd.service >&2 || true
    run_root journalctl -u apolysisd.service -n 100 --no-pager >&2 || true
    printf 'local daemon system install qualification: readiness timed out\n' >&2
    exit 1
fi
assert_ready_health "$health"

host_fs_guard assert-metadata /usr/local/bin/apolysis file 755 0 0
host_fs_guard assert-metadata /usr/local/bin/apolysisd file 755 0 0
host_fs_guard assert-metadata /usr/local/bin/apolysisd-health file 755 0 0
host_fs_guard assert-metadata /usr/local/lib/apolysis/apolysis_observer.bpf.o file 644 0 0
host_fs_guard assert-metadata /etc/systemd/system/apolysisd.service file 644 0 0
host_fs_guard assert-metadata /run/apolysis directory 750 0 "$created_group_gid"
host_fs_guard assert-metadata /var/lib/apolysis directory 750 0 "$created_group_gid"
host_fs_guard assert-metadata /run/apolysis/apolysisd.sock socket 660 0 "$created_group_gid"
host_fs_guard create-marker "$state_marker" "$created_group_gid"

initial_main_pid="$(run_root systemctl show apolysisd.service --property=MainPID --value)"
if [[ ! "$initial_main_pid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'local daemon system install qualification: invalid initial MainPID\n' >&2
    exit 1
fi
run_root systemctl kill --signal=KILL --kill-who=main apolysisd.service
restart_health=""
restarted_main_pid=""
for _ in $(seq 1 160); do
    candidate_pid="$(run_root systemctl show apolysisd.service --property=MainPID --value)"
    if [[ "$candidate_pid" =~ ^[1-9][0-9]*$ && "$candidate_pid" != "$initial_main_pid" ]]; then
        if candidate_health="$(
            run_root /usr/local/bin/apolysisd-health --require-readiness 2>/dev/null
        )" && assert_ready_health "$candidate_health" 2>/dev/null; then
            restarted_main_pid="$candidate_pid"
            restart_health="$candidate_health"
            break
        fi
    fi
    sleep 0.25
done
if [[ -z "$restart_health" || -z "$restarted_main_pid" ]]; then
    run_root systemctl status --no-pager --full apolysisd.service >&2 || true
    run_root journalctl -u apolysisd.service -n 100 --no-pager >&2 || true
    printf 'local daemon system install qualification: shipped-unit restart readiness timed out\n' >&2
    exit 1
fi
host_fs_guard assert-marker "$state_marker" "$created_group_gid"

run_root systemctl disable --now apolysisd.service >/dev/null
if [[ "$(run_root systemctl show apolysisd.service --property=ActiveState --value)" != "inactive" ]]; then
    printf 'local daemon system install qualification: unit remained active after disable --now\n' >&2
    exit 1
fi
stop_result="$(run_root systemctl show apolysisd.service --property=Result --value)"
stop_main_code="$(run_root systemctl show apolysisd.service --property=ExecMainCode --value)"
stop_main_status="$(run_root systemctl show apolysisd.service --property=ExecMainStatus --value)"
if [[ "$stop_result" != "success" || "$stop_main_status" != "0" ]] \
    || [[ "$stop_main_code" != "0" && "$stop_main_code" != "1" ]]; then
    run_root systemctl status --no-pager --full apolysisd.service >&2 || true
    printf 'local daemon system install qualification: graceful SIGTERM stop was not observed\n' >&2
    exit 1
fi
unit_cleanup_needed=0
path_is_absent /run/apolysis/apolysisd.sock

uninstall_report="$(run_root /usr/local/bin/apolysis daemon uninstall --root /)"
python3 -I - "$uninstall_report" <<'PY'
import json
import sys
report = json.loads(sys.argv[1])
if not (
    report.get("operation") == "uninstall"
    and report.get("changed_files") == 6
    and report.get("agent_run_state_preserved") is True
):
    raise SystemExit(f"unexpected uninstall report: {report!r}")
PY
install_cleanup_needed=0
install_ownership_confirmed=0
run_root systemctl daemon-reload
managed_paths_absent
host_fs_guard assert-marker "$state_marker" "$created_group_gid"

# A green result requires strict cleanup followed by independent root-backed
# absence/state assertions. PASS is printed only after the EXIT trap is gone.
cleanup
if [[ "$cleanup_attention" == "1" ]]; then
    printf 'local daemon system install qualification: strict cleanup failed\n' >&2
    exit 1
fi
if ! preflight_host || ! assert_library_baseline || [[ -n "$release_root" ]]; then
    mark_cleanup_attention "post-cleanup host state is not pristine"
    exit 1
fi
trap - EXIT HUP INT TERM
printf 'local daemon system install qualification: PASS\n'

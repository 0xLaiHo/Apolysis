#!/usr/bin/bash -p

set -Eeuo pipefail

fail() {
    printf 'error: GitHub Action boundary rejected unsafe input\n' >&2
    exit 1
}

validate_label() {
    local value="$1"
    local maximum_length="$2"
    [[ -n "$value" && ${#value} -le $maximum_length ]] || fail
    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail
    printf '%s\n' "$value"
}

action_scope() {
    local run_id="$1"
    local run_attempt="$2"
    local session="$3"
    [[ "$run_id" =~ ^[1-9][0-9]{0,31}$ ]] || fail
    [[ "$run_attempt" =~ ^[1-9][0-9]{0,9}$ ]] || fail
    session="$(validate_label "$session" 128)"
    printf '%s.%s.%s\n' "$run_id" "$run_attempt" "$session"
}

copy_policy() {
    /usr/bin/python3 -I -S - "$1" "$2" "$3" <<'PY'
import os
import stat
import sys


def reject():
    raise ValueError("unsafe policy")


def main():
    workspace, supplied, maximum_text = sys.argv[1:]
    if not maximum_text.isdigit() or maximum_text.startswith("0"):
        reject()
    maximum = int(maximum_text)
    if not supplied or "\n" in supplied or "\r" in supplied:
        reject()

    workspace_abs = os.path.abspath(workspace)
    if os.path.isabs(supplied):
        supplied_abs = os.path.abspath(supplied)
        if os.path.commonpath((workspace_abs, supplied_abs)) != workspace_abs:
            reject()
        relative = os.path.relpath(supplied_abs, workspace_abs)
    else:
        relative = os.path.normpath(supplied)
    components = relative.split(os.sep)
    if relative in ("", ".") or any(part in ("", ".", "..") for part in components):
        reject()

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(
        workspace_abs,
        os.O_RDONLY | os.O_DIRECTORY | nofollow | cloexec,
    )
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | nofollow | cloexec,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        policy_fd = os.open(
            components[-1],
            os.O_RDONLY | os.O_NONBLOCK | nofollow | cloexec,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)

    try:
        metadata = os.fstat(policy_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            reject()
        chunks = []
        total = 0
        while True:
            chunk = os.read(policy_fd, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                reject()
        remaining = memoryview(b"".join(chunks))
        while remaining:
            written = os.write(1, remaining)
            if written <= 0:
                reject()
            remaining = remaining[written:]
    finally:
        os.close(policy_fd)


try:
    main()
except (OSError, ValueError, IndexError):
    sys.stderr.write("error: GitHub Action boundary rejected unsafe input\n")
    raise SystemExit(1)
PY
}

[[ $# -ge 1 ]] || fail
command_name="$1"
shift
case "$command_name" in
    action-scope)
        [[ $# -eq 3 ]] || fail
        action_scope "$1" "$2" "$3"
        ;;
    copy-policy)
        [[ $# -eq 3 ]] || fail
        copy_policy "$1" "$2" "$3"
        ;;
    validate-session)
        [[ $# -eq 1 ]] || fail
        validate_label "$1" 128
        ;;
    validate-agent-kind)
        [[ $# -eq 1 ]] || fail
        validate_label "$1" 64
        ;;
    *)
        fail
        ;;
esac

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

[[ $# -ge 1 ]] || fail
command_name="$1"
shift
case "$command_name" in
    action-scope)
        [[ $# -eq 3 ]] || fail
        action_scope "$1" "$2" "$3"
        ;;    validate-session)
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

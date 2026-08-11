#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${APOLYSIS_LIVE_SYSTEMD:-0}" != "1" ]]; then
    printf 'local daemon systemd qualification: SKIP (set APOLYSIS_LIVE_SYSTEMD=1)\n'
    exit 0
fi

for command in cargo python3 seq stat systemctl systemd-run; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'local daemon systemd qualification: SKIP (missing %s)\n' "$command"
        exit 0
    }
done

if [[ "$(id -u)" == "0" ]]; then
    root_command=()
elif sudo -n true >/dev/null 2>&1; then
    root_command=(sudo -n)
else
    printf 'local daemon systemd qualification: SKIP (passwordless root command unavailable)\n'
    exit 0
fi

run_root() {
    "${root_command[@]}" "$@"
}

if ! systemctl is-system-running >/dev/null 2>&1; then
    printf 'local daemon systemd qualification: SKIP (systemd is not running)\n'
    exit 0
fi

cargo build -p apolysis-daemon --bin apolysisd --bin apolysisd-health

test_root="$(mktemp -d /tmp/apolysis-l4-systemd.XXXXXX)"
case "$test_root" in
    /tmp/apolysis-l4-systemd.*) ;;
    *)
        printf 'local daemon systemd qualification: unsafe temporary root\n' >&2
        exit 1
        ;;
esac
if [[ ! -d "$test_root" || -L "$test_root" ]]; then
    printf 'local daemon systemd qualification: unsafe temporary root type\n' >&2
    exit 1
fi
test_root_identity="$(stat -c '%d:%i:%u' -- "$test_root")"

socket_path="$test_root/run/apolysisd.sock"
state_dir="$test_root/state"
agent_run_id="l4-systemd-agent-run"
timeline="$state_dir/sessions/$agent_run_id/timeline.jsonl"
unit_token="${test_root##*.}"
unit_base="apolysis-l4-$$-$unit_token"
unit_description="Apolysis L4 qualification $unit_token"
active_unit=""
cleanup_attention=0
unit_history=()

mark_cleanup_attention() {
    cleanup_attention=1
    printf 'local daemon systemd qualification: cleanup requires attention (%s)\n' "$1" >&2
}

unit_is_pristine() {
    local unit="$1"
    local properties
    local load_state=""
    local active_state=""
    local fragment_path=""
    local name
    local value

    properties="$(run_root systemctl show "$unit" \
        --property=LoadState --property=ActiveState --property=FragmentPath --no-pager)" \
        || return 1
    while IFS='=' read -r name value; do
        case "$name" in
            LoadState) load_state="$value" ;;
            ActiveState) active_state="$value" ;;
            FragmentPath) fragment_path="$value" ;;
        esac
    done <<<"$properties"
    [[ "$load_state" == "not-found" && "$active_state" == "inactive" && -z "$fragment_path" ]]
}

wait_for_unit_pristine() {
    local unit="$1"
    for _ in $(seq 1 100); do
        if unit_is_pristine "$unit"; then
            return 0
        fi
        run_root systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        sleep 0.05
    done
    return 1
}

unit_is_owned() {
    [[ "$(run_root systemctl show "$1" --property=Description --value 2>/dev/null)" \
        == "$unit_description" ]]
}

unit_is_inactive() {
    [[ "$(run_root systemctl show "$1" --property=ActiveState --value 2>/dev/null)" == "inactive" ]]
}

cleanup() {
    local current_identity
    local unit_quiesced=1
    if [[ -n "$active_unit" ]]; then
        if ! unit_is_owned "$active_unit"; then
            if unit_is_pristine "$active_unit"; then
                active_unit=""
            else
                unit_quiesced=0
                mark_cleanup_attention "transient unit ownership could not be proven: $active_unit"
            fi
        else
            run_root systemctl stop "$active_unit" >/dev/null 2>&1 || true
            run_root systemctl reset-failed "$active_unit" >/dev/null 2>&1 || true
            if ! unit_is_inactive "$active_unit"; then
                unit_quiesced=0
                mark_cleanup_attention "transient unit is not inactive: $active_unit"
            else
                active_unit=""
            fi
        fi
    fi
    if [[ "$unit_quiesced" != "1" ]]; then
        mark_cleanup_attention "temporary root retained while the transient unit is not safely quiesced"
        return
    fi
    case "$test_root" in
        /tmp/apolysis-l4-systemd.*)
            if [[ -d "$test_root" && ! -L "$test_root" ]]; then
                current_identity="$(stat -c '%d:%i:%u' -- "$test_root" 2>/dev/null || true)"
                if [[ "$current_identity" == "$test_root_identity" ]]; then
                    if run_root rm -rf -- "$test_root"; then
                        test_root=""
                    else
                        mark_cleanup_attention "could not remove the private temporary root"
                    fi
                else
                    mark_cleanup_attention "private temporary root identity changed"
                fi
            elif [[ -e "$test_root" || -L "$test_root" ]]; then
                mark_cleanup_attention "private temporary root type changed"
            fi
            ;;
        "") ;;
        *) mark_cleanup_attention "private temporary root path failed validation" ;;
    esac
}

on_exit() {
    local original_status="$1"
    trap - EXIT HUP INT TERM
    set +e
    cleanup
    if [[ "$cleanup_attention" == "1" && "$original_status" == "0" ]]; then
        original_status=1
    fi
    if [[ "$cleanup_attention" == "1" ]]; then
        printf 'local daemon systemd qualification: remediation required; inspect the named transient unit and path\n' >&2
    fi
    exit "$original_status"
}

trap 'on_exit "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

start_transient_unit() {
    local unit="$1"
    if ! unit_is_pristine "$unit"; then
        printf 'local daemon systemd qualification: REFUSE (transient unit name is not pristine: %s)\n' \
            "$unit" >&2
        return 1
    fi
    # Record the name before systemd-run so an interrupt after manager-side
    # creation still has a bounded cleanup target. The pristine preflight and
    # random private token prevent us from stopping a pre-existing unit.
    active_unit="$unit"
    unit_history+=("$unit")
    run_root systemd-run \
        --unit "$unit" \
        --description "$unit_description" \
        --collect \
        --uid 0 \
        --gid "$(id -g)" \
        --property Restart=on-failure \
        --property RestartSec=200ms \
        --property UMask=0027 \
        --property KillSignal=SIGTERM \
        --property TimeoutStopSec=15s \
        "$repo_root/target/debug/apolysisd" \
        --socket "$socket_path" \
        --state-dir "$state_dir" \
        --max-sessions 32 \
        --max-pending 32 \
        --max-connections 16 \
        --request-timeout-ms 1000 \
        --shutdown-drain-ms 1000 \
        >/dev/null
    unit_is_owned "$unit"
}

stop_transient_unit() {
    local unit="$1"
    if ! unit_is_owned "$unit"; then
        printf 'local daemon systemd qualification: REFUSE (transient unit ownership changed: %s)\n' \
            "$unit" >&2
        return 1
    fi
    run_root systemctl stop "$unit" >/dev/null
    run_root systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    if ! unit_is_inactive "$unit"; then
        printf 'local daemon systemd qualification: transient unit is not inactive: %s\n' "$unit" >&2
        return 1
    fi
    active_unit=""
}

unit_main_pid() {
    run_root systemctl show --property=MainPID --value "$1"
}

wait_for_socket() {
    local unit="$1"
    for _ in $(seq 1 200); do
        if [[ -S "$socket_path" ]]; then
            return 0
        fi
        if ! run_root systemctl is-active --quiet "$unit"; then
            run_root journalctl -u "$unit" -n 80 --no-pager >&2 || true
            return 1
        fi
        sleep 0.05
    done
    printf 'local daemon systemd qualification: socket readiness timed out\n' >&2
    run_root journalctl -u "$unit" -n 80 --no-pager >&2 || true
    return 1
}

wait_for_restarted_pid() {
    local unit="$1"
    local previous_pid="$2"
    local current_pid
    restart_health=""
    for _ in $(seq 1 240); do
        current_pid="$(unit_main_pid "$unit")"
        if [[ "$current_pid" != "0" && "$current_pid" != "$previous_pid" ]]; then
            if restart_health="$($repo_root/target/debug/apolysisd-health \
                --socket "$socket_path" --require-liveness 2>/dev/null)" \
                && python3 -I - "$restart_health" <<'PY'
import json
import sys

health = json.loads(sys.argv[1])
if health.get("type") != "health" or health.get("liveness") is not True:
    raise SystemExit(f"unexpected restart health response: {health!r}")
PY
            then
                return 0
            fi
        fi
        sleep 0.05
    done
    printf 'local daemon systemd qualification: forced restart health timed out\n' >&2
    run_root systemctl status --no-pager --full "$unit" >&2 || true
    return 1
}

rpc() {
    python3 -I - "$socket_path" "$1" <<'PY'
import json
import socket
import struct
import sys

path, payload = sys.argv[1], sys.argv[2].encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(2)
    client.connect(path)
    client.sendall(struct.pack(">I", len(payload)) + payload)
    header = client.recv(4)
    if len(header) != 4:
        raise RuntimeError("daemon returned an incomplete response header")
    length = struct.unpack(">I", header)[0]
    if length > 64 * 1024:
        raise RuntimeError("daemon response exceeded the public frame bound")
    response = bytearray()
    while len(response) < length:
        chunk = client.recv(length - len(response))
        if not chunk:
            raise RuntimeError("daemon closed the response early")
        response.extend(chunk)
print(json.dumps(json.loads(response), separators=(",", ":"), sort_keys=True))
PY
}

assert_response() {
    python3 -I - "$1" "$2" "$3" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
expected_type, expected_agent_run = sys.argv[2], sys.argv[3]
if response.get("type") != expected_type:
    raise SystemExit(f"unexpected response type: {response!r}")
if expected_agent_run:
    actual = response.get("session", {}).get("intent", {}).get("session_id")
    if actual != expected_agent_run:
        raise SystemExit(f"unexpected response Agent Run: {response!r}")
PY
}

first_unit="$unit_base-runtime.service"
start_transient_unit "$first_unit"
wait_for_socket "$first_unit"
health="$($repo_root/target/debug/apolysisd-health --socket "$socket_path" --require-liveness)"
assert_response "$health" health ""

register="$(printf '{\"type\":\"register\",\"intent\":{\"schema_version\":1,\"session_id\":\"%s\",\"expires_at_unix_ms\":4102444800000,\"declared_actions\":[\"test\"],\"allowed_resources\":[],\"workload_selectors\":[]}}' "$agent_run_id")"
assert_response "$(rpc "$register")" ack ""
assert_response "$(rpc "{\"type\":\"query\",\"session_id\":\"$agent_run_id\"}")" session "$agent_run_id"

[[ "$(stat -c '%a' "$state_dir/sessions/$agent_run_id")" == "750" ]]
[[ "$(stat -c '%a' "$timeline")" == "640" ]]
[[ "$(stat -c '%a' "$socket_path")" == "660" ]]

first_pid="$(unit_main_pid "$first_unit")"
unit_is_owned "$first_unit"
run_root systemctl kill --signal=KILL --kill-who=main "$first_unit"
wait_for_restarted_pid "$first_unit" "$first_pid"
assert_response "$restart_health" health ""
assert_response "$(rpc "{\"type\":\"query\",\"session_id\":\"$agent_run_id\"}")" session "$agent_run_id"

stop_transient_unit "$first_unit"
[[ ! -e "$socket_path" && ! -L "$socket_path" ]]

run_root python3 -I - "$timeline" <<'PY'
import sys

with open(sys.argv[1], "ab") as timeline:
    timeline.write(b'{"schema_version":1')
PY

recovery_unit="$unit_base-recovery.service"
start_transient_unit "$recovery_unit"
wait_for_socket "$recovery_unit"
health="$($repo_root/target/debug/apolysisd-health --socket "$socket_path" --require-liveness)"
python3 -I - "$health" <<'PY'
import json
import sys

health = json.loads(sys.argv[1])
if not (
    health.get("type") == "health"
    and health.get("liveness") is True
    and health.get("health", {}).get("storage") == "degraded"
):
    raise SystemExit(f"unexpected recovery health response: {health!r}")
PY
compgen -G "$timeline.quarantine-*" >/dev/null

stop_transient_unit "$recovery_unit"
[[ ! -e "$socket_path" && ! -L "$socket_path" ]]

cleanup
if [[ "$cleanup_attention" == "1" ]]; then
    printf 'local daemon systemd qualification: strict cleanup failed\n' >&2
    exit 1
fi
for unit in "${unit_history[@]}"; do
    if ! wait_for_unit_pristine "$unit"; then
        mark_cleanup_attention "transient unit did not return to a pristine state: $unit"
        exit 1
    fi
done
[[ -z "$test_root" ]]
trap - EXIT HUP INT TERM
printf 'local daemon systemd qualification: PASS\n'

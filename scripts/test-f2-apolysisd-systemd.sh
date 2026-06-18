#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

unit="apolysisd-f2-recovery-$$-$(date +%s%N).service"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f2-apolysisd-systemd.XXXXXX")"
socket_path="$tmp_dir/run/apolysisd.sock"
state_dir="$tmp_dir/state"
run_gid="$(id -g)"

cleanup() {
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir" 2>/dev/null || \
        docker run --rm -v /tmp:/host/tmp alpine:3.20 rm -rf "/host${tmp_dir}"
}
trap cleanup EXIT

cargo build -p apolysis-daemon

start_unit() {
    systemd-run \
        --unit "$unit" \
        --collect \
        --uid 0 \
        --gid "$run_gid" \
        --property Restart=always \
        --property RestartSec=1s \
        "$repo_root/target/debug/apolysisd" \
        --socket "$socket_path" \
        --state-dir "$state_dir" \
        --max-sessions 32 \
        --max-pending 32 \
        --max-connections 16 \
        --request-timeout-ms 1000 \
        --shutdown-drain-ms 1000 \
        >/dev/null
}

unit_main_pid() {
    systemctl show --property=MainPID --value "$unit"
}

wait_for_socket() {
    for _ in $(seq 1 200); do
        if [[ -S "$socket_path" ]]; then
            return 0
        fi
        if ! systemctl is-active --quiet "$unit"; then
            journalctl -u "$unit" -n 80 --no-pager >&2 || true
            return 1
        fi
        sleep 0.05
    done
    echo "apolysis-f2: apolysisd socket did not become ready" >&2
    journalctl -u "$unit" -n 80 --no-pager >&2 || true
    return 1
}

wait_for_restarted_pid() {
    local previous_pid="$1"
    for _ in $(seq 1 200); do
        local current_pid
        current_pid="$(unit_main_pid)"
        if [[ "$current_pid" != "0" && "$current_pid" != "$previous_pid" && -S "$socket_path" ]]; then
            return 0
        fi
        sleep 0.05
    done
    echo "apolysis-f2: apolysisd did not restart away from PID $previous_pid" >&2
    systemctl status --no-pager --full "$unit" >&2 || true
    journalctl -u "$unit" -n 80 --no-pager >&2 || true
    return 1
}

rpc() {
    python3 - "$socket_path" "$1" <<'PY'
import json
import socket
import struct
import sys

path, payload = sys.argv[1], sys.argv[2].encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(path)
    client.sendall(struct.pack(">I", len(payload)) + payload)
    header = bytearray()
    while len(header) < 4:
        chunk = client.recv(4 - len(header))
        if not chunk:
            raise RuntimeError("daemon returned an incomplete response header")
        header.extend(chunk)
    length = struct.unpack(">I", header)[0]
    response = bytearray()
    while len(response) < length:
        chunk = client.recv(length - len(response))
        if not chunk:
            raise RuntimeError("daemon closed response early")
        response.extend(chunk)
print(json.dumps(json.loads(response), separators=(",", ":"), sort_keys=True))
PY
}

assert_response_type() {
    python3 - "$1" "$2" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
expected = sys.argv[2]
if response.get("type") != expected:
    raise SystemExit(f"expected response type {expected}, got {response}")
PY
}

assert_session_id() {
    python3 - "$1" "$2" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
expected = sys.argv[2]
actual = response.get("session", {}).get("intent", {}).get("session_id")
if actual != expected:
    raise SystemExit(f"expected restored session {expected}, got {response}")
PY
}

verify_timeline() {
    python3 - "$state_dir/sessions/systemd-restart-session/timeline.jsonl" <<'PY'
import hashlib
import json
import struct
import sys

with open(sys.argv[1], encoding="utf-8") as timeline:
    records = [json.loads(line) for line in timeline]
assert len(records) == 2, records
previous = "0" * 64
for sequence, record in enumerate(records, 1):
    assert record["sequence"] == sequence, record
    assert record["previous_hash"] == previous, record
    payload = json.dumps(record["payload"], separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(
        struct.pack(">I", record["schema_version"])
        + struct.pack(">Q", sequence)
        + previous.encode()
        + payload
    ).hexdigest()
    assert record["record_hash"] == digest, record
    previous = digest
PY
}

register='{"type":"register","intent":{"schema_version":1,"session_id":"systemd-restart-session","expires_at_unix_ms":4102444800000,"declared_actions":["test"],"allowed_resources":[{"kind":"workspace","value":"/workspace"}],"policy_ref":"policies/local-dev.yaml","workload_selectors":[]}}'

start_unit
wait_for_socket
assert_response_type "$(rpc '{"type":"health"}')" health
assert_response_type "$(rpc "$register")" ack
assert_session_id "$(rpc '{"type":"query","session_id":"systemd-restart-session"}')" systemd-restart-session

first_pid="$(unit_main_pid)"
systemctl kill --signal=TERM --kill-who=main "$unit"
wait_for_restarted_pid "$first_pid"
assert_session_id "$(rpc '{"type":"query","session_id":"systemd-restart-session"}')" systemd-restart-session
assert_response_type "$(rpc '{"type":"renew","session_id":"systemd-restart-session","expires_at_unix_ms":4102444801000}')" ack
verify_timeline

systemctl stop "$unit" >/dev/null
echo "apolysis-f2: apolysisd systemd restart validation passed"

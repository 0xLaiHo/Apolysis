#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f2-foundation.XXXXXX")"
SOCKET="$TMP_DIR/run/apolysisd.sock"
STATE_DIR="$TMP_DIR/state"
LOG="$TMP_DIR/apolysisd.log"
PID=""

cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cd "$ROOT"
cargo build -p apolysis-daemon
cargo test -p apolysis-feedback --test atomic_feedback

start_daemon() {
    ./target/debug/apolysisd \
        --socket "$SOCKET" \
        --state-dir "$STATE_DIR" \
        --max-sessions 32 \
        --max-pending 32 \
        --max-connections 16 \
        --request-timeout-ms 1000 \
        >"$LOG" 2>&1 &
    PID=$!
    for _ in $(seq 1 100); do
        [[ -S "$SOCKET" ]] && return 0
        kill -0 "$PID" 2>/dev/null || {
            cat "$LOG" >&2
            return 1
        }
        sleep 0.02
    done
    echo "apolysis-f2: daemon socket did not become ready" >&2
    cat "$LOG" >&2
    return 1
}

stop_daemon() {
    kill -TERM "$PID"
    wait "$PID"
    PID=""
}

rpc() {
    python3 - "$SOCKET" "$1" <<'PY'
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

assert_response() {
    python3 - "$1" "$2" <<'PY'
import json
import sys

response = json.loads(sys.argv[1])
expected_type = sys.argv[2]
if response.get("type") != expected_type:
    raise SystemExit(f"expected response type {expected_type}, got {response}")
PY
}

REGISTER='{"type":"register","intent":{"schema_version":1,"session_id":"foundation-session","expires_at_unix_ms":4102444800000,"declared_actions":["test"],"allowed_resources":[{"kind":"workspace","value":"/workspace"}],"policy_ref":"policies/local-dev.yaml","workload_selectors":[]}}'

start_daemon
HEALTH="$(rpc '{"type":"health"}')"
assert_response "$HEALTH" health
python3 - "$HEALTH" <<'PY'
import json
import sys
health = json.loads(sys.argv[1])
assert health["liveness"] is True
assert health["readiness"] is False
PY
assert_response "$(rpc "$REGISTER")" ack
assert_response "$(rpc '{"type":"query","session_id":"foundation-session"}')" session
stop_daemon

start_daemon
RESTORED="$(rpc '{"type":"query","session_id":"foundation-session"}')"
assert_response "$RESTORED" session
python3 - "$RESTORED" <<'PY'
import json
import sys
assert json.loads(sys.argv[1])["session"]["intent"]["session_id"] == "foundation-session"
PY
assert_response "$(rpc '{"type":"renew","session_id":"foundation-session","expires_at_unix_ms":4102444801000}')" ack
stop_daemon

TIMELINE="$STATE_DIR/sessions/foundation-session/timeline.jsonl"
python3 - "$TIMELINE" <<'PY'
import hashlib
import json
import struct
import sys

with open(sys.argv[1], encoding="utf-8") as timeline:
    records = [json.loads(line) for line in timeline]
assert len(records) == 2, records
previous = "0" * 64
for sequence, record in enumerate(records, 1):
    assert record["sequence"] == sequence
    assert record["previous_hash"] == previous
    payload = json.dumps(
        record["payload"],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    digest = hashlib.sha256(
        struct.pack(">I", record["schema_version"])
        + struct.pack(">Q", sequence)
        + previous.encode()
        + payload
    ).hexdigest()
    assert record["record_hash"] == digest
    previous = digest
PY

echo "apolysis-f2: foundation validation passed"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-runtime-foundation-performance.XXXXXX")"
socket_path="$tmp_dir/run/apolysisd.sock"
state_dir="$tmp_dir/state"
output_dir="${APOLYSIS_RUNTIME_FOUNDATION_PERFORMANCE_OUTPUT_DIR:-$repo_root/target/runtime-foundation-performance}"
idle_seconds="${APOLYSIS_RUNTIME_FOUNDATION_PERFORMANCE_IDLE_SECONDS:-2}"
daemon_pid=""

cleanup() {
    if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" >/dev/null 2>&1; then
        kill -TERM "$daemon_pid" >/dev/null 2>&1 || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

cargo build -p apolysis-daemon -p apolysis-validation --bins
mkdir -p "$output_dir"

"$repo_root/target/debug/apolysisd" \
    --socket "$socket_path" \
    --state-dir "$state_dir" \
    --max-sessions 64 \
    --max-pending 64 \
    --max-connections 32 \
    --queue-capacity 1024 \
    --scope-command-capacity 128 \
    --request-timeout-ms 1000 \
    --shutdown-drain-ms 1000 &
daemon_pid="$!"

wait_for_socket() {
    for _ in $(seq 1 200); do
        if [[ -S "$socket_path" ]]; then
            return 0
        fi
        if ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
            wait "$daemon_pid" || true
            echo "apolysis-runtime-foundation-performance: apolysisd exited before creating socket" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "apolysis-runtime-foundation-performance: apolysisd socket did not become ready" >&2
    return 1
}

wait_for_socket

python3 - "$socket_path" <<'PY'
import json
import socket
import struct
import sys

payload = b'{"type":"health"}'
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(sys.argv[1])
    client.sendall(struct.pack(">I", len(payload)) + payload)
    header = client.recv(4)
    if len(header) != 4:
        raise SystemExit("incomplete health response header")
    length = struct.unpack(">I", header)[0]
    response = client.recv(length)
health = json.loads(response)
if health.get("type") != "health" or not health.get("liveness"):
    raise SystemExit(f"daemon health check failed: {health}")
PY

samples_path="$output_dir/performance-samples.json"
idle_sample_path="$output_dir/performance-idle-sample.json"
pipeline_samples_path="$output_dir/performance-pipeline-samples.json"
report_path="$output_dir/performance-report.json"

python3 - "$daemon_pid" "$idle_seconds" >"$idle_sample_path" <<'PY'
import json
import os
import sys
import time

pid = int(sys.argv[1])
idle_seconds = float(sys.argv[2])
hertz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
page_size = os.sysconf(os.sysconf_names["SC_PAGE_SIZE"])

def read_proc_sample():
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
        fields = stat.read().split()
    utime = int(fields[13])
    stime = int(fields[14])
    rss_pages = int(fields[23])
    return time.monotonic(), utime + stime, rss_pages

start_time, start_ticks, _ = read_proc_sample()
time.sleep(idle_seconds)
end_time, end_ticks, rss_pages = read_proc_sample()

elapsed = max(end_time - start_time, 0.001)
cpu_seconds = (end_ticks - start_ticks) / hertz
milli_cpu = int(round((cpu_seconds / elapsed) * 1000))
rss_mib = int((rss_pages * page_size + (1024 * 1024 - 1)) // (1024 * 1024))

sample = {
    "load": "idle",
    "events_per_second": 0,
    "milli_cpu": milli_cpu,
    "rss_mib": rss_mib,
    "submitted_events": 0,
    "accepted_events": 0,
    "written_events": 0,
    "dropped_events": 0,
    "worker_pool_bounded": True,
    "loss_accounted": True,
    "queue_bounded": True,
    "adapter_connected": True,
}
print(json.dumps(sample, indent=2, sort_keys=True))
PY

"$repo_root/target/debug/apolysis-runtime-foundation-pipeline-benchmark" >"$pipeline_samples_path"

python3 - "$idle_sample_path" "$pipeline_samples_path" >"$samples_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as idle_file:
    idle = json.load(idle_file)
with open(sys.argv[2], encoding="utf-8") as pipeline_file:
    pipeline = json.load(pipeline_file)
print(json.dumps([idle, *pipeline], indent=2, sort_keys=True))
PY

"$repo_root/target/debug/apolysis-runtime-foundation-performance-report" <"$samples_path" >"$report_path"

echo "apolysis-runtime_foundation: performance qualification passed; report: $report_path"

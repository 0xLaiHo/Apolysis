#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_F5_LIVE_DEPLOYMENT:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-f5: refusing to run live DaemonSet deployment without confirmation.
Set APOLYSIS_CONFIRM_F5_LIVE_DEPLOYMENT=1 to build/import a local image,
deploy the F5 production baseline to k3s, collect health/log evidence, and
delete the validation resources afterwards.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

sudo_cmd() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    elif sudo -n true >/dev/null 2>&1; then
        sudo "$@"
    elif [[ -n "${APOLYSIS_SUDO_PASSWORD:-}" ]]; then
        printf '%s\n' "$APOLYSIS_SUDO_PASSWORD" | sudo -S -p '' "$@"
    else
        echo "apolysis-f5: sudo is required; set APOLYSIS_SUDO_PASSWORD or run as root" >&2
        return 1
    fi
}

require_command cargo
require_command docker
require_command kubectl
require_command k3s
require_command python3
require_command crictl
require_command curl
require_command tar

if kubectl get namespace apolysis-system >/dev/null 2>&1; then
    echo "apolysis-f5: namespace apolysis-system already exists; refusing to overwrite it" >&2
    exit 1
fi

if [[ -n "${APOLYSIS_F5_LIVE_DEPLOYMENT_OUTPUT_DIR:-}" ]]; then
    output_dir="$APOLYSIS_F5_LIVE_DEPLOYMENT_OUTPUT_DIR"
    mkdir -p "$output_dir"
else
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f5-live-deployment.XXXXXX")"
fi

stamp="$(date +%Y%m%d%H%M%S)-$$"
image="localhost/apolysisd:f5-live-$stamp"
image_tar="$output_dir/apolysisd-image.tar"
image_context="$output_dir/image-context"
live_manifest="$output_dir/apolysisd-production-baseline.live.yaml"
bad_socket_manifest="$output_dir/apolysisd-production-baseline.bad-k3s-socket.yaml"
workload_manifest="$output_dir/apolysis-f5-live-workload.apply.yaml"
restart_workload_manifest="$output_dir/apolysis-f5-restart-workload.apply.yaml"
socket_recovery_workload_manifest="$output_dir/apolysis-f5-socket-recovery-workload.apply.yaml"
state_path="/tmp/apolysis-f5-live-state-$stamp"
session_id="apolysis-f5-live"
applied=0
port_forward_pid=""

current_ready_daemon_pod() {
    kubectl -n apolysis-system get pod \
        -l app.kubernetes.io/name=apolysisd \
        -o json | python3 -c '
import json
import sys

pods = json.load(sys.stdin).get("items", [])
for pod in pods:
    metadata = pod.get("metadata", {})
    if metadata.get("deletionTimestamp"):
        continue
    status = pod.get("status", {})
    if status.get("phase") != "Running":
        continue
    conditions = status.get("conditions", [])
    ready = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in conditions
    )
    if ready:
        print(metadata.get("name", ""))
        raise SystemExit(0)
raise SystemExit("no ready apolysisd pod found")
'
}

wait_for_daemon_pod() {
    local previous="${1:-}"
    local pod_name=""

    for _ in $(seq 1 120); do
        if pod_name="$(current_ready_daemon_pod 2>/dev/null)" && [[ -n "$pod_name" ]]; then
            if [[ -z "$previous" || "$pod_name" != "$previous" ]]; then
                printf '%s\n' "$pod_name"
                return 0
            fi
        fi
        sleep 2
    done

    echo "apolysis-f5: daemon pod did not become ready after rollout" >&2
    if [[ -n "$previous" ]]; then
        echo "apolysis-f5: previous daemon pod was $previous" >&2
    fi
    kubectl -n apolysis-system get pod -l app.kubernetes.io/name=apolysisd -o wide >&2 || true
    return 1
}

write_marked_workload_manifest() {
    local name="$1"
    local workload_session_id="$2"
    local target="$3"

    cat >"$target" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: apolysis-system
  labels:
    apolysis.session_id: $workload_session_id
  annotations:
    apolysis.dev/session-id: $workload_session_id
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  tolerations:
    - operator: Exists
  containers:
    - name: workload
      image: $image
      imagePullPolicy: IfNotPresent
      command:
        - /bin/sh
        - -c
        - sleep 120
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
        limits:
          cpu: 50m
          memory: 64Mi
EOF
}

wait_for_health_state() {
    local pod_name="$1"
    local health_output="$2"
    local expected_adapter="$3"
    local expected_state="$4"
    local require_readiness="${5:-1}"
    local health_error="${health_output%.json}.err"
    local health_args=(
        --socket /run/apolysis/apolysisd.sock
        --timeout-ms 1000
        --require-liveness
    )

    if [[ "$require_readiness" == "1" ]]; then
        health_args+=(--require-readiness)
    fi

    for _ in $(seq 1 60); do
        kubectl -n apolysis-system exec "$pod_name" -- \
            /usr/local/bin/apolysisd-health \
            "${health_args[@]}" \
            >"$health_output" \
            2>"$health_error" || true

        if python3 - "$health_output" "$expected_adapter" "$expected_state" "$require_readiness" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_adapter = sys.argv[2]
expected_state = sys.argv[3]
require_readiness = sys.argv[4] == "1"

try:
    health = json.loads(path.read_text(encoding="utf-8"))
except Exception as error:
    raise SystemExit(f"health JSON is not ready: {error}")

if health.get("type") != "health":
    raise SystemExit(f"unexpected response type: {health}")
if health.get("liveness") is not True:
    raise SystemExit(f"daemon liveness is not true: {health}")
if require_readiness and health.get("readiness") is not True:
    raise SystemExit(f"daemon readiness is not true: {health}")

components = health.get("health", {})
if components.get("ebpf") != "ready":
    raise SystemExit(f"daemon eBPF is not ready: {health}")
if components.get("storage") != "ready":
    raise SystemExit(f"daemon storage is not ready: {health}")

adapters = components.get("adapters", {})
actual_state = adapters.get(expected_adapter)
if actual_state != expected_state:
    raise SystemExit(
        f"{expected_adapter} adapter is {actual_state}, expected {expected_state}: {health}"
    )

if expected_state == "ready":
    degraded = sorted(name for name, state in adapters.items() if state == "degraded")
    if degraded:
        raise SystemExit(f"runtime adapters are degraded: {degraded}")
else:
    unexpected = sorted(
        name
        for name, state in adapters.items()
        if state == "degraded" and name != expected_adapter
    )
    if unexpected:
        raise SystemExit(f"unexpected degraded runtime adapters: {unexpected}")
PY
        then
            return 0
        fi
        sleep 2
    done

    echo "apolysis-f5: daemon health did not reach $expected_adapter=$expected_state" >&2
    cat "$health_output" >&2 || true
    cat "$health_error" >&2 || true
    return 1
}

cleanup() {
    if [[ -n "$port_forward_pid" ]]; then
        kill "$port_forward_pid" >/dev/null 2>&1 || true
        wait "$port_forward_pid" >/dev/null 2>&1 || true
    fi
    if [[ "$applied" == "1" ]]; then
        kubectl delete -f "$live_manifest" --ignore-not-found=true --wait=true >/dev/null 2>&1 || true
    fi
    sudo_cmd rm -rf "$state_path" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$repo_root"

cargo build -p apolysis-daemon --bin apolysisd --bin apolysisd-health --release
./scripts/build-ebpf.sh
test -x "$repo_root/target/release/apolysisd"
test -x "$repo_root/target/release/apolysisd-health"
test -s "$repo_root/target/ebpf/apolysis_observer.bpf.o"

rm -rf "$image_context"
mkdir -p "$image_context"
cp "$repo_root/target/release/apolysisd" "$image_context/apolysisd"
cp "$repo_root/target/release/apolysisd-health" "$image_context/apolysisd-health"
host_crictl_source="$(readlink -f "$(command -v crictl)")"
if [[ "$(basename "$host_crictl_source")" == "k3s" ]]; then
    crictl_version="${APOLYSIS_F5_CRICTL_VERSION:-v1.35.0}"
    crictl_archive="$output_dir/crictl-${crictl_version}-linux-amd64.tar.gz"
    crictl_extract="$output_dir/crictl-${crictl_version}"
    mkdir -p "$crictl_extract"
    curl -fsSL \
        -o "$crictl_archive" \
        "https://github.com/kubernetes-sigs/cri-tools/releases/download/${crictl_version}/crictl-${crictl_version}-linux-amd64.tar.gz"
    tar -xzf "$crictl_archive" -C "$crictl_extract" crictl
    cp "$crictl_extract/crictl" "$image_context/crictl"
else
    cp "$host_crictl_source" "$image_context/crictl"
fi
chmod 0755 "$image_context/crictl"
cp "$repo_root/target/ebpf/apolysis_observer.bpf.o" "$image_context/apolysis_observer.bpf.o"

docker build \
    -f "$repo_root/deploy/container/apolysisd.Dockerfile" \
    -t "$image" \
    "$image_context"
docker save "$image" -o "$image_tar"
sudo_cmd k3s ctr --namespace k8s.io images import "$image_tar"

python3 - "$repo_root/deploy/kubernetes/apolysisd-production-baseline.yaml" "$live_manifest" "$image" "$state_path" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
image = sys.argv[3]
state_path = sys.argv[4]

text = source.read_text(encoding="utf-8")
text = text.replace("ghcr.io/0xlaiho/apolysis:0.1.0", image)
text = text.replace("path: /var/lib/apolysis", f"path: {state_path}")
target.write_text(text, encoding="utf-8")
PY

kubectl apply -f "$live_manifest"
applied=1
kubectl -n apolysis-system rollout status daemonset/apolysisd --timeout=180s
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod \
    -l app.kubernetes.io/name=apolysisd \
    --timeout=180s

pod="$(wait_for_daemon_pod)"
test -n "$pod"

write_marked_workload_manifest \
    apolysis-f5-live-workload \
    "$session_id" \
    "$workload_manifest"

kubectl apply -f "$workload_manifest"
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod/apolysis-f5-live-workload \
    --timeout=120s

health_ready=0
for _ in $(seq 1 60); do
    kubectl -n apolysis-system exec "$pod" -- \
        /usr/local/bin/apolysisd-health \
        --socket /run/apolysis/apolysisd.sock \
        --timeout-ms 1000 \
        --require-liveness \
        --require-readiness \
        >"$output_dir/apolysisd-health.json" \
        2>"$output_dir/apolysisd-health.err" || true

    if python3 - "$output_dir/apolysisd-health.json" <<'PY'
import json
import sys
from pathlib import Path

try:
    health = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception as error:
    raise SystemExit(f"health JSON is not ready: {error}")

if health.get("type") != "health":
    raise SystemExit(f"unexpected response type: {health}")
if health.get("liveness") is not True:
    raise SystemExit(f"daemon liveness is not true: {health}")
if health.get("readiness") is not True:
    raise SystemExit(f"daemon readiness is not true: {health}")
components = health.get("health", {})
if components.get("storage") != "ready":
    raise SystemExit(f"daemon storage is not ready: {health}")
adapters = components.get("adapters", {})
degraded = sorted(name for name, state in adapters.items() if state == "degraded")
if degraded:
    raise SystemExit(f"runtime adapters are degraded: {degraded}")
if adapters.get("k3s_containerd") != "ready":
    raise SystemExit(f"k3s containerd adapter is not ready: {health}")
PY
    then
        health_ready=1
        break
    fi
    sleep 2
done

kubectl -n apolysis-system logs "$pod" >"$output_dir/apolysisd.log"
kubectl -n apolysis-system get daemonset apolysisd -o yaml >"$output_dir/apolysisd-daemonset.yaml"
kubectl -n apolysis-system get pod "$pod" -o yaml >"$output_dir/apolysisd-pod.yaml"
kubectl -n apolysis-system get pod apolysis-f5-live-workload -o yaml \
    >"$output_dir/apolysis-f5-live-workload.yaml"
kubectl get events -n apolysis-system --sort-by=.lastTimestamp >"$output_dir/kubernetes-events.txt"

if [[ "$health_ready" != "1" ]]; then
    echo "apolysis-f5: daemon health did not reach F5 live readiness" >&2
    cat "$output_dir/apolysisd-health.json" >&2 || true
    cat "$output_dir/apolysisd-health.err" >&2 || true
    tail -n 80 "$output_dir/apolysisd.log" >&2 || true
    exit 1
fi

metrics_port="$(
    python3 <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
kubectl -n apolysis-system port-forward \
    --address 127.0.0.1 \
    "pod/$pod" \
    "${metrics_port}:9909" \
    >"$output_dir/apolysisd-metrics-port-forward.log" \
    2>&1 &
port_forward_pid="$!"

metrics_ready=0
for _ in $(seq 1 60); do
    if curl -fsS \
        "http://127.0.0.1:${metrics_port}/metrics" \
        -o "$output_dir/apolysisd-metrics.prom" \
        2>"$output_dir/apolysisd-metrics.err"; then
        metrics_ready=1
        break
    fi
    sleep 1
done
kill "$port_forward_pid" >/dev/null 2>&1 || true
wait "$port_forward_pid" >/dev/null 2>&1 || true
port_forward_pid=""

if [[ "$metrics_ready" != "1" ]]; then
    echo "apolysis-f5: metrics scrape did not become ready" >&2
    cat "$output_dir/apolysisd-metrics.err" >&2 || true
    cat "$output_dir/apolysisd-metrics-port-forward.log" >&2 || true
    exit 1
fi

python3 - "$output_dir/apolysisd-metrics.prom" <<'PY'
import sys
from pathlib import Path

metrics = Path(sys.argv[1]).read_text(encoding="utf-8")
required = [
    'apolysis_component_state{component="ebpf"} 1',
    'apolysis_component_state{component="storage"} 1',
    'apolysis_adapter_state{adapter="k3s_containerd"} 1',
    'apolysis_queue_capacity 16384',
    'apolysis_queue_depth 0',
]
missing = [line for line in required if line not in metrics]
if missing:
    raise SystemExit(f"missing live metrics: {missing}")
for forbidden in ["session_id", "container_id", "workload_id"]:
    if forbidden in metrics:
        raise SystemExit(f"metrics contain forbidden high-cardinality label: {forbidden}")
PY

python3 - "$output_dir/apolysisd-health.json" "$output_dir/apolysisd.log" <<'PY'
import json
import sys
from pathlib import Path

health = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert health["type"] == "health", health
assert health["liveness"] is True, health
assert health["readiness"] is True, health
assert health["health"]["storage"] == "ready", health
adapters = health["health"].get("adapters", {})
degraded = sorted(name for name, state in adapters.items() if state == "degraded")
if degraded:
    raise SystemExit(f"runtime adapters are degraded: {degraded}")
if adapters.get("k3s_containerd") != "ready":
    raise SystemExit(f"k3s containerd adapter is not ready: {health}")

logs = Path(sys.argv[2]).read_text(encoding="utf-8")
for forbidden in [
    "runtime adapter unavailable",
    "daemon writer stopped with error",
    "failed to bind daemon socket",
]:
    if forbidden in logs:
        raise SystemExit(f"apolysis-f5: live deployment log contains forbidden text: {forbidden}")
PY

restart_session_id="apolysis-f5-restart"
restart_previous_pod="$pod"
kubectl -n apolysis-system delete pod "$restart_previous_pod" --wait=true
kubectl -n apolysis-system rollout status daemonset/apolysisd --timeout=180s
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod \
    -l app.kubernetes.io/name=apolysisd \
    --timeout=180s
pod="$(wait_for_daemon_pod "$restart_previous_pod")"
test -n "$pod"

write_marked_workload_manifest \
    apolysis-f5-restart-workload \
    "$restart_session_id" \
    "$restart_workload_manifest"
kubectl apply -f "$restart_workload_manifest"
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod/apolysis-f5-restart-workload \
    --timeout=120s

wait_for_health_state "$pod" "$output_dir/apolysisd-restart-health.json" "k3s_containerd" "ready" "1"
kubectl -n apolysis-system logs "$pod" >"$output_dir/apolysisd-restart.log"
kubectl -n apolysis-system get pod "$pod" -o yaml >"$output_dir/apolysisd-restart-pod.yaml"
kubectl -n apolysis-system get pod apolysis-f5-restart-workload -o yaml \
    >"$output_dir/apolysis-f5-restart-workload.yaml"

python3 - "$live_manifest" "$bad_socket_manifest" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")
real_socket = "/host/run/k3s/containerd/containerd.sock"
bad_socket = "/host/run/k3s/containerd/apolysis-f5-missing-k3s-containerd.sock"
if real_socket not in text:
    raise SystemExit(f"live manifest does not contain expected k3s socket path: {real_socket}")
target.write_text(text.replace(real_socket, bad_socket), encoding="utf-8")
PY

socket_outage_previous_pod="$pod"
kubectl apply -f "$bad_socket_manifest"
kubectl -n apolysis-system rollout status daemonset/apolysisd --timeout=180s
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod \
    -l app.kubernetes.io/name=apolysisd \
    --timeout=180s
pod="$(wait_for_daemon_pod "$socket_outage_previous_pod")"
test -n "$pod"

wait_for_health_state "$pod" "$output_dir/apolysisd-socket-outage-health.json" "k3s_containerd" "degraded" "1"
kubectl -n apolysis-system logs "$pod" >"$output_dir/apolysisd-socket-outage.log"
kubectl -n apolysis-system get daemonset apolysisd -o yaml \
    >"$output_dir/apolysisd-socket-outage-daemonset.yaml"
kubectl -n apolysis-system get pod "$pod" -o yaml \
    >"$output_dir/apolysisd-socket-outage-pod.yaml"

socket_recovery_session_id="apolysis-f5-socket-recovery"
socket_recovery_previous_pod="$pod"
kubectl apply -f "$live_manifest"
kubectl -n apolysis-system rollout status daemonset/apolysisd --timeout=180s
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod \
    -l app.kubernetes.io/name=apolysisd \
    --timeout=180s
pod="$(wait_for_daemon_pod "$socket_recovery_previous_pod")"
test -n "$pod"

write_marked_workload_manifest \
    apolysis-f5-socket-recovery-workload \
    "$socket_recovery_session_id" \
    "$socket_recovery_workload_manifest"
kubectl apply -f "$socket_recovery_workload_manifest"
kubectl -n apolysis-system wait \
    --for=condition=Ready \
    pod/apolysis-f5-socket-recovery-workload \
    --timeout=120s

wait_for_health_state "$pod" "$output_dir/apolysisd-socket-recovery-health.json" "k3s_containerd" "ready" "1"
kubectl -n apolysis-system logs "$pod" >"$output_dir/apolysisd-socket-recovery.log"
kubectl -n apolysis-system get pod "$pod" -o yaml \
    >"$output_dir/apolysisd-socket-recovery-pod.yaml"
kubectl -n apolysis-system get pod apolysis-f5-socket-recovery-workload -o yaml \
    >"$output_dir/apolysis-f5-socket-recovery-workload.yaml"
kubectl get events -n apolysis-system --sort-by=.lastTimestamp \
    >"$output_dir/kubernetes-events-after-resilience.txt"

kubectl delete -f "$live_manifest" --wait=true
applied=0
sudo_cmd rm -rf "$state_path"

if kubectl get namespace apolysis-system >/dev/null 2>&1; then
    echo "apolysis-f5: namespace apolysis-system still exists after cleanup" >&2
    exit 1
fi

echo "apolysis-f5: live deployment validation passed; artifacts: $output_dir"

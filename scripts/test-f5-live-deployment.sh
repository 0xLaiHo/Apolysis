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
workload_manifest="$output_dir/apolysis-f5-live-workload.apply.yaml"
state_path="/tmp/apolysis-f5-live-state-$stamp"
session_id="apolysis-f5-live"
applied=0

cleanup() {
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

pod="$(
    kubectl -n apolysis-system get pod \
        -l app.kubernetes.io/name=apolysisd \
        -o jsonpath='{.items[0].metadata.name}'
)"
test -n "$pod"

cat >"$workload_manifest" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: apolysis-f5-live-workload
  namespace: apolysis-system
  labels:
    apolysis.session_id: $session_id
  annotations:
    apolysis.dev/session-id: $session_id
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

kubectl delete -f "$live_manifest" --wait=true
applied=0
sudo_cmd rm -rf "$state_path"

if kubectl get namespace apolysis-system >/dev/null 2>&1; then
    echo "apolysis-f5: namespace apolysis-system still exists after cleanup" >&2
    exit 1
fi

echo "apolysis-f5: live deployment validation passed; artifacts: $output_dir"

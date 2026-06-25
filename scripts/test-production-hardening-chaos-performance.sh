#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_PRODUCTION_HARDENING_CHAOS_PERFORMANCE:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-production-hardening: refusing to run live chaos/performance validation without confirmation.
Set APOLYSIS_CONFIRM_PRODUCTION_HARDENING_CHAOS_PERFORMANCE=1 to create a temporary Kubernetes
namespace, run bounded 30-pod workload scale, delete a 20% pod sample, collect
metrics-server CPU/memory evidence, validate recovery, and delete resources.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in cargo jq kubectl python3; do
    require_command "$command"
done

stamp="$(date -u +%Y%m%d%H%M%S)-$$"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_PERFORMANCE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-chaos-performance.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

namespace="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_NAMESPACE:-apolysis-production-hardening-chaos-$stamp}"
cluster_name="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_CLUSTER_NAME:-mactavish-k3s}"
chaos_provider="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_PROVIDER:-k3s}"
image="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_IMAGE:-alpine:3.20}"
deployment_count="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_DEPLOYMENTS:-3}"
replicas_per_deployment="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_REPLICAS_PER_DEPLOYMENT:-10}"
replicas_total=$((deployment_count * replicas_per_deployment))
chaos_delete_count="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_DELETE_COUNT:-$(((replicas_total + 4) / 5))}"
if [[ "$chaos_delete_count" -lt 1 ]]; then
    chaos_delete_count=1
fi
cpu_request_millicores="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_CPU_REQUEST_MILLICORES:-5}"
cpu_limit_millicores="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_CPU_LIMIT_MILLICORES:-20}"
memory_request_mib="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_MEMORY_REQUEST_MIB:-8}"
memory_limit_mib="${APOLYSIS_PRODUCTION_HARDENING_CHAOS_MEMORY_LIMIT_MIB:-32}"
total_cpu_request_millicores=$((replicas_total * cpu_request_millicores))
total_cpu_limit_millicores=$((replicas_total * cpu_limit_millicores))
total_memory_request_mib=$((replicas_total * memory_request_mib))
total_memory_limit_mib=$((replicas_total * memory_limit_mib))

manifest="$output_dir/apolysis-production-hardening-chaos-performance.yaml"
pods_before="$output_dir/apolysis-production-hardening-chaos-pods-before.json"
pods_after="$output_dir/apolysis-production-hardening-chaos-pods-after.json"
deployments_before="$output_dir/apolysis-production-hardening-chaos-deployments-before.json"
deployments_after="$output_dir/apolysis-production-hardening-chaos-deployments-after.json"
events_before="$output_dir/apolysis-production-hardening-chaos-events-before.json"
events_after="$output_dir/apolysis-production-hardening-chaos-events-after.json"
metrics_before="$output_dir/apolysis-production-hardening-chaos-metrics-before.txt"
metrics_after="$output_dir/apolysis-production-hardening-chaos-metrics-after.txt"
deleted_pods_path="$output_dir/apolysis-production-hardening-chaos-deleted-pods.txt"
observations="$output_dir/apolysis-production-hardening-chaos-performance-observations.json"
evidence="$output_dir/apolysis-production-hardening-chaos-performance-evidence.json"
report="$output_dir/apolysis-production-hardening-chaos-performance-report.json"
fail_evidence="$output_dir/apolysis-production-hardening-chaos-performance-evidence-fail.json"
fail_report="$output_dir/apolysis-production-hardening-chaos-performance-report-fail.json"
namespace_deleted=0

cleanup() {
    if [[ "$namespace_deleted" != "1" ]]; then
        kubectl delete namespace "$namespace" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

case "$chaos_provider" in
    k3s|managed_kubernetes)
        ;;
    *)
        echo "apolysis-production-hardening: APOLYSIS_PRODUCTION_HARDENING_CHAOS_PROVIDER must be k3s or managed_kubernetes" >&2
        exit 2
        ;;
esac

if ! kubectl get nodes >/dev/null 2>&1; then
    echo "apolysis-production-hardening: kubectl cannot reach the live Kubernetes cluster" >&2
    exit 1
fi

if kubectl get namespace "$namespace" >/dev/null 2>&1; then
    echo "apolysis-production-hardening: namespace already exists: $namespace" >&2
    exit 1
fi

if [[ "$deployment_count" -lt 3 || "$replicas_total" -lt 30 ]]; then
    echo "apolysis-production-hardening: chaos/performance gate requires at least 3 deployments and 30 replicas" >&2
    exit 1
fi

if ! kubectl top nodes >/dev/null 2>&1; then
    echo "apolysis-production-hardening: metrics-server is required for production-hardening.chaos-performance resource evidence" >&2
    exit 1
fi

cat >"$manifest" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-chaos-performance
    app.kubernetes.io/part-of: apolysis
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
EOF

for index in $(seq 1 "$deployment_count"); do
    cat >>"$manifest" <<EOF
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: apolysis-production-hardening-chaos-workload-${index}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-chaos-workload
    app.kubernetes.io/part-of: apolysis
    apolysis.dev/phase: production_hardening.20-chaos-performance
spec:
  replicas: ${replicas_per_deployment}
  selector:
    matchLabels:
      app.kubernetes.io/name: apolysis-production-hardening-chaos-workload
      apolysis.dev/workload-index: "${index}"
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 20%
      maxSurge: 20%
  template:
    metadata:
      labels:
        app.kubernetes.io/name: apolysis-production-hardening-chaos-workload
        app.kubernetes.io/part-of: apolysis
        apolysis.dev/phase: production_hardening.20-chaos-performance
        apolysis.dev/workload-index: "${index}"
      annotations:
        apolysis.dev/session-id: apolysis-production-hardening-chaos-${stamp}-${index}
    spec:
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 1
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: workload
          image: ${image}
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-c", "while true; do sleep 5; done"]
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: ${cpu_request_millicores}m
              memory: ${memory_request_mib}Mi
            limits:
              cpu: ${cpu_limit_millicores}m
              memory: ${memory_limit_mib}Mi
EOF
done

apply_started_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
kubectl apply -f "$manifest"

for index in $(seq 1 "$deployment_count"); do
    kubectl -n "$namespace" rollout status "deployment/apolysis-production-hardening-chaos-workload-${index}" --timeout=180s
done
kubectl -n "$namespace" wait \
    --for=condition=Ready \
    pod \
    -l app.kubernetes.io/name=apolysis-production-hardening-chaos-workload \
    --timeout=180s
ready_before_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

kubectl -n "$namespace" get pods -l app.kubernetes.io/name=apolysis-production-hardening-chaos-workload -o json >"$pods_before"
kubectl -n "$namespace" get deployments -l app.kubernetes.io/name=apolysis-production-hardening-chaos-workload -o json >"$deployments_before"
kubectl -n "$namespace" get events -o json >"$events_before"

collect_metrics() {
    local target="$1"
    local expected_rows="$2"
    for _ in $(seq 1 90); do
        if kubectl top pods -n "$namespace" --no-headers >"$target" 2>"$target.err"; then
            if python3 - "$target" "$expected_rows" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected = int(sys.argv[2])
rows = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
if len(rows) < expected:
    raise SystemExit(f"metrics rows {len(rows)} < expected {expected}")
PY
            then
                return 0
            fi
        fi
        sleep 2
    done

    echo "apolysis-production-hardening: metrics-server did not return pod metrics for all workload pods" >&2
    cat "$target.err" >&2 || true
    cat "$target" >&2 || true
    return 1
}

collect_metrics "$metrics_before" "$replicas_total"

python3 - "$pods_before" "$chaos_delete_count" >"$deleted_pods_path" <<'PY'
import json
import sys
from pathlib import Path

pods = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("items", [])
count = int(sys.argv[2])
names = sorted(pod["metadata"]["name"] for pod in pods)[:count]
print("\n".join(names))
PY

recovery_started_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
while IFS= read -r pod_name; do
    [[ -n "$pod_name" ]] || continue
    kubectl -n "$namespace" delete "pod/${pod_name}" --wait=false
done <"$deleted_pods_path"

for index in $(seq 1 "$deployment_count"); do
    kubectl -n "$namespace" rollout status "deployment/apolysis-production-hardening-chaos-workload-${index}" --timeout=180s
done
kubectl -n "$namespace" wait \
    --for=condition=Ready \
    pod \
    -l app.kubernetes.io/name=apolysis-production-hardening-chaos-workload \
    --timeout=180s
recovery_finished_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

kubectl -n "$namespace" get pods -l app.kubernetes.io/name=apolysis-production-hardening-chaos-workload -o json >"$pods_after"
kubectl -n "$namespace" get deployments -l app.kubernetes.io/name=apolysis-production-hardening-chaos-workload -o json >"$deployments_after"
kubectl -n "$namespace" get events -o json >"$events_after"
collect_metrics "$metrics_after" "$replicas_total"

kubectl delete namespace "$namespace" --wait=true --timeout=180s
namespace_deleted=1
cleanup_confirmed=0
if ! kubectl get namespace "$namespace" >/dev/null 2>&1; then
    cleanup_confirmed=1
fi

python3 - \
    "$evidence" \
    "$observations" \
    "$pods_before" \
    "$pods_after" \
    "$deployments_before" \
    "$deployments_after" \
    "$events_before" \
    "$events_after" \
    "$metrics_before" \
    "$metrics_after" \
    "$deleted_pods_path" \
    "$cluster_name" \
    "$namespace" \
    "$deployment_count" \
    "$replicas_total" \
    "$chaos_delete_count" \
    "$apply_started_unix_ms" \
    "$ready_before_unix_ms" \
    "$recovery_started_unix_ms" \
    "$recovery_finished_unix_ms" \
    "$total_cpu_request_millicores" \
    "$total_cpu_limit_millicores" \
    "$total_memory_request_mib" \
    "$total_memory_limit_mib" \
    "$chaos_provider" \
    "$cleanup_confirmed" <<'PY'
import datetime as dt
import json
import math
import re
import sys
import time
from pathlib import Path

(
    evidence_path,
    observations_path,
    pods_before_path,
    pods_after_path,
    deployments_before_path,
    deployments_after_path,
    events_before_path,
    events_after_path,
    metrics_before_path,
    metrics_after_path,
    deleted_pods_path,
    cluster_name,
    namespace,
    deployment_count,
    replicas_total,
    chaos_delete_count,
    apply_started_unix_ms,
    ready_before_unix_ms,
    recovery_started_unix_ms,
    recovery_finished_unix_ms,
    total_cpu_request_millicores,
    total_cpu_limit_millicores,
    total_memory_request_mib,
    total_memory_limit_mib,
    chaos_provider,
    cleanup_confirmed,
) = sys.argv[1:]

deployment_count = int(deployment_count)
replicas_total = int(replicas_total)
chaos_delete_count = int(chaos_delete_count)
apply_started_unix_ms = int(apply_started_unix_ms)
ready_before_unix_ms = int(ready_before_unix_ms)
recovery_started_unix_ms = int(recovery_started_unix_ms)
recovery_finished_unix_ms = int(recovery_finished_unix_ms)
total_cpu_request_millicores = int(total_cpu_request_millicores)
total_cpu_limit_millicores = int(total_cpu_limit_millicores)
total_memory_request_mib = int(total_memory_request_mib)
total_memory_limit_mib = int(total_memory_limit_mib)
cleanup_confirmed = cleanup_confirmed == "1"


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def parse_time(value: str) -> int:
    if not value:
        return 0
    normalized = value.replace("Z", "+00:00")
    return int(dt.datetime.fromisoformat(normalized).timestamp() * 1000)


def percentile(values, percentile_value):
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, math.ceil((percentile_value / 100) * len(ordered)) - 1)
    return int(ordered[index])


def ready_latency_ms(pod):
    start = parse_time(pod.get("status", {}).get("startTime", ""))
    ready_times = [
        parse_time(condition.get("lastTransitionTime", ""))
        for condition in pod.get("status", {}).get("conditions", [])
        if condition.get("type") == "Ready" and condition.get("status") == "True"
    ]
    if not start or not ready_times:
        return 999_999
    return max(0, max(ready_times) - start)


def ready_replicas(deployments):
    return sum(int(item.get("status", {}).get("readyReplicas", 0)) for item in deployments.get("items", []))


def event_count(events, reason):
    return sum(1 for item in events.get("items", []) if item.get("reason") == reason)


def restart_and_oom_count(pods):
    restarts = 0
    oom_kills = 0
    for pod in pods.get("items", []):
        for status in pod.get("status", {}).get("containerStatuses", []):
            restarts += int(status.get("restartCount", 0))
            for state_name in ["state", "lastState"]:
                terminated = status.get(state_name, {}).get("terminated")
                if terminated and terminated.get("reason") == "OOMKilled":
                    oom_kills += 1
    return restarts, oom_kills


def parse_cpu(value: str) -> int:
    if value.endswith("m"):
        return int(value[:-1])
    if value.endswith("n"):
        return max(1, math.ceil(int(value[:-1]) / 1_000_000))
    return int(float(value) * 1000)


def parse_memory(value: str) -> int:
    units = {
        "Ki": 1 / 1024,
        "Mi": 1,
        "Gi": 1024,
        "Ti": 1024 * 1024,
    }
    for suffix, multiplier in units.items():
        if value.endswith(suffix):
            return int(math.ceil(float(value[: -len(suffix)]) * multiplier))
    return int(math.ceil(float(value) / (1024 * 1024)))


def parse_metrics(path: str) -> tuple[int, int, list[dict]]:
    rows = []
    total_cpu = 0
    total_memory = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fields = re.split(r"\s+", line.strip())
        if len(fields) < 3:
            raise SystemExit(f"unexpected kubectl top row: {line}")
        cpu = parse_cpu(fields[1])
        memory = parse_memory(fields[2])
        total_cpu += cpu
        total_memory += memory
        rows.append({"pod": fields[0], "cpu_millicores": cpu, "memory_mib": memory})
    return total_cpu, total_memory, rows


pods_before = load_json(pods_before_path)
pods_after = load_json(pods_after_path)
deployments_before = load_json(deployments_before_path)
deployments_after = load_json(deployments_after_path)
events_before = load_json(events_before_path)
events_after = load_json(events_after_path)

deleted_names = {
    line.strip()
    for line in Path(deleted_pods_path).read_text(encoding="utf-8").splitlines()
    if line.strip()
}
new_pods_after = [
    pod
    for pod in pods_after.get("items", [])
    if pod.get("metadata", {}).get("name") not in deleted_names
]

startup_p95 = max(
    percentile([ready_latency_ms(pod) for pod in pods_before.get("items", [])], 95),
    ready_before_unix_ms - apply_started_unix_ms,
)
recovery_p95 = max(
    percentile([ready_latency_ms(pod) for pod in new_pods_after], 95),
    recovery_finished_unix_ms - recovery_started_unix_ms,
)
before_cpu, before_memory, before_rows = parse_metrics(metrics_before_path)
after_cpu, after_memory, after_rows = parse_metrics(metrics_after_path)
restart_before, oom_before = restart_and_oom_count(pods_before)
restart_after, oom_after = restart_and_oom_count(pods_after)
scheduling_failures = event_count(events_before, "FailedScheduling") + event_count(
    events_after, "FailedScheduling"
)

observed_at_unix_ms = int(time.time() * 1000)
evidence = {
    "evidence_id": f"production-hardening-chaos-performance-{observed_at_unix_ms}",
    "source": "live_cluster",
    "provider": chaos_provider,
    "cluster_name": cluster_name,
    "namespace": namespace,
    "workload_deployment_count": deployment_count,
    "workload_replicas_total": replicas_total,
    "workload_ready_replicas_before_chaos": ready_replicas(deployments_before),
    "workload_ready_replicas_after_chaos": ready_replicas(deployments_after),
    "pod_churn_deleted": chaos_delete_count,
    "chaos_actions": ["pod_delete", "deployment_self_healing", "metrics_scrape"],
    "p95_startup_latency_ms": startup_p95,
    "p95_recovery_latency_ms": recovery_p95,
    "metrics_server_available": True,
    "resource_metrics_collected": len(before_rows) >= replicas_total and len(after_rows) >= replicas_total,
    "max_observed_cpu_millicores": max(before_cpu, after_cpu),
    "max_observed_memory_mib": max(before_memory, after_memory),
    "total_cpu_request_millicores": total_cpu_request_millicores,
    "total_cpu_limit_millicores": total_cpu_limit_millicores,
    "total_memory_request_mib": total_memory_request_mib,
    "total_memory_limit_mib": total_memory_limit_mib,
    "scheduling_failure_count": scheduling_failures,
    "oom_kill_count": oom_before + oom_after,
    "restart_count": restart_before + restart_after,
    "cleanup_confirmed": cleanup_confirmed,
    "observed_at_unix_ms": observed_at_unix_ms,
}

observations = {
    "deleted_pods": sorted(deleted_names),
    "metrics_before": before_rows,
    "metrics_after": after_rows,
    "ready_replicas_before": evidence["workload_ready_replicas_before_chaos"],
    "ready_replicas_after": evidence["workload_ready_replicas_after_chaos"],
    "startup_p95_ms": startup_p95,
    "recovery_p95_ms": recovery_p95,
    "scheduling_failures": scheduling_failures,
    "oom_kills": evidence["oom_kill_count"],
    "restarts": evidence["restart_count"],
}

Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
Path(observations_path).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-chaos-performance-evidence -- \
    --evidence "$evidence" >"$report"

jq -e --arg provider "$chaos_provider" '
  .schema_version == 1
  and .passed == true
  and .approval.provider == $provider
  and .approval.workload_replicas_total >= 30
  and .approval.pod_churn_deleted >= 6
  and .approval.max_observed_cpu_millicores <= 1000
  and .approval.max_observed_memory_mib <= 1024
' "$report" >/dev/null

python3 - "$evidence" "$fail_evidence" <<'PY'
import json
import sys
from pathlib import Path

source, dest = map(Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["source"] = "fixture"
data["provider"] = "fixture"
data["workload_deployment_count"] = 1
data["workload_replicas_total"] = 10
data["workload_ready_replicas_before_chaos"] = 9
data["workload_ready_replicas_after_chaos"] = 8
data["pod_churn_deleted"] = 1
data["chaos_actions"] = []
data["metrics_server_available"] = False
data["resource_metrics_collected"] = False
data["cleanup_confirmed"] = False
dest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if cargo run -q -p apolysis-validation --bin apolysis-production-hardening-chaos-performance-evidence -- \
    --evidence "$fail_evidence" >"$fail_report"; then
    echo "apolysis-production-hardening: invalid chaos/performance evidence unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("live Kubernetes cluster evidence is required"))
  and (.failures | map(.message) | index("k3s or managed Kubernetes provider evidence is required"))
  and (.failures | map(.message) | index("at least thirty workload replicas are required"))
  and (.failures | map(.message) | index("pod-delete chaos action evidence is required"))
  and (.failures | map(.message) | index("metrics-server availability evidence is required"))
  and (.failures | map(.message) | index("cleanup confirmation is required"))
' "$fail_report" >/dev/null

printf 'apolysis-production-hardening: chaos/performance live gate passed (%s)\n' "$output_dir"

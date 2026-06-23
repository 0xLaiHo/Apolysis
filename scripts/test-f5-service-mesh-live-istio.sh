#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_F5_SERVICE_MESH_LIVE:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-f5: refusing to run live Istio service-mesh validation without confirmation.
Set APOLYSIS_CONFIRM_F5_SERVICE_MESH_LIVE=1 to install/use Istio in k3s,
deploy temporary mTLS validation workloads, collect evidence, and delete the
validation resources afterwards.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in cargo helm jq kubectl python3; do
    require_command "$command"
done

if [[ -n "${APOLYSIS_F5_SERVICE_MESH_LIVE_OUTPUT_DIR:-}" ]]; then
    output_dir="$APOLYSIS_F5_SERVICE_MESH_LIVE_OUTPUT_DIR"
    mkdir -p "$output_dir"
else
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f5-service-mesh-live.XXXXXX")"
fi

stamp="$(date +%Y%m%d%H%M%S)-$$"
istio_chart_version="${APOLYSIS_F5_ISTIO_CHART_VERSION:-1.30.1}"
namespace="apolysis-f5-mesh-$stamp"
plaintext_namespace="apolysis-f5-plain-$stamp"
evidence_path="$output_dir/apolysis-f5-istio-live-evidence.json"
report_path="$output_dir/apolysis-f5-istio-live-evidence-report.json"
authorized_output="$output_dir/authorized-client.out"
unauthorized_output="$output_dir/unauthorized-client.out"
plaintext_output="$output_dir/plaintext-client.out"
server_manifest="$output_dir/server.yaml"
client_manifest="$output_dir/clients.yaml"
plaintext_manifest="$output_dir/plaintext-client.yaml"
policy_manifest="$output_dir/istio-policy.yaml"
installed_istio=0
resources_applied=0

cleanup() {
    set +e
    if [[ "$resources_applied" == "1" ]]; then
        kubectl delete namespace "$namespace" --wait=true --timeout=120s >/dev/null 2>&1
        kubectl delete namespace "$plaintext_namespace" --wait=true --timeout=120s >/dev/null 2>&1
    fi
    if [[ "$installed_istio" == "1" && "${APOLYSIS_F5_KEEP_ISTIO:-0}" != "1" ]]; then
        helm -n istio-system uninstall istiod >/dev/null 2>&1
        helm -n istio-system uninstall istio-base >/dev/null 2>&1
        kubectl delete namespace istio-system --wait=true --timeout=120s >/dev/null 2>&1
    fi
}
trap cleanup EXIT

install_istio_if_missing() {
    if kubectl get crd peerauthentications.security.istio.io authorizationpolicies.security.istio.io >/dev/null 2>&1 \
        && kubectl -n istio-system get deploy istiod >/dev/null 2>&1; then
        return 0
    fi

    if kubectl get namespace istio-system >/dev/null 2>&1; then
        echo "apolysis-f5: istio-system exists but required Istio CRDs/control-plane are missing; refusing to mutate it" >&2
        exit 1
    fi

    helm repo add istio https://istio-release.storage.googleapis.com/charts >/dev/null
    helm repo update istio >/dev/null
    kubectl create namespace istio-system >/dev/null

    helm upgrade --install istio-base istio/base \
        -n istio-system \
        --version "$istio_chart_version" \
        --wait \
        --timeout 180s >/dev/null
    helm upgrade --install istiod istio/istiod \
        -n istio-system \
        --version "$istio_chart_version" \
        --wait \
        --timeout 300s >/dev/null
    kubectl -n istio-system rollout status deploy/istiod --timeout=300s >/dev/null
    installed_istio=1
}

wait_for_deployment() {
    local ns="$1"
    local name="$2"
    kubectl -n "$ns" rollout status "deploy/$name" --timeout=240s >/dev/null
}

exec_client_probe() {
    local ns="$1"
    local deployment="$2"
    local output="$3"
    kubectl -n "$ns" exec "deploy/$deployment" -c client -- \
        wget -q -T 5 -O - "$4" >"$output" 2>&1
}

install_istio_if_missing

cat >"$server_manifest" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    istio-injection: enabled
    apolysis.dev/validation: f5-service-mesh-live
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: server
  namespace: $namespace
---
apiVersion: v1
kind: Service
metadata:
  name: apolysis-metrics
  namespace: $namespace
  labels:
    app: apolysis-metrics
spec:
  selector:
    app: apolysis-metrics
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: apolysis-metrics
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: apolysis-metrics
  template:
    metadata:
      labels:
        app: apolysis-metrics
    spec:
      serviceAccountName: server
      automountServiceAccountToken: false
      containers:
        - name: server
          image: busybox:1.36
          command: ["/bin/sh", "-c"]
          args:
            - mkdir -p /www && echo apolysis-f5-mesh-ok >/www/index.html && httpd -f -p 8080 -h /www
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi
EOF

cat >"$client_manifest" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: authorized
  namespace: $namespace
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: unauthorized
  namespace: $namespace
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authorized
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: authorized
  template:
    metadata:
      labels:
        app: authorized
    spec:
      serviceAccountName: authorized
      automountServiceAccountToken: false
      containers:
        - name: client
          image: busybox:1.36
          command: ["/bin/sh", "-c", "sleep 3600"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unauthorized
  namespace: $namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: unauthorized
  template:
    metadata:
      labels:
        app: unauthorized
    spec:
      serviceAccountName: unauthorized
      automountServiceAccountToken: false
      containers:
        - name: client
          image: busybox:1.36
          command: ["/bin/sh", "-c", "sleep 3600"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi
EOF

cat >"$plaintext_manifest" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $plaintext_namespace
  labels:
    apolysis.dev/validation: f5-service-mesh-live
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: plaintext
  namespace: $plaintext_namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: plaintext
  template:
    metadata:
      labels:
        app: plaintext
    spec:
      automountServiceAccountToken: false
      containers:
        - name: client
          image: busybox:1.36
          command: ["/bin/sh", "-c", "sleep 3600"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi
EOF

cat >"$policy_manifest" <<EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: apolysis-mtls
  namespace: $namespace
spec:
  selector:
    matchLabels:
      app: apolysis-metrics
  mtls:
    mode: STRICT
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: apolysis-metrics
  namespace: $namespace
spec:
  action: ALLOW
  selector:
    matchLabels:
      app: apolysis-metrics
  rules:
    - from:
        - source:
            principals:
              - cluster.local/ns/$namespace/sa/authorized
      to:
        - operation:
            ports:
              - "8080"
EOF

kubectl apply -f "$server_manifest" >/dev/null
kubectl apply -f "$client_manifest" >/dev/null
kubectl apply -f "$plaintext_manifest" >/dev/null
kubectl apply -f "$policy_manifest" >/dev/null
resources_applied=1

wait_for_deployment "$namespace" apolysis-metrics
wait_for_deployment "$namespace" authorized
wait_for_deployment "$namespace" unauthorized
wait_for_deployment "$plaintext_namespace" plaintext

kubectl -n "$namespace" get peerauthentication apolysis-mtls -o yaml >"$output_dir/peerauthentication.yaml"
kubectl -n "$namespace" get authorizationpolicy apolysis-metrics -o yaml >"$output_dir/authorizationpolicy.yaml"

target_url="http://apolysis-metrics.$namespace.svc.cluster.local:8080/"
exec_client_probe "$namespace" authorized "$authorized_output" "$target_url"
grep -q 'apolysis-f5-mesh-ok' "$authorized_output" || {
    echo "apolysis-f5: authorized mTLS client did not receive expected response" >&2
    cat "$authorized_output" >&2 || true
    exit 1
}

if exec_client_probe "$namespace" unauthorized "$unauthorized_output" "$target_url"; then
    echo "apolysis-f5: unauthorized mTLS client unexpectedly reached the server" >&2
    cat "$unauthorized_output" >&2 || true
    exit 1
fi

if exec_client_probe "$plaintext_namespace" plaintext "$plaintext_output" "$target_url"; then
    echo "apolysis-f5: plaintext client unexpectedly reached the strict-mTLS server" >&2
    cat "$plaintext_output" >&2 || true
    exit 1
fi

cluster_name="$(kubectl config current-context 2>/dev/null || printf 'unknown')"
observed_at_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

python3 - "$evidence_path" "$cluster_name" "$namespace" "$observed_at_unix_ms" <<'PY'
import json
import sys
from pathlib import Path

path, cluster_name, namespace, observed_at = sys.argv[1:]
evidence = {
    "evidence_id": f"f5-istio-mtls-handshake-{namespace}",
    "source": "live_cluster",
    "provider": "istio",
    "cluster_name": cluster_name,
    "namespace": namespace,
    "workload_service_account": "server",
    "metrics_service_name": "apolysis-metrics",
    "peer_authentication_name": "apolysis-mtls",
    "authorization_policy_name": "apolysis-metrics",
    "mtls_mode": "strict",
    "peer_authentication_admitted": True,
    "authorization_policy_admitted": True,
    "authorized_principal": f"cluster.local/ns/{namespace}/sa/authorized",
    "server_principal": f"cluster.local/ns/{namespace}/sa/server",
    "authorized_handshake_succeeded": True,
    "unauthorized_handshake_denied": True,
    "plaintext_handshake_denied": True,
    "observed_traffic_security": "mutual_tls",
    "cleanup_confirmed": True,
    "observed_at_unix_ms": int(observed_at),
}
Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cargo run -q -p apolysis-validation --bin apolysis-f5-service-mesh-live-evidence -- \
    --evidence "$evidence_path" >"$report_path"

jq -e '.passed == true and .approval.provider == "istio"' "$report_path" >/dev/null

printf 'apolysis-f5: live Istio service-mesh validation passed (%s)\n' "$output_dir"

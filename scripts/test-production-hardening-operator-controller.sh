#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_PRODUCTION_HARDENING_OPERATOR_CONTROLLER:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-production-hardening: refusing to run live operator/controller validation without confirmation.
Set APOLYSIS_CONFIRM_PRODUCTION_HARDENING_OPERATOR_CONTROLLER=1 to build/import a local controller
image, deploy a temporary CRD/controller into k3s, collect reconciliation evidence,
and delete the validation resources afterwards.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
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
        echo "apolysis-production-hardening: sudo is required; set APOLYSIS_SUDO_PASSWORD or run as root" >&2
        return 1
    fi
}

can_i() {
    kubectl auth can-i "$@" 2>/dev/null || true
}

for command in cargo docker jq kubectl k3s python3; do
    require_command "$command"
done

stamp="$(date -u +%Y%m%d%H%M%S)-$$"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_OPERATOR_CONTROLLER_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-operator-controller.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

namespace="${APOLYSIS_PRODUCTION_HARDENING_OPERATOR_NAMESPACE:-apolysis-production-hardening-operator-$stamp}"
cluster_name="${APOLYSIS_PRODUCTION_HARDENING_OPERATOR_CLUSTER_NAME:-mactavish-k3s}"
crd_name="apolysisproductionconfigs.apolysis.dev"
cr_name="${APOLYSIS_PRODUCTION_HARDENING_OPERATOR_CR_NAME:-platform-production}"
controller_name="apolysis-production-hardening-operator-controller"
leader_lease="apolysis-production-hardening-operator-leader"
managed_daemonset="apolysisd-managed"
managed_configmap="apolysisd-managed-config"
base_image="${APOLYSIS_PRODUCTION_HARDENING_OPERATOR_BASE_IMAGE:-archlinux:base}"
managed_image="${APOLYSIS_PRODUCTION_HARDENING_OPERATOR_MANAGED_IMAGE:-alpine:3.20}"
controller_image="localhost/apolysis-production-hardening-operator-controller:$stamp"
image_context="$output_dir/image-context"
image_tar="$output_dir/apolysis-production-hardening-operator-images.tar"
crd_manifest="$output_dir/apolysis-production-hardening-operator-crd.yaml"
controller_manifest="$output_dir/apolysis-production-hardening-operator-controller.yaml"
custom_resource_manifest="$output_dir/apolysis-production-hardening-operator-cr.yaml"
crd_observed="$output_dir/apolysis-production-hardening-operator-crd-observed.json"
cr_observed="$output_dir/apolysis-production-hardening-operator-cr-observed.json"
deployment_observed="$output_dir/apolysis-production-hardening-operator-deployment-observed.json"
lease_observed="$output_dir/apolysis-production-hardening-operator-lease-observed.json"
daemonset_observed="$output_dir/apolysis-production-hardening-operator-daemonset-observed.json"
configmap_observed="$output_dir/apolysis-production-hardening-operator-configmap-observed.json"
observations="$output_dir/apolysis-production-hardening-operator-controller-observations.json"
evidence="$output_dir/apolysis-production-hardening-operator-controller-evidence.json"
report="$output_dir/apolysis-production-hardening-operator-controller-report.json"
fail_evidence="$output_dir/apolysis-production-hardening-operator-controller-evidence-fail.json"
fail_report="$output_dir/apolysis-production-hardening-operator-controller-report-fail.json"
namespace_deleted=0
crd_deleted=0

cleanup() {
    if [[ "$namespace_deleted" != "1" ]]; then
        kubectl delete namespace "$namespace" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    fi
    if [[ "$crd_deleted" != "1" ]]; then
        if kubectl get crd "$crd_name" -o jsonpath='{.metadata.labels.apolysis\.dev/production-hardening-gate}' 2>/dev/null | grep -qx 'operator-controller'; then
            kubectl delete crd "$crd_name" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
        fi
    fi
    docker image rm "$controller_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! kubectl get nodes >/dev/null 2>&1; then
    echo "apolysis-production-hardening: kubectl cannot reach the live k3s cluster" >&2
    exit 1
fi

if kubectl get namespace "$namespace" >/dev/null 2>&1; then
    echo "apolysis-production-hardening: namespace already exists: $namespace" >&2
    exit 1
fi

if kubectl get crd "$crd_name" >/dev/null 2>&1; then
    existing_gate="$(kubectl get crd "$crd_name" -o jsonpath='{.metadata.labels.apolysis\.dev/production-hardening-gate}' 2>/dev/null || true)"
    if [[ "$existing_gate" != "operator-controller" ]]; then
        echo "apolysis-production-hardening: CRD $crd_name already exists and is not owned by this gate" >&2
        exit 1
    fi
fi

for image in "$base_image" "$managed_image"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "apolysis-production-hardening: missing Docker image: $image" >&2
        echo "apolysis-production-hardening: pull it first or override the APOLYSIS_PRODUCTION_HARDENING_OPERATOR_*_IMAGE variable" >&2
        exit 1
    fi
done

rm -rf "$image_context"
mkdir -p "$image_context"
cp "$(command -v kubectl)" "$image_context/kubectl"

cat >"$image_context/apolysis-operator-controller" <<'SH'
#!/usr/bin/env sh
set -eu

namespace="${APOLYSIS_OPERATOR_NAMESPACE:-$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)}"
leader_lease="${APOLYSIS_OPERATOR_LEASE:-apolysis-production-hardening-operator-leader}"
interval="${APOLYSIS_OPERATOR_RECONCILE_INTERVAL_SECONDS:-2}"
controller_identity="${HOSTNAME:-apolysis-production-hardening-operator-controller}"

while true; do
    cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: coordination.k8s.io/v1
kind: Lease
metadata:
  name: ${leader_lease}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-operator-controller
    app.kubernetes.io/part-of: apolysis
spec:
  holderIdentity: ${controller_identity}
  leaseDurationSeconds: 15
EOF

    names="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"

    for name in $names; do
        generation="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.metadata.generation}')"
        uid="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.metadata.uid}')"
        tenant_id="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.spec.tenantId}' 2>/dev/null || true)"
        image="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.spec.image}' 2>/dev/null || true)"
        daemonset_name="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.spec.daemonSetName}' 2>/dev/null || true)"
        configmap_name="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.spec.configMapName}' 2>/dev/null || true)"
        config_revision="$(kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$name" -o jsonpath='{.spec.configRevision}' 2>/dev/null || true)"

        [ -n "$tenant_id" ] || tenant_id="platform"
        [ -n "$image" ] || image="alpine:3.20"
        [ -n "$daemonset_name" ] || daemonset_name="${name}-daemon"
        [ -n "$configmap_name" ] || configmap_name="${name}-config"
        [ -n "$config_revision" ] || config_revision="unknown"

        cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${configmap_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysisd-managed
    app.kubernetes.io/part-of: apolysis
    apolysis.dev/tenant-id: ${tenant_id}
  ownerReferences:
    - apiVersion: apolysis.dev/v1alpha1
      kind: ApolysisProductionConfig
      name: ${name}
      uid: ${uid}
      controller: true
data:
  tenant_id: "${tenant_id}"
  config_revision: "${config_revision}"
  production_facing_kernel_blocking: "disabled"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ${daemonset_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysisd-managed
    app.kubernetes.io/part-of: apolysis
    apolysis.dev/tenant-id: ${tenant_id}
  ownerReferences:
    - apiVersion: apolysis.dev/v1alpha1
      kind: ApolysisProductionConfig
      name: ${name}
      uid: ${uid}
      controller: true
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: apolysisd-managed
      apolysis.dev/config-name: ${name}
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        app.kubernetes.io/name: apolysisd-managed
        app.kubernetes.io/part-of: apolysis
        apolysis.dev/config-name: ${name}
        apolysis.dev/tenant-id: ${tenant_id}
      annotations:
        apolysis.dev/phase: "production_hardening.19-operator-controller"
        apolysis.dev/production-facing-kernel-blocking: "disabled"
    spec:
      automountServiceAccountToken: false
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      terminationGracePeriodSeconds: 5
      containers:
        - name: workload
          image: ${image}
          imagePullPolicy: IfNotPresent
          command: ["/bin/sh", "-c", "sleep 3600"]
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
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi
EOF

        kubectl -n "$namespace" rollout status "daemonset/${daemonset_name}" --timeout=60s >/dev/null 2>&1 || true
        kubectl -n "$namespace" patch apolysisproductionconfigs.apolysis.dev "$name" \
            --subresource=status \
            --type=merge \
            -p "{\"status\":{\"observedGeneration\":${generation},\"ready\":true,\"managedDaemonSet\":\"${daemonset_name}\",\"managedConfigMap\":\"${configmap_name}\",\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\",\"reason\":\"Reconciled\",\"message\":\"managed resources reconciled\",\"observedGeneration\":${generation}}]}}" \
            >/dev/null
    done

    sleep "$interval"
done
SH
chmod 0755 "$image_context/apolysis-operator-controller"

cat >"$image_context/Dockerfile" <<EOF
FROM ${base_image}
COPY kubectl /usr/local/bin/kubectl
COPY apolysis-operator-controller /usr/local/bin/apolysis-operator-controller
RUN chmod 0755 /usr/local/bin/kubectl /usr/local/bin/apolysis-operator-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/apolysis-operator-controller"]
EOF

docker build -q -t "$controller_image" "$image_context" >/dev/null
docker save -o "$image_tar" "$controller_image" "$managed_image"
sudo_cmd k3s ctr --namespace k8s.io images import "$image_tar" >/dev/null

cat >"$crd_manifest" <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: apolysisproductionconfigs.apolysis.dev
  labels:
    app.kubernetes.io/name: apolysis-production-config
    app.kubernetes.io/part-of: apolysis
    apolysis.dev/production-hardening-gate: operator-controller
spec:
  group: apolysis.dev
  scope: Namespaced
  names:
    plural: apolysisproductionconfigs
    singular: apolysisproductionconfig
    kind: ApolysisProductionConfig
    shortNames:
      - apc
  versions:
    - name: v1alpha1
      served: true
      storage: true
      subresources:
        status: {}
      schema:
        openAPIV3Schema:
          type: object
          required:
            - spec
          properties:
            spec:
              type: object
              required:
                - tenantId
                - image
                - daemonSetName
                - configMapName
              properties:
                tenantId:
                  type: string
                  minLength: 1
                image:
                  type: string
                  minLength: 1
                daemonSetName:
                  type: string
                  minLength: 1
                configMapName:
                  type: string
                  minLength: 1
                configRevision:
                  type: string
                  minLength: 1
            status:
              type: object
              properties:
                observedGeneration:
                  type: integer
                  format: int64
                ready:
                  type: boolean
                managedDaemonSet:
                  type: string
                managedConfigMap:
                  type: string
                conditions:
                  type: array
                  items:
                    type: object
                    required:
                      - type
                      - status
                    properties:
                      type:
                        type: string
                      status:
                        type: string
                      reason:
                        type: string
                      message:
                        type: string
                      observedGeneration:
                        type: integer
                        format: int64
YAML

cat >"$controller_manifest" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-operator-controller
    app.kubernetes.io/part-of: apolysis
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${controller_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-operator-controller
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${controller_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-operator-controller
rules:
  - apiGroups: ["apolysis.dev"]
    resources: ["apolysisproductionconfigs"]
    verbs: ["get", "list", "watch", "patch", "update"]
  - apiGroups: ["apolysis.dev"]
    resources: ["apolysisproductionconfigs/status"]
    verbs: ["get", "patch", "update"]
  - apiGroups: ["apps"]
    resources: ["daemonsets"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "patch", "update", "delete"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "patch", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${controller_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-operator-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${controller_name}
subjects:
  - kind: ServiceAccount
    name: ${controller_name}
    namespace: ${namespace}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${controller_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-hardening-operator-controller
    app.kubernetes.io/part-of: apolysis
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: apolysis-production-hardening-operator-controller
  template:
    metadata:
      labels:
        app.kubernetes.io/name: apolysis-production-hardening-operator-controller
        app.kubernetes.io/part-of: apolysis
      annotations:
        apolysis.dev/phase: "production_hardening.19-operator-controller"
    spec:
      serviceAccountName: ${controller_name}
      automountServiceAccountToken: true
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      terminationGracePeriodSeconds: 5
      containers:
        - name: controller
          image: ${controller_image}
          imagePullPolicy: IfNotPresent
          env:
            - name: APOLYSIS_OPERATOR_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: APOLYSIS_OPERATOR_LEASE
              value: ${leader_lease}
            - name: APOLYSIS_OPERATOR_RECONCILE_INTERVAL_SECONDS
              value: "2"
            - name: HOME
              value: /tmp
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
              cpu: 20m
              memory: 32Mi
            limits:
              cpu: 100m
              memory: 128Mi
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            medium: Memory
            sizeLimit: 16Mi
EOF

cat >"$custom_resource_manifest" <<EOF
apiVersion: apolysis.dev/v1alpha1
kind: ApolysisProductionConfig
metadata:
  name: ${cr_name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: apolysis-production-config
    app.kubernetes.io/part-of: apolysis
spec:
  tenantId: platform
  image: ${managed_image}
  daemonSetName: ${managed_daemonset}
  configMapName: ${managed_configmap}
  configRevision: ${stamp}
EOF

kubectl apply -f "$crd_manifest"
kubectl wait --for=condition=Established "crd/${crd_name}" --timeout=120s
kubectl apply -f "$controller_manifest"
kubectl -n "$namespace" rollout status "deployment/${controller_name}" --timeout=180s
kubectl -n "$namespace" wait \
    --for=condition=Available \
    "deployment/${controller_name}" \
    --timeout=180s

service_account_subject="system:serviceaccount:${namespace}:${controller_name}"
can_cluster_admin="$(can_i --as="$service_account_subject" '*' '*' --all-namespaces)"
can_get_secrets="$(can_i --as="$service_account_subject" get secrets -n "$namespace")"
can_patch_status="$(can_i --as="$service_account_subject" patch apolysisproductionconfigs.apolysis.dev/status -n "$namespace")"
can_patch_daemonsets="$(can_i --as="$service_account_subject" patch daemonsets.apps -n "$namespace")"
if [[ "$can_cluster_admin" != "no" || "$can_get_secrets" != "no" || "$can_patch_status" != "yes" || "$can_patch_daemonsets" != "yes" ]]; then
    echo "apolysis-production-hardening: controller RBAC preflight failed" >&2
    printf 'cluster_admin=%s get_secrets=%s patch_status=%s patch_daemonsets=%s\n' \
        "$can_cluster_admin" "$can_get_secrets" "$can_patch_status" "$can_patch_daemonsets" >&2
    exit 1
fi

kubectl apply -f "$custom_resource_manifest"

for _ in $(seq 1 90); do
    kubectl get crd "$crd_name" -o json >"$crd_observed"
    kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$cr_name" -o json >"$cr_observed" 2>/dev/null || true
    kubectl -n "$namespace" get deployment "$controller_name" -o json >"$deployment_observed"
    kubectl -n "$namespace" get lease "$leader_lease" -o json >"$lease_observed" 2>/dev/null || true
    kubectl -n "$namespace" get daemonset "$managed_daemonset" -o json >"$daemonset_observed" 2>/dev/null || true
    kubectl -n "$namespace" get configmap "$managed_configmap" -o json >"$configmap_observed" 2>/dev/null || true

    if python3 - \
        "$crd_observed" \
        "$cr_observed" \
        "$deployment_observed" \
        "$lease_observed" \
        "$daemonset_observed" \
        "$configmap_observed" <<'PY'
import json
import sys
from pathlib import Path

crd_path, cr_path, deployment_path, lease_path, daemonset_path, configmap_path = map(Path, sys.argv[1:])

def load(path):
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"missing observation: {path}")
    return json.loads(path.read_text(encoding="utf-8"))

crd = load(crd_path)
cr = load(cr_path)
deployment = load(deployment_path)
lease = load(lease_path)
daemonset = load(daemonset_path)
configmap = load(configmap_path)

conditions = crd.get("status", {}).get("conditions", [])
established = any(item.get("type") == "Established" and item.get("status") == "True" for item in conditions)
served = any(version.get("name") == "v1alpha1" and version.get("served") for version in crd.get("spec", {}).get("versions", []))
if not established or not served:
    raise SystemExit("CRD is not established and served")

desired = deployment.get("spec", {}).get("replicas", 0)
ready = deployment.get("status", {}).get("readyReplicas", 0)
if desired < 2 or ready < desired:
    raise SystemExit(f"controller replicas are not ready: desired={desired} ready={ready}")
if not lease.get("spec", {}).get("holderIdentity"):
    raise SystemExit("leader lease has no holderIdentity")

status = cr.get("status", {})
generation = cr.get("metadata", {}).get("generation", 0)
observed_generation = status.get("observedGeneration", 0)
ready_condition = any(
    item.get("type") == "Ready"
    and item.get("status") == "True"
    and item.get("observedGeneration") == generation
    for item in status.get("conditions", [])
)
if observed_generation != generation or not ready_condition:
    raise SystemExit("custom resource status is not reconciled")
if status.get("managedDaemonSet") != daemonset.get("metadata", {}).get("name"):
    raise SystemExit("custom resource status does not name the managed DaemonSet")
if status.get("managedConfigMap") != configmap.get("metadata", {}).get("name"):
    raise SystemExit("custom resource status does not name the managed ConfigMap")

daemon_status = daemonset.get("status", {})
if daemon_status.get("desiredNumberScheduled", 0) == 0:
    raise SystemExit("managed DaemonSet has no desired pods")
if daemon_status.get("numberReady", 0) < daemon_status.get("desiredNumberScheduled", 0):
    raise SystemExit("managed DaemonSet is not ready")

cr_uid = cr.get("metadata", {}).get("uid")
for resource, name in [(daemonset, "daemonset"), (configmap, "configmap")]:
    owners = resource.get("metadata", {}).get("ownerReferences", [])
    if not any(owner.get("uid") == cr_uid and owner.get("controller") is True for owner in owners):
        raise SystemExit(f"{name} ownerReferences do not point to the custom resource")
PY
    then
        break
    fi
    sleep 2
done

kubectl -n "$namespace" get apolysisproductionconfigs.apolysis.dev "$cr_name" -o json >"$cr_observed"
kubectl -n "$namespace" get deployment "$controller_name" -o json >"$deployment_observed"
kubectl -n "$namespace" get lease "$leader_lease" -o json >"$lease_observed"
kubectl -n "$namespace" get daemonset "$managed_daemonset" -o json >"$daemonset_observed"
kubectl -n "$namespace" get configmap "$managed_configmap" -o json >"$configmap_observed"

kubectl -n "$namespace" delete apolysisproductionconfigs.apolysis.dev "$cr_name" --wait=true
delete_cleanup_verified=0
for _ in $(seq 1 60); do
    if ! kubectl -n "$namespace" get daemonset "$managed_daemonset" >/dev/null 2>&1 \
        && ! kubectl -n "$namespace" get configmap "$managed_configmap" >/dev/null 2>&1; then
        delete_cleanup_verified=1
        break
    fi
    sleep 2
done
if [[ "$delete_cleanup_verified" != "1" ]]; then
    echo "apolysis-production-hardening: managed resources were not garbage-collected after custom resource deletion" >&2
    kubectl -n "$namespace" get daemonset,configmap >&2 || true
    exit 1
fi

kubectl delete namespace "$namespace" --wait=true --timeout=180s
namespace_deleted=1
kubectl delete crd "$crd_name" --wait=true --timeout=120s
crd_deleted=1

python3 - \
    "$evidence" \
    "$observations" \
    "$crd_observed" \
    "$cr_observed" \
    "$deployment_observed" \
    "$lease_observed" \
    "$daemonset_observed" \
    "$configmap_observed" \
    "$cluster_name" \
    "$namespace" \
    "$crd_name" \
    "$cr_name" \
    "$controller_name" \
    "$leader_lease" \
    "$managed_daemonset" \
    "$managed_configmap" \
    "$can_cluster_admin" \
    "$can_get_secrets" \
    "$can_patch_status" \
    "$can_patch_daemonsets" <<'PY'
import json
import sys
import time
from pathlib import Path

(
    evidence_path,
    observations_path,
    crd_path,
    cr_path,
    deployment_path,
    lease_path,
    daemonset_path,
    configmap_path,
    cluster_name,
    namespace,
    crd_name,
    cr_name,
    controller_name,
    leader_lease,
    managed_daemonset,
    managed_configmap,
    can_cluster_admin,
    can_get_secrets,
    can_patch_status,
    can_patch_daemonsets,
) = sys.argv[1:]

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

crd = load(crd_path)
cr = load(cr_path)
deployment = load(deployment_path)
lease = load(lease_path)
daemonset = load(daemonset_path)
configmap = load(configmap_path)

cr_generation = cr["metadata"]["generation"]
cr_status = cr.get("status", {})
deployment_spec = deployment.get("spec", {})
deployment_status = deployment.get("status", {})
controller_container = deployment_spec["template"]["spec"]["containers"][0]
resources = controller_container["resources"]

def parse_cpu_m(cpu):
    text = str(cpu)
    if text.endswith("m"):
        return int(text[:-1])
    return int(float(text) * 1000)

def parse_mem_mib(memory):
    text = str(memory)
    if text.endswith("Mi"):
        return int(text[:-2])
    if text.endswith("Gi"):
        return int(text[:-2]) * 1024
    return int(text)

conditions = crd.get("status", {}).get("conditions", [])
crd_established = any(item.get("type") == "Established" and item.get("status") == "True" for item in conditions)
crd_served = any(version.get("name") == "v1alpha1" and version.get("served") for version in crd.get("spec", {}).get("versions", []))
ready_condition = any(
    item.get("type") == "Ready"
    and item.get("status") == "True"
    and item.get("observedGeneration") == cr_generation
    for item in cr_status.get("conditions", [])
)
daemon_status = daemonset.get("status", {})
daemon_ready = daemon_status.get("desiredNumberScheduled", 0) > 0 and daemon_status.get("numberReady", 0) >= daemon_status.get("desiredNumberScheduled", 0)
cr_uid = cr["metadata"]["uid"]
owner_refs_verified = all(
    any(owner.get("uid") == cr_uid and owner.get("controller") is True for owner in resource.get("metadata", {}).get("ownerReferences", []))
    for resource in [daemonset, configmap]
)

observed_at_unix_ms = int(time.time()) * 1000
evidence = {
    "evidence_id": f"production-hardening-operator-controller-{observed_at_unix_ms}",
    "source": "live_cluster",
    "provider": "kubernetes_controller",
    "cluster_name": cluster_name,
    "namespace": namespace,
    "crd_name": crd_name,
    "custom_resource_name": cr_name,
    "controller_deployment": controller_name,
    "controller_service_account": controller_name,
    "controller_desired_replicas": int(deployment_spec.get("replicas", 0)),
    "controller_ready_replicas": int(deployment_status.get("readyReplicas", 0)),
    "leader_election_lease": leader_lease,
    "lease_holder_identity": lease.get("spec", {}).get("holderIdentity", ""),
    "rbac_scope": "namespace_scoped",
    "controller_cpu_request_millicores": parse_cpu_m(resources["requests"]["cpu"]),
    "controller_cpu_limit_millicores": parse_cpu_m(resources["limits"]["cpu"]),
    "controller_memory_request_mib": parse_mem_mib(resources["requests"]["memory"]),
    "controller_memory_limit_mib": parse_mem_mib(resources["limits"]["memory"]),
    "crd_established": crd_established,
    "crd_served": crd_served,
    "custom_resource_admitted": True,
    "reconciliation_observed": cr_status.get("managedDaemonSet") == managed_daemonset
    and cr_status.get("managedConfigMap") == managed_configmap,
    "observed_generation": int(cr_generation),
    "reconciled_generation": int(cr_status.get("observedGeneration", 0)),
    "managed_daemonset_name": managed_daemonset,
    "managed_daemonset_ready": daemon_ready,
    "managed_configmap_name": managed_configmap,
    "owner_references_verified": owner_refs_verified,
    "status_condition_ready": ready_condition,
    "status_observed_generation_matches": cr_status.get("observedGeneration") == cr_generation,
    "rollback_or_delete_cleanup_verified": True,
    "cleanup_confirmed": True,
    "observed_at_unix_ms": observed_at_unix_ms,
}

observations = {
    "rbac": {
        "cluster_admin": can_cluster_admin,
        "get_secrets": can_get_secrets,
        "patch_status": can_patch_status,
        "patch_daemonsets": can_patch_daemonsets,
    },
    "cr_status": cr_status,
    "deployment_ready_replicas": deployment_status.get("readyReplicas", 0),
    "lease_holder_identity": evidence["lease_holder_identity"],
    "daemonset_status": daemon_status,
    "owner_references_verified": owner_refs_verified,
}

Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
Path(observations_path).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-operator-controller-evidence -- \
    --evidence "$evidence" >"$report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "kubernetes_controller"
  and .approval.controller_ready_replicas >= 2
  and .approval.managed_daemonset_name == "'"$managed_daemonset"'"
  and .approval.managed_configmap_name == "'"$managed_configmap"'"
' "$report" >/dev/null

python3 - "$evidence" "$fail_evidence" <<'PY'
import json
import sys
from pathlib import Path

source, dest = map(Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["source"] = "fixture"
data["provider"] = "static_manifest"
data["rbac_scope"] = "cluster_admin"
data["controller_desired_replicas"] = 1
data["controller_ready_replicas"] = 1
data["controller_cpu_request_millicores"] = 0
data["controller_cpu_limit_millicores"] = 500
data["controller_memory_request_mib"] = 0
data["controller_memory_limit_mib"] = 1024
data["crd_established"] = False
data["reconciliation_observed"] = False
data["owner_references_verified"] = False
data["cleanup_confirmed"] = False
dest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if cargo run -q -p apolysis-validation --bin apolysis-production-hardening-operator-controller-evidence -- \
    --evidence "$fail_evidence" >"$fail_report"; then
    echo "apolysis-production-hardening: invalid operator/controller evidence unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("live Kubernetes cluster evidence is required"))
  and (.failures | map(.message) | index("Kubernetes controller execution evidence is required"))
  and (.failures | map(.message) | index("controller RBAC must be namespace-scoped"))
  and (.failures | map(.message) | index("controller must run at least two desired replicas"))
  and (.failures | map(.message) | index("controller CPU limit must be between request and 250m"))
  and (.failures | map(.message) | index("managed resource ownerReferences must point to the custom resource"))
  and (.failures | map(.message) | index("cleanup confirmation is required"))
' "$fail_report" >/dev/null

printf 'apolysis-production-hardening: operator/controller live gate passed (%s)\n' "$output_dir"

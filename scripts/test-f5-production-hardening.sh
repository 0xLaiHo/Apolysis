#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/deploy/kubernetes/apolysisd-production-baseline.yaml"
containerfile="$repo_root/deploy/container/apolysisd.Dockerfile"
live_gate="$repo_root/scripts/test-f5-live-deployment.sh"
supply_chain_builder="$repo_root/scripts/build-f5-release-bundle.sh"
supply_chain_gate="$repo_root/scripts/test-f5-supply-chain.sh"
release_registry_gate="$repo_root/scripts/test-f5-release-registry.sh"
tenant_query_gate="$repo_root/scripts/test-f5-tenant-query-retention.sh"
retention_enforcement_gate="$repo_root/scripts/test-f5-retention-enforcement.sh"
promotion_policy_gate="$repo_root/scripts/test-f5-release-promotion-policy.sh"
registry_promotion_execution_gate="$repo_root/scripts/test-f5-registry-promotion-execution.sh"
signing_profile_gate="$repo_root/scripts/test-f5-signing-profile.sh"
signing_execution_gate="$repo_root/scripts/test-f5-signing-execution.sh"
aws_kms_signing_gate="$repo_root/scripts/test-f5-aws-kms-signing.sh"
worm_archive_policy_gate="$repo_root/scripts/test-f5-worm-archive-policy.sh"
worm_archive_execution_gate="$repo_root/scripts/test-f5-worm-archive-execution.sh"
service_mesh_live_evidence_gate="$repo_root/scripts/test-f5-service-mesh-live-evidence.sh"
service_mesh_live_istio_gate="$repo_root/scripts/test-f5-service-mesh-live-istio.sh"
managed_cloud_service_mesh_gate="$repo_root/scripts/test-f5-managed-cloud-service-mesh.sh"
vke_cluster_readiness_gate="$repo_root/scripts/test-f5-vke-cluster-readiness.sh"
operator_controller_gate="$repo_root/scripts/test-f5-operator-controller.sh"
chaos_performance_gate="$repo_root/scripts/test-f5-chaos-performance.sh"
external_provider_qualification_gate="$repo_root/scripts/test-f5-external-provider-qualification.sh"
final_external_bundle_builder="$repo_root/scripts/build-f5-final-external-provider-bundle.sh"
final_external_bundle_gate="$repo_root/scripts/test-f5-final-external-provider-bundle.sh"
final_provider_readiness_gate="$repo_root/scripts/test-f5-final-provider-readiness.sh"
final_provider_workflow="$repo_root/.github/workflows/f5-final-provider-evidence.yml"
final_bundle_env_gate="$repo_root/scripts/prepare-f5-final-provider-bundle-env.sh"
helm_chart="$repo_root/deploy/helm/apolysis"
helm_gate="$repo_root/scripts/test-f5-helm-production.sh"
makefile="$repo_root/Makefile"

python3 - "$manifest" <<'PY'
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
if not manifest.exists():
    raise SystemExit(f"missing F5 production deployment manifest: {manifest}")

text = manifest.read_text(encoding="utf-8")

required_snippets = [
    "kind: Namespace\nmetadata:\n  name: apolysis-system",
    "kind: ServiceAccount\nmetadata:\n  name: apolysisd\n  namespace: apolysis-system",
    "kind: ClusterRole\nmetadata:\n  name: apolysisd-runtime-reader",
    "resources: [\"pods\", \"namespaces\", \"nodes\"]",
    "resources: [\"runtimeclasses\"]",
    "verbs: [\"get\", \"list\", \"watch\"]",
    "kind: ClusterRoleBinding\nmetadata:\n  name: apolysisd-runtime-reader",
    "kind: DaemonSet\nmetadata:\n  name: apolysisd\n  namespace: apolysis-system",
    "maxUnavailable: 10%",
    "serviceAccountName: apolysisd",
    "automountServiceAccountToken: false",
    "hostPID: true",
    "runAsUser: 0",
    "allowPrivilegeEscalation: false",
    "readOnlyRootFilesystem: true",
    "drop:\n                - ALL",
    "add:\n                - BPF\n                - PERFMON",
    "--socket\n            - /run/apolysis/apolysisd.sock",
    "--state-dir\n            - /var/lib/apolysis",
    "--docker-socket\n            - /host/run/docker.sock",
    "--containerd-socket\n            - /host/run/containerd/containerd.sock",
    "--k3s-containerd-socket\n            - /host/run/k3s/containerd/containerd.sock",
    "--metrics-listen\n            - 0.0.0.0:9909",
    "apolysis.dev/production-facing-kernel-blocking: \"disabled\"",
    "ports:\n            - name: metrics\n              containerPort: 9909\n              protocol: TCP",
    "readinessProbe:",
    "livenessProbe:",
    "/usr/local/bin/apolysisd-health",
    "--timeout-ms\n                - \"1000\"",
    "--require-readiness",
    "--require-liveness",
    "resources:\n            requests:\n              cpu: 100m\n              memory: 128Mi\n            limits:\n              cpu: 500m\n              memory: 512Mi",
    "name: host-run",
    "mountPath: /host/run",
    "readOnly: true",
    "path: /run",
    "name: host-cgroup",
    "mountPath: /sys/fs/cgroup",
    "readOnly: true",
    "path: /sys/fs/cgroup",
    "name: bpf-fs",
    "mountPath: /sys/fs/bpf",
    "path: /sys/fs/bpf",
    "name: host-tracing",
    "mountPath: /sys/kernel/tracing",
    "readOnly: true",
    "path: /sys/kernel/tracing",
    "kind: NetworkPolicy\nmetadata:\n  name: apolysisd-default-deny\n  namespace: apolysis-system",
]

missing = [snippet for snippet in required_snippets if snippet not in text]
if missing:
    details = "\n--- missing snippet ---\n".join(missing)
    raise SystemExit(f"F5 production deployment manifest is missing required hardening fields:\n{details}")

for forbidden in [
    "privileged: true",
    "hostNetwork: true",
    "runAsNonRoot: true",
    "- SYS_ADMIN",
    ":latest",
    "production-facing-kernel-blocking: \"enabled\"",
]:
    if forbidden in text:
        raise SystemExit(f"F5 production deployment manifest contains forbidden field: {forbidden}")

print("apolysis-f5: production hardening manifest gate passed")
PY

for required_path in "$containerfile" "$live_gate"; do
    if [[ ! -s "$required_path" ]]; then
        echo "missing F5.2 live deployment artifact: $required_path" >&2
        exit 1
    fi
done

for required_path in "$supply_chain_builder" "$supply_chain_gate"; do
    if [[ ! -s "$required_path" ]]; then
        echo "missing F5.6 supply-chain release artifact: $required_path" >&2
        exit 1
    fi
done

for required_path in "$helm_chart/Chart.yaml" "$helm_chart/values.yaml" "$helm_gate"; do
    if [[ ! -s "$required_path" ]]; then
        echo "missing F5.7 Helm production artifact: $required_path" >&2
        exit 1
    fi
done

if [[ ! -s "$release_registry_gate" ]]; then
    echo "missing F5.8 release registry/archive artifact: $release_registry_gate" >&2
    exit 1
fi

if [[ ! -s "$tenant_query_gate" ]]; then
    echo "missing F5.10 tenant query/retention artifact: $tenant_query_gate" >&2
    exit 1
fi

if [[ ! -s "$retention_enforcement_gate" ]]; then
    echo "missing F5.11 retention enforcement artifact: $retention_enforcement_gate" >&2
    exit 1
fi

if [[ ! -s "$promotion_policy_gate" ]]; then
    echo "missing F5.12 release promotion policy artifact: $promotion_policy_gate" >&2
    exit 1
fi

if [[ ! -s "$registry_promotion_execution_gate" ]]; then
    echo "missing F5.18 registry promotion execution artifact: $registry_promotion_execution_gate" >&2
    exit 1
fi

if [[ ! -s "$signing_profile_gate" ]]; then
    echo "missing F5.13 signing profile artifact: $signing_profile_gate" >&2
    exit 1
fi

if [[ ! -s "$signing_execution_gate" ]]; then
    echo "missing F5.16 signing execution artifact: $signing_execution_gate" >&2
    exit 1
fi

if [[ ! -s "$aws_kms_signing_gate" ]]; then
    echo "missing F5.25 AWS KMS signing artifact: $aws_kms_signing_gate" >&2
    exit 1
fi

if [[ ! -s "$worm_archive_policy_gate" ]]; then
    echo "missing F5.14 WORM archive policy artifact: $worm_archive_policy_gate" >&2
    exit 1
fi

if [[ ! -s "$worm_archive_execution_gate" ]]; then
    echo "missing F5.17 WORM archive execution artifact: $worm_archive_execution_gate" >&2
    exit 1
fi

if [[ ! -s "$service_mesh_live_evidence_gate" ]]; then
    echo "missing F5.15 service-mesh live evidence artifact: $service_mesh_live_evidence_gate" >&2
    exit 1
fi

if [[ ! -s "$service_mesh_live_istio_gate" ]]; then
    echo "missing F5.15 live Istio service-mesh artifact: $service_mesh_live_istio_gate" >&2
    exit 1
fi

if [[ ! -s "$managed_cloud_service_mesh_gate" ]]; then
    echo "missing F5.27 managed Cloud Service Mesh artifact: $managed_cloud_service_mesh_gate" >&2
    exit 1
fi

if [[ ! -s "$vke_cluster_readiness_gate" ]]; then
    echo "missing F5.28 Vultr VKE cluster readiness artifact: $vke_cluster_readiness_gate" >&2
    exit 1
fi

if [[ ! -s "$operator_controller_gate" ]]; then
    echo "missing F5.19 operator/controller artifact: $operator_controller_gate" >&2
    exit 1
fi

if [[ ! -s "$chaos_performance_gate" ]]; then
    echo "missing F5.20 chaos/performance artifact: $chaos_performance_gate" >&2
    exit 1
fi

if [[ ! -s "$external_provider_qualification_gate" ]]; then
    echo "missing F5.21 external provider qualification artifact: $external_provider_qualification_gate" >&2
    exit 1
fi

if [[ ! -s "$final_external_bundle_builder" ]]; then
    echo "missing F5.26 final external provider bundle builder: $final_external_bundle_builder" >&2
    exit 1
fi

if [[ ! -s "$final_external_bundle_gate" ]]; then
    echo "missing F5.26 final external provider bundle gate: $final_external_bundle_gate" >&2
    exit 1
fi

if [[ ! -s "$final_provider_readiness_gate" ]]; then
    echo "missing F5.29 final provider readiness artifact: $final_provider_readiness_gate" >&2
    exit 1
fi

if [[ ! -s "$final_provider_workflow" ]]; then
    echo "missing F5.30 final provider evidence workflow: $final_provider_workflow" >&2
    exit 1
fi

if [[ ! -s "$final_bundle_env_gate" ]]; then
    echo "missing F5.31 final provider bundle env artifact: $final_bundle_env_gate" >&2
    exit 1
fi

grep -q '^test-f5-live-deployment:' "$makefile" || {
    echo "missing Makefile target: test-f5-live-deployment" >&2
    exit 1
}

grep -q '^test-f5-supply-chain:' "$makefile" || {
    echo "missing Makefile target: test-f5-supply-chain" >&2
    exit 1
}

grep -q '^test-f5-helm-production:' "$makefile" || {
    echo "missing Makefile target: test-f5-helm-production" >&2
    exit 1
}

grep -q '^test-f5-release-registry:' "$makefile" || {
    echo "missing Makefile target: test-f5-release-registry" >&2
    exit 1
}

grep -q '^test-f5-tenant-query-retention:' "$makefile" || {
    echo "missing Makefile target: test-f5-tenant-query-retention" >&2
    exit 1
}

grep -q '^test-f5-retention-enforcement:' "$makefile" || {
    echo "missing Makefile target: test-f5-retention-enforcement" >&2
    exit 1
}

grep -q '^test-f5-release-promotion-policy:' "$makefile" || {
    echo "missing Makefile target: test-f5-release-promotion-policy" >&2
    exit 1
}

grep -q '^test-f5-registry-promotion-execution:' "$makefile" || {
    echo "missing Makefile target: test-f5-registry-promotion-execution" >&2
    exit 1
}

grep -q '^test-f5-signing-profile:' "$makefile" || {
    echo "missing Makefile target: test-f5-signing-profile" >&2
    exit 1
}

grep -q '^test-f5-signing-execution:' "$makefile" || {
    echo "missing Makefile target: test-f5-signing-execution" >&2
    exit 1
}

grep -q '^test-f5-aws-kms-signing:' "$makefile" || {
    echo "missing Makefile target: test-f5-aws-kms-signing" >&2
    exit 1
}

grep -q '^test-f5-worm-archive-policy:' "$makefile" || {
    echo "missing Makefile target: test-f5-worm-archive-policy" >&2
    exit 1
}

grep -q '^test-f5-worm-archive-execution:' "$makefile" || {
    echo "missing Makefile target: test-f5-worm-archive-execution" >&2
    exit 1
}

grep -q '^test-f5-service-mesh-live-evidence:' "$makefile" || {
    echo "missing Makefile target: test-f5-service-mesh-live-evidence" >&2
    exit 1
}

grep -q '^test-f5-service-mesh-live-istio:' "$makefile" || {
    echo "missing Makefile target: test-f5-service-mesh-live-istio" >&2
    exit 1
}

grep -q '^test-f5-managed-cloud-service-mesh:' "$makefile" || {
    echo "missing Makefile target: test-f5-managed-cloud-service-mesh" >&2
    exit 1
}

grep -q '^test-f5-vke-cluster-readiness:' "$makefile" || {
    echo "missing Makefile target: test-f5-vke-cluster-readiness" >&2
    exit 1
}

grep -q '^test-f5-operator-controller:' "$makefile" || {
    echo "missing Makefile target: test-f5-operator-controller" >&2
    exit 1
}

grep -q '^test-f5-chaos-performance:' "$makefile" || {
    echo "missing Makefile target: test-f5-chaos-performance" >&2
    exit 1
}

grep -q '^test-f5-external-provider-qualification:' "$makefile" || {
    echo "missing Makefile target: test-f5-external-provider-qualification" >&2
    exit 1
}

grep -q '^test-f5-final-external-provider-bundle:' "$makefile" || {
    echo "missing Makefile target: test-f5-final-external-provider-bundle" >&2
    exit 1
}

grep -q '^test-f5-final-provider-readiness:' "$makefile" || {
    echo "missing Makefile target: test-f5-final-provider-readiness" >&2
    exit 1
}

grep -q '^test-f5-final-provider-bundle-env:' "$makefile" || {
    echo "missing Makefile target: test-f5-final-provider-bundle-env" >&2
    exit 1
}

grep -q 'COPY crictl /usr/local/bin/crictl' "$containerfile" || {
    echo "F5.2 live deployment image must include crictl for runtime adapter validation" >&2
    exit 1
}

grep -q 'require_command crictl' "$live_gate" || {
    echo "F5.2 live deployment gate must preflight crictl" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_CRICTL_VERSION:-v1.35.0' "$live_gate" || {
    echo "F5.2 live deployment gate must pin the default cri-tools version" >&2
    exit 1
}

grep -q 'kubernetes-sigs/cri-tools/releases/download' "$live_gate" || {
    echo "F5.2 live deployment gate must download a real crictl when host crictl is a k3s wrapper" >&2
    exit 1
}

grep -q 'readlink -f "$(command -v crictl)"' "$live_gate" || {
    echo "F5.2 live deployment gate must copy the resolved crictl binary into the image context" >&2
    exit 1
}

grep -q 'apolysis-f5-live-workload' "$live_gate" || {
    echo "F5.2 live deployment gate must create a live marked workload for adapter evidence" >&2
    exit 1
}

grep -q 'k3s_containerd' "$live_gate" || {
    echo "F5.2 live deployment gate must assert k3s containerd adapter readiness" >&2
    exit 1
}

grep -q 'port-forward' "$live_gate" || {
    echo "F5.3 live deployment gate must scrape metrics through kubectl port-forward" >&2
    exit 1
}

grep -q 'apolysis_component_state{component="ebpf"} 1' "$live_gate" || {
    echo "F5.3 live deployment gate must assert live eBPF metrics readiness" >&2
    exit 1
}

grep -q 'apolysis_adapter_state{adapter="k3s_containerd"} 1' "$live_gate" || {
    echo "F5.3 live deployment gate must assert live k3s adapter metrics readiness" >&2
    exit 1
}

grep -q 'apolysisd-restart-health.json' "$live_gate" || {
    echo "F5.4 live deployment gate must capture daemon restart health evidence" >&2
    exit 1
}

grep -q 'apolysis-f5-restart-workload' "$live_gate" || {
    echo "F5.4 live deployment gate must create a marked workload after DaemonSet restart" >&2
    exit 1
}

grep -q 'apolysisd-socket-outage-health.json' "$live_gate" || {
    echo "F5.4 live deployment gate must capture k3s CRI socket outage health evidence" >&2
    exit 1
}

grep -q 'apolysisd-socket-recovery-health.json' "$live_gate" || {
    echo "F5.4 live deployment gate must capture k3s CRI socket recovery health evidence" >&2
    exit 1
}

grep -q 'apolysis-f5-missing-k3s-containerd.sock' "$live_gate" || {
    echo "F5.4 live deployment gate must inject a missing k3s CRI socket path" >&2
    exit 1
}

grep -q '"k3s_containerd" "degraded"' "$live_gate" || {
    echo "F5.4 live deployment gate must assert k3s adapter degraded state during socket outage" >&2
    exit 1
}

grep -q '"k3s_containerd" "ready"' "$live_gate" || {
    echo "F5.4 live deployment gate must assert k3s adapter recovery to ready" >&2
    exit 1
}

grep -q 'apolysis-f5-queue-pressure-workload' "$live_gate" || {
    echo "F5.5 live deployment gate must create a queue pressure workload" >&2
    exit 1
}

grep -q 'apolysisd-queue-pressure-metrics.prom' "$live_gate" || {
    echo "F5.5 live deployment gate must capture queue pressure metrics evidence" >&2
    exit 1
}

grep -q 'apolysis_queue_accepted_total' "$live_gate" || {
    echo "F5.5 live deployment gate must assert accepted queue event metrics" >&2
    exit 1
}

grep -q 'apolysis-f5-unwritable-store-workload' "$live_gate" || {
    echo "F5.5 live deployment gate must create an unwritable-store workload" >&2
    exit 1
}

grep -q 'apolysisd-unwritable-store-health.json' "$live_gate" || {
    echo "F5.5 live deployment gate must capture unwritable-store health evidence" >&2
    exit 1
}

grep -q '"unavailable"' "$live_gate" || {
    echo "F5.5 live deployment gate must assert unavailable storage during unwritable-store injection" >&2
    exit 1
}

grep -q 'apolysis-f5-release-manifest.json' "$supply_chain_builder" || {
    echo "F5.6 supply-chain builder must create a signed release manifest" >&2
    exit 1
}

grep -q 'apolysis-f5-sbom.cdx.json' "$supply_chain_builder" || {
    echo "F5.6 supply-chain builder must create a CycloneDX SBOM" >&2
    exit 1
}

grep -q 'apolysis-f5-provenance.intoto.json' "$supply_chain_builder" || {
    echo "F5.6 supply-chain builder must create provenance evidence" >&2
    exit 1
}

grep -q 'apolysis-f5-vulnerability-scan.json' "$supply_chain_builder" || {
    echo "F5.6 supply-chain builder must create vulnerability scan evidence" >&2
    exit 1
}

grep -q 'cosign verify-blob' "$supply_chain_gate" || {
    echo "F5.6 supply-chain gate must verify signed release artifacts" >&2
    exit 1
}

grep -q 'syft scan' "$supply_chain_gate" || {
    echo "F5.6 supply-chain gate must run a real SBOM scan" >&2
    exit 1
}

grep -q 'trivy fs' "$supply_chain_gate" || {
    echo "F5.6 supply-chain gate must run a real vulnerability scan" >&2
    exit 1
}

grep -R -q 'apolysis.dev/tenant-id' "$helm_chart" || {
    echo "F5.7 Helm chart must label rendered resources with a tenant id" >&2
    exit 1
}

grep -R -q '/var/lib/apolysis/tenants' "$helm_chart" || {
    echo "F5.7 Helm chart must use tenant-isolated hostPath storage" >&2
    exit 1
}

grep -R -q 'apolysis.dev/mtls-required' "$helm_chart" || {
    echo "F5.7 Helm chart must expose mTLS handoff annotations" >&2
    exit 1
}

grep -R -q 'apolysisd-metrics-allow' "$helm_chart" || {
    echo "F5.7 Helm chart must render a narrow metrics ingress allowlist" >&2
    exit 1
}

grep -R -q 'security.istio.io/v1beta1' "$helm_chart" || {
    echo "F5.9 Helm chart must render service-mesh identity policy resources" >&2
    exit 1
}

grep -R -q 'PeerAuthentication' "$helm_chart" || {
    echo "F5.9 Helm chart must render strict mTLS PeerAuthentication" >&2
    exit 1
}

grep -R -q 'AuthorizationPolicy' "$helm_chart" || {
    echo "F5.9 Helm chart must render metrics identity AuthorizationPolicy" >&2
    exit 1
}

grep -R -q 'allowedPrincipals' "$helm_chart" || {
    echo "F5.9 Helm chart must require bounded service-account principals" >&2
    exit 1
}

grep -q 'helm lint' "$helm_gate" || {
    echo "F5.7 Helm gate must lint the chart" >&2
    exit 1
}

grep -q 'helm template' "$helm_gate" || {
    echo "F5.7 Helm gate must render the chart" >&2
    exit 1
}

grep -q 'kubectl apply --dry-run=client' "$helm_gate" || {
    echo "F5.7 Helm gate must validate rendered Kubernetes manifests" >&2
    exit 1
}

grep -q 'registry:2' "$release_registry_gate" || {
    echo "F5.8 registry gate must use a real local OCI registry" >&2
    exit 1
}

grep -q 'docker push' "$release_registry_gate" || {
    echo "F5.8 registry gate must push the release image to the local registry" >&2
    exit 1
}

grep -q 'cosign attach sbom' "$release_registry_gate" || {
    echo "F5.8 registry gate must attach SBOM evidence to the registry image" >&2
    exit 1
}

grep -q 'apolysis-f5-immutable-archive-manifest.json' "$release_registry_gate" || {
    echo "F5.8 registry gate must create immutable archive manifest evidence" >&2
    exit 1
}

grep -q 'apolysis-f5-registry-attachment.json' "$release_registry_gate" || {
    echo "F5.8 registry gate must create registry attachment evidence" >&2
    exit 1
}

grep -q 'cargo test -p apolysis-accountability --test intent' "$tenant_query_gate" || {
    echo "F5.10 tenant query gate must run accountability intent API tests" >&2
    exit 1
}

grep -q 'cargo test -p apolysis-accountability --test session' "$tenant_query_gate" || {
    echo "F5.10 tenant query gate must run session registry retention tests" >&2
    exit 1
}

grep -q 'cargo test -p apolysis-daemon --test socket_api' "$tenant_query_gate" || {
    echo "F5.10 tenant query gate must run daemon socket API tenant tests" >&2
    exit 1
}

grep -q 'ListSessions' "$repo_root/crates/apolysis-accountability/src/intent.rs" || {
    echo "F5.10 intent API must expose tenant session listing" >&2
    exit 1
}

grep -q 'RetentionTier' "$repo_root/crates/apolysis-accountability/src/intent.rs" || {
    echo "F5.10 intent API must expose retention tiers" >&2
    exit 1
}

grep -q 'list_for_tenant' "$repo_root/crates/apolysis-accountability/src/session.rs" || {
    echo "F5.10 session registry must list sessions by tenant" >&2
    exit 1
}

grep -q 'query_for_tenant' "$repo_root/crates/apolysis-daemon/src/state.rs" || {
    echo "F5.10 daemon state must enforce tenant-scoped query" >&2
    exit 1
}

grep -q 'SessionList' "$repo_root/crates/apolysis-daemon/src/server.rs" || {
    echo "F5.10 daemon response API must return tenant session lists" >&2
    exit 1
}

grep -q 'cargo test -p apolysis-accountability --test intent' "$retention_enforcement_gate" || {
    echo "F5.11 retention enforcement gate must run accountability intent tests" >&2
    exit 1
}

grep -q 'cargo test -p apolysis-accountability --test session' "$retention_enforcement_gate" || {
    echo "F5.11 retention enforcement gate must run session retention purge tests" >&2
    exit 1
}

grep -q 'cargo test -p apolysis-daemon --test socket_api' "$retention_enforcement_gate" || {
    echo "F5.11 retention enforcement gate must run daemon socket API retention tests" >&2
    exit 1
}

grep -q 'ApplyRetention' "$repo_root/crates/apolysis-accountability/src/intent.rs" || {
    echo "F5.11 intent API must expose explicit retention application requests" >&2
    exit 1
}

grep -q 'RetentionPurgeReport' "$repo_root/crates/apolysis-accountability/src/session.rs" || {
    echo "F5.11 session registry must expose retention purge reports" >&2
    exit 1
}

grep -q 'apply_retention_for_tenant' "$repo_root/crates/apolysis-accountability/src/session.rs" || {
    echo "F5.11 session registry must apply tenant-scoped retention purge" >&2
    exit 1
}

grep -q 'apply_retention' "$repo_root/crates/apolysis-daemon/src/state.rs" || {
    echo "F5.11 daemon state must apply retention to registry and state directories" >&2
    exit 1
}

grep -q 'RetentionPurge' "$repo_root/crates/apolysis-daemon/src/server.rs" || {
    echo "F5.11 daemon response API must return retention purge reports" >&2
    exit 1
}

grep -q 'apolysis-f5-release-promotion-policy' "$promotion_policy_gate" || {
    echo "F5.12 promotion policy gate must run the release promotion policy CLI" >&2
    exit 1
}

grep -q 'evaluate_f5_release_promotion_policy' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.12 validation library must expose release promotion policy evaluation" >&2
    exit 1
}

grep -q 'F5ReleasePromotionRequest' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.12 validation library must expose release promotion requests" >&2
    exit 1
}

grep -q 'F5ReleasePromotionPolicyEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.12 validation library must expose release promotion evidence" >&2
    exit 1
}

grep -q 'external or KMS/HSM-backed signing is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.12 promotion policy must reject ephemeral production signing" >&2
    exit 1
}

grep -q 'minimum production retention is 90 days' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.12 promotion policy must enforce production retention" >&2
    exit 1
}

grep -q 'anonymous registry pull access is forbidden' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.12 promotion policy must reject anonymous registry pull access" >&2
    exit 1
}

grep -q 'apolysis-f5-registry-promotion-execution-evidence' "$registry_promotion_execution_gate" || {
    echo "F5.18 registry promotion execution gate must run the registry execution CLI" >&2
    exit 1
}

grep -q 'Docker Registry HTTP API V2' "$registry_promotion_execution_gate" || {
    echo "F5.18 registry promotion execution gate must use the registry HTTP API" >&2
    exit 1
}

grep -q 'manifests/$target_tag' "$registry_promotion_execution_gate" || {
    echo "F5.18 registry promotion execution gate must promote the production manifest tag" >&2
    exit 1
}

grep -q 'manifests/$rollback_tag' "$registry_promotion_execution_gate" || {
    echo "F5.18 registry promotion execution gate must publish a rollback tag" >&2
    exit 1
}

grep -q 'production_delete_without_retention_denied' "$registry_promotion_execution_gate" || {
    echo "F5.18 registry promotion execution gate must prove production delete denial" >&2
    exit 1
}

grep -q 'evaluate_f5_registry_promotion_execution_evidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.18 validation library must expose registry promotion execution evaluation" >&2
    exit 1
}

grep -q 'F5RegistryPromotionExecutionEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.18 validation library must expose registry promotion execution evidence data" >&2
    exit 1
}

grep -q 'live registry promotion execution evidence is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.18 registry promotion execution evidence must reject fixture evidence" >&2
    exit 1
}

grep -q 'promotion must be performed by digest through the registry API' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.18 registry promotion execution evidence must require digest API promotion" >&2
    exit 1
}

grep -q 'production delete without retention bypass must be denied by the registry API' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.18 registry promotion execution evidence must require registry delete denial" >&2
    exit 1
}

grep -q 'apolysis-f5-signing-profile' "$signing_profile_gate" || {
    echo "F5.13 signing profile gate must run the signing profile CLI" >&2
    exit 1
}

grep -q 'evaluate_f5_signing_profile' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.13 validation library must expose signing profile evaluation" >&2
    exit 1
}

grep -q 'F5SigningProfile' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.13 validation library must expose signing profile data" >&2
    exit 1
}

grep -q 'production release signing requires KMS or HSM provider' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.13 signing profile policy must reject non-KMS/HSM providers" >&2
    exit 1
}

grep -q 'production signing key must be non-exportable' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.13 signing profile policy must reject exportable production keys" >&2
    exit 1
}

grep -q 'rotation period must be 180 days or less' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.13 signing profile policy must enforce key rotation bounds" >&2
    exit 1
}

grep -q 'apolysis-f5-signing-execution-evidence' "$signing_execution_gate" || {
    echo "F5.16 signing execution gate must run the signing execution CLI" >&2
    exit 1
}

grep -q 'softhsm2-util --init-token' "$signing_execution_gate" || {
    echo "F5.16 signing execution gate must initialize a live PKCS#11 token" >&2
    exit 1
}

grep -q 'pkcs11-tool' "$signing_execution_gate" || {
    echo "F5.16 signing execution gate must use pkcs11-tool" >&2
    exit 1
}

grep -q -- '--keypairgen' "$signing_execution_gate" || {
    echo "F5.16 signing execution gate must generate a provider-backed key" >&2
    exit 1
}

grep -q 'never extractable' "$signing_execution_gate" || {
    echo "F5.16 signing execution gate must require non-extractable key evidence" >&2
    exit 1
}

grep -q 'openssl dgst -sha256' "$signing_execution_gate" || {
    echo "F5.16 signing execution gate must verify the PKCS#11 signature" >&2
    exit 1
}

grep -q 'evaluate_f5_signing_execution_evidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.16 validation library must expose signing execution evidence evaluation" >&2
    exit 1
}

grep -q 'F5SigningExecutionEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.16 validation library must expose signing execution evidence data" >&2
    exit 1
}

grep -q 'live provider signing evidence is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.16 signing execution evidence must reject fixture evidence" >&2
    exit 1
}

grep -q 'private key must be non-extractable' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.16 signing execution evidence must require non-extractable keys" >&2
    exit 1
}

grep -q 'key must be generated inside the signing provider' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.16 signing execution evidence must require provider-generated keys" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_AWS_KMS_SIGNING' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing gate must require explicit live confirmation" >&2
    exit 1
}

grep -q 'aws kms describe-key' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing gate must inspect KMS key metadata" >&2
    exit 1
}

grep -q 'aws kms get-public-key' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing gate must retain KMS public key evidence" >&2
    exit 1
}

grep -q 'aws kms sign' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing gate must execute a real KMS sign operation" >&2
    exit 1
}

grep -q -- '--message-type DIGEST' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing gate must sign a release manifest digest" >&2
    exit 1
}

grep -q 'provider": "cloud_kms"' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing evidence must use the cloud_kms provider" >&2
    exit 1
}

grep -q 'awskms://' "$aws_kms_signing_gate" || {
    echo "F5.25 AWS KMS signing evidence must retain an awskms provider URI" >&2
    exit 1
}

grep -q 'apolysis-f5-worm-archive-policy' "$worm_archive_policy_gate" || {
    echo "F5.14 WORM archive policy gate must run the WORM archive policy CLI" >&2
    exit 1
}

grep -q 'evaluate_f5_worm_archive_policy' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.14 validation library must expose WORM archive policy evaluation" >&2
    exit 1
}

grep -q 'F5WormArchivePolicy' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.14 validation library must expose WORM archive policy data" >&2
    exit 1
}

grep -q 'external WORM archive requires S3 Object Lock, GCS Bucket Lock, or Azure Immutable Blob' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.14 WORM archive policy must reject local mutable archives" >&2
    exit 1
}

grep -q 'retention mode must be compliance' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.14 WORM archive policy must require compliance retention" >&2
    exit 1
}

grep -q 'delete-deny principals are required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.14 WORM archive policy must require delete-deny principals" >&2
    exit 1
}

grep -q 'apolysis-f5-worm-archive-execution-evidence' "$worm_archive_execution_gate" || {
    echo "F5.17 WORM archive execution gate must run the WORM archive execution CLI" >&2
    exit 1
}

grep -q 'x-amz-bucket-object-lock-enabled' "$worm_archive_execution_gate" || {
    echo "F5.17 WORM archive execution gate must create an object-lock-enabled bucket" >&2
    exit 1
}

grep -q 'x-amz-object-lock-mode' "$worm_archive_execution_gate" || {
    echo "F5.17 WORM archive execution gate must apply object retention through the provider API" >&2
    exit 1
}

grep -q 'x-amz-object-lock-legal-hold' "$worm_archive_execution_gate" || {
    echo "F5.17 WORM archive execution gate must apply legal hold through the provider API" >&2
    exit 1
}

grep -q 'delete_without_bypass_denied' "$worm_archive_execution_gate" || {
    echo "F5.17 WORM archive execution gate must prove delete without bypass is denied" >&2
    exit 1
}

grep -q 'evaluate_f5_worm_archive_execution_evidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.17 validation library must expose WORM archive execution evaluation" >&2
    exit 1
}

grep -q 'F5WormArchiveExecutionEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.17 validation library must expose WORM archive execution evidence data" >&2
    exit 1
}

grep -q 'live WORM archive API execution evidence is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.17 WORM archive execution evidence must reject fixture evidence" >&2
    exit 1
}

grep -q 'retention must be applied through the provider API' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.17 WORM archive execution evidence must require provider retention application" >&2
    exit 1
}

grep -q 'delete without bypass must be denied by the provider API' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.17 WORM archive execution evidence must require provider delete denial" >&2
    exit 1
}

grep -q 'apolysis-f5-service-mesh-live-evidence' "$service_mesh_live_evidence_gate" || {
    echo "F5.15 service-mesh live evidence gate must run the service-mesh evidence CLI" >&2
    exit 1
}

grep -q 'evaluate_f5_service_mesh_live_evidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.15 validation library must expose service-mesh live evidence evaluation" >&2
    exit 1
}

grep -q 'F5ServiceMeshLiveEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.15 validation library must expose service-mesh live evidence data" >&2
    exit 1
}

grep -q 'live cluster evidence is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.15 service-mesh live evidence must reject fixture evidence" >&2
    exit 1
}

grep -q 'strict mTLS mode is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.15 service-mesh live evidence must require strict mTLS" >&2
    exit 1
}

grep -q 'traffic telemetry must report mutual TLS' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.15 service-mesh live evidence must require mutual TLS telemetry" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_SERVICE_MESH_LIVE' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must require explicit live confirmation" >&2
    exit 1
}

grep -q 'helm upgrade --install istiod istio/istiod' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must install or use a real Istio control plane" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_ISTIO_CHART_VERSION:-1.30.1' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must pin the default Istio chart version" >&2
    exit 1
}

grep -q 'kind: PeerAuthentication' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must apply PeerAuthentication" >&2
    exit 1
}

grep -q 'kind: AuthorizationPolicy' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must apply AuthorizationPolicy" >&2
    exit 1
}

grep -q 'unauthorized mTLS client unexpectedly reached the server' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must deny unauthorized mTLS clients" >&2
    exit 1
}

grep -q 'plaintext client unexpectedly reached the strict-mTLS server' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must deny plaintext clients" >&2
    exit 1
}

grep -q 'apolysis-f5-service-mesh-live-evidence' "$service_mesh_live_istio_gate" || {
    echo "F5.15 live Istio gate must validate collected evidence with the CLI" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_MANAGED_CLOUD_SERVICE_MESH' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh gate must require explicit live confirmation" >&2
    exit 1
}

grep -q 'gcloud container fleet mesh describe' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh gate must inspect fleet mesh state" >&2
    exit 1
}

grep -q 'controlPlaneManagement' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh gate must require managed control-plane evidence" >&2
    exit 1
}

grep -q 'MANAGEMENT_AUTOMATIC' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh gate must require automatic managed mesh configuration" >&2
    exit 1
}

grep -q 'controlplanerevision' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh gate must inspect in-cluster managed mesh revision evidence" >&2
    exit 1
}

grep -q 'gke_anthos_service_mesh' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh evidence must use accepted managed mesh provider identity" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_MANAGED_MESH_EVIDENCE' "$managed_cloud_service_mesh_gate" || {
    echo "F5.27 managed Cloud Service Mesh gate must publish final-bundle evidence path" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_VKE_CLUSTER_READINESS' "$vke_cluster_readiness_gate" || {
    echo "F5.28 VKE readiness gate must require explicit live confirmation" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_VKE_EXPECTED_NODES' "$vke_cluster_readiness_gate" || {
    echo "F5.28 VKE readiness gate must make node count explicit" >&2
    exit 1
}

grep -q 'kubectl get nodes' "$vke_cluster_readiness_gate" || {
    echo "F5.28 VKE readiness gate must inspect live node state" >&2
    exit 1
}

grep -q 'containerd' "$vke_cluster_readiness_gate" || {
    echo "F5.28 VKE readiness gate must verify containerd runtime evidence" >&2
    exit 1
}

grep -q 'vultr_vke' "$vke_cluster_readiness_gate" || {
    echo "F5.28 VKE readiness evidence must use Vultr VKE provider identity" >&2
    exit 1
}

grep -q 'apolysis-f5-vke-cluster-readiness-evidence' "$vke_cluster_readiness_gate" || {
    echo "F5.28 VKE readiness gate must retain machine-readable evidence" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_OPERATOR_CONTROLLER' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must require explicit live confirmation" >&2
    exit 1
}

grep -q 'ApolysisProductionConfig' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must create an ApolysisProductionConfig CRD" >&2
    exit 1
}

grep -q 'kind: Lease' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must record leader-election Lease evidence" >&2
    exit 1
}

grep -q 'replicas: 2' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must run an HA controller Deployment" >&2
    exit 1
}

grep -q 'kubectl auth can-i' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must verify bounded controller RBAC" >&2
    exit 1
}

grep -q 'ownerReferences' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must verify managed resource ownerReferences" >&2
    exit 1
}

grep -q 'rollback_or_delete_cleanup_verified' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must prove cleanup after custom resource deletion" >&2
    exit 1
}

grep -q 'apolysis-f5-operator-controller-evidence' "$operator_controller_gate" || {
    echo "F5.19 operator/controller gate must validate collected evidence with the CLI" >&2
    exit 1
}

grep -q 'evaluate_f5_operator_controller_evidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.19 validation library must expose operator/controller evidence evaluation" >&2
    exit 1
}

grep -q 'F5OperatorControllerEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.19 validation library must expose operator/controller evidence data" >&2
    exit 1
}

grep -q 'live Kubernetes cluster evidence is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.19 operator/controller evidence must reject fixture evidence" >&2
    exit 1
}

grep -q 'controller RBAC must be namespace-scoped' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.19 operator/controller evidence must reject broad RBAC" >&2
    exit 1
}

grep -q 'controller CPU limit must be between request and 250m' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.19 operator/controller evidence must enforce controller CPU bounds" >&2
    exit 1
}

grep -q 'managed resource ownerReferences must point to the custom resource' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.19 operator/controller evidence must require owner reference validation" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_CHAOS_PERFORMANCE' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must require explicit live confirmation" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_CHAOS_PROVIDER' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must support explicit Kubernetes provider identity" >&2
    exit 1
}

grep -q 'kubectl top pods' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must collect pod resource metrics" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_CHAOS_DEPLOYMENTS:-3' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must default to at least three deployments" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_CHAOS_REPLICAS_PER_DEPLOYMENT:-10' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must default to at least thirty replicas" >&2
    exit 1
}

grep -q 'delete "pod/' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must perform pod-delete chaos" >&2
    exit 1
}

grep -q 'apolysis-f5-chaos-performance-evidence' "$chaos_performance_gate" || {
    echo "F5.20 chaos/performance gate must validate collected evidence with the CLI" >&2
    exit 1
}

grep -q 'evaluate_f5_chaos_performance_evidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 validation library must expose chaos/performance evidence evaluation" >&2
    exit 1
}

grep -q 'F5ChaosPerformanceEvidence' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 validation library must expose chaos/performance evidence data" >&2
    exit 1
}

grep -q 'at least thirty workload replicas are required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 chaos/performance evidence must enforce workload scale" >&2
    exit 1
}

grep -q 'pod-delete chaos must remove at least 20% of workload pods' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 chaos/performance evidence must enforce pod-delete chaos coverage" >&2
    exit 1
}

grep -q 'metrics-server availability evidence is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 chaos/performance evidence must require metrics-server evidence" >&2
    exit 1
}

grep -q 'observed CPU must stay at or below 1000m' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 chaos/performance evidence must enforce CPU budget" >&2
    exit 1
}

grep -q 'observed memory must stay at or below 1024Mi' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.20 chaos/performance evidence must enforce memory budget" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_EXTERNAL_PROVIDER_QUALIFICATION' "$external_provider_qualification_gate" || {
    echo "F5.21 external provider qualification gate must require explicit confirmation for live bundles" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_EXTERNAL_PROVIDER_BUNDLE' "$external_provider_qualification_gate" || {
    echo "F5.21 external provider qualification gate must accept retained external evidence bundles" >&2
    exit 1
}

grep -q 'APOLYSIS_REQUIRE_F5_EXTERNAL_PROVIDER_QUALIFICATION' "$external_provider_qualification_gate" || {
    echo "F5.21 external provider qualification gate must be able to fail closed when external qualification is required" >&2
    exit 1
}

grep -q 'softhsm' "$external_provider_qualification_gate" || {
    echo "F5.21 external provider qualification gate must include local HSM rejection evidence" >&2
    exit 1
}

grep -q 'minio' "$external_provider_qualification_gate" || {
    echo "F5.21 external provider qualification gate must include local WORM rejection evidence" >&2
    exit 1
}

grep -q 'oci_distribution_registry' "$external_provider_qualification_gate" || {
    echo "F5.21 external provider qualification gate must include local registry rejection evidence" >&2
    exit 1
}

grep -q 'evaluate_f5_external_provider_qualification_bundle' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 validation library must expose external provider qualification evaluation" >&2
    exit 1
}

grep -q 'F5ExternalProviderQualificationBundle' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 validation library must expose external provider qualification data" >&2
    exit 1
}

grep -q 'cloud KMS or external hardware HSM signing qualification is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 external provider qualification must require cloud KMS or external HSM evidence" >&2
    exit 1
}

grep -q 'real cloud WORM/object-lock provider qualification is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 external provider qualification must require real cloud WORM evidence" >&2
    exit 1
}

grep -q 'real cloud registry promotion/retention qualification is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 external provider qualification must require real cloud registry evidence" >&2
    exit 1
}

grep -q 'managed service-mesh provider qualification is required' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 external provider qualification must require managed service-mesh evidence" >&2
    exit 1
}

grep -q 'provider must be an accepted external provider for this requirement' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.21 external provider qualification must reject local provider substitutions" >&2
    exit 1
}

grep -q -- '--bundle-root' "$external_provider_qualification_gate" || {
    echo "F5.24 external provider qualification live bundle must verify retained artifact files" >&2
    exit 1
}

grep -q 'retained evidence artifact' "$repo_root/crates/apolysis-validation/src/bin/apolysis-f5-external-provider-qualification.rs" || {
    echo "F5.24 external provider qualification CLI must inspect retained evidence artifacts" >&2
    exit 1
}

grep -q 'sha256 does not match' "$repo_root/crates/apolysis-validation/src/bin/apolysis-f5-external-provider-qualification.rs" || {
    echo "F5.24 external provider qualification CLI must reject mismatched retained evidence artifacts" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_SIGNING_EVIDENCE' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle builder must require retained signing evidence" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_WORM_EVIDENCE' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle builder must require retained WORM evidence" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_REGISTRY_EVIDENCE' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle builder must require retained registry evidence" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_MANAGED_MESH_EVIDENCE' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle builder must require retained managed mesh evidence" >&2
    exit 1
}

grep -q -- '--bundle-root' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle builder must validate retained artifacts with bundle-root" >&2
    exit 1
}

grep -q 'cloud_kms_or_external_hsm_signing' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle must include signing provider qualification" >&2
    exit 1
}

grep -q 'managed_service_mesh' "$final_external_bundle_builder" || {
    echo "F5.26 final bundle must include managed mesh provider qualification" >&2
    exit 1
}

grep -q 'APOLYSIS_REQUIRE_F5_FINAL_PROVIDER_READINESS' "$final_provider_readiness_gate" || {
    echo "F5.29 final provider readiness gate must expose fail-closed required mode" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_SIGNING_EVIDENCE' "$final_provider_readiness_gate" || {
    echo "F5.29 final provider readiness gate must check retained signing evidence input" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_MANAGED_MESH_EVIDENCE' "$final_provider_readiness_gate" || {
    echo "F5.29 final provider readiness gate must check retained managed mesh evidence input" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_AWS_KMS_KEY_ID' "$final_provider_readiness_gate" || {
    echo "F5.29 final provider readiness gate must report AWS KMS live prerequisites" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_GKE_MESH_FLEET_PROJECT' "$final_provider_readiness_gate" || {
    echo "F5.29 final provider readiness gate must report managed mesh live prerequisites" >&2
    exit 1
}

grep -q 'apolysis-f5-final-provider-readiness-report' "$final_provider_readiness_gate" || {
    echo "F5.29 final provider readiness gate must retain a machine-readable report" >&2
    exit 1
}

grep -q 'workflow_dispatch' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must be manually dispatchable" >&2
    exit 1
}

grep -q 'aws-actions/configure-aws-credentials' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must configure AWS credentials through GitHub Actions" >&2
    exit 1
}

grep -q 'google-github-actions/auth' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must authenticate to GCP through GitHub Actions" >&2
    exit 1
}

grep -q 'google-github-actions/get-gke-credentials' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must acquire GKE credentials for managed mesh evidence" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_AWS_KMS_SIGNING' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must run the opt-in AWS KMS gate" >&2
    exit 1
}

grep -q 'APOLYSIS_CONFIRM_F5_MANAGED_CLOUD_SERVICE_MESH' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must run the opt-in managed mesh gate" >&2
    exit 1
}

grep -q 'scripts/test-f5-aws-kms-signing.sh' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must execute F5.25 AWS KMS signing" >&2
    exit 1
}

grep -q 'scripts/test-f5-managed-cloud-service-mesh.sh' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must execute F5.27 managed mesh qualification" >&2
    exit 1
}

grep -q 'actions/upload-artifact' "$final_provider_workflow" || {
    echo "F5.30 final provider evidence workflow must retain provider artifacts" >&2
    exit 1
}

grep -q 'assemble_final_bundle' "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must optionally assemble the final bundle" >&2
    exit 1
}

grep -q 'retained_provider_artifact_run_id' "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must accept a retained provider artifact run id" >&2
    exit 1
}

grep -q "needs.aws-kms-signing.result == 'success'" "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must wait for AWS KMS evidence success" >&2
    exit 1
}

grep -q "needs.gke-managed-mesh.result == 'success'" "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must wait for managed mesh evidence success" >&2
    exit 1
}

grep -q 'actions/download-artifact' "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must download retained provider artifacts for bundle assembly" >&2
    exit 1
}

grep -q 'scripts/prepare-f5-final-provider-bundle-env.sh' "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must run the F5.31 bundle env gate" >&2
    exit 1
}

grep -q 'APOLYSIS_RUN_F5_FINAL_BUNDLE' "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must run the F5.26 final bundle builder through F5.31" >&2
    exit 1
}

grep -q 'f5-final-external-provider-bundle' "$final_provider_workflow" || {
    echo "F5.32 final provider evidence workflow must upload final bundle artifacts" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_PROVIDER_ARTIFACT_ROOT' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must accept a provider artifact root" >&2
    exit 1
}

grep -q 'explicit_artifact_roots' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must require explicit roots for final provider artifacts" >&2
    exit 1
}

grep -q 'contract tests intentionally create accepted-looking fixture artifacts' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must avoid default target fixture contamination" >&2
    exit 1
}

grep -q 'APOLYSIS_REQUIRE_F5_FINAL_BUNDLE_ENV' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must expose fail-closed required mode" >&2
    exit 1
}

grep -q 'APOLYSIS_RUN_F5_FINAL_BUNDLE' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must optionally run the final bundle builder" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_SIGNING_EVIDENCE' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must export signing evidence paths" >&2
    exit 1
}

grep -q 'APOLYSIS_F5_MANAGED_MESH_EVIDENCE' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must export managed mesh evidence paths" >&2
    exit 1
}

grep -q 'apolysis-f5-final-provider-bundle-env-report' "$final_bundle_env_gate" || {
    echo "F5.31 final provider bundle env gate must retain a machine-readable report" >&2
    exit 1
}

grep -q 'CloudflareR2BucketLock' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.22 WORM archive execution must support Cloudflare R2 Bucket Lock evidence" >&2
    exit 1
}

grep -q 'cloudflare_r2_bucket_lock' "$external_provider_qualification_gate" || {
    echo "F5.22 external provider qualification contract must include Cloudflare R2 Bucket Lock evidence" >&2
    exit 1
}

grep -q 'DockerHub' "$repo_root/crates/apolysis-validation/src/lib.rs" || {
    echo "F5.23 registry promotion execution must support Docker Hub evidence" >&2
    exit 1
}

grep -q 'test-f5-dockerhub-registry-promotion' "$repo_root/Makefile" || {
    echo "F5.23 must expose a Docker Hub live registry promotion target" >&2
    exit 1
}

grep -q '/immutabletags' "$repo_root/scripts/test-f5-dockerhub-registry-promotion.sh" || {
    echo "F5.23 Docker Hub live gate must configure immutable tags" >&2
    exit 1
}

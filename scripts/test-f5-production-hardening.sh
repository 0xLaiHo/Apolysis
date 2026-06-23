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

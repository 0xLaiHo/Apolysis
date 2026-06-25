#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
chart="$repo_root/deploy/helm/apolysis"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_HELM_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-helm-production.XXXXXX")}"
primary_render="$output_dir/apolysis-platform-prod.yaml"
secondary_render="$output_dir/apolysis-tenant-b.yaml"
primary_core_render="$output_dir/apolysis-platform-prod-core.yaml"
secondary_core_render="$output_dir/apolysis-tenant-b-core.yaml"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in helm kubectl python3; do
    require_command "$command"
done

python3 - <<'PY'
try:
    import yaml  # noqa: RuntimeGuardrails01
except Exception as error:
    raise SystemExit(f"apolysis-production-hardening: missing Python PyYAML module: {error}")
PY

helm lint "$chart" \
    --set tenant.id=platform-prod \
    --set namespace.name=apolysis-system

helm template apolysis "$chart" \
    --namespace apolysis-system \
    --set tenant.id=platform-prod \
    --set namespace.name=apolysis-system \
    --set mesh.istio.enabled=true \
    --set mesh.istio.metricsAuthorizationPolicy.allowedPrincipals[0]=cluster.local/ns/apolysis-monitoring/sa/prometheus \
    >"$primary_render"

helm template apolysis-tenant-b "$chart" \
    --namespace apolysis-tenant-b \
    --set tenant.id=tenant-b \
    --set namespace.name=apolysis-tenant-b \
    --set mesh.istio.enabled=true \
    --set mesh.istio.metricsAuthorizationPolicy.allowedPrincipals[0]=cluster.local/ns/apolysis-monitoring/sa/prometheus-tenant-b \
    >"$secondary_render"

python3 - "$primary_render" "$primary_core_render" "$secondary_render" "$secondary_core_render" <<'PY'
import sys
from pathlib import Path

import yaml

custom_kinds = {"AuthorizationPolicy", "PeerAuthentication"}

for render_path, core_path in [(sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4])]:
    docs = [doc for doc in yaml.safe_load_all(Path(render_path).read_text(encoding="utf-8")) if doc]
    core_docs = [doc for doc in docs if doc.get("kind") not in custom_kinds]
    Path(core_path).write_text(yaml.safe_dump_all(core_docs, sort_keys=False), encoding="utf-8")
PY

kubectl apply --dry-run=client --validate=false -f "$primary_core_render" >/dev/null
kubectl apply --dry-run=client --validate=false -f "$secondary_core_render" >/dev/null

python3 - "$primary_render" "$secondary_render" <<'PY'
import sys
from pathlib import Path

import yaml


def load(path: str) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if doc]


def by_kind_name(docs: list[dict], kind: str, name: str) -> dict:
    for doc in docs:
        if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name:
            return doc
    raise SystemExit(f"missing {kind}/{name}")


def first_kind(docs: list[dict], kind: str) -> dict:
    for doc in docs:
        if doc.get("kind") == kind:
            return doc
    raise SystemExit(f"missing kind {kind}")


def assert_equal(actual, expected, message: str) -> None:
    if actual != expected:
        raise SystemExit(f"{message}: expected {expected!r}, got {actual!r}")


def assert_true(value, message: str) -> None:
    if not value:
        raise SystemExit(message)


def verify_render(docs: list[dict], release: str, namespace: str, tenant: str, expected_principal: str) -> None:
    expected_kinds = {
        "Namespace",
        "ServiceAccount",
        "ClusterRole",
        "ClusterRoleBinding",
        "DaemonSet",
        "NetworkPolicy",
        "Service",
        "PeerAuthentication",
        "AuthorizationPolicy",
    }
    rendered_kinds = {doc.get("kind") for doc in docs}
    missing = expected_kinds - rendered_kinds
    if missing:
        raise SystemExit(f"rendered chart is missing expected kinds: {sorted(missing)}")

    namespace_doc = by_kind_name(docs, "Namespace", namespace)
    namespace_labels = namespace_doc.get("metadata", {}).get("labels", {})
    assert_equal(namespace_labels.get("apolysis.dev/tenant-id"), tenant, "namespace tenant label")
    assert_equal(namespace_labels.get("pod-security.kubernetes.io/enforce"), "privileged", "namespace pod-security enforce")

    service_account = by_kind_name(docs, "ServiceAccount", release)
    assert_equal(service_account.get("automountServiceAccountToken"), False, "service account token automount")

    role = by_kind_name(docs, "ClusterRole", f"{release}-runtime-reader")
    for rule in role.get("rules", []):
        verbs = set(rule.get("verbs", []))
        assert_true(verbs <= {"get", "list", "watch"}, f"ClusterRole has write verbs: {verbs}")
    role_resources = {resource for rule in role.get("rules", []) for resource in rule.get("resources", [])}
    assert_true({"pods", "namespaces", "nodes", "runtimeclasses"} <= role_resources, "ClusterRole missing runtime metadata resources")

    binding = by_kind_name(docs, "ClusterRoleBinding", f"{release}-runtime-reader")
    subject = binding.get("subjects", [{}])[0]
    assert_equal(subject.get("kind"), "ServiceAccount", "ClusterRoleBinding subject kind")
    assert_equal(subject.get("name"), release, "ClusterRoleBinding subject name")
    assert_equal(subject.get("namespace"), namespace, "ClusterRoleBinding subject namespace")

    daemonset = by_kind_name(docs, "DaemonSet", release)
    assert_equal(daemonset.get("metadata", {}).get("namespace"), namespace, "DaemonSet namespace")
    strategy = daemonset.get("spec", {}).get("updateStrategy", {})
    assert_equal(strategy.get("rollingUpdate", {}).get("maxUnavailable"), "10%", "DaemonSet maxUnavailable")

    pod_template = daemonset.get("spec", {}).get("template", {})
    pod_labels = pod_template.get("metadata", {}).get("labels", {})
    pod_annotations = pod_template.get("metadata", {}).get("annotations", {})
    assert_equal(pod_labels.get("apolysis.dev/tenant-id"), tenant, "pod tenant label")
    assert_equal(pod_annotations.get("apolysis.dev/tenant-id"), tenant, "pod tenant annotation")
    assert_equal(pod_annotations.get("apolysis.dev/production-facing-kernel-blocking"), "disabled", "kernel blocking annotation")
    assert_equal(pod_annotations.get("apolysis.dev/mtls-required"), "true", "mTLS handoff annotation")
    assert_equal(pod_annotations.get("apolysis.dev/mtls-mode"), "strict", "mTLS handoff mode")

    pod_spec = pod_template.get("spec", {})
    assert_equal(pod_spec.get("serviceAccountName"), release, "DaemonSet service account")
    assert_equal(pod_spec.get("automountServiceAccountToken"), False, "DaemonSet token automount")
    assert_equal(pod_spec.get("hostPID"), True, "DaemonSet hostPID")
    assert_equal(pod_spec.get("hostNetwork"), False, "DaemonSet hostNetwork")

    container = pod_spec.get("containers", [{}])[0]
    security = container.get("securityContext", {})
    assert_equal(security.get("allowPrivilegeEscalation"), False, "allowPrivilegeEscalation")
    assert_equal(security.get("readOnlyRootFilesystem"), True, "readOnlyRootFilesystem")
    capabilities = security.get("capabilities", {})
    assert_true("ALL" in capabilities.get("drop", []), "capabilities must drop ALL")
    assert_true({"BPF", "PERFMON", "SYS_RESOURCE"} <= set(capabilities.get("add", [])), "missing bounded capabilities")
    assert_true("privileged" not in security, "container must not render privileged")

    args = container.get("args", [])
    assert_true("--metrics-listen" in args and "0.0.0.0:9909" in args, "metrics listener args missing")
    assert_true("--queue-capacity" in args and "16384" in args, "queue capacity args missing")
    assert_true(container.get("resources", {}).get("requests", {}).get("cpu") == "100m", "CPU request missing")
    assert_true(container.get("resources", {}).get("limits", {}).get("memory") == "512Mi", "memory limit missing")

    volumes = {volume.get("name"): volume for volume in pod_spec.get("volumes", [])}
    assert_equal(volumes["state"]["hostPath"]["path"], f"/var/lib/apolysis/tenants/{tenant}", "tenant state hostPath")
    assert_equal(volumes["host-run"]["hostPath"]["path"], "/run", "host run path")
    mount_by_name = {mount.get("name"): mount for mount in container.get("volumeMounts", [])}
    assert_equal(mount_by_name["host-run"].get("readOnly"), True, "host-run mount readOnly")
    assert_equal(mount_by_name["host-cgroup"].get("readOnly"), True, "host-cgroup mount readOnly")
    assert_equal(mount_by_name["host-tracing"].get("readOnly"), True, "host-tracing mount readOnly")

    default_deny = by_kind_name(docs, "NetworkPolicy", f"{release}-default-deny")
    assert_equal(default_deny.get("spec", {}).get("ingress"), [], "default deny ingress")
    assert_equal(default_deny.get("spec", {}).get("egress"), [], "default deny egress")

    metrics_allow = by_kind_name(docs, "NetworkPolicy", f"{release}-apolysisd-metrics-allow")
    ingress = metrics_allow.get("spec", {}).get("ingress", [])
    assert_true(ingress, "metrics allowlist ingress missing")
    source = ingress[0].get("from", [{}])[0]
    assert_equal(
        source.get("namespaceSelector", {}).get("matchLabels", {}).get("apolysis.dev/metrics-access"),
        "true",
        "metrics namespace allowlist label",
    )
    assert_equal(
        source.get("podSelector", {}).get("matchLabels", {}).get("apolysis.dev/metrics-client"),
        "true",
        "metrics pod allowlist label",
    )
    assert_equal(ingress[0].get("ports", [{}])[0].get("port"), 9909, "metrics allowlist port")

    service = by_kind_name(docs, "Service", f"{release}-metrics")
    assert_equal(service.get("spec", {}).get("ports", [{}])[0].get("port"), 9909, "metrics service port")
    assert_equal(service.get("metadata", {}).get("annotations", {}).get("apolysis.dev/mtls-required"), "true", "metrics service mTLS annotation")

    peer_authentication = by_kind_name(docs, "PeerAuthentication", f"{release}-mtls")
    assert_equal(peer_authentication.get("apiVersion"), "security.istio.io/v1beta1", "PeerAuthentication apiVersion")
    assert_equal(peer_authentication.get("metadata", {}).get("namespace"), namespace, "PeerAuthentication namespace")
    assert_equal(
        peer_authentication.get("spec", {}).get("selector", {}).get("matchLabels", {}).get("apolysis.dev/tenant-id"),
        tenant,
        "PeerAuthentication tenant selector",
    )
    assert_equal(peer_authentication.get("spec", {}).get("mtls", {}).get("mode"), "STRICT", "PeerAuthentication mTLS mode")

    authorization_policy = by_kind_name(docs, "AuthorizationPolicy", f"{release}-metrics")
    assert_equal(authorization_policy.get("apiVersion"), "security.istio.io/v1beta1", "AuthorizationPolicy apiVersion")
    assert_equal(authorization_policy.get("metadata", {}).get("namespace"), namespace, "AuthorizationPolicy namespace")
    assert_equal(authorization_policy.get("spec", {}).get("action"), "ALLOW", "AuthorizationPolicy action")
    assert_equal(
        authorization_policy.get("spec", {}).get("selector", {}).get("matchLabels", {}).get("apolysis.dev/tenant-id"),
        tenant,
        "AuthorizationPolicy tenant selector",
    )
    rules = authorization_policy.get("spec", {}).get("rules", [])
    assert_true(rules, "AuthorizationPolicy rules missing")
    principals = rules[0].get("from", [{}])[0].get("source", {}).get("principals", [])
    assert_equal(principals, [expected_principal], "AuthorizationPolicy source principal")
    assert_true("/sa/" in expected_principal, "AuthorizationPolicy must use service-account principals")
    ports = rules[0].get("to", [{}])[0].get("operation", {}).get("ports", [])
    assert_equal(ports, ["9909"], "AuthorizationPolicy metrics port")


primary = load(sys.argv[1])
secondary = load(sys.argv[2])
verify_render(
    primary,
    "apolysis",
    "apolysis-system",
    "platform-prod",
    "cluster.local/ns/apolysis-monitoring/sa/prometheus",
)
verify_render(
    secondary,
    "apolysis-tenant-b",
    "apolysis-tenant-b",
    "tenant-b",
    "cluster.local/ns/apolysis-monitoring/sa/prometheus-tenant-b",
)

primary_state = by_kind_name(primary, "DaemonSet", "apolysis")["spec"]["template"]["spec"]["volumes"][1]["hostPath"]["path"]
secondary_state = by_kind_name(secondary, "DaemonSet", "apolysis-tenant-b")["spec"]["template"]["spec"]["volumes"][1]["hostPath"]["path"]
assert_true(primary_state != secondary_state, "tenant renders must not share a state hostPath")
PY

printf 'apolysis-production-hardening: Helm production gate passed (%s)\n' "$output_dir"

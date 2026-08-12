#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "${project_root}" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
daemonset_path = root / "deploy/kubernetes/daemonset.yaml"
rbac_path = root / "deploy/kubernetes/rbac.yaml"
source_image_path = root / "deploy/kubernetes/apolysis-kubernetes-source.Dockerfile"
collector_image_path = root / "deploy/container/apolysisd.Dockerfile"

for path in (daemonset_path, rbac_path, source_image_path, collector_image_path):
    if not path.is_file():
        raise SystemExit(f"missing K1 deployment artifact: {path.relative_to(root)}")

daemonset = daemonset_path.read_text(encoding="utf-8")
rbac = rbac_path.read_text(encoding="utf-8")
source_image = source_image_path.read_text(encoding="utf-8")
collector_image = collector_image_path.read_text(encoding="utf-8")


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise SystemExit(f"K1 deployment contract missing {description}")


def reject(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None:
        raise SystemExit(f"K1 deployment contract permits {description}")


require(daemonset, r"^kind: DaemonSet$", "DaemonSet kind")
require(daemonset, r"^      automountServiceAccountToken: false$", "disabled automatic token mount")
require(daemonset, r"^      hostNetwork: false$", "disabled host networking")
require(daemonset, r"^      hostPID: false$", "disabled host PID namespace")
require(daemonset, r"^      nodeSelector:\n        kubernetes\.io/os: linux$", "Linux-only node selection")
require(daemonset, r"^      serviceAccountName: apolysis-kubernetes-source$", "dedicated ServiceAccount")
require(daemonset, r"^        fsGroup: 65532$", "shared source IPC group")
require(daemonset, r"^        supplementalGroupsPolicy: Strict$", "strict supplemental group policy")

collector_match = re.search(
    r"^        - name: collector\n(?P<body>.*?)(?=^        - name: kubernetes-source\n)",
    daemonset,
    re.MULTILINE | re.DOTALL,
)
source_match = re.search(
    r"^        - name: kubernetes-source\n(?P<body>.*?)(?=^      volumes:\n)",
    daemonset,
    re.MULTILINE | re.DOTALL,
)
if collector_match is None or source_match is None:
    raise SystemExit("K1 DaemonSet must contain exactly ordered collector and kubernetes-source containers")
collector = collector_match.group("body")
source = source_match.group("body")

require(collector, r"--kubernetes-source-socket\n\s+- /run/apolysis-kubernetes/source/source.sock", "collector source socket argument")
require(collector, r"--kubernetes-cluster-id\n\s+- \$\(APOLYSIS_CLUSTER_ID\)", "collector cluster identity argument")
require(collector, r"--kubernetes-namespace\n\s+- \$\(POD_NAMESPACE\)", "collector namespace argument")
require(collector, r"--kubernetes-node-name\n\s+- \$\(NODE_NAME\)", "collector node argument")
require(collector, r"--containerd-socket\n\s+- /run/apolysis-host/containerd.sock", "collector CRI socket")
require(collector, r"--proc-root\n\s+- /host/proc", "collector host proc root")
require(collector, r"--cgroup-root\n\s+- /host/sys/fs/cgroup", "collector host cgroup root")
require(collector, r"name: APOLYSIS_CRICTL\n\s+value: /usr/local/bin/crictl", "absolute trusted CRI client path")
require(collector, r"image: [^\s]+@sha256:[0-9a-f]{64}", "digest-pinned collector image")
reject(collector, r"image: [^\s]+:v[0-9]", "mutable collector image tag")
reject(collector, r"kubernetes-api-access", "a Kubernetes token mount in collector")
reject(collector, r"name: host-bpf$|mountPath: /sys/fs/bpf", "unused writable host bpffs mount")
require(collector, r"runAsUser: 0", "explicit collector user")
require(collector, r"runAsGroup: 0", "explicit collector primary group")
require(collector, r"privileged: false", "non-privileged collector")
require(collector, r"allowPrivilegeEscalation: false", "collector privilege-escalation denial")
require(collector, r"readOnlyRootFilesystem: true", "collector read-only root filesystem")
require(
    collector,
    r"resources:\n\s+requests:\n\s+cpu: 100m\n\s+memory: 128Mi\n\s+ephemeral-storage: 64Mi\n\s+limits:\n\s+cpu: 1000m\n\s+memory: 512Mi\n\s+ephemeral-storage: 256Mi",
    "bounded collector CPU, memory, and ephemeral storage",
)
capability_match = re.search(
    r"capabilities:\n\s+drop:\n\s+- ALL\n\s+add:(?P<values>(?:\n\s+- [A-Z_]+)+)",
    collector,
)
if capability_match is None:
    raise SystemExit("K1 deployment contract missing exact collector capability profile")
collector_capabilities = set(re.findall(r"- ([A-Z_]+)", capability_match.group("values")))
expected_capabilities = {"BPF", "PERFMON", "SYS_RESOURCE", "DAC_READ_SEARCH"}
if collector_capabilities != expected_capabilities:
    raise SystemExit("K1 deployment contract permits a non-exact collector capability profile")
reject(collector, r"^\s+- SYS_ADMIN$", "collector SYS_ADMIN capability")
reject(collector, r"^\s+- DAC_OVERRIDE$", "collector broad DAC override capability")

require(source, r"runAsNonRoot: true", "non-root metadata source")
require(source, r"runAsUser: 65532", "fixed metadata source UID")
require(source, r"runAsGroup: 65532", "fixed metadata source GID")
require(source, r"allowPrivilegeEscalation: false", "source privilege-escalation denial")
require(source, r"readOnlyRootFilesystem: true", "source read-only root filesystem")
require(
    source,
    r"resources:\n\s+requests:\n\s+cpu: 50m\n\s+memory: 64Mi\n\s+ephemeral-storage: 32Mi\n\s+limits:\n\s+cpu: 250m\n\s+memory: 128Mi\n\s+ephemeral-storage: 64Mi",
    "bounded source CPU, memory, and ephemeral storage",
)
require(source, r"capabilities:\n\s+drop:\n\s+- ALL", "source capability drop")
reject(source, r"capabilities:[\s\S]*?\n\s+add:", "source added capability")
require(source, r"name: kubernetes-api-access\n\s+mountPath: /var/run/secrets/kubernetes.io/serviceaccount\n\s+readOnly: true", "source-only projected token")
require(source, r"name: kubernetes-source-ipc\n\s+mountPath: /run/apolysis-kubernetes", "source IPC mount")
require(source, r"APOLYSIS_KUBERNETES_SOCKET\n\s+value: /run/apolysis-kubernetes/source/source.sock", "source-owned socket parent path")
require(source, r"image: [^\s]+@sha256:[0-9a-f]{64}", "digest-pinned source image")
reject(source, r"image: [^\s]+:v[0-9]", "mutable source image tag")
for forbidden_mount in (
    "host-proc",
    "host-cgroup",
    "host-bpf",
    "host-tracing",
    "containerd-socket",
    "apolysis-state",
):
    reject(source, rf"name: {forbidden_mount}$", f"{forbidden_mount} mount in metadata source")

require(daemonset, r"name: kubernetes-api-access\n\s+projected:\n\s+defaultMode: 0440", "explicit projected API credentials")
require(daemonset, r"serviceAccountToken:\n\s+path: token\n\s+expirationSeconds: 3600", "bounded projected token lifetime")
require(daemonset, r"name: kube-root-ca.crt", "projected API CA")
require(daemonset, r"name: kubernetes-source-ipc\n\s+emptyDir:\n\s+medium: Memory\n\s+sizeLimit: 16Mi", "bounded memory-backed IPC directory")
require(
    daemonset,
    r"name: apolysis-state\n\s+hostPath:\n\s+path: /var/lib/apolysis\n\s+type: Directory(?:\n|$)",
    "pre-created host state directory prerequisite",
)
reject(daemonset, r"DirectoryOrCreate", "automatic creation of a permissive host state directory")
reject(daemonset, r"^\s+initContainers:", "privileged state-directory bootstrap container")
reject(daemonset, r"path: /sys/fs/bpf", "unused host bpffs volume")

require(rbac, r"^kind: ServiceAccount$", "ServiceAccount")
require(rbac, r"^automountServiceAccountToken: false$", "ServiceAccount automatic-token denial")
require(rbac, r"^kind: Role$", "namespace Role")
require(rbac, r"resources: \[\"pods\"\]", "Pod-only resource access")
require(rbac, r"verbs: \[\"list\", \"watch\"\]", "minimal Pod list/watch verbs")
require(rbac, r"^kind: RoleBinding$", "namespace RoleBinding")
for forbidden in ("secrets", "configmaps", "nodes", "create", "update", "patch", "delete", "deletecollection"):
    reject(rbac.lower(), rf"resources:.*\b{forbidden}\b|verbs:.*\b{forbidden}\b", f"RBAC access to {forbidden}")
reject(rbac, r"^kind: ClusterRole(?:Binding)?$", "cluster-scoped RBAC")

require(source_image, r"^FROM gcr\.io/distroless/cc-debian12:nonroot$", "non-root distroless source image")
require(source_image, r"^USER 65532:65532$", "fixed source image UID/GID")
reject(source_image, r"\b(?:curl|wget|kubectl|crictl)\b", "generic remote or runtime administration tooling")

require(
    collector_image,
    r"^COPY apolysisd-control /usr/local/bin/apolysisd-control$",
    "operator control binary in the collector image",
)
require(
    collector_image,
    r"chmod 0755[^\n]*?/usr/local/bin/apolysisd-control",
    "executable operator control binary",
)

print("K1 deployment contract: PASS")
PY

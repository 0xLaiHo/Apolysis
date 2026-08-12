#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly default_kubeconfig="/home/mactavish/vultr-k8s/vke-a88389c3-f720-412d-9579-c83d3c21eabb.yaml"
readonly kubeconfig="${KUBECONFIG:-$default_kubeconfig}"
readonly command_timeout_seconds="${APOLYSIS_K1_COMMAND_TIMEOUT_SECONDS:-30}"
readonly max_output_bytes="${APOLYSIS_K1_MAX_OUTPUT_BYTES:-16777216}"
readonly collector_image="${APOLYSIS_K1_COLLECTOR_IMAGE:-}"
readonly source_image="${APOLYSIS_K1_SOURCE_IMAGE:-}"

work_dir=""
owner_uuid=""
cluster_id=""
namespace=""
namespace_uid=""
mutation_started=0
cleanup_complete=0
cleanup_attention=0

skip_before_cluster_access() {
    printf 'K1 VKE qualification: SKIP (%s)\n' "$1"
    exit 0
}

canonical_fail() {
    printf 'K1 VKE qualification: FAIL (code=%s)\n' "$1" >&2
    exit 1
}

unexpected_error() {
    local status=$?
    printf 'K1 VKE qualification: FAIL (code=unexpected_local_error)\n' >&2
    exit "$status"
}
trap unexpected_error ERR

if [[ "${APOLYSIS_K1_VKE_LIVE:-0}" != "1" ]]; then
    skip_before_cluster_access "set APOLYSIS_K1_VKE_LIVE=1"
fi

case "$command_timeout_seconds" in
    '' | *[!0-9]*) skip_before_cluster_access "invalid command deadline" ;;
esac
case "$max_output_bytes" in
    '' | *[!0-9]*) skip_before_cluster_access "invalid output bound" ;;
esac
if (( command_timeout_seconds < 1 || command_timeout_seconds > 300 )); then
    skip_before_cluster_access "invalid command deadline"
fi
if (( max_output_bytes < 4096 || max_output_bytes > 33554432 )); then
    skip_before_cluster_access "invalid output bound"
fi

for command in bash chmod env kubectl mktemp python3 rm; do
    command -v "$command" >/dev/null 2>&1 || skip_before_cluster_access "missing required tool"
done

# The kubeconfig is checked only as a local filesystem object. Its contents are
# never copied, hashed, printed, or passed to a process other than kubectl.
[[ -f "$kubeconfig" && -r "$kubeconfig" ]] || skip_before_cluster_access "designated kubeconfig unavailable"

validate_digest_image() {
    local image="$1"
    [[ "$image" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]
}

# These two digest references are operator-provided artifact trust inputs. This
# gate validates digest syntax only; it does not establish provenance or bind
# either image to the current checkout, a local binary, or a release.
validate_digest_image "$collector_image" || skip_before_cluster_access "collector image is not digest pinned"
validate_digest_image "$source_image" || skip_before_cluster_access "source image is not digest pinned"

work_dir="$(mktemp -d "/tmp/apolysis-k1-vke.XXXXXXXX")"
chmod 0700 "$work_dir"

local_cleanup() {
    case "$work_dir" in
        /tmp/apolysis-k1-vke.*)
            if ! rm -rf -- "$work_dir"; then
                cleanup_attention=1
            fi
            ;;
        '') ;;
        *)
            cleanup_attention=1
            ;;
    esac
}

# One public process boundary for every cluster/release child. It captures both
# streams in private files, enforces a wall deadline and a combined byte bound,
# and kills the entire process group on either violation. Callers expose only
# canonical error codes, never child diagnostics.
bounded_capture_internal() {
    local stdout_path="$1"
    local stderr_path="$2"
    local stdin_path="$3"
    shift 3
    python3 -I - \
        "$command_timeout_seconds" "$max_output_bytes" \
        "$stdout_path" "$stderr_path" "$stdin_path" "$@" <<'PY'
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

deadline = float(sys.argv[1])
limit = int(sys.argv[2])
stdout_path, stderr_path, stdin_path = map(Path, sys.argv[3:6])
command = sys.argv[6:]

stdin = subprocess.DEVNULL
stdin_handle = None
if str(stdin_path) != "/dev/null":
    stdin_handle = stdin_path.open("rb")
    stdin = stdin_handle
process = subprocess.Popen(
    command,
    stdin=stdin,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    start_new_session=True,
)
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ, "stdout")
selector.register(process.stderr, selectors.EVENT_READ, "stderr")
buffers = {"stdout": bytearray(), "stderr": bytearray()}
started = time.monotonic()
failure = None
while selector.get_map():
    remaining = deadline - (time.monotonic() - started)
    if remaining <= 0:
        failure = 124
        break
    events = selector.select(min(remaining, 0.25))
    for key, _ in events:
        chunk = os.read(key.fileobj.fileno(), 65536)
        if not chunk:
            selector.unregister(key.fileobj)
            continue
        remaining_capacity = limit - sum(map(len, buffers.values()))
        buffers[key.data].extend(chunk[:remaining_capacity])
        if len(chunk) > remaining_capacity:
            failure = 125
            break
    if failure is not None:
        break

if failure is not None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
process.wait()
if stdin_handle is not None:
    stdin_handle.close()

for path, data in ((stdout_path, buffers["stdout"]), (stderr_path, buffers["stderr"])):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = memoryview(data)
        while remaining:
            remaining = remaining[os.write(fd, remaining):]
    finally:
        os.close(fd)

if failure is not None:
    raise SystemExit(failure)
raise SystemExit(process.returncode if process.returncode >= 0 else 126)
PY
}

bounded_capture() {
    local stdout_path="$1"
    local stderr_path="$2"
    shift 2
    bounded_capture_internal "$stdout_path" "$stderr_path" /dev/null "$@"
}

bounded_capture_with_input() {
    local stdout_path="$1"
    local stderr_path="$2"
    local stdin_path="$3"
    shift 3
    bounded_capture_internal "$stdout_path" "$stderr_path" "$stdin_path" "$@"
}

next_capture_paths() {
    local stem="$1"
    CAPTURE_STDOUT="$work_dir/${stem}.stdout"
    CAPTURE_STDERR="$work_dir/${stem}.stderr"
    rm -f -- "$CAPTURE_STDOUT" "$CAPTURE_STDERR"
}

kubectl_capture() {
    local stem="$1"
    shift
    next_capture_paths "$stem"
    bounded_capture "$CAPTURE_STDOUT" "$CAPTURE_STDERR" \
        env KUBECONFIG="$kubeconfig" kubectl \
        --request-timeout="${command_timeout_seconds}s" "$@"
}

kubectl_capture_with_input() {
    local stem="$1"
    local input="$2"
    shift 2
    next_capture_paths "$stem"
    bounded_capture_with_input "$CAPTURE_STDOUT" "$CAPTURE_STDERR" "$input" \
        env KUBECONFIG="$kubeconfig" kubectl \
        --request-timeout="${command_timeout_seconds}s" "$@"
}

kubectl_must_capture() {
    local code="$1"
    shift
    kubectl_capture "$@" || canonical_fail "$code"
}

kubectl_create() {
    local code="$1"
    local stem="$2"
    local manifest="$3"
    kubectl_must_capture "$code" "$stem" create -f "$manifest"
}

render_delete_options() {
    local path="$1" expected_uid="$2"
    python3 -I - "$path" "$expected_uid" <<'PY'
import json
from pathlib import Path
import re
import sys

path, expected_uid = sys.argv[1:]
if not re.fullmatch(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    expected_uid,
):
    raise SystemExit(1)
document = {
    "apiVersion": "v1",
    "kind": "DeleteOptions",
    "preconditions": {"uid": expected_uid},
}
Path(path).write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
PY
}

# A preceding GET proves the owner labels, while this DELETE asks the API
# server to atomically reject a same-name replacement with HTTP 409. Every
# child remains behind the fixed kubeconfig, deadline, byte bound, and private
# capture boundary; neither the request body nor server diagnostics are shown.
uid_preconditioned_delete() {
    local stem="$1" api_path="$2" expected_uid="$3"
    local delete_options_path="$work_dir/${stem}-delete-options.json"
    case "$api_path" in
        "/api/v1/namespaces/$namespace" | \
        "/api/v1/namespaces/$namespace/pods/"* | \
        "/apis/networking.k8s.io/v1/namespaces/$namespace/networkpolicies/"*) ;;
        *) return 1 ;;
    esac
    render_delete_options "$delete_options_path" "$expected_uid" || return 1
    kubectl_capture "$stem-delete" delete --raw "$api_path" -f "$delete_options_path"
}

pause_one_second() {
    read -r -t 1 _ </dev/null || true
}

json_assert_cluster_preflight() {
    python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import json
from pathlib import Path
import sys

nodes_path, pods_path, daemonsets_path, baseline_path = map(Path, sys.argv[1:])
nodes_document = json.loads(nodes_path.read_text(encoding="utf-8"))
pods_document = json.loads(pods_path.read_text(encoding="utf-8"))
daemonsets_document = json.loads(daemonsets_path.read_text(encoding="utf-8"))
nodes = nodes_document.get("items", [])
if len(nodes) != 3:
    raise SystemExit(1)

node_selection = []
node_baseline = []
for node in nodes:
    metadata = node.get("metadata", {})
    spec = node.get("spec", {})
    status = node.get("status", {})
    labels = metadata.get("labels", {})
    conditions = {entry.get("type"): entry.get("status") for entry in status.get("conditions", [])}
    runtime = status.get("nodeInfo", {}).get("containerRuntimeVersion", "")
    blocking_taints = [
        taint
        for taint in spec.get("taints", []) or []
        if taint.get("effect") in ("NoSchedule", "NoExecute")
    ]
    # exactly three Ready schedulable Linux containerd nodes. A True
    # NetworkUnavailable condition is rejected; its absence is accepted only
    # together with Ready=True and the successful owned source probe below.
    if (
        labels.get("kubernetes.io/os") != "linux"
        or spec.get("unschedulable", False)
        or blocking_taints
        or conditions.get("Ready") != "True"
        or conditions.get("NetworkUnavailable") not in (None, "False")
        or not runtime.startswith("containerd://")
    ):
        raise SystemExit(1)
    name = metadata.get("name")
    uid = metadata.get("uid")
    hostname = labels.get("kubernetes.io/hostname")
    if not all(isinstance(value, str) and value for value in (name, uid, hostname)):
        raise SystemExit(1)
    node_selection.append({"name": name, "hostname": hostname})
    node_baseline.append(
        {
            "uid": uid,
            "name": name,
            "ready": conditions.get("Ready"),
            "network_unavailable": conditions.get("NetworkUnavailable"),
            "runtime": runtime,
            "unschedulable": bool(spec.get("unschedulable", False)),
            "blocking_taints": blocking_taints,
        }
    )


def pod_projection(pod):
    metadata = pod.get("metadata", {})
    status = pod.get("status", {})
    containers = []
    for entry in status.get("containerStatuses", []) or []:
        containers.append(
            {
                "name": entry.get("name"),
                "ready": entry.get("ready"),
                "restart_count": entry.get("restartCount"),
                "container_id": entry.get("containerID"),
            }
        )
    return {
        "uid": metadata.get("uid"),
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "node": pod.get("spec", {}).get("nodeName"),
        "phase": status.get("phase"),
        "deleting": metadata.get("deletionTimestamp") is not None,
        "containers": sorted(containers, key=lambda entry: entry["name"] or ""),
    }


def daemonset_projection(daemonset):
    metadata = daemonset.get("metadata", {})
    status = daemonset.get("status", {})
    return {
        "uid": metadata.get("uid"),
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "generation": metadata.get("generation"),
        "desired": status.get("desiredNumberScheduled", 0),
        "current": status.get("currentNumberScheduled", 0),
        "ready": status.get("numberReady", 0),
        "updated": status.get("updatedNumberScheduled", 0),
        "unavailable": status.get("numberUnavailable", 0),
    }

baseline = {
    "nodes": sorted(node_baseline, key=lambda entry: entry["uid"]),
    "pods": sorted((pod_projection(pod) for pod in pods_document.get("items", [])), key=lambda entry: entry["uid"] or ""),
    "daemonsets": sorted(
        (daemonset_projection(ds) for ds in daemonsets_document.get("items", [])),
        key=lambda entry: entry["uid"] or "",
    ),
}
baseline_path.write_text(json.dumps(baseline, sort_keys=True, separators=(",", ":")), encoding="utf-8")
Path(str(baseline_path) + ".nodes").write_text(
    json.dumps(sorted(node_selection, key=lambda entry: entry["name"]), separators=(",", ":")),
    encoding="utf-8",
)
PY
}

preflight_cluster() {
    kubectl_must_capture "cluster_nodes_unavailable" preflight-nodes get nodes -o json
    local nodes_output="$CAPTURE_STDOUT"
    kubectl_must_capture "cluster_pods_unavailable" preflight-pods get pods --all-namespaces -o json
    local pods_output="$CAPTURE_STDOUT"
    kubectl_must_capture "cluster_daemonsets_unavailable" preflight-daemonsets get daemonsets --all-namespaces -o json
    local daemonsets_output="$CAPTURE_STDOUT"
    kubectl_must_capture "cluster_identity_unavailable" preflight-cluster-identity get namespace kube-system -o json
    cluster_id="$(python3 -I - "$CAPTURE_STDOUT" <<'PY'
import json
from pathlib import Path
import re
import sys

uid = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("metadata", {}).get("uid", "")
if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uid):
    raise SystemExit(1)
if uid == "00000000-0000-0000-0000-000000000000":
    raise SystemExit(1)
print(uid)
PY
)" || canonical_fail "cluster_identity_invalid"
    json_assert_cluster_preflight \
        "$nodes_output" "$pods_output" "$daemonsets_output" \
        "$work_dir/shared-baseline-before.json" \
        || canonical_fail "cluster_profile_mismatch"
}

kernel_uuid() {
    python3 -I - /proc/sys/kernel/random/uuid <<'PY'
from pathlib import Path
import re
import sys

value = Path(sys.argv[1]).read_text(encoding="ascii").strip()
if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
    raise SystemExit(1)
if value == "00000000-0000-0000-0000-000000000000":
    raise SystemExit(1)
print(value)
PY
}

render_namespace() {
    python3 -I - "$1" "$namespace" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

path, namespace, owner = sys.argv[1:]
document = {
    "apiVersion": "v1",
    "kind": "Namespace",
    "metadata": {
        "name": namespace,
        "labels": {
            "apolysis.dev/owner-uuid": owner,
            "apolysis.dev/qualification": "k1-vke",
        },
    },
}
Path(path).write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
PY
}

assert_owned_namespace_identity() {
    local expected_uid="$1"
    kubectl_capture namespace-identity get namespace "$namespace" -o json || return 1
    python3 -I - "$CAPTURE_STDOUT" "$namespace" "$expected_uid" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
metadata = document.get("metadata", {})
labels = metadata.get("labels", {})
if (
    metadata.get("name") != sys.argv[2]
    or metadata.get("uid") != sys.argv[3]
    or labels.get("apolysis.dev/owner-uuid") != sys.argv[4]
    or labels.get("apolysis.dev/qualification") != "k1-vke"
):
    raise SystemExit(1)
PY
}

wait_namespace_absent() {
    local attempt status
    for attempt in {1..180}; do
        if kubectl_capture namespace-absent get namespace "$namespace" -o json; then
            pause_one_second
            continue
        else
            status=$?
        fi
        # A failed GET is accepted only when a second, machine-readable list
        # proves the exact namespace name is absent.
        if kubectl_capture namespace-list get namespaces -o json && \
            python3 -I - "$CAPTURE_STDOUT" "$namespace" <<'PY'
import json
from pathlib import Path
import sys

items = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("items", [])
raise SystemExit(1 if any(item.get("metadata", {}).get("name") == sys.argv[2] for item in items) else 0)
PY
        then
            return 0
        fi
        [[ "$status" != "0" ]] || true
        pause_one_second
    done
    return 1
}

cleanup_owned_namespace() {
    [[ "$mutation_started" == "1" ]] || return 0
    if [[ -z "$namespace_uid" ]]; then
        if kubectl_capture cleanup-recover-namespace get namespace "$namespace" -o json; then
            namespace_uid="$(python3 -I - "$CAPTURE_STDOUT" "$namespace" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("metadata", {})
labels = metadata.get("labels", {})
uid = metadata.get("uid", "")
if (
    metadata.get("name") != sys.argv[2]
    or labels.get("apolysis.dev/owner-uuid") != sys.argv[3]
    or labels.get("apolysis.dev/qualification") != "k1-vke"
    or not uid
):
    raise SystemExit(1)
print(uid)
PY
)" || return 1
        elif kubectl_capture cleanup-recover-list get namespaces -o json && \
            python3 -I - "$CAPTURE_STDOUT" "$namespace" <<'PY'
import json
from pathlib import Path
import sys

items = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("items", [])
raise SystemExit(1 if any(item.get("metadata", {}).get("name") == sys.argv[2] for item in items) else 0)
PY
        then
            cleanup_complete=1
            return 0
        else
            return 1
        fi
    fi
    assert_owned_namespace_identity "$namespace_uid" || return 1
    uid_preconditioned_delete cleanup-namespace "/api/v1/namespaces/$namespace" "$namespace_uid" \
        || return 1
    wait_namespace_absent || return 1
    cleanup_complete=1
}

on_exit() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ "$mutation_started" == "1" && "$cleanup_complete" != "1" ]]; then
        if ! cleanup_owned_namespace; then
            cleanup_attention=1
            printf 'K1 VKE qualification: CLEANUP_REQUIRED (code=owned_namespace_cleanup_failed)\n' >&2
        fi
    fi
    local_cleanup
    if [[ "$cleanup_attention" == "1" ]]; then
        exit 1
    fi
    exit "$status"
}

trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

preflight_cluster

owner_uuid="$(kernel_uuid)" || canonical_fail "kernel_uuid_unavailable"
namespace="apolysis-k1-$owner_uuid"

# Collision check is read-only. A generated identity is never adopted, and a
# failed point GET is never treated as proof of absence.
kubectl_must_capture "namespace_list_unavailable" namespace-collision-list get namespaces -o json
python3 -I - "$CAPTURE_STDOUT" "$namespace" <<'PY' || canonical_fail "namespace_collision"
import json
from pathlib import Path
import sys

items = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("items", [])
if any(item.get("metadata", {}).get("name") == sys.argv[2] for item in items):
    raise SystemExit(1)
PY

create_owned_namespace() {
    render_namespace "$work_dir/namespace.json"
    mutation_started=1
    kubectl_create "namespace_create_failed" create-namespace "$work_dir/namespace.json"
    kubectl_must_capture "namespace_identity_unavailable" created-namespace get namespace "$namespace" -o json
    namespace_uid="$(python3 -I - "$CAPTURE_STDOUT" "$namespace" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
metadata = document.get("metadata", {})
labels = metadata.get("labels", {})
uid = metadata.get("uid", "")
if (
    metadata.get("name") != sys.argv[2]
    or labels.get("apolysis.dev/owner-uuid") != sys.argv[3]
    or labels.get("apolysis.dev/qualification") != "k1-vke"
    or not uid
):
    raise SystemExit(1)
print(uid)
PY
)" || canonical_fail "namespace_identity_mismatch"
}

create_owned_namespace

render_k1_stack() {
    python3 -I - \
        "$1" "$namespace" "$owner_uuid" "$cluster_id" "$collector_image" "$source_image" <<'PY'
import json
from pathlib import Path
import sys

path, namespace, owner, cluster_id, collector_image, source_image = sys.argv[1:]
labels = {
    "app.kubernetes.io/name": "apolysis-k1-qualification",
    "app.kubernetes.io/component": "node-observer",
    "apolysis.dev/owner-uuid": owner,
    "apolysis.dev/qualification": "k1-vke",
}
owner_labels = {
    "apolysis.dev/owner-uuid": owner,
    "apolysis.dev/qualification": "k1-vke",
}
objects = [
    {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "apolysis-kubernetes-source", "namespace": namespace, "labels": owner_labels},
        "automountServiceAccountToken": False,
    },
    {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "apolysis-kubernetes-source", "namespace": namespace, "labels": owner_labels},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["list", "watch"]}],
    },
    {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "apolysis-kubernetes-source", "namespace": namespace, "labels": owner_labels},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "apolysis-kubernetes-source"},
        "subjects": [{"kind": "ServiceAccount", "name": "apolysis-kubernetes-source", "namespace": namespace}],
    },
    {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "apolysis-k1-profile", "namespace": namespace, "labels": owner_labels},
        "data": {"cluster-id": cluster_id},
    },
]

collector = {
    "name": "collector",
    "image": collector_image,
    "imagePullPolicy": "IfNotPresent",
    "args": [
        "--socket", "/run/apolysis/apolysisd.sock",
        "--state-dir", "/var/lib/apolysis",
        "--bpf-object", "/usr/local/lib/apolysis/apolysis_observer.bpf.o",
        "--proc-root", "/host/proc",
        "--cgroup-root", "/host/sys/fs/cgroup",
        "--containerd-socket", "/run/apolysis-host/containerd.sock",
        "--kubernetes-source-socket", "/run/apolysis-kubernetes/source/source.sock",
        "--kubernetes-cluster-id", "$(APOLYSIS_CLUSTER_ID)",
        "--kubernetes-namespace", "$(POD_NAMESPACE)",
        "--kubernetes-node-name", "$(NODE_NAME)",
    ],
    "env": [
        {"name": "APOLYSIS_CRICTL", "value": "/usr/local/bin/crictl"},
        {"name": "APOLYSIS_CLUSTER_ID", "valueFrom": {"configMapKeyRef": {"name": "apolysis-k1-profile", "key": "cluster-id"}}},
        {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
        {"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
    ],
    "resources": {
        "requests": {"cpu": "100m", "memory": "128Mi", "ephemeral-storage": "64Mi"},
        "limits": {"cpu": "1", "memory": "512Mi", "ephemeral-storage": "256Mi"},
    },
    "securityContext": {
        "runAsUser": 0,
        "runAsGroup": 0,
        "privileged": False,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "seccompProfile": {"type": "Unconfined"},
        "capabilities": {"drop": ["ALL"], "add": ["BPF", "PERFMON", "SYS_RESOURCE", "DAC_READ_SEARCH"]},
    },
    "readinessProbe": {
        "exec": {"command": ["/usr/local/bin/apolysisd-health", "--socket", "/run/apolysis/apolysisd.sock", "--require-readiness"]},
        "periodSeconds": 3,
        "timeoutSeconds": 2,
        "failureThreshold": 10,
    },
    "volumeMounts": [
        {"name": "daemon-runtime", "mountPath": "/run/apolysis"},
        {"name": "source-ipc", "mountPath": "/run/apolysis-kubernetes"},
        {"name": "host-proc", "mountPath": "/host/proc", "readOnly": True},
        {"name": "host-cgroup", "mountPath": "/host/sys/fs/cgroup", "readOnly": True},
        {"name": "host-tracing", "mountPath": "/sys/kernel/tracing", "readOnly": True},
        {"name": "host-btf", "mountPath": "/sys/kernel/btf", "readOnly": True},
        {"name": "containerd-socket", "mountPath": "/run/apolysis-host/containerd.sock"},
        {"name": "apolysis-state", "mountPath": "/var/lib/apolysis"},
    ],
}
source = {
    "name": "kubernetes-source",
    "image": source_image,
    "imagePullPolicy": "IfNotPresent",
    "env": [
        {"name": "APOLYSIS_KUBERNETES_SOCKET", "value": "/run/apolysis-kubernetes/source/source.sock"},
        {"name": "APOLYSIS_KUBERNETES_CLUSTER_ID", "valueFrom": {"configMapKeyRef": {"name": "apolysis-k1-profile", "key": "cluster-id"}}},
        {"name": "APOLYSIS_KUBERNETES_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
        {"name": "APOLYSIS_KUBERNETES_NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
    ],
    "resources": {
        "requests": {"cpu": "50m", "memory": "64Mi", "ephemeral-storage": "32Mi"},
        "limits": {"cpu": "250m", "memory": "128Mi", "ephemeral-storage": "64Mi"},
    },
    "securityContext": {
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "runAsGroup": 65532,
        "privileged": False,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "seccompProfile": {"type": "RuntimeDefault"},
        "capabilities": {"drop": ["ALL"]},
    },
    "volumeMounts": [
        {"name": "source-ipc", "mountPath": "/run/apolysis-kubernetes"},
        {"name": "api-access", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True},
    ],
}
volumes = [
    {"name": "daemon-runtime", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
    {"name": "source-ipc", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
    {"name": "apolysis-state", "emptyDir": {"sizeLimit": "128Mi"}},
    {"name": "host-proc", "hostPath": {"path": "/proc", "type": "Directory"}},
    {"name": "host-cgroup", "hostPath": {"path": "/sys/fs/cgroup", "type": "Directory"}},
    {"name": "host-tracing", "hostPath": {"path": "/sys/kernel/tracing", "type": "Directory"}},
    {"name": "host-btf", "hostPath": {"path": "/sys/kernel/btf", "type": "Directory"}},
    {"name": "containerd-socket", "hostPath": {"path": "/run/containerd/containerd.sock", "type": "Socket"}},
    {
        "name": "api-access",
        "projected": {
            "defaultMode": 0o440,
            "sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
                {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                {"downwardAPI": {"items": [{"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}},
            ],
        },
    },
]
objects.append(
    {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": "apolysis-k1", "namespace": namespace, "labels": labels},
        "spec": {
            "selector": {"matchLabels": labels},
            "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": "apolysis-kubernetes-source",
                    "automountServiceAccountToken": False,
                    "hostNetwork": False,
                    "hostPID": False,
                    "nodeSelector": {"kubernetes.io/os": "linux"},
                    "terminationGracePeriodSeconds": 15,
                    "securityContext": {
                        "fsGroup": 65532,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "supplementalGroupsPolicy": "Strict",
                    },
                    "containers": [collector, source],
                    "volumes": volumes,
                },
            },
        },
    }
)
Path(path).write_text(
    json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}, separators=(",", ":")),
    encoding="utf-8",
)
PY
}

render_k1_stack "$work_dir/k1-stack.json"
kubectl_create "k1_stack_create_failed" create-stack "$work_dir/k1-stack.json"

wait_collectors_ready() {
    local attempt
    for attempt in {1..180}; do
        if kubectl_capture collector-pods -n "$namespace" get pods \
            -l app.kubernetes.io/name=apolysis-k1-qualification -o json && \
            python3 -I - "$CAPTURE_STDOUT" "$work_dir/collectors.json" <<'PY'
import json
from pathlib import Path
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
mapping = {}
for pod in document.get("items", []):
    status = pod.get("status", {})
    node = pod.get("spec", {}).get("nodeName")
    name = pod.get("metadata", {}).get("name")
    uid = pod.get("metadata", {}).get("uid")
    ready = {entry.get("name"): entry.get("ready") for entry in status.get("containerStatuses", []) or []}
    if status.get("phase") != "Running" or ready != {"collector": True, "kubernetes-source": True}:
        continue
    if not all(isinstance(value, str) and value for value in (node, name, uid)) or node in mapping:
        raise SystemExit(1)
    mapping[node] = {"name": name, "uid": uid}
if len(mapping) != 3:
    raise SystemExit(1)
Path(sys.argv[2]).write_text(json.dumps(mapping, sort_keys=True, separators=(",", ":")), encoding="utf-8")
PY
        then
            return 0
        fi
        pause_one_second
    done
    return 1
}

wait_collectors_ready || canonical_fail "collectors_not_ready"

node_value() {
    python3 -I - "$work_dir/shared-baseline-before.json.nodes" "$1" <<'PY'
import json
from pathlib import Path
import sys

nodes = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
index = int(sys.argv[2])
print(nodes[index]["name"])
PY
}

node_hostname() {
    python3 -I - "$work_dir/shared-baseline-before.json.nodes" "$1" <<'PY'
import json
from pathlib import Path
import sys

nodes = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
index = int(sys.argv[2])
print(nodes[index]["hostname"])
PY
}

collector_for_node() {
    python3 -I - "$work_dir/collectors.json" "$1" <<'PY'
import json
from pathlib import Path
import sys

mapping = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(mapping[sys.argv[2]]["name"])
PY
}

readonly first_node="$(node_value 0)"
readonly first_hostname="$(node_hostname 0)"
readonly second_node="$(node_value 1)"
readonly second_hostname="$(node_hostname 1)"
readonly first_collector="$(collector_for_node "$first_node")"
readonly second_collector="$(collector_for_node "$second_node")"

probe_collector_node() {
    local collector="$1"
    local stem="$2"
    kubectl_must_capture "node_probe_failed" "$stem" -n "$namespace" exec "$collector" \
        -c collector -- /usr/bin/bash -ceu \
        'export LC_ALL=C; test -r /host/sys/fs/cgroup/cgroup.controllers; test -r /sys/kernel/btf/vmlinux; grep -E "^(Uid|Gid|Groups|CapEff):" /proc/1/status; stat -Lc "Parent:%u:%g:%a:%F" /run/apolysis-kubernetes/source; stat -Lc "Socket:%u:%g:%a:%F" /run/apolysis-kubernetes/source/source.sock'
    python3 -I - "$CAPTURE_STDOUT" <<'PY'
from pathlib import Path
import re
import sys

lines = Path(sys.argv[1]).read_text(encoding="ascii").splitlines()
if len(lines) != 6:
    raise SystemExit(1)
patterns = (
    r"Uid:\s+0\s+0\s+0\s+0",
    r"Gid:\s+0\s+0\s+0\s+0",
    r"Groups:\s+65532\s*",
    r"CapEff:\s+([0-9a-fA-F]+)",
    r"Parent:65532:65532:700:directory",
    r"Socket:65532:65532:660:socket",
)
matches = [re.fullmatch(pattern, line) for pattern, line in zip(patterns, lines)]
if any(match is None for match in matches):
    raise SystemExit(1)
capabilities = int(matches[3].group(1), 16)
# DAC_READ_SEARCH=2, SYS_RESOURCE=24, PERFMON=38, BPF=39.
required = (1 << 2) | (1 << 24) | (1 << 38) | (1 << 39)
if capabilities != required:
    raise SystemExit(1)
PY
}

for probe_index in 0 1 2; do
    probe_node="$(node_value "$probe_index")"
    probe_collector_node "$(collector_for_node "$probe_node")" "node-probe-$probe_index" \
        || canonical_fail "node_capability_profile_mismatch"
done

kubernetes_ref() {
    python3 -I - "$1" "$2" <<'PY'
import hashlib
import sys

kind, raw = sys.argv[1:]
digest = hashlib.sha256(
    b"apolysis:kubernetes-reference:v1" + b"\0" + kind.encode("ascii") + b"\0" + raw.encode("ascii")
).hexdigest()
print(digest)
PY
}

render_workload() {
    local path="$1" pod_name="$2" node_hostname_value="$3"
    # Reuse the digest-pinned collector image as an unprivileged shell fixture;
    # the Pod overrides its entrypoint, drops every capability, receives no
    # token or host mount, and avoids introducing a third image trust input.
    python3 -I - "$path" "$namespace" "$owner_uuid" "$pod_name" \
        "$node_hostname_value" "$collector_image" <<'PY'
import json
from pathlib import Path
import sys

path, namespace, owner, name, hostname, image = sys.argv[1:]
labels = {
    "apolysis.dev/owner-uuid": owner,
    "apolysis.dev/qualification": "k1-vke",
    "apolysis.dev/observe": "true",
}
document = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": name,
        "namespace": namespace,
        "labels": labels,
        # The exact session-id annotation is D1 routing evidence only. The K1
        # metadata source does not read it as authority; the typed K1 claim
        # enters exclusively through control.
        "annotations": {"apolysis.dev/session-id": f"k1-vke-{owner[:12]}"},
    },
    "spec": {
        "automountServiceAccountToken": False,
        "restartPolicy": "Always",
        "nodeSelector": {"kubernetes.io/hostname": hostname},
        "terminationGracePeriodSeconds": 5,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532},
        "containers": [
            {
                "name": "workload",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-ceu"],
                "args": ["trap 'exit 0' TERM INT; while :; do sleep 3600; done"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "resources": {
                    "requests": {"cpu": "5m", "memory": "8Mi", "ephemeral-storage": "8Mi"},
                    "limits": {"cpu": "100m", "memory": "32Mi", "ephemeral-storage": "32Mi"},
                },
                "volumeMounts": [{"name": "work", "mountPath": "/work"}],
            }
        ],
        "volumes": [{"name": "work", "emptyDir": {"sizeLimit": "8Mi"}}],
    },
}
Path(path).write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
PY
}

wait_workload_identity() {
    local pod_name="$1" expected_node="$2" output="$3" minimum_restart="$4"
    local attempt
    for attempt in {1..180}; do
        if kubectl_capture "workload-$pod_name" -n "$namespace" get pod "$pod_name" -o json && \
            python3 -I - "$CAPTURE_STDOUT" "$expected_node" "$output" "$minimum_restart" <<'PY'
import json
from pathlib import Path
import re
import sys

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
status = document.get("status", {})
metadata = document.get("metadata", {})
statuses = status.get("containerStatuses", []) or []
if status.get("phase") != "Running" or document.get("spec", {}).get("nodeName") != sys.argv[2] or len(statuses) != 1:
    raise SystemExit(1)
entry = statuses[0]
container_id = entry.get("containerID", "")
if entry.get("name") != "workload" or not entry.get("ready") or int(entry.get("restartCount", 0)) < int(sys.argv[4]):
    raise SystemExit(1)
match = re.fullmatch(r"containerd://([0-9a-f]{64})", container_id)
uid = metadata.get("uid", "")
if match is None or not re.fullmatch(r"[0-9a-f-]{36}", uid):
    raise SystemExit(1)
Path(sys.argv[3]).write_text(
    json.dumps(
        {
            "pod_uid": uid,
            "full_container_id": match.group(1),
            "restart_count": int(entry.get("restartCount", 0)),
            "pod_name": metadata.get("name"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="utf-8",
)
PY
        then
            return 0
        fi
        pause_one_second
    done
    return 1
}

json_field() {
    python3 -I - "$1" "$2" <<'PY'
import json
from pathlib import Path
import sys

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))[sys.argv[2]])
PY
}

readonly workload_one_name="k1-workload-a"
render_workload "$work_dir/workload-one.json" "$workload_one_name" "$first_hostname"
kubectl_create "workload_create_failed" create-workload-one "$work_dir/workload-one.json"
wait_workload_identity "$workload_one_name" "$first_node" "$work_dir/workload-one-before.json" 0 \
    || canonical_fail "workload_not_ready"

readonly session_id="k1-vke-${owner_uuid:0:12}"
readonly namespace_ref="$(kubernetes_ref namespace "$namespace")"
readonly container_ref="$(kubernetes_ref container workload)"

render_intent_request() {
    local path="$1" pod_uid_value="$2" revision="$3"
    python3 -I - "$path" "$session_id" "$cluster_id" "$namespace_ref" \
        "$container_ref" "$pod_uid_value" "$revision" <<'PY'
import json
from pathlib import Path
import sys
import time

path, session, cluster, namespace_ref, container_ref, pod_uid, revision = sys.argv[1:]
request = {
    "type": "register",
    "intent": {
        "schema_version": 1,
        "tenant_id": "default",
        "retention_tier": "short",
        "session_id": session,
        "expires_at_unix_ms": int(time.time() * 1000) + 7_200_000,
        "declared_actions": ["test", "read_file", "write_file"],
        "allowed_resources": [],
        "workload_selectors": [],
        "kubernetes_claims": [
            {
                "schema_version": 1,
                "claim_revision": int(revision),
                "cluster_id": cluster,
                "namespace_ref": namespace_ref,
                "pod_uid": pod_uid,
                "container_kind": "application",
                "container_ref": container_ref,
            }
        ],
    },
}
Path(path).write_text(json.dumps(request, separators=(",", ":")), encoding="utf-8")
PY
}

render_query_request() {
    local path="$1"
    python3 -I - "$path" "$session_id" <<'PY'
import json
from pathlib import Path
import sys

Path(sys.argv[1]).write_text(
    json.dumps({"type": "query", "tenant_id": "default", "session_id": sys.argv[2]}, separators=(",", ":")),
    encoding="utf-8",
)
PY
}

control_request() {
    local collector="$1" request_path="$2" stem="$3"
    kubectl_capture_with_input "$stem" "$request_path" -n "$namespace" exec -i "$collector" \
        -c collector -- /usr/local/bin/apolysisd-control \
        --socket /run/apolysis/apolysisd.sock --timeout-ms 2000
}

assert_ack() {
    python3 -I - "$1" "$2" "$session_id" <<'PY'
import json
from pathlib import Path
import sys

response = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if response != {"type": "ack", "schema_version": 1, "operation": sys.argv[2], "session_id": sys.argv[3]}:
    raise SystemExit(1)
PY
}

query_until_exact() {
    local collector="$1" pod_uid_value="$2" full_container_id="$3" evidence_path="$4"
    local attempt
    for attempt in {1..120}; do
        if control_request "$collector" "$work_dir/query.json" "query-exact-$attempt" && \
            python3 -I - "$CAPTURE_STDOUT" "$session_id" "$pod_uid_value" \
                "$full_container_id" "$container_ref" "$evidence_path" <<'PY'
import json
from pathlib import Path
import sys

response = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
session, pod_uid, container_id, container_ref, evidence_path = sys.argv[2:]
if response.get("type") != "session" or response.get("schema_version") != 1:
    raise SystemExit(1)
bindings = response.get("runtime_bindings", [])
attributions = response.get("kubernetes_attributions", [])
workload_id = f"containerd/{container_id}"
binding = next(
    (
        entry
        for entry in bindings
        if entry.get("agent_run_id") == session
        and entry.get("identity", {}).get("adapter") == "containerd"
        and entry.get("identity", {}).get("workload_id") == workload_id
    ),
    None,
)
attribution = next(
    (
        entry
        for entry in attributions
        if entry.get("record_type") == "kubernetes_attribution_observed"
        and entry.get("agent_run_id") == session
        and entry.get("pod_uid") == pod_uid
        and entry.get("container_ref") == container_ref
        and entry.get("runtime_binding", {}).get("workload_id") == workload_id
    ),
    None,
)
if binding is None or attribution is None:
    raise SystemExit(1)
identity = binding["identity"]
if attribution["runtime_binding"].get("start_marker") != identity.get("start_marker"):
    raise SystemExit(1)
Path(evidence_path).write_text(
    json.dumps(
        {
            "pod_uid": pod_uid,
            "full_container_id": container_id,
            "start_marker": identity.get("start_marker"),
            "cgroup": identity.get("cgroup"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="utf-8",
)
PY
        then
            return 0
        fi
        pause_one_second
    done
    return 1
}

query_until_k1_suspended_d1_active() {
    local collector="$1" full_container_id="$2"
    local attempt
    for attempt in {1..120}; do
        if control_request "$collector" "$work_dir/query.json" "query-suspended-$attempt" && \
            python3 -I - "$CAPTURE_STDOUT" "$session_id" "$full_container_id" <<'PY'
import json
from pathlib import Path
import sys

response = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
session, container_id = sys.argv[2:]
workload_id = f"containerd/{container_id}"
bindings = response.get("runtime_bindings", [])
kubernetes = response.get("kubernetes_attributions", [])
if kubernetes:
    raise SystemExit(1)
if not any(
    entry.get("agent_run_id") == session
    and entry.get("identity", {}).get("workload_id") == workload_id
    for entry in bindings
):
    raise SystemExit(1)
PY
        then
            return 0
        fi
        pause_one_second
    done
    return 1
}

render_query_request "$work_dir/query.json"
pod_uid="$(json_field "$work_dir/workload-one-before.json" pod_uid)"
full_container_id="$(json_field "$work_dir/workload-one-before.json" full_container_id)"
render_intent_request "$work_dir/register-one.json" "$pod_uid" 1
control_request "$first_collector" "$work_dir/register-one.json" register-one \
    || canonical_fail "operator_register_failed"
assert_ack "$CAPTURE_STDOUT" register || canonical_fail "operator_register_rejected"

query_until_exact "$first_collector" "$pod_uid" "$full_container_id" "$work_dir/exact-before.json" \
    || canonical_fail "initial_exact_attribution_missing"

trigger_file_event() {
    local pod_name="$1" stem="$2"
    kubectl_must_capture "file_event_failed" "$stem" -n "$namespace" exec "$pod_name" \
        -c workload -- /bin/sh -ceu 'printf "%s\n" k1-vke > /work/observed-event'
}

trigger_file_event "$workload_one_name" trigger-file-event

verify_timeline_hash_chain() {
    local collector="$1" summary_path="$2" required_csv="$3" stem="$4"
    kubectl_must_capture "timeline_export_failed" "$stem" -n "$namespace" exec "$collector" \
        -c collector -- /usr/bin/base64 -w0 "/var/lib/apolysis/sessions/$session_id/timeline.jsonl"
    python3 -I - "$CAPTURE_STDOUT" "$summary_path" "$required_csv" \
        "$namespace" "$workload_one_name" <<'PY'
import base64
import hashlib
import json
from pathlib import Path
import sys

encoded_path, summary_path, required_csv, namespace, workload_name = sys.argv[1:]
try:
    raw = base64.b64decode(Path(encoded_path).read_bytes(), validate=True)
except Exception:
    raise SystemExit(1)
if not raw or not raw.endswith(b"\n"):
    raise SystemExit(1)
previous = "0" * 64
sequence = 0
observed = {}
positions = {}
for line in raw.splitlines():
    record = json.loads(line)
    sequence += 1
    if record.get("sequence") != sequence or record.get("previous_hash") != previous:
        raise SystemExit(1)
    payload = record.get("payload")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(
        int(record.get("schema_version")).to_bytes(4, "big")
        + sequence.to_bytes(8, "big")
        + previous.encode("ascii")
        + canonical
    ).hexdigest()
    if record.get("record_hash") != digest:
        raise SystemExit(1)
    previous = digest
    tokens = []
    if isinstance(payload, dict):
        for field in ("record_type", "kind"):
            value = payload.get(field)
            if isinstance(value, str):
                tokens.append(value)
        detail = payload.get("detail")
        if isinstance(detail, str):
            for candidate in (
                "kubernetes_api_unavailable",
                "kubernetes_identity_transition",
                "kubernetes_late_attach",
            ):
                if candidate in detail:
                    tokens.append(candidate)
    for token in tokens:
        observed[token] = observed.get(token, 0) + 1
        positions.setdefault(token, []).append(sequence)
    previous = record["record_hash"]

# Raw Kubernetes names must not be persisted by the collector. The Pod UID and
# stable hashed references are intentionally permitted by the public contract.
decoded = raw.decode("utf-8")
if namespace in decoded or workload_name in decoded:
    raise SystemExit(1)
for required in filter(None, required_csv.split(",")):
    if observed.get(required, 0) == 0:
        raise SystemExit(1)
Path(summary_path).write_text(
    json.dumps(
        {"records": sequence, "last_hash": previous, "counts": observed, "positions": positions},
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="utf-8",
)
PY
}

wait_timeline_contract() {
    local collector="$1" summary="$2" required="$3" stem="$4"
    local attempt
    for attempt in {1..120}; do
        if verify_timeline_hash_chain "$collector" "$summary" "$required" "$stem-$attempt"; then
            return 0
        fi
        pause_one_second
    done
    return 1
}

assert_timeline_order() {
    local summary="$1" mode="$2"
    python3 -I - "$summary" "$mode" <<'PY'
import json
from pathlib import Path
import sys

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
positions = summary.get("positions", {})


def first(token):
    values = positions.get(token, [])
    if not values:
        raise SystemExit(1)
    return values[0]


def last(token):
    values = positions.get(token, [])
    if not values:
        raise SystemExit(1)
    return values[-1]


mode = sys.argv[2]
if mode == "initial":
    valid = first("runtime_binding_observed") < first("kubernetes_attribution_observed") < last("observed_kernel_event")
elif mode == "replacement":
    valid = (
        last("kubernetes_identity_transition")
        < last("kubernetes_attribution_retired")
        < last("runtime_binding_retired")
        < last("runtime_binding_observed")
        < last("kubernetes_attribution_observed")
    )
elif mode == "outage":
    valid = (
        last("kubernetes_metadata_unavailable")
        < last("kubernetes_attribution_suspended")
        and summary.get("counts", {}).get("runtime_binding_suspended", 0) == 0
    )
elif mode == "recovery":
    valid = last("kubernetes_attribution_suspended") < last("kubernetes_attribution_observed")
else:
    raise SystemExit(1)
raise SystemExit(0 if valid else 1)
PY
}

wait_timeline_contract "$first_collector" "$work_dir/timeline-initial.json" \
    "runtime_binding_observed,kubernetes_attribution_observed,observed_kernel_event" timeline-initial \
    || canonical_fail "initial_timeline_contract_missing"
assert_timeline_order "$work_dir/timeline-initial.json" initial \
    || canonical_fail "initial_timeline_order_invalid"

same_pod_restart() {
    local pod_name="$1"
    kubectl_must_capture "same_pod_restart_failed" same-pod-restart -n "$namespace" exec "$pod_name" \
        -c workload -- /bin/sh -ceu 'kill -TERM 1'
}

same_pod_restart "$workload_one_name"
wait_workload_identity "$workload_one_name" "$first_node" "$work_dir/workload-one-after.json" 1 \
    || canonical_fail "same_pod_replacement_not_ready"

python3 -I - "$work_dir/workload-one-before.json" "$work_dir/workload-one-after.json" <<'PY' \
    || canonical_fail "same_pod_identity_transition_missing"
import json
from pathlib import Path
import sys

before, after = (json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:])
if before["pod_uid"] != after["pod_uid"] or before["full_container_id"] == after["full_container_id"]:
    raise SystemExit(1)
PY

full_container_id="$(json_field "$work_dir/workload-one-after.json" full_container_id)"
query_until_exact "$first_collector" "$pod_uid" "$full_container_id" "$work_dir/exact-after.json" \
    || canonical_fail "replacement_exact_attribution_missing"
python3 -I - "$work_dir/exact-before.json" "$work_dir/exact-after.json" <<'PY' \
    || canonical_fail "replacement_runtime_identity_unchanged"
import json
from pathlib import Path
import sys

before, after = (json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:])
if (
    before["pod_uid"] != after["pod_uid"]
    or before["full_container_id"] == after["full_container_id"]
    or before["start_marker"] == after["start_marker"]
    or before["cgroup"] == after["cgroup"]
):
    raise SystemExit(1)
PY

wait_timeline_contract "$first_collector" "$work_dir/timeline-restart.json" \
    "kubernetes_identity_transition,kubernetes_attribution_retired,runtime_binding_retired,runtime_binding_observed,kubernetes_attribution_observed" \
    timeline-restart || canonical_fail "replacement_timeline_contract_missing"
assert_timeline_order "$work_dir/timeline-restart.json" replacement \
    || canonical_fail "replacement_timeline_order_invalid"

render_source_outage() {
    python3 -I - "$1" "$namespace" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

path, namespace, owner = sys.argv[1:]
document = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {
        "name": "source-proxy-outage",
        "namespace": namespace,
        "labels": {
            "apolysis.dev/owner-uuid": owner,
            "apolysis.dev/qualification": "k1-vke",
        },
    },
    "spec": {
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "apolysis-k1-qualification"}},
        "policyTypes": ["Egress"],
        "egress": [],
    },
}
Path(path).write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
PY
}

object_uid() {
    local kind="$1" name="$2" stem="$3"
    kubectl_must_capture "owned_object_identity_unavailable" "$stem" -n "$namespace" get "$kind" "$name" -o json
    python3 -I - "$CAPTURE_STDOUT" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("metadata", {})
labels = metadata.get("labels", {})
uid = metadata.get("uid", "")
if (
    not uid
    or labels.get("apolysis.dev/owner-uuid") != sys.argv[2]
    or labels.get("apolysis.dev/qualification") != "k1-vke"
):
    raise SystemExit(1)
print(uid)
PY
}

assert_owned_object_identity() {
    local kind="$1" name="$2" expected_uid="$3" stem="$4"
    kubectl_capture "$stem" -n "$namespace" get "$kind" "$name" -o json || return 1
    python3 -I - "$CAPTURE_STDOUT" "$expected_uid" "$owner_uuid" <<'PY'
import json
from pathlib import Path
import sys

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("metadata", {})
labels = metadata.get("labels", {})
if (
    metadata.get("uid") != sys.argv[2]
    or labels.get("apolysis.dev/owner-uuid") != sys.argv[3]
    or labels.get("apolysis.dev/qualification") != "k1-vke"
):
    raise SystemExit(1)
PY
}

wait_namespaced_object_absent() {
    local kind="$1" name="$2" expected_uid="$3" stem="$4"
    local attempt list_status
    for attempt in {1..180}; do
        if kubectl_capture "$stem-get-$attempt" -n "$namespace" get "$kind" "$name" -o json; then
            python3 -I - "$CAPTURE_STDOUT" "$name" "$expected_uid" <<'PY' || return 1
import json
from pathlib import Path
import sys

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("metadata", {})
if metadata.get("name") != sys.argv[2] or metadata.get("uid") != sys.argv[3]:
    raise SystemExit(1)
PY
        elif kubectl_capture "$stem-list-$attempt" -n "$namespace" get "$kind" -o json; then
            if python3 -I - "$CAPTURE_STDOUT" "$name" "$expected_uid" <<'PY'
import json
from pathlib import Path
import sys

items = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("items", [])
matches = [item for item in items if item.get("metadata", {}).get("name") == sys.argv[2]]
if not matches:
    raise SystemExit(0)
if len(matches) == 1 and matches[0].get("metadata", {}).get("uid") == sys.argv[3]:
    raise SystemExit(2)
raise SystemExit(3)
PY
            then
                return 0
            else
                list_status=$?
                [[ "$list_status" == "2" ]] || return 1
            fi
        fi
        pause_one_second
    done
    return 1
}

# source_proxy_outage is namespace-owned egress isolation. Only the metadata
# source performs network I/O; the collector's D1 inventory and BPF paths stay
# node-local. The policy never targets a shared Pod or modifies CNI/iptables.
source_proxy_outage() {
    render_source_outage "$work_dir/source-outage.json"
    kubectl_create "source_outage_create_failed" create-source-outage "$work_dir/source-outage.json"
    source_outage_uid="$(object_uid networkpolicy source-proxy-outage source-outage-uid)" \
        || canonical_fail "source_outage_identity_mismatch"
}

source_proxy_outage
query_until_k1_suspended_d1_active "$first_collector" "$full_container_id" \
    || canonical_fail "source_outage_did_not_suspend_k1"
wait_timeline_contract "$first_collector" "$work_dir/timeline-outage.json" \
    "kubernetes_metadata_unavailable,kubernetes_attribution_suspended" timeline-outage \
    || canonical_fail "source_outage_timeline_contract_missing"
assert_timeline_order "$work_dir/timeline-outage.json" outage \
    || canonical_fail "source_outage_timeline_order_invalid"

assert_runtime_binding_remains() {
    query_until_k1_suspended_d1_active "$1" "$2"
}
assert_runtime_binding_remains "$first_collector" "$full_container_id" \
    || canonical_fail "source_outage_suspended_d1"

assert_owned_object_identity networkpolicy source-proxy-outage "$source_outage_uid" source-outage-delete-proof \
    || canonical_fail "source_outage_identity_changed"
uid_preconditioned_delete delete-source-outage \
    "/apis/networking.k8s.io/v1/namespaces/$namespace/networkpolicies/source-proxy-outage" \
    "$source_outage_uid" || canonical_fail "source_outage_delete_failed"
wait_namespaced_object_absent networkpolicy source-proxy-outage "$source_outage_uid" \
    source-outage-delete-wait || canonical_fail "source_outage_delete_incomplete"

fresh_recovery() {
    query_until_exact "$first_collector" "$pod_uid" "$full_container_id" "$work_dir/exact-recovered.json" \
        || return 1
    wait_timeline_contract "$first_collector" "$work_dir/timeline-recovered.json" \
        "kubernetes_metadata_unavailable,kubernetes_attribution_suspended,kubernetes_attribution_observed" \
        timeline-recovered || return 1
    assert_timeline_order "$work_dir/timeline-recovered.json" recovery || return 1
    python3 -I - "$work_dir/timeline-outage.json" "$work_dir/timeline-recovered.json" <<'PY'
import json
from pathlib import Path
import sys

outage, recovered = (json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:])
if recovered.get("records", 0) <= outage.get("records", 0):
    raise SystemExit(1)
if recovered.get("counts", {}).get("kubernetes_attribution_observed", 0) <= outage.get("counts", {}).get("kubernetes_attribution_observed", 0):
    raise SystemExit(1)
PY
}
fresh_recovery || canonical_fail "source_recovery_missing"

delete_owned_pod() {
    local pod_name="$1" expected_uid="$2" stem="$3"
    assert_owned_object_identity pod "$pod_name" "$expected_uid" "$stem-proof" || return 1
    uid_preconditioned_delete "$stem" "/api/v1/namespaces/$namespace/pods/$pod_name" "$expected_uid" \
        || return 1
    wait_namespaced_object_absent pod "$pod_name" "$expected_uid" "$stem-delete-wait"
}

cross_node_handoff() {
    local old_pod_uid="$1"
    delete_owned_pod "$workload_one_name" "$old_pod_uid" old-workload || return 1
    render_workload "$work_dir/workload-two.json" k1-workload-b "$second_hostname"
    kubectl_create "handoff_workload_create_failed" create-workload-two "$work_dir/workload-two.json"
    wait_workload_identity k1-workload-b "$second_node" "$work_dir/workload-two.json.identity" 0 || return 1

    local new_pod_uid
    new_pod_uid="$(json_field "$work_dir/workload-two.json.identity" pod_uid)" || return 1
    local new_container_id
    new_container_id="$(json_field "$work_dir/workload-two.json.identity" full_container_id)" || return 1
    [[ "$new_pod_uid" != "$old_pod_uid" ]] || return 1

    # Revision 2 reaches the old collector first, forcing old K1 retirement,
    # then the new collector. A new Pod UID is a new K1 key; this boundary must
    # never be mislabeled as a same-key kubernetes_identity_transition.
    render_intent_request "$work_dir/register-two.json" "$new_pod_uid" 2
    control_request "$first_collector" "$work_dir/register-two.json" handoff-register-old || return 1
    assert_ack "$CAPTURE_STDOUT" register || return 1
    control_request "$second_collector" "$work_dir/register-two.json" handoff-register-new || return 1
    assert_ack "$CAPTURE_STDOUT" register || return 1
    query_until_exact "$second_collector" "$new_pod_uid" "$new_container_id" "$work_dir/handoff-new-exact.json" || return 1
    trigger_file_event k1-workload-b handoff-file-event
    wait_timeline_contract "$first_collector" "$work_dir/handoff-old-timeline.json" \
        "kubernetes_attribution_retired" handoff-old || return 1
    wait_timeline_contract "$second_collector" "$work_dir/handoff-new-timeline.json" \
        "runtime_binding_observed,kubernetes_attribution_observed,observed_kernel_event" handoff-new || return 1
    python3 -I - \
        "$work_dir/handoff-old-timeline.json" "$work_dir/handoff-new-timeline.json" \
        "$old_pod_uid" "$new_pod_uid" "$work_dir/handoff-boundary.json" <<'PY'
import json
from pathlib import Path
import sys

old_timeline, new_timeline, old_uid, new_uid, output = sys.argv[1:]
old = json.loads(Path(old_timeline).read_text(encoding="utf-8"))
new = json.loads(Path(new_timeline).read_text(encoding="utf-8"))
if old_uid == new_uid:
    raise SystemExit(1)
if old.get("counts", {}).get("kubernetes_attribution_retired", 0) < 1:
    raise SystemExit(1)
if new.get("counts", {}).get("kubernetes_attribution_observed", 0) < 1:
    raise SystemExit(1)
boundary_kind = (
    "kubernetes_late_attach"
    if new.get("counts", {}).get("kubernetes_late_attach", 0) > 0
    else "same_cycle_attach"
)
Path(output).write_text(
    json.dumps(
        {
            "old_pod_uid": old_uid,
            "new_pod_uid": new_uid,
            "old_claim_revision": 1,
            "new_claim_revision": 2,
            "handoff_boundary": boundary_kind,
            "old_retired": True,
            "new_observed": True,
        },
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="utf-8",
)
PY
}

cross_node_handoff "$pod_uid" || canonical_fail "cross_node_handoff_failed"

cleanup_owned_namespace || {
    cleanup_attention=1
    canonical_fail "owned_namespace_cleanup_failed"
}

assert_shared_baseline_unchanged() {
    kubectl_must_capture "postflight_nodes_unavailable" postflight-nodes get nodes -o json
    local nodes_output="$CAPTURE_STDOUT"
    kubectl_must_capture "postflight_pods_unavailable" postflight-pods get pods --all-namespaces -o json
    local pods_output="$CAPTURE_STDOUT"
    kubectl_must_capture "postflight_daemonsets_unavailable" postflight-daemonsets get daemonsets --all-namespaces -o json
    local daemonsets_output="$CAPTURE_STDOUT"
    json_assert_cluster_preflight \
        "$nodes_output" "$pods_output" "$daemonsets_output" \
        "$work_dir/shared-baseline-after.json" || return 1
    python3 -I - "$work_dir/shared-baseline-before.json" "$work_dir/shared-baseline-after.json" <<'PY'
from pathlib import Path
import sys

if Path(sys.argv[1]).read_bytes() != Path(sys.argv[2]).read_bytes():
    raise SystemExit(1)
PY
}

assert_shared_baseline_unchanged || canonical_fail "shared_cluster_baseline_changed"

# SKIP is not PASS: this line is reachable only after every evidence stage and
# explicit, identity-checked cleanup has completed.
trap - EXIT HUP INT TERM
local_cleanup
[[ "$cleanup_attention" == "0" ]] || canonical_fail "local_cleanup_failed"
printf 'K1 VKE qualification: PASS\n'

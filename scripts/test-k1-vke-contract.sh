#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly gate_path="$project_root/scripts/qualify-k1-vke.sh"

contract_tmp="$(mktemp -d "/tmp/apolysis-k1-vke-contract.XXXXXXXX")"
chmod 0700 "$contract_tmp"
cleanup_contract_tmp() {
    case "$contract_tmp" in
        /tmp/apolysis-k1-vke-contract.*)
            rm -rf -- "$contract_tmp"
            ;;
        *)
            return 1
            ;;
    esac
}
trap cleanup_contract_tmp EXIT

[[ -f "$gate_path" ]] || {
    printf 'K1 VKE gate contract: missing scripts/qualify-k1-vke.sh\n' >&2
    exit 1
}

skip_output="$(env -u APOLYSIS_K1_VKE_LIVE bash "$gate_path")"
[[ "$skip_output" == "K1 VKE qualification: SKIP (set APOLYSIS_K1_VKE_LIVE=1)" ]] || {
    printf 'K1 VKE gate contract: disabled gate did not return the canonical SKIP\n' >&2
    exit 1
}

python3 -I - "$contract_tmp/kubectl" "$contract_tmp/kubectl-called" <<'PY'
from pathlib import Path
import sys

kubectl, marker = map(Path, sys.argv[1:])
kubectl.write_text(f"#!/usr/bin/env bash\nprintf called > {marker}\nexit 99\n", encoding="utf-8")
kubectl.chmod(0o700)
PY

# A disabled gate must not merely avoid mutation; it must not execute kubectl
# at all, even when an executable with that name is available.
disabled_with_stub="$(
    env -u APOLYSIS_K1_VKE_LIVE PATH="$contract_tmp:$PATH" bash "$gate_path"
)"
[[ "$disabled_with_stub" == "K1 VKE qualification: SKIP (set APOLYSIS_K1_VKE_LIVE=1)" ]]
[[ ! -e "$contract_tmp/kubectl-called" ]] || {
    printf 'K1 VKE gate contract: disabled gate accessed kubectl\n' >&2
    exit 1
}

missing_kubeconfig_skip="$(
    env PATH="$contract_tmp:$PATH" \
        KUBECONFIG="$contract_tmp/missing-kubeconfig" \
        APOLYSIS_K1_VKE_LIVE=1 \
        APOLYSIS_K1_COLLECTOR_IMAGE="example.invalid/collector@sha256:$(printf '1%.0s' {1..64})" \
        APOLYSIS_K1_SOURCE_IMAGE="example.invalid/source@sha256:$(printf '2%.0s' {1..64})" \
        bash "$gate_path"
)"
[[ "$missing_kubeconfig_skip" == "K1 VKE qualification: SKIP (designated kubeconfig unavailable)" ]]
[[ ! -e "$contract_tmp/kubectl-called" ]] || {
    printf 'K1 VKE gate contract: missing kubeconfig preflight accessed kubectl\n' >&2
    exit 1
}

# An invalid operator-provided image trust input stops before the first cluster read.
printf 'fixture only; must never be read by the contract\n' > "$contract_tmp/kubeconfig"
chmod 0600 "$contract_tmp/kubeconfig"
preflight_skip="$(
    env PATH="$contract_tmp:$PATH" \
        KUBECONFIG="$contract_tmp/kubeconfig" \
        APOLYSIS_K1_VKE_LIVE=1 \
        APOLYSIS_K1_COLLECTOR_IMAGE=mutable-tag \
        APOLYSIS_K1_SOURCE_IMAGE="example.invalid/source@sha256:$(printf '1%.0s' {1..64})" \
        bash "$gate_path"
)"
[[ "$preflight_skip" == "K1 VKE qualification: SKIP (collector image is not digest pinned)" ]]
[[ ! -e "$contract_tmp/kubectl-called" ]] || {
    printf 'K1 VKE gate contract: invalid image trust input accessed kubectl\n' >&2
    exit 1
}

python3 -I - "$gate_path" "$project_root/Makefile" <<'PY'
from pathlib import Path
import re
import sys

gate = Path(sys.argv[1]).read_text(encoding="utf-8")
makefile = Path(sys.argv[2]).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f"missing {label}: {needle!r}")


def require_regex(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern!r}")


def forbid(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None:
        raise AssertionError(f"forbidden {label}: {pattern!r}")


def ordered(text: str, first: str, second: str, label: str) -> None:
    first_at = text.find(first)
    second_at = text.find(second)
    if first_at < 0 or second_at < 0 or first_at >= second_at:
        raise AssertionError(
            f"unsafe ordering for {label}: {first!r} before {second!r}"
        )


# Explicit opt-in, fixed VKE default, and two operator-provided digest image
# trust inputs are required before the first cluster read or mutation.
require(gate, 'APOLYSIS_K1_VKE_LIVE:-0', "explicit live opt-in")
require(
    gate,
    "/home/mactavish/vultr-k8s/vke-a88389c3-f720-412d-9579-c83d3c21eabb.yaml",
    "designated VKE kubeconfig default",
)
require(gate, "APOLYSIS_K1_COLLECTOR_IMAGE", "collector image input")
require(gate, "APOLYSIS_K1_SOURCE_IMAGE", "source image input")
forbid(gate, r"APOLYSIS_K1_WORKLOAD_IMAGE", "a third image trust input")
require(gate, "@sha256:", "digest-pinned image validation")
require(gate, "operator-provided artifact trust inputs", "honest image trust boundary")
require(gate, "validates digest syntax only", "digest-shape-only claim")
forbid(
    gate,
    r"(?:local_verifier|validate_local_verifier|apolysis-release-verifier|APOLYSIS_K1_RELEASE_VERIFIER)",
    "unbound local verifier provenance claim",
)
require(gate, "skip_before_cluster_access", "pre-access SKIP funnel")
ordered(gate, 'APOLYSIS_K1_VKE_LIVE:-0', "kubectl_capture()", "opt-in before kubectl")
ordered(gate, "validate_digest_image", "preflight_cluster", "image validation before cluster preflight")

# Every subprocess is bounded, and child diagnostics never escape directly.
require(gate, "bounded_capture()", "bounded subprocess seam")
require(gate, "APOLYSIS_K1_COMMAND_TIMEOUT_SECONDS", "subprocess deadline")
require(gate, "APOLYSIS_K1_MAX_OUTPUT_BYTES", "subprocess output cap")
require(gate, "subprocess.Popen", "single bounded child runner")
require(gate, "start_new_session=True", "whole process-group cancellation")
require(gate, "canonical_fail", "canonical failure reporting")
forbid(gate, r"\b(?:cat|head|tail)\s+\"?\$[^\n]*(?:stderr|timeline|kubeconfig)", "raw sensitive output")

# The read-only preflight must establish the exact cluster and take a shared
# baseline before the first create. The owned probe then proves node features.
require(gate, "preflight_cluster()", "read-only cluster preflight")
require(gate, "exactly three Ready schedulable Linux containerd nodes", "exact VKE node contract")
require(gate, "NetworkUnavailable", "network readiness assertion")
require(gate, "containerRuntimeVersion", "runtime readiness assertion")
require(gate, "shared-baseline-before.json", "shared workload baseline")
require(gate, "daemonsets", "shared DaemonSet baseline")
require(gate, "cgroup.controllers", "cgroup v2 probe")
require(gate, "/sys/kernel/btf/vmlinux", "kernel BTF probe")
require(gate, "CapEff", "effective capability probe")
require(gate, "capabilities != required", "exact effective capability set")
require(gate, "Groups:\\s+65532", "exact collector supplemental group")
require(gate, "Parent:65532:65532:700:directory", "source parent ownership and mode probe")
require(gate, "Socket:65532:65532:660:socket", "source socket ownership and mode probe")
require(gate, '"supplementalGroupsPolicy": "Strict"', "strict supplemental group policy")
ordered(gate, "preflight_cluster", "create_owned_namespace", "read-only preflight before mutation")

# Mutation is create-new and namespace-contained. State is ephemeral and no
# host runtime/network administration is permitted.
require(gate, "/proc/sys/kernel/random/uuid", "kernel UUID owner identity")
require(gate, "apolysis.dev/owner-uuid", "owner label")
require(gate, "namespace_uid", "namespace UID proof")
require(gate, "kubectl_create", "create-only mutation seam")
require(gate, "emptyDir", "ephemeral qualification state")
require(gate, '"verbs": ["list", "watch"]', "minimal source Pod RBAC")
forbid(gate, r'"verbs": \["get", "list", "watch"\]', "unused source Pod get permission")
require(gate, '"APOLYSIS_CRICTL", "value": "/usr/local/bin/crictl"', "trusted absolute CRI client path")
forbid(gate, r"kubectl[^\n]*\bapply\b", "apply/update mutation")
forbid(gate, r"kubectl[^\n]*\b(?:patch|replace|edit)\b", "in-place shared mutation")
forbid(gate, r"\b(?:cordon|drain|uncordon)\b", "node scheduling mutation")
forbid(
    gate,
    r"(?m)^\s*(?:sudo\s+)?(?:systemctl|service|iptables|nft)\s",
    "host service or network mutation",
)
forbid(gate, r"hostPath:[\s\S]{0,120}/var/lib/apolysis", "host-persistent qualification state")
forbid(gate, r'"host-bpf"|"/sys/fs/bpf"', "unused writable host bpffs access")

# The evidence path is identity-complete and covers steady state, same-Pod
# replacement, source-only metadata loss/recovery, and cross-node handoff.
require(gate, "apolysis.dev/observe", "candidate marker")
require(gate, "apolysis.dev/session-id", "exact D1 session annotation")
forbid(gate, r'"apolysis\.dev/session"', "obsolete session annotation key")
require(gate, "annotation is D1 routing evidence only", "annotation non-authority rule")
forbid(gate, r"APOLYSIS_KUBERNETES_SESSION", "session annotation as source authority")
require(gate, "pod_uid", "Pod UID capture")
require(gate, "full_container_id", "full container ID capture")
require(gate, "apolysisd-control", "typed operator ingress")
require(gate, '"kubernetes_claims"', "typed Kubernetes claim")
require(gate, "kubernetes_attribution_observed", "K1 exact query assertion")
require(gate, "runtime_binding_observed", "D1 exact query assertion")
require(gate, "verify_timeline_hash_chain", "timeline hash-chain validation")
require(gate, "assert_timeline_order", "D1/K1 lifecycle ordering validation")
require(gate, "same_pod_restart", "same-Pod container replacement stage")
require(gate, "source_proxy_outage", "owned source outage stage")
require(gate, "kubernetes_metadata_unavailable", "K1 outage gap")
require(gate, "kubernetes_attribution_suspended", "K1 suspension")
require(gate, "assert_runtime_binding_remains", "D1 survives metadata outage")
require(gate, "fresh_recovery", "fresh K1 recovery")
require(gate, "cross_node_handoff", "cross-node recreation stage")
require(gate, "handoff-boundary.json", "bounded cross-node handoff boundary")
require(gate, "same_cycle_attach", "non-fabricated same-cycle handoff boundary")
require(gate, "kubernetes_identity_transition", "same-Pod runtime identity gap")
require(gate, "kubernetes_attribution_retired", "old K1 retirement")

# Cleanup is permitted only after re-proving owner UUID and namespace UID. PASS
# comes after namespace disappearance and unchanged shared/node baselines.
require(gate, "cleanup_owned_namespace()", "strict cleanup")
require(gate, "assert_owned_namespace_identity", "owner and UID revalidation")
require(gate, "uid_preconditioned_delete()", "atomic UID-bound delete seam")
require(gate, '"kind": "DeleteOptions"', "Kubernetes DeleteOptions request body")
require(gate, '"preconditions": {"uid": expected_uid}', "server-side UID precondition")
require(gate, 'delete --raw "$api_path" -f "$delete_options_path"', "raw DELETE with request body")
require_regex(
    gate,
    r'uid_preconditioned_delete\s+cleanup-namespace\s+\\?\s*"/api/v1/namespaces/\$namespace"\s+\\?\s*"\$namespace_uid"',
    "namespace UID-preconditioned delete",
)
require_regex(
    gate,
    r'uid_preconditioned_delete\s+delete-source-outage\s+\\?\s*"/apis/networking\.k8s\.io/v1/namespaces/\$namespace/networkpolicies/source-proxy-outage"\s+\\?\s*"\$source_outage_uid"',
    "NetworkPolicy UID-preconditioned delete",
)
require_regex(
    gate,
    r'uid_preconditioned_delete\s+"\$stem"\s+"/api/v1/namespaces/\$namespace/pods/\$pod_name"\s+"\$expected_uid"',
    "Pod UID-preconditioned delete",
)
require(gate, "wait_namespaced_object_absent()", "bounded post-delete absence proof")
require_regex(
    gate,
    r'wait_namespaced_object_absent\s+networkpolicy\s+source-proxy-outage\s+"\$source_outage_uid"',
    "NetworkPolicy deletion completion",
)
require_regex(
    gate,
    r'wait_namespaced_object_absent\s+pod\s+"\$pod_name"\s+"\$expected_uid"',
    "Pod deletion completion",
)
forbid(
    gate,
    r'\bdelete\s+(?:namespace|pod|networkpolicy)\b',
    "check-then-delete name-only mutation",
)
require(gate, "wait_namespace_absent", "namespace deletion completion")
require(gate, "shared-baseline-after.json", "post-cleanup shared baseline")
require(gate, "assert_shared_baseline_unchanged", "shared-state comparison")
ordered(gate, "cleanup_owned_namespace", "K1 VKE qualification: PASS", "cleanup before PASS")
require(gate, "SKIP is not PASS", "qualification status distinction")

require(makefile, "test-k1-vke-contract:", "contract Make target")
require(makefile, "./scripts/test-k1-vke-contract.sh", "contract target command")
require(makefile, "qualify-k1-vke-live: test-k1-vke-contract", "opt-in live Make target")
require(makefile, "APOLYSIS_K1_VKE_LIVE=1 ./scripts/qualify-k1-vke.sh", "live target command")

print("K1 VKE gate contract: PASS")
PY

cleanup_contract_tmp
trap - EXIT

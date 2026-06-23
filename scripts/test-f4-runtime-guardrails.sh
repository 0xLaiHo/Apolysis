#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-validation --test f4_runtime_guardrail_matrix
cargo test -p apolysis-validation --test f4_runtime_adapter_evidence
cargo test -p apolysis-validation --test f4_gvisor_metadata_evidence
cargo test -p apolysis-validation --test f4_kubernetes_agent_sandbox_evidence
cargo test -p apolysis-validation --test f4_kata_boundary_evidence
cargo test -p apolysis-daemon --test runtime_adapters runtime_workload_becomes_f4_runtime_adapter_evidence
cargo test -p apolysis-visibility --test f4_gvisor_metadata
cargo test -p apolysis-visibility --test f4_kata_boundary
cargo test -p apolysis-kubernetes --test f4_agent_sandbox_evidence
cargo run -p apolysis-validation --bin apolysis-f4-runtime-guardrail-matrix \
  < tests/fixtures/validation/f4-runtime-guardrail-local-live.json \
  > /tmp/apolysis-f4-runtime-guardrail-matrix.json
cargo run -p apolysis-validation --bin apolysis-f4-runtime-guardrail-matrix \
  < tests/fixtures/validation/f4-runtime-guardrail-request.json \
  > /tmp/apolysis-f4-runtime-guardrail-adapter-matrix.json

live_bundle_artifacts="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f4-live-runtime-evidence.XXXXXX")"
live_bundle_output="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f4-live-runtime-evidence-output.XXXXXX")"
for artifact in \
  backup-manifest.json \
  service-state.json \
  kubernetes-context.json \
  restore-plan.json \
  runtime-registration-report.json \
  restore-execution-report.json
do
  printf '{}\n' > "$live_bundle_artifacts/$artifact"
done
python - "$live_bundle_artifacts/f4-runtime-adapter-evidence.jsonl" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "evidence_id": "live-docker-runc-from-output",
    "source": "live_host",
    "runtime": "docker",
    "adapter": "docker",
    "session_id": "session-from-live-output",
    "workload_id": "container-from-live-output",
    "cgroup_id": 777,
    "runtime_handler": "runc",
    "metadata_correlation": True,
    "cgroup_correlation": True,
    "host_boundary_visibility": True,
    "guest_semantics_claimed": False,
}) + "\n")
PY
python - "$live_bundle_artifacts/f4-gvisor-metadata-evidence.jsonl" "$live_bundle_artifacts/f4-kubernetes-agent-sandbox-evidence.jsonl" "$live_bundle_artifacts/f4-kata-boundary-evidence.jsonl" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "evidence_id": "live-gvisor-metadata-from-output",
    "source": "live_host",
    "runtime_adapter_evidence_id": "live-docker-runc-from-output",
    "session_id": "session-from-live-output",
    "runtime_handler": "runsc",
    "host_event_subjects": ["runsc", "sentry", "gofer"],
    "runsc_observed": True,
    "sentry_observed": True,
    "gofer_observed": True,
    "host_semantics_collapsed": True,
    "guest_semantics_claimed": False,
}) + "\n")
Path(sys.argv[2]).write_text(json.dumps({
    "evidence_id": "live-kubernetes-agent-sandbox-from-output",
    "source": "live_host",
    "runtime_adapter_evidence_id": "live-docker-runc-from-output",
    "session_id": "session-from-live-output",
    "pod_name": "apolysis-live-gvisor",
    "namespace": "apolysis-live",
    "service_account": "default",
    "runtime_class_name": "gvisor",
    "sandbox_name": "apolysis-live-gvisor-sandbox",
    "node_name": "node-a",
    "pod_uid": "pod-uid-live",
    "host_boundary_visibility": True,
    "guest_semantics_claimed": False,
}) + "\n")
Path(sys.argv[3]).write_text(json.dumps({
    "evidence_id": "live-kata-boundary-from-output",
    "source": "live_host",
    "runtime_adapter_evidence_id": "live-docker-runc-from-output",
    "session_id": "session-from-live-output",
    "runtime_handler": "kata",
    "host_event_subjects": ["containerd-shim-kata-v2", "qemu-system-x86"],
    "shim_observed": True,
    "vmm_observed": True,
    "host_boundary_visibility": True,
    "guest_collector_required": True,
    "guest_semantics_claimed": False,
}) + "\n")
PY

APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$live_bundle_artifacts" \
APOLYSIS_F4_LIVE_RUNTIME_EVIDENCE_OUTPUT_DIR="$live_bundle_output" \
  ./scripts/write-f4-live-runtime-evidence-bundle.sh

test -s "$live_bundle_output/f4-live-runtime-evidence-request.json"
test -s "$live_bundle_output/f4-live-runtime-evidence-report.json"
python - "$live_bundle_output/f4-live-runtime-evidence-request.json" <<'PY'
import json
import sys
from pathlib import Path

request = json.loads(Path(sys.argv[1]).read_text())
evidence_ids = {
    entry["evidence_id"]
    for entry in request["runtime_adapter_evidence_reports"]
}
assert "live-docker-runc-from-output" in evidence_ids
assert "live-docker-runc-cgroup" not in evidence_ids
assert request["gvisor_metadata_evidence_reports"][0]["evidence_id"] == "live-gvisor-metadata-from-output"
assert request["kubernetes_agent_sandbox_evidence_reports"][0]["evidence_id"] == "live-kubernetes-agent-sandbox-from-output"
assert request["kata_boundary_evidence_reports"][0]["evidence_id"] == "live-kata-boundary-from-output"
assert request["gvisor_metadata_evidence_reports"][0]["evidence_id"] != "live-gvisor-runsc-sentry-gofer"
assert request["kubernetes_agent_sandbox_evidence_reports"][0]["evidence_id"] != "live-kubernetes-agent-sandbox-gvisor"
assert request["kata_boundary_evidence_reports"][0]["evidence_id"] != "live-kata-qemu-shim-boundary"
PY

restore_check_root="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f2-restore-check-root.XXXXXX")"
restore_check_artifacts="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f2-restore-check-artifacts.XXXXXX")"
mkdir -p "$restore_check_root/etc/containerd"
mkdir -p "$restore_check_root/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d"
printf 'original-containerd-config\n' > "$restore_check_root/etc/containerd/config.toml"
containerd_sha="$(sha256sum "$restore_check_root/etc/containerd/config.toml" | awk '{print $1}')"
python - "$restore_check_artifacts/backup-manifest.json" "$containerd_sha" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "schema_version": 1,
    "entries": [
        {
            "id": "containerd_config",
            "original_path": "/etc/containerd/config.toml",
            "kind": "regular_file",
            "backup_relative_path": "files/containerd_config",
            "sha256_hex": sys.argv[2],
            "symlink_target": None,
            "uid": 0,
            "gid": 0,
            "mode": 420,
        },
        {
            "id": "k3s_runtime_dropin",
            "original_path": "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml",
            "kind": "missing",
            "backup_relative_path": None,
            "sha256_hex": None,
            "symlink_target": None,
            "uid": None,
            "gid": None,
            "mode": None,
        },
    ],
}, indent=2, sort_keys=True))
PY
APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$restore_check_artifacts" \
APOLYSIS_HOST_ROOT="$restore_check_root" \
  ./scripts/assert-f2-runtime-matrix-restored.sh
printf 'unexpected dropin\n' > "$restore_check_root/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml"
if APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$restore_check_artifacts" \
  APOLYSIS_HOST_ROOT="$restore_check_root" \
  ./scripts/assert-f2-runtime-matrix-restored.sh; then
  echo "apolysis-f4: restore manifest check accepted a stale runtime drop-in" >&2
  exit 1
fi

python - "$live_bundle_output/f4-live-runtime-evidence-report.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path("/tmp/apolysis-f4-runtime-guardrail-matrix.json").read_text())
assert report["production_facing_kernel_blocking_supported"] is False
by_runtime = {entry["runtime"]: entry for entry in report["runtimes"]}
assert by_runtime["local"]["seccomp_block"]["status"] == "prototype_validated"
assert by_runtime["local"]["bpf_lsm_block"]["status"] == "prototype_validated"
assert by_runtime["docker"]["seccomp_block"]["status"] == "requires_runtime_evidence"
assert by_runtime["gvisor"]["bpf_lsm_block"]["status"] == "metadata_only"
assert by_runtime["kata"]["requires_guest_collector"] is True
assert by_runtime["firecracker"]["kill"]["status"] == "boundary_only"

adapter_report = json.loads(Path("/tmp/apolysis-f4-runtime-guardrail-adapter-matrix.json").read_text())
adapter_by_runtime = {entry["runtime"]: entry for entry in adapter_report["runtimes"]}
assert adapter_by_runtime["docker"]["notify"]["evidence_ids"] == ["live-docker-runc-cgroup"]
assert adapter_by_runtime["docker"]["review"]["evidence_ids"] == ["live-docker-runc-cgroup"]
assert adapter_by_runtime["docker"]["kill"]["evidence_ids"] == ["live-docker-runc-cgroup"]
assert adapter_by_runtime["docker"]["seccomp_block"]["status"] == "requires_runtime_evidence"
assert adapter_by_runtime["docker"]["seccomp_block"]["evidence_ids"] == []
assert adapter_by_runtime["gvisor"]["notify"]["evidence_ids"] == [
    "live-containerd-gvisor-cgroup",
    "live-gvisor-runsc-sentry-gofer",
]
assert adapter_by_runtime["gvisor"]["bpf_lsm_block"]["status"] == "metadata_only"
assert adapter_by_runtime["gvisor"]["bpf_lsm_block"]["evidence_ids"] == [
    "live-containerd-gvisor-cgroup",
    "live-gvisor-runsc-sentry-gofer",
]
assert adapter_by_runtime["kubernetes"]["notify"]["evidence_ids"] == [
    "live-kubernetes-agent-sandbox-gvisor",
    "live-kubernetes-gvisor-cgroup",
]
assert adapter_by_runtime["kubernetes"]["review"]["evidence_ids"] == [
    "live-kubernetes-agent-sandbox-gvisor",
    "live-kubernetes-gvisor-cgroup",
]
assert adapter_by_runtime["kubernetes"]["kill"]["evidence_ids"] == [
    "live-kubernetes-agent-sandbox-gvisor",
    "live-kubernetes-gvisor-cgroup",
]
assert adapter_by_runtime["kubernetes"]["seccomp_block"]["status"] == "requires_runtime_evidence"
assert adapter_by_runtime["kubernetes"]["seccomp_block"]["evidence_ids"] == []
assert adapter_by_runtime["kata"]["notify"]["evidence_ids"] == [
    "live-kata-qemu-shim-boundary",
    "live-kubernetes-kata-cgroup",
]
assert adapter_by_runtime["kata"]["review"]["evidence_ids"] == [
    "live-kata-qemu-shim-boundary",
    "live-kubernetes-kata-cgroup",
]
assert adapter_by_runtime["kata"]["kill"]["evidence_ids"] == [
    "live-kata-qemu-shim-boundary",
    "live-kubernetes-kata-cgroup",
]
assert adapter_by_runtime["kata"]["seccomp_block"]["status"] == "boundary_only"
assert adapter_by_runtime["kata"]["seccomp_block"]["evidence_ids"] == [
    "live-kata-qemu-shim-boundary",
    "live-kubernetes-kata-cgroup",
]
assert adapter_by_runtime["kata"]["requires_guest_collector"] is True

bundle = json.loads(Path(sys.argv[1]).read_text())
assert bundle["passed"] is True
assert bundle["matrix"]["production_facing_kernel_blocking_supported"] is False
bundle_by_runtime = {entry["runtime"]: entry for entry in bundle["matrix"]["runtimes"]}
assert bundle_by_runtime["kata"]["seccomp_block"]["status"] == "boundary_only"
PY

echo "apolysis-f4: runtime guardrail support matrix validation passed"

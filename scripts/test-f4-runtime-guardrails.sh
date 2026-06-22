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

python - "$live_bundle_artifacts" <<'PY'
import json
import sys
from pathlib import Path

artifact_dir = sys.argv[1]
source = f"scripts/test-f2-runtime-adapter-matrix.sh artifacts={artifact_dir}"
request = json.loads(Path("tests/fixtures/validation/f4-runtime-guardrail-request.json").read_text())
request["artifact_dir"] = artifact_dir
request["visibility_reports"] = [
    {"target": target, "live_validated": True, "evidence_source": source, "host_visibility_scope": scope, "guest_semantics_claimed": False}
    for target, scope in [
        ("local", "guest_process"),
        ("docker_runc", "guest_process"),
        ("docker_gvisor", "runtime_boundary"),
        ("containerd_runc", "guest_process"),
        ("containerd_gvisor", "runtime_boundary"),
        ("containerd_kata", "boundary_only"),
        ("k3s_runc", "guest_process"),
        ("k3s_gvisor", "runtime_boundary"),
        ("k3s_kata", "boundary_only"),
    ]
]
Path("/tmp/apolysis-f4-live-runtime-evidence-request.json").write_text(
    json.dumps(request, indent=2, sort_keys=True)
)
PY

cargo run -p apolysis-validation --bin apolysis-f4-live-runtime-evidence \
  < /tmp/apolysis-f4-live-runtime-evidence-request.json \
  > /tmp/apolysis-f4-live-runtime-evidence-report.json

python - <<'PY'
import json
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

bundle = json.loads(Path("/tmp/apolysis-f4-live-runtime-evidence-report.json").read_text())
assert bundle["passed"] is True
assert bundle["matrix"]["production_facing_kernel_blocking_supported"] is False
bundle_by_runtime = {entry["runtime"]: entry for entry in bundle["matrix"]["runtimes"]}
assert bundle_by_runtime["kata"]["seccomp_block"]["status"] == "boundary_only"
PY

echo "apolysis-f4: runtime guardrail support matrix validation passed"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-validation --test f4_runtime_guardrail_matrix
cargo test -p apolysis-validation --test f4_runtime_adapter_evidence
cargo test -p apolysis-validation --test f4_gvisor_metadata_evidence
cargo test -p apolysis-validation --test f4_kubernetes_agent_sandbox_evidence
cargo test -p apolysis-daemon --test runtime_adapters runtime_workload_becomes_f4_runtime_adapter_evidence
cargo test -p apolysis-visibility --test f4_gvisor_metadata
cargo test -p apolysis-kubernetes --test f4_agent_sandbox_evidence
cargo run -p apolysis-validation --bin apolysis-f4-runtime-guardrail-matrix \
  < tests/fixtures/validation/f4-runtime-guardrail-local-live.json \
  > /tmp/apolysis-f4-runtime-guardrail-matrix.json
cargo run -p apolysis-validation --bin apolysis-f4-runtime-guardrail-matrix \
  < tests/fixtures/validation/f4-runtime-guardrail-request.json \
  > /tmp/apolysis-f4-runtime-guardrail-adapter-matrix.json

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
PY

echo "apolysis-f4: runtime guardrail support matrix validation passed"

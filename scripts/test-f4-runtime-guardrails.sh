#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-validation --test f4_runtime_guardrail_matrix
cargo run -p apolysis-validation --bin apolysis-f4-runtime-guardrail-matrix \
  < tests/fixtures/validation/f4-runtime-guardrail-local-live.json \
  > /tmp/apolysis-f4-runtime-guardrail-matrix.json

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
PY

echo "apolysis-f4: runtime guardrail support matrix validation passed"

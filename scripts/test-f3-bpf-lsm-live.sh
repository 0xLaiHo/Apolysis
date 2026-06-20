#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_path="${APOLYSIS_F3_BPF_LSM_REPORT:-/tmp/apolysis-f3-bpf-lsm-file-read-report.json}"
gate_path="${APOLYSIS_F3_BPF_LSM_GATE:-/tmp/apolysis-f3-bpf-lsm-file-read-gate.json}"
target_path="${APOLYSIS_F3_BPF_LSM_TARGET:-/etc/passwd}"
object_path="target/ebpf/apolysis_bpf_lsm_file_read.bpf.o"

./scripts/build-ebpf.sh

set +e
cargo run -p apolysis-validation --bin apolysis-f3-bpf-lsm-file-read-prototype -- \
  --bpf-object "$object_path" \
  --target-path "$target_path" \
  > "$report_path"
prototype_status=$?
set -e

if [[ "$prototype_status" == "77" ]]; then
  echo "apolysis-f3: BPF-LSM live validation prerequisites are not satisfied" >&2
  cat "$report_path" >&2
  exit 77
fi
if [[ "$prototype_status" != "0" ]]; then
  echo "apolysis-f3: BPF-LSM live validation failed with status $prototype_status" >&2
  cat "$report_path" >&2 || true
  exit "$prototype_status"
fi

cargo run -p apolysis-validation --bin apolysis-f3-block-validation-report \
  < "$report_path" \
  > "$gate_path"

echo "apolysis-f3: BPF-LSM live validation passed"

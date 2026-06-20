#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_id="${APOLYSIS_F3_BPF_LSM_RUN_ID:-$(date +%s)-$$}"
report_path="${APOLYSIS_F3_BPF_LSM_REPORT:-/tmp/apolysis-f3-bpf-lsm-file-read-report-$run_id.json}"
gate_path="${APOLYSIS_F3_BPF_LSM_GATE:-/tmp/apolysis-f3-bpf-lsm-file-read-gate-$run_id.json}"
enablement_path="${APOLYSIS_F3_BPF_LSM_ENABLEMENT:-/tmp/apolysis-f3-bpf-lsm-enablement-policy-$run_id.json}"
approval_audit_path="${APOLYSIS_F3_BPF_LSM_APPROVAL_AUDIT:-/tmp/apolysis-f3-bpf-lsm-approval-audit-$run_id.jsonl}"
rollback_audit_path="${APOLYSIS_F3_BPF_LSM_ROLLBACK_AUDIT:-/tmp/apolysis-f3-bpf-lsm-rollback-audit-$run_id.jsonl}"
target_path="${APOLYSIS_F3_BPF_LSM_TARGET:-/etc/passwd}"
object_path="target/ebpf/apolysis_bpf_lsm_file_read.bpf.o"
prototype_bin="$repo_root/target/debug/apolysis-f3-bpf-lsm-file-read-prototype"
gate_bin="$repo_root/target/debug/apolysis-f3-block-validation-report"
enablement_bin="$repo_root/target/debug/apolysis-f3-block-enablement-policy"
audit_bin="$repo_root/target/debug/apolysis-f3-block-operator-audit"
cargo_bin="${CARGO:-$(command -v cargo || true)}"
if [[ -z "$cargo_bin" && -n "${SUDO_USER:-}" ]]; then
  sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  if [[ -x "$sudo_home/.cargo/bin/cargo" ]]; then
    cargo_bin="$sudo_home/.cargo/bin/cargo"
  fi
fi
if [[ -z "$cargo_bin" ]]; then
  echo "apolysis-f3: cargo is required; set CARGO=/path/to/cargo when running under sudo" >&2
  exit 127
fi

run_as_sudo_user() {
  if [[ "$(id -u)" == "0" && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H "$@"
  else
    "$@"
  fi
}

run_as_sudo_user ./scripts/build-ebpf.sh
if [[ ! -x "$prototype_bin" || ! -x "$gate_bin" || ! -x "$enablement_bin" || ! -x "$audit_bin" ]]; then
  if [[ "$(id -u)" == "0" && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H "$cargo_bin" build \
      -p apolysis-validation \
      --bin apolysis-f3-bpf-lsm-file-read-prototype \
      --bin apolysis-f3-block-validation-report \
      --bin apolysis-f3-block-enablement-policy \
      --bin apolysis-f3-block-operator-audit
  else
    "$cargo_bin" build \
      -p apolysis-validation \
      --bin apolysis-f3-bpf-lsm-file-read-prototype \
      --bin apolysis-f3-block-validation-report \
      --bin apolysis-f3-block-enablement-policy \
      --bin apolysis-f3-block-operator-audit
  fi
fi

set +e
"$prototype_bin" \
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

"$gate_bin" \
  < "$report_path" \
  > "$gate_path"
"$enablement_bin" \
  --validation-gate "$gate_path" \
  < tests/fixtures/validation/f3-bpf-lsm-enablement-valid.json \
  > "$enablement_path"
"$audit_bin" \
  --operation approve \
  --operator f3-test-operator \
  --timestamp-unix-ms 1780328000789 \
  < "$enablement_path" \
  > "$approval_audit_path"
"$audit_bin" \
  --operation rollback \
  --operator f3-test-operator \
  --timestamp-unix-ms 1780328000890 \
  < "$enablement_path" \
  > "$rollback_audit_path"

echo "apolysis-f3: BPF-LSM live validation passed"
echo "apolysis-f3: report written to $report_path"
echo "apolysis-f3: gate written to $gate_path"
echo "apolysis-f3: enablement written to $enablement_path"
echo "apolysis-f3: approval audit written to $approval_audit_path"
echo "apolysis-f3: rollback audit written to $rollback_audit_path"

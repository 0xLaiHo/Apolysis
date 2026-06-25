#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_id="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_RUN_ID:-$(date +%s)-$$}"
report_path="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_REPORT:-/tmp/apolysis-policy-guardrails-bpf-lsm-file-read-report-$run_id.json}"
gate_path="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_GATE:-/tmp/apolysis-policy-guardrails-bpf-lsm-file-read-gate-$run_id.json}"
enablement_path="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_ENABLEMENT:-/tmp/apolysis-policy-guardrails-bpf-lsm-enablement-policy-$run_id.json}"
approval_audit_path="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_APPROVAL_AUDIT:-/tmp/apolysis-policy-guardrails-bpf-lsm-approval-audit-$run_id.jsonl}"
rollback_audit_path="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_ROLLBACK_AUDIT:-/tmp/apolysis-policy-guardrails-bpf-lsm-rollback-audit-$run_id.jsonl}"
target_path="${APOLYSIS_POLICY_GUARDRAILS_BPF_LSM_TARGET:-/etc/passwd}"
object_path="target/ebpf/apolysis_bpf_lsm_file_read.bpf.o"
prototype_bin="$repo_root/target/debug/apolysis-policy-guardrails-bpf-lsm-file-read-prototype"
gate_bin="$repo_root/target/debug/apolysis-policy-guardrails-block-validation-report"
enablement_bin="$repo_root/target/debug/apolysis-policy-guardrails-block-enablement-policy"
audit_bin="$repo_root/target/debug/apolysis-policy-guardrails-block-operator-audit"
cargo_bin="${CARGO:-$(command -v cargo || true)}"
if [[ -z "$cargo_bin" && -n "${SUDO_USER:-}" ]]; then
  sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -regulated_release)"
  if [[ -x "$sudo_home/.cargo/bin/cargo" ]]; then
    cargo_bin="$sudo_home/.cargo/bin/cargo"
  fi
fi
if [[ -z "$cargo_bin" ]]; then
  echo "apolysis-policy_guardrails: cargo is required; set CARGO=/path/to/cargo when running under sudo" >&2
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
      --bin apolysis-policy-guardrails-bpf-lsm-file-read-prototype \
      --bin apolysis-policy-guardrails-block-validation-report \
      --bin apolysis-policy-guardrails-block-enablement-policy \
      --bin apolysis-policy-guardrails-block-operator-audit
  else
    "$cargo_bin" build \
      -p apolysis-validation \
      --bin apolysis-policy-guardrails-bpf-lsm-file-read-prototype \
      --bin apolysis-policy-guardrails-block-validation-report \
      --bin apolysis-policy-guardrails-block-enablement-policy \
      --bin apolysis-policy-guardrails-block-operator-audit
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
  echo "apolysis-policy_guardrails: BPF-LSM live validation prerequisites are not satisfied" >&2
  cat "$report_path" >&2
  exit 77
fi
if [[ "$prototype_status" != "0" ]]; then
  echo "apolysis-policy_guardrails: BPF-LSM live validation failed with status $prototype_status" >&2
  cat "$report_path" >&2 || true
  exit "$prototype_status"
fi

"$gate_bin" \
  < "$report_path" \
  > "$gate_path"
"$enablement_bin" \
  --validation-gate "$gate_path" \
  < tests/fixtures/validation/policy-guardrails-bpf-lsm-enablement-valid.json \
  > "$enablement_path"
"$audit_bin" \
  --operation approve \
  --operator policy-guardrails-test-operator \
  --timestamp-unix-ms 1780328000789 \
  < "$enablement_path" \
  > "$approval_audit_path"
"$audit_bin" \
  --operation rollback \
  --operator policy-guardrails-test-operator \
  --timestamp-unix-ms 1780328000890 \
  < "$enablement_path" \
  > "$rollback_audit_path"

echo "apolysis-policy_guardrails: BPF-LSM live validation passed"
echo "apolysis-policy_guardrails: report written to $report_path"
echo "apolysis-policy_guardrails: gate written to $gate_path"
echo "apolysis-policy_guardrails: enablement written to $enablement_path"
echo "apolysis-policy_guardrails: approval audit written to $approval_audit_path"
echo "apolysis-policy_guardrails: rollback audit written to $rollback_audit_path"

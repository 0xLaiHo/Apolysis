#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-policy
cargo test -p apolysis-core enforcement_metadata
cargo test -p apolysis-cli observe_fixture_emits_kill_containment_metadata
cargo test -p apolysis-validation --test policy_guardrails_block_validation_gate
cargo test -p apolysis-validation --test policy_guardrails_local_seccomp_execution
cargo test -p apolysis-validation --test policy_guardrails_bpf_lsm_file_read_prototype
./scripts/build-ebpf.sh
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-validation-report \
  < tests/fixtures/validation/policy-guardrails-block-live-valid.json \
  > /tmp/apolysis-policy-guardrails-block-live-valid-report.json

if cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-validation-report \
  < tests/fixtures/validation/policy-guardrails-block-fixture-invalid.json \
  > /tmp/apolysis-policy-guardrails-block-fixture-invalid-report.json 2>&1; then
  echo "apolysis-policy_guardrails: fixture block validation report unexpectedly passed" >&2
  exit 1
fi

cargo run -p apolysis-validation --bin apolysis-policy-guardrails-seccomp-file-read-prototype \
  > /tmp/apolysis-policy-guardrails-seccomp-file-read-report.json
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-validation-report \
  < /tmp/apolysis-policy-guardrails-seccomp-file-read-report.json \
  > /tmp/apolysis-policy-guardrails-seccomp-file-read-gate.json
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-enablement-policy -- \
  --validation-gate /tmp/apolysis-policy-guardrails-seccomp-file-read-gate.json \
  < tests/fixtures/validation/policy-guardrails-block-enablement-valid.json \
  > /tmp/apolysis-policy-guardrails-block-enablement-policy.json
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-operator-audit -- \
  --operation approve \
  --operator policy-guardrails-test-operator \
  --timestamp-unix-ms 1780328000123 \
  < /tmp/apolysis-policy-guardrails-block-enablement-policy.json \
  > /tmp/apolysis-policy-guardrails-block-approval-audit.jsonl
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-operator-audit -- \
  --operation rollback \
  --operator policy-guardrails-test-operator \
  --timestamp-unix-ms 1780328000456 \
  < /tmp/apolysis-policy-guardrails-block-enablement-policy.json \
  > /tmp/apolysis-policy-guardrails-block-rollback-audit.jsonl
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-local-seccomp-execution -- \
  --enablement-policy /tmp/apolysis-policy-guardrails-block-enablement-policy.json \
  --evidence-id live-seccomp-local-file-read \
  --target-path /etc/passwd \
  > /tmp/apolysis-policy-guardrails-local-seccomp-execution.json
if cargo run -p apolysis-validation --bin apolysis-policy-guardrails-local-seccomp-execution -- \
  --enablement-policy /tmp/apolysis-policy-guardrails-block-enablement-policy.json \
  --evidence-id unknown-live-report \
  --target-path /etc/passwd \
  > /tmp/apolysis-policy-guardrails-local-seccomp-execution-invalid.json 2>&1; then
  echo "apolysis-policy_guardrails: local seccomp execution unexpectedly passed without approved evidence" >&2
  exit 1
fi
set +e
cargo run -p apolysis-validation --bin apolysis-policy-guardrails-bpf-lsm-file-read-prototype -- \
  --bpf-object target/ebpf/apolysis_bpf_lsm_file_read.bpf.o \
  --target-path /etc/passwd \
  > /tmp/apolysis-policy-guardrails-bpf-lsm-file-read-report.json
bpf_lsm_status=$?
set -e
if [[ "$bpf_lsm_status" == "0" ]]; then
  cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-validation-report \
    < /tmp/apolysis-policy-guardrails-bpf-lsm-file-read-report.json \
    > /tmp/apolysis-policy-guardrails-bpf-lsm-file-read-gate.json
  cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-enablement-policy -- \
    --validation-gate /tmp/apolysis-policy-guardrails-bpf-lsm-file-read-gate.json \
    < tests/fixtures/validation/policy-guardrails-bpf-lsm-enablement-valid.json \
    > /tmp/apolysis-policy-guardrails-bpf-lsm-enablement-policy.json
  cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-operator-audit -- \
    --operation approve \
    --operator policy-guardrails-test-operator \
    --timestamp-unix-ms 1780328000789 \
    < /tmp/apolysis-policy-guardrails-bpf-lsm-enablement-policy.json \
    > /tmp/apolysis-policy-guardrails-bpf-lsm-approval-audit.jsonl
  cargo run -p apolysis-validation --bin apolysis-policy-guardrails-block-operator-audit -- \
    --operation rollback \
    --operator policy-guardrails-test-operator \
    --timestamp-unix-ms 1780328000890 \
    < /tmp/apolysis-policy-guardrails-bpf-lsm-enablement-policy.json \
    > /tmp/apolysis-policy-guardrails-bpf-lsm-rollback-audit.jsonl
elif [[ "$bpf_lsm_status" == "77" ]]; then
  echo "apolysis-policy_guardrails: BPF-LSM live prototype skipped; prerequisite report written to /tmp/apolysis-policy-guardrails-bpf-lsm-file-read-report.json"
else
  echo "apolysis-policy_guardrails: BPF-LSM live prototype failed with status $bpf_lsm_status" >&2
  cat /tmp/apolysis-policy-guardrails-bpf-lsm-file-read-report.json >&2 || true
  exit "$bpf_lsm_status"
fi

echo "apolysis-policy_guardrails: guardrail capability validation passed"

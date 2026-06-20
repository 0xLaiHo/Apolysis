#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-policy
cargo test -p apolysis-core enforcement_metadata
cargo test -p apolysis-cli observe_fixture_emits_kill_containment_metadata
cargo test -p apolysis-validation --test f3_block_validation_gate
cargo run -p apolysis-validation --bin apolysis-f3-block-validation-report \
  < tests/fixtures/validation/f3-block-live-valid.json \
  > /tmp/apolysis-f3-block-live-valid-report.json

if cargo run -p apolysis-validation --bin apolysis-f3-block-validation-report \
  < tests/fixtures/validation/f3-block-fixture-invalid.json \
  > /tmp/apolysis-f3-block-fixture-invalid-report.json 2>&1; then
  echo "apolysis-f3: fixture block validation report unexpectedly passed" >&2
  exit 1
fi

echo "apolysis-f3: guardrail capability validation passed"

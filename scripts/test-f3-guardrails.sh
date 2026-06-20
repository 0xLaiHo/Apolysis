#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-policy
cargo test -p apolysis-core enforcement_metadata_json_line_records_timing_and_capability_context
cargo test -p apolysis-cli observe_fixture_emits_kill_containment_metadata

echo "apolysis-f3: guardrail capability validation passed"

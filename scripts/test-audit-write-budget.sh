#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-store --test jsonl_writer
cargo test -p apolysis-cli --test observe observe_fixture_rotates_timeline_when_output_budget_is_reached
cargo test -p apolysis-cli --test observe observe_output_rotation_requires_complete_positive_budget

for term in \
  '--output-max-bytes' \
  '--output-max-files' \
  'observer-output-rotation' \
  'max_file_bytes' \
  'max_archived_files'; do
  grep -Fq -- "$term" docs/jsonl-schema-v1.md || {
    echo "docs/jsonl-schema-v1.md must document audit write budget term: $term" >&2
    exit 1
  }
done

echo "audit write budget gate passed"

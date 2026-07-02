#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-core --test schema session_intent_record_json_line_is_append_only_and_joinable
cargo test -p apolysis-cli --test intent

schema_doc="docs/jsonl-schema-v1.md"
for term in \
  'record_type`: always `intent`' \
  'intent_source' \
  'intent_id' \
  'source_event_id' \
  'intent_type' \
  'tool_name' \
  'declared_action' \
  'raw_event_id' \
  'apolysis intent ingest' \
  'codex-jsonl'; do
  grep -Fq "$term" "$schema_doc" || {
    echo "$schema_doc is missing intent-correlation term: $term" >&2
    exit 1
  }
done

grep -Fq 'apolysis intent ingest' README.md || {
  echo "README.md must document intent ingestion" >&2
  exit 1
}

grep -Fq 'apolysis intent ingest' README.zh-CN.md || {
  echo "README.zh-CN.md must document intent ingestion" >&2
  exit 1
}

echo "intent correlation gate passed"

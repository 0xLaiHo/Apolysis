#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

schema_doc="docs/jsonl-schema-v1.md"

if [[ ! -f "$schema_doc" ]]; then
  echo "missing $schema_doc" >&2
  exit 1
fi

required_doc_terms=(
  "Schema version: v1"
  "Append-only compatibility rules"
  "record_type"
  "session"
  "event"
  "raw_kernel_event"
  "policy_violation"
  "enforcement_metadata"
  "observer_diagnostic"
  "visibility_assessment"
  "event_id"
  "raw_event_id"
  "observed_event_id"
  "process_command"
  "process_executable"
  "process_started_at_unix_ms"
  "agent-command-fingerprint"
  "argv_truncated:true"
  "payload_truncated:true"
)

for term in "${required_doc_terms[@]}"; do
  grep -Fq -- "$term" "$schema_doc" || {
    echo "$schema_doc is missing required term: $term" >&2
    exit 1
  }
done

grep -Fq -- "docs/jsonl-schema-v1.md" README.md || {
  echo "README.md must link to $schema_doc" >&2
  exit 1
}

grep -Fq -- "docs/jsonl-schema-v1.md" README.zh-CN.md || {
  echo "README.zh-CN.md must link to $schema_doc" >&2
  exit 1
}

echo "jsonl-schema-contract gate passed"

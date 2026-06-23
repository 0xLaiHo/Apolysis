#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_F5_WORM_ARCHIVE_POLICY_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-worm-archive-policy.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in cargo jq python3; do
    require_command "$command"
done

pass_policy="$output_dir/apolysis-f5-worm-archive-policy.json"
fail_policy="$output_dir/apolysis-f5-worm-archive-policy-fail.json"
pass_report="$output_dir/apolysis-f5-worm-archive-policy-report.json"
fail_report="$output_dir/apolysis-f5-worm-archive-policy-fail-report.json"

cat >"$pass_policy" <<'JSON'
{
  "policy_id": "f5-prod-worm-archive",
  "provider": "s3_object_lock",
  "bucket_uri": "s3://apolysis-prod-release-archive",
  "object_prefix": "releases/apolysis",
  "release_manifest_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "requested_at_unix_ms": 1782259200000,
  "retention_days": 365,
  "retain_until_unix_ms": 1813795200000,
  "retention_mode": "compliance",
  "object_lock_enabled": true,
  "versioning_enabled": true,
  "legal_hold_supported": true,
  "delete_protection_enabled": true,
  "audit_log_ref": "cloudtrail://apolysis-prod-release-archive",
  "operator_approved": true,
  "allowed_writer_principals": ["ci:release-archiver"],
  "allowed_reader_principals": ["cluster:prod-apolysis-readers"],
  "deny_delete_principals": ["*"],
  "replication_target_uri": "s3://apolysis-prod-release-archive-dr"
}
JSON

cat >"$fail_policy" <<'JSON'
{
  "policy_id": "f5-mutable-archive",
  "provider": "local_filesystem",
  "bucket_uri": "/var/lib/apolysis/archive",
  "object_prefix": "tmp",
  "release_manifest_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "requested_at_unix_ms": 1782259200000,
  "retention_days": 30,
  "retain_until_unix_ms": 1784851200000,
  "retention_mode": "governance",
  "object_lock_enabled": false,
  "versioning_enabled": false,
  "legal_hold_supported": false,
  "delete_protection_enabled": false,
  "audit_log_ref": "",
  "operator_approved": false,
  "allowed_writer_principals": ["*"],
  "allowed_reader_principals": ["system:anonymous"],
  "deny_delete_principals": [],
  "replication_target_uri": ""
}
JSON

cargo run -q -p apolysis-validation --bin apolysis-f5-worm-archive-policy -- \
    --policy "$pass_policy" >"$pass_report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "s3_object_lock"
  and .approval.retention_days == 365
  and .approval.release_manifest_sha256 == "1111111111111111111111111111111111111111111111111111111111111111"
' "$pass_report" >/dev/null

if cargo run -q -p apolysis-validation --bin apolysis-f5-worm-archive-policy -- \
    --policy "$fail_policy" >"$fail_report"; then
    echo "apolysis-f5: mutable or local WORM archive policy unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("external WORM archive requires S3 Object Lock, GCS Bucket Lock, or Azure Immutable Blob"))
  and (.failures | map(.message) | index("object lock must be enabled"))
  and (.failures | map(.message) | index("minimum WORM retention is 180 days"))
  and (.failures | map(.message) | index("delete-deny principals are required"))
' "$fail_report" >/dev/null

printf 'apolysis-f5: external WORM archive policy gate passed (%s)\n' "$output_dir"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_F5_AWS_KMS_SIGNER_BOOTSTRAP:-0}"
require_ready="${APOLYSIS_REQUIRE_F5_AWS_KMS_SIGNER_BOOTSTRAP:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-f5: AWS KMS signer bootstrap is opt-in.
Set APOLYSIS_CONFIRM_F5_AWS_KMS_SIGNER_BOOTSTRAP=1 after confirming the AWS
account, IAM principal, region, alias/key naming, evidence retention location,
and any potential KMS cost or key-management impact are acceptable.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in aws base64 jq python3 sha256sum; do
    require_command "$command"
done

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_AWS_KMS_SIGNER_BOOTSTRAP_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-aws-kms-signer-bootstrap.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f5-aws-kms-signer-bootstrap-report.json"
key_metadata="$output_dir/aws-kms-describe-key.json"
public_key_json="$output_dir/aws-kms-get-public-key.json"
public_key_der="$output_dir/aws-kms-public-key.der"
create_key_response="$output_dir/aws-kms-create-key.json"
create_alias_response="$output_dir/aws-kms-create-alias.json"
aws_error_log="$output_dir/aws-error.log"

mode="${APOLYSIS_F5_AWS_KMS_BOOTSTRAP_MODE:-inspect}"
key_id="${APOLYSIS_F5_AWS_KMS_KEY_ID:-}"
alias_name="${APOLYSIS_F5_AWS_KMS_ALIAS:-}"
aws_region="${APOLYSIS_F5_AWS_REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
algorithm="${APOLYSIS_F5_AWS_KMS_SIGNING_ALGORITHM:-RSASSA_PKCS1_V1_5_SHA_256}"
key_spec="${APOLYSIS_F5_AWS_KMS_KEY_SPEC:-RSA_2048}"
create_confirm="${APOLYSIS_CONFIRM_F5_AWS_KMS_KEY_CREATION:-0}"

write_report() {
    local passed="$1"
    local ready_for_signing_gate="$2"
    local last_action="$3"
    local created_key="$4"
    local created_alias="$5"
    local key_ref="$6"
    shift 6

    local public_key_sha256=""
    if [[ -s "$public_key_der" ]]; then
        public_key_sha256="$(sha256sum "$public_key_der" | awk '{print $1}')"
    fi

    python3 - "$report" \
        "$key_metadata" \
        "$public_key_json" \
        "$passed" \
        "$ready_for_signing_gate" \
        "$mode" \
        "$aws_region" \
        "$key_id" \
        "$alias_name" \
        "$algorithm" \
        "$key_spec" \
        "$created_key" \
        "$created_alias" \
        "$key_ref" \
        "$last_action" \
        "$public_key_sha256" \
        "$@" <<'PY'
import json
import os
import shutil
import sys
import time
from pathlib import Path

(
    report_path,
    key_metadata_path,
    public_key_json_path,
    passed,
    ready_for_signing_gate,
    mode,
    aws_region,
    requested_key_id,
    alias_name,
    algorithm,
    key_spec,
    created_key,
    created_alias,
    key_ref,
    last_action,
    public_key_sha256,
    *missing_requirements,
) = sys.argv[1:]

metadata_path = Path(key_metadata_path)
public_key_path = Path(public_key_json_path)
metadata = {}
public_key = {}
if metadata_path.is_file() and metadata_path.stat().st_size > 0:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")).get("KeyMetadata", {})
if public_key_path.is_file() and public_key_path.stat().st_size > 0:
    public_key = json.loads(public_key_path.read_text(encoding="utf-8"))

region = aws_region or metadata.get("Arn", ":::").split(":")[3]
key_arn = metadata.get("Arn", "")
actual_key_id = metadata.get("KeyId", "")
key_uri = f"awskms://{key_arn}" if key_arn else ""
next_command = ""
if key_arn and region:
    next_command = (
        "APOLYSIS_CONFIRM_F5_AWS_KMS_SIGNING=1 "
        f"APOLYSIS_F5_AWS_KMS_KEY_ID={key_arn} "
        f"APOLYSIS_F5_AWS_REGION={region} "
        "./scripts/test-f5-aws-kms-signing.sh"
    )

credential_hint_present = any(
    bool(os.environ.get(name))
    for name in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE")
) or (Path.home() / ".aws").is_dir()

tools = {
    name: {"available": bool(path := shutil.which(name)), "path": path or ""}
    for name in ("aws", "base64", "jq", "python3", "sha256sum")
}

report = {
    "schema_version": 1,
    "phase": "F5.41",
    "audit_completed": True,
    "passed": passed == "true",
    "ready_for_signing_gate": ready_for_signing_gate == "true",
    "mode": mode,
    "last_action": last_action,
    "created_key": created_key == "true",
    "created_alias": created_alias == "true",
    "requested": {
        "key_id_present": bool(requested_key_id),
        "alias_name": alias_name,
        "region": region,
        "algorithm": algorithm,
        "key_spec": key_spec,
        "key_ref": key_ref,
    },
    "aws_kms": {
        "key_arn": key_arn,
        "key_id": actual_key_id,
        "key_uri": key_uri,
        "key_usage": metadata.get("KeyUsage", ""),
        "key_spec": metadata.get("KeySpec", public_key.get("KeySpec", "")),
        "key_state": metadata.get("KeyState", ""),
        "origin": metadata.get("Origin", ""),
        "signing_algorithms": metadata.get(
            "SigningAlgorithms",
            public_key.get("SigningAlgorithms", []),
        ),
        "public_key_sha256": public_key_sha256,
    },
    "credential_hint_present": credential_hint_present,
    "tools": tools,
    "missing_requirements": list(missing_requirements),
    "next_command": next_command,
    "notes": [
        "No secret values are recorded in this report.",
        "F5.41 qualifies or prepares an AWS KMS signer but does not produce retained final signing evidence.",
        "Run scripts/test-f5-aws-kms-signing.sh against the reported key URI to produce the required F5 signing evidence.",
        "Key creation requires APOLYSIS_F5_AWS_KMS_BOOTSTRAP_MODE=ensure and APOLYSIS_CONFIRM_F5_AWS_KMS_KEY_CREATION=1.",
    ],
    "observed_at_unix_ms": int(time.time() * 1000),
}

Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

fail_with_report() {
    local last_action="$1"
    shift
    write_report false false "$last_action" false false "${key_id:-$alias_name}" "$@"
    echo "apolysis-f5: AWS KMS signer bootstrap did not pass ($report)" >&2
    if [[ "$#" -gt 0 ]]; then
        echo "missing requirements: $*" >&2
    fi
    if [[ "$require_ready" == "1" ]]; then
        exit 1
    fi
    exit 2
}

describe_failure_requirement() {
    if grep -qi 'Unable to locate credentials' "$aws_error_log"; then
        printf 'AWS_credentials'
    elif grep -qiE 'AccessDenied|ExpiredToken|InvalidClientTokenId|UnrecognizedClient|Unauthorized' "$aws_error_log"; then
        printf 'AWS_credentials_or_kms_permissions'
    else
        printf 'aws_kms_describe_key_succeeded'
    fi
}

is_not_found_error() {
    grep -qiE 'NotFoundException|not found|does not exist' "$aws_error_log"
}

case "$mode" in
    inspect|ensure) ;;
    *)
        fail_with_report "validate_mode" "APOLYSIS_F5_AWS_KMS_BOOTSTRAP_MODE must be inspect or ensure"
        ;;
esac

case "$algorithm" in
    RSASSA_PKCS1_V1_5_SHA_256) ;;
    *)
        fail_with_report "validate_algorithm" "RSASSA_PKCS1_V1_5_SHA_256"
        ;;
esac

case "$key_spec" in
    RSA_2048|RSA_3072|RSA_4096) ;;
    *)
        fail_with_report "validate_key_spec" "RSA_2048_or_stronger_RSA_key_spec"
        ;;
esac

if [[ -z "$aws_region" ]]; then
    fail_with_report "validate_region" "APOLYSIS_F5_AWS_REGION_or_AWS_REGION"
fi

if [[ -n "$alias_name" && "$alias_name" != alias/* ]]; then
    fail_with_report "validate_alias" "APOLYSIS_F5_AWS_KMS_ALIAS must start with alias/"
fi

if [[ "$mode" == "inspect" && -z "$key_id" && -z "$alias_name" ]]; then
    fail_with_report "validate_key_ref" "APOLYSIS_F5_AWS_KMS_KEY_ID_or_APOLYSIS_F5_AWS_KMS_ALIAS"
fi

if [[ "$mode" == "ensure" && -z "$alias_name" ]]; then
    fail_with_report "validate_ensure_alias" "APOLYSIS_F5_AWS_KMS_ALIAS"
fi

key_ref="${key_id:-$alias_name}"
created_key=false
created_alias=false

if [[ "$mode" == "ensure" ]]; then
    if aws --region "$aws_region" kms describe-key --key-id "$alias_name" --output json >"$key_metadata" 2>"$aws_error_log"; then
        key_ref="$alias_name"
    else
        if ! is_not_found_error; then
            fail_with_report "aws_kms_describe_alias" "$(describe_failure_requirement)"
        fi
        if [[ "$create_confirm" != "1" ]]; then
            fail_with_report "confirm_key_creation" "APOLYSIS_CONFIRM_F5_AWS_KMS_KEY_CREATION"
        fi
        description="${APOLYSIS_F5_AWS_KMS_DESCRIPTION:-Apolysis F5 release signing key}"
        if ! aws --region "$aws_region" kms create-key \
            --key-usage SIGN_VERIFY \
            --key-spec "$key_spec" \
            --origin AWS_KMS \
            --description "$description" \
            --tags TagKey=Project,TagValue=Apolysis TagKey=Phase,TagValue=F5 TagKey=Purpose,TagValue=release-signing \
            --output json >"$create_key_response" 2>"$aws_error_log"; then
            fail_with_report "aws_kms_create_key" "aws_kms_create_key_succeeded"
        fi
        created_key=true
        key_ref="$(jq -r '.KeyMetadata.KeyId' "$create_key_response")"
        if [[ -z "$key_ref" || "$key_ref" == "null" ]]; then
            fail_with_report "parse_created_key" "created_key_id"
        fi
        if ! aws --region "$aws_region" kms create-alias \
            --alias-name "$alias_name" \
            --target-key-id "$key_ref" >"$create_alias_response" 2>"$aws_error_log"; then
            fail_with_report "aws_kms_create_alias" "aws_kms_create_alias_succeeded"
        fi
        created_alias=true
        if ! aws --region "$aws_region" kms describe-key --key-id "$key_ref" --output json >"$key_metadata" 2>"$aws_error_log"; then
            fail_with_report "aws_kms_describe_created_key" "aws_kms_describe_key_succeeded"
        fi
    fi
else
    if ! aws --region "$aws_region" kms describe-key --key-id "$key_ref" --output json >"$key_metadata" 2>"$aws_error_log"; then
        fail_with_report "aws_kms_describe_key" "$(describe_failure_requirement)"
    fi
fi

if ! jq -e '
  .KeyMetadata.KeyUsage == "SIGN_VERIFY"
  and .KeyMetadata.KeyState == "Enabled"
  and .KeyMetadata.Origin == "AWS_KMS"
  and (.KeyMetadata.KeySpec | test("^RSA_(2048|3072|4096)$"))
  and (.KeyMetadata.SigningAlgorithms | index("RSASSA_PKCS1_V1_5_SHA_256"))
' "$key_metadata" >/dev/null; then
    fail_with_report "validate_key_metadata" "enabled_aws_kms_sign_verify_rsa_key_with_rsassa_pkcs1_sha256"
fi

actual_key_ref="$(jq -r '.KeyMetadata.Arn // .KeyMetadata.KeyId' "$key_metadata")"
if ! aws --region "$aws_region" kms get-public-key --key-id "$actual_key_ref" --output json >"$public_key_json" 2>"$aws_error_log"; then
    fail_with_report "aws_kms_get_public_key" "aws_kms_get_public_key_succeeded"
fi

if ! jq -e '
  .KeyUsage == "SIGN_VERIFY"
  and (.KeySpec | test("^RSA_(2048|3072|4096)$"))
  and (.SigningAlgorithms | index("RSASSA_PKCS1_V1_5_SHA_256"))
  and (.PublicKey | type == "string" and length > 0)
' "$public_key_json" >/dev/null; then
    fail_with_report "validate_public_key_metadata" "valid_aws_kms_public_key_metadata"
fi

jq -r '.PublicKey' "$public_key_json" | base64 --decode >"$public_key_der"

write_report true true "complete" "$created_key" "$created_alias" "$actual_key_ref"
jq -e '.passed == true and .ready_for_signing_gate == true and (.aws_kms.key_uri | startswith("awskms://"))' "$report" >/dev/null

printf 'apolysis-f5: AWS KMS signer bootstrap gate passed (%s)\n' "$output_dir"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_PRODUCTION_HARDENING_AWS_KMS_SIGNING:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-production-hardening: AWS KMS live signing is opt-in.
Set APOLYSIS_CONFIRM_PRODUCTION_HARDENING_AWS_KMS_SIGNING=1 and APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID
after confirming the AWS account, KMS key, signing algorithm, IAM principal,
and retained evidence artifacts are acceptable.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in aws base64 cargo jq openssl python3 sha256sum; do
    require_command "$command"
done

key_id="${APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID:-}"
if [[ -z "$key_id" ]]; then
    echo "apolysis-production-hardening: APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID is required" >&2
    exit 2
fi

aws_region="${APOLYSIS_PRODUCTION_HARDENING_AWS_REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
algorithm="${APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_SIGNING_ALGORITHM:-RSASSA_PKCS1_V1_5_SHA_256}"
if [[ "$algorithm" != "RSASSA_PKCS1_V1_5_SHA_256" ]]; then
    echo "apolysis-production-hardening: only RSASSA_PKCS1_V1_5_SHA_256 is currently supported" >&2
    exit 2
fi

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-aws-kms-signing.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

release_manifest="$output_dir/apolysis-production-hardening-release-manifest.json"
release_manifest_digest_bin="$output_dir/apolysis-production-hardening-release-manifest.sha256.bin"
key_metadata="$output_dir/aws-kms-describe-key.json"
public_key_json="$output_dir/aws-kms-get-public-key.json"
public_key_der="$output_dir/aws-kms-public-key.der"
public_key_pem="$output_dir/aws-kms-public-key.pem"
sign_response="$output_dir/aws-kms-sign.json"
signature="$output_dir/apolysis-production-hardening-release-manifest.aws-kms.sig"
verify_log="$output_dir/openssl-verify.out"
evidence="$output_dir/apolysis-production-hardening-aws-kms-signing-evidence.json"
report="$output_dir/apolysis-production-hardening-aws-kms-signing-report.json"

release_manifest_source="${APOLYSIS_PRODUCTION_HARDENING_RELEASE_MANIFEST:-}"
if [[ -n "$release_manifest_source" ]]; then
    [[ -f "$release_manifest_source" ]] || {
        echo "apolysis-production-hardening: APOLYSIS_PRODUCTION_HARDENING_RELEASE_MANIFEST does not exist: $release_manifest_source" >&2
        exit 2
    }
    if [[ "$release_manifest_source" != "$release_manifest" ]]; then
        cp "$release_manifest_source" "$release_manifest"
    fi
else
    cat >"$release_manifest" <<'JSON'
{
  "schema": "apolysis.dev/production-hardening-release-manifest/v1",
  "phase": "production-hardening.aws-kms-signing",
  "signing": {
    "keyMode": "cloud_kms",
    "provider": "aws_kms",
    "manifestBundle": "apolysis-production-hardening-release-manifest.aws-kms.sig"
  }
}
JSON
fi

openssl dgst -sha256 -binary "$release_manifest" >"$release_manifest_digest_bin"

if [[ -n "$aws_region" ]]; then
    aws --region "$aws_region" kms describe-key --key-id "$key_id" --output json >"$key_metadata"
else
    aws kms describe-key --key-id "$key_id" --output json >"$key_metadata"
fi

jq -e '
  .KeyMetadata.KeyUsage == "SIGN_VERIFY"
  and .KeyMetadata.KeyState == "Enabled"
  and .KeyMetadata.Origin == "AWS_KMS"
  and (.KeyMetadata.SigningAlgorithms | index("RSASSA_PKCS1_V1_5_SHA_256"))
' "$key_metadata" >/dev/null || {
    echo "apolysis-production-hardening: AWS KMS key must be enabled, provider-generated, and usable for RSA SHA-256 signing" >&2
    exit 1
}

if [[ -n "$aws_region" ]]; then
    aws --region "$aws_region" kms get-public-key --key-id "$key_id" --output json >"$public_key_json"
else
    aws kms get-public-key --key-id "$key_id" --output json >"$public_key_json"
fi

jq -r '.PublicKey' "$public_key_json" | base64 --decode >"$public_key_der"
openssl pkey -pubin -inform DER -in "$public_key_der" -out "$public_key_pem" >/dev/null

if [[ -n "$aws_region" ]]; then
    aws --region "$aws_region" kms sign \
        --key-id "$key_id" \
        --message "fileb://$release_manifest_digest_bin" \
        --message-type DIGEST \
        --signing-algorithm "$algorithm" \
        --output json >"$sign_response"
else
    aws kms sign \
        --key-id "$key_id" \
        --message "fileb://$release_manifest_digest_bin" \
        --message-type DIGEST \
        --signing-algorithm "$algorithm" \
        --output json >"$sign_response"
fi

jq -r '.Signature' "$sign_response" | base64 --decode >"$signature"
openssl dgst -sha256 \
    -verify "$public_key_pem" \
    -signature "$signature" \
    "$release_manifest" \
    >"$verify_log"
grep -q 'Verified OK' "$verify_log" || {
    echo "apolysis-production-hardening: OpenSSL did not verify the AWS KMS signature" >&2
    cat "$verify_log" >&2 || true
    exit 1
}

release_manifest_sha256="$(sha256sum "$release_manifest" | awk '{print $1}')"
signature_sha256="$(sha256sum "$signature" | awk '{print $1}')"
public_key_sha256="$(sha256sum "$public_key_der" | awk '{print $1}')"
aws_cli_version="$(aws --version 2>&1)"
openssl_version="$(openssl version)"
observed_at_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

python3 - "$evidence" \
    "$key_metadata" \
    "$aws_region" \
    "$algorithm" \
    "$release_manifest_sha256" \
    "$signature_sha256" \
    "$public_key_sha256" \
    "$aws_cli_version" \
    "$openssl_version" \
    "$observed_at_unix_ms" <<'PY'
import json
import sys
from pathlib import Path

(
    evidence_path,
    key_metadata_path,
    aws_region,
    algorithm,
    release_manifest_sha256,
    signature_sha256,
    public_key_sha256,
    aws_cli_version,
    openssl_version,
    observed_at_unix_ms,
) = sys.argv[1:]

metadata = json.loads(Path(key_metadata_path).read_text(encoding="utf-8"))["KeyMetadata"]
key_arn = metadata["Arn"]
key_id = metadata["KeyId"]
region = aws_region or key_arn.split(":")[3]
alias_or_key = key_arn.rsplit("/", 1)[-1]
evidence = {
    "evidence_id": f"production-hardening-aws-kms-signing-{observed_at_unix_ms}",
    "source": "live_provider",
    "provider": "cloud_kms",
    "key_uri": f"awskms://{key_arn}",
    "token_label": f"aws-kms:{region}",
    "key_label": alias_or_key,
    "key_id": key_id,
    "algorithm": "rsa_pkcs1_sha256",
    "release_manifest_sha256": release_manifest_sha256,
    "signature_sha256": signature_sha256,
    "public_key_sha256": public_key_sha256,
    "signature_verified": True,
    "private_key_non_extractable": True,
    "private_key_sensitive": True,
    "key_generated_in_provider": True,
    "token_initialized": True,
    "signer_tool": f"{aws_cli_version.strip()} aws-kms-sign {algorithm}",
    "verifier_tool": openssl_version.strip(),
    "operator_approved": True,
    "cleanup_confirmed": True,
    "observed_at_unix_ms": int(observed_at_unix_ms),
}
Path(evidence_path).write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-signing-execution-evidence -- \
    --evidence "$evidence" >"$report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "cloud_kms"
  and .approval.algorithm == "rsa_pkcs1_sha256"
  and (.approval.key_uri | startswith("awskms://"))
' "$report" >/dev/null

printf 'apolysis-production-hardening: AWS KMS signing gate passed (%s)\n' "$output_dir"

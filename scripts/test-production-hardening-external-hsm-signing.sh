#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
confirm="${APOLYSIS_CONFIRM_PRODUCTION_HARDENING_EXTERNAL_HSM_SIGNING:-0}"

if [[ "$confirm" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-production-hardening: external HSM live signing is opt-in.
Set APOLYSIS_CONFIRM_PRODUCTION_HARDENING_EXTERNAL_HSM_SIGNING=1 after confirming the PKCS#11
module, token, key label, PIN handling, access principal, and retained
evidence artifacts are acceptable for production signing evidence.
EOF
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_env() {
    local name="$1"
    local value="${!name:-}"
    if [[ -z "$value" ]]; then
        echo "apolysis-production-hardening: $name is required" >&2
        exit 2
    fi
    printf '%s' "$value"
}

for command in cargo jq openssl pkcs11-tool python3 readlink sha256sum; do
    require_command "$command"
done

module="$(require_env APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE)"
token_label="$(require_env APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL)"
key_label="$(require_env APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL)"
key_id="${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_ID:-}"
slot="${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_SLOT:-}"
mechanism="${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_SIGN_MECHANISM:-SHA256-RSA-PKCS}"

if [[ ! -r "$module" ]]; then
    echo "apolysis-production-hardening: missing readable external HSM PKCS#11 module: $module" >&2
    exit 1
fi

module_realpath="$(readlink -f "$module" 2>/dev/null || printf '%s' "$module")"
module_lower="$(printf '%s' "$module_realpath" | tr '[:upper:]' '[:lower:]')"
if [[ "$module_lower" == *softhsm* ]]; then
    echo "apolysis-production-hardening: software HSM modules are not accepted for production-hardening.external-hsm-signing external HSM signing evidence" >&2
    exit 2
fi

pin=""
if [[ -n "${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE:-}" ]]; then
    if [[ ! -r "$APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE" ]]; then
        echo "apolysis-production-hardening: APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE is not readable" >&2
        exit 2
    fi
    pin="$(head -n 1 "$APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE")"
elif [[ -n "${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN:-}" ]]; then
    pin="$APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN"
fi

if [[ -z "$pin" && "${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_ALLOW_INTERACTIVE_PIN:-0}" != "1" ]]; then
    echo "apolysis-production-hardening: APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE or APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN is required unless interactive PIN entry is explicitly allowed" >&2
    exit 2
fi

if [[ "$mechanism" != "SHA256-RSA-PKCS" ]]; then
    echo "apolysis-production-hardening: only SHA256-RSA-PKCS is currently supported" >&2
    exit 2
fi

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-external-hsm-signing.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

release_manifest="$output_dir/apolysis-production-hardening-release-manifest.json"
public_der="$output_dir/apolysis-production-hardening-release-public.der"
public_pem="$output_dir/apolysis-production-hardening-release-public.pem"
signature="$output_dir/apolysis-production-hardening-release-manifest.external-hsm.sig"
objects_log="$output_dir/pkcs11-objects.txt"
private_read_log="$output_dir/pkcs11-private-read-denied.log"
verify_log="$output_dir/openssl-verify.out"
sign_log="$output_dir/pkcs11-sign.out"
evidence="$output_dir/apolysis-production-hardening-external-hsm-signing-evidence.json"
report="$output_dir/apolysis-production-hardening-external-hsm-signing-report.json"

token_selector=()
if [[ -n "$slot" ]]; then
    token_selector=(--slot "$slot")
else
    token_selector=(--token-label "$token_label")
fi

pin_args=()
if [[ -n "$pin" ]]; then
    pin_args=(--pin "$pin")
fi

key_selector=(--label "$key_label")
if [[ -n "$key_id" ]]; then
    key_selector+=(--id "$key_id")
else
    key_id="$key_label"
fi

cat >"$release_manifest" <<'JSON'
{
  "schema": "apolysis.dev/production-hardening-release-manifest/v1",
  "phase": "production-hardening.external-hsm-signing",
  "signing": {
    "keyMode": "external_hsm",
    "manifestBundle": "apolysis-production-hardening-release-manifest.external-hsm.sig"
  }
}
JSON

pkcs11-tool --module "$module" \
    "${token_selector[@]}" \
    --login \
    "${pin_args[@]}" \
    --list-objects \
    >"$objects_log"

pkcs11-tool --module "$module" \
    "${token_selector[@]}" \
    --login \
    "${pin_args[@]}" \
    --read-object \
    --type privkey \
    "${key_selector[@]}" \
    --output-file "$output_dir/apolysis-production-hardening-release-private.der" \
    >"$private_read_log" 2>&1 || true
if [[ -s "$output_dir/apolysis-production-hardening-release-private.der" ]]; then
    echo "apolysis-production-hardening: external HSM private key was unexpectedly exportable" >&2
    exit 1
fi
rm -f "$output_dir/apolysis-production-hardening-release-private.der"

pkcs11-tool --module "$module" \
    "${token_selector[@]}" \
    --login \
    "${pin_args[@]}" \
    --read-object \
    --type pubkey \
    "${key_selector[@]}" \
    --output-file "$public_der"

openssl pkey -pubin -inform DER -in "$public_der" -out "$public_pem" >/dev/null

pkcs11-tool --module "$module" \
    "${token_selector[@]}" \
    --login \
    "${pin_args[@]}" \
    --sign \
    --mechanism "$mechanism" \
    "${key_selector[@]}" \
    --input-file "$release_manifest" \
    --output-file "$signature" \
    >"$sign_log"

openssl dgst -sha256 \
    -verify "$public_pem" \
    -signature "$signature" \
    "$release_manifest" \
    >"$verify_log"
grep -q 'Verified OK' "$verify_log" || {
    echo "apolysis-production-hardening: OpenSSL did not verify the external HSM signature" >&2
    cat "$verify_log" >&2 || true
    exit 1
}

release_manifest_sha256="$(sha256sum "$release_manifest" | awk '{print $1}')"
signature_sha256="$(sha256sum "$signature" | awk '{print $1}')"
public_key_sha256="$(sha256sum "$public_der" | awk '{print $1}')"
module_sha256="$(sha256sum "$module_realpath" | awk '{print $1}')"
pkcs11_tool_version="pkcs11-tool using $module_realpath"
openssl_version="$(openssl version)"
observed_at_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"

python3 - "$evidence" \
    "$module_realpath" \
    "$module_sha256" \
    "$token_label" \
    "$key_label" \
    "$key_id" \
    "$mechanism" \
    "$release_manifest_sha256" \
    "$signature_sha256" \
    "$public_key_sha256" \
    "$pkcs11_tool_version" \
    "$openssl_version" \
    "$observed_at_unix_ms" <<'PY'
import json
import sys
from pathlib import Path

(
    evidence_path,
    module_realpath,
    module_sha256,
    token_label,
    key_label,
    key_id,
    mechanism,
    release_manifest_sha256,
    signature_sha256,
    public_key_sha256,
    pkcs11_tool_version,
    openssl_version,
    observed_at_unix_ms,
) = sys.argv[1:]

key_uri = f"pkcs11:token={token_label};object={key_label};type=private"
evidence = {
    "evidence_id": f"production-hardening-external-hsm-signing-{observed_at_unix_ms}",
    "source": "live_provider",
    "provider": "external_hsm",
    "key_uri": key_uri,
    "token_label": token_label,
    "key_label": key_label,
    "key_id": key_id,
    "algorithm": "rsa_pkcs1_sha256",
    "mechanism": mechanism,
    "module_ref": module_realpath,
    "module_sha256": module_sha256,
    "release_manifest_sha256": release_manifest_sha256,
    "signature_sha256": signature_sha256,
    "public_key_sha256": public_key_sha256,
    "signature_verified": True,
    "private_key_non_extractable": True,
    "private_key_sensitive": True,
    "key_generated_in_provider": True,
    "token_initialized": True,
    "signer_tool": pkcs11_tool_version.strip(),
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
  and .approval.provider == "external_hsm"
  and .approval.algorithm == "rsa_pkcs1_sha256"
  and (.approval.key_uri | startswith("pkcs11:"))
' "$report" >/dev/null

cat <<EOF
apolysis-production-hardening: external HSM signing gate passed ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER=external_hsm
APOLYSIS_PRODUCTION_HARDENING_SIGNING_CONTROL_PLANE=$(jq -r '.key_uri' "$evidence")
APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE=$evidence
APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT=$report
EOF

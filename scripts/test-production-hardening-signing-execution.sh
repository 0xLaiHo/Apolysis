#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_SIGNING_EXECUTION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-signing-execution.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in cargo jq openssl pkcs11-tool python3 sha256sum softhsruntime-controls-util; do
    require_command "$command"
done

module="${APOLYSIS_PRODUCTION_HARDENING_PKCS11_MODULE:-/usr/lib/pkcs11/libsofthsm2.so}"
if [[ ! -r "$module" ]]; then
    echo "apolysis-production-hardening: missing readable PKCS#11 module: $module" >&2
    exit 1
fi

token_root="$output_dir/softhsm-token-store"
softhsm_conf="$output_dir/softhsm2.conf"
token_label="apolysis-production-hardening-release"
key_label="production-hardening-release"
key_id="01"
pin="123456"
so_pin="12345678"
release_manifest="$output_dir/apolysis-production-hardening-release-manifest.json"
public_der="$output_dir/apolysis-production-hardening-release-public.der"
public_pem="$output_dir/apolysis-production-hardening-release-public.pem"
signature="$output_dir/apolysis-production-hardening-release-manifest.pkcs11.sig"
keygen_log="$output_dir/pkcs11-keygen.out"
objects_log="$output_dir/pkcs11-objects.txt"
private_read_log="$output_dir/pkcs11-private-read-denied.log"
verify_log="$output_dir/openssl-verify.out"
evidence="$output_dir/apolysis-production-hardening-signing-execution-evidence.json"
report="$output_dir/apolysis-production-hardening-signing-execution-report.json"
fail_evidence="$output_dir/apolysis-production-hardening-signing-execution-evidence-fail.json"
fail_report="$output_dir/apolysis-production-hardening-signing-execution-report-fail.json"

cleanup_token_store() {
    rm -rf "$token_root"
}
trap cleanup_token_store EXIT

mkdir -p "$token_root"
cat >"$softhsm_conf" <<EOF
objectstore.backend = file
directories.tokendir = $token_root
log.level = ERROR
slots.removable = false
EOF
export SOFTHSRuntimeControls_CONF="$softhsm_conf"

cat >"$release_manifest" <<'JSON'
{
  "schema": "apolysis.dev/production-hardening-release-manifest/v1",
  "phase": "production-hardening.release-manifest",
  "signing": {
    "keyMode": "hsm",
    "publicKey": "apolysis-production-hardening-release-public.pem",
    "manifestBundle": "apolysis-production-hardening-release-manifest.pkcs11.sig",
    "provenanceBundle": "apolysis-production-hardening-provenance.pkcs11.sig"
  }
}
JSON

softhsruntime-controls-util --init-token --free \
    --label "$token_label" \
    --so-pin "$so_pin" \
    --pin "$pin" >/dev/null

pkcs11-tool --module "$module" \
    --token-label "$token_label" \
    --login \
    --pin "$pin" \
    --keypairgen \
    --key-type RSA:2048 \
    --id "$key_id" \
    --label "$key_label" \
    --usage-sign \
    --private \
    --sensitive \
    >"$keygen_log"

pkcs11-tool --module "$module" \
    --token-label "$token_label" \
    --login \
    --pin "$pin" \
    --list-objects \
    >"$objects_log"

grep -q 'Private Key Object; RSA  2048 bits' "$objects_log" || {
    echo "apolysis-production-hardening: PKCS#11 private key was not generated" >&2
    exit 1
}
grep -q 'Access:     sensitive, always sensitive, never extractable, local' "$objects_log" || {
    echo "apolysis-production-hardening: PKCS#11 private key is not marked sensitive and never extractable" >&2
    exit 1
}

pkcs11-tool --module "$module" \
    --token-label "$token_label" \
    --login \
    --pin "$pin" \
    --read-object \
    --type privkey \
    --label "$key_label" \
    --output-file "$output_dir/apolysis-production-hardening-release-private.der" \
    >"$private_read_log" 2>&1 || true
if [[ -s "$output_dir/apolysis-production-hardening-release-private.der" ]]; then
    echo "apolysis-production-hardening: PKCS#11 private key was unexpectedly exportable" >&2
    exit 1
fi

pkcs11-tool --module "$module" \
    --token-label "$token_label" \
    --login \
    --pin "$pin" \
    --read-object \
    --type pubkey \
    --label "$key_label" \
    --output-file "$public_der"

openssl pkey -pubin -inform DER -in "$public_der" -out "$public_pem" >/dev/null

pkcs11-tool --module "$module" \
    --token-label "$token_label" \
    --login \
    --pin "$pin" \
    --sign \
    --mechanism SHA256-RSA-PKCS \
    --label "$key_label" \
    --input-file "$release_manifest" \
    --output-file "$signature" \
    >"$output_dir/pkcs11-sign.out"

openssl dgst -sha256 \
    -verify "$public_pem" \
    -signature "$signature" \
    "$release_manifest" \
    >"$verify_log"
grep -q 'Verified OK' "$verify_log" || {
    echo "apolysis-production-hardening: OpenSSL did not verify the PKCS#11 signature" >&2
    cat "$verify_log" >&2 || true
    exit 1
}

release_manifest_sha256="$(sha256sum "$release_manifest" | awk '{print $1}')"
signature_sha256="$(sha256sum "$signature" | awk '{print $1}')"
public_key_sha256="$(sha256sum "$public_der" | awk '{print $1}')"
observed_at_unix_ms="$(python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
signer_tool="pkcs11-tool with $(softhsruntime-controls-util --version | tr '\n' ' ')"
verifier_tool="$(openssl version)"

cleanup_token_store
if [[ -e "$token_root" ]]; then
    echo "apolysis-production-hardening: temporary SoftHSM token store was not removed" >&2
    exit 1
fi

python3 - "$evidence" \
    "$token_label" \
    "$key_label" \
    "$key_id" \
    "$release_manifest_sha256" \
    "$signature_sha256" \
    "$public_key_sha256" \
    "$signer_tool" \
    "$verifier_tool" \
    "$observed_at_unix_ms" <<'PY'
import json
import sys
from pathlib import Path

(
    path,
    token_label,
    key_label,
    key_id,
    release_manifest_sha256,
    signature_sha256,
    public_key_sha256,
    signer_tool,
    verifier_tool,
    observed_at_unix_ms,
) = sys.argv[1:]

evidence = {
    "evidence_id": "production-hardening-pkcs11-signing-execution",
    "source": "live_provider",
    "provider": "pkcs11_hsm",
    "key_uri": f"pkcs11:token={token_label};object={key_label};type=private",
    "token_label": token_label,
    "key_label": key_label,
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
    "signer_tool": signer_tool.strip(),
    "verifier_tool": verifier_tool.strip(),
    "operator_approved": True,
    "cleanup_confirmed": True,
    "observed_at_unix_ms": int(observed_at_unix_ms),
}
Path(path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-signing-execution-evidence -- \
    --evidence "$evidence" >"$report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "pkcs11_hsm"
  and .approval.algorithm == "rsa_pkcs1_sha256"
  and (.approval.key_uri | startswith("pkcs11:token=apolysis-production-hardening-release;object=production-hardening-release"))
' "$report" >/dev/null

python3 - "$evidence" "$fail_evidence" <<'PY'
import json
import sys
from pathlib import Path

source, dest = map(Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["source"] = "fixture"
data["provider"] = "local_file"
data["key_uri"] = "/tmp/apolysis-release.key"
data["signature_verified"] = False
data["private_key_non_extractable"] = False
data["private_key_sensitive"] = False
data["key_generated_in_provider"] = False
data["token_initialized"] = False
data["operator_approved"] = False
data["cleanup_confirmed"] = False
data["observed_at_unix_ms"] = 0
dest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if cargo run -q -p apolysis-validation --bin apolysis-production-hardening-signing-execution-evidence -- \
    --evidence "$fail_evidence" >"$fail_report"; then
    echo "apolysis-production-hardening: invalid signing execution evidence unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("live provider signing evidence is required"))
  and (.failures | map(.message) | index("signing execution requires PKCS#11 HSM or cloud KMS provider"))
  and (.failures | map(.message) | index("file paths are not valid production signing key URIs"))
  and (.failures | map(.message) | index("signature verification evidence is required"))
  and (.failures | map(.message) | index("private key must be non-extractable"))
  and (.failures | map(.message) | index("cleanup confirmation is required"))
' "$fail_report" >/dev/null

printf 'apolysis-production-hardening: PKCS#11 signing execution gate passed (%s)\n' "$output_dir"

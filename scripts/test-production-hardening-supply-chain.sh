#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_SUPPLY_CHAIN_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-supply-chain-test.XXXXXX")}"
verification_dir="$output_dir/verification"
trivy_cache_dir="${APOLYSIS_PRODUCTION_HARDENING_TRIVY_CACHE_DIR:-$repo_root/target/trivy-cache}"
max_high_critical="${APOLYSIS_PRODUCTION_HARDENING_MAX_HIGH_CRITICAL_VULNS:-0}"
expected_key_mode="ephemeral-local-validation"
if [[ -n "${APOLYSIS_PRODUCTION_HARDENING_RELEASE_SIGNING_KEY:-}" ]]; then
    expected_key_mode="external"
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

for command in cosign jq sha256sum syft trivy; do
    require_command "$command"
done

mkdir -p "$verification_dir" "$trivy_cache_dir"

APOLYSIS_PRODUCTION_HARDENING_RELEASE_OUTPUT_DIR="$output_dir" \
APOLYSIS_PRODUCTION_HARDENING_TRIVY_CACHE_DIR="$trivy_cache_dir" \
    "$repo_root/scripts/build-production-hardening-release-bundle.sh"

manifest="$output_dir/apolysis-production-hardening-release-manifest.json"
public_key="$output_dir/apolysis-production-hardening-release.pub"
manifest_bundle="$output_dir/apolysis-production-hardening-release-manifest.sigstore.json"
provenance="$output_dir/apolysis-production-hardening-provenance.intoto.json"
provenance_bundle="$output_dir/apolysis-production-hardening-provenance.sigstore.json"
sbom="$output_dir/apolysis-production-hardening-sbom.cdx.json"
vulnerability_scan="$output_dir/apolysis-production-hardening-vulnerability-scan.json"
checksums="$output_dir/apolysis-production-hardening-release-checksums.sha256"

for artifact in \
    "$manifest" \
    "$public_key" \
    "$manifest_bundle" \
    "$provenance" \
    "$provenance_bundle" \
    "$sbom" \
    "$vulnerability_scan" \
    "$checksums" \
    "$output_dir/apolysis-production-hardening-release-payload.tar.gz" \
    "$output_dir/apolysis-production-hardening-apolysisd-image.tar"; do
    if [[ ! -s "$artifact" ]]; then
        echo "apolysis-production-hardening: missing release supply-chain artifact: $artifact" >&2
        exit 1
    fi
done

(
    cd "$output_dir"
    sha256sum -c apolysis-production-hardening-release-checksums.sha256
)

cosign verify-blob --key "$public_key" --bundle "$manifest_bundle" "$manifest" >/dev/null
cosign verify-blob --key "$public_key" --bundle "$provenance_bundle" "$provenance" >/dev/null

syft scan dir:"$output_dir/staging" -q \
    -o cyclonedx-json="$verification_dir/apolysis-production-hardening-sbom-rescan.cdx.json"
trivy fs \
    --quiet \
    --format json \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --output "$verification_dir/apolysis-production-hardening-vulnerability-rescan.json" \
    "$output_dir/staging"

jq -e --arg expected_key_mode "$expected_key_mode" '
  .schema == "apolysis.dev/production-hardening-release-manifest/v1"
  and .phase == "production-hardening.release-manifest"
  and (.git.commit | test("^[0-9a-f]{40}$"))
  and (.image.archive == "apolysis-production-hardening-apolysisd-image.tar")
  and (.signing.keyMode == $expected_key_mode)
  and (.signing.publicKey == "apolysis-production-hardening-release.pub")
  and (.signing.manifestBundle == "apolysis-production-hardening-release-manifest.sigstore.json")
  and (.signing.provenanceBundle == "apolysis-production-hardening-provenance.sigstore.json")
  and (.tools.cosign.gitVersion | type == "string")
  and (.tools.syft.version | type == "string")
  and (.tools.trivy.Version | type == "string")
  and ([.files[].path] | index("apolysis-production-hardening-release-payload.tar.gz"))
  and ([.files[].path] | index("apolysis-production-hardening-apolysisd-image.tar"))
  and ([.files[].path] | index("apolysis-production-hardening-sbom.cdx.json"))
  and ([.files[].path] | index("apolysis-production-hardening-vulnerability-scan.json"))
  and ([.files[].path] | index("apolysis-production-hardening-provenance.intoto.json"))
  and ([.stagingFiles[].path] | index("bin/apolysisd"))
  and ([.stagingFiles[].path] | index("bin/apolysisd-health"))
  and ([.stagingFiles[].path] | index("lib/apolysis/apolysis_observer.bpf.o"))
  and ([.stagingFiles[].path] | index("deploy/kubernetes/apolysisd-production-baseline.yaml"))
  and ([.stagingFiles[].path] | index("deploy/helm/apolysis/Chart.yaml"))
  and all(.files[]; (.sha256 | test("^[0-9a-f]{64}$")) and (.size > 0))
' "$manifest" >/dev/null

jq -e '
  .bomFormat == "CycloneDX"
  and (.components | type == "array")
  and (.components | length > 0)
' "$sbom" >/dev/null

jq -e '
  .bomFormat == "CycloneDX"
  and (.components | type == "array")
  and (.components | length > 0)
' "$verification_dir/apolysis-production-hardening-sbom-rescan.cdx.json" >/dev/null

jq -e --arg expected_key_mode "$expected_key_mode" '
  ._type == "https://in-toto.io/Statement/v1"
  and .predicateType == "https://slsa.dev/provenance/v1"
  and ([.subject[].name] | index("apolysis-production-hardening-release-payload.tar.gz"))
  and ([.subject[].name] | index("apolysis-production-hardening-apolysisd-image.tar"))
  and (.predicate.buildDefinition.buildType == "https://apolysis.dev/buildtypes/production-hardening-release-bundle/v1")
  and (.predicate.buildDefinition.internalParameters.signingKeyMode == $expected_key_mode)
' "$provenance" >/dev/null

high_critical_count="$(
    jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' \
        "$vulnerability_scan"
)"
rescan_high_critical_count="$(
    jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' \
        "$verification_dir/apolysis-production-hardening-vulnerability-rescan.json"
)"

if (( high_critical_count > max_high_critical )); then
    echo "apolysis-production-hardening: release vulnerability scan found $high_critical_count high/critical findings" >&2
    exit 1
fi
if (( rescan_high_critical_count > max_high_critical )); then
    echo "apolysis-production-hardening: verification vulnerability scan found $rescan_high_critical_count high/critical findings" >&2
    exit 1
fi

printf 'apolysis-production-hardening: supply-chain release gate passed (%s)\n' "$output_dir"

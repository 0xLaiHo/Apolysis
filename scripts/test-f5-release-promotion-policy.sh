#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_F5_PROMOTION_POLICY_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-release-promotion-policy.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

for command in cargo jq python3 sha256sum; do
    require_command "$command"
done

release_manifest="$output_dir/apolysis-f5-release-manifest.json"
registry_attachment="$output_dir/apolysis-f5-registry-attachment.json"
archive_manifest="$output_dir/apolysis-f5-immutable-archive-manifest.json"
request="$output_dir/apolysis-f5-release-promotion-request.json"
pass_report="$output_dir/apolysis-f5-release-promotion-policy-pass.json"
fail_request="$output_dir/apolysis-f5-release-promotion-request-fail.json"
fail_report="$output_dir/apolysis-f5-release-promotion-policy-fail.json"

cat >"$release_manifest" <<'JSON'
{
  "schema": "apolysis.dev/f5-release-manifest/v1",
  "phase": "F5.6",
  "signing": {
    "keyMode": "external",
    "publicKey": "apolysis-f5-release.pub",
    "manifestBundle": "apolysis-f5-release-manifest.sigstore.json",
    "provenanceBundle": "apolysis-f5-provenance.sigstore.json"
  },
  "files": [
    {"path": "apolysis-f5-release-payload.tar.gz", "sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 1},
    {"path": "apolysis-f5-apolysisd-image.tar", "sha256": "4444444444444444444444444444444444444444444444444444444444444444", "size": 1},
    {"path": "apolysis-f5-sbom.cdx.json", "sha256": "5555555555555555555555555555555555555555555555555555555555555555", "size": 1},
    {"path": "apolysis-f5-provenance.intoto.json", "sha256": "6666666666666666666666666666666666666666666666666666666666666666", "size": 1}
  ]
}
JSON

release_sha="$(sha256_file "$release_manifest")"
image_digest="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
sbom_digest="sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
source_tag="f5-registry-20260624"
sbom_tag="sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.sbom"

python3 - "$registry_attachment" "$release_sha" "$image_digest" "$sbom_digest" "$source_tag" "$sbom_tag" <<'PY'
import json
import sys
from pathlib import Path

path, release_sha, image_digest, sbom_digest, source_tag, sbom_tag = sys.argv[1:]
data = {
    "schema": "apolysis.dev/f5-registry-attachment/v1",
    "phase": "F5.8",
    "registry": {
        "implementation": "registry:2",
        "repository": "apolysisd",
        "tag": source_tag,
        "imageDigest": image_digest,
        "sbomAttachmentTag": sbom_tag,
        "sbomAttachmentDigest": sbom_digest,
    },
    "releaseArtifacts": {
        "manifest": {
            "path": "release-bundle/apolysis-f5-release-manifest.json",
            "sha256": release_sha,
        },
        "provenance": {
            "path": "release-bundle/apolysis-f5-provenance.intoto.json",
            "sha256": "6666666666666666666666666666666666666666666666666666666666666666",
        },
        "sbom": {
            "path": "release-bundle/apolysis-f5-sbom.cdx.json",
            "sha256": "5555555555555555555555555555555555555555555555555555555555555555",
        },
    },
    "registryObservedState": {
        "tagsAfterSbom": {"tags": [source_tag, sbom_tag]},
    },
}
Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

registry_sha="$(sha256_file "$registry_attachment")"

python3 - "$archive_manifest" "$release_sha" "$registry_sha" <<'PY'
import json
import sys
from pathlib import Path

path, release_sha, registry_sha = sys.argv[1:]
data = {
    "schema": "apolysis.dev/f5-immutable-archive-manifest/v1",
    "phase": "F5.8",
    "archive": {
        "mode": "content-addressed-read-only-local",
        "object": f"objects/sha256-{release_sha}",
        "releaseManifestSha256": release_sha,
        "registryAttachmentSha256": registry_sha,
    },
    "immutability": {
        "directoryMode": "0555",
        "fileMode": "0444",
        "mutationProbe": "denied",
    },
    "artifacts": [
        {"path": "apolysis-f5-release-manifest.json", "sha256": release_sha, "size": 1, "mode": "0444"},
        {"path": "apolysis-f5-registry-attachment.json", "sha256": registry_sha, "size": 1, "mode": "0444"},
        {"path": "apolysis-f5-apolysisd-image.tar", "sha256": "4444444444444444444444444444444444444444444444444444444444444444", "size": 1, "mode": "0444"},
    ],
}
Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 - "$request" "$release_sha" "$image_digest" "$sbom_digest" "$source_tag" <<'PY'
import json
import sys
from pathlib import Path

path, release_sha, image_digest, sbom_digest, source_tag = sys.argv[1:]
requested_at = 1_782_259_200_000
day_ms = 24 * 60 * 60 * 1000
data = {
    "promotion_id": "promote-apolysisd-2026-06-24",
    "channel": "production",
    "source_tag": source_tag,
    "target_tag": "prod-2026-06-24",
    "image_digest": image_digest,
    "sbom_attachment_digest": sbom_digest,
    "release_manifest_sha256": release_sha,
    "retention_days": 180,
    "requested_at_unix_ms": requested_at,
    "retain_until_unix_ms": requested_at + 180 * day_ms,
    "promotion_approved": True,
    "require_digest_pulls": True,
    "allow_anonymous_pull": False,
    "allowed_pull_principals": ["cluster:prod-apolysis-readers"],
    "allowed_push_principals": ["ci:release-promoter"],
    "rollback_tag": "prod-previous",
}
Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cargo run -q -p apolysis-validation --bin apolysis-f5-release-promotion-policy -- \
    --release-manifest "$release_manifest" \
    --registry-attachment "$registry_attachment" \
    --archive-manifest "$archive_manifest" \
    --request "$request" >"$pass_report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.channel == "production"
  and .approval.target_tag == "prod-2026-06-24"
  and .approval.retention_days == 180
' "$pass_report" >/dev/null

python3 - "$request" "$fail_request" <<'PY'
import json
import sys
from pathlib import Path

source, dest = map(Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["target_tag"] = "latest"
data["retention_days"] = 14
data["promotion_approved"] = False
data["require_digest_pulls"] = False
data["allow_anonymous_pull"] = True
data["allowed_pull_principals"] = ["*"]
data["allowed_push_principals"] = ["system:anonymous"]
data["rollback_tag"] = ""
dest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if cargo run -q -p apolysis-validation --bin apolysis-f5-release-promotion-policy -- \
    --release-manifest "$release_manifest" \
    --registry-attachment "$registry_attachment" \
    --archive-manifest "$archive_manifest" \
    --request "$fail_request" >"$fail_report"; then
    echo "apolysis-f5: invalid production promotion request unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("target tag must be immutable and start with prod-"))
  and (.failures | map(.message) | index("minimum production retention is 90 days"))
  and (.failures | map(.message) | index("anonymous registry pull access is forbidden"))
' "$fail_report" >/dev/null

printf 'apolysis-f5: release promotion policy gate passed (%s)\n' "$output_dir"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stamp="$(date -u +%Y%m%d%H%M%S)-$$"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_RELEASE_REGISTRY_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-release-registry.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
bundle_dir="$output_dir/release-bundle"
archive_root="$output_dir/immutable-archive"
archive_objects="$archive_root/objects"
registry_name="${APOLYSIS_PRODUCTION_HARDENING_REGISTRY_NAME:-apolysis-production-hardening-registry-$stamp}"
registry_repository="${APOLYSIS_PRODUCTION_HARDENING_REGISTRY_REPOSITORY:-apolysisd}"
registry_tag="${APOLYSIS_PRODUCTION_HARDENING_REGISTRY_TAG:-production-hardening-registry-$stamp}"
registry_attachment="$output_dir/apolysis-production-hardening-registry-attachment.json"
archive_manifest="$output_dir/apolysis-production-hardening-immutable-archive-manifest.json"
registry_accept_header="Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

choose_free_port() {
    python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

registry_port="${APOLYSIS_PRODUCTION_HARDENING_REGISTRY_PORT:-$(choose_free_port)}"
registry_url="http://127.0.0.1:$registry_port"
image="localhost:$registry_port/$registry_repository:$registry_tag"

cleanup() {
    docker rm -f "$registry_name" >/dev/null 2>&1 || true
    docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for command in cosign curl docker jq python3 sha256sum; do
    require_command "$command"
done

mkdir -p "$bundle_dir" "$archive_objects"

docker rm -f "$registry_name" >/dev/null 2>&1 || true
docker run -d \
    --name "$registry_name" \
    -p "127.0.0.1:$registry_port:5000" \
    registry:2 >/dev/null

for _ in $(seq 1 60); do
    if curl -fsS "$registry_url/v2/" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! curl -fsS "$registry_url/v2/" >/dev/null 2>&1; then
    echo "apolysis-production-hardening: local OCI registry did not become ready" >&2
    docker logs "$registry_name" >&2 || true
    exit 1
fi

APOLYSIS_PRODUCTION_HARDENING_RELEASE_OUTPUT_DIR="$bundle_dir" \
APOLYSIS_PRODUCTION_HARDENING_RELEASE_IMAGE="$image" \
APOLYSIS_PRODUCTION_HARDENING_REMOVE_IMAGE=0 \
    "$repo_root/scripts/build-production-hardening-release-bundle.sh"

(
    cd "$bundle_dir"
    sha256sum -c apolysis-production-hardening-release-checksums.sha256
)

docker push "$image"

curl -fsSL "$registry_url/v2/_catalog" \
    -o "$output_dir/apolysis-production-hardening-registry-catalog.json"
curl -fsSL "$registry_url/v2/$registry_repository/tags/list" \
    -o "$output_dir/apolysis-production-hardening-registry-tags-before-sbom.json"

image_manifest_body="$output_dir/apolysis-production-hardening-registry-image-manifest.json"
image_manifest_headers="$output_dir/apolysis-production-hardening-registry-image-manifest.headers"
curl -fsSL \
    -D "$image_manifest_headers" \
    -H "$registry_accept_header" \
    -o "$image_manifest_body" \
    "$registry_url/v2/$registry_repository/manifests/$registry_tag"
image_digest="$(
    awk 'tolower($1) == "docker-content-digest:" {gsub("\r", "", $2); print $2; exit}' \
        "$image_manifest_headers"
)"
if [[ ! "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "apolysis-production-hardening: local registry did not return a valid image digest" >&2
    exit 1
fi

cosign attach sbom \
    --type cyclonedx \
    --input-format json \
    --sbom "$bundle_dir/apolysis-production-hardening-sbom.cdx.json" \
    --allow-http-registry \
    --allow-insecure-registry \
    "$image"

sbom_tag="${image_digest/:/-}.sbom"
curl -fsSL "$registry_url/v2/$registry_repository/tags/list" \
    -o "$output_dir/apolysis-production-hardening-registry-tags-after-sbom.json"
jq -e --arg tag "$registry_tag" --arg sbom_tag "$sbom_tag" '
  (.tags | index($tag)) and (.tags | index($sbom_tag))
' "$output_dir/apolysis-production-hardening-registry-tags-after-sbom.json" >/dev/null

sbom_manifest_body="$output_dir/apolysis-production-hardening-registry-sbom-manifest.json"
sbom_manifest_headers="$output_dir/apolysis-production-hardening-registry-sbom-manifest.headers"
curl -fsSL \
    -D "$sbom_manifest_headers" \
    -H "$registry_accept_header" \
    -o "$sbom_manifest_body" \
    "$registry_url/v2/$registry_repository/manifests/$sbom_tag"
sbom_attachment_digest="$(
    awk 'tolower($1) == "docker-content-digest:" {gsub("\r", "", $2); print $2; exit}' \
        "$sbom_manifest_headers"
)"
if [[ ! "$sbom_attachment_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "apolysis-production-hardening: local registry did not return a valid SBOM attachment digest" >&2
    exit 1
fi

python3 - \
    "$repo_root" \
    "$output_dir" \
    "$bundle_dir" \
    "$registry_attachment" \
    "$image" \
    "$registry_repository" \
    "$registry_tag" \
    "$registry_url" \
    "$image_digest" \
    "$sbom_tag" \
    "$sbom_attachment_digest" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
bundle_dir = Path(sys.argv[3])
registry_attachment = Path(sys.argv[4])
image = sys.argv[5]
repository = sys.argv[6]
tag = sys.argv[7]
registry_url = sys.argv[8]
image_digest = sys.argv[9]
sbom_tag = sys.argv[10]
sbom_attachment_digest = sys.argv[11]


def sha256(path: Path) -> str:
    return subprocess.check_output(["sha256sum", str(path)], text=True).split()[0]


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root, text=True).strip()


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


data = {
    "schema": "apolysis.dev/production-hardening-registry-attachment/v1",
    "schemaVersion": 1,
    "phase": "production-hardening.registry-attachment",
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "git": {
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
        "branch": git("branch", "--show-current"),
    },
    "registry": {
        "url": registry_url,
        "implementation": "registry:2",
        "repository": repository,
        "tag": tag,
        "image": image,
        "imageDigest": image_digest,
        "sbomAttachmentTag": sbom_tag,
        "sbomAttachmentDigest": sbom_attachment_digest,
    },
    "releaseArtifacts": {
        "manifest": {
            "path": "release-bundle/apolysis-production-hardening-release-manifest.json",
            "sha256": sha256(bundle_dir / "apolysis-production-hardening-release-manifest.json"),
        },
        "provenance": {
            "path": "release-bundle/apolysis-production-hardening-provenance.intoto.json",
            "sha256": sha256(bundle_dir / "apolysis-production-hardening-provenance.intoto.json"),
        },
        "sbom": {
            "path": "release-bundle/apolysis-production-hardening-sbom.cdx.json",
            "sha256": sha256(bundle_dir / "apolysis-production-hardening-sbom.cdx.json"),
        },
        "checksums": {
            "path": "release-bundle/apolysis-production-hardening-release-checksums.sha256",
            "sha256": sha256(bundle_dir / "apolysis-production-hardening-release-checksums.sha256"),
        },
    },
    "evidenceFiles": {
        "catalog": "apolysis-production-hardening-registry-catalog.json",
        "tagsBeforeSbom": "apolysis-production-hardening-registry-tags-before-sbom.json",
        "tagsAfterSbom": "apolysis-production-hardening-registry-tags-after-sbom.json",
        "imageManifest": "apolysis-production-hardening-registry-image-manifest.json",
        "sbomManifest": "apolysis-production-hardening-registry-sbom-manifest.json",
    },
    "registryObservedState": {
        "catalog": read_json(output_dir / "apolysis-production-hardening-registry-catalog.json"),
        "tagsAfterSbom": read_json(output_dir / "apolysis-production-hardening-registry-tags-after-sbom.json"),
    },
}

registry_attachment.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

release_manifest_digest="$(sha256_file "$bundle_dir/apolysis-production-hardening-release-manifest.json")"
registry_attachment_digest="$(sha256_file "$registry_attachment")"
archive_dir="$archive_objects/sha256-$release_manifest_digest"
archive_tmp="$archive_root/.archive-$stamp"
if [[ -e "$archive_dir" ]]; then
    echo "apolysis-production-hardening: immutable archive object already exists: $archive_dir" >&2
    exit 1
fi
mkdir -p "$archive_tmp"

for artifact in \
    "$bundle_dir/apolysis-production-hardening-release-payload.tar.gz" \
    "$bundle_dir/apolysis-production-hardening-apolysisd-image.tar" \
    "$bundle_dir/apolysis-production-hardening-sbom.cdx.json" \
    "$bundle_dir/apolysis-production-hardening-vulnerability-scan.json" \
    "$bundle_dir/apolysis-production-hardening-provenance.intoto.json" \
    "$bundle_dir/apolysis-production-hardening-release-manifest.json" \
    "$bundle_dir/apolysis-production-hardening-release.pub" \
    "$bundle_dir/apolysis-production-hardening-release-manifest.sigstore.json" \
    "$bundle_dir/apolysis-production-hardening-provenance.sigstore.json" \
    "$bundle_dir/apolysis-production-hardening-release-checksums.sha256" \
    "$registry_attachment"; do
    install -m 0444 "$artifact" "$archive_tmp/$(basename "$artifact")"
done

mv "$archive_tmp" "$archive_dir"
chmod 0555 "$archive_dir"

mutation_probe="denied"
if touch "$archive_dir/.apolysis-mutation-probe" 2>/dev/null; then
    rm -f "$archive_dir/.apolysis-mutation-probe"
    mutation_probe="allowed"
fi
if [[ "$mutation_probe" != "denied" && "$EUID" -ne 0 ]]; then
    echo "apolysis-production-hardening: immutable archive mutation probe unexpectedly succeeded" >&2
    exit 1
fi

python3 - \
    "$repo_root" \
    "$archive_dir" \
    "$archive_manifest" \
    "$release_manifest_digest" \
    "$registry_attachment_digest" \
    "$mutation_probe" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
archive_dir = Path(sys.argv[2])
archive_manifest = Path(sys.argv[3])
release_manifest_digest = sys.argv[4]
registry_attachment_digest = sys.argv[5]
mutation_probe = sys.argv[6]


def sha256(path: Path) -> str:
    return subprocess.check_output(["sha256sum", str(path)], text=True).split()[0]


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root, text=True).strip()


artifacts = []
for path in sorted(archive_dir.iterdir()):
    if not path.is_file():
        continue
    stat = path.stat()
    artifacts.append(
        {
            "path": path.name,
            "sha256": sha256(path),
            "size": stat.st_size,
            "mode": format(stat.st_mode & 0o777, "04o"),
        }
    )

data = {
    "schema": "apolysis.dev/production-hardening-immutable-archive-manifest/v1",
    "schemaVersion": 1,
    "phase": "production-hardening.immutable-archive",
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "git": {
        "commit": git("rev-parse", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
        "branch": git("branch", "--show-current"),
    },
    "archive": {
        "mode": "content-addressed-read-only-local",
        "object": f"objects/sha256-{release_manifest_digest}",
        "path": str(archive_dir),
        "releaseManifestSha256": release_manifest_digest,
        "registryAttachmentSha256": registry_attachment_digest,
    },
    "immutability": {
        "directoryMode": format(archive_dir.stat().st_mode & 0o777, "04o"),
        "fileMode": "0444",
        "mutationProbe": mutation_probe,
        "fsImmutableAttribute": "not-required-for-local-gate",
        "rootExecutionNote": "root can bypass POSIX read-only permissions; production WORM storage remains a separate integration.",
    },
    "artifacts": artifacts,
}

archive_manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

jq -e \
  --arg image_digest "$image_digest" \
  --arg registry_tag "$registry_tag" \
  --arg sbom_tag "$sbom_tag" \
  --arg sbom_digest "$sbom_attachment_digest" '
  .schema == "apolysis.dev/production-hardening-registry-attachment/v1"
  and .phase == "production-hardening.registry-attachment"
  and .registry.implementation == "registry:2"
  and .registry.imageDigest == $image_digest
  and .registry.sbomAttachmentTag == $sbom_tag
  and .registry.sbomAttachmentDigest == $sbom_digest
  and (.registryObservedState.tagsAfterSbom.tags | index($registry_tag))
  and (.registryObservedState.tagsAfterSbom.tags | index($sbom_tag))
' "$registry_attachment" >/dev/null

jq -e --arg release_manifest_digest "$release_manifest_digest" --arg registry_attachment_digest "$registry_attachment_digest" '
  .schema == "apolysis.dev/production-hardening-immutable-archive-manifest/v1"
  and .phase == "production-hardening.immutable-archive"
  and .archive.releaseManifestSha256 == $release_manifest_digest
  and .archive.registryAttachmentSha256 == $registry_attachment_digest
  and .immutability.directoryMode == "0555"
  and .immutability.mutationProbe == "denied"
  and ([.artifacts[].path] | index("apolysis-production-hardening-registry-attachment.json"))
  and ([.artifacts[].path] | index("apolysis-production-hardening-release-manifest.json"))
  and ([.artifacts[].path] | index("apolysis-production-hardening-apolysisd-image.tar"))
  and all(.artifacts[]; (.sha256 | test("^[0-9a-f]{64}$")) and (.size > 0) and (.mode == "0444"))
' "$archive_manifest" >/dev/null

python3 - "$archive_manifest" "$archive_dir" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

archive_manifest = Path(sys.argv[1])
archive_dir = Path(sys.argv[2])
data = json.loads(archive_manifest.read_text(encoding="utf-8"))

for artifact in data["artifacts"]:
    path = archive_dir / artifact["path"]
    digest = subprocess.check_output(["sha256sum", str(path)], text=True).split()[0]
    if digest != artifact["sha256"]:
        raise SystemExit(f"archive digest mismatch for {artifact['path']}")
PY

printf 'apolysis-production-hardening: release registry/archive gate passed (%s)\n' "$output_dir"

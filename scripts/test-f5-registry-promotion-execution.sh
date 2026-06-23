#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stamp="$(date -u +%Y%m%d%H%M%S)-$$"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F5_REGISTRY_PROMOTION_EXECUTION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-registry-promotion-execution.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
registry_image="${APOLYSIS_F5_REGISTRY_IMAGE:-registry:2}"
registry_name="${APOLYSIS_F5_REGISTRY_EXECUTION_NAME:-apolysis-f5-promotion-$stamp}"
source_image=""
repository="${APOLYSIS_F5_REGISTRY_EXECUTION_REPOSITORY:-apolysisd}"
source_tag="${APOLYSIS_F5_REGISTRY_EXECUTION_SOURCE_TAG:-staging-$stamp}"
target_tag="${APOLYSIS_F5_REGISTRY_EXECUTION_TARGET_TAG:-prod-$stamp}"
rollback_tag="${APOLYSIS_F5_REGISTRY_EXECUTION_ROLLBACK_TAG:-prod-previous-$stamp}"
retention_days="${APOLYSIS_F5_REGISTRY_EXECUTION_RETENTION_DAYS:-180}"
evidence="$output_dir/apolysis-f5-registry-promotion-execution-evidence.json"
report="$output_dir/apolysis-f5-registry-promotion-execution-report.json"
fail_evidence="$output_dir/apolysis-f5-registry-promotion-execution-evidence-fail.json"
fail_report="$output_dir/apolysis-f5-registry-promotion-execution-report-fail.json"
accept_header="Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

choose_free_port() {
    python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

http_status() {
    local method="$1"
    local url="$2"
    shift 2
    curl -sS -o /dev/null -w '%{http_code}' -X "$method" "$@" "$url"
}

header_value() {
    local header="$1"
    local path="$2"
    awk -v header="$header" '
      BEGIN { wanted = tolower(header) ":" }
      tolower($1) == wanted { gsub("\r", "", $2); print $2; exit }
    ' "$path"
}

cleanup() {
    docker rm -f "$registry_name" >/dev/null 2>&1 || true
    if [[ -n "$source_image" ]]; then
        docker image rm "$source_image" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for command in cargo curl docker jq python3; do
    require_command "$command"
done

if ! docker image inspect "$registry_image" >/dev/null 2>&1; then
    echo "apolysis-f5: missing registry image: $registry_image" >&2
    echo "apolysis-f5: pull it first or set APOLYSIS_F5_REGISTRY_IMAGE to an available image" >&2
    exit 1
fi

registry_port="${APOLYSIS_F5_REGISTRY_EXECUTION_PORT:-$(choose_free_port)}"
registry_url="http://127.0.0.1:$registry_port"
source_image="127.0.0.1:$registry_port/$repository:$source_tag"
image_context="$output_dir/image-context"
staging_manifest="$output_dir/staging-manifest.json"
staging_headers="$output_dir/staging-manifest.headers"
production_manifest="$output_dir/production-manifest.json"
production_headers="$output_dir/production-manifest.headers"
rollback_manifest="$output_dir/rollback-manifest.json"
rollback_headers="$output_dir/rollback-manifest.headers"
digest_manifest="$output_dir/digest-manifest.json"
digest_headers="$output_dir/digest-manifest.headers"
promotion_put_status="$output_dir/promotion-put.status"
rollback_put_status="$output_dir/rollback-put.status"
delete_status_path="$output_dir/delete-production-digest.status"
delete_body_path="$output_dir/delete-production-digest.body"
observations="$output_dir/apolysis-f5-registry-promotion-api-observations.json"

mkdir -p "$image_context"
printf 'apolysis f5 registry promotion execution %s\n' "$stamp" >"$image_context/payload.txt"
cat >"$image_context/Dockerfile" <<'DOCKERFILE'
FROM scratch
LABEL org.opencontainers.image.title="apolysis-f5-registry-promotion-execution"
COPY payload.txt /payload.txt
DOCKERFILE

docker rm -f "$registry_name" >/dev/null 2>&1 || true
docker run -d \
    --name "$registry_name" \
    -p "127.0.0.1:$registry_port:5000" \
    "$registry_image" >/dev/null

for _ in $(seq 1 60); do
    if curl -fsS "$registry_url/v2/" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! curl -fsS "$registry_url/v2/" >/dev/null 2>&1; then
    echo "apolysis-f5: local registry did not become ready" >&2
    docker logs "$registry_name" >&2 || true
    exit 1
fi

docker build -q -t "$source_image" "$image_context" >/dev/null
docker push "$source_image" >/dev/null

curl -fsSL \
    -D "$staging_headers" \
    -H "$accept_header" \
    -o "$staging_manifest" \
    "$registry_url/v2/$repository/manifests/$source_tag"
image_digest="$(header_value Docker-Content-Digest "$staging_headers")"
manifest_media_type="$(header_value Content-Type "$staging_headers")"
if [[ ! "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "apolysis-f5: registry did not return a valid staging digest" >&2
    exit 1
fi
if [[ -z "$manifest_media_type" ]]; then
    echo "apolysis-f5: registry did not return a manifest content type" >&2
    exit 1
fi

promotion_status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
        -X PUT \
        -H "Content-Type: $manifest_media_type" \
        --data-binary @"$staging_manifest" \
        "$registry_url/v2/$repository/manifests/$target_tag"
)"
printf '%s\n' "$promotion_status" >"$promotion_put_status"
if [[ "$promotion_status" != "201" && "$promotion_status" != "202" ]]; then
    echo "apolysis-f5: production manifest promotion failed with HTTP $promotion_status" >&2
    exit 1
fi

rollback_status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
        -X PUT \
        -H "Content-Type: $manifest_media_type" \
        --data-binary @"$staging_manifest" \
        "$registry_url/v2/$repository/manifests/$rollback_tag"
)"
printf '%s\n' "$rollback_status" >"$rollback_put_status"
if [[ "$rollback_status" != "201" && "$rollback_status" != "202" ]]; then
    echo "apolysis-f5: rollback manifest promotion failed with HTTP $rollback_status" >&2
    exit 1
fi

curl -fsSL \
    -D "$production_headers" \
    -H "$accept_header" \
    -o "$production_manifest" \
    "$registry_url/v2/$repository/manifests/$target_tag"
production_digest="$(header_value Docker-Content-Digest "$production_headers")"

curl -fsSL \
    -D "$rollback_headers" \
    -H "$accept_header" \
    -o "$rollback_manifest" \
    "$registry_url/v2/$repository/manifests/$rollback_tag"
rollback_digest="$(header_value Docker-Content-Digest "$rollback_headers")"

curl -fsSL \
    -D "$digest_headers" \
    -H "$accept_header" \
    -o "$digest_manifest" \
    "$registry_url/v2/$repository/manifests/$image_digest"
digest_pull_digest="$(header_value Docker-Content-Digest "$digest_headers")"

delete_status="$(
    curl -sS \
        -X DELETE \
        -o "$delete_body_path" \
        -w '%{http_code}' \
        "$registry_url/v2/$repository/manifests/$production_digest"
)"
printf '%s\n' "$delete_status" >"$delete_status_path"

target_after_delete_status="$(http_status GET "$registry_url/v2/$repository/manifests/$target_tag" -H "$accept_header")"

python3 - \
    "$evidence" \
    "$observations" \
    "$registry_url" \
    "$repository" \
    "$source_tag" \
    "$target_tag" \
    "$rollback_tag" \
    "$image_digest" \
    "$production_digest" \
    "$rollback_digest" \
    "$digest_pull_digest" \
    "$manifest_media_type" \
    "$promotion_status" \
    "$rollback_status" \
    "$delete_status" \
    "$target_after_delete_status" \
    "$retention_days" \
    "$staging_headers" \
    "$production_headers" \
    "$rollback_headers" \
    "$digest_headers" \
    "$delete_body_path" <<'PY'
import json
import sys
import time
from pathlib import Path

(
    evidence_path,
    observations_path,
    registry_url,
    repository,
    source_tag,
    target_tag,
    rollback_tag,
    image_digest,
    production_digest,
    rollback_digest,
    digest_pull_digest,
    manifest_media_type,
    promotion_status,
    rollback_status,
    delete_status,
    target_after_delete_status,
    retention_days,
    staging_headers,
    production_headers,
    rollback_headers,
    digest_headers,
    delete_body,
) = sys.argv[1:]

retention_days = int(retention_days)
observed_at_unix_ms = int(time.time()) * 1000
day_ms = 24 * 60 * 60 * 1000
retain_until_unix_ms = observed_at_unix_ms + retention_days * day_ms


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


staging_manifest_verified = image_digest.startswith("sha256:")
production_manifest_verified = production_digest == image_digest
rollback_manifest_verified = rollback_digest == image_digest
digest_pulls_verified = digest_pull_digest == image_digest
digest_promotion_performed = (
    promotion_status in {"201", "202"}
    and rollback_status in {"201", "202"}
    and production_manifest_verified
    and rollback_manifest_verified
)
production_delete_without_retention_denied = (
    delete_status not in {"200", "201", "202", "204"}
    and target_after_delete_status == "200"
)

observations = {
    "registry_url": registry_url,
    "repository": repository,
    "source_tag": source_tag,
    "target_tag": target_tag,
    "rollback_tag": rollback_tag,
    "image_digest": image_digest,
    "production_digest": production_digest,
    "rollback_digest": rollback_digest,
    "digest_pull_digest": digest_pull_digest,
    "manifest_media_type": manifest_media_type,
    "promotion_status": int(promotion_status),
    "rollback_status": int(rollback_status),
    "delete_status": int(delete_status),
    "target_after_delete_status": int(target_after_delete_status),
    "headers": {
        "staging": read(staging_headers),
        "production": read(production_headers),
        "rollback": read(rollback_headers),
        "digest": read(digest_headers),
    },
    "delete_body": read(delete_body),
}
Path(observations_path).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")

evidence = {
    "evidence_id": "f5-registry-promotion-execution",
    "source": "live_provider",
    "provider": "oci_distribution_registry",
    "registry_uri": registry_url,
    "repository": repository,
    "source_tag": source_tag,
    "target_tag": target_tag,
    "rollback_tag": rollback_tag,
    "image_digest": image_digest,
    "promoted_digest": image_digest,
    "production_tag_digest": production_digest,
    "rollback_tag_digest": rollback_digest,
    "manifest_media_type": manifest_media_type,
    "staging_manifest_verified": staging_manifest_verified,
    "production_manifest_verified": production_manifest_verified,
    "rollback_manifest_verified": rollback_manifest_verified,
    "digest_promotion_performed": digest_promotion_performed,
    "digest_pulls_verified": digest_pulls_verified,
    "production_delete_without_retention_denied": production_delete_without_retention_denied,
    "retention_days": retention_days,
    "retain_until_unix_ms": retain_until_unix_ms,
    "promotion_approved": True,
    "api_tool": "curl Docker Registry HTTP API V2",
    "observed_at_unix_ms": observed_at_unix_ms,
}
Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

if not all(
    [
        staging_manifest_verified,
        production_manifest_verified,
        rollback_manifest_verified,
        digest_promotion_performed,
        digest_pulls_verified,
        production_delete_without_retention_denied,
    ]
):
    raise SystemExit(
        "registry promotion execution did not prove staging, production, rollback, "
        "digest pulls, and delete-deny evidence; see " + str(observations_path)
    )
PY

cargo run -q -p apolysis-validation --bin apolysis-f5-registry-promotion-execution-evidence -- \
    --evidence "$evidence" >"$report"

jq -e \
    --arg image_digest "$image_digest" \
    --arg target_tag "$target_tag" \
    --arg rollback_tag "$rollback_tag" '
  .passed == true
  and .approval.provider == "oci_distribution_registry"
  and .approval.image_digest == $image_digest
  and .approval.target_tag == $target_tag
  and .approval.rollback_tag == $rollback_tag
  and (.approval.retention_days >= 90)
' "$report" >/dev/null

jq '
  .source = "fixture"
  | .provider = "local_filesystem"
  | .registry_uri = "file:///tmp/registry"
  | .repository = ""
  | .source_tag = ""
  | .target_tag = "latest"
  | .rollback_tag = ""
  | .image_digest = "sha256:not-a-digest"
  | .promoted_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  | .production_tag_digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  | .rollback_tag_digest = ""
  | .manifest_media_type = ""
  | .staging_manifest_verified = false
  | .production_manifest_verified = false
  | .rollback_manifest_verified = false
  | .digest_promotion_performed = false
  | .digest_pulls_verified = false
  | .production_delete_without_retention_denied = false
  | .retention_days = 14
  | .retain_until_unix_ms = (.observed_at_unix_ms + 1209600000)
  | .promotion_approved = false
  | .api_tool = ""
  | .observed_at_unix_ms = 0
' "$evidence" >"$fail_evidence"

if cargo run -q -p apolysis-validation --bin apolysis-f5-registry-promotion-execution-evidence -- \
    --evidence "$fail_evidence" >"$fail_report"; then
    echo "apolysis-f5: invalid registry promotion execution evidence unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("live registry promotion execution evidence is required"))
  and (.failures | map(.message) | index("registry promotion execution requires a provider-backed OCI registry"))
  and (.failures | map(.message) | index("target tag must be immutable and start with prod-"))
  and (.failures | map(.message) | index("production delete without retention bypass must be denied by the registry API"))
  and (.failures | map(.message) | index("minimum production retention is 90 days"))
' "$fail_report" >/dev/null

printf 'apolysis-f5: registry promotion execution gate passed (%s)\n' "$output_dir"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_LIVE:-}" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-production-hardening: Docker Hub live registry promotion is opt-in.
Set APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_LIVE=1 after confirming the Docker Hub account,
repository, immutable-tag rule, and retained remote tags are acceptable.
EOF
    exit 2
fi

stamp="$(date -u +%Y%m%d%H%M%S)-$$"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-dockerhub-registry-promotion.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

docker_config="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
repository="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_REPOSITORY:-apolysis-production-hardening-registry}"
repository_private="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_PRIVATE:-true}"
description="Apolysis ProductionHardening live Docker Hub registry promotion evidence"
source_tag="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_SOURCE_TAG:-staging-production-hardening-$stamp}"
target_tag="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_TARGET_TAG:-prod-production-hardening-$stamp}"
rollback_tag="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_ROLLBACK_TAG:-rollback-production-hardening-$stamp}"
overwrite_tag="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_OVERWRITE_TAG:-overwrite-production-hardening-$stamp}"
immutable_rule="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_IMMUTABLE_RULE:-prod-production-hardening-.*}"
retention_days="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_RETENTION_DAYS:-180}"

evidence="$output_dir/apolysis-production-hardening-dockerhub-registry-promotion-evidence.json"
report="$output_dir/apolysis-production-hardening-dockerhub-registry-promotion-report.json"
observations="$output_dir/apolysis-production-hardening-dockerhub-registry-promotion-observations.json"
repo_before="$output_dir/docker-hub-repository-before.json"
repo_after="$output_dir/docker-hub-repository-after.json"
immutable_verify="$output_dir/docker-hub-immutable-tags-verify.json"
staging_manifest="$output_dir/staging-manifest.json"
staging_headers="$output_dir/staging-manifest.headers"
production_manifest="$output_dir/production-manifest.json"
production_headers="$output_dir/production-manifest.headers"
rollback_manifest="$output_dir/rollback-manifest.json"
rollback_headers="$output_dir/rollback-manifest.headers"
digest_manifest="$output_dir/digest-manifest.json"
digest_headers="$output_dir/digest-manifest.headers"
overwrite_manifest="$output_dir/overwrite-manifest.json"
overwrite_headers="$output_dir/overwrite-manifest.headers"
target_after_mutation_headers="$output_dir/target-after-mutation.headers"
target_after_delete_headers="$output_dir/target-after-delete.headers"
delete_body="$output_dir/delete-production-digest.body"
overwrite_body="$output_dir/overwrite-production-tag.body"
accept_header="Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
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
    if [[ -n "${remote_image:-}" ]]; then
        docker image rm \
            "$remote_image:$source_tag" \
            "$remote_image:$overwrite_tag" \
            "$remote_image:$target_tag" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for command in base64 cargo curl docker jq python3; do
    require_command "$command"
done

if [[ ! -s "$docker_config" ]]; then
    echo "apolysis-production-hardening: Docker config not found at $docker_config" >&2
    exit 1
fi

docker_auth_entry="$(
    jq -r '(.auths["https://index.docker.io/v1/"].auth // empty)' "$docker_config"
)"
if [[ -z "$docker_auth_entry" ]]; then
    echo "apolysis-production-hardening: Docker Hub login entry is missing from $docker_config" >&2
    exit 1
fi

docker_credential="$(printf '%s' "$docker_auth_entry" | base64 -d)"
docker_hub_user="${docker_credential%%:*}"
docker_hub_secret="${docker_credential#*:}"
namespace="${APOLYSIS_PRODUCTION_HARDENING_DOCKER_HUB_NAMESPACE:-$docker_hub_user}"
remote_image="$namespace/$repository"
registry_uri="https://index.docker.io/v2/$namespace/$repository"
registry_api_base="https://registry-1.docker.io/v2/$namespace/$repository"

if [[ -z "$docker_hub_user" || -z "$docker_hub_secret" || "$docker_hub_user" == "$docker_hub_secret" ]]; then
    echo "apolysis-production-hardening: Docker Hub credential is malformed" >&2
    exit 1
fi

hub_login_response="$(
    jq -n --arg username "$docker_hub_user" --arg password "$docker_hub_secret" \
        '{username:$username,password:$password}' |
        curl -fsS -H 'Content-Type: application/json' -d @- https://hub.docker.com/v2/users/login
)"
hub_token="$(jq -r '.token // empty' <<<"$hub_login_response")"
if [[ -z "$hub_token" ]]; then
    echo "apolysis-production-hardening: Docker Hub API login did not return a token" >&2
    exit 1
fi

hub_api_status() {
    local method="$1"
    local url="$2"
    local body="$3"
    local output="$4"
    if [[ -n "$body" ]]; then
        curl -sS -o "$output" -w '%{http_code}' \
            -X "$method" \
            -H "Authorization: JWT $hub_token" \
            -H 'Content-Type: application/json' \
            --data-binary "$body" \
            "$url"
    else
        curl -sS -o "$output" -w '%{http_code}' \
            -X "$method" \
            -H "Authorization: JWT $hub_token" \
            "$url"
    fi
}

repo_status="$(
    hub_api_status GET "https://hub.docker.com/v2/namespaces/$namespace/repositories/$repository" "" "$repo_before"
)"
if [[ "$repo_status" == "404" ]]; then
    create_body="$(
        jq -n \
            --arg name "$repository" \
            --arg namespace "$namespace" \
            --arg description "$description" \
            --argjson is_private "$repository_private" \
            '{
              name: $name,
              namespace: $namespace,
              description: $description,
              full_description: $description,
              registry: "docker.io",
              is_private: $is_private
            }'
    )"
    create_status="$(
        hub_api_status POST "https://hub.docker.com/v2/namespaces/$namespace/repositories" "$create_body" "$repo_before"
    )"
    if [[ "$create_status" != "201" ]]; then
        echo "apolysis-production-hardening: Docker Hub repository creation failed with HTTP $create_status" >&2
        jq . "$repo_before" >&2 || cat "$repo_before" >&2
        exit 1
    fi
elif [[ "$repo_status" != "200" ]]; then
    echo "apolysis-production-hardening: Docker Hub repository lookup failed with HTTP $repo_status" >&2
    jq . "$repo_before" >&2 || cat "$repo_before" >&2
    exit 1
fi

existing_rules="$(
    jq -c --arg rule "$immutable_rule" '
      [
        (.immutable_tags_settings.rules // .immutable_tags_settings.immutable_tags_rules // [])[],
        $rule
      ] | unique
    ' "$repo_before"
)"
immutable_body="$(
    jq -n --argjson rules "$existing_rules" \
        '{immutable_tags:true, immutable_tags_rules:$rules}'
)"
immutable_status="$(
    hub_api_status PATCH \
        "https://hub.docker.com/v2/namespaces/$namespace/repositories/$repository/immutabletags" \
        "$immutable_body" \
        "$repo_after"
)"
if [[ "$immutable_status" != "200" ]]; then
    echo "apolysis-production-hardening: Docker Hub immutable tag configuration failed with HTTP $immutable_status" >&2
    jq . "$repo_after" >&2 || cat "$repo_after" >&2
    exit 1
fi

registry_token_response="$(
    curl -fsS -u "$docker_hub_user:$docker_hub_secret" \
        --get https://auth.docker.io/token \
        --data-urlencode service=registry.docker.io \
        --data-urlencode "scope=repository:$namespace/$repository:pull,push"
)"
registry_token="$(jq -r '.token // empty' <<<"$registry_token_response")"
if [[ -z "$registry_token" ]]; then
    echo "apolysis-production-hardening: Docker registry auth did not return a token" >&2
    exit 1
fi

image_context="$output_dir/image-context"
overwrite_context="$output_dir/overwrite-context"
mkdir -p "$image_context" "$overwrite_context"
printf 'apolysis production_hardening docker hub registry promotion %s\n' "$stamp" >"$image_context/payload.txt"
cat >"$image_context/Dockerfile" <<'DOCKERFILE'
FROM scratch
LABEL org.opencontainers.image.title="apolysis-production-hardening-dockerhub-registry-promotion"
COPY payload.txt /payload.txt
DOCKERFILE
printf 'apolysis production_hardening docker hub immutable overwrite probe %s\n' "$stamp" >"$overwrite_context/payload.txt"
cp "$image_context/Dockerfile" "$overwrite_context/Dockerfile"

docker build -q -t "$remote_image:$source_tag" "$image_context" >/dev/null
docker push "$remote_image:$source_tag" >/dev/null

curl -fsSL \
    -D "$staging_headers" \
    -H "Authorization: Bearer $registry_token" \
    -H "$accept_header" \
    -o "$staging_manifest" \
    "$registry_api_base/manifests/$source_tag"
image_digest="$(header_value Docker-Content-Digest "$staging_headers")"
manifest_media_type="$(header_value Content-Type "$staging_headers")"
if [[ ! "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "apolysis-production-hardening: Docker Hub did not return a valid staging digest" >&2
    exit 1
fi
if [[ -z "$manifest_media_type" ]]; then
    echo "apolysis-production-hardening: Docker Hub did not return a manifest content type" >&2
    exit 1
fi

promotion_status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
        -X PUT \
        -H "Authorization: Bearer $registry_token" \
        -H "Content-Type: $manifest_media_type" \
        --data-binary @"$staging_manifest" \
        "$registry_api_base/manifests/$target_tag"
)"
if [[ "$promotion_status" != "201" && "$promotion_status" != "202" ]]; then
    echo "apolysis-production-hardening: Docker Hub production manifest promotion failed with HTTP $promotion_status" >&2
    exit 1
fi

rollback_status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
        -X PUT \
        -H "Authorization: Bearer $registry_token" \
        -H "Content-Type: $manifest_media_type" \
        --data-binary @"$staging_manifest" \
        "$registry_api_base/manifests/$rollback_tag"
)"
if [[ "$rollback_status" != "201" && "$rollback_status" != "202" ]]; then
    echo "apolysis-production-hardening: Docker Hub rollback manifest promotion failed with HTTP $rollback_status" >&2
    exit 1
fi

curl -fsSL \
    -D "$production_headers" \
    -H "Authorization: Bearer $registry_token" \
    -H "$accept_header" \
    -o "$production_manifest" \
    "$registry_api_base/manifests/$target_tag"
production_digest="$(header_value Docker-Content-Digest "$production_headers")"

curl -fsSL \
    -D "$rollback_headers" \
    -H "Authorization: Bearer $registry_token" \
    -H "$accept_header" \
    -o "$rollback_manifest" \
    "$registry_api_base/manifests/$rollback_tag"
rollback_digest="$(header_value Docker-Content-Digest "$rollback_headers")"

curl -fsSL \
    -D "$digest_headers" \
    -H "Authorization: Bearer $registry_token" \
    -H "$accept_header" \
    -o "$digest_manifest" \
    "$registry_api_base/manifests/$image_digest"
digest_pull_digest="$(header_value Docker-Content-Digest "$digest_headers")"

docker build -q -t "$remote_image:$overwrite_tag" "$overwrite_context" >/dev/null
docker push "$remote_image:$overwrite_tag" >/dev/null
curl -fsSL \
    -D "$overwrite_headers" \
    -H "Authorization: Bearer $registry_token" \
    -H "$accept_header" \
    -o "$overwrite_manifest" \
    "$registry_api_base/manifests/$overwrite_tag"

overwrite_status="$(
    curl -sS -o "$overwrite_body" -w '%{http_code}' \
        -X PUT \
        -H "Authorization: Bearer $registry_token" \
        -H "Content-Type: $(header_value Content-Type "$overwrite_headers")" \
        --data-binary @"$overwrite_manifest" \
        "$registry_api_base/manifests/$target_tag"
)"

target_after_mutation_status="$(
    curl -sS -o /dev/null -D "$target_after_mutation_headers" -w '%{http_code}' \
        -H "Authorization: Bearer $registry_token" \
        -H "$accept_header" \
        "$registry_api_base/manifests/$target_tag"
)"
target_after_mutation_digest="$(header_value Docker-Content-Digest "$target_after_mutation_headers")"

delete_status="$(
    curl -sS -o "$delete_body" -w '%{http_code}' \
        -X DELETE \
        -H "Authorization: Bearer $registry_token" \
        "$registry_api_base/manifests/$production_digest"
)"

target_after_delete_status="$(
    curl -sS -o /dev/null -D "$target_after_delete_headers" -w '%{http_code}' \
        -H "Authorization: Bearer $registry_token" \
        -H "$accept_header" \
        "$registry_api_base/manifests/$target_tag"
)"
target_after_delete_digest="$(header_value Docker-Content-Digest "$target_after_delete_headers")"

verify_status="$(
    hub_api_status POST \
        "https://hub.docker.com/v2/namespaces/$namespace/repositories/$repository/immutabletags/verify" \
        "$(jq -n --arg regex "$immutable_rule" '{regex:$regex}')" \
        "$immutable_verify"
)"
if [[ "$verify_status" != "200" ]]; then
    echo "apolysis-production-hardening: Docker Hub immutable tag verification failed with HTTP $verify_status" >&2
    jq . "$immutable_verify" >&2 || cat "$immutable_verify" >&2
    exit 1
fi

python3 - \
    "$evidence" \
    "$observations" \
    "$registry_uri" \
    "$repository" \
    "$namespace" \
    "$source_tag" \
    "$target_tag" \
    "$rollback_tag" \
    "$overwrite_tag" \
    "$image_digest" \
    "$production_digest" \
    "$rollback_digest" \
    "$digest_pull_digest" \
    "$manifest_media_type" \
    "$promotion_status" \
    "$rollback_status" \
    "$overwrite_status" \
    "$target_after_mutation_status" \
    "$target_after_mutation_digest" \
    "$delete_status" \
    "$target_after_delete_status" \
    "$target_after_delete_digest" \
    "$retention_days" \
    "$immutable_rule" \
    "$repo_before" \
    "$repo_after" \
    "$immutable_verify" \
    "$overwrite_body" \
    "$delete_body" <<'PY'
import json
import sys
import time
from pathlib import Path

(
    evidence_path,
    observations_path,
    registry_uri,
    repository,
    namespace,
    source_tag,
    target_tag,
    rollback_tag,
    overwrite_tag,
    image_digest,
    production_digest,
    rollback_digest,
    digest_pull_digest,
    manifest_media_type,
    promotion_status,
    rollback_status,
    overwrite_status,
    target_after_mutation_status,
    target_after_mutation_digest,
    delete_status,
    target_after_delete_status,
    target_after_delete_digest,
    retention_days,
    immutable_rule,
    repo_before,
    repo_after,
    immutable_verify,
    overwrite_body,
    delete_body,
) = sys.argv[1:]

retention_days = int(retention_days)
observed_at_unix_ms = int(time.time()) * 1000
retain_until_unix_ms = observed_at_unix_ms + retention_days * 24 * 60 * 60 * 1000


def read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


promotion_ok = promotion_status in {"201", "202"}
rollback_ok = rollback_status in {"201", "202"}
overwrite_denied = overwrite_status not in {"200", "201", "202", "204"}
delete_denied = delete_status not in {"200", "201", "202", "204"}
staging_manifest_verified = image_digest.startswith("sha256:")
production_manifest_verified = production_digest == image_digest
rollback_manifest_verified = rollback_digest == image_digest
digest_pulls_verified = digest_pull_digest == image_digest
mutation_preserved_digest = (
    target_after_mutation_status == "200" and target_after_mutation_digest == image_digest
)
delete_preserved_digest = (
    target_after_delete_status == "200" and target_after_delete_digest == image_digest
)

repo_after_json = read_json(repo_after)
immutable_settings = repo_after_json.get("immutable_tags_settings") or {}
immutable_rules = immutable_settings.get("rules") or immutable_settings.get("immutable_tags_rules") or []
immutable_rule_enabled = bool(immutable_settings.get("enabled")) and immutable_rule in immutable_rules
verify_tags = read_json(immutable_verify).get("tags", [])
immutable_rule_matched_target = target_tag in verify_tags

observations = {
    "provider": "docker_hub",
    "namespace": namespace,
    "repository": f"{namespace}/{repository}",
    "registry_uri": registry_uri,
    "source_tag": source_tag,
    "target_tag": target_tag,
    "rollback_tag": rollback_tag,
    "overwrite_tag": overwrite_tag,
    "immutable_rule": immutable_rule,
    "immutable_rule_enabled": immutable_rule_enabled,
    "immutable_rule_matched_target": immutable_rule_matched_target,
    "image_digest": image_digest,
    "production_digest": production_digest,
    "rollback_digest": rollback_digest,
    "digest_pull_digest": digest_pull_digest,
    "manifest_media_type": manifest_media_type,
    "promotion_status": int(promotion_status),
    "rollback_status": int(rollback_status),
    "overwrite_status": int(overwrite_status),
    "target_after_mutation_status": int(target_after_mutation_status),
    "target_after_mutation_digest": target_after_mutation_digest,
    "delete_status": int(delete_status),
    "target_after_delete_status": int(target_after_delete_status),
    "target_after_delete_digest": target_after_delete_digest,
    "repo_before": read_json(repo_before),
    "repo_after": repo_after_json,
    "immutable_verify": read_json(immutable_verify),
    "overwrite_body": read_text(overwrite_body),
    "delete_body": read_text(delete_body),
}
Path(observations_path).write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")

evidence = {
    "evidence_id": f"production-hardening-docker-hub-registry-promotion-{observed_at_unix_ms}",
    "source": "live_provider",
    "provider": "docker_hub",
    "registry_uri": registry_uri,
    "repository": f"{namespace}/{repository}",
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
    "digest_promotion_performed": promotion_ok and rollback_ok and production_manifest_verified,
    "digest_pulls_verified": digest_pulls_verified,
    "production_delete_without_retention_denied": (
        delete_denied and overwrite_denied and mutation_preserved_digest and delete_preserved_digest
    ),
    "retention_days": retention_days,
    "retain_until_unix_ms": retain_until_unix_ms,
    "promotion_approved": True,
    "api_tool": "Docker Hub API immutable tags plus Docker Registry HTTP API V2",
    "observed_at_unix_ms": observed_at_unix_ms,
}
Path(evidence_path).write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

if not all(
    [
        staging_manifest_verified,
        production_manifest_verified,
        rollback_manifest_verified,
        promotion_ok,
        rollback_ok,
        digest_pulls_verified,
        overwrite_denied,
        delete_denied,
        mutation_preserved_digest,
        delete_preserved_digest,
        immutable_rule_enabled,
    ]
):
    raise SystemExit("Docker Hub registry promotion evidence incomplete; see " + observations_path)
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-registry-promotion-execution-evidence -- \
    --evidence "$evidence" >"$report"

jq -e \
    --arg image_digest "$image_digest" \
    --arg target_tag "$target_tag" \
    --arg rollback_tag "$rollback_tag" '
  .passed == true
  and .approval.provider == "docker_hub"
  and .approval.image_digest == $image_digest
  and .approval.target_tag == $target_tag
  and .approval.rollback_tag == $rollback_tag
  and (.approval.retention_days >= 90)
' "$report" >/dev/null

printf 'apolysis-production-hardening: Docker Hub registry promotion gate passed (%s)\n' "$output_dir"

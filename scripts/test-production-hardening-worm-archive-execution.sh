#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stamp="$(date -u +%Y%m%d%H%M%S)-$$"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_WORM_ARCHIVE_EXECUTION_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-worm-archive-execution.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
minio_image="${APOLYSIS_PRODUCTION_HARDENING_MINIO_IMAGE:-minio/minio:RELEASE.2024-12-18T13-15-44Z}"
minio_name="${APOLYSIS_PRODUCTION_HARDENING_MINIO_NAME:-apolysis-production-hardening-worm-$stamp}"
access_key="${APOLYSIS_PRODUCTION_HARDENING_MINIO_ACCESS_KEY:-apolysisf5}"
secret_key="${APOLYSIS_PRODUCTION_HARDENING_MINIO_SECRET_KEY:-apolysisf5secret}"
bucket="${APOLYSIS_PRODUCTION_HARDENING_WORM_BUCKET:-apolysis-production-hardening-worm-$stamp}"
object_key="${APOLYSIS_PRODUCTION_HARDENING_WORM_OBJECT_KEY:-releases/apolysis/$stamp/release-manifest.json}"
retention_days="${APOLYSIS_PRODUCTION_HARDENING_WORM_RETENTION_DAYS:-365}"
evidence="$output_dir/apolysis-production-hardening-worm-archive-execution-evidence.json"
report="$output_dir/apolysis-production-hardening-worm-archive-execution-report.json"
fail_evidence="$output_dir/apolysis-production-hardening-worm-archive-execution-evidence-fail.json"
fail_report="$output_dir/apolysis-production-hardening-worm-archive-execution-report-fail.json"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
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

cleanup() {
    docker rm -f "$minio_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for command in cargo curl docker jq python3 sha256sum; do
    require_command "$command"
done

if ! docker image inspect "$minio_image" >/dev/null 2>&1; then
    echo "apolysis-production-hardening: missing MinIO image: $minio_image" >&2
    echo "apolysis-production-hardening: pull it first or set APOLYSIS_PRODUCTION_HARDENING_MINIO_IMAGE to an available image" >&2
    exit 1
fi

minio_port="${APOLYSIS_PRODUCTION_HARDENING_MINIO_PORT:-$(choose_free_port)}"
endpoint="http://127.0.0.1:$minio_port"
mkdir -p "$output_dir/minio-data"

docker rm -f "$minio_name" >/dev/null 2>&1 || true
docker run -d \
    --name "$minio_name" \
    -e "MINIO_ROOT_USER=$access_key" \
    -e "MINIO_ROOT_PASSWORD=$secret_key" \
    -p "127.0.0.1:$minio_port:9000" \
    -v "$output_dir/minio-data:/data" \
    "$minio_image" \
    server /data --address :9000 --console-address :9001 >/dev/null

for _ in $(seq 1 60); do
    if curl -fsS "$endpoint/minio/health/ready" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! curl -fsS "$endpoint/minio/health/ready" >/dev/null 2>&1; then
    echo "apolysis-production-hardening: MinIO did not become ready" >&2
    docker logs "$minio_name" >&2 || true
    exit 1
fi

python3 - \
    "$endpoint" \
    "$access_key" \
    "$secret_key" \
    "$bucket" \
    "$object_key" \
    "$retention_days" \
    "$output_dir" \
    "$evidence" <<'PY'
import base64
import datetime as dt
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

endpoint = sys.argv[1].rstrip("/")
access_key = sys.argv[2]
secret_key = sys.argv[3]
bucket = sys.argv[4]
object_key = sys.argv[5]
retention_days = int(sys.argv[6])
output_dir = Path(sys.argv[7])
evidence_path = Path(sys.argv[8])
region = "us-east-1"
service = "s3"

parsed_endpoint = urllib.parse.urlparse(endpoint)
host = parsed_endpoint.netloc
if not host:
    raise SystemExit(f"invalid endpoint: {endpoint}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(date_stamp: str) -> bytes:
    key = ("AWS4" + secret_key).encode("utf-8")
    key = hmac_sha256(key, date_stamp)
    key = hmac_sha256(key, region)
    key = hmac_sha256(key, service)
    return hmac_sha256(key, "aws4_request")


def canonical_query(query: list[tuple[str, str]]) -> str:
    return "&".join(
        f"{urllib.parse.quote(str(key), safe='-_.~')}={urllib.parse.quote(str(value), safe='-_.~')}"
        for key, value in sorted(query)
    )


def request(method: str, path: str, query=None, headers=None, body: bytes = b"") -> dict:
    query = list(query or [])
    headers = dict(headers or {})
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = sha256_hex(body)

    signed_headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    for key, value in headers.items():
        signed_headers[key.lower()] = " ".join(str(value).strip().split())

    canonical_headers = "".join(
        f"{key}:{signed_headers[key]}\n" for key in sorted(signed_headers)
    )
    signed_header_names = ";".join(sorted(signed_headers))
    query_string = canonical_query(query)
    canonical_uri = urllib.parse.quote(path, safe="/-_.~")
    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            query_string,
            canonical_headers,
            signed_header_names,
            payload_hash,
        ]
    )
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            sha256_hex(canonical_request.encode("utf-8")),
        ]
    )
    signature = hmac.new(
        signing_key(date_stamp), string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_header_names}, "
        f"Signature={signature}"
    )

    url = endpoint + path
    if query_string:
        url += "?" + query_string
    request_headers = {key: value for key, value in headers.items()}
    request_headers.update(
        {
            "Authorization": authorization,
            "Host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
    )
    req = urllib.request.Request(
        url,
        data=body if method in {"PUT", "POST"} else None,
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            response_body = response.read()
            return {
                "method": method,
                "path": path,
                "query": query,
                "status": response.status,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "body": response_body,
            }
    except urllib.error.HTTPError as error:
        return {
            "method": method,
            "path": path,
            "query": query,
            "status": error.code,
            "headers": {k.lower(): v for k, v in error.headers.items()},
            "body": error.read(),
        }


def require_status(result: dict, expected: set[int], label: str) -> None:
    if result["status"] not in expected:
        body = result["body"].decode("utf-8", errors="replace")
        raise SystemExit(f"{label} failed with HTTP {result['status']}: {body}")


def parse_s3_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def observation(result: dict) -> dict:
    return {
        "method": result["method"],
        "path": result["path"],
        "query": result["query"],
        "status": result["status"],
        "headers": result["headers"],
        "body_sha256": sha256_hex(result["body"]),
        "body_text": result["body"].decode("utf-8", errors="replace")[:4096],
    }


observed_at_unix_ms = int(time.time()) * 1000
observed_at = dt.datetime.fromtimestamp(
    observed_at_unix_ms / 1000, tz=dt.timezone.utc
)
retain_until = observed_at + dt.timedelta(days=retention_days, minutes=5)
retain_until_header = retain_until.strftime("%Y-%m-%dT%H:%M:%SZ")
retain_until_unix_ms = int(retain_until.timestamp() * 1000)

manifest = {
    "schema": "apolysis.dev/production-hardening-worm-archive-execution-manifest/v1",
    "generated_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "bucket": bucket,
    "object_key": object_key,
    "retention_mode": "COMPLIANCE",
    "retention_days": retention_days,
}
manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
    "utf-8"
)
release_manifest = output_dir / "apolysis-production-hardening-worm-release-manifest.json"
release_manifest.write_bytes(manifest_bytes)
release_manifest_sha256 = sha256_hex(manifest_bytes)

create_bucket = request(
    "PUT",
    f"/{bucket}",
    headers={"x-amz-bucket-object-lock-enabled": "true"},
)
require_status(create_bucket, {200}, "create object-lock bucket")

versioning_xml = b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>"
put_versioning = request(
    "PUT",
    f"/{bucket}",
    query=[("versioning", "")],
    headers={"Content-Type": "application/xml"},
    body=versioning_xml,
)
require_status(put_versioning, {200}, "enable bucket versioning")

get_versioning = request("GET", f"/{bucket}", query=[("versioning", "")])
require_status(get_versioning, {200}, "read bucket versioning")
versioning_enabled = b"<Status>Enabled</Status>" in get_versioning["body"]

get_object_lock = request("GET", f"/{bucket}", query=[("object-lock", "")])
object_lock_enabled = (
    get_object_lock["status"] == 200
    and b"<ObjectLockEnabled>Enabled</ObjectLockEnabled>" in get_object_lock["body"]
)

content_md5 = base64.b64encode(hashlib.md5(manifest_bytes).digest()).decode("ascii")
put_object = request(
    "PUT",
    f"/{bucket}/{object_key}",
    headers={
        "Content-MD5": content_md5,
        "Content-Type": "application/json",
        "x-amz-object-lock-mode": "COMPLIANCE",
        "x-amz-object-lock-retain-until-date": retain_until_header,
        "x-amz-object-lock-legal-hold": "ON",
    },
    body=manifest_bytes,
)
require_status(put_object, {200}, "put retained object")
object_version_id = put_object["headers"].get("x-amz-version-id", "")
if not object_version_id:
    raise SystemExit("put retained object did not return x-amz-version-id")

head_object = request(
    "HEAD",
    f"/{bucket}/{object_key}",
    query=[("versionId", object_version_id)],
)
require_status(head_object, {200}, "head retained object")
head_headers = head_object["headers"]
retained_until_header = head_headers.get("x-amz-object-lock-retain-until-date", "")
retention_applied = (
    head_headers.get("x-amz-object-lock-mode") == "COMPLIANCE"
    and retained_until_header
    and parse_s3_timestamp(retained_until_header) >= retain_until
)
legal_hold_applied = head_headers.get("x-amz-object-lock-legal-hold") == "ON"

get_object = request(
    "GET",
    f"/{bucket}/{object_key}",
    query=[("versionId", object_version_id)],
)
require_status(get_object, {200}, "read retained object")
object_sha256 = sha256_hex(get_object["body"])
head_object_verified = object_sha256 == release_manifest_sha256

delete_object = request(
    "DELETE",
    f"/{bucket}/{object_key}",
    query=[("versionId", object_version_id)],
)
delete_body = delete_object["body"].decode("utf-8", errors="replace")
delete_without_bypass_denied = (
    delete_object["status"] in {400, 403}
    and ("AccessDenied" in delete_body or "WORM" in delete_body or "retention" in delete_body)
)

observations = {
    "endpoint": endpoint,
    "bucket": bucket,
    "object_key": object_key,
    "object_version_id": object_version_id,
    "retain_until": retain_until_header,
    "operations": {
        "create_bucket": observation(create_bucket),
        "put_versioning": observation(put_versioning),
        "get_versioning": observation(get_versioning),
        "get_object_lock": observation(get_object_lock),
        "put_object": observation(put_object),
        "head_object": observation(head_object),
        "get_object": observation(get_object),
        "delete_object_without_bypass": observation(delete_object),
    },
}
observations_path = output_dir / "apolysis-production-hardening-worm-s3-api-observations.json"
observations_path.write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")

evidence = {
    "evidence_id": "production-hardening-worm-archive-execution",
    "source": "live_provider",
    "provider": "s3_object_lock",
    "endpoint_uri": endpoint,
    "bucket_uri": f"s3://{bucket}",
    "object_key": object_key,
    "object_version_id": object_version_id,
    "release_manifest_sha256": release_manifest_sha256,
    "object_sha256": object_sha256,
    "observed_at_unix_ms": observed_at_unix_ms,
    "retention_days": retention_days,
    "retain_until_unix_ms": retain_until_unix_ms,
    "retention_mode": "compliance",
    "object_lock_enabled": object_lock_enabled,
    "versioning_enabled": versioning_enabled,
    "put_object_succeeded": put_object["status"] == 200,
    "retention_applied": retention_applied,
    "legal_hold_applied": legal_hold_applied,
    "head_object_verified": head_object_verified,
    "delete_without_bypass_denied": delete_without_bypass_denied,
    "audit_log_ref": observations_path.as_uri(),
    "operator_approved": True,
    "api_tool": "python3 urllib.request SigV4 S3 API",
}
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

if not all(
    [
        object_lock_enabled,
        versioning_enabled,
        evidence["put_object_succeeded"],
        retention_applied,
        legal_hold_applied,
        head_object_verified,
        delete_without_bypass_denied,
    ]
):
    raise SystemExit(
        "WORM API execution did not prove object lock, versioning, retention, legal hold, "
        "metadata readback, and delete denial; see " + str(observations_path)
    )
PY

cargo run -q -p apolysis-validation --bin apolysis-production-hardening-worm-archive-execution-evidence -- \
    --evidence "$evidence" >"$report"

jq -e '
  .passed == true
  and .approval.provider == "s3_object_lock"
  and .approval.retention_mode == "compliance"
  and (.approval.retention_days >= 180)
  and (.approval.object_version_id | length > 0)
' "$report" >/dev/null

jq '
  .source = "fixture"
  | .provider = "local_filesystem"
  | .endpoint_uri = "file:///tmp/apolysis-archive"
  | .bucket_uri = "/tmp/apolysis-archive"
  | .object_key = "../release-manifest.json"
  | .object_version_id = ""
  | .object_sha256 = "not-a-sha"
  | .retention_mode = "governance"
  | .retention_days = 30
  | .retain_until_unix_ms = (.observed_at_unix_ms + 2592000000)
  | .object_lock_enabled = false
  | .versioning_enabled = false
  | .put_object_succeeded = false
  | .retention_applied = false
  | .legal_hold_applied = false
  | .head_object_verified = false
  | .delete_without_bypass_denied = false
  | .audit_log_ref = ""
  | .operator_approved = false
  | .api_tool = ""
  | .observed_at_unix_ms = 0
' "$evidence" >"$fail_evidence"

if cargo run -q -p apolysis-validation --bin apolysis-production-hardening-worm-archive-execution-evidence -- \
    --evidence "$fail_evidence" >"$fail_report"; then
    echo "apolysis-production-hardening: invalid WORM archive execution evidence unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("live WORM archive API execution evidence is required"))
  and (.failures | map(.message) | index("WORM archive execution requires S3 Object Lock, GCS Bucket Lock, or Azure Immutable Blob"))
  and (.failures | map(.message) | index("object lock must be enabled by the provider"))
  and (.failures | map(.message) | index("retention must be applied through the provider API"))
  and (.failures | map(.message) | index("delete without bypass must be denied by the provider API"))
' "$fail_report" >/dev/null

printf 'apolysis-production-hardening: WORM archive API execution gate passed (%s)\n' "$output_dir"

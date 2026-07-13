#!/usr/bin/env bash

set -Eeuo pipefail

# Pin the real database used by the transport gate to the same reviewed image
# as the repository gate. The digest is intentionally duplicated so a change
# to either gate remains visible in review.
readonly DEFAULT_POSTGRES_IMAGE="postgres:16.14-alpine3.23@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3"

postgres_image="$DEFAULT_POSTGRES_IMAGE"
pull_timeout_seconds="${APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS:-300}"
start_timeout_seconds="${APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS:-60}"
gate_timeout_seconds="${APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS:-900}"

if [[ "${APOLYSIS_GATEWAY_TRANSPORT_INNER:-0}" != "1" ]]; then
    if ! command -v timeout >/dev/null 2>&1; then
        printf 'error: required command not found: timeout\n' >&2
        exit 1
    fi
    if [[ ! "$gate_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS must be a positive integer\n' >&2
        exit 1
    fi
    export APOLYSIS_GATEWAY_TRANSPORT_INNER=1
    exec timeout --foreground --kill-after=15s "${gate_timeout_seconds}s" "$0" "$@"
fi

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

require_positive_integer() {
    local variable_name="$1"
    local value="$2"

    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: %s must be a positive integer\n' "$variable_name" >&2
        exit 1
    fi
}

random_hex() {
    local byte_count="$1"
    od -An -N "$byte_count" -tx1 /dev/urandom | tr -d '[:space:]'
}

for command in cargo curl date docker grep head jq mktemp od openssl stat timeout tr; do
    require_command "$command"
done

require_positive_integer APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS "$pull_timeout_seconds"
require_positive_integer APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS "$start_timeout_seconds"
require_positive_integer APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS "$gate_timeout_seconds"

if ! timeout 10s docker info >/dev/null 2>&1; then
    printf 'error: Docker daemon is unavailable or inaccessible\n' >&2
    exit 1
fi

printf 'Building the production Gateway transport binaries...\n'
timeout --foreground --kill-after=15s "${gate_timeout_seconds}s" \
    cargo build -p apolysis-gateway-server --bins

readonly gateway_bin="target/debug/apolysis-gateway-server"
readonly authority_bin="target/debug/apolysis-gateway-authority"
readonly request_bin="target/debug/apolysis-gateway-request"

for binary in "$gateway_bin" "$authority_bin" "$request_bin"; do
    if [[ ! -x "$binary" ]]; then
        printf 'error: expected executable was not built: %s\n' "$binary" >&2
        exit 1
    fi
done

readonly random_suffix="$(random_hex 8)"
readonly container_name="apolysis-gateway-transport-${random_suffix}"
readonly database_name="apolysis_transport_${random_suffix}"
readonly database_user="apolysis_transport_${random_suffix}"
readonly database_password="$(random_hex 24)"
readonly secret_directory="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-gateway-transport.XXXXXXXX")"
readonly container_env_file="${secret_directory}/postgres.env"
readonly database_url_file="${secret_directory}/database.url"
readonly server_log="${secret_directory}/gateway.log"
readonly ready_file="${secret_directory}/gateway.ready"

gateway_pid=""

cleanup() {
    local exit_status=$?

    trap - EXIT INT TERM
    if [[ -n "$gateway_pid" ]] && kill -0 "$gateway_pid" >/dev/null 2>&1; then
        kill -TERM "$gateway_pid" >/dev/null 2>&1 || true
        timeout 10s tail --pid="$gateway_pid" -f /dev/null >/dev/null 2>&1 || \
            kill -KILL "$gateway_pid" >/dev/null 2>&1 || true
    fi
    timeout 15s docker rm --force "$container_name" >/dev/null 2>&1 || true
    rm -rf -- "$secret_directory"
    exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

chmod 700 "$secret_directory"
umask 077

{
    printf 'POSTGRES_DB=%s\n' "$database_name"
    printf 'POSTGRES_USER=%s\n' "$database_user"
    printf 'POSTGRES_PASSWORD=%s\n' "$database_password"
} >"$container_env_file"

printf 'Pulling the pinned PostgreSQL transport-gate image...\n'
timeout --foreground "${pull_timeout_seconds}s" docker pull "$postgres_image" >/dev/null

printf 'Starting an ephemeral loopback-only PostgreSQL server...\n'
timeout --foreground 30s docker run \
    --detach \
    --rm \
    --name "$container_name" \
    --env-file "$container_env_file" \
    --publish "127.0.0.1::5432" \
    "$postgres_image" >/dev/null
rm -f -- "$container_env_file"

readiness_deadline=$((SECONDS + start_timeout_seconds))
until timeout 5s docker exec "$container_name" \
    pg_isready --quiet --username "$database_user" --dbname "$database_name"; do
    if ((SECONDS >= readiness_deadline)); then
        printf 'error: PostgreSQL did not become ready within %s seconds\n' \
            "$start_timeout_seconds" >&2
        exit 1
    fi
    sleep 1
done

published_binding="$(timeout 5s docker port "$container_name" 5432/tcp)"
if [[ ! "$published_binding" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
    printf 'error: expected a single loopback-only PostgreSQL port binding\n' >&2
    exit 1
fi
readonly published_port="${BASH_REMATCH[1]}"
readonly database_url="postgresql://${database_user}:${database_password}@127.0.0.1:${published_port}/${database_name}"
printf '%s\n' "$database_url" >"$database_url_file"
chmod 600 "$database_url_file"

readonly ca_key="${secret_directory}/ca.key.pem"
readonly ca_cert="${secret_directory}/ca.cert.pem"
readonly server_key="${secret_directory}/server.key.pem"
readonly server_csr="${secret_directory}/server.csr.pem"
readonly server_cert="${secret_directory}/server.cert.pem"
readonly server_extensions="${secret_directory}/server.ext"
readonly client_key="${secret_directory}/client.key.pem"
readonly client_csr="${secret_directory}/client.csr.pem"
readonly client_cert="${secret_directory}/client.cert.pem"
readonly client_extensions="${secret_directory}/client.ext"
readonly untrusted_client_key="${secret_directory}/untrusted-client.key.pem"
readonly untrusted_client_cert="${secret_directory}/untrusted-client.cert.pem"
readonly unknown_client_key="${secret_directory}/unknown-client.key.pem"
readonly unknown_client_csr="${secret_directory}/unknown-client.csr.pem"
readonly unknown_client_cert="${secret_directory}/unknown-client.cert.pem"
readonly replay_key_file="${secret_directory}/replay.key"

printf 'Generating a real ephemeral CA and mTLS leaf certificates...\n'
openssl req -x509 -newkey ed25519 -nodes \
    -keyout "$ca_key" \
    -out "$ca_cert" \
    -days 1 \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -subj "/CN=Apolysis transport gate CA ${random_suffix}" >/dev/null 2>&1

openssl req -newkey ed25519 -nodes \
    -keyout "$server_key" \
    -out "$server_csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
{
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
} >"$server_extensions"
openssl x509 -req \
    -in "$server_csr" \
    -CA "$ca_cert" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$server_cert" \
    -days 1 \
    -extfile "$server_extensions" >/dev/null 2>&1

openssl req -newkey ed25519 -nodes \
    -keyout "$client_key" \
    -out "$client_csr" \
    -subj "/CN=apolysis-live-source-${random_suffix}" >/dev/null 2>&1
{
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'extendedKeyUsage=clientAuth\n'
} >"$client_extensions"
openssl x509 -req \
    -in "$client_csr" \
    -CA "$ca_cert" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$client_cert" \
    -days 1 \
    -extfile "$client_extensions" >/dev/null 2>&1

openssl req -x509 -newkey ed25519 -nodes \
    -keyout "$untrusted_client_key" \
    -out "$untrusted_client_cert" \
    -days 1 \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=clientAuth' \
    -subj "/CN=apolysis-untrusted-source-${random_suffix}" >/dev/null 2>&1

openssl req -newkey ed25519 -nodes \
    -keyout "$unknown_client_key" \
    -out "$unknown_client_csr" \
    -subj "/CN=apolysis-unknown-source-${random_suffix}" >/dev/null 2>&1
openssl x509 -req \
    -in "$unknown_client_csr" \
    -CA "$ca_cert" \
    -CAkey "$ca_key" \
    -CAcreateserial \
    -out "$unknown_client_cert" \
    -days 1 \
    -extfile "$client_extensions" >/dev/null 2>&1

random_hex 32 >"$replay_key_file"

readonly now_unix_ms="$(( $(date +%s) * 1000 ))"
readonly expires_at_unix_ms="$((now_unix_ms + 3600000))"
readonly organization_id="org_live_${random_suffix}"
readonly principal_id="principal_live_${random_suffix}"
readonly registration_id="registration_live_${random_suffix}"
readonly source_id="source_live_${random_suffix}"
readonly authority_id="authority_live_${random_suffix}"
readonly policy_file="${secret_directory}/source-registration.json"

jq -n \
    --arg organization_id "$organization_id" \
    --arg principal_id "$principal_id" \
    --arg registration_id "$registration_id" \
    --arg source_id "$source_id" \
    --arg authority_id "$authority_id" \
    --argjson effective_at_unix_ms "$now_unix_ms" \
    --argjson expires_at_unix_ms "$expires_at_unix_ms" \
    '{
        organization_id: $organization_id,
        organization_state: "active",
        source_registration_id: $registration_id,
        source_id: $source_id,
        principal: {kind: "workload", id: $principal_id},
        policy_revision: 1,
        credential_epoch: 1,
        effective_at_unix_ms: $effective_at_unix_ms,
        expires_at_unix_ms: $expires_at_unix_ms,
        allowed_source_kinds: ["semantic_hook"],
        allowed_environments: ["local_cli_or_ide"],
        allowed_operations: ["bind_runtime", "ingest", "finish_run"],
        effective_trust_profile: "harness_observed",
        allowed_capabilities: ["semantic_lifecycle", "tool_calls", "claimed_outcome"],
        allowed_privacy_capabilities: ["structure_only"],
        allowed_redaction_profile_refs: ["redaction_structure_only_v1"],
        allowed_run_authorities: [{kind: "service", id: $authority_id}],
        allowed_run_privacy_profile_refs: ["privacy_structure_only_v1"],
        allowed_run_retention_profile_refs: ["retention_30d_v1"],
        required_run_source_kinds: ["semantic_hook"],
        may_create_runs: true,
        may_join_runs: false,
        may_finalize_runs: true
    }' >"$policy_file"

printf 'Migrating and provisioning the current mTLS authority state...\n'
"$authority_bin" migrate \
    --database-url-file "$database_url_file"
"$authority_bin" register-source \
        --database-url-file "$database_url_file" \
        --registration "$policy_file" \
        --client-certificate "$client_cert"

printf 'Starting the production mTLS Gateway on an ephemeral loopback port...\n'
"$gateway_bin" \
        --listen 127.0.0.1:0 \
        --database-url-file "$database_url_file" \
        --tls-certificate "$server_cert" \
        --tls-private-key "$server_key" \
        --client-ca "$ca_cert" \
        --replay-key "$replay_key_file" \
        --ready-file "$ready_file" \
        >"$server_log" 2>&1 &
gateway_pid=$!

gateway_deadline=$((SECONDS + start_timeout_seconds))
while [[ ! -s "$ready_file" ]]; do
    if ! kill -0 "$gateway_pid" >/dev/null 2>&1; then
        printf 'error: Gateway exited before becoming ready\n' >&2
        exit 1
    fi
    if ((SECONDS >= gateway_deadline)); then
        printf 'error: Gateway did not become ready within %s seconds\n' \
            "$start_timeout_seconds" >&2
        exit 1
    fi
    sleep 0.1
done

gateway_base_url="$(<"$ready_file")"
if [[ ! "$gateway_base_url" =~ ^https://127\.0\.0\.1:[0-9]+$ ]]; then
    printf 'error: Gateway ready file did not contain a loopback HTTPS URL\n' >&2
    exit 1
fi
readonly gateway_base_url
if [[ "$(stat -c '%a' "$ready_file")" != "600" ]]; then
    printf 'error: Gateway ready file is not mode 0600\n' >&2
    exit 1
fi

printf 'Checking that TLS rejects a client without a certificate...\n'
if curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 20 \
    --cacert "$ca_cert" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{}' \
    "${gateway_base_url}/gateway/v0.1/open-run" \
    >/dev/null 2>&1; then
    printf 'error: Gateway TLS accepted a client without a certificate\n' >&2
    exit 1
fi

readonly unknown_response="${secret_directory}/unknown-credential.response.json"
unknown_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 20 \
    --cacert "$ca_cert" \
    --cert "$unknown_client_cert" \
    --key "$unknown_client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{}' \
    --output "$unknown_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$unknown_status" != "401" ]]; then
    printf 'error: unregistered CA-issued credential returned HTTP %s instead of 401\n' \
        "$unknown_status" >&2
    exit 1
fi
if ! jq -e '.code == "unauthenticated" and .retryable == false' \
    "$unknown_response" >/dev/null; then
    printf 'error: unregistered credential response violated the safe error contract\n' >&2
    exit 1
fi

printf 'Checking that TLS rejects a certificate outside the configured CA...\n'
if curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 20 \
    --cacert "$ca_cert" \
    --cert "$untrusted_client_cert" \
    --key "$untrusted_client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{}' \
    "${gateway_base_url}/gateway/v0.1/open-run" \
    >/dev/null 2>&1; then
    printf 'error: Gateway TLS accepted a certificate outside the configured CA\n' >&2
    exit 1
fi

readonly unsigned_request="${secret_directory}/open-run.unsigned.json"
readonly signed_request="${secret_directory}/open-run.json"
readonly first_response="${secret_directory}/open-run.response.json"
readonly revoked_response="${secret_directory}/open-run.revoked.json"
readonly injected_response="${secret_directory}/open-run.injected.json"
readonly oversized_request="${secret_directory}/open-run.oversized.json"
readonly oversized_response="${secret_directory}/open-run.oversized.response.json"

jq -n \
    --arg operation_id "operation_live_${random_suffix}" \
    --arg client_run_key "client_run_live_${random_suffix}" \
    --arg authority_id "$authority_id" \
    --arg principal_id "$principal_id" \
    --arg source_id "$source_id" \
    '{
        schema_version: "0.1",
        mode: "create",
        client_operation_id: $operation_id,
        request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        client_run_key: $client_run_key,
        environment: "local_cli_or_ide",
        authority: {kind: "service", id: $authority_id},
        principal: {kind: "workload", id: $principal_id},
        objective_ref: "objective_content_off_live_transport",
        privacy_profile_ref: "privacy_structure_only_v1",
        retention_profile_ref: "retention_30d_v1",
        expected_source_kinds: ["semantic_hook"],
        source_manifest: {
            schema_version: "0.1",
            source_id: $source_id,
            source_kind: "semantic_hook",
            declared_boundary: "agent_harness",
            adapter_name: "apolysis_live_transport",
            adapter_version: "0.1.0",
            environment: "local_cli_or_ide",
            capabilities: ["semantic_lifecycle", "tool_calls", "claimed_outcome"],
            expected_lifecycle: ["started", "finished"],
            ordering: "strict_per_stream",
            samples: false,
            redaction_profile_ref: "redaction_structure_only_v1",
            redacted_fields: ["payload.command", "payload.arguments"],
            privacy_capabilities: ["structure_only"]
        }
    }' >"$unsigned_request"

"$request_bin" open-run \
    --input "$unsigned_request" \
    --output "$signed_request"

injected_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --header 'X-Organization-Id: attacker_controlled' \
    --data-binary "@${signed_request}" \
    --output "$injected_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$injected_status" != "400" ]] || \
    ! jq -e '.code == "invalid_contract"' "$injected_response" >/dev/null; then
    printf 'error: request-supplied organization authority was not rejected\n' >&2
    exit 1
fi

head -c 1048577 /dev/zero | tr '\0' 'a' >"$oversized_request"
oversized_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${oversized_request}" \
    --output "$oversized_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$oversized_status" != "413" ]] || \
    ! jq -e '.code == "batch_too_large"' "$oversized_response" >/dev/null; then
    printf 'error: oversized Gateway request did not fail closed with HTTP 413\n' >&2
    exit 1
fi

printf 'Opening a real Agent Run through the mTLS HTTP seam...\n'
first_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${signed_request}" \
    --output "$first_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"

if [[ "$first_status" != "200" ]]; then
    printf 'error: authenticated open_run returned HTTP %s\n' "$first_status" >&2
    jq -c '{schema_version,code,message,retryable,retry_after_ms}' \
        "$first_response" >&2 || true
    exit 1
fi

jq -e \
    --arg source_id "$source_id" \
    '.schema_version == "0.1"
     and .outcome == "created"
     and .source_id == $source_id
     and (.run_id | type == "string" and length > 0)
     and (.source_stream_id | type == "string" and length > 0)
     and (.lease.lease_id | type == "string" and length >= 32)' \
    "$first_response" >/dev/null

readonly issued_lease="$(jq -r '.lease.lease_id' "$first_response")"

readonly database_dump="${secret_directory}/database.dump.sql"
if ! timeout 30s docker exec "$container_name" \
    pg_dump --username "$database_user" --dbname "$database_name" \
        --no-owner --no-privileges >"$database_dump"; then
    printf 'error: failed to inspect PostgreSQL secret persistence\n' >&2
    exit 1
fi
if grep -Fq -- "$issued_lease" "$database_dump"; then
    printf 'error: plaintext run lease was persisted in PostgreSQL\n' >&2
    exit 1
fi
rm -f -- "$database_dump"

printf 'Revoking the current transport credential in PostgreSQL...\n'
"$authority_bin" revoke-credential \
        --database-url-file "$database_url_file" \
        --client-certificate "$client_cert" \
        --reason "live_transport_gate_${random_suffix}"

readonly revoked_registration="${secret_directory}/source-registration.revoked.json"
jq '.policy_revision = 2 | .credential_epoch = 2' \
    "$policy_file" >"$revoked_registration"
if "$authority_bin" register-source \
    --database-url-file "$database_url_file" \
    --registration "$revoked_registration" \
    --client-certificate "$client_cert" \
    >/dev/null 2>&1; then
    printf 'error: a revoked client certificate was registered again\n' >&2
    exit 1
fi

revoked_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${signed_request}" \
    --output "$revoked_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"

if [[ "$revoked_status" != "401" ]]; then
    printf 'error: revoked transport credential returned HTTP %s instead of 401\n' \
        "$revoked_status" >&2
    exit 1
fi

jq -e \
    '.schema_version == "0.1"
     and .code == "unauthenticated"
     and .retryable == false
     and .retry_after_ms == null' \
    "$revoked_response" >/dev/null

printf 'Checking that bearer and database secrets were absent from Gateway logs...\n'
readonly replay_key_value="$(<"$replay_key_file")"
if grep -Fq -- "$issued_lease" "$server_log"; then
    printf 'error: plaintext run lease was written to the Gateway log\n' >&2
    exit 1
fi
if grep -Fq -- "$database_password" "$server_log"; then
    printf 'error: PostgreSQL password was written to the Gateway log\n' >&2
    exit 1
fi
if grep -Fq -- "$replay_key_value" "$server_log"; then
    printf 'error: replay protection key was written to the Gateway log\n' >&2
    exit 1
fi
if grep -Fq -- 'BEGIN PRIVATE KEY' "$server_log"; then
    printf 'error: TLS private-key material was written to the Gateway log\n' >&2
    exit 1
fi

printf 'Real mTLS Gateway authority gate passed.\n'

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

assert_no_store() {
    local header_file="$1"
    local context="$2"

    if ! grep -Eiq '^cache-control:[[:space:]]*no-store[[:space:]]*$' "$header_file"; then
        printf 'error: %s response omitted Cache-Control: no-store\n' "$context" >&2
        exit 1
    fi
}

for command in awk cargo cmp curl date docker grep head jq mktemp od openssl stat tail timeout tr; do
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
readonly schema_owner_login="apolysis_transport_schema_${random_suffix}"
readonly schema_owner_password="$(random_hex 24)"
readonly gateway_control_login="apolysis_transport_control_${random_suffix}"
readonly gateway_control_password="$(random_hex 24)"
readonly gateway_runtime_login="apolysis_transport_runtime_${random_suffix}"
readonly gateway_runtime_password="$(random_hex 24)"
readonly secret_directory="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-gateway-transport.XXXXXXXX")"
readonly container_env_file="${secret_directory}/postgres.env"
readonly database_url_file="${secret_directory}/database.url"
readonly schema_owner_database_url_file="${secret_directory}/schema-owner.database.url"
readonly gateway_control_database_url_file="${secret_directory}/gateway-control.database.url"
readonly role_provisioning_sql="${secret_directory}/provision-roles.sql"
readonly server_log="${secret_directory}/gateway.log"
readonly ready_file="${secret_directory}/gateway.ready"

gateway_pid=""
gateway_base_url=""
workload_pid=""

stop_gateway() {
    if [[ -n "$gateway_pid" ]] && kill -0 "$gateway_pid" >/dev/null 2>&1; then
        kill -TERM "$gateway_pid" >/dev/null 2>&1 || true
        timeout 10s tail --pid="$gateway_pid" -f /dev/null >/dev/null 2>&1 || \
            kill -KILL "$gateway_pid" >/dev/null 2>&1 || true
    fi
    if [[ -n "$gateway_pid" ]]; then
        wait "$gateway_pid" 2>/dev/null || true
    fi
    gateway_pid=""
}

start_gateway() {
    rm -f -- "$ready_file"
    "$gateway_bin" \
            --listen 127.0.0.1:0 \
            --database-url-file "$database_url_file" \
            --tls-certificate "$server_cert" \
            --tls-private-key "$server_key" \
            --client-ca "$ca_cert" \
            --replay-key "$replay_key_file" \
            --ready-file "$ready_file" \
            >>"$server_log" 2>&1 &
    gateway_pid=$!

    local gateway_deadline=$((SECONDS + start_timeout_seconds))
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
    if [[ "$(stat -c '%a' "$ready_file")" != "600" ]]; then
        printf 'error: Gateway ready file is not mode 0600\n' >&2
        exit 1
    fi
}

cleanup() {
    local exit_status=$?

    trap - EXIT INT TERM
    stop_gateway
    if [[ -n "$workload_pid" ]] && kill -0 "$workload_pid" >/dev/null 2>&1; then
        kill -TERM "$workload_pid" >/dev/null 2>&1 || true
        wait "$workload_pid" 2>/dev/null || true
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
until [[ "$(timeout 5s docker exec "$container_name" cat /proc/1/comm 2>/dev/null)" == "postgres" ]] && \
    timeout 5s docker exec "$container_name" \
        pg_isready --quiet --username "$database_user" --dbname "$database_name" && \
    [[ "$(timeout 5s docker exec "$container_name" \
        psql --username "$database_user" --dbname "$database_name" \
            --no-align --tuples-only --command 'SELECT 1' 2>/dev/null)" == "1" ]]; do
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

host_readiness_deadline=$((SECONDS + start_timeout_seconds))
until (exec 9<>"/dev/tcp/127.0.0.1/${published_port}") 2>/dev/null; do
    if ((SECONDS >= host_readiness_deadline)); then
        printf 'error: PostgreSQL loopback port did not become reachable within %s seconds\n' \
            "$start_timeout_seconds" >&2
        exit 1
    fi
    sleep 0.1
done

readonly schema_owner_database_url="postgresql://${schema_owner_login}:${schema_owner_password}@127.0.0.1:${published_port}/${database_name}"
readonly gateway_control_database_url="postgresql://${gateway_control_login}:${gateway_control_password}@127.0.0.1:${published_port}/${database_name}"
readonly gateway_runtime_database_url="postgresql://${gateway_runtime_login}:${gateway_runtime_password}@127.0.0.1:${published_port}/${database_name}"
printf '%s\n' "$schema_owner_database_url" >"$schema_owner_database_url_file"
printf '%s\n' "$gateway_control_database_url" >"$gateway_control_database_url_file"
printf '%s\n' "$gateway_runtime_database_url" >"$database_url_file"
chmod 600 \
    "$schema_owner_database_url_file" \
    "$gateway_control_database_url_file" \
    "$database_url_file"

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
readonly attacker_organization_id="org_attacker_${random_suffix}"
readonly attacker_principal_id="principal_attacker_${random_suffix}"
readonly attacker_registration_id="registration_attacker_${random_suffix}"
readonly attacker_source_id="source_attacker_${random_suffix}"
readonly attacker_authority_id="authority_attacker_${random_suffix}"
readonly attacker_policy_file="${secret_directory}/source-registration.attacker.json"

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
        allowed_capabilities: ["semantic_lifecycle", "tool_calls", "process", "claimed_outcome"],
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

jq \
    --arg organization_id "$attacker_organization_id" \
    --arg principal_id "$attacker_principal_id" \
    --arg registration_id "$attacker_registration_id" \
    --arg source_id "$attacker_source_id" \
    --arg authority_id "$attacker_authority_id" \
    '.organization_id = $organization_id
     | .source_registration_id = $registration_id
     | .source_id = $source_id
     | .principal.id = $principal_id
     | .allowed_run_authorities = [{kind: "service", id: $authority_id}]' \
    "$policy_file" >"$attacker_policy_file"

printf 'Bootstrapping the reviewed PostgreSQL role model...\n'
timeout 30s docker exec -i "$container_name" \
    psql --username "$database_user" --dbname "$database_name" \
        --set=ON_ERROR_STOP=1 \
    <crates/apolysis-gateway-postgres/deploy/bootstrap_roles.sql

{
    printf 'BEGIN;\n'
    printf "CREATE ROLE %s WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s';\n" \
        "$schema_owner_login" "$schema_owner_password"
    printf 'GRANT apolysis_schema_owner TO %s;\n' "$schema_owner_login"
    printf 'COMMIT;\n'
} >"$role_provisioning_sql"
chmod 600 "$role_provisioning_sql"
timeout 30s docker exec -i "$container_name" \
    psql --username "$database_user" --dbname "$database_name" \
        --set=ON_ERROR_STOP=1 \
    <"$role_provisioning_sql"
rm -f -- "$role_provisioning_sql"

printf 'Migrating under the dedicated schema-owner login...\n'
"$authority_bin" migrate \
    --database-url-file "$schema_owner_database_url_file"

printf 'Sealing post-migration ownership and application privileges...\n'
timeout 30s docker exec -i "$container_name" \
    psql --username "$schema_owner_login" --dbname "$database_name" \
        --set=ON_ERROR_STOP=1 \
    <crates/apolysis-gateway-postgres/deploy/privileges.sql

{
    printf 'BEGIN;\n'
    printf "CREATE ROLE %s WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s';\n" \
        "$gateway_control_login" "$gateway_control_password"
    printf 'GRANT apolysis_gateway_control TO %s;\n' "$gateway_control_login"
    printf "CREATE ROLE %s WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s';\n" \
        "$gateway_runtime_login" "$gateway_runtime_password"
    printf 'GRANT apolysis_gateway_runtime TO %s;\n' "$gateway_runtime_login"
    printf 'COMMIT;\n'
} >"$role_provisioning_sql"
chmod 600 "$role_provisioning_sql"
timeout 30s docker exec -i "$container_name" \
    psql --username "$database_user" --dbname "$database_name" \
        --set=ON_ERROR_STOP=1 \
    <"$role_provisioning_sql"
rm -f -- "$role_provisioning_sql"

# The final bootstrap audit runs only after migration, privilege sealing, and
# every served login membership are complete.
timeout 30s docker exec -i "$container_name" \
    psql --username "$database_user" --dbname "$database_name" \
        --set=ON_ERROR_STOP=1 \
    <crates/apolysis-gateway-postgres/deploy/bootstrap_roles.sql

printf 'Provisioning current mTLS authority through the control-plane login...\n'
"$authority_bin" register-source \
        --database-url-file "$gateway_control_database_url_file" \
        --registration "$policy_file" \
        --client-certificate "$client_cert"

readonly rotation_registration="${secret_directory}/source-registration.rotation.json"
jq '.policy_revision = 2 | .credential_epoch = 2' \
    "$policy_file" >"$rotation_registration"
if "$authority_bin" register-source \
    --database-url-file "$gateway_control_database_url_file" \
    --registration "$rotation_registration" \
    --client-certificate "$unknown_client_cert" \
    >/dev/null 2>&1; then
    printf 'error: credential rotation was accepted before the rotation safety gate\n' >&2
    exit 1
fi

printf 'Starting the production mTLS Gateway on an ephemeral loopback port...\n'
start_gateway

served_role_sessions="$(timeout 15s docker exec -i "$container_name" \
    psql --username "$database_user" --dbname "$database_name" \
        --no-align --tuples-only \
        --set=gateway_runtime_login="$gateway_runtime_login" \
        --set=gateway_control_login="$gateway_control_login" \
        --set=schema_owner_login="$schema_owner_login" <<'SQL'
SELECT concat_ws('|',
    (SELECT count(*) FROM pg_catalog.pg_stat_activity
      WHERE usename=:'gateway_runtime_login'),
    (SELECT count(*) FROM pg_catalog.pg_stat_activity
      WHERE usename=:'gateway_control_login'),
    (SELECT count(*) FROM pg_catalog.pg_stat_activity
      WHERE usename=:'schema_owner_login')
);
SQL
)"
IFS='|' read -r runtime_session_count control_session_count schema_session_count \
    <<<"$served_role_sessions"
if [[ ! "$runtime_session_count" =~ ^[0-9]+$ ]] || \
    ((runtime_session_count < 2)) || \
    [[ "$control_session_count" != "0" || "$schema_session_count" != "0" ]]; then
    printf 'error: Gateway did not isolate served sessions to the runtime login\n' >&2
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
readonly unknown_headers="${secret_directory}/unknown-credential.response.headers"
unknown_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 20 \
    --cacert "$ca_cert" \
    --cert "$unknown_client_cert" \
    --key "$unknown_client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{}' \
    --dump-header "$unknown_headers" \
    --output "$unknown_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$unknown_status" != "401" ]]; then
    printf 'error: unregistered CA-issued credential returned HTTP %s instead of 401\n' \
        "$unknown_status" >&2
    exit 1
fi
assert_no_store "$unknown_headers" 'unregistered credential'
if ! jq -e '.code == "unauthenticated" and .retryable == false' \
    "$unknown_response" >/dev/null; then
    printf 'error: unregistered credential response violated the safe error contract\n' >&2
    exit 1
fi

printf 'Registering an independent attacker organization for isolation checks...\n'
"$authority_bin" register-source \
        --database-url-file "$gateway_control_database_url_file" \
        --registration "$attacker_policy_file" \
        --client-certificate "$unknown_client_cert"

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
readonly open_replay_response="${secret_directory}/open-run.replay.response.json"
readonly injected_response="${secret_directory}/open-run.injected.json"
readonly oversized_request="${secret_directory}/open-run.oversized.json"
readonly oversized_response="${secret_directory}/open-run.oversized.response.json"
readonly first_headers="${secret_directory}/open-run.response.headers"
readonly open_replay_headers="${secret_directory}/open-run.replay.response.headers"
readonly injected_headers="${secret_directory}/open-run.injected.headers"
readonly oversized_headers="${secret_directory}/open-run.oversized.response.headers"
readonly not_found_response="${secret_directory}/not-found.response.json"
readonly not_found_headers="${secret_directory}/not-found.response.headers"
readonly method_response="${secret_directory}/method-not-allowed.response.json"
readonly method_headers="${secret_directory}/method-not-allowed.response.headers"

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
            capabilities: ["semantic_lifecycle", "tool_calls", "process", "claimed_outcome"],
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
    --header 'X-Forwarded-Organization-Id: attacker_controlled' \
    --data-binary "@${signed_request}" \
    --dump-header "$injected_headers" \
    --output "$injected_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$injected_status" != "400" ]] || \
    ! jq -e '.code == "invalid_contract"' "$injected_response" >/dev/null; then
    printf 'error: forwarded request authority was not rejected\n' >&2
    exit 1
fi
assert_no_store "$injected_headers" 'authority-header rejection'

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
    --dump-header "$oversized_headers" \
    --output "$oversized_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$oversized_status" != "413" ]] || \
    ! jq -e '.code == "batch_too_large"' "$oversized_response" >/dev/null; then
    printf 'error: oversized Gateway request did not fail closed with HTTP 413\n' >&2
    exit 1
fi
assert_no_store "$oversized_headers" 'oversized request'

not_found_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --dump-header "$not_found_headers" \
    --output "$not_found_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/not-a-route")"
if [[ "$not_found_status" != "404" ]] || \
    ! jq -e '.code == "not_found" and .retryable == false' \
        "$not_found_response" >/dev/null; then
    printf 'error: unknown Gateway route did not return the safe JSON 404 contract\n' >&2
    exit 1
fi
assert_no_store "$not_found_headers" 'unknown route'

method_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --request GET \
    --dump-header "$method_headers" \
    --output "$method_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$method_status" != "405" ]] || \
    ! jq -e '.code == "invalid_contract" and .retryable == false' \
        "$method_response" >/dev/null; then
    printf 'error: unsupported Gateway method did not return the safe JSON 405 contract\n' >&2
    exit 1
fi
assert_no_store "$method_headers" 'unsupported method'

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
    --dump-header "$first_headers" \
    --output "$first_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"

if [[ "$first_status" != "200" ]]; then
    printf 'error: authenticated open_run returned HTTP %s\n' "$first_status" >&2
    jq -c '{schema_version,code,message,retryable,retry_after_ms}' \
        "$first_response" >&2 || true
    exit 1
fi
assert_no_store "$first_headers" 'authenticated open_run'

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
readonly issued_run_id="$(jq -r '.run_id' "$first_response")"
readonly issued_stream_id="$(jq -r '.source_stream_id' "$first_response")"

printf 'Restarting the Gateway after open_run to prove durable continuation...\n'
stop_gateway
start_gateway

open_replay_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${signed_request}" \
    --dump-header "$open_replay_headers" \
    --output "$open_replay_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/open-run")"
if [[ "$open_replay_status" != "200" ]] || ! jq -e \
    --arg run_id "$issued_run_id" \
    --arg source_stream_id "$issued_stream_id" \
    --arg lease_id "$issued_lease" \
    '.schema_version == "0.1"
     and .outcome == "idempotent_retry"
     and .run_id == $run_id
     and .source_stream_id == $source_stream_id
     and .lease.lease_id == $lease_id' \
    "$open_replay_response" >/dev/null; then
    printf 'error: open_run exact retry did not survive Gateway restart\n' >&2
    exit 1
fi
assert_no_store "$open_replay_headers" 'open_run exact replay'

printf 'Binding a real local process through the mTLS lifecycle seam...\n'
sleep 300 &
workload_pid=$!
if [[ ! -r "/proc/${workload_pid}/stat" ]]; then
    printf 'error: real transport workload did not expose procfs identity\n' >&2
    exit 1
fi
readonly workload_start_ticks="$(awk '{print $22}' "/proc/${workload_pid}/stat")"
if [[ ! "$workload_start_ticks" =~ ^[1-9][0-9]*$ ]]; then
    printf 'error: real transport workload start time was invalid\n' >&2
    exit 1
fi
readonly binding_valid_from_unix_ms="$(date +%s%3N)"
readonly binding_valid_until_unix_ms="$((binding_valid_from_unix_ms + 300000))"
readonly workload_identity="process_${workload_pid}_${workload_start_ticks}"
readonly bind_unsigned_request="${secret_directory}/bind-runtime.unsigned.json"
readonly bind_signed_request="${secret_directory}/bind-runtime.json"
readonly bind_response="${secret_directory}/bind-runtime.response.json"
readonly bind_replay_response="${secret_directory}/bind-runtime.replay.response.json"
readonly bind_headers="${secret_directory}/bind-runtime.response.headers"
readonly bind_replay_headers="${secret_directory}/bind-runtime.replay.response.headers"
readonly binding_id="binding_live_${random_suffix}"

jq -n \
    --arg operation_id "operation_bind_live_${random_suffix}" \
    --arg run_id "$issued_run_id" \
    --arg lease_id "$issued_lease" \
    --arg binding_id "$binding_id" \
    --arg source_id "$source_id" \
    --arg identity_ref "$workload_identity" \
    --arg evidence_basis_ref "proc_start_${workload_pid}_${workload_start_ticks}" \
    --argjson valid_from_unix_ms "$binding_valid_from_unix_ms" \
    --argjson valid_until_unix_ms "$binding_valid_until_unix_ms" \
    '{
        schema_version: "0.1",
        client_operation_id: $operation_id,
        request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        run_id: $run_id,
        lease_id: $lease_id,
        binding: {
            binding_id: $binding_id,
            asserting_source_id: $source_id,
            identity_kind: "process",
            identity_ref: $identity_ref,
            valid_from_unix_ms: $valid_from_unix_ms,
            valid_until_unix_ms: $valid_until_unix_ms,
            evidence_basis: "heuristic_match",
            evidence_basis_ref: $evidence_basis_ref,
            attribution: "inferred",
            reason_codes: ["pid_start_time_match"],
            confidence_bps: 9000,
            alternative_runtime_candidates: []
        }
    }' >"$bind_unsigned_request"

"$request_bin" bind-runtime \
    --input "$bind_unsigned_request" \
    --output "$bind_signed_request"

bind_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${bind_signed_request}" \
    --dump-header "$bind_headers" \
    --output "$bind_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/bind-runtime")"
if [[ "$bind_status" != "200" ]] || ! jq -e \
    --arg run_id "$issued_run_id" \
    --arg binding_id "$binding_id" \
    '.schema_version == "0.1"
     and .run_id == $run_id
     and .binding_id == $binding_id
     and .accepted == true
     and .idempotent_replay == false' \
    "$bind_response" >/dev/null; then
    printf 'error: authenticated bind_runtime returned HTTP %s\n' "$bind_status" >&2
    jq -c '{schema_version,code,message,retryable,retry_after_ms}' \
        "$bind_response" >&2 || true
    exit 1
fi
assert_no_store "$bind_headers" 'authenticated bind_runtime'

bind_replay_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${bind_signed_request}" \
    --dump-header "$bind_replay_headers" \
    --output "$bind_replay_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/bind-runtime")"
if [[ "$bind_replay_status" != "200" ]] || ! jq -e \
    --arg binding_id "$binding_id" \
    '.binding_id == $binding_id and .idempotent_replay == true' \
    "$bind_replay_response" >/dev/null; then
    printf 'error: bind_runtime exact retry did not return its durable replay\n' >&2
    exit 1
fi
assert_no_store "$bind_replay_headers" 'bind_runtime exact replay'

printf 'Ingesting structure-only evidence from the real local execution...\n'
readonly ingest_unsigned_request="${secret_directory}/ingest.unsigned.json"
readonly ingest_signed_request="${secret_directory}/ingest.json"
readonly ingest_response="${secret_directory}/ingest.response.json"
readonly ingest_replay_response="${secret_directory}/ingest.replay.response.json"
readonly ingest_headers="${secret_directory}/ingest.response.headers"
readonly ingest_replay_headers="${secret_directory}/ingest.replay.response.headers"
readonly source_event_id="event_tool_live_${random_suffix}"
readonly observed_at_unix_ms="$(( $(date +%s) * 1000 ))"

jq -n \
    --arg operation_id "operation_ingest_live_${random_suffix}" \
    --arg run_id "$issued_run_id" \
    --arg lease_id "$issued_lease" \
    --arg source_id "$source_id" \
    --arg source_stream_id "$issued_stream_id" \
    --arg source_event_id "$source_event_id" \
    --arg runtime_ref "$workload_identity" \
    --argjson observed_at_unix_ms "$observed_at_unix_ms" \
    '{
        schema_version: "0.1",
        client_operation_id: $operation_id,
        request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        run_id: $run_id,
        lease_id: $lease_id,
        envelopes: [{
            schema_version: "0.1",
            run_id: $run_id,
            source_id: $source_id,
            source_stream_id: $source_stream_id,
            source_event_id: $source_event_id,
            source_sequence: 1,
            observed_at: {
                unix_ms: $observed_at_unix_ms,
                clock_basis: "wall_clock",
                uncertainty_ms: 25
            },
            correlation: {
                trace_ref: "trace_live_transport",
                agent_ref: "agent_primary",
                tool_ref: "tool_call_01",
                runtime_ref: $runtime_ref
            },
            flags: {
                loss_detected: false,
                redacted: true,
                contains_content: false
            },
            payload_type: "tool_interaction",
            payload_version: "0.1",
            payload_digest: "dcae611e067b1506f6b64620c942a2b9d11811fac310c2c0c94df468d0f02bf2",
            inline_payload: {
                evidence_type: "tool_interaction",
                body: {
                    interaction_ref: "tool_call_01",
                    agent_ref: "agent_primary",
                    tool_ref: "exec_command",
                    capability: "process",
                    event: "completed",
                    request_ref: "request_digest_01",
                    response_ref: null,
                    outcome: "succeeded"
                }
            },
            object_ref: null
        }]
    }' >"$ingest_unsigned_request"

"$request_bin" ingest \
    --input "$ingest_unsigned_request" \
    --output "$ingest_signed_request"

ingest_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${ingest_signed_request}" \
    --dump-header "$ingest_headers" \
    --output "$ingest_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/ingest")"
if [[ "$ingest_status" != "200" ]] || ! jq -e \
    --arg run_id "$issued_run_id" \
    --arg source_event_id "$source_event_id" \
    '.schema_version == "0.1"
     and .run_id == $run_id
     and .committed_count == 1
     and .duplicate_count == 0
     and .durable_ingest_watermark == 5
     and .source_watermark == 1
     and .known_gaps == []
     and (.acknowledgements | length == 1)
     and .acknowledgements[0].source_event_id == $source_event_id
     and .acknowledgements[0].disposition == "committed"
     and .acknowledgements[0].ingest_sequence == 5' \
    "$ingest_response" >/dev/null; then
    printf 'error: authenticated ingest returned HTTP %s\n' "$ingest_status" >&2
    jq -c '{schema_version,code,message,retryable,retry_after_ms}' \
        "$ingest_response" >&2 || true
    exit 1
fi
assert_no_store "$ingest_headers" 'authenticated ingest'

printf 'Restarting the Gateway after ingest to prove durable replay...\n'
stop_gateway
start_gateway

ingest_replay_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${ingest_signed_request}" \
    --dump-header "$ingest_replay_headers" \
    --output "$ingest_replay_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/ingest")"
if [[ "$ingest_replay_status" != "200" ]] || \
    ! cmp -s "$ingest_response" "$ingest_replay_response"; then
    printf 'error: ingest exact retry did not return its durable replay\n' >&2
    exit 1
fi
assert_no_store "$ingest_replay_headers" 'ingest exact replay'

readonly ingest_duplicate_unsigned_request="${secret_directory}/ingest.duplicate.unsigned.json"
readonly ingest_duplicate_signed_request="${secret_directory}/ingest.duplicate.json"
readonly ingest_duplicate_response="${secret_directory}/ingest.duplicate.response.json"
readonly ingest_duplicate_headers="${secret_directory}/ingest.duplicate.response.headers"
jq \
    --arg operation_id "operation_ingest_duplicate_${random_suffix}" \
    '.client_operation_id = $operation_id
     | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"' \
    "$ingest_unsigned_request" >"$ingest_duplicate_unsigned_request"
"$request_bin" ingest \
    --input "$ingest_duplicate_unsigned_request" \
    --output "$ingest_duplicate_signed_request"

ingest_duplicate_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${ingest_duplicate_signed_request}" \
    --dump-header "$ingest_duplicate_headers" \
    --output "$ingest_duplicate_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/ingest")"
if [[ "$ingest_duplicate_status" != "200" ]] || ! jq -e \
    --arg source_event_id "$source_event_id" \
    '.committed_count == 0
     and .duplicate_count == 1
     and .durable_ingest_watermark == 5
     and .source_watermark == 1
     and .known_gaps == []
     and (.acknowledgements | length == 1)
     and .acknowledgements[0].source_event_id == $source_event_id
     and .acknowledgements[0].disposition == "duplicate"
     and .acknowledgements[0].ingest_sequence == 5' \
    "$ingest_duplicate_response" >/dev/null; then
    printf 'error: new ingest operation did not report the existing event as duplicate\n' >&2
    exit 1
fi
assert_no_store "$ingest_duplicate_headers" 'ingest event duplicate'

readonly ingest_conflict_unsigned_request="${secret_directory}/ingest.conflict.unsigned.json"
readonly ingest_conflict_signed_request="${secret_directory}/ingest.conflict.json"
readonly ingest_conflict_response="${secret_directory}/ingest.conflict.response.json"
readonly ingest_conflict_headers="${secret_directory}/ingest.conflict.response.headers"
jq \
    '.request_digest = "0000000000000000000000000000000000000000000000000000000000000000"
     | .envelopes[0].observed_at.uncertainty_ms = 50' \
    "$ingest_unsigned_request" >"$ingest_conflict_unsigned_request"
"$request_bin" ingest \
    --input "$ingest_conflict_unsigned_request" \
    --output "$ingest_conflict_signed_request"

ingest_conflict_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${ingest_conflict_signed_request}" \
    --dump-header "$ingest_conflict_headers" \
    --output "$ingest_conflict_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/ingest")"
if [[ "$ingest_conflict_status" != "409" ]] || ! jq -e \
    '.schema_version == "0.1"
     and .code == "idempotency_conflict"
     and .retryable == false
     and .retry_after_ms == null' \
    "$ingest_conflict_response" >/dev/null; then
    printf 'error: changed ingest content reused an operation identity without conflict\n' >&2
    exit 1
fi
assert_no_store "$ingest_conflict_headers" 'ingest idempotency conflict'

printf 'Finishing the real Agent Run through the mTLS lifecycle seam...\n'
readonly finish_unsigned_request="${secret_directory}/finish-run.unsigned.json"
readonly finish_signed_request="${secret_directory}/finish-run.json"
readonly finish_response="${secret_directory}/finish-run.response.json"
readonly finish_replay_response="${secret_directory}/finish-run.replay.response.json"
readonly finish_headers="${secret_directory}/finish-run.response.headers"
readonly finish_replay_headers="${secret_directory}/finish-run.replay.response.headers"

jq -n \
    --arg operation_id "operation_finish_live_${random_suffix}" \
    --arg run_id "$issued_run_id" \
    --arg lease_id "$issued_lease" \
    --arg source_id "$source_id" \
    --arg source_stream_id "$issued_stream_id" \
    '{
        schema_version: "0.1",
        client_operation_id: $operation_id,
        request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        run_id: $run_id,
        lease_id: $lease_id,
        terminal_positions: [{
            source_id: $source_id,
            source_stream_id: $source_stream_id,
            final_source_sequence: 1
        }],
        outcome_claim_refs: [],
        requested_finalization_deadline_unix_ms: null
    }' >"$finish_unsigned_request"

"$request_bin" finish-run \
    --input "$finish_unsigned_request" \
    --output "$finish_signed_request"
for private_request in \
    "$signed_request" "$bind_signed_request" "$ingest_signed_request" "$finish_signed_request"; do
    if [[ "$(stat -c '%a' "$private_request")" != "600" ]]; then
        printf 'error: signed Gateway request was not created with mode 0600\n' >&2
        exit 1
    fi
done
if "$request_bin" finish-run \
    --input "$finish_unsigned_request" \
    --output "$finish_signed_request" \
    >/dev/null 2>&1; then
    printf 'error: request signer overwrote an existing private output\n' >&2
    exit 1
fi

finish_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${finish_signed_request}" \
    --dump-header "$finish_headers" \
    --output "$finish_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/finish-run")"
if [[ "$finish_status" != "200" ]] || ! jq -e \
    --arg run_id "$issued_run_id" \
    '.schema_version == "0.1"
     and .run_id == $run_id
     and .state == "finished"
     and .finalization_deadline_unix_ms == null
     and .idempotent_replay == false' \
    "$finish_response" >/dev/null; then
    printf 'error: authenticated finish_run returned HTTP %s\n' "$finish_status" >&2
    jq -c '{schema_version,code,message,retryable,retry_after_ms}' \
        "$finish_response" >&2 || true
    exit 1
fi
assert_no_store "$finish_headers" 'authenticated finish_run'

finish_replay_status="$(curl --silent --show-error \
    --connect-timeout 5 \
    --max-time 30 \
    --cacert "$ca_cert" \
    --cert "$client_cert" \
    --key "$client_key" \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data-binary "@${finish_signed_request}" \
    --dump-header "$finish_replay_headers" \
    --output "$finish_replay_response" \
    --write-out '%{http_code}' \
    "${gateway_base_url}/gateway/v0.1/finish-run")"
if [[ "$finish_replay_status" != "200" ]] || ! jq -e \
    --arg run_id "$issued_run_id" \
    '.run_id == $run_id
     and .state == "finished"
     and .finalization_deadline_unix_ms == null
     and .idempotent_replay == true' \
    "$finish_replay_response" >/dev/null; then
    printf 'error: finish_run exact retry did not return its durable replay\n' >&2
    exit 1
fi
assert_no_store "$finish_replay_headers" 'finish_run exact replay'

printf 'Checking durable full-lifecycle PostgreSQL invariants...\n'
database_invariants="$(timeout 30s docker exec -i "$container_name" \
    psql --username "$gateway_runtime_login" --dbname "$database_name" \
        --no-align --tuples-only --set=organization_id="$organization_id" \
        --set=run_id="$issued_run_id" \
        --set=binding_valid_from_unix_ms="$binding_valid_from_unix_ms" \
        --set=binding_valid_until_unix_ms="$binding_valid_until_unix_ms" <<'SQL'
SELECT concat_ws('|',
    (SELECT count(*) FROM apolysis_gateway.runs
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'
        AND state='finished' AND finalization_deadline_unix_ms IS NULL),
    (SELECT count(*) FROM apolysis_gateway.client_runs
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.run_expected_source_kinds
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.source_streams
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.leases
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.lease_operations AS operation
      JOIN apolysis_gateway.leases AS lease
        ON lease.organization_id=operation.organization_id
       AND lease.lease_digest=operation.lease_digest
      WHERE lease.organization_id=:'organization_id' AND lease.run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.runtime_bindings
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'
        AND attribution='inferred'
        AND valid_from_unix_ms=:'binding_valid_from_unix_ms'::bigint
        AND valid_until_unix_ms=:'binding_valid_until_unix_ms'::bigint
        AND accepted_binding_json #>> '{binding,evidence_basis}'='heuristic_match'
        AND accepted_binding_json #>> '{binding,reason_codes,0}'='pid_start_time_match'
        AND accepted_binding_json #>> '{binding,confidence_bps}'='9000'
        AND accepted_binding_json #> '{binding,alternative_runtime_candidates}'='[]'::jsonb),
    (SELECT count(*) FROM apolysis_gateway.active_runtime_identities
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.evidence_events
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'
        AND source_sequence=1 AND ledger_ingest_sequence=5),
    (SELECT count(*) FROM apolysis_gateway.finalization_declarations
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'
        AND resulting_run_state='finished' AND ledger_ingest_sequence=6),
    (SELECT count(*) FROM apolysis_gateway.finalization_terminal_positions
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'
        AND final_source_sequence=1),
    (SELECT count(*) FROM apolysis_gateway.finalization_outcome_claims
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.record_items
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.projection_outbox
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.record_items AS record
      LEFT JOIN apolysis_gateway.projection_outbox AS outbox
        ON outbox.organization_id=record.organization_id
       AND outbox.ingest_sequence=record.ingest_sequence
      WHERE record.organization_id=:'organization_id' AND outbox.ingest_sequence IS NULL),
    (SELECT count(*) FROM apolysis_gateway.projection_outbox AS outbox
      LEFT JOIN apolysis_gateway.record_items AS record
        ON record.organization_id=outbox.organization_id
       AND record.ingest_sequence=outbox.ingest_sequence
      WHERE outbox.organization_id=:'organization_id' AND record.ingest_sequence IS NULL),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.operation_replays AS replay
      JOIN apolysis_gateway.gateway_operations AS operation
        ON operation.organization_id=replay.organization_id
       AND operation.operation_id=replay.operation_id
      WHERE operation.organization_id=:'organization_id' AND operation.run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.organization_sequences
      WHERE organization_id=:'organization_id' AND next_ingest_sequence=9),
    (SELECT count(*) FROM (
        SELECT min(ingest_sequence)=1
               AND max(ingest_sequence)=8
               AND count(*)=8
               AND bool_and(outbox_ingest_sequence=ingest_sequence) AS valid
          FROM apolysis_gateway.record_items
         WHERE organization_id=:'organization_id' AND run_id=:'run_id'
    ) AS ledger WHERE valid),
    (SELECT count(*) FROM (
        SELECT array_agg(fact_kind ORDER BY ingest_sequence) AS facts
          FROM apolysis_gateway.record_items
         WHERE organization_id=:'organization_id' AND run_id=:'run_id'
    ) AS ordered
     WHERE facts=ARRAY[
        'run_opened', 'run_state_changed', 'source_registered', 'runtime_bound',
        'evidence_accepted', 'run_finalization_declared', 'run_state_changed',
        'run_state_changed'
     ]::text[]),
    (SELECT count(*) FROM apolysis_gateway.runtime_bindings AS binding
      JOIN apolysis_gateway.evidence_events AS event
        ON event.organization_id=binding.organization_id
       AND event.run_id=binding.run_id
       AND event.source_registration_id=binding.source_registration_id
       AND event.source_stream_id=binding.source_stream_id
      WHERE binding.organization_id=:'organization_id' AND binding.run_id=:'run_id'
        AND binding.identity_ref=
            event.accepted_envelope_json #>> '{envelope,correlation,runtime_ref}')
);
SQL
)"
readonly expected_database_invariants='1|1|1|1|1|3|1|0|1|1|1|0|8|8|0|0|5|5|1|1|1|1'
if [[ "$database_invariants" != "$expected_database_invariants" ]]; then
    printf 'error: durable lifecycle invariants did not match the reviewed vector: %s\n' \
        "$database_invariants" >&2
    exit 1
fi

printf 'Checking cross-organization lifecycle isolation with an independent certificate...\n'
for attack_route in open-run bind-runtime ingest finish-run; do
    case "$attack_route" in
        open-run)
            attack_request="$signed_request"
            expected_attack_status=403
            expected_attack_code=forbidden
            ;;
        bind-runtime)
            attack_request="$bind_signed_request"
            expected_attack_status=403
            expected_attack_code=forbidden
            ;;
        ingest)
            attack_request="$ingest_signed_request"
            expected_attack_status=403
            expected_attack_code=forbidden
            ;;
        finish-run)
            attack_request="$finish_signed_request"
            expected_attack_status=404
            expected_attack_code=not_found
            ;;
        *) exit 1 ;;
    esac
    attack_response="${secret_directory}/${attack_route}.cross-org.json"
    attack_headers="${secret_directory}/${attack_route}.cross-org.headers"
    attack_status="$(curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 30 \
        --cacert "$ca_cert" \
        --cert "$unknown_client_cert" \
        --key "$unknown_client_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-binary "@${attack_request}" \
        --dump-header "$attack_headers" \
        --output "$attack_response" \
        --write-out '%{http_code}' \
        "${gateway_base_url}/gateway/v0.1/${attack_route}")"
    if [[ "$attack_status" != "$expected_attack_status" ]] || ! jq -e \
        --arg code "$expected_attack_code" \
        '.schema_version == "0.1"
         and .code == $code
         and .retryable == false
         and .retry_after_ms == null' \
        "$attack_response" >/dev/null; then
        printf 'error: cross-organization %s request did not fail closed\n' \
            "$attack_route" >&2
        exit 1
    fi
    assert_no_store "$attack_headers" "cross-organization ${attack_route}"
    if grep -Fq -- "$issued_run_id" "$attack_response" || \
        grep -Fq -- "$issued_stream_id" "$attack_response" || \
        grep -Fq -- "$issued_lease" "$attack_response"; then
        printf 'error: cross-organization %s response disclosed victim scope\n' \
            "$attack_route" >&2
        exit 1
    fi
done

post_isolation_state="$(timeout 15s docker exec -i "$container_name" \
    psql --username "$gateway_runtime_login" --dbname "$database_name" \
        --no-align --tuples-only --set=organization_id="$organization_id" \
        --set=run_id="$issued_run_id" \
        --set=attacker_organization_id="$attacker_organization_id" <<'SQL'
SELECT concat_ws('|',
    (SELECT next_ingest_sequence FROM apolysis_gateway.organization_sequences
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.record_items
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.runs
      WHERE organization_id=:'attacker_organization_id'),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations
      WHERE organization_id=:'attacker_organization_id'),
    (SELECT count(*) FROM apolysis_gateway.record_items
      WHERE organization_id=:'attacker_organization_id')
);
SQL
)"
if [[ "$post_isolation_state" != '9|5|8|0|0|0' ]]; then
    printf 'error: cross-organization requests changed durable state\n' >&2
    exit 1
fi

readonly database_dump="${secret_directory}/database.dump.sql"
readonly replay_key_value="$(<"$replay_key_file")"
if ! timeout 30s docker exec "$container_name" \
    pg_dump --username "$database_user" --dbname "$database_name" \
        --no-owner --no-privileges >"$database_dump"; then
    printf 'error: failed to inspect PostgreSQL secret persistence\n' >&2
    exit 1
fi
if grep -Fq -- "$issued_lease" "$database_dump" || \
    grep -Fq -- "$database_password" "$database_dump" || \
    grep -Fq -- "$schema_owner_password" "$database_dump" || \
    grep -Fq -- "$gateway_control_password" "$database_dump" || \
    grep -Fq -- "$gateway_runtime_password" "$database_dump" || \
    grep -Fq -- "$replay_key_value" "$database_dump" || \
    grep -Fq -- 'BEGIN PRIVATE KEY' "$database_dump"; then
    printf 'error: generated secret material was persisted in PostgreSQL\n' >&2
    exit 1
fi
rm -f -- "$database_dump"

printf 'Revoking the current transport credential in PostgreSQL...\n'
"$authority_bin" revoke-credential \
        --database-url-file "$gateway_control_database_url_file" \
        --client-certificate "$client_cert" \
        --reason "live_transport_gate_${random_suffix}"

readonly revoked_registration="${secret_directory}/source-registration.revoked.json"
jq '.policy_revision = 3 | .credential_epoch = 3' \
    "$policy_file" >"$revoked_registration"
if "$authority_bin" register-source \
    --database-url-file "$gateway_control_database_url_file" \
    --registration "$revoked_registration" \
    --client-certificate "$client_cert" \
    >/dev/null 2>&1; then
    printf 'error: a revoked client certificate was registered again\n' >&2
    exit 1
fi

for revoked_route in open-run bind-runtime ingest finish-run; do
    case "$revoked_route" in
        open-run) revoked_request="$signed_request" ;;
        bind-runtime) revoked_request="$bind_signed_request" ;;
        ingest) revoked_request="$ingest_signed_request" ;;
        finish-run) revoked_request="$finish_signed_request" ;;
        *) exit 1 ;;
    esac
    revoked_response="${secret_directory}/${revoked_route}.revoked.json"
    revoked_headers="${secret_directory}/${revoked_route}.revoked.headers"
    revoked_status="$(curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 30 \
        --cacert "$ca_cert" \
        --cert "$client_cert" \
        --key "$client_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --header 'X-Organization-Id: attacker_controlled' \
        --data-binary "@${revoked_request}" \
        --dump-header "$revoked_headers" \
        --output "$revoked_response" \
        --write-out '%{http_code}' \
        "${gateway_base_url}/gateway/v0.1/${revoked_route}")"

    if [[ "$revoked_status" != "401" ]]; then
        printf 'error: revoked credential reached %s with HTTP %s instead of 401\n' \
            "$revoked_route" "$revoked_status" >&2
        exit 1
    fi
    assert_no_store "$revoked_headers" "revoked credential on ${revoked_route}"
    if ! jq -e \
        '.schema_version == "0.1"
         and .code == "unauthenticated"
         and .retryable == false
         and .retry_after_ms == null' \
        "$revoked_response" >/dev/null; then
        printf 'error: revoked credential response on %s was not content-free\n' \
            "$revoked_route" >&2
        exit 1
    fi
done

post_revocation_state="$(timeout 15s docker exec -i "$container_name" \
    psql --username "$gateway_runtime_login" --dbname "$database_name" \
        --no-align --tuples-only --set=organization_id="$organization_id" \
        --set=run_id="$issued_run_id" <<'SQL'
SELECT concat_ws('|',
    (SELECT next_ingest_sequence FROM apolysis_gateway.organization_sequences
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations
      WHERE organization_id=:'organization_id' AND run_id=:'run_id'),
    (SELECT count(*) FROM apolysis_gateway.record_items
      WHERE organization_id=:'organization_id' AND run_id=:'run_id')
);
SQL
)"
if [[ "$post_revocation_state" != '9|5|8' ]]; then
    printf 'error: rejected credential changed durable lifecycle state\n' >&2
    exit 1
fi

printf 'Checking that bearer and database secrets were absent from Gateway logs...\n'
if grep -Fq -- "$issued_lease" "$server_log"; then
    printf 'error: plaintext run lease was written to the Gateway log\n' >&2
    exit 1
fi
if grep -Fq -- "$database_password" "$server_log" || \
    grep -Fq -- "$schema_owner_password" "$server_log" || \
    grep -Fq -- "$gateway_control_password" "$server_log" || \
    grep -Fq -- "$gateway_runtime_password" "$server_log"; then
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

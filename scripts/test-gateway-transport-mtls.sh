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
crash_recovery_enabled="${APOLYSIS_GATEWAY_HTTPS_CRASH_RECOVERY:-0}"
multiprocess_races_enabled="${APOLYSIS_GATEWAY_MULTIPROCESS_LIFECYCLE_RACES:-0}"

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
    # The grace interval must cover the bounded EXIT cleanup path: Gateway and
    # client termination, container removal/verification, and private files.
    exec timeout --foreground --kill-after=90s "${gate_timeout_seconds}s" "$0" "$@"
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

for command in awk cargo cmp curl date docker grep head jq mktemp mv od openssl sha256sum stat tail timeout tr; do
    require_command "$command"
done

# Every HTTP target in this gate is a loopback listener. Ignore ambient proxy
# configuration so a CONNECT intermediary can neither observe nor satisfy the
# mTLS qualification seam.
curl() {
    command curl --noproxy '*' "$@"
}

require_positive_integer APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS "$pull_timeout_seconds"
require_positive_integer APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS "$start_timeout_seconds"
require_positive_integer APOLYSIS_GATEWAY_TRANSPORT_TEST_TIMEOUT_SECONDS "$gate_timeout_seconds"
if [[ "$crash_recovery_enabled" != "0" && "$crash_recovery_enabled" != "1" ]]; then
    printf 'error: APOLYSIS_GATEWAY_HTTPS_CRASH_RECOVERY must be 0 or 1\n' >&2
    exit 1
fi
if [[ "$multiprocess_races_enabled" != "0" && "$multiprocess_races_enabled" != "1" ]]; then
    printf 'error: APOLYSIS_GATEWAY_MULTIPROCESS_LIFECYCLE_RACES must be 0 or 1\n' >&2
    exit 1
fi

if ! timeout 10s docker info >/dev/null 2>&1; then
    printf 'error: Docker daemon is unavailable or inaccessible\n' >&2
    exit 1
fi

printf 'Building the production Gateway transport binaries...\n'
timeout --foreground --kill-after=15s "${gate_timeout_seconds}s" \
    cargo build -p apolysis-gateway-server --bins

if [[ "$crash_recovery_enabled" == "1" || "$multiprocess_races_enabled" == "1" ]]; then
    timeout --foreground --kill-after=15s "${gate_timeout_seconds}s" \
        cargo build -p apolysis-gateway-server \
            --features qualification \
            --bin apolysis-gateway-qualification-server \
            --bin apolysis-gateway-qualification-join-grant
fi

readonly gateway_bin="target/debug/apolysis-gateway-server"
readonly authority_bin="target/debug/apolysis-gateway-authority"
readonly request_bin="target/debug/apolysis-gateway-request"
readonly qualification_gateway_bin="target/debug/apolysis-gateway-qualification-server"
readonly qualification_join_grant_bin="target/debug/apolysis-gateway-qualification-join-grant"

for binary in "$gateway_bin" "$authority_bin" "$request_bin"; do
    if [[ ! -x "$binary" ]]; then
        printf 'error: expected executable was not built: %s\n' "$binary" >&2
        exit 1
    fi
done
if [[ ("$crash_recovery_enabled" == "1" || "$multiprocess_races_enabled" == "1") && \
    (! -x "$qualification_gateway_bin" || ! -x "$qualification_join_grant_bin") ]]; then
    printf 'error: expected qualification executables were not built\n' >&2
    exit 1
fi

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
crash_client_pid=""
qualification_private_artifacts=()
race_gateway_pids=()
race_client_pids=()
race_gateway_urls=()
race_blocker_pid=""
race_blocker_application_name=""
race_overlap_watcher_pid=""
race_overlap_watcher_application_name=""
race_overlap_watcher_log=""
race_secret_values=()
race_forbidden_response_values=()
race_lease_files=()
race_private_artifacts=()
race_accepted_operation_ids=()
race_rejected_operation_ids=()
declare -A race_expected_lease_file_by_response=()

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

stop_owned_process() {
    local process_pid="$1"
    if [[ -n "$process_pid" ]] && kill -0 "$process_pid" >/dev/null 2>&1; then
        kill -TERM "$process_pid" >/dev/null 2>&1 || true
        timeout 5s tail --pid="$process_pid" -f /dev/null >/dev/null 2>&1 || \
            kill -KILL "$process_pid" >/dev/null 2>&1 || true
    fi
    if [[ -n "$process_pid" ]]; then
        wait "$process_pid" 2>/dev/null || true
    fi
}

stop_race_database_blocker() {
    stop_owned_process "$race_overlap_watcher_pid"
    race_overlap_watcher_pid=""
    race_overlap_watcher_application_name=""
    race_overlap_watcher_log=""
    if [[ -n "$race_blocker_application_name" ]] && \
        timeout 5s docker container inspect "$container_name" >/dev/null 2>&1; then
        timeout 5s docker exec -i "$container_name" \
            psql --username "$database_user" --dbname "$database_name" \
                --no-align --tuples-only \
                --set=application_name="$race_blocker_application_name" <<'SQL' \
                >/dev/null 2>&1 || true
WITH blocker AS MATERIALIZED (
    SELECT pid FROM pg_catalog.pg_stat_activity
     WHERE application_name=:'application_name'
       AND pid <> pg_backend_pid()
)
SELECT pg_terminate_backend(pid) FROM blocker;
SQL
    fi
    stop_owned_process "$race_blocker_pid"
    race_blocker_pid=""
    race_blocker_application_name=""
}

stop_race_processes() {
    local process_pid=""
    stop_race_database_blocker
    for process_pid in "${race_client_pids[@]}" "${race_gateway_pids[@]}"; do
        stop_owned_process "$process_pid"
    done
    race_client_pids=()
    race_gateway_pids=()
    race_gateway_urls=()
}

record_accepted_race_operation() {
    race_accepted_operation_ids+=("$(jq -er '.client_operation_id' "$1")")
}

record_rejected_race_operation() {
    race_rejected_operation_ids+=("$(jq -er '.client_operation_id' "$1")")
}

write_private_race_secret() {
    local value="$1"
    local path="$2"
    printf '%s' "$value" >"$path"
    chmod 600 "$path"
}

start_gateway_process() {
    local gateway_executable="$1"
    shift
    rm -f -- "$ready_file"
    "$gateway_executable" \
            "$@" \
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

start_gateway() {
    start_gateway_process "$gateway_bin"
}

start_qualification_gateway() {
    local operation="$1"
    local marker="$2"
    rm -f -- "$marker"
    start_gateway_process "$qualification_gateway_bin" \
        --qualification-operation "$operation" \
        --qualification-marker "$marker"
}

wait_for_gateway_sessions_to_close() {
    local deadline=$((SECONDS + 15))
    local session_count=""
    while true; do
        session_count="$(timeout 10s docker exec -i "$container_name" \
            psql --username "$database_user" --dbname "$database_name" \
                --no-align --tuples-only \
                --set=runtime_login="$gateway_runtime_login" <<'SQL' | tr -d '[:space:]'
SELECT count(*) FROM pg_catalog.pg_stat_activity
WHERE usename=:'runtime_login';
SQL
)"
        if [[ "$session_count" == "0" ]]; then
            return
        fi
        if ((SECONDS >= deadline)); then
            printf 'error: killed Gateway runtime sessions did not close\n' >&2
            exit 1
        fi
        sleep 0.1
    done
}

qualify_post_commit_crash() {
    local operation="$1"
    local route="$2"
    local request_file="$3"
    local artifact_prefix="$4"
    local operation_id=""
    operation_id="$(jq -er '.client_operation_id' "$request_file")"
    local expected_replay_fingerprint=""

    printf 'Qualifying HTTPS post-commit/pre-ack recovery for %s...\n' "$operation"
    local attempt=""
    for attempt in committed replay; do
        local marker="${secret_directory}/${artifact_prefix}.${attempt}.post-commit"
        local response="${secret_directory}/${artifact_prefix}.${attempt}.response"
        local headers="${secret_directory}/${artifact_prefix}.${attempt}.headers"
        local http_status="${secret_directory}/${artifact_prefix}.${attempt}.http-status"
        local curl_status="${secret_directory}/${artifact_prefix}.${attempt}.curl-status"
        local curl_stderr="${secret_directory}/${artifact_prefix}.${attempt}.curl-stderr"
        # curl may not create its body output when the connection dies before
        # the first response byte, so establish the private empty artifact now.
        : >"$response"
        qualification_private_artifacts+=(
            "$marker" "$response" "$headers" "$http_status" "$curl_status" "$curl_stderr"
        )

        stop_gateway
        start_qualification_gateway "$operation" "$marker"
        # Launch the real curl process directly so kill -0 below proves the
        # network client itself—not a wrapper subshell—is still blocked.
        command curl --noproxy '*' --silent --show-error --http1.1 \
            --connect-timeout 5 \
            --max-time 45 \
            --cacert "$ca_cert" \
            --cert "$client_cert" \
            --key "$client_key" \
            --header 'Accept: application/json' \
            --header 'Content-Type: application/json' \
            --data-binary "@${request_file}" \
            --dump-header "$headers" \
            --output "$response" \
            --write-out '%{http_code}\n' \
            "${gateway_base_url}/gateway/v0.1/${route}" \
            >"$http_status" 2>"$curl_stderr" &
        crash_client_pid=$!

        local marker_deadline=$((SECONDS + 30))
        while [[ ! -s "$marker" ]]; do
            if ! kill -0 "$gateway_pid" >/dev/null 2>&1; then
                printf 'error: qualification Gateway exited before the %s marker\n' \
                    "$operation" >&2
                exit 1
            fi
            if ! kill -0 "$crash_client_pid" >/dev/null 2>&1; then
                printf 'error: %s client received a response before the post-commit marker\n' \
                    "$operation" >&2
                exit 1
            fi
            if ((SECONDS >= marker_deadline)); then
                printf 'error: timed out waiting for the %s post-commit marker\n' \
                    "$operation" >&2
                exit 1
            fi
            sleep 0.1
        done

        if [[ "$(<"$marker")" != "committed" ]] || \
            [[ "$(stat -c '%a' "$marker")" != "600" ]]; then
            printf 'error: %s qualification marker violated its static private contract\n' \
                "$operation" >&2
            exit 1
        fi
        if ! kill -0 "$crash_client_pid" >/dev/null 2>&1; then
            printf 'error: %s HTTP client exited before process death\n' \
                "$operation" >&2
            exit 1
        fi
        if [[ -s "$headers" || -s "$response" || -s "$http_status" ]]; then
            printf 'error: %s HTTP acknowledgement escaped before process death (headers=%s body=%s status=%s)\n' \
                "$operation" \
                "$(stat -c '%s' "$headers" 2>/dev/null || printf '0')" \
                "$(stat -c '%s' "$response" 2>/dev/null || printf '0')" \
                "$(stat -c '%s' "$http_status" 2>/dev/null || printf '0')" >&2
            exit 1
        fi

        local durable_operation_counts=""
        durable_operation_counts="$(timeout 15s docker exec -i "$container_name" \
            psql --username "$gateway_runtime_login" --dbname "$database_name" \
                --no-align --tuples-only \
                --set=organization_id="$organization_id" \
                --set=operation_id="$operation_id" <<'SQL' | tr -d '[:space:]'
SELECT concat_ws('|',
    (SELECT count(*) FROM apolysis_gateway.gateway_operations
      WHERE organization_id=:'organization_id' AND client_operation_id=:'operation_id'),
    (SELECT count(*) FROM apolysis_gateway.operation_replays AS replay
      JOIN apolysis_gateway.gateway_operations AS operation
        ON operation.organization_id=replay.organization_id
       AND operation.operation_id=replay.operation_id
      WHERE operation.organization_id=:'organization_id'
        AND operation.client_operation_id=:'operation_id'),
    (SELECT md5(concat_ws('|',
        replay.encryption_algorithm,
        replay.cipher_version::text,
        replay.encryption_key_ref,
        coalesce(encode(replay.wrapped_data_key, 'hex'), ''),
        encode(replay.nonce, 'hex'),
        encode(replay.authentication_tag, 'hex'),
        replay.aad_digest,
        encode(replay.outcome_ciphertext, 'hex'),
        replay.created_at_unix_ms::text,
        replay.expires_at_unix_ms::text
    )) FROM apolysis_gateway.operation_replays AS replay
      JOIN apolysis_gateway.gateway_operations AS operation
        ON operation.organization_id=replay.organization_id
       AND operation.operation_id=replay.operation_id
      WHERE operation.organization_id=:'organization_id'
        AND operation.client_operation_id=:'operation_id')
);
SQL
)"
        local current_replay_fingerprint=""
        if [[ "$durable_operation_counts" =~ ^1\|1\|([0-9a-f]{32})$ ]]; then
            current_replay_fingerprint="${BASH_REMATCH[1]}"
        else
            printf 'error: %s marker preceded its unique durable operation/replay\n' \
                "$operation" >&2
            exit 1
        fi
        if [[ -z "$expected_replay_fingerprint" ]]; then
            expected_replay_fingerprint="$current_replay_fingerprint"
        elif [[ "$current_replay_fingerprint" != "$expected_replay_fingerprint" ]]; then
            printf 'error: %s replay rewrote its encrypted durable result\n' \
                "$operation" >&2
            exit 1
        fi

        kill -KILL "$gateway_pid"
        if wait "$gateway_pid" >/dev/null 2>&1; then
            printf 'error: killed %s Gateway exited successfully\n' "$operation" >&2
            exit 1
        fi
        gateway_pid=""
        local observed_curl_status=""
        if wait "$crash_client_pid" >/dev/null 2>&1; then
            observed_curl_status=0
        else
            observed_curl_status=$?
        fi
        printf '%s\n' "$observed_curl_status" >"$curl_status"
        crash_client_pid=""

        if [[ "$observed_curl_status" == "0" ]] || \
            [[ "$(<"$http_status")" != "000" ]] || \
            [[ -s "$headers" || -s "$response" ]]; then
            printf 'error: killed %s Gateway still acknowledged its response\n' \
                "$operation" >&2
            exit 1
        fi
        wait_for_gateway_sessions_to_close
    done

    start_gateway
}

start_pre_operation_race_gateways() {
    local operation="$1"
    local artifact_prefix="$2"
    local release_file="$3"

    stop_gateway
    stop_race_processes
    rm -f -- "$release_file" "${release_file}.tmp"

    local side=""
    for side in left right; do
        local marker="${secret_directory}/${artifact_prefix}.${side}.ready"
        local instance_ready="${secret_directory}/${artifact_prefix}.${side}.listener"
        local instance_log="${secret_directory}/${artifact_prefix}.${side}.log"
        rm -f -- "$marker" "$instance_ready" "$instance_log"
        qualification_private_artifacts+=("$marker" "$instance_ready" "$instance_log")

        "$qualification_gateway_bin" \
            --qualification-operation "$operation" \
            --qualification-marker "$marker" \
            --qualification-phase pre_operation \
            --qualification-release "$release_file" \
            --listen 127.0.0.1:0 \
            --database-url-file "$database_url_file" \
            --tls-certificate "$server_cert" \
            --tls-private-key "$server_key" \
            --client-ca "$ca_cert" \
            --replay-key "$replay_key_file" \
            --ready-file "$instance_ready" \
            >>"$instance_log" 2>&1 &
        race_gateway_pids+=("$!")

        local gateway_deadline=$((SECONDS + start_timeout_seconds))
        while [[ ! -s "$instance_ready" ]]; do
            if ! kill -0 "${race_gateway_pids[-1]}" >/dev/null 2>&1; then
                printf 'error: %s race Gateway exited before becoming ready\n' "$side" >&2
                exit 1
            fi
            if ((SECONDS >= gateway_deadline)); then
                printf 'error: %s race Gateway did not become ready within %s seconds\n' \
                    "$side" "$start_timeout_seconds" >&2
                exit 1
            fi
            sleep 0.1
        done
        local instance_url=""
        instance_url="$(<"$instance_ready")"
        if [[ ! "$instance_url" =~ ^https://127\.0\.0\.1:[0-9]+$ ]] || \
            [[ "$(stat -c '%a' "$instance_ready")" != "600" ]]; then
            printf 'error: %s race Gateway ready file violated its private loopback contract\n' \
                "$side" >&2
            exit 1
        fi
        race_gateway_urls+=("$instance_url")
    done
}

start_race_database_blocker() {
    local artifact_prefix="$1"
    local blocker_log="${secret_directory}/${artifact_prefix}.database-blocker.log"
    race_blocker_application_name="apolysis-race-blocker-${random_suffix}"
    qualification_private_artifacts+=("$blocker_log")

    timeout --foreground --kill-after=5s 120s \
        docker exec --env "PGAPPNAME=${race_blocker_application_name}" \
            -i "$container_name" \
            psql --username "$database_user" --dbname "$database_name" \
                --set=ON_ERROR_STOP=1 >"$blocker_log" 2>&1 <<'SQL' &
BEGIN;
LOCK TABLE apolysis_gateway.gateway_operations IN ACCESS EXCLUSIVE MODE;
SELECT pg_sleep(110);
ROLLBACK;
SQL
    race_blocker_pid=$!

    local blocker_deadline=$((SECONDS + 10))
    local blocker_ready=""
    while [[ "$blocker_ready" != "1" ]]; do
        if ! kill -0 "$race_blocker_pid" >/dev/null 2>&1; then
            printf 'error: %s database blocker exited before acquiring its lock\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
        blocker_ready="$(timeout 5s docker exec -i "$container_name" \
            psql --username "$database_user" --dbname "$database_name" \
                --no-align --tuples-only \
                --set=application_name="$race_blocker_application_name" <<'SQL' | tr -d '[:space:]'
SELECT count(*) FROM pg_catalog.pg_stat_activity
 WHERE application_name=:'application_name'
   AND state='active'
   AND wait_event='PgSleep';
SQL
)"
        if ((SECONDS >= blocker_deadline)); then
            printf 'error: %s database blocker did not acquire the operation-table lock\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
    done
}

start_race_overlap_watcher() {
    local artifact_prefix="$1"
    race_overlap_watcher_application_name="apolysis-race-watcher-${random_suffix}"
    race_overlap_watcher_log="${secret_directory}/${artifact_prefix}.database-watcher.log"
    qualification_private_artifacts+=("$race_overlap_watcher_log")

    timeout --foreground --kill-after=5s 45s \
        docker exec --env "PGAPPNAME=${race_overlap_watcher_application_name}" \
            -i "$container_name" \
            psql --username "$database_user" --dbname "$database_name" \
                --no-align --tuples-only --set=ON_ERROR_STOP=1 \
                --set=runtime_login="$gateway_runtime_login" \
                --set=blocker_application_name="$race_blocker_application_name" \
                >"$race_overlap_watcher_log" 2>&1 <<'SQL' &
SELECT set_config('apolysis.runtime_login', :'runtime_login', false);
SELECT set_config(
    'apolysis.blocker_application_name',
    :'blocker_application_name',
    false
);
DO $watcher$
DECLARE
    deadline timestamptz := clock_timestamp() + interval '30 seconds';
    waiter_count bigint;
    blocker_pid integer;
BEGIN
    LOOP
        PERFORM pg_stat_clear_snapshot();
        SELECT count(*) INTO waiter_count
          FROM pg_catalog.pg_stat_activity
         WHERE usename=current_setting('apolysis.runtime_login')
           AND state='active'
           AND wait_event_type='Lock';
        IF waiter_count >= 2 THEN
            SELECT pid INTO blocker_pid
              FROM pg_catalog.pg_stat_activity
             WHERE application_name=current_setting(
                       'apolysis.blocker_application_name'
                   )
               AND pid <> pg_backend_pid();
            IF blocker_pid IS NULL THEN
                RAISE EXCEPTION 'race blocker disappeared before overlap release';
            END IF;
            IF NOT pg_terminate_backend(blocker_pid) THEN
                RAISE EXCEPTION 'race blocker could not be terminated';
            END IF;
            RETURN;
        END IF;
        IF clock_timestamp() >= deadline THEN
            RAISE EXCEPTION 'two Gateway transactions did not overlap';
        END IF;
        PERFORM pg_sleep(0.01);
    END LOOP;
END
$watcher$;
SELECT 'overlap-observed';
SQL
    race_overlap_watcher_pid=$!

    local watcher_deadline=$((SECONDS + 10))
    local watcher_ready=""
    while [[ "$watcher_ready" != "1" ]]; do
        if ! kill -0 "$race_overlap_watcher_pid" >/dev/null 2>&1; then
            printf 'error: %s database overlap watcher exited before release\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
        watcher_ready="$(timeout 5s docker exec -i "$container_name" \
            psql --username "$database_user" --dbname "$database_name" \
                --no-align --tuples-only \
                --set=application_name="$race_overlap_watcher_application_name" <<'SQL' | tr -d '[:space:]'
SELECT count(*) FROM pg_catalog.pg_stat_activity
 WHERE application_name=:'application_name'
   AND state='active'
   AND wait_event='PgSleep';
SQL
)"
        if ((SECONDS >= watcher_deadline)); then
            printf 'error: %s database overlap watcher did not become ready\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
    done
}

wait_for_race_transaction_overlap() {
    local artifact_prefix="$1"
    local watcher_status=""
    if wait "$race_overlap_watcher_pid"; then
        watcher_status=0
    else
        watcher_status=$?
    fi
    race_overlap_watcher_pid=""
    race_overlap_watcher_application_name=""
    if [[ "$watcher_status" != "0" ]] || \
        ! grep -Fxq 'overlap-observed' "$race_overlap_watcher_log"; then
        printf 'error: %s did not place two Gateway transactions in concurrent lock waits\n' \
            "$artifact_prefix" >&2
        exit 1
    fi
    race_overlap_watcher_log=""

    local blocker_status=""
    if wait "$race_blocker_pid" >/dev/null 2>&1; then
        blocker_status=0
    else
        blocker_status=$?
    fi
    if [[ "$blocker_status" == "0" ]]; then
        printf 'error: %s database blocker completed without controlled termination\n' \
            "$artifact_prefix" >&2
        exit 1
    fi
    race_blocker_pid=""
    race_blocker_application_name=""
}

run_pre_operation_race() {
    local operation="$1"
    local route="$2"
    local target_organization_id="$3"
    local left_request="$4"
    local left_certificate="$5"
    local left_key="$6"
    local right_request="$7"
    local right_certificate="$8"
    local right_key="$9"
    local artifact_prefix="${10}"
    local release_file="${secret_directory}/${artifact_prefix}.release"

    printf 'Qualifying two-process pre-operation race for %s...\n' "$artifact_prefix"
    start_pre_operation_race_gateways "$operation" "$artifact_prefix" "$release_file"

    race_left_response="${secret_directory}/${artifact_prefix}.left.response.json"
    race_right_response="${secret_directory}/${artifact_prefix}.right.response.json"
    race_left_headers="${secret_directory}/${artifact_prefix}.left.headers"
    race_right_headers="${secret_directory}/${artifact_prefix}.right.headers"
    race_left_status_file="${secret_directory}/${artifact_prefix}.left.http-status"
    race_right_status_file="${secret_directory}/${artifact_prefix}.right.http-status"
    local left_stderr="${secret_directory}/${artifact_prefix}.left.curl-stderr"
    local right_stderr="${secret_directory}/${artifact_prefix}.right.curl-stderr"
    local artifact=""
    for artifact in "$race_left_response" "$race_right_response"; do
        : >"$artifact"
        race_private_artifacts+=("$artifact")
    done
    for artifact in \
        "$race_left_headers" "$race_right_headers" \
        "$race_left_status_file" "$race_right_status_file" \
        "$left_stderr" "$right_stderr"; do
        : >"$artifact"
        qualification_private_artifacts+=("$artifact")
    done

    command curl --noproxy '*' --silent --show-error --http1.1 \
        --connect-timeout 5 \
        --max-time 105 \
        --cacert "$ca_cert" \
        --cert "$left_certificate" \
        --key "$left_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-binary "@${left_request}" \
        --dump-header "$race_left_headers" \
        --output "$race_left_response" \
        --write-out '%{http_code}\n' \
        "${race_gateway_urls[0]}/gateway/v0.1/${route}" \
        >"$race_left_status_file" 2>"$left_stderr" &
    race_client_pids+=("$!")
    command curl --noproxy '*' --silent --show-error --http1.1 \
        --connect-timeout 5 \
        --max-time 105 \
        --cacert "$ca_cert" \
        --cert "$right_certificate" \
        --key "$right_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-binary "@${right_request}" \
        --dump-header "$race_right_headers" \
        --output "$race_right_response" \
        --write-out '%{http_code}\n' \
        "${race_gateway_urls[1]}/gateway/v0.1/${route}" \
        >"$race_right_status_file" 2>"$right_stderr" &
    race_client_pids+=("$!")

    local left_marker="${secret_directory}/${artifact_prefix}.left.ready"
    local right_marker="${secret_directory}/${artifact_prefix}.right.ready"
    local marker_deadline=$((SECONDS + 30))
    while [[ ! -s "$left_marker" || ! -s "$right_marker" ]]; do
        local process_pid=""
        for process_pid in "${race_gateway_pids[@]}" "${race_client_pids[@]}"; do
            if ! kill -0 "$process_pid" >/dev/null 2>&1; then
                printf 'error: %s race participant exited before both markers\n' \
                    "$artifact_prefix" >&2
                exit 1
            fi
        done
        if ((SECONDS >= marker_deadline)); then
            printf 'error: timed out waiting for both %s pre-operation markers\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
        sleep 0.1
    done

    if [[ "$(<"$left_marker")" != "ready" || "$(<"$right_marker")" != "ready" ]] || \
        [[ "$(stat -c '%a' "$left_marker")" != "600" ]] || \
        [[ "$(stat -c '%a' "$right_marker")" != "600" ]] || \
        [[ -s "$race_left_headers" || -s "$race_right_headers" || \
            -s "$race_left_response" || -s "$race_right_response" || \
            -s "$race_left_status_file" || -s "$race_right_status_file" ]]; then
        printf 'error: %s requests escaped the private pre-operation barrier\n' \
            "$artifact_prefix" >&2
        exit 1
    fi

    local left_operation_id=""
    local right_operation_id=""
    left_operation_id="$(jq -er '.client_operation_id' "$left_request")"
    right_operation_id="$(jq -er '.client_operation_id' "$right_request")"
    local premature_operation_count=""
    premature_operation_count="$(timeout 15s docker exec -i "$container_name" \
        psql --username "$gateway_runtime_login" --dbname "$database_name" \
            --no-align --tuples-only \
            --set=organization_id="$target_organization_id" \
            --set=left_operation_id="$left_operation_id" \
            --set=right_operation_id="$right_operation_id" <<'SQL' | tr -d '[:space:]'
SELECT count(*) FROM apolysis_gateway.gateway_operations
 WHERE organization_id=:'organization_id'
   AND client_operation_id IN (:'left_operation_id', :'right_operation_id');
SQL
)"
    if [[ "$premature_operation_count" != "0" ]]; then
        printf 'error: %s reached durable state before release\n' "$artifact_prefix" >&2
        exit 1
    fi

    start_race_database_blocker "$artifact_prefix"
    local process_pid=""
    for process_pid in "${race_gateway_pids[@]}" "${race_client_pids[@]}"; do
        if ! kill -0 "$process_pid" >/dev/null 2>&1; then
            printf 'error: %s race participant exited before coordinated release\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
    done
    if [[ -s "$race_left_headers" || -s "$race_right_headers" || \
        -s "$race_left_response" || -s "$race_right_response" || \
        -s "$race_left_status_file" || -s "$race_right_status_file" ]]; then
        printf 'error: %s response escaped while the database blocker was armed\n' \
            "$artifact_prefix" >&2
        exit 1
    fi

    start_race_overlap_watcher "$artifact_prefix"
    for process_pid in "${race_gateway_pids[@]}" "${race_client_pids[@]}"; do
        if ! kill -0 "$process_pid" >/dev/null 2>&1; then
            printf 'error: %s race participant exited before watcher-backed release\n' \
                "$artifact_prefix" >&2
            exit 1
        fi
    done
    local release_temp="${release_file}.tmp"
    printf 'release\n' >"$release_temp"
    chmod 600 "$release_temp"
    mv -- "$release_temp" "$release_file"
    qualification_private_artifacts+=("$release_file")

    wait_for_race_transaction_overlap "$artifact_prefix"

    local index=0
    for index in 0 1; do
        if ! wait "${race_client_pids[$index]}"; then
            printf 'error: %s HTTP client %s failed after release\n' \
                "$artifact_prefix" "$index" >&2
            exit 1
        fi
    done
    race_client_pids=()
    race_left_status="$(tr -d '[:space:]' <"$race_left_status_file")"
    race_right_status="$(tr -d '[:space:]' <"$race_right_status_file")"
    assert_no_store "$race_left_headers" "${artifact_prefix} left response"
    assert_no_store "$race_right_headers" "${artifact_prefix} right response"

    for index in 0 1; do
        if ! kill -0 "${race_gateway_pids[$index]}" >/dev/null 2>&1; then
            printf 'error: %s Gateway %s exited after the coordinated release\n' \
                "$artifact_prefix" "$index" >&2
            exit 1
        fi
    done
    stop_race_processes
    start_gateway
}

build_race_open_request() {
    local operation_id="$1"
    local client_run_key="$2"
    local unsigned_file="$3"
    local signed_file="$4"
    jq -n \
        --arg operation_id "$operation_id" \
        --arg client_run_key "$client_run_key" \
        --arg authority_id "$race_authority_id" \
        --arg principal_id "$race_principal_id" \
        --arg source_id "$race_source_id" \
        '{
            schema_version: "0.1",
            mode: "create",
            client_operation_id: $operation_id,
            request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
            client_run_key: $client_run_key,
            environment: "local_cli_or_ide",
            authority: {kind: "service", id: $authority_id},
            principal: {kind: "workload", id: $principal_id},
            objective_ref: "objective_multiprocess_race",
            privacy_profile_ref: "privacy_structure_only_v1",
            retention_profile_ref: "retention_30d_v1",
            expected_source_kinds: ["semantic_hook"],
            source_manifest: {
                schema_version: "0.1",
                source_id: $source_id,
                source_kind: "semantic_hook",
                declared_boundary: "agent_harness",
                adapter_name: "apolysis_multiprocess_race",
                adapter_version: "0.1.0",
                environment: "local_cli_or_ide",
                capabilities: ["semantic_lifecycle", "tool_calls", "process", "workload", "claimed_outcome"],
                expected_lifecycle: ["started", "finished"],
                ordering: "strict_per_stream",
                samples: false,
                redaction_profile_ref: "redaction_structure_only_v1",
                redacted_fields: ["payload.command", "payload.arguments"],
                privacy_capabilities: ["structure_only"]
            }
        }' >"$unsigned_file"
    "$request_bin" open-run --input "$unsigned_file" --output "$signed_file"
}

build_race_ingest_request() {
    local operation_id="$1"
    local run_id="$2"
    local lease_file="$3"
    local event_source_id="$4"
    local source_stream_id="$5"
    local race_event_id="$6"
    local source_sequence="$7"
    local unsigned_file="$8"
    local signed_file="$9"
    local race_observed_at_unix_ms=""
    race_observed_at_unix_ms="$(( $(date +%s) * 1000 ))"
    jq -n \
        --arg operation_id "$operation_id" \
        --arg run_id "$run_id" \
        --rawfile lease_id "$lease_file" \
        --arg source_id "$event_source_id" \
        --arg source_stream_id "$source_stream_id" \
        --arg source_event_id "$race_event_id" \
        --argjson source_sequence "$source_sequence" \
        --argjson observed_at_unix_ms "$race_observed_at_unix_ms" \
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
                source_sequence: $source_sequence,
                observed_at: {
                    unix_ms: $observed_at_unix_ms,
                    clock_basis: "wall_clock",
                    uncertainty_ms: 25
                },
                correlation: {
                    trace_ref: "trace_multiprocess_race",
                    agent_ref: "agent_primary",
                    tool_ref: "tool_race",
                    runtime_ref: null
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
        }' >"$unsigned_file"
    "$request_bin" ingest --input "$unsigned_file" --output "$signed_file"
}

assert_terminal_lifecycle_rejection() {
    local route="$1"
    local request_file="$2"
    local artifact_prefix="$3"
    local response="${secret_directory}/${artifact_prefix}.response.json"
    local headers="${secret_directory}/${artifact_prefix}.headers"
    race_private_artifacts+=("$response")
    qualification_private_artifacts+=("$headers")
    local status=""
    status="$(curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 30 \
        --cacert "$ca_cert" \
        --cert "$race_client_cert" \
        --key "$race_client_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-binary "@${request_file}" \
        --dump-header "$headers" \
        --output "$response" \
        --write-out '%{http_code}' \
        "${gateway_base_url}/gateway/v0.1/${route}")"
    if [[ "$status" != "409" ]] || ! jq -e \
        '.code == "invalid_lifecycle_transition" and .retryable == false' \
        "$response" >/dev/null; then
        printf 'error: terminal %s request did not remain irreversible\n' \
            "$artifact_prefix" >&2
        exit 1
    fi
    assert_no_store "$headers" "terminal ${artifact_prefix}"
    record_rejected_race_operation "$request_file"
}

run_multiprocess_lifecycle_races() {
    race_accepted_operation_ids=()
    race_rejected_operation_ids=()
    race_expected_lease_file_by_response=()
    local identical_unsigned="${secret_directory}/race-open-identical.unsigned.json"
    local identical_signed="${secret_directory}/race-open-identical.json"
    build_race_open_request \
        "operation_race_open_identical_${random_suffix}" \
        "client_race_open_identical_${random_suffix}" \
        "$identical_unsigned" "$identical_signed"
    run_pre_operation_race \
        open_run open-run "$race_organization_id" \
        "$identical_signed" "$race_client_cert" "$race_client_key" \
        "$identical_signed" "$race_client_cert" "$race_client_key" \
        race-open-identical
    if [[ "$race_left_status" != "200" || "$race_right_status" != "200" ]]; then
        printf 'error: identical open_run writers did not both converge successfully\n' >&2
        exit 1
    fi
    local left_outcome=""
    local right_outcome=""
    left_outcome="$(jq -er '.outcome' "$race_left_response")"
    right_outcome="$(jq -er '.outcome' "$race_right_response")"
    if [[ !("$left_outcome" == "created" && "$right_outcome" == "idempotent_retry") && \
        !("$left_outcome" == "idempotent_retry" && "$right_outcome" == "created") ]]; then
        printf 'error: identical open_run writers did not produce one novel and one replay\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$identical_signed"
    local race_primary_run_id=""
    local race_primary_stream_id=""
    local race_primary_lease=""
    race_primary_run_id="$(jq -er '.run_id' "$race_left_response")"
    race_primary_stream_id="$(jq -er '.source_stream_id' "$race_left_response")"
    race_primary_lease="$(jq -er '.lease.lease_id' "$race_left_response")"
    local race_primary_lease_file="${secret_directory}/race-primary.lease"
    write_private_race_secret "$race_primary_lease" "$race_primary_lease_file"
    race_lease_files+=("$race_primary_lease_file")
    race_expected_lease_file_by_response["$race_left_response"]="$race_primary_lease_file"
    race_expected_lease_file_by_response["$race_right_response"]="$race_primary_lease_file"
    if ! jq -e \
        --arg run_id "$race_primary_run_id" \
        --arg stream_id "$race_primary_stream_id" \
        --rawfile lease_id "$race_primary_lease_file" \
        '.run_id == $run_id and .source_stream_id == $stream_id and .lease.lease_id == $lease_id' \
        "$race_right_response" >/dev/null; then
        printf 'error: identical open_run writers returned different durable identities\n' >&2
        exit 1
    fi
    race_secret_values+=("$race_primary_lease")

    local distinct_left_unsigned="${secret_directory}/race-open-key.left.unsigned.json"
    local distinct_left_signed="${secret_directory}/race-open-key.left.json"
    local distinct_right_unsigned="${secret_directory}/race-open-key.right.unsigned.json"
    local distinct_right_signed="${secret_directory}/race-open-key.right.json"
    local shared_client_run_key="client_race_open_key_${random_suffix}"
    build_race_open_request \
        "operation_race_open_key_left_${random_suffix}" "$shared_client_run_key" \
        "$distinct_left_unsigned" "$distinct_left_signed"
    build_race_open_request \
        "operation_race_open_key_right_${random_suffix}" "$shared_client_run_key" \
        "$distinct_right_unsigned" "$distinct_right_signed"
    run_pre_operation_race \
        open_run open-run "$race_organization_id" \
        "$distinct_left_signed" "$race_client_cert" "$race_client_key" \
        "$distinct_right_signed" "$race_client_cert" "$race_client_key" \
        race-open-client-key
    local race_secondary_response=""
    local distinct_conflict_response=""
    local distinct_winner_request=""
    local distinct_loser_request=""
    if [[ "$race_left_status" == "200" && "$race_right_status" == "409" ]]; then
        race_secondary_response="$race_left_response"
        distinct_conflict_response="$race_right_response"
        distinct_winner_request="$distinct_left_signed"
        distinct_loser_request="$distinct_right_signed"
    elif [[ "$race_left_status" == "409" && "$race_right_status" == "200" ]]; then
        race_secondary_response="$race_right_response"
        distinct_conflict_response="$race_left_response"
        distinct_winner_request="$distinct_right_signed"
        distinct_loser_request="$distinct_left_signed"
    else
        printf 'error: competing client run key did not yield one winner and one conflict\n' >&2
        exit 1
    fi
    if ! jq -e '.outcome == "created"' "$race_secondary_response" >/dev/null || \
        ! jq -e '.code == "idempotency_conflict" and .retryable == false' \
            "$distinct_conflict_response" >/dev/null; then
        printf 'error: competing client run key responses violated the contract\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$distinct_winner_request"
    record_rejected_race_operation "$distinct_loser_request"
    local race_secondary_run_id=""
    local race_secondary_stream_id=""
    local race_secondary_lease=""
    race_secondary_run_id="$(jq -er '.run_id' "$race_secondary_response")"
    race_secondary_stream_id="$(jq -er '.source_stream_id' "$race_secondary_response")"
    race_secondary_lease="$(jq -er '.lease.lease_id' "$race_secondary_response")"
    local race_secondary_lease_file="${secret_directory}/race-secondary.lease"
    write_private_race_secret "$race_secondary_lease" "$race_secondary_lease_file"
    race_lease_files+=("$race_secondary_lease_file")
    race_expected_lease_file_by_response["$race_secondary_response"]="$race_secondary_lease_file"
    race_secret_values+=("$race_secondary_lease")

    local join_proof_file="${secret_directory}/race-join.proof"
    random_hex 32 >"$join_proof_file"
    chmod 600 "$join_proof_file"
    local join_expires_at_unix_ms=""
    join_expires_at_unix_ms="$(( $(date +%s) * 1000 + 1800000 ))"
    "$qualification_join_grant_bin" \
        --database-url-file "$database_url_file" \
        --replay-key "$replay_key_file" \
        --issuer-certificate "$race_client_cert" \
        --joining-certificate "$race_join_client_cert" \
        --run-id "$race_primary_run_id" \
        --proof-file "$join_proof_file" \
        --expires-at-unix-ms "$join_expires_at_unix_ms"
    race_secret_values+=("$(<"$join_proof_file")")
    race_forbidden_response_values+=("$(<"$join_proof_file")")

    local join_base_unsigned="${secret_directory}/race-join.base.unsigned.json"
    jq -n \
        --rawfile proof_ref "$join_proof_file" \
        --arg operation_id "operation_race_join_left_${random_suffix}" \
        --arg run_id "$race_primary_run_id" \
        --arg source_id "$race_join_source_id" \
        --argjson expires_at_unix_ms "$join_expires_at_unix_ms" \
        '{
            schema_version: "0.1",
            mode: "join",
            client_operation_id: $operation_id,
            request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
            run_id: $run_id,
            join_proof: {
                kind: "grant",
                proof_ref: $proof_ref,
                run_id: $run_id,
                source_id: $source_id,
                expires_at_unix_ms: $expires_at_unix_ms
            },
            source_manifest: {
                schema_version: "0.1",
                source_id: $source_id,
                source_kind: "semantic_hook",
                declared_boundary: "agent_harness",
                adapter_name: "apolysis_multiprocess_join_race",
                adapter_version: "0.1.0",
                environment: "local_cli_or_ide",
                capabilities: ["semantic_lifecycle", "tool_calls", "process", "workload", "claimed_outcome"],
                expected_lifecycle: ["started", "finished"],
                ordering: "strict_per_stream",
                samples: false,
                redaction_profile_ref: "redaction_structure_only_v1",
                redacted_fields: ["payload.command", "payload.arguments"],
                privacy_capabilities: ["structure_only"]
            }
        }' >"$join_base_unsigned"
    local join_left_signed="${secret_directory}/race-join.left.json"
    local join_right_unsigned="${secret_directory}/race-join.right.unsigned.json"
    local join_right_signed="${secret_directory}/race-join.right.json"
    "$request_bin" open-run --input "$join_base_unsigned" --output "$join_left_signed"
    jq \
        --arg operation_id "operation_race_join_right_${random_suffix}" \
        '.client_operation_id = $operation_id
         | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"' \
        "$join_base_unsigned" >"$join_right_unsigned"
    "$request_bin" open-run --input "$join_right_unsigned" --output "$join_right_signed"
    run_pre_operation_race \
        open_run open-run "$race_organization_id" \
        "$join_left_signed" "$race_join_client_cert" "$race_join_client_key" \
        "$join_right_signed" "$race_join_client_cert" "$race_join_client_key" \
        race-join-grant
    local join_winner_response=""
    local join_winner_request=""
    local join_loser_response=""
    local join_loser_request=""
    if [[ "$race_left_status" == "200" && "$race_right_status" == "404" ]]; then
        join_winner_response="$race_left_response"
        join_winner_request="$join_left_signed"
        join_loser_response="$race_right_response"
        join_loser_request="$join_right_signed"
    elif [[ "$race_left_status" == "404" && "$race_right_status" == "200" ]]; then
        join_winner_response="$race_right_response"
        join_winner_request="$join_right_signed"
        join_loser_response="$race_left_response"
        join_loser_request="$join_left_signed"
    else
        printf 'error: one-use join grant did not yield one join and one denial\n' >&2
        exit 1
    fi
    if ! jq -e '.outcome == "joined"' "$join_winner_response" >/dev/null || \
        ! jq -e '.code == "not_found" and .retryable == false' \
            "$join_loser_response" >/dev/null; then
        printf 'error: one-use join grant race responses violated the contract\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$join_winner_request"
    record_rejected_race_operation "$join_loser_request"
    local race_join_stream_id=""
    local race_join_lease=""
    race_join_stream_id="$(jq -er '.source_stream_id' "$join_winner_response")"
    race_join_lease="$(jq -er '.lease.lease_id' "$join_winner_response")"
    local race_join_lease_file="${secret_directory}/race-join.lease"
    write_private_race_secret "$race_join_lease" "$race_join_lease_file"
    race_lease_files+=("$race_join_lease_file")
    race_expected_lease_file_by_response["$join_winner_response"]="$race_join_lease_file"
    race_secret_values+=("$race_join_lease")

    local join_replay_response="${secret_directory}/race-join.replay.response.json"
    local join_replay_headers="${secret_directory}/race-join.replay.headers"
    race_private_artifacts+=("$join_replay_response")
    race_expected_lease_file_by_response["$join_replay_response"]="$race_join_lease_file"
    qualification_private_artifacts+=("$join_replay_headers")
    local join_replay_status=""
    join_replay_status="$(curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 30 \
        --cacert "$ca_cert" \
        --cert "$race_join_client_cert" \
        --key "$race_join_client_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-binary "@${join_winner_request}" \
        --dump-header "$join_replay_headers" \
        --output "$join_replay_response" \
        --write-out '%{http_code}' \
        "${gateway_base_url}/gateway/v0.1/open-run")"
    if [[ "$join_replay_status" != "200" ]] || ! jq -e \
        --arg stream_id "$race_join_stream_id" \
        --rawfile lease_id "$race_join_lease_file" \
        '.outcome == "idempotent_retry"
         and .source_stream_id == $stream_id
         and .lease.lease_id == $lease_id' \
        "$join_replay_response" >/dev/null; then
        printf 'error: winning join operation did not retain exact replay\n' >&2
        exit 1
    fi
    assert_no_store "$join_replay_headers" 'join winner exact replay'

    local race_binding_valid_from_unix_ms=""
    local race_binding_valid_until_unix_ms=""
    race_binding_valid_from_unix_ms="$(date +%s%3N)"
    race_binding_valid_until_unix_ms="$((race_binding_valid_from_unix_ms + 300000))"
    local race_identity_ref="cluster_race:namespace_gate:pod_shared_${random_suffix}"
    local bind_left_unsigned="${secret_directory}/race-bind.left.unsigned.json"
    local bind_left_signed="${secret_directory}/race-bind.left.json"
    local bind_right_unsigned="${secret_directory}/race-bind.right.unsigned.json"
    local bind_right_signed="${secret_directory}/race-bind.right.json"
    jq -n \
        --arg operation_id "operation_race_bind_left_${random_suffix}" \
        --arg run_id "$race_primary_run_id" \
        --rawfile lease_id "$race_primary_lease_file" \
        --arg binding_id "binding_race_left_${random_suffix}" \
        --arg source_id "$race_source_id" \
        --arg identity_ref "$race_identity_ref" \
        --argjson valid_from_unix_ms "$race_binding_valid_from_unix_ms" \
        --argjson valid_until_unix_ms "$race_binding_valid_until_unix_ms" \
        '{
            schema_version: "0.1",
            client_operation_id: $operation_id,
            request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
            run_id: $run_id,
            lease_id: $lease_id,
            binding: {
                binding_id: $binding_id,
                asserting_source_id: $source_id,
                identity_kind: "pod",
                identity_ref: $identity_ref,
                valid_from_unix_ms: $valid_from_unix_ms,
                valid_until_unix_ms: $valid_until_unix_ms,
                evidence_basis: "propagated_and_validated",
                evidence_basis_ref: "race_identity_readback",
                attribution: "exact",
                reason_codes: [],
                confidence_bps: null,
                alternative_runtime_candidates: []
            }
        }' >"$bind_left_unsigned"
    "$request_bin" bind-runtime --input "$bind_left_unsigned" --output "$bind_left_signed"
    jq \
        --arg operation_id "operation_race_bind_right_${random_suffix}" \
        --arg run_id "$race_secondary_run_id" \
        --rawfile lease_id "$race_secondary_lease_file" \
        --arg binding_id "binding_race_right_${random_suffix}" \
        '.client_operation_id = $operation_id
         | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"
         | .run_id = $run_id
         | .lease_id = $lease_id
         | .binding.binding_id = $binding_id' \
        "$bind_left_unsigned" >"$bind_right_unsigned"
    "$request_bin" bind-runtime --input "$bind_right_unsigned" --output "$bind_right_signed"
    run_pre_operation_race \
        bind_runtime bind-runtime "$race_organization_id" \
        "$bind_left_signed" "$race_client_cert" "$race_client_key" \
        "$bind_right_signed" "$race_client_cert" "$race_client_key" \
        race-bind-exact-identity
    local bind_winner_response=""
    local bind_loser_response=""
    local bind_winner_request=""
    local bind_loser_request=""
    if [[ "$race_left_status" == "200" && "$race_right_status" == "400" ]]; then
        bind_winner_response="$race_left_response"
        bind_loser_response="$race_right_response"
        bind_winner_request="$bind_left_signed"
        bind_loser_request="$bind_right_signed"
    elif [[ "$race_left_status" == "400" && "$race_right_status" == "200" ]]; then
        bind_winner_response="$race_right_response"
        bind_loser_response="$race_left_response"
        bind_winner_request="$bind_right_signed"
        bind_loser_request="$bind_left_signed"
    else
        printf 'error: exact runtime identity race did not yield one winner and one denial (left=%s/%s right=%s/%s)\n' \
            "$race_left_status" \
            "$(jq -r '.code // .accepted // "unknown"' "$race_left_response")" \
            "$race_right_status" \
            "$(jq -r '.code // .accepted // "unknown"' "$race_right_response")" >&2
        exit 1
    fi
    if ! jq -e '.accepted == true and .idempotent_replay == false' \
        "$bind_winner_response" >/dev/null || \
        ! jq -e '.code == "invalid_contract" and .retryable == false' \
            "$bind_loser_response" >/dev/null; then
        printf 'error: exact runtime identity race responses violated the contract\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$bind_winner_request"
    record_rejected_race_operation "$bind_loser_request"

    local duplicate_left_unsigned="${secret_directory}/race-ingest-duplicate.left.unsigned.json"
    local duplicate_left_signed="${secret_directory}/race-ingest-duplicate.left.json"
    local duplicate_right_unsigned="${secret_directory}/race-ingest-duplicate.right.unsigned.json"
    local duplicate_right_signed="${secret_directory}/race-ingest-duplicate.right.json"
    build_race_ingest_request \
        "operation_race_ingest_duplicate_left_${random_suffix}" \
        "$race_primary_run_id" "$race_primary_lease_file" "$race_source_id" \
        "$race_primary_stream_id" "event_race_duplicate_${random_suffix}" 1 \
        "$duplicate_left_unsigned" "$duplicate_left_signed"
    jq \
        --arg operation_id "operation_race_ingest_duplicate_right_${random_suffix}" \
        '.client_operation_id = $operation_id
         | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"' \
        "$duplicate_left_unsigned" >"$duplicate_right_unsigned"
    "$request_bin" ingest --input "$duplicate_right_unsigned" --output "$duplicate_right_signed"
    run_pre_operation_race \
        ingest ingest "$race_organization_id" \
        "$duplicate_left_signed" "$race_client_cert" "$race_client_key" \
        "$duplicate_right_signed" "$race_client_cert" "$race_client_key" \
        race-ingest-duplicate-event
    if [[ "$race_left_status" != "200" || "$race_right_status" != "200" ]]; then
        printf 'error: duplicate event writers did not both converge successfully\n' >&2
        exit 1
    fi
    local duplicate_left_committed=""
    local duplicate_right_committed=""
    local duplicate_left_sequence=""
    local duplicate_right_sequence=""
    duplicate_left_committed="$(jq -er '.committed_count' "$race_left_response")"
    duplicate_right_committed="$(jq -er '.committed_count' "$race_right_response")"
    duplicate_left_sequence="$(jq -er '.acknowledgements[0].ingest_sequence' "$race_left_response")"
    duplicate_right_sequence="$(jq -er '.acknowledgements[0].ingest_sequence' "$race_right_response")"
    if [[ "$((duplicate_left_committed + duplicate_right_committed))" != "1" ]] || \
        [[ "$duplicate_left_sequence" != "$duplicate_right_sequence" ]] || \
        [[ "$(( $(jq -er '.duplicate_count' "$race_left_response") + \
            $(jq -er '.duplicate_count' "$race_right_response") ))" != "1" ]]; then
        printf 'error: duplicate event writers did not converge on one ledger identity\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$duplicate_left_signed"
    record_accepted_race_operation "$duplicate_right_signed"

    local concurrent_primary_unsigned="${secret_directory}/race-ingest-concurrent.primary.unsigned.json"
    local concurrent_primary_signed="${secret_directory}/race-ingest-concurrent.primary.json"
    local concurrent_secondary_unsigned="${secret_directory}/race-ingest-concurrent.secondary.unsigned.json"
    local concurrent_secondary_signed="${secret_directory}/race-ingest-concurrent.secondary.json"
    build_race_ingest_request \
        "operation_race_ingest_primary_${random_suffix}" \
        "$race_primary_run_id" "$race_primary_lease_file" "$race_source_id" \
        "$race_primary_stream_id" "event_race_primary_2_${random_suffix}" 2 \
        "$concurrent_primary_unsigned" "$concurrent_primary_signed"
    build_race_ingest_request \
        "operation_race_ingest_secondary_${random_suffix}" \
        "$race_secondary_run_id" "$race_secondary_lease_file" "$race_source_id" \
        "$race_secondary_stream_id" "event_race_secondary_1_${random_suffix}" 1 \
        "$concurrent_secondary_unsigned" "$concurrent_secondary_signed"
    run_pre_operation_race \
        ingest ingest "$race_organization_id" \
        "$concurrent_primary_signed" "$race_client_cert" "$race_client_key" \
        "$concurrent_secondary_signed" "$race_client_cert" "$race_client_key" \
        race-ingest-organization-sequence
    if [[ "$race_left_status" != "200" || "$race_right_status" != "200" ]] || \
        ! jq -e '.committed_count == 1 and .duplicate_count == 0' \
            "$race_left_response" >/dev/null || \
        ! jq -e '.committed_count == 1 and .duplicate_count == 0' \
            "$race_right_response" >/dev/null; then
        printf 'error: concurrent source writers did not both commit\n' >&2
        exit 1
    fi
    local concurrent_primary_sequence=""
    local concurrent_secondary_sequence=""
    concurrent_primary_sequence="$(jq -er '.acknowledgements[0].ingest_sequence' "$race_left_response")"
    concurrent_secondary_sequence="$(jq -er '.acknowledgements[0].ingest_sequence' "$race_right_response")"
    if ((concurrent_primary_sequence == concurrent_secondary_sequence)); then
        printf 'error: concurrent cross-run writers reused an organization sequence\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$concurrent_primary_signed"
    record_accepted_race_operation "$concurrent_secondary_signed"

    local join_ingest_unsigned="${secret_directory}/race-ingest-join.unsigned.json"
    local join_ingest_signed="${secret_directory}/race-ingest-join.json"
    local join_ingest_response="${secret_directory}/race-ingest-join.response.json"
    local join_ingest_headers="${secret_directory}/race-ingest-join.headers"
    build_race_ingest_request \
        "operation_race_ingest_join_${random_suffix}" \
        "$race_primary_run_id" "$race_join_lease_file" "$race_join_source_id" \
        "$race_join_stream_id" "event_race_join_1_${random_suffix}" 1 \
        "$join_ingest_unsigned" "$join_ingest_signed"
    local join_ingest_status=""
    join_ingest_status="$(curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 30 \
        --cacert "$ca_cert" \
        --cert "$race_join_client_cert" \
        --key "$race_join_client_key" \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data-binary "@${join_ingest_signed}" \
        --dump-header "$join_ingest_headers" \
        --output "$join_ingest_response" \
        --write-out '%{http_code}' \
        "${gateway_base_url}/gateway/v0.1/ingest")"
    race_private_artifacts+=("$join_ingest_response")
    qualification_private_artifacts+=("$join_ingest_headers")
    if [[ "$join_ingest_status" != "200" ]] || ! jq -e \
        '.committed_count == 1 and .duplicate_count == 0' \
        "$join_ingest_response" >/dev/null; then
        printf 'error: joined race stream could not establish its terminal event\n' >&2
        exit 1
    fi
    assert_no_store "$join_ingest_headers" 'joined race stream ingest'
    record_accepted_race_operation "$join_ingest_signed"

    local finish_primary_unsigned="${secret_directory}/race-finish-primary.unsigned.json"
    local finish_primary_signed="${secret_directory}/race-finish-primary.json"
    jq -n \
        --arg operation_id "operation_race_finish_primary_${random_suffix}" \
        --arg run_id "$race_primary_run_id" \
        --rawfile lease_id "$race_primary_lease_file" \
        --arg primary_source_id "$race_source_id" \
        --arg primary_stream_id "$race_primary_stream_id" \
        --arg join_source_id "$race_join_source_id" \
        --arg join_stream_id "$race_join_stream_id" \
        '{
            schema_version: "0.1",
            client_operation_id: $operation_id,
            request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
            run_id: $run_id,
            lease_id: $lease_id,
            terminal_positions: [
                {
                    source_id: $primary_source_id,
                    source_stream_id: $primary_stream_id,
                    final_source_sequence: 2
                },
                {
                    source_id: $join_source_id,
                    source_stream_id: $join_stream_id,
                    final_source_sequence: 1
                }
            ],
            outcome_claim_refs: [],
            requested_finalization_deadline_unix_ms: null
        }' >"$finish_primary_unsigned"
    "$request_bin" finish-run --input "$finish_primary_unsigned" --output "$finish_primary_signed"
    run_pre_operation_race \
        finish_run finish-run "$race_organization_id" \
        "$finish_primary_signed" "$race_client_cert" "$race_client_key" \
        "$finish_primary_signed" "$race_client_cert" "$race_client_key" \
        race-finish-identical
    if [[ "$race_left_status" != "200" || "$race_right_status" != "200" ]] || \
        ! jq -e '.state == "finished"' "$race_left_response" >/dev/null || \
        ! jq -e '.state == "finished"' "$race_right_response" >/dev/null; then
        printf 'error: identical finish writers did not converge on the terminal state\n' >&2
        exit 1
    fi
    local left_finish_replay=""
    local right_finish_replay=""
    left_finish_replay="$(jq -r '.idempotent_replay' "$race_left_response")"
    right_finish_replay="$(jq -r '.idempotent_replay' "$race_right_response")"
    if [[ !("$left_finish_replay" == "false" && "$right_finish_replay" == "true") && \
        !("$left_finish_replay" == "true" && "$right_finish_replay" == "false") ]]; then
        printf 'error: identical finish writers did not produce one novel and one replay\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$finish_primary_signed"

    local finish_secondary_left_unsigned="${secret_directory}/race-finish-secondary.left.unsigned.json"
    local finish_secondary_left_signed="${secret_directory}/race-finish-secondary.left.json"
    local finish_secondary_right_unsigned="${secret_directory}/race-finish-secondary.right.unsigned.json"
    local finish_secondary_right_signed="${secret_directory}/race-finish-secondary.right.json"
    jq -n \
        --arg operation_id "operation_race_finish_secondary_left_${random_suffix}" \
        --arg run_id "$race_secondary_run_id" \
        --rawfile lease_id "$race_secondary_lease_file" \
        --arg source_id "$race_source_id" \
        --arg stream_id "$race_secondary_stream_id" \
        '{
            schema_version: "0.1",
            client_operation_id: $operation_id,
            request_digest: "0000000000000000000000000000000000000000000000000000000000000000",
            run_id: $run_id,
            lease_id: $lease_id,
            terminal_positions: [{
                source_id: $source_id,
                source_stream_id: $stream_id,
                final_source_sequence: 1
            }],
            outcome_claim_refs: [],
            requested_finalization_deadline_unix_ms: null
        }' >"$finish_secondary_left_unsigned"
    "$request_bin" finish-run \
        --input "$finish_secondary_left_unsigned" \
        --output "$finish_secondary_left_signed"
    jq \
        --arg operation_id "operation_race_finish_secondary_right_${random_suffix}" \
        '.client_operation_id = $operation_id
         | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"' \
        "$finish_secondary_left_unsigned" >"$finish_secondary_right_unsigned"
    "$request_bin" finish-run \
        --input "$finish_secondary_right_unsigned" \
        --output "$finish_secondary_right_signed"
    run_pre_operation_race \
        finish_run finish-run "$race_organization_id" \
        "$finish_secondary_left_signed" "$race_client_cert" "$race_client_key" \
        "$finish_secondary_right_signed" "$race_client_cert" "$race_client_key" \
        race-finish-distinct
    local finish_secondary_winner=""
    local finish_secondary_loser=""
    local finish_secondary_winner_request=""
    local finish_secondary_loser_request=""
    if [[ "$race_left_status" == "200" && "$race_right_status" == "409" ]]; then
        finish_secondary_winner="$race_left_response"
        finish_secondary_loser="$race_right_response"
        finish_secondary_winner_request="$finish_secondary_left_signed"
        finish_secondary_loser_request="$finish_secondary_right_signed"
    elif [[ "$race_left_status" == "409" && "$race_right_status" == "200" ]]; then
        finish_secondary_winner="$race_right_response"
        finish_secondary_loser="$race_left_response"
        finish_secondary_winner_request="$finish_secondary_right_signed"
        finish_secondary_loser_request="$finish_secondary_left_signed"
    else
        printf 'error: distinct finish writers did not yield one terminal winner\n' >&2
        exit 1
    fi
    if ! jq -e '.state == "finished" and .idempotent_replay == false' \
        "$finish_secondary_winner" >/dev/null || \
        ! jq -e '.code == "invalid_lifecycle_transition" and .retryable == false' \
            "$finish_secondary_loser" >/dev/null; then
        printf 'error: distinct finish writer responses violated terminal semantics\n' >&2
        exit 1
    fi
    record_accepted_race_operation "$finish_secondary_winner_request"
    record_rejected_race_operation "$finish_secondary_loser_request"

    local terminal_ingest_unsigned="${secret_directory}/race-terminal-ingest.unsigned.json"
    local terminal_ingest_signed="${secret_directory}/race-terminal-ingest.json"
    build_race_ingest_request \
        "operation_race_terminal_ingest_${random_suffix}" \
        "$race_primary_run_id" "$race_primary_lease_file" "$race_source_id" \
        "$race_primary_stream_id" "event_race_terminal_3_${random_suffix}" 3 \
        "$terminal_ingest_unsigned" "$terminal_ingest_signed"
    assert_terminal_lifecycle_rejection \
        ingest "$terminal_ingest_signed" race-terminal-ingest

    local terminal_bind_unsigned="${secret_directory}/race-terminal-bind.unsigned.json"
    local terminal_bind_signed="${secret_directory}/race-terminal-bind.json"
    jq \
        --arg operation_id "operation_race_terminal_bind_${random_suffix}" \
        --arg run_id "$race_primary_run_id" \
        --rawfile lease_id "$race_primary_lease_file" \
        --arg binding_id "binding_race_terminal_${random_suffix}" \
        '.client_operation_id = $operation_id
         | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"
         | .run_id = $run_id
         | .lease_id = $lease_id
         | .binding.binding_id = $binding_id' \
        "$bind_left_unsigned" >"$terminal_bind_unsigned"
    "$request_bin" bind-runtime --input "$terminal_bind_unsigned" --output "$terminal_bind_signed"
    assert_terminal_lifecycle_rejection \
        bind-runtime "$terminal_bind_signed" race-terminal-bind

    local terminal_finish_unsigned="${secret_directory}/race-terminal-finish.unsigned.json"
    local terminal_finish_signed="${secret_directory}/race-terminal-finish.json"
    jq \
        --arg operation_id "operation_race_terminal_finish_${random_suffix}" \
        '.client_operation_id = $operation_id
         | .request_digest = "0000000000000000000000000000000000000000000000000000000000000000"' \
        "$finish_primary_unsigned" >"$terminal_finish_unsigned"
    "$request_bin" finish-run \
        --input "$terminal_finish_unsigned" \
        --output "$terminal_finish_signed"
    assert_terminal_lifecycle_rejection \
        finish-run "$terminal_finish_signed" race-terminal-finish

    if [[ "${#race_accepted_operation_ids[@]}" != "11" || \
        "${#race_rejected_operation_ids[@]}" != "7" ]]; then
        printf 'error: race operation oracle did not record the reviewed accepted/rejected sets\n' >&2
        exit 1
    fi
    local accepted_operation_ids=""
    local rejected_operation_ids=""
    accepted_operation_ids="$(IFS=,; printf '%s' "${race_accepted_operation_ids[*]}")"
    rejected_operation_ids="$(IFS=,; printf '%s' "${race_rejected_operation_ids[*]}")"

    local race_database_invariants=""
    race_database_invariants="$(timeout 30s docker exec -i "$container_name" \
        psql --username "$gateway_runtime_login" --dbname "$database_name" \
            --no-align --tuples-only \
            --set=organization_id="$race_organization_id" \
            --set=primary_run_id="$race_primary_run_id" \
            --set=secondary_run_id="$race_secondary_run_id" \
            --set=join_source_id="$race_join_source_id" \
            --set=identity_ref="$race_identity_ref" \
            --set=accepted_operation_ids="$accepted_operation_ids" \
            --set=rejected_operation_ids="$rejected_operation_ids" <<'SQL' | tr -d '[:space:]'
SELECT concat_ws('|',
    (SELECT count(*) FROM apolysis_gateway.runs
      WHERE organization_id=:'organization_id' AND state='finished'),
    (SELECT count(*) FROM apolysis_gateway.client_runs
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.source_streams
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.leases
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.join_authorizations
      WHERE organization_id=:'organization_id'
        AND source_id=:'join_source_id'
        AND authorization_kind='grant'
        AND authorization_state='consumed'
        AND consumed_at_unix_ms IS NOT NULL),
    (SELECT count(*) FROM apolysis_gateway.runtime_bindings
      WHERE organization_id=:'organization_id'
        AND identity_ref=:'identity_ref' AND attribution='exact'),
    (SELECT count(*) FROM apolysis_gateway.active_runtime_identities
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.evidence_events
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.finalization_declarations
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations
      WHERE organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.operation_replays AS replay
      JOIN apolysis_gateway.gateway_operations AS operation
        ON operation.organization_id=replay.organization_id
       AND operation.operation_id=replay.operation_id
      WHERE operation.organization_id=:'organization_id'),
    (SELECT count(*) FROM apolysis_gateway.record_items AS record
      LEFT JOIN apolysis_gateway.projection_outbox AS outbox
        ON outbox.organization_id=record.organization_id
       AND outbox.ingest_sequence=record.ingest_sequence
      WHERE record.organization_id=:'organization_id'
        AND outbox.ingest_sequence IS NULL),
    (SELECT count(*) FROM apolysis_gateway.projection_outbox AS outbox
      LEFT JOIN apolysis_gateway.record_items AS record
        ON record.organization_id=outbox.organization_id
       AND record.ingest_sequence=outbox.ingest_sequence
      WHERE outbox.organization_id=:'organization_id'
        AND record.ingest_sequence IS NULL),
    (SELECT count(*) FROM apolysis_gateway.organization_sequences AS sequence
      WHERE sequence.organization_id=:'organization_id'
        AND sequence.next_ingest_sequence=(
            SELECT count(*) + 1 FROM apolysis_gateway.record_items
             WHERE organization_id=:'organization_id')),
    (SELECT count(*) FROM (
        SELECT min(ingest_sequence)=1
               AND max(ingest_sequence)=count(*)
               AND bool_and(outbox_ingest_sequence=ingest_sequence) AS valid
          FROM apolysis_gateway.record_items
         WHERE organization_id=:'organization_id'
    ) AS contiguous WHERE valid),
    (SELECT count(*) FROM apolysis_gateway.runs
      WHERE organization_id=:'organization_id'
        AND run_id IN (:'primary_run_id', :'secondary_run_id')),
    (SELECT count(*)
       FROM unnest(string_to_array(:'accepted_operation_ids', ','))
            AS expected(client_operation_id)
      WHERE (SELECT count(*) FROM apolysis_gateway.gateway_operations AS operation
              WHERE operation.organization_id=:'organization_id'
                AND operation.client_operation_id=expected.client_operation_id) <> 1),
    (SELECT count(*)
       FROM unnest(string_to_array(:'accepted_operation_ids', ','))
            AS expected(client_operation_id)
      WHERE (SELECT count(*) FROM apolysis_gateway.operation_replays AS replay
              JOIN apolysis_gateway.gateway_operations AS operation
                ON operation.organization_id=replay.organization_id
               AND operation.operation_id=replay.operation_id
              WHERE operation.organization_id=:'organization_id'
                AND operation.client_operation_id=expected.client_operation_id) <> 1),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations AS operation
      WHERE operation.organization_id=:'organization_id'
        AND NOT operation.client_operation_id = ANY(
            string_to_array(:'accepted_operation_ids', ','))),
    (SELECT count(*) FROM apolysis_gateway.gateway_operations AS operation
      WHERE operation.organization_id=:'organization_id'
        AND operation.client_operation_id = ANY(
            string_to_array(:'rejected_operation_ids', ',')))
);
SQL
)"
    if [[ "$race_database_invariants" != '2|2|3|3|1|1|0|4|2|11|11|0|0|1|1|2|0|0|0|0' ]]; then
        printf 'error: multiprocess lifecycle invariants did not match the reviewed vector: %s\n' \
            "$race_database_invariants" >&2
        exit 1
    fi

    printf 'Two-process Gateway lifecycle race matrix passed.\n'
}

cleanup() {
    local exit_status=$?

    trap - EXIT INT TERM
    stop_gateway
    stop_race_processes
    stop_owned_process "$workload_pid"
    stop_owned_process "$crash_client_pid"
    timeout 15s docker rm --force "$container_name" >/dev/null 2>&1 || true
    local remaining_containers=""
    if ! remaining_containers="$(timeout 5s docker container ls --all \
        --filter "name=${container_name}" --format '{{.Names}}' 2>/dev/null)"; then
        printf 'error: unable to verify Gateway transport container cleanup\n' >&2
        exit_status=1
    elif grep -Fxq -- "$container_name" <<<"$remaining_containers"; then
        printf 'error: Gateway transport gate left its PostgreSQL container behind\n' >&2
        exit_status=1
    fi
    rm -rf -- "$secret_directory"
    if [[ -e "$secret_directory" ]]; then
        printf 'error: Gateway transport gate left its private control directory behind\n' >&2
        exit_status=1
    fi
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
readonly race_client_key="${secret_directory}/race-client.key.pem"
readonly race_client_csr="${secret_directory}/race-client.csr.pem"
readonly race_client_cert="${secret_directory}/race-client.cert.pem"
readonly race_join_client_key="${secret_directory}/race-join-client.key.pem"
readonly race_join_client_csr="${secret_directory}/race-join-client.csr.pem"
readonly race_join_client_cert="${secret_directory}/race-join-client.cert.pem"
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

if [[ "$multiprocess_races_enabled" == "1" ]]; then
    openssl req -newkey ed25519 -nodes \
        -keyout "$race_client_key" \
        -out "$race_client_csr" \
        -subj "/CN=apolysis-race-source-${random_suffix}" >/dev/null 2>&1
    openssl x509 -req \
        -in "$race_client_csr" \
        -CA "$ca_cert" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$race_client_cert" \
        -days 1 \
        -extfile "$client_extensions" >/dev/null 2>&1

    openssl req -newkey ed25519 -nodes \
        -keyout "$race_join_client_key" \
        -out "$race_join_client_csr" \
        -subj "/CN=apolysis-race-join-source-${random_suffix}" >/dev/null 2>&1
    openssl x509 -req \
        -in "$race_join_client_csr" \
        -CA "$ca_cert" \
        -CAkey "$ca_key" \
        -CAcreateserial \
        -out "$race_join_client_cert" \
        -days 1 \
        -extfile "$client_extensions" >/dev/null 2>&1
fi

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
readonly race_organization_id="org_race_${random_suffix}"
readonly race_principal_id="principal_race_${random_suffix}"
readonly race_registration_id="registration_race_${random_suffix}"
readonly race_source_id="source_race_${random_suffix}"
readonly race_authority_id="authority_race_${random_suffix}"
readonly race_policy_file="${secret_directory}/source-registration.race.json"
readonly race_join_principal_id="principal_race_join_${random_suffix}"
readonly race_join_registration_id="registration_race_join_${random_suffix}"
readonly race_join_source_id="source_race_join_${random_suffix}"
readonly race_join_policy_file="${secret_directory}/source-registration.race-join.json"

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

if [[ "$multiprocess_races_enabled" == "1" ]]; then
    jq \
        --arg organization_id "$race_organization_id" \
        --arg principal_id "$race_principal_id" \
        --arg registration_id "$race_registration_id" \
        --arg source_id "$race_source_id" \
        --arg authority_id "$race_authority_id" \
        '.organization_id = $organization_id
         | .source_registration_id = $registration_id
         | .source_id = $source_id
         | .principal.id = $principal_id
         | .allowed_capabilities += ["workload"]
         | .allowed_run_authorities = [{kind: "service", id: $authority_id}]' \
        "$policy_file" >"$race_policy_file"
    jq \
        --arg principal_id "$race_join_principal_id" \
        --arg registration_id "$race_join_registration_id" \
        --arg source_id "$race_join_source_id" \
        '.source_registration_id = $registration_id
         | .source_id = $source_id
         | .principal.id = $principal_id
         | .may_create_runs = false
         | .may_join_runs = true
         | .may_finalize_runs = false
         | .allowed_run_authorities = []
         | .allowed_run_privacy_profile_refs = []
         | .allowed_run_retention_profile_refs = []
         | .required_run_source_kinds = []' \
        "$race_policy_file" >"$race_join_policy_file"
fi

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

if [[ "$multiprocess_races_enabled" == "1" ]]; then
    printf 'Provisioning isolated multiprocess-race mTLS authorities...\n'
    "$authority_bin" register-source \
        --database-url-file "$gateway_control_database_url_file" \
        --registration "$race_policy_file" \
        --client-certificate "$race_client_cert"
    "$authority_bin" register-source \
        --database-url-file "$gateway_control_database_url_file" \
        --registration "$race_join_policy_file" \
        --client-certificate "$race_join_client_cert"
fi

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
if [[ "$crash_recovery_enabled" == "1" ]]; then
    qualify_post_commit_crash \
        open_run open-run "$signed_request" open-run
fi
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

expected_open_outcome="created"
if [[ "$crash_recovery_enabled" == "1" ]]; then
    expected_open_outcome="idempotent_retry"
fi
jq -e \
    --arg source_id "$source_id" \
    --arg expected_outcome "$expected_open_outcome" \
    '.schema_version == "0.1"
     and .outcome == $expected_outcome
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

if [[ "$crash_recovery_enabled" == "1" ]]; then
    qualify_post_commit_crash \
        bind_runtime bind-runtime "$bind_signed_request" bind-runtime
fi
expected_bind_replay=false
if [[ "$crash_recovery_enabled" == "1" ]]; then
    expected_bind_replay=true
fi
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
    --argjson expected_replay "$expected_bind_replay" \
    '.schema_version == "0.1"
     and .run_id == $run_id
     and .binding_id == $binding_id
     and .accepted == true
     and .idempotent_replay == $expected_replay' \
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

if [[ "$crash_recovery_enabled" == "1" ]]; then
    qualify_post_commit_crash \
        ingest ingest "$ingest_signed_request" ingest
fi
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

if [[ "$crash_recovery_enabled" == "1" ]]; then
    qualify_post_commit_crash \
        finish_run finish-run "$finish_signed_request" finish-run
fi
expected_finish_replay=false
if [[ "$crash_recovery_enabled" == "1" ]]; then
    expected_finish_replay=true
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
    --argjson expected_replay "$expected_finish_replay" \
    '.schema_version == "0.1"
     and .run_id == $run_id
     and .state == "finished"
     and .finalization_deadline_unix_ms == null
     and .idempotent_replay == $expected_replay' \
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

if [[ "$multiprocess_races_enabled" == "1" ]]; then
    run_multiprocess_lifecycle_races
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
    attack_response_body="$(<"$attack_response")"
    if [[ "$attack_response_body" == *"$issued_run_id"* || \
        "$attack_response_body" == *"$issued_stream_id"* || \
        "$attack_response_body" == *"$issued_lease"* ]]; then
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
readonly secret_scan_patterns="${secret_directory}/secret-scan.patterns"
readonly response_forbidden_patterns="${secret_directory}/response-forbidden.patterns"
{
    printf '%s\n' \
        "$issued_lease" \
        "$database_password" \
        "$schema_owner_password" \
        "$gateway_control_password" \
        "$gateway_runtime_password" \
        "$replay_key_value"
    if [[ "$multiprocess_races_enabled" == "1" ]]; then
        printf '%s\n' "${race_secret_values[@]}"
    fi
} >"$secret_scan_patterns"
chmod 600 "$secret_scan_patterns"
{
    printf '%s\n' \
        "$issued_lease" \
        "$database_password" \
        "$schema_owner_password" \
        "$gateway_control_password" \
        "$gateway_runtime_password" \
        "$replay_key_value"
    if [[ "$multiprocess_races_enabled" == "1" ]]; then
        printf '%s\n' "${race_forbidden_response_values[@]}"
    fi
} >"$response_forbidden_patterns"
chmod 600 "$response_forbidden_patterns"
if ! timeout 30s docker exec "$container_name" \
    pg_dump --username "$database_user" --dbname "$database_name" \
        --no-owner --no-privileges >"$database_dump"; then
    printf 'error: failed to inspect PostgreSQL secret persistence\n' >&2
    exit 1
fi
if grep -Fq -f "$secret_scan_patterns" "$database_dump" || \
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
if grep -Fq -f "$secret_scan_patterns" "$server_log"; then
    printf 'error: protected test secret was written to the Gateway log\n' >&2
    exit 1
fi
if grep -Fq -- 'BEGIN PRIVATE KEY' "$server_log"; then
    printf 'error: TLS private-key material was written to the Gateway log\n' >&2
    exit 1
fi
if [[ "$crash_recovery_enabled" == "1" || "$multiprocess_races_enabled" == "1" ]]; then
    for qualification_artifact in "${qualification_private_artifacts[@]}"; do
        if [[ "$(stat -c '%a' "$qualification_artifact")" != "600" ]]; then
            printf 'error: HTTPS crash qualification artifact is not mode 0600\n' >&2
            exit 1
        fi
    done
    if grep -Fq -f "$secret_scan_patterns" "${qualification_private_artifacts[@]}"; then
        printf 'error: secret material entered an HTTPS crash qualification artifact\n' >&2
        exit 1
    fi
    if grep -Fq -- 'BEGIN PRIVATE KEY' "${qualification_private_artifacts[@]}"; then
        printf 'error: TLS private-key material entered a Gateway qualification artifact\n' >&2
        exit 1
    fi
fi
if [[ "$multiprocess_races_enabled" == "1" ]]; then
    for race_lease_file in "${race_lease_files[@]}"; do
        if [[ "$(stat -c '%a' "$race_lease_file")" != "600" ]]; then
            printf 'error: multiprocess race lease input is not mode 0600\n' >&2
            exit 1
        fi
    done
    for race_artifact in "${race_private_artifacts[@]}"; do
        if [[ "$(stat -c '%a' "$race_artifact")" != "600" ]]; then
            printf 'error: multiprocess race response artifact is not mode 0600\n' >&2
            exit 1
        fi
        expected_race_lease_file="${race_expected_lease_file_by_response[$race_artifact]:-}"
        for race_lease_file in "${race_lease_files[@]}"; do
            if [[ "$race_lease_file" == "$expected_race_lease_file" ]]; then
                if ! jq -e --rawfile lease "$race_lease_file" \
                    '[paths(scalars) as $path
                      | getpath($path) as $value
                      | select(($value | type) == "string" and ($value | contains($lease)))
                      | {path: $path, exact: ($value == $lease)}] as $matches
                     | (($matches | length) == 1
                        and ($matches
                             | all(.path == ["lease", "lease_id"] and .exact)))' \
                    "$race_artifact" >/dev/null; then
                    printf 'error: expected bearer lease escaped its exact response field\n' >&2
                    exit 1
                fi
            elif ! jq -e --rawfile lease "$race_lease_file" \
                '[paths(scalars) as $path
                  | getpath($path) as $value
                  | select(($value | type) == "string" and ($value | contains($lease)))]
                 | length == 0' "$race_artifact" >/dev/null; then
                printf 'error: unexpected bearer lease entered a race response\n' >&2
                exit 1
            fi
        done
    done
    if grep -Fq -f "$response_forbidden_patterns" "${race_private_artifacts[@]}"; then
        printf 'error: non-response secret entered a race response artifact\n' >&2
        exit 1
    fi
    if grep -Fq -- 'BEGIN PRIVATE KEY' "${race_private_artifacts[@]}"; then
        printf 'error: TLS private-key material entered a race response artifact\n' >&2
        exit 1
    fi
fi

printf 'Real mTLS Gateway authority gate passed.\n'

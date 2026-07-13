#!/usr/bin/env bash

set -Eeuo pipefail

# Pin the qualified PostgreSQL point release and its verified multi-platform
# OCI index digest. A database upgrade must therefore be an explicit change.
readonly POSTGRES_IMAGE="postgres:16.14-alpine3.23@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3"
readonly PROJECTION_DRIVER_EXAMPLE="postgres_projection_driver"
readonly CONCURRENT_DRIVER_COUNT=4
readonly MAX_STAGE_OUTPUT_BYTES=8388608
readonly MAX_DUMP_BYTES=67108864

pull_timeout_seconds="${APOLYSIS_PROJECTION_PULL_TIMEOUT_SECONDS:-300}"
start_timeout_seconds="${APOLYSIS_PROJECTION_START_TIMEOUT_SECONDS:-90}"
build_timeout_seconds="${APOLYSIS_PROJECTION_BUILD_TIMEOUT_SECONDS:-900}"
test_timeout_seconds="${APOLYSIS_PROJECTION_TEST_TIMEOUT_SECONDS:-1200}"
driver_timeout_seconds="${APOLYSIS_PROJECTION_DRIVER_TIMEOUT_SECONDS:-300}"
stop_timeout_seconds="${APOLYSIS_PROJECTION_STOP_TIMEOUT_SECONDS:-30}"

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

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$repository_root"

require_command bash
require_command cat
require_command cargo
require_command chmod
require_command cp
require_command docker
require_command env
require_command date
require_command dirname
require_command grep
require_command head
require_command mkdir
require_command mktemp
require_command mv
require_command od
require_command rm
require_command seq
require_command sleep
require_command stat
require_command timeout
require_command tr

require_positive_integer APOLYSIS_PROJECTION_PULL_TIMEOUT_SECONDS "$pull_timeout_seconds"
require_positive_integer APOLYSIS_PROJECTION_START_TIMEOUT_SECONDS "$start_timeout_seconds"
require_positive_integer APOLYSIS_PROJECTION_BUILD_TIMEOUT_SECONDS "$build_timeout_seconds"
require_positive_integer APOLYSIS_PROJECTION_TEST_TIMEOUT_SECONDS "$test_timeout_seconds"
require_positive_integer APOLYSIS_PROJECTION_DRIVER_TIMEOUT_SECONDS "$driver_timeout_seconds"
require_positive_integer APOLYSIS_PROJECTION_STOP_TIMEOUT_SECONDS "$stop_timeout_seconds"

# Docker is the only host privilege needed. This gate never accepts DATABASE_URL
# or a caller-selected database and binds both generated databases to loopback.
if ! timeout 10s docker info >/dev/null 2>&1; then
    printf 'error: Docker daemon is unavailable or inaccessible\n' >&2
    exit 1
fi

umask 077
readonly random_suffix="$(random_hex 8)"
readonly ownership_label_key="io.apolysis.projection-qualification"
readonly ownership_label="${ownership_label_key}=${random_suffix}"
readonly primary_container="apolysis-projection-primary-${random_suffix}"
readonly restore_container="apolysis-projection-restore-${random_suffix}"
readonly primary_volume="apolysis-projection-primary-data-${random_suffix}"
readonly restore_volume="apolysis-projection-restore-data-${random_suffix}"
readonly primary_database="apolysis_primary_${random_suffix}"
readonly restore_database="apolysis_restore_${random_suffix}"
readonly primary_user="apolysis_primary_${random_suffix}"
readonly restore_user="apolysis_restore_${random_suffix}"
readonly primary_password="$(random_hex 24)"
readonly restore_password="$(random_hex 24)"
readonly private_directory="$(mktemp -d /tmp/apolysis-projection-postgres.XXXXXXXX)"
trap 'status=$?; trap - EXIT; rm -rf -- "$private_directory" || exit 1; exit "$status"' EXIT
readonly log_directory="${private_directory}/logs"
readonly primary_env_file="${private_directory}/primary.env"
readonly restore_env_file="${private_directory}/restore.env"
readonly primary_url_file="${private_directory}/primary.url"
readonly restore_url_file="${private_directory}/restore.url"
readonly primary_state_file="${private_directory}/primary-state.json"
readonly restore_state_file="${private_directory}/restore-state.json"
readonly postcommit_marker="${private_directory}/postcommit.marker"
readonly bearer_pattern_file="${private_directory}/bearer-patterns"
readonly dump_file="${private_directory}/projection.dump"
readonly dump_plaintext_file="${private_directory}/projection-dump.sql"
readonly restore_plaintext_file="${private_directory}/restore-database.sql"
readonly leak_pattern_file="${private_directory}/leak-patterns"
readonly artifact_leak_pattern_file="${private_directory}/artifact-leak-patterns"
readonly background_output_blocks=$(((MAX_STAGE_OUTPUT_BYTES + 1023) / 1024))
mkdir -m 700 -- "$log_directory"
chmod 700 -- "$private_directory"
: >"$bearer_pattern_file"
chmod 600 -- "$bearer_pattern_file"

declare -A active_child_pids=()
primary_container_owned=0
restore_container_owned=0
primary_volume_owned=0
restore_volume_owned=0
primary_container_id=""
restore_container_id=""
primary_paused=0

stop_owned_children() {
    local pid

    for pid in "${!active_child_pids[@]}"; do
        kill -TERM "$pid" >/dev/null 2>&1 || true
    done
    for _ in {1..20}; do
        if ((${#active_child_pids[@]} == 0)); then
            break
        fi
        local any_running=0
        for pid in "${!active_child_pids[@]}"; do
            if kill -0 "$pid" >/dev/null 2>&1; then
                any_running=1
            else
                wait "$pid" >/dev/null 2>&1 || true
                unset 'active_child_pids[$pid]'
            fi
        done
        if ((any_running == 0)); then
            break
        fi
        sleep 0.1
    done
    for pid in "${!active_child_pids[@]}"; do
        kill -KILL "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
        unset 'active_child_pids[$pid]'
    done
}

remove_owned_resources() {
    local observed_id
    local observed_label

    observed_id="$(timeout 5s docker container inspect \
        --format '{{.Id}}' "$primary_container" 2>/dev/null || true)"
    observed_label="$(timeout 5s docker container inspect \
        --format "{{ index .Config.Labels \"${ownership_label_key}\" }}" \
        "$primary_container" 2>/dev/null || true)"
    if [[ "$observed_label" == "$random_suffix" \
        && ( -z "$primary_container_id" || "$observed_id" == "$primary_container_id" ) ]]; then
        if timeout 20s docker rm --force "$observed_id" >/dev/null 2>&1; then
            primary_container_owned=0
        fi
    fi

    observed_id="$(timeout 5s docker container inspect \
        --format '{{.Id}}' "$restore_container" 2>/dev/null || true)"
    observed_label="$(timeout 5s docker container inspect \
        --format "{{ index .Config.Labels \"${ownership_label_key}\" }}" \
        "$restore_container" 2>/dev/null || true)"
    if [[ "$observed_label" == "$random_suffix" \
        && ( -z "$restore_container_id" || "$observed_id" == "$restore_container_id" ) ]]; then
        if timeout 20s docker rm --force "$observed_id" >/dev/null 2>&1; then
            restore_container_owned=0
        fi
    fi

    observed_label="$(timeout 5s docker volume inspect \
        --format "{{ index .Labels \"${ownership_label_key}\" }}" \
        "$primary_volume" 2>/dev/null || true)"
    if [[ "$observed_label" == "$random_suffix" ]]; then
        if timeout 20s docker volume rm --force "$primary_volume" >/dev/null 2>&1; then
            primary_volume_owned=0
        fi
    fi

    observed_label="$(timeout 5s docker volume inspect \
        --format "{{ index .Labels \"${ownership_label_key}\" }}" \
        "$restore_volume" 2>/dev/null || true)"
    if [[ "$observed_label" == "$random_suffix" ]]; then
        if timeout 20s docker volume rm --force "$restore_volume" >/dev/null 2>&1; then
            restore_volume_owned=0
        fi
    fi
}

ensure_owned_primary_unpaused() {
    local observed_id
    local observed_label
    local observed_paused

    observed_id="$(timeout 5s docker container inspect \
        --format '{{.Id}}' "$primary_container" 2>/dev/null || true)"
    observed_label="$(timeout 5s docker container inspect \
        --format "{{ index .Config.Labels \"${ownership_label_key}\" }}" \
        "$primary_container" 2>/dev/null || true)"
    observed_paused="$(timeout 5s docker container inspect \
        --format '{{.State.Paused}}' "$primary_container" 2>/dev/null || true)"
    if [[ "$observed_label" != "$random_suffix" \
        || ( -n "$primary_container_id" && "$observed_id" != "$primary_container_id" ) ]]; then
        return 0
    fi
    if [[ "$observed_paused" == true ]]; then
        timeout 10s docker unpause "$observed_id" >/dev/null 2>&1 || return 1
    elif [[ "$observed_paused" != false ]]; then
        return 1
    fi
    primary_paused=0
}

cleanup() {
    local exit_status=$?
    local cleanup_failed=0
    local cleanup_verified=0

    trap - EXIT INT TERM
    stop_owned_children
    for _ in 1 2; do
        if ! ensure_owned_primary_unpaused; then
            cleanup_failed=1
        fi
        remove_owned_resources
        if verify_owned_resources_removed; then
            cleanup_verified=1
            break
        fi
    done
    if ((cleanup_verified == 0)); then
        cleanup_failed=1
    fi
    if ! rm -rf -- "$private_directory" || [[ -e "$private_directory" ]]; then
        cleanup_failed=1
    fi
    if ((cleanup_failed != 0)); then
        printf 'error: stage=cleanup verification_failed\n' >&2
        exit 1
    fi
    exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

bounded_file() {
    local path="$1"
    local size

    size="$(stat -c '%s' -- "$path")" || return 1
    [[ "$size" =~ ^[0-9]+$ ]] || return 1
    ((size <= MAX_STAGE_OUTPUT_BYTES))
}

stage_log_path() {
    local stage="$1"

    if [[ ! "$stage" =~ ^[a-z0-9_]+$ ]]; then
        return 1
    fi
    printf '%s/%s.log\n' "$log_directory" "$stage"
}

run_stage() {
    local stage="$1"
    local timeout_seconds="$2"
    shift 2
    local log_path
    local exit_status

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    if (
        set -o pipefail
        timeout --kill-after=15s "${timeout_seconds}s" "$@" 2>&1 | {
            set +e
            head -c "$((MAX_STAGE_OUTPUT_BYTES + 1))" >"$log_path"
            head_status=$?
            cat >/dev/null
            drain_status=$?
            if ((head_status != 0)); then
                exit "$head_status"
            fi
            exit "$drain_status"
        }
    ); then
        exit_status=0
    else
        exit_status=$?
    fi
    if ((exit_status != 0)); then
        printf 'error: stage=%s exit_status=%s\n' "$stage" "$exit_status" >&2
        grep -E -m 1 '^stage=[a-z0-9_]+$' "$log_path" >&2 || true
        grep -E -m 10 '^test [A-Za-z0-9_:]+ \.\.\. FAILED$' "$log_path" >&2 || true
        return 1
    fi
    if ! bounded_file "$log_path"; then
        printf 'error: stage=%s output_exceeded_bound\n' "$stage" >&2
        return 1
    fi
    printf 'stage=%s status=passed\n' "$stage"
}

run_capped_artifact_stage() {
    local stage="$1"
    local timeout_seconds="$2"
    local max_bytes="$3"
    shift 3
    local file_blocks=$(((max_bytes + 1023) / 1024))

    run_stage "$stage" "$timeout_seconds" \
        bash -c '
            set -Eeuo pipefail
            file_blocks="$1"
            shift
            ulimit -f "$file_blocks"
            exec "$@"
        ' _ "$file_blocks" "$@"
}

write_container_environment() {
    local path="$1"
    local database="$2"
    local user="$3"
    local password="$4"

    {
        printf 'POSTGRES_DB=%s\n' "$database"
        printf 'POSTGRES_USER=%s\n' "$user"
        printf 'POSTGRES_PASSWORD=%s\n' "$password"
        printf 'POSTGRES_INITDB_ARGS=--data-checksums\n'
    } >"$path"
    chmod 600 -- "$path"
}

create_volume() {
    local stage="$1"
    local volume="$2"
    local owned_variable="$3"

    run_stage "$stage" 30 docker volume create \
        --label "$ownership_label" \
        "$volume"
    local observed_label
    observed_label="$(timeout 5s docker volume inspect \
        --format "{{ index .Labels \"${ownership_label_key}\" }}" \
        "$volume" 2>/dev/null || true)"
    if [[ "$observed_label" != "$random_suffix" ]]; then
        printf 'error: stage=%s ownership_label_mismatch\n' "$stage" >&2
        return 1
    fi
    printf -v "$owned_variable" '%s' 1
}

start_new_container() {
    local stage="$1"
    local container="$2"
    local volume="$3"
    local env_file="$4"
    local owned_variable="$5"
    local id_variable="$6"

    run_stage "$stage" 45 docker run \
        --detach \
        --name "$container" \
        --label "$ownership_label" \
        --env-file "$env_file" \
        --mount "type=volume,source=${volume},target=/var/lib/postgresql/data" \
        --publish '127.0.0.1::5432' \
        "$POSTGRES_IMAGE" \
        -c fsync=on \
        -c synchronous_commit=on \
        -c full_page_writes=on \
        -c client_connection_check_interval=1s \
        -c checkpoint_timeout=1h
    local observed_id
    local observed_label
    observed_id="$(timeout 5s docker container inspect \
        --format '{{.Id}}' "$container" 2>/dev/null || true)"
    observed_label="$(timeout 5s docker container inspect \
        --format "{{ index .Config.Labels \"${ownership_label_key}\" }}" \
        "$container" 2>/dev/null || true)"
    if [[ ! "$observed_id" =~ ^[0-9a-f]{64}$ || "$observed_label" != "$random_suffix" ]]; then
        printf 'error: stage=%s ownership_identity_mismatch\n' "$stage" >&2
        return 1
    fi
    printf -v "$id_variable" '%s' "$observed_id"
    printf -v "$owned_variable" '%s' 1
}

verify_resource_names_available() {
    local log_path
    local existing_primary_container
    local existing_restore_container
    local existing_primary_volume
    local existing_restore_volume

    log_path="$(stage_log_path resource_name_preflight)"
    : >"$log_path"
    chmod 600 -- "$log_path"
    if ! existing_primary_container="$(timeout 10s docker container ls --all \
        --filter "name=^/${primary_container}$" --format '{{.Names}}' 2>"$log_path")" \
        || ! existing_restore_container="$(timeout 10s docker container ls --all \
            --filter "name=^/${restore_container}$" --format '{{.Names}}' 2>>"$log_path")" \
        || ! existing_primary_volume="$(timeout 10s docker volume ls \
            --filter "name=^${primary_volume}$" --format '{{.Name}}' 2>>"$log_path")" \
        || ! existing_restore_volume="$(timeout 10s docker volume ls \
            --filter "name=^${restore_volume}$" --format '{{.Name}}' 2>>"$log_path")"; then
        printf 'error: stage=resource_name_preflight inventory_failed\n' >&2
        return 1
    fi
    if [[ -n "$existing_primary_container" || -n "$existing_restore_container" \
        || -n "$existing_primary_volume" || -n "$existing_restore_volume" ]]; then
        printf 'error: stage=resource_name_preflight collision\n' >&2
        return 1
    fi
    printf 'stage=resource_name_preflight status=passed\n'
}

wait_for_database() {
    local stage="$1"
    local container="$2"
    local user="$3"
    local database="$4"
    local log_path
    local deadline=$((SECONDS + start_timeout_seconds))

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    until timeout 5s docker exec "$container" \
        psql -X --no-psqlrc --username "$user" --dbname "$database" \
        --tuples-only --no-align --command 'SELECT 1' >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            printf 'error: stage=%s readiness_timeout\n' "$stage" >&2
            return 1
        fi
        sleep 0.5
    done
    if ! bounded_file "$log_path"; then
        printf 'error: stage=%s output_exceeded_bound\n' "$stage" >&2
        return 1
    fi
    printf 'stage=%s status=passed\n' "$stage"
}

verify_durability_settings() {
    local stage="$1"
    local container="$2"
    local user="$3"
    local database="$4"
    local log_path
    local settings

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    if ! settings="$(timeout 10s docker exec "$container" \
        psql -X --no-psqlrc --username "$user" --dbname "$database" \
        --tuples-only --no-align --field-separator '|' --command \
        "SELECT current_setting('data_checksums'), current_setting('fsync'), current_setting('full_page_writes'), current_setting('synchronous_commit'), current_setting('client_connection_check_interval'), current_setting('checkpoint_timeout')" \
        2>/dev/null)"; then
        printf 'error: stage=%s settings_query_failed\n' "$stage" >&2
        return 1
    fi
    if [[ "$settings" != 'on|on|on|on|1s|1h' ]]; then
        printf 'error: stage=%s unsafe_postgres_settings\n' "$stage" >&2
        return 1
    fi
    printf 'stage=%s status=passed\n' "$stage"
}

write_database_url_file() {
    local stage="$1"
    local container="$2"
    local user="$3"
    local password="$4"
    local database="$5"
    local path="$6"
    local binding
    local log_path
    local temporary_path="${path}.tmp"
    local mode
    local links
    local size

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    if ! binding="$(timeout 5s docker port "$container" 5432/tcp 2>/dev/null)"; then
        printf 'error: stage=%s port_query_failed\n' "$stage" >&2
        return 1
    fi
    if [[ ! "$binding" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
        printf 'error: stage=%s non_loopback_binding\n' "$stage" >&2
        return 1
    fi
    rm -f -- "$temporary_path"
    printf 'postgresql://%s:%s@127.0.0.1:%s/%s\n' \
        "$user" "$password" "${BASH_REMATCH[1]}" "$database" >"$temporary_path"
    chmod 600 -- "$temporary_path"
    mode="$(stat -c '%a' -- "$temporary_path")"
    links="$(stat -c '%h' -- "$temporary_path")"
    size="$(stat -c '%s' -- "$temporary_path")"
    if [[ ! -f "$temporary_path" || -L "$temporary_path" || "$mode" != 600 \
        || "$links" != 1 || ! "$size" =~ ^[1-9][0-9]*$ || "$size" -gt 4096 ]]; then
        rm -f -- "$temporary_path"
        printf 'error: stage=%s private_url_permissions\n' "$stage" >&2
        return 1
    fi
    mv -f -- "$temporary_path" "$path"
    printf 'stage=%s status=passed\n' "$stage"
}

readonly cargo_target_directory="${CARGO_TARGET_DIR:-${repository_root}/target}"
readonly projection_driver="${cargo_target_directory}/debug/examples/${PROJECTION_DRIVER_EXAMPLE}"

run_driver_stage() {
    local stage="$1"
    local url_file="$2"
    local state_file="$3"
    local mode="$4"
    shift 4

    run_stage "$stage" "$driver_timeout_seconds" \
        env -u DATABASE_URL -u APOLYSIS_TEST_DATABASE_URL \
        -u PGDATABASE -u PGHOST -u PGPASSWORD -u PGPORT -u PGUSER \
        "$@" \
        APOLYSIS_TEST_DATABASE_URL_FILE="$url_file" \
        APOLYSIS_TEST_BEARER_PATTERN_FILE="$bearer_pattern_file" \
        APOLYSIS_PROJECTION_STATE_FILE="$state_file" \
        "$projection_driver" "$mode"
}

launch_driver_background() {
    local stage="$1"
    local url_file="$2"
    local state_file="$3"
    local mode="$4"
    shift 4
    local log_path

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    (
        ulimit -f "$background_output_blocks"
        exec env -u DATABASE_URL -u APOLYSIS_TEST_DATABASE_URL \
            -u PGDATABASE -u PGHOST -u PGPASSWORD -u PGPORT -u PGUSER \
            "$@" \
            APOLYSIS_TEST_DATABASE_URL_FILE="$url_file" \
            APOLYSIS_TEST_BEARER_PATTERN_FILE="$bearer_pattern_file" \
            APOLYSIS_PROJECTION_STATE_FILE="$state_file" \
            "$projection_driver" "$mode"
    ) >"$log_path" 2>&1 &
    background_pid=$!
    active_child_pids["$background_pid"]="$stage"
}

wait_for_background_success() {
    local pid="$1"
    local stage="$2"
    local deadline=$((SECONDS + driver_timeout_seconds))
    local exit_status
    local log_path

    while kill -0 "$pid" >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            kill -KILL "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
            unset 'active_child_pids[$pid]'
            printf 'error: stage=%s timeout\n' "$stage" >&2
            return 1
        fi
        sleep 0.1
    done
    if wait "$pid" >/dev/null 2>&1; then
        exit_status=0
    else
        exit_status=$?
    fi
    unset 'active_child_pids[$pid]'
    log_path="$(stage_log_path "$stage")"
    if ((exit_status != 0)); then
        printf 'error: stage=%s exit_status=%s\n' "$stage" "$exit_status" >&2
        return 1
    fi
    if ! bounded_file "$log_path"; then
        printf 'error: stage=%s output_exceeded_bound\n' "$stage" >&2
        return 1
    fi
    printf 'stage=%s status=passed\n' "$stage"
}

assert_background_processes_alive() {
    local stage="$1"
    shift
    local pid

    for pid in "$@"; do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            printf 'error: stage=%s driver_not_concurrent\n' "$stage" >&2
            return 1
        fi
    done
    printf 'stage=%s status=passed\n' "$stage"
}

kill_background_after_barrier() {
    local pid="$1"
    local stage="$2"
    local log_path
    local exit_status

    if ! kill -KILL "$pid" >/dev/null 2>&1; then
        printf 'error: stage=%s process_exited_before_kill\n' "$stage" >&2
        return 1
    fi
    if wait "$pid" >/dev/null 2>&1; then
        exit_status=0
    else
        exit_status=$?
    fi
    unset 'active_child_pids[$pid]'
    if ((exit_status == 0)); then
        printf 'error: stage=%s killed_process_reported_success\n' "$stage" >&2
        return 1
    fi
    log_path="$(stage_log_path "$stage")"
    if ! bounded_file "$log_path"; then
        printf 'error: stage=%s output_exceeded_bound\n' "$stage" >&2
        return 1
    fi
    printf 'stage=%s status=passed\n' "$stage"
}

wait_for_sleeping_trigger() {
    local stage="$1"
    local deadline=$((SECONDS + driver_timeout_seconds))
    local log_path
    local sleeping_count

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    while ((SECONDS < deadline)); do
        if sleeping_count="$(timeout 5s docker exec "$primary_container" \
            psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
            --tuples-only --no-align --command \
            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep' AND query LIKE 'INSERT INTO apolysis_projection.commits%'" \
            2>/dev/null)" \
            && [[ "$sleeping_count" =~ ^[1-9][0-9]*$ ]]; then
            printf 'stage=%s status=passed\n' "$stage"
            return 0
        fi
        sleep 0.1
    done
    printf 'error: stage=%s trigger_barrier_timeout\n' "$stage" >&2
    return 1
}

wait_for_private_marker() {
    local stage="$1"
    local path="$2"
    local deadline=$((SECONDS + driver_timeout_seconds))
    local mode
    local links
    local size

    while ((SECONDS < deadline)); do
        if [[ -f "$path" && ! -L "$path" ]]; then
            mode="$(stat -c '%a' -- "$path")"
            links="$(stat -c '%h' -- "$path")"
            size="$(stat -c '%s' -- "$path")"
            if [[ "$mode" == 600 && "$links" == 1 && "$size" =~ ^[1-9][0-9]*$ && "$size" -le 64 ]]; then
                printf 'stage=%s status=passed\n' "$stage"
                return 0
            fi
            printf 'error: stage=%s marker_permissions\n' "$stage" >&2
            return 1
        fi
        sleep 0.1
    done
    printf 'error: stage=%s marker_timeout\n' "$stage" >&2
    return 1
}

capture_wal_lsn() {
    local stage="$1"
    local log_path
    local lsn

    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    if ! lsn="$(timeout 10s docker exec "$primary_container" \
        psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
        --tuples-only --no-align --command 'SELECT pg_current_wal_insert_lsn()' \
        2>/dev/null)"; then
        printf 'error: stage=%s lsn_query_failed\n' "$stage" >&2
        return 1
    fi
    if [[ ! "$lsn" =~ ^[0-9A-F]+/[0-9A-F]+$ ]]; then
        printf 'error: stage=%s invalid_lsn\n' "$stage" >&2
        return 1
    fi
    captured_wal_lsn="$lsn"
    printf 'stage=%s status=passed\n' "$stage"
}

assert_wal_lsn_order() {
    local stage="$1"
    local older_lsn="$2"
    local newer_lsn="$3"
    local operator="$4"
    local log_path
    local advanced

    if [[ ! "$older_lsn" =~ ^[0-9A-F]+/[0-9A-F]+$ \
        || ! "$newer_lsn" =~ ^[0-9A-F]+/[0-9A-F]+$ \
        || ("$operator" != '>' && "$operator" != '>=') ]]; then
        printf 'error: stage=%s invalid_lsn_comparison\n' "$stage" >&2
        return 1
    fi
    log_path="$(stage_log_path "$stage")"
    : >"$log_path"
    chmod 600 -- "$log_path"
    if ! advanced="$(timeout 10s docker exec "$primary_container" \
        psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
        --tuples-only --no-align --command \
        "SELECT '${newer_lsn}'::pg_lsn ${operator} '${older_lsn}'::pg_lsn" \
        2>/dev/null)"; then
        printf 'error: stage=%s lsn_comparison_failed\n' "$stage" >&2
        return 1
    fi
    if [[ "$advanced" != t ]]; then
        printf 'error: stage=%s lsn_did_not_advance\n' "$stage" >&2
        return 1
    fi
    printf 'stage=%s status=passed\n' "$stage"
}

verify_wal_recovery_log() {
    local since="$1"
    local log_path

    run_stage wal_recovery_log_capture 15 \
        docker logs --since "$since" "$primary_container"
    log_path="$(stage_log_path wal_recovery_log_capture)"
    if ! grep -F -q 'database system was interrupted' "$log_path" \
        || ! grep -F -q 'redo starts at' "$log_path" \
        || ! grep -F -q 'redo done at' "$log_path"; then
        printf 'error: stage=wal_recovery_evidence recovery_marker_missing\n' >&2
        return 1
    fi
    if ! bounded_file "$log_path"; then
        printf 'error: stage=wal_recovery_evidence output_exceeded_bound\n' >&2
        return 1
    fi
    printf 'stage=wal_recovery_evidence status=passed\n'
}

verify_graceful_shutdown() {
    local since="$1"
    local log_path
    local exit_code

    if ! exit_code="$(timeout 5s docker container inspect \
        --format '{{.State.ExitCode}}' "$primary_container" 2>/dev/null)"; then
        printf 'error: stage=graceful_shutdown_evidence inspect_failed\n' >&2
        return 1
    fi
    if [[ "$exit_code" != 0 ]]; then
        printf 'error: stage=graceful_shutdown_evidence unclean_exit\n' >&2
        return 1
    fi
    run_stage graceful_shutdown_log_capture 15 \
        docker logs --since "$since" "$primary_container"
    log_path="$(stage_log_path graceful_shutdown_log_capture)"
    if ! grep -F -q 'database system is shut down' "$log_path"; then
        printf 'error: stage=graceful_shutdown_evidence clean_marker_missing\n' >&2
        return 1
    fi
    printf 'stage=graceful_shutdown_evidence status=passed\n'
}

scan_for_leaks() {
    local stage_log="${log_directory}/leak_scan.log"
    local scan_status
    local pattern
    local bearer_count=0
    declare -A observed_bearers=()

    while IFS= read -r pattern; do
        if [[ ! "$pattern" =~ ^lease_[0-9a-f]{64}$ \
            || -n "${observed_bearers[$pattern]+present}" ]]; then
            printf 'error: stage=leak_scan invalid_bearer_inventory\n' >&2
            return 1
        fi
        observed_bearers["$pattern"]=1
        ((bearer_count += 1))
    done <"$bearer_pattern_file"
    if ((bearer_count <= 5)); then
        printf 'error: stage=leak_scan incomplete_bearer_inventory\n' >&2
        return 1
    fi

    {
        printf '%s\n' "$primary_password"
        printf '%s\n' "$restore_password"
        tr -d '\r\n' <"$primary_url_file"
        printf '\n'
        tr -d '\r\n' <"$restore_url_file"
        printf '\n'
        cat -- "$bearer_pattern_file"
    } >"$leak_pattern_file"
    chmod 600 -- "$leak_pattern_file"
    : >"$artifact_leak_pattern_file"
    while IFS= read -r pattern; do
        [[ -n "$pattern" ]] || continue
        printf '%s\n' "$pattern" >>"$artifact_leak_pattern_file"
        printf '%s' "$pattern" | od -An -tx1 | tr -d '[:space:]' \
            >>"$artifact_leak_pattern_file"
        printf '\n' >>"$artifact_leak_pattern_file"
    done <"$leak_pattern_file"
    chmod 600 -- "$artifact_leak_pattern_file"
    : >"$stage_log"
    chmod 600 -- "$stage_log"

    set +e
    LC_ALL=C grep -a -r -F -f "$artifact_leak_pattern_file" \
        --exclude='leak_scan.log' \
        -- "$log_directory" "$primary_state_file" "$restore_state_file" \
        "$dump_file" "$dump_plaintext_file" "$restore_plaintext_file" \
        >/dev/null 2>&1
    scan_status=$?
    set -e
    if ((scan_status == 0)); then
        printf 'error: stage=leak_scan private_artifact_match\n' >&2
        return 1
    fi
    if ((scan_status != 1)); then
        printf 'error: stage=leak_scan private_artifact_scan_failed\n' >&2
        return 1
    fi

    set +e
    LC_ALL=C grep -r -I -F -f "$leak_pattern_file" \
        --exclude-dir=.git --exclude-dir=target -- "$repository_root" \
        >/dev/null 2>&1
    scan_status=$?
    set -e
    if ((scan_status == 0)); then
        printf 'error: stage=leak_scan repository_match\n' >&2
        return 1
    fi
    if ((scan_status != 1)); then
        printf 'error: stage=leak_scan repository_scan_failed\n' >&2
        return 1
    fi
    if ! bounded_file "$stage_log"; then
        printf 'error: stage=leak_scan output_exceeded_bound\n' >&2
        return 1
    fi
    printf 'stage=leak_scan status=passed\n'
}

verify_owned_resources_removed() {
    local labeled_containers
    local labeled_volumes
    local named_primary_container
    local named_restore_container
    local named_primary_volume
    local named_restore_volume

    if ! labeled_containers="$(timeout 10s docker container ls --all \
        --filter "label=${ownership_label}" --format '{{.ID}}' 2>/dev/null)" \
        || ! labeled_volumes="$(timeout 10s docker volume ls \
            --filter "label=${ownership_label}" --format '{{.Name}}' 2>/dev/null)" \
        || ! named_primary_container="$(timeout 10s docker container ls --all \
            --filter "name=^/${primary_container}$" --format '{{.Names}}' 2>/dev/null)" \
        || ! named_restore_container="$(timeout 10s docker container ls --all \
            --filter "name=^/${restore_container}$" --format '{{.Names}}' 2>/dev/null)" \
        || ! named_primary_volume="$(timeout 10s docker volume ls \
            --filter "name=^${primary_volume}$" --format '{{.Name}}' 2>/dev/null)" \
        || ! named_restore_volume="$(timeout 10s docker volume ls \
            --filter "name=^${restore_volume}$" --format '{{.Name}}' 2>/dev/null)"; then
        printf 'error: stage=cleanup inventory_failed\n' >&2
        return 1
    fi
    if [[ -n "$labeled_containers" || -n "$labeled_volumes" \
        || -n "$named_primary_container" || -n "$named_restore_container" \
        || -n "$named_primary_volume" || -n "$named_restore_volume" ]]; then
        printf 'error: stage=cleanup owned_resource_remains\n' >&2
        return 1
    fi
    return 0
}

write_container_environment \
    "$primary_env_file" "$primary_database" "$primary_user" "$primary_password"
write_container_environment \
    "$restore_env_file" "$restore_database" "$restore_user" "$restore_password"

run_stage pull_postgres "$pull_timeout_seconds" docker pull "$POSTGRES_IMAGE"
verify_resource_names_available
create_volume create_primary_volume "$primary_volume" primary_volume_owned
create_volume create_restore_volume "$restore_volume" restore_volume_owned
start_new_container \
    start_primary "$primary_container" "$primary_volume" "$primary_env_file" \
    primary_container_owned primary_container_id
wait_for_database \
    primary_ready "$primary_container" "$primary_user" "$primary_database"
verify_durability_settings \
    primary_durability_settings "$primary_container" "$primary_user" "$primary_database"
write_database_url_file \
    primary_url "$primary_container" "$primary_user" "$primary_password" \
    "$primary_database" "$primary_url_file"
rm -f -- "$primary_env_file"

run_stage reject_unsentinel_database "$test_timeout_seconds" \
    bash -c '
        set -Eeuo pipefail
        url_file="$1"
        unset DATABASE_URL PGDATABASE PGHOST PGPASSWORD PGPORT PGUSER
        unset APOLYSIS_TEST_DATABASE_URL
        if APOLYSIS_TEST_DATABASE_URL_FILE="$url_file" \
            cargo test --locked -p apolysis-projection-postgres \
                --test postgres_projection \
                lifecycle_projection::genuine_open_run_projects_lifecycle_and_exact_retry_adds_nothing \
                -- --ignored --exact; then
            exit 1
        fi
    ' _ "$primary_url_file"
run_stage verify_unsentinel_database_untouched 30 \
    bash -c '
        set -Eeuo pipefail
        container="$1"
        user="$2"
        database="$3"
        untouched="$(docker exec "$container" \
            psql -X --no-psqlrc --username "$user" --dbname "$database" \
            --tuples-only --no-align --set ON_ERROR_STOP=1 --command \
            "SELECT to_regnamespace('"'"'apolysis_gateway'"'"') IS NULL \
                AND to_regnamespace('"'"'apolysis_projection'"'"') IS NULL")"
        [[ "$untouched" == t ]]
    ' _ "$primary_container" "$primary_user" "$primary_database"

run_stage create_test_ownership_sentinel 30 \
    docker exec "$primary_container" \
    psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
    --set ON_ERROR_STOP=1 --command \
    "CREATE TABLE public.apolysis_projection_test_ownership (\
         singleton boolean PRIMARY KEY CHECK (singleton), \
         gate_version text NOT NULL CHECK (gate_version='v1'), \
         database_name text NOT NULL, \
         database_user text NOT NULL\
     ); \
     INSERT INTO public.apolysis_projection_test_ownership \
         (singleton, gate_version, database_name, database_user) \
     VALUES (true, 'v1', current_database(), current_user);"

run_stage projection_unit_suite "$test_timeout_seconds" \
    cargo test --locked -p apolysis-projection-postgres
run_stage ignored_integration_suite "$test_timeout_seconds" \
    bash -c '
        set -Eeuo pipefail
        url_file="$1"
        bearer_file="$2"
        unset DATABASE_URL PGDATABASE PGHOST PGPASSWORD PGPORT PGUSER
        unset APOLYSIS_TEST_DATABASE_URL
        export APOLYSIS_TEST_DATABASE_URL_FILE="$url_file"
        export APOLYSIS_TEST_BEARER_PATTERN_FILE="$bearer_file"
        exec cargo test --locked -p apolysis-projection-postgres \
            --test postgres_projection -- --ignored --test-threads=1
    ' _ "$primary_url_file" "$bearer_pattern_file"

run_stage drop_test_ownership_sentinel 30 \
    docker exec "$primary_container" \
    psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
    --set ON_ERROR_STOP=1 --command \
    'DROP TABLE public.apolysis_projection_test_ownership;'

run_stage build_projection_driver "$build_timeout_seconds" \
    cargo build --locked -p apolysis-projection-postgres \
    --example "$PROJECTION_DRIVER_EXAMPLE"
if [[ ! -x "$projection_driver" ]]; then
    printf 'error: stage=build_projection_driver executable_missing\n' >&2
    exit 1
fi

run_driver_stage seed_projection \
    "$primary_url_file" "$primary_state_file" seed

run_stage install_precommit_trigger 30 \
    docker exec "$primary_container" \
    psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
    --set ON_ERROR_STOP=1 --command \
    'CREATE FUNCTION apolysis_projection.qualification_hold_before_commit()
       RETURNS trigger LANGUAGE plpgsql AS $function$
       BEGIN
           PERFORM pg_sleep(300);
           RETURN NEW;
       END
     $function$;
     CREATE TRIGGER qualification_hold_before_commit
       BEFORE INSERT ON apolysis_projection.commits
       FOR EACH ROW EXECUTE FUNCTION apolysis_projection.qualification_hold_before_commit();'

launch_driver_background precommit_process \
    "$primary_url_file" "$primary_state_file" project-one
precommit_pid="$background_pid"
wait_for_sleeping_trigger precommit_trigger_barrier
kill_background_after_barrier "$precommit_pid" precommit_process

run_stage remove_precommit_trigger 30 \
    docker exec "$primary_container" \
    psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
    --set ON_ERROR_STOP=1 --command \
    'DROP TRIGGER qualification_hold_before_commit ON apolysis_projection.commits;
     DROP FUNCTION apolysis_projection.qualification_hold_before_commit();'
run_driver_stage verify_precommit_rollback \
    "$primary_url_file" "$primary_state_file" verify-zero

launch_driver_background postcommit_process \
    "$primary_url_file" "$primary_state_file" project-one \
    APOLYSIS_TEST_POST_COMMIT_MARKER="$postcommit_marker" \
    APOLYSIS_TEST_HOLD_AFTER_COMMIT=1
postcommit_pid="$background_pid"
wait_for_private_marker postcommit_barrier "$postcommit_marker"
kill_background_after_barrier "$postcommit_pid" postcommit_process

run_stage pause_primary_for_concurrency 30 docker pause "$primary_container"
primary_paused=1
concurrent_pids=()
for ordinal in $(seq 1 "$CONCURRENT_DRIVER_COUNT"); do
    stage="concurrent_driver_${ordinal}"
    launch_driver_background "$stage" \
        "$primary_url_file" "$primary_state_file" project-one
    concurrent_pids+=("$background_pid")
done
sleep 0.5
assert_background_processes_alive concurrent_process_barrier "${concurrent_pids[@]}"
run_stage release_concurrent_processes 30 docker unpause "$primary_container"
primary_paused=0
for index in "${!concurrent_pids[@]}"; do
    ordinal=$((index + 1))
    wait_for_background_success \
        "${concurrent_pids[$index]}" "concurrent_driver_${ordinal}"
done
run_driver_stage drain_after_concurrent_commits \
    "$primary_url_file" "$primary_state_file" project-until-idle
run_driver_stage verify_concurrent_completion \
    "$primary_url_file" "$primary_state_file" verify-complete

graceful_stop_since="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
if [[ ! "$graceful_stop_since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    printf 'error: stage=graceful_shutdown_evidence invalid_log_boundary\n' >&2
    exit 1
fi
run_stage graceful_stop_primary $((stop_timeout_seconds + 15)) \
    docker stop --time "$stop_timeout_seconds" "$primary_container"
verify_graceful_shutdown "$graceful_stop_since"
run_stage graceful_start_primary 30 docker start "$primary_container"
wait_for_database \
    graceful_restart_ready "$primary_container" "$primary_user" "$primary_database"
write_database_url_file \
    graceful_restart_url "$primary_container" "$primary_user" "$primary_password" \
    "$primary_database" "$primary_url_file"
run_driver_stage verify_graceful_restart \
    "$primary_url_file" "$primary_state_file" verify-complete

run_stage checkpoint_before_wal_crash 30 \
    docker exec "$primary_container" \
    psql -X --no-psqlrc --username "$primary_user" --dbname "$primary_database" \
    --set ON_ERROR_STOP=1 --command 'CHECKPOINT'
capture_wal_lsn capture_pre_append_lsn
pre_append_lsn="$captured_wal_lsn"
run_driver_stage append_before_wal_crash \
    "$primary_url_file" "$primary_state_file" append-and-project \
    APOLYSIS_TEST_APPEND_ORDINAL=3
run_driver_stage verify_pre_crash_append \
    "$primary_url_file" "$primary_state_file" verify-complete
capture_wal_lsn capture_post_append_lsn
post_append_lsn="$captured_wal_lsn"
assert_wal_lsn_order assert_append_advanced_wal \
    "$pre_append_lsn" "$post_append_lsn" '>'
wal_kill_since="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
if [[ ! "$wal_kill_since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    printf 'error: stage=wal_recovery_evidence invalid_log_boundary\n' >&2
    exit 1
fi
run_stage abrupt_kill_primary 30 \
    docker kill --signal KILL "$primary_container"
run_stage wal_recovery_start_primary 30 docker start "$primary_container"
wait_for_database \
    wal_recovery_ready "$primary_container" "$primary_user" "$primary_database"
write_database_url_file \
    wal_recovery_url "$primary_container" "$primary_user" "$primary_password" \
    "$primary_database" "$primary_url_file"
verify_wal_recovery_log "$wal_kill_since"
run_driver_stage verify_wal_recovery \
    "$primary_url_file" "$primary_state_file" verify-complete
capture_wal_lsn capture_recovered_lsn
recovered_lsn="$captured_wal_lsn"
assert_wal_lsn_order assert_recovered_wal_position \
    "$post_append_lsn" "$recovered_lsn" '>='
run_driver_stage append_after_wal_recovery \
    "$primary_url_file" "$primary_state_file" append-and-project \
    APOLYSIS_TEST_APPEND_ORDINAL=4
run_driver_stage verify_append_after_wal_recovery \
    "$primary_url_file" "$primary_state_file" verify-complete
capture_wal_lsn capture_post_recovery_append_lsn
post_recovery_append_lsn="$captured_wal_lsn"
assert_wal_lsn_order assert_post_recovery_append_advanced_wal \
    "$recovered_lsn" "$post_recovery_append_lsn" '>'
run_stage primary_pg_amcheck "$driver_timeout_seconds" \
    docker exec "$primary_container" \
    pg_amcheck --install-missing --username "$primary_user" --database "$primary_database"

: >"$dump_file"
chmod 600 -- "$dump_file"
run_capped_artifact_stage create_custom_dump "$driver_timeout_seconds" \
    "$MAX_DUMP_BYTES" \
    bash -c '
        set -Eeuo pipefail
        container="$1"
        user="$2"
        database="$3"
        dump_file="$4"
        docker exec "$container" pg_dump \
            --username "$user" --dbname "$database" \
            --format=custom --compress=6 --no-owner --no-privileges >"$dump_file"
    ' _ "$primary_container" "$primary_user" "$primary_database" "$dump_file"
dump_size="$(stat -c '%s' -- "$dump_file")"
if [[ ! "$dump_size" =~ ^[1-9][0-9]*$ ]] || ((dump_size > MAX_DUMP_BYTES)); then
    printf 'error: stage=create_custom_dump invalid_size\n' >&2
    exit 1
fi

start_new_container \
    start_restore "$restore_container" "$restore_volume" "$restore_env_file" \
    restore_container_owned restore_container_id
wait_for_database \
    restore_ready "$restore_container" "$restore_user" "$restore_database"
verify_durability_settings \
    restore_durability_settings "$restore_container" "$restore_user" "$restore_database"
write_database_url_file \
    restore_url "$restore_container" "$restore_user" "$restore_password" \
    "$restore_database" "$restore_url_file"
rm -f -- "$restore_env_file"

run_stage prepare_clean_restore 30 \
    docker exec "$restore_container" \
    psql -X --no-psqlrc --username "$restore_user" --dbname "$restore_database" \
    --set ON_ERROR_STOP=1 --command \
    'CREATE SCHEMA apolysis_gateway; CREATE SCHEMA apolysis_projection;'
run_stage clean_restore_custom_dump "$driver_timeout_seconds" \
    bash -c '
        set -Eeuo pipefail
        container="$1"
        user="$2"
        database="$3"
        dump_file="$4"
        docker exec --interactive "$container" pg_restore \
            --username "$user" --dbname "$database" \
            --clean --if-exists --no-owner --no-privileges \
            --exit-on-error --single-transaction <"$dump_file"
    ' _ "$restore_container" "$restore_user" "$restore_database" "$dump_file"

cp -- "$primary_state_file" "$restore_state_file"
chmod 600 -- "$restore_state_file"
run_driver_stage verify_restored_database \
    "$restore_url_file" "$restore_state_file" verify-complete
run_driver_stage append_after_restore \
    "$restore_url_file" "$restore_state_file" append-and-project \
    APOLYSIS_TEST_APPEND_ORDINAL=5
run_driver_stage verify_append_after_restore \
    "$restore_url_file" "$restore_state_file" verify-complete
run_stage restore_pg_amcheck "$driver_timeout_seconds" \
    docker exec "$restore_container" \
    pg_amcheck --install-missing --username "$restore_user" --database "$restore_database"

: >"$dump_plaintext_file"
chmod 600 -- "$dump_plaintext_file"
run_capped_artifact_stage render_custom_dump_for_leak_scan "$driver_timeout_seconds" \
    "$MAX_DUMP_BYTES" \
    bash -c '
        set -Eeuo pipefail
        container="$1"
        dump_file="$2"
        plaintext_file="$3"
        docker exec --interactive "$container" pg_restore --file=- \
            <"$dump_file" >"$plaintext_file"
    ' _ "$restore_container" "$dump_file" "$dump_plaintext_file"
dump_plaintext_size="$(stat -c '%s' -- "$dump_plaintext_file")"
if [[ ! "$dump_plaintext_size" =~ ^[1-9][0-9]*$ ]] \
    || ((dump_plaintext_size > MAX_DUMP_BYTES)); then
    printf 'error: stage=render_custom_dump_for_leak_scan invalid_size\n' >&2
    exit 1
fi

: >"$restore_plaintext_file"
chmod 600 -- "$restore_plaintext_file"
run_capped_artifact_stage render_restore_database_for_leak_scan \
    "$driver_timeout_seconds" "$MAX_DUMP_BYTES" \
    bash -c '
        set -Eeuo pipefail
        container="$1"
        user="$2"
        database="$3"
        plaintext_file="$4"
        docker exec "$container" pg_dump \
            --username "$user" --dbname "$database" \
            --format=plain --no-owner --no-privileges >"$plaintext_file"
    ' _ "$restore_container" "$restore_user" "$restore_database" \
    "$restore_plaintext_file"
restore_plaintext_size="$(stat -c '%s' -- "$restore_plaintext_file")"
if [[ ! "$restore_plaintext_size" =~ ^[1-9][0-9]*$ ]] \
    || ((restore_plaintext_size > MAX_DUMP_BYTES)); then
    printf 'error: stage=render_restore_database_for_leak_scan invalid_size\n' >&2
    exit 1
fi

scan_for_leaks

stop_owned_children
if ! ensure_owned_primary_unpaused; then
    printf 'error: stage=cleanup primary_unpause_failed\n' >&2
    exit 1
fi
remove_owned_resources
if ! verify_owned_resources_removed; then
    exit 1
fi
rm -rf -- "$private_directory"
if [[ -e "$private_directory" ]]; then
    printf 'error: stage=cleanup private_directory_remains\n' >&2
    exit 1
fi
trap - EXIT INT TERM
printf 'stage=cleanup status=passed\n'
printf 'PostgreSQL projection durability and recovery qualification passed.\n'

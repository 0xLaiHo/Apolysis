#!/usr/bin/env bash

set -Eeuo pipefail

# Keep this qualification database identical to the reviewed repository gate.
readonly DEFAULT_POSTGRES_IMAGE="postgres:16.14-alpine3.23@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3"
readonly ADVISORY_LOCK_KEY="4715382012602313076"

postgres_image="${APOLYSIS_POSTGRES_IMAGE-$DEFAULT_POSTGRES_IMAGE}"
gate_timeout_seconds="${APOLYSIS_POSTGRES_CRASH_TEST_TIMEOUT_SECONDS:-900}"
start_timeout_seconds="${APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS:-60}"
pull_timeout_seconds="${APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS:-300}"

if [[ "${APOLYSIS_POSTGRES_CRASH_INNER:-0}" != "1" ]]; then
    if ! command -v timeout >/dev/null 2>&1; then
        printf 'error: required command not found: timeout\n' >&2
        exit 1
    fi
    if [[ ! "$gate_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: APOLYSIS_POSTGRES_CRASH_TEST_TIMEOUT_SECONDS must be a positive integer\n' >&2
        exit 1
    fi
    export APOLYSIS_POSTGRES_CRASH_INNER=1
    # Keep the gate and every fault-injection child in timeout's process group.
    # The inner EXIT trap receives TERM and has a bounded cleanup window before
    # timeout escalates the whole group to KILL.
    exec timeout --kill-after=30s "${gate_timeout_seconds}s" "$0" "$@"
fi

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: %s must be a positive integer\n' "$name" >&2
        exit 1
    fi
}

random_hex() {
    local bytes="$1"
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d '[:space:]'
}

for command in bash cargo date docker grep jq mktemp od openssl rustc sed sleep stat timeout tr; do
    require_command "$command"
done
require_positive_integer APOLYSIS_POSTGRES_CRASH_TEST_TIMEOUT_SECONDS "$gate_timeout_seconds"
require_positive_integer APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS "$start_timeout_seconds"
require_positive_integer APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS "$pull_timeout_seconds"
if [[ -z "$postgres_image" ]]; then
    printf 'error: APOLYSIS_POSTGRES_IMAGE must not be empty\n' >&2
    exit 1
fi
if ! timeout --foreground 10s docker info >/dev/null 2>&1; then
    printf 'error: Docker daemon is unavailable or inaccessible\n' >&2
    exit 1
fi

printf 'Building the real Gateway/PostgreSQL recovery driver...\n'
target_directory="$(cargo metadata --format-version 1 --no-deps | jq -er '.target_directory')" || {
    printf 'error: could not resolve the Cargo target directory\n' >&2
    exit 1
}
host_target="$(rustc -vV | sed -n 's/^host: //p')" || {
    printf 'error: could not resolve the native Rust target\n' >&2
    exit 1
}
if [[ ! "$target_directory" = /* ]] || [[ -z "$host_target" ]]; then
    printf 'error: invalid native Cargo artifact location\n' >&2
    exit 1
fi
readonly target_directory host_target
driver="${target_directory}/${host_target}/debug/examples/postgres_crash_driver"
readonly driver
rm -f -- "$driver"
cargo build --target "$host_target" -p apolysis-gateway-postgres \
    --example postgres_crash_driver
if [[ ! -x "$driver" ]]; then
    printf 'error: recovery driver was not built\n' >&2
    exit 1
fi

suffix="$(random_hex 8)" || {
    printf 'error: failed to generate a unique recovery-gate suffix\n' >&2
    exit 1
}
if [[ ! "$suffix" =~ ^[0-9a-f]{16}$ ]]; then
    printf 'error: recovery-gate suffix has invalid entropy\n' >&2
    exit 1
fi
readonly suffix
readonly container_name="apolysis-postgres-crash-${suffix}"
readonly volume_name="apolysis-postgres-crash-${suffix}"
readonly database_name="apolysis_crash_${suffix}"
readonly database_user="apolysis_crash_${suffix}"
database_password="$(random_hex 24)" || {
    printf 'error: failed to generate the recovery database credential\n' >&2
    exit 1
}
if [[ ! "$database_password" =~ ^[0-9a-f]{48}$ ]]; then
    printf 'error: recovery database credential has invalid entropy\n' >&2
    exit 1
fi
readonly database_password
control_directory="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-postgres-crash.XXXXXXXX")" || {
    printf 'error: failed to create the private recovery control directory\n' >&2
    exit 1
}
if [[ ! -d "$control_directory" ]]; then
    printf 'error: private recovery control directory was not created\n' >&2
    exit 1
fi
readonly control_directory
readonly container_env_file="${control_directory}/postgres.env"
readonly database_url_file="${control_directory}/database.url"
readonly replay_key_file="${control_directory}/replay.key"
readonly driver_log="${control_directory}/gateway-driver.log"
readonly postgres_log="${control_directory}/postgres-recovery.log"

driver_pid=""
lock_holder_pid=""
container_owned=0
volume_owned=0
gate_passed=0

cleanup() {
    local exit_status=$?
    local cleanup_failed=0
    trap - EXIT INT TERM
    for pid in "$driver_pid" "$lock_holder_pid"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill -KILL "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done
    if [[ "$container_owned" == "1" ]]; then
        timeout --foreground 8s docker rm --force "$container_name" >/dev/null 2>&1 || true
        remaining_containers="$(timeout --foreground 3s docker container ls --all --format '{{.Names}}')" || {
            cleanup_failed=1
            remaining_containers=""
        }
        if grep -Fxq -- "$container_name" <<<"$remaining_containers"; then
            cleanup_failed=1
        fi
    fi
    if [[ "$volume_owned" == "1" ]]; then
        timeout --foreground 8s docker volume rm --force "$volume_name" >/dev/null 2>&1 || true
        remaining_volumes="$(timeout --foreground 3s docker volume ls --format '{{.Name}}')" || {
            cleanup_failed=1
            remaining_volumes=""
        }
        if grep -Fxq -- "$volume_name" <<<"$remaining_volumes"; then
            cleanup_failed=1
        fi
    fi
    if ! rm -rf -- "$control_directory"; then
        cleanup_failed=1
    fi
    if [[ "$cleanup_failed" == "1" ]]; then
        printf 'error: recovery gate could not remove all dedicated test state\n' >&2
        if [[ "$exit_status" == "0" ]]; then
            exit_status=1
        fi
    elif [[ "$exit_status" == "0" && "$gate_passed" == "1" ]]; then
        printf 'Real PostgreSQL process crash and WAL recovery gate passed.\n'
    fi
    exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

existing_containers="$(timeout --foreground 3s docker container ls --all --format '{{.Names}}')" || {
    printf 'error: could not verify recovery container-name availability\n' >&2
    exit 1
}
existing_volumes="$(timeout --foreground 3s docker volume ls --format '{{.Name}}')" || {
    printf 'error: could not verify recovery volume-name availability\n' >&2
    exit 1
}
if grep -Fxq -- "$container_name" <<<"$existing_containers" || \
    grep -Fxq -- "$volume_name" <<<"$existing_volumes"; then
    printf 'error: generated recovery resource name is already in use\n' >&2
    exit 1
fi

chmod 700 "$control_directory"
umask 077
{
    printf 'POSTGRES_DB=%s\n' "$database_name"
    printf 'POSTGRES_USER=%s\n' "$database_user"
    printf 'POSTGRES_PASSWORD=%s\n' "$database_password"
    printf 'POSTGRES_INITDB_ARGS=--data-checksums\n'
} >"$container_env_file"
openssl rand 32 >"$replay_key_file"
chmod 600 "$replay_key_file"
if [[ "$(stat -c '%s' "$replay_key_file")" != "32" ]]; then
    printf 'error: replay key generation returned an invalid byte count\n' >&2
    exit 1
fi

printf 'Pulling the pinned PostgreSQL recovery image...\n'
timeout --foreground "${pull_timeout_seconds}s" docker pull "$postgres_image" >/dev/null
volume_owned=1
docker volume create "$volume_name" >/dev/null

printf 'Starting PostgreSQL on a dedicated persistent volume...\n'
container_owned=1
timeout --foreground 30s docker run \
    --detach \
    --name "$container_name" \
    --env-file "$container_env_file" \
    --publish "127.0.0.1::5432" \
    --volume "${volume_name}:/var/lib/postgresql/data" \
    "$postgres_image" \
    -c fsync=on \
    -c synchronous_commit=on \
    -c full_page_writes=on \
    -c client_connection_check_interval=1s \
    -c checkpoint_timeout=1h >/dev/null
rm -f -- "$container_env_file"

wait_for_postgres() {
    local deadline=$((SECONDS + start_timeout_seconds))
    until timeout --foreground 5s docker exec "$container_name" sh -c \
            'IFS= read -r process </proc/1/comm && [ "$process" = postgres ]' \
            >/dev/null 2>&1 \
        && timeout --foreground 5s docker exec "$container_name" \
            pg_isready --quiet --username "$database_user" --dbname "$database_name" \
        && timeout --foreground 5s docker exec "$container_name" psql \
            --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
            --username "$database_user" --dbname "$database_name" \
            --command 'SELECT 1' >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            printf 'error: PostgreSQL did not become ready within %s seconds\n' \
                "$start_timeout_seconds" >&2
            exit 1
        fi
        sleep 1
    done
}

wait_for_published_postgres() {
    local deadline=$((SECONDS + start_timeout_seconds))
    until timeout --foreground 2s bash -c \
        "exec 3<>/dev/tcp/127.0.0.1/${published_port}" >/dev/null 2>&1; do
        if ((SECONDS >= deadline)); then
            printf 'error: published PostgreSQL socket did not become ready within %s seconds\n' \
                "$start_timeout_seconds" >&2
            exit 1
        fi
        sleep 0.1
    done
}

refresh_published_database_url() {
    local binding
    binding="$(timeout --foreground 5s docker port "$container_name" 5432/tcp)" || {
        printf 'error: could not resolve the published PostgreSQL port\n' >&2
        exit 1
    }
    if [[ ! "$binding" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
        printf 'error: expected one loopback-only PostgreSQL port binding\n' >&2
        exit 1
    fi
    published_port="${BASH_REMATCH[1]}"
    printf 'postgresql://%s:%s@127.0.0.1:%s/%s?application_name=apolysis_crash_driver\n' \
        "$database_user" "$database_password" "$published_port" "$database_name" \
        >"$database_url_file"
    chmod 600 "$database_url_file"
}

psql_scalar() {
    local statement="$1"
    timeout --foreground 15s docker exec "$container_name" psql \
        --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username "$database_user" --dbname "$database_name" \
        --command "$statement" | tr -d '[:space:]'
}

driver_run() {
    local mode="$1"
    local scenario="$2"
    shift 2
    if ! "$driver" "$mode" \
        --database-url-file "$database_url_file" \
        --replay-key-file "$replay_key_file" \
        --scenario "$scenario" \
        "$@" >>"$driver_log" 2>&1; then
        printf 'error: recovery driver failed in mode %s\n' "$mode" >&2
        return 1
    fi
}

driver_start() {
    local mode="$1"
    local scenario="$2"
    shift 2
    "$driver" "$mode" \
        --database-url-file "$database_url_file" \
        --replay-key-file "$replay_key_file" \
        --scenario "$scenario" \
        "$@" >>"$driver_log" 2>&1 &
    driver_pid=$!
}

wait_for_file() {
    local path="$1"
    local context="$2"
    local deadline=$((SECONDS + 30))
    while [[ ! -s "$path" ]]; do
        if [[ -n "$driver_pid" ]] && ! kill -0 "$driver_pid" >/dev/null 2>&1; then
            printf 'error: recovery driver exited before %s\n' "$context" >&2
            exit 1
        fi
        if ((SECONDS >= deadline)); then
            printf 'error: timed out waiting for %s\n' "$context" >&2
            exit 1
        fi
        sleep 0.1
    done
}

require_client_ack_absent() {
    local ack_file="$1"
    local release_file="$2"
    local context="$3"
    if [[ -e "$ack_file" || -e "$release_file" ]]; then
        printf 'error: client acknowledgement escaped before %s\n' "$context" >&2
        exit 1
    fi
}

kill_driver_before_ack() {
    local context="$1"
    kill -KILL "$driver_pid"
    if wait "$driver_pid" >/dev/null 2>&1; then
        printf 'error: killed %s driver unexpectedly acknowledged success\n' "$context" >&2
        exit 1
    fi
    driver_pid=""
    local backend_deadline=$((SECONDS + 15))
    until [[ "$(psql_scalar "SELECT count(*) FROM pg_stat_activity WHERE application_name='apolysis_crash_driver'")" == "0" ]]; do
        if ((SECONDS >= backend_deadline)); then
            printf 'error: killed %s Gateway database sessions did not close\n' "$context" >&2
            exit 1
        fi
        sleep 0.1
    done
}

wait_for_postgres
published_port=""
refresh_published_database_url
wait_for_published_postgres

if [[ "$(psql_scalar 'SHOW data_checksums')" != "on" ]] || \
    [[ "$(psql_scalar 'SHOW fsync')" != "on" ]] || \
    [[ "$(psql_scalar 'SHOW synchronous_commit')" != "on" ]] || \
    [[ "$(psql_scalar 'SHOW full_page_writes')" != "on" ]] || \
    [[ "$(psql_scalar 'SHOW client_connection_check_interval')" != "1s" ]]; then
    printf 'error: PostgreSQL durability settings are not active\n' >&2
    exit 1
fi

printf 'Qualifying exact replay across a graceful PostgreSQL restart...\n'
readonly graceful_scenario="graceful_${suffix}"
readonly graceful_state="${control_directory}/graceful.state.json"
driver_run open "$graceful_scenario" --state-file "$graceful_state"
timeout --foreground 30s docker stop --time 15 "$container_name" >/dev/null
timeout --foreground 30s docker start "$container_name" >/dev/null
wait_for_postgres
refresh_published_database_url
wait_for_published_postgres
driver_run verify-replay "$graceful_scenario" --state-file "$graceful_state"

printf 'Qualifying committed replay across PostgreSQL SIGKILL and WAL recovery...\n'
readonly wal_scenario="wal_${suffix}"
readonly wal_state="${control_directory}/wal.state.json"
psql_scalar 'CHECKPOINT' >/dev/null
wal_before="$(psql_scalar 'SELECT pg_current_wal_insert_lsn()')"
driver_run open "$wal_scenario" --state-file "$wal_state"
wal_after="$(psql_scalar 'SELECT pg_current_wal_insert_lsn()')"
if [[ "$wal_before" == "$wal_after" ]]; then
    printf 'error: committed Gateway write did not advance the WAL insert position\n' >&2
    exit 1
fi
recovery_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || {
    printf 'error: could not establish the WAL recovery log boundary\n' >&2
    exit 1
}
if [[ ! "$recovery_started_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    printf 'error: WAL recovery log boundary has an invalid format\n' >&2
    exit 1
fi
readonly recovery_started_at
timeout --foreground 15s docker kill --signal KILL "$container_name" >/dev/null
timeout --foreground 30s docker start "$container_name" >/dev/null
wait_for_postgres
refresh_published_database_url
wait_for_published_postgres
timeout --foreground 15s docker logs --since "$recovery_started_at" "$container_name" \
    >"$postgres_log" 2>&1
if ! grep -Fq 'database system was interrupted' "$postgres_log" || \
    ! grep -Fq 'redo starts at' "$postgres_log" || \
    ! grep -Fq 'redo done at' "$postgres_log"; then
    printf 'error: PostgreSQL did not report crash recovery after SIGKILL\n' >&2
    exit 1
fi
driver_run verify-replay "$wal_scenario" --state-file "$wal_state"

printf 'Qualifying rollback when the Gateway process dies before commit...\n'
readonly precommit_scenario="precommit_${suffix}"
readonly precommit_state="${control_directory}/precommit.state.json"
timeout --foreground 15s docker exec "$container_name" psql \
    --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$database_user" --dbname "$database_name" \
    --command 'CREATE FUNCTION apolysis_gateway.crash_gate_pause_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(4715382012602313076); RETURN NEW; END $$; CREATE TRIGGER crash_gate_pause_outbox BEFORE INSERT ON apolysis_gateway.projection_outbox FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.crash_gate_pause_outbox();' \
    >/dev/null
docker exec --env PGAPPNAME=apolysis_crash_lock_holder "$container_name" psql \
    --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$database_user" --dbname "$database_name" \
    --command "SELECT pg_advisory_lock(${ADVISORY_LOCK_KEY}); SELECT pg_sleep(300)" \
    >/dev/null 2>&1 &
lock_holder_pid=$!
lock_deadline=$((SECONDS + 15))
until [[ "$(psql_scalar "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted")" -ge 1 ]]; do
    if ((SECONDS >= lock_deadline)); then
        printf 'error: advisory fault-injection lock was not acquired\n' >&2
        exit 1
    fi
    sleep 0.1
done
driver_start open "$precommit_scenario" --state-file "$precommit_state"
blocked_deadline=$((SECONDS + 30))
until [[ "$(psql_scalar "SELECT count(*) FROM pg_locks AS lock JOIN pg_stat_activity AS activity ON activity.pid=lock.pid WHERE lock.locktype='advisory' AND NOT lock.granted AND activity.application_name='apolysis_crash_driver'")" -ge 1 ]]; do
    if ! kill -0 "$driver_pid" >/dev/null 2>&1; then
        printf 'error: pre-commit driver exited before reaching the database lock\n' >&2
        exit 1
    fi
    if ((SECONDS >= blocked_deadline)); then
        printf 'error: pre-commit driver did not reach the deterministic lock\n' >&2
        exit 1
    fi
    sleep 0.1
done
blocked_backend_pid="$(psql_scalar "SELECT activity.pid FROM pg_locks AS lock JOIN pg_stat_activity AS activity ON activity.pid=lock.pid WHERE lock.locktype='advisory' AND NOT lock.granted AND activity.application_name='apolysis_crash_driver'")"
if [[ ! "$blocked_backend_pid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'error: expected exactly one blocked Gateway database backend\n' >&2
    exit 1
fi
kill -KILL "$driver_pid"
if wait "$driver_pid" >/dev/null 2>&1; then
    printf 'error: killed pre-commit driver unexpectedly succeeded\n' >&2
    exit 1
fi
driver_pid=""
backend_deadline=$((SECONDS + 15))
until [[ "$(psql_scalar "SELECT count(*) FROM pg_stat_activity WHERE pid=${blocked_backend_pid}")" == "0" ]]; do
    if ((SECONDS >= backend_deadline)); then
        printf 'error: PostgreSQL did not detect the killed pre-commit client\n' >&2
        exit 1
    fi
    sleep 0.1
done
if [[ -e "$precommit_state" ]]; then
    printf 'error: pre-commit process wrote durable client state before commit\n' >&2
    exit 1
fi
if [[ "$(psql_scalar "SELECT count(*) FROM apolysis_gateway.record_items WHERE organization_id='org_${precommit_scenario}'")" != "0" ]]; then
    printf 'error: pre-commit process death left partially committed records\n' >&2
    exit 1
fi
psql_scalar "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='apolysis_crash_lock_holder'" >/dev/null
if [[ -n "$lock_holder_pid" ]]; then
    wait "$lock_holder_pid" >/dev/null 2>&1 || true
    lock_holder_pid=""
fi
timeout --foreground 15s docker exec "$container_name" psql \
    --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "$database_user" --dbname "$database_name" \
    --command 'DROP TRIGGER crash_gate_pause_outbox ON apolysis_gateway.projection_outbox; DROP FUNCTION apolysis_gateway.crash_gate_pause_outbox();' \
    >/dev/null
driver_run verify-rollback-and-retry "$precommit_scenario" --state-file "$precommit_state"

printf 'Qualifying exact retry after process death post-commit and pre-ack...\n'
readonly lost_ack_scenario="lostack_${suffix}"
readonly lost_ack_state="${control_directory}/lostack.state.json"
readonly lost_ack_ready="${control_directory}/lostack.ready"
readonly lost_ack_release="${control_directory}/lostack.release"
readonly lost_ack_client_ack="${control_directory}/lostack.client-ack"
driver_start open-and-hold-before-client-ack "$lost_ack_scenario" \
    --state-file "$lost_ack_state" --ready-file "$lost_ack_ready" \
    --release-file "$lost_ack_release" --ack-file "$lost_ack_client_ack"
wait_for_file "$lost_ack_ready" 'the post-commit client-acknowledgement barrier'
require_client_ack_absent "$lost_ack_client_ack" "$lost_ack_release" \
    'the post-commit process kill'
expected_counts="1|1|1|1|3|3"
actual_counts="$(psql_scalar "SELECT (SELECT count(*) FROM apolysis_gateway.runs WHERE organization_id='org_${lost_ack_scenario}') || '|' || (SELECT count(*) FROM apolysis_gateway.gateway_operations WHERE organization_id='org_${lost_ack_scenario}') || '|' || (SELECT count(*) FROM apolysis_gateway.operation_replays WHERE organization_id='org_${lost_ack_scenario}') || '|' || (SELECT count(*) FROM apolysis_gateway.leases WHERE organization_id='org_${lost_ack_scenario}') || '|' || (SELECT count(*) FROM apolysis_gateway.record_items WHERE organization_id='org_${lost_ack_scenario}') || '|' || (SELECT count(*) FROM apolysis_gateway.projection_outbox WHERE organization_id='org_${lost_ack_scenario}')")"
if [[ "$actual_counts" != "$expected_counts" ]]; then
    printf 'error: post-commit marker preceded the atomic durable result\n' >&2
    exit 1
fi
kill_driver_before_ack 'post-commit/pre-ack'

printf 'Qualifying replay convergence when the retry process also dies pre-ack...\n'
readonly retry_ready="${control_directory}/retry.ready"
readonly retry_release="${control_directory}/retry.release"
readonly retry_client_ack="${control_directory}/retry.client-ack"
driver_start replay-and-hold-before-client-ack "$lost_ack_scenario" \
    --state-file "$lost_ack_state" --ready-file "$retry_ready" \
    --release-file "$retry_release" --ack-file "$retry_client_ack"
wait_for_file "$retry_ready" 'the retry client-acknowledgement barrier'
require_client_ack_absent "$retry_client_ack" "$retry_release" \
    'the retry process kill'
kill_driver_before_ack 'retry/pre-ack'
driver_run verify-replay "$lost_ack_scenario" --state-file "$lost_ack_state"

printf 'Checking database integrity and secret absence...\n'
timeout --foreground 60s docker exec "$container_name" pg_amcheck \
    --username "$database_user" --database "$database_name" --install-missing >/dev/null
readonly database_dump="${control_directory}/database.dump.sql"
timeout --foreground 45s docker exec "$container_name" pg_dump \
    --username "$database_user" --dbname "$database_name" \
    --no-owner --no-privileges >"$database_dump"
if grep -Eq 'lease_[0-9a-f]{64}' "$database_dump"; then
    printf 'error: plaintext bearer lease appeared in the PostgreSQL dump\n' >&2
    exit 1
fi
if grep -Eq 'lease_[0-9a-f]{64}' "$driver_log" "$postgres_log" \
    "$graceful_state" "$wal_state" "$precommit_state" "$lost_ack_state"; then
    printf 'error: plaintext bearer lease appeared in a log or test artifact\n' >&2
    exit 1
fi
replay_key_hex="$(od -An -tx1 "$replay_key_file" | tr -d '[:space:]')" || {
    printf 'error: could not inspect replay-key leakage safely\n' >&2
    exit 1
}
if [[ ! "$replay_key_hex" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'error: replay-key leakage sentinel has an invalid encoding\n' >&2
    exit 1
fi
readonly replay_key_hex
for protected_value in "$database_password" "$replay_key_hex"; do
    if grep -Fq -- "$protected_value" "$driver_log" "$postgres_log" \
        "$database_dump" "$graceful_state" "$wal_state" "$precommit_state" \
        "$lost_ack_state"; then
        printf 'error: secret material appeared in a log or test artifact\n' >&2
        exit 1
    fi
done
for file in "$database_url_file" "$replay_key_file" "$graceful_state" "$wal_state" \
    "$precommit_state" "$lost_ack_state" "$lost_ack_ready" "$retry_ready"; do
    if [[ "$(stat -c '%a' "$file")" != "600" ]]; then
        printf 'error: recovery control file is not mode 0600\n' >&2
        exit 1
    fi
done

gate_passed=1

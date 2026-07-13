#!/usr/bin/env bash

set -Eeuo pipefail

# Pin both the supported point release and its verified multi-platform OCI index
# digest. Updating PostgreSQL is therefore an explicit, reviewable change.
readonly DEFAULT_POSTGRES_IMAGE="postgres:16.14-alpine3.23@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3"
readonly DEFAULT_TEST_COMMAND="cargo test -p apolysis-gateway-postgres --tests -- --ignored --test-threads=1"

postgres_image="${APOLYSIS_POSTGRES_IMAGE-$DEFAULT_POSTGRES_IMAGE}"
test_command="${APOLYSIS_POSTGRES_TEST_COMMAND-$DEFAULT_TEST_COMMAND}"
pull_timeout_seconds="${APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS:-300}"
start_timeout_seconds="${APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS:-60}"
command_timeout_seconds="${APOLYSIS_POSTGRES_TEST_TIMEOUT_SECONDS:-600}"

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

require_nonempty() {
    local variable_name="$1"
    local value="$2"

    if [[ -z "$value" ]]; then
        printf 'error: %s must not be empty\n' "$variable_name" >&2
        exit 1
    fi
}

random_hex() {
    local byte_count="$1"
    od -An -N "$byte_count" -tx1 /dev/urandom | tr -d '[:space:]'
}

require_command cargo
require_command bash
require_command docker
require_command mktemp
require_command od
require_command timeout
require_command tr

require_positive_integer APOLYSIS_POSTGRES_PULL_TIMEOUT_SECONDS "$pull_timeout_seconds"
require_positive_integer APOLYSIS_POSTGRES_START_TIMEOUT_SECONDS "$start_timeout_seconds"
require_positive_integer APOLYSIS_POSTGRES_TEST_TIMEOUT_SECONDS "$command_timeout_seconds"
require_nonempty APOLYSIS_POSTGRES_IMAGE "$postgres_image"
require_nonempty APOLYSIS_POSTGRES_TEST_COMMAND "$test_command"

# Docker access is the only privileged host prerequisite. Check it before
# creating credentials or container state. The pinned image remains in Docker's
# normal cache intentionally; operators may remove precisely `$postgres_image`
# with `docker image rm` after the gate if retaining the cache is undesirable.
if ! timeout 10s docker info >/dev/null 2>&1; then
    printf 'error: Docker daemon is unavailable or inaccessible\n' >&2
    exit 1
fi

readonly random_suffix="$(random_hex 8)"
readonly container_name="apolysis-gateway-postgres-${random_suffix}"
readonly database_name="apolysis_${random_suffix}"
readonly database_user="apolysis_${random_suffix}"
readonly database_password="$(random_hex 24)"
readonly secret_directory="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-gateway-postgres.XXXXXXXX")"
readonly container_env_file="${secret_directory}/postgres.env"

cleanup() {
    local exit_status=$?

    trap - EXIT INT TERM
    # A timed-out `docker run` may still have created the uniquely named
    # container. Removing only that name is safe and leaves host state alone.
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

printf 'Pulling the pinned PostgreSQL integration-test image...\n'
timeout --foreground "${pull_timeout_seconds}s" docker pull "$postgres_image" >/dev/null

printf 'Starting an ephemeral loopback-only PostgreSQL container...\n'
timeout --foreground 30s docker run \
    --detach \
    --rm \
    --name "$container_name" \
    --env-file "$container_env_file" \
    --publish "127.0.0.1::5432" \
    "$postgres_image" >/dev/null

# The credentials are no longer needed on the host after Docker has created the
# container. The generated database URL is never printed.
rm -f -- "$container_env_file"

printf 'Waiting for PostgreSQL readiness...\n'
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
readonly test_database_url="postgresql://${database_user}:${database_password}@127.0.0.1:${published_port}/${database_name}"

printf 'Running ignored PostgreSQL gateway integration tests single-threaded...\n'
(
    # Keep database access opt-in and scoped to the test child. In particular,
    # do not export DATABASE_URL or leak this URL into the parent shell.
    export APOLYSIS_TEST_DATABASE_URL="$test_database_url"
    timeout --foreground --kill-after=15s "${command_timeout_seconds}s" \
        bash -o pipefail -c "$test_command"
)

printf 'PostgreSQL gateway integration tests passed.\n'

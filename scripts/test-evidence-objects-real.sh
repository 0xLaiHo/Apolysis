#!/bin/bash -p

set -Eeuo pipefail

# These OCI index digests pin the exact provider builds qualified by this gate.
# Image changes must be explicit review events; this script intentionally has no
# image override knobs.
readonly POSTGRES_IMAGE="postgres:16.14-alpine3.23@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3"
readonly SEAWEEDFS_IMAGE="docker.io/chrislusf/seaweedfs:4.39@sha256:c7d6c721b30ae711db766bbbfd40192776e263d4e51e22f57baef7bef93c12c6"
readonly GATE_LABEL="org.apolysis.qualification.evidence-objects-real"
readonly RUN_LABEL="org.apolysis.qualification.run"
readonly ROLE_LABEL="org.apolysis.qualification.role"
readonly LOG_LIMIT_BYTES=8388608
readonly STREAM_LIMIT_BYTES=67108864
readonly FINAL_SCAN_LIMIT_BYTES=536870912
readonly LOG_TAIL_LINES=160
readonly PRIVACY_GUARD_STATUS=41

gate_timeout_seconds="${APOLYSIS_EVIDENCE_OBJECT_GATE_TIMEOUT_SECONDS:-2400}"
runner_self_test=false

# Before the hard wall exists, use Bash builtins only. Bound length before any
# arithmetic so an oversized decimal cannot wrap around the maximum.
if [[ ! "$gate_timeout_seconds" =~ ^[1-9][0-9]{0,3}$ ]] ||
    ((10#$gate_timeout_seconds > 3600)); then
    printf 'error: APOLYSIS_EVIDENCE_OBJECT_GATE_TIMEOUT_SECONDS must be 1..3600 without leading zeroes\n' >&2
    exit 1
fi

if [[ -n "${APOLYSIS_EVIDENCE_OBJECT_RUNNER_SELF_TEST+x}" ]]; then
    printf 'error: legacy evidence-object runner self-test environment is forbidden\n' >&2
    exit 1
fi
case "$#" in
    0) ;;
    1)
        if [[ "$1" != "--runner-self-test" ]]; then
            printf 'error: unsupported evidence-object qualification argument\n' >&2
            exit 1
        fi
        runner_self_test=true
        ;;
    *)
        printf 'error: unsupported evidence-object qualification arguments\n' >&2
        exit 1
        ;;
esac

if [[ -x /usr/bin/timeout ]]; then
    trusted_timeout_binary=/usr/bin/timeout
elif [[ -x /bin/timeout ]]; then
    trusted_timeout_binary=/bin/timeout
else
    printf 'error: trusted provider-gate timeout binary is unavailable\n' >&2
    exit 1
fi
readonly trusted_timeout_binary

# Put a hard wall-clock bound around the complete provider gate. The legacy
# inner sentinel is always rejected. The marker binds the inner process to the
# PID that becomes the fixed, absolute GNU timeout binary after exec.
if [[ -n "${APOLYSIS_EVIDENCE_OBJECT_GATE_INNER+x}" ]]; then
    printf 'error: reserved provider-gate recursion marker was pre-set or invalid\n' >&2
    exit 1
fi
if [[ -z "${APOLYSIS_EVIDENCE_OBJECT_GATE_WRAPPER+x}" ]]; then
    gate_timeout_parent_pid="$BASHPID"
    export APOLYSIS_EVIDENCE_OBJECT_GATE_WRAPPER="$gate_timeout_parent_pid"
    exec "$trusted_timeout_binary" --kill-after=90s "${gate_timeout_seconds}s" "$0" "$@"
fi

gate_inner_marker="$APOLYSIS_EVIDENCE_OBJECT_GATE_WRAPPER"
if [[ ! "$gate_inner_marker" =~ ^[1-9][0-9]*$ ]]; then
    printf 'error: reserved provider-gate recursion marker was pre-set or invalid\n' >&2
    exit 1
fi
gate_timeout_parent_pid="$gate_inner_marker"
if [[ "$gate_timeout_parent_pid" != "$PPID" ||
    ! "/proc/${PPID}/exe" -ef "$trusted_timeout_binary" ]]; then
    printf 'error: provider-gate wrapper parent identity is invalid\n' >&2
    exit 1
fi
declare -a gate_timeout_parent_cmdline=()
expected_gate_timeout_parent_argc=4
if [[ "$runner_self_test" == "true" ]]; then
    expected_gate_timeout_parent_argc=5
fi
if ! mapfile -d '' -t gate_timeout_parent_cmdline <"/proc/${PPID}/cmdline" ||
    ((${#gate_timeout_parent_cmdline[@]} != expected_gate_timeout_parent_argc)) ||
    [[ "${gate_timeout_parent_cmdline[0]}" != "$trusted_timeout_binary" ||
        "${gate_timeout_parent_cmdline[1]}" != "--kill-after=90s" ||
        "${gate_timeout_parent_cmdline[2]}" != "${gate_timeout_seconds}s" ||
        "${gate_timeout_parent_cmdline[3]}" != "$0" ]] ||
    { [[ "$runner_self_test" == "true" ]] &&
        [[ "${gate_timeout_parent_cmdline[4]}" != "--runner-self-test" ]]; }; then
    printf 'error: provider-gate wrapper command line is invalid\n' >&2
    exit 1
fi
unset APOLYSIS_EVIDENCE_OBJECT_GATE_WRAPPER

# Everything below executes under the authenticated hard wall. Privileged mode
# ignored BASH_ENV and exported functions; now establish a system-only tool PATH
# and resolve cargo separately without allowing HOME to shadow provider tools.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
unset BASH_ENV ENV PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT

if [[ -x /usr/bin/cargo ]]; then
    cargo_binary=/usr/bin/cargo
elif [[ "${HOME:-}" == /* && "${HOME:-}" != *:* && -x "${HOME}/.cargo/bin/cargo" ]]; then
    cargo_binary="${HOME}/.cargo/bin/cargo"
else
    printf 'error: trusted cargo binary is unavailable\n' >&2
    exit 1
fi
readonly cargo_binary

if [[ ! -x /usr/bin/stat ]]; then
    printf 'error: trusted provider-gate stat binary is unavailable\n' >&2
    exit 1
fi
if ! IFS=' ' read -r timeout_binary_owner timeout_binary_mode < <(
    /usr/bin/stat -Lc '%u %a' -- "$trusted_timeout_binary"
); then
    printf 'error: trusted provider-gate timeout binary could not be inspected\n' >&2
    exit 1
fi
if [[ "$timeout_binary_owner" != "0" ||
    ! "$timeout_binary_mode" =~ ^[0-7]{3,4}$ ]] ||
    ((8#$timeout_binary_mode & 0022)); then
    printf 'error: provider-gate timeout binary ownership or mode is unsafe\n' >&2
    exit 1
fi

pull_timeout_seconds="${APOLYSIS_EVIDENCE_OBJECT_PULL_TIMEOUT_SECONDS:-300}"
start_timeout_seconds="${APOLYSIS_EVIDENCE_OBJECT_START_TIMEOUT_SECONDS:-90}"
test_timeout_seconds="${APOLYSIS_EVIDENCE_OBJECT_TEST_TIMEOUT_SECONDS:-900}"
crash_ready_timeout_seconds="${APOLYSIS_EVIDENCE_OBJECT_CRASH_READY_TIMEOUT_SECONDS:-300}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'error: required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

require_bounded_positive_integer() {
    local variable_name="$1"
    local value="$2"
    local maximum="$3"

    if [[ ! "$value" =~ ^[1-9][0-9]{0,3}$ ]] || ((10#$value > maximum)); then
        printf 'error: %s must be within its bounded positive range without leading zeroes\n' \
            "$variable_name" >&2
        exit 1
    fi
}

random_hex() {
    local byte_count="$1"
    od -An -N "$byte_count" -tx1 /dev/urandom | tr -d '[:space:]'
}

for command in bash cat chmod curl dd docker id mkdir mkfifo mktemp od python3 rm setsid sleep stat tr; do
    require_command "$command"
done

require_bounded_positive_integer \
    APOLYSIS_EVIDENCE_OBJECT_PULL_TIMEOUT_SECONDS "$pull_timeout_seconds" 900
require_bounded_positive_integer \
    APOLYSIS_EVIDENCE_OBJECT_START_TIMEOUT_SECONDS "$start_timeout_seconds" 600
require_bounded_positive_integer \
    APOLYSIS_EVIDENCE_OBJECT_TEST_TIMEOUT_SECONDS "$test_timeout_seconds" 1800
require_bounded_positive_integer \
    APOLYSIS_EVIDENCE_OBJECT_CRASH_READY_TIMEOUT_SECONDS "$crash_ready_timeout_seconds" 600

umask 077
run_id="$(random_hex 12)"
host_uid="$(id -u)"
host_gid="$(id -g)"
if [[ ! "$run_id" =~ ^[0-9a-f]{24}$ ]]; then
    printf 'error: could not generate a valid qualification run identifier\n' >&2
    exit 1
fi
if [[ ! "$host_uid" =~ ^[0-9]+$ || ! "$host_gid" =~ ^[0-9]+$ ]]; then
    printf 'error: could not determine the invoking user identity\n' >&2
    exit 1
fi
if [[ "$host_uid" == "0" ]]; then
    printf 'error: run this gate as a non-root user with Docker access\n' >&2
    exit 1
fi
private_directory="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-evidence-objects.XXXXXXXX")"
readonly run_id host_uid host_gid private_directory
readonly container_prefix="apolysis-evidence-objects-${run_id}"
readonly postgres_network_name="${container_prefix}-postgres-network"
readonly seaweed_network_name="${container_prefix}-seaweed-network"
readonly database_name="apolysis_object_${run_id}"
readonly database_user="apolysis_object_${run_id}"
readonly bucket_name="apolysis-object-${run_id}"
readonly seaweed_data_directory="${private_directory}/seaweed-data"
readonly postgres_password_file="${private_directory}/postgres.password"
readonly postgres_bootstrap_file="${private_directory}/postgres-bootstrap.sql"
readonly postgres_hba_file="${private_directory}/pg_hba.conf"
readonly postgres_container_pgpass_file="${private_directory}/postgres-container.pgpass"
readonly postgres_invalid_pgpass_file="${private_directory}/postgres-invalid.pgpass"
readonly postgres_host_pgpass_file="${private_directory}/postgres-host.pgpass"
readonly s3_access_key_file="${private_directory}/s3-access-key"
readonly s3_secret_key_file="${private_directory}/s3-secret-key"
readonly s3_credential_file="${private_directory}/s3-credentials.json"
readonly seaweed_s3_config_file="${private_directory}/seaweed-s3.json"
readonly wrapping_key_file="${private_directory}/object-wrapping.key"
readonly qualification_io_helper="${private_directory}/qualification-io.py"
readonly postgres_pull_log="${private_directory}/postgres-pull.log"
readonly seaweed_pull_log="${private_directory}/seaweed-pull.log"
readonly postgres_network_create_log="${private_directory}/postgres-network-create.log"
readonly postgres_network_inspect_log="${private_directory}/postgres-network-inspect.json"
readonly seaweed_network_create_log="${private_directory}/seaweed-network-create.log"
readonly seaweed_network_inspect_log="${private_directory}/seaweed-network-inspect.json"
readonly postgres_log="${private_directory}/postgres.log"
readonly seaweed_log="${private_directory}/seaweed.log"
readonly cargo_schema_log="${private_directory}/cargo-schema.log"
readonly cargo_privileges_log="${private_directory}/cargo-privileges.log"
readonly cargo_served_session_log="${private_directory}/cargo-served-session.log"
readonly cargo_gateway_authority_lock_order_log="${private_directory}/cargo-gateway-authority-lock-order.log"
readonly cargo_normal_log="${private_directory}/cargo-normal.log"
readonly cargo_concurrent_identity_log="${private_directory}/cargo-concurrent-identity.log"
readonly cargo_database_deadline_log="${private_directory}/cargo-database-deadline.log"
readonly cargo_reaper_lock_order_log="${private_directory}/cargo-reaper-lock-order.log"
readonly cargo_reaper_fairness_log="${private_directory}/cargo-reaper-fairness.log"
readonly cargo_reaper_expiry_fence_log="${private_directory}/cargo-reaper-expiry-fence.log"
readonly cargo_policy_tightening_log="${private_directory}/cargo-policy-tightening.log"
readonly cargo_backend_binding_log="${private_directory}/cargo-backend-binding.log"
readonly cargo_deletion_rotation_log="${private_directory}/cargo-deletion-rotation.log"
readonly cargo_reserve_setup_log="${private_directory}/cargo-after-reserve.log"
readonly cargo_reserve_recover_log="${private_directory}/cargo-recover-reserve.log"
readonly cargo_put_setup_log="${private_directory}/cargo-after-put.log"
readonly cargo_put_unavailable_log="${private_directory}/cargo-recover-put-unavailable.log"
readonly cargo_put_recover_log="${private_directory}/cargo-recover-put.log"
readonly database_dump="${private_directory}/database.sql"
readonly reserve_state_file="${private_directory}/crash-reserve.state"
readonly reserve_ready_file="${private_directory}/crash-reserve.ready"
readonly reserve_replay_key_file="${private_directory}/crash-reserve-replay.key"
readonly put_state_file="${private_directory}/crash-put.state"
readonly put_ready_file="${private_directory}/crash-put.ready"
readonly put_replay_key_file="${private_directory}/crash-put-replay.key"
readonly role_password_prefix_file="${private_directory}/role-password-prefix"

postgres_container_id=""
seaweed_container_id=""
seaweed_generation=0
crash_process_group=""
crash_log_tail_pid=""
crash_log_fifo=""
postgres_internal_ip=""
seaweed_internal_ip=""
database_url=""
s3_endpoint=""
last_container_inspect_log=""
docker_state_may_exist=false
declare -a inspect_logs=()

labelled_container_ids() {
    "$trusted_timeout_binary" --kill-after=1s 3s docker ps --all --quiet --no-trunc \
        --filter "label=${GATE_LABEL}=true" \
        --filter "label=${RUN_LABEL}=${run_id}"
}

labelled_network_ids() {
    "$trusted_timeout_binary" --kill-after=1s 3s docker network ls --quiet --no-trunc \
        --filter "label=${GATE_LABEL}=true" \
        --filter "label=${RUN_LABEL}=${run_id}"
}

remove_labelled_containers() {
    local ids_text
    local container_id
    local empty_observations=0
    local deadline=$((SECONDS + 30))
    local -a ids=()
    local -a direct_targets=(
        "${container_prefix}-postgres"
        "${container_prefix}-seaweed-1"
        "${container_prefix}-seaweed-2"
    )

    if [[ -n "$postgres_container_id" ]]; then
        direct_targets+=("$postgres_container_id")
    fi
    if [[ -n "$seaweed_container_id" ]]; then
        direct_targets+=("$seaweed_container_id")
    fi

    while true; do
        "$trusted_timeout_binary" --kill-after=2s 8s \
            docker rm --force "${direct_targets[@]}" >/dev/null 2>&1 || true
        if ! ids_text="$(labelled_container_ids 2>/dev/null)"; then
            return 1
        fi
        ids=()
        while IFS= read -r container_id; do
            [[ -n "$container_id" ]] && ids+=("$container_id")
        done <<<"$ids_text"
        if ((${#ids[@]} > 0)); then
            empty_observations=0
            "$trusted_timeout_binary" --kill-after=2s 8s \
                docker rm --force "${ids[@]}" >/dev/null 2>&1 || true
        else
            empty_observations=$((empty_observations + 1))
            if ((empty_observations >= 2)); then
                return
            fi
        fi
        if ((SECONDS >= deadline)); then
            return 1
        fi
        sleep 1
    done
}

remove_labelled_networks() {
    local ids_text
    local network_id
    local empty_observations=0
    local deadline=$((SECONDS + 30))
    local -a ids=()
    local -a direct_targets=("$postgres_network_name" "$seaweed_network_name")

    while true; do
        "$trusted_timeout_binary" --kill-after=2s 8s \
            docker network rm "${direct_targets[@]}" >/dev/null 2>&1 || true
        if ! ids_text="$(labelled_network_ids 2>/dev/null)"; then
            return 1
        fi
        ids=()
        while IFS= read -r network_id; do
            [[ -n "$network_id" ]] && ids+=("$network_id")
        done <<<"$ids_text"
        if ((${#ids[@]} > 0)); then
            empty_observations=0
            "$trusted_timeout_binary" --kill-after=2s 8s \
                docker network rm "${ids[@]}" >/dev/null 2>&1 || true
        else
            empty_observations=$((empty_observations + 1))
            if ((empty_observations >= 2)); then
                return
            fi
        fi
        if ((SECONDS >= deadline)); then
            return 1
        fi
        sleep 1
    done
}

kill_crash_process_group() {
    local watchdog_pid=""

    if [[ -z "$crash_process_group" ]]; then
        return
    fi
    kill -TERM -- "-${crash_process_group}" >/dev/null 2>&1 || true
    (
        sleep 1
        kill -KILL -- "-${crash_process_group}" >/dev/null 2>&1 || true
        kill -KILL "$crash_process_group" >/dev/null 2>&1 || true
    ) >/dev/null 2>&1 &
    watchdog_pid=$!
    wait "$crash_process_group" >/dev/null 2>&1 || true
    kill -TERM "$watchdog_pid" >/dev/null 2>&1 || true
    wait "$watchdog_pid" >/dev/null 2>&1 || true
    crash_process_group=""
}

finish_crash_log_capture() {
    local capture_status=0
    local watchdog_pid=""
    local term_grace_seconds="${1:-3}"
    local kill_grace_seconds="${2:-2}"

    if [[ -n "$crash_log_tail_pid" ]]; then
        (
            sleep "$term_grace_seconds"
            kill -TERM "$crash_log_tail_pid" >/dev/null 2>&1 || true
            sleep "$kill_grace_seconds"
            kill -KILL "$crash_log_tail_pid" >/dev/null 2>&1 || true
        ) >/dev/null 2>&1 &
        watchdog_pid=$!
        if wait "$crash_log_tail_pid"; then
            capture_status=0
        else
            capture_status=$?
        fi
        kill -TERM "$watchdog_pid" >/dev/null 2>&1 || true
        wait "$watchdog_pid" >/dev/null 2>&1 || true
        crash_log_tail_pid=""
    fi
    if [[ -n "$crash_log_fifo" ]]; then
        rm -f -- "$crash_log_fifo"
        crash_log_fifo=""
    fi
    return "$capture_status"
}

remove_secret_material() {
    local path
    local complete=true

    for path in \
        "$postgres_password_file" \
        "$postgres_bootstrap_file" \
        "$postgres_container_pgpass_file" \
        "$postgres_invalid_pgpass_file" \
        "$postgres_host_pgpass_file" \
        "$s3_access_key_file" \
        "$s3_secret_key_file" \
        "$s3_credential_file" \
        "$seaweed_s3_config_file" \
        "$wrapping_key_file" \
        "$reserve_replay_key_file" \
        "$put_replay_key_file" \
        "$role_password_prefix_file"; do
        if ! rm -f -- "$path"; then
            complete=false
        fi
    done
    [[ "$complete" == "true" ]]
}

cleanup() {
    local exit_status=$?
    local cleanup_complete=true

    trap - EXIT INT TERM
    # Remove credential pathnames and every unqualified local artifact before
    # potentially slow child or Docker cleanup. A still-live bind mount can
    # retain random ephemeral bytes until labelled-container removal succeeds;
    # it no longer has a host pathname after this step.
    if ! remove_secret_material; then
        cleanup_complete=false
    fi
    if ! rm -rf -- "$private_directory"; then
        cleanup_complete=false
    fi
    kill_crash_process_group
    if ! finish_crash_log_capture; then
        exit_status=1
    fi
    if [[ "$docker_state_may_exist" == "true" ]]; then
        if ! remove_labelled_containers; then
            cleanup_complete=false
        fi
        if ! remove_labelled_networks; then
            cleanup_complete=false
        fi
    fi
    # A process that held an unlinked directory or FIFO may have attempted a
    # late write while being terminated. Remove the path again before exit.
    if ! rm -rf -- "$private_directory" || [[ -e "$private_directory" ]]; then
        cleanup_complete=false
    fi
    if [[ "$cleanup_complete" != "true" ]]; then
        printf 'error: exact-run cleanup was incomplete for run %s\n' "$run_id" >&2
        exit_status=1
    fi
    exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

chmod 700 "$private_directory"
mkdir -m 700 "$seaweed_data_directory"

# Canary-labelled credentials make accidental disclosure detectable. Secret
# values are written only by shell builtins or stdin; they are never exported or
# passed as a process argument.
{
    printf 'ApolysisPgCanary_'
    random_hex 20
    printf '\n'
} >"$postgres_password_file"
{
    printf 'APOLYSIS'
    random_hex 12 | tr '[:lower:]' '[:upper:]'
    printf '\n'
} >"$s3_access_key_file"
{
    printf 'ApolysisS3Canary_'
    random_hex 24
    printf '\n'
} >"$s3_secret_key_file"
dd if=/dev/urandom of="$wrapping_key_file" bs=32 count=1 status=none
dd if=/dev/urandom of="$reserve_replay_key_file" bs=32 count=1 status=none
dd if=/dev/urandom of="$put_replay_key_file" bs=32 count=1 status=none
printf '%s\n' 'ApolysisRole_' >"$role_password_prefix_file"

python3 - \
    "$postgres_password_file" \
    "$postgres_bootstrap_file" \
    "$postgres_container_pgpass_file" \
    "$postgres_invalid_pgpass_file" \
    "$database_user" \
    "$database_name" <<'PY'
import pathlib
import re
import sys

password_path, bootstrap_path, pgpass_path, invalid_pgpass_path, database_user, database_name = sys.argv[1:]
if not re.fullmatch(r"[a-z0-9_]+", database_user):
    raise SystemExit("unsafe generated database user")
if not re.fullmatch(r"[a-z0-9_]+", database_name):
    raise SystemExit("unsafe generated database name")
password = pathlib.Path(password_path).read_text(encoding="ascii").strip()
if not re.fullmatch(r"[A-Za-z0-9_]+", password):
    raise SystemExit("unsafe generated database password")
pathlib.Path(bootstrap_path).write_text(
    f'ALTER ROLE "{database_user}" PASSWORD \'{password}\';\n',
    encoding="ascii",
)
pathlib.Path(pgpass_path).write_text(
    f"127.0.0.1:5432:{database_name}:{database_user}:{password}\n",
    encoding="ascii",
)
pathlib.Path(invalid_pgpass_path).write_text(
    f"127.0.0.1:5432:{database_name}:{database_user}:invalid_qualification_credential\n",
    encoding="ascii",
)
PY

python3 - \
    "$s3_access_key_file" \
    "$s3_secret_key_file" \
    "$s3_credential_file" \
    "$seaweed_s3_config_file" <<'PY'
import json
import pathlib
import sys

access_path, secret_path, credential_path, config_path = sys.argv[1:]
access_key = pathlib.Path(access_path).read_text(encoding="ascii").strip()
secret_key = pathlib.Path(secret_path).read_text(encoding="ascii").strip()
pathlib.Path(credential_path).write_text(
    json.dumps(
        {"access_key_id": access_key, "secret_access_key": secret_key},
        separators=(",", ":"),
    ) + "\n",
    encoding="ascii",
)
pathlib.Path(config_path).write_text(
    json.dumps(
        {
            "identities": [
                {
                    "name": "apolysis-object-qualification",
                    "credentials": [
                        {"accessKey": access_key, "secretKey": secret_key}
                    ],
                    "actions": ["Admin", "Read", "List", "Tagging", "Write"],
                }
            ]
        },
        separators=(",", ":"),
    ) + "\n",
    encoding="ascii",
)
PY

{
    printf 'local all all trust\n'
    printf 'host all all 0.0.0.0/0 scram-sha-256\n'
    printf 'host all all ::/0 scram-sha-256\n'
} >"$postgres_hba_file"

chmod 600 \
    "$postgres_password_file" \
    "$postgres_bootstrap_file" \
    "$postgres_container_pgpass_file" \
    "$postgres_invalid_pgpass_file" \
    "$s3_access_key_file" \
    "$s3_secret_key_file" \
    "$s3_credential_file" \
    "$seaweed_s3_config_file" \
    "$wrapping_key_file" \
    "$reserve_replay_key_file" \
    "$put_replay_key_file" \
    "$role_password_prefix_file"
chmod 644 "$postgres_hba_file"

cat >"$qualification_io_helper" <<'PY'
#!/usr/bin/env python3
import base64
import os
import pathlib
import sys
import urllib.parse

CHUNK_BYTES = 64 * 1024
SUPPRESSED_LOG = b"qualification output suppressed by privacy guard\n"


def load_patterns(paths):
    patterns = set()
    for path_text in paths:
        path = pathlib.Path(path_text)
        secret = path.read_bytes()
        if path.suffix != ".key":
            secret = secret.removesuffix(b"\n")
        if len(secret) < 8:
            raise ValueError("secret scan input was unexpectedly short")
        patterns.add(secret)
        patterns.add(secret.hex().encode("ascii"))
        patterns.add(("\\x" + secret.hex()).encode("ascii"))
        patterns.add(base64.b64encode(secret))
        # A complete base64 encoding of a prefix is not necessarily a prefix of
        # the encoding of a longer credential because its padded final quantum
        # changes. Complete three-byte groups are stable in either encoding.
        stable_base64_bytes = len(secret) - (len(secret) % 3)
        if stable_base64_bytes >= 8:
            patterns.add(base64.b64encode(secret[:stable_base64_bytes]))
        patterns.add(urllib.parse.quote_from_bytes(secret).encode("ascii"))
    return tuple(sorted(patterns, key=len, reverse=True))


def scan_reader(reader, patterns, byte_limit, tail_limit=0):
    overlap = b""
    overlap_size = max(len(pattern) for pattern in patterns) - 1
    found = False
    exceeded = False
    total = 0
    tail = bytearray()
    while True:
        chunk = reader.read(CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        exceeded = exceeded or total > byte_limit
        window = overlap + chunk
        chunk_found = any(pattern in window for pattern in patterns)
        found = found or chunk_found
        overlap = window[-overlap_size:] if overlap_size else b""
        if chunk_found:
            tail.clear()
        elif tail_limit and not found:
            tail.extend(chunk)
            if len(tail) > tail_limit:
                del tail[:-tail_limit]
    return found, exceeded, total, bytes(tail)


def write_private(path_text, data):
    descriptor = os.open(path_text, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def destroy_private_artifact(path):
    try:
        path.unlink()
    except OSError:
        try:
            write_private(path, SUPPRESSED_LOG)
        except OSError:
            pass


def capture(arguments):
    output_path, tail_limit, byte_limit, secret_count, *rest = arguments
    count = int(secret_count)
    patterns = load_patterns(rest[:count])
    # Truncate first so interruption can never leave content from a previous
    # capture at this path.
    write_private(output_path, b"")
    found, exceeded, _, tail = scan_reader(
        sys.stdin.buffer, patterns, int(byte_limit), int(tail_limit)
    )
    if found:
        write_private(output_path, SUPPRESSED_LOG)
        print("error: secret/canary detected in streamed qualification output", file=sys.stderr)
        return 41
    write_private(output_path, tail)
    if exceeded:
        print("error: qualification output exceeded its streaming byte bound", file=sys.stderr)
        return 42
    return 0


def iter_target_files(targets):
    for target_text in targets:
        target = pathlib.Path(target_text)
        if target.is_symlink():
            raise ValueError(f"refusing symlink scan target: {target}")
        if target.is_dir():
            for child in sorted(target.rglob("*")):
                if child.is_symlink():
                    raise ValueError(f"refusing symlink in scan target: {child}")
                if child.is_file():
                    yield child
        elif target.is_file():
            yield target
        else:
            raise ValueError(f"missing qualification scan target: {target}")


def scan(arguments):
    byte_limit, secret_count, *rest = arguments
    count = int(secret_count)
    patterns = load_patterns(rest[:count])
    total = 0
    for target in iter_target_files(rest[count:]):
        remaining = max(0, int(byte_limit) - total)
        with target.open("rb") as source:
            found, exceeded, consumed, _ = scan_reader(source, patterns, remaining)
        total += consumed
        if found:
            destroy_private_artifact(target)
            print("error: qualification artifact suppressed by privacy guard", file=sys.stderr)
            return 41
        if exceeded:
            print("error: qualification scan inputs exceeded their byte bound", file=sys.stderr)
            return 42
    return 0


def bounded_tail(arguments):
    log_path, line_limit, secret_count, *secret_paths = arguments
    patterns = load_patterns(secret_paths[: int(secret_count)])
    data = pathlib.Path(log_path).read_bytes()
    if any(pattern in data for pattern in patterns):
        write_private(log_path, SUPPRESSED_LOG)
        print("error: qualification output suppressed by privacy guard", file=sys.stderr)
        return 41
    lines = data.decode("utf-8", errors="replace").splitlines()
    for line in lines[-int(line_limit):]:
        print(line)
    return 0


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    try:
        if command == "capture":
            status = capture(arguments)
        elif command == "scan":
            status = scan(arguments)
        elif command == "bounded-tail":
            status = bounded_tail(arguments)
        else:
            raise ValueError("unsupported qualification I/O command")
    except (OSError, ValueError) as error:
        print(f"error: qualification I/O failed: {error}", file=sys.stderr)
        status = 43
    raise SystemExit(status)
PY
chmod 700 "$qualification_io_helper"

capture_and_scan_stream() {
    local output_path="$1"

    python3 "$qualification_io_helper" \
        capture \
        "$output_path" \
        "$LOG_LIMIT_BYTES" \
        "$STREAM_LIMIT_BYTES" \
        7 \
        "$postgres_password_file" \
        "$s3_access_key_file" \
        "$s3_secret_key_file" \
        "$wrapping_key_file" \
        "$reserve_replay_key_file" \
        "$put_replay_key_file" \
        "$role_password_prefix_file"
}

print_bounded_tail() {
    local log_path="$1"

    python3 "$qualification_io_helper" \
        bounded-tail \
        "$log_path" \
        "$LOG_TAIL_LINES" \
        7 \
        "$postgres_password_file" \
        "$s3_access_key_file" \
        "$s3_secret_key_file" \
        "$wrapping_key_file" \
        "$reserve_replay_key_file" \
        "$put_replay_key_file" \
        "$role_password_prefix_file"
}

scan_paths_for_secret_canaries() {
    python3 "$qualification_io_helper" \
        scan \
        "$FINAL_SCAN_LIMIT_BYTES" \
        7 \
        "$postgres_password_file" \
        "$s3_access_key_file" \
        "$s3_secret_key_file" \
        "$wrapping_key_file" \
        "$reserve_replay_key_file" \
        "$put_replay_key_file" \
        "$role_password_prefix_file" \
        "$@"
}

assert_private_file() {
    local path="$1"
    local mode

    mode="$(stat -c '%a' "$path")"
    if [[ "$mode" != "600" ]]; then
        printf 'error: private file does not have mode 0600: %s\n' "$path" >&2
        exit 1
    fi
}

for private_file in \
    "$postgres_password_file" \
    "$postgres_bootstrap_file" \
    "$postgres_container_pgpass_file" \
    "$postgres_invalid_pgpass_file" \
    "$s3_access_key_file" \
    "$s3_secret_key_file" \
    "$s3_credential_file" \
    "$seaweed_s3_config_file" \
    "$wrapping_key_file" \
    "$role_password_prefix_file"; do
    assert_private_file "$private_file"
done

run_privacy_guard_self_test() {
    local self_test_directory="${private_directory}/privacy-guard-self-test"
    local role_password_file="${self_test_directory}/generated-role-password"
    local input_path
    local case_name
    local log_path
    local stdout_path
    local stderr_path
    local capture_status
    local bounded_tail_status
    local scan_status
    local cleanup_wait_status

    mkdir -m 700 "$self_test_directory"
    {
        printf 'ApolysisRole_'
        random_hex 24
        printf '\n'
    } >"$role_password_file"
    chmod 600 "$role_password_file"

    python3 - "$role_password_file" "$self_test_directory" <<'PY'
import base64
import os
import pathlib
import sys
import urllib.parse

password_path, directory_path = sys.argv[1:]
password = pathlib.Path(password_path).read_bytes().removesuffix(b"\n")
representations = (
    password + b"\n",
    password.hex().encode("ascii") + b"\n",
    (b"\\x" + password.hex().encode("ascii") + b"\n"),
    base64.b64encode(password) + b"\n",
    urllib.parse.quote_from_bytes(password).encode("ascii") + b"\n",
)
directory = pathlib.Path(directory_path)
for index, representation in enumerate(representations):
    path = directory / f"input-{index}"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(representation)
PY

    for input_path in "$self_test_directory"/input-*; do
        case_name="${input_path##*-}"
        log_path="${self_test_directory}/diagnostic-${case_name}.log"
        stdout_path="${self_test_directory}/diagnostic-${case_name}.stdout"
        stderr_path="${self_test_directory}/diagnostic-${case_name}.stderr"
        set +e
        python3 "$qualification_io_helper" \
            capture \
            "$log_path" \
            "$LOG_LIMIT_BYTES" \
            "$STREAM_LIMIT_BYTES" \
            1 \
            "$role_password_prefix_file" \
            <"$input_path" \
            >"$stdout_path" \
            2>"$stderr_path"
        capture_status=$?
        set -e
        if [[ "$capture_status" != "$PRIVACY_GUARD_STATUS" ]]; then
            printf 'error: privacy-guard self-test did not reject a credential representation\n' >&2
            return 1
        fi
    done

    set +e
    capture_and_scan_stream "${self_test_directory}/seven-pattern.log" \
        <"$postgres_password_file" \
        >"${self_test_directory}/seven-pattern.stdout" \
        2>"${self_test_directory}/seven-pattern.stderr"
    capture_status=$?
    set -e
    if [[ "$capture_status" != "$PRIVACY_GUARD_STATUS" ]]; then
        printf 'error: privacy-guard self-test did not exercise the seven-pattern capture wrapper\n' >&2
        return 1
    fi

    python3 - "$role_password_file" "$self_test_directory" <<'PY'
import os
import pathlib
import sys

password_path, directory_path = sys.argv[1:]
password = pathlib.Path(password_path).read_bytes()
for name in ("bounded-tail.log", "scan-target"):
    path = pathlib.Path(directory_path) / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(password)
PY

    set +e
    print_bounded_tail "${self_test_directory}/bounded-tail.log" \
        >"${self_test_directory}/bounded-tail.stdout" \
        2>"${self_test_directory}/bounded-tail.stderr"
    bounded_tail_status=$?
    set -e
    if [[ "$bounded_tail_status" != "$PRIVACY_GUARD_STATUS" ]]; then
        printf 'error: privacy-guard self-test did not reject a bounded-tail canary\n' >&2
        return 1
    fi

    set +e
    scan_paths_for_secret_canaries "${self_test_directory}/scan-target" \
        >"${self_test_directory}/scan.stdout" \
        2>"${self_test_directory}/scan.stderr"
    scan_status=$?
    set -e
    if [[ "$scan_status" != "$PRIVACY_GUARD_STATUS" ||
        -e "${self_test_directory}/scan-target" ]]; then
        printf 'error: privacy-guard self-test did not destroy a scanned canary artifact\n' >&2
        return 1
    fi

    python3 - \
        "$role_password_file" \
        "$role_password_prefix_file" \
        "$self_test_directory" <<'PY'
import base64
import pathlib
import sys
import urllib.parse

password_path, prefix_path, directory_path = sys.argv[1:]
password = pathlib.Path(password_path).read_bytes().removesuffix(b"\n")
prefix = pathlib.Path(prefix_path).read_bytes().removesuffix(b"\n")
if not password.startswith(prefix) or len(password) <= len(prefix):
    raise SystemExit("privacy-guard self-test fixture was invalid")
suffix = password[len(prefix):]
recoverable_fragments = {
    password,
    prefix,
    suffix,
    password.hex().encode("ascii"),
    b"\\x" + password.hex().encode("ascii"),
    base64.b64encode(password),
    urllib.parse.quote_from_bytes(password).encode("ascii"),
}
expected_log = b"qualification output suppressed by privacy guard\n"
expected_stderr = b"error: secret/canary detected in streamed qualification output\n"
expected_bounded_stderr = b"error: qualification output suppressed by privacy guard\n"
expected_scan_stderr = b"error: qualification artifact suppressed by privacy guard\n"
directory = pathlib.Path(directory_path)
diagnostics = sorted(directory.glob("diagnostic-*"))
if not diagnostics:
    raise SystemExit("privacy-guard self-test produced no diagnostics")
for path in diagnostics:
    if path.stat().st_mode & 0o777 != 0o600:
        raise SystemExit("privacy-guard self-test diagnostic was not mode 0600")
    data = path.read_bytes()
    if path.suffix == ".log" and data != expected_log:
        raise SystemExit("privacy-guard self-test retained captured content")
    if path.suffix == ".stdout" and data:
        raise SystemExit("privacy-guard self-test wrote unexpected standard output")
    if path.suffix == ".stderr" and data != expected_stderr:
        raise SystemExit("privacy-guard self-test wrote non-generic failure output")
    if any(fragment in data for fragment in recoverable_fragments):
        raise SystemExit("privacy-guard self-test retained reconstructable credentials")
fixed_diagnostics = {
    "seven-pattern.log": expected_log,
    "seven-pattern.stdout": b"",
    "seven-pattern.stderr": expected_stderr,
    "bounded-tail.log": expected_log,
    "bounded-tail.stdout": b"",
    "bounded-tail.stderr": expected_bounded_stderr,
    "scan.stdout": b"",
    "scan.stderr": expected_scan_stderr,
}
for name, expected in fixed_diagnostics.items():
    path = directory / name
    if path.stat().st_mode & 0o777 != 0o600:
        raise SystemExit("privacy-guard self-test fixed diagnostic was not mode 0600")
    data = path.read_bytes()
    if data != expected:
        raise SystemExit("privacy-guard self-test fixed diagnostic was not generic")
    if any(fragment in data for fragment in recoverable_fragments):
        raise SystemExit("privacy-guard self-test fixed diagnostic retained credentials")
if (directory / "scan-target").exists():
    raise SystemExit("privacy-guard self-test retained a scanned canary artifact")
PY

    /bin/bash -c 'trap "" TERM; while :; do :; done' >/dev/null 2>&1 &
    crash_log_tail_pid=$!
    set +e
    finish_crash_log_capture 0.05 0.05 2>/dev/null
    cleanup_wait_status=$?
    set -e
    if [[ "$cleanup_wait_status" != "137" || -n "$crash_log_tail_pid" ]]; then
        printf 'error: privacy-guard self-test cleanup watchdog was not bounded\n' >&2
        return 1
    fi

    rm -f -- "$role_password_file" "$self_test_directory"/input-*
}

if [[ "$runner_self_test" == "true" ]]; then
    run_privacy_guard_self_test
    remove_secret_material
    rm -rf -- "$private_directory"
    trap - EXIT INT TERM
    printf 'Evidence-object runner privacy-guard self-test passed.\n'
    exit 0
fi

if ! "$trusted_timeout_binary" --kill-after=5s 10s docker info >/dev/null 2>&1; then
    printf 'error: Docker daemon is unavailable or inaccessible\n' >&2
    exit 1
fi

printf 'Pulling immutable PostgreSQL 16.14 and SeaweedFS 4.39 images...\n'
"$trusted_timeout_binary" --kill-after=20s "${pull_timeout_seconds}s" \
    docker pull --quiet "$POSTGRES_IMAGE" 2>&1 | \
    capture_and_scan_stream "$postgres_pull_log"
"$trusted_timeout_binary" --kill-after=20s "${pull_timeout_seconds}s" \
    docker pull --quiet "$SEAWEEDFS_IMAGE" 2>&1 | \
    capture_and_scan_stream "$seaweed_pull_log"

create_internal_network() {
    local name="$1"
    local role="$2"
    local create_log="$3"
    local inspect_log="$4"

    "$trusted_timeout_binary" --kill-after=5s 20s docker network create \
        --driver bridge \
        --internal \
        --label "${GATE_LABEL}=true" \
        --label "${RUN_LABEL}=${run_id}" \
        --label "${ROLE_LABEL}=${role}" \
        "$name" 2>&1 | capture_and_scan_stream "$create_log"
    "$trusted_timeout_binary" --kill-after=5s 10s docker network inspect "$name" 2>&1 | \
        capture_and_scan_stream "$inspect_log"
    if [[ "$("$trusted_timeout_binary" --kill-after=2s 5s docker network inspect --format '{{.Driver}} {{.Internal}}' "$name")" != "bridge true" ]]; then
        printf 'error: qualification network is not an internal bridge\n' >&2
        return 1
    fi
}

# The host reaches each provider through its validated internal-bridge address;
# no host port is published. Separate networks remove PostgreSQL/S3 peer reachability.
printf 'Creating isolated internal Docker networks...\n'
docker_state_may_exist=true
create_internal_network \
    "$postgres_network_name" \
    postgres \
    "$postgres_network_create_log" \
    "$postgres_network_inspect_log"
create_internal_network \
    "$seaweed_network_name" \
    seaweedfs \
    "$seaweed_network_create_log" \
    "$seaweed_network_inspect_log"

postgres_version="$("$trusted_timeout_binary" --kill-after=5s 10s docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
    "$POSTGRES_IMAGE" | python3 -c 'import sys; print(next((line.split("=", 1)[1] for line in sys.stdin if line.startswith("PG_VERSION=")), ""))')"
seaweed_version="$("$trusted_timeout_binary" --kill-after=5s 10s docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' \
    "$SEAWEEDFS_IMAGE")"
if [[ "$postgres_version" != "16.14" || "$seaweed_version" != "4.39" ]]; then
    printf 'error: pulled provider image metadata did not match the qualified versions\n' >&2
    exit 1
fi

capture_inspect() {
    local container_id="$1"
    local output_path="${private_directory}/container-inspect-${#inspect_logs[@]}.json"

    "$trusted_timeout_binary" --kill-after=5s 10s docker inspect "$container_id" 2>&1 | \
        capture_and_scan_stream "$output_path"
    inspect_logs+=("$output_path")
    last_container_inspect_log="$output_path"
}

resolve_internal_container_ipv4() {
    local container_inspect_log="$1"
    local network_inspect_log="$2"
    local expected_network_name="$3"
    local address

    if ! address="$(python3 - \
        "$container_inspect_log" \
        "$network_inspect_log" \
        "$expected_network_name" <<'PY'
import ipaddress
import json
import pathlib
import re
import sys

container_path, network_path, expected_name = sys.argv[1:]
try:
    containers = json.loads(pathlib.Path(container_path).read_text(encoding="utf-8"))
    networks = json.loads(pathlib.Path(network_path).read_text(encoding="utf-8"))
    if not isinstance(containers, list) or len(containers) != 1:
        raise ValueError
    if not isinstance(networks, list) or len(networks) != 1:
        raise ValueError
    network = networks[0]
    network_id = network.get("Id")
    if (
        network.get("Name") != expected_name
        or network.get("Driver") != "bridge"
        or network.get("Internal") is not True
        or not isinstance(network_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", network_id) is None
    ):
        raise ValueError
    attachments = containers[0].get("NetworkSettings", {}).get("Networks")
    if not isinstance(attachments, dict) or set(attachments) != {expected_name}:
        raise ValueError
    attachment = attachments[expected_name]
    address_text = attachment.get("IPAddress")
    if attachment.get("NetworkID") != network_id or not isinstance(address_text, str):
        raise ValueError
    address = ipaddress.IPv4Address(address_text)
    if str(address) != address_text:
        raise ValueError
    ipam_configs = network.get("IPAM", {}).get("Config")
    if not isinstance(ipam_configs, list):
        raise ValueError
    subnets = []
    for config in ipam_configs:
        subnet_text = config.get("Subnet") if isinstance(config, dict) else None
        if isinstance(subnet_text, str):
            subnet = ipaddress.ip_network(subnet_text, strict=False)
            if isinstance(subnet, ipaddress.IPv4Network):
                subnets.append(subnet)
    if not subnets or not any(address in subnet for subnet in subnets):
        raise ValueError
except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
    print("error: provider internal-address metadata was invalid", file=sys.stderr)
    raise SystemExit(1)
print(address)
PY
    )" || [[ ! "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        printf 'error: provider internal IPv4 resolution failed\n' >&2
        return 1
    fi
    printf '%s\n' "$address"
}

printf 'Starting hardened ephemeral PostgreSQL...\n'
postgres_container_id="$("$trusted_timeout_binary" --kill-after=10s 30s docker run \
    --detach \
    --rm \
    --pull never \
    --name "${container_prefix}-postgres" \
    --hostname postgres-object-gate \
    --network "$postgres_network_name" \
    --label "${GATE_LABEL}=true" \
    --label "${RUN_LABEL}=${run_id}" \
    --label "${ROLE_LABEL}=postgres" \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --cap-add SETGID \
    --cap-add SETUID \
    --security-opt no-new-privileges:true \
    --read-only \
    --init \
    --pids-limit 256 \
    --memory 768m \
    --cpus 2 \
    --shm-size 64m \
    --ulimit nofile=1024:1024 \
    --log-driver local \
    --log-opt max-size=1m \
    --log-opt max-file=1 \
    --log-opt compress=false \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,size=16m,mode=3775,uid=70,gid=70 \
    --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=512m,mode=0700,uid=70,gid=70 \
    --mount "type=bind,src=${postgres_bootstrap_file},dst=/run/secrets/bootstrap.sql,readonly" \
    --mount "type=bind,src=${postgres_container_pgpass_file},dst=/run/secrets/postgres.pgpass,readonly" \
    --mount "type=bind,src=${postgres_invalid_pgpass_file},dst=/run/secrets/postgres-invalid.pgpass,readonly" \
    --mount "type=bind,src=${postgres_hba_file},dst=/run/secrets/pg_hba.conf,readonly" \
    --env "POSTGRES_DB=${database_name}" \
    --env "POSTGRES_USER=${database_user}" \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    "$POSTGRES_IMAGE" \
    postgres \
    -c hba_file=/run/secrets/pg_hba.conf \
    -c password_encryption=scram-sha-256 \
    -c log_connections=on \
    -c log_disconnections=on)"
capture_inspect "$postgres_container_id"
postgres_internal_ip="$(resolve_internal_container_ipv4 \
    "$last_container_inspect_log" \
    "$postgres_network_inspect_log" \
    "$postgres_network_name")"

readiness_deadline=$((SECONDS + start_timeout_seconds))
until "$trusted_timeout_binary" --kill-after=2s 5s docker exec "$postgres_container_id" \
    pg_isready --quiet --username "$database_user" --dbname "$database_name"; do
    if ! "$trusted_timeout_binary" --kill-after=2s 5s \
        docker inspect --format '{{.State.Running}}' "$postgres_container_id" 2>/dev/null | \
        tr -d '\n' | python3 -c 'import sys; raise SystemExit(0 if sys.stdin.read() == "true" else 1)'; then
        printf 'error: PostgreSQL container exited before readiness\n' >&2
        exit 1
    fi
    if ((SECONDS >= readiness_deadline)); then
        printf 'error: PostgreSQL did not become ready within %s seconds\n' \
            "$start_timeout_seconds" >&2
        exit 1
    fi
    sleep 1
done

# Bootstrap the SCRAM verifier through the trusted local socket from a mounted
# 0600 SQL file, then prove TCP password authentication using a mounted pgpass
# file. No password enters argv or an environment value.
"$trusted_timeout_binary" --kill-after=5s 15s docker exec --user 0 "$postgres_container_id" \
    psql --set ON_ERROR_STOP=1 \
    --username "$database_user" \
    --dbname "$database_name" \
    --file /run/secrets/bootstrap.sql >/dev/null
authenticated_user="$("$trusted_timeout_binary" --kill-after=5s 15s docker exec \
    --env PGPASSFILE=/run/secrets/postgres.pgpass \
    "$postgres_container_id" \
    psql --host 127.0.0.1 --port 5432 \
    --username "$database_user" --dbname "$database_name" \
    --tuples-only --no-align --command 'SELECT current_user')"
if [[ "$authenticated_user" != "$database_user" ]]; then
    printf 'error: PostgreSQL SCRAM authentication probe returned an unexpected principal\n' >&2
    exit 1
fi
if "$trusted_timeout_binary" --kill-after=5s 15s docker exec \
    --env PGPASSFILE=/run/secrets/postgres-invalid.pgpass \
    "$postgres_container_id" \
    psql --host 127.0.0.1 --port 5432 \
    --username "$database_user" --dbname "$database_name" \
    --tuples-only --no-align --command 'SELECT current_user' \
    >/dev/null 2>&1; then
    printf 'error: PostgreSQL accepted an invalid SCRAM credential\n' >&2
    exit 1
fi

database_url="postgresql://${database_user}@${postgres_internal_ip}:5432/${database_name}"
python3 - \
    "$postgres_password_file" \
    "$postgres_host_pgpass_file" \
    "$postgres_internal_ip" \
    "$database_name" \
    "$database_user" <<'PY'
import pathlib
import sys

password_path, pgpass_path, host, database_name, database_user = sys.argv[1:]
password = pathlib.Path(password_path).read_text(encoding="ascii").strip()
pathlib.Path(pgpass_path).write_text(
    f"{host}:5432:{database_name}:{database_user}:{password}\n",
    encoding="ascii",
)
PY
chmod 600 "$postgres_host_pgpass_file"
assert_private_file "$postgres_host_pgpass_file"

start_seaweed() {
    local container_name

    seaweed_generation=$((seaweed_generation + 1))
    container_name="${container_prefix}-seaweed-${seaweed_generation}"
    seaweed_container_id="$("$trusted_timeout_binary" --kill-after=10s 30s docker run \
        --detach \
        --rm \
        --pull never \
        --name "$container_name" \
        --hostname seaweed-object-gate \
        --network "$seaweed_network_name" \
        --label "${GATE_LABEL}=true" \
        --label "${RUN_LABEL}=${run_id}" \
        --label "${ROLE_LABEL}=seaweedfs" \
        --user "${host_uid}:${host_gid}" \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --read-only \
        --init \
        --pids-limit 256 \
        --memory 768m \
        --cpus 2 \
        --ulimit nofile=2048:2048 \
        --log-driver local \
        --log-opt max-size=1m \
        --log-opt max-file=1 \
        --log-opt compress=false \
        --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777,uid=${host_uid},gid=${host_gid}" \
        --mount "type=bind,src=${seaweed_data_directory},dst=/data" \
        --mount "type=bind,src=${seaweed_s3_config_file},dst=/run/secrets/seaweed-s3.json,readonly" \
        --env GODEBUG=fips140=on \
        --entrypoint /usr/bin/weed \
        "$SEAWEEDFS_IMAGE" \
        -logtostderr=true \
        server \
        -dir=/data \
        -ip=127.0.0.1 \
        -ip.bind=0.0.0.0 \
        -master.telemetry=false \
        -master.volumeSizeLimitMB=64 \
        -volume.max=4 \
        -filer=true \
        -filer.port=8888 \
        -filer.exposeDirectoryData=false \
        -filer.disableDirListing=true \
        -s3=true \
        -s3.port=8333 \
        -s3.ip.bind=0.0.0.0 \
        -s3.config=/run/secrets/seaweed-s3.json \
        -s3.iam=false \
        -s3.port.iceberg=0)"
    capture_inspect "$seaweed_container_id"
    seaweed_internal_ip="$(resolve_internal_container_ipv4 \
        "$last_container_inspect_log" \
        "$seaweed_network_inspect_log" \
        "$seaweed_network_name")"
    s3_endpoint="http://${seaweed_internal_ip}:8333"
}

wait_for_seaweed() {
    local status
    local readiness_deadline=$((SECONDS + start_timeout_seconds))
    local response_file="${private_directory}/seaweed-readiness.response"

    while true; do
        status=""
        if status="$(curl --silent --show-error --max-time 3 --max-filesize 65536 \
            --output "$response_file" --write-out '%{http_code}' \
            "${s3_endpoint}/" 2>/dev/null)"; then
            if [[ "$status" == "403" ]]; then
                return
            fi
        fi
        if ! "$trusted_timeout_binary" --kill-after=2s 5s \
            docker inspect --format '{{.State.Running}}' "$seaweed_container_id" 2>/dev/null | \
            tr -d '\n' | python3 -c 'import sys; raise SystemExit(0 if sys.stdin.read() == "true" else 1)'; then
            printf 'error: SeaweedFS container exited before readiness\n' >&2
            exit 1
        fi
        if ((SECONDS >= readiness_deadline)); then
            printf 'error: SeaweedFS S3 did not become ready within %s seconds\n' \
                "$start_timeout_seconds" >&2
            exit 1
        fi
        sleep 1
    done
}

s3_authenticated_operation() {
    local operation="$1"

    python3 - \
        "$s3_credential_file" \
        "$s3_endpoint" \
        "$bucket_name" \
        "$operation" <<'PY'
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import pathlib
import sys
import urllib.parse

credential_path, endpoint, bucket, operation = sys.argv[1:]
credentials = json.loads(pathlib.Path(credential_path).read_text(encoding="ascii"))
access_key = credentials["access_key_id"]
secret_key = credentials["secret_access_key"]
parsed = urllib.parse.urlparse(endpoint)
try:
    endpoint_address = ipaddress.IPv4Address(parsed.hostname or "")
except ipaddress.AddressValueError:
    raise SystemExit("unsafe S3 qualification endpoint") from None
if parsed.scheme != "http" or parsed.port != 8333:
    raise SystemExit("unsafe S3 qualification endpoint")

method = "PUT" if operation == "create" else "HEAD"
if operation not in {"create", "head"}:
    raise SystemExit("unsupported S3 qualification operation")
path = urllib.parse.quote("/" + bucket, safe="/-_.~")
now = datetime.datetime.now(datetime.timezone.utc)
amz_date = now.strftime("%Y%m%dT%H%M%SZ")
date_stamp = now.strftime("%Y%m%d")
payload_hash = hashlib.sha256(b"").hexdigest()
endpoint_host = str(endpoint_address)
host = f"{endpoint_host}:{parsed.port}"
canonical_headers = (
    f"host:{host}\n"
    f"x-amz-content-sha256:{payload_hash}\n"
    f"x-amz-date:{amz_date}\n"
)
signed_headers = "host;x-amz-content-sha256;x-amz-date"
canonical_request = "\n".join(
    [method, path, "", canonical_headers, signed_headers, payload_hash]
)
scope = f"{date_stamp}/us-east-1/s3/aws4_request"
string_to_sign = "\n".join(
    [
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ]
)

def sign(key, value):
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()

date_key = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
region_key = sign(date_key, "us-east-1")
service_key = sign(region_key, "s3")
signing_key = sign(service_key, "aws4_request")
signature = hmac.new(
    signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
).hexdigest()
authorization = (
    f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
    f"SignedHeaders={signed_headers}, Signature={signature}"
)
headers = {
    "Authorization": authorization,
    "Host": host,
    "X-Amz-Content-Sha256": payload_hash,
    "X-Amz-Date": amz_date,
}
connection = http.client.HTTPConnection(endpoint_host, parsed.port, timeout=10)
try:
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    response.read(4097)
finally:
    connection.close()
expected = 200
if response.status != expected:
    raise SystemExit(
        f"authenticated S3 {operation} failed with HTTP status {response.status}"
    )
PY
}

printf 'Starting hardened SeaweedFS and proving S3 authentication...\n'
start_seaweed
wait_for_seaweed
s3_authenticated_operation create
s3_authenticated_operation head

export_test_environment() {
    # Every exported value is nonsecret metadata or a path to a mode-0600 file.
    export APOLYSIS_TEST_DATABASE_URL="$database_url"
    export PGPASSFILE="$postgres_host_pgpass_file"
    export APOLYSIS_TEST_S3_ENDPOINT="$s3_endpoint"
    export APOLYSIS_TEST_S3_BUCKET="$bucket_name"
    export APOLYSIS_TEST_S3_CREDENTIAL_FILE="$s3_credential_file"
    export APOLYSIS_TEST_OBJECT_WRAPPING_KEY_FILE="$wrapping_key_file"
    export APOLYSIS_TEST_ALLOW_DATABASE_RESET=1
}

assert_log_bound() {
    local path="$1"
    local size

    size="$(stat -c '%s' "$path")"
    if ((size > LOG_LIMIT_BYTES)); then
        printf 'error: qualification log exceeded the %s-byte bound: %s\n' \
            "$LOG_LIMIT_BYTES" "$path" >&2
        return 1
    fi
}

run_real_test() {
    local test_target="$1"
    local test_name="$2"
    local log_path="$3"

    if (
        export_test_environment
        "$trusted_timeout_binary" --kill-after=20s "${test_timeout_seconds}s" \
            "$cargo_binary" test --quiet \
            -p apolysis-evidence-objects \
            --test "$test_target" \
            "$test_name" \
            -- \
            --ignored \
            --exact \
            --test-threads=1 \
            2>&1 | capture_and_scan_stream "$log_path"
    ); then
        assert_log_bound "$log_path"
        return
    else
        local test_status=$?
        printf 'error: real evidence-object test failed: %s (status %s)\n' \
            "$test_name" "$test_status" >&2
        if [[ "$test_status" == "$PRIVACY_GUARD_STATUS" ]]; then
            printf 'error: failure diagnostics suppressed by privacy guard\n' >&2
            return "$test_status"
        fi
        capture_container_log "$postgres_container_id" \
            "${private_directory}/postgres-failure.log" || true
        capture_container_log "$seaweed_container_id" \
            "${private_directory}/seaweed-failure.log" || true
        print_bounded_tail "$log_path" >&2
        printf '%s\n' '--- bounded PostgreSQL provider log ---' >&2
        print_bounded_tail "${private_directory}/postgres-failure.log" >&2
        printf '%s\n' '--- bounded SeaweedFS provider log ---' >&2
        print_bounded_tail "${private_directory}/seaweed-failure.log" >&2
        return "$test_status"
    fi
}

run_gateway_authority_lock_order_test() {
    if (
        export_test_environment
        "$trusted_timeout_binary" --kill-after=20s "${test_timeout_seconds}s" \
            "$cargo_binary" test --quiet \
            -p apolysis-gateway-server \
            --lib \
            authority::store::real_postgres_tests::register_source_obeys_organization_registration_credential_lock_order \
            -- \
            --ignored \
            --exact \
            --test-threads=1 \
            2>&1 | capture_and_scan_stream "$cargo_gateway_authority_lock_order_log"
    ); then
        assert_log_bound "$cargo_gateway_authority_lock_order_log"
        return
    else
        local test_status=$?
        printf 'error: real Gateway authority lock-order test failed (status %s)\n' \
            "$test_status" >&2
        if [[ "$test_status" == "$PRIVACY_GUARD_STATUS" ]]; then
            printf 'error: failure diagnostics suppressed by privacy guard\n' >&2
            return "$test_status"
        fi
        capture_container_log "$postgres_container_id" \
            "${private_directory}/postgres-failure.log" || true
        print_bounded_tail "$cargo_gateway_authority_lock_order_log" >&2
        return "$test_status"
    fi
}

wait_for_crash_ready() {
    local mode="$1"
    local ready_path="$2"
    local log_path="$3"
    local marker=""
    local deadline=$((SECONDS + crash_ready_timeout_seconds))

    while true; do
        if [[ -s "$ready_path" ]]; then
            IFS= read -r marker <"$ready_path"
            if [[ "$marker" != "$mode" ]]; then
                printf 'error: crash seam reported an unexpected readiness marker\n' >&2
                return 1
            fi
            assert_private_file "$ready_path"
            return
        fi
        if ! kill -0 "$crash_process_group" >/dev/null 2>&1; then
            printf 'error: crash-seam test exited before reaching %s\n' "$mode" >&2
            wait "$crash_process_group" >/dev/null 2>&1 || true
            crash_process_group=""
            finish_crash_log_capture || true
            print_bounded_tail "$log_path" >&2
            return 1
        fi
        if ((SECONDS >= deadline)); then
            printf 'error: crash seam did not become ready within %s seconds: %s\n' \
                "$crash_ready_timeout_seconds" "$mode" >&2
            return 1
        fi
        sleep 1
    done
}

start_crash_setup() {
    local mode="$1"
    local state_path="$2"
    local ready_path="$3"
    local log_path="$4"
    local replay_key_path="$5"

    rm -f -- "$state_path" "$ready_path"
    assert_private_file "$replay_key_path"
    crash_log_fifo="${log_path}.pipe"
    rm -f -- "$crash_log_fifo"
    mkfifo -m 600 "$crash_log_fifo"
    capture_and_scan_stream "$log_path" <"$crash_log_fifo" &
    crash_log_tail_pid=$!
    (
        export_test_environment
        export APOLYSIS_TEST_CRASH_MODE="$mode"
        export APOLYSIS_TEST_CRASH_STATE_FILE="$state_path"
        export APOLYSIS_TEST_CRASH_READY_FILE="$ready_path"
        export APOLYSIS_TEST_CRASH_REPLAY_KEY_FILE="$replay_key_path"
        exec setsid "$cargo_binary" test --quiet \
            -p apolysis-evidence-objects \
            --test real_lifecycle \
            real_postgres_and_s3_object_crash_seams_recover \
            -- \
            --ignored \
            --exact \
            --test-threads=1 \
            >"$crash_log_fifo" 2>&1
    ) &
    crash_process_group=$!
    wait_for_crash_ready "$mode" "$ready_path" "$log_path"
    assert_private_file "$state_path"
}

kill_ready_crash_setup() {
    local mode="$1"
    local status

    kill -KILL -- "-${crash_process_group}"
    set +e
    wait "$crash_process_group" 2>/dev/null
    status=$?
    set -e
    crash_process_group=""
    if ! finish_crash_log_capture; then
        printf 'error: crash setup output failed privacy or size qualification: %s\n' \
            "$mode" >&2
        return 1
    fi
    case "$mode" in
        after_reserve) assert_log_bound "$cargo_reserve_setup_log" ;;
        after_put) assert_log_bound "$cargo_put_setup_log" ;;
        *)
            printf 'error: unsupported crash setup mode: %s\n' "$mode" >&2
            return 1
            ;;
    esac
    if [[ "$status" != "137" ]]; then
        printf 'error: %s crash seam did not terminate by SIGKILL (status %s)\n' \
            "$mode" "$status" >&2
        return 1
    fi
}

run_crash_recovery() {
    local mode="$1"
    local state_path="$2"
    local ready_path="$3"
    local log_path="$4"
    local replay_key_path="$5"
    local marker=""

    rm -f -- "$ready_path"
    if (
        export_test_environment
        export APOLYSIS_TEST_CRASH_MODE="$mode"
        export APOLYSIS_TEST_CRASH_STATE_FILE="$state_path"
        export APOLYSIS_TEST_CRASH_READY_FILE="$ready_path"
        export APOLYSIS_TEST_CRASH_REPLAY_KEY_FILE="$replay_key_path"
        "$trusted_timeout_binary" --kill-after=20s "${test_timeout_seconds}s" \
            "$cargo_binary" test --quiet \
            -p apolysis-evidence-objects \
            --test real_lifecycle \
            real_postgres_and_s3_object_crash_seams_recover \
            -- \
            --ignored \
            --exact \
            --test-threads=1 \
            2>&1 | capture_and_scan_stream "$log_path"
    ); then
        assert_log_bound "$log_path"
    else
        local test_status=$?
        printf 'error: crash recovery failed: %s (status %s)\n' \
            "$mode" "$test_status" >&2
        if [[ "$test_status" == "$PRIVACY_GUARD_STATUS" ]]; then
            printf 'error: failure diagnostics suppressed by privacy guard\n' >&2
            return "$test_status"
        fi
        print_bounded_tail "$log_path" >&2
        return "$test_status"
    fi
    if [[ ! -s "$ready_path" ]]; then
        printf 'error: crash recovery omitted its completion marker: %s\n' "$mode" >&2
        return 1
    fi
    IFS= read -r marker <"$ready_path"
    if [[ "$marker" != "$mode" ]]; then
        printf 'error: crash recovery wrote an unexpected completion marker\n' >&2
        return 1
    fi
    assert_private_file "$ready_path"
}

capture_container_log() {
    local container_id="$1"
    local output_path="$2"

    "$trusted_timeout_binary" --kill-after=5s 10s docker logs "$container_id" 2>&1 | \
        capture_and_scan_stream "$output_path"
}

wait_for_exact_container_removal() {
    local container_id="$1"
    local ids_text=""
    local listed_id=""
    local exact_container_present=false
    local deadline=$((SECONDS + 30))

    while true; do
        exact_container_present=false
        if ids_text="$("$trusted_timeout_binary" --kill-after=2s 5s \
            docker ps --all --quiet --no-trunc --filter "id=${container_id}" 2>/dev/null)"; then
            while IFS= read -r listed_id; do
                if [[ "$listed_id" == "$container_id" ]]; then
                    exact_container_present=true
                    break
                fi
            done <<<"$ids_text"
            if [[ "$exact_container_present" == "false" ]]; then
                return
            fi
        fi
        if ((SECONDS >= deadline)); then
            printf 'error: killed SeaweedFS container was not removed within bounds\n' >&2
            return 1
        fi
        sleep 1
    done
}

printf 'Running the direct-SQL lifecycle invariant test...\n'
run_real_test \
    real_schema_invariants \
    migration_0003_rejects_direct_sql_lifecycle_bypasses \
    "$cargo_schema_log"

printf 'Qualifying real non-owner PostgreSQL role boundaries...\n'
run_real_test \
    real_privileges \
    non_owner_application_roles_enforce_privilege_boundaries \
    "$cargo_privileges_log"

printf 'Qualifying fail-closed PostgreSQL served-session trigger mode...\n'
run_real_test \
    real_served_session \
    replica_default_served_sessions_fail_before_mutation \
    "$cargo_served_session_log"

printf 'Qualifying Gateway authority lock order...\n'
run_gateway_authority_lock_order_test

printf 'Qualifying concurrent admission for one upload identity...\n'
run_real_test \
    real_concurrency \
    concurrent_same_upload_identity_admits_exactly_one_object \
    "$cargo_concurrent_identity_log"

printf 'Qualifying bounded database lock waits...\n'
run_real_test \
    real_concurrency \
    served_transactions_bound_database_lock_waits \
    "$cargo_database_deadline_log"

printf 'Qualifying organization-before-object reaper lock order...\n'
run_real_test \
    real_concurrency \
    reaper_claim_obeys_organization_before_object_lock_order \
    "$cargo_reaper_lock_order_log"

printf 'Qualifying per-organization reaper fairness...\n'
run_real_test \
    real_concurrency \
    reaper_batch_claims_at_most_one_object_per_organization \
    "$cargo_reaper_fairness_log"

printf 'Qualifying expired reaper-attempt fencing...\n'
run_real_test \
    real_concurrency \
    expired_reaper_attempt_is_fenced_before_database_commit \
    "$cargo_reaper_expiry_fence_log"

printf 'Qualifying fail-closed policy tightening before finalization...\n'
run_real_test \
    real_concurrency \
    policy_tightening_before_finalize_is_fail_closed \
    "$cargo_policy_tightening_log"

printf 'Qualifying real-bucket backend binding...\n'
run_real_test \
    real_concurrency \
    same_logical_backend_with_different_real_bucket_cannot_reap \
    "$cargo_backend_binding_log"

printf 'Qualifying authenticated deletion-component credential rotation...\n'
run_real_test \
    real_concurrency \
    deletion_acknowledgement_requires_current_rotated_credential \
    "$cargo_deletion_rotation_log"

printf 'Running the complete real PostgreSQL and S3 lifecycle test...\n'
run_real_test \
    real_lifecycle \
    real_postgres_and_s3_object_lifecycle_is_fail_closed \
    "$cargo_normal_log"

printf 'Qualifying SIGKILL recovery after durable reservation...\n'
start_crash_setup after_reserve "$reserve_state_file" "$reserve_ready_file" \
    "$cargo_reserve_setup_log" "$reserve_replay_key_file"
kill_ready_crash_setup after_reserve
run_crash_recovery recover_reserve "$reserve_state_file" "$reserve_ready_file" \
    "$cargo_reserve_recover_log" "$reserve_replay_key_file"

printf 'Qualifying SIGKILL recovery after object PUT...\n'
start_crash_setup after_put "$put_state_file" "$put_ready_file" "$cargo_put_setup_log" \
    "$put_replay_key_file"
kill_ready_crash_setup after_put

# Preserve a bounded pre-crash provider log, then hard-kill the exact SeaweedFS
# container and start the same immutable image against the same data directory.
capture_container_log "$seaweed_container_id" \
    "${private_directory}/seaweed-before-sigkill.log"
"$trusted_timeout_binary" --kill-after=5s 15s \
    docker kill --signal KILL "$seaweed_container_id" >/dev/null
wait_for_exact_container_removal "$seaweed_container_id"
seaweed_container_id=""
run_crash_recovery recover_put_unavailable "$put_state_file" "$put_ready_file" \
    "$cargo_put_unavailable_log" "$put_replay_key_file"
start_seaweed
wait_for_seaweed
s3_authenticated_operation head
run_crash_recovery recover_put "$put_state_file" "$put_ready_file" \
    "$cargo_put_recover_log" "$put_replay_key_file"

# Final authenticated and unauthenticated operations must retain their expected
# results after every real test and the unclean provider restart.
if ! unsigned_status="$(curl --silent --show-error --max-time 5 --max-filesize 65536 \
    --output "${private_directory}/seaweed-final-unauthenticated.response" \
    --write-out '%{http_code}' "${s3_endpoint}/" 2>/dev/null)"; then
    printf 'error: final unauthenticated SeaweedFS request did not complete within bounds\n' >&2
    exit 1
fi
if [[ "$unsigned_status" != "403" ]]; then
    printf 'error: SeaweedFS accepted or mishandled the final unauthenticated request\n' >&2
    exit 1
fi
s3_authenticated_operation head

capture_container_log "$postgres_container_id" "$postgres_log"
capture_container_log "$seaweed_container_id" "$seaweed_log"

# Inspect the live database in its canonical textual dump form. This catches
# accidental plaintext and bytea-hex persistence without exposing credentials.
if ! (
    ulimit -f 8192
    "$trusted_timeout_binary" --kill-after=10s 30s docker exec "$postgres_container_id" \
        pg_dump --data-only --inserts --no-owner --no-privileges \
        --username "$database_user" "$database_name"
) >"$database_dump" 2>/dev/null; then
    printf 'error: could not produce the bounded database privacy scan input\n' >&2
    exit 1
fi
assert_log_bound "$database_dump"

scan_for_secret_canaries() {
    scan_paths_for_secret_canaries \
        "${inspect_logs[@]}" \
        "$postgres_pull_log" \
        "$seaweed_pull_log" \
        "$postgres_network_create_log" \
        "$postgres_network_inspect_log" \
        "$seaweed_network_create_log" \
        "$seaweed_network_inspect_log" \
        "$postgres_hba_file" \
        "$qualification_io_helper" \
        "$postgres_log" \
        "$seaweed_log" \
        "${private_directory}/seaweed-before-sigkill.log" \
        "${private_directory}/seaweed-readiness.response" \
        "${private_directory}/seaweed-final-unauthenticated.response" \
        "$cargo_schema_log" \
        "$cargo_privileges_log" \
        "$cargo_served_session_log" \
        "$cargo_gateway_authority_lock_order_log" \
        "$cargo_normal_log" \
        "$cargo_concurrent_identity_log" \
        "$cargo_database_deadline_log" \
        "$cargo_reaper_lock_order_log" \
        "$cargo_reaper_fairness_log" \
        "$cargo_reaper_expiry_fence_log" \
        "$cargo_policy_tightening_log" \
        "$cargo_backend_binding_log" \
        "$cargo_deletion_rotation_log" \
        "$cargo_reserve_setup_log" \
        "$cargo_reserve_recover_log" \
        "$cargo_put_setup_log" \
        "$cargo_put_unavailable_log" \
        "$cargo_put_recover_log" \
        "$database_dump" \
        "$reserve_state_file" \
        "$reserve_ready_file" \
        "$put_state_file" \
        "$put_ready_file" \
        "$seaweed_data_directory"
}

if ! remove_labelled_containers; then
    printf 'error: exact-run provider cleanup did not complete\n' >&2
    exit 1
fi
if ! remove_labelled_networks; then
    printf 'error: exact-run network cleanup did not complete\n' >&2
    exit 1
fi
printf 'Scanning complete provider output, metadata, data, and database values for secret canaries...\n'
scan_for_secret_canaries

if ! remove_secret_material; then
    printf 'error: qualification secret-file removal failed for run %s\n' "$run_id" >&2
    exit 1
fi
rm -rf -- "$private_directory"
trap - EXIT INT TERM
printf 'Real evidence-object provider qualification passed.\n'

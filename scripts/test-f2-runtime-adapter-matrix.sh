#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_root/target/debug/apolysis-validate-host"
output_dir="${APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/apolysis-f2-runtime-adapter-matrix.XXXXXX")}"
applied=0

if [[ "${APOLYSIS_CONFIRM_RUNTIME_ADAPTER_MATRIX:-0}" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-f2: runtime adapter matrix test is disabled by default because it
temporarily writes Docker, standalone containerd, and k3s runtime configuration
and restarts those services. Set APOLYSIS_CONFIRM_RUNTIME_ADAPTER_MATRIX=1 on a
validation host to run the full Docker/containerd/k3s/Kubernetes adapter matrix.
EOF
    exit 0
fi

run_host() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    else
        docker run --rm \
            --privileged \
            --pid=host \
            --cgroupns=host \
            --network=host \
            -v /:/host \
            alpine:3.20 \
            chroot /host "$@"
    fi
}

host_bash() {
    run_host /bin/bash -lc "$1"
}

wait_for_services() {
    local i
    for i in $(seq 1 90); do
        if systemctl is-active --quiet containerd.service docker.service k3s.service; then
            return 0
        fi
        sleep 1
    done
    systemctl --no-pager --full status containerd.service docker.service k3s.service || true
    return 1
}

wait_for_docker_runtime() {
    local runtime="$1"
    local expected="$2"
    local i
    for i in $(seq 1 60); do
        if docker info --format '{{json .Runtimes}}' | jq -e "has(\"$runtime\") == $expected"; then
            return 0
        fi
        sleep 1
    done
    docker info --format '{{json .Runtimes}}' || true
    return 1
}

start_host_unit() {
    local unit="$1"
    shift
    run_host /bin/systemd-run --unit="$unit" --collect "$@"
}

restart_runtime_services() {
    local unit="apolysis-runtime-adapter-matrix-restart-$$"
    if ! start_host_unit "$unit" /bin/bash -lc \
        "systemctl restart containerd.service docker.service k3s.service"; then
        echo "apolysis-f2: restart runner was interrupted, likely by Docker restart; waiting for host services"
    fi
    wait_for_services
}

make_output_dir_user_writable() {
    [[ "${EUID:-$(id -u)}" -ne 0 ]] || return 0
    run_host /bin/chown -R "$(id -u):$(id -g)" "$output_dir"
}

restore_runtime_registration() {
    [[ "$applied" == "1" ]] || return 0
    echo "apolysis-f2: restoring runtime configuration from $output_dir"
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        rm -f "$output_dir/restore-execution-report.json"
    else
        run_host /bin/rm -f "$output_dir/restore-execution-report.json"
    fi
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$binary" --restore --output "$output_dir"
    else
        local unit="apolysis-runtime-adapter-matrix-restore-$$"
        start_host_unit "$unit" "$binary" --restore --output "$output_dir"
        local i
        for i in $(seq 1 120); do
            [[ -s "$output_dir/restore-execution-report.json" ]] && break
            sleep 1
        done
        if [[ ! -s "$output_dir/restore-execution-report.json" ]]; then
            journalctl -u "$unit" -n 120 --no-pager || true
            return 1
        fi
    fi
    wait_for_services
    make_output_dir_user_writable
    applied=0
}

cleanup() {
    restore_runtime_registration || true
}
trap cleanup EXIT

cd "$repo_root"

for command in docker jq crictl systemctl kubectl; do
    command -v "$command" >/dev/null || {
        echo "apolysis-f2: missing required command: $command" >&2
        exit 2
    }
done

host_bash 'command -v /usr/local/bin/runsc >/dev/null'
host_bash 'command -v /usr/local/bin/containerd-shim-runsc-v1 >/dev/null'
host_bash 'command -v /usr/local/bin/kata-runtime >/dev/null'
host_bash 'command -v /usr/local/bin/containerd-shim-kata-v2 >/dev/null'
host_bash '/usr/local/bin/kata-runtime check --verbose >/dev/null'

cargo test -p apolysis-validation
cargo build -p apolysis-validation --bin apolysis-validate-host

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$binary" --apply-runtime-registration --output "$output_dir"
else
    run_host "$binary" --apply-runtime-registration --output "$output_dir"
fi
applied=1
make_output_dir_user_writable

restart_runtime_services

wait_for_docker_runtime runsc true
host_bash 'crictl --config /dev/null --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info | jq -e '\''.config.containerd.runtimes | has("runc") and has("runsc") and has("kata")'\'''
host_bash 'crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock info | jq -e '\''.config.containerd.runtimes | has("runc") and has("runsc") and has("kata")'\'''

APOLYSIS_REQUIRE_FULL_RUNTIME_ADAPTERS=1 \
APOLYSIS_REQUIRE_DOCKER_ADAPTER=1 \
APOLYSIS_REQUIRE_CONTAINERD_ADAPTER=1 \
APOLYSIS_REQUIRE_K3S_CONTAINERD_ADAPTER=1 \
APOLYSIS_REQUIRE_KUBERNETES_ADAPTER=1 \
    ./scripts/test-f2-runtime-adapters.sh

restore_runtime_registration

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$output_dir" \
        ./scripts/assert-f2-runtime-matrix-restored.sh
else
    host_bash "cd '$repo_root' && APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR='$output_dir' ./scripts/assert-f2-runtime-matrix-restored.sh"
fi
wait_for_docker_runtime runsc false
host_bash 'crictl --config /dev/null --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info | jq -e '\''(.config.containerd.runtimes // {}) as $r | (($r | has("runsc") | not) and ($r | has("kata") | not))'\'''
host_bash 'crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock info | jq -e '\''(.config.containerd.runtimes // {}) as $r | (($r | has("runsc") | not) and ($r | has("kata") | not))'\'''

APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR="$output_dir" \
    ./scripts/write-f4-live-runtime-evidence-bundle.sh
test -s "$output_dir/f4-live-runtime-evidence-request.json"
test -s "$output_dir/f4-live-runtime-evidence-report.json"

echo "apolysis-f2: runtime adapter matrix passed; artifacts kept at $output_dir"

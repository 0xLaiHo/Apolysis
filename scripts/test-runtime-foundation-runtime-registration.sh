#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_root/target/debug/apolysis-validate-host"
output_dir="${APOLYSIS_RUNTIME_REGISTRATION_OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/apolysis-runtime-foundation-runtime-registration.XXXXXX")}"
applied=0

if [[ "${APOLYSIS_CONFIRM_RUNTIME_REGISTRATION:-0}" != "1" ]]; then
    cat >&2 <<'EOF'
apolysis-runtime_foundation: runtime registration test is disabled by default because it writes
Docker, standalone containerd, and k3s runtime configuration and restarts those
services. Set APOLYSIS_CONFIRM_RUNTIME_REGISTRATION=1 to run it on a validation
host after backing up any workload you cannot restart.
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

start_host_unit() {
    local unit="$1"
    shift
    run_host /bin/systemd-run --unit="$unit" --collect "$@"
}

restart_runtime_services() {
    local unit="apolysis-runtime-registration-restart-$$"
    if ! start_host_unit "$unit" /bin/bash -lc \
        "systemctl restart containerd.service docker.service k3s.service"; then
        echo "apolysis-runtime_foundation: restart runner was interrupted, likely by Docker restart; waiting for host services"
    fi
    wait_for_services
}

restore_runtime_registration() {
    [[ "$applied" == "1" ]] || return 0
    echo "apolysis-runtime_foundation: restoring runtime configuration from $output_dir"
    rm -f "$output_dir/restore-execution-report.json"
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$binary" --restore --output "$output_dir"
    else
        local unit="apolysis-runtime-registration-restore-$$"
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
    applied=0
}

cleanup() {
    restore_runtime_registration || true
}
trap cleanup EXIT

cd "$repo_root"

for command in docker jq crictl systemctl; do
    command -v "$command" >/dev/null || {
        echo "apolysis-runtime_foundation: missing required command: $command" >&2
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

restart_runtime_services

docker info --format '{{json .Runtimes}}' | jq -e 'has("runsc")'
host_bash 'crictl --config /dev/null --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info | jq -e '\''.config.containerd.runtimes | has("runc") and has("runsc") and has("kata")'\'''
host_bash 'crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock info | jq -e '\''.config.containerd.runtimes | has("runc") and has("runsc") and has("kata")'\'''

restore_runtime_registration

docker info --format '{{json .Runtimes}}' | jq -e 'has("runsc") | not'
host_bash 'test ! -e /etc/containerd/config.toml'
host_bash 'test ! -e /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml'
host_bash 'crictl --config /dev/null --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info | jq -e '\''(.config.containerd.runtimes // {}) as $r | (($r | has("runsc") | not) and ($r | has("kata") | not))'\'''
host_bash 'crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock info | jq -e '\''(.config.containerd.runtimes // {}) as $r | (($r | has("runsc") | not) and ($r | has("kata") | not))'\'''

echo "apolysis-runtime_foundation: runtime registration apply/restore passed; artifacts kept at $output_dir"

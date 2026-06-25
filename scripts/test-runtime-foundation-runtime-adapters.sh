#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_live_adapter_test() {
    local test_name="$1"
    if [[ "$test_name" == "live_docker_engine_adapter_recovers_after_systemd_restart" ||
        "$test_name" == "live_containerd_cri_adapter_recovers_after_systemd_restart" ||
        "$test_name" == "live_k3s_containerd_cri_adapter_recovers_after_systemd_restart" ]]; then
        if ! cargo test -p apolysis-daemon --test runtime_adapters \
            "$test_name" \
            -- --ignored --exact --list | grep -Fqx "$test_name: test"; then
            echo "apolysis-runtime_foundation: live adapter test not found: $test_name" >&2
            exit 1
        fi
        cargo test -p apolysis-daemon --test runtime_adapters \
            "$test_name" \
            -- --ignored --exact --nocapture
    elif [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        if ! cargo test -p apolysis-daemon --test runtime_adapters \
            "$test_name" \
            -- --ignored --exact --list | grep -Fqx "$test_name: test"; then
            echo "apolysis-runtime_foundation: live adapter test not found: $test_name" >&2
            exit 1
        fi
        cargo test -p apolysis-daemon --test runtime_adapters \
            "$test_name" \
            -- --ignored --exact --nocapture
    else
        local docker_env=()
        local env_name
        local env_value
        for env_name in \
            APOLYSIS_RUNTIME_GUARDRAILS_RUNTIME_ADAPTER_EVIDENCE_OUTPUT \
            APOLYSIS_RUNTIME_GUARDRAILS_GVISOR_METADATA_EVIDENCE_OUTPUT \
            APOLYSIS_RUNTIME_GUARDRAILS_KUBERNETES_AGENT_SANDBOX_EVIDENCE_OUTPUT \
            APOLYSIS_RUNTIME_GUARDRAILS_KATA_BOUNDARY_EVIDENCE_OUTPUT
        do
            env_value="${!env_name:-}"
            if [[ -n "$env_value" ]]; then
                docker_env+=(
                -e
                "$env_name=$env_value"
                )
            fi
        done
        docker run --rm \
            "${docker_env[@]}" \
            --privileged \
            --pid=host \
            --cgroupns=host \
            --network=host \
            -v /:/host \
            alpine:3.20 \
            chroot /host /bin/bash -lc "
                set -euo pipefail
                cd '$repo_root'
                export HOME='${HOME:-/home/mactavish}'
                export CARGO_HOME='${CARGO_HOME:-${HOME:-/home/mactavish}/.cargo}'
                export RUSTUP_HOME='${RUSTUP_HOME:-${HOME:-/home/mactavish}/.rustup}'
                export CARGO_TARGET_DIR=/tmp/apolysis-runtime-foundation-live-target
                export PATH='${CARGO_HOME:-${HOME:-/home/mactavish}/.cargo}/bin:/usr/local/bin:/usr/bin:/bin'
                export APOLYSIS_REQUIRE_FULL_RUNTIME_ADAPTERS='${APOLYSIS_REQUIRE_FULL_RUNTIME_ADAPTERS:-0}'
                if ! cargo test -p apolysis-daemon --test runtime_adapters '$test_name' -- --ignored --exact --list | grep -Fqx '$test_name: test'; then
                    echo 'apolysis-runtime_foundation: live adapter test not found: $test_name' >&2
                    exit 1
                fi
                cargo test -p apolysis-daemon --test runtime_adapters '$test_name' -- --ignored --exact --nocapture
            "
    fi
}

cargo test -p apolysis-daemon --test runtime_adapters
cargo test -p apolysis-daemon --test daemon_pipeline
cargo test -p apolysis-daemon --test metrics
cargo test -p apolysis-feedback

if [[ "${APOLYSIS_REQUIRE_DOCKER_ADAPTER:-0}" == "1" ]]; then
    run_live_adapter_test live_docker_engine_adapter_recovers_after_systemd_restart
    run_live_adapter_test live_docker_engine_adapter_discovers_labelled_container
    run_live_adapter_test live_docker_engine_adapter_recovers_after_socket_disconnect
else
    echo "apolysis-runtime_foundation: Docker live adapter validation skipped; set APOLYSIS_REQUIRE_DOCKER_ADAPTER=1 to run it"
fi

if [[ "${APOLYSIS_REQUIRE_CONTAINERD_ADAPTER:-0}" == "1" ]]; then
    run_live_adapter_test live_containerd_cri_adapter_recovers_after_systemd_restart
    run_live_adapter_test live_containerd_cri_adapter_discovers_labelled_containers
    run_live_adapter_test live_containerd_cri_adapter_recovers_after_socket_disconnect
else
    echo "apolysis-runtime_foundation: standalone containerd live adapter validation skipped; set APOLYSIS_REQUIRE_CONTAINERD_ADAPTER=1 to run it"
fi

if [[ "${APOLYSIS_REQUIRE_K3S_CONTAINERD_ADAPTER:-0}" == "1" ]]; then
    run_live_adapter_test live_k3s_containerd_cri_adapter_recovers_after_systemd_restart
    run_live_adapter_test live_k3s_containerd_cri_adapter_discovers_labelled_containers
    run_live_adapter_test live_k3s_containerd_cri_adapter_recovers_after_socket_disconnect
else
    echo "apolysis-runtime_foundation: k3s/containerd live adapter validation skipped; set APOLYSIS_REQUIRE_K3S_CONTAINERD_ADAPTER=1 to run it"
fi

if [[ "${APOLYSIS_REQUIRE_KUBERNETES_ADAPTER:-0}" == "1" ]]; then
    run_live_adapter_test live_kubernetes_cli_adapter_discovers_annotated_pods
    run_live_adapter_test live_kubernetes_cli_adapter_recovers_after_cri_socket_disconnect
else
    echo "apolysis-runtime_foundation: Kubernetes live adapter validation skipped; set APOLYSIS_REQUIRE_KUBERNETES_ADAPTER=1 to run it"
fi

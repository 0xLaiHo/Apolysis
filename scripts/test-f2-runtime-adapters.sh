#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-daemon --test runtime_adapters
cargo test -p apolysis-daemon --test daemon_pipeline
cargo test -p apolysis-daemon --test metrics
cargo test -p apolysis-feedback

if [[ "${APOLYSIS_REQUIRE_DOCKER_ADAPTER:-0}" == "1" ]]; then
    cargo test -p apolysis-daemon --test runtime_adapters \
        live_docker_engine_adapter_discovers_labelled_container \
        -- --ignored --exact --nocapture
else
    echo "apolysis-f2: Docker live adapter validation skipped; set APOLYSIS_REQUIRE_DOCKER_ADAPTER=1 to run it"
fi

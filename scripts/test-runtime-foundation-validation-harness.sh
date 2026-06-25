#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-runtime-foundation-validation.XXXXXX")"

cleanup() {
    rm -rf "$output_dir" 2>/dev/null || \
        docker run --rm \
            --privileged \
            -v /:/host \
            alpine:3.20 \
            chroot /host rm -rf "$output_dir" 2>/dev/null || true
}
trap cleanup EXIT

cd "$repo_root"
cargo test -p apolysis-validation
cargo build -p apolysis-validation --bin apolysis-validate-host

if [[ "${EUID:-$(id -u)}" -eq 0 || -r /var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl ]]; then
    ./target/debug/apolysis-validate-host \
        --dry-run \
        --output "$output_dir"
else
    docker run --rm \
        --privileged \
        --pid=host \
        --cgroupns=host \
        --network=host \
        -v /:/host \
        alpine:3.20 \
        chroot /host /bin/bash -lc \
        "set -euo pipefail; '$repo_root/target/debug/apolysis-validate-host' --dry-run --output '$output_dir'"
fi

for artifact in backup-manifest.json service-state.json kubernetes-context.json restore-plan.json; do
    test -s "$output_dir/$artifact"
done

echo "apolysis-runtime_foundation: validation harness dry-run passed"

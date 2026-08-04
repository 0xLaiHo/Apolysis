#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${APOLYSIS_CONFIRM_QUALIFICATION:-0}" != "1" ]]; then
    printf 'live qualification capture requires APOLYSIS_CONFIRM_QUALIFICATION=1\n' >&2
    exit 2
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'live qualification capture requires command: %s\n' "$1" >&2
        exit 2
    }
}

for qualification_command in git date cargo rustc python3; do
    require_command "$qualification_command"
done

if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
    printf 'live qualification capture requires a clean Git worktree\n' >&2
    exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="$repo_root/target/qualification/$timestamp"
mkdir -p "$repo_root/target/qualification"
if ! mkdir "$output_dir"; then
    printf 'qualification output already exists: %s\n' "$output_dir" >&2
    exit 2
fi

printf 'running full live prerequisite check\n'
if ! APOLYSIS_REQUIRE_BPF=1 "$repo_root/scripts/check-bpf-prereqs.sh" live \
    >"$output_dir/prerequisites.log" 2>&1; then
    printf 'live qualification prerequisites failed; see %s\n' \
        "$output_dir/prerequisites.log" >&2
    exit 1
fi

printf 'building the production eBPF object\n'
if ! APOLYSIS_REQUIRE_BPF=1 "$repo_root/scripts/build-ebpf.sh" \
    >"$output_dir/build.log" 2>&1; then
    printf 'live qualification build failed; see %s\n' "$output_dir/build.log" >&2
    exit 1
fi

printf 'loading and attaching the production observer\n'
mkdir -p "$output_dir/tmp"
if ! TMPDIR="$output_dir/tmp" APOLYSIS_REQUIRE_BPF=1 \
    "$repo_root/scripts/test-live-observer.sh" \
    >"$output_dir/live-attach.log" 2>&1; then
    printf 'live qualification attach gate failed; see %s\n' \
        "$output_dir/live-attach.log" >&2
    exit 1
fi

qualification_samples="${APOLYSIS_QUALIFICATION_SAMPLES:-3}"
if [[ ! "$qualification_samples" =~ ^[1-9][0-9]*$ ]] ||
    (( qualification_samples > 100 )); then
    printf 'APOLYSIS_QUALIFICATION_SAMPLES must be an integer from 1 to 100\n' >&2
    exit 2
fi

printf 'building the qualification-only workload driver\n'
if ! cargo build --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p apolysis-cli --bin apolysis-qualification \
    >"$output_dir/qualification-build.log" 2>&1; then
    printf 'qualification workload build failed; see %s\n' \
        "$output_dir/qualification-build.log" >&2
    exit 1
fi
qualification_binary="$repo_root/target/debug/apolysis-qualification"
production_object="$repo_root/target/ebpf/apolysis_observer.bpf.o"
measurement_root="$output_dir/measurements"
mkdir "$measurement_root"

run_off_trial() {
    local workload="$1"
    local trial_dir="$2"
    mkdir "$trial_dir"
    mkdir "$trial_dir/scratch"
    "$qualification_binary" run-workload \
        "$repo_root" "$workload" "$trial_dir/scratch" \
        "$trial_dir/workload-raw.json"
}

run_on_trial() {
    local workload="$1"
    local trial_dir="$2"
    local log_path="$3"
    mkdir "$trial_dir"
    "$qualification_binary" measure-live \
        "$repo_root" "$production_object" "$workload" "$trial_dir" \
        >"$log_path" 2>&1
}

printf 'capturing alternating collector-off/on synthetic trials\n'
for workload in idle representative burst; do
    workload_root="$measurement_root/$workload"
    mkdir "$workload_root"
    for ((sample = 1; sample <= qualification_samples; sample++)); do
        pair_root="$workload_root/pair-$(printf '%03d' "$sample")"
        mkdir "$pair_root"
        if (( sample % 2 == 1 )); then
            if ! run_off_trial "$workload" "$pair_root/off" \
                >"$pair_root/off.log" 2>&1 ||
                ! run_on_trial "$workload" "$pair_root/on" "$pair_root/on.log"; then
                printf 'qualification trial failed: workload=%s sample=%s; see %s\n' \
                    "$workload" "$sample" "$pair_root" >&2
                exit 1
            fi
        else
            if ! run_on_trial "$workload" "$pair_root/on" "$pair_root/on.log" ||
                ! run_off_trial "$workload" "$pair_root/off" \
                    >"$pair_root/off.log" 2>&1; then
                printf 'qualification trial failed: workload=%s sample=%s; see %s\n' \
                    "$workload" "$sample" "$pair_root" >&2
                exit 1
            fi
        fi
    done
done

cargo run --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p apolysis-cli --bin apolysis-qualification -- capture-preflight \
    "$repo_root" "$output_dir/preflight-evidence.json"

set +e
"$repo_root/scripts/check-qualification-envelope.sh" \
    --envelope "$repo_root/qualification/envelope-v1.json" \
    --evidence "$output_dir/preflight-evidence.json" \
    >"$output_dir/decision.json"
decision_status=$?
set -e

case "$decision_status" in
    0)
        printf 'qualification profile passed: %s\n' "$output_dir"
        ;;
    1)
        printf 'preflight captured; numeric workloads remain unqualified: %s\n' "$output_dir"
        exit 1
        ;;
    *)
        printf 'qualification checker failed; see %s\n' "$output_dir/decision.json" >&2
        exit "$decision_status"
        ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit real-provider/eBPF validation of the native Rust entry. Run as the
# ordinary user; apolysis elevates only its collector. This gate deliberately
# selects each product's own noninteractive mode for a bounded synthetic task.
# It does not change the daily entry's native UI, global config, permissions,
# authentication, or application-owned history. Provider stdout is discarded,
# apart from fixed error categories; never save a transcript. Optional arguments
# after -- are native options.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required=0
agent=
native_options=()
usage() {
    printf 'Usage: %s --agent codex|claude|cursor|pi|opencode [--require-all] [-- native options]\n' "$0"
}
while (( $# )); do
    case "$1" in
        --agent)
            [[ -z "$agent" && $# -ge 2 && "$2" != --* ]] || { usage >&2; exit 2; }
            agent="$2"
            shift 2
            ;;
        --require-all) required=1; shift ;;
        --) shift; native_options=("$@"); break ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$agent" in
    codex|claude|cursor|pi|opencode) ;;
    *) usage >&2; exit 2 ;;
esac
skip_or_fail() {
    if [[ "$required" == 1 ]]; then
        printf 'apolysis-native-live: FAIL: %s\n' "$1" >&2
        exit 1
    fi
    printf 'apolysis-native-live: SKIP: %s\n' "$1"
    exit 0
}
fail() {
    printf 'apolysis-native-live: FAIL: %s\n' "$1" >&2
    [[ -z "${run_dir:-}" ]] || printf 'apolysis-native-live: retained run: %s\n' "$run_dir" >&2
    exit 1
}

[[ "$EUID" != 0 ]] || skip_or_fail 'run as your normal user without sudo'
[[ "$(uname -s)" == Linux ]] || skip_or_fail 'Linux is required'
for name in jq timeout mktemp realpath cmp sudo stat; do
    command -v "$name" >/dev/null 2>&1 || skip_or_fail "missing $name"
done
native_binary="$agent"
[[ "$agent" != cursor ]] || native_binary=cursor-agent
command -v "$native_binary" >/dev/null 2>&1 || skip_or_fail 'the selected native application is not installed in PATH'
binary="${APOLYSIS_BIN:-$repo_root/target/debug/apolysis}"
bpf="${APOLYSIS_BPF_OBJECT:-$repo_root/target/ebpf/apolysis_observer.bpf.o}"
[[ -x "$binary" && -r "$bpf" ]] || skip_or_fail 'build the CLI and matching BPF object first'
binary="$(realpath "$binary")"
bpf="$(realpath "$bpf")"
[[ -r /sys/kernel/btf/vmlinux && -e /sys/fs/cgroup/cgroup.controllers ]] ||
    skip_or_fail 'kernel BTF and cgroup v2 are required'
time_limit="${APOLYSIS_NATIVE_TEST_TIMEOUT:-300}"
[[ "$time_limit" =~ ^[1-9][0-9]*$ ]] && (( time_limit <= 3600 )) ||
    fail 'APOLYSIS_NATIVE_TEST_TIMEOUT must be between 1 and 3600 seconds'

mkdir -p "$repo_root/target"
run_dir="$(mktemp -d "$repo_root/target/native-observe-live-$agent.XXXXXXXX")"
workspace="$run_dir/workspace"
captures="$run_dir/captures"
mkdir -m 700 "$workspace" "$captures"
sentinel='APOLYSIS_NATIVE_PROMPT_PRIVATE_CANARY_6108'
prompt="This is a bounded synthetic native-tool validation in the current working directory. Use the native shell tool to run exactly these lines:
# APOLYSIS_REASON_CODE=verify_change
printf 'apolysis-native-ok\\n' > native-result.txt && cat native-result.txt
Do not use file-edit tools, run Python, change directories, inspect home configuration, read credentials or evidence, or start background processes. The following prompt-only privacy canary must not appear in tool commands, descriptions, summaries, task files, or your answer: $sentinel. After the command completes, briefly report completion."

case "$agent" in
    claude) native_args=(-p --allowedTools Bash --output-format json) ;;
    pi) native_args=(-p) ;;
    opencode) native_args=(run --dir "$workspace" --format json) ;;
    codex) native_args=(exec --skip-git-repo-check --json) ;;
    cursor) native_args=(--print --output-format json) ;;
esac
native_args+=("${native_options[@]}" "$prompt")
printf 'apolysis-native-live: testing %s with its native noninteractive options\n' "$agent" >&2
printf 'apolysis-native-live: private run: %s\n' "$run_dir" >&2
# Existing auth and history behavior remain native. No credential values or
# original command-line arguments are written to validation artifacts.
# Native applications may emit failure details only on JSON stdout. Print fixed
# categories, never arbitrary provider messages, tool results, or prompt text.
classify_native_errors() {
    jq --unbuffered -Rr '
        fromjson? | select(type == "object") |
        select(.type == "error" or .is_error == true or (.error? != null)) |
        (.error.name? // .error.type? // .error.code? // .subtype? // "") as $kind |
        (if (["ProviderModelNotFoundError", "ModelNotFoundError"] | index($kind)) != null then
            "model selection failed"
        elif (["ProviderAuthError", "AuthenticationError", "UnauthorizedError"] | index($kind)) != null then
            "authentication failed"
        elif (["ConfigInvalidError", "ConfigError", "InvalidConfigError"] | index($kind)) != null then
            "native configuration failed"
        elif (["APICallError", "APIError"] | index($kind)) != null then
            "provider API call failed"
        else "native application reported a JSON error" end) |
        "apolysis-native-live: " + . + "; provider details omitted"
    ' >&2
}
set +e
# Exercise the entry under an ordinary permissive umask. Its exported evidence
# must still use explicit private modes; the gate's own artifacts retain 077.
(
    umask 022
    timeout --foreground --signal=INT --kill-after=30s "${time_limit}s" \
        "$binary" observe --agent "$agent" --workspace "$workspace" \
        --output-dir "$captures" --bpf-object "$bpf" --shell-bridge /bin/bash \
        -- "${native_args[@]}"
) | classify_native_errors
statuses=("${PIPESTATUS[@]}")
set -e
[[ "${statuses[0]}" == 0 ]] || fail 'native application or capture failed; authentication, provider and timeout failures are not passes'
[[ "${statuses[1]}" == 0 ]] || fail 'native output privacy filter failed'

shopt -s nullglob
results=("$captures"/native-"$agent"-*/evidence/result.json)
[[ "${#results[@]}" == 1 ]] || fail 'expected exactly one report for this invocation'
result="${results[0]}"
evidence="${result%/result.json}"
private_evidence() {
    local artifact
    [[ -d "$evidence" && ! -L "$evidence" &&
        "$(stat -c '%u:%a' -- "$evidence")" == "$EUID:700" ]] || return 1
    for artifact in "$evidence"/* "$evidence"/.[!.]* "$evidence"/..?*; do
        [[ -f "$artifact" && ! -L "$artifact" &&
            "$(stat -c '%u:%a' -- "$artifact")" == "$EUID:600" ]] || return 1
    done
}
private_evidence || fail 'evidence must contain only current-user regular files with mode 600 in a current-user directory with mode 700'
[[ -f "$workspace/native-result.txt" ]] || fail 'the native tool did not create its synthetic output in the requested workspace'
printf 'apolysis-native-ok\n' | cmp -s - "$workspace/native-result.txt" || fail 'synthetic output differs from the expected exact bytes'

jq -e --arg agent "$agent" '
    .record_type == "native_observation_report" and .controller_runtime == "rust" and
    .agent == $agent and .capture_status == "complete" and
    .correlation_status == "complete" and .report_status == "complete" and
    .application.status == "exited" and .application.exit_code == 0 and .application.signal == null and
    (.kernel_events | type == "number" and . > 0) and .loss_or_failure_count == 0 and
    (.truncations | type == "number" and . >= 0) and
    .totals.tool_calls >= 1 and .totals.exact_relations >= 1 and
    (.diagnostics | length == 0) and (.controller_errors | length == 0) and
    (.totals.correlation_diagnostics | length == 0) and (.totals.reason_diagnostics | length == 0)
' "$result" > /dev/null || fail 'the native report did not meet the complete capture and attribution gate'

# Independently require the real raw -> canonical -> exact relation chain for
# the synthetic target file. The readable report alone is not sufficient proof.
jq -n -e --slurpfile report "$result" \
    --slurpfile intents "$evidence/intent.jsonl" \
    --slurpfile timeline "$evidence/timeline.jsonl" \
    --slurpfile relations "$evidence/correlation.jsonl" '
    $report[0].session_id as $session |
    [$timeline[] | select(.record_type == "raw_kernel_event")] as $raw |
    [$timeline[] | select(.record_type == "event")] as $events |
    [$events[] | select(.resource == "agent-root-pid")] as $roots |
    [$relations[] | select(.record_type == "intent_correlation" and
        .relation_status == "exact" and .match_basis == "intent_id" and
        .session_id == $session and .resource == "native-result.txt" and
        (.event_type == "file_open" or .event_type == "file_create"))] as $targets |
    ($raw | length) == $report[0].kernel_events and
    ($roots | length) == 1 and
    any($raw[]; (.pid | tostring) == $roots[0].action and
        (.event_name == "sched_process_exec" or .event_name == "execve" or .event_name == "execveat")) and
    any($targets[];
        . as $relation |
        ([$intents[] | select(.record_type == "intent" and .session_id == $session and
            .intent_id == $relation.intent_id and .intent_source == $relation.intent_source and
            .observation_mode == "local_shell")] | length) == 1 and
        any($raw[]; .event_id == $relation.raw_event_id and .session_id == $session and
            .intent_id == $relation.intent_id and .pid == $relation.pid and .resource == $relation.resource) and
        any($events[]; .raw_event_id == $relation.raw_event_id and .session_id == $session and
            .intent_id == $relation.intent_id and .pid == $relation.pid and
            .event_type == $relation.event_type and .resource == $relation.resource))
' > /dev/null || fail 'the synthetic file lacks a unique declaration and matching raw/canonical/exact evidence chain'

artifacts=("$evidence"/*.jsonl)
jq -s -e --arg sentinel "$sentinel" 'all(.[]; tostring | contains($sentinel) | not)' \
    "${artifacts[@]}" > /dev/null || fail 'the prompt-only privacy canary appeared in exported JSONL'
[[ -s "$evidence/report.html" && -s "$evidence/report.md" ]] || fail 'readable reports were not generated'
jq '{record_type:"native_live_validation",status:"passed",agent,session_id,
    native_invocation:"explicit_product_noninteractive_mode",interactive_tui_verified:false,
    outcome_check:"native-result.txt_exact_bytes",prompt_canary_absent:true,
    native_history_policy:"unchanged",shell_bridge:"/bin/bash",
    kernel_events,loss_or_failure_count,truncations,
    tool_calls:.totals.tool_calls,exact_relations:.totals.exact_relations}' \
    "$result" > "$evidence/validation.json"
private_evidence || fail 'evidence permissions changed while writing the validation result'
jq -r '"apolysis-native-live: PASS: agent=\(.agent) events=\(.kernel_events) exact=\(.exact_relations) truncations=\(.truncations) loss/failures=\(.loss_or_failure_count)"' \
    "$evidence/validation.json"
printf 'apolysis-native-live: readable report: %s/report.html\n' "$evidence"

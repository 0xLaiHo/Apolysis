#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit privileged/provider gate for the Rust chat controller. Runs only the
# fixed three-turn synthetic smoke conversation, using the invoking user's Claude
# authentication. No Kubernetes or global product configuration is changed.
# bpftrace or strace observes the controller's full descendant tree. Only exec
# filenames and counts are exported. The strace fallback temporarily includes
# argv for this fixed synthetic smoke in a root-private directory, removed on
# exit; it never expands environment values (-v is forbidden). Do not adapt this
# gate to record an ordinary user conversation. Empty/truncated filenames or
# trace warnings fail the gate. This is run evidence, not hostile-code proof.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required="${APOLYSIS_REQUIRE_BPF:-0}"
if [[ "${1:-}" == --require-all && $# == 1 ]]; then
    required=1
elif [[ $# != 0 ]]; then
    printf 'Usage: %s [--require-all]\n' "$0" >&2
    exit 2
fi
skip() {
    printf 'apolysis-chat-live: SKIP: %s\n' "$1"
    [[ "$required" != 1 ]] || exit 1
    exit 0
}
fail() {
    printf 'apolysis-chat-live: FAIL: %s\n' "$1" >&2
    exit 1
}

[[ "$EUID" == 0 && "${SUDO_UID:-0}" =~ ^[0-9]+$ && "${SUDO_UID:-0}" != 0 &&
    "${SUDO_GID:-0}" =~ ^[0-9]+$ && "${SUDO_GID:-0}" != 0 ]] ||
    skip 'explicit sudo from a non-root invoking user is required'
for name in jq setpriv timeout realpath; do
    command -v "$name" >/dev/null 2>&1 || skip "missing $name"
done
strace_bin="${APOLYSIS_STRACE:-$(command -v strace || true)}"
trace_backend="${APOLYSIS_EXEC_TRACER:-auto}"
if [[ "$trace_backend" == auto ]]; then
    if [[ -n "$strace_bin" && -x "$strace_bin" ]]; then
        trace_backend=strace
    else
        trace_backend=bpftrace
    fi
fi
case "$trace_backend" in
    strace)
        [[ -n "$strace_bin" && -x "$strace_bin" ]] || skip 'strace is unavailable; set APOLYSIS_STRACE to a verified local binary'
        command -v gawk >/dev/null 2>&1 || skip 'gawk is required to decode strace filenames'
        strace_bin="$(realpath "$strace_bin")"
        ;;
    bpftrace)
        command -v bpftrace >/dev/null 2>&1 || skip 'bpftrace or strace is required'
        ;;
    *) fail 'APOLYSIS_EXEC_TRACER must be auto, strace or bpftrace' ;;
esac
binary="$(realpath "${APOLYSIS_BIN:-$repo_root/target/debug/apolysis}")"
bpf="$repo_root/target/ebpf/apolysis_observer.bpf.o"
[[ -x "$binary" && -f "$bpf" ]] || skip 'build the CLI and eBPF object first'
set +e
APOLYSIS_REQUIRE_BPF="$required" "$repo_root/scripts/check-bpf-prereqs.sh" live
preflight=$?
set -e
[[ "$preflight" != 77 ]] || skip 'live BPF prerequisites are unavailable'
[[ "$preflight" == 0 ]] || fail 'live BPF preflight failed'

# A new parent makes result discovery specific to this invocation. Only its
# root-created chat child and unprivileged publisher write beneath it.
run_dir="$(mktemp -d "$repo_root/target/reason-chat-live.XXXXXXXX")"
chmod 711 "$run_dir"
private="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-chat-exec-trace.XXXXXXXX")"
cleanup() {
    rm -rf -- "$private"
}
trap cleanup EXIT

cat > "$private/exec.bt" <<'BPF'
config = {
    max_strlen = 256;
    max_map_keys = 16384;
    missing_probes = "error";
}

BEGIN
{
    @tracked[(uint64)cpid] = 1;
    // Baseline one distinguishes a successful trace from a missing scalar map.
    @trace_errors = count();
    if (!@tracked[(uint64)cpid]) {
        @trace_errors = count();
    }
}

tracepoint:sched:sched_process_fork
/@tracked[(uint64)args.parent_pid]/
{
    // Despite their names, these fields contain task->pid, i.e. thread IDs.
    @tracked[(uint64)args.child_pid] = 1;
    if (!@tracked[(uint64)args.child_pid]) {
        @trace_errors = count();
    }
}

tracepoint:sched:sched_process_exec
/@tracked[(uint64)args.old_pid] || @tracked[(uint64)args.pid]/
{
    // A non-leader thread can acquire the group leader's ID during exec.
    @tracked[(uint64)args.pid] = 1;
    if (!@tracked[(uint64)args.pid]) {
        @trace_errors = count();
    }
    if (args.old_pid != args.pid) {
        delete(@tracked, (uint64)args.old_pid);
    }
}

tracepoint:sched:sched_process_exit
/@tracked[(uint64)tid]/
{
    delete(@tracked, (uint64)tid);
}

tracepoint:syscalls:sys_enter_execve,
tracepoint:syscalls:sys_enter_execveat
/@tracked[(uint64)tid]/
{
    $filename = str(args.filename, 256);
    // Empty execveat filenames and bounded/truncated reads cannot establish
    // executable identity. Fail rather than treating them as proof of absence.
    if (strlen($filename) == 0 || strlen($filename) >= 255) {
        @trace_errors = count();
    }
    @executables[$filename] = count();
    if (@executables[$filename] == 0) {
        @trace_errors = count();
    }
}

END
{
    // Never export task IDs or the tracking map, only filenames and counts.
    clear(@tracked);
}
BPF

# -c accepts a command with quoted arguments, not an arbitrary shell pipeline.
# The initial controller exec may precede probe attachment; its subsequently
# created observer, native launch, hook, correlator and publisher are tracked.
quote_arg() {
    printf "'%s'" "${1//\'/\'\\\'\'}"
}
command_text="$(quote_arg "$binary") chat --smoke --output-dir $(quote_arg "$run_dir") --bpf-object $(quote_arg "$bpf")"
set +e
if [[ "$trace_backend" == strace ]]; then
    timeout --signal=INT --kill-after=30s 660s \
        "$strace_bin" -f -qq -xx -s 4096 -e signal=none -e trace=execve,execveat \
        -o "$private/exec.trace" -- "$binary" chat --smoke --output-dir "$run_dir" \
        --bpf-object "$bpf" \
        2>"$private/trace-errors.log"
else
    timeout --signal=INT --kill-after=30s 660s \
        bpftrace -q -k -f json -o "$private/exec.jsonl" \
        -c "$command_text" "$private/exec.bt" 2>"$private/trace-errors.log"
fi
trace_status=$?
set -e
[[ "$trace_status" == 0 ]] || fail 'executable tracing or the bounded conversation failed'
[[ ! -s "$private/trace-errors.log" ]] || fail 'executable tracer reported a warning or error'

# bpftrace -c does not document propagation of the child's status. Its exit code
# is insufficient: independently require this invocation's strict chat report.
shopt -s nullglob
results=("$run_dir"/reason-chat-rust-*/evidence/result.json)
[[ "${#results[@]}" == 1 ]] || fail 'the current run did not publish exactly one result'
result="${results[0]}"
evidence="${result%/result.json}"
jq -e '
    .controller_runtime == "rust" and .capture_status == "complete" and
    .correlation_status == "complete" and .conversation_status == "finished" and
    .smoke_status == "passed" and .native_exit_success == true and .forced_stop == false and
    .loss_or_failure_count == 0 and (.kernel_events | type == "number" and . > 0) and
    (.turns | length == 3) and .turns[0].tool_calls > 0 and
    .turns[1].tool_calls > 0 and .turns[2].tool_calls == 0
' "$result" >/dev/null || fail 'the Rust chat report did not pass the complete smoke gate'

# strace -xx gives an unambiguous hexadecimal first filename for both syscalls.
# Decode only that argument; argv/environment text is never copied to outputs.
# NUL-separated bytes preserve spaces, quotes and embedded filename newlines.
if [[ "$trace_backend" == strace ]]; then
    LC_ALL=C gawk '
        /execve(at)?\(/ {
            if (!match($0, /execve(at)?\([^"]*"((\\x[0-9a-fA-F]{2})*)"/, fields)) {
                bad = 1; exit 1;
            }
            encoded = fields[2];
            if (length(encoded) == 0 || length(encoded) / 4 >= 4095 ||
                substr($0, RSTART + RLENGTH, 1) != ",") {
                bad = 1; exit 1;
            }
            filename = "";
            for (i = 1; i <= length(encoded); i += 4) {
                byte = strtonum("0x" substr(encoded, i + 2, 2));
                if (byte == 0) { bad = 1; exit 1; }
                filename = filename sprintf("%c", byte);
            }
            printf "%s%c", filename, 0;
            found++;
        }
        END { if (!found || bad) exit 1; }
    ' "$private/exec.trace" > "$private/filenames" || fail 'strace executable filenames are incomplete'
    jq -Rse 'split("\u0000") | .[0:-1] | group_by(.) |
        map({key:.[0],value:length}) | from_entries' "$private/filenames" \
        > "$private/executables.json" || fail 'could not count executable filenames'
else
    # Native JSON output escapes unusual filenames; never scrape text-mode maps.
    jq -se '
    [.[] | select(.type == "map") | .data] | add |
    select(type == "object") |
    select(."@trace_errors" == 1) |
    ."@executables" |
    select(type == "object" and length > 0) |
    select(all(to_entries[];
        (.key | length > 0 and length < 255) and
        (.value | type == "number" and . > 0 and floor == .))) |
    select(all(keys[]; (split("/") | last | test("^python([0-9]+([.][0-9]+)*)?$")) | not))
    ' "$private/exec.jsonl" > "$private/executables.json" ||
        fail 'the full descendant trace is incomplete or contains a Python executable'
fi
jq -e 'type == "object" and length > 0 and
    all(to_entries[]; (.key | length > 0) and (.value | type == "number" and . > 0)) and
    all(keys[]; (split("/") | last | test("^python([0-9]+([.][0-9]+)*)?$")) | not)
' "$private/executables.json" >/dev/null || fail 'a Python executable or invalid count was observed'

# The observer's managed scope omits sibling publish/correlate helpers. Verify
# that this outer trace saw additional apolysis exec attempts beyond that scope.
inner_execs="$(jq -s --arg executable "executable_ref:${binary##*/}" '[.[] | select(.record_type == "raw_kernel_event" and .event_name == "sched_process_exec" and .resource == $executable)] | length' "$evidence/timeline.jsonl")"
jq -e --arg binary "$binary" --argjson inner "$inner_execs" \
    '.[$binary] > $inner and .[$binary] >= 3' "$private/executables.json" >/dev/null ||
    fail 'outer tracing did not establish coverage of controller helpers'

# Publishing runs as the invoking user and atomically replaces destination
# symlinks; the privileged gate never overwrites a model-writable path as root.
setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --clear-groups \
    "$binary" chat publish "$evidence/executable-counts.json" < "$private/executables.json" ||
    fail 'could not publish executable filename counts'
printf 'apolysis-chat-live: PASS: Rust controller, three native turns, exact reasons, no Python exec observed (%s)\n' "$trace_backend"
printf 'Evidence: %s\nExecutable counts: %s\n' "$evidence" "$evidence/executable-counts.json"

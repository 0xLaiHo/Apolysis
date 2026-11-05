#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Explicit opt-in live gate. Requires CAP_BPF+CAP_PERFMON (or CAP_SYS_ADMIN).
# Attaches audit-only probes filtered to each newly launched test process tree.
# Reads only synthetic temporary files and attempts a loopback connection;
# does not change policies, mount filesystems, pin maps, or contact a provider.
# Loader exit detaches probes. The trap removes only this gate's mktemp directory.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set +e
"$repo_root/scripts/check-bpf-prereqs.sh" live
status=$?
set -e
[[ "$status" == 77 ]] && exit 0
[[ "$status" == 0 ]] || exit "$status"
for command_name in python3 clang; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'apolysis-intent-live: SKIP: missing %s\n' "$command_name"
        [[ "${APOLYSIS_REQUIRE_BPF:-0}" != 1 ]] || exit 1
        exit 0
    fi
done
apolysis_bin="${APOLYSIS_BIN:-$repo_root/target/debug/apolysis}"
[[ -x "$apolysis_bin" ]] || { printf 'Run cargo build -p apolysis-cli first.\n' >&2; exit 1; }
"$repo_root/scripts/build-ebpf.sh"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-intent-live.XXXXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
# Managed test children may drop to the invoking SUDO_UID; all inputs are synthetic.
chmod 755 "$fixture_dir"
cat > "$fixture_dir/workload.c" <<'C'
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
static char **paths;
static pthread_t main_thread;
static void probe(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) _exit(20);
    close(fd);
}
static void *worker(void *unused) {
    (void)unused;
    if (pthread_join(main_thread, NULL)) _exit(27); /* prove leader has exited */
    probe(paths[3]);
    pid_t child = fork(); /* fork from a non-leader thread */
    if (child < 0) _exit(21);
    if (!child) { probe(paths[2]); _exit(0); }
    int status;
    if (waitpid(child, &status, 0) < 0 || status) _exit(22);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_port=htons(9)};
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (sock >= 0) { connect(sock, (struct sockaddr *)&address, sizeof(address)); close(sock); }
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 4) return 23;
    paths = argv;
    main_thread = pthread_self();
    pid_t child = fork(); /* child intentionally performs no exec */
    if (child < 0) return 24;
    if (!child) { probe(paths[1]); _exit(0); }
    int status;
    if (waitpid(child, &status, 0) < 0 || status) return 25;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) return 26;
    pthread_exit(NULL); /* remaining thread must retain the group's token */
}
C
clang -O2 -pthread "$fixture_dir/workload.c" -o "$fixture_dir/workload"
chmod 755 "$fixture_dir/workload"
for name in fork-only.txt threaded-fork.txt leader-exited.txt; do
    printf 'synthetic fixture\n' > "$fixture_dir/$name"
    chmod 644 "$fixture_dir/$name"
done
python3 - "$repo_root" "$apolysis_bin" "$fixture_dir" <<'PY'
import json
import pathlib
import shlex
import subprocess
import sys
repo, binary, root = map(pathlib.Path, sys.argv[1:])
identity = 'intent-live-regression'
capture_counts = []

def require(condition, message):
    # These checks must still run if the caller exports PYTHONOPTIMIZE.
    if not condition:
        raise RuntimeError(message)

original = '# APOLYSIS_REASON_CODE=verify_change\nexec ' + shlex.join([str(root / 'workload'), *(str(root / name) for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt'))])
payload = {'session_id': 'synthetic-harness-session', 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_use_id': 'synthetic-long-id-' + 'x' * 200, 'tool_input': {'command': original, 'description': 'DESCRIPTION_PRIVATE_SENTINEL'}, 'prompt': 'PROMPT_PRIVATE_SENTINEL', 'tool_result': 'RESULT_PRIVATE_SENTINEL'}
result = subprocess.run([str(binary), 'intent', 'hook', '--harness', 'claude', '--session', identity, '--workspace-root', str(root), '--output', str(root / 'intent.jsonl')], input=json.dumps(payload), text=True, capture_output=True, check=True)
command = json.loads(result.stdout)['hookSpecificOutput']['updatedInput']['command']
intent = json.loads((root / 'intent.jsonl').read_text().splitlines()[0])
token = intent['intent_id']
require(len(token) == 32 and all(ch in '0123456789abcdef' for ch in token), 'hook did not return a complete internal token')
require(command == '# APOLYSIS_INTENT_ID=' + token + '\n' + original, 'hook changed the original command or omitted the exact header')
reason_path = root / 'intent.jsonl.reasons.jsonl'
reason = json.loads(reason_path.read_text().splitlines()[0])
require(reason['intent_id'] == token and reason['reason_code'] == 'verify_change' and reason['reason_source'] == 'agent_declared', 'hook did not bind declared reason')
require(reason['reason_summary'] is None, 'default reason capture retained text')
require(all(sentinel not in (root / 'intent.jsonl').read_text() + reason_path.read_text() for sentinel in ('PROMPT_PRIVATE_SENTINEL', 'DESCRIPTION_PRIVATE_SENTINEL', 'RESULT_PRIVATE_SENTINEL')), 'private input reached stored intent/reason')

def capture(name, argv):
    output = root / (name + '.jsonl')
    subprocess.run([str(binary), 'observe', '--backend', 'live', '--session', identity, '--policy', str(repo / 'policies/local-dev.yaml'), '--output', str(output), '--bpf-object', str(repo / 'target/ebpf/apolysis_observer.bpf.o'), '--workspace-root', str(root), '--duration-seconds', '5', '--agent-kind', 'intent-fixture', '--agent-run', '--', *argv], stdout=subprocess.DEVNULL, check=True)
    records = [json.loads(line) for line in output.read_text().splitlines()]
    diagnostics = [r for r in records if r.get('record_type') == 'observer_diagnostic']
    known_kinds = {'ring_buffer_reserve_failure', 'map_pressure', 'decode_failure', 'attach_failure', 'verifier_failure', 'truncation', 'summary'}
    require(all(r.get('kind') in known_kinds for r in diagnostics), f'{name}: unknown diagnostic kind')
    failures = [r for r in diagnostics if r.get('kind') not in {'truncation', 'summary'} and r.get('count', 0)]
    require(not failures, f'{name}: observer failure/loss counters: ' + ', '.join(f"{r['kind']}={r['count']}" for r in failures))
    raw_count = sum(r.get('record_type') == 'raw_kernel_event' for r in records)
    summaries = [r for r in diagnostics if r.get('kind') == 'summary']
    require(len(summaries) == 1 and summaries[0].get('count') == raw_count and raw_count > 0, f'{name}: missing or empty capture summary')
    events = [r for r in records if r.get('record_type') == 'event']
    root_pids = [int(r['action']) for r in events if r.get('resource') == 'agent-root-pid']
    require(len(root_pids) == 1, f'{name}: missing managed process identity')
    executable = 'executable_ref:' + pathlib.Path(argv[0]).name
    require(any(r.get('event_type') == 'exec' and r.get('pid') == root_pids[0] and r.get('process_executable') == executable for r in events), f'{name}: managed target exec was not observed')
    exits = [r for r in events if r.get('resource') == 'agent-exit-status']
    require(len(exits) == 1 and exits[0].get('action') == 'exit:0', f'{name}: managed workload did not finish successfully (or capture timed out)')
    capture_counts.append(raw_count)
    return records

records = capture('valid', ['/bin/bash', '-c', command])
require(not any('intent_capture_incomplete:true' in r.get('raw_payload', '') for r in records), 'valid workload had incomplete intent capture')
events = [r for r in records if r.get('record_type') == 'event']
for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt'):
    matching = [r for r in events if r.get('event_type') == 'file_open' and r.get('resource') == str(root / name)]
    require(matching and all(r.get('intent_id') == token for r in matching), f'{name}: missing file attempt or incorrect attribution')
require(any(r.get('event_type') == 'network_connect' and r.get('intent_id') == token for r in events), 'loopback connection attempt is missing its token')
require(len({r['pid'] for r in events if r.get('event_type') == 'file_open' and r.get('resource') in {str(root / name) for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt')}}) == 3, 'expected three distinct fixture process identities')
root_pid = next(int(r['action']) for r in events if r.get('resource') == 'agent-root-pid')
require(any(r.get('event_type') == 'exec' and r.get('pid') == root_pid and r.get('intent_id') == token and r.get('process_executable') == 'executable_ref:workload' for r in events), 'same-PID exec lost its token')

# Real product shells may put the returned command inside an eval wrapper.
# The explicit inner-shell mode must recover attribution without accepting an
# embedded marker in the outer shell's arguments.
bridge_result = subprocess.run([str(binary), 'intent', 'hook', '--harness', 'claude', '--session', identity, '--workspace-root', str(root), '--output', str(root / 'intent.jsonl'), '--shell-bridge', '/bin/bash'], input=json.dumps(payload), text=True, capture_output=True, check=True)
bridge_command = json.loads(bridge_result.stdout)['hookSpecificOutput']['updatedInput']['command']
bridged = capture('bridge-wrapper', ['/bin/bash', '-c', 'true && eval ' + shlex.quote(bridge_command)])
for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt'):
    attempts = [r for r in bridged if r.get('record_type') == 'event' and r.get('event_type') == 'file_open' and r.get('resource') == str(root / name)]
    require(attempts and all(r.get('intent_id') == token for r in attempts), f'bridge {name}: native-style wrapping lost attribution')
require(any(r.get('event_type') == 'network_connect' and r.get('intent_id') == token for r in bridged), 'bridge connection lost attribution')
require(len((root / 'intent.jsonl').read_text().splitlines()) == 1 and len(reason_path.read_text().splitlines()) == 1, 'bridge retry changed intent or reason identity')

# Verify the actual kernel events join through the original token to the reason.
correlation_path = root / 'correlation.jsonl'
def correlate():
    subprocess.run([str(binary), 'intent', 'correlate', '--intent-input', str(root / 'intent.jsonl'), '--timeline-input', str(root / 'valid.jsonl'), '--reason-input', str(reason_path), '--output', str(correlation_path)], check=True, capture_output=True)
    return [json.loads(line) for line in correlation_path.read_text().splitlines()]
joined = correlate()
exact = [r for r in joined if r.get('record_type') == 'intent_correlation']
require(exact and all(r.get('declared_reason', {}).get('reason_code') == 'verify_change' for r in exact), 'kernel relations lost their declared reason')
require(any(r.get('event_type') == 'file_open' for r in exact) and any(r.get('event_type') == 'network_connect' for r in exact), 'reason did not reach both file and network attempts')
require(not any(r.get('record_type') == 'intent_reason_diagnostic' for r in joined), 'unexpected reason diagnostic')
# Late correction enriches the same evidence; it must not create/change a relation.
payload['apolysis_reason'] = {'reason_id': 'late-correction', 'reason_code': 'gather_evidence', 'supersedes_reason_id': reason['reason_id']}
payload['tool_input'] = {}
subprocess.run([str(binary), 'intent', 'reason', '--harness', 'claude', '--session', identity, '--output', str(reason_path)], input=json.dumps(payload), text=True, capture_output=True, check=True)
corrected = [r for r in correlate() if r.get('record_type') == 'intent_correlation']
require({r['raw_event_id'] for r in corrected} == {r['raw_event_id'] for r in exact}, 'late correction changed execution relations')
require(all(r.get('declared_reason', {}).get('reason_id') == 'late-correction' for r in corrected), 'late correction was not selected')

# No token may be manufactured by ordinary argv, a later comment, or a partial header.
header = '# APOLYSIS_INTENT_ID=' + token + '\n'
(root / 'noop.sh').write_text('exit 0\n')
(root / 'noop.sh').chmod(0o644)
for name, argv in [
    ('ordinary-arg', ['/bin/echo', header]),
    ('script-argument', ['/bin/bash', str(root / 'noop.sh'), '-c', header]),
    ('later-comment', ['/bin/bash', '-c', ':; ' + header + 'true']),
    ('short-token', ['/bin/bash', '-c', '# APOLYSIS_INTENT_ID=' + token[:-1] + '\ntrue']),
    ('uppercase-token', ['/bin/bash', '-c', '# APOLYSIS_INTENT_ID=' + 'A' * 32 + '\ntrue']),
]:
    require(not any(r.get('intent_id') for r in capture(name, argv)), f'{name}: unexpected attribution')
print(f'apolysis-intent-live: PASS: {len(capture_counts)} complete captures, {sum(capture_counts)} kernel events; content-off reason, late correction, explicit inner shell through eval, exact syscall join, hook, bounded token capture, exec, fork-only, threaded fork, leader exit, loopback connect, and malformed/ordinary arguments')
PY

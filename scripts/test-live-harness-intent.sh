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
static void probe(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) _exit(20);
    close(fd);
}
static void *worker(void *unused) {
    (void)unused;
    usleep(100000); /* main thread has called pthread_exit by now */
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
for name in fork-only.txt threaded-fork.txt leader-exited.txt; do
    printf 'synthetic fixture\n' > "$fixture_dir/$name"
done
python3 - "$repo_root" "$apolysis_bin" "$fixture_dir" <<'PY'
import json
import pathlib
import shlex
import subprocess
import sys
repo, binary, root = map(pathlib.Path, sys.argv[1:])
identity = 'intent-live-regression'
original = 'exec ' + shlex.join([str(root / 'workload'), *(str(root / name) for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt'))])
payload = {'session_id': 'synthetic-harness-session', 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash', 'tool_use_id': 'synthetic-long-id-' + 'x' * 200, 'tool_input': {'command': original}}
result = subprocess.run([str(binary), 'intent', 'hook', '--harness', 'claude', '--session', identity, '--workspace-root', str(root), '--output', str(root / 'intent.jsonl')], input=json.dumps(payload), text=True, capture_output=True, check=True)
command = json.loads(result.stdout)['hookSpecificOutput']['updatedInput']['command']
intent = json.loads((root / 'intent.jsonl').read_text().splitlines()[0])
token = intent['intent_id']
assert len(token) == 32 and all(ch in '0123456789abcdef' for ch in token)
assert command == '# APOLYSIS_INTENT_ID=' + token + '\n' + original

def capture(name, argv):
    output = root / (name + '.jsonl')
    subprocess.run([str(binary), 'observe', '--backend', 'live', '--session', identity, '--policy', str(repo / 'policies/local-dev.yaml'), '--output', str(output), '--bpf-object', str(repo / 'target/ebpf/apolysis_observer.bpf.o'), '--workspace-root', str(root), '--duration-seconds', '5', '--agent-kind', 'intent-fixture', '--agent-run', '--', *argv], stdout=subprocess.DEVNULL, check=True)
    records = [json.loads(line) for line in output.read_text().splitlines()]
    failures = [r for r in records if r.get('record_type') == 'observer_diagnostic' and r.get('kind') in ('ring_buffer_reserve_failure', 'map_pressure', 'decode_failure') and r.get('count', 0)]
    assert not failures, f'{name}: evidence loss: {failures}'
    return records

records = capture('valid', ['/bin/bash', '-c', command])
events = [r for r in records if r.get('record_type') == 'event']
for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt'):
    matching = [r for r in events if r.get('event_type') == 'file_open' and r.get('resource') == str(root / name)]
    assert matching and all(r.get('intent_id') == token for r in matching), (name, matching)
assert any(r.get('event_type') == 'network_connect' and r.get('intent_id') == token for r in events)
assert len({r['pid'] for r in events if r.get('event_type') == 'file_open' and r.get('resource') in {str(root / name) for name in ('fork-only.txt', 'threaded-fork.txt', 'leader-exited.txt')}}) == 3
assert any(r.get('event_type') == 'exec' and r.get('intent_id') == token and r.get('process_executable', '').endswith('workload') for r in events), 'same-PID exec lost its token'

# No token may be manufactured by ordinary argv, a later comment, or a partial header.
header = '# APOLYSIS_INTENT_ID=' + token + '\n'
(root / 'noop.sh').write_text('exit 0\n')
for name, argv in [
    ('ordinary-arg', ['/bin/echo', header]),
    ('script-argument', ['/bin/bash', str(root / 'noop.sh'), '-c', header]),
    ('later-comment', ['/bin/bash', '-c', ':; ' + header + 'true']),
    ('short-token', ['/bin/bash', '-c', '# APOLYSIS_INTENT_ID=' + token[:-1] + '\ntrue']),
    ('uppercase-token', ['/bin/bash', '-c', '# APOLYSIS_INTENT_ID=' + 'A' * 32 + '\ntrue']),
]:
    assert not any(r.get('intent_id') for r in capture(name, argv)), name
print('apolysis-intent-live: PASS: hook, bounded token capture, exec, fork-only, threaded fork, leader exit, loopback connect, and malformed/ordinary arguments')
PY

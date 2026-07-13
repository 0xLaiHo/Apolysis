#!/usr/bin/bash

set -Eeuo pipefail

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd -- "$script_dir/.." && pwd)"
readonly action_file="$repository_root/action.yml"
readonly action_self_test="$repository_root/.github/workflows/action-self-test.yml"
readonly boundary_helper="$repository_root/scripts/github-action-boundary.sh"
readonly pinned_bundle_digest='6d6ea336fc4fdd9461bb85fdb6829ec5b7343a81c8040aa899ded3ab1affb78e'

fail() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

expect_rejection() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$description was accepted"
    fi
}

inputs_block="$(awk '
    /^inputs:/ { in_inputs=1; next }
    /^runs:/ { in_inputs=0 }
    in_inputs { print }
' "$action_file")"

for forbidden_input in binary bpf-object output-dir version; do
    if grep -Eq "^  ${forbidden_input}:" <<<"$inputs_block"; then
        fail "public Action still accepts caller-controlled ${forbidden_input}"
    fi
done

grep -A3 -F '  session:' "$action_file" | grep -Fq 'required: true' \
    || fail 'safe unique session is not required'
grep -Fq '[[ "$RUN_CMD" =~ [^[:space:]] ]]' "$action_file" \
    || fail 'empty managed commands are not rejected explicitly'
if grep -Eq '>>.*GITHUB_OUTPUT|GITHUB_OUTPUT.*>>' "$action_file"; then
    fail 'Action still transports values through a same-UID workflow command file'
fi
if grep -Eq '(^|[[:space:]])chown([[:space:]]|$)' "$action_file"; then
    fail 'public Action still changes file ownership after untrusted work'
fi
if grep -Eq '(^|[[:space:]])sudo([[:space:]]|$)|\$\(sudo([[:space:]]|$)' "$action_file"; then
    fail 'public Action still resolves a privileged launcher through PATH'
fi
grep -Fq "$pinned_bundle_digest" "$action_file" \
    || fail 'public Action does not embed the pinned release-bundle digest'
grep -Fq -- '--no-same-owner' "$action_file" \
    || fail 'root extraction still preserves archive ownership'
grep -Fq -- '--no-same-permissions' "$action_file" \
    || fail 'root extraction still preserves archive permissions'
grep -A1 -F '/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin \' "$action_file" \
    | grep -Fq '/usr/bin/curl --disable' \
    || fail 'privileged curl can still load caller-controlled configuration'
grep -A1 -F '/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/bin \' "$action_file" \
    | grep -Fq '/usr/bin/tar \' \
    || fail 'privileged tar can still consume caller-controlled environment options'
grep -Fq -- '--use-compress-program=/usr/bin/gzip' "$action_file" \
    || fail 'privileged tar still resolves its decompressor through caller PATH'
grep -Fq "'0:0:regular file:1:500'" "$action_file" \
    || fail 'privileged executable ownership and type are not asserted'
grep -Fq "'0:0:regular file:1:400'" "$action_file" \
    || fail 'privileged read-only inputs are not asserted'
grep -Fq '[[ "$(/usr/bin/id -u)" -ne 0 ]]' "$action_file" \
    || fail 'already-root runners are not rejected'
grep -Fq '/usr/bin/sudo -n /usr/bin/mkdir --mode=0700 -- "$secure_dir"' "$action_file" \
    || fail 'privileged inputs are not staged in an exclusive root directory'
grep -Fq '/usr/bin/sudo -n /usr/bin/mkdir --mode=0700 -- "$artifact_dir"' "$action_file" \
    || fail 'evidence is not staged in an exclusive root directory'
grep -Fq -- '--output "$timeline"' "$action_file" \
    || fail 'observer output is not confined to the root-owned stage'
grep -Fq -- '--mode=0440' "$action_file" \
    || fail 'sealed evidence is not root-owned and read-only'
grep -Fq 'scripts/github-action-boundary.sh action-scope' "$action_file" \
    || fail 'Action-owned paths are not derived from bounded identifiers'
grep -Fq 'copy-policy' "$action_file" \
    || fail 'custom policy is not copied from one bounded file descriptor'
grep -Fq 'exit "$code"' "$action_file" \
    || fail 'runner-recorded step status does not propagate the observed failure'
grep -Fq "id: install" "$action_file" \
    || fail 'path reservation does not have a runner-recorded outcome'
grep -Fq "steps.install.outcome == 'success'" "$action_file" \
    || fail 'a failed path reservation can reach another invocation'
grep -Fq "steps.verify.outcome == 'success'" "$action_file" \
    || fail 'unverified evidence can reach report or upload'
grep -Fq '/usr/bin/test -s "$timeline"' "$action_file" \
    || fail 'an empty timeline can be sealed as valid evidence'
grep -Fq '/usr/bin/setpriv --no-new-privs' "$action_file" \
    || fail 'managed work can regain ambient setuid privileges'
grep -Fq -- '--preserve-env /usr/bin/env' "$action_file" \
    || fail 'managed work loses the deliberate runner environment'
grep -Fq '/usr/bin/bash --noprofile --norc -p "$command_script"' "$action_file" \
    || fail 'managed command content is still passed through process arguments'
grep -Fq '/usr/bin/python3 -I -S "$sanitizer" "$bin" observe' "$action_file" \
    || fail 'the observer environment does not pass through the root-owned sanitizer'
grep -Fq 'name.startswith("BASH_FUNC_")' "$action_file" \
    || fail 'exported Bash functions can reach the pre-observation gate shell'
[[ "$(grep -Fc 'readonly sanitizer="$secure_dir/environment-sanitizer.py"' \
    "$action_file")" -eq 3 ]] \
    || fail 'every sanitizer consumer does not bind the root-owned path'
grep -Fq -- '-u APOLYSIS_BPF_LSM_AVAILABLE' "$action_file" \
    || fail 'caller input can override observed BPF LSM capability metadata'
grep -Fq 'SUDO_UID="$runner_uid"' "$action_file" \
    || fail 'the pinned observer is not forced to restore the invoking non-root uid'
grep -Fq 'SUDO_GID="$runner_gid"' "$action_file" \
    || fail 'the pinned observer is not forced to restore the invoking non-root gid'
grep -Fq -- '--mode=0600' "$action_file" \
    || fail 'live evidence is not reserved as a root-only file'
timeline_reservation_block="$(awk '
    /--mode=0600/ { capture=1 }
    capture { print }
    capture && /chgrp.*secure_dir/ { exit }
' "$action_file")"
grep -Fq '/usr/bin/test -f "$timeline"' <<<"$timeline_reservation_block" \
    || fail 'the empty reserved timeline is not validated as a regular file'
grep -Fq '/usr/bin/test ! -L "$timeline"' <<<"$timeline_reservation_block" \
    || fail 'the empty reserved timeline is not rejected when it is a symlink'
grep -Fq "stat -c '%u:%g:%h:%a'" <<<"$timeline_reservation_block" \
    || fail 'the empty reserved timeline is not validated with stable numeric metadata'
grep -Fq "'0:0:1:600'" <<<"$timeline_reservation_block" \
    || fail 'the empty reserved timeline does not require root ownership, one link, and mode 0600'
if grep -Fq "stat -c '%u:%g:%F:%h:%a'" <<<"$timeline_reservation_block"; then
    fail 'the empty reserved timeline still relies on the size-sensitive stat file-type label'
fi
grep -Fq "'0:0:regular file:1:600'" "$action_file" \
    || fail 'root-only live evidence mode is not asserted'
grep -Fq 'if-no-files-found: error' "$action_file" \
    || fail 'missing verified evidence does not fail the upload step'
grep -Eq 'uses: actions/upload-artifact@[0-9a-f]{40}([[:space:]]|$)' "$action_file" \
    || fail 'the evidence uploader is not pinned to an immutable commit'

shell_count="$(grep -c '^      shell:' "$action_file")"
privileged_shell_count="$(grep -c \
    '^      shell: /usr/bin/bash --noprofile --norc -p ' "$action_file")"
[[ "$shell_count" -eq "$privileged_shell_count" ]] \
    || fail 'a composite run step can import caller-controlled Bash startup state'
if grep -Eq '/usr/bin/sudo.*/usr/bin/bash' "$action_file"; then
    fail 'the privileged observer path still starts a root Bash process'
fi
if grep -Eq "/usr/bin/(stat|cat).*'\\\$sentinel" "$action_self_test"; then
    fail 'a sentinel assertion expands its path before the deferred eval check'
fi

env_block_count="$(grep -c '^      env:' "$action_file")"
for safe_setting in \
    "BASHOPTS: ''" \
    "BASH_XTRACEFD: ''" \
    'BASH_ENV: /dev/null' \
    "LD_AUDIT: ''" \
    "LD_LIBRARY_PATH: ''" \
    "LD_PRELOAD: ''" \
    "PS4: '+ '" \
    "SHELLOPTS: ''"
do
    setting_count="$(grep -Fc "        $safe_setting" "$action_file")"
    [[ "$setting_count" -eq "$env_block_count" ]] \
        || fail "not every Action step neutralizes ${safe_setting%%:*}"
done

[[ -x "$boundary_helper" ]] || fail 'Action boundary helper is missing or not executable'
[[ "$(head -n 1 "$boundary_helper")" == '#!/usr/bin/bash -p' ]] \
    || fail 'Action boundary helper can import caller-controlled Bash functions'
grep -Fq 'O_NOFOLLOW' "$boundary_helper" \
    || fail 'policy copy does not reject symlink components at open time'
grep -Fq 'os.fstat(policy_fd)' "$boundary_helper" \
    || fail 'policy copy does not validate the opened file descriptor'
grep -Fq '/usr/bin/python3 -I -S -' "$boundary_helper" \
    || fail 'policy copy allows workspace-controlled Python startup hooks'

temporary_base="${RUNNER_TEMP:-/tmp}"
temporary_root="$(mktemp -d "$temporary_base/apolysis-action-boundary.XXXXXXXX")"
trap 'rm -rf -- "$temporary_root"' EXIT
workspace="$temporary_root/workspace"
outside="$temporary_root/outside"
mkdir -p "$workspace/policies" "$outside"
printf 'version: 1\n' >"$workspace/policy.yaml"
printf 'version: 1\n' >"$outside/policy.yaml"
printf 'version: 1\n' >"$outside/hardlink-source.yaml"
printf '%s\n' \
    'import os' \
    'open(os.environ["APOLYSIS_SITECUSTOMIZE_MARKER"], "w").write("ran")' \
    >"$workspace/sitecustomize.py"
ln -s "$outside/policy.yaml" "$workspace/policy-link.yaml"
ln -s "$outside" "$workspace/policies/linked"
ln "$outside/hardlink-source.yaml" "$workspace/policy-hardlink.yaml"
mkfifo "$workspace/policy.fifo"
truncate -s 1048577 "$workspace/oversized-policy.yaml"
truncate -s 1048576 "$workspace/maximum-policy.yaml"

copied_policy="$($boundary_helper copy-policy "$workspace" policy.yaml 1048576)"
[[ "$copied_policy" == 'version: 1' ]] \
    || fail 'workspace policy bytes changed during bounded copy'
absolute_copy="$($boundary_helper copy-policy \
    "$workspace" "$workspace/policy.yaml" 1048576)"
[[ "$absolute_copy" == 'version: 1' ]] \
    || fail 'absolute in-workspace policy was not copied'
startup_marker="$temporary_root/sitecustomize-ran"
isolated_copy="$(APOLYSIS_SITECUSTOMIZE_MARKER="$startup_marker" \
    PYTHONPATH="$workspace" \
    "$boundary_helper" copy-policy "$workspace" policy.yaml 1048576)"
[[ "$isolated_copy" == 'version: 1' && ! -e "$startup_marker" ]] \
    || fail 'workspace-controlled Python startup code ran during policy copy'
bash_function_marker="$temporary_root/bash-function-ran"
function_copy="$(/usr/bin/env \
    APOLYSIS_BASH_FUNCTION_MARKER="$bash_function_marker" \
    'BASH_FUNC_printf%%=() { /usr/bin/touch "$APOLYSIS_BASH_FUNCTION_MARKER"; builtin printf "$@"; }' \
    "$boundary_helper" copy-policy "$workspace" policy.yaml 1048576)"
[[ "$function_copy" == 'version: 1' && ! -e "$bash_function_marker" ]] \
    || fail 'caller-controlled Bash function ran inside the boundary helper'
sanitizer_fixture="$temporary_root/environment-sanitizer.py"
awk '
    /tee "\$sanitizer".*<<.*PY/ { copying=1; next }
    copying && /^        PY$/ { exit }
    copying { sub(/^        /, ""); print }
' "$action_file" >"$sanitizer_fixture"
[[ -s "$sanitizer_fixture" ]] \
    || fail 'root-owned environment sanitizer could not be extracted for testing'
sanitized_environment="$(/usr/bin/env \
    APOLYSIS_SANITIZER_PRESERVE=preserved \
    APOLYSIS_BPF_LSM_AVAILABLE=0 \
    'BASH_FUNC_read%%=() { /usr/bin/false; }' \
    /usr/bin/python3 -I -S "$sanitizer_fixture" /usr/bin/env)"
grep -Fq 'APOLYSIS_SANITIZER_PRESERVE=preserved' <<<"$sanitized_environment" \
    || fail 'environment sanitizer discarded deliberate workload configuration'
if grep -Eq '^(BASH_FUNC_|APOLYSIS_BPF_LSM_AVAILABLE=)' \
    <<<"$sanitized_environment"; then
    fail 'environment sanitizer retained observer-control input'
fi
maximum_source_digest="$(sha256sum "$workspace/maximum-policy.yaml" | awk '{print $1}')"
maximum_copy_digest="$($boundary_helper copy-policy \
    "$workspace" maximum-policy.yaml 1048576 | sha256sum | awk '{print $1}')"
[[ "$maximum_copy_digest" == "$maximum_source_digest" ]] \
    || fail 'maximum-sized policy was truncated during descriptor copy'

expect_rejection 'policy outside the workspace' \
    "$boundary_helper" copy-policy "$workspace" "$outside/policy.yaml" 1048576
expect_rejection 'final-component policy symlink' \
    "$boundary_helper" copy-policy "$workspace" policy-link.yaml 1048576
expect_rejection 'parent-component policy symlink' \
    "$boundary_helper" copy-policy "$workspace" policies/linked/policy.yaml 1048576
expect_rejection 'policy hard link' \
    "$boundary_helper" copy-policy "$workspace" policy-hardlink.yaml 1048576
expect_rejection 'policy directory' \
    "$boundary_helper" copy-policy "$workspace" policies 1048576
expect_rejection 'policy FIFO' \
    "$boundary_helper" copy-policy "$workspace" policy.fifo 1048576
expect_rejection 'oversized policy' \
    "$boundary_helper" copy-policy "$workspace" oversized-policy.yaml 1048576

[[ "$($boundary_helper validate-session action-run_01.test)" == 'action-run_01.test' ]] \
    || fail 'safe session identifier changed during validation'
expect_rejection 'session traversal' \
    "$boundary_helper" validate-session ../../root-owned
expect_rejection 'session output injection' \
    "$boundary_helper" validate-session $'safe\nforged=value'
expect_rejection 'oversized session identifier' \
    "$boundary_helper" validate-session "$(printf 's%.0s' {1..129})"

[[ "$($boundary_helper validate-agent-kind ci-agent)" == 'ci-agent' ]] \
    || fail 'safe agent kind changed during validation'
expect_rejection 'agent-kind option injection' \
    "$boundary_helper" validate-agent-kind --workspace-root
expect_rejection 'agent-kind path separator' \
    "$boundary_helper" validate-agent-kind agent/kind

[[ "$($boundary_helper action-scope 12345 2 action-run_01.test)" == \
    '12345.2.action-run_01.test' ]] \
    || fail 'safe Action scope changed during validation'
expect_rejection 'zero run id' \
    "$boundary_helper" action-scope 0 1 action-run
expect_rejection 'nonnumeric run attempt' \
    "$boundary_helper" action-scope 123 first action-run
expect_rejection 'scope traversal' \
    "$boundary_helper" action-scope 123 1 ../../root-owned

printf 'GitHub Action privilege-boundary checks passed.\n'

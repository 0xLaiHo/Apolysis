#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real product/provider gate; never part of the default test suite.

Runs only a synthetic cat command, with private temporary hook configuration,
under a managed eBPF process scope. Provider calls may incur charges. Existing
authentication remains with each product; credentials and product output are
never printed or copied. Bubblewrap masks global hooks without modifying them.
Temporary captures and product logs are removed on every normal/error exit.
Build the current CLI and BPF object before running. Run through sudo while
preserving PATH; the runner restores the invoking user's real home for the
observer's UID/GID-dropped child. It never substitutes a temporary home.
"""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid


REPO = Path(__file__).resolve().parents[1]
PRODUCTS = ("codex", "claude", "cursor", "pi", "opencode")
COMMAND = "# APOLYSIS_REASON_CODE=verify_change\ncat fixture.txt"
PROMPT_SENTINEL = "APOLYSIS_PROMPT_SENTINEL_NEVER_PERSIST"
PROMPT = (
    "This is a bounded synthetic tool-hook integration test. Invoke your shell "
    "tool exactly once, with the following command string exactly as written, "
    "including its first comment line and newline. Do not add cd, a shell "
    "wrapper, other commands, or other tool calls. Do not inspect any other "
    "files. After the command succeeds, reply only DONE. "
    "The following prompt-only privacy sentinel must not be printed or used "
    "in commands: " + PROMPT_SENTINEL + ".\n\n" + COMMAND
)


class GateError(Exception):
    pass


class PrerequisiteMissing(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def write(path, content, uid, gid, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o700 if executable else 0o600)
    if os.geteuid() == 0:
        os.chown(path, uid, gid)


def own_tree(root, uid, gid):
    for path in [root, *root.rglob("*")]:
        if path.is_dir():
            path.chmod(0o700)
        if os.geteuid() == 0:
            os.chown(path, uid, gid)


@contextmanager
def private_workspace(keep_failed):
    root = Path(tempfile.mkdtemp(prefix="apolysis-reason-products-"))
    retained = False
    try:
        yield root
    except BaseException as error:
        if keep_failed and not isinstance(error, PrerequisiteMissing):
            retained = True
            print("apolysis-products-live: private failure directory retained: " + str(root), flush=True)
        raise
    finally:
        if not retained:
            shutil.rmtree(root)


def run_private(argv, log, cwd, env, timeout=180):
    with log.open("wb") as output:
        log.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(log, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise GateError("native product or observer timed out; " + failure_category(log)) from None


def failure_category(log):
    """Emit only fixed categories, never a product error or credential value."""
    try:
        text = log.read_text(errors="replace").lower()
    except OSError:
        return "unclassified_failure"
    categories = [
        ("auth_refresh_denied", ("refresh failed: 403", "refresh_token_reused", "token refresh failed", "failed to refresh token", "oauth refresh failed")),
        ("provider_forbidden", ("403 forbidden", "status code 403", "status: 403")),
        ("auth_required", ("not logged in", "authentication required", "missing api key", "invalid api key", "unauthorized", "authentication failed", "configured authentication unavailable")),
        ("read_only_state", ("read-only file system", "erofs")),
        ("permission_error", ("permission denied", "eacces", "operation not permitted")),
        ("network_unavailable", ("tls", "handshake", "unexpected eof", "connection timed out", "network error", "fetch failed", "enotfound", "connection refused", "request timed out", "request timeout", "error sending request")),
        ("rate_or_quota", ("rate limit", "quota exceeded", "insufficient credits")),
        ("config_error", ("unknown argument", "unrecognized option", "invalid config", "invalid settings", "failed to load config")),
    ]
    return next((name for name, patterns in categories if any(p in text for p in patterns)), "unclassified_failure")


def jsonl(path):
    if not path.is_file():
        raise GateError("required capture or hook output is missing")
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line]
    except (OSError, ValueError):
        raise GateError("invalid capture or hook output") from None


def write_hook(root, binary, product, session, uid, gid, shell_bridge=None):
    """Validate synthetic commands before passing the genuine native hook input.

    Never save the incoming payload. Denied tools cannot escape the fixture
    via this hook. Product permissions and the read-only outer mount remain
    separate boundaries; this is a test guard, not a hostile-agent sandbox.
    """
    script = root / "hook.py"
    args = [str(binary), "intent", "hook", "--harness", product,
            "--session", session, "--output", str(root / "intent.jsonl"),
            "--workspace-root", str(root)]
    if shell_bridge:
        args += ["--shell-bridge", shell_bridge]
    body = '''#!/usr/bin/env python3
import json, re, shlex, subprocess, sys
args = ARGS
expected = EXPECTED
product = PRODUCT
bridge = BRIDGE
try:
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError()
    value = json.loads(raw)
    tool = value.get("tool_input", {})
    command = value.get("command") if value.get("hook_event_name") == "beforeShellExecution" else tool.get("command", tool.get("cmd"))
    if not isinstance(command, str):
        raise ValueError()
    if bridge and value.get("hook_event_name") == "beforeShellExecution":
        parts = shlex.split(command)
        if len(parts) == 3 and parts[:2] == [bridge, "-c"]:
            command = parts[2]
    command = re.sub(r"^# APOLYSIS_INTENT_ID=[0-9a-f]{32}\\n", "", command, count=1)
    if command.rstrip("\\n") != expected:
        raise ValueError()
except (ValueError, TypeError, AttributeError):
    if product == "cursor":
        response = {"permission":"deny", "user_message":"synthetic gate permits only its fixture command"}
    else:
        response = {"hookSpecificOutput":{"hookEventName":"PreToolUse", "permissionDecision":"deny", "permissionDecisionReason":"synthetic gate permits only its fixture command"}}
    print(json.dumps(response))
    sys.exit(0)
result = subprocess.run(args, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sys.stdout.buffer.write(result.stdout)
if result.returncode:
    sys.stderr.write("synthetic intent hook failed\\n")
sys.exit(result.returncode)
'''.replace("ARGS", repr(args)).replace("EXPECTED", repr(COMMAND)).replace("PRODUCT", repr(product)).replace("BRIDGE", repr(shell_bridge))
    write(script, body, uid, gid, executable=True)
    return shlex.join([sys.executable, str(script)])


def product_command(product, root, hook, model):
    executable = shutil.which("cursor-agent" if product == "cursor" else product)
    if executable is None:
        home = Path(pwd.getpwuid(int(os.environ.get("SUDO_UID", os.getuid()))).pw_dir)
        name = "cursor-agent" if product == "cursor" else product
        candidates = [home / ".local/bin" / name, home / ".opencode/bin" / name]
        executable = next((str(p) for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    if executable is None:
        raise PrerequisiteMissing("native CLI is not installed on PATH")
    if product == "codex":
        config = {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": hook}]}]}}
        (root / ".codex").mkdir()
        (root / ".codex/hooks.json").write_text(json.dumps(config))
        argv = [executable, "exec", "--ignore-user-config", "--ignore-rules",
                "--ephemeral", "--enable", "hooks", "--dangerously-bypass-hook-trust",
                "--skip-git-repo-check", "--sandbox", "workspace-write",
                "-c", 'web_search="disabled"', "--cd", str(root)]
        if model:
            argv += ["--model", model]
        return argv + [PROMPT]
    if product == "claude":
        config = {"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": hook}]}]}}
        settings = root / "settings.json"
        settings.write_text(json.dumps(config))
        argv = [executable, "--print", "--no-session-persistence",
                "--setting-sources", "", "--settings", str(settings),
                "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                "--disable-slash-commands", "--tools", "Bash", "--allowedTools", "Bash",
                "--permission-mode", "dontAsk", "--output-format", "json"]
        if model:
            argv += ["--model", model]
        return argv + [PROMPT]
    if product == "cursor":
        config = {"version": 1, "hooks": {
            "preToolUse": [{"command": hook}],
            "beforeShellExecution": [{"command": hook}],
        }}
        (root / ".cursor").mkdir()
        (root / ".cursor/hooks.json").write_text(json.dumps(config))
        argv = [executable, "--print", "--workspace", str(root), "--trust",
                "--force", "--sandbox", "enabled", "--output-format", "json"]
        if model:
            argv += ["--model", model]
        return argv + [PROMPT]
    if product == "pi":
        guard = root / "pi-extension.ts"
        bridge = (REPO / "hooks/pi/apolysis-intent.ts").as_uri()
        guard.write_text(
            "import apolysis from " + json.dumps(bridge) + ";\n"
            "export default function(pi) {\n"
            " pi.on('tool_call', (event) => {\n"
            "  if (event.toolName !== 'bash' || event.input?.command !== " + json.dumps(COMMAND) + ")\n"
            "   return {block: true, reason: 'synthetic gate permits only its fixture command'};\n"
            " });\n apolysis(pi);\n}\n"
        )
        provider, separator, selected_model = (model or "openai-codex/gpt-6.1-sol").partition("/")
        if not separator:
            provider, selected_model = "openai-codex", provider
        return [executable, "--no-extensions", "-e", str(guard), "--no-mcp",
                "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files",
                "--no-approve", "--no-session", "--offline", "--tools", "bash",
                "--provider", provider, "--model", selected_model,
                "--thinking", "off", "--mode", "json", "-p", PROMPT]
    if product == "opencode":
        guard = root / "opencode-plugin.ts"
        bridge = (REPO / "hooks/opencode/apolysis-intent.ts").as_uri()
        guard.write_text(
            "import apolysis from " + json.dumps(bridge) + ";\n"
            "export default function() {\n const inner = apolysis();\n"
            " return {'tool.execute.before': async (input, output) => {\n"
            "  if (input.tool !== 'bash' || output.args?.command !== " + json.dumps(COMMAND) + ")\n"
            "   throw new Error('synthetic gate permits only its fixture command');\n"
            "  await inner['tool.execute.before'](input, output);\n }};\n}\n"
        )
        config = {"plugin": [guard.as_uri()], "model": model or "openai/gpt-5.4-mini",
                  "share": "disabled", "autoupdate": False,
                  "permission": {"*": "deny", "bash": "allow"}, "mcp": {}, "instructions": []}
        (root / "opencode-config.json").write_text(json.dumps(config))
        return [executable, "run", "--dir", str(root), "--format", "json",
                "--model", model or "openai/gpt-5.4-mini", "--title", "apolysis-reason-native",
                "--log-level", "ERROR", PROMPT]
    raise PrerequisiteMissing("isolated native launch adapter is not implemented")


def isolated_command(root, argv, operator_home, product, binary, session, shell_bridge=None,
                     workspace=None, writable_paths=()):
    bubblewrap = shutil.which("bwrap")
    if bubblewrap is None:
        raise PrerequisiteMissing("bubblewrap is required to mask global hooks")
    empty = root / "empty-hooks.json"
    empty.write_text('{"hooks":{}}\n')
    empty_cursor = root / "empty-cursor-hooks.json"
    empty_cursor.write_text('{"version":1,"hooks":{}}\n')
    empty_text = root / "empty-instructions.txt"
    empty_text.write_text("")
    # No host writes are permitted except this gate's private fixture directory.
    # Authentication stays at its original path; no credentials are copied.
    command = [bubblewrap, "--ro-bind", "/", "/", "--bind", str(root), str(root),
               "--proc", "/proc", "--dev", "/dev", "--die-with-parent",
               "--chdir", str(workspace or root)]
    for path in writable_paths:
        command += ["--bind", str(path), str(path)]
    masks = [operator_home / ".codex/hooks.json", operator_home / ".claude/settings.json",
             operator_home / ".claude/settings.local.json", operator_home / ".cursor/hooks.json",
             operator_home / ".cursor/managed/active-team-hooks/hooks.json",
             Path("/etc/cursor/hooks.json")]
    for path in masks:
        if path.is_file():
            source = empty_cursor if "cursor" in str(path) else empty
            command += ["--ro-bind", str(source), str(path)]
    instruction_and_startup_files = [
        operator_home / ".codex/AGENTS.md", operator_home / ".claude/CLAUDE.md",
        *(operator_home / name for name in
          (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv")),
    ]
    for path in instruction_and_startup_files:
        if path.is_file():
            command += ["--ro-bind", str(empty_text), str(path)]
    environment = {
        "NODE_COMPILE_CACHE": str(root / "node-cache"),
        "CURSOR_DATA_DIR": str(root / "cursor-data"), "TMPDIR": str(root),
        "APOLYSIS_BIN": str(binary), "APOLYSIS_SESSION_ID": session,
        "APOLYSIS_INTENT_OUTPUT": str(root / "intent.jsonl"),
        "APOLYSIS_REASON_OUTPUT": str(root / "intent.jsonl.reasons.jsonl"),
    }
    command += ["--unsetenv", "APOLYSIS_REASON_SUMMARY", "--unsetenv", "APOLYSIS_SHELL_BRIDGE"]
    if shell_bridge:
        environment["APOLYSIS_SHELL_BRIDGE"] = shell_bridge
    if product == "cursor":
        (root / "cursor-config").mkdir()
        environment["CURSOR_CONFIG_DIR"] = str(root / "cursor-config")
    if product == "codex":
        original_state = Path(os.environ.get("CODEX_HOME", str(operator_home / ".codex")))
        original_auth = original_state / "auth.json"
        if not original_auth.is_file():
            raise PrerequisiteMissing("native Codex authentication file is unavailable")
        state = root / "codex-state"
        state.mkdir()
        destination = state / "auth.json"
        destination.touch(mode=0o600)
        # Bubblewrap opens bind sources before applying the namespace mounts.
        # Bind the original auth directly after the state overlay, never from
        # an alias placeholder whose source descriptor would still be empty.
        # Resolve the standalone runtime symlink before masking its packages.
        runtime = Path(argv[0]).resolve()
        runtime_alias = root / "codex-runtime"
        runtime_alias.mkdir()
        command += ["--ro-bind", str(runtime.parent), str(runtime_alias)]
        command += ["--bind", str(state), str(original_state)]
        command += ["--ro-bind", str(original_auth), str(original_state / "auth.json")]
        argv = [str(runtime_alias / runtime.name), *argv[1:]]
    if product == "pi":
        original_auth = operator_home / ".pi/agent/auth.json"
        if not original_auth.is_file():
            raise PrerequisiteMissing("native Pi authentication file is unavailable")
        destination = root / "pi-agent/auth.json"
        destination.parent.mkdir()
        destination.touch(mode=0o600)
        command += ["--ro-bind", str(original_auth), str(destination)]
        environment["PI_CODING_AGENT_DIR"] = str(destination.parent)
    if product == "opencode":
        original_data = Path(os.environ.get("XDG_DATA_HOME", str(operator_home / ".local/share")))
        original_auth = original_data / "opencode/auth.json"
        if not original_auth.is_file():
            raise PrerequisiteMissing("native OpenCode authentication file is unavailable")
        destination = root / "opencode-data/opencode/auth.json"
        destination.parent.mkdir(parents=True)
        destination.touch(mode=0o600)
        command += ["--ro-bind", str(original_auth), str(destination)]
        for name in os.environ:
            if name.startswith("OPENCODE_"):
                command += ["--unsetenv", name]
        for name in ("config", "state", "cache", "home", "managed"):
            (root / ("opencode-" + name)).mkdir()
        environment.update({
            "XDG_CONFIG_HOME": str(root / "opencode-config"),
            "XDG_DATA_HOME": str(root / "opencode-data"),
            "XDG_STATE_HOME": str(root / "opencode-state"),
            "XDG_CACHE_HOME": str(root / "opencode-cache"),
            "OPENCODE_TEST_HOME": str(root / "opencode-home"),
            "OPENCODE_TEST_MANAGED_CONFIG_DIR": str(root / "opencode-managed"),
            "OPENCODE_CONFIG": str(root / "opencode-config.json"),
            "OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1", "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1", "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
            "OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER": "true",
        })
    for name, value in environment.items():
        command += ["--setenv", name, value]
    command += ["--", *argv]
    if product == "claude" and (operator_home / ".claude/settings.json").is_file():
        # The user's native Claude settings can supply authentication as env
        # values. Preserve only those two existing settings in the unprivileged
        # child, before the settings file is masked. Never serialize their
        # values into argv, fixture files, observer metadata, or logs.
        launcher = root / "claude-auth-launcher.py"
        launcher.write_text(
            "import json, os, sys\n"
            "environment = os.environ.copy()\n"
            "try:\n"
            " with open(" + repr(str(operator_home / ".claude/settings.json")) + ") as source:\n"
            "  configured = json.load(source).get('env', {})\n"
            " for name in ('ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL'):\n"
            "  value = configured.get(name)\n"
            "  if name not in environment and isinstance(value, str) and value:\n"
            "   environment[name] = value\n"
            "except Exception:\n"
            " sys.stderr.write('native configured authentication unavailable\\n')\n"
            " sys.exit(78)\n"
            "command = " + repr(command) + "\n"
            "os.execvpe(command[0], command, environment)\n"
        )
        return [sys.executable, str(launcher)]
    return command


def verify_capture(root, session, binary, env):
    records = jsonl(root / "timeline.jsonl")
    diagnostics = [r for r in records if r.get("record_type") == "observer_diagnostic"]
    known = {"ring_buffer_reserve_failure", "map_pressure", "decode_failure",
             "attach_failure", "verifier_failure", "truncation", "summary"}
    require(all(r.get("kind") in known for r in diagnostics), "unknown observer diagnostic")
    require(not any(r.get("count", 0) for r in diagnostics
                    if r.get("kind") not in {"truncation", "summary"}),
            "observer reported loss or failure")
    raw_count = sum(r.get("record_type") == "raw_kernel_event" for r in records)
    summaries = [r for r in diagnostics if r.get("kind") == "summary"]
    require(raw_count > 0 and len(summaries) == 1 and summaries[0].get("count") == raw_count,
            "empty or inconsistent kernel capture")
    events = [r for r in records if r.get("record_type") == "event"]
    roots = [r for r in events if r.get("resource") == "agent-root-pid"]
    require(len(roots) == 1, "missing managed root identity")
    root_pid = int(roots[0]["action"])
    require(any(r.get("event_type") == "exec" and r.get("pid") == root_pid for r in events),
            "managed product entry exec is missing")
    exits = [r for r in events if r.get("resource") == "agent-exit-status"]
    require(len(exits) == 1 and exits[0].get("action") == "exit:0",
            "native product did not exit successfully")
    intents = jsonl(root / "intent.jsonl")
    reasons = jsonl(root / "intent.jsonl.reasons.jsonl")
    require(len(intents) == 1 and len(reasons) == 1,
            "expected exactly one native tool declaration and reason")
    intent, reason = intents[0], reasons[0]
    require(intent.get("session_id") == session and intent.get("observation_mode") == "local_shell",
            "native declaration has wrong capture identity or mode")
    require(reason.get("intent_id") == intent.get("intent_id")
            and reason.get("reason_code") == "verify_change"
            and reason.get("reason_source") == "agent_declared"
            and reason.get("reason_summary") is None, "native reason is missing or not content-off")
    code = run_private([str(binary), "intent", "correlate", "--intent-input", str(root / "intent.jsonl"),
                        "--reason-input", str(root / "intent.jsonl.reasons.jsonl"),
                        "--timeline-input", str(root / "timeline.jsonl"),
                        "--output", str(root / "correlation.jsonl")],
                       root / "correlation-private.log", root, env)
    require(code == 0, "correlation command failed")
    joined = jsonl(root / "correlation.jsonl")
    for name in ("timeline.jsonl", "intent.jsonl", "intent.jsonl.reasons.jsonl", "correlation.jsonl"):
        require(PROMPT_SENTINEL not in (root / name).read_text(),
                "prompt-only sentinel crossed the content-off persistence boundary")
    require(not any(r.get("record_type") == "intent_reason_diagnostic" for r in joined),
            "reason binding is ambiguous or invalid")
    exact = [r for r in joined if r.get("record_type") == "intent_correlation"
             and r.get("relation_status") == "exact" and r.get("intent_id") == intent["intent_id"]]
    fixture_names = {str(root / "fixture.txt"), "fixture.txt"}
    require(any(r.get("event_type") == "file_open" and r.get("resource") in fixture_names
                and r.get("process_executable") == "executable_ref:cat"
                and r.get("declared_reason", {}).get("reason_id") == reason["reason_id"] for r in exact),
            "fixture file attempt lacks exact intent/reason attribution")
    require(any(r.get("record_type") == "intent_reason_binding"
                and r.get("binding_status") == "declared" for r in joined),
            "declaration reason binding is missing")
    truncations = sum(r.get("count", 0) for r in diagnostics if r.get("kind") == "truncation")
    return raw_count, truncations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--products", default=",".join(PRODUCTS))
    parser.add_argument("--require-all", action="store_true", help="Treat prerequisite skips as failure")
    parser.add_argument("--keep-failed-private", action="store_true",
                        help="Retain a failed fixture and private logs under /tmp for explicit local diagnosis")
    parser.add_argument("--model", action="append", default=[], metavar="PRODUCT=MODEL")
    parser.add_argument("--shell-bridge", metavar="/ABS/PATH/TO/SHELL",
                        help="Explicitly execute each tool command in a separate supported shell; outer-shell state does not propagate back")
    args = parser.parse_args()
    selected = args.products.split(",")
    if not selected or len(set(selected)) != len(selected) or any(p not in PRODUCTS for p in selected):
        parser.error("--products requires unique names from codex,claude,cursor,pi,opencode")
    if args.shell_bridge and (not Path(args.shell_bridge).is_absolute()
                              or not os.access(args.shell_bridge, os.X_OK)):
        parser.error("--shell-bridge requires an absolute executable shell path")
    models = {}
    for entry in args.model:
        name, separator, model = entry.partition("=")
        if not separator or name not in PRODUCTS or not model:
            parser.error("--model requires PRODUCT=MODEL")
        models[name] = model
    binary = Path(os.environ.get("APOLYSIS_BIN", REPO / "target/debug/apolysis")).resolve()
    bpf = REPO / "target/ebpf/apolysis_observer.bpf.o"
    try:
        if not binary.is_file() or not os.access(binary, os.X_OK) or not bpf.is_file():
            raise PrerequisiteMissing("build the current CLI and eBPF object first")
        if os.geteuid() != 0:
            raise PrerequisiteMissing("run explicitly through sudo with the invoking user PATH preserved")
        uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
        if uid == 0:
            raise PrerequisiteMissing("a non-root SUDO_UID is required for native products")
        operator_home = Path(pwd.getpwuid(uid).pw_dir)
        preflight = subprocess.run([str(REPO / "scripts/check-bpf-prereqs.sh"), "live"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if preflight.returncode:
            raise PrerequisiteMissing("live eBPF prerequisites are unavailable")
    except (PrerequisiteMissing, ValueError, KeyError) as error:
        message = str(error) if isinstance(error, PrerequisiteMissing) else "invalid invoking user identity"
        print("apolysis-products-live: SKIP: " + message, flush=True)
        return 1 if args.require_all else 0
    results = []
    env = os.environ.copy()
    # sudo may supply /root while the managed child drops to SUDO_UID. Restore
    # that actual user's existing home; never relocate or copy their credentials.
    env["HOME"] = str(operator_home)
    for product in selected:
        try:
            with private_workspace(args.keep_failed_private) as root:
                session = "native-reason-" + product + "-" + uuid.uuid4().hex
                write(root / "fixture.txt", "apolysis synthetic reason fixture\n", uid, gid)
                hook = write_hook(root, binary, product, session, uid, gid, args.shell_bridge)
                argv = product_command(product, root, hook, models.get(product))
                argv = isolated_command(root, argv, operator_home, product, binary, session, args.shell_bridge)
                own_tree(root, uid, gid)
                command = [str(binary), "observe", "--backend", "live", "--session", session,
                           "--policy", str(REPO / "policies/local-dev.yaml"),
                           "--output", str(root / "timeline.jsonl"), "--bpf-object", str(bpf),
                           "--workspace-root", str(root), "--duration-seconds", "180",
                           "--agent-kind", product, "--agent-run", "--", *argv]
                status = run_private(command, root / "product-private.log", root, env)
                require(status == 0, "observer or native product exited unsuccessfully; "
                        + failure_category(root / "product-private.log"))
                try:
                    count, truncations = verify_capture(root, session, binary, env)
                except GateError as error:
                    raise GateError(str(error) + "; " + failure_category(root / "product-private.log")) from None
                print(f"apolysis-products-live: {product}: PASS: {count} kernel events, "
                      f"{truncations} truncations; native reason to exact fixture file attempt; "
                      + ("explicit shell bridge" if args.shell_bridge else "default comment transport"), flush=True)
                results.append("PASS")
        except PrerequisiteMissing as error:
            print(f"apolysis-products-live: {product}: SKIP: {error}", flush=True)
            results.append("SKIP")
        except GateError as error:
            # GateError messages are fixed assertions/categories written above.
            print(f"apolysis-products-live: {product}: FAIL: {error}", flush=True)
            results.append("FAIL")
        except (OSError, ValueError):
            # Never echo exception text from OS paths or parsed product input.
            print(f"apolysis-products-live: {product}: FAIL: native invocation or evidence assertion failed", flush=True)
            results.append("FAIL")
    print(f"apolysis-products-live: {results.count('PASS')} passed, "
          f"{results.count('SKIP')} skipped, {results.count('FAIL')} failed; "
          + ("failed fixtures retained only by explicit request" if args.keep_failed_private
             else "private fixtures cleaned"), flush=True)
    return 1 if "FAIL" in results or (args.require_all and "SKIP" in results) else 0


if __name__ == "__main__":
    sys.exit(main())

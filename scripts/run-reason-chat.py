#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Experimental terminal conversation: real Claude, explicit reasons and live BPF.

User input and provider streams stay in memory. Only intent/reason/kernel
metadata and the user's generated workspace files persist under target/.
This is an observation demo, not a hostile-agent isolation boundary.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import queue
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

SCRIPT = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("reason_summary_gate", SCRIPT.with_name("test-live-reason-summary.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)
gate = summary.gate
INSTRUCTIONS = """This session tests tool-call accountability in a separate scratch workspace.
Respond to the user's ordinary requests. Conversation alone does not require a tool.
For EVERY Bash call, put APOLYSIS_REASON_JSON= followed by a JSON object in its
description, with exactly reason_code and reason_summary. Choose reason_code from
unknown, inspect_context, verify_change, reproduce_issue, implement_change,
diagnose_failure, gather_evidence. Write your own short Chinese explanation of WHY
this call is needed. Do not include filenames, paths, code, credentials, prompt quotes or results
in the reason. Do not invent an intent ID. The hook supplies that automatically.
Use the current workspace only for task files. Do not inspect authentication,
home configuration, the observer's evidence or temporary control files. Do not
start background/detached processes. Each command runs in a fresh /bin/bash;
make any needed directory changes inside the same command. Do not use sudo.
"""
SMOKE_PROMPTS = [
    "请在当前目录创建 greeting.txt，内容为 hello apolysis，然后告诉我完成了什么。",
    "请读取刚才创建的文件，统计其中的单词数量，并用中文告诉我结果。",
    "谢谢。请只用一句话回复，不要调用工具。",
]


def message(prompt):
    return {"type": "user", "message": {"role": "user", "content": prompt},
            "parent_tool_use_id": None, "session_id": "default", "client_composed": True}


def assistant_text(value):
    if not isinstance(value, dict) or value.get("type") != "assistant":
        return []
    envelope = value.get("message")
    content = envelope.get("content") if isinstance(envelope, dict) else None
    if not isinstance(content, list):
        return []
    return [part["text"] for part in content
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)]


def hook(workspace, evidence, session):
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        value = json.loads(raw)
        if (value.get("hook_event_name") != "PreToolUse" or value.get("tool_name") != "Bash"
                or not isinstance(value.get("tool_input", {}).get("command"), str)
                or not value["tool_input"]["command"].strip()
                or not isinstance(value.get("session_id"), str) or not value["session_id"]
                or not isinstance(value.get("tool_use_id"), str) or not value["tool_use_id"]):
            raise ValueError()
        value["apolysis_reason"] = summary.parse_declaration(value["tool_input"].get("description"))
        result = subprocess.run([str(gate.REPO / "target/debug/apolysis"), "intent", "hook", "--harness", "claude",
                                 "--session", session, "--workspace-root", str(workspace),
                                 "--output", str(evidence / "intent.jsonl"), "--allow-reason-summary",
                                 "--shell-bridge", "/bin/bash"], input=json.dumps(value).encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode:
            raise ValueError()
        sys.stdout.buffer.write(result.stdout)
    except (ValueError, TypeError, AttributeError, KeyError, OSError, subprocess.TimeoutExpired):
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
              "permissionDecisionReason": "Declare a valid APOLYSIS_REASON_JSON reason_code and short reason_summary in Bash.description before executing."}}))
    return 0


def read_complete(path):
    """Ignore only a concurrent writer's unfinished last line."""
    data = path.read_bytes() if path.exists() else b""
    if data and not data.endswith(b"\n"):
        data = data[:data.rfind(b"\n") + 1]
    return [json.loads(line) for line in data.splitlines() if line]


def user_identity():
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    if uid <= 0 or gid <= 0:
        raise ValueError("non-root invoking identity required")
    return {"user": uid, "group": gid, "extra_groups": []}


def publish(path, data):
    # All post-launch writes into the user's tree run as the invoking user.
    # Atomic replacement replaces a destination symlink rather than following it.
    code = """import os, pathlib, sys, tempfile
path = pathlib.Path(sys.argv[1])
fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.apolysis-')
try:
    with os.fdopen(fd, 'wb') as output:
        output.write(sys.stdin.buffer.read())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
"""
    result = subprocess.run([sys.executable, "-c", code, str(path)], input=data.encode(),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, **user_identity())
    gate.require(result.returncode == 0, "could not publish user-owned evidence")


def correlate(evidence, binary, env):
    # The model cannot replace files in this root-owned, short-lived directory.
    with tempfile.TemporaryDirectory(prefix="apolysis-chat-join-") as private:
        directory = Path(private)
        directory.chmod(0o711)
        snapshot, output = directory / "snapshot.jsonl", directory / "correlation.jsonl"
        for path, data in ((snapshot, "".join(json.dumps(row) + "\n" for row in read_complete(evidence / "timeline.jsonl"))), (output, "")):
            gate.write(path, data, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
        result = subprocess.run([str(binary), "intent", "correlate", "--intent-input", str(evidence / "intent.jsonl"),
                                 "--reason-input", str(evidence / "intent.jsonl.reasons.jsonl"),
                                 "--timeline-input", str(snapshot), "--output", str(output)],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, **user_identity())
        gate.require(result.returncode == 0, "reason correlation failed")
        publish(evidence / "correlation.jsonl", output.read_text())
    return read_complete(evidence / "correlation.jsonl")


def read_stream(stream, output):
    try:
        for line in stream:
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    output.put(value)
            except ValueError:
                continue
    finally:
        output.put(None)


def wait_turn(process, output, timeout):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = output.get(timeout=min(1, max(0, deadline - time.monotonic())))
        except queue.Empty:
            if time.monotonic() >= deadline:
                raise gate.GateError("model turn timed out") from None
            if process.poll() is not None:
                raise gate.GateError("native process exited before completing the turn") from None
            continue
        if value is None:
            raise gate.GateError("native output ended before completing the turn")
        for text in assistant_text(value):
            print("Claude：" + text, flush=True)
        if value.get("type") == "result":
            gate.require(value.get("subtype") == "success" and not value.get("is_error", False),
                         "native model reported a failed turn")
            return


def close_process(process):
    """Wait for EOF, terminate the owned session's group, and reap its leader."""
    try:
        if process.stdin and not process.stdin.closed:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        try:
            return process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return None
    finally:
        # Popen uses start_new_session=True. Descendants can outlive a normally
        # exited observer too, so cleanup must cover both return paths and errors.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            if process.poll() is None:
                process.wait(timeout=5)


def report(evidence, session, turns, closed_normally):
    records = read_complete(evidence / "timeline.jsonl")
    diagnostics = [r for r in records if r.get("record_type") == "observer_diagnostic"]
    summaries = [r for r in diagnostics if r.get("kind") == "summary"]
    known = {"summary", "truncation", "ring_buffer_reserve_failure", "map_pressure", "decode_failure", "attach_failure", "verifier_failure"}
    valid_diagnostics = all(r.get("kind") in known and type(r.get("count")) is int and r["count"] >= 0 for r in diagnostics)
    errors = sum(r.get("count", 0) for r in diagnostics if r.get("kind") not in ("summary", "truncation")
                 and type(r.get("count")) is int and r["count"] > 0)
    raw_count = sum(r.get("record_type") == "raw_kernel_event" for r in records)
    exits = [r for r in records if r.get("record_type") == "event" and r.get("resource") == "agent-exit-status"]
    exited = len(exits) == 1 and exits[0].get("action") == "exit:0"
    timeline = evidence / "timeline.jsonl"
    data = timeline.read_bytes() if timeline.exists() else b""
    same_session = all(r.get("session_id") == session for r in records)
    capture_ok = bool(closed_normally and exited and valid_diagnostics and same_session and data.endswith(b"\n")
                      and len(summaries) == 1 and summaries[0].get("count") == raw_count and raw_count > 0 and errors == 0)
    return {"session_id": session, "capture_status": "complete" if capture_ok else "incomplete",
            "turns": turns, "kernel_events": raw_count, "loss_or_failure_count": errors,
            "truncations": sum(r["count"] for r in diagnostics if r.get("kind") == "truncation" and type(r.get("count")) is int and r["count"] > 0),
            "native_exit_success": exited, "forced_stop": not closed_normally}


def validate_smoke(workspace, evidence, turns):
    gate.require(len(turns) == 3 and turns[-1]["tool_calls"] == 0, "conversation-only turn invoked a tool")
    gate.require((workspace / "greeting.txt").read_text().strip() == "hello apolysis", "natural-language write did not produce the requested file")
    intents = read_complete(evidence / "intent.jsonl")
    reasons = read_complete(evidence / "intent.jsonl.reasons.jsonl")
    joined = read_complete(evidence / "correlation.jsonl")
    gate.require(len(intents) >= 2 and len({r["harness_session_id"] for r in intents}) == 1, "multi-turn native session identity missing")
    gate.require(len({r["intent_id"] for r in intents}) == len(intents) == len(reasons), "call identity or reason count mismatch")
    gate.require(all(r.get("reason_source") == "agent_declared" and r.get("reason_summary") not in (None, "") for r in reasons), "native reason summary missing")
    gate.require(any(r["reason_summary"] != "[redacted]" for r in reasons), "no readable model-written summary in smoke run")
    gate.require(not any(r.get("record_type") == "intent_reason_diagnostic" for r in joined), "reason binding diagnostic")
    for reason in reasons:
        gate.require(any(r.get("record_type") == "intent_correlation" and r.get("relation_status") == "exact"
                         and r.get("intent_id") == reason["intent_id"]
                         and r.get("declared_reason", {}).get("reason_summary") == reason["reason_summary"] for r in joined),
                     "native call lacks an exact reason relation")
    gate.require(any(r.get("relation_status") == "exact" and r.get("event_type") == "file_open"
                     and r.get("resource") in ("greeting.txt", str(workspace / "greeting.txt")) for r in joined),
                 "requested file has no exact kernel relation")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--hook":
        return hook(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="Run three natural-language turns for live regression")
    parser.add_argument("--turn-timeout", type=int, default=180)
    args = parser.parse_args()
    if args.turn_timeout < 1:
        parser.error("--turn-timeout must be positive")
    if os.geteuid() != 0 or int(os.environ.get("SUDO_UID", "0")) == 0:
        print("请从普通用户终端通过 sudo 运行此入口。", flush=True)
        return 1
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    operator_home = Path(pwd.getpwuid(uid).pw_dir)
    binary, bpf = gate.REPO / "target/debug/apolysis", gate.REPO / "target/ebpf/apolysis_observer.bpf.o"
    preflight = subprocess.run([str(gate.REPO / "scripts/check-bpf-prereqs.sh"), "live"], capture_output=True)
    if preflight.returncode or not binary.is_file() or not bpf.is_file():
        print("缺少实时 eBPF 前置条件或 CLI/BPF 构建产物。", flush=True)
        return 1
    os.umask(0o077)
    session = "reason-chat-" + uuid.uuid4().hex
    root = Path(tempfile.mkdtemp(prefix="reason-chat-", dir=gate.REPO / "target"))
    workspace, evidence = root / "workspace", root / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    gate.write(evidence / "intent.jsonl", "", uid, gid)
    gate.write(evidence / "intent.jsonl.reasons.jsonl", "", uid, gid)
    gate.write(evidence / "timeline.jsonl", "", uid, gid)
    gate.own_tree(root, uid, gid)
    env = os.environ.copy()
    env["HOME"] = str(operator_home)  # Restore the actual invoking home after sudo.
    process = None
    turns = []
    failed = False
    closed_normally = False
    try:
        with gate.private_workspace(False) as control:
            hook_command = shlex.join([sys.executable, str(SCRIPT), "--hook", str(workspace), str(evidence), session])
            argv = gate.product_command("claude", control, hook_command, None)[:-1]
            argv[argv.index("--output-format") + 1] = "stream-json"
            argv += ["--input-format", "stream-json", "--verbose", "--permission-prompts", "none",
                     "--append-system-prompt", INSTRUCTIONS]
            argv = gate.isolated_command(control, argv, operator_home, "claude", binary, session, "/bin/bash",
                                         workspace=workspace, writable_paths=(workspace, evidence))
            gate.own_tree(control, uid, gid)
            command = [str(binary), "observe", "--backend", "live", "--session", session,
                       "--policy", str(gate.REPO / "policies/local-dev.yaml"), "--output", str(evidence / "timeline.jsonl"),
                       "--bpf-object", str(bpf), "--workspace-root", str(workspace), "--agent-kind", "claude", "--agent-run", "--", *argv]
            process = subprocess.Popen(command, cwd=workspace, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                       encoding="utf-8", errors="replace", bufsize=1, start_new_session=True)
            output = queue.Queue()
            threading.Thread(target=read_stream, args=(process.stdout, output), daemon=True).start()
            print("测试目录：" + str(workspace), flush=True)
            print("证据目录：" + str(evidence), flush=True)
            print("直接输入任务，每行一轮；/exit 或 Ctrl+D 退出。Ctrl+C 结束会话。仅启用 Bash，任务可写入测试目录。", flush=True)
            index = 0
            try:
                while True:
                    if args.smoke:
                        if index == len(SMOKE_PROMPTS):
                            break
                        prompt = SMOKE_PROMPTS[index]
                        print("你：" + prompt, flush=True)
                    else:
                        try:
                            prompt = input("你：")
                        except EOFError:
                            break
                    if prompt.strip() == "/exit":
                        break
                    if not prompt.strip():
                        continue
                    before = {r["intent_id"] for r in read_complete(evidence / "intent.jsonl")}
                    process.stdin.write(json.dumps(message(prompt), ensure_ascii=False) + "\n")
                    process.stdin.flush()
                    wait_turn(process, output, args.turn_timeout)
                    joined = correlate(evidence, binary, env)
                    reasons = {r["intent_id"]: r for r in read_complete(evidence / "intent.jsonl.reasons.jsonl")}
                    new_calls = [r for r in read_complete(evidence / "intent.jsonl") if r["intent_id"] not in before]
                    if not new_calls:
                        print("观测：本轮未调用工具。", flush=True)
                    for call in new_calls:
                        reason = reasons.get(call["intent_id"], {})
                        exact = sum(r.get("record_type") == "intent_correlation" and r.get("intent_id") == call["intent_id"]
                                    and r.get("relation_status") == "exact" for r in joined)
                        purpose = reason.get("reason_summary") or reason.get("reason_code", "未声明")
                        if purpose == "[redacted]":
                            purpose = reason.get("reason_code", "unknown") + "（摘要已脱敏）"
                        print(f"观测：intent_id={call['intent_id']}；理由={purpose}；已关联事件={exact}", flush=True)
                    turns.append({"turn": index + 1, "tool_calls": len(new_calls)})
                    index += 1
            finally:
                closed_normally = close_process(process) == 0
    except KeyboardInterrupt:
        failed = True
        print("会话已中止；已采集证据保留，退出时将报告采集完整性。", flush=True)
    except (gate.GateError, gate.PrerequisiteMissing, OSError, ValueError, KeyError, BrokenPipeError, subprocess.TimeoutExpired):
        failed = True
        print("对话或采集未完成，请检查现有 Claude 认证、网络和采集诊断；原始模型输出未写入日志。", flush=True)
    finally:
        if process is not None and process.poll() is None:
            close_process(process)
        correlation_status = "complete"
        try:
            correlate(evidence, binary, env)
        except (gate.GateError, OSError, ValueError, KeyError, subprocess.TimeoutExpired):
            failed = True
            correlation_status = "incomplete"
            print("最终关联未完成。", flush=True)
        smoke_status = "not_requested"
        if args.smoke:
            smoke_status = "failed"
            try:
                gate.require(not failed, "conversation did not finish")
                validate_smoke(workspace, evidence, turns)
                smoke_status = "passed"
            except (gate.GateError, OSError, ValueError, KeyError):
                failed = True
                print("自然语言回归检查未通过。", flush=True)
        try:
            final = report(evidence, session, turns, closed_normally)
        except (OSError, ValueError, TypeError, KeyError):
            failed = True
            final = {"session_id": session, "capture_status": "incomplete", "kernel_events": None,
                     "loss_or_failure_count": None, "truncations": None, "turns": turns}
        final["correlation_status"] = correlation_status
        final["smoke_status"] = smoke_status
        final["conversation_status"] = "interrupted_or_failed" if failed else "finished"
        publish(evidence / "result.json", json.dumps(final, ensure_ascii=False, indent=2) + "\n")
        print("会话结束。证据：" + str(evidence), flush=True)
        print(f"采集状态={final['capture_status']}；事件={final['kernel_events']}；丢失/失败={final['loss_or_failure_count']}；截断={final['truncations']}", flush=True)
    return 1 if failed or final["capture_status"] != "complete" else 0


if __name__ == "__main__":
    sys.exit(main())

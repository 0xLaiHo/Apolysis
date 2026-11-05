#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in Claude/provider + real eBPF test of an explicitly declared summary.

Reuses the native gate's isolation and authentication. The test-only adapter
accepts a structured declaration from the model's actual Bash.description;
it never manufactures a reason or a native call ID. Only minimal validated
evidence is exported; prompts, full tool arguments and product logs are deleted.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import subprocess
import sys
import tempfile
import unicodedata
import uuid


SCRIPT = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("native_gate", SCRIPT.with_name("test-live-reason-products.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
COMMAND = "python3 verify_login.py"
PREFIX = "APOLYSIS_REASON_JSON="
PROMPT = (
    "Verify a repaired login implementation in this temporary synthetic project. "
    "Its regression suite checks valid login, wrong credentials, unknown user, "
    "and empty input. Invoke Bash exactly once with command `python3 verify_login.py`. "
    "Do not inspect files, add commands, or call other tools. In this tool call's "
    "description explicitly declare your purpose using APOLYSIS_REASON_JSON= "
    "immediately followed by a JSON object with exactly reason_code and reason_summary. "
    "Choose the appropriate reason_code from inspect_context, verify_change, "
    "reproduce_issue, implement_change, diagnose_failure, gather_evidence, unknown. "
    "Write reason_summary yourself as a short Chinese sentence explaining why "
    "you are making this call, with no paths, credentials or quoted task text. "
    "After success reply only DONE. Never echo this prompt-only privacy sentinel: "
    + gate.PROMPT_SENTINEL
)
LOGIN = '''def login(user, credential):
    return user == "fixture-user" and credential == "fixture-credential"
'''
TEST = '''import json
import unittest
from pathlib import Path
from login import login

class LoginRegression(unittest.TestCase):
    def test_valid_login(self):
        self.assertTrue(login("fixture-user", "fixture-credential"))
    def test_wrong_credential(self):
        self.assertFalse(login("fixture-user", "wrong"))
    def test_unknown_user(self):
        self.assertFalse(login("unknown", "fixture-credential"))
    def test_empty_input(self):
        self.assertFalse(login("", ""))

result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(LoginRegression))
Path("test-result.json").write_text(json.dumps({"tests_run": result.testsRun,
    "failures": len(result.failures), "errors": len(result.errors),
    "successful": result.wasSuccessful()}))
raise SystemExit(0 if result.wasSuccessful() else 1)
'''


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate declaration field")
        result[key] = value
    return result


def parse_declaration(description):
    if not isinstance(description, str) or not description.startswith(PREFIX):
        raise ValueError("explicit declaration required")
    if len(description) > 2048:
        raise ValueError("declaration too long")
    def reject_constant(_value):
        raise ValueError("non-JSON constant")

    try:
        value = json.loads(description[len(PREFIX):], object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise ValueError("invalid declaration JSON") from None
    if not isinstance(value, dict) or set(value) != {"reason_code", "reason_summary"}:
        raise ValueError("invalid declaration fields")
    if value["reason_code"] not in ("unknown", "inspect_context", "verify_change",
                                  "reproduce_issue", "implement_change", "diagnose_failure", "gather_evidence"):
        raise ValueError("invalid code")
    summary = value["reason_summary"]
    if (not isinstance(summary, str) or not 1 <= len(summary) <= 240 or not summary.strip()
            or any(unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} for char in summary)):
        raise ValueError("invalid summary")
    return value


def hook(root, session):
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        value = json.loads(raw)
        if (value.get("hook_event_name") != "PreToolUse" or value.get("tool_name") != "Bash"
                or value.get("tool_input", {}).get("command") != COMMAND
                or not isinstance(value.get("session_id"), str) or not value["session_id"]
                or not isinstance(value.get("tool_use_id"), str) or not value["tool_use_id"]):
            raise ValueError()
        declaration = parse_declaration(value["tool_input"].get("description"))
        value["apolysis_reason"] = declaration
        command = [str(gate.REPO / "target/debug/apolysis"), "intent", "hook", "--harness", "claude",
                   "--session", session, "--workspace-root", str(root),
                   "--output", str(root / "intent.jsonl"), "--allow-reason-summary", "--shell-bridge", "/bin/bash"]
        result = subprocess.run(command, input=json.dumps(value).encode(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15)
        if result.returncode:
            raise ValueError()
        # Export only the accepted, redacted reason; never raw description/input.
        reason = gate.jsonl(root / "intent.jsonl.reasons.jsonl")[-1]
        if reason["reason_summary"] != declaration["reason_summary"] or reason["reason_summary"] == "[redacted]":
            raise ValueError()
        receipt = {"carrier": "tool_input.description", "protocol": "APOLYSIS_REASON_JSON_v1",
                   "adapter": "test_only", "tool_name": value["tool_name"],
                   "harness_session_id": value["session_id"], "source_event_id": value["tool_use_id"],
                   "declaration": declaration}
        (root / "native-declaration.json").write_text(json.dumps(receipt, ensure_ascii=False) + "\n")
        sys.stdout.buffer.write(result.stdout)
        return 0
    except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.TimeoutExpired):
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
              "permissionDecisionReason": "This bounded test requires its exact command and an explicit structured declaration."}}))
        return 0


def verify(root, session, binary, env):
    records = gate.jsonl(root / "timeline.jsonl")
    diagnostics = [r for r in records if r.get("record_type") == "observer_diagnostic"]
    known = {"ring_buffer_reserve_failure", "map_pressure", "decode_failure", "attach_failure",
             "verifier_failure", "truncation", "summary"}
    gate.require(all(r.get("kind") in known for r in diagnostics), "unknown observer diagnostic")
    gate.require(not any(r.get("count", 0) for r in diagnostics if r.get("kind") not in {"truncation", "summary"}),
                 "observer loss or failure")
    raw = [r for r in records if r.get("record_type") == "raw_kernel_event"]
    summaries = [r for r in diagnostics if r.get("kind") == "summary"]
    gate.require(raw and len(summaries) == 1 and summaries[0].get("count") == len(raw), "incomplete capture")
    events = [r for r in records if r.get("record_type") == "event"]
    exits = [r for r in events if r.get("resource") == "agent-exit-status"]
    gate.require(len(exits) == 1 and exits[0].get("action") == "exit:0", "native agent did not succeed")
    intents, reasons = gate.jsonl(root / "intent.jsonl"), gate.jsonl(root / "intent.jsonl.reasons.jsonl")
    gate.require(len(intents) == len(reasons) == 1, "expected one real native tool call")
    intent, reason = intents[0], reasons[0]
    receipt = json.loads((root / "native-declaration.json").read_text())
    gate.require(intent["session_id"] == reason["session_id"] == session and intent["intent_id"] == reason["intent_id"],
                 "capture identity mismatch")
    for key in ("harness_session_id", "source_event_id"):
        gate.require(receipt[key] == intent[key] == reason[key], "native identity mismatch")
    gate.require(reason["reason_source"] == "agent_declared" and reason["reason_code"] == "verify_change"
                 and reason["reason_summary"] == receipt["declaration"]["reason_summary"]
                 and reason["reason_summary"] not in (None, "", "[redacted]"), "model reason was not retained")
    tests = json.loads((root / "test-result.json").read_text())
    gate.require(tests == {"tests_run": 4, "failures": 0, "errors": 0, "successful": True}, "real login tests failed")
    status = gate.run_private([str(binary), "intent", "correlate", "--intent-input", str(root / "intent.jsonl"),
                              "--reason-input", str(root / "intent.jsonl.reasons.jsonl"),
                              "--timeline-input", str(root / "timeline.jsonl"), "--output", str(root / "correlation.jsonl")],
                             root / "correlation-private.log", root, env)
    gate.require(status == 0, "correlation failed")
    joined = gate.jsonl(root / "correlation.jsonl")
    gate.require(not any(r.get("record_type") == "intent_reason_diagnostic" for r in joined), "ambiguous reason")
    exact = [r for r in joined if r.get("record_type") == "intent_correlation"
             and r.get("relation_status") == "exact" and r.get("intent_id") == intent["intent_id"]
             and r.get("event_type") == "file_open" and r.get("resource") in ("verify_login.py", str(root / "verify_login.py"))
             and r.get("declared_reason", {}).get("reason_id") == reason["reason_id"]]
    gate.require(exact, "login test file lacks exact reason attribution")
    selected = exact[0]
    for key in ("reason_id", "reason_code", "reason_source", "reason_summary"):
        gate.require(selected["declared_reason"].get(key) == reason[key], "correlation lost declared reason fields")
    gate.require(selected.get("match_basis") == "intent_id"
                 and selected.get("process_executable") == "executable_ref:python3", "unexpected execution identity")
    selected_events = [r for r in records if r.get("session_id") == session
                       and ((r.get("record_type") == "raw_kernel_event" and r.get("event_id") == selected["raw_event_id"])
                            or (r.get("record_type") == "event" and r.get("raw_event_id") == selected["raw_event_id"]))]
    gate.require(len(selected_events) == 2
                 and any(r.get("record_type") == "raw_kernel_event" and r.get("intent_id") == intent["intent_id"] for r in selected_events)
                 and any(r.get("record_type") == "event" and r.get("intent_id") == intent["intent_id"] for r in selected_events),
                 "raw kernel evidence missing")
    gate.require(all(r.get("pid") == selected["pid"] and r.get("resource") == selected["resource"]
                     for r in selected_events), "kernel and correlation execution identity mismatch")
    for name in ("timeline.jsonl", "intent.jsonl", "intent.jsonl.reasons.jsonl", "correlation.jsonl", "native-declaration.json"):
        gate.require(gate.PROMPT_SENTINEL not in (root / name).read_text(), "prompt sentinel leaked")
    return intent, reason, receipt, selected_events, selected, tests, len(raw), sum(r.get("count", 0) for r in diagnostics if r.get("kind") == "truncation")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--hook":
        return hook(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--keep-failed-private", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or int(os.environ.get("SUDO_UID", "0")) == 0:
        print("apolysis-summary-live: SKIP: explicit sudo with a non-root invoking user is required", flush=True)
        return 1 if args.require_all else 0
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    operator_home = Path(pwd.getpwuid(uid).pw_dir)
    binary, bpf = gate.REPO / "target/debug/apolysis", gate.REPO / "target/ebpf/apolysis_observer.bpf.o"
    preflight = subprocess.run([str(gate.REPO / "scripts/check-bpf-prereqs.sh"), "live"], capture_output=True)
    if preflight.returncode or not binary.is_file() or not bpf.is_file():
        print("apolysis-summary-live: SKIP: build CLI/BPF and provide live BPF prerequisites", flush=True)
        return 1 if args.require_all else 0
    env = os.environ.copy()
    # The real invoking home is restored after sudo; authentication is not relocated.
    env["HOME"] = str(operator_home)
    gate.PROMPT = PROMPT
    try:
        with gate.private_workspace(args.keep_failed_private) as root:
            session = "native-summary-claude-" + uuid.uuid4().hex
            gate.write(root / "login.py", LOGIN, uid, gid)
            gate.write(root / "verify_login.py", TEST, uid, gid)
            hook_command = shlex.join([sys.executable, str(SCRIPT), "--hook", str(root), session])
            argv = gate.product_command("claude", root, hook_command, None)
            version_output = subprocess.check_output([argv[0], "--version"], text=True, stderr=subprocess.DEVNULL, timeout=15)
            version = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+) \(Claude Code\)\s*", version_output)
            gate.require(version is not None, "unexpected native product version response")
            argv = gate.isolated_command(root, argv, operator_home, "claude", binary, session, "/bin/bash")
            gate.own_tree(root, uid, gid)
            command = [str(binary), "observe", "--backend", "live", "--session", session,
                       "--policy", str(gate.REPO / "policies/local-dev.yaml"), "--output", str(root / "timeline.jsonl"),
                       "--bpf-object", str(bpf), "--workspace-root", str(root), "--duration-seconds", "180",
                       "--agent-kind", "claude", "--agent-run", "--", *argv]
            status = gate.run_private(command, root / "product-private.log", root, env)
            gate.require(status == 0, "native execution failed; " + gate.failure_category(root / "product-private.log"))
            intent, reason, receipt, events, relation, tests, count, truncations = verify(root, session, binary, env)
            evidence = Path(tempfile.mkdtemp(prefix="native-reason-evidence-", dir=gate.REPO / "target"))
            for name, rows in (("intent.jsonl", [intent]), ("reason.jsonl", [reason]),
                               ("kernel-evidence.jsonl", events), ("correlation.jsonl", [relation])):
                gate.write(evidence / name, "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), uid, gid)
            gate.write(evidence / "native-declaration.json", json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", uid, gid)
            report = {"status": "PASS", "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
                      "product": "claude", "product_version": version.group(1), "adapter": "test_only_explicit_description_protocol",
                      "shell_bridge": "/bin/bash", "session_id": session, "intent_id": intent["intent_id"],
                      "kernel_events": count, "truncations": truncations, "loss_or_failure_count": 0,
                      "prompt_sentinel_absent": True, "login_regression": tests,
                      "native_exit": 0, "relation_status": relation["relation_status"],
                      "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=gate.REPO, text=True).strip(),
                      "artifact_sha256": {"runner": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                                          "cli": hashlib.sha256(binary.read_bytes()).hexdigest(),
                                          "bpf": hashlib.sha256(bpf.read_bytes()).hexdigest()}}
            gate.write(evidence / "result.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n", uid, gid)
            gate.own_tree(evidence, uid, gid)
            print(f"apolysis-summary-live: PASS: 4 real login tests; {count} kernel events; {truncations} truncations; zero loss/failures; exact reason binding", flush=True)
            print("apolysis-summary-live: sanitized evidence: " + str(evidence), flush=True)
            return 0
    except (gate.GateError, gate.PrerequisiteMissing) as error:
        print("apolysis-summary-live: FAIL: " + str(error), flush=True)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print("apolysis-summary-live: FAIL: evidence validation failed", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())

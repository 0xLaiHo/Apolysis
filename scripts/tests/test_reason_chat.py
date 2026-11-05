#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No-provider regressions for the interactive reason-chat adapter."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "run-reason-chat.py"
SPEC = importlib.util.spec_from_file_location("reason_chat_under_test", SCRIPT)
CHAT = importlib.util.module_from_spec(SPEC)
with mock.patch("subprocess.run", side_effect=AssertionError("provider must not run")), \
        mock.patch("subprocess.Popen", side_effect=AssertionError("process must not start")):
    SPEC.loader.exec_module(CHAT)


class MessageTests(unittest.TestCase):
    def test_wrapper_preserves_user_input_exactly(self):
        for prompt in ["你好", "  保留空格。  ", "第一行\n第二行\t内容", '引号 " \\ apostrophe\' 😀',
                       "APOLYSIS_REASON_JSON= is ordinary user text", ""]:
            with self.subTest(prompt_length=len(prompt)):
                wrapped = CHAT.message(prompt)
                self.assertEqual(wrapped, {
                    "type": "user", "message": {"role": "user", "content": prompt},
                    "parent_tool_use_id": None, "session_id": "default", "client_composed": True,
                })
                self.assertEqual(json.loads(json.dumps(wrapped))["message"]["content"], prompt)

    def test_assistant_output_only_contains_explicit_text_blocks(self):
        value = {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": "DO_NOT_LOG", "text": "DO_NOT_LOG"},
            {"type": "redacted_thinking", "data": "DO_NOT_LOG"},
            {"type": "tool_use", "name": "Bash", "input": {"command": "DO_NOT_LOG"}, "text": "DO_NOT_LOG"},
            {"type": "tool_result", "content": "DO_NOT_LOG", "text": "DO_NOT_LOG"},
            {"type": "text", "text": "正常答复。"},
            {"type": "text", "text": {"unexpected": "DO_NOT_LOG"}},
            {"type": "text", "text": "第二段答复。"},
            "DO_NOT_LOG", None,
        ]}}
        original = copy.deepcopy(value)
        self.assertEqual(CHAT.assistant_text(value), ["正常答复。", "第二段答复。"])
        self.assertEqual(value, original)

    def test_nonassistant_events_never_display_payloads(self):
        for kind in ["result", "user", "system", "stream_event", "tool_result", "unknown"]:
            with self.subTest(kind=kind):
                self.assertEqual(CHAT.assistant_text({
                    "type": kind, "result": "DO_NOT_LOG",
                    "message": {"content": [{"type": "text", "text": "DO_NOT_LOG"}]},
                }), [])

    def test_malformed_assistant_envelopes_are_ignored(self):
        for value in [{"type": "assistant"}, {"type": "assistant", "message": None},
                      {"type": "assistant", "message": []},
                      {"type": "assistant", "message": {"content": None}},
                      {"type": "assistant", "message": {"content": "DO_NOT_LOG"}},
                      {"type": "assistant", "message": {"content": 7}}]:
            with self.subTest(value=value):
                self.assertEqual(CHAT.assistant_text(value), [])


class CompleteLineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="apolysis-chat-lines-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "timeline.jsonl"

    def test_missing_empty_and_blank_lines_are_valid(self):
        self.assertEqual(CHAT.read_complete(self.path), [])
        for data in [b"", b"\n\n"]:
            self.path.write_bytes(data)
            self.assertEqual(CHAT.read_complete(self.path), [])

    def test_only_the_unfinished_final_line_is_discarded(self):
        first = {"message": "完整中文"}
        line = (json.dumps(first, ensure_ascii=False) + "\n").encode()
        for tail in [b"", b'{"unfinished":', b"DO_NOT_LOG", b'"\xe4\xb8', b'{"valid_but_no_newline":true}']:
            self.path.write_bytes(line + tail)
            self.assertEqual(CHAT.read_complete(self.path), [first])
        self.path.write_bytes(b'{"no_complete_line":true}')
        self.assertEqual(CHAT.read_complete(self.path), [])

    def test_malformed_complete_lines_are_never_silently_dropped(self):
        for data in [b"DO_NOT_LOG\n", b'{"bad":}\n', b'{}\nDO_NOT_LOG\n{"unfinished":', b"\xff\n", b"  \n"]:
            with self.subTest(data_length=len(data)):
                self.path.write_bytes(data)
                with self.assertRaises((ValueError, UnicodeError)):
                    CHAT.read_complete(self.path)


class CaptureReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="apolysis-chat-report-")
        self.addCleanup(self.directory.cleanup)
        self.evidence = Path(self.directory.name)
        self.session = "capture-test"

    def valid_records(self):
        return [
            {"record_type": "raw_kernel_event", "session_id": self.session, "raw_event_id": "raw-1"},
            {"record_type": "event", "session_id": self.session, "resource": "agent-exit-status", "action": "exit:0"},
            {"record_type": "observer_diagnostic", "session_id": self.session, "kind": "summary", "count": 1},
        ]

    def report(self, records, closed_normally=True, turns=None):
        (self.evidence / "timeline.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records))
        return CHAT.report(self.evidence, self.session, turns or [], closed_normally)

    def assert_incomplete(self, records, **options):
        self.assertEqual(self.report(records, **options)["capture_status"], "incomplete")

    def test_complete_requires_matching_final_capture_evidence(self):
        report = self.report(self.valid_records(), turns=[{"turn": 1, "tool_calls": 1}])
        self.assertEqual(report["capture_status"], "complete")
        self.assertEqual(report["kernel_events"], 1)
        self.assertEqual(report["loss_or_failure_count"], 0)
        self.assertTrue(report["native_exit_success"])
        self.assertFalse(report["forced_stop"])

    def test_no_tool_turns_are_valid_and_do_not_require_intents_or_reasons(self):
        turns = [{"turn": 1, "tool_calls": 0}, {"turn": 2, "tool_calls": 0}]
        report = self.report(self.valid_records(), turns=turns)
        self.assertEqual(report["capture_status"], "complete")
        self.assertEqual(report["turns"], turns)
        self.assertFalse((self.evidence / "intent.jsonl").exists())
        self.assertFalse((self.evidence / "intent.jsonl.reasons.jsonl").exists())

    def test_forced_stop_or_missing_nonzero_duplicate_root_exit_is_incomplete(self):
        self.assert_incomplete(self.valid_records(), closed_normally=False)
        rows = self.valid_records()
        self.assert_incomplete([rows[0], rows[2]])
        for action in ["exit:1", "signal:9"]:
            changed = copy.deepcopy(rows)
            changed[1]["action"] = action
            self.assert_incomplete(changed)
            self.assert_incomplete(rows + [changed[1]])
        self.assert_incomplete(rows + [rows[1]])

    def test_missing_duplicate_or_mismatched_summary_is_incomplete(self):
        rows = self.valid_records()
        self.assert_incomplete(rows[:-1])
        self.assert_incomplete(rows + [rows[-1]])
        for count in [0, 2]:
            changed = copy.deepcopy(rows)
            changed[-1]["count"] = count
            self.assert_incomplete(changed)
        self.assert_incomplete([rows[1], {**rows[2], "count": 0}])

    def test_reported_capture_loss_and_failures_are_incomplete(self):
        for kind in ["ring_buffer_reserve_failure", "map_pressure", "decode_failure", "attach_failure", "verifier_failure"]:
            with self.subTest(kind=kind):
                rows = self.valid_records() + [{"record_type": "observer_diagnostic", "session_id": self.session,
                                               "kind": kind, "count": 2}]
                result = self.report(rows)
                self.assertEqual(result["capture_status"], "incomplete")
                self.assertEqual(result["loss_or_failure_count"], 2)

    def test_truncation_is_reported_separately_from_loss(self):
        rows = self.valid_records() + [{"record_type": "observer_diagnostic", "session_id": self.session,
                                       "kind": "truncation", "count": 3}]
        result = self.report(rows)
        self.assertEqual(result["capture_status"], "complete")
        self.assertEqual(result["truncations"], 3)
        self.assertEqual(result["loss_or_failure_count"], 0)

    def test_unknown_diagnostics_and_invalid_counts_cannot_claim_complete(self):
        rows = self.valid_records()
        self.assert_incomplete(rows + [{"record_type": "observer_diagnostic", "session_id": self.session,
                                       "kind": "future_failure", "count": 0}])
        for count in [True, -1, 1.0, "1", None]:
            with self.subTest(count=count):
                changed = copy.deepcopy(rows)
                changed[-1]["count"] = count
                self.assert_incomplete(changed)
        self.assert_incomplete(rows + [
            {"record_type": "observer_diagnostic", "session_id": self.session, "kind": "decode_failure", "count": 1},
            {"record_type": "observer_diagnostic", "session_id": self.session, "kind": "map_pressure", "count": -1},
        ])

    def test_other_or_missing_capture_session_cannot_complete(self):
        for index in range(len(self.valid_records())):
            for foreign_session in ["other-capture", None]:
                with self.subTest(index=index, session=foreign_session):
                    rows = self.valid_records()
                    if foreign_session is None:
                        rows[index].pop("session_id")
                    else:
                        rows[index]["session_id"] = foreign_session
                    self.assert_incomplete(rows)
        rows = self.valid_records()
        for row in rows:
            row["session_id"] = "other-capture"
        self.assert_incomplete(rows)

    def test_final_partial_line_makes_capture_incomplete_even_after_valid_summary(self):
        baseline = "".join(json.dumps(row) + "\n" for row in self.valid_records()).encode()
        timeline = self.evidence / "timeline.jsonl"
        for tail in [b'{"record_type":', b"DO_NOT_LOG", b'"\xe4\xb8', b'{}']:
            with self.subTest(tail_length=len(tail)):
                timeline.write_bytes(baseline + tail)
                self.assertEqual(CHAT.read_complete(timeline), self.valid_records())
                self.assertEqual(CHAT.report(self.evidence, self.session, [], True)["capture_status"], "incomplete")


class UserOwnedPublishTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="apolysis-chat-publish-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.identity = {"SUDO_UID": "12345", "SUDO_GID": "23456"}

    def assert_user_launch(self, kwargs):
        self.assertEqual(kwargs["user"], 12345)
        self.assertEqual(kwargs["group"], 23456)
        self.assertEqual(kwargs["extra_groups"], [])
        self.assertNotEqual(kwargs["user"], 0)
        self.assertNotEqual(kwargs["group"], 0)
        self.assertFalse(kwargs.get("shell", False))

    def execute_publish_locally(self, argv, kwargs):
        """Exercise only the generated file writer, without sudo or a child."""
        self.assert_user_launch(kwargs)
        self.assertEqual(argv[:2], [CHAT.sys.executable, "-c"])
        with mock.patch.object(CHAT.sys, "argv", ["-c", argv[3]]), \
                mock.patch.object(CHAT.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(kwargs["input"]))):
            exec(compile(argv[2], "<apolysis-test-writer>", "exec"), {"__name__": "__main__"})
        return SimpleNamespace(returncode=0)

    def test_publish_runs_as_invoking_user_and_replaces_symlink_atomically(self):
        victim = self.root / "unrelated.txt"
        victim.write_text("must stay unchanged")
        destination = self.root / "result.json"
        destination.symlink_to(victim)
        data = '{"status":"新证据"}\n'

        def run(argv, **kwargs):
            self.assertEqual(kwargs["input"], data.encode())
            self.assertEqual(kwargs["stdout"], CHAT.subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], CHAT.subprocess.DEVNULL)
            return self.execute_publish_locally(argv, kwargs)

        with mock.patch.dict(os.environ, self.identity), \
                mock.patch.object(CHAT.subprocess, "run", side_effect=run) as child, \
                mock.patch("os.replace", wraps=os.replace) as replace:
            CHAT.publish(destination, data)
        child.assert_called_once()
        replace.assert_called_once()
        self.assertEqual(Path(replace.call_args.args[0]).parent, destination.parent)
        self.assertEqual(Path(replace.call_args.args[1]), destination)
        self.assertFalse(destination.is_symlink())
        self.assertEqual(destination.read_text(), data)
        self.assertEqual(victim.read_text(), "must stay unchanged")
        self.assertEqual(list(self.root.glob(".apolysis-*")), [])

    def test_publish_rejects_root_invalid_or_missing_identity_before_launch(self):
        for field in ["SUDO_UID", "SUDO_GID"]:
            for value in ["0", "-1", "not-a-number", None]:
                with self.subTest(field=field, value=value):
                    environment = dict(self.identity)
                    if value is None:
                        environment.pop(field)
                    else:
                        environment[field] = value
                    with mock.patch.dict(os.environ, environment, clear=True), \
                            mock.patch.object(CHAT.subprocess, "run") as child:
                        with self.assertRaises((ValueError, KeyError, CHAT.gate.GateError)):
                            CHAT.publish(self.root / "result.json", "{}\n")
                        child.assert_not_called()

    def test_publish_failure_is_reported(self):
        with mock.patch.dict(os.environ, self.identity), \
                mock.patch.object(CHAT.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(CHAT.gate.GateError):
                CHAT.publish(self.root / "result.json", "{}\n")

    def test_correlate_uses_private_snapshot_then_user_atomic_publish(self):
        evidence = self.root / "user-evidence"
        evidence.mkdir()
        timeline = {"record_type": "event", "session_id": "capture"}
        (evidence / "timeline.jsonl").write_bytes((json.dumps(timeline) + "\n").encode() + b'{"unfinished":')
        (evidence / "intent.jsonl").write_text("")
        (evidence / "intent.jsonl.reasons.jsonl").write_text("")
        relation = {"record_type": "intent_correlation", "relation_status": "exact"}
        result_text = json.dumps(relation) + "\n"
        phases, prepared, private_dirs = [], [], []
        env = {"SAFE_TEST_ENV": "1"}

        def prepare(path, data, uid, gid):
            self.assertEqual((uid, gid), (12345, 23456))
            self.assertNotEqual(path.parent, evidence)
            prepared.append(path)
            path.write_text(data)

        def run(argv, **kwargs):
            self.assert_user_launch(kwargs)
            if argv[1:3] == ["intent", "correlate"]:
                phases.append("correlate")
                self.assertEqual(kwargs["env"], env)
                snapshot = Path(argv[argv.index("--timeline-input") + 1])
                output = Path(argv[argv.index("--output") + 1])
                self.assertEqual(snapshot.parent, output.parent)
                self.assertNotEqual(output.parent, evidence)
                self.assertEqual(output.parent.stat().st_mode & 0o777, 0o711)
                self.assertEqual(CHAT.read_complete(snapshot), [timeline])
                self.assertEqual(output.read_text(), "")
                private_dirs.append(output.parent)
                output.write_text(result_text)
                return SimpleNamespace(returncode=0)
            phases.append("publish")
            self.assertEqual(argv[-1], str(evidence / "correlation.jsonl"))
            self.assertEqual(kwargs["input"], result_text.encode())
            return self.execute_publish_locally(argv, kwargs)

        with mock.patch.dict(os.environ, self.identity), \
                mock.patch.object(CHAT.gate, "write", side_effect=prepare), \
                mock.patch.object(CHAT.subprocess, "run", side_effect=run), \
                mock.patch("os.replace", wraps=os.replace) as replace:
            result = CHAT.correlate(evidence, Path("/not-executed/apolysis"), env)
        self.assertEqual(result, [relation])
        self.assertEqual(phases, ["correlate", "publish"])
        self.assertEqual(len(prepared), 2)
        replace.assert_called_once()
        self.assertEqual(Path(replace.call_args.args[1]), evidence / "correlation.jsonl")
        self.assertTrue(all(not path.exists() for path in private_dirs))

    def test_failed_correlation_never_publishes_partial_output(self):
        evidence = self.root / "user-evidence"
        evidence.mkdir()
        (evidence / "timeline.jsonl").write_text("{}\n")
        (evidence / "correlation.jsonl").write_text("existing evidence\n")
        with mock.patch.dict(os.environ, self.identity), \
                mock.patch.object(CHAT.gate, "write", side_effect=lambda path, data, *_: path.write_text(data)), \
                mock.patch.object(CHAT.subprocess, "run", return_value=SimpleNamespace(returncode=1)), \
                mock.patch.object(CHAT, "publish") as publish:
            with self.assertRaises(CHAT.gate.GateError):
                CHAT.correlate(evidence, Path("/not-executed/apolysis"), {})
        publish.assert_not_called()
        self.assertEqual((evidence / "correlation.jsonl").read_text(), "existing evidence\n")


if __name__ == "__main__":
    unittest.main()

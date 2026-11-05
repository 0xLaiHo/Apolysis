#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure parser regressions; importing the gate must never launch a provider."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "test-live-reason-summary.py"
SPEC = importlib.util.spec_from_file_location("live_reason_summary_under_test", SCRIPT)
SUMMARY_GATE = importlib.util.module_from_spec(SPEC)
with mock.patch("subprocess.run", side_effect=AssertionError("provider must not run")), \
        mock.patch("subprocess.Popen", side_effect=AssertionError("process must not start")):
    SPEC.loader.exec_module(SUMMARY_GATE)


class DeclarationParserTests(unittest.TestCase):
    def declaration(self, **changes):
        value = {"reason_code": "verify_change", "reason_summary": "验证登录修复是否通过回归检查。"}
        value.update(changes)
        return SUMMARY_GATE.PREFIX + json.dumps(value, ensure_ascii=False)

    def assert_rejected(self, value):
        with self.assertRaises(ValueError) as error:
            SUMMARY_GATE.parse_declaration(value)
        self.assertNotIn("DO_NOT_LOG", str(error.exception))

    def test_ordinary_descriptions_do_not_become_declarations(self):
        for description in [None, 7, {}, [], "", "Run the regression tests", "验证登录修复。",
                            '{"reason_code":"verify_change","reason_summary":"验证修复"}',
                            " " + self.declaration(), "Explanation: " + self.declaration()]:
            with self.subTest(description=type(description).__name__):
                self.assert_rejected(description)

    def test_duplicate_unknown_and_missing_fields_are_rejected(self):
        documents = [
            '{"reason_code":"unknown","reason_code":"verify_change","reason_summary":"DO_NOT_LOG"}',
            '{"reason_code":"verify_change","reason_summary":"a","reason_summary":"DO_NOT_LOG"}',
            '{"reason_code":"verify_change","reason_summary":"DO_NOT_LOG","reason_source":"agent_declared"}',
            '{"reason_code":"verify_change","reason_summary":"DO_NOT_LOG","extra":true}',
            '{"reason_code":"verify_change"}',
            '{"reason_summary":"DO_NOT_LOG"}',
            '{}',
        ]
        for document in documents:
            with self.subTest(document_index=documents.index(document)):
                self.assert_rejected(SUMMARY_GATE.PREFIX + document)

    def test_malformed_and_nonstandard_json_are_rejected_with_static_errors(self):
        for document in ["DO_NOT_LOG", "{", "[]", "null", '"DO_NOT_LOG"', "1",
                         '{"reason_code":"verify_change","reason_summary":"DO_NOT_LOG",}',
                         '{"reason_code":"verify_change","reason_summary":"ok"} DO_NOT_LOG',
                         '{"reason_code":NaN,"reason_summary":"DO_NOT_LOG"}',
                         '{"reason_code":"verify_change","reason_summary":Infinity}',
                         '{"reason_code":"verify_change","reason_summary":-Infinity}',
                         "[" * 1000 + "]" * 1000]:
            self.assert_rejected(SUMMARY_GATE.PREFIX + document)

    def test_invalid_codes_are_rejected_without_inference_or_correction(self):
        for code in [None, 1, True, [], {}, "", "VERIFY_CHANGE", " verify_change", "fix_bug", "DO_NOT_LOG"]:
            with self.subTest(code_type=type(code).__name__):
                self.assert_rejected(self.declaration(reason_code=code))

    def test_invalid_summaries_are_rejected_and_raw_length_is_bounded(self):
        for summary in [None, 1, True, [], {}, "", "   ", "验" * 241,
                        " " * 240 + "验", "验" + " " * 240,
                        "DO_NOT_LOG\nnext", "DO_NOT_LOG\rnext", "DO_NOT_LOG\tnext",
                        "DO_NOT_LOG\x00next", "DO_NOT_LOG\x85next", "DO_NOT_LOG\u2028next",
                        "DO_NOT_LOG\u2029next", "DO_NOT_LOG\ud800"]:
            with self.subTest(summary_type=type(summary).__name__):
                self.assert_rejected(self.declaration(reason_summary=summary))

    def test_oversized_declarations_are_rejected(self):
        self.assert_rejected(self.declaration(reason_summary="DO_NOT_LOG" * 300))

    def test_all_closed_codes_and_unicode_values_are_returned_unchanged(self):
        for code in ["unknown", "inspect_context", "verify_change", "reproduce_issue",
                     "implement_change", "diagnose_failure", "gather_evidence"]:
            value = {"reason_code": code, "reason_summary": "检查登录修复，确认异常输入仍被拒绝。"}
            actual = SUMMARY_GATE.parse_declaration(SUMMARY_GATE.PREFIX + json.dumps(value, ensure_ascii=False))
            self.assertEqual(actual, value)
            self.assertEqual(set(actual), {"reason_code", "reason_summary"})

    def test_parser_never_trims_normalizes_or_fills_in_model_text(self):
        for summary in ["验", "验" * 240, "  验证  登录修复。  ", "e\u0301 与 é 都是模型原文。"]:
            actual = SUMMARY_GATE.parse_declaration(self.declaration(reason_summary=summary))
            self.assertEqual(actual["reason_summary"], summary)
            self.assertEqual(actual["reason_code"], "verify_change")
        value = {"reason_summary": "自主选择的目的。", "reason_code": "unknown"}
        actual = SUMMARY_GATE.parse_declaration(SUMMARY_GATE.PREFIX + json.dumps(value))
        self.assertEqual(actual, value)
        self.assertEqual(list(actual), list(value))


if __name__ == "__main__":
    unittest.main()

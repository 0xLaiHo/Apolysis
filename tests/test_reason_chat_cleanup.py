#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged process cleanup regressions; no provider or BPF is started."""

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-reason-chat.py"
SPEC = importlib.util.spec_from_file_location("reason_chat_cleanup", SCRIPT)
CHAT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHAT)


def process_running(pid):
    try:
        # An orphan may briefly remain a zombie until its new parent reaps it.
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except FileNotFoundError:
        return False


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux process groups and /proc")
class ReasonChatCleanupTests(unittest.TestCase):
    def launch(self, command):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, start_new_session=True)

        def cleanup():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()

        self.addCleanup(cleanup)
        return process

    def assert_terminated(self, pid):
        deadline = time.monotonic() + 2
        while process_running(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(process_running(pid), "owned background process survived cleanup")

    def test_normal_exit_terminates_background_process(self):
        process = self.launch(["/bin/sh", "-c", 'sleep 60 & echo "$!"; exit 0'])
        background_pid = int(process.stdout.readline())
        self.assertTrue(process_running(background_pid))
        self.assertEqual(CHAT.close_process(process), 0)
        self.assert_terminated(background_pid)

    def test_eof_allows_graceful_exit_and_preserves_status(self):
        process = self.launch([sys.executable, "-c", "import sys; sys.stdin.read(); sys.exit(7)"])
        self.assertEqual(CHAT.close_process(process), 7)
        self.assertEqual(process.returncode, 7)
        self.assertTrue(process.stdin.closed)

    def test_timeout_kills_and_reaps_term_ignoring_process(self):
        process = self.launch([sys.executable, "-u", "-c",
                               "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                               "print('ready'); time.sleep(60)"])
        self.assertEqual(process.stdout.readline().strip(), "ready")
        real_wait = process.wait

        def short_wait(timeout=None):
            return real_wait(timeout=min(timeout, 0.1) if timeout is not None else None)

        with mock.patch.object(process, "wait", side_effect=short_wait):
            self.assertIsNone(CHAT.close_process(process))
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assert_terminated(process.pid)


if __name__ == "__main__":
    unittest.main()

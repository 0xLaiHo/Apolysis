#!/usr/bin/env python3
"""TCP connect fixture for future network event tests.

The script only attempts a TCP connection to the host and port supplied by the
test harness.  It is intentionally tiny so future eBPF tests can reason about
the expected socket operation without unrelated application behavior.
"""

import socket
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: connect.py <host> <port>", file=sys.stderr)
        return 2

    host = sys.argv[1]
    port = int(sys.argv[2])
    with socket.create_connection((host, port), timeout=2):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

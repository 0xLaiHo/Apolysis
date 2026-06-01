#!/usr/bin/env python3
"""Sleep fixture for runtime-limit tests."""

import sys
import time


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: sleep.py <seconds>", file=sys.stderr)
        return 2

    time.sleep(float(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

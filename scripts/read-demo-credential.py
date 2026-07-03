#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Read the Codex live-demo fake credential fixture without printing secrets."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


def fail(message: str) -> int:
    print(f"read-demo-credential: {message}", file=sys.stderr)
    return 1


def main() -> int:
    demo_home = os.environ.get("APOLYSIS_CODEX_DEMO_HOME")
    if not demo_home:
        return fail("APOLYSIS_CODEX_DEMO_HOME is required")

    credential_path = Path(demo_home).expanduser() / ".aws" / "credentials"
    if not credential_path.is_file():
        return fail(f"missing fake credential fixture: {credential_path}")

    data = credential_path.read_bytes()
    if b"APOLYSIS_FAKE_" not in data:
        return fail("refusing to read a credential file that is not a fake fixture")

    digest = hashlib.sha256(data).hexdigest()
    print(
        "fake credential fixture read: "
        f"path={credential_path} bytes={len(data)} sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

artifact_dir="${APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR:-}"
host_root="${APOLYSIS_HOST_ROOT:-/}"

if [[ -z "$artifact_dir" || ! -d "$artifact_dir" ]]; then
    cat >&2 <<'EOF'
apolysis-f2: restore assertion requires APOLYSIS_RUNTIME_ADAPTER_MATRIX_OUTPUT_DIR
to point at the retained runtime adapter matrix artifact directory.
EOF
    exit 2
fi

manifest="$artifact_dir/backup-manifest.json"
if [[ ! -s "$manifest" ]]; then
    echo "apolysis-f2: missing backup manifest: $manifest" >&2
    exit 2
fi

python3 - "$manifest" "$host_root" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
host_root = Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text())
failures = []

for entry in manifest.get("entries", []):
    original_path = entry.get("original_path")
    kind = entry.get("kind")
    if not original_path or not original_path.startswith("/"):
        failures.append(f"invalid original_path for {entry.get('id', '<unknown>')}: {original_path!r}")
        continue
    host_path = host_root / original_path.lstrip("/")
    try:
        stat = host_path.lstat()
    except FileNotFoundError:
        stat = None

    if kind == "missing":
        if stat is not None:
            failures.append(f"{original_path} should be absent after restore")
    elif kind == "regular_file":
        if stat is None:
            failures.append(f"{original_path} should exist after restore")
            continue
        if not host_path.is_file() or host_path.is_symlink():
            failures.append(f"{original_path} should be restored as a regular file")
            continue
        expected_sha = entry.get("sha256_hex")
        actual_sha = hashlib.sha256(host_path.read_bytes()).hexdigest()
        if expected_sha and actual_sha != expected_sha:
            failures.append(
                f"{original_path} checksum mismatch after restore: expected {expected_sha}, got {actual_sha}"
            )
    elif kind == "symlink":
        if stat is None:
            failures.append(f"{original_path} should exist as a symlink after restore")
            continue
        if not host_path.is_symlink():
            failures.append(f"{original_path} should be restored as a symlink")
            continue
        expected_target = entry.get("symlink_target")
        actual_target = os.readlink(host_path)
        if expected_target and actual_target != expected_target:
            failures.append(
                f"{original_path} symlink target mismatch after restore: expected {expected_target}, got {actual_target}"
            )
    else:
        failures.append(f"unsupported backup manifest kind for {original_path}: {kind!r}")

if failures:
    for failure in failures:
        print(f"apolysis-f2: {failure}", file=sys.stderr)
    sys.exit(1)
PY

echo "apolysis-f2: runtime matrix restore matches backup manifest"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'codex live demo final assets check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing required file: $1"
}

require_contains() {
    local path="$1"
    local needle="$2"
    grep -Fq -- "$needle" "$path" || fail "$path missing required text: $needle"
}

require_not_contains() {
    local path="$1"
    local needle="$2"
    if grep -Fq -- "$needle" "$path"; then
        fail "$path must not contain: $needle"
    fi
}

require_not_matches() {
    local path="$1"
    local pattern="$2"
    if grep -Eq -- "$pattern" "$path"; then
        fail "$path must not match: $pattern"
    fi
}

asset_dir="docs/assets/codex-live-demo"
summary="$asset_dir/summary.json"
transcript="$asset_dir/terminal-transcript.txt"
cast="$asset_dir/codex-live-demo.cast"
gif="$asset_dir/codex-live-demo.gif"
public_assets_doc="docs/codex-live-demo-public-assets.md"
render_script="scripts/render-codex-live-demo-assets.py"

for path in "$summary" "$transcript" "$cast" "$gif" "$public_assets_doc" "$render_script"; do
    require_file "$path"
done

require_contains README.md "$gif"
require_contains README.md "$cast"
require_contains README.zh-CN.md "$gif"
require_contains README.zh-CN.md "$cast"
require_not_contains README.md "demo placeholder"
require_not_contains README.zh-CN.md "demo 占位"

python3 - <<'PY'
from pathlib import Path

def before(path: str, needle: str, marker: str) -> None:
    text = Path(path).read_text(encoding="utf-8")
    needle_index = text.find(needle)
    marker_index = text.find(marker)
    if needle_index < 0:
        raise SystemExit(f"{path} missing {needle}")
    if marker_index < 0:
        raise SystemExit(f"{path} missing marker {marker}")
    if needle_index > marker_index:
        raise SystemExit(f"{needle} must appear before {marker} in {path}")

before("README.md", "docs/assets/codex-live-demo/codex-live-demo.gif", "## Current Status")
before("README.zh-CN.md", "docs/assets/codex-live-demo/codex-live-demo.gif", "## 当前状态")
PY

for path in "$summary" "$transcript" "$cast"; do
    require_not_matches "$path" '/home/[^[:space:]"'\'']+'
    require_not_matches "$path" 'APOLYSIS_FAKE_(KEY|SECRET)'
    require_not_matches "$path" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
    require_not_matches "$path" 'sk-[A-Za-z0-9_-]{20,}'
    require_not_matches "$path" 'aws_secret_access_key|aws_access_key_id'
    require_not_matches "$path" 'password[[:space:]]*[:=]'
done

python3 - <<'PY'
import json
from pathlib import Path


def skip_sub_blocks(data: bytes, index: int) -> int:
    while True:
        if index >= len(data):
            raise SystemExit("unterminated GIF sub-block stream")
        block_size = data[index]
        index += 1
        if block_size == 0:
            return index
        index += block_size


def gif_frame_count(data: bytes) -> tuple[int, int, int]:
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        raise SystemExit("asset is not a GIF")
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    packed = data[10]
    index = 13
    if packed & 0x80:
        index += 3 * (2 ** ((packed & 0x07) + 1))
    frames = 0
    while index < len(data):
        sentinel = data[index]
        index += 1
        if sentinel == 0x3B:
            return width, height, frames
        if sentinel == 0x21:
            index += 1
            index = skip_sub_blocks(data, index)
            continue
        if sentinel == 0x2C:
            if index + 9 > len(data):
                raise SystemExit("truncated GIF image descriptor")
            local_packed = data[index + 8]
            index += 9
            if local_packed & 0x80:
                index += 3 * (2 ** ((local_packed & 0x07) + 1))
            index += 1
            index = skip_sub_blocks(data, index)
            frames += 1
            continue
        raise SystemExit(f"unexpected GIF block sentinel: {sentinel:#x}")
    raise SystemExit("missing GIF trailer")

summary = json.loads(Path("docs/assets/codex-live-demo/summary.json").read_text(encoding="utf-8"))
if summary.get("demo_status") != "validated_local_live":
    raise SystemExit("summary is not validated_local_live")
if summary.get("redaction_boundary") != "curated_public_excerpt":
    raise SystemExit("summary is not bounded to curated_public_excerpt")

cast_path = Path("docs/assets/codex-live-demo/codex-live-demo.cast")
lines = cast_path.read_text(encoding="utf-8").splitlines()
if len(lines) < 5:
    raise SystemExit("cast file has too few events")
header = json.loads(lines[0])
if header.get("version") != 2:
    raise SystemExit("cast file must use asciinema v2 format")
events = [json.loads(line) for line in lines[1:]]
payload = "".join(event[2] for event in events if len(event) >= 3 and event[1] == "o")
for needle in (
    "codex-live-demo",
    "run-codex-live-demo-workload.sh",
    "process_executable",
    "missing_intent",
):
    if needle not in payload:
        raise SystemExit(f"cast missing {needle}")

gif_path = Path("docs/assets/codex-live-demo/codex-live-demo.gif")
if gif_path.stat().st_size > 2_000_000:
    raise SystemExit("GIF is too large for README use")
width, height, frames = gif_frame_count(gif_path.read_bytes())
if frames < 8:
    raise SystemExit("GIF does not have enough frames")
if width < 900 or height < 500:
    raise SystemExit("GIF dimensions are too small for README first viewport")
PY

require_contains "$public_assets_doc" "$cast"
require_contains "$public_assets_doc" "$gif"
require_contains "$public_assets_doc" "final README demo"
require_contains "$repo_root/.github/workflows/release-validation.yml" "make test-codex-live-demo-final-assets"
require_contains "$repo_root/scripts/test-release-validation-ci.sh" "test-codex-live-demo-final-assets:"

printf 'codex live demo final assets check passed\n'

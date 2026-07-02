#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'apolysis-release-artifacts: %s\n' "$*" >&2
    exit 1
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

default_target() {
    case "$(uname -m)" in
        x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
        aarch64) printf 'aarch64-unknown-linux-gnu\n' ;;
        *)
            fail "unsupported release target for architecture $(uname -m); set APOLYSIS_RELEASE_TARGET"
            ;;
    esac
}

release_version="${APOLYSIS_RELEASE_VERSION:-}"
if [[ -z "$release_version" ]]; then
    release_version="$(git describe --tags --always --dirty 2>/dev/null || true)"
fi
[[ -n "$release_version" ]] || fail "set APOLYSIS_RELEASE_VERSION"

release_target="${APOLYSIS_RELEASE_TARGET:-$(default_target)}"
release_binary="${APOLYSIS_RELEASE_BINARY:-target/release/apolysis}"
release_bpf_object="${APOLYSIS_RELEASE_BPF_OBJECT:-target/ebpf/apolysis_observer.bpf.o}"
output_dir="${APOLYSIS_RELEASE_OUTPUT_DIR:-target/release-artifacts}"
package_base="apolysis-${release_version}-${release_target}"
package_name="${package_base}.tar.gz"
package_path="$output_dir/$package_name"
manifest_name="apolysis-release-manifest.json"
manifest_path="$output_dir/$manifest_name"
checksum_path="$package_path.sha256"

[[ -f "$release_binary" ]] || fail "missing CLI binary: $release_binary"
[[ -x "$release_binary" ]] || fail "CLI binary is not executable: $release_binary"
[[ -f "$release_bpf_object" ]] || fail "missing CO-RE BPF object: $release_bpf_object"

mkdir -p "$output_dir"
tmpdir="$(mktemp -d "$output_dir/.packaging.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

stage="$tmpdir/$package_base"
mkdir -p "$stage/bin" "$stage/ebpf" "$stage/docs"

install -m 0755 "$release_binary" "$stage/bin/apolysis"
install -m 0644 "$release_bpf_object" "$stage/ebpf/apolysis_observer.bpf.o"
install -m 0644 README.md "$stage/README.md"
install -m 0644 README.zh-CN.md "$stage/README.zh-CN.md"
install -m 0644 docs/jsonl-schema-v1.md "$stage/docs/jsonl-schema-v1.md"

python3 - "$stage/$manifest_name" "$release_version" "$release_target" "$package_name" "$stage/bin/apolysis" "$stage/ebpf/apolysis_observer.bpf.o" <<'PY'
import hashlib
import json
import sys
import time
from pathlib import Path

manifest_path = Path(sys.argv[1])
release_version = sys.argv[2]
release_target = sys.argv[3]
package_name = sys.argv[4]
binary_path = Path(sys.argv[5])
bpf_path = Path(sys.argv[6])

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def size(path: Path) -> int:
    return path.stat().st_size

manifest = {
    "schema_version": 1,
    "release_version": release_version,
    "target": release_target,
    "created_at_unix_ms": int(time.time() * 1000),
    "package": {
        "name": package_name,
        "format": "tar.gz",
        "sha256_file": f"{package_name}.sha256",
    },
    "artifacts": [
        {
            "path": "bin/apolysis",
            "kind": "cli_binary",
            "sha256": sha256(binary_path),
            "size_bytes": size(binary_path),
        },
        {
            "path": "ebpf/apolysis_observer.bpf.o",
            "kind": "core_bpf_object",
            "sha256": sha256(bpf_path),
            "size_bytes": size(bpf_path),
        },
    ],
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

tar -czf "$package_path" -C "$tmpdir" "$package_base"
sha256sum "$package_path" >"$checksum_path"
cp "$stage/$manifest_name" "$manifest_path"

printf 'apolysis-release-artifacts: package=%s sha256=%s\n' "$package_path" "$(sha256 "$package_path")"
printf 'apolysis-release-artifacts: manifest=%s\n' "$manifest_path"
printf 'apolysis-release-artifacts: checksum=%s\n' "$checksum_path"

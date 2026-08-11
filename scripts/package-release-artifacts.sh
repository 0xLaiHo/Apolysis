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
safe_component_pattern='^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
[[ "$release_version" =~ $safe_component_pattern ]] || fail "release version is not a safe bounded component"
[[ "$release_target" =~ $safe_component_pattern ]] || fail "release target is not a safe bounded component"
release_binary="${APOLYSIS_RELEASE_BINARY:-target/release/apolysis}"
release_daemon_binary="${APOLYSIS_RELEASE_DAEMON_BINARY:-target/release/apolysisd}"
release_health_binary="${APOLYSIS_RELEASE_HEALTH_BINARY:-target/release/apolysisd-health}"
release_bpf_object="${APOLYSIS_RELEASE_BPF_OBJECT:-target/ebpf/apolysis_observer.bpf.o}"
release_systemd_unit="${APOLYSIS_RELEASE_SYSTEMD_UNIT:-deploy/systemd/apolysisd.service}"
output_dir="${APOLYSIS_RELEASE_OUTPUT_DIR:-target/release-artifacts}"
package_base="apolysis-${release_version}-${release_target}"
package_name="${package_base}.tar.gz"
manifest_name="apolysis-release-manifest.json"
published_package_path="$output_dir/$package_name"
published_manifest_path="$output_dir/$manifest_name"
published_checksum_path="$published_package_path.sha256"

[[ -f "$release_binary" ]] || fail "missing CLI binary: $release_binary"
[[ -x "$release_binary" ]] || fail "CLI binary is not executable: $release_binary"
[[ -f "$release_daemon_binary" ]] || fail "missing daemon binary: $release_daemon_binary"
[[ -x "$release_daemon_binary" ]] || fail "daemon binary is not executable: $release_daemon_binary"
[[ -f "$release_health_binary" ]] || fail "missing health binary: $release_health_binary"
[[ -x "$release_health_binary" ]] || fail "health binary is not executable: $release_health_binary"
[[ -f "$release_bpf_object" ]] || fail "missing CO-RE BPF object: $release_bpf_object"
[[ -f "$release_systemd_unit" ]] || fail "missing systemd unit: $release_systemd_unit"

mkdir -p "$output_dir"
[[ -d "$output_dir" && ! -L "$output_dir" ]] || fail "release output is not a plain directory"
tmpdir="$(mktemp -d "$output_dir/.packaging.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

stage="$tmpdir/$package_base"
publish="$tmpdir/publish"
mkdir -p "$stage/bin" "$stage/ebpf" "$stage/systemd" "$stage/docs" "$publish"
chmod 0755 "$stage" "$stage/bin" "$stage/ebpf" "$stage/systemd" "$stage/docs"
package_path="$publish/$package_name"
manifest_path="$publish/$manifest_name"
checksum_path="$publish/$package_name.sha256"

install -m 0755 "$release_binary" "$stage/bin/apolysis"
install -m 0755 "$release_daemon_binary" "$stage/bin/apolysisd"
install -m 0755 "$release_health_binary" "$stage/bin/apolysisd-health"
install -m 0644 "$release_bpf_object" "$stage/ebpf/apolysis_observer.bpf.o"
install -m 0644 "$release_systemd_unit" "$stage/systemd/apolysisd.service"
install -m 0644 README.md "$stage/README.md"
install -m 0644 README.zh-CN.md "$stage/README.zh-CN.md"
install -m 0644 docs/design.md "$stage/docs/design.md"
install -m 0644 docs/design.zh-CN.md "$stage/docs/design.zh-CN.md"

python3 -I - "$stage/$manifest_name" "$release_version" "$release_target" "$package_name" "$stage" <<'PY'
import hashlib
import json
import sys
import time
from pathlib import Path

manifest_path = Path(sys.argv[1])
release_version = sys.argv[2]
release_target = sys.argv[3]
package_name = sys.argv[4]
stage = Path(sys.argv[5])

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def size(path: Path) -> int:
    return path.stat().st_size

artifact_contract = [
    ("bin/apolysis", "cli_binary", "0755", 128 * 1024 * 1024),
    ("bin/apolysisd", "daemon_binary", "0755", 256 * 1024 * 1024),
    ("bin/apolysisd-health", "health_binary", "0755", 64 * 1024 * 1024),
    ("ebpf/apolysis_observer.bpf.o", "core_bpf_object", "0644", 32 * 1024 * 1024),
    ("systemd/apolysisd.service", "systemd_unit", "0644", 1024 * 1024),
]
for relative_path, _, _, maximum_size in artifact_contract:
    assert size(stage / relative_path) <= maximum_size, f"oversized artifact: {relative_path}"
assert sum(size(stage / path) for path, _, _, _ in artifact_contract) <= 512 * 1024 * 1024

manifest = {
    "schema_version": 2,
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
            "path": relative_path,
            "kind": kind,
            "sha256": sha256(stage / relative_path),
            "size_bytes": size(stage / relative_path),
            "mode": mode,
        }
        for relative_path, kind, mode, _ in artifact_contract
    ],
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 0644 "$stage/$manifest_name"

tar --owner=0 --group=0 --numeric-owner -czf "$package_path" -C "$tmpdir" "$package_base"
(cd "$publish" && sha256sum "$package_name" >"$package_name.sha256")
install -m 0644 "$stage/$manifest_name" "$manifest_path"

python3 -I - \
    "$output_dir" \
    "$package_path" "$package_name" \
    "$manifest_path" "$manifest_name" \
    "$checksum_path" "$package_name.sha256" <<'PY'
import os
import stat
import sys
from pathlib import Path

output = Path(sys.argv[1])
pairs = [(Path(sys.argv[index]), sys.argv[index + 1]) for index in range(2, len(sys.argv), 2)]
metadata = os.lstat(output)
if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise RuntimeError("release output is not a plain directory")

created = []
directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    for source, name in pairs:
        destination = output / name
        os.link(source, destination, follow_symlinks=False)
        source_metadata = os.lstat(source)
        created.append((destination, source_metadata.st_dev, source_metadata.st_ino))
    os.fsync(directory_fd)
except BaseException:
    for destination, device, inode in reversed(created):
        try:
            destination_metadata = os.lstat(destination)
            if (destination_metadata.st_dev, destination_metadata.st_ino) == (device, inode):
                os.unlink(destination)
        except FileNotFoundError:
            pass
    os.fsync(directory_fd)
    raise
finally:
    os.close(directory_fd)
PY

printf 'apolysis-release-artifacts: package=%s sha256=%s\n' "$published_package_path" "$(sha256 "$published_package_path")"
printf 'apolysis-release-artifacts: manifest=%s\n' "$published_manifest_path"
printf 'apolysis-release-artifacts: checksum=%s\n' "$published_checksum_path"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

workflow=".github/workflows/release-artifacts.yml"
packager="scripts/package-release-artifacts.sh"
makefile="Makefile"

fail() {
    printf 'release artifact check failed: %s\n' "$*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing $1"
}

require_contains() {
    local file="$1"
    local needle="$2"
    grep -Fq -- "$needle" "$file" || fail "$file missing required text: $needle"
}

require_file "$workflow"
require_file "$packager"
require_contains "$makefile" "test-release-artifacts:"

for needle in \
    "name: Release Artifacts" \
    "workflow_dispatch:" \
    "tags:" \
    "'v*'" \
    "contents: write" \
    "clang" \
    "llvm" \
    "libbpf-dev" \
    "linux-tools-common" \
    "linux-tools-generic" \
    "hash -r" \
    "bpftool version" \
    "cargo build --release -p apolysis-cli --bin apolysis" \
    "APOLYSIS_REQUIRE_BPF=1 make build-ebpf" \
    "test -s \"\$APOLYSIS_RELEASE_BPF_OBJECT\"" \
    "./scripts/package-release-artifacts.sh" \
    "actions/upload-artifact@v4" \
    "target/release-artifacts/*" \
    "gh release upload"; do
    require_contains "$workflow" "$needle"
done

for needle in \
    "APOLYSIS_RELEASE_VERSION" \
    "APOLYSIS_RELEASE_TARGET" \
    "APOLYSIS_RELEASE_BINARY" \
    "APOLYSIS_RELEASE_BPF_OBJECT" \
    "apolysis_observer.bpf.o" \
    "apolysis-release-manifest.json" \
    "sha256sum" \
    "tar -czf"; do
    require_contains "$packager" "$needle"
done

tmpdir="$(mktemp -d "$repo_root/target/release-artifacts-test.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

fixture_bin="$tmpdir/apolysis"
fixture_bpf="$tmpdir/apolysis_observer.bpf.o"
output_dir="$tmpdir/out"

printf '#!/usr/bin/env bash\nprintf "apolysis fixture\\n"\n' >"$fixture_bin"
chmod +x "$fixture_bin"
printf 'fixture bpf object\n' >"$fixture_bpf"

APOLYSIS_RELEASE_VERSION="v0.2.0-test" \
APOLYSIS_RELEASE_TARGET="x86_64-unknown-linux-gnu" \
APOLYSIS_RELEASE_BINARY="$fixture_bin" \
APOLYSIS_RELEASE_BPF_OBJECT="$fixture_bpf" \
APOLYSIS_RELEASE_OUTPUT_DIR="$output_dir" \
    "$packager"

package="$output_dir/apolysis-v0.2.0-test-x86_64-unknown-linux-gnu.tar.gz"
manifest="$output_dir/apolysis-release-manifest.json"
checksum="$package.sha256"

[[ -s "$package" ]] || fail "missing release tarball"
[[ -s "$manifest" ]] || fail "missing release manifest"
[[ -s "$checksum" ]] || fail "missing release checksum"
grep -Eq "  $(basename "$package")$" "$checksum" \
    || fail "checksum file must reference the package basename, not a build-workspace path"

tar -tzf "$package" | grep -Fq -- "apolysis-v0.2.0-test-x86_64-unknown-linux-gnu/bin/apolysis" \
    || fail "tarball missing CLI binary"
tar -tzf "$package" | grep -Fq -- "apolysis-v0.2.0-test-x86_64-unknown-linux-gnu/ebpf/apolysis_observer.bpf.o" \
    || fail "tarball missing observer BPF object"
tar -tzf "$package" | grep -Fq -- "apolysis-v0.2.0-test-x86_64-unknown-linux-gnu/apolysis-release-manifest.json" \
    || fail "tarball missing embedded manifest"

python3 - "$manifest" "$package" "$fixture_bin" "$fixture_bpf" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
package_path = Path(sys.argv[2])
binary_path = Path(sys.argv[3])
bpf_path = Path(sys.argv[4])

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

assert manifest["schema_version"] == 1
assert manifest["release_version"] == "v0.2.0-test"
assert manifest["target"] == "x86_64-unknown-linux-gnu"
assert manifest["package"]["name"] == package_path.name
assert manifest["package"]["format"] == "tar.gz"
assert manifest["package"]["sha256_file"] == f"{package_path.name}.sha256"

artifacts = {artifact["path"]: artifact for artifact in manifest["artifacts"]}
assert artifacts["bin/apolysis"]["kind"] == "cli_binary"
assert artifacts["bin/apolysis"]["sha256"] == sha256(binary_path)
assert artifacts["ebpf/apolysis_observer.bpf.o"]["kind"] == "core_bpf_object"
assert artifacts["ebpf/apolysis_observer.bpf.o"]["sha256"] == sha256(bpf_path)
PY

(cd "$output_dir" && sha256sum -c "$(basename "$checksum")" >/dev/null)

printf 'release artifact check passed\n'

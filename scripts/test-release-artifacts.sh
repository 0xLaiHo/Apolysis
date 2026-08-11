#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if grep -Eq 'python(3)?[[:space:]]' "$repo_root/scripts/verify-release-artifacts.sh"; then
    printf 'release verifier orchestration must not contain inline Python\n' >&2
    exit 1
fi
[[ -x "$repo_root/target/release/apolysis-release-verifier" ]] || {
    printf 'missing compiled Rust release verifier\n' >&2
    exit 1
}
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/apolysis-release-test.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

inputs="$tmpdir/inputs"
output="$tmpdir/output"
extract="$tmpdir/extract"
mkdir -p "$inputs" "$output" "$extract"

python3 -I - "$inputs" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])

def elf(machine: int, elf_type: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = elf_type.to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[52:54] = (64).to_bytes(2, "little")
    if elf_type == 3:
        header[24:32] = (0x1000).to_bytes(8, "little")
        header[32:40] = (64).to_bytes(8, "little")
        header[54:56] = (56).to_bytes(2, "little")
        header[56:58] = (1).to_bytes(2, "little")
        program = bytearray(56)
        program[0:4] = (1).to_bytes(4, "little")
        program[4:8] = (5).to_bytes(4, "little")
        program[8:16] = (0).to_bytes(8, "little")
        program[16:24] = (0x1000).to_bytes(8, "little")
        program[32:40] = (120).to_bytes(8, "little")
        program[40:48] = (120).to_bytes(8, "little")
        return bytes(header) + bytes(program)
    raise ValueError("userspace fixture must be ET_DYN")

for name in ("apolysis", "apolysisd", "apolysisd-health"):
    (root / name).write_bytes(elf(62, 3))
PY
chmod 0755 "$inputs/apolysis" "$inputs/apolysisd" "$inputs/apolysisd-health"
install -m 0644 \
    "$repo_root/target/ebpf/apolysis_observer.bpf.o" \
    "$inputs/apolysis_observer.bpf.o"

unsafe_output="$tmpdir/unsafe-output"
mkdir -p "$unsafe_output/apolysis-escape"
if APOLYSIS_RELEASE_VERSION='escape/../../escaped-release' \
    APOLYSIS_RELEASE_TARGET='x86_64-unknown-linux-gnu' \
    APOLYSIS_RELEASE_BINARY="$inputs/apolysis" \
    APOLYSIS_RELEASE_DAEMON_BINARY="$inputs/apolysisd" \
    APOLYSIS_RELEASE_HEALTH_BINARY="$inputs/apolysisd-health" \
    APOLYSIS_RELEASE_BPF_OBJECT="$inputs/apolysis_observer.bpf.o" \
    APOLYSIS_RELEASE_SYSTEMD_UNIT="$repo_root/deploy/systemd/apolysisd.service" \
    APOLYSIS_RELEASE_OUTPUT_DIR="$unsafe_output" \
        "$repo_root/scripts/package-release-artifacts.sh" >/dev/null 2>&1; then
    printf 'unsafe release version unexpectedly packaged\n' >&2
    exit 1
fi
if compgen -G "$tmpdir/escaped-release-*" >/dev/null; then
    printf 'unsafe release version escaped the output directory\n' >&2
    exit 1
fi

linked_output="$tmpdir/linked-output"
linked_sentinel="$tmpdir/linked-sentinel"
mkdir -p "$linked_output"
printf 'must remain unchanged\n' >"$linked_sentinel"
ln -s "$linked_sentinel" "$linked_output/apolysis-release-manifest.json"
if APOLYSIS_RELEASE_VERSION='v0.0.0-linked-output-test' \
    APOLYSIS_RELEASE_TARGET='x86_64-unknown-linux-gnu' \
    APOLYSIS_RELEASE_BINARY="$inputs/apolysis" \
    APOLYSIS_RELEASE_DAEMON_BINARY="$inputs/apolysisd" \
    APOLYSIS_RELEASE_HEALTH_BINARY="$inputs/apolysisd-health" \
    APOLYSIS_RELEASE_BPF_OBJECT="$inputs/apolysis_observer.bpf.o" \
    APOLYSIS_RELEASE_SYSTEMD_UNIT="$repo_root/deploy/systemd/apolysisd.service" \
    APOLYSIS_RELEASE_OUTPUT_DIR="$linked_output" \
        "$repo_root/scripts/package-release-artifacts.sh" >/dev/null 2>&1; then
    printf 'linked release output unexpectedly packaged\n' >&2
    exit 1
fi
[[ "$(cat "$linked_sentinel")" == 'must remain unchanged' ]]
[[ ! -e "$linked_output/apolysis-v0.0.0-linked-output-test-x86_64-unknown-linux-gnu.tar.gz" ]]
[[ ! -e "$linked_output/apolysis-v0.0.0-linked-output-test-x86_64-unknown-linux-gnu.tar.gz.sha256" ]]

release_version="v0.0.0-packaging-test"
release_target="x86_64-unknown-linux-gnu"
package_base="apolysis-${release_version}-${release_target}"
package="$output/${package_base}.tar.gz"
manifest="$output/apolysis-release-manifest.json"

APOLYSIS_RELEASE_VERSION="$release_version" \
APOLYSIS_RELEASE_TARGET="$release_target" \
APOLYSIS_RELEASE_BINARY="$inputs/apolysis" \
APOLYSIS_RELEASE_DAEMON_BINARY="$inputs/apolysisd" \
APOLYSIS_RELEASE_HEALTH_BINARY="$inputs/apolysisd-health" \
APOLYSIS_RELEASE_BPF_OBJECT="$inputs/apolysis_observer.bpf.o" \
APOLYSIS_RELEASE_SYSTEMD_UNIT="$repo_root/deploy/systemd/apolysisd.service" \
APOLYSIS_RELEASE_OUTPUT_DIR="$output" \
    "$repo_root/scripts/package-release-artifacts.sh"

[[ -f "$package" ]] || {
    printf 'missing package: %s\n' "$package" >&2
    exit 1
}
[[ -f "$manifest" ]] || {
    printf 'missing release manifest: %s\n' "$manifest" >&2
    exit 1
}

(
    cd "$output"
    sha256sum --check "$(basename "$package").sha256"
)
tar -xzf "$package" -C "$extract"
"$repo_root/scripts/verify-release-artifacts.sh" "$output"

python3 -I - "$extract/$package_base" "$manifest" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

stage = Path(sys.argv[1])
published_manifest_path = Path(sys.argv[2])
archive_manifest_path = stage / "apolysis-release-manifest.json"

published_manifest = json.loads(published_manifest_path.read_text(encoding="utf-8"))
archive_manifest = json.loads(archive_manifest_path.read_text(encoding="utf-8"))
assert published_manifest == archive_manifest, "published and archived manifests differ"
assert archive_manifest["schema_version"] == 2, "release manifest must use schema version 2"

expected = {
    "bin/apolysis": ("cli_binary", "0755"),
    "bin/apolysisd": ("daemon_binary", "0755"),
    "bin/apolysisd-health": ("health_binary", "0755"),
    "ebpf/apolysis_observer.bpf.o": ("core_bpf_object", "0644"),
    "systemd/apolysisd.service": ("systemd_unit", "0644"),
}
artifacts = {entry["path"]: entry for entry in archive_manifest["artifacts"]}
assert set(artifacts) == set(expected), (
    f"manifest paths differ: expected {sorted(expected)}, got {sorted(artifacts)}"
)

for relative_path, (kind, mode) in expected.items():
    artifact = artifacts[relative_path]
    installed_path = stage / relative_path
    assert installed_path.is_file(), f"missing packaged artifact: {relative_path}"
    assert artifact["kind"] == kind, f"wrong kind for {relative_path}"
    assert artifact["mode"] == mode, f"wrong manifest mode for {relative_path}"
    actual_mode = f"{stat.S_IMODE(installed_path.stat().st_mode):04o}"
    assert actual_mode == mode, f"wrong archive mode for {relative_path}: {actual_mode}"
    payload = installed_path.read_bytes()
    assert artifact["sha256"] == hashlib.sha256(payload).hexdigest(), (
        f"wrong hash for {relative_path}"
    )
    assert artifact["size_bytes"] == len(payload), f"wrong size for {relative_path}"

unit = (stage / "systemd/apolysisd.service").read_text(encoding="utf-8")
assert "UMask=0027" in unit, "systemd unit must default state files to owner/group read only"
assert "KillSignal=SIGTERM" in unit, "systemd unit must request graceful shutdown"
assert "TimeoutStopSec=15s" in unit, "systemd stop must have a bounded deadline"
PY

python3 -I - "$output" "$tmpdir" <<'PY'
import copy
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

source = Path(sys.argv[1])
workspace = Path(sys.argv[2])
manifest = json.loads((source / "apolysis-release-manifest.json").read_text(encoding="utf-8"))
package_name = manifest["package"]["name"]
package_base = package_name.removesuffix(".tar.gz")


def read_members(package_path):
    members = []
    with tarfile.open(package_path, mode="r:gz") as archive:
        for member in archive:
            stream = archive.extractfile(member) if member.isfile() else None
            members.append((copy.copy(member), stream.read() if stream is not None else None))
    return members


def publish_case(name, transform):
    destination = workspace / name
    shutil.copytree(source, destination)
    package_path = destination / package_name
    members, published_manifest = transform(read_members(package_path), copy.deepcopy(manifest))
    temporary = destination / "rewritten.tar.gz"
    with tarfile.open(temporary, mode="w:gz") as archive:
        for member, data in members:
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    os.replace(temporary, package_path)
    if published_manifest is not None:
        (destination / "apolysis-release-manifest.json").write_bytes(published_manifest)
    digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
    (destination / f"{package_name}.sha256").write_text(
        f"{digest}  {package_name}\n",
        encoding="utf-8",
    )


def replace_archived_manifest(members, manifest_bytes):
    manifest_path = f"{package_base}/apolysis-release-manifest.json"
    replaced = False
    for index, (member, data) in enumerate(members):
        if member.name == manifest_path:
            member.size = len(manifest_bytes)
            members[index] = (member, manifest_bytes)
            replaced = True
            break
    assert replaced
    return members


def serialized_manifest(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def add_canonical_duplicate(members, published_manifest):
    evil = bytearray(64)
    evil[:4] = b"\x7fELF"
    member = tarfile.TarInfo(f"{package_base}/bin//apolysis")
    member.size = len(evil)
    member.mode = 0o755
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    members.append((member, bytes(evil)))
    return members, None


def add_raw_duplicate(members, published_manifest):
    for member, data in members:
        if member.name == f"{package_base}/README.md":
            members.append((copy.copy(member), data))
            break
    return members, None


def add_traversal(members, published_manifest):
    member = tarfile.TarInfo(f"{package_base}/docs/../escaped")
    member.size = 1
    member.mode = 0o644
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    members.append((member, b"x"))
    return members, None


def replace_readme_with_symlink(members, published_manifest):
    target = f"{package_base}/README.md"
    for index, (member, _) in enumerate(members):
        if member.name == target:
            member.type = tarfile.SYMTYPE
            member.linkname = "README.zh-CN.md"
            member.size = 0
            members[index] = (member, None)
            break
    return members, None


def replace_readme_with_hardlink(members, published_manifest):
    target = f"{package_base}/README.md"
    for index, (member, _) in enumerate(members):
        if member.name == target:
            member.type = tarfile.LNKTYPE
            member.linkname = f"{package_base}/README.zh-CN.md"
            member.size = 0
            members[index] = (member, None)
            break
    return members, None


def replace_readme_with_sparse_member(members, published_manifest):
    target = f"{package_base}/README.md"
    for index, (member, _) in enumerate(members):
        if member.name == target:
            member.type = tarfile.GNUTYPE_SPARSE
            member.size = 0
            members[index] = (member, None)
            break
    return members, None


def add_pax_metadata(members, published_manifest):
    target = f"{package_base}/README.md"
    for member, _ in members:
        if member.name == target:
            member.pax_headers = {"SCHILY.xattr.user.apolysis-test": "present"}
            break
    return members, None


def change_artifact_mode(members, published_manifest):
    target = f"{package_base}/bin/apolysis"
    for member, _ in members:
        if member.name == target:
            member.mode = 0o775
            break
    return members, None


def change_artifact_without_manifest(members, published_manifest):
    target = f"{package_base}/bin/apolysis"
    for index, (member, data) in enumerate(members):
        if member.name == target:
            changed = bytes((data[0] ^ 0xFF,)) + data[1:]
            members[index] = (member, changed)
            break
    return members, None


def truncate_userspace_elf(members, published_manifest):
    target = f"{package_base}/bin/apolysis"
    malformed = None
    for index, (member, data) in enumerate(members):
        if member.name == target:
            malformed = data[:64]
            member.size = len(malformed)
            members[index] = (member, malformed)
            break
    assert malformed is not None
    for artifact in published_manifest["artifacts"]:
        if artifact["path"] == "bin/apolysis":
            artifact["sha256"] = hashlib.sha256(malformed).hexdigest()
            artifact["size_bytes"] = len(malformed)
    manifest_bytes = serialized_manifest(published_manifest)
    return replace_archived_manifest(members, manifest_bytes), manifest_bytes


def duplicate_manifest_key(members, published_manifest):
    manifest_bytes = serialized_manifest(published_manifest)
    manifest_bytes = manifest_bytes.replace(
        b"{\n", b'{\n  "schema_version": 2,\n', 1
    )
    return replace_archived_manifest(members, manifest_bytes), manifest_bytes


def duplicate_nested_manifest_key(members, published_manifest):
    manifest_bytes = serialized_manifest(published_manifest)
    manifest_bytes = manifest_bytes.replace(
        b'    "format": "tar.gz",\n',
        b'    "format": "tar.gz",\n    "format": "tar.gz",\n',
        1,
    )
    return replace_archived_manifest(members, manifest_bytes), manifest_bytes


def add_root_lifecycle_directive(members, published_manifest):
    unit_path = f"{package_base}/systemd/apolysisd.service"
    manifest_path = f"{package_base}/apolysis-release-manifest.json"
    transformed = []
    unit_bytes = None
    for member, data in members:
        if member.name == unit_path:
            unit_bytes = data.replace(b"[Service]\n", b"[Service]\nExecStartPre=/bin/true\n", 1)
            member.size = len(unit_bytes)
            data = unit_bytes
        transformed.append((member, data))
    assert unit_bytes is not None
    for artifact in published_manifest["artifacts"]:
        if artifact["path"] == "systemd/apolysisd.service":
            artifact["sha256"] = hashlib.sha256(unit_bytes).hexdigest()
            artifact["size_bytes"] = len(unit_bytes)
    manifest_bytes = serialized_manifest(published_manifest)
    return replace_archived_manifest(transformed, manifest_bytes), manifest_bytes


publish_case("canonical-duplicate", add_canonical_duplicate)
publish_case("raw-duplicate", add_raw_duplicate)
publish_case("path-traversal", add_traversal)
publish_case("linked-member", replace_readme_with_symlink)
publish_case("hard-linked-member", replace_readme_with_hardlink)
publish_case("sparse-member", replace_readme_with_sparse_member)
publish_case("pax-metadata", add_pax_metadata)
publish_case("wrong-mode", change_artifact_mode)
publish_case("artifact-mismatch", change_artifact_without_manifest)
publish_case("malformed-elf", truncate_userspace_elf)
publish_case("duplicate-json-key", duplicate_manifest_key)
publish_case("duplicate-nested-json-key", duplicate_nested_manifest_key)
publish_case("extra-systemd-lifecycle", add_root_lifecycle_directive)

trailing = workspace / "trailing-gzip-data"
shutil.copytree(source, trailing)
trailing_package = trailing / package_name
with trailing_package.open("ab") as package_file:
    package_file.write(b"TRAILING")
trailing_digest = hashlib.sha256(trailing_package.read_bytes()).hexdigest()
(trailing / f"{package_name}.sha256").write_text(
    f"{trailing_digest}  {package_name}\n",
    encoding="utf-8",
)

concatenated = workspace / "concatenated-gzip-member"
shutil.copytree(source, concatenated)
concatenated_package = concatenated / package_name
with concatenated_package.open("ab") as package_file:
    package_file.write(gzip.compress(b""))
concatenated_digest = hashlib.sha256(concatenated_package.read_bytes()).hexdigest()
(concatenated / f"{package_name}.sha256").write_text(
    f"{concatenated_digest}  {package_name}\n",
    encoding="utf-8",
)

nonzero_padding = workspace / "nonzero-member-padding"
shutil.copytree(source, nonzero_padding)
nonzero_padding_package = nonzero_padding / package_name
archive_bytes = bytearray(gzip.decompress(nonzero_padding_package.read_bytes()))
offset = 0
padding_changed = False
while offset + 512 <= len(archive_bytes):
    header = archive_bytes[offset:offset + 512]
    if not any(header):
        break
    raw_size = bytes(header[124:136]).rstrip(b"\0 ").lstrip(b" ")
    member_size = int(raw_size or b"0", 8)
    content_end = offset + 512 + member_size
    next_header = (content_end + 511) // 512 * 512
    if next_header > content_end:
        archive_bytes[content_end] = 0x41
        padding_changed = True
        break
    offset = next_header
assert padding_changed, "fixture archive has no member padding to corrupt"
nonzero_padding_package.write_bytes(gzip.compress(bytes(archive_bytes), mtime=0))
nonzero_padding_digest = hashlib.sha256(nonzero_padding_package.read_bytes()).hexdigest()
(nonzero_padding / f"{package_name}.sha256").write_text(
    f"{nonzero_padding_digest}  {package_name}\n",
    encoding="utf-8",
)

bad_checksum = workspace / "checksum-mismatch"
shutil.copytree(source, bad_checksum)
(bad_checksum / f"{package_name}.sha256").write_text(
    f"{'0' * 64}  {package_name}\n",
    encoding="utf-8",
)
PY

for hostile_case in \
    canonical-duplicate raw-duplicate path-traversal linked-member hard-linked-member \
    sparse-member pax-metadata \
    wrong-mode artifact-mismatch malformed-elf duplicate-json-key \
    duplicate-nested-json-key \
    extra-systemd-lifecycle trailing-gzip-data concatenated-gzip-member \
    nonzero-member-padding \
    checksum-mismatch; do
    if "$repo_root/scripts/verify-release-artifacts.sh" "$tmpdir/$hostile_case" >/dev/null 2>&1; then
        printf 'hostile release case unexpectedly verified: %s\n' "$hostile_case" >&2
        exit 1
    fi
done

printf 'release artifact packaging test: PASS\n'

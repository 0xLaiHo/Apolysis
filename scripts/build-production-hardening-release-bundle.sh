#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stamp="$(date -u +%Y%m%d%H%M%S)-$$"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_RELEASE_OUTPUT_DIR:-$repo_root/target/production-hardening-release-bundle/$stamp}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
staging_dir="$output_dir/staging"
image_context="$output_dir/image-context"
image="${APOLYSIS_PRODUCTION_HARDENING_RELEASE_IMAGE:-localhost/apolysisd:production-hardening-release-$stamp}"
payload_tar="$output_dir/apolysis-production-hardening-release-payload.tar.gz"
image_tar="$output_dir/apolysis-production-hardening-apolysisd-image.tar"
manifest="$output_dir/apolysis-production-hardening-release-manifest.json"
sbom="$output_dir/apolysis-production-hardening-sbom.cdx.json"
provenance="$output_dir/apolysis-production-hardening-provenance.intoto.json"
vulnerability_scan="$output_dir/apolysis-production-hardening-vulnerability-scan.json"
checksums="$output_dir/apolysis-production-hardening-release-checksums.sha256"
public_key="$output_dir/apolysis-production-hardening-release.pub"
manifest_bundle="$output_dir/apolysis-production-hardening-release-manifest.sigstore.json"
provenance_bundle="$output_dir/apolysis-production-hardening-provenance.sigstore.json"
trivy_cache_dir="${APOLYSIS_PRODUCTION_HARDENING_TRIVY_CACHE_DIR:-$repo_root/target/trivy-cache}"
signing_key="${APOLYSIS_PRODUCTION_HARDENING_RELEASE_SIGNING_KEY:-}"
signing_pub="${APOLYSIS_PRODUCTION_HARDENING_RELEASE_SIGNING_PUB:-}"
key_mode="external"
tmp_key_dir=""
remove_image="${APOLYSIS_PRODUCTION_HARDENING_REMOVE_IMAGE:-1}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

cleanup() {
    if [[ -n "$tmp_key_dir" ]]; then
        rm -rf "$tmp_key_dir"
    fi
    if [[ "$remove_image" == "1" ]]; then
        docker image rm "$image" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for command in cargo cosign crictl curl docker git jq python3 sha256sum syft tar trivy; do
    require_command "$command"
done

cd "$repo_root"
mkdir -p "$output_dir" "$staging_dir" "$image_context" "$trivy_cache_dir"

cargo build --release \
    -p apolysis-daemon --bin apolysisd --bin apolysisd-health \
    -p apolysis-cli --bin apolysis \
    -p apolysis-validation --bin apolysis-validate-host
./scripts/build-ebpf.sh

test -x "$repo_root/target/release/apolysisd"
test -x "$repo_root/target/release/apolysisd-health"
test -x "$repo_root/target/release/apolysis"
test -x "$repo_root/target/release/apolysis-validate-host"
test -s "$repo_root/target/ebpf/apolysis_observer.bpf.o"

rm -rf "$staging_dir" "$image_context"
mkdir -p \
    "$staging_dir/bin" \
    "$staging_dir/lib/apolysis" \
    "$staging_dir/deploy/container" \
    "$staging_dir/deploy/helm" \
    "$staging_dir/deploy/kubernetes" \
    "$staging_dir/licenses" \
    "$staging_dir/source/crates" \
    "$image_context"

install -m 0755 "$repo_root/target/release/apolysisd" "$staging_dir/bin/apolysisd"
install -m 0755 "$repo_root/target/release/apolysisd-health" "$staging_dir/bin/apolysisd-health"
install -m 0755 "$repo_root/target/release/apolysis" "$staging_dir/bin/apolysis"
install -m 0755 "$repo_root/target/release/apolysis-validate-host" "$staging_dir/bin/apolysis-validate-host"
install -m 0644 "$repo_root/target/ebpf/apolysis_observer.bpf.o" "$staging_dir/lib/apolysis/apolysis_observer.bpf.o"
if [[ -s "$repo_root/target/ebpf/apolysis_bpf_lsm_file_read.bpf.o" ]]; then
    install -m 0644 "$repo_root/target/ebpf/apolysis_bpf_lsm_file_read.bpf.o" \
        "$staging_dir/lib/apolysis/apolysis_bpf_lsm_file_read.bpf.o"
fi
install -m 0644 "$repo_root/deploy/container/apolysisd.Dockerfile" \
    "$staging_dir/deploy/container/apolysisd.Dockerfile"
install -m 0644 "$repo_root/deploy/kubernetes/apolysisd-production-baseline.yaml" \
    "$staging_dir/deploy/kubernetes/apolysisd-production-baseline.yaml"
cp -R "$repo_root/deploy/helm/apolysis" "$staging_dir/deploy/helm/apolysis"
find "$staging_dir/deploy/helm/apolysis" -type d -exec chmod 0755 {} +
find "$staging_dir/deploy/helm/apolysis" -type f -exec chmod 0644 {} +
install -m 0644 "$repo_root/LICENSE" "$staging_dir/licenses/LICENSE"
install -m 0644 "$repo_root/NOTICE" "$staging_dir/licenses/NOTICE"
install -m 0644 "$repo_root/Cargo.lock" "$staging_dir/source/Cargo.lock"
install -m 0644 "$repo_root/Cargo.toml" "$staging_dir/source/Cargo.toml"
find "$repo_root/crates" -maxdepth 2 -name Cargo.toml -print0 |
    while IFS= read -r -d '' cargo_toml; do
        rel="${cargo_toml#"$repo_root/crates/"}"
        install -D -m 0644 "$cargo_toml" "$staging_dir/source/crates/$rel"
    done

cp "$repo_root/target/release/apolysisd" "$image_context/apolysisd"
cp "$repo_root/target/release/apolysisd-health" "$image_context/apolysisd-health"
host_crictl_source="$(readlink -f "$(command -v crictl)")"
if [[ "$(basename "$host_crictl_source")" == "k3s" ]]; then
    crictl_version="${APOLYSIS_PRODUCTION_HARDENING_CRICTL_VERSION:-v1.35.0}"
    case "$(uname -m)" in
        x86_64) crictl_arch=amd64 ;;
        aarch64) crictl_arch=arm64 ;;
        armv7l) crictl_arch=arm ;;
        *)
            echo "apolysis-production-hardening: unsupported crictl download architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
    crictl_archive="$output_dir/crictl-${crictl_version}-linux-${crictl_arch}.tar.gz"
    crictl_extract="$output_dir/crictl-${crictl_version}"
    mkdir -p "$crictl_extract"
    curl -fsSL \
        -o "$crictl_archive" \
        "https://github.com/kubernetes-sigs/cri-tools/releases/download/${crictl_version}/crictl-${crictl_version}-linux-${crictl_arch}.tar.gz"
    tar -xzf "$crictl_archive" -C "$crictl_extract" crictl
    cp "$crictl_extract/crictl" "$image_context/crictl"
else
    cp "$host_crictl_source" "$image_context/crictl"
fi
chmod 0755 "$image_context/crictl"
cp "$repo_root/target/ebpf/apolysis_observer.bpf.o" "$image_context/apolysis_observer.bpf.o"

docker build \
    --label "org.opencontainers.image.source=https://github.com/0xLaiHo/Apolysis" \
    --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
    --label "org.opencontainers.image.title=apolysisd" \
    -f "$repo_root/deploy/container/apolysisd.Dockerfile" \
    -t "$image" \
    "$image_context"
docker save "$image" -o "$image_tar"
docker image inspect "$image" >"$output_dir/apolysis-production-hardening-image-inspect.json"

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -cf - -C "$staging_dir" . | gzip -n >"$payload_tar"

syft scan dir:"$staging_dir" -q -o cyclonedx-json="$sbom"
TRIVY_CACHE_DIR="$trivy_cache_dir" trivy fs \
    --quiet \
    --format json \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --output "$vulnerability_scan" \
    "$staging_dir"

if [[ -z "$signing_key" ]]; then
    key_mode="ephemeral-local-validation"
    tmp_key_dir="$(mktemp -d "$output_dir/signing-key.XXXXXX")"
    COSIGN_PASSWORD="${COSIGN_PASSWORD:-apolysis-production-hardening-local-validation}" \
        cosign generate-key-pair --output-key-prefix "$tmp_key_dir/apolysis-production-hardening-release" >/dev/null
    signing_key="$tmp_key_dir/apolysis-production-hardening-release.key"
    signing_pub="$tmp_key_dir/apolysis-production-hardening-release.pub"
else
    if [[ -z "$signing_pub" ]]; then
        echo "apolysis-production-hardening: APOLYSIS_PRODUCTION_HARDENING_RELEASE_SIGNING_PUB is required with external signing key" >&2
        exit 1
    fi
fi
install -m 0644 "$signing_pub" "$public_key"

python3 - "$repo_root" "$output_dir" "$staging_dir" "$image" "$key_mode" "$provenance" <<'PY'
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
staging_dir = Path(sys.argv[3])
image = sys.argv[4]
key_mode = sys.argv[5]
provenance = Path(sys.argv[6])

subjects = [
    "apolysis-production-hardening-release-payload.tar.gz",
    "apolysis-production-hardening-apolysisd-image.tar",
    "apolysis-production-hardening-sbom.cdx.json",
    "apolysis-production-hardening-vulnerability-scan.json",
]


def sha256(path: Path) -> str:
    result = subprocess.check_output(["sha256sum", str(path)], text=True)
    return result.split()[0]


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root, text=True).strip()


def maybe_json(command: list[str]) -> object:
    try:
        raw = subprocess.check_output(command, cwd=repo_root, text=True, stderr=subprocess.DEVNULL)
        return json.loads(raw)
    except Exception:
        return None


def material(path: str) -> dict[str, object]:
    full = repo_root / path
    return {
        "uri": f"git+file://{repo_root}#{path}",
        "digest": {"sha256": sha256(full)},
        "mediaType": "text/plain",
    }


statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
        {
            "name": name,
            "digest": {"sha256": sha256(output_dir / name)},
        }
        for name in subjects
    ],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://apolysis.dev/buildtypes/production-hardening-release-bundle/v1",
            "externalParameters": {
                "phase": "production-hardening.release-manifest",
                "image": image,
                "stagingSource": str(staging_dir),
            },
            "internalParameters": {
                "gitDirty": bool(git("status", "--porcelain")),
                "signingKeyMode": key_mode,
            },
            "resolvedDependencies": [
                material("Cargo.lock"),
                material("Cargo.toml"),
                material("deploy/container/apolysisd.Dockerfile"),
                material("deploy/helm/apolysis/Chart.yaml"),
                material("deploy/helm/apolysis/values.yaml"),
                material("deploy/kubernetes/apolysisd-production-baseline.yaml"),
                material("scripts/build-production-hardening-release-bundle.sh"),
                material("scripts/test-production-hardening-supply-chain.sh"),
            ],
        },
        "runDetails": {
            "builder": {"id": "apolysis-local-production-hardening-supply-chain-gate"},
            "metadata": {
                "invocationId": os.environ.get("APOLYSIS_PRODUCTION_HARDENING_RELEASE_INVOCATION_ID", ""),
                "startedOn": datetime.now(timezone.utc).isoformat(),
                "gitCommit": git("rev-parse", "HEAD"),
            },
            "byproducts": [
                {
                    "name": "cosign",
                    "version": maybe_json(["cosign", "version", "--json"]),
                },
                {
                    "name": "syft",
                    "version": maybe_json(["syft", "version", "-o", "json"]),
                },
                {
                    "name": "trivy",
                    "version": maybe_json(["trivy", "--version", "--format", "json"]),
                },
            ],
        },
    },
}

provenance.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 - "$repo_root" "$output_dir" "$staging_dir" "$image" "$key_mode" "$manifest" <<'PY'
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
staging_dir = Path(sys.argv[3])
image = sys.argv[4]
key_mode = sys.argv[5]
manifest = Path(sys.argv[6])

artifact_names = [
    "apolysis-production-hardening-release-payload.tar.gz",
    "apolysis-production-hardening-apolysisd-image.tar",
    "apolysis-production-hardening-sbom.cdx.json",
    "apolysis-production-hardening-vulnerability-scan.json",
    "apolysis-production-hardening-provenance.intoto.json",
    "apolysis-production-hardening-image-inspect.json",
]


def run(command: list[str]) -> str:
    return subprocess.check_output(command, cwd=repo_root, text=True).strip()


def sha256(path: Path) -> str:
    return subprocess.check_output(["sha256sum", str(path)], text=True).split()[0]


def tool_json(command: list[str]) -> object:
    try:
        return json.loads(subprocess.check_output(command, cwd=repo_root, text=True, stderr=subprocess.DEVNULL))
    except Exception:
        return None


def file_entry(path: Path, base: Path) -> dict[str, object]:
    rel = path.relative_to(base).as_posix()
    stat = path.stat()
    return {
        "path": rel,
        "sha256": sha256(path),
        "size": stat.st_size,
        "mode": oct(stat.st_mode & 0o777),
    }


staged_files = [
    file_entry(path, staging_dir)
    for path in sorted(staging_dir.rglob("*"))
    if path.is_file()
]

manifest_data = {
    "schema": "apolysis.dev/production-hardening-release-manifest/v1",
    "schemaVersion": 1,
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "phase": "production-hardening.release-manifest",
    "git": {
        "commit": run(["git", "rev-parse", "HEAD"]),
        "dirty": bool(run(["git", "status", "--porcelain"])),
        "branch": run(["git", "branch", "--show-current"]),
    },
    "image": {
        "tag": image,
        "archive": "apolysis-production-hardening-apolysisd-image.tar",
        "archiveSha256": sha256(output_dir / "apolysis-production-hardening-apolysisd-image.tar"),
    },
    "signing": {
        "keyMode": key_mode,
        "publicKey": "apolysis-production-hardening-release.pub",
        "manifestBundle": "apolysis-production-hardening-release-manifest.sigstore.json",
        "provenanceBundle": "apolysis-production-hardening-provenance.sigstore.json",
    },
    "tools": {
        "cosign": tool_json(["cosign", "version", "--json"]),
        "syft": tool_json(["syft", "version", "-o", "json"]),
        "trivy": tool_json(["trivy", "--version", "--format", "json"]),
        "rustc": run(["rustc", "--version"]),
        "cargo": run(["cargo", "--version"]),
    },
    "files": [
        {
            "path": name,
            "sha256": sha256(output_dir / name),
            "size": (output_dir / name).stat().st_size,
            "mode": oct((output_dir / name).stat().st_mode & 0o777),
        }
        for name in artifact_names
    ],
    "stagingFiles": staged_files,
    "vulnerabilityPolicy": {
        "scanner": "trivy fs",
        "severity": ["HIGH", "CRITICAL"],
        "maxHighCritical": int(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_MAX_HIGH_CRITICAL_VULNS", "0")),
    },
}

manifest.write_text(json.dumps(manifest_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

COSIGN_PASSWORD="${COSIGN_PASSWORD:-apolysis-production-hardening-local-validation}" \
    cosign sign-blob --yes --key "$signing_key" --bundle "$manifest_bundle" "$manifest" >/dev/null
COSIGN_PASSWORD="${COSIGN_PASSWORD:-apolysis-production-hardening-local-validation}" \
    cosign sign-blob --yes --key "$signing_key" --bundle "$provenance_bundle" "$provenance" >/dev/null

(
    cd "$output_dir"
    sha256sum \
        apolysis-production-hardening-release-payload.tar.gz \
        apolysis-production-hardening-apolysisd-image.tar \
        apolysis-production-hardening-sbom.cdx.json \
        apolysis-production-hardening-vulnerability-scan.json \
        apolysis-production-hardening-provenance.intoto.json \
        apolysis-production-hardening-release-manifest.json \
        apolysis-production-hardening-release.pub \
        apolysis-production-hardening-release-manifest.sigstore.json \
        apolysis-production-hardening-provenance.sigstore.json \
        >"$checksums"
)

printf 'apolysis-production-hardening: release supply-chain bundle written to %s\n' "$output_dir"

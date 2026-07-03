#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-store --test hash_chain offline_verification
cargo test -p apolysis-cli --test verify

for term in \
  'apolysis verify hash-chain' \
  'HashChainStore::verify' \
  'record_count' \
  'last_sequence' \
  'valid_bytes'; do
  grep -Fq -- "$term" README.md README.zh-CN.md docs/hash-chain-verification.md || {
    echo "offline hash-chain verification docs must mention: $term" >&2
    exit 1
  }
done

echo "offline hash-chain verification gate passed"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

: "${APOLYSIS_CODEX_DEMO_HOME:?APOLYSIS_CODEX_DEMO_HOME is required}"

cargo test -p apolysis-cli --test intent
python3 "$repo_root/scripts/read-demo-credential.py"

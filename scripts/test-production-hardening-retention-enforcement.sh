#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-accountability --test intent -- retention_purge
cargo test -p apolysis-accountability --test session -- retention_purge_is_tenant_scoped_and_only_removes_inactive_expired_sessions
cargo test -p apolysis-daemon --test socket_api -- retention_purge_request_dry_runs_then_removes_only_matching_tenant_state

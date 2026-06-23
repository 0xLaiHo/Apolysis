#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-accountability --test intent -- tenant
cargo test -p apolysis-accountability --test session -- lists_sessions_by_tenant_and_retention_tier
cargo test -p apolysis-daemon --test socket_api -- tenant_scoped_queries_and_session_lists_do_not_cross_tenant_boundaries

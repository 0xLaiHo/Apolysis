#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'community surface check failed: %s\n' "$*" >&2
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

for file in \
    CONTRIBUTING.md \
    SECURITY.md \
    docs/threat-model.md \
    docs/starter-issues.md \
    .github/ISSUE_TEMPLATE/config.yml \
    .github/ISSUE_TEMPLATE/bug_report.yml \
    .github/ISSUE_TEMPLATE/feature_request.yml \
    .github/ISSUE_TEMPLATE/starter_issue.yml \
    .github/pull_request_template.md; do
    require_file "$file"
done

for needle in \
    "Development Workflow" \
    "Do not develop directly on main" \
    "Verification" \
    "Privacy And Captured Data" \
    "make test" \
    "make lint"; do
    require_contains CONTRIBUTING.md "$needle"
done

for needle in \
    "Supported Versions" \
    "Reporting A Vulnerability" \
    "Do Not Include Secrets" \
    "Scope" \
    "Apolysis records evidence"; do
    require_contains SECURITY.md "$needle"
done

for needle in \
    "# Apolysis Threat Model" \
    "Not A Sandbox" \
    "Trust Boundaries" \
    "Primary Assets" \
    "In Scope Threats" \
    "Out Of Scope"; do
    require_contains docs/threat-model.md "$needle"
done

for needle in \
    "good first issue" \
    "help wanted" \
    "Starter Issue Set" \
    "Runtime evidence fixtures" \
    "Release artifact verification" \
    "Timeline shipping documentation"; do
    require_contains docs/starter-issues.md "$needle"
done

for template in bug_report feature_request starter_issue; do
    require_contains ".github/ISSUE_TEMPLATE/${template}.yml" "name:"
    require_contains ".github/ISSUE_TEMPLATE/${template}.yml" "description:"
    require_contains ".github/ISSUE_TEMPLATE/${template}.yml" "labels:"
    require_contains ".github/ISSUE_TEMPLATE/${template}.yml" "body:"
done

require_contains .github/ISSUE_TEMPLATE/starter_issue.yml "good first issue"
require_contains .github/ISSUE_TEMPLATE/starter_issue.yml "help wanted"
require_contains .github/pull_request_template.md "Verification"
require_contains .github/pull_request_template.md "Privacy And Secret Checks"
require_contains .github/pull_request_template.md "Privileged Or Live Assumptions"

for readme in README.md README.zh-CN.md; do
    require_contains "$readme" "CONTRIBUTING.md"
    require_contains "$readme" "SECURITY.md"
    require_contains "$readme" "docs/threat-model.md"
    require_contains "$readme" "docs/starter-issues.md"
    require_contains "$readme" "actions/workflows/release-validation.yml/badge.svg"
    require_contains "$readme" "img.shields.io/github/v/release/0xLaiHo/Apolysis"
    require_contains "$readme" "img.shields.io/github/license/0xLaiHo/Apolysis"
    require_contains "$readme" "Codex"
done

require_contains README.md "30-second summary"
require_contains README.md "Demo status"
require_contains README.md "environment-owned flight recorder"
require_contains README.md "host-side evidence"
require_contains README.zh-CN.md "30 秒摘要"
require_contains README.zh-CN.md "Demo 状态"
require_contains README.zh-CN.md "环境侧飞行记录仪"
require_contains README.zh-CN.md "主机侧证据"

printf 'community surface check passed\n'

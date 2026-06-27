#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/../.." && pwd)"
ROADMAP_EN="$WORKSPACE_ROOT/research/docs/production-readiness-roadmap.md"
ROADMAP_ZH="$WORKSPACE_ROOT/research/docs/production-readiness-roadmap.zh-CN.md"
PROGRESS_DOC="$WORKSPACE_ROOT/research/docs/progress.md"
HANDOFF_DOC="$REPO_ROOT/docs/release-validation-handoff.md"
CI_WORKFLOW="$REPO_ROOT/.github/workflows/release-validation.yml"
MAKEFILE="$REPO_ROOT/Makefile"

fail() {
  printf 'release validation handoff check failed: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing required file: $path"
}

require_contains() {
  local path="$1"
  local needle="$2"
  grep -Fq "$needle" "$path" || fail "$path must contain: $needle"
}

require_not_contains() {
  local path="$1"
  local needle="$2"
  if grep -Fq "$needle" "$path"; then
    fail "$path still contains stale text: $needle"
  fi
}

require_file "$HANDOFF_DOC"
require_file "$CI_WORKFLOW"
require_file "$MAKEFILE"

if [[ -f "$ROADMAP_EN" && -f "$ROADMAP_ZH" && -f "$PROGRESS_DOC" ]]; then
  require_contains "$ROADMAP_EN" "Status: **complete as of 2026-06-18**."
  require_contains "$ROADMAP_ZH" "状态：**已于 2026-06-18 完成**。"
  require_not_contains "$ROADMAP_EN" "Status: implementation in progress."
  require_not_contains "$ROADMAP_ZH" "状态：正在实现。"
  require_not_contains "$ROADMAP_EN" "Remaining before F2 completion:"
  require_not_contains "$ROADMAP_ZH" "F2 完成前的剩余工作："

  require_contains "$ROADMAP_EN" "## Next Milestone: Release Validation Operationalization"
  require_contains "$ROADMAP_ZH" "## 下一里程碑：发布验证可运营化"
  require_contains "$ROADMAP_EN" "## Historical 30/60/90-Day Completion Map"
  require_contains "$ROADMAP_ZH" "## 历史 30/60/90 天完成映射"
  require_contains "$ROADMAP_EN" "None. F6 Regulated Release and Evidence Integrity is complete for this"
  require_contains "$ROADMAP_ZH" "无。F6 Regulated Release and Evidence Integrity 在本里程碑已完成。"

  require_contains "$PROGRESS_DOC" "## Next Milestone"
  require_contains "$PROGRESS_DOC" "Release Validation Operationalization"
  require_not_contains "$PROGRESS_DOC" "Start F2 Accountability Beta planning from the completed F1 evidence:"
fi

require_contains "$HANDOFF_DOC" "## Operator Preflight"
require_contains "$HANDOFF_DOC" "## Required Inputs"
require_contains "$HANDOFF_DOC" "## Cleanup and Retention Checks"
require_contains "$HANDOFF_DOC" "APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_TIMESTAMP_UNIX_MS"
require_contains "$HANDOFF_DOC" "APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_TIMESTAMP_UNIX_MS"
require_contains "$HANDOFF_DOC" "SOURCE_DATE_EPOCH"
require_contains "$HANDOFF_DOC" "dockerhub-registry-promotion-evidence.json"
require_contains "$HANDOFF_DOC" "secret_scan_findings"
require_contains "$HANDOFF_DOC" "KUBECONFIG=/home/mactavish/vultr-k8s/vke-a88389c3-f720-412d-9579-c83d3c21eabb.yaml"
require_contains "$HANDOFF_DOC" "make test-release-validation-preflight"
require_contains "$HANDOFF_DOC" "make test-release-validation-ci"
require_contains "$HANDOFF_DOC" "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_AGGREGATE_REPORT"
require_contains "$HANDOFF_DOC" "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_INDEX"
require_contains "$HANDOFF_DOC" "evidence index"
require_contains "$HANDOFF_DOC" "release-validation-preflight-evidence"
require_contains "$HANDOFF_DOC" "release-validation-final-signoff-evidence"
require_contains "$HANDOFF_DOC" "release-validation-production-hardening-evidence"
require_contains "$HANDOFF_DOC" "target/release-validation-ci"
require_contains "$MAKEFILE" "test-release-validation-ci:"
require_contains "$MAKEFILE" "test-release-validation-preflight:"
require_contains "$CI_WORKFLOW" "make test-release-validation-ci"
require_contains "$CI_WORKFLOW" "make test-release-validation-handoff"
require_contains "$CI_WORKFLOW" "make test-release-validation-preflight"
require_contains "$CI_WORKFLOW" "make test-regulated-release-final-release-signoff"
require_contains "$CI_WORKFLOW" "make test-production-hardening"
require_contains "$CI_WORKFLOW" "APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_APPROVER: ci-release-validation"

if [[ -f "$ROADMAP_EN" && -f "$ROADMAP_ZH" && -f "$PROGRESS_DOC" ]]; then
  require_contains "$PROGRESS_DOC" "evidence index"
  require_contains "$ROADMAP_EN" "evidence index"
  require_contains "$ROADMAP_ZH" "evidence index"
fi

printf 'release validation handoff check passed\n'

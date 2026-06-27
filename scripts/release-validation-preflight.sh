#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-release-validation: missing command: $1" >&2
        exit 1
    }
}

require_command python3

mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/release-validation-preflight.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report_path="$output_dir/apolysis-release-validation-preflight-report.json"
index_path="${APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_INDEX:-$output_dir/apolysis-release-validation-evidence-index.json}"
require_ready="${APOLYSIS_REQUIRE_RELEASE_VALIDATION_PREFLIGHT:-0}"

python3 - "$report_path" "$index_path" "$require_ready" <<'PY'
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

report_path = Path(sys.argv[1]).resolve()
index_path = Path(sys.argv[2]).resolve()
require_ready = sys.argv[3].strip().lower() in {"1", "true", "yes", "required"}

PROVIDER_FILES = (
    ("signing_evidence", "signing-evidence.json"),
    ("signing_report", "signing-report.json"),
    ("worm_evidence", "worm-evidence.json"),
    ("worm_report", "worm-report.json"),
    ("managed_mesh_evidence", "managed-mesh-evidence.json"),
    ("managed_mesh_report", "managed-mesh-report.json"),
)
REGISTRY_FILE_PAIRS = (
    (
        ("registry_evidence", "registry-evidence.json"),
        ("registry_report", "registry-report.json"),
    ),
    (
        ("dockerhub_registry_promotion_evidence", "dockerhub-registry-promotion-evidence.json"),
        ("dockerhub_registry_promotion_report", "dockerhub-registry-promotion-report.json"),
    ),
)
SECRET_PATTERNS = (
    ("aws_access_key_id", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("aws_secret_label", re.compile(b"aws_" + b"secret_" + b"access_" + b"key", re.IGNORECASE)),
    ("private_key_block", re.compile(rb"BEGIN (RSA|OPENSSH|DSA|EC|PRIVATE) KEY")),
    ("openai_api_key", re.compile(rb"sk-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}")),
)


def env_path(*names: str) -> Path | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return Path(value).expanduser().resolve()
    return None


def add_missing(missing: list[str], requirement: str) -> None:
    if requirement not in missing:
        missing.append(requirement)


def load_json(path: Path | None, label: str, missing: list[str]) -> dict[str, Any] | None:
    if path is None:
        add_missing(missing, f"{label} path is required")
        return None
    if not path.is_file():
        add_missing(missing, f"{label} must exist: {path}")
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - this is an operator-facing gate.
        add_missing(missing, f"{label} must be valid JSON: {exc}")
        return None
    if not isinstance(document, dict):
        add_missing(missing, f"{label} must be a JSON object")
        return None
    return document


def require_true(document: dict[str, Any] | None, key: str, label: str, missing: list[str]) -> None:
    if document is None:
        return
    if document.get(key) is not True:
        add_missing(missing, f"{label}.{key} must be true")


def require_empty_list(document: dict[str, Any] | None, key: str, label: str, missing: list[str]) -> None:
    if document is None:
        return
    if document.get(key) != []:
        add_missing(missing, f"{label}.{key} must be []")


def collect_embedded_secret_findings(value: Any) -> list[Any]:
    findings: list[Any] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "secret_scan_findings":
                if child:
                    findings.append(child)
            else:
                findings.extend(collect_embedded_secret_findings(child))
    elif isinstance(value, list):
        for child in value:
            findings.extend(collect_embedded_secret_findings(child))
    return findings


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def index_item(kind: str, path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "kind": kind,
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "size_bytes": stat.st_size,
    }


def scan_indexed_files(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for item in items:
        path = Path(str(item["path"]))
        try:
            content = path.read_bytes()
        except OSError as exc:
            findings.append({"path": str(path), "pattern": "read_error", "detail": str(exc)})
            continue
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(content):
                findings.append({"path": str(path), "pattern": name})
    return findings


missing: list[str] = []
items: list[dict[str, Any]] = []
notes: list[str] = []

provider_root = env_path(
    "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_PROVIDER_ROOT",
    "APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT",
)
aggregate_report = env_path(
    "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_AGGREGATE_REPORT",
    "APOLYSIS_REGULATED_RELEASE_REGULATED_RELEASE_REPORT",
    "APOLYSIS_REGULATED_RELEASE_REPORT",
)
external_readback = env_path(
    "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_EXTERNAL_RETENTION_READBACK_EVIDENCE",
    "APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_READBACK_EVIDENCE",
)
registry_readback = env_path(
    "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_IMMUTABLE_REGISTRY_READBACK_EVIDENCE",
    "APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_READBACK_EVIDENCE",
)
final_signoff = env_path(
    "APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_FINAL_SIGNOFF",
    "APOLYSIS_REGULATED_RELEASE_FINAL_RELEASE_SIGNOFF",
    "APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_ARTIFACT",
)

if provider_root is None:
    add_missing(missing, "provider artifact root path is required")
elif not provider_root.is_dir():
    add_missing(missing, f"provider artifact root must exist: {provider_root}")
else:
    for kind, filename in PROVIDER_FILES:
        path = provider_root / filename
        if path.is_file():
            items.append(index_item(kind, path))
        else:
            add_missing(missing, f"provider artifact is required: {filename}")

    registry_pair_found = False
    for pair in REGISTRY_FILE_PAIRS:
        evidence = provider_root / pair[0][1]
        report = provider_root / pair[1][1]
        if evidence.is_file() and report.is_file():
            registry_pair_found = True
            items.append(index_item(pair[0][0], evidence))
            items.append(index_item(pair[1][0], report))
        elif evidence.exists() or report.exists():
            add_missing(missing, f"registry evidence/report pair is incomplete: {pair[0][1]}, {pair[1][1]}")
    if not registry_pair_found:
        add_missing(missing, "provider root must include a registry evidence/report pair")

aggregate = load_json(aggregate_report, "aggregate report", missing)
for key in (
    "passed",
    "regulated_release_ready",
    "pre_signoff_regulated_release_ready",
    "final_release_signoff_ready",
):
    require_true(aggregate, key, "aggregate report", missing)
require_empty_list(aggregate, "missing_requirements", "aggregate report", missing)
embedded_secret_findings = collect_embedded_secret_findings(aggregate)
if embedded_secret_findings:
    add_missing(missing, "aggregate report secret_scan_findings must be empty")
if aggregate_report is not None and aggregate_report.is_file():
    items.append(index_item("aggregate_report", aggregate_report))

external = load_json(external_readback, "external retention readback evidence", missing)
for key in ("readback_verified", "retention_policy_verified", "delete_denied"):
    require_true(external, key, "external retention readback evidence", missing)
if external_readback is not None and external_readback.is_file():
    items.append(index_item("external_retention_readback_evidence", external_readback))

registry = load_json(registry_readback, "immutable registry readback evidence", missing)
for key in ("digest_readback_verified", "immutability_policy_verified", "mutation_denied"):
    require_true(registry, key, "immutable registry readback evidence", missing)
if registry_readback is not None and registry_readback.is_file():
    items.append(index_item("immutable_registry_readback_evidence", registry_readback))

signoff = load_json(final_signoff, "final signoff", missing)
if signoff is not None:
    if signoff.get("decision") != "approve_regulated_release":
        add_missing(missing, "final signoff.decision must be approve_regulated_release")
    if not str(signoff.get("approver", "")).strip():
        add_missing(missing, "final signoff.approver is required")
    if not str(signoff.get("approved_at", "")).strip():
        add_missing(missing, "final signoff.approved_at is required")
    if len(str(signoff.get("rationale", "")).strip()) < 16:
        add_missing(missing, "final signoff.rationale must describe the approval basis")
    require_true(signoff, "regulated_release_ready", "final signoff", missing)
    require_true(signoff, "no_secret_material_recorded", "final signoff", missing)
    require_empty_list(signoff, "missing_requirements", "final signoff", missing)
if final_signoff is not None and final_signoff.is_file():
    items.append(index_item("final_signoff", final_signoff))

secret_findings = scan_indexed_files(items)
if secret_findings:
    add_missing(missing, "indexed evidence files must not contain secret patterns")

index_path.parent.mkdir(parents=True, exist_ok=True)
evidence_index = {
    "schema_version": 1,
    "phase": "release-validation.evidence-index",
    "generated_by": "release-validation-preflight",
    "observed_at_unix_ms": int(time.time() * 1000),
    "items": items,
    "secret_scan_findings": secret_findings,
}
index_path.write_text(json.dumps(evidence_index, indent=2, sort_keys=True) + "\n", encoding="utf-8")

ready = not missing
report_path.parent.mkdir(parents=True, exist_ok=True)
report = {
    "schema_version": 1,
    "phase": "release-validation.preflight",
    "passed": ready,
    "release_validation_preflight_ready": ready,
    "missing_requirements": sorted(missing),
    "provider_root": str(provider_root) if provider_root else "",
    "aggregate_report": str(aggregate_report) if aggregate_report else "",
    "external_retention_readback_evidence": str(external_readback) if external_readback else "",
    "immutable_registry_readback_evidence": str(registry_readback) if registry_readback else "",
    "final_signoff": str(final_signoff) if final_signoff else "",
    "evidence_index": str(index_path),
    "evidence_item_count": len(items),
    "secret_scan_findings": secret_findings,
    "notes": notes,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print(f"apolysis-release-validation: preflight report: {report_path}")
print(f"apolysis-release-validation: evidence index: {index_path}")
if not ready:
    print("apolysis-release-validation: missing requirements:", file=sys.stderr)
    for requirement in sorted(missing):
        print(f"- {requirement}", file=sys.stderr)
    if require_ready:
        sys.exit(1)
PY

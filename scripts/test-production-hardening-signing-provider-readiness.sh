#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER_READINESS_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/production-hardening-signing-provider-readiness.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-production-hardening-signing-provider-readiness-report.json"
require_ready="${APOLYSIS_REQUIRE_PRODUCTION_HARDENING_SIGNING_PROVIDER_READINESS:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-production-hardening: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$report" "$require_ready" <<'PY'
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
report_path = Path(sys.argv[2])
require_ready = sys.argv[3] == "1"

accepted_signing_providers = {
    "cloud_kms",
    "aws_kms",
    "gcp_cloud_kms",
    "azure_key_vault",
    "aws_cloudhsm",
    "external_hsm",
}

def tool(name: str) -> dict:
    path = shutil.which(name) or ""
    return {"available": bool(path), "path": path}

tools = {
    name: tool(name)
    for name in ("aws", "cargo", "jq", "openssl", "pkcs11-tool", "python3", "readlink", "sha256sum")
}

def load_json(path: Path | None) -> tuple[dict, str]:
    if path is None:
        return {}, "missing_path"
    if not path.is_file():
        return {}, "missing_file"
    try:
        return json.loads(path.read_text(encoding="utf-8")), "loaded"
    except json.JSONDecodeError as exc:
        return {}, f"invalid_json:{exc}"

def env_path(name: str) -> Path | None:
    value = os.environ.get(name, "")
    return Path(value) if value else None

signing_evidence_path = env_path("APOLYSIS_PRODUCTION_HARDENING_SIGNING_EVIDENCE")
signing_report_path = env_path("APOLYSIS_PRODUCTION_HARDENING_SIGNING_REPORT")
signing_evidence, signing_evidence_status = load_json(signing_evidence_path)
signing_report, signing_report_status = load_json(signing_report_path)
signing_provider = str(signing_evidence.get("provider") or signing_evidence.get("approval", {}).get("provider", ""))
try:
    signing_observed_at = int(
        signing_evidence.get("observed_at_unix_ms")
        or signing_evidence.get("approval", {}).get("observed_at_unix_ms")
        or 0
    )
except Exception:
    signing_observed_at = 0

retained_signing_evidence = {
    "configured": signing_evidence_path is not None and signing_report_path is not None,
    "evidence_path": str(signing_evidence_path) if signing_evidence_path else "",
    "report_path": str(signing_report_path) if signing_report_path else "",
    "evidence_status": signing_evidence_status,
    "report_status": signing_report_status,
    "provider": signing_provider,
    "evidence_source": signing_evidence.get("source", ""),
    "live_provider_evidence": signing_evidence.get("source") == "live_provider",
    "report_passed": signing_report.get("passed") is True,
    "observed_at_unix_ms": signing_observed_at,
}
retained_signing_evidence["ready"] = (
    retained_signing_evidence["configured"]
    and retained_signing_evidence["live_provider_evidence"]
    and retained_signing_evidence["report_passed"]
    and retained_signing_evidence["provider"] in accepted_signing_providers
    and retained_signing_evidence["observed_at_unix_ms"] > 0
)

aws_region = (
    os.environ.get("APOLYSIS_PRODUCTION_HARDENING_AWS_REGION")
    or os.environ.get("AWS_REGION")
    or os.environ.get("AWS_DEFAULT_REGION")
    or ""
)
aws_credential_hint = any(
    bool(os.environ.get(name))
    for name in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE")
) or (Path.home() / ".aws").is_dir()
aws_kms = {
    "tool_aws": tools["aws"]["available"],
    "APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID": bool(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID")),
    "region": bool(aws_region),
    "credential_hint_present": bool(aws_credential_hint),
    "confirmation_required": "APOLYSIS_CONFIRM_PRODUCTION_HARDENING_AWS_KMS_SIGNING=1",
}
aws_kms["missing_prerequisites"] = [
    name
    for name, present in aws_kms.items()
    if name != "confirmation_required" and present is not True
]
aws_kms["ready_to_execute"] = not aws_kms["missing_prerequisites"]

def resolve_module(module: str) -> str:
    if not module:
        return ""
    try:
        return str(Path(module).resolve(strict=False))
    except Exception:
        return module

def is_software_hsm(module: str) -> bool:
    return "softhsm" in module.lower()

def list_slots(module: str) -> tuple[bool, str]:
    if not module or not tools["pkcs11-tool"]["available"]:
        return False, ""
    process = subprocess.run(
        ["pkcs11-tool", "--module", module, "--list-slots"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return process.returncode == 0, process.stdout[:12000]

external_hsm_module = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE", "")
external_hsm_module_realpath = resolve_module(external_hsm_module)
external_hsm_module_path = Path(external_hsm_module_realpath) if external_hsm_module_realpath else None
external_hsm_pin_configured = bool(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN_FILE")) or bool(
    os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PIN")
)
external_hsm_interactive_pin = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_ALLOW_INTERACTIVE_PIN", "0") == "1"
slot_list_ok, slot_list_output = list_slots(external_hsm_module_realpath)
token_label = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL", "")
slot = os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_SLOT", "")
token_or_slot_configured = bool(token_label or slot)
token_or_slot_visible = False
if slot:
    token_or_slot_visible = f"Slot {slot}" in slot_list_output or f"slot {slot}" in slot_list_output.lower()
elif token_label:
    token_or_slot_visible = token_label in slot_list_output

external_hsm = {
    "tool_pkcs11_tool": tools["pkcs11-tool"]["available"],
    "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE": bool(external_hsm_module),
    "module_exists": bool(external_hsm_module_path and external_hsm_module_path.is_file()),
    "module_is_not_software_hsm": bool(external_hsm_module_realpath and not is_software_hsm(external_hsm_module_realpath)),
    "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL_OR_SLOT": token_or_slot_configured,
    "APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL": bool(os.environ.get("APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL")),
    "pin_source_or_interactive_pin": external_hsm_pin_configured or external_hsm_interactive_pin,
    "slot_list_succeeded": slot_list_ok,
    "token_or_slot_visible": token_or_slot_visible,
    "module_ref": external_hsm_module_realpath,
    "confirmation_required": "APOLYSIS_CONFIRM_PRODUCTION_HARDENING_EXTERNAL_HSM_SIGNING=1",
}
external_hsm["missing_prerequisites"] = [
    name
    for name, present in external_hsm.items()
    if name
    not in {
        "confirmation_required",
        "missing_prerequisites",
        "module_ref",
    }
    and present is not True
]
external_hsm["ready_to_execute"] = not external_hsm["missing_prerequisites"]

detected_pkcs11_modules = []
for directory in (Path("/usr/lib/pkcs11"), Path("/usr/lib64/pkcs11")):
    if directory.is_dir():
        for module in sorted(directory.glob("*.so")):
            detected_pkcs11_modules.append(str(module))
for module in (Path("/usr/lib/opensc-pkcs11.so"), Path("/usr/lib/onepin-opensc-pkcs11.so")):
    if module.is_file() and str(module) not in detected_pkcs11_modules:
        detected_pkcs11_modules.append(str(module))

ready_to_execute = aws_kms["ready_to_execute"] or external_hsm["ready_to_execute"]
signing_provider_ready = retained_signing_evidence["ready"] or ready_to_execute
if signing_provider_ready:
    missing = []
else:
    missing = [
        "retained_live_provider_signing_evidence",
        "aws_kms_or_external_hsm_execution_prerequisites",
    ]

report = {
    "schema_version": 1,
    "audit_completed": True,
    "passed": signing_provider_ready or not require_ready,
    "fail_closed_required": require_ready,
    "signing_provider_ready": signing_provider_ready,
    "retained_signing_evidence_ready": retained_signing_evidence["ready"],
    "ready_to_execute_live_signing": ready_to_execute,
    "missing_requirements": missing,
    "retained_signing_evidence": retained_signing_evidence,
    "aws_kms": aws_kms,
    "external_hsm": external_hsm,
    "detected_pkcs11_modules": detected_pkcs11_modules,
    "tools": tools,
    "notes": [
        "No secret values are recorded in this report.",
        "A ready AWS KMS path still requires running scripts/test-production-hardening-aws-kms-signing.sh to create retained signing evidence.",
        "A ready external HSM path still requires running scripts/test-production-hardening-external-hsm-signing.sh to create retained signing evidence.",
        "SoftHSM and local TPM evidence do not satisfy the current ProductionHardening cloud KMS/external hardware HSM requirement.",
    ],
    "next_commands": {
        "aws_kms": "APOLYSIS_CONFIRM_PRODUCTION_HARDENING_AWS_KMS_SIGNING=1 APOLYSIS_PRODUCTION_HARDENING_AWS_KMS_KEY_ID=<key-id-or-arn> ./scripts/test-production-hardening-aws-kms-signing.sh",
        "external_hsm": "APOLYSIS_CONFIRM_PRODUCTION_HARDENING_EXTERNAL_HSM_SIGNING=1 APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_PKCS11_MODULE=<module> APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_TOKEN_LABEL=<token> APOLYSIS_PRODUCTION_HARDENING_EXTERNAL_HSM_KEY_LABEL=<key> ./scripts/test-production-hardening-external-hsm-signing.sh",
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not signing_provider_ready:
    print(f"apolysis-production-hardening: signing provider readiness failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-production-hardening: signing provider readiness audit written ($output_dir)
APOLYSIS_PRODUCTION_HARDENING_SIGNING_PROVIDER_READINESS_REPORT=$report
EOF

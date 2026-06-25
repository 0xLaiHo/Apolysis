#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_root/target"
output_dir="${APOLYSIS_F6_SIGNING_EVIDENCE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f6-signing-evidence.XXXXXX")}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

report="$output_dir/apolysis-f6-signing-evidence-report.json"
require_ready="${APOLYSIS_REQUIRE_F6_SIGNING_EVIDENCE:-0}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f6: missing command: $1" >&2
        exit 1
    }
}

require_command python3

python3 - "$repo_root" "$output_dir" "$report" "$require_ready" <<'PY'
import json
import os
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
report_path = Path(sys.argv[3])
require_ready = sys.argv[4] == "1"

f5_gate = repo_root / "scripts/test-f5-signing-provider-readiness.sh"
downstream_dir = output_dir / "f5-signing-provider-readiness"
downstream_report_path = downstream_dir / "apolysis-f5-signing-provider-readiness-report.json"

allowed_providers = {"auto", "aws_kms", "external_hsm", "retained_signing"}

def env_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return ""

requested_provider = env_value("APOLYSIS_F6_SIGNING_PROVIDER") or "auto"
signing_evidence = env_value("APOLYSIS_F6_SIGNING_EVIDENCE", "APOLYSIS_F5_SIGNING_EVIDENCE")
signing_report = env_value("APOLYSIS_F6_SIGNING_REPORT", "APOLYSIS_F5_SIGNING_REPORT")

provider_errors: list[str] = []
if requested_provider not in allowed_providers:
    provider_errors.append("APOLYSIS_F6_SIGNING_PROVIDER")

env = os.environ.copy()
env["APOLYSIS_F5_SIGNING_PROVIDER_READINESS_OUTPUT_DIR"] = str(downstream_dir)
env["APOLYSIS_REQUIRE_F5_SIGNING_PROVIDER_READINESS"] = "0"

if signing_evidence:
    env["APOLYSIS_F5_SIGNING_EVIDENCE"] = signing_evidence
if signing_report:
    env["APOLYSIS_F5_SIGNING_REPORT"] = signing_report

f6_to_f5_env = {
    "APOLYSIS_F6_AWS_REGION": "APOLYSIS_F5_AWS_REGION",
    "APOLYSIS_F6_AWS_KMS_KEY_ID": "APOLYSIS_F5_AWS_KMS_KEY_ID",
    "APOLYSIS_F6_AWS_ROLE_TO_ASSUME": "APOLYSIS_F5_AWS_ROLE_TO_ASSUME",
    "APOLYSIS_F6_EXTERNAL_HSM_PKCS11_MODULE": "APOLYSIS_F5_EXTERNAL_HSM_PKCS11_MODULE",
    "APOLYSIS_F6_EXTERNAL_HSM_TOKEN_LABEL": "APOLYSIS_F5_EXTERNAL_HSM_TOKEN_LABEL",
    "APOLYSIS_F6_EXTERNAL_HSM_SLOT": "APOLYSIS_F5_EXTERNAL_HSM_SLOT",
    "APOLYSIS_F6_EXTERNAL_HSM_KEY_LABEL": "APOLYSIS_F5_EXTERNAL_HSM_KEY_LABEL",
    "APOLYSIS_F6_EXTERNAL_HSM_PIN_FILE": "APOLYSIS_F5_EXTERNAL_HSM_PIN_FILE",
    "APOLYSIS_F6_EXTERNAL_HSM_PIN": "APOLYSIS_F5_EXTERNAL_HSM_PIN",
    "APOLYSIS_F6_EXTERNAL_HSM_ALLOW_INTERACTIVE_PIN": "APOLYSIS_F5_EXTERNAL_HSM_ALLOW_INTERACTIVE_PIN",
}
for source, target in f6_to_f5_env.items():
    if os.environ.get(source, ""):
        env[target] = os.environ[source]

if os.environ.get("APOLYSIS_F6_AWS_KMS_ALIAS", ""):
    env["APOLYSIS_F5_AWS_KMS_ALIAS"] = os.environ["APOLYSIS_F6_AWS_KMS_ALIAS"]
    env.setdefault("APOLYSIS_F5_AWS_KMS_KEY_ID", os.environ["APOLYSIS_F6_AWS_KMS_ALIAS"])

downstream_dir.mkdir(parents=True, exist_ok=True)
process = subprocess.run(
    [str(f5_gate)],
    cwd=repo_root,
    env=env,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
)
downstream_output_path = output_dir / "f5-signing-provider-readiness.out"
downstream_output_path.write_text(process.stdout, encoding="utf-8")

downstream_doc: dict = {}
if downstream_report_path.is_file():
    try:
        downstream_doc = json.loads(downstream_report_path.read_text(encoding="utf-8"))
    except Exception:
        downstream_doc = {}

retained_doc = downstream_doc.get("retained_signing_evidence") or {}
aws_doc = downstream_doc.get("aws_kms") or {}
external_doc = downstream_doc.get("external_hsm") or {}

retained_signing_evidence_ready = bool(downstream_doc.get("retained_signing_evidence_ready"))
ready_to_execute_live_signing = bool(downstream_doc.get("ready_to_execute_live_signing"))
aws_kms_ready_to_execute = bool(aws_doc.get("ready_to_execute"))
external_hsm_ready_to_execute = bool(external_doc.get("ready_to_execute"))
evidence_provider = str(retained_doc.get("provider") or "")

provider_evidence_matches = {
    "retained_signing": retained_signing_evidence_ready,
    "aws_kms": retained_signing_evidence_ready and evidence_provider in {"aws_kms", "cloud_kms"},
    "external_hsm": retained_signing_evidence_ready and evidence_provider == "external_hsm",
}
if requested_provider == "auto":
    if provider_evidence_matches["aws_kms"]:
        selected_provider = "aws_kms"
    elif provider_evidence_matches["external_hsm"]:
        selected_provider = "external_hsm"
    elif retained_signing_evidence_ready:
        selected_provider = "retained_signing"
    elif aws_kms_ready_to_execute:
        selected_provider = "aws_kms"
    elif external_hsm_ready_to_execute:
        selected_provider = "external_hsm"
    else:
        selected_provider = "retained_signing"
elif requested_provider in allowed_providers:
    selected_provider = requested_provider
else:
    selected_provider = "retained_signing"

if selected_provider == "auto":
    selected_provider = "retained_signing"

selected_provider_evidence_ready = provider_evidence_matches.get(
    selected_provider,
    retained_signing_evidence_ready,
)
signing_evidence_ready = process.returncode == 0 and not provider_errors and selected_provider_evidence_ready
signing_provider_ready = bool(downstream_doc.get("signing_provider_ready"))

missing_requirements: list[str] = []
missing_requirements.extend(provider_errors)
if process.returncode != 0:
    missing_requirements.append("f5_signing_provider_readiness_audit_succeeded")
if not retained_signing_evidence_ready:
    missing_requirements.append("retained_live_provider_signing_evidence")
if retained_signing_evidence_ready and not selected_provider_evidence_ready:
    missing_requirements.append(f"{selected_provider}_signing_evidence")
missing_requirements.extend(str(value) for value in downstream_doc.get("missing_requirements") or [])
missing_requirements = list(dict.fromkeys(missing_requirements))

passed = signing_evidence_ready or not require_ready

report = {
    "schema_version": 1,
    "phase": "F6.5",
    "audit_completed": True,
    "passed": passed,
    "fail_closed_required": require_ready,
    "signing_evidence_ready": signing_evidence_ready,
    "signing_provider_ready": signing_provider_ready,
    "retained_signing_evidence_ready": retained_signing_evidence_ready,
    "ready_to_execute_live_signing": ready_to_execute_live_signing,
    "requested_signing_provider": requested_provider,
    "selected_signing_provider": selected_provider,
    "provider_evidence_matches_selection": selected_provider_evidence_ready,
    "retained_signing_evidence": {
        "evidence_path_present": bool(signing_evidence),
        "report_path_present": bool(signing_report),
        "evidence_path_exists": bool(signing_evidence) and Path(signing_evidence).is_file(),
        "report_path_exists": bool(signing_report) and Path(signing_report).is_file(),
        "provider": evidence_provider,
        "evidence_source": retained_doc.get("evidence_source", ""),
        "live_provider_evidence": bool(retained_doc.get("live_provider_evidence")),
        "report_passed": bool(retained_doc.get("report_passed")),
        "observed_at_unix_ms": int(retained_doc.get("observed_at_unix_ms") or 0),
    },
    "execution_prerequisites": {
        "aws_kms_ready_to_execute": aws_kms_ready_to_execute,
        "external_hsm_ready_to_execute": external_hsm_ready_to_execute,
        "aws_kms": {
            "tool_aws": bool(aws_doc.get("tool_aws")),
            "region": bool(aws_doc.get("region")),
            "kms_key_id_or_alias_present": bool(
                aws_doc.get("APOLYSIS_F5_AWS_KMS_KEY_ID")
                or os.environ.get("APOLYSIS_F6_AWS_KMS_ALIAS", "")
            ),
            "credential_hint_present": bool(aws_doc.get("credential_hint_present")),
            "missing_prerequisites": aws_doc.get("missing_prerequisites") or [],
        },
        "external_hsm": {
            "tool_pkcs11_tool": bool(external_doc.get("tool_pkcs11_tool")),
            "module_present": bool(external_doc.get("APOLYSIS_F5_EXTERNAL_HSM_PKCS11_MODULE")),
            "token_or_slot_present": bool(external_doc.get("APOLYSIS_F5_EXTERNAL_HSM_TOKEN_LABEL_or_SLOT")),
            "key_label_present": bool(external_doc.get("APOLYSIS_F5_EXTERNAL_HSM_KEY_LABEL")),
            "pin_source_or_interactive_pin": bool(external_doc.get("pin_source_or_interactive_pin")),
            "module_is_not_software_hsm": bool(external_doc.get("module_is_not_software_hsm")),
            "missing_prerequisites": external_doc.get("missing_prerequisites") or [],
        },
    },
    "downstream": {
        "gate": str(f5_gate),
        "exit_code": process.returncode,
        "output_file": str(downstream_output_path),
        "report": str(downstream_report_path) if downstream_report_path.is_file() else "",
    },
    "missing_requirements": [] if signing_evidence_ready else missing_requirements,
    "notes": [
        "No secret values are recorded in this report.",
        "F6.5 maps F6 signing evidence controls to the historical F5.40 signing-provider readiness gate.",
        "ready_to_execute_live_signing is only a handoff signal; regulated release readiness requires retained live-provider signing evidence.",
        "Default audit mode does not call AWS or HSM signing APIs.",
    ],
    "next_commands": {
        "audit": "./scripts/test-f6-signing-evidence.sh",
        "audit_retained_signing": (
            "APOLYSIS_F6_SIGNING_EVIDENCE=<signing-evidence.json> "
            "APOLYSIS_F6_SIGNING_REPORT=<signing-report.json> "
            "APOLYSIS_REQUIRE_F6_SIGNING_EVIDENCE=1 ./scripts/test-f6-signing-evidence.sh"
        ),
        "aws_kms_evidence": (
            "APOLYSIS_CONFIRM_F5_AWS_KMS_SIGNING=1 "
            "APOLYSIS_F5_AWS_KMS_KEY_ID=<key-id-or-arn> ./scripts/test-f5-aws-kms-signing.sh"
        ),
        "external_hsm_evidence": (
            "APOLYSIS_CONFIRM_F5_EXTERNAL_HSM_SIGNING=1 "
            "APOLYSIS_F5_EXTERNAL_HSM_PKCS11_MODULE=<module> "
            "APOLYSIS_F5_EXTERNAL_HSM_TOKEN_LABEL=<token> "
            "APOLYSIS_F5_EXTERNAL_HSM_KEY_LABEL=<key> ./scripts/test-f5-external-hsm-signing.sh"
        ),
    },
    "observed_at_unix_ms": int(time.time() * 1000),
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if require_ready and not signing_evidence_ready:
    print(f"apolysis-f6: signing evidence failed closed ({report_path})", file=sys.stderr)
    print("missing requirements: " + ", ".join(report["missing_requirements"]), file=sys.stderr)
    raise SystemExit(1)
PY

cat <<EOF
apolysis-f6: signing evidence audit written ($output_dir)
APOLYSIS_F6_SIGNING_EVIDENCE_REPORT=$report
EOF

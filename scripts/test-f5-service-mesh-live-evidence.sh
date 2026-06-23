#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${APOLYSIS_F5_SERVICE_MESH_LIVE_EVIDENCE_OUTPUT_DIR:-$(mktemp -d "$repo_root/target/f5-service-mesh-live-evidence.XXXXXX")}"
mkdir -p "$output_dir"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "apolysis-f5: missing command: $1" >&2
        exit 1
    }
}

for command in cargo jq python3; do
    require_command "$command"
done

pass_evidence="$output_dir/apolysis-f5-istio-live-evidence.json"
fail_evidence="$output_dir/apolysis-f5-istio-live-evidence-fail.json"
pass_report="$output_dir/apolysis-f5-istio-live-evidence-report.json"
fail_report="$output_dir/apolysis-f5-istio-live-evidence-fail-report.json"

cat >"$pass_evidence" <<'JSON'
{
  "evidence_id": "f5-istio-mtls-handshake-20260624",
  "source": "live_cluster",
  "provider": "istio",
  "cluster_name": "mactavish-k3s",
  "namespace": "apolysis-system",
  "workload_service_account": "apolysis",
  "metrics_service_name": "apolysis-metrics",
  "peer_authentication_name": "apolysis-mtls",
  "authorization_policy_name": "apolysis-metrics",
  "mtls_mode": "strict",
  "peer_authentication_admitted": true,
  "authorization_policy_admitted": true,
  "authorized_principal": "cluster.local/ns/apolysis-monitoring/sa/prometheus",
  "server_principal": "cluster.local/ns/apolysis-system/sa/apolysis",
  "authorized_handshake_succeeded": true,
  "unauthorized_handshake_denied": true,
  "plaintext_handshake_denied": true,
  "observed_traffic_security": "mutual_tls",
  "cleanup_confirmed": true,
  "observed_at_unix_ms": 1782259200000
}
JSON

cargo run -q -p apolysis-validation --bin apolysis-f5-service-mesh-live-evidence -- \
    --evidence "$pass_evidence" >"$pass_report"

jq -e '
  .schema_version == 1
  and .passed == true
  and .approval.provider == "istio"
  and .approval.namespace == "apolysis-system"
  and .approval.authorized_principal == "cluster.local/ns/apolysis-monitoring/sa/prometheus"
  and .approval.server_principal == "cluster.local/ns/apolysis-system/sa/apolysis"
' "$pass_report" >/dev/null

python3 - "$pass_evidence" "$fail_evidence" <<'PY'
import json
import sys
from pathlib import Path

source, dest = map(Path, sys.argv[1:])
data = json.loads(source.read_text(encoding="utf-8"))
data["source"] = "fixture"
data["provider"] = "none"
data["mtls_mode"] = "permissive"
data["peer_authentication_admitted"] = False
data["authorization_policy_admitted"] = False
data["authorized_principal"] = "*"
data["server_principal"] = "anonymous"
data["authorized_handshake_succeeded"] = False
data["unauthorized_handshake_denied"] = False
data["plaintext_handshake_denied"] = False
data["observed_traffic_security"] = "plaintext"
data["cleanup_confirmed"] = False
data["observed_at_unix_ms"] = 0
dest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if cargo run -q -p apolysis-validation --bin apolysis-f5-service-mesh-live-evidence -- \
    --evidence "$fail_evidence" >"$fail_report"; then
    echo "apolysis-f5: invalid service-mesh live evidence unexpectedly passed" >&2
    exit 1
fi

jq -e '
  .passed == false
  and (.failures | map(.message) | index("live cluster evidence is required"))
  and (.failures | map(.message) | index("Istio is required for this F5 service-mesh live gate"))
  and (.failures | map(.message) | index("strict mTLS mode is required"))
  and (.failures | map(.message) | index("authorized service-account principal is required"))
  and (.failures | map(.message) | index("traffic telemetry must report mutual TLS"))
' "$fail_report" >/dev/null

printf 'apolysis-f5: service-mesh live evidence gate passed (%s)\n' "$output_dir"

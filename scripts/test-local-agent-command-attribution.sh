#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo test -p apolysis-cli --test observe observe_live
cargo test -p apolysis-observer

if [[ "${APOLYSIS_CONFIRM_LOCAL_AGENT_COMMAND_ATTRIBUTION:-0}" != "1" ]]; then
  echo "local-agent-command-attribution fixture gate passed"
  echo "set APOLYSIS_CONFIRM_LOCAL_AGENT_COMMAND_ATTRIBUTION=1 and run as root for the opt-in live gate"
  exit 0
fi

if [[ "$(id -u)" != "0" ]]; then
  echo "opt-in live gate requires root/CAP_BPF/CAP_PERFMON; re-run with sudo -E" >&2
  exit 2
fi

if [[ ! -f target/ebpf/apolysis_observer.bpf.o ]]; then
  echo "missing target/ebpf/apolysis_observer.bpf.o; run make build-ebpf first" >&2
  exit 2
fi

cargo build -p apolysis-cli
mkdir -p .apolysis/local-agent-command-attribution
output=".apolysis/local-agent-command-attribution/timeline.agent-run.jsonl"
rm -f "$output"

./target/debug/apolysis observe \
  --backend live \
  --session local-agent-command-attribution-smoke \
  --policy policies/local-dev.yaml \
  --output "$output" \
  --bpf-object target/ebpf/apolysis_observer.bpf.o \
  --workspace-root "$PWD" \
  --agent-kind shell \
  --agent-run -- sh -lc 'pwd >/dev/null; cat Cargo.toml >/dev/null; stat crates/apolysis-observer/src/live.rs >/dev/null'

rg -q '"resource":"agent-supervisor-mode".*"action":"apolysis_managed_launch"' "$output"
rg -q '"resource":"agent-kind".*"action":"shell"' "$output"
rg -q '"resource":"agent-root-pid"' "$output"
rg -q '"resource":"observer-scope".*"mode:process_tree,root_pid:' "$output"
rg -q '"resource":"agent-exit-status".*"action":"exit:0"' "$output"

echo "local-agent-command-attribution live gate passed: $output"

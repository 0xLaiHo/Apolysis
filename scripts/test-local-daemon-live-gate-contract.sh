#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -I - \
    "$repo_root/scripts/qualify-local-daemon-install.sh" \
    "$repo_root/scripts/test-local-daemon-systemd.sh" <<'PY'
from pathlib import Path
import subprocess
import sys

install = Path(sys.argv[1]).read_text(encoding="utf-8")
transient = Path(sys.argv[2]).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f"missing {label}: {needle!r}")


def ordered(text: str, first: str, second: str, label: str) -> None:
    first_at = text.find(first)
    second_at = text.find(second)
    if first_at < 0 or second_at < 0 or first_at >= second_at:
        raise AssertionError(f"unsafe ordering for {label}: {first!r} before {second!r}")


def forbid(text: str, needle: str, label: str) -> None:
    if needle in text:
        raise AssertionError(f"forbidden {label}: {needle!r}")


def extract_shell_function(text: str, name: str, following_name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index(f"\n}}\n\n{following_name}()", start) + 3
    return text[start:end]


def run_created_directory_identity_wait(responses: list[str]) -> subprocess.CompletedProcess[str]:
    helper = extract_shell_function(
        install,
        "wait_for_created_directory_identity",
        "managed_paths_absent",
    )
    harness = f"""{helper}
host_fs_guard() {{
    local response
    IFS= read -r response <&9 || return 1
    printf '%s\\n' "$response"
}}
sleep() {{ :; }}
exec 9<<<"$1"
wait_for_created_directory_identity /fixture/apolysis
"""
    return subprocess.run(
        ["bash", "-c", harness, "wait-helper", "\n".join(responses)],
        check=False,
        capture_output=True,
        text=True,
    )


created_identity = "1:2:0:3:750"
eventual_identity = run_created_directory_identity_wait(["absent", created_identity])
if eventual_identity.returncode != 0 or eventual_identity.stdout.strip() != created_identity:
    raise AssertionError(
        "created-directory wait did not accept the first real identity after absence: "
        f"status={eventual_identity.returncode}, stdout={eventual_identity.stdout!r}, "
        f"stderr={eventual_identity.stderr!r}"
    )

persistent_absence = run_created_directory_identity_wait(["absent"] * 120)
if persistent_absence.returncode == 0 or persistent_absence.stdout:
    raise AssertionError(
        "created-directory wait did not fail closed on persistent absence: "
        f"status={persistent_absence.returncode}, stdout={persistent_absence.stdout!r}, "
        f"stderr={persistent_absence.stderr!r}"
    )
if "created directory did not appear" not in persistent_absence.stderr:
    raise AssertionError(
        "created-directory wait did not report its bounded timeout: "
        f"{persistent_absence.stderr!r}"
    )


for unit_root in (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
):
    require(install, unit_root, f"unit-source preflight for {unit_root}")

for property_name in ("LoadState", "ActiveState", "UnitFileState", "FragmentPath"):
    require(install, property_name, f"systemd {property_name} preflight")

require(install, "/run/apolysis", "runtime-root preflight")
require(install, "preflight_complete=1", "completed-preflight guard")
require(install, '"$preflight_complete" == "1"', "cleanup preflight guard")
require(install, "install_mutation_attempted=1", "install-attempt guard")
require(install, "unit_mutation_attempted=1", "unit-attempt guard")
require(install, "group_mutation_attempted=1", "group-attempt guard")
require(install, "cleanup_attention", "visible cleanup failure state")
require(install, "O_NOFOLLOW", "no-follow cleanup validation")
require(install, "strict state cleanup refused", "strict state allowlist")
require(install, "library_dir_initial_identity", "library-directory baseline")
require(install, "library_dir_created_identity", "created library-directory identity")
require(install, "state_root_created_identity", "created state-root identity")
require(install, "runtime_root_created_identity", "created runtime-root identity")
require(
    install,
    '[[ -z "$state_root_created_identity" || "$state_root_created_identity" == "absent" ]]',
    "state cleanup rejects missing or absent identity",
)
require(
    install,
    '[[ -z "$runtime_root_created_identity" || "$runtime_root_created_identity" == "absent" ]]',
    "runtime cleanup rejects missing or absent identity",
)
require(
    install,
    "wait_for_created_directory_identity()",
    "bounded created-directory identity wait",
)
require(
    install,
    'state_root_created_identity="$(wait_for_created_directory_identity /var/lib/apolysis)"',
    "state-root identity captured after creation",
)
require(
    install,
    'runtime_root_created_identity="$(wait_for_created_directory_identity /run/apolysis)"',
    "runtime-root identity captured after creation",
)
require(install, "check-bpf-prereqs.sh\" build", "non-mutating BPF build preflight")
require(install, "check-bpf-prereqs.sh\" live", "non-mutating live-kernel preflight")
require(install, 'bpf_build_prerequisite_status" == "77"', "missing build prerequisite skip")
require(install, 'bpf_live_prerequisite_status" == "77"', "missing live prerequisite skip")
require(install, "systemd-analyze tar uname", "complete release-tool prerequisite preflight")
require(install, "cargo --version", "Cargo toolchain probe")
require(install, "rustc --version", "Rust compiler probe")
require(install, "rustc --print target-libdir", "host Rust target probe")
require(install, "APOLYSIS_REQUIRE_BPF=1 make build-ebpf", "fresh BPF build")
require(install, "./scripts/verify-release-artifacts.sh", "post-package verification")
require(install, "python3 -I -", "isolated inline Python")
require(
    install,
    "cleanup\nif [[ \"$cleanup_attention\" == \"1\" ]]",
    "explicit successful cleanup",
)
require(install, "trap - EXIT HUP INT TERM\nprintf 'local daemon system install qualification: PASS", "PASS after trap removal")
ordered(install, "group_mutation_attempted=1", "groupadd --system apolysis", "group creation")
ordered(install, "install_mutation_attempted=1", "daemon install --bundle", "bundle installation")
ordered(install, "unit_mutation_attempted=1", "enable --now apolysisd.service", "unit activation")
ordered(
    install,
    "enable --now apolysisd.service",
    'state_root_created_identity="$(wait_for_created_directory_identity /var/lib/apolysis)"',
    "state identity after activation",
)
ordered(install, "check-bpf-prereqs.sh\" live", "cargo build --release", "prerequisites before build")
ordered(install, "check-bpf-prereqs.sh\" live", "group_mutation_attempted=1", "prerequisites before mutation")
ordered(install, "package-release-artifacts.sh", "verify-release-artifacts.sh", "package verification")
ordered(install, "verify-release-artifacts.sh", "tar -xzf", "verified archive extraction")
require(install, "initial_main_pid", "shipped-unit initial PID")
require(install, "systemctl kill --signal=KILL --kill-who=main apolysisd.service", "shipped-unit forced restart")
require(install, "restarted_main_pid", "shipped-unit replacement PID")
require(install, "/usr/local/bin/apolysisd-health --require-readiness", "installed restart health gate")
require(install, "--property=Result --value", "graceful stop result")
require(install, "--property=ExecMainCode --value", "graceful stop exit kind")
require(install, "--property=ExecMainStatus --value", "graceful stop exit status")
require(install, 'stop_result" != "success"', "graceful stop success assertion")
require(install, 'stop_main_status" != "0"', "graceful stop zero-status assertion")
require(
    install,
    '"$stop_main_code" != "0" && "$stop_main_code" != "1"',
    "graceful stop accepts only zero or CLD_EXITED code",
)
forbid(install, 'stop_main_code" != "exited"', "non-numeric graceful stop code")
ordered(install, "initial_main_pid", "systemctl kill --signal=KILL", "capture PID before forced failure")
ordered(install, "systemctl kill --signal=KILL", "restart_health", "forced failure before readiness")
ordered(install, "restart_health", "disable --now apolysisd.service", "restart readiness before graceful stop")
ordered(install, "disable --now apolysisd.service", "stop_result", "stop before result assertion")
forbid(install, "systemctl stop apolysisd.service", "unguarded stop fallback")

require(transient, "restart_health", "restart health response")
require(transient, "--require-liveness", "restart health CLI gate")
require(transient, "unit_is_owned", "transient unit ownership proof")
ordered(transient, "current_pid", "restart_health", "new PID then health confirmation")
require(transient, "trap 'exit 130' INT", "interrupt-safe INT trap")
require(transient, "trap 'exit 143' TERM", "interrupt-safe TERM trap")

print("local daemon live gate contract: PASS")
PY

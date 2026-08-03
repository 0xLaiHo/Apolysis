#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: str) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def find_profile(envelope: dict[str, Any], profile_id: str) -> dict[str, Any] | None:
    profiles = envelope.get("profiles", [])
    if not isinstance(profiles, list):
        return None
    return next(
        (
            profile
            for profile in profiles
            if isinstance(profile, dict) and profile.get("id") == profile_id
        ),
        None,
    )


def evaluate(envelope: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if envelope.get("schema_version") != 1:
        reasons.append("envelope.schema_version")
    if evidence.get("schema_version") != 1:
        reasons.append("evidence.schema_version")

    profile = find_profile(envelope, evidence.get("profile"))
    if profile is None:
        return reasons + ["profile"]
    environment = evidence.get("environment")
    measurements = evidence.get("measurements")
    if not isinstance(environment, dict):
        return reasons + ["environment"]
    if not isinstance(measurements, dict):
        return reasons + ["measurements"]

    if environment.get("architecture") not in profile.get("architectures", []):
        reasons.append("environment.architecture")
    kernel_line = ".".join(str(environment.get("kernel_release", "")).split(".")[:2])
    if kernel_line not in profile.get("kernel_lines", []):
        reasons.append("environment.kernel_release")

    required = profile.get("required_environment", {})
    for field in ("btf_vmlinux", "cgroup_v2", "tracepoints_complete"):
        if environment.get(field) is not required.get(field):
            reasons.append(f"environment.{field}")
    if environment.get("capability_mode") not in required.get("capability_modes", []):
        reasons.append("environment.capability_mode")
    if environment.get("runtime") not in required.get("runtimes", []):
        reasons.append("environment.runtime")

    workload = evidence.get("workload")
    budgets = profile.get("workloads", {}).get(workload)
    if not isinstance(budgets, dict):
        return reasons + ["workload"]
    checks = (
        ("samples", "minimum_samples", lambda actual, limit: actual >= limit),
        (
            "collector_cpu_percent_p95",
            "maximum_collector_cpu_percent_p95",
            lambda actual, limit: actual <= limit,
        ),
        (
            "collector_peak_rss_mib",
            "maximum_collector_peak_rss_mib",
            lambda actual, limit: actual <= limit,
        ),
        (
            "workload_latency_overhead_percent_p95",
            "maximum_workload_latency_overhead_percent_p95",
            lambda actual, limit: actual <= limit,
        ),
        (
            "event_loss_count",
            "maximum_event_loss_count",
            lambda actual, limit: actual <= limit,
        ),
    )
    for measurement, budget, predicate in checks:
        actual = measurements.get(measurement)
        limit = budgets.get(budget)
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            reasons.append(f"measurements.{measurement}")
        elif actual < 0:
            reasons.append(f"measurements.{measurement}")
        elif isinstance(limit, bool) or not isinstance(limit, (int, float)):
            reasons.append(f"envelope.{budget}")
        elif not predicate(actual, limit):
            reasons.append(f"measurements.{measurement}")
    return reasons


def main() -> int:
    try:
        envelope = load_json(sys.argv[1])
        evidence = load_json(sys.argv[2])
        reasons = evaluate(envelope, evidence)
    except (IndexError, OSError, ValueError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {"decision": "fail", "reasons": [f"invalid_input:{error}"]},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {"decision": "fail" if reasons else "pass", "reasons": reasons},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 1 if reasons else 0


if __name__ == "__main__":
    raise SystemExit(main())

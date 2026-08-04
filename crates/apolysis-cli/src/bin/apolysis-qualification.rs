// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const TRACEPOINT_MANIFEST: &str =
    include_str!("../../../../qualification/required-tracepoints-v1.txt");
const LOSS_COUNTERS: &[&str] = &[
    "ring_buffer_reserve",
    "map_pressure",
    "pairing",
    "decode",
    "queue",
    "writer",
    "lifecycle_gap",
];
const FLOAT_METRICS: &[(&str, &str, bool)] = &[
    (
        "event_rate_per_second",
        "minimum_event_rate_per_second",
        true,
    ),
    (
        "collector_cpu_percent_p95",
        "maximum_collector_cpu_percent_p95",
        false,
    ),
    (
        "workload_cpu_overhead_percent_p95",
        "maximum_workload_cpu_overhead_percent_p95",
        false,
    ),
    (
        "collector_peak_rss_mib",
        "maximum_collector_peak_rss_mib",
        false,
    ),
    (
        "collector_cgroup_memory_peak_mib",
        "maximum_collector_cgroup_memory_peak_mib",
        false,
    ),
    ("bpf_memory_mib", "maximum_bpf_memory_mib", false),
    (
        "workload_latency_overhead_percent_p95",
        "maximum_workload_latency_overhead_percent_p95",
        false,
    ),
    (
        "observation_lag_ms_p95",
        "maximum_observation_lag_ms_p95",
        false,
    ),
    (
        "observation_lag_ms_p99",
        "maximum_observation_lag_ms_p99",
        false,
    ),
    ("append_lag_ms_p95", "maximum_append_lag_ms_p95", false),
    ("append_lag_ms_p99", "maximum_append_lag_ms_p99", false),
];
const DISTRIBUTION_METRICS: &[&str] = &[
    "observation_lag_ms_p50",
    "observation_lag_ms_max",
    "append_lag_ms_p50",
    "append_lag_ms_max",
];

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let status = match arguments.first().map(String::as_str) {
        Some("check") => check_command(&arguments[1..]),
        Some("capture-preflight") => capture_command(&arguments[1..]),
        _ => {
            eprintln!(
                "usage: apolysis-qualification check <envelope> <evidence> | \
                 capture-preflight <repo-root> <output>"
            );
            2
        }
    };
    process::exit(status);
}

fn check_command(arguments: &[String]) -> i32 {
    if arguments.len() != 2 {
        render_decision("fail", &["invalid_input:expected envelope and evidence"]);
        return 2;
    }
    let envelope = match load_json(Path::new(&arguments[0])) {
        Ok(value) => value,
        Err(error) => {
            render_decision("fail", &[&format!("invalid_input:{error}")]);
            return 2;
        }
    };
    let evidence = match load_json(Path::new(&arguments[1])) {
        Ok(value) => value,
        Err(error) => {
            render_decision("fail", &[&format!("invalid_input:{error}")]);
            return 2;
        }
    };
    let reasons = evaluate(&envelope, &evidence);
    render_decision(if reasons.is_empty() { "pass" } else { "fail" }, &reasons);
    i32::from(!reasons.is_empty())
}

fn load_json(path: &Path) -> Result<Value, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let value: Value = serde_json::from_str(&source)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    if !value.is_object() {
        return Err(format!("{} must contain a JSON object", path.display()));
    }
    Ok(value)
}

fn render_decision(decision: &str, reasons: &[impl AsRef<str>]) {
    let reasons = reasons
        .iter()
        .map(|reason| Value::String(reason.as_ref().to_string()))
        .collect::<Vec<_>>();
    println!("{}", json!({"decision": decision, "reasons": reasons}));
}

fn evaluate(envelope: &Value, evidence: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    require_u64(
        envelope,
        "schema_version",
        1,
        "envelope.schema_version",
        &mut reasons,
    );
    require_u64(
        evidence,
        "schema_version",
        1,
        "evidence.schema_version",
        &mut reasons,
    );

    let Some(profile_id) = evidence.get("profile").and_then(Value::as_str) else {
        reasons.push("profile".to_string());
        return reasons;
    };
    let Some(profile) = envelope
        .get("profiles")
        .and_then(Value::as_array)
        .and_then(|profiles| {
            profiles
                .iter()
                .find(|profile| profile.get("id").and_then(Value::as_str) == Some(profile_id))
        })
    else {
        reasons.push("profile".to_string());
        return reasons;
    };
    if profile.get("status").and_then(Value::as_str) != Some("supported") {
        reasons.push("profile.status".to_string());
    }

    let Some(environment) = evidence.get("environment").and_then(Value::as_object) else {
        reasons.push("environment".to_string());
        return reasons;
    };
    let Some(provenance) = evidence.get("provenance").and_then(Value::as_object) else {
        reasons.push("provenance".to_string());
        return reasons;
    };
    validate_environment(profile, environment, provenance, &mut reasons);
    match profile.get("measurement_protocol") {
        Some(protocol) if protocol.is_object() => {
            if evidence.get("measurement_protocol") != Some(protocol) {
                reasons.push("measurement_protocol".to_string());
            }
        }
        _ => reasons.push("envelope.measurement_protocol".to_string()),
    }

    let Some(workloads) = profile.get("workloads").and_then(Value::as_object) else {
        reasons.push("envelope.workloads".to_string());
        return deduplicate(reasons);
    };
    let Some(results) = evidence.get("results").and_then(Value::as_array) else {
        reasons.push("results".to_string());
        return deduplicate(reasons);
    };
    let mut by_workload = BTreeMap::new();
    let mut duplicate = false;
    for result in results {
        let Some(workload) = result.get("workload").and_then(Value::as_str) else {
            reasons.push("results.workload".to_string());
            continue;
        };
        if by_workload.insert(workload, result).is_some() {
            duplicate = true;
        }
    }
    let expected = workloads
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actual = by_workload.keys().copied().collect::<BTreeSet<_>>();
    if duplicate || actual != expected {
        reasons.push("results.coverage".to_string());
    }
    for (workload, budgets) in workloads {
        if let Some(result) = by_workload.get(workload.as_str()) {
            evaluate_result(workload, budgets, result, &mut reasons);
        }
    }
    deduplicate(reasons)
}

fn validate_environment(
    profile: &Value,
    environment: &Map<String, Value>,
    provenance: &Map<String, Value>,
    reasons: &mut Vec<String>,
) {
    let architecture = environment.get("architecture").and_then(Value::as_str);
    let architectures = profile.get("architectures").and_then(Value::as_array);
    if architecture.is_none()
        || !architectures
            .is_some_and(|values| values.iter().any(|value| value.as_str() == architecture))
    {
        reasons.push("environment.architecture".to_string());
    }
    let kernel_release = environment.get("kernel_release").and_then(Value::as_str);
    let kernel_line = kernel_release.and_then(|release| {
        let mut parts = release.split('.');
        Some(format!("{}.{}", parts.next()?, parts.next()?))
    });
    let kernel_lines = profile.get("kernel_lines").and_then(Value::as_array);
    if kernel_line.as_deref().is_none()
        || !kernel_lines.is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == kernel_line.as_deref())
        })
    {
        reasons.push("environment.kernel_release".to_string());
    }

    let Some(required) = profile
        .get("required_environment")
        .and_then(Value::as_object)
    else {
        reasons.push("envelope.required_environment".to_string());
        return;
    };
    for field in [
        "btf_vmlinux",
        "cgroup_v2",
        "tracepoints_complete",
        "verifier_load_attach",
    ] {
        if required.get(field) != Some(&Value::Bool(true)) {
            reasons.push(format!("envelope.required_environment.{field}"));
        }
        if environment.get(field) != Some(&Value::Bool(true)) {
            reasons.push(format!("environment.{field}"));
        }
    }
    if required
        .get("tracepoint_manifest_version")
        .and_then(Value::as_u64)
        != Some(1)
    {
        reasons.push("envelope.required_environment.tracepoint_manifest_version".to_string());
    }
    if environment
        .get("tracepoint_manifest_version")
        .and_then(Value::as_u64)
        != Some(1)
    {
        reasons.push("environment.tracepoint_manifest_version".to_string());
    }
    validate_membership(
        required,
        environment,
        "capability_modes",
        "capability_mode",
        reasons,
    );
    validate_membership(required, environment, "runtimes", "runtime", reasons);

    let btf_hash = environment
        .get("btf_vmlinux_sha256")
        .and_then(Value::as_str);
    if !btf_hash.is_some_and(is_sha256) {
        reasons.push("environment.btf_vmlinux_sha256".to_string());
    }
    let object_hash = provenance.get("bpf_object_sha256").and_then(Value::as_str);
    if !object_hash.is_some_and(is_sha256) {
        reasons.push("provenance.bpf_object_sha256".to_string());
    }
    let source_commit = provenance.get("source_commit").and_then(Value::as_str);
    if !source_commit.is_some_and(is_git_commit) {
        reasons.push("provenance.source_commit".to_string());
    }
    let cargo_lock_hash = provenance.get("cargo_lock_sha256").and_then(Value::as_str);
    if !cargo_lock_hash.is_some_and(is_sha256) {
        reasons.push("provenance.cargo_lock_sha256".to_string());
    }
    if provenance.get("synthetic_workload_only") != Some(&Value::Bool(true)) {
        reasons.push("provenance.synthetic_workload_only".to_string());
    }
    let format_set_hash = validate_tracepoint_fingerprints(environment, reasons);

    let exact_match = profile
        .get("qualified_tuples")
        .and_then(Value::as_array)
        .is_some_and(|tuples| {
            tuples.iter().any(|tuple| {
                tuple.get("architecture").and_then(Value::as_str) == architecture
                    && tuple.get("kernel_release").and_then(Value::as_str) == kernel_release
                    && tuple.get("btf_vmlinux_sha256").and_then(Value::as_str) == btf_hash
                    && tuple.get("bpf_object_sha256").and_then(Value::as_str) == object_hash
                    && tuple
                        .get("tracepoint_format_set_sha256")
                        .and_then(Value::as_str)
                        == format_set_hash.as_deref()
                    && tuple.get("source_commit").and_then(Value::as_str) == source_commit
                    && tuple.get("cargo_lock_sha256").and_then(Value::as_str) == cargo_lock_hash
            })
        });
    if !exact_match {
        reasons.push("environment.qualified_tuple".to_string());
    }
}

fn validate_membership(
    required: &Map<String, Value>,
    environment: &Map<String, Value>,
    allowed_field: &str,
    actual_field: &str,
    reasons: &mut Vec<String>,
) {
    let actual = environment.get(actual_field).and_then(Value::as_str);
    let valid = required
        .get(allowed_field)
        .and_then(Value::as_array)
        .is_some_and(|allowed| {
            !allowed.is_empty() && allowed.iter().any(|value| value.as_str() == actual)
        });
    if !valid {
        reasons.push(format!("environment.{actual_field}"));
    }
}

fn validate_tracepoint_fingerprints(
    environment: &Map<String, Value>,
    reasons: &mut Vec<String>,
) -> Option<String> {
    let expected = tracepoint_names();
    let Some(actual) = environment
        .get("tracepoint_format_sha256")
        .and_then(Value::as_object)
    else {
        reasons.push("environment.tracepoint_format_sha256".to_string());
        return None;
    };
    let actual_names = actual.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_names = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual_names != expected_names
        || actual
            .values()
            .any(|value| !value.as_str().is_some_and(is_sha256))
    {
        reasons.push("environment.tracepoint_format_sha256".to_string());
        return None;
    }
    let mut digest = Sha256::new();
    for name in expected {
        let fingerprint = actual.get(name).and_then(Value::as_str)?;
        digest.update(format!("{name}={fingerprint}\n"));
    }
    Some(hex_digest(&digest.finalize()))
}

fn evaluate_result(workload: &str, budgets: &Value, result: &Value, reasons: &mut Vec<String>) {
    let prefix = format!("results.{workload}");
    let Some(budgets) = budgets.as_object() else {
        reasons.push(format!("envelope.workloads.{workload}"));
        return;
    };
    let expected_manifest = budgets.get("manifest_sha256").and_then(Value::as_str);
    if !expected_manifest.is_some_and(is_sha256) {
        reasons.push(format!("envelope.workloads.{workload}.manifest_sha256"));
    }
    let manifest = result
        .get("workload_manifest_sha256")
        .and_then(Value::as_str);
    if !manifest.is_some_and(is_sha256) || manifest != expected_manifest {
        reasons.push(format!("{prefix}.workload_manifest_sha256"));
    }
    if !result
        .get("raw_samples_sha256")
        .and_then(Value::as_str)
        .is_some_and(is_sha256)
    {
        reasons.push(format!("{prefix}.raw_samples_sha256"));
    }

    let Some(measurements) = result.get("measurements").and_then(Value::as_object) else {
        reasons.push(format!("{prefix}.measurements"));
        return;
    };
    let samples = measurements.get("samples").and_then(Value::as_u64);
    let minimum_samples = budgets.get("minimum_samples").and_then(Value::as_u64);
    if minimum_samples.is_none() {
        reasons.push(format!("envelope.workloads.{workload}.minimum_samples"));
    }
    if samples.is_none() || minimum_samples.is_some_and(|minimum| samples < Some(minimum)) {
        reasons.push(format!("{prefix}.measurements.samples"));
    }
    for (measurement, budget, is_minimum) in FLOAT_METRICS {
        let actual = finite_nonnegative(measurements.get(*measurement));
        let limit = finite_nonnegative(budgets.get(*budget));
        if limit.is_none() {
            reasons.push(format!("envelope.workloads.{workload}.{budget}"));
        }
        let within = match (actual, limit) {
            (Some(actual), Some(limit)) if *is_minimum => actual >= limit,
            (Some(actual), Some(limit)) => actual <= limit,
            _ => false,
        };
        if !within {
            reasons.push(format!("{prefix}.measurements.{measurement}"));
        }
    }
    for measurement in DISTRIBUTION_METRICS {
        if finite_nonnegative(measurements.get(*measurement)).is_none() {
            reasons.push(format!("{prefix}.measurements.{measurement}"));
        }
    }
    validate_distribution_order(measurements, "observation_lag_ms", &prefix, reasons);
    validate_distribution_order(measurements, "append_lag_ms", &prefix, reasons);
    validate_integrity(workload, budgets, result, reasons);
}

fn validate_distribution_order(
    measurements: &Map<String, Value>,
    family: &str,
    prefix: &str,
    reasons: &mut Vec<String>,
) {
    let values = ["p50", "p95", "p99", "max"]
        .map(|suffix| finite_nonnegative(measurements.get(&format!("{family}_{suffix}"))));
    if let [Some(p50), Some(p95), Some(p99), Some(max)] = values {
        if !(p50 <= p95 && p95 <= p99 && p99 <= max) {
            reasons.push(format!("{prefix}.measurements.{family}_distribution"));
        }
    }
}

fn validate_integrity(
    workload: &str,
    budgets: &Map<String, Value>,
    result: &Value,
    reasons: &mut Vec<String>,
) {
    let prefix = format!("results.{workload}.integrity");
    let Some(integrity) = result.get("integrity").and_then(Value::as_object) else {
        reasons.push(prefix);
        return;
    };
    let expected = event_counts(integrity.get("expected_event_counts"));
    let observed = event_counts(integrity.get("observed_event_counts"));
    let required_expected = event_counts(budgets.get("expected_event_counts"));
    if required_expected.is_none() {
        reasons.push(format!(
            "envelope.workloads.{workload}.expected_event_counts"
        ));
    }
    if expected.is_none() {
        reasons.push(format!("{prefix}.expected_event_counts"));
    }
    if observed.is_none() {
        reasons.push(format!("{prefix}.observed_event_counts"));
    }
    if expected.is_some() && required_expected.is_some() && expected != required_expected {
        reasons.push(format!("{prefix}.expected_event_counts"));
    }
    if required_expected.is_some() && observed.is_some() && required_expected != observed {
        reasons.push(format!("{prefix}.event_reconciliation"));
    }

    let known_loss = integrity
        .get("loss_counters")
        .and_then(Value::as_object)
        .and_then(|counters| {
            let names = counters.keys().map(String::as_str).collect::<BTreeSet<_>>();
            if names != LOSS_COUNTERS.iter().copied().collect::<BTreeSet<_>>() {
                return None;
            }
            LOSS_COUNTERS.iter().try_fold(0_u64, |total, counter| {
                total.checked_add(counters.get(*counter)?.as_u64()?)
            })
        });
    let maximum_known = budgets
        .get("maximum_known_loss_count")
        .and_then(Value::as_u64);
    if maximum_known.is_none() {
        reasons.push(format!(
            "envelope.workloads.{workload}.maximum_known_loss_count"
        ));
    }
    if known_loss.is_none() || maximum_known.is_some_and(|maximum| known_loss > Some(maximum)) {
        reasons.push(format!("{prefix}.known_loss_count"));
    }

    let unexplained = integrity
        .get("unexplained_loss_count")
        .and_then(Value::as_u64);
    let maximum_unexplained = budgets
        .get("maximum_unexplained_loss_count")
        .and_then(Value::as_u64);
    if maximum_unexplained.is_none() {
        reasons.push(format!(
            "envelope.workloads.{workload}.maximum_unexplained_loss_count"
        ));
    }
    if unexplained.is_none()
        || maximum_unexplained.is_some_and(|maximum| unexplained > Some(maximum))
    {
        reasons.push(format!("{prefix}.unexplained_loss_count"));
    }
}

fn event_counts(value: Option<&Value>) -> Option<BTreeMap<String, u64>> {
    value?
        .as_object()?
        .iter()
        .try_fold(BTreeMap::new(), |mut counts, (event_class, count)| {
            counts.insert(event_class.clone(), count.as_u64()?);
            Some(counts)
        })
}

fn require_u64(value: &Value, field: &str, expected: u64, reason: &str, reasons: &mut Vec<String>) {
    if value.get(field).and_then(Value::as_u64) != Some(expected) {
        reasons.push(reason.to_string());
    }
}

fn finite_nonnegative(value: Option<&Value>) -> Option<f64> {
    value?
        .as_f64()
        .filter(|number| number.is_finite() && *number >= 0.0)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_git_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn tracepoint_names() -> Vec<&'static str> {
    TRACEPOINT_MANIFEST
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn deduplicate(reasons: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    reasons
        .into_iter()
        .filter(|reason| seen.insert(reason.clone()))
        .collect()
}

fn capture_command(arguments: &[String]) -> i32 {
    if arguments.len() != 2 {
        eprintln!("capture-preflight requires repo-root and output");
        return 2;
    }
    match capture_preflight(Path::new(&arguments[0]), Path::new(&arguments[1])) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("qualification preflight capture failed: {error}");
            1
        }
    }
}

fn capture_preflight(repo_root: &Path, output: &Path) -> Result<(), String> {
    let tracefs = tracefs_root().ok_or_else(|| "tracefs events are unavailable".to_string())?;
    let fingerprints = tracepoint_names()
        .into_iter()
        .map(|name| {
            let path = tracefs.join("events").join(name).join("format");
            Ok((name.to_string(), Value::String(sha256_path(&path)?)))
        })
        .collect::<Result<Map<String, Value>, String>>()?;
    let source_commit = command_output(
        "git",
        &["-C", &repo_root.display().to_string(), "rev-parse", "HEAD"],
    )?;
    let bpf_object = repo_root.join("target/ebpf/apolysis_observer.bpf.o");
    let measurements = || {
        json!({
            "samples": null,
            "event_rate_per_second": null,
            "collector_cpu_percent_p95": null,
            "workload_cpu_overhead_percent_p95": null,
            "collector_peak_rss_mib": null,
            "collector_cgroup_memory_peak_mib": null,
            "bpf_memory_mib": null,
            "workload_latency_overhead_percent_p95": null,
            "observation_lag_ms_p50": null,
            "observation_lag_ms_p95": null,
            "observation_lag_ms_p99": null,
            "observation_lag_ms_max": null,
            "append_lag_ms_p50": null,
            "append_lag_ms_p95": null,
            "append_lag_ms_p99": null,
            "append_lag_ms_max": null
        })
    };
    let result = |workload: &str| {
        json!({
            "workload": workload,
            "workload_manifest_sha256": null,
            "raw_samples_sha256": null,
            "measurements": measurements(),
            "integrity": {
                "expected_event_counts": null,
                "observed_event_counts": null,
                "loss_counters": null,
                "unexplained_loss_count": null
            }
        })
    };
    let evidence = json!({
        "schema_version": 1,
        "profile": "linux-x86_64-host-managed",
        "environment": {
            "architecture": env::consts::ARCH,
            "kernel_release": fs::read_to_string("/proc/sys/kernel/osrelease")
                .map_err(|error| format!("failed to read kernel release: {error}"))?
                .trim(),
            "btf_vmlinux": true,
            "btf_vmlinux_sha256": sha256_path(Path::new("/sys/kernel/btf/vmlinux"))?,
            "cgroup_v2": Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
            "tracepoints_complete": fingerprints.len() == tracepoint_names().len(),
            "tracepoint_manifest_version": 1,
            "tracepoint_format_sha256": fingerprints,
            "verifier_load_attach": true,
            "capability_mode": effective_capability_mode()?,
            "runtime": "host"
        },
        "provenance": {
            "source_commit": source_commit,
            "bpf_object_sha256": sha256_path(&bpf_object)?,
            "cargo_lock_sha256": sha256_path(&repo_root.join("Cargo.lock"))?,
            "synthetic_workload_only": true,
            "rustc_version": command_output("rustc", &["--version"])?
        },
        "measurement_protocol": {
            "percentile_method": "nearest_rank",
            "interval_method": "bootstrap_percentile_95",
            "bootstrap_resamples": 10000,
            "collector_comparison": "alternating_off_on_same_boot",
            "clock": "clock_monotonic",
            "reject_suspend": true
        },
        "results": [result("idle"), result("representative"), result("burst")]
    });
    let rendered = serde_json::to_string_pretty(&evidence)
        .map_err(|error| format!("failed to serialize evidence: {error}"))?;
    fs::write(output, format!("{rendered}\n"))
        .map_err(|error| format!("failed to write {}: {error}", output.display()))
}

fn sha256_path(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn tracefs_root() -> Option<PathBuf> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join("events").is_dir())
}

fn effective_capability_mode() -> Result<&'static str, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("failed to read capabilities: {error}"))?;
    let cap_hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)
        .ok_or_else(|| "missing CapEff".to_string())?;
    let effective =
        u64::from_str_radix(cap_hex, 16).map_err(|error| format!("invalid CapEff: {error}"))?;
    if effective & (1_u64 << 39) != 0 && effective & (1_u64 << 38) != 0 {
        Ok("bpf_perfmon")
    } else if effective & (1_u64 << 21) != 0 {
        Ok("sys_admin")
    } else {
        Ok("missing")
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("failed to run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| format!("{program} output was not UTF-8: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/qualification")
            .join(name);
        load_json(&path).expect("qualification fixture")
    }

    #[test]
    fn accepts_complete_exact_tuple_bundle() {
        assert!(evaluate(
            &fixture("supported-envelope.json"),
            &fixture("host-managed-pass.json")
        )
        .is_empty());
    }

    #[test]
    fn rejects_candidate_profile_and_unset_budgets() {
        let envelope = load_json(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../qualification/envelope-v1.json"),
        )
        .expect("production envelope");
        let reasons = evaluate(&envelope, &fixture("host-managed-pass.json"));
        assert!(reasons.contains(&"profile.status".to_string()));
        assert!(reasons.contains(&"environment.qualified_tuple".to_string()));
        assert!(reasons
            .iter()
            .any(|reason| reason.starts_with("envelope.workloads.")));
    }

    #[test]
    fn rejects_environment_artifact_and_tracepoint_mismatch() {
        let envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        evidence["environment"]["kernel_release"] = json!("6.12.9-fixture");
        evidence["provenance"]["bpf_object_sha256"] = json!("9".repeat(64));
        evidence["environment"]["tracepoint_format_sha256"]
            .as_object_mut()
            .expect("format map")
            .remove("syscalls/sys_exit_connect");
        let reasons = evaluate(&envelope, &evidence);
        assert!(reasons.contains(&"environment.qualified_tuple".to_string()));
        assert!(reasons.contains(&"environment.tracepoint_format_sha256".to_string()));
    }

    #[test]
    fn rejects_missing_and_duplicate_workload_coverage() {
        let envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        let results = evidence["results"].as_array_mut().expect("results");
        results.pop();
        results.push(results[0].clone());
        assert!(evaluate(&envelope, &evidence).contains(&"results.coverage".to_string()));
    }

    #[test]
    fn rejects_under_sample_over_budget_and_fractional_samples() {
        let envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        evidence["results"][1]["measurements"]["samples"] = json!(9.5);
        evidence["results"][1]["measurements"]["collector_cpu_percent_p95"] = json!(5.1);
        let reasons = evaluate(&envelope, &evidence);
        assert!(reasons.contains(&"results.representative.measurements.samples".to_string()));
        assert!(reasons.contains(
            &"results.representative.measurements.collector_cpu_percent_p95".to_string()
        ));
    }

    #[test]
    fn rejects_known_unexplained_and_reconciled_event_loss() {
        let envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        evidence["results"][1]["integrity"]["loss_counters"]["decode"] = json!(1);
        evidence["results"][1]["integrity"]["unexplained_loss_count"] = json!(1);
        evidence["results"][1]["integrity"]["observed_event_counts"]["file"] = json!(399);
        let reasons = evaluate(&envelope, &evidence);
        assert!(reasons.contains(&"results.representative.integrity.known_loss_count".to_string()));
        assert!(reasons
            .contains(&"results.representative.integrity.unexplained_loss_count".to_string()));
        assert!(
            reasons.contains(&"results.representative.integrity.event_reconciliation".to_string())
        );
    }

    #[test]
    fn rejects_empty_expected_counts_and_measurement_protocol_drift() {
        let envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        evidence["results"][1]["integrity"]["expected_event_counts"] = json!({});
        evidence["results"][1]["integrity"]["observed_event_counts"] = json!({});
        evidence["measurement_protocol"]["interval_method"] = json!("unspecified");
        let reasons = evaluate(&envelope, &evidence);
        assert!(
            reasons.contains(&"results.representative.integrity.expected_event_counts".to_string())
        );
        assert!(
            reasons.contains(&"results.representative.integrity.event_reconciliation".to_string())
        );
        assert!(reasons.contains(&"measurement_protocol".to_string()));
    }

    #[test]
    fn rejects_missing_paired_required_fields_and_invalid_distribution() {
        let mut envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        envelope["profiles"][0]["required_environment"]
            .as_object_mut()
            .expect("required environment")
            .remove("cgroup_v2");
        evidence["environment"]
            .as_object_mut()
            .expect("environment")
            .remove("cgroup_v2");
        evidence["environment"]["tracepoint_manifest_version"] = json!(true);
        evidence["results"][1]["measurements"]["observation_lag_ms_p50"] = json!(30.0);
        let reasons = evaluate(&envelope, &evidence);
        assert!(reasons.contains(&"envelope.required_environment.cgroup_v2".to_string()));
        assert!(reasons.contains(&"environment.cgroup_v2".to_string()));
        assert!(reasons.contains(&"environment.tracepoint_manifest_version".to_string()));
        assert!(reasons.contains(
            &"results.representative.measurements.observation_lag_ms_distribution".to_string()
        ));
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::Duration;

use apolysis_observer::{
    observe_live, AgentRunRequest, LiveObserveRequest, QualificationTelemetryConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

#[path = "apolysis-qualification/summary.rs"]
mod apolysis_qualification_summary;

const TRACEPOINT_MANIFEST: &str =
    include_str!("../../../../qualification/required-tracepoints-v1.txt");
const IDLE_WORKLOAD_MANIFEST: &[u8] =
    include_bytes!("../../../../qualification/workloads/idle-v1.json");
const REPRESENTATIVE_WORKLOAD_MANIFEST: &[u8] =
    include_bytes!("../../../../qualification/workloads/representative-v1.json");
const BURST_WORKLOAD_MANIFEST: &[u8] =
    include_bytes!("../../../../qualification/workloads/burst-v1.json");
const SUSPEND_DETECTION_TOLERANCE_NS: u64 = 100_000_000;
const RATE_PHASE_SETTLE_DURATION: Duration = Duration::from_millis(150);
const QUALIFICATION_RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct WorkloadManifest {
    schema_version: u32,
    id: String,
    #[serde(flatten)]
    kind: WorkloadKind,
    expected_event_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WorkloadKind {
    Idle {
        duration_ms: u64,
    },
    OperationMix {
        iterations: u64,
        operations: Vec<SyntheticOperation>,
    },
    RateSweep {
        operation: SyntheticOperation,
        phases: Vec<RatePhase>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum SyntheticOperation {
    Openat,
    Creat,
    Truncate,
    Renameat2,
    Unlinkat,
    Connect,
    ForkExit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct RatePhase {
    rate_per_second: u64,
    events: u64,
}

#[derive(Clone, Debug)]
struct EmbeddedWorkloadManifest {
    source: &'static [u8],
    value: WorkloadManifest,
}

impl EmbeddedWorkloadManifest {
    fn sha256(&self) -> String {
        hex_digest(&Sha256::digest(self.source))
    }

    fn expected_event_counts(&self) -> BTreeMap<String, u64> {
        self.value.expected_event_counts.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawWorkloadResult {
    schema_version: u32,
    workload: String,
    workload_manifest_sha256: String,
    synthetic_workload_only: bool,
    host_boot_id_sha256: String,
    started_boottime_ns: u64,
    ended_boottime_ns: u64,
    started_monotonic_ns: u64,
    ended_monotonic_ns: u64,
    elapsed_monotonic_ns: u64,
    workload_user_cpu_ns: u64,
    workload_system_cpu_ns: u64,
    workload_self_user_cpu_ns: u64,
    workload_self_system_cpu_ns: u64,
    workload_children_user_cpu_ns: u64,
    workload_children_system_cpu_ns: u64,
    suspend_detected: bool,
    expected_event_counts: BTreeMap<String, u64>,
    completed_event_counts: BTreeMap<String, u64>,
    operation_latency_ns: BTreeMap<SyntheticOperation, Vec<u64>>,
    phases: Vec<RawWorkloadPhase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawWorkloadPhase {
    rate_per_second: Option<u64>,
    started_monotonic_ns: u64,
    ended_monotonic_ns: u64,
    requested_events: u64,
    completed_events: u64,
    elapsed_monotonic_ns: u64,
    expected_event_counts: BTreeMap<String, u64>,
    completed_event_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize)]
struct CapturedTelemetry {
    schema_version: u32,
    clock: String,
    samples: Vec<CapturedTelemetrySample>,
    dropped_samples: u64,
    resource_sample_interval_ns: u64,
    resource_sample_gap_limit_ns: u64,
    resource_sample_max_gap_ns: u64,
    resource_samples: Vec<CapturedResourceSample>,
    loss_samples: Vec<CapturedLossSample>,
    collector_cgroup_isolated: bool,
    bpf_map_memory_bytes: u64,
    bpf_program_memory_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct CapturedTelemetrySample {
    event_name: String,
    kernel_timestamp_ns: u64,
    decoded_monotonic_ns: u64,
    appended_monotonic_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CapturedResourceSample {
    monotonic_ns: u64,
    process_user_cpu_ns: u64,
    process_system_cpu_ns: u64,
    process_rss_bytes: u64,
    process_peak_rss_bytes: u64,
    collector_cgroup_memory_current_bytes: u64,
    collector_cgroup_memory_peak_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CapturedLossSample {
    monotonic_ns: u64,
    loss_counters: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawLivePhase {
    rate_per_second: Option<u64>,
    started_monotonic_ns: u64,
    ended_monotonic_ns: u64,
    expected_event_counts: BTreeMap<String, u64>,
    observed_event_counts: BTreeMap<String, u64>,
    exact_event_reconciliation: bool,
    loss_counters: BTreeMap<String, u64>,
    kernel_to_decode_ns: Vec<u64>,
    kernel_to_append_ns: Vec<u64>,
}

#[cfg(test)]
impl CapturedTelemetrySample {
    fn new(event_name: &str, kernel: u64, decoded: u64, appended: u64) -> Self {
        Self {
            event_name: event_name.to_string(),
            kernel_timestamp_ns: kernel,
            decoded_monotonic_ns: decoded,
            appended_monotonic_ns: appended,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RawLiveTrial {
    schema_version: u32,
    workload: String,
    workload_manifest_sha256: String,
    workload_raw_sha256: String,
    timeline_sha256: String,
    telemetry_sha256: String,
    started_monotonic_ns: u64,
    ended_monotonic_ns: u64,
    suspend_detected: bool,
    expected_event_counts: BTreeMap<String, u64>,
    observed_event_counts: BTreeMap<String, u64>,
    exact_event_reconciliation: bool,
    loss_counters: BTreeMap<String, u64>,
    kernel_to_decode_ns: Vec<u64>,
    kernel_to_append_ns: Vec<u64>,
    telemetry_samples_total: usize,
    telemetry_samples_outside_window: usize,
    resource_sample_interval_ns: u64,
    resource_sample_gap_limit_ns: u64,
    resource_sample_max_gap_ns: u64,
    collector_resource_samples: Vec<CapturedResourceSample>,
    collector_cgroup_isolated: bool,
    bpf_map_memory_bytes: u64,
    bpf_program_memory_bytes: u64,
    phases: Vec<RawLivePhase>,
    collector_lifecycle: Value,
}

struct WorkloadScratch {
    directory: OwnedFd,
    entry_path: CString,
    entry_name: CString,
    renamed_name: CString,
    dev_null: CString,
}

struct QualificationCgroups {
    root: PathBuf,
    collector: PathBuf,
    workload: PathBuf,
    active: bool,
}

#[derive(Clone, Copy)]
struct CpuUsage {
    user_ns: u64,
    system_ns: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let status = match arguments.first().map(String::as_str) {
        Some("check") => check_command(&arguments[1..]),
        Some("capture-preflight") => capture_command(&arguments[1..]),
        Some("run-workload") => run_workload_command(&arguments[1..]),
        Some("measure-off") => measure_off_command(&arguments[1..]),
        Some("measure-live") => measure_live_command(&arguments[1..]),
        Some("measure-live-inner") => measure_live_inner_command(&arguments[1..]).await,
        Some("summarize") => summarize_command(&arguments[1..]),
        _ => {
            eprintln!(
                "usage: apolysis-qualification check <envelope> <evidence> | \
                 capture-preflight <repo-root> <output> | \
                 run-workload <repo-root> <idle|representative|burst> <scratch-dir> <output> | \
                 measure-off <repo-root> <idle|representative|burst> <trial-dir> | \
                 measure-live <repo-root> <bpf-object> \
                 <idle|representative|burst> <trial-dir> | \
                 summarize <repo-root> <measurement-root> <output>"
            );
            2
        }
    };
    process::exit(status);
}

fn summarize_command(arguments: &[String]) -> i32 {
    if arguments.len() != 3 {
        eprintln!("summarize requires repo-root, measurement-root, and output");
        return 2;
    }
    match apolysis_qualification_summary::summarize_measurements(
        Path::new(&arguments[0]),
        Path::new(&arguments[1]),
        Path::new(&arguments[2]),
    ) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("qualification summary failed: {error}");
            1
        }
    }
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
    let measurement_summary_hash = provenance
        .get("measurement_summary_sha256")
        .and_then(Value::as_str);
    if !measurement_summary_hash.is_some_and(is_sha256) {
        reasons.push("provenance.measurement_summary_sha256".to_string());
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

fn run_workload_command(arguments: &[String]) -> i32 {
    if arguments.len() != 4 {
        eprintln!(
            "run-workload requires repo-root, idle|representative|burst, scratch-dir, and output"
        );
        return 2;
    }
    let output = match qualification_output_path(Path::new(&arguments[0]), Path::new(&arguments[3]))
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("qualification workload failed: {error}");
            return 1;
        }
    };
    if let Err(error) = prepare_standalone_workload_identity(Path::new(&arguments[2]), &output) {
        eprintln!("qualification workload failed: {error}");
        return 1;
    }
    match run_workload(
        Path::new(&arguments[0]),
        &arguments[1],
        Path::new(&arguments[2]),
    ) {
        Ok(result) => match serde_json::to_string(&result) {
            Ok(rendered) => match write_new_private(&output, format!("{rendered}\n").as_bytes()) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("failed to write raw workload result: {error}");
                    1
                }
            },
            Err(error) => {
                eprintln!("failed to serialize raw workload result: {error}");
                1
            }
        },
        Err(error) => {
            eprintln!("qualification workload failed: {error}");
            1
        }
    }
}

fn qualification_output_path(repo_root: &Path, output: &Path) -> Result<PathBuf, String> {
    let repo_root = repo_root
        .canonicalize()
        .map_err(|error| format!("failed to resolve repo root: {error}"))?;
    let qualification_root = repo_root
        .join("target/qualification")
        .canonicalize()
        .map_err(|error| format!("failed to resolve target/qualification: {error}"))?;
    let parent = output
        .parent()
        .ok_or_else(|| "qualification output must have a parent directory".to_string())?
        .canonicalize()
        .map_err(|error| format!("failed to resolve qualification output parent: {error}"))?;
    if parent == qualification_root || !parent.starts_with(&qualification_root) {
        return Err("qualification output must be below a trial directory".to_string());
    }
    let name = output
        .file_name()
        .ok_or_else(|| "qualification output must name a file".to_string())?;
    Ok(parent.join(name))
}

fn write_new_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist {}: {error}", path.display()))
}

fn prepare_standalone_workload_identity(scratch_dir: &Path, output: &Path) -> Result<(), String> {
    // Managed launch restores SUDO_UID/GID. Mirror that identity for the
    // collector-off arm so only collection changes inside the timed window.
    // Both arms inherit the invoking shell's cgroup.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let Some(uid_text) = env::var("SUDO_UID").ok() else {
        return Ok(());
    };
    let uid = uid_text
        .parse::<u32>()
        .map_err(|error| format!("invalid SUDO_UID: {error}"))?;
    if uid == 0 {
        return Ok(());
    }
    let gid = env::var("SUDO_GID")
        .map_err(|_| "SUDO_UID is set but SUDO_GID is unavailable".to_string())?
        .parse::<u32>()
        .map_err(|error| format!("invalid SUDO_GID: {error}"))?;
    let output_parent = output
        .parent()
        .ok_or_else(|| "qualification output must have a parent".to_string())?;
    chown_paths_to_operator(&[output_parent, scratch_dir], uid, gid)?;
    // SAFETY: this command has not started worker threads, and the numeric IDs
    // came from sudo's identity variables.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setgid(gid) } != 0
        || unsafe { libc::setuid(uid) } != 0
    {
        return Err(format!(
            "failed to restore qualification workload identity: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn measure_live_command(arguments: &[String]) -> i32 {
    if arguments.len() != 4 {
        eprintln!(
            "measure-live requires repo-root, production BPF object, workload, and trial-dir"
        );
        return 2;
    }
    match measure_live_supervised(
        Path::new(&arguments[0]),
        Path::new(&arguments[1]),
        &arguments[2],
        Path::new(&arguments[3]),
    ) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("live qualification measurement failed: {error}");
            1
        }
    }
}

async fn measure_live_inner_command(arguments: &[String]) -> i32 {
    if arguments.len() != 6 {
        eprintln!("internal live measurement contract mismatch");
        return 2;
    }
    match measure_live_trial(
        Path::new(&arguments[0]),
        Path::new(&arguments[1]),
        &arguments[2],
        Path::new(&arguments[3]),
        Path::new(&arguments[4]),
        Path::new(&arguments[5]),
    )
    .await
    {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("inner live qualification measurement failed: {error}");
            1
        }
    }
}

fn measure_live_supervised(
    repo_root: &Path,
    object_path: &Path,
    workload_id: &str,
    trial_dir: &Path,
) -> Result<(), String> {
    let (repo_root, trial_dir) = resolve_empty_trial(repo_root, trial_dir, "live")?;
    let object_path = resolve_production_object(&repo_root, object_path)?;
    workload_manifest(workload_id)?;
    let mut cgroups = QualificationCgroups::create()?;
    let run = (|| {
        let cgroup_fd = fs::OpenOptions::new()
            .write(true)
            .open(cgroups.collector.join("cgroup.procs"))
            .map_err(|error| format!("failed to open qualification collector cgroup: {error}"))?;
        let qualification_binary = env::current_exe()
            .map_err(|error| format!("failed to resolve qualification binary: {error}"))?;
        let mut command = Command::new(qualification_binary);
        command
            .arg("measure-live-inner")
            .arg(&repo_root)
            .arg(&object_path)
            .arg(workload_id)
            .arg(&trial_dir)
            .arg(&cgroups.collector)
            .arg(&cgroups.workload);
        // SAFETY: only async-signal-safe getpid/write calls run after fork,
        // before the fresh collector image is exec'd in its own cgroup.
        unsafe {
            command.pre_exec(move || write_self_pid_to_cgroup(cgroup_fd.as_raw_fd()));
        }
        let status = command
            .status()
            .map_err(|error| format!("failed to start cgroup-isolated live collector: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "cgroup-isolated live collector exited with {status}"
            ))
        }
    })();
    let cleanup = cgroups.finish();
    finish_qualification_cgroups(run, cleanup)
}

fn measure_off_command(arguments: &[String]) -> i32 {
    if arguments.len() != 3 {
        eprintln!("measure-off requires repo-root, workload, and trial-dir");
        return 2;
    }
    match measure_off_trial(
        Path::new(&arguments[0]),
        &arguments[1],
        Path::new(&arguments[2]),
    ) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("collector-off qualification measurement failed: {error}");
            1
        }
    }
}

fn measure_off_trial(repo_root: &Path, workload_id: &str, trial_dir: &Path) -> Result<(), String> {
    let (repo_root, trial_dir) = resolve_empty_trial(repo_root, trial_dir, "collector-off")?;
    workload_manifest(workload_id)?;
    let workload_dir = trial_dir.join("workload");
    fs::create_dir(&workload_dir)
        .map_err(|error| format!("failed to create workload directory: {error}"))?;
    let scratch_dir = workload_dir.join("scratch");
    fs::create_dir(&scratch_dir)
        .map_err(|error| format!("failed to create workload scratch: {error}"))?;
    allow_managed_workload_access(&workload_dir, &scratch_dir)?;
    let workload_output = workload_dir.join("workload-raw.json");
    let mut cgroups = QualificationCgroups::create()?;
    let run = (|| {
        let qualification_binary = env::current_exe()
            .map_err(|error| format!("failed to resolve qualification binary: {error}"))?;
        let cgroup_fd = fs::OpenOptions::new()
            .write(true)
            .open(cgroups.workload.join("cgroup.procs"))
            .map_err(|error| format!("failed to open qualification workload cgroup: {error}"))?;
        let mut command = Command::new(qualification_binary);
        command.args([
            "run-workload",
            repo_root
                .to_str()
                .ok_or_else(|| "repo root is not valid UTF-8".to_string())?,
            workload_id,
            scratch_dir
                .to_str()
                .ok_or_else(|| "workload scratch is not valid UTF-8".to_string())?,
            workload_output
                .to_str()
                .ok_or_else(|| "workload output is not valid UTF-8".to_string())?,
        ]);
        // SAFETY: only async-signal-safe getpid/write calls run after fork.
        unsafe {
            command.pre_exec(move || write_self_pid_to_cgroup(cgroup_fd.as_raw_fd()));
        }
        let status = command
            .status()
            .map_err(|error| format!("failed to start collector-off workload: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("collector-off workload exited with {status}"))
        }
    })();
    let cleanup = cgroups.finish();
    finish_qualification_cgroups(run, cleanup)
}

fn finish_qualification_cgroups(
    run: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (run, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(format!("cgroup cleanup failed: {cleanup_error}")),
        (Err(error), Err(cleanup_error)) => {
            Err(format!("{error}; cgroup cleanup failed: {cleanup_error}"))
        }
    }
}

async fn measure_live_trial(
    repo_root: &Path,
    object_path: &Path,
    workload_id: &str,
    trial_dir: &Path,
    collector_cgroup: &Path,
    workload_cgroup: &Path,
) -> Result<(), String> {
    let (repo_root, trial_dir) = resolve_empty_trial(repo_root, trial_dir, "live")?;
    let object_path = resolve_production_object(&repo_root, object_path)?;
    let (collector_cgroup, workload_cgroup) =
        resolve_isolated_cgroups(collector_cgroup, workload_cgroup)?;

    let workload_manifest = workload_manifest(workload_id)?;
    let workload_dir = trial_dir.join("workload");
    fs::create_dir(&workload_dir)
        .map_err(|error| format!("failed to create workload directory: {error}"))?;
    let scratch_dir = workload_dir.join("scratch");
    fs::create_dir(&scratch_dir)
        .map_err(|error| format!("failed to create workload scratch: {error}"))?;
    allow_managed_workload_access(&workload_dir, &scratch_dir)?;
    let workload_output = workload_dir.join("workload-raw.json");
    let timeline_output = trial_dir.join("timeline.jsonl");
    let telemetry_output = trial_dir.join("kernel-latency-raw.json");
    let live_trial_output = trial_dir.join("live-trial-raw.json");
    let qualification_binary = env::current_exe()
        .map_err(|error| format!("failed to resolve qualification binary: {error}"))?;
    let agent_run = AgentRunRequest::new(
        "qualification",
        vec![
            qualification_binary.display().to_string(),
            "run-workload".to_string(),
            repo_root.display().to_string(),
            workload_id.to_string(),
            scratch_dir.display().to_string(),
            workload_output.display().to_string(),
        ],
    )?;
    let expected_samples = workload_manifest
        .value
        .expected_event_counts
        .values()
        .copied()
        .sum::<u64>();
    let max_samples = usize::try_from(expected_samples.saturating_add(8_192))
        .map_err(|_| "qualification telemetry sample bound exceeds usize".to_string())?;
    let result = observe_live(LiveObserveRequest {
        object_path,
        output_path: timeline_output.clone(),
        session_id: format!("qualification-{workload_id}-{}", process::id()),
        scope: None,
        agent_run: Some(agent_run),
        agent_registration_path: None,
        agent_discovery: None,
        duration: None,
        workspace_root: repo_root.clone(),
        output_rotation: None,
        qualification_telemetry: Some(QualificationTelemetryConfig {
            output_path: telemetry_output.clone(),
            max_samples,
            resource_sample_interval: QUALIFICATION_RESOURCE_SAMPLE_INTERVAL,
            collector_cgroup_path: collector_cgroup,
            managed_agent_cgroup_path: workload_cgroup,
        }),
    })
    .await?;
    if result.agent_exit_code != Some(0) {
        return Err(format!(
            "managed qualification workload exited with {:?}",
            result.agent_exit_code
        ));
    }

    let workload: RawWorkloadResult = load_typed_json(&workload_output)?;
    let telemetry: CapturedTelemetry = load_typed_json(&telemetry_output)?;
    let collector_lifecycle = terminal_collector_lifecycle(&timeline_output)?;
    let workload_raw_sha256 = sha256_path(&workload_output)?;
    let timeline_sha256 = sha256_path(&timeline_output)?;
    let telemetry_sha256 = sha256_path(&telemetry_output)?;
    let trial = assemble_live_trial(
        workload,
        telemetry,
        collector_lifecycle,
        workload_raw_sha256,
        timeline_sha256,
        telemetry_sha256,
    )?;
    let rendered = serde_json::to_string(&trial)
        .map_err(|error| format!("failed to serialize raw live trial: {error}"))?;
    write_new_private(&live_trial_output, format!("{rendered}\n").as_bytes())
}

fn resolve_production_object(repo_root: &Path, object_path: &Path) -> Result<PathBuf, String> {
    let production_object = repo_root
        .join("target/ebpf/apolysis_observer.bpf.o")
        .canonicalize()
        .map_err(|error| format!("failed to resolve production BPF object: {error}"))?;
    let object_path = object_path
        .canonicalize()
        .map_err(|error| format!("failed to resolve requested BPF object: {error}"))?;
    if object_path != production_object {
        return Err("measure-live requires the production BPF object".to_string());
    }
    Ok(object_path)
}

fn resolve_isolated_cgroups(
    collector: &Path,
    workload: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    let mount = Path::new("/sys/fs/cgroup")
        .canonicalize()
        .map_err(|error| format!("failed to resolve cgroup v2 mount: {error}"))?;
    let collector = collector
        .canonicalize()
        .map_err(|error| format!("failed to resolve collector cgroup: {error}"))?;
    let workload = workload
        .canonicalize()
        .map_err(|error| format!("failed to resolve workload cgroup: {error}"))?;
    let shared_parent = collector.parent().filter(|parent| {
        workload.parent() == Some(*parent)
            && parent
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("apolysis-qualification-"))
    });
    if !collector.starts_with(&mount)
        || !workload.starts_with(&mount)
        || collector.file_name().and_then(|name| name.to_str()) != Some("collector")
        || workload.file_name().and_then(|name| name.to_str()) != Some("workload")
        || shared_parent.is_none()
    {
        return Err("qualification collector/workload cgroup contract mismatch".to_string());
    }
    let current = current_cgroup_path(&mount)?;
    if current != collector {
        return Err("qualification collector was not exec'd in its isolated cgroup".to_string());
    }
    let collector_pids = read_cgroup_pids(&collector)?;
    if collector_pids != vec![process::id()] || !read_cgroup_pids(&workload)?.is_empty() {
        return Err("qualification cgroups were populated before collector startup".to_string());
    }
    for required in [
        collector.join("memory.current"),
        collector.join("memory.peak"),
        workload.join("cgroup.procs"),
    ] {
        if !required.is_file() {
            return Err(format!(
                "qualification cgroup controller file is unavailable: {}",
                required.display()
            ));
        }
    }
    Ok((collector, workload))
}

fn read_cgroup_pids(cgroup: &Path) -> Result<Vec<u32>, String> {
    let source = fs::read_to_string(cgroup.join("cgroup.procs"))
        .map_err(|error| format!("failed to read {} cgroup.procs: {error}", cgroup.display()))?;
    let mut pids = source
        .lines()
        .map(|line| {
            line.parse::<u32>()
                .map_err(|error| format!("invalid cgroup PID {line}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    pids.sort_unstable();
    Ok(pids)
}

fn current_cgroup_path(mount: &Path) -> Result<PathBuf, String> {
    let relative = current_cgroup_relative_path()?;
    mount
        .join(relative.strip_prefix(Path::new("/")).unwrap_or(&relative))
        .canonicalize()
        .map_err(|error| format!("failed to resolve current cgroup: {error}"))
}

fn resolve_empty_trial(
    repo_root: &Path,
    trial_dir: &Path,
    kind: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let repo_root = repo_root
        .canonicalize()
        .map_err(|error| format!("failed to resolve repo root: {error}"))?;
    let qualification_root = repo_root
        .join("target/qualification")
        .canonicalize()
        .map_err(|error| format!("failed to resolve target/qualification: {error}"))?;
    let trial_dir = trial_dir
        .canonicalize()
        .map_err(|error| format!("failed to resolve {kind} trial directory: {error}"))?;
    if trial_dir == qualification_root || !trial_dir.starts_with(&qualification_root) {
        return Err(format!(
            "{kind} trial must be a child of target/qualification"
        ));
    }
    if fs::read_dir(&trial_dir)
        .map_err(|error| format!("failed to inspect {kind} trial directory: {error}"))?
        .next()
        .is_some()
    {
        return Err(format!("{kind} trial directory must be empty"));
    }
    Ok((repo_root, trial_dir))
}

impl QualificationCgroups {
    fn create() -> Result<Self, String> {
        let mount = Path::new("/sys/fs/cgroup");
        if !mount.join("cgroup.controllers").is_file() {
            return Err("qualification requires a unified cgroup v2 mount".to_string());
        }
        let relative = current_cgroup_relative_path()?;
        let parent = mount.join(relative.strip_prefix(Path::new("/")).unwrap_or(&relative));
        let parent = parent
            .canonicalize()
            .map_err(|error| format!("failed to resolve current cgroup: {error}"))?;
        let mount = mount
            .canonicalize()
            .map_err(|error| format!("failed to resolve cgroup v2 mount: {error}"))?;
        if !parent.starts_with(&mount) {
            return Err("current cgroup escaped the cgroup v2 mount".to_string());
        }
        let nonce = clock_ns(libc::CLOCK_MONOTONIC)?;
        let root = parent.join(format!("apolysis-qualification-{}-{nonce}", process::id()));
        let collector = root.join("collector");
        let workload = root.join("workload");
        fs::create_dir(&root).map_err(|error| {
            format!(
                "failed to create qualification cgroup {}: {error}",
                root.display()
            )
        })?;
        let mut guard = Self {
            root,
            collector,
            workload,
            active: true,
        };
        let setup = (|| {
            let controllers = fs::read_to_string(guard.root.join("cgroup.controllers"))
                .map_err(|error| format!("failed to read delegated cgroup controllers: {error}"))?;
            if !controllers
                .split_whitespace()
                .any(|controller| controller == "memory")
            {
                return Err(
                    "qualification requires a delegated cgroup v2 memory controller".to_string(),
                );
            }
            fs::write(guard.root.join("cgroup.subtree_control"), "+memory").map_err(|error| {
                format!("failed to enable qualification memory controller: {error}")
            })?;
            fs::create_dir(&guard.collector).map_err(|error| {
                format!("failed to create collector qualification cgroup: {error}")
            })?;
            fs::create_dir(&guard.workload).map_err(|error| {
                format!("failed to create workload qualification cgroup: {error}")
            })?;
            for required in [
                guard.collector.join("cgroup.procs"),
                guard.collector.join("memory.current"),
                guard.collector.join("memory.peak"),
                guard.workload.join("cgroup.procs"),
            ] {
                if !required.is_file() {
                    return Err(format!(
                        "qualification cgroup controller file is unavailable: {}",
                        required.display()
                    ));
                }
            }
            Ok(())
        })();
        if let Err(error) = setup {
            let cleanup = guard.finish();
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => format!("{error}; cleanup failed: {cleanup_error}"),
            });
        }
        Ok(guard)
    }

    fn finish(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let mut errors = Vec::new();
        for path in [&self.workload, &self.collector, &self.root] {
            if let Err(error) = fs::remove_dir(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    errors.push(format!(
                        "failed to remove qualification cgroup {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        if errors.is_empty() {
            self.active = false;
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for QualificationCgroups {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn current_cgroup_relative_path() -> Result<PathBuf, String> {
    let source = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("failed to read current cgroup: {error}"))?;
    let path = source
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "current process has no unified cgroup v2 membership".to_string())?;
    if !path.starts_with('/') || path.contains("/../") || path.ends_with("/..") {
        return Err("current cgroup v2 membership path is invalid".to_string());
    }
    Ok(PathBuf::from(path))
}

fn write_self_pid_to_cgroup(fd: libc::c_int) -> std::io::Result<()> {
    let mut pid = unsafe { libc::getpid() } as u32;
    let mut buffer = [0_u8; 11];
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    let mut written = 0;
    let bytes = &buffer[start..];
    while written < bytes.len() {
        let status =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if status < 0 {
            return Err(std::io::Error::last_os_error());
        }
        written += status as usize;
    }
    Ok(())
}

fn allow_managed_workload_access(workload_dir: &Path, scratch_dir: &Path) -> Result<(), String> {
    // The production managed-launch path intentionally restores the invoking
    // user under sudo. Keep the privileged trial root private and give that
    // user only the synthetic workload/result subdirectory.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let Some(uid) = env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
    else {
        return Ok(());
    };
    let gid = env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| "SUDO_UID is set but SUDO_GID is unavailable".to_string())?;
    chown_paths_to_operator(&[workload_dir, scratch_dir], uid, gid)
}

fn chown_paths_to_operator(paths: &[&Path], uid: u32, gid: u32) -> Result<(), String> {
    for path in paths {
        let path = path_c_string(path)?;
        // SAFETY: path is valid and each caller bounds it to qualification
        // output directories resolved below target/qualification.
        if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
            return Err(format!(
                "failed to grant managed workload trial access: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn load_typed_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let source =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&source)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

fn terminal_collector_lifecycle(timeline: &Path) -> Result<Value, String> {
    let source = fs::read_to_string(timeline)
        .map_err(|error| format!("failed to read {}: {error}", timeline.display()))?;
    let mut terminal = None;
    for (index, line) in source.lines().enumerate() {
        let record: Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "failed to parse {} line {}: {error}",
                timeline.display(),
                index + 1
            )
        })?;
        if record.get("record_type").and_then(Value::as_str) == Some("collector_lifecycle")
            && matches!(
                record.get("state").and_then(Value::as_str),
                Some("stopped" | "failed")
            )
        {
            terminal = Some(record);
        }
    }
    terminal.ok_or_else(|| "timeline has no terminal collector lifecycle".to_string())
}

fn workload_manifest(id: &str) -> Result<EmbeddedWorkloadManifest, String> {
    let source = match id {
        "idle" => IDLE_WORKLOAD_MANIFEST,
        "representative" => REPRESENTATIVE_WORKLOAD_MANIFEST,
        "burst" => BURST_WORKLOAD_MANIFEST,
        _ => return Err(format!("unknown qualification workload: {id}")),
    };
    let value: WorkloadManifest = serde_json::from_slice(source)
        .map_err(|error| format!("invalid embedded {id} workload manifest: {error}"))?;
    validate_workload_manifest(id, &value)?;
    Ok(EmbeddedWorkloadManifest { source, value })
}

fn validate_workload_manifest(id: &str, manifest: &WorkloadManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err(format!("{id} workload manifest schema must be 1"));
    }
    if manifest.id != id {
        return Err(format!(
            "workload manifest id mismatch: expected {id}, found {}",
            manifest.id
        ));
    }

    let mut calculated = BTreeMap::new();
    match &manifest.kind {
        WorkloadKind::Idle { duration_ms } => {
            if *duration_ms == 0 {
                return Err("idle workload duration must be positive".to_string());
            }
        }
        WorkloadKind::OperationMix {
            iterations,
            operations,
        } => {
            if *iterations == 0 || operations.is_empty() {
                return Err(
                    "operation_mix workload requires positive iterations and operations"
                        .to_string(),
                );
            }
            for operation in operations {
                operation.add_expected_events(*iterations, &mut calculated);
            }
        }
        WorkloadKind::RateSweep { operation, phases } => {
            if phases.is_empty() {
                return Err("rate_sweep workload requires at least one phase".to_string());
            }
            for phase in phases {
                if phase.rate_per_second == 0 || phase.events == 0 {
                    return Err(
                        "rate_sweep phases require positive rates and event counts".to_string()
                    );
                }
                operation.add_expected_events(phase.events, &mut calculated);
            }
        }
    }
    if calculated != manifest.expected_event_counts {
        return Err(format!(
            "{id} expected event counts do not match the declared operations"
        ));
    }
    Ok(())
}

impl SyntheticOperation {
    fn add_expected_events(self, count: u64, counts: &mut BTreeMap<String, u64>) {
        let mut add = |event: &str| {
            let total = counts.entry(event.to_string()).or_default();
            *total = total.saturating_add(count);
        };
        match self {
            Self::Openat => add("openat"),
            Self::Creat => add("creat"),
            Self::Truncate => add("truncate"),
            Self::Renameat2 => add("renameat2"),
            Self::Unlinkat => add("unlinkat"),
            Self::Connect => add("connect"),
            Self::ForkExit => {
                add("sched_process_fork");
                add("sched_process_exit");
            }
        }
    }
}

fn run_workload(
    repo_root: &Path,
    id: &str,
    scratch_dir: &Path,
) -> Result<RawWorkloadResult, String> {
    let manifest = workload_manifest(id)?;
    let scratch = WorkloadScratch::prepare(repo_root, scratch_dir)?;
    scratch.remove_stale_entries()?;

    let started_boottime_ns = clock_ns(libc::CLOCK_BOOTTIME)?;
    let started_monotonic_ns = clock_ns(libc::CLOCK_MONOTONIC)?;
    let started_self_cpu = cpu_usage(libc::RUSAGE_SELF)?;
    let started_children_cpu = cpu_usage(libc::RUSAGE_CHILDREN)?;
    let mut completed_event_counts = BTreeMap::new();
    let mut operation_latency_ns = BTreeMap::new();
    let mut phases = Vec::new();

    match &manifest.value.kind {
        WorkloadKind::Idle { duration_ms } => {
            let phase_start = clock_ns(libc::CLOCK_MONOTONIC)?;
            std::thread::sleep(Duration::from_millis(*duration_ms));
            let phase_end = clock_ns(libc::CLOCK_MONOTONIC)?;
            phases.push(RawWorkloadPhase {
                rate_per_second: None,
                started_monotonic_ns: phase_start,
                ended_monotonic_ns: phase_end,
                requested_events: 0,
                completed_events: 0,
                elapsed_monotonic_ns: phase_end.saturating_sub(phase_start),
                expected_event_counts: BTreeMap::new(),
                completed_event_counts: BTreeMap::new(),
            });
        }
        WorkloadKind::OperationMix {
            iterations,
            operations,
        } => {
            let phase_start = clock_ns(libc::CLOCK_MONOTONIC)?;
            for _ in 0..*iterations {
                for operation in operations {
                    execute_measured_operation(
                        *operation,
                        &scratch,
                        &mut completed_event_counts,
                        &mut operation_latency_ns,
                    )?;
                }
            }
            let phase_end = clock_ns(libc::CLOCK_MONOTONIC)?;
            phases.push(RawWorkloadPhase {
                rate_per_second: None,
                started_monotonic_ns: phase_start,
                ended_monotonic_ns: phase_end,
                requested_events: manifest.value.expected_event_counts.values().sum(),
                completed_events: completed_event_counts.values().sum(),
                elapsed_monotonic_ns: phase_end.saturating_sub(phase_start),
                expected_event_counts: manifest.value.expected_event_counts.clone(),
                completed_event_counts: completed_event_counts.clone(),
            });
        }
        WorkloadKind::RateSweep {
            operation,
            phases: plan,
        } => {
            for (phase_index, phase) in plan.iter().enumerate() {
                let phase_start = clock_ns(libc::CLOCK_MONOTONIC)?;
                let interval_ns = 1_000_000_000_u64 / phase.rate_per_second;
                for event_index in 0..phase.events {
                    if event_index > 0 {
                        sleep_until_monotonic(
                            phase_start.saturating_add(interval_ns.saturating_mul(event_index)),
                        )?;
                    }
                    execute_measured_operation(
                        *operation,
                        &scratch,
                        &mut completed_event_counts,
                        &mut operation_latency_ns,
                    )?;
                }
                let phase_end = clock_ns(libc::CLOCK_MONOTONIC)?;
                let mut phase_event_counts = BTreeMap::new();
                operation.add_expected_events(phase.events, &mut phase_event_counts);
                phases.push(RawWorkloadPhase {
                    rate_per_second: Some(phase.rate_per_second),
                    started_monotonic_ns: phase_start,
                    ended_monotonic_ns: phase_end,
                    requested_events: phase.events,
                    completed_events: phase.events,
                    elapsed_monotonic_ns: phase_end.saturating_sub(phase_start),
                    expected_event_counts: phase_event_counts.clone(),
                    completed_event_counts: phase_event_counts,
                });
                if phase_index + 1 < plan.len() {
                    std::thread::sleep(RATE_PHASE_SETTLE_DURATION);
                }
            }
        }
    }

    let ended_self_cpu = cpu_usage(libc::RUSAGE_SELF)?;
    let ended_children_cpu = cpu_usage(libc::RUSAGE_CHILDREN)?;
    let ended_monotonic_ns = clock_ns(libc::CLOCK_MONOTONIC)?;
    let ended_boottime_ns = clock_ns(libc::CLOCK_BOOTTIME)?;
    let elapsed_monotonic_ns = ended_monotonic_ns.saturating_sub(started_monotonic_ns);
    let elapsed_boottime_ns = ended_boottime_ns.saturating_sub(started_boottime_ns);
    let suspend_detected =
        elapsed_boottime_ns > elapsed_monotonic_ns.saturating_add(SUSPEND_DETECTION_TOLERANCE_NS);
    if suspend_detected {
        return Err(format!("{id} workload crossed a host suspend boundary"));
    }
    if completed_event_counts != manifest.value.expected_event_counts {
        return Err(format!(
            "{id} completed event counts do not match its versioned manifest"
        ));
    }

    let self_user_cpu_ns = ended_self_cpu
        .user_ns
        .saturating_sub(started_self_cpu.user_ns);
    let self_system_cpu_ns = ended_self_cpu
        .system_ns
        .saturating_sub(started_self_cpu.system_ns);
    let children_user_cpu_ns = ended_children_cpu
        .user_ns
        .saturating_sub(started_children_cpu.user_ns);
    let children_system_cpu_ns = ended_children_cpu
        .system_ns
        .saturating_sub(started_children_cpu.system_ns);
    Ok(RawWorkloadResult {
        schema_version: 1,
        workload: id.to_string(),
        workload_manifest_sha256: manifest.sha256(),
        synthetic_workload_only: true,
        host_boot_id_sha256: host_boot_id_sha256()?,
        started_boottime_ns,
        ended_boottime_ns,
        started_monotonic_ns,
        ended_monotonic_ns,
        elapsed_monotonic_ns,
        workload_user_cpu_ns: self_user_cpu_ns.saturating_add(children_user_cpu_ns),
        workload_system_cpu_ns: self_system_cpu_ns.saturating_add(children_system_cpu_ns),
        workload_self_user_cpu_ns: self_user_cpu_ns,
        workload_self_system_cpu_ns: self_system_cpu_ns,
        workload_children_user_cpu_ns: children_user_cpu_ns,
        workload_children_system_cpu_ns: children_system_cpu_ns,
        suspend_detected: false,
        expected_event_counts: manifest.value.expected_event_counts,
        completed_event_counts,
        operation_latency_ns,
        phases,
    })
}

fn host_boot_id_sha256() -> Result<String, String> {
    let source = fs::read("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("failed to read host boot identity: {error}"))?;
    Ok(hex_digest(&Sha256::digest(source)))
}

fn assemble_live_trial(
    workload: RawWorkloadResult,
    telemetry: CapturedTelemetry,
    collector_lifecycle: Value,
    workload_raw_sha256: String,
    timeline_sha256: String,
    telemetry_sha256: String,
) -> Result<RawLiveTrial, String> {
    if workload.suspend_detected {
        return Err("qualification workload crossed a host suspend boundary".to_string());
    }
    if telemetry.schema_version != 1 || telemetry.clock != "clock_monotonic" {
        return Err("qualification telemetry contract mismatch".to_string());
    }
    if telemetry.resource_sample_interval_ns == 0
        || telemetry.resource_sample_gap_limit_ns
            != telemetry.resource_sample_interval_ns.saturating_mul(4)
        || telemetry.resource_sample_max_gap_ns > telemetry.resource_sample_gap_limit_ns
        || !telemetry.collector_cgroup_isolated
    {
        return Err("qualification resource telemetry is not isolated".to_string());
    }
    let actual_max_gap = telemetry
        .resource_samples
        .windows(2)
        .map(|pair| pair[1].monotonic_ns.saturating_sub(pair[0].monotonic_ns))
        .max()
        .unwrap_or(0);
    if actual_max_gap != telemetry.resource_sample_max_gap_ns {
        return Err("qualification resource sample gap metadata mismatch".to_string());
    }
    if telemetry.loss_samples.len() != telemetry.resource_samples.len()
        || telemetry
            .loss_samples
            .iter()
            .zip(&telemetry.resource_samples)
            .any(|(loss, resource)| {
                loss.monotonic_ns != resource.monotonic_ns
                    || loss
                        .loss_counters
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>()
                        != LOSS_COUNTERS.iter().copied().collect::<BTreeSet<_>>()
            })
    {
        return Err("qualification loss sample contract mismatch".to_string());
    }
    if telemetry.loss_samples.windows(2).any(|samples| {
        LOSS_COUNTERS
            .iter()
            .any(|name| samples[0].loss_counters.get(*name) > samples[1].loss_counters.get(*name))
    }) {
        return Err("qualification loss counters regressed between samples".to_string());
    }
    if telemetry.resource_samples.windows(2).any(|pair| {
        pair[0].monotonic_ns >= pair[1].monotonic_ns
            || pair[0].process_user_cpu_ns > pair[1].process_user_cpu_ns
            || pair[0].process_system_cpu_ns > pair[1].process_system_cpu_ns
            || pair[0].process_peak_rss_bytes > pair[1].process_peak_rss_bytes
            || pair[0].collector_cgroup_memory_peak_bytes
                > pair[1].collector_cgroup_memory_peak_bytes
    }) {
        return Err(
            "qualification resource samples are not cumulative monotonic samples".to_string(),
        );
    }
    let resource_start = telemetry
        .resource_samples
        .iter()
        .rposition(|sample| sample.monotonic_ns <= workload.started_monotonic_ns)
        .ok_or_else(|| "qualification resources do not bracket workload start".to_string())?;
    let resource_end = telemetry
        .resource_samples
        .iter()
        .position(|sample| sample.monotonic_ns >= workload.ended_monotonic_ns)
        .ok_or_else(|| "qualification resources do not bracket workload end".to_string())?;
    if resource_end <= resource_start {
        return Err("qualification resource sample window is invalid".to_string());
    }
    if workload
        .started_monotonic_ns
        .saturating_sub(telemetry.resource_samples[resource_start].monotonic_ns)
        > telemetry.resource_sample_gap_limit_ns
        || telemetry.resource_samples[resource_end]
            .monotonic_ns
            .saturating_sub(workload.ended_monotonic_ns)
            > telemetry.resource_sample_gap_limit_ns
    {
        return Err(
            "qualification resource samples are too far from workload boundaries".to_string(),
        );
    }
    let collector_resource_samples =
        telemetry.resource_samples[resource_start..=resource_end].to_vec();
    let phases = assemble_live_phases(&workload.phases, &telemetry)?;
    if collector_lifecycle
        .get("record_type")
        .and_then(Value::as_str)
        != Some("collector_lifecycle")
        || collector_lifecycle.get("state").and_then(Value::as_str) != Some("stopped")
    {
        return Err("timeline has no normal terminal collector lifecycle".to_string());
    }
    let counters = collector_lifecycle
        .get("counters")
        .and_then(Value::as_object)
        .ok_or_else(|| "terminal collector lifecycle has no counters".to_string())?;
    let counter = |name: &str| -> Result<u64, String> {
        counters
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("terminal collector lifecycle counter is missing: {name}"))
    };
    let mut observed_event_counts = BTreeMap::new();
    let mut kernel_to_decode_ns = Vec::new();
    let mut kernel_to_append_ns = Vec::new();
    let mut outside_window = 0;
    for sample in &telemetry.samples {
        if sample.kernel_timestamp_ns < workload.started_monotonic_ns
            || sample.kernel_timestamp_ns > workload.ended_monotonic_ns
        {
            outside_window += 1;
            continue;
        }
        if sample.decoded_monotonic_ns < sample.kernel_timestamp_ns
            || sample.appended_monotonic_ns < sample.decoded_monotonic_ns
        {
            return Err("qualification telemetry timestamps are not monotonic".to_string());
        }
        let count = observed_event_counts
            .entry(sample.event_name.clone())
            .or_default();
        *count += 1;
        kernel_to_decode_ns.push(
            sample
                .decoded_monotonic_ns
                .saturating_sub(sample.kernel_timestamp_ns),
        );
        kernel_to_append_ns.push(
            sample
                .appended_monotonic_ns
                .saturating_sub(sample.kernel_timestamp_ns),
        );
    }

    let pairing = counter("scope_missing_entries")?
        .saturating_add(counter("scope_missing_exits")?)
        .saturating_add(counter("scope_pending")?);
    let decode = counter("global_abi_mismatches")?
        .saturating_add(counter("global_decode_failures")?)
        .saturating_add(counter("global_truncations")?);
    let loss_counters = BTreeMap::from([
        (
            "ring_buffer_reserve".to_string(),
            counter("global_reserve_failures")?,
        ),
        ("map_pressure".to_string(), counter("global_map_pressure")?),
        ("pairing".to_string(), pairing),
        ("decode".to_string(), decode),
        ("queue".to_string(), telemetry.dropped_samples),
        ("writer".to_string(), 0),
        ("lifecycle_gap".to_string(), 0),
    ]);
    let exact_event_reconciliation = observed_event_counts == workload.expected_event_counts;

    Ok(RawLiveTrial {
        schema_version: 1,
        workload: workload.workload,
        workload_manifest_sha256: workload.workload_manifest_sha256,
        workload_raw_sha256,
        timeline_sha256,
        telemetry_sha256,
        started_monotonic_ns: workload.started_monotonic_ns,
        ended_monotonic_ns: workload.ended_monotonic_ns,
        suspend_detected: workload.suspend_detected,
        expected_event_counts: workload.expected_event_counts,
        observed_event_counts,
        exact_event_reconciliation,
        loss_counters,
        kernel_to_decode_ns,
        kernel_to_append_ns,
        telemetry_samples_total: telemetry.samples.len(),
        telemetry_samples_outside_window: outside_window,
        resource_sample_interval_ns: telemetry.resource_sample_interval_ns,
        resource_sample_gap_limit_ns: telemetry.resource_sample_gap_limit_ns,
        resource_sample_max_gap_ns: telemetry.resource_sample_max_gap_ns,
        collector_resource_samples,
        collector_cgroup_isolated: telemetry.collector_cgroup_isolated,
        bpf_map_memory_bytes: telemetry.bpf_map_memory_bytes,
        bpf_program_memory_bytes: telemetry.bpf_program_memory_bytes,
        phases,
        collector_lifecycle,
    })
}

fn assemble_live_phases(
    workload_phases: &[RawWorkloadPhase],
    telemetry: &CapturedTelemetry,
) -> Result<Vec<RawLivePhase>, String> {
    workload_phases
        .iter()
        .map(|phase| {
            if phase.started_monotonic_ns >= phase.ended_monotonic_ns
                || phase.elapsed_monotonic_ns
                    != phase
                        .ended_monotonic_ns
                        .saturating_sub(phase.started_monotonic_ns)
                || phase.completed_event_counts != phase.expected_event_counts
            {
                return Err("qualification workload phase contract mismatch".to_string());
            }
            let mut observed_event_counts = BTreeMap::new();
            let mut kernel_to_decode_ns = Vec::new();
            let mut kernel_to_append_ns = Vec::new();
            for sample in telemetry.samples.iter().filter(|sample| {
                sample.kernel_timestamp_ns >= phase.started_monotonic_ns
                    && sample.kernel_timestamp_ns <= phase.ended_monotonic_ns
            }) {
                *observed_event_counts
                    .entry(sample.event_name.clone())
                    .or_default() += 1;
                kernel_to_decode_ns.push(
                    sample
                        .decoded_monotonic_ns
                        .saturating_sub(sample.kernel_timestamp_ns),
                );
                kernel_to_append_ns.push(
                    sample
                        .appended_monotonic_ns
                        .saturating_sub(sample.kernel_timestamp_ns),
                );
            }
            let loss_start = telemetry
                .loss_samples
                .iter()
                .rposition(|sample| sample.monotonic_ns <= phase.started_monotonic_ns)
                .ok_or_else(|| {
                    "qualification loss samples do not bracket phase start".to_string()
                })?;
            let loss_end = telemetry
                .loss_samples
                .iter()
                .position(|sample| sample.monotonic_ns >= phase.ended_monotonic_ns)
                .ok_or_else(|| "qualification loss samples do not bracket phase end".to_string())?;
            if loss_end <= loss_start
                || phase
                    .started_monotonic_ns
                    .saturating_sub(telemetry.loss_samples[loss_start].monotonic_ns)
                    > telemetry.resource_sample_gap_limit_ns
                || telemetry.loss_samples[loss_end]
                    .monotonic_ns
                    .saturating_sub(phase.ended_monotonic_ns)
                    > telemetry.resource_sample_gap_limit_ns
            {
                return Err(
                    "qualification loss samples are too far from phase boundaries".to_string(),
                );
            }
            let loss_counters = LOSS_COUNTERS
                .iter()
                .map(|name| {
                    let start = telemetry.loss_samples[loss_start]
                        .loss_counters
                        .get(*name)
                        .copied()
                        .ok_or_else(|| format!("phase loss sample is missing {name}"))?;
                    let end = telemetry.loss_samples[loss_end]
                        .loss_counters
                        .get(*name)
                        .copied()
                        .ok_or_else(|| format!("phase loss sample is missing {name}"))?;
                    let delta = end.checked_sub(start).ok_or_else(|| {
                        format!("phase loss counter {name} regressed between samples")
                    })?;
                    Ok(((*name).to_string(), delta))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            Ok(RawLivePhase {
                rate_per_second: phase.rate_per_second,
                started_monotonic_ns: phase.started_monotonic_ns,
                ended_monotonic_ns: phase.ended_monotonic_ns,
                expected_event_counts: phase.expected_event_counts.clone(),
                exact_event_reconciliation: observed_event_counts == phase.expected_event_counts,
                observed_event_counts,
                loss_counters,
                kernel_to_decode_ns,
                kernel_to_append_ns,
            })
        })
        .collect()
}

impl WorkloadScratch {
    fn prepare(repo_root: &Path, scratch_dir: &Path) -> Result<Self, String> {
        let repo_root = repo_root
            .canonicalize()
            .map_err(|error| format!("failed to resolve repo root: {error}"))?;
        let qualification_root = repo_root
            .join("target/qualification")
            .canonicalize()
            .map_err(|error| format!("failed to resolve target/qualification: {error}"))?;
        let scratch_dir = scratch_dir
            .canonicalize()
            .map_err(|error| format!("failed to resolve workload scratch directory: {error}"))?;
        if scratch_dir == qualification_root || !scratch_dir.starts_with(&qualification_root) {
            return Err("workload scratch must be a child of target/qualification".to_string());
        }
        if !scratch_dir.is_dir() {
            return Err("workload scratch must be a directory".to_string());
        }

        let directory_path = path_c_string(&scratch_dir)?;
        // SAFETY: directory_path is a valid NUL-terminated path. The returned
        // descriptor is checked before ownership is transferred to OwnedFd.
        let directory_fd = unsafe {
            libc::open(
                directory_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if directory_fd < 0 {
            return Err(format!(
                "failed to open workload scratch directory: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: open returned a new owned descriptor.
        let directory = unsafe { OwnedFd::from_raw_fd(directory_fd) };
        Ok(Self {
            directory,
            entry_path: path_c_string(&scratch_dir.join("synthetic-entry"))?,
            entry_name: CString::new("synthetic-entry").expect("static path has no NUL"),
            renamed_name: CString::new("synthetic-renamed").expect("static path has no NUL"),
            dev_null: CString::new("/dev/null").expect("static path has no NUL"),
        })
    }

    fn remove_stale_entries(&self) -> Result<(), String> {
        for name in [&self.entry_name, &self.renamed_name] {
            // SAFETY: the directory descriptor and relative C path are valid.
            let status = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
            if status != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err(format!(
                    "failed to clean synthetic workload entry: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }
}

fn path_c_string(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "qualification path contains a NUL byte".to_string())
}

fn execute_measured_operation(
    operation: SyntheticOperation,
    scratch: &WorkloadScratch,
    completed: &mut BTreeMap<String, u64>,
    latency: &mut BTreeMap<SyntheticOperation, Vec<u64>>,
) -> Result<(), String> {
    let started = clock_ns(libc::CLOCK_MONOTONIC)?;
    execute_operation(operation, scratch)?;
    let ended = clock_ns(libc::CLOCK_MONOTONIC)?;
    latency
        .entry(operation)
        .or_default()
        .push(ended.saturating_sub(started));
    operation.add_expected_events(1, completed);
    Ok(())
}

fn execute_operation(
    operation: SyntheticOperation,
    scratch: &WorkloadScratch,
) -> Result<(), String> {
    match operation {
        SyntheticOperation::Openat => {
            // SAFETY: dev_null is a valid C path and the return is checked.
            let fd = unsafe {
                libc::openat(
                    libc::AT_FDCWD,
                    scratch.dev_null.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            close_checked(fd, "openat")
        }
        SyntheticOperation::Creat => {
            // SAFETY: entry_path is a valid C path and the return is checked.
            let fd = unsafe { libc::creat(scratch.entry_path.as_ptr(), 0o600) };
            close_checked(fd, "creat")
        }
        SyntheticOperation::Truncate => {
            // SAFETY: entry_path is a valid C path and the return is checked.
            syscall_status(
                unsafe { libc::truncate(scratch.entry_path.as_ptr(), 0) },
                "truncate",
            )
        }
        SyntheticOperation::Renameat2 => {
            // SAFETY: directory descriptors and relative C paths are valid.
            let status = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    scratch.directory.as_raw_fd(),
                    scratch.entry_name.as_ptr(),
                    scratch.directory.as_raw_fd(),
                    scratch.renamed_name.as_ptr(),
                    0,
                )
            };
            syscall_status(status as libc::c_int, "renameat2")
        }
        SyntheticOperation::Unlinkat => {
            // SAFETY: directory descriptor and relative C path are valid.
            syscall_status(
                unsafe {
                    libc::unlinkat(
                        scratch.directory.as_raw_fd(),
                        scratch.renamed_name.as_ptr(),
                        0,
                    )
                },
                "unlinkat",
            )
        }
        SyntheticOperation::Connect => connect_loopback_attempt(),
        SyntheticOperation::ForkExit => fork_and_wait(),
    }
}

fn close_checked(fd: libc::c_int, operation: &str) -> Result<(), String> {
    if fd < 0 {
        return Err(format!(
            "{operation} failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd was returned by a successful open syscall and is owned here.
    if unsafe { libc::close(fd) } != 0 {
        return Err(format!(
            "close after {operation} failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn syscall_status(status: libc::c_int, operation: &str) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "{operation} failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn connect_loopback_attempt() -> Result<(), String> {
    // SAFETY: socket arguments are constants and the return is checked.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(format!(
            "socket for connect workload failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 9_u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    // A refused connection is intentional: the qualification event contract
    // counts the attempted connect without starting an untracked server.
    // SAFETY: address points to a fully initialized sockaddr_in.
    unsafe {
        libc::connect(
            socket,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(socket);
    }
    Ok(())
}

fn fork_and_wait() -> Result<(), String> {
    // SAFETY: the child immediately calls the async-signal-safe _exit syscall.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }
    if child == 0 {
        // SAFETY: terminate the fork child without invoking Rust destructors.
        unsafe { libc::_exit(0) }
    }
    loop {
        let mut status = 0;
        // SAFETY: child is the owned child PID and status is valid writable memory.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            return Ok(());
        }
        if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!(
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        ));
    }
}

fn sleep_until_monotonic(deadline_ns: u64) -> Result<(), String> {
    let deadline = libc::timespec {
        tv_sec: (deadline_ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (deadline_ns % 1_000_000_000) as libc::c_long,
    };
    loop {
        // SAFETY: deadline points to a valid absolute CLOCK_MONOTONIC timespec.
        let status = unsafe {
            libc::clock_nanosleep(
                libc::CLOCK_MONOTONIC,
                libc::TIMER_ABSTIME,
                &deadline,
                std::ptr::null_mut(),
            )
        };
        if status == 0 {
            return Ok(());
        }
        if status != libc::EINTR {
            return Err(format!(
                "clock_nanosleep failed: {}",
                std::io::Error::from_raw_os_error(status)
            ));
        }
    }
}

fn clock_ns(clock: libc::clockid_t) -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes value on success.
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return Err(format!(
            "failed to read qualification clock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value.tv_nsec as u64))
}

fn cpu_usage(who: libc::c_int) -> Result<CpuUsage, String> {
    // SAFETY: zero is a valid initialization for rusage before getrusage fills it.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    // SAFETY: usage points to valid writable rusage memory.
    if unsafe { libc::getrusage(who, &mut usage) } != 0 {
        return Err(format!(
            "failed to read workload CPU usage: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(CpuUsage {
        user_ns: timeval_ns(usage.ru_utime),
        system_ns: timeval_ns(usage.ru_stime),
    })
}

fn timeval_ns(value: libc::timeval) -> u64 {
    (value.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((value.tv_usec as u64).saturating_mul(1_000))
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
    let evidence_root = output
        .parent()
        .ok_or_else(|| "preflight evidence output must have a parent".to_string())?;
    let measurement_summary_path = evidence_root.join("measurement-summary.json");
    let measurement_summary_sha256 = sha256_path(&measurement_summary_path)?;
    let measurement_summary = load_json(&measurement_summary_path)?;
    let summary_results = measurement_summary
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "measurement summary has no results".to_string())?;
    let result = |workload: &str| -> Result<Value, String> {
        let manifest = workload_manifest(workload)?;
        let raw_samples_sha256 =
            sha256_json_tree(&evidence_root.join("measurements").join(workload))?;
        let summary_result = summary_results
            .iter()
            .find(|result| result.get("workload").and_then(Value::as_str) == Some(workload))
            .ok_or_else(|| format!("measurement summary is missing {workload}"))?;
        if summary_result
            .get("raw_samples_sha256")
            .and_then(Value::as_str)
            != raw_samples_sha256.as_deref()
            || summary_result
                .get("workload_manifest_sha256")
                .and_then(Value::as_str)
                != Some(manifest.sha256().as_str())
        {
            return Err(format!(
                "measurement summary digest contract mismatch for {workload}"
            ));
        }
        Ok(json!({
            "workload": workload,
            "workload_manifest_sha256": manifest.sha256(),
            "raw_samples_sha256": raw_samples_sha256,
            "measurements": measurements(),
            "integrity": {
                "expected_event_counts": manifest.expected_event_counts(),
                "observed_event_counts": null,
                "loss_counters": null,
                "unexplained_loss_count": null
            }
        }))
    };
    let results = ["idle", "representative", "burst"]
        .into_iter()
        .map(result)
        .collect::<Result<Vec<_>, _>>()?;
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
            "rustc_version": command_output("rustc", &["--version"])?,
            "measurement_summary_sha256": measurement_summary_sha256.clone()
        },
        "measurement_protocol": {
            "percentile_method": "nearest_rank",
            "interval_method": "bootstrap_percentile_95",
            "bootstrap_resamples": 10000,
            "collector_comparison": "alternating_off_on_same_boot",
            "clock": "clock_monotonic",
            "reject_suspend": true
        },
        "results": results
    });
    let rendered = serde_json::to_string_pretty(&evidence)
        .map_err(|error| format!("failed to serialize evidence: {error}"))?;
    fs::write(output, format!("{rendered}\n"))
        .map_err(|error| format!("failed to write {}: {error}", output.display()))
}

fn sha256_json_tree(root: &Path) -> Result<Option<String>, String> {
    if !root.is_dir() {
        return Ok(None);
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("failed to read {}: {error}", directory.display()))?
        {
            let path = entry
                .map_err(|error| format!("failed to read qualification artifact: {error}"))?
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("json" | "jsonl")
            ) {
                files.push(path);
            }
        }
    }
    files.sort();
    if files.is_empty() {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "qualification artifact escaped its workload root".to_string())?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        hasher.update(relative.as_os_str().as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(Some(hex_digest(&hasher.finalize())))
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

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root")
    }

    fn fixture(name: &str) -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/qualification")
            .join(name);
        load_json(&path).expect("qualification fixture")
    }

    #[test]
    fn embedded_workload_manifests_freeze_exact_event_counts() {
        let idle = workload_manifest("idle").expect("idle manifest");
        let representative = workload_manifest("representative").expect("representative manifest");
        let burst = workload_manifest("burst").expect("burst manifest");

        assert_eq!(idle.expected_event_counts(), BTreeMap::new());
        assert_eq!(
            representative.expected_event_counts(),
            BTreeMap::from([
                ("connect".to_string(), 25),
                ("creat".to_string(), 25),
                ("openat".to_string(), 25),
                ("renameat2".to_string(), 25),
                ("sched_process_exit".to_string(), 25),
                ("sched_process_fork".to_string(), 25),
                ("truncate".to_string(), 25),
                ("unlinkat".to_string(), 25),
            ])
        );
        assert_eq!(
            burst.expected_event_counts(),
            BTreeMap::from([("openat".to_string(), 1_300)])
        );
        assert_ne!(idle.sha256(), representative.sha256());
        assert_ne!(representative.sha256(), burst.sha256());
    }

    #[test]
    fn candidate_envelope_references_the_embedded_workload_manifests() {
        let envelope = load_json(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../qualification/envelope-v1.json"),
        )
        .expect("candidate envelope");
        let workloads = envelope["profiles"][0]["workloads"]
            .as_object()
            .expect("candidate workloads");

        for id in ["idle", "representative", "burst"] {
            let manifest = workload_manifest(id).expect("embedded manifest");
            assert_eq!(
                workloads[id]["manifest_sha256"].as_str(),
                Some(manifest.sha256().as_str())
            );
            assert_eq!(
                workloads[id]["expected_event_counts"],
                serde_json::to_value(manifest.expected_event_counts())
                    .expect("serialize expected counts")
            );
        }
    }

    #[test]
    fn representative_workload_emits_only_non_secret_raw_measurements() {
        let repo_root = repository_root();
        let scratch = repo_root
            .join("target/qualification")
            .join(format!("unit-workload-{}", process::id()));
        fs::create_dir_all(&scratch).expect("create qualification scratch");

        let result = run_workload(&repo_root, "representative", &scratch)
            .expect("run representative workload");
        fs::remove_dir_all(&scratch).expect("remove qualification scratch");

        assert_eq!(result.workload, "representative");
        assert_eq!(result.schema_version, 1);
        assert!(result.synthetic_workload_only);
        assert!(!result.suspend_detected);
        assert!(result.ended_monotonic_ns >= result.started_monotonic_ns);
        assert_eq!(result.completed_event_counts, result.expected_event_counts);
        assert_eq!(
            result.workload_user_cpu_ns,
            result
                .workload_self_user_cpu_ns
                .saturating_add(result.workload_children_user_cpu_ns)
        );
        assert_eq!(
            result.workload_system_cpu_ns,
            result
                .workload_self_system_cpu_ns
                .saturating_add(result.workload_children_system_cpu_ns)
        );

        let rendered = serde_json::to_string(&result).expect("serialize raw result");
        assert!(!rendered.contains(scratch.to_string_lossy().as_ref()));
        assert!(!rendered.contains("resource"));
        assert!(!rendered.contains("payload"));
    }

    #[test]
    fn live_trial_uses_only_samples_inside_the_workload_window() {
        let workload = RawWorkloadResult {
            schema_version: 1,
            workload: "representative".to_string(),
            workload_manifest_sha256: "a".repeat(64),
            synthetic_workload_only: true,
            host_boot_id_sha256: "d".repeat(64),
            started_boottime_ns: 100,
            ended_boottime_ns: 200,
            started_monotonic_ns: 100,
            ended_monotonic_ns: 200,
            elapsed_monotonic_ns: 100,
            workload_user_cpu_ns: 10,
            workload_system_cpu_ns: 5,
            workload_self_user_cpu_ns: 8,
            workload_self_system_cpu_ns: 4,
            workload_children_user_cpu_ns: 2,
            workload_children_system_cpu_ns: 1,
            suspend_detected: false,
            expected_event_counts: BTreeMap::from([("openat".to_string(), 1)]),
            completed_event_counts: BTreeMap::from([("openat".to_string(), 1)]),
            operation_latency_ns: BTreeMap::new(),
            phases: Vec::new(),
        };
        let telemetry = CapturedTelemetry {
            schema_version: 1,
            clock: "clock_monotonic".to_string(),
            samples: vec![
                CapturedTelemetrySample::new("openat", 90, 95, 96),
                CapturedTelemetrySample::new("openat", 150, 160, 170),
                CapturedTelemetrySample::new("openat", 210, 220, 230),
            ],
            dropped_samples: 0,
            resource_sample_interval_ns: 26,
            resource_sample_gap_limit_ns: 104,
            resource_sample_max_gap_ns: 102,
            resource_samples: vec![
                CapturedResourceSample {
                    monotonic_ns: 99,
                    process_user_cpu_ns: 1,
                    process_system_cpu_ns: 2,
                    process_rss_bytes: 1024,
                    process_peak_rss_bytes: 2048,
                    collector_cgroup_memory_current_bytes: 4096,
                    collector_cgroup_memory_peak_bytes: 8192,
                },
                CapturedResourceSample {
                    monotonic_ns: 201,
                    process_user_cpu_ns: 4,
                    process_system_cpu_ns: 6,
                    process_rss_bytes: 2048,
                    process_peak_rss_bytes: 3072,
                    collector_cgroup_memory_current_bytes: 5120,
                    collector_cgroup_memory_peak_bytes: 9216,
                },
            ],
            loss_samples: vec![
                CapturedLossSample {
                    monotonic_ns: 99,
                    loss_counters: LOSS_COUNTERS
                        .iter()
                        .map(|name| ((*name).to_string(), 0))
                        .collect(),
                },
                CapturedLossSample {
                    monotonic_ns: 201,
                    loss_counters: LOSS_COUNTERS
                        .iter()
                        .map(|name| ((*name).to_string(), 0))
                        .collect(),
                },
            ],
            collector_cgroup_isolated: true,
            bpf_map_memory_bytes: 4096,
            bpf_program_memory_bytes: 8192,
        };
        let lifecycle = json!({
            "record_type": "collector_lifecycle",
            "state": "stopped",
            "health": "healthy",
            "counters": {
                "global_reserve_failures": 0,
                "global_map_pressure": 0,
                "global_abi_mismatches": 0,
                "global_decode_failures": 0,
                "global_truncations": 0,
                "scope_missing_entries": 0,
                "scope_missing_exits": 0,
                "scope_pending": 0
            }
        });

        let mut regressed = telemetry.clone();
        regressed.loss_samples[0]
            .loss_counters
            .insert("queue".to_string(), 1);
        let error = assemble_live_trial(
            workload.clone(),
            regressed,
            lifecycle.clone(),
            "b".repeat(64),
            "c".repeat(64),
            "e".repeat(64),
        )
        .expect_err("loss counter regression must fail closed");
        assert!(error.contains("regressed"));

        let trial = assemble_live_trial(
            workload,
            telemetry,
            lifecycle,
            "b".repeat(64),
            "c".repeat(64),
            "e".repeat(64),
        )
        .expect("assemble live trial");

        assert_eq!(trial.observed_event_counts, trial.expected_event_counts);
        assert_eq!(trial.kernel_to_decode_ns, vec![10]);
        assert_eq!(trial.kernel_to_append_ns, vec![20]);
        assert_eq!(trial.loss_counters.values().sum::<u64>(), 0);
        assert!(trial.exact_event_reconciliation);
        assert_eq!(trial.collector_resource_samples.len(), 2);
        assert!(trial.collector_cgroup_isolated);
        assert_eq!(trial.bpf_map_memory_bytes, 4096);
        assert_eq!(trial.bpf_program_memory_bytes, 8192);
    }

    #[test]
    fn live_trial_rejects_a_workload_that_crossed_suspend() {
        let workload = RawWorkloadResult {
            schema_version: 1,
            workload: "idle".to_string(),
            workload_manifest_sha256: "a".repeat(64),
            synthetic_workload_only: true,
            host_boot_id_sha256: "d".repeat(64),
            started_boottime_ns: 100,
            ended_boottime_ns: 200,
            started_monotonic_ns: 100,
            ended_monotonic_ns: 200,
            elapsed_monotonic_ns: 100,
            workload_user_cpu_ns: 0,
            workload_system_cpu_ns: 0,
            workload_self_user_cpu_ns: 0,
            workload_self_system_cpu_ns: 0,
            workload_children_user_cpu_ns: 0,
            workload_children_system_cpu_ns: 0,
            suspend_detected: true,
            expected_event_counts: BTreeMap::new(),
            completed_event_counts: BTreeMap::new(),
            operation_latency_ns: BTreeMap::new(),
            phases: Vec::new(),
        };

        let error = assemble_live_trial(
            workload,
            CapturedTelemetry {
                schema_version: 0,
                clock: "invalid".to_string(),
                samples: Vec::new(),
                dropped_samples: 0,
                resource_sample_interval_ns: 0,
                resource_sample_gap_limit_ns: 0,
                resource_sample_max_gap_ns: 0,
                resource_samples: Vec::new(),
                loss_samples: Vec::new(),
                collector_cgroup_isolated: false,
                bpf_map_memory_bytes: 0,
                bpf_program_memory_bytes: 0,
            },
            json!({}),
            "b".repeat(64),
            "c".repeat(64),
            "e".repeat(64),
        )
        .expect_err("suspend must invalidate a raw live trial");

        assert!(error.contains("suspend"));
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
    fn rejects_missing_or_invalid_measurement_summary_provenance() {
        let envelope = fixture("supported-envelope.json");
        let mut evidence = fixture("host-managed-pass.json");
        evidence["provenance"]
            .as_object_mut()
            .expect("provenance")
            .remove("measurement_summary_sha256");
        assert!(evaluate(&envelope, &evidence)
            .contains(&"provenance.measurement_summary_sha256".to_string()));

        evidence["provenance"]["measurement_summary_sha256"] = json!("not-a-sha256");
        assert!(evaluate(&envelope, &evidence)
            .contains(&"provenance.measurement_summary_sha256".to_string()));
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

// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    load_typed_json, qualification_output_path, sha256_json_tree, sha256_path, workload_manifest,
    write_new_private, RawLiveTrial, RawWorkloadResult, LOSS_COUNTERS,
};

const BOOTSTRAP_RESAMPLES: usize = 10_000;
const MIB: f64 = 1_048_576.0;

#[derive(Serialize)]
struct QualificationSummary {
    schema_version: u32,
    measurement_protocol: MeasurementProtocol,
    results: Vec<WorkloadSummary>,
}

#[derive(Serialize)]
struct MeasurementProtocol {
    percentile_method: &'static str,
    interval_method: &'static str,
    bootstrap_resamples: usize,
    collector_comparison: &'static str,
    bootstrap_unit: &'static str,
    clock: &'static str,
    reject_suspend: bool,
    resource_sample_interval_ns: u64,
    resource_sample_gap_limit_ns: u64,
}

#[derive(Serialize)]
struct WorkloadSummary {
    workload: String,
    workload_manifest_sha256: String,
    host_boot_id_sha256: String,
    raw_samples_sha256: String,
    measurements: BTreeMap<String, Value>,
    bootstrap_percentile_95: BTreeMap<String, BootstrapInterval>,
    sample_counts: SampleCounts,
    integrity: IntegritySummary,
    rate_sweep: Option<RateSweepSummary>,
    paired_samples: Vec<PairSummary>,
}

#[derive(Clone, Copy, Serialize)]
struct BootstrapInterval {
    point_estimate: f64,
    lower: f64,
    upper: f64,
}

#[derive(Serialize)]
struct SampleCounts {
    pairs: usize,
    observation_events: usize,
    collector_resource_samples: usize,
}

#[derive(Serialize)]
struct IntegritySummary {
    expected_event_counts: BTreeMap<String, u64>,
    observed_event_counts: BTreeMap<String, u64>,
    loss_counters: BTreeMap<String, u64>,
    unexplained_loss_count: u64,
    exact_event_reconciliation: bool,
}

#[derive(Serialize)]
struct PairSummary {
    pair: usize,
    collector_first: bool,
    metrics: BTreeMap<String, f64>,
    observation_events: usize,
    collector_resource_samples: usize,
    phases: Vec<PairPhaseSummary>,
}

#[derive(Serialize)]
struct PairPhaseSummary {
    rate_per_second: Option<u64>,
    measured_event_rate_per_second: f64,
    expected_event_counts: BTreeMap<String, u64>,
    observed_event_counts: BTreeMap<String, u64>,
    loss_counters: BTreeMap<String, u64>,
    metrics: BTreeMap<String, f64>,
}

#[derive(Serialize)]
struct RateSweepSummary {
    phases: Vec<RateSweepPhaseSummary>,
    first_detected_loss_rate_per_second: Option<u64>,
}

#[derive(Serialize)]
struct RateSweepPhaseSummary {
    rate_per_second: u64,
    pair_samples: usize,
    measured_event_rate_per_second: BootstrapInterval,
    observation_lag_ms_p95: BootstrapInterval,
    append_lag_ms_p95: BootstrapInterval,
    loss_counters: BTreeMap<String, u64>,
    unexplained_loss_count: u64,
}

#[derive(Clone, Copy)]
enum AggregateStatistic {
    Percentile(u32),
    Maximum,
}

struct ExpectedPhase {
    rate_per_second: Option<u64>,
    requested_events: u64,
    expected_event_counts: BTreeMap<String, u64>,
}

pub(super) fn summarize_measurements(
    repo_root: &Path,
    measurement_root: &Path,
    output: &Path,
) -> Result<(), String> {
    let repo_root = repo_root
        .canonicalize()
        .map_err(|error| format!("failed to resolve repo root: {error}"))?;
    let qualification_root = repo_root
        .join("target/qualification")
        .canonicalize()
        .map_err(|error| format!("failed to resolve target/qualification: {error}"))?;
    let measurement_root = measurement_root
        .canonicalize()
        .map_err(|error| format!("failed to resolve measurement root: {error}"))?;
    if measurement_root == qualification_root || !measurement_root.starts_with(&qualification_root)
    {
        return Err("measurement root must be below target/qualification".to_string());
    }
    let output = qualification_output_path(&repo_root, output)?;
    validate_bundle_suspend(&measurement_root)?;

    let mut results = Vec::new();
    let mut boot_id = None;
    let mut sample_interval = None;
    for workload in ["idle", "representative", "burst"] {
        let summary = summarize_workload(
            workload,
            &measurement_root.join(workload),
            boot_id.as_deref(),
            sample_interval,
        )?;
        boot_id = Some(summary.host_boot_id_sha256.clone());
        sample_interval = summary
            .paired_samples
            .first()
            .map(|_| summary_resource_interval(&measurement_root.join(workload)))
            .transpose()?;
        results.push(summary);
    }
    let resource_sample_interval_ns = sample_interval
        .ok_or_else(|| "qualification summary has no resource sample interval".to_string())?;
    let report = QualificationSummary {
        schema_version: 1,
        measurement_protocol: MeasurementProtocol {
            percentile_method: "nearest_rank",
            interval_method: "bootstrap_percentile_95",
            bootstrap_resamples: BOOTSTRAP_RESAMPLES,
            collector_comparison: "alternating_off_on_same_boot",
            bootstrap_unit: "paired_trial",
            clock: "clock_monotonic",
            reject_suspend: true,
            resource_sample_interval_ns,
            resource_sample_gap_limit_ns: resource_sample_interval_ns.saturating_mul(4),
        },
        results,
    };
    let rendered = serde_json::to_string(&report)
        .map_err(|error| format!("failed to serialize qualification summary: {error}"))?;
    write_new_private(&output, format!("{rendered}\n").as_bytes())
}

fn validate_bundle_suspend(measurement_root: &Path) -> Result<(), String> {
    let mut windows = Vec::new();
    for workload in ["idle", "representative", "burst"] {
        for pair in pair_directories(&measurement_root.join(workload))? {
            windows.push(load_typed_json::<RawWorkloadResult>(
                &pair.join("off/workload/workload-raw.json"),
            )?);
            windows.push(load_typed_json::<RawWorkloadResult>(
                &pair.join("on/workload/workload-raw.json"),
            )?);
        }
    }
    windows.sort_by_key(|window| window.started_monotonic_ns);
    let first = windows
        .first()
        .ok_or_else(|| "qualification bundle has no workload windows".to_string())?;
    let last = windows
        .last()
        .expect("first qualification workload window exists");
    let monotonic_elapsed = last
        .ended_monotonic_ns
        .saturating_sub(first.started_monotonic_ns);
    let boottime_elapsed = last
        .ended_boottime_ns
        .saturating_sub(first.started_boottime_ns);
    if boottime_elapsed > monotonic_elapsed.saturating_add(super::SUSPEND_DETECTION_TOLERANCE_NS) {
        return Err("qualification bundle crossed a host suspend boundary".to_string());
    }
    Ok(())
}

fn summary_resource_interval(workload_root: &Path) -> Result<u64, String> {
    let pair = pair_directories(workload_root)?
        .into_iter()
        .next()
        .ok_or_else(|| format!("{} has no paired trials", workload_root.display()))?;
    let live: RawLiveTrial = load_typed_json(&pair.join("on/live-trial-raw.json"))?;
    Ok(live.resource_sample_interval_ns)
}

fn summarize_workload(
    workload_id: &str,
    workload_root: &Path,
    required_boot_id: Option<&str>,
    required_sample_interval: Option<u64>,
) -> Result<WorkloadSummary, String> {
    let manifest = workload_manifest(workload_id)?;
    let pairs = pair_directories(workload_root)?;
    if pairs.is_empty() {
        return Err(format!("{workload_id} has no paired trials"));
    }

    let mut pair_summaries = Vec::with_capacity(pairs.len());
    let mut boot_id = None;
    let mut sample_interval = None;
    let mut loss_counters = LOSS_COUNTERS
        .iter()
        .map(|name| ((*name).to_string(), 0_u64))
        .collect::<BTreeMap<_, _>>();
    let mut observed_min = manifest.expected_event_counts();
    let mut unexplained_loss_count = 0_u64;
    let mut exact_event_reconciliation = true;

    for (offset, pair_root) in pairs.iter().enumerate() {
        let pair_number = offset + 1;
        let off_path = pair_root.join("off/workload/workload-raw.json");
        let on_path = pair_root.join("on/workload/workload-raw.json");
        let live_path = pair_root.join("on/live-trial-raw.json");
        let timeline_path = pair_root.join("on/timeline.jsonl");
        let telemetry_path = pair_root.join("on/kernel-latency-raw.json");
        let off: RawWorkloadResult = load_typed_json(&off_path)?;
        let on: RawWorkloadResult = load_typed_json(&on_path)?;
        let live: RawLiveTrial = load_typed_json(&live_path)?;
        validate_pair(
            workload_id,
            pair_number,
            &manifest,
            &off,
            &on,
            &live,
            &on_path,
            &timeline_path,
            &telemetry_path,
        )?;

        for raw in [&off, &on] {
            if let Some(expected) = boot_id.as_deref().or(required_boot_id) {
                if raw.host_boot_id_sha256 != expected {
                    return Err("qualification pairs crossed a host boot boundary".to_string());
                }
            } else {
                boot_id = Some(raw.host_boot_id_sha256.clone());
            }
        }
        if let Some(expected) = required_sample_interval.or(sample_interval) {
            if live.resource_sample_interval_ns != expected {
                return Err(
                    "qualification resource sample interval changed between trials".to_string(),
                );
            }
        } else {
            sample_interval = Some(live.resource_sample_interval_ns);
        }

        for name in LOSS_COUNTERS {
            let value = live
                .loss_counters
                .get(*name)
                .ok_or_else(|| format!("pair {pair_number} is missing loss counter {name}"))?;
            let total = loss_counters
                .get_mut(*name)
                .expect("loss counter names were initialized");
            *total = total.saturating_add(*value);
        }
        let observed_keys = live
            .observed_event_counts
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected_keys = manifest
            .value
            .expected_event_counts
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !observed_keys.is_subset(&expected_keys) {
            return Err(format!(
                "pair {pair_number} observed an undeclared event class"
            ));
        }
        for (event, expected) in &manifest.value.expected_event_counts {
            let observed = live.observed_event_counts.get(event).copied().unwrap_or(0);
            observed_min
                .entry(event.clone())
                .and_modify(|minimum| *minimum = (*minimum).min(observed));
            unexplained_loss_count =
                unexplained_loss_count.saturating_add(expected.saturating_sub(observed));
        }
        exact_event_reconciliation &= live.exact_event_reconciliation;
        pair_summaries.push(pair_summary(pair_number, &off, &on, &live)?);
    }

    let metric_specs = [
        (
            "event_rate_per_second",
            "event_rate_per_second",
            AggregateStatistic::Percentile(5_000),
            false,
        ),
        (
            "collector_cpu_percent_p95",
            "collector_cpu_percent",
            AggregateStatistic::Percentile(9_500),
            false,
        ),
        (
            "workload_cpu_overhead_percent_p95",
            "workload_cpu_overhead_percent",
            AggregateStatistic::Percentile(9_500),
            true,
        ),
        (
            "collector_rss_mib",
            "collector_rss_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "collector_peak_rss_mib",
            "collector_peak_rss_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "collector_cgroup_memory_mib",
            "collector_cgroup_memory_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "collector_cgroup_memory_peak_mib",
            "collector_cgroup_memory_peak_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "bpf_map_memory_mib",
            "bpf_map_memory_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "bpf_program_memory_mib",
            "bpf_program_memory_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "bpf_memory_mib",
            "bpf_memory_mib",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "workload_latency_overhead_percent_p95",
            "workload_latency_overhead_percent",
            AggregateStatistic::Percentile(9_500),
            true,
        ),
        (
            "observation_lag_ms_p50",
            "observation_lag_ms_p50",
            AggregateStatistic::Percentile(5_000),
            false,
        ),
        (
            "observation_lag_ms_p95",
            "observation_lag_ms_p95",
            AggregateStatistic::Percentile(9_500),
            false,
        ),
        (
            "observation_lag_ms_p99",
            "observation_lag_ms_p99",
            AggregateStatistic::Percentile(9_900),
            false,
        ),
        (
            "observation_lag_ms_max",
            "observation_lag_ms_max",
            AggregateStatistic::Maximum,
            false,
        ),
        (
            "append_lag_ms_p50",
            "append_lag_ms_p50",
            AggregateStatistic::Percentile(5_000),
            false,
        ),
        (
            "append_lag_ms_p95",
            "append_lag_ms_p95",
            AggregateStatistic::Percentile(9_500),
            false,
        ),
        (
            "append_lag_ms_p99",
            "append_lag_ms_p99",
            AggregateStatistic::Percentile(9_900),
            false,
        ),
        (
            "append_lag_ms_max",
            "append_lag_ms_max",
            AggregateStatistic::Maximum,
            false,
        ),
    ];
    let mut measurements = BTreeMap::new();
    measurements.insert("samples".to_string(), json!(pair_summaries.len()));
    let mut intervals = BTreeMap::new();
    for (name, paired_name, statistic, one_sided) in metric_specs {
        let values = pair_summaries
            .iter()
            .map(|pair| {
                pair.metrics
                    .get(paired_name)
                    .copied()
                    .ok_or_else(|| format!("paired sample is missing {paired_name}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut interval = bootstrap_interval(
            &values,
            statistic,
            &format!("{}:{workload_id}:{name}", manifest.sha256()),
        )?;
        if one_sided {
            interval.point_estimate = interval.point_estimate.max(0.0);
            interval.lower = interval.lower.max(0.0);
            interval.upper = interval.upper.max(0.0);
        }
        measurements.insert(name.to_string(), json!(interval.point_estimate));
        intervals.insert(name.to_string(), interval);
    }
    let rate_sweep = summarize_rate_sweep(workload_id, &pair_summaries, &loss_counters)?;

    Ok(WorkloadSummary {
        workload: workload_id.to_string(),
        workload_manifest_sha256: manifest.sha256(),
        host_boot_id_sha256: boot_id
            .or_else(|| required_boot_id.map(str::to_string))
            .ok_or_else(|| "qualification summary has no boot identity".to_string())?,
        raw_samples_sha256: sha256_json_tree(workload_root)?
            .ok_or_else(|| format!("{workload_id} has no raw JSON samples"))?,
        sample_counts: SampleCounts {
            pairs: pair_summaries.len(),
            observation_events: pair_summaries
                .iter()
                .map(|pair| pair.observation_events)
                .sum(),
            collector_resource_samples: pair_summaries
                .iter()
                .map(|pair| pair.collector_resource_samples)
                .sum(),
        },
        integrity: IntegritySummary {
            expected_event_counts: manifest.expected_event_counts(),
            observed_event_counts: observed_min,
            loss_counters,
            unexplained_loss_count,
            exact_event_reconciliation,
        },
        rate_sweep,
        measurements,
        bootstrap_percentile_95: intervals,
        paired_samples: pair_summaries,
    })
}

fn summarize_rate_sweep(
    workload_id: &str,
    pairs: &[PairSummary],
    global_loss_counters: &BTreeMap<String, u64>,
) -> Result<Option<RateSweepSummary>, String> {
    let mut phase_loss_totals = LOSS_COUNTERS
        .iter()
        .map(|name| ((*name).to_string(), 0_u64))
        .collect::<BTreeMap<_, _>>();
    for pair in pairs {
        for phase in &pair.phases {
            for name in LOSS_COUNTERS {
                let value = phase
                    .loss_counters
                    .get(*name)
                    .ok_or_else(|| format!("paired phase is missing loss counter {name}"))?;
                let total = phase_loss_totals
                    .get_mut(*name)
                    .expect("phase loss counters were initialized");
                *total = total.saturating_add(*value);
            }
        }
    }
    if &phase_loss_totals != global_loss_counters {
        return Err(format!(
            "{workload_id} has collector loss that cannot be attributed to a workload phase"
        ));
    }
    if workload_id != "burst" {
        return Ok(None);
    }
    let rates = pairs
        .first()
        .ok_or_else(|| "burst has no paired samples".to_string())?
        .phases
        .iter()
        .map(|phase| {
            phase
                .rate_per_second
                .ok_or_else(|| "burst phase has no offered rate".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut phases = Vec::with_capacity(rates.len());
    let mut first_detected_loss_rate_per_second = None;
    for (index, rate) in rates.into_iter().enumerate() {
        let samples = pairs
            .iter()
            .map(|pair| {
                pair.phases
                    .get(index)
                    .filter(|phase| phase.rate_per_second == Some(rate))
                    .ok_or_else(|| "burst phase order changed between pairs".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let event_rates = samples
            .iter()
            .map(|phase| phase.measured_event_rate_per_second)
            .collect::<Vec<_>>();
        let observation_p95 = samples
            .iter()
            .map(|phase| phase.metrics["observation_lag_ms_p95"])
            .collect::<Vec<_>>();
        let append_p95 = samples
            .iter()
            .map(|phase| phase.metrics["append_lag_ms_p95"])
            .collect::<Vec<_>>();
        let mut loss_counters = LOSS_COUNTERS
            .iter()
            .map(|name| ((*name).to_string(), 0_u64))
            .collect::<BTreeMap<_, _>>();
        let mut unexplained_loss_count = 0_u64;
        for phase in &samples {
            for name in LOSS_COUNTERS {
                let value = phase.loss_counters[*name];
                let total = loss_counters
                    .get_mut(*name)
                    .expect("phase loss counters were initialized");
                *total = total.saturating_add(value);
            }
            for (event, expected) in &phase.expected_event_counts {
                unexplained_loss_count =
                    unexplained_loss_count.saturating_add(expected.saturating_sub(
                        phase.observed_event_counts.get(event).copied().unwrap_or(0),
                    ));
            }
        }
        if first_detected_loss_rate_per_second.is_none()
            && (unexplained_loss_count > 0 || loss_counters.values().any(|value| *value > 0))
        {
            first_detected_loss_rate_per_second = Some(rate);
        }
        phases.push(RateSweepPhaseSummary {
            rate_per_second: rate,
            pair_samples: samples.len(),
            measured_event_rate_per_second: bootstrap_interval(
                &event_rates,
                AggregateStatistic::Percentile(5_000),
                &format!("burst:{rate}:event-rate"),
            )?,
            observation_lag_ms_p95: bootstrap_interval(
                &observation_p95,
                AggregateStatistic::Percentile(9_500),
                &format!("burst:{rate}:observation-p95"),
            )?,
            append_lag_ms_p95: bootstrap_interval(
                &append_p95,
                AggregateStatistic::Percentile(9_500),
                &format!("burst:{rate}:append-p95"),
            )?,
            loss_counters,
            unexplained_loss_count,
        });
    }
    Ok(Some(RateSweepSummary {
        phases,
        first_detected_loss_rate_per_second,
    }))
}

fn pair_directories(workload_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut pairs = fs::read_dir(workload_root)
        .map_err(|error| format!("failed to read {}: {error}", workload_root.display()))?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                format!("failed to read {} entry: {error}", workload_root.display())
            })?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("failed to inspect paired trial: {error}"))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| "paired trial name is not valid UTF-8".to_string())?;
            if !file_type.is_dir()
                || name.len() != 8
                || !name.starts_with("pair-")
                || !name[5..].bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(format!("unexpected measurement entry: {name}"));
            }
            Ok((name.to_string(), entry.path()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    for (offset, (name, _)) in pairs.iter().enumerate() {
        if name != &format!("pair-{:03}", offset + 1) {
            return Err(format!("paired trials must be contiguous; found {name}"));
        }
    }
    Ok(pairs.into_iter().map(|(_, path)| path).collect())
}

#[allow(clippy::too_many_arguments)]
fn validate_pair(
    workload_id: &str,
    pair_number: usize,
    manifest: &super::EmbeddedWorkloadManifest,
    off: &RawWorkloadResult,
    on: &RawWorkloadResult,
    live: &RawLiveTrial,
    on_path: &Path,
    timeline_path: &Path,
    telemetry_path: &Path,
) -> Result<(), String> {
    for raw in [off, on] {
        if raw.schema_version != 1
            || raw.workload != workload_id
            || raw.workload_manifest_sha256 != manifest.sha256()
            || !raw.synthetic_workload_only
            || raw.suspend_detected
            || raw.expected_event_counts != manifest.value.expected_event_counts
            || raw.completed_event_counts != raw.expected_event_counts
            || !super::is_sha256(&raw.host_boot_id_sha256)
            || raw.elapsed_monotonic_ns
                != raw
                    .ended_monotonic_ns
                    .saturating_sub(raw.started_monotonic_ns)
            || raw
                .ended_boottime_ns
                .saturating_sub(raw.started_boottime_ns)
                > raw
                    .elapsed_monotonic_ns
                    .saturating_add(super::SUSPEND_DETECTION_TOLERANCE_NS)
            || raw.workload_user_cpu_ns
                != raw
                    .workload_self_user_cpu_ns
                    .saturating_add(raw.workload_children_user_cpu_ns)
            || raw.workload_system_cpu_ns
                != raw
                    .workload_self_system_cpu_ns
                    .saturating_add(raw.workload_children_system_cpu_ns)
        {
            return Err(format!("pair {pair_number} workload contract mismatch"));
        }
        validate_workload_phase_plan(manifest, raw, pair_number)?;
    }
    let collector_first = pair_number.is_multiple_of(2);
    let alternating_order_is_valid = if collector_first {
        on.ended_monotonic_ns <= off.started_monotonic_ns
    } else {
        off.ended_monotonic_ns <= on.started_monotonic_ns
    };
    if !alternating_order_is_valid {
        return Err(format!(
            "pair {pair_number} does not preserve alternating order"
        ));
    }
    let (pair_start, pair_end) = if collector_first {
        (on, off)
    } else {
        (off, on)
    };
    if pair_end
        .ended_boottime_ns
        .saturating_sub(pair_start.started_boottime_ns)
        > pair_end
            .ended_monotonic_ns
            .saturating_sub(pair_start.started_monotonic_ns)
            .saturating_add(super::SUSPEND_DETECTION_TOLERANCE_NS)
    {
        return Err(format!(
            "pair {pair_number} crossed a host suspend boundary"
        ));
    }
    if live.schema_version != 1
        || live.workload != workload_id
        || live.workload_manifest_sha256 != manifest.sha256()
        || live.started_monotonic_ns != on.started_monotonic_ns
        || live.ended_monotonic_ns != on.ended_monotonic_ns
        || live.suspend_detected
        || !live.collector_cgroup_isolated
        || live.resource_sample_interval_ns
            != u64::try_from(super::QUALIFICATION_RESOURCE_SAMPLE_INTERVAL.as_nanos())
                .expect("qualification sample interval fits u64")
        || live.resource_sample_gap_limit_ns != live.resource_sample_interval_ns.saturating_mul(4)
        || live.resource_sample_max_gap_ns > live.resource_sample_gap_limit_ns
        || live.workload_raw_sha256 != sha256_path(on_path)?
        || live.timeline_sha256 != sha256_path(timeline_path)?
        || live.telemetry_sha256 != sha256_path(telemetry_path)?
        || live.expected_event_counts != manifest.value.expected_event_counts
        || live.exact_event_reconciliation
            != (live.observed_event_counts == live.expected_event_counts)
    {
        return Err(format!("pair {pair_number} live trial contract mismatch"));
    }
    if live
        .loss_counters
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != LOSS_COUNTERS.iter().copied().collect::<BTreeSet<_>>()
    {
        return Err(format!("pair {pair_number} loss counter contract mismatch"));
    }
    if live.phases.len() != on.phases.len() {
        return Err(format!("pair {pair_number} phase coverage mismatch"));
    }
    for (workload_phase, live_phase) in on.phases.iter().zip(&live.phases) {
        let observed_samples = live_phase
            .observed_event_counts
            .values()
            .copied()
            .sum::<u64>() as usize;
        if workload_phase.rate_per_second != live_phase.rate_per_second
            || workload_phase.started_monotonic_ns != live_phase.started_monotonic_ns
            || workload_phase.ended_monotonic_ns != live_phase.ended_monotonic_ns
            || workload_phase.expected_event_counts != live_phase.expected_event_counts
            || workload_phase.completed_event_counts != workload_phase.expected_event_counts
            || live_phase.exact_event_reconciliation
                != (live_phase.observed_event_counts == live_phase.expected_event_counts)
            || live_phase.kernel_to_decode_ns.len() != observed_samples
            || live_phase.kernel_to_append_ns.len() != observed_samples
            || live_phase
                .loss_counters
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != LOSS_COUNTERS.iter().copied().collect::<BTreeSet<_>>()
        {
            return Err(format!("pair {pair_number} phase contract mismatch"));
        }
    }
    let resources = &live.collector_resource_samples;
    let first = resources
        .first()
        .ok_or_else(|| format!("pair {pair_number} has no collector resource samples"))?;
    let last = resources
        .last()
        .expect("first collector resource sample exists");
    let actual_max_gap = resources
        .windows(2)
        .map(|samples| {
            samples[1]
                .monotonic_ns
                .saturating_sub(samples[0].monotonic_ns)
        })
        .max()
        .unwrap_or(0);
    if first.monotonic_ns > on.started_monotonic_ns
        || last.monotonic_ns < on.ended_monotonic_ns
        || on.started_monotonic_ns.saturating_sub(first.monotonic_ns)
            > live.resource_sample_gap_limit_ns
        || last.monotonic_ns.saturating_sub(on.ended_monotonic_ns)
            > live.resource_sample_gap_limit_ns
        || actual_max_gap != live.resource_sample_max_gap_ns
        || resources.iter().any(|sample| {
            sample.process_rss_bytes > sample.process_peak_rss_bytes
                || sample.collector_cgroup_memory_current_bytes
                    > sample.collector_cgroup_memory_peak_bytes
        })
        || resources.windows(2).any(|samples| {
            samples[0].monotonic_ns >= samples[1].monotonic_ns
                || samples[0].process_user_cpu_ns > samples[1].process_user_cpu_ns
                || samples[0].process_system_cpu_ns > samples[1].process_system_cpu_ns
                || samples[0].process_peak_rss_bytes > samples[1].process_peak_rss_bytes
                || samples[0].collector_cgroup_memory_peak_bytes
                    > samples[1].collector_cgroup_memory_peak_bytes
        })
    {
        return Err(format!(
            "pair {pair_number} resource sample contract mismatch"
        ));
    }
    if live.kernel_to_decode_ns.len() != live.kernel_to_append_ns.len()
        || live.kernel_to_decode_ns.len()
            != live.observed_event_counts.values().copied().sum::<u64>() as usize
        || live.telemetry_samples_total
            != live
                .kernel_to_decode_ns
                .len()
                .saturating_add(live.telemetry_samples_outside_window)
        || live
            .kernel_to_decode_ns
            .iter()
            .zip(&live.kernel_to_append_ns)
            .any(|(decode, append)| decode > append)
    {
        return Err(format!(
            "pair {pair_number} latency sample contract mismatch"
        ));
    }
    if live
        .collector_lifecycle
        .get("record_type")
        .and_then(Value::as_str)
        != Some("collector_lifecycle")
        || live
            .collector_lifecycle
            .get("state")
            .and_then(Value::as_str)
            != Some("stopped")
    {
        return Err(format!(
            "pair {pair_number} collector lifecycle is not complete"
        ));
    }
    Ok(())
}

fn validate_workload_phase_plan(
    manifest: &super::EmbeddedWorkloadManifest,
    raw: &RawWorkloadResult,
    pair_number: usize,
) -> Result<(), String> {
    let expected = match &manifest.value.kind {
        super::WorkloadKind::Idle { .. } => vec![ExpectedPhase {
            rate_per_second: None,
            requested_events: 0,
            expected_event_counts: BTreeMap::new(),
        }],
        super::WorkloadKind::OperationMix { .. } => vec![ExpectedPhase {
            rate_per_second: None,
            requested_events: manifest.value.expected_event_counts.values().sum(),
            expected_event_counts: manifest.value.expected_event_counts.clone(),
        }],
        super::WorkloadKind::RateSweep { operation, phases } => phases
            .iter()
            .map(|phase| {
                let mut expected_event_counts = BTreeMap::new();
                operation.add_expected_events(phase.events, &mut expected_event_counts);
                ExpectedPhase {
                    rate_per_second: Some(phase.rate_per_second),
                    requested_events: phase.events,
                    expected_event_counts,
                }
            })
            .collect(),
    };
    if raw.phases.len() != expected.len() {
        return Err(format!(
            "pair {pair_number} phase plan does not match its manifest"
        ));
    }
    let mut previous_end = None;
    for (phase, expected) in raw.phases.iter().zip(expected) {
        if phase.started_monotonic_ns < raw.started_monotonic_ns
            || phase.ended_monotonic_ns > raw.ended_monotonic_ns
            || phase.started_monotonic_ns >= phase.ended_monotonic_ns
            || previous_end.is_some_and(|ended| ended > phase.started_monotonic_ns)
            || phase.elapsed_monotonic_ns
                != phase
                    .ended_monotonic_ns
                    .saturating_sub(phase.started_monotonic_ns)
            || phase.rate_per_second != expected.rate_per_second
            || phase.requested_events != expected.requested_events
            || phase.completed_events != expected.requested_events
            || phase.expected_event_counts != expected.expected_event_counts
            || phase.completed_event_counts != expected.expected_event_counts
        {
            return Err(format!(
                "pair {pair_number} phase plan does not match its manifest"
            ));
        }
        previous_end = Some(phase.ended_monotonic_ns);
    }
    Ok(())
}

fn pair_summary(
    pair_number: usize,
    off: &RawWorkloadResult,
    on: &RawWorkloadResult,
    live: &RawLiveTrial,
) -> Result<PairSummary, String> {
    let first = live
        .collector_resource_samples
        .first()
        .ok_or_else(|| format!("pair {pair_number} has no collector resource samples"))?;
    let last = live
        .collector_resource_samples
        .last()
        .expect("first collector resource sample exists");
    let collector_cpu_ns = last
        .process_user_cpu_ns
        .saturating_sub(first.process_user_cpu_ns)
        .saturating_add(
            last.process_system_cpu_ns
                .saturating_sub(first.process_system_cpu_ns),
        );
    let collector_elapsed_ns = last.monotonic_ns.saturating_sub(first.monotonic_ns);
    if collector_elapsed_ns == 0 {
        return Err(format!(
            "pair {pair_number} has a zero collector sample window"
        ));
    }
    let off_cpu = off
        .workload_user_cpu_ns
        .saturating_add(off.workload_system_cpu_ns);
    let on_cpu = on
        .workload_user_cpu_ns
        .saturating_add(on.workload_system_cpu_ns);
    let observed_events = live.observed_event_counts.values().copied().sum::<u64>();
    if on.elapsed_monotonic_ns == 0 {
        return Err(format!("pair {pair_number} has a zero workload window"));
    }

    let phases = live
        .phases
        .iter()
        .map(pair_phase_summary)
        .collect::<Result<Vec<_>, _>>()?;
    let event_rate_per_second = phases
        .iter()
        .rev()
        .find(|phase| phase.rate_per_second.is_some())
        .map(|phase| phase.measured_event_rate_per_second)
        .unwrap_or(observed_events as f64 * 1_000_000_000.0 / on.elapsed_monotonic_ns as f64);
    let mut metrics = BTreeMap::from([
        ("event_rate_per_second".to_string(), event_rate_per_second),
        (
            "collector_cpu_percent".to_string(),
            collector_cpu_ns as f64 * 100.0 / collector_elapsed_ns as f64,
        ),
        (
            "workload_cpu_overhead_percent".to_string(),
            percent_delta(on_cpu, off_cpu, "workload CPU", pair_number)?,
        ),
        (
            "collector_rss_mib".to_string(),
            live.collector_resource_samples
                .iter()
                .map(|sample| sample.process_rss_bytes)
                .max()
                .unwrap_or(0) as f64
                / MIB,
        ),
        (
            "collector_peak_rss_mib".to_string(),
            live.collector_resource_samples
                .iter()
                .map(|sample| sample.process_peak_rss_bytes)
                .max()
                .unwrap_or(0) as f64
                / MIB,
        ),
        (
            "collector_cgroup_memory_mib".to_string(),
            live.collector_resource_samples
                .iter()
                .map(|sample| sample.collector_cgroup_memory_current_bytes)
                .max()
                .unwrap_or(0) as f64
                / MIB,
        ),
        (
            "collector_cgroup_memory_peak_mib".to_string(),
            live.collector_resource_samples
                .iter()
                .map(|sample| sample.collector_cgroup_memory_peak_bytes)
                .max()
                .unwrap_or(0) as f64
                / MIB,
        ),
        (
            "bpf_map_memory_mib".to_string(),
            live.bpf_map_memory_bytes as f64 / MIB,
        ),
        (
            "bpf_program_memory_mib".to_string(),
            live.bpf_program_memory_bytes as f64 / MIB,
        ),
        (
            "bpf_memory_mib".to_string(),
            live.bpf_map_memory_bytes
                .saturating_add(live.bpf_program_memory_bytes) as f64
                / MIB,
        ),
        (
            "workload_latency_overhead_percent".to_string(),
            percent_delta(
                on.elapsed_monotonic_ns,
                off.elapsed_monotonic_ns,
                "workload wall time",
                pair_number,
            )?,
        ),
    ]);
    add_lag_metrics(
        &mut metrics,
        "observation_lag_ms",
        &live.kernel_to_decode_ns,
    )?;
    add_lag_metrics(&mut metrics, "append_lag_ms", &live.kernel_to_append_ns)?;
    if metrics.values().any(|value| !value.is_finite()) {
        return Err(format!("pair {pair_number} produced a non-finite metric"));
    }
    Ok(PairSummary {
        pair: pair_number,
        collector_first: pair_number.is_multiple_of(2),
        metrics,
        observation_events: live.kernel_to_decode_ns.len(),
        collector_resource_samples: live.collector_resource_samples.len(),
        phases,
    })
}

fn pair_phase_summary(phase: &super::RawLivePhase) -> Result<PairPhaseSummary, String> {
    let elapsed = phase
        .ended_monotonic_ns
        .saturating_sub(phase.started_monotonic_ns);
    if elapsed == 0 {
        return Err("workload phase has a zero event window".to_string());
    }
    let observed = phase.observed_event_counts.values().copied().sum::<u64>();
    let mut metrics = BTreeMap::new();
    add_lag_metrics(
        &mut metrics,
        "observation_lag_ms",
        &phase.kernel_to_decode_ns,
    )?;
    add_lag_metrics(&mut metrics, "append_lag_ms", &phase.kernel_to_append_ns)?;
    Ok(PairPhaseSummary {
        rate_per_second: phase.rate_per_second,
        measured_event_rate_per_second: observed as f64 * 1_000_000_000.0 / elapsed as f64,
        expected_event_counts: phase.expected_event_counts.clone(),
        observed_event_counts: phase.observed_event_counts.clone(),
        loss_counters: phase.loss_counters.clone(),
        metrics,
    })
}

fn percent_delta(value: u64, baseline: u64, name: &str, pair: usize) -> Result<f64, String> {
    if baseline == 0 {
        return if value == 0 {
            Ok(0.0)
        } else {
            Err(format!(
                "pair {pair} cannot calculate {name} overhead from a zero baseline"
            ))
        };
    }
    Ok((value as f64 - baseline as f64) * 100.0 / baseline as f64)
}

fn add_lag_metrics(
    metrics: &mut BTreeMap<String, f64>,
    prefix: &str,
    samples_ns: &[u64],
) -> Result<(), String> {
    let values = samples_ns
        .iter()
        .map(|value| *value as f64 / 1_000_000.0)
        .collect::<Vec<_>>();
    for (suffix, statistic) in [
        ("p50", AggregateStatistic::Percentile(5_000)),
        ("p95", AggregateStatistic::Percentile(9_500)),
        ("p99", AggregateStatistic::Percentile(9_900)),
        ("max", AggregateStatistic::Maximum),
    ] {
        let value = if values.is_empty() {
            0.0
        } else {
            aggregate(&values, statistic)?
        };
        metrics.insert(format!("{prefix}_{suffix}"), value);
    }
    Ok(())
}

fn bootstrap_interval(
    values: &[f64],
    statistic: AggregateStatistic,
    seed_material: &str,
) -> Result<BootstrapInterval, String> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return Err("bootstrap requires finite paired samples".to_string());
    }
    let point_estimate = aggregate(values, statistic)?;
    let digest = Sha256::digest(seed_material.as_bytes());
    let mut seed_bytes = [0_u8; 8];
    seed_bytes.copy_from_slice(&digest[..8]);
    let mut rng = XorShift64::new(u64::from_le_bytes(seed_bytes));
    let mut estimates = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut sample = vec![0.0; values.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut sample {
            *value = values[rng.index(values.len())];
        }
        estimates.push(aggregate(&sample, statistic)?);
    }
    Ok(BootstrapInterval {
        point_estimate,
        lower: nearest_rank(&estimates, 250)?,
        upper: nearest_rank(&estimates, 9_750)?,
    })
}

fn aggregate(values: &[f64], statistic: AggregateStatistic) -> Result<f64, String> {
    match statistic {
        AggregateStatistic::Percentile(percentile) => nearest_rank(values, percentile),
        AggregateStatistic::Maximum => values
            .iter()
            .copied()
            .max_by(f64::total_cmp)
            .ok_or_else(|| "maximum requires at least one sample".to_string()),
    }
}

fn nearest_rank(values: &[f64], percentile_basis_points: u32) -> Result<f64, String> {
    if values.is_empty()
        || percentile_basis_points == 0
        || percentile_basis_points > 10_000
        || values.iter().any(|value| !value.is_finite())
    {
        return Err("nearest-rank percentile input is invalid".to_string());
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let numerator = percentile_basis_points as usize * ordered.len();
    let rank = numerator.div_ceil(10_000).saturating_sub(1);
    Ok(ordered[rank])
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn index(&mut self, upper: usize) -> usize {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        (value as usize) % upper
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn nearest_rank_uses_the_frozen_definition() {
        let values = [4.0, 1.0, 3.0, 2.0];
        assert_eq!(nearest_rank(&values, 5_000).expect("p50"), 2.0);
        assert_eq!(nearest_rank(&values, 9_500).expect("p95"), 4.0);
        assert_eq!(nearest_rank(&values, 9_900).expect("p99"), 4.0);
    }

    #[test]
    fn paired_bootstrap_is_deterministic() {
        let first = bootstrap_interval(
            &[1.0, 2.0, 3.0, 4.0],
            AggregateStatistic::Percentile(9_500),
            "worked-example",
        )
        .expect("bootstrap interval");
        let second = bootstrap_interval(
            &[1.0, 2.0, 3.0, 4.0],
            AggregateStatistic::Percentile(9_500),
            "worked-example",
        )
        .expect("bootstrap interval");
        assert_eq!(first.point_estimate, 4.0);
        assert_eq!(first.lower, second.lower);
        assert_eq!(first.upper, second.upper);
        assert!(first.lower <= first.point_estimate);
        assert!(first.upper >= first.point_estimate);
    }

    #[test]
    fn overhead_preserves_signed_pair_delta() {
        assert_eq!(percent_delta(120, 100, "cpu", 1).expect("overhead"), 20.0);
        assert_eq!(percent_delta(80, 100, "cpu", 1).expect("overhead"), -20.0);
        assert_eq!(percent_delta(0, 0, "cpu", 1).expect("zero overhead"), 0.0);
        assert!(percent_delta(1, 0, "cpu", 1).is_err());
    }

    #[test]
    fn summary_command_seam_writes_content_free_paired_evidence() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let root = repo_root
            .join("target/qualification")
            .join(format!("summary-fixture-{}", process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale summary fixture");
        }
        let measurements = root.join("measurements");
        fs::create_dir_all(&measurements).expect("create measurement root");
        for workload in ["idle", "representative", "burst"] {
            write_pair_fixture(&measurements, workload);
        }
        let output = root.join("measurement-summary.json");

        summarize_measurements(&repo_root, &measurements, &output).expect("summarize fixture");

        let rendered = fs::read_to_string(&output).expect("read summary");
        let summary: Value = serde_json::from_str(&rendered).expect("parse summary");
        assert_eq!(summary["results"].as_array().map(Vec::len), Some(3));
        assert_eq!(
            summary["results"][1]["measurements"]["workload_cpu_overhead_percent_p95"].as_f64(),
            Some(20.0)
        );
        assert_eq!(
            summary["measurement_protocol"]["bootstrap_unit"].as_str(),
            Some("paired_trial")
        );
        assert_eq!(
            summary["results"][2]["rate_sweep"]["phases"]
                .as_array()
                .map(Vec::len),
            Some(3)
        );
        assert_eq!(
            summary["results"][2]["rate_sweep"]["phases"][2]["rate_per_second"].as_u64(),
            Some(2_000)
        );
        let representative_raw_digest = sha256_json_tree(&measurements.join("representative"))
            .expect("hash representative raw tree")
            .expect("representative raw samples");
        assert_eq!(
            summary["results"][1]["raw_samples_sha256"].as_str(),
            Some(representative_raw_digest.as_str())
        );
        assert!(!rendered.contains(root.to_string_lossy().as_ref()));
        assert!(!rendered.contains("payload"));

        let burst_off_path = measurements.join("burst/pair-001/off/workload/workload-raw.json");
        let burst_on_path = measurements.join("burst/pair-001/on/workload/workload-raw.json");
        let burst_live_path = measurements.join("burst/pair-001/on/live-trial-raw.json");
        let mut burst_off: RawWorkloadResult =
            load_typed_json(&burst_off_path).expect("load burst off fixture");
        let mut burst_on: RawWorkloadResult =
            load_typed_json(&burst_on_path).expect("load burst on fixture");
        let mut burst_live: RawLiveTrial =
            load_typed_json(&burst_live_path).expect("load burst live fixture");
        burst_off.phases[1].rate_per_second = Some(700);
        burst_on.phases[1].rate_per_second = Some(700);
        burst_live.phases[1].rate_per_second = Some(700);
        write_json(&burst_off_path, &burst_off);
        write_json(&burst_on_path, &burst_on);
        burst_live.workload_raw_sha256 =
            sha256_path(&burst_on_path).expect("hash mutated burst on fixture");
        write_json(&burst_live_path, &burst_live);
        let invalid_output = root.join("measurement-summary-invalid-phase.json");
        let error = summarize_measurements(&repo_root, &measurements, &invalid_output)
            .expect_err("manifest phase drift must fail closed");
        assert!(error.contains("phase plan"));

        burst_off.phases[1].rate_per_second = Some(500);
        burst_on.phases[1].rate_per_second = Some(500);
        burst_live.phases[1].rate_per_second = Some(500);
        write_json(&burst_off_path, &burst_off);
        write_json(&burst_on_path, &burst_on);
        burst_live.workload_raw_sha256 =
            sha256_path(&burst_on_path).expect("hash restored burst on fixture");
        write_json(&burst_live_path, &burst_live);

        burst_live
            .observed_event_counts
            .insert("openat".to_string(), 1_299);
        burst_live.exact_event_reconciliation = false;
        burst_live.kernel_to_decode_ns.pop();
        burst_live.kernel_to_append_ns.pop();
        burst_live.telemetry_samples_total -= 1;
        burst_live.phases[1]
            .observed_event_counts
            .insert("openat".to_string(), 199);
        burst_live.phases[1].exact_event_reconciliation = false;
        burst_live.phases[1].kernel_to_decode_ns.pop();
        burst_live.phases[1].kernel_to_append_ns.pop();
        write_json(&burst_live_path, &burst_live);
        let loss_output = root.join("measurement-summary-loss.json");
        summarize_measurements(&repo_root, &measurements, &loss_output)
            .expect("summarize phase loss fixture");
        let loss_summary: Value =
            serde_json::from_slice(&fs::read(&loss_output).expect("read phase loss summary"))
                .expect("parse phase loss summary");
        assert_eq!(
            loss_summary["results"][2]["rate_sweep"]["first_detected_loss_rate_per_second"]
                .as_u64(),
            Some(500)
        );
        fs::remove_dir_all(root).expect("remove summary fixture");
    }

    fn write_pair_fixture(measurement_root: &Path, workload: &str) {
        let pair = measurement_root.join(workload).join("pair-001");
        let off_root = pair.join("off/workload");
        let on_root = pair.join("on/workload");
        fs::create_dir_all(&off_root).expect("create off fixture");
        fs::create_dir_all(&on_root).expect("create on fixture");
        let manifest = workload_manifest(workload).expect("workload manifest");
        let expected = manifest.expected_event_counts();
        let off = raw_workload(
            workload,
            &manifest.sha256(),
            expected.clone(),
            100,
            200,
            100,
        );
        let on = raw_workload(
            workload,
            &manifest.sha256(),
            expected.clone(),
            300,
            410,
            120,
        );
        let off_path = off_root.join("workload-raw.json");
        let on_path = on_root.join("workload-raw.json");
        write_json(&off_path, &off);
        write_json(&on_path, &on);
        let timeline_path = pair.join("on/timeline.jsonl");
        let telemetry_path = pair.join("on/kernel-latency-raw.json");
        fs::write(
            &timeline_path,
            "{\"record_type\":\"collector_lifecycle\",\"state\":\"stopped\"}\n",
        )
        .expect("write timeline fixture");
        fs::write(&telemetry_path, "{}\n").expect("write telemetry fixture");
        let observation_count = expected.values().copied().sum::<u64>() as usize;
        let live_phases = on
            .phases
            .iter()
            .map(|phase| {
                let count = phase.expected_event_counts.values().copied().sum::<u64>() as usize;
                super::super::RawLivePhase {
                    rate_per_second: phase.rate_per_second,
                    started_monotonic_ns: phase.started_monotonic_ns,
                    ended_monotonic_ns: phase.ended_monotonic_ns,
                    expected_event_counts: phase.expected_event_counts.clone(),
                    observed_event_counts: phase.expected_event_counts.clone(),
                    exact_event_reconciliation: true,
                    loss_counters: LOSS_COUNTERS
                        .iter()
                        .map(|name| ((*name).to_string(), 0))
                        .collect(),
                    kernel_to_decode_ns: vec![1_000_000; count],
                    kernel_to_append_ns: vec![2_000_000; count],
                }
            })
            .collect();
        let live = RawLiveTrial {
            schema_version: 1,
            workload: workload.to_string(),
            workload_manifest_sha256: manifest.sha256(),
            workload_raw_sha256: sha256_path(&on_path).expect("hash on workload"),
            timeline_sha256: sha256_path(&timeline_path).expect("hash timeline"),
            telemetry_sha256: sha256_path(&telemetry_path).expect("hash telemetry"),
            started_monotonic_ns: on.started_monotonic_ns,
            ended_monotonic_ns: on.ended_monotonic_ns,
            suspend_detected: false,
            expected_event_counts: expected.clone(),
            observed_event_counts: expected,
            exact_event_reconciliation: true,
            loss_counters: LOSS_COUNTERS
                .iter()
                .map(|name| ((*name).to_string(), 0))
                .collect(),
            kernel_to_decode_ns: vec![1_000_000; observation_count],
            kernel_to_append_ns: vec![2_000_000; observation_count],
            telemetry_samples_total: observation_count,
            telemetry_samples_outside_window: 0,
            resource_sample_interval_ns: 25_000_000,
            resource_sample_gap_limit_ns: 100_000_000,
            resource_sample_max_gap_ns: 112,
            collector_resource_samples: vec![
                super::super::CapturedResourceSample {
                    monotonic_ns: 299,
                    process_user_cpu_ns: 10,
                    process_system_cpu_ns: 10,
                    process_rss_bytes: 2 * 1024 * 1024,
                    process_peak_rss_bytes: 3 * 1024 * 1024,
                    collector_cgroup_memory_current_bytes: 4 * 1024 * 1024,
                    collector_cgroup_memory_peak_bytes: 5 * 1024 * 1024,
                },
                super::super::CapturedResourceSample {
                    monotonic_ns: 411,
                    process_user_cpu_ns: 16,
                    process_system_cpu_ns: 15,
                    process_rss_bytes: 3 * 1024 * 1024,
                    process_peak_rss_bytes: 4 * 1024 * 1024,
                    collector_cgroup_memory_current_bytes: 5 * 1024 * 1024,
                    collector_cgroup_memory_peak_bytes: 6 * 1024 * 1024,
                },
            ],
            collector_cgroup_isolated: true,
            bpf_map_memory_bytes: 1024 * 1024,
            bpf_program_memory_bytes: 2 * 1024 * 1024,
            phases: live_phases,
            collector_lifecycle: json!({
                "record_type": "collector_lifecycle",
                "state": "stopped"
            }),
        };
        write_json(&pair.join("on/live-trial-raw.json"), &live);
    }

    fn raw_workload(
        workload: &str,
        manifest_sha256: &str,
        expected: BTreeMap<String, u64>,
        started: u64,
        ended: u64,
        cpu: u64,
    ) -> RawWorkloadResult {
        let phases = if workload == "burst" {
            [(100, 100_u64), (500, 200), (2_000, 1_000)]
                .into_iter()
                .enumerate()
                .map(|(index, (rate, events))| {
                    let phase_start = started + index as u64 * 30;
                    let phase_end = if index == 2 { ended } else { phase_start + 20 };
                    let counts = BTreeMap::from([("openat".to_string(), events)]);
                    super::super::RawWorkloadPhase {
                        rate_per_second: Some(rate),
                        started_monotonic_ns: phase_start,
                        ended_monotonic_ns: phase_end,
                        requested_events: events,
                        completed_events: events,
                        elapsed_monotonic_ns: phase_end - phase_start,
                        expected_event_counts: counts.clone(),
                        completed_event_counts: counts,
                    }
                })
                .collect()
        } else {
            vec![super::super::RawWorkloadPhase {
                rate_per_second: None,
                started_monotonic_ns: started,
                ended_monotonic_ns: ended,
                requested_events: expected.values().copied().sum(),
                completed_events: expected.values().copied().sum(),
                elapsed_monotonic_ns: ended - started,
                expected_event_counts: expected.clone(),
                completed_event_counts: expected.clone(),
            }]
        };
        RawWorkloadResult {
            schema_version: 1,
            workload: workload.to_string(),
            workload_manifest_sha256: manifest_sha256.to_string(),
            synthetic_workload_only: true,
            host_boot_id_sha256: "a".repeat(64),
            started_boottime_ns: started + 1_000,
            ended_boottime_ns: ended + 1_000,
            started_monotonic_ns: started,
            ended_monotonic_ns: ended,
            elapsed_monotonic_ns: ended - started,
            workload_user_cpu_ns: cpu,
            workload_system_cpu_ns: 0,
            workload_self_user_cpu_ns: cpu,
            workload_self_system_cpu_ns: 0,
            workload_children_user_cpu_ns: 0,
            workload_children_system_cpu_ns: 0,
            suspend_detected: false,
            completed_event_counts: expected.clone(),
            expected_event_counts: expected,
            operation_latency_ns: BTreeMap::new(),
            phases,
        }
    }

    fn write_json(path: &Path, value: &impl Serialize) {
        let rendered = serde_json::to_vec(value).expect("serialize fixture");
        fs::write(path, rendered).expect("write fixture");
    }
}

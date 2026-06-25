// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use apolysis_accountability::{PushOutcome, QueuePriority};
use apolysis_daemon::{DaemonConfig, DaemonRecord, DaemonState};
use apolysis_validation::{PerformanceLoad, PerformanceSample};
use serde_json::json;
use tokio::sync::oneshot;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("apolysis-runtime-foundation-pipeline-benchmark: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let root = benchmark_root()?;
    let output = run_profile(root.clone()).await;
    let cleanup = std::fs::remove_dir_all(&root).map_err(|error| {
        format!(
            "failed to remove benchmark root {}: {error}",
            root.display()
        )
    });
    let output = output?;
    cleanup?;
    println!(
        "{}",
        serde_json::to_string_pretty(&output)
            .map_err(|error| format!("failed to serialize benchmark samples: {error}"))?
    );
    Ok(())
}

async fn run_profile(root: PathBuf) -> Result<Vec<PerformanceSample>, String> {
    let steady = run_load(
        root.join("steady"),
        PerformanceLoad::Steady10000,
        10_000,
        10_000,
        false,
    )
    .await?;
    let burst = run_load(
        root.join("burst"),
        PerformanceLoad::Burst50000,
        50_000,
        16_384,
        true,
    )
    .await?;
    Ok(vec![steady, burst])
}

async fn run_load(
    state_dir: PathBuf,
    load: PerformanceLoad,
    submitted_events: u64,
    queue_capacity: usize,
    allow_drops: bool,
) -> Result<PerformanceSample, String> {
    std::fs::create_dir_all(&state_dir)
        .map_err(|error| format!("failed to create benchmark state dir: {error}"))?;
    let config = DaemonConfig {
        socket_path: state_dir.join("run/apolysisd.sock"),
        state_dir: state_dir.clone(),
        max_sessions: 4,
        max_pending: 4,
        max_connections: 4,
        queue_capacity,
        ..DaemonConfig::default()
    };
    let state = Arc::new(DaemonState::new(&config)?);
    let pipeline = state.pipeline();
    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(receiver).await })
    };

    let before = ProcSample::read()?;
    let started = Instant::now();
    let mut accepted_events = 0_u64;
    let mut dropped_events = 0_u64;
    for sequence in 0..submitted_events {
        let outcome = pipeline.submit(DaemonRecord::new(
            load_session(load),
            QueuePriority::Ordinary,
            json!({
                "record_type": "benchmark_event",
                "session_id": load_session(load),
                "sequence": sequence,
                "load": load_name(load),
            }),
        ));
        match outcome {
            Ok(PushOutcome::Accepted) | Ok(PushOutcome::AcceptedAfterShedding { .. }) => {
                accepted_events = accepted_events.saturating_add(1);
            }
            Ok(PushOutcome::Dropped { .. }) => {
                dropped_events = dropped_events.saturating_add(1);
            }
            Err(error) => return Err(format!("failed to submit benchmark event: {error}")),
        }
    }
    shutdown
        .send(())
        .map_err(|_| "failed to stop benchmark writer".to_string())?;
    let summary = writer
        .await
        .map_err(|error| format!("benchmark writer task failed: {error}"))??;
    let elapsed = started.elapsed();
    let after = ProcSample::read()?;

    if !allow_drops && dropped_events != 0 {
        return Err(format!(
            "{} dropped {dropped_events} events in a no-drop benchmark",
            load_name(load)
        ));
    }
    let accounted_events = summary
        .written
        .saturating_add(dropped_events)
        .saturating_add(summary.failed);
    if accounted_events < submitted_events {
        return Err(format!(
            "{} accounted for {accounted_events} of {submitted_events} events",
            load_name(load)
        ));
    }

    Ok(PerformanceSample {
        load,
        events_per_second: events_per_second(submitted_events, elapsed),
        milli_cpu: milli_cpu(before.cpu_ticks, after.cpu_ticks, elapsed)?,
        rss_mib: after.rss_mib,
        submitted_events,
        accepted_events,
        written_events: summary.written,
        dropped_events,
        worker_pool_bounded: true,
        loss_accounted: accounted_events >= submitted_events,
        queue_bounded: summary.final_stats.capacity == queue_capacity,
        adapter_connected: true,
    })
}

#[derive(Clone, Copy)]
struct ProcSample {
    cpu_ticks: u64,
    rss_mib: u64,
}

impl ProcSample {
    fn read() -> Result<Self, String> {
        let stat = std::fs::read_to_string("/proc/self/stat")
            .map_err(|error| format!("failed to read /proc/self/stat: {error}"))?;
        let fields: Vec<&str> = stat.split_whitespace().collect();
        let utime: u64 = fields
            .get(13)
            .ok_or_else(|| "missing utime in /proc/self/stat".to_string())?
            .parse()
            .map_err(|error| format!("invalid utime in /proc/self/stat: {error}"))?;
        let stime: u64 = fields
            .get(14)
            .ok_or_else(|| "missing stime in /proc/self/stat".to_string())?
            .parse()
            .map_err(|error| format!("invalid stime in /proc/self/stat: {error}"))?;
        let rss_pages: u64 = fields
            .get(23)
            .ok_or_else(|| "missing rss in /proc/self/stat".to_string())?
            .parse()
            .map_err(|error| format!("invalid rss in /proc/self/stat: {error}"))?;
        Ok(Self {
            cpu_ticks: utime.saturating_add(stime),
            rss_mib: pages_to_mib(rss_pages)?,
        })
    }
}

fn benchmark_root() -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "apolysis-runtime-foundation-pipeline-benchmark-{}-{now}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("failed to create benchmark root: {error}"))?;
    Ok(root)
}

fn events_per_second(events: u64, elapsed: std::time::Duration) -> u64 {
    let nanos = elapsed.as_nanos().max(1);
    ((u128::from(events) * 1_000_000_000) / nanos) as u64
}

fn milli_cpu(
    before_ticks: u64,
    after_ticks: u64,
    elapsed: std::time::Duration,
) -> Result<u64, String> {
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return Err("failed to read clock ticks per second".to_string());
    }
    let elapsed_nanos = elapsed.as_nanos().max(1);
    let cpu_ticks = after_ticks.saturating_sub(before_ticks);
    Ok(
        ((u128::from(cpu_ticks) * 1_000_000_000 * 1000)
            / (ticks_per_second as u128)
            / elapsed_nanos) as u64,
    )
}

fn pages_to_mib(pages: u64) -> Result<u64, String> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err("failed to read page size".to_string());
    }
    Ok((u128::from(pages) * page_size as u128).div_ceil(1024 * 1024) as u64)
}

fn load_session(load: PerformanceLoad) -> &'static str {
    match load {
        PerformanceLoad::Idle => "benchmark-idle",
        PerformanceLoad::Steady10000 => "benchmark-steady-10000",
        PerformanceLoad::Burst50000 => "benchmark-burst-50000",
    }
}

fn load_name(load: PerformanceLoad) -> &'static str {
    match load {
        PerformanceLoad::Idle => "idle",
        PerformanceLoad::Steady10000 => "steady_10000",
        PerformanceLoad::Burst50000 => "burst_50000",
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_core::{
    CanonicalEvent, EventSource, ObserverDiagnostic, ObserverDiagnosticKind, RawKernelEvent,
};
use apolysis_feedback::FeedbackWriter;
use apolysis_policy::PolicyRuntimeCapabilities;
use apolysis_store::JsonlStore;
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader, Pod};
use tokio::io::unix::AsyncFd;

use crate::abi::{
    KernelEventKind, KernelEventRecord, FLAG_PAYLOAD_SOCKADDR, FLAG_PAYLOAD_TRUNCATED,
    FLAG_RESOURCE_TRUNCATED,
};
use crate::capabilities::validate_live_prerequisites;
use crate::{
    append_policy_evaluation, canonicalize, load_policy, write_observer_metadata, AyaLoaderPlan,
    ObserveResult, ObserverBackend, ObserverMode, ObserverRunnerPlan, Redactor,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveScope {
    Cgroup(u64),
    ProcessTree(u32),
}

impl LiveScope {
    pub fn metadata_value(&self) -> String {
        match self {
            Self::Cgroup(id) => format!("mode:cgroup,cgroup_id:{id}"),
            Self::ProcessTree(pid) => format!("mode:process_tree,root_pid:{pid}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveObserveRequest {
    pub object_path: PathBuf,
    pub output_path: PathBuf,
    pub policy_path: PathBuf,
    pub session_id: String,
    pub feedback_dir: Option<PathBuf>,
    pub scope: LiveScope,
    pub duration: Option<Duration>,
    pub workspace_root: PathBuf,
}

impl LiveObserveRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !self.object_path.is_file() {
            return Err(format!(
                "BPF object does not exist: {}",
                self.object_path.display()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonObserverConfig {
    pub object_path: PathBuf,
}

impl DaemonObserverConfig {
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.object_path.is_file() {
            return Err(format!(
                "BPF object does not exist: {}",
                self.object_path.display()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonKernelEvent {
    pub timestamp_unix_ms: u128,
    pub record: KernelEventRecord,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DaemonObserverBatch {
    pub events: Vec<DaemonKernelEvent>,
    pub decode_failures: u64,
    pub truncations: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaemonObserverCounters {
    pub reserve_failures: u64,
    pub map_pressure: u64,
}

pub struct DaemonObserver {
    ebpf: Ebpf,
    ring: AsyncFd<RingBuf<MapData>>,
    decoder: ObserverBatchDecoder,
}

impl DaemonObserver {
    pub fn load(config: DaemonObserverConfig) -> Result<Self, String> {
        config.validate()?;
        let loader_plan = AyaLoaderPlan::audit_observer_default(&config.object_path);
        validate_live_prerequisites(&LiveScope::Cgroup(1), &loader_plan)
            .map_err(|error| format!("daemon observer prerequisite failed: {error}"))?;
        let mut ebpf = EbpfLoader::new()
            .load_file(&loader_plan.object_path)
            .map_err(|error| format!("BPF load or verifier failure: {error:#}"))?;
        enable_multi_cgroup_scope(&mut ebpf)?;
        attach_tracepoints(&mut ebpf, &loader_plan)?;
        let ring_map = ebpf
            .take_map(&loader_plan.ring_buffer_map)
            .ok_or_else(|| format!("missing BPF map: {}", loader_plan.ring_buffer_map))?;
        let ring_buffer = RingBuf::try_from(ring_map)
            .map_err(|error| format!("failed to open observer ring buffer: {error}"))?;
        let ring = AsyncFd::new(ring_buffer)
            .map_err(|error| format!("failed to poll observer ring buffer: {error}"))?;
        Ok(Self {
            ebpf,
            ring,
            decoder: ObserverBatchDecoder::capture()?,
        })
    }

    pub fn track_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        update_tracked_cgroup(&mut self.ebpf, cgroup_id, true)
    }

    pub fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        update_tracked_cgroup(&mut self.ebpf, cgroup_id, false)
    }

    pub async fn read_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        let records = read_ring_batch(&mut self.ring).await?;
        Ok(self.decoder.decode(records))
    }

    pub fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        let counters = read_observer_counters(&mut self.ebpf)?;
        Ok(DaemonObserverCounters {
            reserve_failures: counters.reserve_failures,
            map_pressure: counters.map_pressure,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct ScopeConfig {
    cgroup_id: u64,
    root_pid: u32,
    mode: u32,
}

unsafe impl Pod for ScopeConfig {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct ObserverCounters {
    reserve_failures: u64,
    map_pressure: u64,
}

unsafe impl Pod for ObserverCounters {}

pub async fn observe_live(request: LiveObserveRequest) -> Result<crate::ObserveResult, String> {
    request.validate()?;
    let policy = load_policy(&request.policy_path)?;
    let capabilities = PolicyRuntimeCapabilities::detect();
    let feedback = request.feedback_dir.clone().map(FeedbackWriter::new);
    let runner_plan = ObserverRunnerPlan::host_observer_default();
    let loader_plan = AyaLoaderPlan::audit_observer_default(&request.object_path);
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create live observer timeline: {error}"))?;

    write_observer_metadata(
        &request.session_id,
        &runner_plan,
        ObserverBackend::AyaRingBuffer,
        policy.startup_downgrade(&capabilities),
        &mut store,
    )?;
    write_scope_metadata(&request, &mut store)?;
    if let Err(error) = validate_live_prerequisites(&request.scope, &loader_plan) {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::AttachFailure,
            1,
            &error,
            &mut store,
        )?;
        store
            .flush()
            .map_err(|flush| format!("failed to flush prerequisite diagnostic: {flush}"))?;
        return Err(format!("live observer prerequisite failed: {error}"));
    }

    let mut ebpf = match EbpfLoader::new().load_file(&loader_plan.object_path) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            append_diagnostic(
                &request.session_id,
                ObserverDiagnosticKind::VerifierFailure,
                1,
                format!("{error:#}"),
                &mut store,
            )?;
            store
                .flush()
                .map_err(|flush| format!("failed to flush verifier diagnostic: {flush}"))?;
            return Err(format!("BPF load or verifier failure: {error:#}"));
        }
    };
    configure_scope(&mut ebpf, &request.scope)?;
    if let Err(error) = attach_tracepoints(&mut ebpf, &loader_plan) {
        let kind = if error.contains("verifier") {
            ObserverDiagnosticKind::VerifierFailure
        } else {
            ObserverDiagnosticKind::AttachFailure
        };
        append_diagnostic(&request.session_id, kind, 1, &error, &mut store)?;
        store
            .flush()
            .map_err(|flush| format!("failed to flush attach diagnostic: {flush}"))?;
        return Err(error);
    }

    let ring_map = ebpf
        .take_map(&loader_plan.ring_buffer_map)
        .ok_or_else(|| format!("missing BPF map: {}", loader_plan.ring_buffer_map))?;
    let ring_buffer = RingBuf::try_from(ring_map)
        .map_err(|error| format!("failed to open observer ring buffer: {error}"))?;
    let mut async_ring = AsyncFd::new(ring_buffer)
        .map_err(|error| format!("failed to poll observer ring buffer: {error}"))?;
    let calibration = ObserverBatchDecoder::capture()?;
    let deadline = request
        .duration
        .map(|duration| tokio::time::Instant::now() + duration);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut raw_count = 0;
    let mut canonical_count = 0;
    let mut decode_failures = 0_u64;
    let mut truncations = 0_u64;
    let redactor = Redactor::new(&request.session_id, &request.workspace_root);

    loop {
        let batch = if let Some(deadline) = deadline {
            tokio::select! {
                result = read_ring_batch(&mut async_ring) => Some(result?),
                result = &mut shutdown => {
                    result?;
                    None
                },
                _ = tokio::time::sleep_until(deadline) => None,
            }
        } else {
            tokio::select! {
                result = read_ring_batch(&mut async_ring) => Some(result?),
                result = &mut shutdown => {
                    result?;
                    None
                }
            }
        };

        let Some(batch) = batch else {
            break;
        };

        for bytes in batch {
            let record = match KernelEventRecord::decode(&bytes) {
                Ok(record) => record,
                Err(_) => {
                    decode_failures += 1;
                    continue;
                }
            };
            if record.flags & (FLAG_RESOURCE_TRUNCATED | FLAG_PAYLOAD_TRUNCATED) != 0 {
                truncations += 1;
            }
            let raw = match raw_event_from_record(
                &record,
                &request.session_id,
                calibration.to_unix_ms(record.timestamp_ns),
            ) {
                Ok(raw) => raw,
                Err(_) => {
                    decode_failures += 1;
                    continue;
                }
            };
            let canonical = canonicalize(&raw, &policy);
            let (persisted_raw, persisted_canonical) =
                redact_for_persistence(&raw, &canonical, &redactor);
            store
                .append(&persisted_raw)
                .map_err(|error| format!("failed to write live raw event: {error}"))?;
            raw_count += 1;

            store
                .append(&persisted_canonical)
                .map_err(|error| format!("failed to write live canonical event: {error}"))?;
            append_policy_evaluation(
                &canonical,
                &policy,
                &capabilities,
                feedback.as_ref(),
                Some(&persisted_canonical.resource),
                &mut store,
            )?;
            canonical_count += 1;
        }
    }

    let counters = read_observer_counters(&mut ebpf)?;
    if counters.reserve_failures > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::RingBufferReserveFailure,
            counters.reserve_failures,
            "kernel APOLYSIS_COUNTERS",
            &mut store,
        )?;
    }
    if counters.map_pressure > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::MapPressure,
            counters.map_pressure,
            "kernel APOLYSIS_COUNTERS",
            &mut store,
        )?;
    }
    if decode_failures > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::DecodeFailure,
            decode_failures,
            "userspace ring-buffer decoder",
            &mut store,
        )?;
    }
    if truncations > 0 {
        append_diagnostic(
            &request.session_id,
            ObserverDiagnosticKind::Truncation,
            truncations,
            "kernel event flags",
            &mut store,
        )?;
    }
    append_diagnostic(
        &request.session_id,
        ObserverDiagnosticKind::Summary,
        raw_count as u64,
        format!(
            "raw_events:{raw_count},canonical_events:{canonical_count},reserve_failures:{},map_pressure:{},decode_failures:{decode_failures},truncations:{truncations}",
            counters.reserve_failures, counters.map_pressure
        ),
        &mut store,
    )?;

    store
        .flush()
        .map_err(|error| format!("failed to flush live observer timeline: {error}"))?;

    Ok(ObserveResult {
        raw_events: raw_count,
        canonical_events: canonical_count,
        backend: ObserverBackend::AyaRingBuffer,
        mode: ObserverMode::AuditOnly,
    })
}

async fn shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("failed to install SIGTERM handler: {error}"))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("failed to install SIGINT handler: {error}"))
        }
        _ = terminate.recv() => Ok(()),
    }
}

fn configure_scope(ebpf: &mut Ebpf, scope: &LiveScope) -> Result<(), String> {
    let config = match scope {
        LiveScope::Cgroup(cgroup_id) => ScopeConfig {
            cgroup_id: *cgroup_id,
            root_pid: 0,
            mode: 1,
        },
        LiveScope::ProcessTree(root_pid) => ScopeConfig {
            cgroup_id: 0,
            root_pid: *root_pid,
            mode: 2,
        },
    };
    let config_map = ebpf
        .map_mut("APOLYSIS_CONFIG")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONFIG".to_string())?;
    let mut config_array = Array::<_, ScopeConfig>::try_from(config_map)
        .map_err(|error| format!("invalid APOLYSIS_CONFIG map: {error}"))?;
    config_array
        .set(0, config, 0)
        .map_err(|error| format!("failed to configure live observer scope: {error}"))?;

    if let LiveScope::ProcessTree(root_pid) = scope {
        let tracked_map = ebpf
            .map_mut("APOLYSIS_TRACKED_PIDS")
            .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_PIDS".to_string())?;
        let mut tracked = HashMap::<_, u32, u8>::try_from(tracked_map)
            .map_err(|error| format!("invalid APOLYSIS_TRACKED_PIDS map: {error}"))?;
        tracked
            .insert(root_pid, 1, 0)
            .map_err(|error| format!("failed to seed process-tree scope: {error}"))?;
    }
    Ok(())
}

/// Configure the observer to accept events from a dynamically managed cgroup set.
pub fn enable_multi_cgroup_scope(ebpf: &mut Ebpf) -> Result<(), String> {
    let config = ScopeConfig {
        cgroup_id: 0,
        root_pid: 0,
        mode: 3,
    };
    let config_map = ebpf
        .map_mut("APOLYSIS_CONFIG")
        .ok_or_else(|| "missing BPF map: APOLYSIS_CONFIG".to_string())?;
    let mut config_array = Array::<_, ScopeConfig>::try_from(config_map)
        .map_err(|error| format!("invalid APOLYSIS_CONFIG map: {error}"))?;
    config_array
        .set(0, config, 0)
        .map_err(|error| format!("failed to configure multi-cgroup observer scope: {error}"))
}

/// Add or remove one cgroup id from the daemon observer scope map.
pub fn update_tracked_cgroup(ebpf: &mut Ebpf, cgroup_id: u64, present: bool) -> Result<(), String> {
    if cgroup_id == 0 {
        return Err("cgroup id must be non-zero".to_string());
    }
    let tracked_map = ebpf
        .map_mut("APOLYSIS_TRACKED_CGROUPS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_TRACKED_CGROUPS".to_string())?;
    let mut tracked = HashMap::<_, u64, u8>::try_from(tracked_map)
        .map_err(|error| format!("invalid APOLYSIS_TRACKED_CGROUPS map: {error}"))?;
    if present {
        tracked
            .insert(cgroup_id, 1, 0)
            .map_err(|error| format!("failed to add cgroup observer scope: {error}"))
    } else {
        tracked
            .remove(&cgroup_id)
            .map_err(|error| format!("failed to remove cgroup observer scope: {error}"))
    }
}

fn attach_tracepoints(ebpf: &mut Ebpf, plan: &AyaLoaderPlan) -> Result<(), String> {
    for attach in &plan.tracepoints {
        let program_name = attach.program_name();
        let program = ebpf
            .program_mut(&program_name)
            .ok_or_else(|| format!("missing BPF program: {program_name}"))?;
        let tracepoint: &mut TracePoint = program
            .try_into()
            .map_err(|error| format!("invalid tracepoint program {program_name}: {error}"))?;
        tracepoint
            .load()
            .map_err(|error| format!("BPF load or verifier failure for {program_name}: {error}"))?;
        tracepoint
            .attach(&attach.category, &attach.name)
            .map_err(|error| {
                format!(
                    "BPF attach failure for {program_name} at {}/{}: {error}",
                    attach.category, attach.name
                )
            })?;
    }
    Ok(())
}

fn read_observer_counters(ebpf: &mut Ebpf) -> Result<ObserverCounters, String> {
    let counters_map = ebpf
        .map_mut("APOLYSIS_COUNTERS")
        .ok_or_else(|| "missing BPF map: APOLYSIS_COUNTERS".to_string())?;
    let counters = Array::<_, ObserverCounters>::try_from(counters_map)
        .map_err(|error| format!("invalid APOLYSIS_COUNTERS map: {error}"))?;
    counters
        .get(&0, 0)
        .map_err(|error| format!("failed to read observer counters: {error}"))
}

async fn read_ring_batch(ring: &mut AsyncFd<RingBuf<MapData>>) -> Result<Vec<Vec<u8>>, String> {
    let mut guard = ring
        .readable_mut()
        .await
        .map_err(|error| format!("ring-buffer poll failure: {error}"))?;
    let mut batch = Vec::new();
    while let Some(item) = guard.get_inner_mut().next() {
        batch.push(item.to_vec());
    }
    guard.clear_ready();
    Ok(batch)
}

fn write_scope_metadata(
    request: &LiveObserveRequest,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let event = apolysis_core::CanonicalEvent::new(
        &request.session_id,
        apolysis_core::EventSource::RuntimeMetadata,
        apolysis_core::EventType::RuntimeMetadata,
        std::process::id(),
        0,
        apolysis_core::actors::OBSERVER,
        apolysis_core::resources::OBSERVER_SCOPE,
        request.scope.metadata_value(),
    );
    store
        .append(&event)
        .map_err(|error| format!("failed to write live observer scope: {error}"))
}

fn append_diagnostic(
    session_id: &str,
    kind: ObserverDiagnosticKind,
    count: u64,
    detail: impl Into<String>,
    store: &mut JsonlStore,
) -> Result<(), String> {
    let diagnostic = ObserverDiagnostic::new(session_id, kind, count, detail);
    store
        .append(&diagnostic)
        .map_err(|error| format!("failed to write observer diagnostic: {error}"))
}

fn redact_for_persistence(
    raw: &RawKernelEvent,
    canonical: &CanonicalEvent,
    redactor: &Redactor,
) -> (RawKernelEvent, CanonicalEvent) {
    let mut persisted_raw = raw.clone();
    let mut persisted_canonical = canonical.clone();
    let resource = redactor.redact_resource(canonical.event_type.clone(), &canonical.resource);
    persisted_raw.resource.clone_from(&resource.value);
    persisted_canonical.resource = resource.value;
    if resource.redacted {
        append_marker(&mut persisted_raw.raw_payload, "redacted:resource");
    }

    if canonical.event_type == apolysis_core::EventType::FileRename && !raw.raw_payload.is_empty() {
        let payload =
            redactor.redact_resource(apolysis_core::EventType::FileRename, &raw.raw_payload);
        persisted_raw.raw_payload = payload.value;
        if payload.redacted {
            append_marker(&mut persisted_raw.raw_payload, "redacted:payload");
        }
    }
    (persisted_raw, persisted_canonical)
}

fn append_marker(payload: &mut String, marker: &str) {
    if !payload.is_empty() {
        payload.push(',');
    }
    payload.push_str(marker);
}

pub struct ObserverBatchDecoder {
    monotonic_ns: u64,
    unix_ms: u128,
}

impl ObserverBatchDecoder {
    pub fn new(monotonic_ns: u64, unix_ms: u128) -> Self {
        Self {
            monotonic_ns,
            unix_ms,
        }
    }

    fn capture() -> Result<Self, String> {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
            .as_millis();
        Ok(Self {
            monotonic_ns: monotonic_now_ns()?,
            unix_ms,
        })
    }

    pub fn decode(&self, records: Vec<Vec<u8>>) -> DaemonObserverBatch {
        let mut batch = DaemonObserverBatch::default();
        for bytes in records {
            let Ok(record) = KernelEventRecord::decode(&bytes) else {
                batch.decode_failures += 1;
                continue;
            };
            if record.flags & (FLAG_RESOURCE_TRUNCATED | FLAG_PAYLOAD_TRUNCATED) != 0 {
                batch.truncations += 1;
            }
            batch.events.push(DaemonKernelEvent {
                timestamp_unix_ms: self.to_unix_ms(record.timestamp_ns),
                record,
            });
        }
        batch
    }

    fn to_unix_ms(&self, timestamp_ns: u64) -> u128 {
        if timestamp_ns >= self.monotonic_ns {
            self.unix_ms + u128::from(timestamp_ns - self.monotonic_ns) / 1_000_000
        } else {
            self.unix_ms
                .saturating_sub(u128::from(self.monotonic_ns - timestamp_ns) / 1_000_000)
        }
    }
}

fn monotonic_now_ns() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes the provided timespec on success.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
    if status != 0 {
        return Err(format!(
            "failed to read monotonic clock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64)
}

pub fn raw_event_from_record(
    record: &KernelEventRecord,
    session_id: &str,
    timestamp_unix_ms: u128,
) -> Result<RawKernelEvent, String> {
    let kind = record.kind()?;
    let event_name = match kind {
        KernelEventKind::Exec => "sched_process_exec",
        KernelEventKind::Open => "openat",
        KernelEventKind::Create => "creat",
        KernelEventKind::Truncate => "truncate",
        KernelEventKind::Unlink => "unlinkat",
        KernelEventKind::Rename => "renameat2",
        KernelEventKind::Connect => "connect",
        KernelEventKind::Exit => "sched_process_exit",
        KernelEventKind::Fork => "sched_process_fork",
    };

    let mut resource = record.resource();
    let mut payload = record.payload();
    if record.flags & FLAG_PAYLOAD_SOCKADDR != 0 {
        let (address, family) = decode_sockaddr(record.payload_bytes())?;
        resource = address;
        payload = format!("family:{family}");
    }

    let mut markers = Vec::new();
    if record.flags & FLAG_RESOURCE_TRUNCATED != 0 {
        markers.push("resource_truncated:true");
    }
    if record.flags & FLAG_PAYLOAD_TRUNCATED != 0 {
        markers.push("payload_truncated:true");
    }
    if !markers.is_empty() {
        if !payload.is_empty() {
            markers.insert(0, payload.as_str());
        }
        payload = markers.join(",");
    }

    Ok(RawKernelEvent::new(
        timestamp_unix_ms,
        session_id,
        EventSource::KernelTracepoint,
        event_name,
        record.pid,
        record.ppid,
        record.uid,
        record.gid,
        record.comm(),
        resource,
        record.action(),
        None,
        Some(record.cgroup_id.to_string()),
        payload,
    ))
}

fn decode_sockaddr(bytes: &[u8]) -> Result<(String, &'static str), String> {
    if bytes.len() < 4 {
        return Err("socket address payload is too short".to_string());
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        2 if bytes.len() >= 8 => {
            let address = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Ok((format!("{address}:{port}"), "inet"))
        }
        10 if bytes.len() >= 24 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let address = std::net::Ipv6Addr::from(octets);
            Ok((format!("[{address}]:{port}"), "inet6"))
        }
        2 | 10 => Err("socket address payload is truncated".to_string()),
        unknown => Ok((format!("family:{unknown},port:{port}"), "unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apolysis_core::{CanonicalEvent, EventType};

    #[test]
    fn persisted_live_events_redact_credentials_before_jsonl_output() {
        let raw = RawKernelEvent::new(
            1,
            "session-a",
            EventSource::KernelTracepoint,
            "openat",
            10,
            1,
            1000,
            1000,
            "cat",
            "/workspace/.env",
            "read",
            None,
            Some("42".to_string()),
            "",
        );
        let canonical = CanonicalEvent::new(
            "session-a",
            EventSource::KernelTracepoint,
            EventType::CredentialRead,
            10,
            1,
            "cat",
            "/workspace/.env",
            "read",
        );
        let redactor = crate::Redactor::new("session-a", "/workspace");

        let (persisted_raw, persisted_canonical) =
            redact_for_persistence(&raw, &canonical, &redactor);

        assert!(!persisted_raw.to_json_line().contains("/workspace/.env"));
        assert!(!persisted_canonical
            .to_json_line()
            .contains("/workspace/.env"));
        assert!(persisted_raw.resource.starts_with("path_token:"));
        assert!(persisted_raw.raw_payload.contains("redacted:resource"));
    }
}

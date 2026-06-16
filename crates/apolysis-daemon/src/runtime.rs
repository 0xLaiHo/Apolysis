// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use apolysis_accountability::{
    ComponentState, EffectKind, EvidenceBoundary, ObservedEffect, PushOutcome, QueuePriority,
    RuntimeIdentity,
};
use apolysis_core::RawKernelEvent;
use apolysis_observer::{
    raw_event_from_record, redact_raw_event_for_persistence, DaemonObserver, DaemonObserverBatch,
    DaemonObserverCounters, Redactor,
};
use tokio::sync::{mpsc, oneshot};

use crate::{DaemonRecord, DaemonState, EventPipeline, ScopeOperation, ScopeRequest, SubmitError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserverIngestSummary {
    pub submitted: u64,
    pub dropped: u64,
    pub unscoped: u64,
    pub decode_failures: u64,
    pub truncations: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserverRuntimeSummary {
    pub counters: DaemonObserverCounters,
    pub ingest: ObserverIngestSummary,
}

pub trait ObserverRuntimeBackend: Send + 'static {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<(), String>;
    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<(), String>;
    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>>;
    fn counters(&mut self) -> Result<DaemonObserverCounters, String>;
}

impl ObserverRuntimeBackend for DaemonObserver {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        DaemonObserver::track_cgroup(self, cgroup_id)
    }

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<(), String> {
        DaemonObserver::untrack_cgroup(self, cgroup_id)
    }

    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>> {
        Box::pin(DaemonObserver::read_batch(self))
    }

    fn counters(&mut self) -> Result<DaemonObserverCounters, String> {
        DaemonObserver::counters(self)
    }
}

pub async fn run_observer_runtime<B: ObserverRuntimeBackend>(
    mut backend: B,
    initial_cgroups: Vec<u64>,
    mut scope_requests: mpsc::Receiver<ScopeRequest>,
    state: Arc<DaemonState>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<ObserverRuntimeSummary, String> {
    for cgroup_id in initial_cgroups {
        if let Err(error) = backend.track_cgroup(cgroup_id) {
            state.set_ebpf(ComponentState::Unavailable).await;
            return Err(format!(
                "failed to restore observer scope for cgroup {cgroup_id}: {error}"
            ));
        }
    }
    state.set_ebpf(ComponentState::Ready).await;
    let pipeline = state.pipeline();
    let mut summary = ObserverIngestSummary::default();
    let mut scope_open = true;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            request = scope_requests.recv(), if scope_open => {
                match request {
                    Some(request) => {
                        let result = match request.operation() {
                            ScopeOperation::Track => backend.track_cgroup(request.cgroup_id()),
                            ScopeOperation::Untrack => backend.untrack_cgroup(request.cgroup_id()),
                        };
                        request.complete(result);
                    }
                    None => scope_open = false,
                }
            }
            batch = backend.read_batch() => {
                let batch = match batch {
                    Ok(batch) => batch,
                    Err(error) => {
                        state.set_ebpf(ComponentState::Unavailable).await;
                        return Err(error);
                    }
                };
                let current = ingest_observer_batch(&state, &pipeline, batch).await;
                summary.submitted = summary.submitted.saturating_add(current.submitted);
                summary.dropped = summary.dropped.saturating_add(current.dropped);
                summary.unscoped = summary.unscoped.saturating_add(current.unscoped);
                summary.decode_failures = summary
                    .decode_failures
                    .saturating_add(current.decode_failures);
                summary.truncations =
                    summary.truncations.saturating_add(current.truncations);
            }
        }
    }

    let counters = match backend.counters() {
        Ok(counters) => counters,
        Err(error) => {
            state.set_ebpf(ComponentState::Unavailable).await;
            return Err(error);
        }
    };
    state.set_ebpf(ComponentState::Unavailable).await;
    Ok(ObserverRuntimeSummary {
        counters,
        ingest: summary,
    })
}

pub async fn ingest_observer_batch(
    state: &DaemonState,
    pipeline: &EventPipeline,
    batch: DaemonObserverBatch,
) -> ObserverIngestSummary {
    let mut summary = ObserverIngestSummary {
        decode_failures: batch.decode_failures,
        truncations: batch.truncations,
        ..ObserverIngestSummary::default()
    };
    for event in batch.events {
        let Some(session_id) = state.session_for_cgroup(event.record.cgroup_id).await else {
            summary.unscoped = summary.unscoped.saturating_add(1);
            continue;
        };
        let raw = match raw_event_from_record(&event.record, &session_id, event.timestamp_unix_ms) {
            Ok(raw) => raw,
            Err(_) => {
                summary.decode_failures = summary.decode_failures.saturating_add(1);
                continue;
            }
        };
        let workspace_root = state.workspace_root_for_session(&session_id).await;
        let redactor = Redactor::new(&session_id, workspace_root);
        let credential_read = matches!(raw.event_name.as_str(), "open" | "openat" | "openat2")
            && state
                .credential_path_requires_redaction(&session_id, &raw.resource)
                .await;
        let persisted = redact_raw_event_for_persistence(&raw, &redactor, credential_read);
        let payload = serde_json::json!({
            "record_type": apolysis_core::records::RAW_KERNEL_EVENT,
            "timestamp_unix_ms": persisted.timestamp_unix_ms,
            "session_id": persisted.session_id,
            "event_source": persisted.event_source.as_str(),
            "event_name": persisted.event_name,
            "pid": persisted.pid,
            "ppid": persisted.ppid,
            "uid": persisted.uid,
            "gid": persisted.gid,
            "comm": persisted.comm,
            "resource": persisted.resource,
            "action": persisted.action,
            "container_id": persisted.container_id,
            "cgroup_id": persisted.cgroup_id,
            "raw_payload": persisted.raw_payload,
        });
        record_submission(
            &mut summary,
            pipeline.submit(DaemonRecord::new(
                session_id.clone(),
                QueuePriority::Ordinary,
                payload,
            )),
        );
        if let Some(effect) = observed_effect_from_raw_event(&persisted, credential_read) {
            match state.accountability_finding_payloads(&effect).await {
                Ok(payloads) => {
                    for payload in payloads {
                        record_submission(
                            &mut summary,
                            pipeline.submit(DaemonRecord::new(
                                session_id.clone(),
                                QueuePriority::Finding,
                                payload,
                            )),
                        );
                    }
                }
                Err(_) => {
                    summary.decode_failures = summary.decode_failures.saturating_add(1);
                }
            }
        }
    }
    summary
}

fn record_submission(
    summary: &mut ObserverIngestSummary,
    result: Result<PushOutcome, SubmitError>,
) {
    match result {
        Ok(PushOutcome::Accepted | PushOutcome::AcceptedAfterShedding { .. }) => {
            summary.submitted = summary.submitted.saturating_add(1);
        }
        Ok(PushOutcome::Dropped { .. }) | Err(_) => {
            summary.dropped = summary.dropped.saturating_add(1);
        }
    }
}

fn observed_effect_from_raw_event(
    raw: &RawKernelEvent,
    credential_read: bool,
) -> Option<ObservedEffect> {
    let kind = match raw.event_name.as_str() {
        "exec" | "execve" | "sched_process_exec" => EffectKind::Exec,
        "open" | "openat" | "openat2" if credential_read => EffectKind::CredentialRead,
        "open" | "openat" | "openat2" => EffectKind::FileRead,
        "creat" | "truncate" | "ftruncate" | "unlink" | "unlinkat" | "rename" | "renameat"
        | "renameat2" => EffectKind::FileWrite,
        "connect" => EffectKind::NetworkConnect,
        _ => return None,
    };
    let actor = if raw.action.trim().is_empty() {
        raw.comm.clone()
    } else {
        raw.action.clone()
    };
    Some(ObservedEffect {
        session_id: raw.session_id.clone(),
        evidence_ref: format!(
            "raw_kernel_event:{}:{}:{}",
            raw.timestamp_unix_ms, raw.pid, raw.event_name
        ),
        kind,
        actor,
        resource: raw.resource.clone(),
        runtime: RuntimeIdentity {
            runtime: "kernel_tracepoint".to_string(),
            container_id: raw.container_id.clone(),
            pod_uid: None,
            cgroup_id: raw
                .cgroup_id
                .as_deref()
                .and_then(|value| value.parse::<u64>().ok()),
        },
        evidence_boundary: EvidenceBoundary::HostBoundary,
    })
}

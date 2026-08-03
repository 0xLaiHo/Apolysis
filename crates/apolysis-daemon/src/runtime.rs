// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use apolysis_accountability::{
    AccountabilityAnalyzer, ComponentState, EffectKind, EvidenceBoundary, ObservedEffect,
    PushOutcome, QueuePriority, ResourceKind, RuntimeIdentity, SessionIntent,
};
use apolysis_core::{
    new_collector_instance_id, CollectorFailureReason, CollectorHealthState,
    CollectorLifecycleCounters, CollectorLifecycleRecord, CollectorNormalStopReason,
    RawKernelEvent,
};
use apolysis_observer::{
    raw_event_from_record, scope_observation_gaps, DaemonObserver, DaemonObserverBatch,
    DaemonObserverCounters, OperationPairCounters, Redactor, RuntimeEvidencePersistence,
    ScopeGeneration, ScopeObservationGapCounters,
};
use tokio::sync::{mpsc, oneshot};

use crate::{DaemonRecord, DaemonState, EventPipeline, ScopeOperation, ScopeRequest};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserverIngestSummary {
    pub submitted: u64,
    pub dropped: u64,
    pub unscoped: u64,
    pub abi_mismatches: u64,
    pub decode_failures: u64,
    pub truncations: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObserverRuntimeSummary {
    pub counters: DaemonObserverCounters,
    pub ingest: ObserverIngestSummary,
}

#[derive(Clone, Debug)]
struct ScopeObservationContext {
    agent_run_id: String,
    intent: Option<SessionIntent>,
    workspace_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScopeRuntimeIdentity {
    cgroup_id: u64,
    generation: ScopeGeneration,
}

impl ScopeRuntimeIdentity {
    fn new(cgroup_id: u64, generation: ScopeGeneration) -> Self {
        Self {
            cgroup_id,
            generation,
        }
    }
}

impl ScopeObservationContext {
    fn new(agent_run_id: impl Into<String>, intent: Option<SessionIntent>) -> Self {
        let agent_run_id = agent_run_id.into();
        let workspace_root = intent
            .as_ref()
            .and_then(|intent| {
                intent
                    .allowed_resources
                    .iter()
                    .find(|selector| selector.kind == ResourceKind::Workspace)
            })
            .map(|selector| PathBuf::from(&selector.value))
            .unwrap_or_else(|| PathBuf::from("/__apolysis_no_workspace__"));
        Self {
            agent_run_id,
            intent,
            workspace_root,
        }
    }
}

pub trait ObserverRuntimeBackend: Send + 'static {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeGeneration, String>;
    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String>;
    fn scope_counters(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String>;
    fn drain_batch(&mut self) -> Result<DaemonObserverBatch, String>;
    fn read_batch(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<DaemonObserverBatch, String>> + Send + '_>>;
    fn counters(&mut self) -> Result<DaemonObserverCounters, String>;
}

impl ObserverRuntimeBackend for DaemonObserver {
    fn track_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeGeneration, String> {
        DaemonObserver::track_cgroup(self, cgroup_id)
    }

    fn untrack_cgroup(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        DaemonObserver::untrack_cgroup(self, cgroup_id)
    }

    fn scope_counters(&mut self, cgroup_id: u64) -> Result<ScopeObservationGapCounters, String> {
        DaemonObserver::scope_counters(self, cgroup_id)
    }

    fn drain_batch(&mut self) -> Result<DaemonObserverBatch, String> {
        Ok(DaemonObserver::drain_batch(self))
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
    let collector_instance_id = new_collector_instance_id()?;
    let mut tracked_cgroups = BTreeMap::new();
    let mut scope_contexts = BTreeMap::new();
    let mut lifecycle_counters = BTreeMap::new();
    for cgroup_id in initial_cgroups {
        let generation = match backend.track_cgroup(cgroup_id) {
            Ok(generation) => generation,
            Err(error) => {
                state.set_ebpf(ComponentState::Unavailable).await;
                return Err(format!(
                    "failed to restore observer scope for cgroup {cgroup_id}: {error}"
                ));
            }
        };
        tracked_cgroups.insert(cgroup_id, generation);
        if let Some(agent_run_id) = state.session_for_cgroup(cgroup_id).await {
            let intent = state.intent_for_session(&agent_run_id).await;
            scope_contexts.insert(
                ScopeRuntimeIdentity::new(cgroup_id, generation),
                ScopeObservationContext::new(agent_run_id, intent),
            );
        }
    }
    state.set_ebpf(ComponentState::Ready).await;
    let initial_agent_runs: BTreeSet<String> = scope_contexts
        .values()
        .map(|context| context.agent_run_id.clone())
        .collect();
    for agent_run_id in initial_agent_runs {
        persist_collector_started(&state, &agent_run_id, &collector_instance_id).await?;
    }
    let pipeline = state.pipeline();
    let mut summary = ObserverIngestSummary::default();
    let mut scope_open = true;
    let checkpoint_interval = state.collector_checkpoint_interval();
    let mut checkpoint = tokio::time::interval_at(
        tokio::time::Instant::now() + checkpoint_interval,
        checkpoint_interval,
    );
    checkpoint.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = checkpoint.tick(), if !scope_contexts.is_empty() => {
                let batch = match backend.drain_batch() {
                    Ok(batch) => batch,
                    Err(error) => {
                        let error = format!("failed to drain observer checkpoint: {error}");
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            CollectorFailureReason::ObserverFailure,
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                };
                let current = match ingest_observer_batch_confirmed(
                    &state,
                    &pipeline,
                    batch,
                    &scope_contexts,
                )
                .await
                {
                    Ok(current) => current,
                    Err(error) => {
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            collector_failure_reason(&error),
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                };
                accumulate_ingest_summary(&mut summary, current);
                let global = match backend.counters() {
                    Ok(counters) => counters,
                    Err(error) => {
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            CollectorFailureReason::CounterReadFailure,
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                };
                let mut checkpoints = BTreeMap::new();
                for (identity, context) in &scope_contexts {
                    let scoped = match backend.scope_counters(identity.cgroup_id) {
                        Ok(counters) => counters,
                        Err(error) => {
                            return Err(fail_collector_lifecycles(
                                &state,
                                &scope_contexts,
                                &collector_instance_id,
                                CollectorFailureReason::CounterReadFailure,
                                summary,
                                &lifecycle_counters,
                                error,
                            )
                            .await);
                        }
                    };
                    let counters = checkpoints
                        .entry(context.agent_run_id.clone())
                        .or_insert_with(|| {
                            lifecycle_counters
                                .get(&context.agent_run_id)
                                .copied()
                                .unwrap_or_default()
                        });
                    add_scope_lifecycle_counters(counters, scoped);
                }
                for (agent_run_id, counters) in checkpoints {
                    if let Err(error) = persist_collector_checkpoint(
                        &state,
                        &agent_run_id,
                        &collector_instance_id,
                        global,
                        summary,
                        counters,
                    )
                    .await
                    {
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            CollectorFailureReason::StorageFailure,
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                }
            }
            request = scope_requests.recv(), if scope_open => {
                match request {
                    Some(request) => {
                        let cgroup_id = request.cgroup_id();
                        let agent_run_id = request.agent_run_id().map(str::to_owned);
                        let agent_intent = request.agent_intent().cloned();
                        let operation = request.operation();
                        let result = match operation {
                            ScopeOperation::Track => match backend.track_cgroup(cgroup_id) {
                                Ok(generation) => {
                                    let first_scope = agent_run_id.as_ref().is_some_and(|agent_run_id| {
                                        !scope_contexts.values().any(|context| {
                                            context.agent_run_id == *agent_run_id
                                        })
                                    });
                                    tracked_cgroups.insert(cgroup_id, generation);
                                    if let Some(agent_run_id) = &agent_run_id {
                                        scope_contexts.insert(
                                            ScopeRuntimeIdentity::new(cgroup_id, generation),
                                            ScopeObservationContext::new(
                                                agent_run_id.clone(),
                                                agent_intent.clone(),
                                            ),
                                        );
                                        if first_scope {
                                            if let Err(error) = persist_collector_started(
                                                &state,
                                                agent_run_id,
                                                &collector_instance_id,
                                            )
                                            .await
                                            {
                                                let _ = backend.untrack_cgroup(cgroup_id);
                                                tracked_cgroups.remove(&cgroup_id);
                                                scope_contexts.remove(&ScopeRuntimeIdentity::new(
                                                    cgroup_id,
                                                    generation,
                                                ));
                                                Err(error)
                                            } else {
                                                Ok(())
                                            }
                                        } else {
                                            Ok(())
                                        }
                                    } else {
                                        Ok(())
                                    }
                                }
                                Err(error) => Err(error),
                            },
                            ScopeOperation::Untrack => {
                                let generation = tracked_cgroups.get(&cgroup_id).copied();
                                if let Some(agent_run_id) = &agent_run_id {
                                    if let Some(generation) = generation {
                                        scope_contexts.insert(
                                            ScopeRuntimeIdentity::new(cgroup_id, generation),
                                            ScopeObservationContext::new(
                                                agent_run_id.clone(),
                                                agent_intent.clone(),
                                            ),
                                        );
                                    }
                                }
                                match backend.untrack_cgroup(cgroup_id) {
                                Ok(counters) => {
                                    match backend.drain_batch() {
                                        Ok(batch) => match ingest_observer_batch_confirmed(
                                            &state,
                                            &pipeline,
                                            batch,
                                            &scope_contexts,
                                        )
                                        .await
                                        {
                                            Ok(current) => {
                                                accumulate_ingest_summary(&mut summary, current);
                                                match submit_scope_observation_gaps(
                                                    &state,
                                                    &pipeline,
                                                    cgroup_id,
                                                    counters,
                                                    agent_run_id.as_deref(),
                                                )
                                                .await
                                                {
                                                    Ok(()) => {
                                                        if let Some(agent_run_id) = &agent_run_id {
                                                            add_scope_lifecycle_counters(
                                                                lifecycle_counters
                                                                    .entry(agent_run_id.clone())
                                                                    .or_default(),
                                                                counters,
                                                            );
                                                        }
                                                        tracked_cgroups.remove(&cgroup_id);
                                                        if let Some(generation) = generation {
                                                            scope_contexts.remove(&ScopeRuntimeIdentity::new(cgroup_id, generation));
                                                        }
                                                        if let Some(agent_run_id) = &agent_run_id {
                                                            let final_scope = !scope_contexts.values().any(|context| {
                                                                context.agent_run_id == *agent_run_id
                                                            });
                                                            if final_scope {
                                                                match backend.counters() {
                                                                    Ok(global) => persist_collector_stopped(
                                                                        &state,
                                                                        agent_run_id,
                                                                        &collector_instance_id,
                                                                        CollectorNormalStopReason::AgentRunClosed,
                                                                        global,
                                                                        summary,
                                                                        lifecycle_counters
                                                                            .remove(agent_run_id)
                                                                            .unwrap_or_default(),
                                                                    )
                                                                    .await,
                                                                    Err(error) => Err(error),
                                                                }
                                                            } else {
                                                                Ok(())
                                                            }
                                                        } else {
                                                            Ok(())
                                                        }
                                                    }
                                                    Err(error) => Err(error),
                                                }
                                            }
                                            Err(error) => Err(error),
                                        },
                                        Err(error) => Err(error),
                                    }
                                }
                                Err(error) => Err(error),
                                }
                            }
                        };
                        match result {
                            Ok(()) => request.complete(Ok(())),
                            Err(error) => {
                                let reason = collector_failure_reason(&error);
                                let runtime_error = format!(
                                    "observer scope {operation:?} failed for cgroup {cgroup_id}: {error}"
                                );
                                let runtime_error = fail_collector_lifecycles(
                                    &state,
                                    &scope_contexts,
                                    &collector_instance_id,
                                    reason,
                                    summary,
                                    &lifecycle_counters,
                                    runtime_error,
                                )
                                .await;
                                request.complete(Err(error.clone()));
                                return Err(runtime_error);
                            }
                        }
                    }
                    None => scope_open = false,
                }
            }
            batch = backend.read_batch() => {
                let batch = match batch {
                    Ok(batch) => batch,
                    Err(error) => {
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            CollectorFailureReason::ObserverFailure,
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                };
                if batch.abi_mismatches > 0 {
                    summary.abi_mismatches = summary
                        .abi_mismatches
                        .saturating_add(batch.abi_mismatches);
                    let error = format!(
                        "kernel/userspace ABI mismatch: {} incompatible record(s)",
                        batch.abi_mismatches
                    );
                    return Err(fail_collector_lifecycles(
                        &state,
                        &scope_contexts,
                        &collector_instance_id,
                        CollectorFailureReason::AbiMismatch,
                        summary,
                        &lifecycle_counters,
                        error,
                    )
                    .await);
                }
                let current = match ingest_observer_batch_scoped(
                    &state,
                    &pipeline,
                    batch,
                    &scope_contexts,
                )
                .await
                {
                    Ok(current) => current,
                    Err(error) => {
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            collector_failure_reason(&error),
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                };
                accumulate_ingest_summary(&mut summary, current);
            }
        }
    }

    let mut shutdown_agent_runs = BTreeSet::new();
    for (cgroup_id, generation) in tracked_cgroups {
        if let Some(agent_run_id) = state.session_for_cgroup(cgroup_id).await {
            let intent = state.intent_for_session(&agent_run_id).await;
            scope_contexts.insert(
                ScopeRuntimeIdentity::new(cgroup_id, generation),
                ScopeObservationContext::new(agent_run_id, intent),
            );
        }
        let counters = match backend.untrack_cgroup(cgroup_id) {
            Ok(counters) => counters,
            Err(error) => {
                let error =
                    format!("failed to drain observer scope for cgroup {cgroup_id}: {error}");
                return Err(fail_collector_lifecycles(
                    &state,
                    &scope_contexts,
                    &collector_instance_id,
                    CollectorFailureReason::CounterReadFailure,
                    summary,
                    &lifecycle_counters,
                    error,
                )
                .await);
            }
        };
        let current = match backend.drain_batch() {
            Ok(batch) => {
                match ingest_observer_batch_confirmed(&state, &pipeline, batch, &scope_contexts)
                    .await
                {
                    Ok(current) => current,
                    Err(error) => {
                        return Err(fail_collector_lifecycles(
                            &state,
                            &scope_contexts,
                            &collector_instance_id,
                            collector_failure_reason(&error),
                            summary,
                            &lifecycle_counters,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                let error =
                    format!("failed to flush observer scope for cgroup {cgroup_id}: {error}");
                return Err(fail_collector_lifecycles(
                    &state,
                    &scope_contexts,
                    &collector_instance_id,
                    CollectorFailureReason::ObserverFailure,
                    summary,
                    &lifecycle_counters,
                    error,
                )
                .await);
            }
        };
        accumulate_ingest_summary(&mut summary, current);
        if let Err(error) =
            submit_scope_observation_gaps(&state, &pipeline, cgroup_id, counters, None).await
        {
            return Err(fail_collector_lifecycles(
                &state,
                &scope_contexts,
                &collector_instance_id,
                collector_failure_reason(&error),
                summary,
                &lifecycle_counters,
                error,
            )
            .await);
        }
        if let Some(context) = scope_contexts.get(&ScopeRuntimeIdentity::new(cgroup_id, generation))
        {
            shutdown_agent_runs.insert(context.agent_run_id.clone());
            add_scope_lifecycle_counters(
                lifecycle_counters
                    .entry(context.agent_run_id.clone())
                    .or_default(),
                counters,
            );
        }
        scope_contexts.remove(&ScopeRuntimeIdentity::new(cgroup_id, generation));
    }

    let counters = match backend.counters() {
        Ok(counters) => counters,
        Err(error) => {
            return Err(fail_collector_lifecycles(
                &state,
                &scope_contexts,
                &collector_instance_id,
                CollectorFailureReason::CounterReadFailure,
                summary,
                &lifecycle_counters,
                error,
            )
            .await);
        }
    };
    for agent_run_id in shutdown_agent_runs {
        if let Err(error) = persist_collector_stopped(
            &state,
            &agent_run_id,
            &collector_instance_id,
            CollectorNormalStopReason::DaemonShutdown,
            counters,
            summary,
            lifecycle_counters.remove(&agent_run_id).unwrap_or_default(),
        )
        .await
        {
            return Err(fail_collector_lifecycles(
                &state,
                &scope_contexts,
                &collector_instance_id,
                CollectorFailureReason::StorageFailure,
                summary,
                &lifecycle_counters,
                error,
            )
            .await);
        }
    }
    state.set_ebpf(ComponentState::Unavailable).await;
    Ok(ObserverRuntimeSummary {
        counters,
        ingest: summary,
    })
}

async fn persist_collector_started(
    state: &DaemonState,
    agent_run_id: &str,
    collector_instance_id: &str,
) -> Result<(), String> {
    state
        .persist_collector_lifecycle(CollectorLifecycleRecord::started(
            agent_run_id,
            collector_instance_id,
        ))
        .await
        .map_err(|error| format!("failed to persist collector start: {error}"))
}

async fn persist_collector_stopped(
    state: &DaemonState,
    agent_run_id: &str,
    collector_instance_id: &str,
    reason: CollectorNormalStopReason,
    global: DaemonObserverCounters,
    ingest: ObserverIngestSummary,
    mut counters: CollectorLifecycleCounters,
) -> Result<(), String> {
    apply_global_lifecycle_counters(&mut counters, global, ingest);
    let health = if counters.has_loss() {
        CollectorHealthState::Degraded
    } else {
        CollectorHealthState::Healthy
    };
    state
        .persist_collector_lifecycle(CollectorLifecycleRecord::stopped(
            agent_run_id,
            collector_instance_id,
            health,
            reason,
            counters,
        ))
        .await
        .map_err(|error| format!("failed to persist collector terminal state: {error}"))
}

async fn persist_collector_checkpoint(
    state: &DaemonState,
    agent_run_id: &str,
    collector_instance_id: &str,
    global: DaemonObserverCounters,
    ingest: ObserverIngestSummary,
    mut counters: CollectorLifecycleCounters,
) -> Result<(), String> {
    apply_global_lifecycle_counters(&mut counters, global, ingest);
    let health = if counters.has_loss() {
        CollectorHealthState::Degraded
    } else {
        CollectorHealthState::Healthy
    };
    state
        .persist_collector_lifecycle(CollectorLifecycleRecord::checkpoint(
            agent_run_id,
            collector_instance_id,
            health,
            counters,
        ))
        .await
        .map_err(|error| format!("failed to persist collector checkpoint: {error}"))
}

fn apply_global_lifecycle_counters(
    counters: &mut CollectorLifecycleCounters,
    global: DaemonObserverCounters,
    ingest: ObserverIngestSummary,
) {
    counters.global_reserve_failures = global.reserve_failures;
    counters.global_map_pressure = global.map_pressure;
    counters.global_abi_mismatches = ingest.abi_mismatches;
    counters.global_decode_failures = ingest.decode_failures;
    counters.global_truncations = ingest.truncations;
}

async fn fail_collector_lifecycles(
    state: &DaemonState,
    scope_contexts: &BTreeMap<ScopeRuntimeIdentity, ScopeObservationContext>,
    collector_instance_id: &str,
    reason: CollectorFailureReason,
    ingest: ObserverIngestSummary,
    lifecycle_counters: &BTreeMap<String, CollectorLifecycleCounters>,
    error: String,
) -> String {
    state.set_ebpf(ComponentState::Unavailable).await;
    let mut agent_run_ids: BTreeSet<String> = scope_contexts
        .values()
        .map(|context| context.agent_run_id.clone())
        .collect();
    agent_run_ids.extend(lifecycle_counters.keys().cloned());
    let mut terminal_failures = Vec::new();
    for agent_run_id in agent_run_ids {
        let mut counters = lifecycle_counters
            .get(&agent_run_id)
            .copied()
            .unwrap_or_default();
        counters.global_abi_mismatches = ingest.abi_mismatches;
        counters.global_decode_failures = ingest.decode_failures;
        counters.global_truncations = ingest.truncations;
        match reason {
            CollectorFailureReason::AbiMismatch => {
                counters.global_abi_mismatches = counters.global_abi_mismatches.max(1);
            }
            CollectorFailureReason::DecodeFailure => {
                counters.global_decode_failures = counters.global_decode_failures.max(1);
            }
            _ => {}
        }
        if let Err(terminal_error) = state
            .persist_collector_lifecycle(CollectorLifecycleRecord::failed(
                &agent_run_id,
                collector_instance_id,
                reason,
                counters,
            ))
            .await
        {
            terminal_failures.push(format!("{agent_run_id}:{terminal_error}"));
        }
    }
    if terminal_failures.is_empty() {
        error
    } else {
        format!(
            "{error}; collector terminal persistence failed: {}",
            terminal_failures.join(",")
        )
    }
}

fn collector_failure_reason(error: &str) -> CollectorFailureReason {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("verifier") {
        CollectorFailureReason::VerifierFailure
    } else if normalized.contains("attach") {
        CollectorFailureReason::AttachFailure
    } else if normalized.contains("abi mismatch") || normalized.contains("abi_mismatch") {
        CollectorFailureReason::AbiMismatch
    } else if normalized.contains("normalize") || normalized.contains("decode") {
        CollectorFailureReason::DecodeFailure
    } else if normalized.contains("counter") {
        CollectorFailureReason::CounterReadFailure
    } else if normalized.contains("persist")
        || normalized.contains("writer")
        || normalized.contains("storage")
    {
        CollectorFailureReason::StorageFailure
    } else {
        CollectorFailureReason::ObserverFailure
    }
}

fn add_scope_lifecycle_counters(
    totals: &mut CollectorLifecycleCounters,
    scoped: ScopeObservationGapCounters,
) {
    let pairs = [
        OperationPairCounters {
            missing_entries: scoped.network_connect.missing_entries,
            missing_exits: scoped.network_connect.missing_exits,
            pending: scoped.network_connect.pending,
        },
        scoped.file_operations.open,
        scoped.file_operations.create,
        scoped.file_operations.truncate,
        scoped.file_operations.unlink,
        scoped.file_operations.rename,
    ];
    for pair in pairs {
        totals.scope_missing_entries = totals
            .scope_missing_entries
            .saturating_add(pair.missing_entries);
        totals.scope_missing_exits = totals
            .scope_missing_exits
            .saturating_add(pair.missing_exits);
        totals.scope_pending = totals.scope_pending.saturating_add(pair.pending);
    }
}

async fn submit_scope_observation_gaps(
    state: &DaemonState,
    pipeline: &EventPipeline,
    cgroup_id: u64,
    counters: ScopeObservationGapCounters,
    known_agent_run_id: Option<&str>,
) -> Result<(), String> {
    if counters == ScopeObservationGapCounters::default() {
        return Ok(());
    }
    let agent_run_id = match known_agent_run_id {
        Some(agent_run_id) => agent_run_id.to_owned(),
        None => state
            .session_for_cgroup(cgroup_id)
            .await
            .ok_or_else(|| format!("no Agent Run owns observer scope cgroup {cgroup_id}"))?,
    };
    for gap in scope_observation_gaps(&agent_run_id, &counters) {
        let payload = serde_json::from_str(&gap.to_json_line())
            .map_err(|error| format!("failed to encode Observation Gap: {error}"))?;
        match pipeline
            .submit_and_wait(DaemonRecord::new(
                agent_run_id.clone(),
                QueuePriority::Gap,
                payload,
            ))
            .await
            .map_err(|error| format!("failed to persist Observation Gap: {error}"))?
        {
            crate::RecordWriteOutcome::Written => {}
            crate::RecordWriteOutcome::Failed => {
                return Err("failed to persist Observation Gap".to_string());
            }
        }
    }
    Ok(())
}

pub async fn ingest_observer_batch(
    state: &DaemonState,
    pipeline: &EventPipeline,
    batch: DaemonObserverBatch,
) -> Result<ObserverIngestSummary, String> {
    ingest_observer_batch_with_delivery(state, pipeline, batch, ObserverDelivery::Queued, None)
        .await
}

async fn ingest_observer_batch_scoped(
    state: &DaemonState,
    pipeline: &EventPipeline,
    batch: DaemonObserverBatch,
    scope_contexts: &BTreeMap<ScopeRuntimeIdentity, ScopeObservationContext>,
) -> Result<ObserverIngestSummary, String> {
    ingest_observer_batch_with_delivery(
        state,
        pipeline,
        batch,
        ObserverDelivery::Queued,
        Some(scope_contexts),
    )
    .await
}

async fn ingest_observer_batch_confirmed(
    state: &DaemonState,
    pipeline: &EventPipeline,
    batch: DaemonObserverBatch,
    scope_contexts: &BTreeMap<ScopeRuntimeIdentity, ScopeObservationContext>,
) -> Result<ObserverIngestSummary, String> {
    ingest_observer_batch_with_delivery(
        state,
        pipeline,
        batch,
        ObserverDelivery::Confirmed,
        Some(scope_contexts),
    )
    .await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObserverDelivery {
    Queued,
    Confirmed,
}

async fn ingest_observer_batch_with_delivery(
    state: &DaemonState,
    pipeline: &EventPipeline,
    batch: DaemonObserverBatch,
    delivery: ObserverDelivery,
    scope_contexts: Option<&BTreeMap<ScopeRuntimeIdentity, ScopeObservationContext>>,
) -> Result<ObserverIngestSummary, String> {
    if delivery == ObserverDelivery::Confirmed && batch.abi_mismatches > 0 {
        return Err(format!(
            "kernel/userspace ABI mismatch while flushing scope: {} incompatible record(s)",
            batch.abi_mismatches
        ));
    }
    if delivery == ObserverDelivery::Confirmed && batch.decode_failures > 0 {
        return Err(format!(
            "failed to decode {} observer record(s) while flushing scope",
            batch.decode_failures
        ));
    }
    let mut summary = ObserverIngestSummary {
        abi_mismatches: batch.abi_mismatches,
        decode_failures: batch.decode_failures,
        truncations: batch.truncations,
        ..ObserverIngestSummary::default()
    };
    for event in batch.events {
        let context = match scope_contexts {
            Some(scope_contexts) => ScopeGeneration::new(event.record.scope_generation)
                .ok()
                .and_then(|generation| {
                    scope_contexts.get(&ScopeRuntimeIdentity::new(
                        event.record.cgroup_id,
                        generation,
                    ))
                })
                .cloned(),
            None => match state.session_for_cgroup(event.record.cgroup_id).await {
                Some(agent_run_id) => {
                    let intent = state.intent_for_session(&agent_run_id).await;
                    Some(ScopeObservationContext::new(agent_run_id, intent))
                }
                None => None,
            },
        };
        let Some(context) = context else {
            summary.unscoped = summary.unscoped.saturating_add(1);
            continue;
        };
        let session_id = context.agent_run_id;
        let raw = match raw_event_from_record(
            &event.record,
            &session_id,
            event.timestamp_unix_ms,
            event.host_boot_id.as_deref().unwrap_or_default(),
        ) {
            Ok(raw) => raw,
            Err(error) => {
                return Err(format!(
                    "failed to normalize observer record for Agent Run {session_id}: {error}"
                ));
            }
        };
        let redactor = Redactor::new(&session_id, context.workspace_root);
        let credential_read = matches!(raw.event_name.as_str(), "open" | "openat" | "openat2")
            && apolysis_observer::is_credential_path(&raw.resource);
        let persisted =
            RuntimeEvidencePersistence::new(&redactor).persist_raw(&raw, credential_read);
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
            "outcome": persisted.operation_result.map(|result| result.outcome.as_str()),
            "return_value": persisted.operation_result.map(|result| result.return_value),
            "errno": persisted.operation_result.and_then(|result| result.errno),
            "container_id": persisted.container_id,
            "cgroup_id": persisted.cgroup_id,
            "host_boot_id": persisted.host_boot_id,
            "scope_generation": persisted.scope_generation,
            "process_generation": persisted.process_generation,
            "process_start_time_ns": persisted.process_start_time_ns,
            "exec_generation": persisted.exec_generation,
            "parent_process_generation": persisted.parent_process_generation,
            "parent_exec_generation": persisted.parent_exec_generation,
            "relation_status": persisted.relation_status.as_str(),
            "relation_reason": persisted.relation_reason,
            "raw_payload": persisted.raw_payload,
        });
        submit_observer_record(
            pipeline,
            DaemonRecord::new(session_id.clone(), QueuePriority::Ordinary, payload),
            delivery,
        )
        .await?;
        summary.submitted = summary.submitted.saturating_add(1);
        if let Some(effect) = observed_effect_from_raw_event(&persisted, credential_read) {
            let findings = AccountabilityAnalyzer::evaluate(context.intent.as_ref(), &effect);
            for finding in findings {
                match finding.to_record_value() {
                    Ok(payload) => {
                        submit_observer_record(
                            pipeline,
                            DaemonRecord::new(session_id.clone(), QueuePriority::Finding, payload),
                            delivery,
                        )
                        .await?;
                        summary.submitted = summary.submitted.saturating_add(1);
                    }
                    Err(_) => {
                        summary.decode_failures = summary.decode_failures.saturating_add(1);
                    }
                }
            }
        }
    }
    if scope_contexts.is_some() && summary.unscoped > 0 {
        return Err(format!(
            "{} observer record(s) had stale or unknown scope generations",
            summary.unscoped
        ));
    }
    Ok(summary)
}

async fn submit_observer_record(
    pipeline: &EventPipeline,
    record: DaemonRecord,
    delivery: ObserverDelivery,
) -> Result<(), String> {
    match delivery {
        ObserverDelivery::Confirmed => match pipeline.submit_and_wait(record).await? {
            crate::RecordWriteOutcome::Written => Ok(()),
            crate::RecordWriteOutcome::Failed => {
                Err("failed to persist observer record while flushing scope".to_string())
            }
        },
        ObserverDelivery::Queued => match pipeline.submit(record) {
            Ok(PushOutcome::Accepted) => Ok(()),
            Ok(PushOutcome::AcceptedAfterShedding { dropped }) => Err(format!(
                "observer queue shed a {dropped:?} record while ingesting runtime evidence"
            )),
            Ok(PushOutcome::Dropped { dropped }) => Err(format!(
                "observer queue dropped a {dropped:?} runtime evidence record"
            )),
            Err(error) => Err(format!("failed to submit observer record: {error}")),
        },
    }
}

fn accumulate_ingest_summary(summary: &mut ObserverIngestSummary, current: ObserverIngestSummary) {
    summary.submitted = summary.submitted.saturating_add(current.submitted);
    summary.dropped = summary.dropped.saturating_add(current.dropped);
    summary.unscoped = summary.unscoped.saturating_add(current.unscoped);
    summary.abi_mismatches = summary
        .abi_mismatches
        .saturating_add(current.abi_mismatches);
    summary.decode_failures = summary
        .decode_failures
        .saturating_add(current.decode_failures);
    summary.truncations = summary.truncations.saturating_add(current.truncations);
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

// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use apolysis_accountability::{BoundedPriorityQueue, PushOutcome, QueuePriority, QueueStats};
use serde_json::Value;
use tokio::sync::{oneshot, Notify};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonRecord {
    pub session_id: String,
    pub priority: QueuePriority,
    pub payload: Value,
}

impl DaemonRecord {
    pub fn new(session_id: impl Into<String>, priority: QueuePriority, payload: Value) -> Self {
        Self {
            session_id: session_id.into(),
            priority,
            payload,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError {
    Closed,
    Unavailable,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("event pipeline is closed"),
            Self::Unavailable => formatter.write_str("event pipeline queue is unavailable"),
        }
    }
}

impl std::error::Error for SubmitError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterSummary {
    pub written: u64,
    pub failed: u64,
    pub final_stats: QueueStats,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordWriteOutcome {
    Written,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDeliveryMode {
    Queued,
    Confirmed,
}

struct PipelineInner {
    state: Mutex<PipelineState>,
    notify: Notify,
    progress: Notify,
    accepting: AtomicBool,
    writer_started: AtomicBool,
}

struct PipelineState {
    queue: BoundedPriorityQueue<QueuedRecord>,
    next_sequence: u64,
    pending: BTreeSet<u64>,
    writer_failure: Option<String>,
}

struct QueuedRecord {
    sequence: u64,
    record: DaemonRecord,
    delivery: RecordDelivery,
}

enum RecordDelivery {
    Queued,
    Confirmed(oneshot::Sender<Result<RecordWriteOutcome, String>>),
}

impl RecordDelivery {
    fn mode(&self) -> RecordDeliveryMode {
        match self {
            Self::Queued => RecordDeliveryMode::Queued,
            Self::Confirmed(_) => RecordDeliveryMode::Confirmed,
        }
    }

    fn complete(self, outcome: Result<RecordWriteOutcome, String>) {
        if let Self::Confirmed(confirmation) = self {
            let _ = confirmation.send(outcome);
        }
    }
}

#[derive(Clone)]
pub struct EventPipeline {
    inner: Arc<PipelineInner>,
}

impl EventPipeline {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(PipelineInner {
                state: Mutex::new(PipelineState {
                    queue: BoundedPriorityQueue::new(capacity),
                    next_sequence: 1,
                    pending: BTreeSet::new(),
                    writer_failure: None,
                }),
                notify: Notify::new(),
                progress: Notify::new(),
                accepting: AtomicBool::new(true),
                writer_started: AtomicBool::new(false),
            }),
        }
    }

    pub fn submit(&self, record: DaemonRecord) -> Result<PushOutcome, SubmitError> {
        self.submit_queued(QueuedRecord {
            sequence: 0,
            record,
            delivery: RecordDelivery::Queued,
        })
    }

    pub async fn submit_and_wait(
        &self,
        record: DaemonRecord,
    ) -> Result<RecordWriteOutcome, String> {
        let (confirmation, receiver) = oneshot::channel();
        match self
            .submit_queued(QueuedRecord {
                sequence: 0,
                record,
                delivery: RecordDelivery::Confirmed(confirmation),
            })
            .map_err(|error| format!("failed to submit record: {error}"))?
        {
            PushOutcome::Accepted => receiver
                .await
                .map_err(|_| "record left the queue before writer confirmation".to_string())?,
            PushOutcome::AcceptedAfterShedding { dropped } => Err(format!(
                "confirmed record admission shed a {dropped:?} record"
            )),
            PushOutcome::Dropped { dropped } => {
                Err(format!("record was dropped from the {dropped:?} queue"))
            }
        }
    }

    fn submit_queued(&self, queued: QueuedRecord) -> Result<PushOutcome, SubmitError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(SubmitError::Closed);
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| SubmitError::Unavailable)?;
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(SubmitError::Closed);
        }
        let sequence = state.next_sequence;
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or(SubmitError::Unavailable)?;
        let mut queued = queued;
        queued.sequence = sequence;
        let priority = queued.record.priority;
        let (outcome, evicted) = state.queue.push_with_evicted(priority, queued);
        if matches!(
            outcome,
            PushOutcome::Accepted | PushOutcome::AcceptedAfterShedding { .. }
        ) {
            state.pending.insert(sequence);
        }
        if let Some(evicted) = evicted {
            state.pending.remove(&evicted.sequence);
            evicted.delivery.complete(Err(
                "record was shed from the Ordinary queue before writer confirmation".to_string(),
            ));
        }
        drop(state);
        self.inner.progress.notify_waiters();
        self.inner.notify.notify_one();
        Ok(outcome)
    }

    pub async fn fence(&self) -> Result<(), String> {
        let target = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| "event pipeline queue is unavailable".to_string())?;
            state.next_sequence.saturating_sub(1)
        };
        loop {
            let progress = self.inner.progress.notified();
            {
                let state = self
                    .inner
                    .state
                    .lock()
                    .map_err(|_| "event pipeline queue is unavailable".to_string())?;
                if let Some(error) = &state.writer_failure {
                    return Err(format!(
                        "event pipeline writer stopped before fence: {error}"
                    ));
                }
                if state.pending.range(..=target).next().is_none() {
                    return Ok(());
                }
            }
            progress.await;
        }
    }

    pub fn stats(&self) -> Result<QueueStats, SubmitError> {
        self.inner
            .state
            .lock()
            .map(|state| state.queue.stats().clone())
            .map_err(|_| SubmitError::Unavailable)
    }

    pub async fn run_writer<S, F>(
        &self,
        mut shutdown: oneshot::Receiver<()>,
        mut sink: S,
    ) -> Result<WriterSummary, String>
    where
        S: FnMut(DaemonRecord, RecordDeliveryMode) -> F,
        F: Future<Output = Result<RecordWriteOutcome, String>>,
    {
        if self
            .inner
            .writer_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("event pipeline already has a writer".to_string());
        }

        let mut stopping = false;
        let mut written = 0_u64;
        let mut failed = 0_u64;
        loop {
            if let Some(queued) = self.pop()? {
                let delivery_mode = queued.delivery.mode();
                let sequence = queued.sequence;
                let outcome = sink(queued.record, delivery_mode).await;
                self.complete_sequence(sequence, outcome.as_ref().err().cloned())?;
                queued.delivery.complete(outcome.clone());
                match outcome {
                    Ok(RecordWriteOutcome::Written) => {
                        written = written.saturating_add(1);
                    }
                    Ok(RecordWriteOutcome::Failed) => {
                        failed = failed.saturating_add(1);
                    }
                    Err(error) => {
                        self.inner.accepting.store(false, Ordering::Release);
                        self.set_writer_failure(&error)?;
                        return Err(error);
                    }
                }
                continue;
            }
            if stopping {
                let final_stats = self.stats().map_err(|error| error.to_string())?;
                return Ok(WriterSummary {
                    written,
                    failed,
                    final_stats,
                });
            }

            tokio::select! {
                _ = self.inner.notify.notified() => {}
                _ = &mut shutdown => {
                    self.inner.accepting.store(false, Ordering::Release);
                    stopping = true;
                }
            }
        }
    }

    fn pop(&self) -> Result<Option<QueuedRecord>, String> {
        self.inner
            .state
            .lock()
            .map_err(|_| "event pipeline queue is unavailable".to_string())
            .map(|mut state| state.queue.pop())
    }

    fn complete_sequence(&self, sequence: u64, error: Option<String>) -> Result<(), String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "event pipeline queue is unavailable".to_string())?;
        state.pending.remove(&sequence);
        if let Some(error) = error {
            state.writer_failure = Some(error);
        }
        drop(state);
        self.inner.progress.notify_waiters();
        Ok(())
    }

    fn set_writer_failure(&self, error: &str) -> Result<(), String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "event pipeline queue is unavailable".to_string())?;
        state.writer_failure = Some(error.to_string());
        drop(state);
        self.inner.progress.notify_waiters();
        Ok(())
    }
}

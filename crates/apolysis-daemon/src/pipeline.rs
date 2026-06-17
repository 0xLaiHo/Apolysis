// SPDX-License-Identifier: Apache-2.0

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

struct PipelineInner {
    queue: Mutex<BoundedPriorityQueue<DaemonRecord>>,
    notify: Notify,
    accepting: AtomicBool,
    writer_started: AtomicBool,
}

#[derive(Clone)]
pub struct EventPipeline {
    inner: Arc<PipelineInner>,
}

impl EventPipeline {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(PipelineInner {
                queue: Mutex::new(BoundedPriorityQueue::new(capacity)),
                notify: Notify::new(),
                accepting: AtomicBool::new(true),
                writer_started: AtomicBool::new(false),
            }),
        }
    }

    pub fn submit(&self, record: DaemonRecord) -> Result<PushOutcome, SubmitError> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(SubmitError::Closed);
        }
        let mut queue = self
            .inner
            .queue
            .lock()
            .map_err(|_| SubmitError::Unavailable)?;
        if !self.inner.accepting.load(Ordering::Acquire) {
            return Err(SubmitError::Closed);
        }
        let outcome = queue.push(record.priority, record);
        drop(queue);
        self.inner.notify.notify_one();
        Ok(outcome)
    }

    pub fn stats(&self) -> Result<QueueStats, SubmitError> {
        self.inner
            .queue
            .lock()
            .map(|queue| queue.stats().clone())
            .map_err(|_| SubmitError::Unavailable)
    }

    pub async fn run_writer<S, F>(
        &self,
        mut shutdown: oneshot::Receiver<()>,
        mut sink: S,
    ) -> Result<WriterSummary, String>
    where
        S: FnMut(DaemonRecord) -> F,
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
            if let Some(record) = self.pop()? {
                match sink(record).await {
                    Ok(RecordWriteOutcome::Written) => {
                        written = written.saturating_add(1);
                    }
                    Ok(RecordWriteOutcome::Failed) => {
                        failed = failed.saturating_add(1);
                    }
                    Err(error) => {
                        self.inner.accepting.store(false, Ordering::Release);
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

    fn pop(&self) -> Result<Option<DaemonRecord>, String> {
        self.inner
            .queue
            .lock()
            .map_err(|_| "event pipeline queue is unavailable".to_string())
            .map(|mut queue| queue.pop())
    }
}

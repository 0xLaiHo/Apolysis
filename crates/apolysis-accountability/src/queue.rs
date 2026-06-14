// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuePriority {
    Ordinary,
    Lifecycle,
    Diagnostic,
    Finding,
    Integrity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PushOutcome {
    Accepted,
    AcceptedAfterShedding { dropped: QueuePriority },
    Dropped { dropped: QueuePriority },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueStats {
    pub capacity: usize,
    pub depth: usize,
    pub accepted: u64,
    dropped: BTreeMap<QueuePriority, u64>,
}

impl QueueStats {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            depth: 0,
            accepted: 0,
            dropped: BTreeMap::new(),
        }
    }

    pub fn dropped(&self, priority: QueuePriority) -> u64 {
        self.dropped.get(&priority).copied().unwrap_or(0)
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    pub fn with_accepted(mut self, accepted: u64) -> Self {
        self.accepted = accepted;
        self
    }

    pub fn with_drop(mut self, priority: QueuePriority) -> Self {
        self.increment_drop(priority);
        self
    }

    fn increment_drop(&mut self, priority: QueuePriority) {
        *self.dropped.entry(priority).or_insert(0) += 1;
    }
}

pub struct BoundedPriorityQueue<T> {
    queues: BTreeMap<QueuePriority, VecDeque<T>>,
    stats: QueueStats,
}

impl<T> BoundedPriorityQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            queues: BTreeMap::new(),
            stats: QueueStats::new(capacity),
        }
    }

    pub fn push(&mut self, priority: QueuePriority, value: T) -> PushOutcome {
        if self.stats.depth < self.stats.capacity {
            self.enqueue(priority, value);
            return PushOutcome::Accepted;
        }

        if priority != QueuePriority::Ordinary && self.shed_oldest_ordinary() {
            self.stats.increment_drop(QueuePriority::Ordinary);
            self.enqueue(priority, value);
            return PushOutcome::AcceptedAfterShedding {
                dropped: QueuePriority::Ordinary,
            };
        }

        self.stats.increment_drop(priority);
        PushOutcome::Dropped { dropped: priority }
    }

    pub fn pop(&mut self) -> Option<T> {
        for priority in [
            QueuePriority::Integrity,
            QueuePriority::Finding,
            QueuePriority::Diagnostic,
            QueuePriority::Lifecycle,
            QueuePriority::Ordinary,
        ] {
            if let Some(value) = self.queues.get_mut(&priority).and_then(VecDeque::pop_front) {
                self.stats.depth -= 1;
                return Some(value);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.stats.depth
    }

    pub fn is_empty(&self) -> bool {
        self.stats.depth == 0
    }

    pub fn stats(&self) -> &QueueStats {
        &self.stats
    }

    fn enqueue(&mut self, priority: QueuePriority, value: T) {
        self.queues.entry(priority).or_default().push_back(value);
        self.stats.depth += 1;
        self.stats.accepted += 1;
    }

    fn shed_oldest_ordinary(&mut self) -> bool {
        let dropped = self
            .queues
            .get_mut(&QueuePriority::Ordinary)
            .and_then(VecDeque::pop_front)
            .is_some();
        if dropped {
            self.stats.depth -= 1;
        }
        dropped
    }
}

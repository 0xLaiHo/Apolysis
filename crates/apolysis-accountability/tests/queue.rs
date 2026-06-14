// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{BoundedPriorityQueue, PushOutcome, QueuePriority, QueueStats};

#[test]
fn preserves_fifo_order_within_each_priority() {
    let mut queue = BoundedPriorityQueue::new(5);
    queue.push(QueuePriority::Ordinary, "event-1");
    queue.push(QueuePriority::Finding, "finding-1");
    queue.push(QueuePriority::Ordinary, "event-2");
    queue.push(QueuePriority::Finding, "finding-2");

    assert_eq!(queue.pop(), Some("finding-1"));
    assert_eq!(queue.pop(), Some("finding-2"));
    assert_eq!(queue.pop(), Some("event-1"));
    assert_eq!(queue.pop(), Some("event-2"));
}

#[test]
fn protected_record_evicts_the_oldest_ordinary_event_when_full() {
    let mut queue = BoundedPriorityQueue::new(2);
    assert_eq!(
        queue.push(QueuePriority::Ordinary, "event-1"),
        PushOutcome::Accepted
    );
    queue.push(QueuePriority::Ordinary, "event-2");

    assert_eq!(
        queue.push(QueuePriority::Integrity, "integrity-1"),
        PushOutcome::AcceptedAfterShedding {
            dropped: QueuePriority::Ordinary
        }
    );
    assert_eq!(queue.pop(), Some("integrity-1"));
    assert_eq!(queue.pop(), Some("event-2"));
    assert_eq!(queue.stats().dropped(QueuePriority::Ordinary), 1);
}

#[test]
fn ordinary_record_is_rejected_when_queue_is_full() {
    let mut queue = BoundedPriorityQueue::new(1);
    queue.push(QueuePriority::Finding, "finding");
    assert_eq!(
        queue.push(QueuePriority::Ordinary, "event"),
        PushOutcome::Dropped {
            dropped: QueuePriority::Ordinary
        }
    );
    assert_eq!(queue.len(), 1);
}

#[test]
fn protected_record_is_counted_as_dropped_when_no_ordinary_record_can_be_shed() {
    let mut queue = BoundedPriorityQueue::new(1);
    queue.push(QueuePriority::Integrity, "integrity");
    assert_eq!(
        queue.push(QueuePriority::Finding, "finding"),
        PushOutcome::Dropped {
            dropped: QueuePriority::Finding
        }
    );
    assert_eq!(queue.stats().dropped(QueuePriority::Finding), 1);
}

#[test]
fn queue_capacity_is_fixed_and_zero_capacity_never_accepts_records() {
    let mut queue = BoundedPriorityQueue::new(0);
    assert_eq!(
        queue.push(QueuePriority::Diagnostic, "diagnostic"),
        PushOutcome::Dropped {
            dropped: QueuePriority::Diagnostic
        }
    );
    assert_eq!(
        queue.stats(),
        &QueueStats::new(0).with_drop(QueuePriority::Diagnostic)
    );
}

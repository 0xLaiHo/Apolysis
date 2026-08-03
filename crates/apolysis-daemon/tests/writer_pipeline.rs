// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use apolysis_accountability::{PushOutcome, QueuePriority};
use apolysis_daemon::{
    DaemonRecord, EventPipeline, RecordDeliveryMode, RecordWriteOutcome, SubmitError,
};
use serde_json::json;
use tokio::sync::oneshot;

#[tokio::test]
async fn protected_records_shed_ordinary_events_and_write_first() {
    let pipeline = EventPipeline::new(2);
    assert_eq!(
        pipeline.submit(record("ordinary-a", QueuePriority::Ordinary)),
        Ok(PushOutcome::Accepted)
    );
    assert_eq!(
        pipeline.submit(record("ordinary-b", QueuePriority::Ordinary)),
        Ok(PushOutcome::Accepted)
    );
    assert_eq!(
        pipeline.submit(record("finding", QueuePriority::Finding)),
        Ok(PushOutcome::AcceptedAfterShedding {
            dropped: QueuePriority::Ordinary
        })
    );

    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&written);
    let (shutdown, receiver) = oneshot::channel();
    shutdown.send(()).unwrap();
    let summary = pipeline
        .run_writer(receiver, move |record, _delivery_mode| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(record.session_id);
                Ok(RecordWriteOutcome::Written)
            }
        })
        .await
        .expect("writer drain");

    assert_eq!(*written.lock().unwrap(), vec!["finding", "ordinary-b"]);
    assert_eq!(summary.written, 2);
    assert_eq!(summary.final_stats.depth, 0);
    assert_eq!(summary.final_stats.dropped(QueuePriority::Ordinary), 1);
}

#[tokio::test]
async fn shutdown_stops_admission_and_drains_accepted_records() {
    let pipeline = EventPipeline::new(4);
    pipeline
        .submit(record("lifecycle", QueuePriority::Lifecycle))
        .expect("accepted lifecycle");
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&written);
    let (shutdown, receiver) = oneshot::channel();
    let runner = {
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            pipeline
                .run_writer(receiver, move |record, _delivery_mode| {
                    let sink = Arc::clone(&sink);
                    async move {
                        sink.lock().unwrap().push(record.session_id);
                        Ok(RecordWriteOutcome::Written)
                    }
                })
                .await
        })
    };

    shutdown.send(()).unwrap();
    let summary = runner.await.unwrap().expect("clean writer shutdown");

    assert_eq!(summary.written, 1);
    assert_eq!(*written.lock().unwrap(), vec!["lifecycle"]);
    assert_eq!(
        pipeline.submit(record("late", QueuePriority::Finding)),
        Err(SubmitError::Closed)
    );
}

#[tokio::test]
async fn writer_counts_handled_record_failures_and_continues() {
    let pipeline = EventPipeline::new(4);
    pipeline
        .submit(record("bad-session", QueuePriority::Ordinary))
        .expect("accepted bad session");
    pipeline
        .submit(record("healthy-session", QueuePriority::Ordinary))
        .expect("accepted healthy session");
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&written);
    let (shutdown, receiver) = oneshot::channel();
    shutdown.send(()).unwrap();
    let summary = pipeline
        .run_writer(receiver, move |record, _delivery_mode| {
            let sink = Arc::clone(&sink);
            async move {
                if record.session_id == "bad-session" {
                    Ok(RecordWriteOutcome::Failed)
                } else {
                    sink.lock().unwrap().push(record.session_id);
                    Ok(RecordWriteOutcome::Written)
                }
            }
        })
        .await
        .expect("writer drain");

    assert_eq!(summary.written, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(*written.lock().unwrap(), vec!["healthy-session"]);
}

#[tokio::test]
async fn confirmed_submission_waits_for_the_writer_outcome() {
    let pipeline = EventPipeline::new(1);
    let (sink_entered, sink_entered_receiver) = oneshot::channel();
    let (release_sink, release_sink_receiver) = oneshot::channel();
    let (shutdown, shutdown_receiver) = oneshot::channel();
    let writer = {
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            let mut sink_entered = Some(sink_entered);
            let mut release_sink_receiver = Some(release_sink_receiver);
            pipeline
                .run_writer(shutdown_receiver, move |_record, delivery_mode| {
                    let sink_entered = sink_entered.take();
                    let release_sink_receiver = release_sink_receiver.take();
                    async move {
                        sink_entered
                            .expect("single record")
                            .send(delivery_mode)
                            .unwrap();
                        release_sink_receiver
                            .expect("single record")
                            .await
                            .expect("release writer");
                        Ok(RecordWriteOutcome::Written)
                    }
                })
                .await
        })
    };
    let confirmation = {
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            pipeline
                .submit_and_wait(record("gap", QueuePriority::Gap))
                .await
        })
    };

    assert_eq!(
        sink_entered_receiver.await.expect("writer receives record"),
        RecordDeliveryMode::Confirmed
    );
    assert!(!confirmation.is_finished());
    release_sink.send(()).expect("release writer");
    assert_eq!(
        confirmation.await.unwrap().expect("confirmed write"),
        RecordWriteOutcome::Written
    );
    shutdown.send(()).expect("stop writer");
    writer.await.unwrap().expect("writer drain");
}

#[tokio::test]
async fn confirmed_submission_fails_loud_when_admission_sheds_a_record() {
    let pipeline = EventPipeline::new(1);
    pipeline
        .submit(record("ordinary", QueuePriority::Ordinary))
        .expect("fill queue");

    let error = pipeline
        .submit_and_wait(record("gap", QueuePriority::Gap))
        .await
        .expect_err("confirmed admission must report shedding");

    assert!(error.contains("shed a Ordinary record"));
    assert_eq!(
        pipeline
            .stats()
            .expect("queue stats")
            .dropped(QueuePriority::Ordinary),
        1
    );
}

#[tokio::test]
async fn fence_waits_for_the_full_queue_snapshot_without_consuming_capacity() {
    let pipeline = EventPipeline::new(1);
    pipeline
        .submit(record("before-fence", QueuePriority::Ordinary))
        .expect("fill queue");
    let fence = {
        let pipeline = pipeline.clone();
        tokio::spawn(async move { pipeline.fence().await })
    };
    tokio::task::yield_now().await;
    assert!(!fence.is_finished());
    assert_eq!(pipeline.stats().expect("queue stats").accepted, 1);

    let (shutdown, receiver) = oneshot::channel();
    let writer = {
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            pipeline
                .run_writer(receiver, |_record, _delivery_mode| async {
                    Ok(RecordWriteOutcome::Written)
                })
                .await
        })
    };
    fence.await.unwrap().expect("fence completes after drain");
    shutdown.send(()).expect("stop writer");
    writer.await.unwrap().expect("writer drain");
}

fn record(session_id: &str, priority: QueuePriority) -> DaemonRecord {
    DaemonRecord::new(
        session_id,
        priority,
        json!({"record_type":"test","session_id":session_id}),
    )
}

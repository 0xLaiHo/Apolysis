// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use apolysis_accountability::{PushOutcome, QueuePriority};
use apolysis_daemon::{DaemonRecord, EventPipeline, SubmitError};
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
        .run_writer(receiver, move |record| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(record.session_id);
                Ok(())
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
                .run_writer(receiver, move |record| {
                    let sink = Arc::clone(&sink);
                    async move {
                        sink.lock().unwrap().push(record.session_id);
                        Ok(())
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

fn record(session_id: &str, priority: QueuePriority) -> DaemonRecord {
    DaemonRecord::new(
        session_id,
        priority,
        json!({"record_type":"test","session_id":session_id}),
    )
}

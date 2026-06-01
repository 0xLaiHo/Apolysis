// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{CanonicalEvent, EventSource, EventType};
use apolysis_store::{AsyncJsonlStore, JsonlStore};

#[test]
fn jsonl_store_appends_one_event_per_line() {
    let path =
        std::env::temp_dir().join(format!("apolysis-jsonl-store-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let mut store = JsonlStore::create(&path).expect("create jsonl store");
    store
        .append(&CanonicalEvent::new(
            "session-1",
            EventSource::Manual,
            EventType::Exec,
            7,
            1,
            "echo hello",
            "process",
            "exec",
        ))
        .expect("append event");
    store.flush().expect("flush event");

    let contents = std::fs::read_to_string(&path).expect("read jsonl output");
    assert_eq!(contents.lines().count(), 1);
    assert!(contents.contains(r#""actor":"echo hello""#));

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn async_jsonl_store_appends_one_event_per_line() {
    let path = std::env::temp_dir().join(format!(
        "apolysis-async-jsonl-store-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let event = CanonicalEvent::new(
        "session-async",
        EventSource::Manual,
        EventType::Exec,
        42,
        1,
        "python3",
        "process",
        "exec",
    );

    let mut store = AsyncJsonlStore::create(&path).await.expect("create store");
    store.append(&event).await.expect("append event");
    store.flush().await.expect("flush store");

    let output = std::fs::read_to_string(&path).expect("read jsonl");
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains(r#""session_id":"session-async""#));

    let _ = std::fs::remove_file(&path);
}

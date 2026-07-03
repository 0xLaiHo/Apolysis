// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{CanonicalEvent, EventSource, EventType};
use apolysis_store::{AsyncJsonlStore, JsonlRotationPolicy, JsonlStore};

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

#[test]
fn rotating_jsonl_store_rotates_before_budget_boundary() {
    let path = std::env::temp_dir().join(format!(
        "apolysis-rotating-jsonl-store-{}.jsonl",
        std::process::id()
    ));
    let archive = path.with_extension("jsonl.1");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);

    let first = CanonicalEvent::new(
        "session-rotate",
        EventSource::Manual,
        EventType::Exec,
        42,
        1,
        "python3",
        "process",
        "exec",
    );
    let second = CanonicalEvent::new(
        "session-rotate",
        EventSource::Manual,
        EventType::NetworkConnect,
        42,
        1,
        "python3",
        "address_token:test:port:443",
        "connect",
    );
    let max_file_bytes = first.to_json_line().len() as u64 + 1;

    let mut store = JsonlStore::create_with_rotation(
        &path,
        JsonlRotationPolicy {
            max_file_bytes,
            max_archived_files: 1,
        },
    )
    .expect("create rotating jsonl store");
    store.append(&first).expect("append first event");
    store.append(&second).expect("append second event");
    store.flush().expect("flush rotating store");

    let active = std::fs::read_to_string(&path).expect("read active jsonl");
    let rotated = std::fs::read_to_string(&archive).expect("read rotated jsonl");
    assert_eq!(rotated.lines().count(), 1);
    assert!(rotated.contains(r#""event_type":"exec""#));
    assert_eq!(active.lines().count(), 1);
    assert!(active.contains(r#""event_type":"network_connect""#));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&archive);
}

#[test]
fn rotating_jsonl_store_rejects_invalid_policy() {
    let path = std::env::temp_dir().join(format!(
        "apolysis-invalid-rotating-jsonl-store-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let missing_byte_budget = JsonlStore::create_with_rotation_policy(
        &path,
        Some(JsonlRotationPolicy {
            max_file_bytes: 0,
            max_archived_files: 1,
        }),
    )
    .err()
    .expect("zero max_file_bytes is invalid");
    assert_eq!(missing_byte_budget.kind(), std::io::ErrorKind::InvalidInput);

    let missing_archive_budget = JsonlStore::create_with_rotation_policy(
        &path,
        Some(JsonlRotationPolicy {
            max_file_bytes: 1024,
            max_archived_files: 0,
        }),
    )
    .err()
    .expect("zero max_archived_files is invalid");
    assert_eq!(
        missing_archive_budget.kind(),
        std::io::ErrorKind::InvalidInput
    );

    let _ = std::fs::remove_file(&path);
}

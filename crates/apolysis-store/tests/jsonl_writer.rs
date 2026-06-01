// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{CanonicalEvent, EventSource, EventType};
use apolysis_store::JsonlStore;

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

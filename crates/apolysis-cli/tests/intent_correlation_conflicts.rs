// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

fn declaration() -> Value {
    json!({
        "record_type": "intent", "session_id": "capture", "intent_source": "claude",
        "intent_id": "same-id", "tool_name": "Bash", "observation_mode": "local_shell",
        "command": "executable_ref:curl argv_redacted:true",
    })
}

fn correlate(intents: &[Value]) -> Vec<Value> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "apolysis-correlation-conflicts-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("intents"),
        intents
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>(),
    )
    .unwrap();
    std::fs::write(
        dir.join("events"),
        format!(
            "{}\n",
            json!({
                "record_type": "event", "session_id": "capture", "event_type": "exec",
                "raw_event_id": "raw-1", "intent_id": "same-id", "pid": 42,
                "resource": "executable_ref:curl",
            })
        ),
    )
    .unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .args(["intent", "correlate", "--intent-input"])
        .arg(dir.join("intents"))
        .arg("--timeline-input")
        .arg(dir.join("events"))
        .arg("--output")
        .arg(dir.join("output"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let records = std::fs::read_to_string(dir.join("output"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    std::fs::remove_dir_all(dir).unwrap();
    records
}

fn assert_identifier_gap(records: &[Value]) {
    assert!(!records.iter().any(|record| matches!(
        record["record_type"].as_str(),
        Some("intent_correlation" | "intent_correlation_candidate")
    )));
    assert!(records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation_diagnostic"));
}

#[test]
fn conflicting_full_declaration_fields_are_not_lost_during_deduplication() {
    for field in ["declared_action", "target", "future_schema_field"] {
        let mut first = declaration();
        let mut second = declaration();
        first[field] = "first".into();
        second[field] = "second".into();
        assert_identifier_gap(&correlate(&[first, second]));
    }
}

#[test]
fn semantic_mode_filter_does_not_hide_conflicting_same_id_declarations() {
    let mut semantic = declaration();
    semantic["observation_mode"] = "semantic_only".into();
    assert_identifier_gap(&correlate(&[declaration(), semantic]));
}

#[test]
fn explicit_marker_for_semantic_only_declaration_is_a_gap_not_a_match() {
    let mut semantic = declaration();
    semantic["observation_mode"] = "semantic_only".into();
    assert_identifier_gap(&correlate(&[semantic]));
}

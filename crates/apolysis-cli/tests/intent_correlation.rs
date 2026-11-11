// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

fn intent(id: &str) -> Value {
    json!({"record_type":"intent", "session_id":"capture", "intent_source":"claude",
        "intent_id":id, "tool_name":"Bash", "command":"executable_ref:curl argv_redacted:true"})
}

fn event(id: Option<&str>) -> Value {
    json!({"record_type":"event", "session_id":"capture", "event_type":"exec",
        "raw_event_id":"raw-1", "intent_id":id, "pid":42, "resource":"executable_ref:curl",
        "process_executable":"executable_ref:curl"})
}

fn correlate(intents: &[Value], events: &[Value]) -> (Vec<Value>, String) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "apolysis-correlate-regression-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (file, values) in [("intents", intents), ("events", events)] {
        let body = values
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>();
        std::fs::write(dir.join(file), body).unwrap();
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .args(["intent", "correlate", "--intent-input"])
        .arg(dir.join("intents"))
        .arg("--timeline-input")
        .arg(dir.join("events"))
        .arg("--output")
        .arg(dir.join("output"))
        .arg("--summary")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = std::fs::read_to_string(dir.join("output"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    std::fs::remove_dir_all(dir).unwrap();
    (records, String::from_utf8(output.stdout).unwrap())
}

#[test]
fn unknown_explicit_id_never_downgrades_to_executable() {
    let (records, _) = correlate(&[intent("expected")], &[event(Some("unknown"))]);
    assert!(!records.iter().any(|record| matches!(
        record["record_type"].as_str(),
        Some("intent_correlation" | "intent_correlation_candidate")
    )));
    assert!(records
        .iter()
        .any(|record| record["reason"] == "unrecognized_intent_id"));
}

#[test]
fn legacy_same_executable_is_ambiguous_not_first_match() {
    let (records, summary) = correlate(&[intent("one"), intent("two")], &[event(None)]);
    let candidates: Vec<_> = records
        .iter()
        .filter(|record| record["record_type"] == "intent_correlation_candidate")
        .collect();
    assert_eq!(candidates.len(), 2);
    assert!(candidates
        .iter()
        .all(|record| record["relation_status"] == "ambiguous" && record["candidate_count"] == 2));
    assert!(!records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation"));
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "unobserved_intent")
            .count(),
        2
    );
    assert!(summary.contains("ambiguous"));
}

#[test]
fn conflicting_raw_and_intent_ids_do_not_select_either() {
    let mut first = intent("one");
    first["raw_event_id"] = "raw-1".into();
    let (records, _) = correlate(&[first, intent("two")], &[event(Some("two"))]);
    assert!(records
        .iter()
        .any(|record| record["reason"] == "conflicting_identifiers"));
    assert!(!records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation"));
}

#[test]
fn duplicated_identical_declarations_do_not_create_false_ambiguity() {
    let (records, _) = correlate(&[intent("one"), intent("one")], &[event(Some("one"))]);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record_type"], "intent_correlation");
    assert_eq!(records[0]["relation_status"], "exact");
}

#[test]
fn conflicting_declarations_with_same_id_are_not_silently_deduplicated() {
    let mut second = intent("one");
    second["harness_session_id"] = "other-native".into();
    let (records, _) = correlate(&[intent("one"), second], &[event(Some("one"))]);
    assert!(records
        .iter()
        .any(|record| record["reason"] == "ambiguous_intent_id"));
    assert!(!records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation"));
}

#[test]
fn session_mismatch_cannot_match_even_an_identical_id() {
    let mut observed = event(Some("one"));
    observed["session_id"] = "another-capture".into();
    let (records, _) = correlate(&[intent("one")], &[observed]);
    assert!(!records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation"));
}

#[test]
fn semantic_only_declarations_are_not_reported_as_missing_runtime_evidence() {
    let mut declared = intent("web");
    declared["observation_mode"] = "semantic_only".into();
    let (records, summary) = correlate(&[declared], &[]);
    assert!(records.is_empty());
    assert!(!summary.contains("every observed side effect matched"));
    assert!(summary.contains("does not establish complete coverage"));
}

#[test]
fn one_explicit_intent_can_link_multiple_attempts() {
    let mut open = event(Some("one"));
    open["event_type"] = "file_open".into();
    open["raw_event_id"] = "raw-2".into();
    let mut connect = event(Some("one"));
    connect["event_type"] = "network_connect".into();
    connect["raw_event_id"] = "raw-3".into();
    let (records, _) = correlate(&[intent("one")], &[event(Some("one")), open, connect]);
    assert_eq!(records.len(), 3);
    assert!(records
        .iter()
        .all(|record| record["record_type"] == "intent_correlation"));
}

#[test]
fn weak_command_candidate_does_not_hide_missing_intent_findings() {
    let mut observed = event(None);
    observed["event_type"] = "network_connect".into();
    observed["process_command"] = "executable_ref:curl argv_redacted:true".into();
    let (records, _) = correlate(&[intent("one")], &[observed]);
    assert!(records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation_candidate"));
    assert!(records
        .iter()
        .any(|record| record["kind"] == "missing_intent"));
}

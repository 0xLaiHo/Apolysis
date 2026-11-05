// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::{Command, Stdio};

use apolysis_core::SessionIntentRecord;
use apolysis_store::{append_intent, IntentAppendOutcome};

fn record(id: &str) -> SessionIntentRecord {
    SessionIntentRecord::new("capture", "test", id, "tool_call", "Bash")
        .with_source_event_id(id)
        .with_harness_session_id("native")
        .with_observation_mode("local_shell")
}

fn path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "apolysis-intent-append-{label}-{}.jsonl",
        std::process::id()
    ))
}

#[test]
fn independent_writers_append_and_retry_without_truncating() {
    let path = path("retry");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        append_intent(&path, &record("first")).unwrap(),
        IntentAppendOutcome::Appended
    );
    assert_eq!(
        append_intent(&path, &record("second")).unwrap(),
        IntentAppendOutcome::Appended
    );
    assert_eq!(
        append_intent(&path, &record("first").with_timestamp(42)).unwrap(),
        IntentAppendOutcome::AlreadyRecorded
    );
    let body = std::fs::read_to_string(&path).unwrap();
    assert_eq!(body.lines().count(), 2);
    assert!(body.contains("first") && body.contains("second"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn conflicting_identity_and_partial_tail_do_not_change_evidence() {
    let path = path("conflict");
    let _ = std::fs::remove_file(&path);
    append_intent(&path, &record("first")).unwrap();
    let original = std::fs::read(&path).unwrap();
    let conflict = record("first").with_command("executable_ref:other argv_redacted:true");
    assert!(append_intent(&path, &conflict).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    std::fs::write(&path, &original[..original.len() - 1]).unwrap();
    assert!(append_intent(&path, &record("second")).is_err());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original[..original.len() - 1]
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn separate_native_sessions_can_reuse_a_product_call_id() {
    let path = path("native");
    let _ = std::fs::remove_file(&path);
    let first = record("id-1").with_source_event_id("same-call");
    let second = record("id-2")
        .with_source_event_id("same-call")
        .with_harness_session_id("another-native");
    append_intent(&path, &first).unwrap();
    append_intent(&path, &second).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    std::fs::remove_file(path).unwrap();
}

// Invoked only by concurrent_processes_keep_complete_unique_lines below.
#[test]
fn append_subprocess() {
    let Ok(path) = std::env::var("APOLYSIS_APPEND_TEST_PATH") else {
        return;
    };
    let worker = std::env::var("APOLYSIS_APPEND_TEST_WORKER").unwrap();
    for index in 0..8 {
        let record = record(&format!("{worker}-{index}"));
        append_intent(&path, &record).unwrap();
        append_intent(&path, &record).unwrap();
    }
}

#[test]
fn concurrent_processes_keep_complete_unique_lines() {
    let path = path("concurrent");
    let _ = std::fs::remove_file(&path);
    let executable = std::env::current_exe().unwrap();
    let mut children: Vec<_> = (0..12)
        .map(|worker| {
            Command::new(&executable)
                .args(["--exact", "append_subprocess"])
                .env("APOLYSIS_APPEND_TEST_PATH", &path)
                .env("APOLYSIS_APPEND_TEST_WORKER", worker.to_string())
                .stdout(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let body = std::fs::read_to_string(&path).unwrap();
    let ids: std::collections::HashSet<_> = body
        .lines()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            value["intent_id"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(body.lines().count(), 96);
    assert_eq!(ids.len(), 96);
    std::fs::remove_file(path).unwrap();
}

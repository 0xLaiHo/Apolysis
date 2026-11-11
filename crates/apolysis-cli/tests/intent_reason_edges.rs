// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

const INTENT_ID: &str = "0123456789abcdef0123456789abcdef";
const OTHER_ID: &str = "fedcba9876543210fedcba9876543210";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "apolysis-reason-edges-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, values: &[Value]) {
        let body = values
            .iter()
            .map(|value| format!("{value}\n"))
            .collect::<String>();
        std::fs::write(self.path(name), body).unwrap();
    }

    fn seed(&self, intents: &[Value], events: &[Value], reasons: &[Value]) {
        self.write("intents", intents);
        self.write("events", events);
        self.write("reasons", reasons);
    }

    fn correlate(&self, output: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_apolysis"))
            .args(["intent", "correlate", "--intent-input"])
            .arg(self.path("intents"))
            .arg("--timeline-input")
            .arg(self.path("events"))
            .arg("--reason-input")
            .arg(self.path("reasons"))
            .arg("--output")
            .arg(output)
            .output()
            .unwrap()
    }

    fn joined(&self) -> Vec<Value> {
        let output = self.correlate(&self.path("output"));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.read("output")
    }

    fn read(&self, name: &str) -> Vec<Value> {
        std::fs::read_to_string(self.path(name))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn hook(&self, payload: &Value, reason_path: &Path) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_apolysis"))
            .args([
                "intent",
                "hook",
                "--harness",
                "claude",
                "--session",
                "capture",
                "--output",
            ])
            .arg(self.path("intents"))
            .arg("--workspace-root")
            .arg(&self.0)
            .arg("--reason-output")
            .arg(reason_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn intent() -> Value {
    json!({"record_type":"intent", "session_id":"capture", "intent_source":"claude",
        "intent_id":INTENT_ID, "tool_name":"Bash", "command":"executable_ref:cat argv_redacted:true",
        "harness_session_id":"native", "source_event_id":"call", "observation_mode":"local_shell"})
}

fn reason() -> Value {
    json!({"record_type":"intent_reason", "timestamp_unix_ms":42, "session_id":"capture",
        "intent_id":INTENT_ID, "intent_source":"claude", "harness_session_id":"native",
        "source_event_id":"call", "reason_id":"reason", "reason_code":"inspect_context",
        "reason_source":"agent_declared", "reason_summary":null, "task_ref":null,
        "supersedes_reason_id":null})
}

fn event(id: Option<&str>) -> Value {
    json!({"record_type":"event", "session_id":"capture", "event_type":"exec",
        "raw_event_id":"event-1", "intent_id":id, "resource":"executable_ref:cat",
        "process_executable":"executable_ref:cat"})
}

fn hook_payload() -> Value {
    json!({"session_id":"native", "tool_use_id":"call", "tool_name":"Bash",
        "tool_input":{"command":"true"}, "apolysis_reason":{"reason_code":"verify_change"}})
}

#[test]
fn weak_executable_candidate_never_inherits_a_declared_reason_or_becomes_exact() {
    let fixture = Fixture::new();
    fixture.seed(&[intent()], &[event(None)], &[reason()]);
    let records = fixture.joined();
    let candidate = records
        .iter()
        .find(|record| record["record_type"] == "intent_correlation_candidate")
        .unwrap();
    assert_eq!(candidate["relation_status"], "inferred");
    assert!(candidate.get("declared_reason").is_none());
    assert!(!records
        .iter()
        .any(|record| record["record_type"] == "intent_correlation"));
    assert!(records
        .iter()
        .any(|record| record["kind"] == "unobserved_intent"));
    assert!(records
        .iter()
        .any(|record| record["record_type"] == "intent_reason_binding"));
}

#[test]
fn reason_cannot_repair_an_unknown_explicit_event_identifier() {
    let fixture = Fixture::new();
    fixture.seed(&[intent()], &[event(Some(OTHER_ID))], &[reason()]);
    let records = fixture.joined();
    assert!(records
        .iter()
        .any(|record| record["reason"] == "unrecognized_intent_id"));
    assert!(records
        .iter()
        .any(|record| record["kind"] == "unobserved_intent"));
    assert!(!records.iter().any(|record| matches!(
        record["record_type"].as_str(),
        Some("intent_correlation" | "intent_correlation_candidate")
    )));
}

#[test]
fn complete_native_identity_is_required_even_when_intent_token_matches() {
    for field in ["intent_source", "harness_session_id", "source_event_id"] {
        let fixture = Fixture::new();
        let mut wrong = reason();
        wrong[field] = "another".into();
        fixture.seed(&[intent()], &[event(Some(INTENT_ID))], &[wrong]);
        let records = fixture.joined();
        assert!(records
            .iter()
            .any(|record| record["reason"] == "reason_identity_mismatch"));
        assert!(!records
            .iter()
            .any(|record| record["record_type"] == "intent_reason_binding"));
        let exact = records
            .iter()
            .find(|record| record["record_type"] == "intent_correlation")
            .unwrap();
        assert!(exact.get("declared_reason").is_none());
    }
    let fixture = Fixture::new();
    let mut legacy = intent();
    legacy.as_object_mut().unwrap().remove("harness_session_id");
    fixture.seed(&[legacy], &[event(Some(INTENT_ID))], &[reason()]);
    let records = fixture.joined();
    assert!(records
        .iter()
        .any(|record| record["reason"] == "reason_identity_mismatch"));
}

#[test]
fn exact_raw_event_join_can_be_annotated_and_timestamp_retries_are_deduplicated() {
    let fixture = Fixture::new();
    let mut declaration = intent();
    declaration["raw_event_id"] = "event-1".into();
    let mut retry = reason();
    retry["timestamp_unix_ms"] = 100.into();
    fixture.seed(&[declaration], &[event(None)], &[reason(), retry]);
    let records = fixture.joined();
    let exact = records
        .iter()
        .find(|record| record["record_type"] == "intent_correlation")
        .unwrap();
    assert_eq!(exact["match_basis"], "raw_event_id");
    assert_eq!(exact["declared_reason"]["reason_code"], "inspect_context");
    assert_eq!(
        records
            .iter()
            .filter(|record| record["record_type"] == "intent_reason_binding")
            .count(),
        1
    );
    assert!(!records
        .iter()
        .any(|record| record["record_type"] == "intent_reason_diagnostic"));
}

#[test]
fn cross_call_reason_id_conflict_diagnoses_both_affected_calls_without_binding() {
    let fixture = Fixture::new();
    let mut second_intent = intent();
    second_intent["intent_id"] = OTHER_ID.into();
    second_intent["source_event_id"] = "second-call".into();
    let mut second_reason = reason();
    second_reason["intent_id"] = OTHER_ID.into();
    second_reason["source_event_id"] = "second-call".into();
    let mut second_event = event(Some(OTHER_ID));
    second_event["raw_event_id"] = "event-2".into();
    fixture.seed(
        &[intent(), second_intent],
        &[event(Some(INTENT_ID)), second_event],
        &[reason(), second_reason],
    );
    let records = fixture.joined();
    for intent_id in [INTENT_ID, OTHER_ID] {
        assert!(records
            .iter()
            .any(|record| record["reason"] == "conflicting_reason_id"
                && record["intent_id"] == intent_id));
    }
    assert!(!records
        .iter()
        .any(|record| record.get("declared_reason").is_some()));
    assert_eq!(
        records
            .iter()
            .filter(|record| record["record_type"] == "intent_correlation")
            .count(),
        2
    );
}

#[test]
fn malformed_or_truncated_reasons_fail_with_static_errors_and_preserve_output() {
    let valid = reason().to_string();
    for malformed in [
        valid.clone(), // complete JSON without the committed JSONL delimiter
        format!("{valid}\n\n"),
        format!("{valid}\n{{\"record_type\":\"intent\"}}\n"),
        format!(
            "{},\"SYNTHETIC_PRIVATE_INPUT\":\"private\"}}\n",
            valid.trim_end_matches('}')
        ),
        format!(
            "{},\"reason_id\":\"SYNTHETIC_PRIVATE_INPUT\"}}\n",
            valid.trim_end_matches('}')
        ),
        valid.replace("\"agent_declared\"", "\"SYNTHETIC_PRIVATE_INPUT\"") + "\n",
    ] {
        let fixture = Fixture::new();
        fixture.seed(&[intent()], &[event(Some(INTENT_ID))], &[]);
        std::fs::write(fixture.path("reasons"), malformed).unwrap();
        std::fs::write(fixture.path("output"), "existing evidence\n").unwrap();
        let output = fixture.correlate(&fixture.path("output"));
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            matches!(
                stderr.trim(),
                "apolysis: invalid intent reason input"
                    | "apolysis: intent reason input has an incomplete trailing line"
            ),
            "{stderr}"
        );
        assert!(!stderr.contains("SYNTHETIC_PRIVATE_INPUT"));
        assert_eq!(
            std::fs::read_to_string(fixture.path("output")).unwrap(),
            "existing evidence\n"
        );
    }
}

#[test]
fn correlation_output_must_not_replace_any_input_file() {
    for name in ["intents", "events", "reasons"] {
        let fixture = Fixture::new();
        fixture.seed(&[intent()], &[event(Some(INTENT_ID))], &[reason()]);
        let before = std::fs::read(fixture.path(name)).unwrap();
        let output = fixture.correlate(&fixture.path(name));
        assert!(!output.status.success(), "accepted input alias {name}");
        assert_eq!(std::fs::read(fixture.path(name)).unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn correlation_output_rejects_symlink_and_hardlink_aliases_of_reason_history() {
    for symlink in [true, false] {
        let fixture = Fixture::new();
        fixture.seed(&[intent()], &[event(Some(INTENT_ID))], &[reason()]);
        let original = fixture.path("reasons");
        let alias = fixture.path("alias");
        if symlink {
            std::os::unix::fs::symlink(&original, &alias).unwrap();
        } else {
            std::fs::hard_link(&original, &alias).unwrap();
        }
        let before = std::fs::read(&original).unwrap();
        let output = fixture.correlate(&alias);
        assert!(!output.status.success());
        assert_eq!(std::fs::read(&original).unwrap(), before);
    }
}

#[test]
fn reason_storage_failure_returns_no_marker_and_retry_recovers_without_duplicate_intent() {
    let fixture = Fixture::new();
    let reason_path = fixture.path("reasons");
    std::fs::create_dir(&reason_path).unwrap();
    let first = fixture.hook(&hook_payload(), &reason_path);
    assert!(!first.status.success());
    assert!(first.stdout.is_empty());
    let before = std::fs::read(fixture.path("intents")).unwrap();
    assert_eq!(fixture.read("intents").len(), 1);
    std::fs::remove_dir(&reason_path).unwrap();
    let retry = fixture.hook(&hook_payload(), &reason_path);
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(std::fs::read(fixture.path("intents")).unwrap(), before);
    let intents = fixture.read("intents");
    let reasons = fixture.read("reasons");
    assert_eq!(reasons.len(), 1);
    assert_eq!(reasons[0]["intent_id"], intents[0]["intent_id"]);
    assert!(String::from_utf8(retry.stdout)
        .unwrap()
        .contains(intents[0]["intent_id"].as_str().unwrap()));
}

#[test]
fn invalid_reason_reference_is_rejected_before_appending_intent() {
    for reference in ["not:opaque".to_string(), "a".repeat(65)] {
        let fixture = Fixture::new();
        let mut payload = hook_payload();
        payload["apolysis_reason"]["reason_id"] = reference.into();
        let output = fixture.hook(&payload, &fixture.path("reasons"));
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!fixture.path("intents").exists());
        assert!(!fixture.path("reasons").exists());
    }
}

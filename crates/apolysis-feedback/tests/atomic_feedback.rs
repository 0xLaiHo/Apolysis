// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{EnforcementBackend, PolicyDecision, PolicyViolation};
use apolysis_feedback::FeedbackWriter;

#[test]
fn writes_human_and_machine_readable_feedback_atomically() {
    let directory =
        std::env::temp_dir().join(format!("apolysis-atomic-feedback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let writer = FeedbackWriter::new(&directory);

    writer
        .write_last_violation(&violation("rule.first", "first reason"))
        .expect("first feedback");
    writer
        .write_last_violation(&violation("rule.second", "second reason"))
        .expect("replace feedback");

    let text = std::fs::read_to_string(writer.path()).expect("text feedback");
    assert!(text.contains("rule_id: rule.second"));
    assert!(!text.contains("rule.first"));

    let json = std::fs::read_to_string(writer.json_path()).expect("JSON feedback");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["rule_id"], "rule.second");
    assert_eq!(value["reason"], "second reason");

    let temporary_files: Vec<_> = std::fs::read_dir(&directory)
        .expect("feedback directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(
        temporary_files.is_empty(),
        "temporary files remain: {temporary_files:?}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn machine_feedback_escapes_untrusted_fields() {
    let directory =
        std::env::temp_dir().join(format!("apolysis-feedback-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let writer = FeedbackWriter::new(&directory);
    writer
        .write_last_violation(&violation("rule.quote", "line 1\n\"line 2\""))
        .expect("feedback");

    let json = std::fs::read_to_string(writer.json_path()).expect("JSON feedback");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["reason"], "line 1\n\"line 2\"");

    let _ = std::fs::remove_dir_all(&directory);
}

fn violation(rule_id: &str, reason: &str) -> PolicyViolation {
    PolicyViolation::new(
        "session-runtime_foundation",
        rule_id,
        PolicyDecision::Notify,
        reason,
        42,
        "credential:path:abc",
        EnforcementBackend::TracepointNotify,
    )
}

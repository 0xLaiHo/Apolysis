// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{records, JsonLine, SessionIntentReasonRecord};

fn record() -> SessionIntentReasonRecord {
    SessionIntentReasonRecord {
        timestamp_unix_ms: 42,
        session_id: "capture".into(),
        intent_id: "0123456789abcdef0123456789abcdef".into(),
        intent_source: "codex".into(),
        harness_session_id: "native-session".into(),
        source_event_id: "call-1".into(),
        reason_id: "reason-1".into(),
        reason_code: "inspect_context".into(),
        reason_source: "agent_declared".into(),
        reason_summary: None,
        task_ref: None,
        supersedes_reason_id: None,
    }
}

#[test]
fn reason_record_keeps_join_identity_and_optional_content_explicit() {
    let reason = record();
    assert_eq!(records::INTENT_REASON, "intent_reason");
    assert_eq!(reason.validate(), Ok(()));
    let line = reason.to_json_line();
    assert_eq!(line, JsonLine::to_json_line(&reason));
    assert_eq!(
        line,
        concat!(
            "{\"record_type\":\"intent_reason\",\"timestamp_unix_ms\":42,",
            "\"session_id\":\"capture\",\"intent_id\":\"0123456789abcdef0123456789abcdef\",",
            "\"intent_source\":\"codex\",\"harness_session_id\":\"native-session\",",
            "\"source_event_id\":\"call-1\",\"reason_id\":\"reason-1\",",
            "\"reason_code\":\"inspect_context\",\"reason_source\":\"agent_declared\",",
            "\"reason_summary\":null,\"task_ref\":null,\"supersedes_reason_id\":null}"
        )
    );
    assert!(!line.contains("prompt"));
    assert!(!line.contains("command"));
}

#[test]
fn summary_limit_counts_unicode_characters_and_rejects_line_controls() {
    let mut reason = record();
    reason.reason_summary = Some("查".repeat(240));
    assert!(reason.validate().is_ok());
    reason.reason_summary = Some("查".repeat(241));
    assert!(reason.validate().is_err());
    for summary in [
        "first\nsecond",
        "first\rsecond",
        "first\tsecond",
        "first\u{85}second",
        "first\u{2028}second",
        "first\u{2029}second",
    ] {
        reason.reason_summary = Some(summary.into());
        assert!(reason.validate().is_err(), "accepted a line control");
    }
    reason.reason_summary = Some("Inspect \"quoted\" names \\ safely".into());
    assert!(reason.validate().is_ok());
    assert!(reason
        .to_json_line()
        .contains(r#"Inspect \"quoted\" names \\ safely"#));
}

#[test]
fn references_are_bounded_opaque_identifiers() {
    for reference in ["", "with/slash", "with space", "\u{00e9}", &"a".repeat(65)] {
        let mut reason = record();
        reason.reason_id = reference.into();
        assert!(reason.validate().is_err());
        reason = record();
        reason.task_ref = Some(reference.into());
        assert!(reason.validate().is_err());
        reason = record();
        reason.supersedes_reason_id = Some(reference.into());
        assert!(reason.validate().is_err());
    }
    let mut reason = record();
    reason.reason_id = "Az09_-".repeat(10);
    reason.task_ref = Some("t".repeat(64));
    assert!(reason.validate().is_ok());
    reason.supersedes_reason_id = Some(reason.reason_id.clone());
    assert!(reason.validate().is_err());
}

#[test]
fn invalid_or_incomplete_call_identity_is_rejected() {
    for token in [
        "",
        "a",
        "0123456789abcdef0123456789abcdeF",
        "g123456789abcdef0123456789abcdef",
    ] {
        let mut reason = record();
        reason.intent_id = token.into();
        assert!(reason.validate().is_err());
    }
    for field in 0..4 {
        let mut reason = record();
        let identity = match field {
            0 => &mut reason.session_id,
            1 => &mut reason.intent_source,
            2 => &mut reason.harness_session_id,
            _ => &mut reason.source_event_id,
        };
        *identity = " ".into();
        assert!(reason.validate().is_err());
    }
}

#[test]
fn descriptions_do_not_imply_a_declared_reason() {
    let mut reason = record();
    reason.reason_source = "tool_description".into();
    assert!(reason.validate().is_err());
    reason.reason_code = "unknown".into();
    assert!(reason.validate().is_ok());
    reason.reason_source = "inferred".into();
    assert!(reason.validate().is_err());
    reason.reason_source = "operator_annotation".into();
    reason.reason_code = "execute".into();
    assert!(reason.validate().is_err());
    for code in [
        "unknown",
        "inspect_context",
        "verify_change",
        "reproduce_issue",
        "implement_change",
        "diagnose_failure",
        "gather_evidence",
    ] {
        reason.reason_code = code.into();
        assert!(reason.validate().is_ok());
    }
}

// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{
    CanonicalEvent, EnforcementBackend, EventSource, EventType, PolicyDecision, PolicyViolation,
    RuntimeKind, SandboxSession,
};

#[test]
fn session_json_line_contains_stable_identity_fields() {
    let session = SandboxSession::new("session-1", RuntimeKind::Local, "policies/local-dev.yaml");

    let line = session.to_json_line();

    assert!(line.contains(r#""id":"session-1""#));
    assert!(line.contains(r#""runtime":"local""#));
    assert!(line.contains(r#""policy_path":"policies/local-dev.yaml""#));
}

#[test]
fn canonical_event_json_line_escapes_strings_and_records_actor_resource_action() {
    let event = CanonicalEvent::new(
        "session-1",
        EventSource::Manual,
        EventType::Exec,
        42,
        1,
        r#"bash -c "echo hi""#,
        "process",
        "exec",
    );

    let line = event.to_json_line();

    assert!(line.contains(r#""session_id":"session-1""#));
    assert!(line.contains(r#""event_type":"exec""#));
    assert!(line.contains(r#""pid":42"#));
    assert!(line.contains(r#""resource":"process""#));
    assert!(line.contains(r#"bash -c \"echo hi\""#));
}

#[test]
fn policy_violation_json_line_records_decision_and_backend() {
    let violation = PolicyViolation::new(
        "session-1",
        "deny-credentials",
        PolicyDecision::Notify,
        "credential path read",
        99,
        "~/.ssh/id_rsa",
        EnforcementBackend::AuditOnly,
    );

    let line = violation.to_json_line();

    assert!(line.contains(r#""decision":"notify""#));
    assert!(line.contains(r#""enforcement_backend":"audit_only""#));
    assert!(line.contains(r#""rule_id":"deny-credentials""#));
}

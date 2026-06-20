// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{
    actions, actors, env, feedback, records, resources, runtimes, CanonicalEvent,
    EnforcementBackend, EnforcementMetadata, EventSource, EventType, ObserverDiagnostic,
    ObserverDiagnosticKind, PolicyDecision, PolicyViolation, RawKernelEvent, RuntimeKind,
    SandboxSession,
};

#[test]
fn shared_schema_vocabulary_keeps_public_strings_stable() {
    assert_eq!(records::SESSION, "session");
    assert_eq!(records::EVENT, "event");
    assert_eq!(records::RAW_KERNEL_EVENT, "raw_kernel_event");
    assert_eq!(records::POLICY_VIOLATION, "policy_violation");
    assert_eq!(records::ENFORCEMENT_METADATA, "enforcement_metadata");
    assert_eq!(records::OBSERVER_DIAGNOSTIC, "observer_diagnostic");
    assert_eq!(actors::APOLYSIS, "apolysis");
    assert_eq!(actors::DOCKER, "docker");
    assert_eq!(runtimes::FIRECRACKER, "firecracker");
    assert_eq!(resources::PROCESS, "process");
    assert_eq!(actions::START, "start");
    assert_eq!(actions::EXEC, "exec");
    assert_eq!(env::SESSION_ID, "APOLYSIS_SESSION_ID");
    assert_eq!(feedback::VIOLATION_TAG, "APOLYSIS_VIOLATION");
    assert_eq!(EnforcementBackend::SeccompBlock.as_str(), "seccomp_block");
}

#[test]
fn enforcement_metadata_json_line_records_timing_and_capability_context() {
    let metadata = EnforcementMetadata::new(
        "session-1",
        PolicyDecision::Kill,
        PolicyDecision::Kill,
        EnforcementBackend::SignalKill,
        "post_event_containment",
        "local",
        "credential_read",
        false,
    )
    .with_rule_id("credentials.deny_read")
    .with_downgrade_reason(None::<String>)
    .with_measurement(1_780_328_000_003, 1_780_328_000_123);

    let line = metadata.to_json_line();

    assert!(line.contains(r#""record_type":"enforcement_metadata""#));
    assert!(line.contains(r#""requested_decision":"kill""#));
    assert!(line.contains(r#""effective_decision":"kill""#));
    assert!(line.contains(r#""enforcement_backend":"signal_kill""#));
    assert!(line.contains(r#""timing":"post_event_containment""#));
    assert!(line.contains(r#""runtime":"local""#));
    assert!(line.contains(r#""action":"credential_read""#));
    assert!(line.contains(r#""preoperation_prevention":false"#));
    assert!(line.contains(r#""observed_event_timestamp_unix_ms":1780328000003"#));
    assert!(line.contains(r#""decision_latency_ms":120"#));
    assert!(line.contains(r#""side_effect_race_window_ms":120"#));
    assert!(line.contains(r#""rule_id":"credentials.deny_read""#));
    assert!(line.contains(r#""downgrade_reason":null"#));
}

#[test]
fn enforcement_metadata_records_zero_race_window_for_preoperation_prevention() {
    let metadata = EnforcementMetadata::new(
        "session-1",
        PolicyDecision::Block,
        PolicyDecision::Block,
        EnforcementBackend::BpfLsmBlock,
        "pre_operation",
        "local",
        "file_read",
        true,
    )
    .with_measurement(1_780_328_000_003, 1_780_328_000_123);

    let line = metadata.to_json_line();

    assert!(line.contains(r#""decision_latency_ms":120"#));
    assert!(line.contains(r#""side_effect_race_window_ms":0"#));
}

#[test]
fn observer_diagnostic_json_line_records_typed_loss_evidence() {
    let diagnostic = ObserverDiagnostic::new(
        "session-1",
        ObserverDiagnosticKind::RingBufferReserveFailure,
        7,
        "kernel counter",
    );

    let line = diagnostic.to_json_line();

    assert!(line.contains(r#""record_type":"observer_diagnostic""#));
    assert!(line.contains(r#""kind":"ring_buffer_reserve_failure""#));
    assert!(line.contains(r#""count":7"#));
    assert!(line.contains(r#""detail":"kernel counter""#));
}

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
    assert!(line.contains(r#""container_id":null"#));
    assert!(line.contains(r#""cgroup_id":null"#));
}

#[test]
fn runtime_metadata_event_records_process_tree_source() {
    let event = CanonicalEvent::new(
        "session-1",
        EventSource::ProcessTree,
        EventType::RuntimeMetadata,
        42,
        1,
        "process_tree",
        "local-attribution",
        "mode:process_tree",
    );

    let line = event.to_json_line();

    assert!(line.contains(r#""event_source":"process_tree""#));
    assert!(line.contains(r#""event_type":"runtime_metadata""#));
    assert!(line.contains(r#""action":"mode:process_tree""#));
}

#[test]
fn canonical_event_json_line_records_runtime_identity_when_present() {
    let event = CanonicalEvent::new(
        "session-1",
        EventSource::KernelTracepoint,
        EventType::NetworkConnect,
        42,
        1,
        "python3",
        "1.1.1.1:443",
        "connect",
    )
    .with_runtime_identity(Some("container-a".to_string()), Some("42".to_string()));

    let line = event.to_json_line();

    assert!(line.contains(r#""container_id":"container-a""#));
    assert!(line.contains(r#""cgroup_id":"42""#));
}

#[test]
fn raw_kernel_event_json_line_keeps_raw_payload_and_runtime_identity() {
    let raw = RawKernelEvent::new(
        123,
        "session-1",
        EventSource::KernelTracepoint,
        "openat2",
        42,
        1,
        1000,
        1000,
        "bash",
        "/workspace/.env",
        "read",
        Some("container-a".to_string()),
        Some("42".to_string()),
        "flags=O_RDONLY",
    );

    let line = raw.to_json_line();

    assert!(line.contains(r#""record_type":"raw_kernel_event""#));
    assert!(line.contains(r#""event_name":"openat2""#));
    assert!(line.contains(r#""uid":1000"#));
    assert!(line.contains(r#""raw_payload":"flags=O_RDONLY""#));
    assert!(line.contains(r#""container_id":"container-a""#));
    assert!(line.contains(r#""cgroup_id":"42""#));
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

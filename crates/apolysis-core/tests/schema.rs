// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{
    actors, records, resources, CanonicalEvent, CollectorCapability, CollectorCapabilityManifest,
    EventSource, EventType, ObservationGap, ObservationGapKind, ObserverDiagnostic,
    ObserverDiagnosticKind, OperationOutcome, OperationResult, RawKernelEvent, SessionIntentRecord,
};

#[test]
fn shared_schema_vocabulary_keeps_public_strings_stable() {
    assert_eq!(records::EVENT, "event");
    assert_eq!(records::RAW_KERNEL_EVENT, "raw_kernel_event");
    assert_eq!(records::INTENT, "intent");
    assert_eq!(records::OBSERVER_DIAGNOSTIC, "observer_diagnostic");
    assert_eq!(records::OBSERVATION_GAP, "observation_gap");
    assert_eq!(
        records::COLLECTOR_CAPABILITY_MANIFEST,
        "collector_capability_manifest"
    );
    assert_eq!(actors::OBSERVER, "observer");
    assert_eq!(resources::PROCESS, "process");
    assert_eq!(
        resources::AGENT_COMMAND_FINGERPRINT,
        "agent-command-fingerprint"
    );
}

#[test]
fn session_intent_record_json_line_is_append_only_and_joinable() {
    let intent = SessionIntentRecord::new(
        "session-intent",
        "codex",
        "codex:item:call-1",
        "tool_call",
        "exec_command",
    )
    .with_timestamp(1_780_328_100_007)
    .with_source_event_id("call-1")
    .with_declared_action("shell.command")
    .with_target("workspace")
    .with_command("cat Cargo.toml")
    .with_raw_event_id("session-intent:event:0000000000000004");

    let line = intent.to_json_line();

    assert!(line.contains(r#""record_type":"intent""#));
    assert!(line.contains(r#""timestamp_unix_ms":1780328100007"#));
    assert!(line.contains(r#""session_id":"session-intent""#));
    assert!(line.contains(r#""intent_source":"codex""#));
    assert!(line.contains(r#""intent_id":"codex:item:call-1""#));
    assert!(line.contains(r#""source_event_id":"call-1""#));
    assert!(line.contains(r#""intent_type":"tool_call""#));
    assert!(line.contains(r#""tool_name":"exec_command""#));
    assert!(line.contains(r#""declared_action":"shell.command""#));
    assert!(line.contains(r#""target":"workspace""#));
    assert!(line.contains(r#""command":"cat Cargo.toml""#));
    assert!(line.contains(r#""raw_event_id":"session-intent:event:0000000000000004""#));
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
fn observer_diagnostic_records_an_abi_mismatch_as_an_observation_gap() {
    let diagnostic = ObserverDiagnostic::new(
        "agent-run-abi-mismatch",
        ObserverDiagnosticKind::AbiMismatch,
        1,
        "expected_version:2,received_version:3",
    );

    let line = diagnostic.to_json_line();

    assert!(line.contains(r#""kind":"abi_mismatch""#));
    assert!(line.contains(r#""count":1"#));
    assert!(line.contains("expected_version:2,received_version:3"));
}

#[test]
fn observation_gap_records_missing_network_exit_without_claiming_absence() {
    let gap = ObservationGap::new(
        "agent-run-missing-connect-exit",
        "network_connect",
        ObservationGapKind::MissingExit,
        2,
        "pending connect entries at collector stop",
    )
    .with_timestamp(1_780_328_100_007);

    assert_eq!(
        gap.to_json_line(),
        r#"{"record_type":"observation_gap","schema_version":1,"timestamp_unix_ms":1780328100007,"agent_run_id":"agent-run-missing-connect-exit","operation":"network_connect","kind":"missing_exit","count":2,"detail":"pending connect entries at collector stop"}"#
    );
}

#[test]
fn collector_capability_manifest_declares_the_versioned_observation_boundary() {
    let manifest = CollectorCapabilityManifest::new(
        "agent-run-capability",
        "0.1.0",
        3,
        656,
        "process_tree",
        vec![
            CollectorCapability::new(
                "process_exec",
                ["sched/sched_process_exec"],
                vec![OperationOutcome::Succeeded],
            ),
            CollectorCapability::new(
                "file_open",
                ["syscalls/sys_enter_openat", "syscalls/sys_enter_openat2"],
                vec![OperationOutcome::Attempted],
            ),
        ],
    )
    .with_timestamp(1_780_328_100_007);

    assert_eq!(
        manifest.to_json_line(),
        r#"{"record_type":"collector_capability_manifest","schema_version":1,"timestamp_unix_ms":1780328100007,"agent_run_id":"agent-run-capability","collector":"apolysis_observer","collector_version":"0.1.0","kernel_abi_version":3,"kernel_record_size":656,"observation_scope":"process_tree","privacy_profile":"content_off","capabilities":[{"operation":"process_exec","event_sources":["sched/sched_process_exec"],"outcomes":["succeeded"]},{"operation":"file_open","event_sources":["syscalls/sys_enter_openat","syscalls/sys_enter_openat2"],"outcomes":["attempted"]}]}"#
    );
}

#[test]
fn canonical_network_event_serializes_the_supported_operation_result() {
    let event = CanonicalEvent::new(
        "agent-run-network-result",
        EventSource::KernelTracepoint,
        EventType::NetworkConnect,
        42,
        1,
        "curl",
        "address_token:test:port:443",
        "connect",
    )
    .with_operation_result(OperationResult::new(
        OperationOutcome::Denied,
        -13,
        Some(13),
    ))
    .with_timestamp(1_780_328_100_007);

    let line = event.to_json_line();

    assert!(line.contains(r#""outcome":"denied""#));
    assert!(line.contains(r#""return_value":-13"#));
    assert!(line.contains(r#""errno":13"#));
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
    assert!(line.contains(r#""raw_event_id":null"#));
    assert!(line.contains(r#""process_command":null"#));
    assert!(line.contains(r#""process_executable":null"#));
    assert!(line.contains(r#""process_started_at_unix_ms":null"#));
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
fn canonical_event_json_line_records_process_context_when_present() {
    let event = CanonicalEvent::new(
        "session-1",
        EventSource::KernelTracepoint,
        EventType::ProcessExit,
        42,
        1,
        "sed",
        "",
        "exit",
    )
    .with_process_context(
        "/usr/bin/sed -n 1,5p README.md",
        "/usr/bin/sed",
        1_780_328_000_004,
    );

    let line = event.to_json_line();

    assert!(line.contains(r#""process_command":"/usr/bin/sed -n 1,5p README.md""#));
    assert!(line.contains(r#""process_executable":"/usr/bin/sed""#));
    assert!(line.contains(r#""process_started_at_unix_ms":1780328000004"#));
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
    assert!(line.contains(r#""event_id":null"#));
}

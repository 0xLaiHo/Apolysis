// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{
    actors, audit_observer_capability_contract_v1, records, resources,
    AuditObserverCapabilityContract, CanonicalEvent, CollectorCapability,
    CollectorCapabilityManifest, CollectorHealthState, CollectorLifecycleCounters,
    CollectorLifecycleRecord, CollectorLifecycleState, CollectorStopReason, EventSource, EventType,
    ObservationGap, ObservationGapKind, ObserverDiagnostic, ObserverDiagnosticKind,
    OperationOutcome, OperationResult, RawKernelEvent, RuntimeRelation, SessionIntentRecord,
    AUDIT_OBSERVER_COLLECTOR, CGROUP_OBSERVATION_SCOPE, CONTENT_OFF_PRIVACY_PROFILE,
    PROCESS_TREE_OBSERVATION_SCOPE,
};

#[test]
fn shared_schema_vocabulary_keeps_public_strings_stable() {
    assert_eq!(records::EVENT, "event");
    assert_eq!(records::RAW_KERNEL_EVENT, "raw_kernel_event");
    assert_eq!(records::INTENT, "intent");
    assert_eq!(records::OBSERVER_DIAGNOSTIC, "observer_diagnostic");
    assert_eq!(records::OBSERVATION_GAP, "observation_gap");
    assert_eq!(records::COLLECTOR_LIFECYCLE, "collector_lifecycle");
    assert_eq!(
        records::COLLECTOR_CAPABILITY_MANIFEST,
        "collector_capability_manifest"
    );
    assert_eq!(actors::OBSERVER, "observer");
    assert_eq!(resources::PROCESS, "process");
    assert_eq!(AUDIT_OBSERVER_COLLECTOR, "apolysis_observer");
    assert_eq!(CONTENT_OFF_PRIVACY_PROFILE, "content_off");
    assert_eq!(PROCESS_TREE_OBSERVATION_SCOPE, "process_tree");
    assert_eq!(CGROUP_OBSERVATION_SCOPE, "cgroup");
    assert_eq!(
        resources::AGENT_COMMAND_FINGERPRINT,
        "agent-command-fingerprint"
    );
}

#[test]
fn shared_lifecycle_vocabulary_round_trips_wire_values() {
    assert_eq!(
        CollectorLifecycleState::parse_v1("checkpoint"),
        Some(CollectorLifecycleState::Checkpoint)
    );
    assert_eq!(
        CollectorHealthState::parse_v1("degraded"),
        Some(CollectorHealthState::Degraded)
    );
    assert_eq!(
        CollectorStopReason::parse_v1("duration_elapsed"),
        Some(CollectorStopReason::DurationElapsed)
    );
    assert_eq!(
        CollectorStopReason::parse_v1("decode_failure"),
        Some(CollectorStopReason::DecodeFailure)
    );
    assert_eq!(
        OperationOutcome::parse_v1("denied"),
        Some(OperationOutcome::Denied)
    );
    assert_eq!(CollectorLifecycleState::parse_v1("running"), None);
    assert_eq!(CollectorStopReason::parse_v1("operator_override"), None);
    assert_eq!(OperationOutcome::parse_v1("successful"), None);
}

#[test]
fn audit_observer_capability_contract_v1_is_shared_and_complete() {
    let contracts = audit_observer_capability_contract_v1();

    assert_eq!(contracts.len(), 10);
    assert_eq!(
        contracts
            .iter()
            .map(|contract| contract.operation)
            .collect::<Vec<_>>(),
        vec![
            "process_fork",
            "process_exec",
            "process_exit",
            "file_open",
            "file_create",
            "file_truncate",
            "file_unlink",
            "file_rename",
            "network_connect",
            "credential_path_access",
        ]
    );
    let process_exec = contracts
        .iter()
        .find(|contract| contract.operation == "process_exec")
        .expect("process exec contract");
    assert_eq!(
        process_exec,
        &AuditObserverCapabilityContract {
            operation: "process_exec",
            event_sources: &[
                "sched/sched_process_exec",
                "syscalls/sys_enter_execve",
                "syscalls/sys_enter_execveat",
            ],
            required_event_sources: &["sched/sched_process_exec"],
            outcomes: &[OperationOutcome::Succeeded],
        }
    );
    assert!(contracts.iter().all(|contract| {
        !contract.operation.is_empty()
            && !contract.event_sources.is_empty()
            && !contract.outcomes.is_empty()
            && contract
                .event_sources
                .iter()
                .all(|source| source.split_once('/').is_some())
            && contract
                .required_event_sources
                .iter()
                .all(|required| contract.event_sources.contains(required))
    }));
}

#[test]
fn collector_lifecycle_checkpoint_records_health_and_bounded_loss_counters() {
    let checkpoint = CollectorLifecycleRecord::checkpoint(
        "agent-run-lifecycle",
        "collector-instance-7",
        CollectorLifecycleCounters {
            global_reserve_failures: 2,
            global_map_pressure: 3,
            global_abi_mismatches: 5,
            global_decode_failures: 7,
            global_truncations: 11,
            scope_missing_entries: 13,
            scope_missing_exits: 17,
            scope_pending: 19,
        },
    )
    .with_timestamp(1_780_328_100_007);

    assert_eq!(
        checkpoint.to_json_line(),
        r#"{"record_type":"collector_lifecycle","schema_version":1,"timestamp_unix_ms":1780328100007,"agent_run_id":"agent-run-lifecycle","collector":"apolysis_observer","collector_instance_id":"collector-instance-7","state":"checkpoint","health":"degraded","stop_reason":null,"counters":{"global_reserve_failures":2,"global_map_pressure":3,"global_abi_mismatches":5,"global_decode_failures":7,"global_truncations":11,"scope_missing_entries":13,"scope_missing_exits":17,"scope_pending":19}}"#
    );
}

#[test]
fn collector_lifecycle_treats_pending_as_inflight_until_the_terminal_boundary() {
    let counters = CollectorLifecycleCounters {
        scope_pending: 3,
        ..CollectorLifecycleCounters::default()
    };
    let checkpoint = CollectorLifecycleRecord::checkpoint("agent-run", "collector", counters);
    let stopped = CollectorLifecycleRecord::stopped(
        "agent-run",
        "collector",
        apolysis_core::CollectorNormalStopReason::DurationElapsed,
        counters,
    );

    assert!(checkpoint.to_json_line().contains(r#""health":"healthy""#));
    assert!(stopped.to_json_line().contains(r#""health":"degraded""#));
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
fn late_attach_gap_records_one_unknown_history_boundary_without_counting_missing_operations() {
    let gap = ObservationGap::new(
        "agent-run-late-attach",
        "collector_lifecycle",
        ObservationGapKind::LateAttach,
        1,
        "collection began after the existing process started; earlier activity is unknown",
    )
    .with_timestamp(1_780_328_100_007);

    assert_eq!(
        gap.to_json_line(),
        r#"{"record_type":"observation_gap","schema_version":1,"timestamp_unix_ms":1780328100007,"agent_run_id":"agent-run-late-attach","operation":"collector_lifecycle","kind":"late_attach","count":1,"detail":"collection began after the existing process started; earlier activity is unknown"}"#
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

#[test]
fn runtime_identity_without_scope_generation_is_not_exact() {
    let raw = RawKernelEvent::new(
        123,
        "session-identity",
        EventSource::KernelTracepoint,
        "openat2",
        42,
        1,
        1000,
        1000,
        "bash",
        "/workspace/file",
        "read",
        None,
        Some("42".to_string()),
        "",
    )
    .with_process_identity(
        Some("11111111-2222-3333-4444-555555555555".to_string()),
        None,
        Some(100),
        Some(1_000),
        Some(1),
        Some(90),
        Some(1),
    );

    assert_eq!(raw.relation_status, RuntimeRelation::Inferred);
    assert_eq!(raw.relation_reason, "runtime_generation_unavailable");
}

#[test]
fn runtime_identity_without_process_start_is_not_exact() {
    let raw = RawKernelEvent::new(
        124,
        "session-identity",
        EventSource::KernelTracepoint,
        "sched_process_fork",
        43,
        42,
        1000,
        1000,
        "worker",
        "",
        "fork",
        None,
        Some("42".to_string()),
        "",
    )
    .with_process_identity(
        Some("11111111-2222-3333-4444-555555555555".to_string()),
        Some(7),
        Some(101),
        None,
        Some(0),
        Some(100),
        Some(1),
    );

    assert_eq!(raw.relation_status, RuntimeRelation::Inferred);
    assert_eq!(raw.relation_reason, "runtime_generation_unavailable");
}

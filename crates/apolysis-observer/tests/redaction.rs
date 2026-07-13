// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{CanonicalEvent, EventSource, EventType, RawKernelEvent};
use apolysis_observer::{
    redact_command_text_for_persistence, Redactor, RuntimeEvidencePersistence,
};

#[test]
fn redactor_preserves_workspace_paths_and_masks_sensitive_paths() {
    let redactor = Redactor::new("session-a", "/workspace");

    let workspace = redactor.redact_resource(EventType::FileOpen, "/workspace/src/main.rs");
    let credential = redactor.redact_resource(EventType::CredentialRead, "/workspace/.env");
    let external = redactor.redact_resource(EventType::FileOpen, "/home/user/.ssh/id_rsa");

    assert_eq!(workspace.value, "/workspace/src/main.rs");
    assert!(!workspace.redacted);
    assert!(credential.value.starts_with("path_token:"));
    assert!(!credential.value.contains(".env"));
    assert!(credential.redacted);
    assert!(external.value.starts_with("path_token:"));
    assert!(!external.value.contains("id_rsa"));
    assert!(external.redacted);
}

#[test]
fn redactor_masks_socket_addresses_but_preserves_the_port() {
    let redactor = Redactor::new("session-a", "/workspace");

    let redacted = redactor.redact_resource(EventType::NetworkConnect, "1.1.1.1:443");

    assert!(redacted.value.starts_with("address_token:"));
    assert!(redacted.value.ends_with(":port:443"));
    assert!(!redacted.value.contains("1.1.1.1"));
    assert!(redacted.redacted);
}

#[test]
fn redaction_tokens_are_scoped_to_the_session() {
    let first = Redactor::new("session-a", "/workspace")
        .redact_resource(EventType::CredentialRead, "/home/user/.aws/credentials");
    let second = Redactor::new("session-b", "/workspace")
        .redact_resource(EventType::CredentialRead, "/home/user/.aws/credentials");

    assert_ne!(first.value, second.value);
}

#[test]
fn executable_references_normalize_path_forms_without_persisting_paths() {
    let redactor = Redactor::new("session-a", "/workspace");

    let bare = redactor.redact_resource(EventType::Exec, "codex");
    let installed = redactor.redact_resource(EventType::Exec, "/usr/bin/codex");
    let workspace = redactor.redact_resource(EventType::Exec, "./bin/codex");

    assert_eq!(bare.value, installed.value);
    assert_eq!(bare.value, workspace.value);
    assert_eq!(bare.value, "executable_ref:codex");
    assert!(!bare.value.contains("/usr/bin"));
}

#[test]
fn command_persistence_removes_workspace_and_credential_arguments() {
    let redacted = redact_command_text_for_persistence(
        "session-a",
        std::path::Path::new("/workspace/project"),
        "./scripts/run-codex-live-demo-workload.sh ../outside ~/.aws/credentials ./.env",
    );

    assert!(redacted.redacted);
    assert!(redacted.value.starts_with("executable_ref:"));
    assert!(redacted.value.ends_with(" argv_redacted:true"));
    assert!(!redacted
        .value
        .contains("./scripts/run-codex-live-demo-workload.sh"));
    assert!(!redacted.value.contains("../outside"));
    assert!(!redacted.value.contains("~/.aws/credentials"));
    assert!(!redacted.value.contains("./.env"));
    assert!(!redacted.value.contains("path_token:"));
}

#[test]
fn command_persistence_removes_network_arguments() {
    let redacted = redact_command_text_for_persistence(
        "session-a",
        std::path::Path::new("/workspace/project"),
        "python3 tests/fixtures/connect.py 127.0.0.1 1.1.1.1:443 '[::1]'",
    );

    assert!(redacted.redacted);
    assert!(!redacted.value.contains("127.0.0.1"));
    assert!(!redacted.value.contains("1.1.1.1"));
    assert!(!redacted.value.contains("::1"));
    assert!(redacted.value.starts_with("executable_ref:"));
    assert!(redacted.value.ends_with(" argv_redacted:true"));
    assert!(!redacted.value.contains("address_token:"));
    assert!(!redacted.value.contains(":port:443"));
}

#[test]
fn content_off_runtime_persistence_removes_exec_argv_and_process_command() {
    let raw = RawKernelEvent::new(
        1_700_000_000_100,
        "session-a",
        EventSource::KernelTracepoint,
        "sched_process_exec",
        101,
        100,
        1000,
        1000,
        "codex",
        "/usr/bin/codex",
        "exec",
        None,
        Some("42".to_string()),
        "argv:/usr/bin/codex exec write-the-secret --api-key sk-test-secret /workspace/private.txt,argv_truncated:true,payload_truncated:true",
    );
    let canonical = CanonicalEvent::new(
        "session-a",
        EventSource::KernelTracepoint,
        EventType::Exec,
        101,
        100,
        "codex",
        "/usr/bin/codex",
        "exec",
    )
    .with_process_context(
        "/usr/bin/codex exec write-the-secret --api-key sk-test-secret /workspace/private.txt",
        "/usr/bin/codex",
        1_700_000_000_000,
    );
    let redactor = Redactor::new("session-a", "/workspace");

    let (persisted_raw, persisted_canonical) =
        RuntimeEvidencePersistence::new(&redactor).persist_event(&raw, &canonical, false);
    let serialized = format!(
        "{}\n{}",
        persisted_raw.to_json_line(),
        persisted_canonical.to_json_line()
    );

    assert!(persisted_raw.raw_payload.contains("argv_redacted:true"));
    assert!(persisted_raw.raw_payload.contains("argv_truncated:true"));
    assert!(persisted_raw.raw_payload.contains("payload_truncated:true"));
    assert_eq!(persisted_canonical.process_command, None);
    assert!(persisted_canonical
        .process_executable
        .as_deref()
        .is_some_and(|value| value.starts_with("executable_ref:")));
    for forbidden in [
        "write-the-secret",
        "sk-test-secret",
        "/workspace/private.txt",
        "/usr/bin/codex exec",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "leaked {forbidden}: {serialized}"
        );
    }
}

#[test]
fn persisted_command_text_keeps_only_an_executable_reference() {
    let persisted = redact_command_text_for_persistence(
        "session-a",
        std::path::Path::new("/workspace"),
        "/usr/bin/codex exec write-the-secret --api-key sk-test-secret",
    );

    assert!(persisted.redacted);
    assert!(persisted.value.starts_with("executable_ref:"));
    assert!(persisted.value.ends_with(" argv_redacted:true"));
    assert!(!persisted.value.contains("write-the-secret"));
    assert!(!persisted.value.contains("sk-test-secret"));
}

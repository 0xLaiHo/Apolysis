// SPDX-License-Identifier: Apache-2.0

use apolysis_core::EventType;
use apolysis_observer::Redactor;

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

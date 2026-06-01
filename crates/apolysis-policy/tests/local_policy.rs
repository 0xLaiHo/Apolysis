// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{CanonicalEvent, EnforcementBackend, EventSource, EventType};
use apolysis_policy::{Policy, PolicyDecision, PolicyRuntimeCapabilities};

#[test]
fn local_policy_parses_credential_deny_and_runtime_limits() {
    let policy = Policy::parse(
        r#"
version: 1
credentials:
  deny_read:
    - ~/.ssh
    - .env
runtime:
  max_seconds: 60
  max_processes: 128
"#,
    )
    .expect("parse policy");

    assert!(policy.denies_credential_path("/home/dev/.ssh/id_rsa"));
    assert!(policy.denies_credential_path("/work/repo/.env"));
    assert_eq!(policy.runtime.max_seconds, Some(60));
    assert_eq!(policy.runtime.max_processes, Some(128));
}

#[test]
fn audit_only_policy_notifies_for_denied_credentials() {
    let policy = Policy::parse(
        r#"
version: 1
credentials:
  deny_read:
    - ~/.aws
"#,
    )
    .expect("parse policy");

    let decision = policy.evaluate_file_read("/home/dev/.aws/credentials");

    assert_eq!(
        decision,
        PolicyDecision::Notify {
            rule_id: "credentials.deny_read".to_string(),
            reason: "file path matches credential deny list".to_string()
        }
    );
}

#[test]
fn json_policy_parses_v1_access_controls() {
    let policy = Policy::parse(
        r#"{
  "version": 1,
  "credentials": {
    "deny_read": ["~/.ssh", ".env"]
  },
  "workspace": {
    "allow_read": ["./crates", "./tests"],
    "allow_write": ["./.apolysis"]
  },
  "commands": {
    "deny": ["rm -rf /"]
  },
  "network": {
    "allow_egress": ["127.0.0.1:0"]
  },
  "runtime": {
    "max_seconds": 45,
    "max_processes": 64
  }
}"#,
    )
    .expect("parse json policy");

    assert_eq!(policy.credentials.deny_read, vec!["~/.ssh", ".env"]);
    assert_eq!(policy.workspace.allow_read, vec!["./crates", "./tests"]);
    assert_eq!(policy.workspace.allow_write, vec!["./.apolysis"]);
    assert_eq!(policy.commands.deny, vec!["rm -rf /"]);
    assert_eq!(policy.network.allow_egress, vec!["127.0.0.1:0"]);
    assert_eq!(policy.runtime.max_seconds, Some(45));
    assert_eq!(policy.runtime.max_processes, Some(64));
}

#[test]
fn block_request_uses_notify_when_bpf_lsm_is_unavailable() {
    let policy = Policy::parse(
        r#"
version: 1
enforcement:
  requested: block
  fallback: block
network:
  allow_egress:
    - 127.0.0.1:0
"#,
    )
    .expect("parse policy");
    let event = CanonicalEvent::new(
        "session-m5",
        EventSource::KernelTracepoint,
        EventType::NetworkConnect,
        42,
        1,
        "curl",
        "1.1.1.1:443",
        "connect",
    );

    let evaluation = policy.evaluate_event(
        &event,
        &PolicyRuntimeCapabilities {
            bpf_lsm_available: false,
        },
    );

    assert_eq!(
        evaluation.decision,
        PolicyDecision::Notify {
            rule_id: "network.allow_egress".to_string(),
            reason: "network endpoint is outside egress allow list".to_string()
        }
    );
    assert_eq!(
        evaluation.enforcement_backend,
        EnforcementBackend::TracepointNotify
    );
}

#[test]
fn relative_dot_allowlist_matches_workspace_paths() {
    let policy = Policy::parse(
        r#"
version: 1
workspace:
  allow_read:
    - ./tests
"#,
    )
    .expect("parse policy");
    let event = CanonicalEvent::new(
        "session-m5",
        EventSource::KernelTracepoint,
        EventType::FileOpen,
        42,
        1,
        "python3",
        "tests/fixtures/child.py",
        "open",
    );

    let evaluation = policy.evaluate_event(
        &event,
        &PolicyRuntimeCapabilities {
            bpf_lsm_available: false,
        },
    );

    assert_eq!(evaluation.decision, PolicyDecision::Allow);
    assert_eq!(
        evaluation.enforcement_backend,
        EnforcementBackend::AuditOnly
    );
}

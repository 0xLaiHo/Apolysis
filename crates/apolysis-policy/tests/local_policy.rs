// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{CanonicalEvent, EnforcementBackend, EventSource, EventType};
use apolysis_policy::{
    BlockPrototypeEvidence, BlockPrototypeEvidenceSource, DecisionKind,
    EnforcementCapabilityMatrix, EnforcementRuntime, EnforcementTiming, Policy, PolicyDecision,
    PolicyRuntimeCapabilities, PreoperationBlockSupport,
};

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
            ..PolicyRuntimeCapabilities::default()
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
            ..PolicyRuntimeCapabilities::default()
        },
    );

    assert_eq!(evaluation.decision, PolicyDecision::Allow);
    assert_eq!(
        evaluation.enforcement_backend,
        EnforcementBackend::AuditOnly
    );
}

#[test]
fn capability_matrix_keeps_notify_and_review_as_default_guardrails() {
    let capabilities = PolicyRuntimeCapabilities::default();
    let matrix = EnforcementCapabilityMatrix::new(&capabilities);

    for requested in [DecisionKind::Notify, DecisionKind::Review] {
        let capability = matrix.resolve(
            requested,
            DecisionKind::Notify,
            EnforcementRuntime::Docker,
            EventType::NetworkConnect,
        );

        assert!(capability.requested_supported);
        assert_eq!(capability.requested, requested);
        assert_eq!(capability.effective, requested);
        assert_eq!(
            capability.enforcement_backend,
            EnforcementBackend::TracepointNotify
        );
        assert_eq!(capability.timing, EnforcementTiming::PostEventFeedback);
        assert!(!capability.preoperation_prevention);
        assert_eq!(capability.downgrade, None);
    }
}

#[test]
fn capability_matrix_marks_kill_as_post_event_containment() {
    let capabilities = PolicyRuntimeCapabilities::default();
    let matrix = EnforcementCapabilityMatrix::new(&capabilities);

    let capability = matrix.resolve(
        DecisionKind::Kill,
        DecisionKind::Notify,
        EnforcementRuntime::Containerd,
        EventType::Exec,
    );

    assert!(capability.requested_supported);
    assert_eq!(capability.effective, DecisionKind::Kill);
    assert_eq!(
        capability.enforcement_backend,
        EnforcementBackend::SignalKill
    );
    assert_eq!(capability.timing, EnforcementTiming::PostEventContainment);
    assert!(!capability.preoperation_prevention);
    assert_eq!(capability.downgrade, None);
}

#[test]
fn block_requires_runtime_action_and_prototype_support() {
    let policy = Policy::parse(
        r#"
version: 1
enforcement:
  requested: block
  fallback: review
workspace:
  allow_read:
    - ./safe
network:
  allow_egress:
    - 127.0.0.1:0
"#,
    )
    .expect("parse policy");
    let capabilities = PolicyRuntimeCapabilities {
        bpf_lsm_available: true,
        runtime: EnforcementRuntime::Local,
        preoperation_block: PreoperationBlockSupport {
            file_read: true,
            ..PreoperationBlockSupport::default()
        },
        ..PolicyRuntimeCapabilities::default()
    };

    let file_event = CanonicalEvent::new(
        "session-f3",
        EventSource::KernelTracepoint,
        EventType::FileOpen,
        42,
        1,
        "python3",
        "/tmp/secret.txt",
        "open",
    );
    let network_event = CanonicalEvent::new(
        "session-f3",
        EventSource::KernelTracepoint,
        EventType::NetworkConnect,
        42,
        1,
        "curl",
        "1.1.1.1:443",
        "connect",
    );

    let file_evaluation = policy.evaluate_event(&file_event, &capabilities);
    assert_eq!(
        file_evaluation.decision,
        PolicyDecision::Block {
            rule_id: "workspace.allow_read".to_string(),
            reason: "file read is outside workspace read allow list".to_string()
        }
    );
    assert_eq!(
        file_evaluation.enforcement_backend,
        EnforcementBackend::BpfLsmBlock
    );
    assert_eq!(file_evaluation.downgrade, None);

    let network_evaluation = policy.evaluate_event(&network_event, &capabilities);
    assert_eq!(
        network_evaluation.decision,
        PolicyDecision::Review {
            rule_id: "network.allow_egress".to_string(),
            reason: "network endpoint is outside egress allow list".to_string()
        }
    );
    assert_eq!(
        network_evaluation.enforcement_backend,
        EnforcementBackend::TracepointNotify
    );
    let downgrade = network_evaluation
        .downgrade
        .expect("unsupported block should downgrade");
    assert_eq!(downgrade.from, DecisionKind::Block);
    assert_eq!(downgrade.to, DecisionKind::Review);
    assert!(downgrade.reason.contains("network_connect"));
    assert!(downgrade.reason.contains("local"));
}

#[test]
fn detected_capabilities_do_not_enable_preoperation_block_by_default() {
    let capabilities = PolicyRuntimeCapabilities::detect();

    assert!(!capabilities.preoperation_block.any_enabled());
}

#[test]
fn fixture_evidence_cannot_enable_preoperation_block_support() {
    let capabilities = PolicyRuntimeCapabilities {
        bpf_lsm_available: true,
        runtime: EnforcementRuntime::Local,
        ..PolicyRuntimeCapabilities::default()
    };
    let evidence = BlockPrototypeEvidence {
        source: BlockPrototypeEvidenceSource::Fixture,
        runtime: EnforcementRuntime::Local,
        action: EventType::FileOpen,
        preoperation_prevention: true,
        decision_latency_ms: Some(2),
        side_effect_race_window_ms: Some(0),
    };

    let error = capabilities
        .with_validated_block_prototype(evidence)
        .expect_err("fixture evidence must not enable live block");

    assert!(error.contains("live-host validation"));
}

#[test]
fn live_zero_race_window_evidence_enables_only_the_validated_action() {
    let capabilities = PolicyRuntimeCapabilities {
        bpf_lsm_available: true,
        runtime: EnforcementRuntime::Local,
        ..PolicyRuntimeCapabilities::default()
    };
    let evidence = BlockPrototypeEvidence {
        source: BlockPrototypeEvidenceSource::LiveHost,
        runtime: EnforcementRuntime::Local,
        action: EventType::FileOpen,
        preoperation_prevention: true,
        decision_latency_ms: Some(2),
        side_effect_race_window_ms: Some(0),
    };

    let capabilities = capabilities
        .with_validated_block_prototype(evidence)
        .expect("live zero-race evidence should enable file read block");

    assert!(capabilities.preoperation_block.file_read);
    assert!(!capabilities.preoperation_block.network_connect);
    assert!(capabilities.can_preoperation_block(EnforcementRuntime::Local, EventType::FileOpen));
    assert!(
        !capabilities.can_preoperation_block(EnforcementRuntime::Local, EventType::NetworkConnect)
    );
}

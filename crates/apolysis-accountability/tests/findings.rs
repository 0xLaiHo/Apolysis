// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    AccountabilityAnalyzer, ActionClass, EffectKind, EvidenceBoundary, FindingDecision,
    FindingKind, ObservedEffect, ResourceKind, ResourceSelector, RuntimeIdentity, SessionIntent,
};

#[test]
fn finding_kind_v1_accepts_every_golden_wire_value() {
    let wire_values: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/finding-kind-v1-wire-values.json"))
            .expect("valid finding-kind v1 golden fixture");

    let kinds = [
        FindingKind::MissingIntent,
        FindingKind::UnobservedIntent,
        FindingKind::UndeclaredAction,
        FindingKind::CredentialRead,
        FindingKind::WorkspaceBoundary,
        FindingKind::UnknownEgress,
        FindingKind::DangerousCommand,
        FindingKind::ServiceAccountTokenRead,
    ];
    let serialized_kinds: Vec<_> = kinds
        .into_iter()
        .map(|kind| serde_json::to_value(kind).expect("serialize finding kind"))
        .collect();
    assert_eq!(serialized_kinds, wire_values);

    for wire_value in wire_values {
        let _: FindingKind = serde_json::from_value(wire_value.clone())
            .unwrap_or_else(|error| panic!("unsupported v1 wire value {wire_value}: {error}"));
    }
}

#[test]
fn finding_v1_serializes_a_complete_jsonl_record_through_the_shared_interface() {
    let finding = AccountabilityAnalyzer::evaluate(None, &effect(EffectKind::Exec, "cargo test"))
        .into_iter()
        .next()
        .expect("missing-intent finding");

    let record = finding
        .to_record_value()
        .expect("serialize complete finding record");
    assert_eq!(record["record_type"], "accountability_finding");
    assert_eq!(record["schema_version"], 1);
    assert_eq!(record["kind"], "missing_intent");
    let decoded: apolysis_accountability::AccountabilityFinding =
        serde_json::from_value(record).expect("record remains compatible with finding v1");
    assert_eq!(decoded, finding);
}

#[test]
fn marked_workload_without_intent_produces_missing_intent_review() {
    let findings = AccountabilityAnalyzer::evaluate(None, &effect(EffectKind::Exec, "cargo test"));
    assert_finding(
        &findings,
        FindingKind::MissingIntent,
        FindingDecision::Review,
    );
}

#[test]
fn action_not_declared_by_intent_produces_undeclared_action_review() {
    let intent = intent(vec![ActionClass::Test], Vec::new());
    let findings = AccountabilityAnalyzer::evaluate(
        Some(&intent),
        &effect(EffectKind::NetworkConnect, "1.1.1.1:443"),
    );
    assert_finding(
        &findings,
        FindingKind::UndeclaredAction,
        FindingDecision::Review,
    );
}

#[test]
fn credential_read_produces_notify_with_runtime_evidence() {
    let intent = intent(vec![ActionClass::ReadFile], Vec::new());
    let findings = AccountabilityAnalyzer::evaluate(
        Some(&intent),
        &effect(EffectKind::CredentialRead, "credential:path:abc"),
    );
    let finding = assert_finding(
        &findings,
        FindingKind::CredentialRead,
        FindingDecision::Notify,
    );
    assert_eq!(finding.evidence_ref, "event-17");
    assert_eq!(finding.runtime.container_id.as_deref(), Some("container-7"));
    assert_eq!(finding.evidence_boundary, EvidenceBoundary::HostBoundary);
    assert!(!finding.reason.is_empty());
}

#[test]
fn path_outside_allowed_workspace_produces_workspace_boundary_review() {
    let intent = intent(
        vec![ActionClass::WriteFile],
        vec![ResourceSelector {
            kind: ResourceKind::Workspace,
            value: "/workspace".to_string(),
        }],
    );
    let findings = AccountabilityAnalyzer::evaluate(
        Some(&intent),
        &effect(EffectKind::FileWrite, "/etc/cron.d/agent"),
    );
    assert_finding(
        &findings,
        FindingKind::WorkspaceBoundary,
        FindingDecision::Review,
    );
}

#[test]
fn endpoint_outside_allowlist_produces_unknown_egress_review() {
    let intent = intent(
        vec![ActionClass::Network],
        vec![ResourceSelector {
            kind: ResourceKind::Egress,
            value: "api.example.com:443".to_string(),
        }],
    );
    let findings = AccountabilityAnalyzer::evaluate(
        Some(&intent),
        &effect(EffectKind::NetworkConnect, "1.1.1.1:443"),
    );
    assert_finding(
        &findings,
        FindingKind::UnknownEgress,
        FindingDecision::Review,
    );
}

#[test]
fn dangerous_command_produces_dangerous_command_review() {
    let intent = intent(vec![ActionClass::Execute], Vec::new());
    let findings = AccountabilityAnalyzer::evaluate(
        Some(&intent),
        &effect(EffectKind::Exec, "rm -rf /workspace"),
    );
    assert_finding(
        &findings,
        FindingKind::DangerousCommand,
        FindingDecision::Review,
    );
}

#[test]
fn service_account_token_read_produces_review() {
    let intent = intent(vec![ActionClass::ReadFile], Vec::new());
    let mut observed = effect(
        EffectKind::ServiceAccountTokenRead,
        "credential:path:service-account",
    );
    observed.evidence_boundary = EvidenceBoundary::GuestSemantic;
    let findings = AccountabilityAnalyzer::evaluate(Some(&intent), &observed);
    let finding = assert_finding(
        &findings,
        FindingKind::ServiceAccountTokenRead,
        FindingDecision::Review,
    );
    assert_eq!(finding.evidence_boundary, EvidenceBoundary::GuestSemantic);
}

fn assert_finding(
    findings: &[apolysis_accountability::AccountabilityFinding],
    kind: FindingKind,
    decision: FindingDecision,
) -> &apolysis_accountability::AccountabilityFinding {
    let finding = findings
        .iter()
        .find(|finding| finding.kind == kind)
        .unwrap_or_else(|| panic!("missing finding {kind:?}: {findings:?}"));
    assert_eq!(finding.decision, decision);
    finding
}

fn effect(kind: EffectKind, resource: &str) -> ObservedEffect {
    ObservedEffect {
        session_id: "session-runtime_foundation".to_string(),
        evidence_ref: "event-17".to_string(),
        kind,
        actor: resource.to_string(),
        resource: resource.to_string(),
        runtime: RuntimeIdentity {
            runtime: "containerd".to_string(),
            container_id: Some("container-7".to_string()),
            pod_uid: None,
            cgroup_id: Some(42),
        },
        evidence_boundary: EvidenceBoundary::HostBoundary,
    }
}

fn intent(
    declared_actions: Vec<ActionClass>,
    allowed_resources: Vec<ResourceSelector>,
) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: apolysis_accountability::DEFAULT_TENANT_ID.to_string(),
        retention_tier: apolysis_accountability::RetentionTier::Standard,
        session_id: "session-runtime_foundation".to_string(),
        expires_at_unix_ms: u64::MAX,
        declared_actions,
        allowed_resources,
        policy_ref: "policy.yaml".to_string(),
        workload_selectors: Vec::new(),
    }
}

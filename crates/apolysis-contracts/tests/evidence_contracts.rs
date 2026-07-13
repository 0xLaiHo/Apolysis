// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use apolysis_contracts::{OperationOutcome, TypedEvidencePayload};

const POSITIVE_FIXTURES: &[(&str, &str)] = &[
    (
        "agent_lifecycle",
        include_str!("fixtures/evidence/positive/agent_lifecycle.json"),
    ),
    (
        "delegation_lifecycle",
        include_str!("fixtures/evidence/positive/delegation_lifecycle.json"),
    ),
    (
        "tool_interaction",
        include_str!("fixtures/evidence/positive/tool_interaction.json"),
    ),
    (
        "protocol_interaction_mcp",
        include_str!("fixtures/evidence/positive/protocol_interaction_mcp.json"),
    ),
    (
        "protocol_interaction_a2a",
        include_str!("fixtures/evidence/positive/protocol_interaction_a2a.json"),
    ),
    (
        "policy_decision",
        include_str!("fixtures/evidence/positive/policy_decision.json"),
    ),
    (
        "actuation_report",
        include_str!("fixtures/evidence/positive/actuation_report.json"),
    ),
    (
        "runtime_effect",
        include_str!("fixtures/evidence/positive/runtime_effect.json"),
    ),
    (
        "outcome_claim",
        include_str!("fixtures/evidence/positive/outcome_claim.json"),
    ),
    (
        "outcome_verification",
        include_str!("fixtures/evidence/positive/outcome_verification.json"),
    ),
    (
        "source_diagnostic",
        include_str!("fixtures/evidence/positive/source_diagnostic.json"),
    ),
];

#[test]
fn v0_1_positive_fixtures_cover_every_typed_evidence_variant() {
    let mut variants = BTreeSet::new();
    let mut outcomes = BTreeSet::new();

    for (fixture_name, json) in POSITIVE_FIXTURES {
        let expected: serde_json::Value = serde_json::from_str(json).unwrap();
        let payload: TypedEvidencePayload = serde_json::from_str(json)
            .unwrap_or_else(|error| panic!("{fixture_name} must deserialize: {error}"));

        variants.insert(payload.evidence_type());
        if let Some(outcome) = payload.operation_outcome() {
            outcomes.insert(outcome);
        }

        assert_eq!(serde_json::to_value(payload).unwrap(), expected);
    }

    assert_eq!(
        variants,
        BTreeSet::from([
            "actuation_report",
            "agent_lifecycle",
            "delegation_lifecycle",
            "outcome_claim",
            "outcome_verification",
            "policy_decision",
            "protocol_interaction",
            "runtime_effect",
            "source_diagnostic",
            "tool_interaction",
        ])
    );
    assert_eq!(
        outcomes,
        BTreeSet::from([
            OperationOutcome::Denied,
            OperationOutcome::Failed,
            OperationOutcome::Pending,
            OperationOutcome::Succeeded,
            OperationOutcome::Unknown,
        ])
    );
}

#[test]
fn v0_1_typed_evidence_rejects_unknown_content_fields() {
    let error = serde_json::from_str::<TypedEvidencePayload>(include_str!(
        "fixtures/evidence/negative/unknown_field.json"
    ))
    .unwrap_err();

    assert!(error.to_string().contains("raw_prompt"));
}

#[test]
fn v0_1_typed_evidence_rejects_unsafe_opaque_references() {
    let error = serde_json::from_str::<TypedEvidencePayload>(include_str!(
        "fixtures/evidence/negative/unsafe_ref.json"
    ))
    .unwrap_err();

    assert!(error.to_string().contains("invalid evidence_ref"));
}

#[test]
fn v0_1_opaque_references_reject_paths_urls_and_prose() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/evidence/positive/runtime_effect.json"
    ))
    .unwrap();

    for unsafe_reference in [
        "../container_agent_01",
        "https://runtime.example/agent/01",
        "container agent one",
    ] {
        let mut candidate = fixture.clone();
        candidate["body"]["runtime_ref"] = unsafe_reference.into();
        assert!(serde_json::from_value::<TypedEvidencePayload>(candidate).is_err());
    }
}

#[test]
fn v0_1_actuation_requires_a_policy_decision_reference() {
    let error = serde_json::from_str::<TypedEvidencePayload>(include_str!(
        "fixtures/evidence/negative/actuation_without_decision_ref.json"
    ))
    .unwrap_err();

    assert!(error.to_string().contains("decision_ref"));
}

#[test]
fn v0_1_protocol_operations_must_match_the_declared_protocol() {
    let error = serde_json::from_str::<TypedEvidencePayload>(include_str!(
        "fixtures/evidence/negative/protocol_operation_mismatch.json"
    ))
    .unwrap_err();

    assert!(error.to_string().contains("protocol operation"));
}

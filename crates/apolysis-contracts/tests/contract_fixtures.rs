// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    AgentExecutionRecordFact, AgentExecutionRecordItem, CoverageSummary, EvidenceBoundary,
    ExecutionCoverageState, OutcomeCoverageState, PrivacyCapability, RunDescriptor,
    SemanticCoverageState, SourceEnvelope, SourceManifest,
};

#[test]
fn positive_fixtures_deserialize_through_validated_public_contracts() {
    let run: RunDescriptor =
        serde_json::from_str(include_str!("fixtures/positive/run_descriptor.json"))
            .expect("valid run descriptor");
    assert_eq!(run.run_id().as_str(), "run_01");

    let manifest: SourceManifest =
        serde_json::from_str(include_str!("fixtures/positive/source_manifest.json"))
            .expect("valid source manifest");
    assert_eq!(manifest.source_id().as_str(), "source_codex");
    assert_eq!(manifest.declared_boundary(), EvidenceBoundary::AgentHarness);
    assert_eq!(
        manifest.privacy_capabilities(),
        &[PrivacyCapability::StructureOnly]
    );

    for fixture in [
        include_str!("fixtures/positive/source_envelope_inline.json"),
        include_str!("fixtures/positive/source_envelope_object_ref.json"),
    ] {
        let envelope: SourceEnvelope =
            serde_json::from_str(fixture).expect("valid source envelope");
        assert!(envelope.source_sequence() > 0);
    }

    let summaries: Vec<CoverageSummary> =
        serde_json::from_str(include_str!("fixtures/positive/coverage_states.json"))
            .expect("all coverage states are valid");
    assert_eq!(summaries.len(), 5);
    assert!(summaries[0]
        .semantic()
        .contributing_source_refs()
        .iter()
        .any(|source| source.as_str() == "source_semantic"));
    assert!(summaries[1]
        .semantic()
        .coverage_gap_refs()
        .iter()
        .any(|gap| gap == "gap_semantic_missing"));
    assert_eq!(
        summaries
            .iter()
            .map(|summary| *summary.semantic().state())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            SemanticCoverageState::Complete,
            SemanticCoverageState::Partial,
            SemanticCoverageState::Opaque,
            SemanticCoverageState::Unavailable,
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        summaries
            .iter()
            .map(|summary| *summary.execution().state())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            ExecutionCoverageState::HostVerified,
            ExecutionCoverageState::Partial,
            ExecutionCoverageState::Opaque,
            ExecutionCoverageState::NotApplicable,
            ExecutionCoverageState::Incomplete,
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        summaries
            .iter()
            .map(|summary| *summary.outcome().state())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            OutcomeCoverageState::Verified,
            OutcomeCoverageState::Unconfirmed,
            OutcomeCoverageState::Unknown,
            OutcomeCoverageState::NotApplicable,
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn append_item_round_trips_with_server_scope_and_source_assertion_separated() {
    let source = include_str!("fixtures/positive/record_item.json");
    let item: AgentExecutionRecordItem = serde_json::from_str(source).expect("valid append item");
    assert_eq!(item.organization_id().as_str(), "org_acme");
    assert_eq!(item.run_id().as_str(), "run_01");
    assert_eq!(item.ingest_sequence(), 41);
    assert_eq!(
        serde_json::to_value(&item).expect("serialize item"),
        serde_json::from_str::<serde_json::Value>(source).expect("fixture JSON")
    );
}

#[test]
fn runtime_binding_is_a_first_class_append_fact() {
    let item: AgentExecutionRecordItem = serde_json::from_str(include_str!(
        "fixtures/positive/record_item_runtime_bound.json"
    ))
    .expect("valid runtime-bound append item");
    assert!(matches!(
        item.fact(),
        AgentExecutionRecordFact::RuntimeBound(binding)
            if binding.attribution() == apolysis_contracts::RuntimeAttribution::Exact
    ));
}

#[test]
fn append_item_rejects_invalid_server_sequence_and_scope_mismatch() {
    for (fixture, expected) in [
        (
            include_str!("fixtures/negative/record_item_zero_ingest_sequence.json"),
            "ingest_sequence",
        ),
        (
            include_str!("fixtures/negative/record_item_scope_mismatch.json"),
            "scope assertion",
        ),
    ] {
        let error = serde_json::from_str::<AgentExecutionRecordItem>(fixture)
            .expect_err("invalid append item must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn unknown_schema_version_is_rejected() {
    let error = serde_json::from_str::<RunDescriptor>(include_str!(
        "fixtures/negative/unknown_schema_version.json"
    ))
    .expect_err("unknown schema version must fail");
    assert!(error.to_string().contains("0.2"));
}

#[test]
fn unsafe_identifiers_are_rejected() {
    let error = serde_json::from_str::<RunDescriptor>(include_str!(
        "fixtures/negative/unsafe_identifier.json"
    ))
    .expect_err("path-like identifier must fail");
    assert!(error.to_string().contains("run_id"));
}

#[test]
fn source_sequence_must_start_at_one() {
    let error = serde_json::from_str::<SourceEnvelope>(include_str!(
        "fixtures/negative/zero_source_sequence.json"
    ))
    .expect_err("zero source sequence must fail");
    assert!(error.to_string().contains("source_sequence"));
}

#[test]
fn inline_payload_and_object_reference_are_exclusive() {
    for fixture in [
        include_str!("fixtures/negative/payload_both.json"),
        include_str!("fixtures/negative/payload_neither.json"),
    ] {
        let error = serde_json::from_str::<SourceEnvelope>(fixture)
            .expect_err("payload must have exactly one representation");
        assert!(error.to_string().contains("exactly one"));
    }
}

#[test]
fn source_envelope_enforces_typed_content_off_payloads_and_integrity() {
    for (fixture, expected) in [
        (
            include_str!("fixtures/negative/inline_content_forbidden.json"),
            "contains_content",
        ),
        (
            include_str!("fixtures/negative/payload_type_mismatch.json"),
            "payload_type",
        ),
        (
            include_str!("fixtures/negative/invalid_payload_digest.json"),
            "payload_digest",
        ),
    ] {
        let error = serde_json::from_str::<SourceEnvelope>(fixture)
            .expect_err("invalid source payload boundary must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn every_coverage_state_has_a_deterministic_negative_case() {
    let cases = [
        (
            "semantic",
            "complete",
            include_str!("fixtures/negative/coverage/semantic_complete.json"),
        ),
        (
            "semantic",
            "partial",
            include_str!("fixtures/negative/coverage/semantic_partial.json"),
        ),
        (
            "semantic",
            "opaque",
            include_str!("fixtures/negative/coverage/semantic_opaque.json"),
        ),
        (
            "semantic",
            "unavailable",
            include_str!("fixtures/negative/coverage/semantic_unavailable.json"),
        ),
        (
            "execution",
            "host_verified",
            include_str!("fixtures/negative/coverage/execution_host_verified.json"),
        ),
        (
            "execution",
            "partial",
            include_str!("fixtures/negative/coverage/execution_partial.json"),
        ),
        (
            "execution",
            "opaque",
            include_str!("fixtures/negative/coverage/execution_opaque.json"),
        ),
        (
            "execution",
            "not_applicable",
            include_str!("fixtures/negative/coverage/execution_not_applicable.json"),
        ),
        (
            "execution",
            "incomplete",
            include_str!("fixtures/negative/coverage/execution_incomplete.json"),
        ),
        (
            "outcome",
            "verified",
            include_str!("fixtures/negative/coverage/outcome_verified.json"),
        ),
        (
            "outcome",
            "unconfirmed",
            include_str!("fixtures/negative/coverage/outcome_unconfirmed.json"),
        ),
        (
            "outcome",
            "unknown",
            include_str!("fixtures/negative/coverage/outcome_unknown.json"),
        ),
        (
            "outcome",
            "not_applicable",
            include_str!("fixtures/negative/coverage/outcome_not_applicable.json"),
        ),
    ];
    assert_eq!(cases.len(), 13);

    for (dimension, state, fixture) in cases {
        let wire: serde_json::Value = serde_json::from_str(fixture).expect("valid JSON fixture");
        assert_eq!(wire[dimension]["state"], state);
        let error = serde_json::from_str::<CoverageSummary>(fixture)
            .expect_err("coverage without a reason must fail");
        assert!(error.to_string().contains("reason_codes"));
    }
}

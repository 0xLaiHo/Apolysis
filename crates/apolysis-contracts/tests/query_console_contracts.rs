// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    EvidenceAccessState, EvidenceReference, Finding, OutcomeComparison, OutcomeComparisonState,
    OutcomeCoverageState, ProjectionFreshness, QueryError, QueryErrorCode, RelationAttribution,
    RunExplorerPage, RunOverview, SourceHealthState, TimelineLane, TimelinePage,
    MAX_QUERY_PAGE_SIZE,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

fn fixture<T: DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(value).expect("deterministic Console fixture must satisfy the contract")
}

#[test]
fn normal_run_fixture_keeps_three_coverage_dimensions_independent() {
    let overview: RunOverview = fixture(include_str!("fixtures/console/normal_run_overview.json"));

    assert_eq!(overview.run_id.as_str(), "run-normal-001");
    assert_eq!(
        serde_json::to_value(overview.coverage.semantic().state()).unwrap(),
        json!("complete")
    );
    assert_eq!(
        serde_json::to_value(overview.coverage.execution().state()).unwrap(),
        json!("host_verified")
    );
    assert_eq!(
        serde_json::to_value(overview.coverage.outcome().state()).unwrap(),
        json!("verified")
    );
    assert_eq!(
        overview.coverage.outcome_comparison(),
        Some(OutcomeComparisonState::Match)
    );
    assert_eq!(overview.source_health.len(), 3);
    assert_eq!(overview.projection.freshness, ProjectionFreshness::Current);
}

#[test]
fn explorer_and_partial_fixture_preserve_limitations() {
    let explorer: RunExplorerPage =
        fixture(include_str!("fixtures/console/run_explorer_page.json"));
    let overview: RunOverview = fixture(include_str!("fixtures/console/partial_run_overview.json"));

    assert_eq!(explorer.items.len(), 2);
    assert_eq!(explorer.limit, 25);
    assert!(explorer.next_cursor.is_some());
    assert_eq!(
        serde_json::to_value(overview.coverage.semantic().state()).unwrap(),
        json!("partial")
    );
    assert_eq!(
        serde_json::to_value(overview.coverage.execution().state()).unwrap(),
        json!("opaque")
    );
    assert_eq!(overview.source_health[0].state, SourceHealthState::Degraded);
    assert!(!overview.coverage_gaps.is_empty());
}

#[test]
fn source_loss_fixture_exposes_bounded_order_and_clock_uncertainty() {
    let timeline: TimelinePage =
        fixture(include_str!("fixtures/console/source_loss_timeline.json"));

    assert_eq!(timeline.limit, 50);
    assert!(timeline.window.start_unix_ms < timeline.window.end_unix_ms);
    assert_eq!(timeline.items[0].lane, TimelineLane::CoverageGap);
    assert_eq!(timeline.items[0].observed_at.uncertainty_ms, Some(2_500));
    assert!(timeline.items[0].ingested_at_unix_ms > 0);
    assert!(timeline.items[0].ingest_sequence > 0);
    assert_eq!(timeline.projection.freshness, ProjectionFreshness::Stale);
}

#[test]
fn verified_outcome_can_still_be_a_mismatch() {
    let comparison: OutcomeComparison =
        fixture(include_str!("fixtures/console/outcome_mismatch.json"));

    assert_eq!(comparison.coverage, OutcomeCoverageState::Verified);
    assert_eq!(
        comparison.comparison,
        Some(OutcomeComparisonState::Mismatch)
    );
    assert_ne!(
        comparison.claimed.as_ref().unwrap().state,
        comparison.verified.as_ref().unwrap().state
    );
}

#[test]
fn timeline_fixture_retains_every_attribution_class_without_inventing_causality() {
    let timeline: TimelinePage =
        fixture(include_str!("fixtures/console/attribution_timeline.json"));

    assert!(matches!(
        timeline.items[0].attribution,
        RelationAttribution::Exact { .. }
    ));
    assert!(matches!(
        timeline.items[1].attribution,
        RelationAttribution::Inferred { .. }
    ));
    assert!(matches!(
        timeline.items[2].attribution,
        RelationAttribution::Ambiguous { .. }
    ));
    assert!(matches!(
        timeline.items[3].attribution,
        RelationAttribution::Unattributed { .. }
    ));
    assert!(timeline
        .items
        .iter()
        .all(|item| !item.evidence_refs.is_empty()));
}

#[test]
fn attribution_contract_rejects_heuristic_exactness_and_unsupported_inference() {
    let base: Value =
        serde_json::from_str(include_str!("fixtures/console/attribution_timeline.json")).unwrap();

    let mut heuristic_exact = base.clone();
    heuristic_exact["items"][0]["attribution"]["basis"] = json!("pid_time_cwd");
    assert!(serde_json::from_value::<TimelinePage>(heuristic_exact).is_err());

    let mut evidence_free_inference = base.clone();
    evidence_free_inference["items"][1]["attribution"]["evidence_refs"] = json!([]);
    assert!(serde_json::from_value::<TimelinePage>(evidence_free_inference).is_err());

    let mut single_candidate = base;
    let first = single_candidate["items"][2]["attribution"]["candidates"][0].clone();
    single_candidate["items"][2]["attribution"]["candidates"] = json!([first]);
    assert!(serde_json::from_value::<TimelinePage>(single_candidate).is_err());
}

#[test]
fn unknown_and_incomplete_are_visible_in_the_read_model() {
    let overview: RunOverview =
        fixture(include_str!("fixtures/console/unknown_incomplete_run.json"));

    assert_eq!(
        serde_json::to_value(overview.state).unwrap(),
        json!("incomplete")
    );
    assert_eq!(overview.outcome.coverage, OutcomeCoverageState::Unknown);
    assert_eq!(
        overview.outcome.comparison,
        Some(OutcomeComparisonState::Unresolved)
    );
    assert!(!overview.coverage_gaps.is_empty());
}

#[test]
fn evidence_reference_is_opaque_and_rejects_storage_or_credential_fields() {
    let reference: EvidenceReference = fixture(include_str!(
        "fixtures/console/redacted_evidence_reference.json"
    ));
    assert_eq!(reference.access, EvidenceAccessState::NotAuthorized);
    assert!(reference.redacted);

    let safe = serde_json::to_value(&reference).unwrap();
    for forbidden in ["url", "uri", "path", "credential", "token", "bucket"] {
        assert!(safe.get(forbidden).is_none());
    }

    let mut leaking = safe;
    leaking["url"] = json!("https://object-store.invalid/private");
    assert!(serde_json::from_value::<EvidenceReference>(leaking).is_err());

    let mut unauthorized_size: Value = serde_json::from_str(include_str!(
        "fixtures/console/redacted_evidence_reference.json"
    ))
    .unwrap();
    unauthorized_size["size_bytes"] = json!(4096);
    assert!(serde_json::from_value::<EvidenceReference>(unauthorized_size).is_err());
}

#[test]
fn authorization_errors_are_enumeration_safe_and_content_free() {
    let error: QueryError = fixture(include_str!("fixtures/console/authorization_failure.json"));

    assert_eq!(error.code, QueryErrorCode::NotFound);
    assert!(!error.retryable);
    let wire = serde_json::to_value(error).unwrap();
    let text = wire.to_string();
    assert!(!text.contains("other-org"));
    assert!(!text.contains("forbidden"));
    assert!(!text.contains("organization_id"));
}

#[test]
fn timeline_pages_reject_unbounded_or_invalid_cursor_responses() {
    let base: Value =
        serde_json::from_str(include_str!("fixtures/console/source_loss_timeline.json")).unwrap();

    let mut oversized = base.clone();
    oversized["limit"] = json!(MAX_QUERY_PAGE_SIZE + 1);
    assert!(serde_json::from_value::<TimelinePage>(oversized).is_err());

    let mut overfilled = base.clone();
    overfilled["limit"] = json!(1);
    overfilled["items"] = json!([base["items"][0].clone(), base["items"][0].clone()]);
    assert!(serde_json::from_value::<TimelinePage>(overfilled).is_err());

    let mut unsafe_cursor = base;
    unsafe_cursor["next_cursor"] = json!("cursor\nleak");
    assert!(serde_json::from_value::<TimelinePage>(unsafe_cursor).is_err());
}

#[test]
fn finding_v0_is_a_read_only_projection() {
    let finding: Finding = fixture(include_str!("fixtures/console/finding_v0.json"));
    let mut wire = serde_json::to_value(finding).unwrap();
    assert!(wire.get("available_actions").is_none());
    assert!(wire.get("assignment").is_none());

    wire["available_actions"] = json!(["resolve"]);
    assert!(serde_json::from_value::<Finding>(wire).is_err());
}

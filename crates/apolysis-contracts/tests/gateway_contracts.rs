// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    BindRuntimeRequest, BindRuntimeResponse, ContractErrorCode, FinishRunRequest,
    FinishRunResponse, GatewayErrorResponse, IngestAck, IngestRequest, OpenRunRequest,
    OpenRunResponse, MAX_INGEST_BATCH_ITEMS,
};
use serde::de::DeserializeOwned;

fn fixture(path: &str) -> String {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gateway/");
    std::fs::read_to_string(format!("{root}{path}"))
        .unwrap_or_else(|error| panic!("failed to read gateway fixture {path}: {error}"))
}

fn parse<T: DeserializeOwned>(path: &str) -> T {
    serde_json::from_str(&fixture(path))
        .unwrap_or_else(|error| panic!("failed to parse gateway fixture {path}: {error}"))
}

#[test]
fn four_gateway_operations_have_stable_positive_wire_fixtures() {
    let create: OpenRunRequest = parse("positive/open_run_create_request.json");
    assert!(create.is_create());

    let join: OpenRunRequest = parse("positive/open_run_join_request.json");
    assert!(join.is_join());

    let _: OpenRunResponse = parse("positive/open_run_response.json");
    let _: BindRuntimeRequest = parse("positive/bind_runtime_request.json");
    let ambiguous: BindRuntimeRequest = parse("positive/bind_runtime_ambiguous_request.json");
    assert_eq!(
        ambiguous.binding().alternative_runtime_candidates().len(),
        1
    );
    assert_eq!(
        ambiguous.binding().alternative_runtime_candidates()[0].confidence_bps(),
        6400
    );
    assert_eq!(ambiguous.binding().confidence_bps(), Some(7100));
    assert_eq!(
        ambiguous.binding().asserting_source_id().as_str(),
        "source_runtime"
    );
    let _: BindRuntimeResponse = parse("positive/bind_runtime_response.json");

    let ingest: IngestRequest = parse("positive/ingest_request.json");
    assert_eq!(ingest.envelopes().len(), 2);

    let ack: IngestAck = parse("positive/ingest_ack.json");
    assert_eq!(ack.committed_count(), 1);
    assert_eq!(ack.duplicate_count(), 1);
    assert_eq!(ack.durable_ingest_watermark(), 42);
    assert_eq!(ack.known_gaps().len(), 1);

    let finish: FinishRunRequest = parse("positive/finish_run_request.json");
    assert_eq!(finish.terminal_positions().len(), 2);
    assert_eq!(finish.outcome_claim_refs().len(), 2);
    let _: FinishRunResponse = parse("positive/finish_run_response.json");
}

#[test]
fn authentication_and_organization_authority_are_not_request_wire_fields() {
    for path in [
        "negative/open_run_auth_context.json",
        "negative/open_run_organization_id.json",
        "negative/open_run_tenant_id.json",
    ] {
        let error = serde_json::from_str::<OpenRunRequest>(&fixture(path))
            .expect_err("transport authority must be rejected as a request field");
        assert!(
            error.to_string().contains("unknown field"),
            "{path}: {error}"
        );
    }
}

#[test]
fn all_gateway_structures_reject_unknown_fields() {
    for (path, rejects) in [
        (
            "negative/bind_runtime_unknown_field.json",
            serde_json::from_str::<BindRuntimeRequest>(&fixture(
                "negative/bind_runtime_unknown_field.json",
            ))
            .is_err(),
        ),
        (
            "negative/ingest_unknown_field.json",
            serde_json::from_str::<IngestRequest>(&fixture("negative/ingest_unknown_field.json"))
                .is_err(),
        ),
        (
            "negative/finish_run_unknown_field.json",
            serde_json::from_str::<FinishRunRequest>(&fixture(
                "negative/finish_run_unknown_field.json",
            ))
            .is_err(),
        ),
    ] {
        assert!(rejects, "{path} unexpectedly accepted an unknown field");
    }
}

#[test]
fn lease_and_idempotency_fields_are_mandatory_and_validated() {
    for path in [
        "negative/open_run_invalid_digest.json",
        "negative/bind_runtime_missing_lease.json",
        "negative/ingest_missing_lease.json",
        "negative/finish_run_missing_operation_id.json",
    ] {
        assert!(
            serde_json::from_str::<serde_json::Value>(&fixture(path)).is_ok(),
            "negative fixture itself must be valid JSON: {path}"
        );
    }

    assert!(serde_json::from_str::<OpenRunRequest>(&fixture(
        "negative/open_run_invalid_digest.json"
    ))
    .is_err());
    assert!(serde_json::from_str::<BindRuntimeRequest>(&fixture(
        "negative/bind_runtime_missing_lease.json"
    ))
    .is_err());
    assert!(
        serde_json::from_str::<IngestRequest>(&fixture("negative/ingest_missing_lease.json"))
            .is_err()
    );
    assert!(serde_json::from_str::<FinishRunRequest>(&fixture(
        "negative/finish_run_missing_operation_id.json"
    ))
    .is_err());
}

#[test]
fn semantic_validation_rejects_invalid_batches_bindings_positions_and_acks() {
    assert!(
        serde_json::from_str::<IngestRequest>(&fixture("negative/ingest_empty_batch.json"))
            .is_err()
    );
    assert!(serde_json::from_str::<BindRuntimeRequest>(&fixture(
        "negative/bind_runtime_ambiguous_without_alternatives.json"
    ))
    .is_err());
    assert!(serde_json::from_str::<BindRuntimeRequest>(&fixture(
        "negative/bind_runtime_exact_heuristic.json"
    ))
    .is_err());
    assert!(serde_json::from_str::<FinishRunRequest>(&fixture(
        "negative/finish_run_duplicate_stream.json"
    ))
    .is_err());
    assert!(
        serde_json::from_str::<IngestAck>(&fixture("negative/ingest_ack_invalid_gap.json"))
            .is_err()
    );
    assert!(serde_json::from_str::<IngestAck>(&fixture(
        "negative/ingest_ack_mixed_atomicity.json"
    ))
    .is_err());

    let mut oversized: serde_json::Value =
        serde_json::from_str(&fixture("positive/ingest_request.json")).unwrap();
    let envelope = oversized["envelopes"][0].clone();
    oversized["envelopes"] = serde_json::Value::Array(vec![envelope; MAX_INGEST_BATCH_ITEMS + 1]);
    assert!(serde_json::from_value::<IngestRequest>(oversized).is_err());
}

#[test]
fn contract_error_wire_codes_are_closed_and_stable() {
    let expected = [
        (ContractErrorCode::Unauthenticated, "unauthenticated"),
        (ContractErrorCode::Forbidden, "forbidden"),
        (ContractErrorCode::NotFound, "not_found"),
        (
            ContractErrorCode::UnsupportedContractVersion,
            "unsupported_contract_version",
        ),
        (
            ContractErrorCode::UnsupportedSourceVersion,
            "unsupported_source_version",
        ),
        (ContractErrorCode::InvalidContract, "invalid_contract"),
        (
            ContractErrorCode::InvalidLifecycleTransition,
            "invalid_lifecycle_transition",
        ),
        (ContractErrorCode::LeaseExpired, "lease_expired"),
        (ContractErrorCode::LeaseRevoked, "lease_revoked"),
        (
            ContractErrorCode::LeaseScopeMismatch,
            "lease_scope_mismatch",
        ),
        (
            ContractErrorCode::IdempotencyConflict,
            "idempotency_conflict",
        ),
        (
            ContractErrorCode::SourceEventConflict,
            "source_event_conflict",
        ),
        (ContractErrorCode::SequenceConflict, "sequence_conflict"),
        (ContractErrorCode::CapabilityMismatch, "capability_mismatch"),
        (ContractErrorCode::RedactionRequired, "redaction_required"),
        (
            ContractErrorCode::ContentNotAuthorized,
            "content_not_authorized",
        ),
        (
            ContractErrorCode::RetentionNotAuthorized,
            "retention_not_authorized",
        ),
        (ContractErrorCode::BatchTooLarge, "batch_too_large"),
        (ContractErrorCode::Backpressure, "backpressure"),
        (ContractErrorCode::RateLimited, "rate_limited"),
        (ContractErrorCode::CursorInvalid, "cursor_invalid"),
        (ContractErrorCode::CursorExpired, "cursor_expired"),
        (
            ContractErrorCode::ProjectionUnavailable,
            "projection_unavailable",
        ),
    ];

    for (code, wire) in expected {
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{wire}\""));
        assert_eq!(
            serde_json::from_str::<ContractErrorCode>(&format!("\"{wire}\"")).unwrap(),
            code
        );
    }

    assert!(serde_json::from_str::<ContractErrorCode>("\"internal\"").is_err());
    let error: GatewayErrorResponse = parse("positive/error_response.json");
    assert_eq!(error.code(), ContractErrorCode::Backpressure);
    assert!(error.retryable());
    assert_eq!(error.retry_after_ms(), Some(250));
}

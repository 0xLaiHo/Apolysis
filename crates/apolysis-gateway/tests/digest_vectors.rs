// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    BindRuntimeRequest, FinishRunRequest, IngestRequest, OpenRunRequest, TypedEvidencePayload,
};
use apolysis_gateway::{canonical_inline_payload_digest, canonical_request_digest};

fn fixture(path: &str) -> serde_json::Value {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/"
    );
    serde_json::from_str(
        &std::fs::read_to_string(format!("{root}{path}"))
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}")),
    )
    .expect("fixture JSON")
}

#[test]
fn committed_gateway_fixtures_are_cross_language_digest_vectors() {
    let create: OpenRunRequest =
        serde_json::from_value(fixture("open_run_create_request.json")).expect("create request");
    let join: OpenRunRequest =
        serde_json::from_value(fixture("open_run_join_request.json")).expect("join request");
    let bind: BindRuntimeRequest =
        serde_json::from_value(fixture("bind_runtime_request.json")).expect("bind request");
    let ingest: IngestRequest =
        serde_json::from_value(fixture("ingest_request.json")).expect("ingest request");
    let finish: FinishRunRequest =
        serde_json::from_value(fixture("finish_run_request.json")).expect("finish request");

    let claimed = vec![
        ("open_run_create", create.request_digest().to_string()),
        ("open_run_join", join.request_digest().to_string()),
        ("bind_runtime", bind.request_digest().to_string()),
        ("ingest", ingest.request_digest().to_string()),
        ("finish_run", finish.request_digest().to_string()),
        (
            "ingest_payload_1",
            ingest.envelopes()[0].payload_digest().to_string(),
        ),
        (
            "ingest_payload_2",
            ingest.envelopes()[1].payload_digest().to_string(),
        ),
    ];
    let computed = vec![
        (
            "open_run_create",
            canonical_request_digest("open_run", &create).expect("create digest"),
        ),
        (
            "open_run_join",
            canonical_request_digest("open_run", &join).expect("join digest"),
        ),
        (
            "bind_runtime",
            canonical_request_digest("bind_runtime", &bind).expect("bind digest"),
        ),
        (
            "ingest",
            canonical_request_digest("ingest", &ingest).expect("ingest digest"),
        ),
        (
            "finish_run",
            canonical_request_digest("finish_run", &finish).expect("finish digest"),
        ),
        (
            "ingest_payload_1",
            canonical_inline_payload_digest(
                ingest.envelopes()[0]
                    .inline_payload()
                    .expect("inline payload one"),
            )
            .expect("payload one digest"),
        ),
        (
            "ingest_payload_2",
            canonical_inline_payload_digest(
                ingest.envelopes()[1]
                    .inline_payload()
                    .expect("inline payload two"),
            )
            .expect("payload two digest"),
        ),
    ];

    // These values are protocol artifacts, not values recomputed by the test
    // fixture loader. Changing canonicalization, domain separation, or field
    // omission therefore requires an explicit golden-vector review.
    let expected = vec![
        (
            "open_run_create",
            "5d509404863816fa3270afc5b1353e6390eefa71dcfae637df09071f0d87d692".to_string(),
        ),
        (
            "open_run_join",
            "5bbe3c7716a9ec4f63155cca6dd78587314deea0df161f8412e9748f072a89d4".to_string(),
        ),
        (
            "bind_runtime",
            "4c015c864c186074086f16c7000aaed46453ea80f7acf65147b2b2f0a395c876".to_string(),
        ),
        (
            "ingest",
            "ce560c1819bed85aded2276e2d71ef8f7f9fe911d8ab3388a693fbf80ea1455b".to_string(),
        ),
        (
            "finish_run",
            "ce8a43caabce05c35d9c9f3519d023cdb7159ead46b55282f9a4e6c71ede5376".to_string(),
        ),
        (
            "ingest_payload_1",
            "dcae611e067b1506f6b64620c942a2b9d11811fac310c2c0c94df468d0f02bf2".to_string(),
        ),
        (
            "ingest_payload_2",
            "6c0c8f48bb2388160d7326b39c808a4c60ffea7876a6221c9490209db954a64a".to_string(),
        ),
    ];

    assert_eq!(claimed, expected);
    assert_eq!(computed, expected);
}

#[test]
fn payload_digest_is_independent_of_json_member_order() {
    let wire = fixture("ingest_request.json");
    let payload: TypedEvidencePayload =
        serde_json::from_value(wire["envelopes"][0]["inline_payload"].clone())
            .expect("typed payload");
    let first = canonical_inline_payload_digest(&payload).expect("first digest");
    let reordered: TypedEvidencePayload = serde_json::from_str(
        r#"{"body":{"outcome":"succeeded","response_ref":null,"request_ref":"request_digest_01","event":"completed","capability":"process","tool_ref":"exec_command","agent_ref":"agent_primary","interaction_ref":"tool_call_01"},"evidence_type":"tool_interaction"}"#,
    )
    .expect("reordered payload");
    let second = canonical_inline_payload_digest(&reordered).expect("second digest");
    assert_eq!(first, second);
}

#[test]
fn canonical_digest_rejects_numbers_outside_the_i_json_safe_range() {
    let request = serde_json::json!({
        "request_digest": "0".repeat(64),
        "unsafe_sequence": 9_007_199_254_740_992_u64
    });

    let error = canonical_request_digest("ingest", &request)
        .expect_err("cross-language digest inputs must remain inside I-JSON");
    assert!(error.to_string().contains("I-JSON safe range"));
}

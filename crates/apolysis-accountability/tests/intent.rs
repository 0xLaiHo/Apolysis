// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    decode_intent_frame, ActionClass, IntentError, IntentRequest, RuntimeSelector,
    MAX_INTENT_FRAME_BYTES,
};

const NOW_MS: u64 = 1_780_000_000_000;

#[test]
fn parses_a_v1_register_intent_request() {
    let frame = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-f2",
            "expires_at_unix_ms":1780000060000,
            "declared_actions":["test","read_file"],
            "allowed_resources":[
                {"kind":"workspace","value":"/workspace"},
                {"kind":"egress","value":"api.example.com:443"}
            ],
            "policy_ref":"policies/local-dev.yaml",
            "workload_selectors":[
                {
                    "runtime":"docker",
                    "key":"apolysis.session_id",
                    "value":"session-f2"
                }
            ]
        }
    }"#;

    let request = decode_intent_frame(frame, NOW_MS).expect("valid register frame");
    let IntentRequest::Register { intent } = request else {
        panic!("expected register request");
    };

    assert_eq!(intent.schema_version, 1);
    assert_eq!(intent.session_id, "session-f2");
    assert_eq!(
        intent.declared_actions,
        vec![ActionClass::Test, ActionClass::ReadFile]
    );
    assert_eq!(intent.allowed_resources[0].value, "/workspace");
    assert_eq!(
        intent.workload_selectors[0].runtime,
        RuntimeSelector::Docker
    );
}

#[test]
fn parses_health_and_session_lifecycle_requests() {
    assert_eq!(
        decode_intent_frame(br#"{"type":"health"}"#, NOW_MS).expect("health"),
        IntentRequest::Health
    );
    assert_eq!(
        decode_intent_frame(
            br#"{"type":"renew","session_id":"session-f2","expires_at_unix_ms":1780000060000}"#,
            NOW_MS,
        )
        .expect("renew"),
        IntentRequest::Renew {
            session_id: "session-f2".to_string(),
            expires_at_unix_ms: 1_780_000_060_000,
        }
    );
    assert_eq!(
        decode_intent_frame(br#"{"type":"close","session_id":"session-f2"}"#, NOW_MS)
            .expect("close"),
        IntentRequest::Close {
            session_id: "session-f2".to_string(),
        }
    );
    assert_eq!(
        decode_intent_frame(br#"{"type":"query","session_id":"session-f2"}"#, NOW_MS)
            .expect("query"),
        IntentRequest::Query {
            session_id: "session-f2".to_string(),
        }
    );
}

#[test]
fn rejects_unknown_schema_versions() {
    let frame = br#"{
        "type":"register",
        "intent":{
            "schema_version":2,
            "session_id":"session-f2",
            "expires_at_unix_ms":1780000060000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "policy_ref":"policy.yaml",
            "workload_selectors":[]
        }
    }"#;

    assert_eq!(
        decode_intent_frame(frame, NOW_MS),
        Err(IntentError::UnsupportedSchemaVersion(2))
    );
}

#[test]
fn rejects_empty_session_ids_and_expired_intent() {
    let empty = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":" ",
            "expires_at_unix_ms":1780000060000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "policy_ref":"policy.yaml",
            "workload_selectors":[]
        }
    }"#;
    assert_eq!(
        decode_intent_frame(empty, NOW_MS),
        Err(IntentError::EmptySessionId)
    );

    let expired = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-f2",
            "expires_at_unix_ms":1779999999999,
            "declared_actions":["test"],
            "allowed_resources":[],
            "policy_ref":"policy.yaml",
            "workload_selectors":[]
        }
    }"#;
    assert_eq!(
        decode_intent_frame(expired, NOW_MS),
        Err(IntentError::Expired)
    );
}

#[test]
fn rejects_invalid_renew_and_query_session_ids() {
    assert_eq!(
        decode_intent_frame(
            br#"{"type":"renew","session_id":"","expires_at_unix_ms":1780000060000}"#,
            NOW_MS,
        ),
        Err(IntentError::EmptySessionId)
    );
    assert_eq!(
        decode_intent_frame(br#"{"type":"query","session_id":" "}"#, NOW_MS),
        Err(IntentError::EmptySessionId)
    );
}

#[test]
fn rejects_frames_larger_than_64_kib_before_json_parsing() {
    let frame = vec![b'x'; MAX_INTENT_FRAME_BYTES + 1];
    assert_eq!(
        decode_intent_frame(&frame, NOW_MS),
        Err(IntentError::FrameTooLarge(MAX_INTENT_FRAME_BYTES + 1))
    );
}

// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    decode_intent_frame, ActionClass, IntentError, IntentRequest, RetentionTier, RuntimeSelector,
    DEFAULT_TENANT_ID, MAX_INTENT_FRAME_BYTES,
};

const NOW_MS: u64 = 1_780_000_000_000;

#[test]
fn parses_a_v1_register_intent_request() {
    let frame = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "tenant_id":"tenant-a",
            "retention_tier":"extended",
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
    assert_eq!(intent.tenant_id, "tenant-a");
    assert_eq!(intent.retention_tier, RetentionTier::Extended);
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
            tenant_id: DEFAULT_TENANT_ID.to_string(),
            session_id: "session-f2".to_string(),
        }
    );
}

#[test]
fn parses_tenant_scoped_query_and_session_list_requests() {
    assert_eq!(
        decode_intent_frame(
            br#"{"type":"query","tenant_id":"tenant-a","session_id":"session-f2"}"#,
            NOW_MS,
        )
        .expect("tenant query"),
        IntentRequest::Query {
            tenant_id: "tenant-a".to_string(),
            session_id: "session-f2".to_string(),
        }
    );
    assert_eq!(
        decode_intent_frame(
            br#"{"type":"list_sessions","tenant_id":"tenant-a","retention_tier":"short"}"#,
            NOW_MS,
        )
        .expect("tenant session list"),
        IntentRequest::ListSessions {
            tenant_id: "tenant-a".to_string(),
            retention_tier: Some(RetentionTier::Short),
        }
    );
}

#[test]
fn parses_retention_purge_requests_as_dry_run_by_default() {
    assert_eq!(
        decode_intent_frame(
            br#"{"type":"apply_retention","tenant_id":"tenant-a"}"#,
            NOW_MS
        )
        .expect("default dry-run retention request"),
        IntentRequest::ApplyRetention {
            tenant_id: "tenant-a".to_string(),
            dry_run: true,
            now_unix_ms: None,
        }
    );
    assert_eq!(
        decode_intent_frame(
            br#"{"type":"apply_retention","tenant_id":"tenant-a","dry_run":false,"now_unix_ms":1786048000000}"#,
            NOW_MS,
        )
        .expect("retention apply request"),
        IntentRequest::ApplyRetention {
            tenant_id: "tenant-a".to_string(),
            dry_run: false,
            now_unix_ms: Some(1_786_048_000_000),
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
fn rejects_tenant_ids_that_are_unsafe_for_state_or_query_scope() {
    for tenant_id in ["", " ", "../escape", "nested/tenant", "tenant\nbreak"] {
        let frame =
            format!(r#"{{"type":"query","tenant_id":{tenant_id:?},"session_id":"session-f2"}}"#);
        assert!(
            matches!(
                decode_intent_frame(frame.as_bytes(), NOW_MS),
                Err(IntentError::EmptyTenantId | IntentError::InvalidTenantId)
            ),
            "tenant id {tenant_id:?} must be rejected"
        );
    }
    let oversized = "a".repeat(64);
    let frame = format!(
        r#"{{"type":"list_sessions","tenant_id":"{oversized}","retention_tier":"standard"}}"#
    );
    assert_eq!(
        decode_intent_frame(frame.as_bytes(), NOW_MS),
        Err(IntentError::InvalidTenantId)
    );

    let frame = r#"{"type":"apply_retention","tenant_id":"nested/tenant"}"#;
    assert_eq!(
        decode_intent_frame(frame.as_bytes(), NOW_MS),
        Err(IntentError::InvalidTenantId)
    );
}

#[test]
fn rejects_session_ids_that_are_unsafe_for_state_paths() {
    for session_id in ["../escape", "nested/session", "session\nbreak"] {
        let frame = format!(r#"{{"type":"query","session_id":{session_id:?}}}"#);
        assert_eq!(
            decode_intent_frame(frame.as_bytes(), NOW_MS),
            Err(IntentError::InvalidSessionId)
        );
    }
    let oversized = "a".repeat(129);
    let frame = format!(r#"{{"type":"query","session_id":"{oversized}"}}"#);
    assert_eq!(
        decode_intent_frame(frame.as_bytes(), NOW_MS),
        Err(IntentError::InvalidSessionId)
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

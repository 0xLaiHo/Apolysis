// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    BindRuntimeRequest, ContractErrorCode, EnvironmentKind, FinishRunRequest, GatewayOperation,
    IngestRequest, OpenRunOutcome, OpenRunRequest, PrincipalKind, PrincipalRef, PrivacyCapability,
    RunState, SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy, TrustProfile,
    TypedEvidencePayload,
};
use apolysis_gateway::{
    canonical_inline_payload_digest, canonical_request_digest, ExecutionEvidenceGateway,
    GatewayClock, GatewayIdGenerator, MemoryGatewayRepository,
};

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl GatewayClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

struct FixedIds {
    values: Mutex<Vec<String>>,
}

impl FixedIds {
    fn new(values: &[&str]) -> Self {
        Self {
            values: Mutex::new(
                values
                    .iter()
                    .rev()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
        }
    }
}

impl GatewayIdGenerator for FixedIds {
    fn next_id(&self, _kind: &'static str) -> Result<String, String> {
        self.values
            .lock()
            .expect("id lock")
            .pop()
            .ok_or_else(|| "no deterministic ID left".to_string())
    }
}

fn request_fixture(path: &str) -> serde_json::Value {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/"
    );
    serde_json::from_str(
        &std::fs::read_to_string(format!("{root}{path}"))
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}")),
    )
    .expect("fixture JSON")
}

fn create_request() -> OpenRunRequest {
    let mut wire = request_fixture("positive/open_run_create_request.json");
    wire["expected_source_kinds"] = serde_json::json!(["semantic_hook"]);
    resign_open_wire(wire)
}

fn create_request_with_expected_source_kinds(kinds: serde_json::Value) -> OpenRunRequest {
    let mut wire = serde_json::to_value(create_request()).expect("serialize create request");
    wire["expected_source_kinds"] = kinds;
    resign_open_wire(wire)
}

fn resign_open_wire(mut wire: serde_json::Value) -> OpenRunRequest {
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let request: OpenRunRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid request");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("open_run", &request).expect("canonical request digest"),
    );
    serde_json::from_value(wire).expect("digest-valid request")
}

fn runtime_create_request() -> OpenRunRequest {
    let mut wire = request_fixture("positive/open_run_create_request.json");
    let join = request_fixture("positive/open_run_join_request.json");
    wire["source_manifest"] = join["source_manifest"].clone();
    wire["expected_source_kinds"] = serde_json::json!(["runtime_witness"]);
    wire["client_operation_id"] = serde_json::json!("operation_open_runtime_01");
    wire["client_run_key"] = serde_json::json!("runtime_workload_01");
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let request: OpenRunRequest = serde_json::from_value(wire.clone()).expect("runtime open shape");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("open_run", &request).expect("runtime open digest"),
    );
    serde_json::from_value(wire).expect("runtime open request")
}

fn join_request(run_id: &str) -> OpenRunRequest {
    let mut wire = request_fixture("positive/open_run_join_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["join_proof"]["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let request: OpenRunRequest = serde_json::from_value(wire.clone()).expect("join request shape");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("open_run", &request).expect("join request digest"),
    );
    serde_json::from_value(wire).expect("join request")
}

fn registration_policy_join_request(run_id: &str, operation_id: &str) -> OpenRunRequest {
    let mut wire = request_fixture("positive/open_run_join_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["client_operation_id"] = serde_json::Value::String(operation_id.to_string());
    wire["join_proof"]["kind"] = serde_json::json!("registration_policy");
    wire["join_proof"]["proof_ref"] = serde_json::json!("join_policy_runtime_01");
    wire["join_proof"]["run_id"] = serde_json::Value::String(run_id.to_string());
    resign_open_wire(wire)
}

fn bind_runtime_request(run_id: &str, lease_id: &str) -> BindRuntimeRequest {
    let mut wire = request_fixture("positive/bind_runtime_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    resign_bind_wire(wire)
}

fn resign_bind_wire(mut wire: serde_json::Value) -> BindRuntimeRequest {
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let request: BindRuntimeRequest =
        serde_json::from_value(wire.clone()).expect("binding request shape");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("bind_runtime", &request).expect("binding request digest"),
    );
    serde_json::from_value(wire).expect("binding request")
}

fn ingest_request(run_id: &str, lease_id: &str, source_stream_id: &str) -> IngestRequest {
    let mut wire = request_fixture("positive/ingest_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    for envelope in wire["envelopes"].as_array_mut().expect("envelope array") {
        envelope["run_id"] = serde_json::Value::String(run_id.to_string());
        envelope["source_stream_id"] = serde_json::Value::String(source_stream_id.to_string());
    }
    finalize_ingest_wire(wire)
}

fn gap_fill_request(run_id: &str, lease_id: &str, source_stream_id: &str) -> IngestRequest {
    let mut wire = request_fixture("positive/ingest_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    wire["client_operation_id"] = serde_json::json!("operation_ingest_gap_fill_01");
    let mut envelope = wire["envelopes"][0].clone();
    envelope["run_id"] = serde_json::Value::String(run_id.to_string());
    envelope["source_stream_id"] = serde_json::Value::String(source_stream_id.to_string());
    envelope["source_event_id"] = serde_json::json!("event_tool_02");
    envelope["source_sequence"] = serde_json::json!(2);
    wire["envelopes"] = serde_json::Value::Array(vec![envelope]);
    finalize_ingest_wire(wire)
}

fn runtime_ingest_request(run_id: &str, lease_id: &str, source_stream_id: &str) -> IngestRequest {
    let mut wire = request_fixture("positive/ingest_request.json");
    wire["client_operation_id"] = serde_json::json!("operation_ingest_runtime_late_01");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    let mut envelope = wire["envelopes"][0].clone();
    envelope["run_id"] = serde_json::Value::String(run_id.to_string());
    envelope["source_id"] = serde_json::json!("source_runtime");
    envelope["source_stream_id"] = serde_json::Value::String(source_stream_id.to_string());
    envelope["source_event_id"] = serde_json::json!("event_runtime_01");
    envelope["payload_type"] = serde_json::json!("runtime_effect");
    envelope["inline_payload"] = serde_json::json!({
        "evidence_type": "runtime_effect",
        "body": {
            "effect_ref": "runtime_effect_01",
            "runtime_ref": "container_agent_01",
            "effect_kind": "network",
            "target_ref": "endpoint_digest_01",
            "outcome": "unknown"
        }
    });
    wire["envelopes"] = serde_json::json!([envelope]);
    finalize_ingest_wire(wire)
}

fn finalize_ingest_wire(mut wire: serde_json::Value) -> IngestRequest {
    for envelope in wire["envelopes"].as_array_mut().expect("envelope array") {
        let payload: TypedEvidencePayload =
            serde_json::from_value(envelope["inline_payload"].clone()).expect("typed payload");
        envelope["payload_digest"] = serde_json::Value::String(
            canonical_inline_payload_digest(&payload).expect("payload digest"),
        );
    }
    resign_ingest_wire(wire)
}

fn resign_ingest_wire(mut wire: serde_json::Value) -> IngestRequest {
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let request: IngestRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid ingest request");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("ingest", &request).expect("ingest request digest"),
    );
    serde_json::from_value(wire).expect("digest-valid ingest request")
}

fn finish_run_request(
    run_id: &str,
    lease_id: &str,
    source_stream_id: &str,
    client_operation_id: &str,
) -> FinishRunRequest {
    let mut wire = request_fixture("positive/finish_run_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    wire["client_operation_id"] = serde_json::Value::String(client_operation_id.to_string());
    wire["terminal_positions"] = serde_json::json!([{
        "source_id": "source_codex",
        "source_stream_id": source_stream_id,
        "final_source_sequence": 3
    }]);
    resign_finish_wire(wire)
}

fn runtime_finish_run_request(
    run_id: &str,
    lease_id: &str,
    source_stream_id: &str,
) -> FinishRunRequest {
    let mut wire = serde_json::to_value(finish_run_request(
        run_id,
        lease_id,
        source_stream_id,
        "operation_finish_runtime_01",
    ))
    .expect("serialize runtime finish request");
    wire["terminal_positions"][0]["source_id"] = serde_json::json!("source_runtime");
    wire["terminal_positions"][0]["final_source_sequence"] = serde_json::json!(1);
    resign_finish_wire(wire)
}

fn resign_finish_wire(mut wire: serde_json::Value) -> FinishRunRequest {
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let request: FinishRunRequest =
        serde_json::from_value(wire.clone()).expect("finish request shape");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("finish_run", &request).expect("finish request digest"),
    );
    serde_json::from_value(wire).expect("finish request")
}

fn source_context_with_policy(
    expires_at_unix_ms: u64,
    allowed_capabilities: Vec<SourceCapability>,
    required_run_source_kinds: Vec<SourceKind>,
) -> AuthenticatedSourceContext {
    source_context_with_trust_and_revision(
        expires_at_unix_ms,
        allowed_capabilities,
        required_run_source_kinds,
        TrustProfile::HarnessObserved,
        7,
    )
}

fn source_context_with_trust_and_revision(
    expires_at_unix_ms: u64,
    allowed_capabilities: Vec<SourceCapability>,
    required_run_source_kinds: Vec<SourceKind>,
    effective_trust_profile: TrustProfile,
    policy_revision: u64,
) -> AuthenticatedSourceContext {
    let principal =
        PrincipalRef::new(PrincipalKind::Workload, "principal_runner").expect("principal");
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from("source_codex").expect("source id"),
        vec![SourceKind::SemanticHook],
        vec![EnvironmentKind::CiRunnerOrRemoteWorkspace],
        vec![
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ],
        true,
        false,
    )
    .expect("registration policy")
    .with_run_authorities(vec![AuthorityRef::new(
        AuthorityKind::Service,
        "authority_ci",
    )
    .expect("authority")])
    .expect("run authority policy")
    .with_run_profiles(
        vec!["privacy_structure_only_v1".to_string()],
        vec!["retention_30d_v1".to_string()],
        required_run_source_kinds,
    )
    .expect("run profiles")
    .with_evidence_policy(
        effective_trust_profile,
        allowed_capabilities,
        vec![PrivacyCapability::StructureOnly],
        vec!["redaction_structure_only_v1".to_string()],
    )
    .expect("evidence policy");
    AuthenticatedSourceContext::new(
        "org_acme".try_into().expect("organization"),
        principal,
        "registration_codex",
        AuthenticationSnapshot::new(
            "credential_ci_runner",
            policy_revision,
            1_783_891_100_000,
            expires_at_unix_ms,
        )
        .expect("authentication snapshot"),
        policy,
    )
    .expect("authenticated source context")
}

fn source_context_with_expiry(expires_at_unix_ms: u64) -> AuthenticatedSourceContext {
    source_context_with_policy(
        expires_at_unix_ms,
        vec![
            SourceCapability::SemanticLifecycle,
            SourceCapability::ToolCalls,
            SourceCapability::ClaimedOutcome,
        ],
        vec![SourceKind::SemanticHook],
    )
}

fn source_context() -> AuthenticatedSourceContext {
    source_context_with_expiry(1_783_894_800_000)
}

fn source_context_for_organization(organization_id: &str) -> AuthenticatedSourceContext {
    let template = source_context();
    AuthenticatedSourceContext::new(
        organization_id.try_into().expect("organization"),
        template.principal().clone(),
        template.source_registration_id(),
        template.authentication().clone(),
        template.registration_policy().clone(),
    )
    .expect("organization-scoped source context")
}

fn runtime_source_context_with_finish(may_finish: bool) -> AuthenticatedSourceContext {
    let principal =
        PrincipalRef::new(PrincipalKind::Workload, "principal_runner").expect("principal");
    let mut allowed_operations = vec![GatewayOperation::BindRuntime, GatewayOperation::Ingest];
    if may_finish {
        allowed_operations.push(GatewayOperation::FinishRun);
    }
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from("source_runtime").expect("source id"),
        vec![SourceKind::RuntimeWitness],
        vec![EnvironmentKind::CiRunnerOrRemoteWorkspace],
        allowed_operations,
        true,
        true,
    )
    .expect("registration policy")
    .with_run_authorities(vec![AuthorityRef::new(
        AuthorityKind::Service,
        "authority_ci",
    )
    .expect("authority")])
    .expect("run authority policy")
    .with_run_profiles(
        vec!["privacy_structure_only_v1".to_string()],
        vec!["retention_30d_v1".to_string()],
        vec![SourceKind::RuntimeWitness],
    )
    .expect("run profiles")
    .with_evidence_policy(
        TrustProfile::HostVerified,
        vec![
            SourceCapability::Process,
            SourceCapability::File,
            SourceCapability::Network,
            SourceCapability::Workload,
            SourceCapability::SourceHealth,
        ],
        vec![PrivacyCapability::StructureOnly],
        vec!["redaction_runtime_metadata_v1".to_string()],
    )
    .expect("evidence policy");
    AuthenticatedSourceContext::new(
        "org_acme".try_into().expect("organization"),
        principal,
        "registration_runtime",
        AuthenticationSnapshot::new(
            "credential_runtime",
            3,
            1_783_891_100_000,
            1_783_894_800_000,
        )
        .expect("authentication snapshot"),
        policy,
    )
    .expect("runtime context")
}

fn runtime_source_context() -> AuthenticatedSourceContext {
    runtime_source_context_with_finish(false)
}

fn runtime_finalizer_context() -> AuthenticatedSourceContext {
    runtime_source_context_with_finish(true)
}

fn runtime_source_context_for_organization(organization_id: &str) -> AuthenticatedSourceContext {
    let template = runtime_source_context();
    AuthenticatedSourceContext::new(
        organization_id.try_into().expect("organization"),
        template.principal().clone(),
        template.source_registration_id(),
        template.authentication().clone(),
        template.registration_policy().clone(),
    )
    .expect("organization-scoped runtime context")
}

#[tokio::test]
async fn open_run_returns_a_scoped_lease_and_exact_retry() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let request = create_request();

    let opened = gateway
        .open_run(&context, request.clone())
        .await
        .expect("create run");
    assert_eq!(opened.outcome(), OpenRunOutcome::Created);
    assert_eq!(opened.run_id().as_str(), "run_generated_01");
    assert_eq!(opened.source_id().as_str(), "source_codex");
    assert_eq!(opened.source_stream_id(), "stream_generated_01");
    assert!(!format!("{opened:?}").contains(opened.lease().lease_id()));
    assert!(format!("{opened:?}").contains("[REDACTED]"));
    assert_eq!(opened.lease().expires_at_unix_ms(), 1_783_891_500_000);
    assert_eq!(
        opened.lease().allowed_operations(),
        &[
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ]
    );

    let retried = gateway
        .open_run(&context, request)
        .await
        .expect("idempotent retry");
    assert_eq!(retried.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(retried.run_id(), opened.run_id());
    assert_eq!(retried.source_stream_id(), opened.source_stream_id());
    assert_eq!(retried.lease().lease_id(), opened.lease().lease_id());

    let mut conflicting_run_wire =
        serde_json::to_value(create_request()).expect("serialize conflicting create");
    conflicting_run_wire["client_operation_id"] =
        serde_json::json!("operation_open_same_client_key_02");
    let conflict = gateway
        .open_run(&context, resign_open_wire(conflicting_run_wire))
        .await
        .expect_err("a client run key cannot implicitly create or join another run");
    assert_eq!(conflict.code(), ContractErrorCode::IdempotencyConflict);
}

#[tokio::test]
async fn source_stream_freezes_trust_and_policy_revision() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let allowed_capabilities = vec![
        SourceCapability::SemanticLifecycle,
        SourceCapability::ToolCalls,
        SourceCapability::ClaimedOutcome,
    ];
    let initial = source_context_with_trust_and_revision(
        1_783_894_800_000,
        allowed_capabilities.clone(),
        vec![SourceKind::SemanticHook],
        TrustProfile::HarnessObserved,
        7,
    );
    let opened = gateway
        .open_run(&initial, create_request())
        .await
        .expect("open run");
    let silently_upgraded = source_context_with_trust_and_revision(
        1_783_894_800_000,
        allowed_capabilities.clone(),
        vec![SourceKind::SemanticHook],
        TrustProfile::HostVerified,
        7,
    );

    gateway
        .ingest(
            &silently_upgraded,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("existing policy revision may authenticate without changing stream trust");
    assert_eq!(
        repository
            .snapshot()
            .expect("snapshot")
            .accepted_effective_trust_profiles(),
        &[TrustProfile::HarnessObserved, TrustProfile::HarnessObserved]
    );

    let revised_policy = source_context_with_trust_and_revision(
        1_783_894_800_000,
        allowed_capabilities,
        vec![SourceKind::SemanticHook],
        TrustProfile::HostVerified,
        8,
    );
    let error = gateway
        .ingest(
            &revised_policy,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect_err("a changed policy revision revokes the old stream lease");
    assert_eq!(error.code(), ContractErrorCode::LeaseRevoked);
}

#[tokio::test]
async fn open_run_join_requires_a_server_registered_grant() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_runtime_01",
            "lease_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let opened = gateway
        .open_run(&source_context(), create_request())
        .await
        .expect("create run");
    let runtime_context = runtime_source_context();
    let request = join_request(opened.run_id().as_str());
    assert!(!format!("{request:?}").contains("join_grant_01"));
    assert!(format!("{request:?}").contains("[REDACTED]"));

    let error = gateway
        .open_run(&runtime_context, request.clone())
        .await
        .expect_err("a client-asserted proof is not authority");
    assert_eq!(error.code(), ContractErrorCode::NotFound);

    let self_authorization = repository
        .register_join_grant(
            &runtime_context,
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .expect_err("joining source cannot mint its own grant");
    assert_eq!(self_authorization.code(), ContractErrorCode::Forbidden);

    repository
        .register_join_grant(
            &source_context(),
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .expect("register server-side join grant");
    let revised_runtime_context = AuthenticatedSourceContext::new(
        runtime_context.organization_id().clone(),
        runtime_context.principal().clone(),
        runtime_context.source_registration_id(),
        AuthenticationSnapshot::new(
            runtime_context.authentication().credential_id(),
            runtime_context.authentication().policy_revision() + 1,
            runtime_context.authentication().authenticated_at_unix_ms(),
            runtime_context.authentication().expires_at_unix_ms(),
        )
        .expect("revised authentication snapshot"),
        runtime_context.registration_policy().clone(),
    )
    .expect("revised runtime context");
    let stale_grant_error = gateway
        .open_run(&revised_runtime_context, request.clone())
        .await
        .expect_err("a join grant is bound to its registered policy revision");
    assert_eq!(stale_grant_error.code(), ContractErrorCode::NotFound);

    let joined = gateway
        .open_run(&runtime_context, request.clone())
        .await
        .expect("join existing run");
    assert_eq!(joined.outcome(), OpenRunOutcome::Joined);
    assert_eq!(joined.run_id(), opened.run_id());
    assert_eq!(joined.source_id().as_str(), "source_runtime");
    assert_ne!(joined.source_stream_id(), opened.source_stream_id());

    let retried = gateway
        .open_run(&runtime_context, request)
        .await
        .expect("exact join retry");
    assert_eq!(retried.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(retried.source_stream_id(), joined.source_stream_id());
    assert_eq!(retried.lease().lease_id(), joined.lease().lease_id());

    let resurrection = repository
        .register_join_grant(
            &source_context(),
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .expect_err("consumed grant tombstones cannot be resurrected");
    assert_eq!(resurrection.code(), ContractErrorCode::IdempotencyConflict);

    let mut consumed_wire = serde_json::to_value(join_request(opened.run_id().as_str()))
        .expect("serialize consumed grant replay");
    consumed_wire["client_operation_id"] = serde_json::json!("operation_join_consumed_grant_02");
    let consumed_error = gateway
        .open_run(&runtime_context, resign_open_wire(consumed_wire))
        .await
        .expect_err("a consumed one-use grant cannot authorize a new operation");
    assert_eq!(consumed_error.code(), ContractErrorCode::NotFound);

    repository
        .register_join_grant(
            &source_context(),
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_expiring_01",
            1_783_891_300_000,
        )
        .expect("register expiring join grant");
    let mut expired_wire = serde_json::to_value(join_request(opened.run_id().as_str()))
        .expect("serialize expired join request");
    expired_wire["client_operation_id"] = serde_json::json!("operation_join_expired_01");
    expired_wire["join_proof"]["proof_ref"] = serde_json::json!("join_grant_expiring_01");
    expired_wire["join_proof"]["expires_at_unix_ms"] = serde_json::json!(1_783_891_300_000_u64);
    let expired_gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_300_000),
        FixedIds::new(&[]),
    );
    let expired_error = expired_gateway
        .open_run(&runtime_context, resign_open_wire(expired_wire))
        .await
        .expect_err("an expired grant fails closed without consuming identities");
    assert_eq!(expired_error.code(), ContractErrorCode::NotFound);
}

#[tokio::test]
async fn open_run_join_is_enumeration_safe_across_organizations() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_enumeration_01",
            "stream_enumeration_01",
            "lease_e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let opened = gateway
        .open_run(&source_context(), create_request())
        .await
        .expect("create run");
    let same_organization = runtime_source_context();
    let other_organization = runtime_source_context_for_organization("org_other");

    let unauthorized_existing = gateway
        .open_run(&same_organization, join_request(opened.run_id().as_str()))
        .await
        .expect_err("an existing run without a grant remains undiscoverable");
    let same_organization_missing = gateway
        .open_run(&same_organization, join_request("run_missing"))
        .await
        .expect_err("a missing same-organization run uses the same response");

    let cross_organization = gateway
        .open_run(&other_organization, join_request(opened.run_id().as_str()))
        .await
        .expect_err("cross-organization joins must not reveal the target run");
    let missing = gateway
        .open_run(&other_organization, join_request("run_missing"))
        .await
        .expect_err("a missing run uses the same external response");

    assert_eq!(cross_organization.code(), ContractErrorCode::NotFound);
    assert_eq!(unauthorized_existing.code(), ContractErrorCode::NotFound);
    assert_eq!(
        unauthorized_existing.response().expect("safe response"),
        same_organization_missing.response().expect("safe response")
    );
    assert_eq!(
        unauthorized_existing.response().expect("safe response"),
        cross_organization.response().expect("safe response")
    );
    assert_eq!(
        cross_organization.response().expect("safe response"),
        missing.response().expect("safe response")
    );
}

#[tokio::test]
async fn open_run_registration_policy_is_server_registered_and_reusable() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_runtime_01",
            "lease_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_runtime_02",
            "lease_2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let coordinator = source_context();
    let opened = gateway
        .open_run(&coordinator, create_request())
        .await
        .expect("create run");
    let runtime = runtime_source_context();

    repository
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .expect("register server-side join policy");

    let first = gateway
        .open_run(
            &runtime,
            registration_policy_join_request(opened.run_id().as_str(), "operation_join_policy_01"),
        )
        .await
        .expect("join through registration policy");
    let replacement = gateway
        .open_run(
            &runtime,
            registration_policy_join_request(opened.run_id().as_str(), "operation_join_policy_02"),
        )
        .await
        .expect("establish a replacement stream through the same policy");

    assert_eq!(first.outcome(), OpenRunOutcome::Joined);
    assert_eq!(replacement.outcome(), OpenRunOutcome::Joined);
    assert_ne!(first.source_stream_id(), replacement.source_stream_id());
    assert_ne!(first.lease().lease_id(), replacement.lease().lease_id());
}

#[tokio::test]
async fn open_run_rejects_an_expired_authentication_snapshot() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[]),
    );

    let error = gateway
        .open_run(
            &source_context_with_expiry(1_783_891_199_999),
            create_request(),
        )
        .await
        .expect_err("expired transport authentication must fail closed");

    assert_eq!(error.code(), ContractErrorCode::Unauthenticated);
}

#[tokio::test]
async fn open_run_rejects_source_capability_escalation() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[]),
    );
    let context = source_context_with_policy(
        1_783_894_800_000,
        vec![SourceCapability::SemanticLifecycle],
        vec![SourceKind::SemanticHook],
    );

    let error = gateway
        .open_run(&context, create_request())
        .await
        .expect_err("manifest cannot self-authorize additional capabilities");

    assert_eq!(error.code(), ContractErrorCode::CapabilityMismatch);
}

#[tokio::test]
async fn open_run_rejects_a_client_selected_authority() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[]),
    );
    let mut wire = serde_json::to_value(create_request()).expect("serialize create request");
    wire["authority"]["id"] = serde_json::json!("authority_other");
    wire["request_digest"] = serde_json::json!("0".repeat(64));
    let unsigned: OpenRunRequest =
        serde_json::from_value(wire.clone()).expect("alternate authority request");
    wire["request_digest"] = serde_json::json!(
        canonical_request_digest("open_run", &unsigned).expect("alternate authority digest")
    );
    let request = serde_json::from_value(wire).expect("digest-valid alternate authority request");

    let error = gateway
        .open_run(&source_context(), request)
        .await
        .expect_err("wire authority is not an authorization decision");
    assert_eq!(error.code(), ContractErrorCode::Forbidden);
}

#[tokio::test]
async fn open_run_rejects_stale_request_digest_without_consuming_identity() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_digest_recovery_01",
            "stream_digest_recovery_01",
            "lease_d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let valid = create_request();
    let mut stale_wire = serde_json::to_value(valid.clone()).expect("serialize create request");
    stale_wire["objective_ref"] = serde_json::json!("objective_changed_without_resigning");
    let stale: OpenRunRequest =
        serde_json::from_value(stale_wire).expect("shape-valid request with a stale digest");

    let error = gateway
        .open_run(&context, stale)
        .await
        .expect_err("request content cannot change without recomputing its digest");
    assert_eq!(error.code(), ContractErrorCode::InvalidContract);
    let rejected_snapshot = repository.snapshot().expect("rejected snapshot");
    assert_eq!(rejected_snapshot.record_item_count(), 0);
    assert_eq!(rejected_snapshot.projection_outbox_count(), 0);

    let opened = gateway
        .open_run(&context, valid)
        .await
        .expect("digest rejection must not consume request or generated identities");
    assert_eq!(opened.run_id().as_str(), "run_digest_recovery_01");
}

#[tokio::test]
async fn ingest_commits_an_atomic_batch_and_reports_source_gaps() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let request = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );

    let accepted = gateway
        .ingest(&context, request.clone())
        .await
        .expect("atomic ingest");
    assert_eq!(accepted.committed_count(), 2);
    assert_eq!(accepted.duplicate_count(), 0);
    assert_eq!(accepted.source_watermark(), 3);
    assert_eq!(accepted.known_gaps().len(), 1);
    assert_eq!(accepted.known_gaps()[0].first_missing_sequence(), 2);
    assert_eq!(accepted.known_gaps()[0].last_missing_sequence(), 2);
    let committed_snapshot = repository.snapshot().expect("memory ledger snapshot");
    assert_eq!(committed_snapshot.record_item_count(), 5);
    assert_eq!(committed_snapshot.projection_outbox_count(), 5);
    assert_eq!(committed_snapshot.evidence_event_count(), 2);

    let replayed = gateway
        .ingest(&context, request.clone())
        .await
        .expect("exact operation retry");
    assert_eq!(replayed, accepted);

    let expired_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_500_000),
        FixedIds::new(&[]),
    );
    let recovered = expired_gateway
        .ingest(&context, request)
        .await
        .expect("durable acknowledgement survives lease expiry");
    assert_eq!(recovered, accepted);
    assert_eq!(
        repository.snapshot().expect("replayed ledger snapshot"),
        committed_snapshot
    );
}

#[tokio::test]
async fn ingest_accepts_a_mixed_duplicate_and_gap_fill_retry() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let initial = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    gateway
        .ingest(&context, initial.clone())
        .await
        .expect("initial ingest");

    let mut wire = serde_json::to_value(initial).expect("serialize ingest");
    wire["client_operation_id"] = serde_json::json!("operation_ingest_mixed_retry_01");
    let duplicate = wire["envelopes"][1].clone();
    let mut gap_fill = wire["envelopes"][0].clone();
    gap_fill["source_event_id"] = serde_json::json!("event_tool_02");
    gap_fill["source_sequence"] = serde_json::json!(2);
    gap_fill["correlation"]["tool_ref"] = serde_json::json!("tool_call_02");
    gap_fill["inline_payload"]["body"]["interaction_ref"] = serde_json::json!("tool_call_02");
    gap_fill["inline_payload"]["body"]["request_ref"] = serde_json::json!("request_digest_02");
    wire["envelopes"] = serde_json::Value::Array(vec![duplicate, gap_fill]);
    let request = finalize_ingest_wire(wire);

    let accepted = gateway
        .ingest(&context, request.clone())
        .await
        .expect("partially repeated batch");
    assert_eq!(accepted.committed_count(), 1);
    assert_eq!(accepted.duplicate_count(), 1);
    assert_eq!(accepted.source_watermark(), 3);
    assert!(accepted.known_gaps().is_empty());

    let replayed = gateway
        .ingest(&context, request)
        .await
        .expect("exact mixed-batch retry");
    assert_eq!(replayed, accepted);
}

#[tokio::test]
async fn ingest_rejects_payload_tampering_without_a_partial_commit() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let valid = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    let mut wire = serde_json::to_value(valid.clone()).expect("serialize ingest");
    wire["envelopes"][0]["inline_payload"]["body"]["outcome"] = serde_json::json!("failed");
    let tampered = resign_ingest_wire(wire);

    let error = gateway
        .ingest(&context, tampered)
        .await
        .expect_err("payload digest mismatch must fail the whole batch");
    assert_eq!(error.code(), ContractErrorCode::InvalidContract);

    let accepted = gateway
        .ingest(&context, valid)
        .await
        .expect("failed validation must not consume operation or event identities");
    assert_eq!(accepted.committed_count(), 2);
    assert_eq!(accepted.duplicate_count(), 0);
}

#[tokio::test]
async fn ingest_rejects_reused_operation_identity_with_changed_content() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let original = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    gateway
        .ingest(&context, original.clone())
        .await
        .expect("initial ingest");
    let mut changed = serde_json::to_value(original).expect("serialize ingest");
    changed["envelopes"][0]["observed_at"]["uncertainty_ms"] = serde_json::json!(50);
    let changed = resign_ingest_wire(changed);

    let error = gateway
        .ingest(&context, changed)
        .await
        .expect_err("operation identity cannot be rebound to new content");
    assert_eq!(error.code(), ContractErrorCode::IdempotencyConflict);
}

#[tokio::test]
async fn ingest_conflicts_roll_back_the_entire_batch_and_operation_identity() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_conflict_01",
            "stream_conflict_01",
            "lease_c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let initial = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    gateway
        .ingest(&context, initial.clone())
        .await
        .expect("seed source sequences one and three");

    let mut event_conflict_wire = serde_json::to_value(initial.clone()).expect("serialize ingest");
    event_conflict_wire["client_operation_id"] = serde_json::json!("operation_event_conflict_01");
    let mut novel_sequence_two = event_conflict_wire["envelopes"][0].clone();
    novel_sequence_two["source_event_id"] = serde_json::json!("event_tool_02");
    novel_sequence_two["source_sequence"] = serde_json::json!(2);
    let mut conflicting_event = event_conflict_wire["envelopes"][0].clone();
    conflicting_event["observed_at"]["uncertainty_ms"] = serde_json::json!(99);
    event_conflict_wire["envelopes"] =
        serde_json::json!([novel_sequence_two.clone(), conflicting_event]);
    let event_conflict_recovery_wire = event_conflict_wire.clone();
    let event_conflict = finalize_ingest_wire(event_conflict_wire);
    let before_event_conflict = repository
        .snapshot()
        .expect("snapshot before event conflict");

    let error = gateway
        .ingest(&context, event_conflict)
        .await
        .expect_err("one conflicting event must reject the whole batch");
    assert_eq!(error.code(), ContractErrorCode::SourceEventConflict);
    assert_eq!(
        repository
            .snapshot()
            .expect("snapshot after event conflict"),
        before_event_conflict
    );

    let mut recovery_wire = event_conflict_recovery_wire;
    recovery_wire["envelopes"] = serde_json::json!([novel_sequence_two]);
    let recovered = gateway
        .ingest(&context, finalize_ingest_wire(recovery_wire))
        .await
        .expect("rejected event conflict must not consume sequence or operation identity");
    assert_eq!(recovered.committed_count(), 1);
    assert_eq!(recovered.source_watermark(), 3);
    assert!(recovered.known_gaps().is_empty());

    let mut sequence_conflict_wire =
        serde_json::to_value(initial).expect("serialize sequence conflict");
    sequence_conflict_wire["client_operation_id"] =
        serde_json::json!("operation_sequence_conflict_01");
    let mut novel_sequence_four = sequence_conflict_wire["envelopes"][0].clone();
    novel_sequence_four["source_event_id"] = serde_json::json!("event_tool_04");
    novel_sequence_four["source_sequence"] = serde_json::json!(4);
    let mut reused_sequence_three = sequence_conflict_wire["envelopes"][0].clone();
    reused_sequence_three["source_event_id"] = serde_json::json!("event_other_03");
    reused_sequence_three["source_sequence"] = serde_json::json!(3);
    sequence_conflict_wire["envelopes"] =
        serde_json::json!([novel_sequence_four.clone(), reused_sequence_three]);
    let sequence_conflict_recovery_wire = sequence_conflict_wire.clone();
    let sequence_conflict = finalize_ingest_wire(sequence_conflict_wire);
    let before_sequence_conflict = repository
        .snapshot()
        .expect("snapshot before sequence conflict");

    let error = gateway
        .ingest(&context, sequence_conflict)
        .await
        .expect_err("one reused sequence must reject the whole batch");
    assert_eq!(error.code(), ContractErrorCode::SequenceConflict);
    assert_eq!(
        repository
            .snapshot()
            .expect("snapshot after sequence conflict"),
        before_sequence_conflict
    );

    let mut recovery_wire = sequence_conflict_recovery_wire;
    recovery_wire["envelopes"] = serde_json::json!([novel_sequence_four]);
    let recovered = gateway
        .ingest(&context, finalize_ingest_wire(recovery_wire))
        .await
        .expect("rejected sequence conflict must not consume event or operation identity");
    assert_eq!(recovered.committed_count(), 1);
    assert_eq!(recovered.source_watermark(), 4);
}

#[tokio::test]
async fn lease_failures_are_explicit_and_cross_organization_safe() {
    let repository = MemoryGatewayRepository::new();
    let creator = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = creator
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let request = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );

    let other_organization = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[]),
    );
    let cross_org = other_organization
        .ingest(
            &source_context_for_organization("org_other"),
            request.clone(),
        )
        .await
        .expect_err("lease is organization-bound");

    let mut missing_wire = serde_json::to_value(request.clone()).expect("serialize ingest");
    missing_wire["run_id"] = serde_json::json!("run_missing");
    missing_wire["lease_id"] = serde_json::json!("lease_missing");
    for envelope in missing_wire["envelopes"].as_array_mut().expect("envelopes") {
        envelope["run_id"] = serde_json::json!("run_missing");
    }
    let missing = resign_ingest_wire(missing_wire);
    let missing_error = other_organization
        .ingest(&source_context_for_organization("org_other"), missing)
        .await
        .expect_err("missing run is enumeration-safe");
    assert_eq!(
        cross_org.response().expect("safe response"),
        missing_error.response().expect("safe response")
    );
    assert_eq!(cross_org.code(), ContractErrorCode::NotFound);

    let mut unknown_wire = serde_json::to_value(request.clone()).expect("serialize ingest");
    unknown_wire["lease_id"] = serde_json::json!("lease_unknown");
    let unknown = resign_ingest_wire(unknown_wire);
    let unknown_error = creator
        .ingest(&context, unknown)
        .await
        .expect_err("unknown lease must not reveal scope details");
    assert_eq!(unknown_error.code(), ContractErrorCode::LeaseScopeMismatch);

    let expired_gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_500_000),
        FixedIds::new(&[]),
    );
    let expired = expired_gateway
        .ingest(&context, request)
        .await
        .expect_err("lease expiry is server-controlled");
    assert_eq!(expired.code(), ContractErrorCode::LeaseExpired);
}

#[tokio::test]
async fn active_run_seals_only_after_its_last_lease_expires_and_cannot_be_revived() {
    let repository = MemoryGatewayRepository::new();
    let creator = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_lease_reconcile_01",
            "stream_lease_reconcile_01",
            "lease_3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let coordinator = source_context();
    let opened = creator
        .open_run(&coordinator, create_request())
        .await
        .expect("open run");
    let runtime = runtime_source_context();
    repository
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .expect("register runtime join policy");

    let join_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_300_000),
        FixedIds::new(&[
            "stream_lease_reconcile_02",
            "lease_4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let join_request = registration_policy_join_request(
        opened.run_id().as_str(),
        "operation_join_lease_reconcile_01",
    );
    let joined = join_gateway
        .open_run(&runtime, join_request.clone())
        .await
        .expect("join with a lease that outlives the coordinator lease");
    assert!(joined.lease().expires_at_unix_ms() > opened.lease().expires_at_unix_ms());
    let before_first_expiry = repository.snapshot().expect("snapshot before first expiry");

    let first_expiry_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(opened.lease().expires_at_unix_ms()),
        FixedIds::new(&[]),
    );
    let first_expiry = first_expiry_gateway
        .ingest(
            &coordinator,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect_err("an expired source lease is rejected while another lease keeps the run active");
    assert_eq!(first_expiry.code(), ContractErrorCode::LeaseExpired);
    assert_eq!(
        repository.snapshot().expect("snapshot with one live lease"),
        before_first_expiry
    );

    let last_expiry_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(joined.lease().expires_at_unix_ms()),
        FixedIds::new(&[]),
    );
    let late_join = last_expiry_gateway
        .open_run(
            &runtime,
            registration_policy_join_request(
                opened.run_id().as_str(),
                "operation_join_after_all_leases_expired_01",
            ),
        )
        .await
        .expect_err("a reusable join policy cannot revive a run after its last lease expires");
    assert_eq!(
        late_join.code(),
        ContractErrorCode::InvalidLifecycleTransition
    );
    let sealed = repository
        .snapshot()
        .expect("snapshot after lazy reconciliation");
    assert_eq!(
        sealed.record_item_count(),
        before_first_expiry.record_item_count() + 1
    );
    assert_eq!(
        sealed.projection_outbox_count(),
        before_first_expiry.projection_outbox_count() + 1
    );

    let replayed = last_expiry_gateway
        .open_run(&runtime, join_request)
        .await
        .expect("exact join replay remains stable after lazy sealing");
    assert_eq!(replayed.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(replayed.lease().lease_id(), joined.lease().lease_id());
    assert_eq!(repository.snapshot().expect("replay snapshot"), sealed);
}

#[tokio::test]
async fn open_run_does_not_leave_partial_state_when_identity_generation_fails() {
    let repository = MemoryGatewayRepository::new();
    let failing_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&["run_partial_01", "stream_partial_01"]),
    );
    let context = source_context();
    let request = create_request();
    let error = failing_gateway
        .open_run(&context, request.clone())
        .await
        .expect_err("lease identity generation fails closed");
    assert_eq!(error.code(), ContractErrorCode::Backpressure);
    let response = error.response().expect("safe backpressure response");
    assert!(response.retryable());
    assert_eq!(response.retry_after_ms(), Some(250));

    let recovery_gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_recovered_01",
            "stream_recovered_01",
            "lease_7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let recovered = recovery_gateway
        .open_run(&context, request)
        .await
        .expect("failed transaction leaves no client-run or operation residue");
    assert_eq!(recovered.outcome(), OpenRunOutcome::Created);
    assert_eq!(recovered.run_id().as_str(), "run_recovered_01");
}

#[tokio::test]
async fn bind_runtime_is_source_scoped_and_idempotent() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_runtime_01",
            "stream_runtime_01",
            "lease_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = runtime_source_context();
    let opened = gateway
        .open_run(&context, runtime_create_request())
        .await
        .expect("open runtime run");
    let request = bind_runtime_request(opened.run_id().as_str(), opened.lease().lease_id());

    let accepted = gateway
        .bind_runtime(&context, request.clone())
        .await
        .expect("bind runtime");
    assert!(accepted.accepted());
    assert!(!accepted.idempotent_replay());
    assert_eq!(accepted.binding_id(), "binding_pod_01");

    let replayed = gateway
        .bind_runtime(&context, request)
        .await
        .expect("binding retry");
    assert!(replayed.accepted());
    assert!(replayed.idempotent_replay());
    assert_eq!(replayed.binding_id(), accepted.binding_id());
}

#[tokio::test]
async fn bind_runtime_prevents_cross_run_identity_confusion_until_seal() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_runtime_exclusive_01",
            "stream_runtime_exclusive_01",
            "lease_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "run_runtime_exclusive_02",
            "stream_runtime_exclusive_02",
            "lease_2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = runtime_finalizer_context();
    let first_open = runtime_create_request();
    let mut second_open_wire =
        serde_json::to_value(first_open.clone()).expect("serialize second runtime run");
    second_open_wire["client_operation_id"] = serde_json::json!("operation_open_runtime_02");
    second_open_wire["client_run_key"] = serde_json::json!("runtime_workload_02");
    let second_open = resign_open_wire(second_open_wire);
    let first = gateway
        .open_run(&context, first_open)
        .await
        .expect("open first runtime run");
    let second = gateway
        .open_run(&context, second_open)
        .await
        .expect("open second runtime run");

    let first_binding = bind_runtime_request(first.run_id().as_str(), first.lease().lease_id());
    gateway
        .bind_runtime(&context, first_binding.clone())
        .await
        .expect("bind exact runtime identity to first run");

    let mut changed_binding_wire =
        serde_json::to_value(first_binding.clone()).expect("serialize changed binding");
    changed_binding_wire["client_operation_id"] =
        serde_json::json!("operation_bind_runtime_changed_01");
    changed_binding_wire["binding"]["identity_ref"] =
        serde_json::json!("cluster_a:namespace_default:pod_agent_changed");
    let changed_binding = resign_bind_wire(changed_binding_wire);
    let changed_error = gateway
        .bind_runtime(&context, changed_binding)
        .await
        .expect_err("a binding identity cannot be reused with changed content");
    assert_eq!(changed_error.code(), ContractErrorCode::IdempotencyConflict);

    let mut second_binding_wire =
        serde_json::to_value(first_binding).expect("serialize second-run binding");
    second_binding_wire["client_operation_id"] =
        serde_json::json!("operation_bind_runtime_second_01");
    second_binding_wire["run_id"] = serde_json::json!(second.run_id().as_str());
    second_binding_wire["lease_id"] = serde_json::json!(second.lease().lease_id());
    second_binding_wire["binding"]["binding_id"] = serde_json::json!("binding_pod_02");
    let second_binding = resign_bind_wire(second_binding_wire);
    let cross_run_error = gateway
        .bind_runtime(&context, second_binding.clone())
        .await
        .expect_err("one exact runtime identity cannot belong to two active runs");
    assert_eq!(cross_run_error.code(), ContractErrorCode::InvalidContract);

    gateway
        .ingest(
            &context,
            runtime_ingest_request(
                first.run_id().as_str(),
                first.lease().lease_id(),
                first.source_stream_id(),
            ),
        )
        .await
        .expect("reconcile first runtime stream");
    let finished = gateway
        .finish_run(
            &context,
            runtime_finish_run_request(
                first.run_id().as_str(),
                first.lease().lease_id(),
                first.source_stream_id(),
            ),
        )
        .await
        .expect("seal first runtime run");
    assert_eq!(finished.state(), RunState::Finished);

    let rebound = gateway
        .bind_runtime(&context, second_binding)
        .await
        .expect("sealed run releases the exact runtime identity");
    assert!(rebound.accepted());
    assert!(!rebound.idempotent_replay());
}

#[tokio::test]
async fn finish_run_remains_bounded_until_declared_gaps_are_filled() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("ingest with declared gap");

    let finishing = gateway
        .finish_run(
            &context,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_finish_gap_01",
            ),
        )
        .await
        .expect("enter bounded finalization");
    assert_eq!(finishing.state(), RunState::Finishing);
    assert_eq!(
        finishing.finalization_deadline_unix_ms(),
        Some(opened.lease().expires_at_unix_ms())
    );

    let mut extended_wire = serde_json::to_value(finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_extend_terminal_01",
    ))
    .expect("serialize finish request");
    extended_wire["terminal_positions"][0]["final_source_sequence"] = serde_json::json!(4);
    let extension_error = gateway
        .finish_run(&context, resign_finish_wire(extended_wire))
        .await
        .expect_err("a terminal source position is immutable once declared");
    assert_eq!(extension_error.code(), ContractErrorCode::InvalidContract);

    let filled = gateway
        .ingest(
            &context,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("fill sequence gap while finishing");
    assert!(filled.known_gaps().is_empty());

    let finished_request = finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_complete_01",
    );
    let finished = gateway
        .finish_run(&context, finished_request.clone())
        .await
        .expect("seal reconciled run");
    assert_eq!(finished.state(), RunState::Finished);
    assert_eq!(finished.finalization_deadline_unix_ms(), None);
    assert!(!finished.idempotent_replay());

    let replayed = gateway
        .finish_run(&context, finished_request)
        .await
        .expect("finish retry");
    assert_eq!(replayed.state(), RunState::Finished);
    assert!(replayed.idempotent_replay());
}

#[tokio::test]
async fn first_finish_seals_an_already_reconciled_run_atomically() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("ingest sequences one and three");
    gateway
        .ingest(
            &context,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("reconcile the source stream");

    let request = finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_first_complete_01",
    );
    let finished = gateway
        .finish_run(&context, request.clone())
        .await
        .expect("finish an already reconciled run");
    assert_eq!(finished.state(), RunState::Finished);
    assert_eq!(finished.finalization_deadline_unix_ms(), None);

    let retry = gateway
        .finish_run(&context, request)
        .await
        .expect("exact finish retry");
    assert_eq!(retry.state(), RunState::Finished);
    assert!(retry.idempotent_replay());

    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(snapshot.record_item_count(), 9);
    assert_eq!(snapshot.projection_outbox_count(), 9);
    assert_eq!(snapshot.finalization_declaration_count(), 1);
}

#[tokio::test]
async fn finish_run_rejects_a_terminal_position_below_the_durable_watermark() {
    let gateway = ExecutionEvidenceGateway::new(
        MemoryGatewayRepository::new(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("ingest sequences one and three");
    let mut wire = serde_json::to_value(finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_truncated_01",
    ))
    .expect("serialize finish request");
    wire["terminal_positions"][0]["final_source_sequence"] = serde_json::json!(1);
    let truncated = resign_finish_wire(wire);

    let error = gateway
        .finish_run(&context, truncated)
        .await
        .expect_err("accepted evidence cannot be hidden by lowering a terminal position");
    assert_eq!(error.code(), ContractErrorCode::InvalidContract);

    let finishing = gateway
        .finish_run(
            &context,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_finish_after_rejection_01",
            ),
        )
        .await
        .expect("rejected declaration leaves no finalization residue");
    assert_eq!(finishing.state(), RunState::Finishing);
}

#[tokio::test]
async fn finish_run_deadline_is_frozen_and_expires_to_incomplete() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    gateway
        .ingest(
            &context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("ingest with gap");
    let first_request = finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_deadline_01",
    );
    let mut first_wire =
        serde_json::to_value(first_request).expect("serialize bounded finish request");
    first_wire["requested_finalization_deadline_unix_ms"] =
        serde_json::json!(1_783_891_260_000_u64);
    let first_request = resign_finish_wire(first_wire);
    let first = gateway
        .finish_run(&context, first_request.clone())
        .await
        .expect("start finalization");
    assert_eq!(first.state(), RunState::Finishing);
    let accepted_deadline = first
        .finalization_deadline_unix_ms()
        .expect("explicit finalization deadline");
    assert_eq!(accepted_deadline, 1_783_891_260_000);

    let mut conflict_wire =
        serde_json::to_value(first_request.clone()).expect("serialize finish conflict");
    conflict_wire["outcome_claim_refs"] = serde_json::json!(["outcome_changed_01"]);
    let conflict = gateway
        .finish_run(&context, resign_finish_wire(conflict_wire))
        .await
        .expect_err("a finish operation identity cannot be rebound to changed content");
    assert_eq!(conflict.code(), ContractErrorCode::IdempotencyConflict);

    let deadline_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(accepted_deadline),
        FixedIds::new(&[]),
    );
    let expired = deadline_gateway
        .finish_run(
            &context,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_finish_deadline_expired_01",
            ),
        )
        .await
        .expect("deadline reconciliation seals an incomplete run");
    assert_eq!(expired.state(), RunState::Incomplete);
    assert_eq!(expired.finalization_deadline_unix_ms(), None);

    let replay_gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(accepted_deadline),
        FixedIds::new(&[]),
    );
    let replayed = replay_gateway
        .finish_run(&context, first_request)
        .await
        .expect("an exact pre-deadline finish retry retains its committed response");
    assert_eq!(replayed.state(), RunState::Finishing);
    assert!(replayed.idempotent_replay());
    assert_eq!(
        replayed.finalization_deadline_unix_ms(),
        Some(accepted_deadline)
    );
}

#[tokio::test]
async fn finish_run_rejects_an_elapsed_requested_deadline_without_extending_it() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_past_deadline_01",
            "stream_past_deadline_01",
            "lease_f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let valid = finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_past_deadline_01",
    );
    let mut elapsed_wire = serde_json::to_value(valid.clone()).expect("serialize finalization");
    elapsed_wire["requested_finalization_deadline_unix_ms"] =
        serde_json::json!(1_783_891_200_000_u64);
    let elapsed = resign_finish_wire(elapsed_wire);
    let before = repository.snapshot().expect("snapshot before rejection");

    let error = gateway
        .finish_run(&context, elapsed)
        .await
        .expect_err("an elapsed caller deadline cannot be replaced by a longer policy window");
    assert_eq!(error.code(), ContractErrorCode::InvalidContract);
    assert_eq!(
        repository.snapshot().expect("snapshot after rejection"),
        before
    );

    let accepted = gateway
        .finish_run(&context, valid)
        .await
        .expect("deadline rejection must not consume the operation identity");
    assert_eq!(accepted.state(), RunState::Finishing);
}

#[tokio::test]
async fn finishing_run_bounds_joined_leases_and_rejects_novel_work_at_deadline() {
    let repository = MemoryGatewayRepository::new();
    let coordinator_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_bounded_join_01",
            "stream_bounded_join_01",
            "lease_b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let coordinator = source_context_with_policy(
        1_783_894_800_000,
        vec![
            SourceCapability::SemanticLifecycle,
            SourceCapability::ToolCalls,
            SourceCapability::ClaimedOutcome,
        ],
        vec![SourceKind::SemanticHook, SourceKind::RuntimeWitness],
    );
    let opened = coordinator_gateway
        .open_run(
            &coordinator,
            create_request_with_expected_source_kinds(serde_json::json!([
                "semantic_hook",
                "runtime_witness"
            ])),
        )
        .await
        .expect("open multi-source run");
    let runtime = runtime_source_context();
    repository
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .expect("register runtime join policy");
    let finishing = coordinator_gateway
        .finish_run(
            &coordinator,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_finish_before_join_01",
            ),
        )
        .await
        .expect("enter finishing before the runtime source joins");
    let deadline = finishing
        .finalization_deadline_unix_ms()
        .expect("bounded finalization deadline");

    let join_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_300_000),
        FixedIds::new(&[
            "stream_runtime_bounded_01",
            "lease_a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let join = registration_policy_join_request(
        opened.run_id().as_str(),
        "operation_join_during_finishing_01",
    );
    let joined = join_gateway
        .open_run(&runtime, join.clone())
        .await
        .expect("required source may join before the deadline");
    assert_eq!(joined.lease().expires_at_unix_ms(), deadline);

    let deadline_gateway =
        ExecutionEvidenceGateway::new(repository, FixedClock(deadline), FixedIds::new(&[]));
    let replayed = deadline_gateway
        .open_run(&runtime, join)
        .await
        .expect("exact join retry retains its original response");
    assert_eq!(replayed.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(replayed.lease().lease_id(), joined.lease().lease_id());

    let late_join = deadline_gateway
        .open_run(
            &runtime,
            registration_policy_join_request(
                opened.run_id().as_str(),
                "operation_join_after_deadline_01",
            ),
        )
        .await
        .expect_err("a novel stream cannot join at the finalization deadline");
    assert_eq!(
        late_join.code(),
        ContractErrorCode::InvalidLifecycleTransition
    );

    let late_ingest = deadline_gateway
        .ingest(
            &runtime,
            runtime_ingest_request(
                opened.run_id().as_str(),
                joined.lease().lease_id(),
                joined.source_stream_id(),
            ),
        )
        .await
        .expect_err("the joined lease cannot accept novel evidence at the deadline");
    assert_eq!(late_ingest.code(), ContractErrorCode::LeaseExpired);
}

#[tokio::test]
async fn finish_run_requires_every_server_required_source_stream() {
    let repository = MemoryGatewayRepository::new();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_generated_01",
            "stream_generated_01",
            "lease_a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_runtime_01",
            "lease_b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let coordinator_context = source_context_with_policy(
        1_783_894_800_000,
        vec![
            SourceCapability::SemanticLifecycle,
            SourceCapability::ToolCalls,
            SourceCapability::ClaimedOutcome,
        ],
        vec![SourceKind::SemanticHook, SourceKind::RuntimeWitness],
    );
    let opened = gateway
        .open_run(
            &coordinator_context,
            create_request_with_expected_source_kinds(serde_json::json!([
                "semantic_hook",
                "runtime_witness"
            ])),
        )
        .await
        .expect("open multi-source run");
    let runtime_context = runtime_source_context();
    repository
        .register_join_grant(
            &coordinator_context,
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .expect("register runtime join grant");
    gateway
        .open_run(&runtime_context, join_request(opened.run_id().as_str()))
        .await
        .expect("join required runtime source");

    gateway
        .ingest(
            &coordinator_context,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("ingest semantic stream");
    gateway
        .ingest(
            &coordinator_context,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("reconcile semantic stream");

    for operation_id in [
        "operation_finish_missing_runtime_01",
        "operation_finish_missing_runtime_02",
    ] {
        let response = gateway
            .finish_run(
                &coordinator_context,
                finish_run_request(
                    opened.run_id().as_str(),
                    opened.lease().lease_id(),
                    opened.source_stream_id(),
                    operation_id,
                ),
            )
            .await
            .expect("missing required terminal declaration remains bounded");
        assert_eq!(response.state(), RunState::Finishing);
        assert_eq!(
            response.finalization_deadline_unix_ms(),
            Some(opened.lease().expires_at_unix_ms())
        );
    }
}

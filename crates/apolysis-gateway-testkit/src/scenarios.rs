// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use crate::{GatewayConformanceHarness, GatewayConformanceSnapshot};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    BindRuntimeRequest, ContractErrorCode, EnvironmentKind, FinishRunRequest, GatewayOperation,
    IngestRequest, OpenRunOutcome, OpenRunRequest, PrincipalKind, PrincipalRef, PrivacyCapability,
    RunState, SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy, TrustProfile,
    TypedEvidencePayload,
};
use apolysis_gateway::{
    canonical_inline_payload_digest, canonical_request_digest, AuditReason,
    ExecutionEvidenceGateway, GatewayClock, GatewayFailure, GatewayIdGenerator,
};

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl GatewayClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy)]
struct AdvancingClock {
    admission_unix_ms: u64,
    transaction_unix_ms: u64,
}

impl AdvancingClock {
    fn new(admission_unix_ms: u64, transaction_unix_ms: u64) -> Self {
        Self {
            admission_unix_ms,
            transaction_unix_ms,
        }
    }
}

impl GatewayClock for AdvancingClock {
    fn now_unix_ms(&self) -> u64 {
        self.admission_unix_ms
    }

    fn transaction_now_unix_ms(&self) -> u64 {
        self.transaction_unix_ms
    }
}

struct ReplayOnlyClock {
    authority_unix_ms: u64,
    transaction_reads: AtomicUsize,
}

impl ReplayOnlyClock {
    fn new(authority_unix_ms: u64) -> Self {
        Self {
            authority_unix_ms,
            transaction_reads: AtomicUsize::new(0),
        }
    }
}

impl GatewayClock for ReplayOnlyClock {
    fn now_unix_ms(&self) -> u64 {
        self.authority_unix_ms
    }

    fn transaction_now_unix_ms(&self) -> u64 {
        assert_eq!(
            self.transaction_reads.fetch_add(1, Ordering::SeqCst),
            0,
            "exact operation replay may refresh current authority once but must not sample dynamic lifecycle time"
        );
        self.authority_unix_ms
    }
}

struct AuthorityExpiryClock {
    admission_unix_ms: u64,
    authority_unix_ms: u64,
    expired_unix_ms: u64,
    transaction_reads: AtomicUsize,
}

impl AuthorityExpiryClock {
    fn new(admission_unix_ms: u64, authority_unix_ms: u64, expired_unix_ms: u64) -> Self {
        Self {
            admission_unix_ms,
            authority_unix_ms,
            expired_unix_ms,
            transaction_reads: AtomicUsize::new(0),
        }
    }
}

impl GatewayClock for AuthorityExpiryClock {
    fn now_unix_ms(&self) -> u64 {
        self.admission_unix_ms
    }

    fn transaction_now_unix_ms(&self) -> u64 {
        if self.transaction_reads.fetch_add(1, Ordering::SeqCst) == 0 {
            self.authority_unix_ms
        } else {
            self.expired_unix_ms
        }
    }
}

fn assert_non_retryable(error: &GatewayFailure) {
    let response = error.response().expect("safe Gateway error response");
    assert!(!response.retryable());
    assert_eq!(response.retry_after_ms(), None);
}

fn assert_no_novel_gateway_effects(
    before: &GatewayConformanceSnapshot,
    after: &GatewayConformanceSnapshot,
) {
    assert_eq!(after.evidence_event_count(), before.evidence_event_count());
    assert_eq!(after.operation_count(), before.operation_count());
    assert_eq!(after.replay_count(), before.replay_count());
    assert_eq!(after.source_stream_count(), before.source_stream_count());
    assert_eq!(after.lease_count(), before.lease_count());
    assert_eq!(
        after.runtime_binding_count(),
        before.runtime_binding_count()
    );
    assert_eq!(
        after.pending_join_authorization_count(),
        before.pending_join_authorization_count()
    );
    assert_eq!(
        after.consumed_join_authorization_count(),
        before.consumed_join_authorization_count()
    );
}

fn assert_single_incomplete_transition(
    before: &GatewayConformanceSnapshot,
    after: &GatewayConformanceSnapshot,
) {
    assert_eq!(after.record_item_count(), before.record_item_count() + 1);
    assert_eq!(
        after.projection_outbox_count(),
        before.projection_outbox_count() + 1
    );
    assert_eq!(
        after.incomplete_record_item_count(),
        before.incomplete_record_item_count() + 1
    );
    assert_eq!(
        after.incomplete_projection_outbox_count(),
        before.incomplete_projection_outbox_count() + 1
    );
}

struct FixedIds {
    values: Mutex<Vec<String>>,
}

impl FixedIds {
    fn new(values: &[&str]) -> Self {
        Self::from_owned(values.iter().map(|value| (*value).to_string()).collect())
    }

    fn from_owned(values: Vec<String>) -> Self {
        Self {
            values: Mutex::new(values.into_iter().rev().collect()),
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
    registration_policy_join_request_with_proof(run_id, operation_id, "join_policy_runtime_01")
}

fn registration_policy_join_request_with_proof(
    run_id: &str,
    operation_id: &str,
    proof_ref: &str,
) -> OpenRunRequest {
    let mut wire = request_fixture("positive/open_run_join_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["client_operation_id"] = serde_json::Value::String(operation_id.to_string());
    wire["join_proof"]["kind"] = serde_json::json!("registration_policy");
    wire["join_proof"]["proof_ref"] = serde_json::json!(proof_ref);
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
            1,
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

fn context_with_authority(
    template: &AuthenticatedSourceContext,
    credential_id: &str,
    credential_epoch: u64,
    policy_revision: u64,
) -> AuthenticatedSourceContext {
    AuthenticatedSourceContext::new(
        template.organization_id().clone(),
        template.principal().clone(),
        template.source_registration_id(),
        AuthenticationSnapshot::new(
            credential_id,
            credential_epoch,
            policy_revision,
            template.authentication().authenticated_at_unix_ms(),
            template.authentication().expires_at_unix_ms(),
        )
        .expect("replacement authentication snapshot"),
        template.registration_policy().clone(),
    )
    .expect("replacement authenticated source context")
}

fn context_with_expiry(
    template: &AuthenticatedSourceContext,
    expires_at_unix_ms: u64,
) -> AuthenticatedSourceContext {
    AuthenticatedSourceContext::new(
        template.organization_id().clone(),
        template.principal().clone(),
        template.source_registration_id(),
        AuthenticationSnapshot::new(
            template.authentication().credential_id(),
            template.authentication().credential_epoch(),
            template.authentication().policy_revision(),
            template.authentication().authenticated_at_unix_ms(),
            expires_at_unix_ms,
        )
        .expect("expiry-bound authentication snapshot"),
        template.registration_policy().clone(),
    )
    .expect("expiry-bound authenticated source context")
}

fn source_context_for_organization(organization_id: &str) -> AuthenticatedSourceContext {
    let template = source_context();
    AuthenticatedSourceContext::new(
        organization_id.try_into().expect("organization"),
        template.principal().clone(),
        format!("{}_{}", template.source_registration_id(), organization_id),
        AuthenticationSnapshot::new(
            format!(
                "{}_{}",
                template.authentication().credential_id(),
                organization_id
            ),
            template.authentication().credential_epoch(),
            template.authentication().policy_revision(),
            template.authentication().authenticated_at_unix_ms(),
            template.authentication().expires_at_unix_ms(),
        )
        .expect("organization-scoped authentication"),
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
            1,
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
        format!("{}_{}", template.source_registration_id(), organization_id),
        AuthenticationSnapshot::new(
            format!(
                "{}_{}",
                template.authentication().credential_id(),
                organization_id
            ),
            template.authentication().credential_epoch(),
            template.authentication().policy_revision(),
            template.authentication().authenticated_at_unix_ms(),
            template.authentication().expires_at_unix_ms(),
        )
        .expect("organization-scoped runtime authentication"),
        template.registration_policy().clone(),
    )
    .expect("organization-scoped runtime context")
}

async fn start_harness<H: GatewayConformanceHarness>() -> H {
    let harness = H::start().await.expect("start isolated Gateway harness");
    harness
        .seed_current_authority(&source_context())
        .await
        .expect("seed coordinator current authority");
    harness
        .seed_current_authority(&runtime_source_context())
        .await
        .expect("seed runtime current authority");
    harness
}

pub async fn open_run_returns_a_scoped_lease_and_exact_retry<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

pub async fn source_stream_freezes_trust_and_policy_revision<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
        harness
            .snapshot()
            .await
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
    harness
        .rotate_current_authority(&initial, &revised_policy)
        .await
        .expect("publish the revised current policy");
    let old_policy_replay = gateway
        .open_run(&initial, create_request())
        .await
        .expect_err("the current credential cannot authenticate an old policy snapshot");
    assert_eq!(old_policy_replay.code(), ContractErrorCode::Forbidden);
    let revised_policy_replay = gateway
        .open_run(&revised_policy, create_request())
        .await
        .expect_err("an operation replay cannot cross a policy-only rotation");
    assert_eq!(
        revised_policy_replay.code(),
        ContractErrorCode::LeaseRevoked
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

pub async fn current_authority_rotation_rejects_stale_replay_and_preserves_operation_identity<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let initial = source_context();
    harness
        .seed_current_authority(&initial)
        .await
        .expect("seed initial current authority");
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_authority_epoch_01",
            "stream_authority_epoch_01",
            "lease_f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "run_authority_epoch_02",
            "stream_authority_epoch_02",
            "lease_f223456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let original_request = create_request();
    let opened = gateway
        .open_run(&initial, original_request.clone())
        .await
        .expect("open under initial current authority");
    let replacement = context_with_authority(&initial, "credential_ci_runner_rotated", 2, 8);
    harness
        .rotate_current_authority(&initial, &replacement)
        .await
        .expect("rotate current credential, epoch, and policy");
    let after_rotation = harness.snapshot().await.expect("snapshot after rotation");

    let old_replay = gateway
        .open_run(&initial, original_request.clone())
        .await
        .expect_err("an old credential cannot retrieve a stored replay");
    assert_eq!(old_replay.code(), ContractErrorCode::Unauthenticated);

    let mut novel_wire =
        serde_json::to_value(create_request()).expect("serialize novel old-authority request");
    novel_wire["client_operation_id"] = serde_json::json!("operation_open_old_authority_novel");
    novel_wire["client_run_key"] = serde_json::json!("workload_old_authority_novel");
    let novel_request = resign_open_wire(novel_wire);
    let old_novel = gateway
        .open_run(&initial, novel_request.clone())
        .await
        .expect_err("an old credential cannot perform novel work");
    assert_eq!(old_novel.code(), ContractErrorCode::Unauthenticated);

    let wrong_epoch = context_with_authority(&initial, "credential_ci_runner_rotated", 1, 8);
    let wrong_epoch_error = gateway
        .open_run(&wrong_epoch, novel_request.clone())
        .await
        .expect_err("the current credential identifier cannot reuse an old epoch");
    assert_eq!(wrong_epoch_error.code(), ContractErrorCode::Unauthenticated);

    let stale_policy = context_with_authority(&initial, "credential_ci_runner_rotated", 2, 7);
    let stale_policy_replay = gateway
        .open_run(&stale_policy, original_request.clone())
        .await
        .expect_err("the current credential cannot use an old policy for replay");
    assert_eq!(stale_policy_replay.code(), ContractErrorCode::Forbidden);
    let stale_policy_novel = gateway
        .open_run(&stale_policy, novel_request.clone())
        .await
        .expect_err("the current credential cannot use an old policy for novel work");
    assert_eq!(stale_policy_novel.code(), ContractErrorCode::Forbidden);

    let stale_replay = gateway
        .open_run(&replacement, original_request.clone())
        .await
        .expect_err("a replay bound to the old epoch cannot cross authority rotation");
    assert_eq!(stale_replay.code(), ContractErrorCode::LeaseRevoked);

    let mut conflicting_wire =
        serde_json::to_value(original_request).expect("serialize old operation identity");
    conflicting_wire["objective_ref"] = serde_json::json!("objective_changed_after_rotation");
    let stale_conflict = gateway
        .open_run(&replacement, resign_open_wire(conflicting_wire))
        .await
        .expect_err("the old operation identity remains a tombstone after rotation");
    assert_eq!(stale_conflict.code(), ContractErrorCode::LeaseRevoked);

    let stale_lease = gateway
        .ingest(
            &replacement,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect_err("a lease bound to the old epoch cannot cross authority rotation");
    assert_eq!(stale_lease.code(), ContractErrorCode::LeaseRevoked);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after stale authority attempts"),
        after_rotation,
        "stale authority and replay attempts have no lifecycle effects"
    );

    let recovered = gateway
        .open_run(&replacement, novel_request)
        .await
        .expect("a distinct operation identity works under the current authority");
    assert_eq!(recovered.outcome(), OpenRunOutcome::Created);
    assert_eq!(recovered.run_id().as_str(), "run_authority_epoch_02");
}

pub async fn novel_lifecycle_operations_recheck_authentication_expiry_at_final_transaction_time<
    H: GatewayConformanceHarness,
>() {
    const ADMISSION_UNIX_MS: u64 = 1_783_891_200_000;
    const AUTHORITY_UNIX_MS: u64 = 1_783_891_249_999;
    const AUTHENTICATION_EXPIRY_UNIX_MS: u64 = 1_783_891_250_000;

    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let current = source_context();
    let runtime_current = runtime_source_context();
    let setup_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(ADMISSION_UNIX_MS),
        FixedIds::new(&[
            "run_authority_expiry_01",
            "stream_authority_expiry_01",
            "lease_a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_runtime_authority_expiry_01",
            "lease_c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let opened = setup_gateway
        .open_run(&current, create_request())
        .await
        .expect("open run before the authentication-expiry boundary");
    harness
        .register_join_policy(
            &current,
            &runtime_current,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_authority_expiry_01",
            1_783_894_800_000,
        )
        .await
        .expect("register runtime source before the authentication-expiry boundary");
    let joined = setup_gateway
        .open_run(
            &runtime_current,
            registration_policy_join_request_with_proof(
                opened.run_id().as_str(),
                "operation_join_runtime_authority_expiry_01",
                "join_policy_runtime_authority_expiry_01",
            ),
        )
        .await
        .expect("join runtime source before the authentication-expiry boundary");
    setup_gateway
        .ingest(
            &current,
            ingest_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect("seed valid evidence before the authentication-expiry boundary");
    let baseline = harness.snapshot().await.expect("baseline snapshot");
    let expiring = context_with_expiry(&current, AUTHENTICATION_EXPIRY_UNIX_MS);
    let runtime_expiring = context_with_expiry(&runtime_current, AUTHENTICATION_EXPIRY_UNIX_MS);

    let mut open_wire =
        serde_json::to_value(create_request()).expect("serialize expiry-boundary open");
    open_wire["client_operation_id"] = serde_json::json!("operation_open_authentication_expiry_01");
    open_wire["client_run_key"] = serde_json::json!("workload_authentication_expiry_01");
    let open_error = ExecutionEvidenceGateway::new(
        repository.clone(),
        AuthorityExpiryClock::new(
            ADMISSION_UNIX_MS,
            AUTHORITY_UNIX_MS,
            AUTHENTICATION_EXPIRY_UNIX_MS,
        ),
        FixedIds::new(&[
            "run_authentication_expiry_rejected",
            "stream_authentication_expiry_rejected",
            "lease_b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&expiring, resign_open_wire(open_wire))
    .await
    .expect_err("open_run must not cross authentication expiry after its client-run lock");
    assert_eq!(open_error.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(
        open_error.audit_reason(),
        AuditReason::CurrentAuthorityStale
    );
    assert_non_retryable(&open_error);
    assert_eq!(
        harness.snapshot().await.expect("post-open snapshot"),
        baseline
    );

    let bind_error = ExecutionEvidenceGateway::new(
        repository.clone(),
        AuthorityExpiryClock::new(
            ADMISSION_UNIX_MS,
            AUTHORITY_UNIX_MS,
            AUTHENTICATION_EXPIRY_UNIX_MS,
        ),
        FixedIds::new(&[]),
    )
    .bind_runtime(
        &runtime_expiring,
        bind_runtime_request(opened.run_id().as_str(), joined.lease().lease_id()),
    )
    .await
    .expect_err("bind_runtime must not cross authentication expiry after run and lease locks");
    assert_eq!(bind_error.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(
        bind_error.audit_reason(),
        AuditReason::CurrentAuthorityStale
    );
    assert_non_retryable(&bind_error);
    assert_eq!(
        harness.snapshot().await.expect("post-bind snapshot"),
        baseline
    );

    let ingest_error = ExecutionEvidenceGateway::new(
        repository.clone(),
        AuthorityExpiryClock::new(
            ADMISSION_UNIX_MS,
            AUTHORITY_UNIX_MS,
            AUTHENTICATION_EXPIRY_UNIX_MS,
        ),
        FixedIds::new(&[]),
    )
    .ingest(
        &expiring,
        gap_fill_request(
            opened.run_id().as_str(),
            opened.lease().lease_id(),
            opened.source_stream_id(),
        ),
    )
    .await
    .expect_err("ingest must not cross authentication expiry after run and lease locks");
    assert_eq!(ingest_error.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(
        ingest_error.audit_reason(),
        AuditReason::CurrentAuthorityStale
    );
    assert_non_retryable(&ingest_error);
    assert_eq!(
        harness.snapshot().await.expect("post-ingest snapshot"),
        baseline
    );

    let finish_error = ExecutionEvidenceGateway::new(
        repository,
        AuthorityExpiryClock::new(
            ADMISSION_UNIX_MS,
            AUTHORITY_UNIX_MS,
            AUTHENTICATION_EXPIRY_UNIX_MS,
        ),
        FixedIds::new(&[]),
    )
    .finish_run(
        &expiring,
        finish_run_request(
            opened.run_id().as_str(),
            opened.lease().lease_id(),
            opened.source_stream_id(),
            "operation_finish_authentication_expiry_01",
        ),
    )
    .await
    .expect_err("finish_run must not cross authentication expiry after run and lease locks");
    assert_eq!(finish_error.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(
        finish_error.audit_reason(),
        AuditReason::CurrentAuthorityStale
    );
    assert_non_retryable(&finish_error);
    assert_eq!(
        harness.snapshot().await.expect("post-finish snapshot"),
        baseline
    );
}

pub async fn credential_rotation_requires_new_join_authority_and_a_new_source_stream<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let coordinator = source_context();
    let original_runtime = runtime_source_context();
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_rotation_continuity_01",
            "stream_rotation_coordinator_01",
            "lease_c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_rotation_runtime_01",
            "lease_c223456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_rotation_runtime_02",
            "lease_c323456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let opened = gateway
        .open_run(&coordinator, create_request())
        .await
        .expect("open run with a coordinator lease that remains live");
    harness
        .register_join_policy(
            &coordinator,
            &original_runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_epoch_01",
            1_783_894_800_000,
        )
        .await
        .expect("register runtime join policy for epoch one");
    let first_join_request = registration_policy_join_request_with_proof(
        opened.run_id().as_str(),
        "operation_join_runtime_epoch_01",
        "join_policy_runtime_epoch_01",
    );
    let first_join = gateway
        .open_run(&original_runtime, first_join_request.clone())
        .await
        .expect("join runtime source under epoch one");

    let rotated_runtime =
        context_with_authority(&original_runtime, "credential_runtime_rotated", 2, 3);
    harness
        .rotate_current_authority(&original_runtime, &rotated_runtime)
        .await
        .expect("rotate only the runtime credential and epoch");
    let after_rotation = harness.snapshot().await.expect("snapshot after rotation");

    let old_replay = gateway
        .open_run(&original_runtime, first_join_request.clone())
        .await
        .expect_err("the old runtime credential cannot retrieve its join replay");
    assert_eq!(old_replay.code(), ContractErrorCode::Unauthenticated);
    let rotated_replay = gateway
        .open_run(&rotated_runtime, first_join_request)
        .await
        .expect_err("the old join operation remains bound to epoch one");
    assert_eq!(rotated_replay.code(), ContractErrorCode::LeaseRevoked);
    let old_lease = gateway
        .ingest(
            &rotated_runtime,
            runtime_ingest_request(
                opened.run_id().as_str(),
                first_join.lease().lease_id(),
                first_join.source_stream_id(),
            ),
        )
        .await
        .expect_err("the rotated runtime cannot reuse its epoch-one lease");
    assert_eq!(old_lease.code(), ContractErrorCode::LeaseRevoked);

    let stale_join_policy = gateway
        .open_run(
            &rotated_runtime,
            registration_policy_join_request_with_proof(
                opened.run_id().as_str(),
                "operation_join_runtime_stale_policy",
                "join_policy_runtime_epoch_01",
            ),
        )
        .await
        .expect_err("join authority issued for epoch one cannot authorize epoch two");
    assert_eq!(stale_join_policy.code(), ContractErrorCode::NotFound);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after stale credential artifacts"),
        after_rotation
    );

    harness
        .register_join_policy(
            &coordinator,
            &rotated_runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_epoch_02",
            1_783_894_800_000,
        )
        .await
        .expect("register fresh runtime join policy for epoch two");
    let second_join = gateway
        .open_run(
            &rotated_runtime,
            registration_policy_join_request_with_proof(
                opened.run_id().as_str(),
                "operation_join_runtime_epoch_02",
                "join_policy_runtime_epoch_02",
            ),
        )
        .await
        .expect("join the still-live run with a fresh epoch-two stream");
    assert_ne!(
        second_join.source_stream_id(),
        first_join.source_stream_id()
    );
    assert_ne!(
        second_join.lease().lease_id(),
        first_join.lease().lease_id()
    );
}

pub async fn revoked_current_authority_rejects_novel_work_and_replay_without_effects<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let current = source_context();
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_authority_revoke_01",
            "stream_authority_revoke_01",
            "lease_c423456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let request = create_request();
    gateway
        .open_run(&current, request.clone())
        .await
        .expect("open under the current authority");
    harness
        .revoke_current_authority(&current)
        .await
        .expect("revoke the current authority");
    let after_revoke = harness.snapshot().await.expect("snapshot after revocation");

    let replay = gateway
        .open_run(&current, request)
        .await
        .expect_err("a revoked credential cannot retrieve a replay");
    assert_eq!(replay.code(), ContractErrorCode::Unauthenticated);
    let mut novel_wire =
        serde_json::to_value(create_request()).expect("serialize novel revoked request");
    novel_wire["client_operation_id"] = serde_json::json!("operation_open_revoked_novel");
    novel_wire["client_run_key"] = serde_json::json!("workload_revoked_novel");
    let novel = gateway
        .open_run(&current, resign_open_wire(novel_wire))
        .await
        .expect_err("a revoked credential cannot perform novel work");
    assert_eq!(novel.code(), ContractErrorCode::Unauthenticated);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after revoked authority attempts"),
        after_revoke
    );
}

pub async fn every_lifecycle_replay_is_bound_to_its_credential_epoch_and_policy<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let registered_runtime = runtime_source_context();
    let initial = context_with_authority(&runtime_finalizer_context(), "credential_runtime", 1, 4);
    harness
        .rotate_current_authority(&registered_runtime, &initial)
        .await
        .expect("publish a current runtime policy that permits finalization");
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_all_epoch_replays_01",
            "stream_all_epoch_replays_01",
            "lease_c523456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let open_request = runtime_create_request();
    let opened = gateway
        .open_run(&initial, open_request.clone())
        .await
        .expect("open runtime run under epoch one");
    let bind_request = bind_runtime_request(opened.run_id().as_str(), opened.lease().lease_id());
    gateway
        .bind_runtime(&initial, bind_request.clone())
        .await
        .expect("bind runtime under epoch one");
    let ingest_request = runtime_ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    gateway
        .ingest(&initial, ingest_request.clone())
        .await
        .expect("ingest runtime evidence under epoch one");
    let finish_request = runtime_finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    gateway
        .finish_run(&initial, finish_request.clone())
        .await
        .expect("finish runtime run under epoch one");

    let replacement = context_with_authority(&initial, "credential_runtime_epoch_two", 2, 4);
    harness
        .rotate_current_authority(&initial, &replacement)
        .await
        .expect("rotate runtime credential without changing policy");
    let after_rotation = harness.snapshot().await.expect("snapshot after rotation");

    let old_failures = [
        gateway
            .open_run(&initial, open_request)
            .await
            .expect_err("old open replay must fail"),
        gateway
            .bind_runtime(&initial, bind_request.clone())
            .await
            .expect_err("old bind replay must fail"),
        gateway
            .ingest(&initial, ingest_request.clone())
            .await
            .expect_err("old ingest replay must fail"),
        gateway
            .finish_run(&initial, finish_request.clone())
            .await
            .expect_err("old finish replay must fail"),
    ];
    for failure in old_failures {
        assert_eq!(failure.code(), ContractErrorCode::Unauthenticated);
    }

    let replacement_failures = [
        gateway
            .open_run(&replacement, runtime_create_request())
            .await
            .expect_err("epoch-one open replay must not materialize under epoch two"),
        gateway
            .bind_runtime(&replacement, bind_request)
            .await
            .expect_err("epoch-one bind replay must not materialize under epoch two"),
        gateway
            .ingest(&replacement, ingest_request)
            .await
            .expect_err("epoch-one ingest replay must not materialize under epoch two"),
        gateway
            .finish_run(&replacement, finish_request)
            .await
            .expect_err("epoch-one finish replay must not materialize under epoch two"),
    ];
    for failure in replacement_failures {
        assert_eq!(failure.code(), ContractErrorCode::LeaseRevoked);
    }
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after rejected lifecycle replays"),
        after_rotation
    );
}

pub async fn open_run_join_requires_a_server_registered_grant<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

    let self_authorization = harness
        .register_join_grant(
            &runtime_context,
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .await
        .expect_err("joining source cannot mint its own grant");
    assert_eq!(self_authorization.code(), ContractErrorCode::Forbidden);

    harness
        .register_join_grant(
            &source_context(),
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .await
        .expect("register server-side join grant");
    let revised_runtime_context = AuthenticatedSourceContext::new(
        runtime_context.organization_id().clone(),
        runtime_context.principal().clone(),
        runtime_context.source_registration_id(),
        AuthenticationSnapshot::new(
            runtime_context.authentication().credential_id(),
            runtime_context.authentication().credential_epoch(),
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
        .expect_err("an unregistered policy revision is not current authority");
    assert_eq!(stale_grant_error.code(), ContractErrorCode::Forbidden);

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

    let resurrection = harness
        .register_join_grant(
            &source_context(),
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .await
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

    harness
        .register_join_grant(
            &source_context(),
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_expiring_01",
            1_783_891_300_000,
        )
        .await
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

pub async fn open_run_join_rechecks_grant_expiry_after_admission<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admission_unix_ms = 1_783_891_200_000;
    let grant_expiry_unix_ms = admission_unix_ms + 100_000;
    let creator = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "run_join_grant_boundary_01",
            "stream_join_grant_boundary_01",
            "lease_aa23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let coordinator = source_context();
    let opened = creator
        .open_run(&coordinator, create_request())
        .await
        .expect("open run");
    let runtime = runtime_source_context();
    harness
        .register_join_grant(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_transaction_boundary_01",
            grant_expiry_unix_ms,
        )
        .await
        .expect("register boundary join grant");
    let mut join_wire =
        serde_json::to_value(join_request(opened.run_id().as_str())).expect("serialize join");
    join_wire["client_operation_id"] =
        serde_json::json!("operation_join_grant_transaction_boundary_01");
    join_wire["join_proof"]["proof_ref"] = serde_json::json!("join_grant_transaction_boundary_01");
    join_wire["join_proof"]["expires_at_unix_ms"] = serde_json::json!(grant_expiry_unix_ms);
    let request = resign_open_wire(join_wire);
    let before = harness
        .snapshot()
        .await
        .expect("snapshot before grant-expiry rejection");

    let crossing_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        AdvancingClock::new(admission_unix_ms, grant_expiry_unix_ms),
        FixedIds::new(&[
            "stream_join_grant_rejected_01",
            "lease_ab23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let error = crossing_gateway
        .open_run(&runtime, request.clone())
        .await
        .expect_err("a grant expiring during transaction admission must fail closed");
    assert_eq!(error.code(), ContractErrorCode::NotFound);
    assert_non_retryable(&error);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after grant-expiry rejection"),
        before
    );

    let recovery_gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(grant_expiry_unix_ms - 1),
        FixedIds::new(&[
            "stream_join_grant_recovery_01",
            "lease_ac23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let joined = recovery_gateway
        .open_run(&runtime, request)
        .await
        .expect("a rejected boundary attempt must leave its grant and operation reusable");
    assert_eq!(joined.outcome(), OpenRunOutcome::Joined);
    let after_recovery = harness
        .snapshot()
        .await
        .expect("snapshot after valid grant consumption");
    assert_eq!(
        after_recovery.pending_join_authorization_count() + 1,
        before.pending_join_authorization_count()
    );
    assert_eq!(
        after_recovery.consumed_join_authorization_count(),
        before.consumed_join_authorization_count() + 1
    );
}

pub async fn open_run_join_rechecks_finalization_deadline_after_admission<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admission_unix_ms = 1_783_891_200_000;
    let coordinator_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "run_join_deadline_boundary_01",
            "stream_join_deadline_boundary_01",
            "lease_af23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
        .expect("register reusable join policy");
    let finishing = coordinator_gateway
        .finish_run(
            &coordinator,
            finish_run_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
                "operation_finish_join_deadline_boundary_01",
            ),
        )
        .await
        .expect("enter finishing before the runtime source joins");
    let deadline = finishing
        .finalization_deadline_unix_ms()
        .expect("bounded finalization deadline");
    let baseline_join = registration_policy_join_request(
        opened.run_id().as_str(),
        "operation_join_before_deadline_boundary_01",
    );
    let joined = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(deadline - 1),
        FixedIds::new(&[
            "stream_join_before_deadline_boundary_01",
            "lease_b023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&runtime, baseline_join.clone())
    .await
    .expect("join before the finalization deadline");
    assert_eq!(joined.lease().expires_at_unix_ms(), deadline);

    let replayed = ExecutionEvidenceGateway::new(
        repository.clone(),
        ReplayOnlyClock::new(deadline),
        FixedIds::new(&[]),
    )
    .open_run(&runtime, baseline_join)
    .await
    .expect("exact join replay must precede transaction-time reconciliation");
    assert_eq!(replayed.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(replayed.source_stream_id(), joined.source_stream_id());
    assert_eq!(replayed.lease().lease_id(), joined.lease().lease_id());
    let before = harness
        .snapshot()
        .await
        .expect("snapshot before crossing-deadline join");

    let error = ExecutionEvidenceGateway::new(
        repository,
        AdvancingClock::new(deadline - 1, deadline),
        FixedIds::new(&[]),
    )
    .open_run(
        &runtime,
        registration_policy_join_request(
            opened.run_id().as_str(),
            "operation_join_crossing_deadline_boundary_01",
        ),
    )
    .await
    .expect_err("a novel join cannot cross the finalization deadline");
    assert_eq!(error.code(), ContractErrorCode::InvalidLifecycleTransition);
    assert_non_retryable(&error);
    let after = harness
        .snapshot()
        .await
        .expect("snapshot after crossing-deadline join");
    assert_no_novel_gateway_effects(&before, &after);
    assert_single_incomplete_transition(&before, &after);
}

pub async fn open_run_join_rechecks_last_lease_expiry_after_admission<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let opened_at_unix_ms = 1_783_891_200_000;
    let coordinator = source_context();
    let opened = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(opened_at_unix_ms),
        FixedIds::new(&[
            "run_join_last_lease_boundary_01",
            "stream_join_last_lease_boundary_01",
            "lease_b523456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&coordinator, create_request())
    .await
    .expect("open run");
    let last_lease_expiry = opened.lease().expires_at_unix_ms();
    let runtime = runtime_source_context();
    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
        .expect("register reusable join policy");
    let before = harness
        .snapshot()
        .await
        .expect("snapshot before crossing last-lease expiry");

    let error = ExecutionEvidenceGateway::new(
        repository,
        AdvancingClock::new(last_lease_expiry - 1, last_lease_expiry),
        FixedIds::new(&[]),
    )
    .open_run(
        &runtime,
        registration_policy_join_request(
            opened.run_id().as_str(),
            "operation_join_crossing_last_lease_01",
        ),
    )
    .await
    .expect_err("a novel join cannot revive a run after its last lease expires");
    assert_eq!(error.code(), ContractErrorCode::InvalidLifecycleTransition);
    assert_non_retryable(&error);
    let after = harness
        .snapshot()
        .await
        .expect("snapshot after crossing last-lease expiry");
    assert_no_novel_gateway_effects(&before, &after);
    assert_single_incomplete_transition(&before, &after);
}

pub async fn open_run_join_rejects_invalid_transaction_time_without_partial_state<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admission_unix_ms = 1_783_891_200_000;
    let creator = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "run_join_invalid_time_01",
            "stream_join_invalid_time_01",
            "lease_ad23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let coordinator = source_context();
    let opened = creator
        .open_run(&coordinator, create_request())
        .await
        .expect("open run");
    let runtime = runtime_source_context();
    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
        .expect("register reusable join policy");
    let request = registration_policy_join_request(
        opened.run_id().as_str(),
        "operation_join_invalid_transaction_time_01",
    );
    let before = harness
        .snapshot()
        .await
        .expect("snapshot before invalid join transaction time");

    for transaction_unix_ms in [0, admission_unix_ms - 1] {
        let invalid_gateway = ExecutionEvidenceGateway::new(
            repository.clone(),
            AdvancingClock::new(admission_unix_ms, transaction_unix_ms),
            FixedIds::new(&[]),
        );
        let error = invalid_gateway
            .open_run(&runtime, request.clone())
            .await
            .expect_err("invalid join transaction time must fail closed");
        assert_eq!(error.code(), ContractErrorCode::Backpressure);
        assert_eq!(
            harness
                .snapshot()
                .await
                .expect("snapshot after invalid join transaction time"),
            before
        );
    }

    let recovery = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "stream_join_invalid_time_recovery_01",
            "lease_ae23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&runtime, request)
    .await
    .expect("invalid transaction time must not consume join authority or operation identity");
    assert_eq!(recovery.outcome(), OpenRunOutcome::Joined);
}

pub async fn open_run_join_is_enumeration_safe_across_organizations<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    harness
        .seed_current_authority(&other_organization)
        .await
        .expect("seed authenticated source in the other organization");

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

pub async fn open_run_registration_policy_is_server_registered_and_reusable<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
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

pub async fn open_run_enforces_the_256_source_stream_limit_without_partial_state<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let mut identities = vec![
        "run_stream_cap_01".to_string(),
        "stream_cap_001".to_string(),
        "lease_cap_001".to_string(),
    ];
    for ordinal in 2..=256 {
        identities.push(format!("stream_cap_{ordinal:03}"));
        identities.push(format!("lease_cap_{ordinal:03}"));
    }
    identities.extend([
        "run_stream_cap_recovery".to_string(),
        "stream_cap_recovery".to_string(),
        "lease_cap_recovery".to_string(),
    ]);
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::from_owned(identities),
    );
    let coordinator = source_context();
    let opened = gateway
        .open_run(&coordinator, create_request())
        .await
        .expect("create the run with its first source stream");
    let runtime = runtime_source_context();

    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
        .expect("register reusable source-stream admission policy");

    let mut last_joined_stream = None;
    for ordinal in 2..=256 {
        let operation_id = format!("operation_join_stream_cap_{ordinal:03}");
        let joined = gateway
            .open_run(
                &runtime,
                registration_policy_join_request(opened.run_id().as_str(), &operation_id),
            )
            .await
            .unwrap_or_else(|error| panic!("source stream {ordinal} must be admitted: {error}"));
        assert_eq!(joined.outcome(), OpenRunOutcome::Joined);
        last_joined_stream = Some(joined.source_stream_id().to_string());
    }
    assert_eq!(
        last_joined_stream.as_deref(),
        Some("stream_cap_256"),
        "the 256th source stream is the final admitted stream"
    );

    let before_rejection = harness
        .snapshot()
        .await
        .expect("snapshot before source-stream cap rejection");
    let rejected_operation_id = "operation_join_stream_cap_rejected";
    let rejection = gateway
        .open_run(
            &runtime,
            registration_policy_join_request(opened.run_id().as_str(), rejected_operation_id),
        )
        .await
        .expect_err("the 257th source stream must be rejected");
    assert_eq!(
        rejection.code(),
        ContractErrorCode::InvalidLifecycleTransition
    );
    let response = rejection.response().expect("safe capacity response");
    assert!(!response.retryable());
    assert_eq!(response.retry_after_ms(), None);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after source-stream cap rejection"),
        before_rejection,
        "capacity rejection must not append facts or projection outbox work"
    );

    let mut recovery_wire =
        serde_json::to_value(runtime_create_request()).expect("serialize recovery request");
    recovery_wire["client_operation_id"] = serde_json::json!(rejected_operation_id);
    recovery_wire["client_run_key"] = serde_json::json!("runtime_stream_cap_recovery");
    let recovered = gateway
        .open_run(&runtime, resign_open_wire(recovery_wire))
        .await
        .expect("the rejected operation identity and generated identities remain available");
    assert_eq!(recovered.outcome(), OpenRunOutcome::Created);
    assert_eq!(recovered.run_id().as_str(), "run_stream_cap_recovery");
    assert_eq!(recovered.source_stream_id(), "stream_cap_recovery");
    assert_eq!(recovered.lease().lease_id(), "lease_cap_recovery");
}

pub async fn open_run_rejects_an_expired_authentication_snapshot<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn open_run_rejects_source_capability_escalation<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn open_run_rejects_a_client_selected_authority<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn open_run_rejects_stale_request_digest_without_consuming_identity<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    let rejected_snapshot = harness.snapshot().await.expect("rejected snapshot");
    assert_eq!(rejected_snapshot.record_item_count(), 0);
    assert_eq!(rejected_snapshot.projection_outbox_count(), 0);

    let opened = gateway
        .open_run(&context, valid)
        .await
        .expect("digest rejection must not consume request or generated identities");
    assert_eq!(opened.run_id().as_str(), "run_digest_recovery_01");
}

pub async fn ingest_commits_an_atomic_batch_and_reports_source_gaps<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    let committed_snapshot = harness.snapshot().await.expect("memory ledger snapshot");
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
        harness.snapshot().await.expect("replayed ledger snapshot"),
        committed_snapshot
    );
}

pub async fn ingest_accepts_a_mixed_duplicate_and_gap_fill_retry<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn ingest_coalesces_same_batch_exact_duplicates_without_partial_state<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_same_batch_01",
            "stream_same_batch_01",
            "lease_b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let template = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );

    let mut duplicate_wire = serde_json::to_value(template.clone()).expect("serialize ingest");
    duplicate_wire["client_operation_id"] = serde_json::json!("operation_same_batch_exact_01");
    let first = duplicate_wire["envelopes"][0].clone();
    duplicate_wire["envelopes"] = serde_json::Value::Array(vec![first.clone(), first]);
    let duplicate_request = finalize_ingest_wire(duplicate_wire);

    let before = harness.snapshot().await.expect("snapshot before ingest");
    let accepted = gateway
        .ingest(&context, duplicate_request.clone())
        .await
        .expect("same-batch exact duplicate is coalesced");
    assert_eq!(accepted.committed_count(), 1);
    assert_eq!(accepted.duplicate_count(), 0);
    assert_eq!(accepted.acknowledgements().len(), 1);
    assert_eq!(accepted.source_watermark(), 1);
    assert!(accepted.known_gaps().is_empty());
    let after = harness.snapshot().await.expect("snapshot after ingest");
    assert_eq!(
        after.evidence_event_count(),
        before.evidence_event_count() + 1
    );
    assert_eq!(after.record_item_count(), before.record_item_count() + 1);
    assert_eq!(
        after.projection_outbox_count(),
        before.projection_outbox_count() + 1
    );

    let replayed = gateway
        .ingest(&context, duplicate_request)
        .await
        .expect("exact operation replay remains stable");
    assert_eq!(replayed, accepted);
    assert_eq!(
        harness.snapshot().await.expect("snapshot after replay"),
        after
    );

    let mut conflict_wire = serde_json::to_value(template).expect("serialize conflict ingest");
    conflict_wire["client_operation_id"] = serde_json::json!("operation_same_batch_conflict_01");
    let mut novel = conflict_wire["envelopes"][0].clone();
    novel["source_event_id"] = serde_json::json!("event_same_batch_conflict_01");
    novel["source_sequence"] = serde_json::json!(2);
    let mut conflicting = novel.clone();
    conflicting["observed_at"]["uncertainty_ms"] = serde_json::json!(99);
    conflict_wire["envelopes"] = serde_json::Value::Array(vec![novel.clone(), conflicting]);
    let conflict = finalize_ingest_wire(conflict_wire.clone());
    let rejection = gateway
        .ingest(&context, conflict)
        .await
        .expect_err("same event identity with different content must conflict");
    assert_eq!(rejection.code(), ContractErrorCode::SourceEventConflict);
    assert_eq!(
        harness.snapshot().await.expect("snapshot after conflict"),
        after,
        "conflicting batch must not commit partial evidence or outbox state"
    );

    conflict_wire["envelopes"] = serde_json::Value::Array(vec![novel]);
    let recovery = finalize_ingest_wire(conflict_wire);
    let recovered = gateway
        .ingest(&context, recovery)
        .await
        .expect("rejected batch must not consume its operation identity");
    assert_eq!(recovered.committed_count(), 1);
    assert_eq!(recovered.duplicate_count(), 0);
}

pub async fn ingest_rejects_payload_tampering_without_a_partial_commit<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

pub async fn ingest_rejects_reused_operation_identity_with_changed_content<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn ingest_conflicts_roll_back_the_entire_batch_and_operation_identity<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    let before_event_conflict = harness
        .snapshot()
        .await
        .expect("snapshot before event conflict");

    let error = gateway
        .ingest(&context, event_conflict)
        .await
        .expect_err("one conflicting event must reject the whole batch");
    assert_eq!(error.code(), ContractErrorCode::SourceEventConflict);
    assert_eq!(
        harness
            .snapshot()
            .await
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
    let before_sequence_conflict = harness
        .snapshot()
        .await
        .expect("snapshot before sequence conflict");

    let error = gateway
        .ingest(&context, sequence_conflict)
        .await
        .expect_err("one reused sequence must reject the whole batch");
    assert_eq!(error.code(), ContractErrorCode::SequenceConflict);
    assert_eq!(
        harness
            .snapshot()
            .await
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

pub async fn lease_failures_are_explicit_and_cross_organization_safe<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

    let other_context = source_context_for_organization("org_other");
    harness
        .seed_current_authority(&other_context)
        .await
        .expect("seed authenticated source in the other organization");
    let other_organization = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[]),
    );
    let cross_org = other_organization
        .ingest(&other_context, request.clone())
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
        .ingest(&other_context, missing)
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

pub async fn active_run_seals_only_after_its_last_lease_expires_and_cannot_be_revived<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
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
    let before_first_expiry = harness
        .snapshot()
        .await
        .expect("snapshot before first expiry");

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
        harness
            .snapshot()
            .await
            .expect("snapshot with one live lease"),
        before_first_expiry
    );

    let last_expiry_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        AdvancingClock::new(
            joined.lease().expires_at_unix_ms() - 1,
            joined.lease().expires_at_unix_ms(),
        ),
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
    assert_non_retryable(&late_join);
    let sealed = harness
        .snapshot()
        .await
        .expect("snapshot after lazy reconciliation");
    assert_no_novel_gateway_effects(&before_first_expiry, &sealed);
    assert_single_incomplete_transition(&before_first_expiry, &sealed);

    let replay_gateway = ExecutionEvidenceGateway::new(
        repository,
        ReplayOnlyClock::new(joined.lease().expires_at_unix_ms()),
        FixedIds::new(&[]),
    );
    let replayed = replay_gateway
        .open_run(&runtime, join_request)
        .await
        .expect("exact join replay remains stable after lazy sealing");
    assert_eq!(replayed.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(replayed.lease().lease_id(), joined.lease().lease_id());
    assert_eq!(harness.snapshot().await.expect("replay snapshot"), sealed);
}

pub async fn open_run_does_not_leave_partial_state_when_identity_generation_fails<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

pub async fn bind_runtime_is_source_scoped_and_idempotent<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(1_783_891_200_000),
        FixedIds::new(&[
            "run_runtime_01",
            "stream_runtime_01",
            "lease_1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "stream_runtime_02",
            "lease_2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
        .bind_runtime(&context, request.clone())
        .await
        .expect("binding retry");
    assert!(replayed.accepted());
    assert!(replayed.idempotent_replay());
    assert_eq!(replayed.binding_id(), accepted.binding_id());

    let mut additional_binding_wire =
        serde_json::to_value(request).expect("serialize same-run binding");
    additional_binding_wire["client_operation_id"] =
        serde_json::json!("operation_bind_runtime_same_run_02");
    additional_binding_wire["binding"]["binding_id"] = serde_json::json!("binding_pod_same_run_02");
    let additional_binding = resign_bind_wire(additional_binding_wire);
    let accepted_again = gateway
        .bind_runtime(&context, additional_binding)
        .await
        .expect("same run may reaffirm an exact identity with a new binding");
    assert!(accepted_again.accepted());
    assert!(!accepted_again.idempotent_replay());
    assert_eq!(accepted_again.binding_id(), "binding_pod_same_run_02");

    harness
        .register_join_policy(
            &context,
            &context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
        .expect("register a same-source replacement-stream policy");
    let replacement = gateway
        .open_run(
            &context,
            registration_policy_join_request(
                opened.run_id().as_str(),
                "operation_join_runtime_replacement_01",
            ),
        )
        .await
        .expect("open a replacement stream for the same registered source");
    let replacement_request = bind_runtime_request(
        replacement.run_id().as_str(),
        replacement.lease().lease_id(),
    );
    let mut replacement_wire =
        serde_json::to_value(replacement_request).expect("serialize replacement-stream binding");
    replacement_wire["client_operation_id"] =
        serde_json::json!("operation_bind_runtime_replacement_01");
    let replacement_request = resign_bind_wire(replacement_wire);
    let scope_error = gateway
        .bind_runtime(&context, replacement_request)
        .await
        .expect_err("a replacement stream cannot claim an earlier stream's binding");
    assert_eq!(scope_error.code(), ContractErrorCode::LeaseScopeMismatch);
}

pub async fn bind_runtime_prevents_cross_run_identity_confusion_until_seal<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

pub async fn bind_runtime_rechecks_last_lease_expiry_after_admission<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admission_unix_ms = 1_783_891_200_000;
    let context = runtime_source_context();
    let opened = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "run_bind_lease_boundary_01",
            "stream_bind_lease_boundary_01",
            "lease_b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&context, runtime_create_request())
    .await
    .expect("open runtime run");
    let lease_expiry_unix_ms = opened.lease().expires_at_unix_ms();
    let baseline_request =
        bind_runtime_request(opened.run_id().as_str(), opened.lease().lease_id());
    let baseline = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[]),
    )
    .bind_runtime(&context, baseline_request.clone())
    .await
    .expect("commit binding replay baseline");
    assert!(!baseline.idempotent_replay());
    let before_replay = harness
        .snapshot()
        .await
        .expect("snapshot before exact binding replay");

    let replay_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        ReplayOnlyClock::new(lease_expiry_unix_ms),
        FixedIds::new(&[]),
    );
    let replayed = replay_gateway
        .bind_runtime(&context, baseline_request.clone())
        .await
        .expect("exact binding replay remains stable at lease expiry");
    assert!(replayed.idempotent_replay());
    assert_eq!(replayed.run_id(), baseline.run_id());
    assert_eq!(replayed.binding_id(), baseline.binding_id());
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after exact binding replay"),
        before_replay
    );

    let mut novel_wire =
        serde_json::to_value(&baseline_request).expect("serialize novel binding request");
    novel_wire["client_operation_id"] = serde_json::json!("operation_bind_crossing_last_lease_01");
    novel_wire["binding"]["binding_id"] = serde_json::json!("binding_pod_crossing_last_lease_01");
    let novel_request = resign_bind_wire(novel_wire);
    let error = ExecutionEvidenceGateway::new(
        repository.clone(),
        AdvancingClock::new(lease_expiry_unix_ms - 1, lease_expiry_unix_ms),
        FixedIds::new(&[]),
    )
    .bind_runtime(&context, novel_request)
    .await
    .expect_err("a novel binding cannot cross its last lease expiry");
    assert_eq!(error.code(), ContractErrorCode::LeaseExpired);
    assert_non_retryable(&error);
    let after_rejection = harness
        .snapshot()
        .await
        .expect("snapshot after crossing-lease binding rejection");
    assert_no_novel_gateway_effects(&before_replay, &after_rejection);
    assert_single_incomplete_transition(&before_replay, &after_rejection);
    assert_eq!(before_replay.active_runtime_identity_count(), 1);
    assert_eq!(after_rejection.active_runtime_identity_count(), 0);

    let post_seal_replay_gateway = ExecutionEvidenceGateway::new(
        repository,
        ReplayOnlyClock::new(lease_expiry_unix_ms),
        FixedIds::new(&[]),
    );
    let replayed_after_seal = post_seal_replay_gateway
        .bind_runtime(&context, baseline_request)
        .await
        .expect("exact binding replay remains stable after lazy sealing");
    assert!(replayed_after_seal.idempotent_replay());
    assert_eq!(replayed_after_seal.binding_id(), baseline.binding_id());
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after post-seal binding replay"),
        after_rejection
    );
}

pub async fn bind_runtime_rejects_an_expired_lease_without_sealing_while_another_lease_is_live<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admission_unix_ms = 1_783_891_200_000;
    let context = runtime_source_context();
    let opened = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "run_bind_staggered_lease_01",
            "stream_bind_staggered_lease_01",
            "lease_b223456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&context, runtime_create_request())
    .await
    .expect("open runtime run");
    harness
        .register_join_policy(
            &context,
            &context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
        .expect("register same-source replacement-stream policy");
    let replacement = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms + 100_000),
        FixedIds::new(&[
            "stream_bind_staggered_lease_02",
            "lease_b323456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(
        &context,
        registration_policy_join_request(
            opened.run_id().as_str(),
            "operation_join_bind_staggered_lease_01",
        ),
    )
    .await
    .expect("open a replacement stream with a later lease");
    let first_expiry = opened.lease().expires_at_unix_ms();
    assert!(replacement.lease().expires_at_unix_ms() > first_expiry);

    let mut expired_wire = serde_json::to_value(bind_runtime_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
    ))
    .expect("serialize expired-lease binding");
    expired_wire["client_operation_id"] =
        serde_json::json!("operation_bind_staggered_expired_lease_01");
    expired_wire["binding"]["binding_id"] =
        serde_json::json!("binding_pod_staggered_expired_lease_01");
    let before = harness
        .snapshot()
        .await
        .expect("snapshot before staggered-lease rejection");
    let error = ExecutionEvidenceGateway::new(
        repository.clone(),
        AdvancingClock::new(first_expiry - 1, first_expiry),
        FixedIds::new(&[]),
    )
    .bind_runtime(&context, resign_bind_wire(expired_wire))
    .await
    .expect_err("an expired requested lease is rejected while another lease keeps the run active");
    assert_eq!(error.code(), ContractErrorCode::LeaseExpired);
    assert_non_retryable(&error);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after staggered-lease rejection"),
        before
    );

    let mut live_wire = serde_json::to_value(bind_runtime_request(
        replacement.run_id().as_str(),
        replacement.lease().lease_id(),
    ))
    .expect("serialize live-lease binding");
    live_wire["client_operation_id"] = serde_json::json!("operation_bind_staggered_live_lease_01");
    live_wire["binding"]["binding_id"] = serde_json::json!("binding_pod_staggered_live_lease_01");
    let accepted =
        ExecutionEvidenceGateway::new(repository, FixedClock(first_expiry), FixedIds::new(&[]))
            .bind_runtime(&context, resign_bind_wire(live_wire))
            .await
            .expect("the later lease proves the run remained active");
    assert!(accepted.accepted());
    assert!(!accepted.idempotent_replay());
}

pub async fn bind_runtime_rejects_invalid_transaction_time_without_partial_state<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admission_unix_ms = 1_783_891_200_000;
    let context = runtime_source_context();
    let opened = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admission_unix_ms),
        FixedIds::new(&[
            "run_bind_invalid_time_01",
            "stream_bind_invalid_time_01",
            "lease_b423456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    )
    .open_run(&context, runtime_create_request())
    .await
    .expect("open runtime run");
    let request = bind_runtime_request(opened.run_id().as_str(), opened.lease().lease_id());
    let before = harness
        .snapshot()
        .await
        .expect("snapshot before invalid binding transaction time");

    for transaction_unix_ms in [0, admission_unix_ms - 1] {
        let error = ExecutionEvidenceGateway::new(
            repository.clone(),
            AdvancingClock::new(admission_unix_ms, transaction_unix_ms),
            FixedIds::new(&[]),
        )
        .bind_runtime(&context, request.clone())
        .await
        .expect_err("invalid binding transaction time must fail closed");
        assert_eq!(error.code(), ContractErrorCode::Backpressure);
        assert_eq!(
            harness
                .snapshot()
                .await
                .expect("snapshot after invalid binding transaction time"),
            before
        );
    }

    let accepted = ExecutionEvidenceGateway::new(
        repository,
        FixedClock(admission_unix_ms),
        FixedIds::new(&[]),
    )
    .bind_runtime(&context, request)
    .await
    .expect("invalid transaction time must not consume binding identity");
    assert!(accepted.accepted());
    assert!(!accepted.idempotent_replay());
}

pub async fn finish_run_remains_bounded_until_declared_gaps_are_filled<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn first_finish_seals_an_already_reconciled_run_atomically<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

    let snapshot = harness.snapshot().await.expect("snapshot");
    assert_eq!(snapshot.record_item_count(), 9);
    assert_eq!(snapshot.projection_outbox_count(), 9);
    assert_eq!(snapshot.finalization_declaration_count(), 1);
}

pub async fn finish_run_rejects_a_terminal_position_below_the_durable_watermark<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
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

pub async fn finish_run_deadline_is_frozen_and_expires_to_incomplete<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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

pub async fn ingest_rechecks_finalization_deadline_after_admission<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admitted_at_unix_ms = 1_783_891_200_000;
    let deadline_unix_ms = admitted_at_unix_ms + 60_000;
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admitted_at_unix_ms),
        FixedIds::new(&[
            "run_crossing_deadline_01",
            "stream_crossing_deadline_01",
            "lease_c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let original_ingest = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    let original_acknowledgement = gateway
        .ingest(&context, original_ingest.clone())
        .await
        .expect("commit the replay baseline with a source gap");
    let mut finish_wire = serde_json::to_value(finish_run_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
        "operation_finish_crossing_deadline_01",
    ))
    .expect("serialize crossing-deadline finish request");
    finish_wire["requested_finalization_deadline_unix_ms"] = serde_json::json!(deadline_unix_ms);
    let finishing = gateway
        .finish_run(&context, resign_finish_wire(finish_wire))
        .await
        .expect("enter the bounded finishing state");
    assert_eq!(
        finishing.finalization_deadline_unix_ms(),
        Some(deadline_unix_ms)
    );

    let before_replay = harness
        .snapshot()
        .await
        .expect("snapshot before exact replay at finalization deadline");
    let replay_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        ReplayOnlyClock::new(deadline_unix_ms),
        FixedIds::new(&[]),
    );
    let replayed = replay_gateway
        .ingest(&context, original_ingest)
        .await
        .expect("an exact replay remains stable at the finalization deadline");
    assert_eq!(
        serde_json::to_value(replayed).expect("serialize replayed acknowledgement"),
        serde_json::to_value(original_acknowledgement).expect("serialize original acknowledgement")
    );
    let before_rejection = harness
        .snapshot()
        .await
        .expect("snapshot after exact replay at finalization deadline");
    assert_eq!(before_rejection, before_replay);
    let crossing_gateway = ExecutionEvidenceGateway::new(
        repository,
        AdvancingClock::new(deadline_unix_ms - 1, deadline_unix_ms),
        FixedIds::new(&[]),
    );
    let error = crossing_gateway
        .ingest(
            &context,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect_err("novel ingest cannot commit after its transaction crosses the deadline");
    assert_eq!(error.code(), ContractErrorCode::InvalidLifecycleTransition);

    let after_rejection = harness
        .snapshot()
        .await
        .expect("snapshot after crossing-deadline rejection");
    assert_eq!(
        after_rejection.evidence_event_count(),
        before_rejection.evidence_event_count()
    );
    assert_eq!(
        after_rejection.operation_count(),
        before_rejection.operation_count()
    );
    assert_eq!(
        after_rejection.replay_count(),
        before_rejection.replay_count()
    );
    assert_eq!(
        after_rejection.record_item_count(),
        before_rejection.record_item_count() + 1
    );
    assert_eq!(
        after_rejection.projection_outbox_count(),
        before_rejection.projection_outbox_count() + 1
    );
    assert_eq!(
        after_rejection.incomplete_record_item_count(),
        before_rejection.incomplete_record_item_count() + 1
    );
    assert_eq!(
        after_rejection.incomplete_projection_outbox_count(),
        before_rejection.incomplete_projection_outbox_count() + 1
    );
}

pub async fn ingest_rechecks_last_lease_expiry_after_admission<H: GatewayConformanceHarness>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admitted_at_unix_ms = 1_783_891_200_000;
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admitted_at_unix_ms),
        FixedIds::new(&[
            "run_crossing_lease_expiry_01",
            "stream_crossing_lease_expiry_01",
            "lease_d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]),
    );
    let context = source_context();
    let opened = gateway
        .open_run(&context, create_request())
        .await
        .expect("open run");
    let lease_expiry_unix_ms = opened.lease().expires_at_unix_ms();
    let original_ingest = ingest_request(
        opened.run_id().as_str(),
        opened.lease().lease_id(),
        opened.source_stream_id(),
    );
    let original_acknowledgement = gateway
        .ingest(&context, original_ingest.clone())
        .await
        .expect("commit the replay baseline with a source gap");
    let before_replay = harness
        .snapshot()
        .await
        .expect("snapshot before exact replay at last-lease expiry");

    let replay_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        ReplayOnlyClock::new(lease_expiry_unix_ms),
        FixedIds::new(&[]),
    );
    let replayed = replay_gateway
        .ingest(&context, original_ingest)
        .await
        .expect("an exact replay remains stable at last-lease expiry");
    assert_eq!(
        serde_json::to_value(replayed).expect("serialize replayed acknowledgement"),
        serde_json::to_value(original_acknowledgement).expect("serialize original acknowledgement")
    );

    let before_rejection = harness
        .snapshot()
        .await
        .expect("snapshot before crossing-lease rejection");
    assert_eq!(before_rejection, before_replay);
    let crossing_gateway = ExecutionEvidenceGateway::new(
        repository,
        AdvancingClock::new(lease_expiry_unix_ms - 1, lease_expiry_unix_ms),
        FixedIds::new(&[]),
    );
    let error = crossing_gateway
        .ingest(
            &context,
            gap_fill_request(
                opened.run_id().as_str(),
                opened.lease().lease_id(),
                opened.source_stream_id(),
            ),
        )
        .await
        .expect_err("novel ingest cannot commit after its transaction crosses last-lease expiry");
    assert_eq!(error.code(), ContractErrorCode::LeaseExpired);

    let after_rejection = harness
        .snapshot()
        .await
        .expect("snapshot after crossing-lease rejection");
    assert_eq!(
        after_rejection.evidence_event_count(),
        before_rejection.evidence_event_count()
    );
    assert_eq!(
        after_rejection.operation_count(),
        before_rejection.operation_count()
    );
    assert_eq!(
        after_rejection.replay_count(),
        before_rejection.replay_count()
    );
    assert_eq!(
        after_rejection.record_item_count(),
        before_rejection.record_item_count() + 1
    );
    assert_eq!(
        after_rejection.projection_outbox_count(),
        before_rejection.projection_outbox_count() + 1
    );
    assert_eq!(
        after_rejection.incomplete_record_item_count(),
        before_rejection.incomplete_record_item_count() + 1
    );
    assert_eq!(
        after_rejection.incomplete_projection_outbox_count(),
        before_rejection.incomplete_projection_outbox_count() + 1
    );
}

pub async fn ingest_rejects_invalid_transaction_time_without_partial_state<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
    let admitted_at_unix_ms = 1_783_891_200_000;
    let gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        FixedClock(admitted_at_unix_ms),
        FixedIds::new(&[
            "run_invalid_transaction_time_01",
            "stream_invalid_transaction_time_01",
            "lease_e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
    let before_rejection = harness
        .snapshot()
        .await
        .expect("snapshot before invalid transaction time");

    for transaction_unix_ms in [0, admitted_at_unix_ms - 1] {
        let invalid_time_gateway = ExecutionEvidenceGateway::new(
            repository.clone(),
            AdvancingClock::new(admitted_at_unix_ms, transaction_unix_ms),
            FixedIds::new(&[]),
        );
        let error = invalid_time_gateway
            .ingest(&context, request.clone())
            .await
            .expect_err("invalid transaction time must fail closed");
        assert_eq!(error.code(), ContractErrorCode::Backpressure);
        assert_eq!(
            harness
                .snapshot()
                .await
                .expect("snapshot after invalid transaction time"),
            before_rejection
        );
    }
}

pub async fn finish_run_rejects_an_elapsed_requested_deadline_without_extending_it<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    let before = harness.snapshot().await.expect("snapshot before rejection");

    let error = gateway
        .finish_run(&context, elapsed)
        .await
        .expect_err("an elapsed caller deadline cannot be replaced by a longer policy window");
    assert_eq!(error.code(), ContractErrorCode::InvalidContract);
    assert_eq!(
        harness.snapshot().await.expect("snapshot after rejection"),
        before
    );

    let accepted = gateway
        .finish_run(&context, valid)
        .await
        .expect("deadline rejection must not consume the operation identity");
    assert_eq!(accepted.state(), RunState::Finishing);
}

pub async fn finishing_run_bounds_joined_leases_and_rejects_novel_work_at_deadline<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    harness
        .register_join_policy(
            &coordinator,
            &runtime,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_policy_runtime_01",
            1_783_894_800_000,
        )
        .await
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

    let replay_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        ReplayOnlyClock::new(deadline),
        FixedIds::new(&[]),
    );
    let replayed = replay_gateway
        .open_run(&runtime, join)
        .await
        .expect("exact join retry retains its original response");
    assert_eq!(replayed.outcome(), OpenRunOutcome::IdempotentRetry);
    assert_eq!(replayed.lease().lease_id(), joined.lease().lease_id());
    assert_eq!(
        replayed.lease().expires_at_unix_ms(),
        joined.lease().expires_at_unix_ms()
    );

    let before_deadline = harness
        .snapshot()
        .await
        .expect("snapshot before the co-terminating deadline and lease boundary");
    let deadline_ingest_gateway = ExecutionEvidenceGateway::new(
        repository.clone(),
        AdvancingClock::new(deadline - 1, deadline),
        FixedIds::new(&[]),
    );
    let late_ingest = deadline_ingest_gateway
        .ingest(
            &runtime,
            runtime_ingest_request(
                opened.run_id().as_str(),
                joined.lease().lease_id(),
                joined.source_stream_id(),
            ),
        )
        .await
        .expect_err("the finalization deadline dominates a co-terminating joined lease");
    assert_eq!(
        late_ingest.code(),
        ContractErrorCode::InvalidLifecycleTransition
    );
    assert_non_retryable(&late_ingest);
    let after_deadline = harness
        .snapshot()
        .await
        .expect("snapshot after deadline reconciliation");
    assert_no_novel_gateway_effects(&before_deadline, &after_deadline);
    assert_single_incomplete_transition(&before_deadline, &after_deadline);

    let mut second_late_ingest_wire = serde_json::to_value(runtime_ingest_request(
        opened.run_id().as_str(),
        joined.lease().lease_id(),
        joined.source_stream_id(),
    ))
    .expect("serialize second novel ingest after deadline reconciliation");
    second_late_ingest_wire["client_operation_id"] =
        serde_json::json!("operation_ingest_after_deadline_02");
    second_late_ingest_wire["envelopes"][0]["source_event_id"] =
        serde_json::json!("event_runtime_after_deadline_02");
    let second_late_ingest = deadline_ingest_gateway
        .ingest(&runtime, resign_ingest_wire(second_late_ingest_wire))
        .await
        .expect_err("a sealed deadline cannot degrade to lease expiry for later novel ingest");
    assert_eq!(
        second_late_ingest.code(),
        ContractErrorCode::InvalidLifecycleTransition
    );
    assert_non_retryable(&second_late_ingest);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after second novel ingest rejection"),
        after_deadline
    );

    let late_bind = ExecutionEvidenceGateway::new(
        repository.clone(),
        AdvancingClock::new(deadline - 1, deadline),
        FixedIds::new(&[]),
    )
    .bind_runtime(
        &runtime,
        bind_runtime_request(opened.run_id().as_str(), joined.lease().lease_id()),
    )
    .await
    .expect_err("a sealed deadline cannot degrade to lease expiry for a later novel binding");
    assert_eq!(
        late_bind.code(),
        ContractErrorCode::InvalidLifecycleTransition
    );
    assert_non_retryable(&late_bind);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after post-deadline binding rejection"),
        after_deadline
    );

    let late_join_gateway = ExecutionEvidenceGateway::new(
        repository,
        AdvancingClock::new(deadline - 1, deadline),
        FixedIds::new(&[]),
    );
    let late_join = late_join_gateway
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
    assert_non_retryable(&late_join);
    assert_eq!(
        harness
            .snapshot()
            .await
            .expect("snapshot after novel join rejection"),
        after_deadline
    );
}

pub async fn finish_run_requires_every_server_required_source_stream<
    H: GatewayConformanceHarness,
>() {
    let harness = start_harness::<H>().await;
    let repository = harness.repository();
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
    harness
        .register_join_grant(
            &coordinator_context,
            &runtime_context,
            opened.run_id().clone(),
            SourceKind::RuntimeWitness,
            "join_grant_01",
            1_783_894_800_000,
        )
        .await
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

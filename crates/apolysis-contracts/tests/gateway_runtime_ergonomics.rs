// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    AcceptedSourceEnvelope, AgentExecutionRecordFact, AgentExecutionRecordItem, BindRuntimeRequest,
    BindRuntimeResponse, ContractErrorCode, EnvelopeAck, EnvironmentKind, FinishRunRequest,
    FinishRunResponse, GatewayErrorResponse, GatewayOperation, IngestAck, IngestDisposition,
    IngestRequest, JoinProofKind, OpenRunMode, OpenRunOutcome, OpenRunRequest, OpenRunResponse,
    OrderingCapability, OrganizationId, PrincipalKind, PrincipalRef, RunId, RunLease, RunState,
    SchemaVersion, SequenceGap, SourceId, SourceKind, TerminalSourcePosition, TrustProfile,
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

fn run_id() -> RunId {
    RunId::try_from("run_01").expect("run id")
}

fn source_id(value: &str) -> SourceId {
    SourceId::try_from(value).expect("source id")
}

#[test]
fn open_run_exposes_common_and_mode_specific_runtime_inputs() {
    let create: OpenRunRequest = parse("positive/open_run_create_request.json");
    assert_eq!(create.mode(), OpenRunMode::Create);
    assert_eq!(create.schema_version(), SchemaVersion::V0_1);
    assert_eq!(create.client_operation_id(), "operation_open_01");
    assert_eq!(create.request_digest().len(), 64);
    assert_eq!(create.client_run_key(), Some("github_pr_42_attempt_1"));
    assert_eq!(
        create.environment(),
        Some(EnvironmentKind::CiRunnerOrRemoteWorkspace)
    );
    assert_eq!(create.authority().expect("authority").id(), "authority_ci");
    assert_eq!(
        create.principal().expect("principal").id(),
        "principal_runner"
    );
    assert_eq!(create.objective_ref(), Some("objective_sha256_012345"));
    assert_eq!(
        create.privacy_profile_ref(),
        Some("privacy_structure_only_v1")
    );
    assert_eq!(create.retention_profile_ref(), Some("retention_30d_v1"));
    assert_eq!(
        create.expected_source_kinds().expect("source kinds").len(),
        3
    );
    assert_eq!(
        create.source_manifest().source_kind(),
        SourceKind::SemanticHook
    );
    assert!(create.run_id().is_none());
    assert!(create.join_proof().is_none());

    let join: OpenRunRequest = parse("positive/open_run_join_request.json");
    assert_eq!(join.mode(), OpenRunMode::Join);
    assert_eq!(join.run_id().expect("join run").as_str(), "run_01");
    let proof = join.join_proof().expect("join proof");
    assert_eq!(proof.kind(), JoinProofKind::Grant);
    assert_eq!(proof.proof_ref(), "join_grant_01");
    assert_eq!(proof.run_id().as_str(), "run_01");
    assert_eq!(proof.source_id().as_str(), "source_runtime");
    assert_eq!(proof.expires_at_unix_ms(), 1_783_894_800_000);
    assert!(join.client_run_key().is_none());
}

#[test]
fn server_constructors_produce_valid_gateway_responses() {
    let lease = RunLease::new(
        "lease_01",
        1_783_894_800_000,
        vec![
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ],
    )
    .expect("valid lease");
    assert_eq!(lease.lease_id(), "lease_01");
    assert_eq!(lease.expires_at_unix_ms(), 1_783_894_800_000);

    let open = OpenRunResponse::new(
        run_id(),
        source_id("source_codex"),
        "stream_codex_01",
        OpenRunOutcome::Created,
        lease,
    )
    .expect("valid open response");
    assert_eq!(open.schema_version(), SchemaVersion::V0_1);
    assert_eq!(open.run_id().as_str(), "run_01");
    assert_eq!(open.source_id().as_str(), "source_codex");
    assert_eq!(open.source_stream_id(), "stream_codex_01");
    assert_eq!(open.outcome(), OpenRunOutcome::Created);

    let binding = BindRuntimeResponse::new(run_id(), "binding_pod_01", true, false)
        .expect("valid binding response");
    assert_eq!(binding.schema_version(), SchemaVersion::V0_1);
    assert_eq!(binding.run_id().as_str(), "run_01");
    assert_eq!(binding.binding_id(), "binding_pod_01");
    assert!(binding.accepted());
    assert!(!binding.idempotent_replay());

    let finishing = FinishRunResponse::new(
        run_id(),
        RunState::Finishing,
        Some(1_783_891_800_000),
        false,
    )
    .expect("valid finish response");
    assert_eq!(finishing.schema_version(), SchemaVersion::V0_1);
    assert_eq!(finishing.run_id().as_str(), "run_01");
    assert_eq!(finishing.state(), RunState::Finishing);
    assert_eq!(
        finishing.finalization_deadline_unix_ms(),
        Some(1_783_891_800_000)
    );
    assert!(!finishing.idempotent_replay());

    let error = GatewayErrorResponse::new(
        ContractErrorCode::Backpressure,
        "gateway capacity is temporarily unavailable",
        true,
        Some(250),
    )
    .expect("valid gateway error");
    assert_eq!(error.schema_version(), SchemaVersion::V0_1);
    assert_eq!(error.code(), ContractErrorCode::Backpressure);
    assert_eq!(
        error.message(),
        "gateway capacity is temporarily unavailable"
    );
    assert!(error.retryable());
    assert_eq!(error.retry_after_ms(), Some(250));
}

#[test]
fn runtime_requests_and_source_types_expose_policy_and_persistence_inputs() {
    let binding_request: BindRuntimeRequest = parse("positive/bind_runtime_request.json");
    assert_eq!(binding_request.schema_version(), SchemaVersion::V0_1);
    assert_eq!(binding_request.client_operation_id(), "operation_bind_01");
    assert_eq!(binding_request.request_digest().len(), 64);
    assert_eq!(binding_request.run_id().as_str(), "run_01");
    assert_eq!(binding_request.lease_id(), "lease_01");
    let binding = binding_request.binding();
    assert_eq!(binding.binding_id(), "binding_pod_01");
    assert_eq!(
        binding.identity_ref(),
        "cluster_a:namespace_default:pod_agent_01"
    );
    assert_eq!(binding.valid_from_unix_ms(), 1_783_891_200_000);
    assert_eq!(binding.valid_until_unix_ms(), Some(1_783_894_800_000));
    assert_eq!(binding.evidence_basis_ref(), "kubernetes_uid_readback_01");
    assert!(binding.reason_codes().is_empty());

    let ingest: IngestRequest = parse("positive/ingest_request.json");
    assert_eq!(ingest.schema_version(), SchemaVersion::V0_1);
    assert_eq!(ingest.client_operation_id(), "operation_ingest_01");
    assert_eq!(ingest.request_digest().len(), 64);
    assert_eq!(ingest.run_id().as_str(), "run_01");
    assert_eq!(ingest.lease_id(), "lease_01");
    let envelope = &ingest.envelopes()[0];
    assert_eq!(envelope.schema_version(), SchemaVersion::V0_1);
    assert_eq!(envelope.source_stream_id(), "stream_codex_01");
    assert_eq!(envelope.source_event_id(), "event_tool_01");
    assert_eq!(envelope.observed_at().unix_ms(), 1_783_891_200_000);
    assert_eq!(envelope.observed_at().uncertainty_ms(), Some(25));
    assert_eq!(
        envelope.correlation().trace_ref.as_deref(),
        Some("trace_01")
    );
    assert!(envelope.flags().redacted);
    assert_eq!(envelope.payload_type(), "tool_interaction");
    assert_eq!(envelope.payload_version(), "0.1");
    assert!(envelope.inline_payload().is_some());
    assert!(envelope.object_ref().is_none());

    let manifest = ingest.envelopes()[0].source_id();
    assert_eq!(manifest.as_str(), "source_codex");
    let create: OpenRunRequest = parse("positive/open_run_create_request.json");
    let manifest = create.source_manifest();
    assert_eq!(manifest.schema_version(), SchemaVersion::V0_1);
    assert_eq!(manifest.adapter_name(), "codex_hook");
    assert_eq!(manifest.adapter_version(), "1.0.0");
    assert_eq!(
        manifest.environment(),
        EnvironmentKind::CiRunnerOrRemoteWorkspace
    );
    assert_eq!(manifest.ordering(), OrderingCapability::StrictPerStream);
    assert!(!manifest.samples());
    assert_eq!(manifest.expected_lifecycle().len(), 2);
    assert_eq!(
        manifest.redaction_profile_ref(),
        "redaction_structure_only_v1"
    );
    assert_eq!(manifest.redacted_fields(), ["payload.command"]);
}

#[test]
fn ingest_and_record_constructors_preserve_validated_server_facts() {
    let committed =
        EnvelopeAck::new("event_tool_01", IngestDisposition::Committed, 42).expect("committed ack");
    let duplicate =
        EnvelopeAck::new("event_tool_03", IngestDisposition::Duplicate, 41).expect("duplicate ack");
    let gap = SequenceGap::new(2, 2).expect("sequence gap");
    let ack = IngestAck::new(run_id(), vec![committed, duplicate], 42, 3, vec![gap])
        .expect("valid ingest ack");
    assert_eq!(ack.schema_version(), SchemaVersion::V0_1);
    assert_eq!(ack.run_id().as_str(), "run_01");
    assert_eq!(ack.acknowledgements().len(), 2);
    assert_eq!(ack.acknowledgements()[0].source_event_id(), "event_tool_01");
    assert_eq!(
        ack.acknowledgements()[0].disposition(),
        IngestDisposition::Committed
    );
    assert_eq!(ack.acknowledgements()[0].ingest_sequence(), Some(42));
    assert_eq!(ack.source_watermark(), 3);

    let create: OpenRunRequest = parse("positive/open_run_create_request.json");
    let registered = apolysis_contracts::RegisteredSource::new(
        "registration_codex",
        "stream_codex_01",
        7,
        PrincipalRef::new(PrincipalKind::Workload, "principal_runner").expect("principal"),
        create.source_manifest().clone(),
        TrustProfile::HarnessObserved,
    )
    .expect("registered source");
    assert_eq!(
        registered.effective_trust_profile(),
        TrustProfile::HarnessObserved
    );
    assert_eq!(registered.source_registration_id(), "registration_codex");
    assert_eq!(registered.source_stream_id(), "stream_codex_01");
    assert_eq!(registered.registration_policy_revision(), 7);
    assert_eq!(registered.principal().id(), "principal_runner");

    let ingest: IngestRequest = parse("positive/ingest_request.json");
    let accepted = AcceptedSourceEnvelope::new(
        "registration_codex",
        "stream_codex_01",
        7,
        TrustProfile::HarnessObserved,
        SchemaVersion::V0_1,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ingest.envelopes()[0].clone(),
    )
    .expect("accepted source envelope");
    assert_eq!(accepted.source_registration_id(), "registration_codex");
    assert_eq!(accepted.source_stream_id(), "stream_codex_01");
    assert_eq!(accepted.registration_policy_revision(), 7);
    assert_eq!(accepted.manifest_version(), SchemaVersion::V0_1);
    assert_eq!(accepted.envelope().source_event_id(), "event_tool_01");

    let item = AgentExecutionRecordItem::new(
        OrganizationId::try_from("org_acme").expect("organization id"),
        run_id(),
        42,
        1_783_891_200_100,
        AgentExecutionRecordFact::EvidenceAccepted(Box::new(accepted)),
    )
    .expect("record item");
    assert_eq!(item.schema_version(), SchemaVersion::V0_1);
    assert_eq!(item.ingest_sequence(), 42);
    assert_eq!(item.ingested_at_unix_ms(), 1_783_891_200_100);
}

#[test]
fn terminal_position_and_finish_request_expose_finalization_inputs() {
    let position = TerminalSourcePosition::new(source_id("source_codex"), "stream_codex_01", 3)
        .expect("terminal position");
    assert_eq!(position.source_id().as_str(), "source_codex");
    assert_eq!(position.source_stream_id(), "stream_codex_01");
    assert_eq!(position.final_source_sequence(), 3);

    let finish: FinishRunRequest = parse("positive/finish_run_request.json");
    assert_eq!(finish.schema_version(), SchemaVersion::V0_1);
    assert_eq!(finish.client_operation_id(), "operation_finish_01");
    assert_eq!(finish.request_digest().len(), 64);
    assert_eq!(finish.run_id().as_str(), "run_01");
    assert_eq!(finish.lease_id(), "lease_01");
    assert_eq!(
        finish.terminal_positions()[0].source_id().as_str(),
        "source_codex"
    );
    assert_eq!(
        finish.requested_finalization_deadline_unix_ms(),
        Some(1_783_891_800_000)
    );
}

#[test]
fn server_constructors_reject_invalid_invariants() {
    assert!(RunLease::new("lease_01", 0, vec![GatewayOperation::Ingest]).is_err());
    assert!(EnvelopeAck::new("event_tool_01", IngestDisposition::Committed, 0).is_err());
    assert!(SequenceGap::new(3, 2).is_err());
    assert!(IngestAck::new(
        run_id(),
        vec![EnvelopeAck::new("event_tool_01", IngestDisposition::Committed, 42).expect("ack")],
        41,
        1,
        Vec::new(),
    )
    .is_err());
    assert!(FinishRunResponse::new(run_id(), RunState::Active, None, false).is_err());
    assert!(GatewayErrorResponse::new(
        ContractErrorCode::InvalidContract,
        "invalid request",
        false,
        Some(100),
    )
    .is_err());
    assert!(AgentExecutionRecordItem::new(
        OrganizationId::try_from("org_acme").expect("organization id"),
        run_id(),
        0,
        1,
        AgentExecutionRecordFact::RunStateChanged(
            apolysis_contracts::RunStateTransition::new(RunState::Opening, RunState::Active, 1,)
                .expect("transition"),
        ),
    )
    .is_err());
}

// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

use apolysis_contracts::{
    AcceptedRunFinalization, AcceptedRuntimeBinding, AcceptedSourceEnvelope,
    AgentExecutionRecordFact, AgentExecutionRecordItem, BindRuntimeRequest, BindRuntimeResponse,
    ContractErrorCode, EnvelopeAck, EnvironmentKind, FinishRunRequest, FinishRunResponse,
    GatewayOperation, IngestAck, IngestDisposition, IngestRequest, JoinProofKind, OpenRunOutcome,
    OpenRunRequest, OpenRunResponse, PrincipalKind, RegisteredSource, RunDescriptor, RunId,
    RunLease, RunPolicySelection, RunState, RunStateTransition, RuntimeAttribution,
    RuntimeIdentityKind, SequenceGap, SourceCapability, SourceId, SourceKind, SourceManifest,
    TerminalSourcePosition, TrustProfile,
};

use crate::{
    digest::{
        canonical_runtime_binding_digest, canonical_source_envelope_digest,
        canonical_source_manifest_digest,
    },
    lease_id_digest, AuditReason, GatewayFailure, GatewayIdGenerator, GatewayRepository,
    LedgerCommand, LedgerOperation, LedgerOutcome, RepositoryFuture, MAX_SOURCE_STREAMS_PER_RUN,
};

/// Non-durable reference adapter used by the shared Gateway conformance suite.
/// Production durability claims require the PostgreSQL adapter and its gates.
#[derive(Clone, Default)]
pub struct MemoryGatewayRepository {
    state: Arc<Mutex<State>>,
}

#[derive(Clone, Default)]
struct State {
    operations: HashMap<OperationKey, StoredOperation>,
    client_runs: HashMap<ClientRunKey, RunId>,
    runs: HashMap<RunKey, RunRecord>,
    streams: HashMap<StreamKey, StreamRecord>,
    leases: HashMap<LeaseKey, LeaseRecord>,
    events: HashMap<EventKey, StoredEnvelope>,
    bindings: HashMap<BindingKey, StoredBinding>,
    exact_runtime_identities: HashMap<RuntimeIdentityKey, RunId>,
    join_grants: HashMap<JoinGrantKey, JoinGrantRecord>,
    next_ingest_sequences: HashMap<String, u64>,
    ledger: Vec<AgentExecutionRecordItem>,
    projection_outbox: Vec<(String, RunId, u64)>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OperationKey {
    organization_id: String,
    source_registration_id: String,
    principal_kind: PrincipalKind,
    principal_id: String,
    operation: &'static str,
    client_operation_id: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ClientRunKey {
    organization_id: String,
    principal_kind: PrincipalKind,
    principal_id: String,
    client_run_key: String,
}

#[derive(Clone)]
struct StoredOperation {
    request_digest: String,
    outcome: LedgerOutcome,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RunKey {
    organization_id: String,
    run_id: String,
}

#[derive(Clone)]
struct RunRecord {
    state: RunState,
    environment: EnvironmentKind,
    initiating_source_registration_id: String,
    initiating_principal_kind: PrincipalKind,
    initiating_principal_id: String,
    expected_source_kinds: Vec<SourceKind>,
    finalization_deadline_unix_ms: Option<u64>,
    declared_terminal_positions: BTreeMap<String, DeclaredTerminalPosition>,
    declared_outcome_claim_refs: BTreeSet<String>,
}

#[derive(Clone)]
struct DeclaredTerminalPosition {
    source_id: SourceId,
    final_source_sequence: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StreamKey {
    organization_id: String,
    run_id: String,
    source_registration_id: String,
    source_stream_id: String,
}

#[derive(Clone)]
struct StreamRecord {
    source_id: SourceId,
    manifest: SourceManifest,
    effective_trust_profile: TrustProfile,
    registration_policy_revision: u64,
    sequences: BTreeMap<u64, String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LeaseKey {
    organization_id: String,
    lease_digest: String,
}

#[derive(Clone)]
struct LeaseRecord {
    run_id: RunId,
    source_registration_id: String,
    principal_kind: PrincipalKind,
    principal_id: String,
    registration_policy_revision: u64,
    source_id: SourceId,
    source_stream_id: String,
    expires_at_unix_ms: u64,
    allowed_operations: Vec<GatewayOperation>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EventKey {
    organization_id: String,
    run_id: String,
    source_registration_id: String,
    source_stream_id: String,
    source_event_id: String,
}

#[derive(Clone)]
struct StoredEnvelope {
    digest: String,
    source_sequence: u64,
    ingest_sequence: u64,
    accepted: AcceptedSourceEnvelope,
}

/// Content-free inspection metrics for the non-durable reference adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryGatewaySnapshot {
    record_item_count: usize,
    projection_outbox_count: usize,
    evidence_event_count: usize,
    finalization_declaration_count: usize,
    accepted_effective_trust_profiles: Vec<TrustProfile>,
}

impl MemoryGatewaySnapshot {
    pub fn record_item_count(&self) -> usize {
        self.record_item_count
    }

    pub fn projection_outbox_count(&self) -> usize {
        self.projection_outbox_count
    }

    pub fn evidence_event_count(&self) -> usize {
        self.evidence_event_count
    }

    pub fn finalization_declaration_count(&self) -> usize {
        self.finalization_declaration_count
    }

    /// Return only the trust classifications assigned to accepted evidence.
    pub fn accepted_effective_trust_profiles(&self) -> &[TrustProfile] {
        &self.accepted_effective_trust_profiles
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BindingKey {
    organization_id: String,
    run_id: String,
    binding_id: String,
}

#[derive(Clone)]
struct StoredBinding {
    digest: String,
    accepted: AcceptedRuntimeBinding,
    response: BindRuntimeResponse,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RuntimeIdentityKey {
    organization_id: String,
    identity_kind: String,
    identity_ref: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct JoinGrantKey {
    organization_id: String,
    proof_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JoinGrantRecord {
    kind: JoinProofKind,
    run_id: RunId,
    source_id: SourceId,
    source_kind: SourceKind,
    environment: EnvironmentKind,
    source_registration_id: String,
    principal_kind: PrincipalKind,
    principal_id: String,
    registration_policy_revision: u64,
    expires_at_unix_ms: u64,
    status: JoinGrantStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JoinGrantStatus {
    Pending,
    Consumed,
}

struct JoinAuthorizationSpec {
    kind: JoinProofKind,
    run_id: RunId,
    source_kind: SourceKind,
    proof_ref: String,
    expires_at_unix_ms: u64,
}

impl MemoryGatewayRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Result<MemoryGatewaySnapshot, GatewayFailure> {
        let state = self.state.lock().map_err(|_| repository_invariant())?;
        let evidence_event_count = state
            .events
            .values()
            .filter(|stored| stored.accepted.envelope().source_sequence() == stored.source_sequence)
            .count();
        let accepted_effective_trust_profiles = state
            .ledger
            .iter()
            .filter_map(|item| match item.fact() {
                AgentExecutionRecordFact::EvidenceAccepted(accepted) => {
                    Some(accepted.effective_trust_profile())
                }
                _ => None,
            })
            .collect();
        let finalization_declaration_count = state
            .ledger
            .iter()
            .filter(|item| {
                matches!(
                    item.fact(),
                    AgentExecutionRecordFact::RunFinalizationDeclared(_)
                )
            })
            .count();
        Ok(MemoryGatewaySnapshot {
            record_item_count: state.ledger.len(),
            projection_outbox_count: state.projection_outbox.len(),
            evidence_event_count,
            finalization_declaration_count,
            accepted_effective_trust_profiles,
        })
    }

    /// Seed a one-use, identity-bound join grant in the reference adapter.
    ///
    /// Production adapters are expected to resolve grants from their trusted
    /// control-plane store; request bytes alone never authorize a join.
    pub fn register_join_grant(
        &self,
        issuer: &apolysis_contracts::AuthenticatedSourceContext,
        joining_source: &apolysis_contracts::AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: impl Into<String>,
        expires_at_unix_ms: u64,
    ) -> Result<(), GatewayFailure> {
        self.register_join_authorization(
            issuer,
            joining_source,
            JoinAuthorizationSpec {
                kind: JoinProofKind::Grant,
                run_id,
                source_kind,
                proof_ref: proof_ref.into(),
                expires_at_unix_ms,
            },
        )
    }

    /// Seed a reusable, identity-bound registration policy in the reference adapter.
    ///
    /// Unlike a grant, a registration policy remains usable until its fixed
    /// expiry so a registered source can establish a replacement stream after
    /// a restart. It is still scoped to one organization, run, source, and
    /// authenticated principal.
    pub fn register_join_policy(
        &self,
        issuer: &apolysis_contracts::AuthenticatedSourceContext,
        joining_source: &apolysis_contracts::AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: impl Into<String>,
        expires_at_unix_ms: u64,
    ) -> Result<(), GatewayFailure> {
        self.register_join_authorization(
            issuer,
            joining_source,
            JoinAuthorizationSpec {
                kind: JoinProofKind::RegistrationPolicy,
                run_id,
                source_kind,
                proof_ref: proof_ref.into(),
                expires_at_unix_ms,
            },
        )
    }

    fn register_join_authorization(
        &self,
        issuer: &apolysis_contracts::AuthenticatedSourceContext,
        joining_source: &apolysis_contracts::AuthenticatedSourceContext,
        spec: JoinAuthorizationSpec,
    ) -> Result<(), GatewayFailure> {
        if spec.proof_ref.is_empty()
            || spec.proof_ref.len() > 512
            || spec.proof_ref.chars().any(char::is_control)
            || spec.expires_at_unix_ms == 0
            || spec.expires_at_unix_ms <= issuer.authentication().authenticated_at_unix_ms()
        {
            return Err(GatewayFailure::new(
                ContractErrorCode::InvalidContract,
                "Join grant is invalid",
                AuditReason::RepositoryInvariant,
            ));
        }
        let mut committed_state = self.state.lock().map_err(|_| repository_invariant())?;
        let mut state = committed_state.clone();
        if issuer.organization_id() != joining_source.organization_id() {
            return Err(join_forbidden());
        }
        let run = state
            .runs
            .get(&RunKey {
                organization_id: issuer.organization_id().to_string(),
                run_id: spec.run_id.to_string(),
            })
            .cloned()
            .ok_or_else(not_found)?;
        if run.initiating_source_registration_id != issuer.source_registration_id()
            || run.initiating_principal_kind != issuer.principal().kind()
            || run.initiating_principal_id != issuer.principal().id()
            || !joining_source
                .registration_policy()
                .allowed_source_kinds()
                .contains(&spec.source_kind)
        {
            return Err(join_forbidden());
        }
        if matches!(run.state, RunState::Finished | RunState::Incomplete) {
            return Err(GatewayFailure::new(
                ContractErrorCode::InvalidLifecycleTransition,
                "Run is already sealed",
                AuditReason::RepositoryInvariant,
            ));
        }
        let key = JoinGrantKey {
            organization_id: issuer.organization_id().to_string(),
            proof_ref: spec.proof_ref,
        };
        let grant = JoinGrantRecord {
            kind: spec.kind,
            run_id: spec.run_id,
            source_id: joining_source.registration_policy().source_id().clone(),
            source_kind: spec.source_kind,
            environment: run.environment,
            source_registration_id: joining_source.source_registration_id().to_string(),
            principal_kind: joining_source.principal().kind(),
            principal_id: joining_source.principal().id().to_string(),
            registration_policy_revision: joining_source.authentication().policy_revision(),
            expires_at_unix_ms: spec.expires_at_unix_ms,
            status: JoinGrantStatus::Pending,
        };
        if let Some(existing) = state.join_grants.get(&key) {
            if existing == &grant && existing.status == JoinGrantStatus::Pending {
                return Ok(());
            }
            return Err(GatewayFailure::new(
                ContractErrorCode::IdempotencyConflict,
                "Join grant identity is already in use",
                AuditReason::IdempotencyConflict,
            ));
        }
        state.join_grants.insert(key, grant);
        *committed_state = state;
        Ok(())
    }

    fn open_run(
        &self,
        context: apolysis_contracts::AuthenticatedSourceContext,
        request: OpenRunRequest,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
        ids: &dyn GatewayIdGenerator,
    ) -> Result<OpenRunResponse, GatewayFailure> {
        let operation_key = OperationKey {
            organization_id: context.organization_id().to_string(),
            source_registration_id: context.source_registration_id().to_string(),
            principal_kind: context.principal().kind(),
            principal_id: context.principal().id().to_string(),
            operation: "open_run",
            client_operation_id: request.client_operation_id().to_string(),
        };
        let mut committed_state = self.state.lock().map_err(|_| repository_invariant())?;
        let mut state = committed_state.clone();
        if let Some(stored) = state.operations.get(&operation_key) {
            if stored.request_digest != request.request_digest() {
                return Err(GatewayFailure::new(
                    ContractErrorCode::IdempotencyConflict,
                    "Operation identity was reused with different content",
                    AuditReason::IdempotencyConflict,
                ));
            }
            let LedgerOutcome::OpenRun(original) = &stored.outcome else {
                return Err(repository_invariant());
            };
            return OpenRunResponse::new(
                original.run_id().clone(),
                original.source_id().clone(),
                original.source_stream_id(),
                OpenRunOutcome::IdempotentRetry,
                original.lease().clone(),
            )
            .map_err(contract_invariant);
        }

        let (
            run_id,
            source_stream_id,
            source_manifest,
            outcome,
            allowed_operations,
            created_run,
            consumed_join_grant,
            run_finalization_deadline_unix_ms,
        ) = match &request {
            OpenRunRequest::Create {
                client_run_key,
                environment,
                expected_source_kinds,
                source_manifest,
                ..
            } => {
                let client_run_key = ClientRunKey {
                    organization_id: context.organization_id().to_string(),
                    principal_kind: context.principal().kind(),
                    principal_id: context.principal().id().to_string(),
                    client_run_key: client_run_key.clone(),
                };
                if state.client_runs.contains_key(&client_run_key) {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::IdempotencyConflict,
                        "Client run identity is already in use",
                        AuditReason::ClientRunKeyConflict,
                    ));
                }
                let run_id = RunId::try_from(next_id(ids, "run")?).map_err(contract_invariant)?;
                let source_stream_id = next_id(ids, "stream")?;
                let run_record = (
                    RunKey {
                        organization_id: context.organization_id().to_string(),
                        run_id: run_id.to_string(),
                    },
                    RunRecord {
                        state: RunState::Active,
                        environment: *environment,
                        initiating_source_registration_id: context
                            .source_registration_id()
                            .to_string(),
                        initiating_principal_kind: context.principal().kind(),
                        initiating_principal_id: context.principal().id().to_string(),
                        expected_source_kinds: expected_source_kinds.clone(),
                        finalization_deadline_unix_ms: None,
                        declared_terminal_positions: BTreeMap::new(),
                        declared_outcome_claim_refs: BTreeSet::new(),
                    },
                );
                (
                    run_id,
                    source_stream_id,
                    source_manifest.clone(),
                    OpenRunOutcome::Created,
                    context.registration_policy().allowed_operations().to_vec(),
                    Some((client_run_key, run_record)),
                    None,
                    None,
                )
            }
            OpenRunRequest::Join {
                run_id,
                join_proof,
                source_manifest,
                ..
            } => {
                let run = state
                    .runs
                    .get(&RunKey {
                        organization_id: context.organization_id().to_string(),
                        run_id: run_id.to_string(),
                    })
                    .cloned()
                    .ok_or_else(not_found)?;
                let grant_key = JoinGrantKey {
                    organization_id: context.organization_id().to_string(),
                    proof_ref: join_proof.proof_ref().to_string(),
                };
                let grant = state
                    .join_grants
                    .get(&grant_key)
                    .cloned()
                    .ok_or_else(unauthorized_join_not_found)?;
                if join_proof.kind() != grant.kind
                    || grant.run_id != *run_id
                    || grant.source_id != *source_manifest.source_id()
                    || grant.source_kind != source_manifest.source_kind()
                    || grant.environment != source_manifest.environment()
                    || grant.source_registration_id != context.source_registration_id()
                    || grant.principal_kind != context.principal().kind()
                    || grant.principal_id != context.principal().id()
                    || grant.registration_policy_revision
                        != context.authentication().policy_revision()
                    || grant.expires_at_unix_ms != join_proof.expires_at_unix_ms()
                    || now_unix_ms >= grant.expires_at_unix_ms
                    || grant.status != JoinGrantStatus::Pending
                {
                    return Err(unauthorized_join_not_found());
                }
                if reconcile_expired_run(&mut state, &context, run_id, now_unix_ms)?.is_some() {
                    *committed_state = state;
                    return Err(GatewayFailure::new(
                        ContractErrorCode::InvalidLifecycleTransition,
                        "Run is already sealed",
                        AuditReason::RepositoryInvariant,
                    ));
                }
                if matches!(run.state, RunState::Finished | RunState::Incomplete) {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::InvalidLifecycleTransition,
                        "Run is already sealed",
                        AuditReason::RepositoryInvariant,
                    ));
                }
                let stream_count = state
                    .streams
                    .keys()
                    .filter(|key| {
                        key.organization_id == context.organization_id().as_str()
                            && key.run_id == run_id.as_str()
                    })
                    .count();
                if stream_count >= MAX_SOURCE_STREAMS_PER_RUN {
                    return Err(GatewayFailure::admission_limit(AuditReason::AdmissionLimit));
                }
                let run_finalization_deadline_unix_ms = if run.state == RunState::Finishing {
                    let deadline = run
                        .finalization_deadline_unix_ms
                        .ok_or_else(repository_invariant)?;
                    if now_unix_ms >= deadline {
                        return Err(GatewayFailure::new(
                            ContractErrorCode::InvalidLifecycleTransition,
                            "Run finalization deadline has elapsed",
                            AuditReason::RepositoryInvariant,
                        ));
                    }
                    Some(deadline)
                } else {
                    None
                };
                let source_stream_id = next_id(ids, "stream")?;
                let allowed_operations = context
                    .registration_policy()
                    .allowed_operations()
                    .iter()
                    .copied()
                    .filter(|operation| {
                        *operation != GatewayOperation::FinishRun
                            || context.registration_policy().may_finalize_runs()
                    })
                    .collect();
                (
                    run_id.clone(),
                    source_stream_id,
                    source_manifest.clone(),
                    OpenRunOutcome::Joined,
                    allowed_operations,
                    None,
                    (grant.kind == JoinProofKind::Grant).then_some(grant_key),
                    run_finalization_deadline_unix_ms,
                )
            }
        };
        let lease_expires_at_unix_ms = run_finalization_deadline_unix_ms
            .map(|deadline| lease_expires_at_unix_ms.min(deadline))
            .unwrap_or(lease_expires_at_unix_ms);
        let lease_id = next_id(ids, "lease")?;
        let lease = RunLease::new(
            lease_id.clone(),
            lease_expires_at_unix_ms,
            allowed_operations.clone(),
        )
        .map_err(contract_invariant)?;
        let stream_key = StreamKey {
            organization_id: context.organization_id().to_string(),
            run_id: run_id.to_string(),
            source_registration_id: context.source_registration_id().to_string(),
            source_stream_id: source_stream_id.clone(),
        };
        let lease_key = LeaseKey {
            organization_id: context.organization_id().to_string(),
            lease_digest: lease_id_digest(&lease_id),
        };
        if created_run
            .as_ref()
            .is_some_and(|(_, (run_key, _))| state.runs.contains_key(run_key))
            || state.streams.keys().any(|existing| {
                existing.organization_id == stream_key.organization_id
                    && existing.run_id == stream_key.run_id
                    && existing.source_stream_id == stream_key.source_stream_id
            })
            || state.leases.contains_key(&lease_key)
        {
            return Err(GatewayFailure::repository_backpressure(
                250,
                AuditReason::EntropyUnavailable,
            ));
        }
        let response = OpenRunResponse::new(
            run_id.clone(),
            context.registration_policy().source_id().clone(),
            source_stream_id.clone(),
            outcome,
            lease,
        )
        .map_err(contract_invariant)?;
        if let OpenRunRequest::Create {
            authority,
            principal,
            objective_ref,
            environment,
            privacy_profile_ref,
            retention_profile_ref,
            expected_source_kinds,
            ..
        } = &request
        {
            let policy = RunPolicySelection::new(
                privacy_profile_ref,
                retention_profile_ref,
                expected_source_kinds.clone(),
            )
            .map_err(contract_invariant)?;
            let descriptor = RunDescriptor::new(
                context.organization_id().as_str(),
                run_id.as_str(),
                authority.clone(),
                principal.clone(),
                objective_ref,
                *environment,
                policy,
            )
            .map_err(contract_invariant)?;
            append_record_fact(
                &mut state,
                &context,
                &run_id,
                now_unix_ms,
                AgentExecutionRecordFact::RunOpened(Box::new(descriptor)),
            )?;
            append_record_fact(
                &mut state,
                &context,
                &run_id,
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(RunState::Opening, RunState::Active, now_unix_ms)
                        .map_err(contract_invariant)?,
                ),
            )?;
        }
        let registered = RegisteredSource::new(
            context.source_registration_id(),
            source_stream_id.as_str(),
            context.authentication().policy_revision(),
            context.principal().clone(),
            source_manifest.clone(),
            context.registration_policy().effective_trust_profile(),
        )
        .map_err(contract_invariant)?;
        append_record_fact(
            &mut state,
            &context,
            &run_id,
            now_unix_ms,
            AgentExecutionRecordFact::SourceRegistered(Box::new(registered)),
        )?;
        if let Some((client_run_key, (run_key, run_record))) = created_run {
            state.client_runs.insert(client_run_key, run_id.clone());
            state.runs.insert(run_key, run_record);
        }
        if let Some(grant_key) = consumed_join_grant {
            let grant = state
                .join_grants
                .get_mut(&grant_key)
                .ok_or_else(repository_invariant)?;
            grant.status = JoinGrantStatus::Consumed;
        }
        state.streams.insert(
            stream_key,
            StreamRecord {
                source_id: source_manifest.source_id().clone(),
                manifest: source_manifest.clone(),
                effective_trust_profile: context.registration_policy().effective_trust_profile(),
                registration_policy_revision: context.authentication().policy_revision(),
                sequences: BTreeMap::new(),
            },
        );
        state.leases.insert(
            lease_key,
            LeaseRecord {
                run_id,
                source_registration_id: context.source_registration_id().to_string(),
                principal_kind: context.principal().kind(),
                principal_id: context.principal().id().to_string(),
                registration_policy_revision: context.authentication().policy_revision(),
                source_id: source_manifest.source_id().clone(),
                source_stream_id,
                expires_at_unix_ms: lease_expires_at_unix_ms,
                allowed_operations,
            },
        );
        state.operations.insert(
            operation_key,
            StoredOperation {
                request_digest: request.request_digest().to_string(),
                outcome: LedgerOutcome::OpenRun(response.clone()),
            },
        );
        *committed_state = state;
        Ok(response)
    }

    fn ingest(
        &self,
        context: apolysis_contracts::AuthenticatedSourceContext,
        request: IngestRequest,
        now_unix_ms: u64,
    ) -> Result<IngestAck, GatewayFailure> {
        let mut committed_state = self.state.lock().map_err(|_| repository_invariant())?;
        let mut state = committed_state.clone();
        let operation_key = OperationKey {
            organization_id: context.organization_id().to_string(),
            source_registration_id: context.source_registration_id().to_string(),
            principal_kind: context.principal().kind(),
            principal_id: context.principal().id().to_string(),
            operation: "ingest",
            client_operation_id: request.client_operation_id().to_string(),
        };
        if let Some(stored) = state.operations.get(&operation_key) {
            if stored.request_digest != request.request_digest() {
                return Err(GatewayFailure::new(
                    ContractErrorCode::IdempotencyConflict,
                    "Operation identity was reused with different content",
                    AuditReason::IdempotencyConflict,
                ));
            }
            let LedgerOutcome::Ingest(acknowledgement) = &stored.outcome else {
                return Err(repository_invariant());
            };
            return Ok(acknowledgement.clone());
        }
        let lease = scoped_lease(&state, &context, request.run_id(), request.lease_id())?;
        if lease.registration_policy_revision != context.authentication().policy_revision() {
            return Err(lease_scope_failure(ContractErrorCode::LeaseRevoked));
        }
        if lease.run_id != *request.run_id()
            || lease.source_registration_id != context.source_registration_id()
            || lease.principal_kind != context.principal().kind()
            || lease.principal_id != context.principal().id()
            || !lease.allowed_operations.contains(&GatewayOperation::Ingest)
        {
            return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
        }
        let requested_lease_expired = now_unix_ms >= lease.expires_at_unix_ms;
        if reconcile_expired_run(&mut state, &context, request.run_id(), now_unix_ms)?.is_some() {
            *committed_state = state;
            return Err(if requested_lease_expired {
                lease_scope_failure(ContractErrorCode::LeaseExpired)
            } else {
                GatewayFailure::new(
                    ContractErrorCode::InvalidLifecycleTransition,
                    "Run is already sealed",
                    AuditReason::RepositoryInvariant,
                )
            });
        }
        if requested_lease_expired {
            return Err(lease_scope_failure(ContractErrorCode::LeaseExpired));
        }

        let run_key = RunKey {
            organization_id: context.organization_id().to_string(),
            run_id: request.run_id().to_string(),
        };
        let run = state.runs.get(&run_key).cloned().ok_or_else(not_found)?;
        let stream_key = StreamKey {
            organization_id: context.organization_id().to_string(),
            run_id: request.run_id().to_string(),
            source_registration_id: context.source_registration_id().to_string(),
            source_stream_id: lease.source_stream_id.clone(),
        };
        let stream = state
            .streams
            .get(&stream_key)
            .cloned()
            .ok_or_else(|| lease_scope_failure(ContractErrorCode::LeaseScopeMismatch))?;
        let manifest_digest = canonical_source_manifest_digest(&stream.manifest)
            .map_err(|_| repository_invariant())?;

        let mut classified = Vec::with_capacity(request.envelopes().len());
        let mut batch_events = BTreeMap::new();
        let mut batch_sequences = stream.sequences.clone();
        for envelope in request.envelopes() {
            if envelope.run_id() != request.run_id() {
                return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
            }
            if envelope.source_id() != &lease.source_id
                || envelope.source_stream_id() != lease.source_stream_id
            {
                return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
            }
            if run.state == RunState::Finishing
                && run
                    .declared_terminal_positions
                    .get(envelope.source_stream_id())
                    .is_some_and(|position| {
                        envelope.source_sequence() > position.final_source_sequence
                    })
            {
                return Err(GatewayFailure::new(
                    ContractErrorCode::InvalidLifecycleTransition,
                    "Evidence exceeds the declared terminal source position",
                    AuditReason::RepositoryInvariant,
                ));
            }
            let required_capability = envelope
                .inline_payload()
                .map(|payload| payload.required_source_capability())
                .ok_or_else(|| {
                    GatewayFailure::new(
                        ContractErrorCode::ContentNotAuthorized,
                        "Evidence object requires an authorized persistence adapter",
                        AuditReason::SourcePolicyMismatch,
                    )
                })?;
            if !stream
                .manifest
                .capabilities()
                .contains(&required_capability)
            {
                return Err(GatewayFailure::new(
                    ContractErrorCode::CapabilityMismatch,
                    "Evidence payload exceeds the source manifest capability",
                    AuditReason::SourcePolicyMismatch,
                ));
            }
            let digest =
                canonical_source_envelope_digest(envelope).map_err(|_| repository_invariant())?;
            if let Some((prior_sequence, prior_digest)) =
                batch_events.get(envelope.source_event_id())
            {
                if *prior_sequence != envelope.source_sequence() || prior_digest != &digest {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::SourceEventConflict,
                        "Source event identity was reused with different content",
                        AuditReason::IdempotencyConflict,
                    ));
                }
                continue;
            }
            batch_events.insert(
                envelope.source_event_id().to_string(),
                (envelope.source_sequence(), digest.clone()),
            );
            let event_key = EventKey {
                organization_id: context.organization_id().to_string(),
                run_id: request.run_id().to_string(),
                source_registration_id: context.source_registration_id().to_string(),
                source_stream_id: lease.source_stream_id.clone(),
                source_event_id: envelope.source_event_id().to_string(),
            };
            if let Some(existing) = state.events.get(&event_key) {
                if existing.digest != digest
                    || existing.source_sequence != envelope.source_sequence()
                {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::SourceEventConflict,
                        "Source event identity was reused with different content",
                        AuditReason::IdempotencyConflict,
                    ));
                }
                classified.push((
                    event_key,
                    digest,
                    IngestDisposition::Duplicate,
                    existing.ingest_sequence,
                    envelope.clone(),
                ));
                continue;
            }
            if let Some(existing_event_id) = batch_sequences.get(&envelope.source_sequence()) {
                if existing_event_id != envelope.source_event_id() {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::SequenceConflict,
                        "Source sequence is already assigned to another event",
                        AuditReason::IdempotencyConflict,
                    ));
                }
            }
            batch_sequences.insert(
                envelope.source_sequence(),
                envelope.source_event_id().to_string(),
            );
            classified.push((
                event_key,
                digest,
                IngestDisposition::Committed,
                0,
                envelope.clone(),
            ));
        }

        if matches!(run.state, RunState::Finished | RunState::Incomplete)
            && classified
                .iter()
                .any(|(_, _, disposition, _, _)| *disposition == IngestDisposition::Committed)
        {
            return Err(GatewayFailure::new(
                ContractErrorCode::InvalidLifecycleTransition,
                "Run is sealed or its finalization deadline elapsed",
                AuditReason::RepositoryInvariant,
            ));
        }

        let organization_id = context.organization_id().to_string();
        let mut acknowledgements = Vec::with_capacity(classified.len());
        let mut committed_count = 0_u32;
        let mut duplicate_count = 0_u32;
        for (event_key, digest, disposition, prior_ingest_sequence, envelope) in classified {
            let ingest_sequence = match disposition {
                IngestDisposition::Committed => {
                    let accepted = AcceptedSourceEnvelope::new(
                        context.source_registration_id(),
                        lease.source_stream_id.as_str(),
                        stream.registration_policy_revision,
                        stream.effective_trust_profile,
                        stream.manifest.schema_version(),
                        manifest_digest.clone(),
                        envelope.clone(),
                    )
                    .map_err(contract_invariant)?;
                    let assigned_sequence = append_record_fact(
                        &mut state,
                        &context,
                        request.run_id(),
                        now_unix_ms,
                        AgentExecutionRecordFact::EvidenceAccepted(Box::new(accepted.clone())),
                    )?;
                    committed_count += 1;
                    state.events.insert(
                        event_key,
                        StoredEnvelope {
                            digest,
                            source_sequence: envelope.source_sequence(),
                            ingest_sequence: assigned_sequence,
                            accepted,
                        },
                    );
                    assigned_sequence
                }
                IngestDisposition::Duplicate => {
                    duplicate_count += 1;
                    prior_ingest_sequence
                }
            };
            acknowledgements.push(
                EnvelopeAck::new(envelope.source_event_id(), disposition, ingest_sequence)
                    .map_err(contract_invariant)?,
            );
        }
        let stream = state
            .streams
            .get_mut(&stream_key)
            .ok_or_else(repository_invariant)?;
        stream.sequences = batch_sequences;
        let source_watermark = stream
            .sequences
            .keys()
            .next_back()
            .copied()
            .unwrap_or_default();
        let known_gaps = sequence_gaps(&stream.sequences)?;
        let durable_ingest_watermark = state
            .next_ingest_sequences
            .get(&organization_id)
            .copied()
            .unwrap_or_default();
        let acknowledgement = IngestAck::new(
            request.run_id().clone(),
            acknowledgements,
            durable_ingest_watermark,
            source_watermark,
            known_gaps,
        )
        .map_err(contract_invariant)?;
        if acknowledgement.committed_count() != committed_count
            || acknowledgement.duplicate_count() != duplicate_count
        {
            return Err(repository_invariant());
        }
        state.operations.insert(
            operation_key,
            StoredOperation {
                request_digest: request.request_digest().to_string(),
                outcome: LedgerOutcome::Ingest(acknowledgement.clone()),
            },
        );
        *committed_state = state;
        Ok(acknowledgement)
    }

    fn bind_runtime(
        &self,
        context: apolysis_contracts::AuthenticatedSourceContext,
        request: BindRuntimeRequest,
        now_unix_ms: u64,
    ) -> Result<BindRuntimeResponse, GatewayFailure> {
        let mut committed_state = self.state.lock().map_err(|_| repository_invariant())?;
        let mut state = committed_state.clone();
        let operation_key = OperationKey {
            organization_id: context.organization_id().to_string(),
            source_registration_id: context.source_registration_id().to_string(),
            principal_kind: context.principal().kind(),
            principal_id: context.principal().id().to_string(),
            operation: "bind_runtime",
            client_operation_id: request.client_operation_id().to_string(),
        };
        if let Some(stored) = state.operations.get(&operation_key) {
            if stored.request_digest != request.request_digest() {
                return Err(GatewayFailure::new(
                    ContractErrorCode::IdempotencyConflict,
                    "Operation identity was reused with different content",
                    AuditReason::IdempotencyConflict,
                ));
            }
            let LedgerOutcome::BindRuntime(original) = &stored.outcome else {
                return Err(repository_invariant());
            };
            return BindRuntimeResponse::new(
                original.run_id().clone(),
                original.binding_id(),
                original.accepted(),
                true,
            )
            .map_err(contract_invariant);
        }
        let lease = scoped_lease(&state, &context, request.run_id(), request.lease_id())?;
        if lease.registration_policy_revision != context.authentication().policy_revision() {
            return Err(lease_scope_failure(ContractErrorCode::LeaseRevoked));
        }
        if lease.run_id != *request.run_id()
            || lease.source_registration_id != context.source_registration_id()
            || lease.principal_kind != context.principal().kind()
            || lease.principal_id != context.principal().id()
            || lease.source_id != *request.binding().asserting_source_id()
            || !lease
                .allowed_operations
                .contains(&GatewayOperation::BindRuntime)
        {
            return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
        }
        let requested_lease_expired = now_unix_ms >= lease.expires_at_unix_ms;
        if reconcile_expired_run(&mut state, &context, request.run_id(), now_unix_ms)?.is_some() {
            *committed_state = state;
            return Err(if requested_lease_expired {
                lease_scope_failure(ContractErrorCode::LeaseExpired)
            } else {
                GatewayFailure::new(
                    ContractErrorCode::InvalidLifecycleTransition,
                    "Run is already sealed",
                    AuditReason::RepositoryInvariant,
                )
            });
        }
        if requested_lease_expired {
            return Err(lease_scope_failure(ContractErrorCode::LeaseExpired));
        }
        let run_key = RunKey {
            organization_id: context.organization_id().to_string(),
            run_id: request.run_id().to_string(),
        };
        let run = state.runs.get(&run_key).cloned().ok_or_else(not_found)?;
        if run.state != RunState::Active {
            return Err(GatewayFailure::new(
                ContractErrorCode::InvalidLifecycleTransition,
                "Runtime binding is not valid in the current run state",
                AuditReason::RepositoryInvariant,
            ));
        }
        let stream = state
            .streams
            .get(&StreamKey {
                organization_id: context.organization_id().to_string(),
                run_id: request.run_id().to_string(),
                source_registration_id: context.source_registration_id().to_string(),
                source_stream_id: lease.source_stream_id.clone(),
            })
            .cloned()
            .ok_or_else(|| lease_scope_failure(ContractErrorCode::LeaseScopeMismatch))?;
        if stream.source_id != lease.source_id {
            return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
        }
        let required_capability = match request.binding().identity_kind() {
            RuntimeIdentityKind::Process => SourceCapability::Process,
            RuntimeIdentityKind::Cgroup
            | RuntimeIdentityKind::Container
            | RuntimeIdentityKind::Pod
            | RuntimeIdentityKind::Vm
            | RuntimeIdentityKind::Runner
            | RuntimeIdentityKind::ProviderWorkload => SourceCapability::Workload,
        };
        if !stream
            .manifest
            .capabilities()
            .contains(&required_capability)
        {
            return Err(GatewayFailure::new(
                ContractErrorCode::CapabilityMismatch,
                "Runtime binding exceeds the source manifest capability",
                AuditReason::SourcePolicyMismatch,
            ));
        }
        let manifest_digest = canonical_source_manifest_digest(&stream.manifest)
            .map_err(|_| repository_invariant())?;

        let binding_key = BindingKey {
            organization_id: context.organization_id().to_string(),
            run_id: request.run_id().to_string(),
            binding_id: request.binding().binding_id().to_string(),
        };
        let binding_digest = canonical_runtime_binding_digest(request.binding())
            .map_err(|_| repository_invariant())?;
        if let Some(existing) = state.bindings.get(&binding_key).cloned() {
            if existing.accepted.source_registration_id() != context.source_registration_id()
                || existing.accepted.source_stream_id() != lease.source_stream_id
                || existing.accepted.registration_policy_revision()
                    != stream.registration_policy_revision
                || existing.accepted.effective_trust_profile() != stream.effective_trust_profile
                || existing.accepted.manifest_version() != stream.manifest.schema_version()
                || existing.accepted.manifest_digest() != manifest_digest
            {
                return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
            }
            if existing.digest != binding_digest {
                return Err(GatewayFailure::new(
                    ContractErrorCode::IdempotencyConflict,
                    "Runtime binding identity was reused with different content",
                    AuditReason::IdempotencyConflict,
                ));
            }
            let response = BindRuntimeResponse::new(
                existing.response.run_id().clone(),
                existing.response.binding_id(),
                true,
                true,
            )
            .map_err(contract_invariant)?;
            state.operations.insert(
                operation_key,
                StoredOperation {
                    request_digest: request.request_digest().to_string(),
                    outcome: LedgerOutcome::BindRuntime(response.clone()),
                },
            );
            *committed_state = state;
            return Ok(response);
        }

        let exact_identity_key = (request.binding().attribution() == RuntimeAttribution::Exact)
            .then(|| RuntimeIdentityKey {
                organization_id: context.organization_id().to_string(),
                identity_kind: format!("{:?}", request.binding().identity_kind()),
                identity_ref: request.binding().identity_ref().to_string(),
            });
        if let Some(key) = &exact_identity_key {
            if state
                .exact_runtime_identities
                .get(key)
                .is_some_and(|run_id| run_id != request.run_id())
            {
                return Err(GatewayFailure::new(
                    ContractErrorCode::InvalidContract,
                    "Runtime identity is already bound to an active run",
                    AuditReason::IdempotencyConflict,
                ));
            }
        }

        let response = BindRuntimeResponse::new(
            request.run_id().clone(),
            request.binding().binding_id(),
            true,
            false,
        )
        .map_err(contract_invariant)?;
        let accepted_binding = AcceptedRuntimeBinding::new(
            context.source_registration_id(),
            lease.source_stream_id.as_str(),
            stream.registration_policy_revision,
            stream.effective_trust_profile,
            stream.manifest.schema_version(),
            manifest_digest,
            request.binding().clone(),
        )
        .map_err(contract_invariant)?;
        append_record_fact(
            &mut state,
            &context,
            request.run_id(),
            now_unix_ms,
            AgentExecutionRecordFact::RuntimeBound(Box::new(accepted_binding.clone())),
        )?;
        state.bindings.insert(
            binding_key,
            StoredBinding {
                digest: binding_digest,
                accepted: accepted_binding,
                response: response.clone(),
            },
        );
        if let Some(key) = exact_identity_key {
            state
                .exact_runtime_identities
                .insert(key, request.run_id().clone());
        }
        state.operations.insert(
            operation_key,
            StoredOperation {
                request_digest: request.request_digest().to_string(),
                outcome: LedgerOutcome::BindRuntime(response.clone()),
            },
        );
        *committed_state = state;
        Ok(response)
    }

    fn finish_run(
        &self,
        context: apolysis_contracts::AuthenticatedSourceContext,
        request: FinishRunRequest,
        now_unix_ms: u64,
        finalization_deadline_unix_ms: u64,
    ) -> Result<FinishRunResponse, GatewayFailure> {
        let mut committed_state = self.state.lock().map_err(|_| repository_invariant())?;
        let mut state = committed_state.clone();
        let operation_key = OperationKey {
            organization_id: context.organization_id().to_string(),
            source_registration_id: context.source_registration_id().to_string(),
            principal_kind: context.principal().kind(),
            principal_id: context.principal().id().to_string(),
            operation: "finish_run",
            client_operation_id: request.client_operation_id().to_string(),
        };
        if let Some(stored) = state.operations.get(&operation_key) {
            if stored.request_digest != request.request_digest() {
                return Err(GatewayFailure::new(
                    ContractErrorCode::IdempotencyConflict,
                    "Operation identity was reused with different content",
                    AuditReason::IdempotencyConflict,
                ));
            }
            let LedgerOutcome::FinishRun(original) = &stored.outcome else {
                return Err(repository_invariant());
            };
            return FinishRunResponse::new(
                original.run_id().clone(),
                original.state(),
                original.finalization_deadline_unix_ms(),
                true,
            )
            .map_err(contract_invariant);
        }

        let lease = scoped_lease(&state, &context, request.run_id(), request.lease_id())?;
        if lease.registration_policy_revision != context.authentication().policy_revision() {
            return Err(lease_scope_failure(ContractErrorCode::LeaseRevoked));
        }
        if lease.run_id != *request.run_id()
            || lease.source_registration_id != context.source_registration_id()
            || lease.principal_kind != context.principal().kind()
            || lease.principal_id != context.principal().id()
            || !lease
                .allowed_operations
                .contains(&GatewayOperation::FinishRun)
        {
            return Err(lease_scope_failure(ContractErrorCode::LeaseScopeMismatch));
        }

        let run_key = RunKey {
            organization_id: context.organization_id().to_string(),
            run_id: request.run_id().to_string(),
        };
        let run = state.runs.get(&run_key).cloned().ok_or_else(not_found)?;
        if run.initiating_source_registration_id != context.source_registration_id()
            && !context.registration_policy().may_finalize_runs()
        {
            return Err(GatewayFailure::new(
                ContractErrorCode::Forbidden,
                "Authenticated source is not authorized to finalize this run",
                AuditReason::SourcePolicyMismatch,
            ));
        }
        if reconcile_expired_run(&mut state, &context, request.run_id(), now_unix_ms)?.is_some() {
            let response =
                FinishRunResponse::new(request.run_id().clone(), RunState::Incomplete, None, false)
                    .map_err(contract_invariant)?;
            state.operations.insert(
                operation_key,
                StoredOperation {
                    request_digest: request.request_digest().to_string(),
                    outcome: LedgerOutcome::FinishRun(response.clone()),
                },
            );
            *committed_state = state;
            return Ok(response);
        }
        if matches!(run.state, RunState::Finished | RunState::Incomplete) {
            return Err(GatewayFailure::new(
                ContractErrorCode::InvalidLifecycleTransition,
                "Run is already sealed",
                AuditReason::RepositoryInvariant,
            ));
        }
        if run.state == RunState::Active && finalization_deadline_unix_ms <= now_unix_ms {
            return Err(GatewayFailure::new(
                ContractErrorCode::InvalidContract,
                "Finalization deadline must be in the future",
                AuditReason::RequestContractInvalid,
            ));
        }
        if now_unix_ms >= lease.expires_at_unix_ms {
            return Err(lease_scope_failure(ContractErrorCode::LeaseExpired));
        }

        let organization_id = context.organization_id().to_string();
        let run_streams: Vec<(String, StreamRecord)> = state
            .streams
            .iter()
            .filter(|(key, _)| {
                key.organization_id == organization_id && key.run_id == request.run_id().as_str()
            })
            .map(|(key, stream)| (key.source_stream_id.clone(), stream.clone()))
            .collect();
        let mut declared_positions = run.declared_terminal_positions.clone();
        for position in request.terminal_positions() {
            let (_, stream) = run_streams
                .iter()
                .find(|(stream_id, stream)| {
                    stream_id == position.source_stream_id()
                        && stream.source_id == *position.source_id()
                })
                .ok_or_else(invalid_finalization_declaration)?;
            let durable_watermark = stream
                .sequences
                .keys()
                .next_back()
                .copied()
                .unwrap_or_default();
            if position.final_source_sequence() < durable_watermark {
                return Err(invalid_finalization_declaration());
            }
            if declared_positions
                .get(position.source_stream_id())
                .is_some_and(|declared| {
                    declared.source_id != *position.source_id()
                        || position.final_source_sequence() != declared.final_source_sequence
                })
            {
                return Err(invalid_finalization_declaration());
            }
            declared_positions.insert(
                position.source_stream_id().to_string(),
                DeclaredTerminalPosition {
                    source_id: position.source_id().clone(),
                    final_source_sequence: position.final_source_sequence(),
                },
            );
        }
        let mut outcome_claim_refs = run.declared_outcome_claim_refs.clone();
        outcome_claim_refs.extend(request.outcome_claim_refs().iter().cloned());

        let all_expected_sources_registered = run.expected_source_kinds.iter().all(|expected| {
            run_streams
                .iter()
                .any(|(_, stream)| stream.manifest.source_kind() == *expected)
        });
        let all_required_streams_declared = run_streams.iter().all(|(stream_id, stream)| {
            !run.expected_source_kinds
                .contains(&stream.manifest.source_kind())
                || declared_positions.contains_key(stream_id)
        });
        let all_declared_positions_reconciled =
            declared_positions.iter().all(|(stream_id, position)| {
                run_streams.iter().any(|(candidate_id, stream)| {
                    candidate_id == stream_id
                        && stream.source_id == position.source_id
                        && terminal_position_is_reconciled(
                            &stream.sequences,
                            position.final_source_sequence,
                        )
                })
            });
        let fully_reconciled = all_expected_sources_registered
            && all_required_streams_declared
            && all_declared_positions_reconciled;
        let next_state = if fully_reconciled {
            RunState::Finished
        } else {
            RunState::Finishing
        };
        let accepted_deadline = run
            .finalization_deadline_unix_ms
            .unwrap_or_else(|| finalization_deadline_unix_ms.min(lease.expires_at_unix_ms));
        let deadline = if next_state == RunState::Finished {
            None
        } else {
            Some(accepted_deadline)
        };
        let response =
            FinishRunResponse::new(request.run_id().clone(), next_state, deadline, false)
                .map_err(contract_invariant)?;
        let accepted_positions = declared_positions
            .iter()
            .map(|(stream_id, position)| {
                TerminalSourcePosition::new(
                    position.source_id.clone(),
                    stream_id,
                    position.final_source_sequence,
                )
                .map_err(contract_invariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let accepted_finalization = AcceptedRunFinalization::new(
            context.source_registration_id(),
            lease.source_stream_id.as_str(),
            context.principal().clone(),
            lease.registration_policy_revision,
            accepted_positions,
            outcome_claim_refs.iter().cloned().collect(),
            accepted_deadline,
        )
        .map_err(contract_invariant)?;
        append_record_fact(
            &mut state,
            &context,
            request.run_id(),
            now_unix_ms,
            AgentExecutionRecordFact::RunFinalizationDeclared(Box::new(accepted_finalization)),
        )?;
        if run.state == RunState::Active && next_state == RunState::Finished {
            append_record_fact(
                &mut state,
                &context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(RunState::Active, RunState::Finishing, now_unix_ms)
                        .map_err(contract_invariant)?,
                ),
            )?;
            append_record_fact(
                &mut state,
                &context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(RunState::Finishing, RunState::Finished, now_unix_ms)
                        .map_err(contract_invariant)?,
                ),
            )?;
        } else if next_state != run.state {
            append_record_fact(
                &mut state,
                &context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(run.state, next_state, now_unix_ms)
                        .map_err(contract_invariant)?,
                ),
            )?;
        }
        let stored_run = state
            .runs
            .get_mut(&run_key)
            .ok_or_else(repository_invariant)?;
        stored_run.state = next_state;
        stored_run.finalization_deadline_unix_ms = deadline;
        stored_run.declared_terminal_positions = declared_positions;
        stored_run.declared_outcome_claim_refs = outcome_claim_refs;
        if next_state == RunState::Finished {
            state
                .exact_runtime_identities
                .retain(|_, bound_run| bound_run != request.run_id());
        }
        state.operations.insert(
            operation_key,
            StoredOperation {
                request_digest: request.request_digest().to_string(),
                outcome: LedgerOutcome::FinishRun(response.clone()),
            },
        );
        *committed_state = state;
        Ok(response)
    }
}

impl GatewayRepository for MemoryGatewayRepository {
    fn execute<'a>(
        &'a self,
        command: LedgerCommand,
        ids: &'a dyn GatewayIdGenerator,
    ) -> RepositoryFuture<'a, Result<LedgerOutcome, GatewayFailure>> {
        Box::pin(async move {
            match command.operation() {
                LedgerOperation::OpenRun {
                    context,
                    request,
                    now_unix_ms,
                    lease_expires_at_unix_ms,
                } => self
                    .open_run(
                        context.clone(),
                        request.clone(),
                        now_unix_ms,
                        lease_expires_at_unix_ms,
                        ids,
                    )
                    .map(LedgerOutcome::OpenRun),
                LedgerOperation::Ingest {
                    context,
                    request,
                    now_unix_ms,
                } => self
                    .ingest(context.clone(), request.clone(), now_unix_ms)
                    .map(LedgerOutcome::Ingest),
                LedgerOperation::BindRuntime {
                    context,
                    request,
                    now_unix_ms,
                } => self
                    .bind_runtime(context.clone(), request.clone(), now_unix_ms)
                    .map(LedgerOutcome::BindRuntime),
                LedgerOperation::FinishRun {
                    context,
                    request,
                    now_unix_ms,
                    finalization_deadline_unix_ms,
                } => self
                    .finish_run(
                        context.clone(),
                        request.clone(),
                        now_unix_ms,
                        finalization_deadline_unix_ms,
                    )
                    .map(LedgerOutcome::FinishRun),
            }
        })
    }
}

fn next_organization_sequence(
    state: &mut State,
    organization_id: &str,
) -> Result<u64, GatewayFailure> {
    let sequence = state
        .next_ingest_sequences
        .entry(organization_id.to_string())
        .or_default();
    *sequence = sequence.checked_add(1).ok_or_else(repository_invariant)?;
    Ok(*sequence)
}

fn append_record_fact(
    state: &mut State,
    context: &apolysis_contracts::AuthenticatedSourceContext,
    run_id: &RunId,
    ingested_at_unix_ms: u64,
    fact: AgentExecutionRecordFact,
) -> Result<u64, GatewayFailure> {
    let ingest_sequence = next_organization_sequence(state, context.organization_id().as_str())?;
    let item = AgentExecutionRecordItem::new(
        context.organization_id().clone(),
        run_id.clone(),
        ingest_sequence,
        ingested_at_unix_ms,
        fact,
    )
    .map_err(contract_invariant)?;
    state.ledger.push(item);
    state.projection_outbox.push((
        context.organization_id().to_string(),
        run_id.clone(),
        ingest_sequence,
    ));
    Ok(ingest_sequence)
}

fn reconcile_expired_run(
    state: &mut State,
    context: &apolysis_contracts::AuthenticatedSourceContext,
    run_id: &RunId,
    now_unix_ms: u64,
) -> Result<Option<RunState>, GatewayFailure> {
    let run_key = RunKey {
        organization_id: context.organization_id().to_string(),
        run_id: run_id.to_string(),
    };
    let run = state.runs.get(&run_key).cloned().ok_or_else(not_found)?;
    let deadline_elapsed = run.state == RunState::Finishing
        && run
            .finalization_deadline_unix_ms
            .is_some_and(|deadline| now_unix_ms >= deadline);
    let has_unexpired_lease = state.leases.iter().any(|(key, lease)| {
        key.organization_id == context.organization_id().as_str()
            && lease.run_id == *run_id
            && now_unix_ms < lease.expires_at_unix_ms
    });
    let should_seal = match run.state {
        RunState::Active => !has_unexpired_lease,
        RunState::Finishing => deadline_elapsed || !has_unexpired_lease,
        RunState::Opening | RunState::Finished | RunState::Incomplete => false,
    };
    if !should_seal {
        return Ok(None);
    }

    append_record_fact(
        state,
        context,
        run_id,
        now_unix_ms,
        AgentExecutionRecordFact::RunStateChanged(
            RunStateTransition::new(run.state, RunState::Incomplete, now_unix_ms)
                .map_err(contract_invariant)?,
        ),
    )?;
    let stored_run = state
        .runs
        .get_mut(&run_key)
        .ok_or_else(repository_invariant)?;
    stored_run.state = RunState::Incomplete;
    stored_run.finalization_deadline_unix_ms = None;
    state
        .exact_runtime_identities
        .retain(|_, bound_run| bound_run != run_id);
    Ok(Some(run.state))
}

fn terminal_position_is_reconciled(
    sequences: &BTreeMap<u64, String>,
    final_source_sequence: u64,
) -> bool {
    if sequences.keys().next_back().copied() != Some(final_source_sequence) {
        return false;
    }
    let mut expected = 1_u64;
    for sequence in sequences
        .keys()
        .copied()
        .take_while(|sequence| *sequence <= final_source_sequence)
    {
        if sequence != expected {
            return false;
        }
        expected = expected.saturating_add(1);
    }
    expected > final_source_sequence
}

fn invalid_finalization_declaration() -> GatewayFailure {
    GatewayFailure::new(
        ContractErrorCode::InvalidContract,
        "Terminal source declaration conflicts with durable run evidence",
        AuditReason::IdempotencyConflict,
    )
}

fn sequence_gaps(sequences: &BTreeMap<u64, String>) -> Result<Vec<SequenceGap>, GatewayFailure> {
    let mut gaps = Vec::new();
    let mut expected = 1_u64;
    for sequence in sequences.keys().copied() {
        if sequence > expected {
            gaps.push(SequenceGap::new(expected, sequence - 1).map_err(contract_invariant)?);
        }
        expected = sequence.saturating_add(1);
    }
    Ok(gaps)
}

fn lease_scope_failure(code: ContractErrorCode) -> GatewayFailure {
    GatewayFailure::new(
        code,
        "Lease is expired or not valid for this operation scope",
        AuditReason::SourceRegistrationMismatch,
    )
}

fn scoped_lease(
    state: &State,
    context: &apolysis_contracts::AuthenticatedSourceContext,
    run_id: &RunId,
    lease_id: &str,
) -> Result<LeaseRecord, GatewayFailure> {
    if !state.runs.contains_key(&RunKey {
        organization_id: context.organization_id().to_string(),
        run_id: run_id.to_string(),
    }) {
        return Err(not_found());
    }
    state
        .leases
        .get(&LeaseKey {
            organization_id: context.organization_id().to_string(),
            lease_digest: lease_id_digest(lease_id),
        })
        .cloned()
        .ok_or_else(|| lease_scope_failure(ContractErrorCode::LeaseScopeMismatch))
}

fn not_found() -> GatewayFailure {
    GatewayFailure::new(
        ContractErrorCode::NotFound,
        "Requested run was not found",
        AuditReason::SourceRegistrationMismatch,
    )
}

fn join_forbidden() -> GatewayFailure {
    GatewayFailure::new(
        ContractErrorCode::Forbidden,
        "Source is not authorized to join this run",
        AuditReason::SourcePolicyMismatch,
    )
}

fn unauthorized_join_not_found() -> GatewayFailure {
    GatewayFailure::new(
        ContractErrorCode::NotFound,
        "Requested run was not found",
        AuditReason::SourcePolicyMismatch,
    )
}

fn repository_invariant() -> GatewayFailure {
    GatewayFailure::repository_fault(AuditReason::RepositoryInvariant)
}

fn next_id(ids: &dyn GatewayIdGenerator, kind: &'static str) -> Result<String, GatewayFailure> {
    ids.next_id(kind)
        .map_err(|_| GatewayFailure::repository_backpressure(250, AuditReason::EntropyUnavailable))
}

fn contract_invariant(_error: apolysis_contracts::ContractError) -> GatewayFailure {
    GatewayFailure::new(
        ContractErrorCode::InvalidContract,
        "Gateway generated an invalid contract value",
        AuditReason::RepositoryInvariant,
    )
}

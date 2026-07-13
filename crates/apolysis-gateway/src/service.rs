// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use apolysis_contracts::{
    AuthenticatedSourceContext, BindRuntimeRequest, BindRuntimeResponse, ContractErrorCode,
    FinishRunRequest, FinishRunResponse, GatewayOperation, IngestAck, IngestRequest,
    OpenRunRequest, OpenRunResponse, PrivacyCapability, RuntimeIdentityKind, SourceCapability,
};

use crate::{
    digest::constant_time_digest_eq, AuditReason, GatewayClock, GatewayFailure, GatewayIdGenerator,
    GatewayRepository, GatewayResult, LedgerCommand, LedgerOutcome,
};

const DEFAULT_LEASE_TTL_MS: u64 = 5 * 60 * 1000;
const DEFAULT_FINALIZATION_WINDOW_MS: u64 = 10 * 60 * 1000;

/// Authenticated application service for the four Gateway lifecycle operations.
pub struct ExecutionEvidenceGateway<R, C, I> {
    repository: R,
    clock: C,
    ids: I,
    lease_ttl_ms: u64,
    finalization_window_ms: u64,
}

impl<R, C, I> ExecutionEvidenceGateway<R, C, I>
where
    R: GatewayRepository,
    C: GatewayClock,
    I: GatewayIdGenerator,
{
    pub fn new(repository: R, clock: C, ids: I) -> Self {
        Self {
            repository,
            clock,
            ids,
            lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
            finalization_window_ms: DEFAULT_FINALIZATION_WINDOW_MS,
        }
    }

    pub async fn open_run(
        &self,
        context: &AuthenticatedSourceContext,
        request: OpenRunRequest,
    ) -> GatewayResult<OpenRunResponse> {
        let now_unix_ms = self.clock.now_unix_ms();
        validate_authentication_snapshot(context, now_unix_ms)?;
        validate_request_contract(request.validate())?;
        authorize_open_run(context, &request)?;
        verify_request_digest("open_run", request.request_digest(), &request)?;
        let lease_expires_at_unix_ms =
            now_unix_ms.checked_add(self.lease_ttl_ms).ok_or_else(|| {
                GatewayFailure::new(
                    ContractErrorCode::Backpressure,
                    "Gateway time source is temporarily unavailable",
                    AuditReason::RepositoryInvariant,
                )
            })?;
        match self
            .repository
            .execute(
                LedgerCommand::open_run(
                    context.clone(),
                    request,
                    now_unix_ms,
                    lease_expires_at_unix_ms,
                ),
                &self.ids,
            )
            .await?
        {
            LedgerOutcome::OpenRun(response) => Ok(response),
            _ => Err(GatewayFailure::new(
                ContractErrorCode::Backpressure,
                "Gateway persistence returned an invalid outcome",
                AuditReason::RepositoryInvariant,
            )),
        }
    }

    pub async fn ingest(
        &self,
        context: &AuthenticatedSourceContext,
        request: IngestRequest,
    ) -> GatewayResult<IngestAck> {
        let now_unix_ms = self.clock.now_unix_ms();
        validate_authentication_snapshot(context, now_unix_ms)?;
        validate_request_contract(request.validate())?;
        authorize_operation(context, GatewayOperation::Ingest)?;
        verify_request_digest("ingest", request.request_digest(), &request)?;
        validate_ingest_batch(context, &request)?;
        match self
            .repository
            .execute(
                LedgerCommand::ingest(context.clone(), request, now_unix_ms),
                &self.ids,
            )
            .await?
        {
            LedgerOutcome::Ingest(acknowledgement) => Ok(acknowledgement),
            _ => Err(GatewayFailure::new(
                ContractErrorCode::Backpressure,
                "Gateway persistence returned an invalid outcome",
                AuditReason::RepositoryInvariant,
            )),
        }
    }

    pub async fn bind_runtime(
        &self,
        context: &AuthenticatedSourceContext,
        request: BindRuntimeRequest,
    ) -> GatewayResult<BindRuntimeResponse> {
        let now_unix_ms = self.clock.now_unix_ms();
        validate_authentication_snapshot(context, now_unix_ms)?;
        validate_request_contract(request.validate())?;
        authorize_operation(context, GatewayOperation::BindRuntime)?;
        verify_request_digest("bind_runtime", request.request_digest(), &request)?;
        if request.binding().asserting_source_id() != context.registration_policy().source_id() {
            return Err(forbidden(AuditReason::SourceRegistrationMismatch));
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
        if !context
            .registration_policy()
            .allowed_capabilities()
            .contains(&required_capability)
        {
            return Err(GatewayFailure::new(
                ContractErrorCode::CapabilityMismatch,
                "Runtime binding exceeds its registered source capability",
                AuditReason::SourcePolicyMismatch,
            ));
        }
        match self
            .repository
            .execute(
                LedgerCommand::bind_runtime(context.clone(), request, now_unix_ms),
                &self.ids,
            )
            .await?
        {
            LedgerOutcome::BindRuntime(response) => Ok(response),
            _ => Err(GatewayFailure::new(
                ContractErrorCode::Backpressure,
                "Gateway persistence returned an invalid outcome",
                AuditReason::RepositoryInvariant,
            )),
        }
    }

    pub async fn finish_run(
        &self,
        context: &AuthenticatedSourceContext,
        request: FinishRunRequest,
    ) -> GatewayResult<FinishRunResponse> {
        let now_unix_ms = self.clock.now_unix_ms();
        validate_authentication_snapshot(context, now_unix_ms)?;
        validate_request_contract(request.validate())?;
        authorize_operation(context, GatewayOperation::FinishRun)?;
        verify_request_digest("finish_run", request.request_digest(), &request)?;
        let policy_deadline = now_unix_ms
            .checked_add(self.finalization_window_ms)
            .ok_or_else(|| {
                GatewayFailure::new(
                    ContractErrorCode::Backpressure,
                    "Gateway time source is temporarily unavailable",
                    AuditReason::RepositoryInvariant,
                )
            })?;
        let finalization_deadline_unix_ms = request
            .requested_finalization_deadline_unix_ms()
            .map(|deadline| deadline.min(policy_deadline))
            .unwrap_or(policy_deadline);
        match self
            .repository
            .execute(
                LedgerCommand::finish_run(
                    context.clone(),
                    request,
                    now_unix_ms,
                    finalization_deadline_unix_ms,
                ),
                &self.ids,
            )
            .await?
        {
            LedgerOutcome::FinishRun(response) => Ok(response),
            _ => Err(GatewayFailure::new(
                ContractErrorCode::Backpressure,
                "Gateway persistence returned an invalid outcome",
                AuditReason::RepositoryInvariant,
            )),
        }
    }
}

fn validate_authentication_snapshot(
    context: &AuthenticatedSourceContext,
    now_unix_ms: u64,
) -> GatewayResult<()> {
    let authentication = context.authentication();
    if now_unix_ms == 0
        || now_unix_ms < authentication.authenticated_at_unix_ms()
        || now_unix_ms >= authentication.expires_at_unix_ms()
    {
        return Err(GatewayFailure::new(
            ContractErrorCode::Unauthenticated,
            "Authentication is missing or expired",
            AuditReason::AuthenticationExpired,
        ));
    }
    Ok(())
}

fn validate_request_contract(
    validation: Result<(), apolysis_contracts::ContractError>,
) -> GatewayResult<()> {
    validation.map_err(|_| {
        GatewayFailure::new(
            ContractErrorCode::InvalidContract,
            "Request violates the Gateway contract",
            AuditReason::RequestContractInvalid,
        )
    })
}

fn authorize_open_run(
    context: &AuthenticatedSourceContext,
    request: &OpenRunRequest,
) -> GatewayResult<()> {
    let policy = context.registration_policy();
    match request {
        OpenRunRequest::Create {
            environment,
            authority,
            principal,
            privacy_profile_ref,
            retention_profile_ref,
            expected_source_kinds,
            source_manifest,
            ..
        } => {
            if !policy.may_create_runs() {
                return Err(forbidden(AuditReason::SourcePolicyMismatch));
            }
            if principal != context.principal() {
                return Err(forbidden(AuditReason::PrincipalMismatch));
            }
            if !policy.allowed_run_authorities().contains(authority) {
                return Err(forbidden(AuditReason::SourcePolicyMismatch));
            }
            if source_manifest.source_id() != policy.source_id() {
                return Err(forbidden(AuditReason::SourceRegistrationMismatch));
            }
            if source_manifest.environment() != *environment
                || !policy.allowed_environments().contains(environment)
                || !policy
                    .allowed_source_kinds()
                    .contains(&source_manifest.source_kind())
            {
                return Err(forbidden(AuditReason::SourcePolicyMismatch));
            }
            if !policy
                .allowed_run_privacy_profile_refs()
                .iter()
                .any(|profile| profile == privacy_profile_ref)
                || !policy
                    .allowed_run_retention_profile_refs()
                    .iter()
                    .any(|profile| profile == retention_profile_ref)
                || !expected_source_kinds.contains(&source_manifest.source_kind())
                || policy
                    .required_run_source_kinds()
                    .iter()
                    .any(|required| !expected_source_kinds.contains(required))
            {
                return Err(forbidden(AuditReason::SourcePolicyMismatch));
            }
            authorize_manifest(policy, source_manifest)?;
        }
        OpenRunRequest::Join {
            source_manifest, ..
        } => {
            if !policy.may_join_runs() {
                return Err(forbidden(AuditReason::SourcePolicyMismatch));
            }
            if source_manifest.source_id() != policy.source_id() {
                return Err(forbidden(AuditReason::SourceRegistrationMismatch));
            }
            if !policy
                .allowed_environments()
                .contains(&source_manifest.environment())
                || !policy
                    .allowed_source_kinds()
                    .contains(&source_manifest.source_kind())
            {
                return Err(forbidden(AuditReason::SourcePolicyMismatch));
            }
            authorize_manifest(policy, source_manifest)?;
        }
    }
    Ok(())
}

fn authorize_manifest(
    policy: &apolysis_contracts::SourceRegistrationPolicy,
    manifest: &apolysis_contracts::SourceManifest,
) -> GatewayResult<()> {
    if manifest
        .capabilities()
        .iter()
        .any(|capability| !policy.allowed_capabilities().contains(capability))
    {
        return Err(GatewayFailure::new(
            ContractErrorCode::CapabilityMismatch,
            "Source manifest exceeds its registered capability",
            AuditReason::SourcePolicyMismatch,
        ));
    }
    if manifest
        .privacy_capabilities()
        .iter()
        .any(|capability| !policy.allowed_privacy_capabilities().contains(capability))
    {
        return Err(GatewayFailure::new(
            ContractErrorCode::ContentNotAuthorized,
            "Source manifest exceeds its registered privacy ceiling",
            AuditReason::SourcePolicyMismatch,
        ));
    }
    if !manifest
        .privacy_capabilities()
        .contains(&PrivacyCapability::StructureOnly)
        || !policy
            .allowed_redaction_profile_refs()
            .iter()
            .any(|profile| profile == manifest.redaction_profile_ref())
    {
        return Err(GatewayFailure::new(
            ContractErrorCode::RedactionRequired,
            "Source manifest does not use an authorized redaction profile",
            AuditReason::SourcePolicyMismatch,
        ));
    }
    Ok(())
}

fn authorize_operation(
    context: &AuthenticatedSourceContext,
    operation: GatewayOperation,
) -> GatewayResult<()> {
    if !context
        .registration_policy()
        .allowed_operations()
        .contains(&operation)
    {
        return Err(forbidden(AuditReason::SourcePolicyMismatch));
    }
    Ok(())
}

fn validate_ingest_batch(
    context: &AuthenticatedSourceContext,
    request: &IngestRequest,
) -> GatewayResult<()> {
    let policy = context.registration_policy();
    let mut event_ids = BTreeSet::new();
    let mut source_sequences = BTreeSet::new();
    for envelope in request.envelopes() {
        if envelope.run_id() != request.run_id() {
            return Err(GatewayFailure::new(
                ContractErrorCode::LeaseScopeMismatch,
                "Evidence envelope is outside the requested run scope",
                AuditReason::SourceRegistrationMismatch,
            ));
        }
        if envelope.source_id() != policy.source_id() {
            return Err(forbidden(AuditReason::SourceRegistrationMismatch));
        }
        if !event_ids.insert(envelope.source_event_id()) {
            return Err(GatewayFailure::new(
                ContractErrorCode::SourceEventConflict,
                "Batch contains a repeated source event identity",
                AuditReason::IdempotencyConflict,
            ));
        }
        if !source_sequences.insert(envelope.source_sequence()) {
            return Err(GatewayFailure::new(
                ContractErrorCode::SequenceConflict,
                "Batch contains a repeated source sequence",
                AuditReason::IdempotencyConflict,
            ));
        }
        match (envelope.inline_payload(), envelope.object_ref()) {
            (Some(payload), None) => {
                let expected = crate::canonical_inline_payload_digest(payload).map_err(|_| {
                    GatewayFailure::new(
                        ContractErrorCode::InvalidContract,
                        "Evidence payload cannot be canonicalized",
                        AuditReason::RequestDigestMismatch,
                    )
                })?;
                if !constant_time_digest_eq(envelope.payload_digest(), &expected) {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::InvalidContract,
                        "Evidence payload digest does not match canonical content",
                        AuditReason::RequestDigestMismatch,
                    ));
                }
                let required_capability = payload.required_source_capability();
                if !policy.allowed_capabilities().contains(&required_capability) {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::CapabilityMismatch,
                        "Evidence payload exceeds its registered source capability",
                        AuditReason::SourcePolicyMismatch,
                    ));
                }
            }
            (None, Some(_)) => {
                if !policy
                    .allowed_privacy_capabilities()
                    .contains(&PrivacyCapability::AuthorizedContentReference)
                {
                    return Err(GatewayFailure::new(
                        ContractErrorCode::ContentNotAuthorized,
                        "Evidence content reference exceeds the registered privacy ceiling",
                        AuditReason::SourcePolicyMismatch,
                    ));
                }
            }
            _ => {
                return Err(GatewayFailure::new(
                    ContractErrorCode::InvalidContract,
                    "Evidence requires exactly one payload representation",
                    AuditReason::RequestDigestMismatch,
                ));
            }
        }
    }
    Ok(())
}

fn verify_request_digest<T: serde::Serialize>(
    operation: &str,
    claimed: &str,
    request: &T,
) -> GatewayResult<()> {
    let expected = crate::canonical_request_digest(operation, request).map_err(|_| {
        GatewayFailure::new(
            ContractErrorCode::InvalidContract,
            "Request cannot be canonicalized",
            AuditReason::RequestDigestMismatch,
        )
    })?;
    if !constant_time_digest_eq(claimed, &expected) {
        return Err(GatewayFailure::new(
            ContractErrorCode::InvalidContract,
            "Request digest does not match canonical content",
            AuditReason::RequestDigestMismatch,
        ));
    }
    Ok(())
}

fn forbidden(reason: AuditReason) -> GatewayFailure {
    GatewayFailure::new(
        ContractErrorCode::Forbidden,
        "Authenticated source is not authorized for this operation",
        reason,
    )
}

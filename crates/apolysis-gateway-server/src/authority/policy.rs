// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use apolysis_contracts::{
    AuthorityRef, EnvironmentKind, GatewayOperation, OrganizationId, PrincipalKind, PrincipalRef,
    PrivacyCapability, SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy,
    TrustProfile,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::{
    certificate::ClientCertificate,
    input::{
        checked_database_integer, require_absolute_path, validate_contract_identifier,
        MAX_REGISTRATION_BYTES,
    },
};
use crate::{file_input::read_bounded_file, GatewayServerError};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OrganizationState {
    Active,
    Suspended,
}

impl OrganizationState {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistrationDocument {
    pub(super) organization_id: OrganizationId,
    pub(super) organization_state: OrganizationState,
    pub(super) source_registration_id: String,
    pub(super) source_id: SourceId,
    pub(super) principal: PrincipalRef,
    pub(super) policy_revision: u64,
    pub(super) credential_epoch: u64,
    pub(super) effective_at_unix_ms: u64,
    pub(super) expires_at_unix_ms: u64,
    allowed_source_kinds: Vec<SourceKind>,
    allowed_environments: Vec<EnvironmentKind>,
    allowed_operations: Vec<GatewayOperation>,
    effective_trust_profile: TrustProfile,
    allowed_capabilities: Vec<SourceCapability>,
    allowed_privacy_capabilities: Vec<PrivacyCapability>,
    allowed_redaction_profile_refs: Vec<String>,
    allowed_run_authorities: Vec<AuthorityRef>,
    allowed_run_privacy_profile_refs: Vec<String>,
    allowed_run_retention_profile_refs: Vec<String>,
    required_run_source_kinds: Vec<SourceKind>,
    may_create_runs: bool,
    may_join_runs: bool,
    may_finalize_runs: bool,
}

impl RegistrationDocument {
    pub(super) fn validate(
        &self,
        now_unix_ms: u64,
        certificate: &ClientCertificate,
    ) -> Result<(), GatewayServerError> {
        validate_contract_identifier(
            &self.source_registration_id,
            "Source registration identifier is invalid",
        )?;
        for (value, message) in [
            (self.policy_revision, "Source policy revision is invalid"),
            (
                self.credential_epoch,
                "Transport credential epoch is invalid",
            ),
            (
                self.effective_at_unix_ms,
                "Source registration validity is invalid",
            ),
            (
                self.expires_at_unix_ms,
                "Source registration validity is invalid",
            ),
        ] {
            checked_database_integer(value, message)?;
        }
        if self.expires_at_unix_ms <= self.effective_at_unix_ms
            || self.expires_at_unix_ms <= now_unix_ms
        {
            return Err(GatewayServerError::configuration(
                "Source registration validity is invalid",
            ));
        }
        if self.effective_at_unix_ms < certificate.not_before_unix_ms
            || self.expires_at_unix_ms > certificate.not_after_unix_ms
        {
            return Err(GatewayServerError::configuration(
                "Source registration exceeds client certificate validity",
            ));
        }
        self.stored_policy()
            .build_policy()
            .map_err(|_| GatewayServerError::configuration("Source policy is invalid"))?;
        Ok(())
    }

    pub(super) fn stored_policy(&self) -> StoredPolicy {
        StoredPolicy {
            source_id: self.source_id.clone(),
            allowed_source_kinds: self.allowed_source_kinds.clone(),
            allowed_environments: self.allowed_environments.clone(),
            allowed_operations: self.allowed_operations.clone(),
            effective_trust_profile: self.effective_trust_profile,
            allowed_capabilities: self.allowed_capabilities.clone(),
            allowed_privacy_capabilities: self.allowed_privacy_capabilities.clone(),
            allowed_redaction_profile_refs: self.allowed_redaction_profile_refs.clone(),
            allowed_run_authorities: self.allowed_run_authorities.clone(),
            allowed_run_privacy_profile_refs: self.allowed_run_privacy_profile_refs.clone(),
            allowed_run_retention_profile_refs: self.allowed_run_retention_profile_refs.clone(),
            required_run_source_kinds: self.required_run_source_kinds.clone(),
            may_create_runs: self.may_create_runs,
            may_join_runs: self.may_join_runs,
            may_finalize_runs: self.may_finalize_runs,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredPolicy {
    pub(super) source_id: SourceId,
    allowed_source_kinds: Vec<SourceKind>,
    allowed_environments: Vec<EnvironmentKind>,
    allowed_operations: Vec<GatewayOperation>,
    effective_trust_profile: TrustProfile,
    allowed_capabilities: Vec<SourceCapability>,
    allowed_privacy_capabilities: Vec<PrivacyCapability>,
    allowed_redaction_profile_refs: Vec<String>,
    allowed_run_authorities: Vec<AuthorityRef>,
    allowed_run_privacy_profile_refs: Vec<String>,
    allowed_run_retention_profile_refs: Vec<String>,
    required_run_source_kinds: Vec<SourceKind>,
    may_create_runs: bool,
    may_join_runs: bool,
    may_finalize_runs: bool,
}

impl StoredPolicy {
    pub(super) fn build_policy(
        &self,
    ) -> Result<SourceRegistrationPolicy, apolysis_contracts::ContractError> {
        let mut policy = SourceRegistrationPolicy::new(
            self.source_id.clone(),
            self.allowed_source_kinds.clone(),
            self.allowed_environments.clone(),
            self.allowed_operations.clone(),
            self.may_create_runs,
            self.may_join_runs,
        )?
        .with_evidence_policy(
            self.effective_trust_profile,
            self.allowed_capabilities.clone(),
            self.allowed_privacy_capabilities.clone(),
            self.allowed_redaction_profile_refs.clone(),
        )?
        .with_finalization_permission(self.may_finalize_runs);

        if self.may_create_runs {
            policy = policy
                .with_run_authorities(self.allowed_run_authorities.clone())?
                .with_run_profiles(
                    self.allowed_run_privacy_profile_refs.clone(),
                    self.allowed_run_retention_profile_refs.clone(),
                    self.required_run_source_kinds.clone(),
                )?;
        } else if !self.allowed_run_authorities.is_empty()
            || !self.allowed_run_privacy_profile_refs.is_empty()
            || !self.allowed_run_retention_profile_refs.is_empty()
            || !self.required_run_source_kinds.is_empty()
        {
            return Err(apolysis_contracts::ContractError::InvalidField {
                field: "source_registration_policy.run_profiles",
                reason: "run-creation profiles require create permission",
            });
        }
        Ok(policy)
    }
}

pub(super) fn read_registration(path: &Path) -> Result<RegistrationDocument, GatewayServerError> {
    require_absolute_path(path)?;
    let bytes = read_bounded_file(path, MAX_REGISTRATION_BYTES as u64, false)?;
    if bytes.is_empty() || bytes.len() > MAX_REGISTRATION_BYTES {
        return Err(GatewayServerError::configuration(
            "Source registration file is invalid",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GatewayServerError::configuration("Source registration JSON is invalid"))
}

pub(super) fn validate_registration_update(
    existing: &sqlx::postgres::PgRow,
    registration: &RegistrationDocument,
    policy_document: &serde_json::Value,
) -> Result<(), GatewayServerError> {
    let existing_organization: String = existing
        .try_get("organization_id")
        .map_err(GatewayServerError::database)?;
    let existing_source: String = existing
        .try_get("source_id")
        .map_err(GatewayServerError::database)?;
    let existing_principal_kind: String = existing
        .try_get("principal_kind")
        .map_err(GatewayServerError::database)?;
    let existing_principal_id: String = existing
        .try_get("principal_id")
        .map_err(GatewayServerError::database)?;
    if existing_organization != registration.organization_id.as_str()
        || existing_source != registration.source_id.as_str()
        || existing_principal_kind != principal_kind_as_str(registration.principal.kind())
        || existing_principal_id != registration.principal.id()
    {
        return Err(GatewayServerError::configuration(
            "Source registration identity is immutable",
        ));
    }

    let existing_organization_state: String = existing
        .try_get("organization_state")
        .map_err(GatewayServerError::database)?;
    let existing_registration_state: String = existing
        .try_get("registration_state")
        .map_err(GatewayServerError::database)?;
    let existing_revision: i64 = existing
        .try_get("policy_revision")
        .map_err(GatewayServerError::database)?;
    let existing_epoch: i64 = existing
        .try_get("credential_epoch")
        .map_err(GatewayServerError::database)?;
    let new_revision = i64::try_from(registration.policy_revision)
        .map_err(|_| GatewayServerError::configuration("Source policy revision is invalid"))?;
    let new_epoch = i64::try_from(registration.credential_epoch)
        .map_err(|_| GatewayServerError::configuration("Transport credential epoch is invalid"))?;
    let existing_policy: serde_json::Value = existing
        .try_get("policy_document")
        .map_err(GatewayServerError::database)?;
    let existing_effective: i64 = existing
        .try_get("effective_at_unix_ms")
        .map_err(GatewayServerError::database)?;
    let existing_expires: i64 = existing
        .try_get("expires_at_unix_ms")
        .map_err(GatewayServerError::database)?;
    if existing_organization_state != registration.organization_state.as_str()
        || existing_registration_state != "active"
        || new_revision != existing_revision
        || new_epoch != existing_epoch
        || existing_policy != *policy_document
        || existing_effective
            != i64::try_from(registration.effective_at_unix_ms).unwrap_or(i64::MAX)
        || existing_expires != i64::try_from(registration.expires_at_unix_ms).unwrap_or(i64::MAX)
    {
        return Err(GatewayServerError::configuration(
            "Source authority updates require the credential rotation gate",
        ));
    }
    Ok(())
}

pub(super) fn policy_allows_operation(policy: &SourceRegistrationPolicy, operation: &str) -> bool {
    match operation {
        "open_run" => policy.may_create_runs() || policy.may_join_runs(),
        "bind_runtime" => policy
            .allowed_operations()
            .contains(&GatewayOperation::BindRuntime),
        "ingest" => policy
            .allowed_operations()
            .contains(&GatewayOperation::Ingest),
        "finish_run" => policy
            .allowed_operations()
            .contains(&GatewayOperation::FinishRun),
        _ => false,
    }
}

pub(super) fn parse_principal_kind(value: &str) -> Option<PrincipalKind> {
    match value {
        "human" => Some(PrincipalKind::Human),
        "workload" => Some(PrincipalKind::Workload),
        _ => None,
    }
}

pub(super) fn principal_kind_as_str(value: PrincipalKind) -> &'static str {
    match value {
        PrincipalKind::Human => "human",
        PrincipalKind::Workload => "workload",
    }
}

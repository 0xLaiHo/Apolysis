// SPDX-License-Identifier: Apache-2.0

//! Pure wire contracts for the authenticated Execution Evidence Gateway.
//!
//! Transport authentication context is deliberately absent from these types.
//! A server must inject the authenticated organization and source principal
//! before validating a request; no request field is an authority decision.

use std::{collections::BTreeSet, fmt};

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    id::{validate_contract_identifier, validate_reference},
    AuthorityRef, ContractError, EnvironmentKind, OrganizationId, PrincipalRef, PrivacyCapability,
    RunId, RunState, SchemaVersion, SourceCapability, SourceEnvelope, SourceId, SourceKind,
    SourceManifest, TrustProfile,
};

/// Maximum number of envelopes in one atomic v0.1 ingest request.
pub const MAX_INGEST_BATCH_ITEMS: usize = 256;
const MAX_TERMINAL_POSITIONS: usize = 256;
const MAX_OUTCOME_CLAIMS: usize = 64;

/// Server-owned source authorization policy selected by transport identity.
///
/// This type intentionally has no `Serialize` or `Deserialize` implementation:
/// request bytes can never manufacture it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRegistrationPolicy {
    source_id: SourceId,
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

impl SourceRegistrationPolicy {
    /// Create a transport-resolved registration policy.
    pub fn new(
        source_id: SourceId,
        allowed_source_kinds: Vec<SourceKind>,
        allowed_environments: Vec<EnvironmentKind>,
        allowed_operations: Vec<GatewayOperation>,
        may_create_runs: bool,
        may_join_runs: bool,
    ) -> Result<Self, ContractError> {
        if allowed_source_kinds.is_empty()
            || allowed_environments.is_empty()
            || allowed_operations.is_empty()
        {
            return Err(ContractError::InvalidField {
                field: "source_registration_policy",
                reason: "source kinds, environments, and operations must not be empty",
            });
        }
        let mut source_kinds = BTreeSet::new();
        if allowed_source_kinds
            .iter()
            .any(|value| !source_kinds.insert(value))
        {
            return Err(ContractError::DuplicateValue {
                field: "allowed_source_kinds",
            });
        }
        let mut operations = BTreeSet::new();
        if allowed_operations
            .iter()
            .any(|value| !operations.insert(value))
        {
            return Err(ContractError::DuplicateValue {
                field: "allowed_operations",
            });
        }
        for (index, environment) in allowed_environments.iter().enumerate() {
            if allowed_environments[..index].contains(environment) {
                return Err(ContractError::DuplicateValue {
                    field: "allowed_environments",
                });
            }
        }
        Ok(Self {
            source_id,
            allowed_source_kinds,
            allowed_environments,
            allowed_operations,
            effective_trust_profile: TrustProfile::Declared,
            allowed_capabilities: Vec::new(),
            allowed_privacy_capabilities: vec![PrivacyCapability::StructureOnly],
            allowed_redaction_profile_refs: Vec::new(),
            allowed_run_authorities: Vec::new(),
            allowed_run_privacy_profile_refs: Vec::new(),
            allowed_run_retention_profile_refs: Vec::new(),
            required_run_source_kinds: Vec::new(),
            may_create_runs,
            may_join_runs,
            may_finalize_runs: false,
        })
    }

    /// Attach the server-assigned trust and evidence ceilings for this source.
    pub fn with_evidence_policy(
        mut self,
        effective_trust_profile: TrustProfile,
        allowed_capabilities: Vec<SourceCapability>,
        allowed_privacy_capabilities: Vec<PrivacyCapability>,
        allowed_redaction_profile_refs: Vec<String>,
    ) -> Result<Self, ContractError> {
        if allowed_capabilities.is_empty()
            || allowed_privacy_capabilities.is_empty()
            || !allowed_privacy_capabilities.contains(&PrivacyCapability::StructureOnly)
            || allowed_redaction_profile_refs.is_empty()
        {
            return Err(ContractError::InvalidField {
                field: "source_registration_policy.evidence_policy",
                reason: "capabilities, structure-only privacy, and redaction profiles are required",
            });
        }
        let mut capabilities = BTreeSet::new();
        if allowed_capabilities
            .iter()
            .any(|value| !capabilities.insert(value))
        {
            return Err(ContractError::DuplicateValue {
                field: "allowed_capabilities",
            });
        }
        let mut privacy_capabilities = BTreeSet::new();
        if allowed_privacy_capabilities
            .iter()
            .any(|value| !privacy_capabilities.insert(value))
        {
            return Err(ContractError::DuplicateValue {
                field: "allowed_privacy_capabilities",
            });
        }
        let mut redaction_profiles = BTreeSet::new();
        for profile in &allowed_redaction_profile_refs {
            validate_contract_identifier(profile, "allowed_redaction_profile_refs")?;
            if !redaction_profiles.insert(profile.as_str()) {
                return Err(ContractError::DuplicateValue {
                    field: "allowed_redaction_profile_refs",
                });
            }
        }
        self.effective_trust_profile = effective_trust_profile;
        self.allowed_capabilities = allowed_capabilities;
        self.allowed_privacy_capabilities = allowed_privacy_capabilities;
        self.allowed_redaction_profile_refs = allowed_redaction_profile_refs;
        Ok(self)
    }

    /// Allow a joined source registration to finalize runs when its lease also
    /// grants `finish_run`.
    pub fn with_finalization_permission(mut self, may_finalize_runs: bool) -> Self {
        self.may_finalize_runs = may_finalize_runs;
        self
    }

    /// Bind create authorization to server-resolved run authorities.
    pub fn with_run_authorities(
        mut self,
        allowed_run_authorities: Vec<AuthorityRef>,
    ) -> Result<Self, ContractError> {
        if allowed_run_authorities.is_empty() {
            return Err(ContractError::InvalidField {
                field: "source_registration_policy.allowed_run_authorities",
                reason: "must not be empty",
            });
        }
        for (index, authority) in allowed_run_authorities.iter().enumerate() {
            if allowed_run_authorities[..index].contains(authority) {
                return Err(ContractError::DuplicateValue {
                    field: "allowed_run_authorities",
                });
            }
        }
        self.allowed_run_authorities = allowed_run_authorities;
        Ok(self)
    }

    /// Bind create requests to organization-approved privacy, retention, and
    /// required-source profiles selected by trusted policy lookup.
    pub fn with_run_profiles(
        mut self,
        allowed_run_privacy_profile_refs: Vec<String>,
        allowed_run_retention_profile_refs: Vec<String>,
        required_run_source_kinds: Vec<SourceKind>,
    ) -> Result<Self, ContractError> {
        if allowed_run_privacy_profile_refs.is_empty()
            || allowed_run_retention_profile_refs.is_empty()
            || required_run_source_kinds.is_empty()
        {
            return Err(ContractError::InvalidField {
                field: "source_registration_policy.run_profiles",
                reason: "privacy, retention, and required source profiles must not be empty",
            });
        }
        validate_unique_profile_refs(
            &allowed_run_privacy_profile_refs,
            "allowed_run_privacy_profile_refs",
        )?;
        validate_unique_profile_refs(
            &allowed_run_retention_profile_refs,
            "allowed_run_retention_profile_refs",
        )?;
        let mut source_kinds = BTreeSet::new();
        if required_run_source_kinds
            .iter()
            .any(|kind| !source_kinds.insert(kind))
        {
            return Err(ContractError::DuplicateValue {
                field: "required_run_source_kinds",
            });
        }
        self.allowed_run_privacy_profile_refs = allowed_run_privacy_profile_refs;
        self.allowed_run_retention_profile_refs = allowed_run_retention_profile_refs;
        self.required_run_source_kinds = required_run_source_kinds;
        Ok(self)
    }

    /// Return the registered source identity.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Return source kinds accepted for this registration.
    pub fn allowed_source_kinds(&self) -> &[SourceKind] {
        &self.allowed_source_kinds
    }

    /// Return environment profiles accepted for this registration.
    pub fn allowed_environments(&self) -> &[EnvironmentKind] {
        &self.allowed_environments
    }

    /// Return operations that a minted lease may grant.
    pub fn allowed_operations(&self) -> &[GatewayOperation] {
        &self.allowed_operations
    }

    /// Return the trust profile assigned by the accepting control plane.
    pub fn effective_trust_profile(&self) -> TrustProfile {
        self.effective_trust_profile
    }

    /// Return the source capabilities authorized by registration policy.
    pub fn allowed_capabilities(&self) -> &[SourceCapability] {
        &self.allowed_capabilities
    }

    /// Return privacy representations authorized for this source.
    pub fn allowed_privacy_capabilities(&self) -> &[PrivacyCapability] {
        &self.allowed_privacy_capabilities
    }

    /// Return registered redaction profiles accepted for this source.
    pub fn allowed_redaction_profile_refs(&self) -> &[String] {
        &self.allowed_redaction_profile_refs
    }

    /// Return run authorities admitted by this server-loaded registration.
    pub fn allowed_run_authorities(&self) -> &[AuthorityRef] {
        &self.allowed_run_authorities
    }

    /// Return organization-approved run privacy profiles.
    pub fn allowed_run_privacy_profile_refs(&self) -> &[String] {
        &self.allowed_run_privacy_profile_refs
    }

    /// Return organization-approved run retention profiles.
    pub fn allowed_run_retention_profile_refs(&self) -> &[String] {
        &self.allowed_run_retention_profile_refs
    }

    /// Return source kinds required by the selected server-side run policy.
    pub fn required_run_source_kinds(&self) -> &[SourceKind] {
        &self.required_run_source_kinds
    }

    /// Return whether this registration may initiate a run.
    pub fn may_create_runs(&self) -> bool {
        self.may_create_runs
    }

    /// Return whether this registration may join a run.
    pub fn may_join_runs(&self) -> bool {
        self.may_join_runs
    }

    /// Return whether this source may finalize a run it did not initiate.
    pub fn may_finalize_runs(&self) -> bool {
        self.may_finalize_runs
    }
}

fn validate_unique_profile_refs(
    values: &[String],
    field: &'static str,
) -> Result<(), ContractError> {
    let mut profiles = BTreeSet::new();
    for value in values {
        validate_contract_identifier(value, field)?;
        if !profiles.insert(value.as_str()) {
            return Err(ContractError::DuplicateValue { field });
        }
    }
    Ok(())
}

/// Authenticated source facts injected by the transport adapter.
///
/// It is a server-side input to authorization, not part of any operation's
/// wire request. Deliberately omitting serde implementations makes that
/// boundary mechanically visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationSnapshot {
    credential_id: String,
    policy_revision: u64,
    authenticated_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl AuthenticationSnapshot {
    /// Record the bounded authentication and authorization snapshot resolved by
    /// trusted transport middleware.
    pub fn new(
        credential_id: impl Into<String>,
        policy_revision: u64,
        authenticated_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            credential_id: credential_id.into(),
            policy_revision,
            authenticated_at_unix_ms,
            expires_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the opaque credential identity for protected audit records.
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// Return the server-loaded policy revision used for this decision.
    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// Return when transport authentication completed.
    pub fn authenticated_at_unix_ms(&self) -> u64 {
        self.authenticated_at_unix_ms
    }

    /// Return the hard expiry of this authentication snapshot.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.credential_id, "credential_id")?;
        if self.policy_revision == 0 {
            return Err(ContractError::InvalidField {
                field: "policy_revision",
                reason: "must be greater than zero",
            });
        }
        if self.authenticated_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.authenticated_at_unix_ms
        {
            return Err(ContractError::InvalidField {
                field: "authenticated_at_unix_ms/expires_at_unix_ms",
                reason: "authentication must have a positive bounded validity window",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSourceContext {
    organization_id: OrganizationId,
    principal: PrincipalRef,
    source_registration_id: String,
    authentication: AuthenticationSnapshot,
    registration_policy: SourceRegistrationPolicy,
}

impl AuthenticatedSourceContext {
    /// Create context after transport authentication and policy lookup.
    pub fn new(
        organization_id: OrganizationId,
        principal: PrincipalRef,
        source_registration_id: impl Into<String>,
        authentication: AuthenticationSnapshot,
        registration_policy: SourceRegistrationPolicy,
    ) -> Result<Self, ContractError> {
        let source_registration_id = source_registration_id.into();
        validate_contract_identifier(&source_registration_id, "source_registration_id")?;
        Ok(Self {
            organization_id,
            principal,
            source_registration_id,
            authentication,
            registration_policy,
        })
    }

    /// Return the authoritative organization scope.
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Return the transport-authenticated principal.
    pub fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    /// Return the server-side source registration identity.
    pub fn source_registration_id(&self) -> &str {
        &self.source_registration_id
    }

    /// Return the bounded transport authentication snapshot.
    pub fn authentication(&self) -> &AuthenticationSnapshot {
        &self.authentication
    }

    /// Return the server-loaded source registration policy.
    pub fn registration_policy(&self) -> &SourceRegistrationPolicy {
        &self.registration_policy
    }
}

fn validate_sha256_digest(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidField {
            field,
            reason: "must be a lowercase 64-character SHA-256 digest",
        });
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ContractError> {
    validate_sha256_digest(value, "request_digest")
}

fn validate_idempotency(
    client_operation_id: &str,
    request_digest: &str,
) -> Result<(), ContractError> {
    validate_contract_identifier(client_operation_id, "client_operation_id")?;
    validate_digest(request_digest)
}

fn reject_duplicate_refs<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &'static str,
) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ContractError::DuplicateValue { field });
        }
    }
    Ok(())
}

/// A create or explicit join request for an Agent Run.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum OpenRunRequest {
    /// Establish a new canonical run and the initiating source lease.
    Create {
        /// Wire schema marker.
        schema_version: SchemaVersion,
        /// Client-scoped idempotency identity.
        #[schemars(
            length(min = 1, max = 128),
            regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
        )]
        client_operation_id: String,
        /// Canonical SHA-256 digest of this operation.
        #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
        request_digest: String,
        /// Client identity for collision detection; it is not a run ID.
        client_run_key: String,
        /// Deployment environment profile.
        environment: EnvironmentKind,
        /// Authority permitting this run.
        authority: AuthorityRef,
        /// Authenticated actor reference inside that authority.
        principal: PrincipalRef,
        /// Content-free objective reference.
        objective_ref: String,
        /// Registered privacy policy reference.
        privacy_profile_ref: String,
        /// Registered retention policy reference.
        retention_profile_ref: String,
        /// Source roles expected to contribute before finalization.
        expected_source_kinds: Vec<SourceKind>,
        /// Initiating source declaration.
        source_manifest: SourceManifest,
    },
    /// Join an existing run with a distinct source stream and lease.
    Join {
        /// Wire schema marker.
        schema_version: SchemaVersion,
        /// Client-scoped idempotency identity.
        #[schemars(
            length(min = 1, max = 128),
            regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
        )]
        client_operation_id: String,
        /// Canonical SHA-256 digest of this operation.
        #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
        request_digest: String,
        /// Existing organization-scoped run assertion.
        run_id: RunId,
        /// Time-bounded proof scoped to this run and joining source.
        join_proof: JoinProof,
        /// Joining source declaration.
        source_manifest: SourceManifest,
    },
}

/// Explicit branch selected by an [`OpenRunRequest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenRunMode {
    /// Establish a new canonical run.
    Create,
    /// Join an existing canonical run.
    Join,
}

impl OpenRunRequest {
    /// Return the selected create-or-join operation mode.
    pub fn mode(&self) -> OpenRunMode {
        match self {
            Self::Create { .. } => OpenRunMode::Create,
            Self::Join { .. } => OpenRunMode::Join,
        }
    }

    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        match self {
            Self::Create { schema_version, .. } | Self::Join { schema_version, .. } => {
                *schema_version
            }
        }
    }

    /// Return the client-scoped idempotency identity.
    pub fn client_operation_id(&self) -> &str {
        match self {
            Self::Create {
                client_operation_id,
                ..
            }
            | Self::Join {
                client_operation_id,
                ..
            } => client_operation_id,
        }
    }

    /// Return the client-supplied canonical request digest.
    pub fn request_digest(&self) -> &str {
        match self {
            Self::Create { request_digest, .. } | Self::Join { request_digest, .. } => {
                request_digest
            }
        }
    }

    /// Return the source declaration supplied by either open mode.
    pub fn source_manifest(&self) -> &SourceManifest {
        match self {
            Self::Create {
                source_manifest, ..
            }
            | Self::Join {
                source_manifest, ..
            } => source_manifest,
        }
    }

    /// Return the collision-detection key supplied by create mode.
    pub fn client_run_key(&self) -> Option<&str> {
        match self {
            Self::Create { client_run_key, .. } => Some(client_run_key),
            Self::Join { .. } => None,
        }
    }

    /// Return the environment selected by create mode.
    pub fn environment(&self) -> Option<EnvironmentKind> {
        match self {
            Self::Create { environment, .. } => Some(*environment),
            Self::Join { .. } => None,
        }
    }

    /// Return the authority assertion supplied by create mode.
    pub fn authority(&self) -> Option<&AuthorityRef> {
        match self {
            Self::Create { authority, .. } => Some(authority),
            Self::Join { .. } => None,
        }
    }

    /// Return the principal assertion supplied by create mode.
    pub fn principal(&self) -> Option<&PrincipalRef> {
        match self {
            Self::Create { principal, .. } => Some(principal),
            Self::Join { .. } => None,
        }
    }

    /// Return the content-free objective reference supplied by create mode.
    pub fn objective_ref(&self) -> Option<&str> {
        match self {
            Self::Create { objective_ref, .. } => Some(objective_ref),
            Self::Join { .. } => None,
        }
    }

    /// Return the privacy profile selected by create mode.
    pub fn privacy_profile_ref(&self) -> Option<&str> {
        match self {
            Self::Create {
                privacy_profile_ref,
                ..
            } => Some(privacy_profile_ref),
            Self::Join { .. } => None,
        }
    }

    /// Return the retention profile selected by create mode.
    pub fn retention_profile_ref(&self) -> Option<&str> {
        match self {
            Self::Create {
                retention_profile_ref,
                ..
            } => Some(retention_profile_ref),
            Self::Join { .. } => None,
        }
    }

    /// Return expected source kinds declared by create mode.
    pub fn expected_source_kinds(&self) -> Option<&[SourceKind]> {
        match self {
            Self::Create {
                expected_source_kinds,
                ..
            } => Some(expected_source_kinds),
            Self::Join { .. } => None,
        }
    }

    /// Return the existing run assertion supplied by join mode.
    pub fn run_id(&self) -> Option<&RunId> {
        match self {
            Self::Create { .. } => None,
            Self::Join { run_id, .. } => Some(run_id),
        }
    }

    /// Return the authorization proof supplied by join mode.
    pub fn join_proof(&self) -> Option<&JoinProof> {
        match self {
            Self::Create { .. } => None,
            Self::Join { join_proof, .. } => Some(join_proof),
        }
    }

    /// Return whether this request explicitly creates a new run.
    pub fn is_create(&self) -> bool {
        matches!(self, Self::Create { .. })
    }

    /// Return whether this request explicitly joins an existing run.
    pub fn is_join(&self) -> bool {
        matches!(self, Self::Join { .. })
    }

    /// Validate source-controlled request fields without transport authority.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Create {
                client_operation_id,
                request_digest,
                client_run_key,
                objective_ref,
                privacy_profile_ref,
                retention_profile_ref,
                expected_source_kinds,
                source_manifest,
                ..
            } => {
                validate_idempotency(client_operation_id, request_digest)?;
                validate_contract_identifier(client_run_key, "client_run_key")?;
                validate_reference(objective_ref, "objective_ref")?;
                validate_contract_identifier(privacy_profile_ref, "privacy_profile_ref")?;
                validate_contract_identifier(retention_profile_ref, "retention_profile_ref")?;
                if expected_source_kinds.is_empty() {
                    return Err(ContractError::InvalidField {
                        field: "expected_source_kinds",
                        reason: "must declare at least one expected source kind",
                    });
                }
                let mut kinds = BTreeSet::new();
                for kind in expected_source_kinds {
                    if !kinds.insert(kind) {
                        return Err(ContractError::DuplicateValue {
                            field: "expected_source_kinds",
                        });
                    }
                }
                source_manifest.validate()
            }
            Self::Join {
                client_operation_id,
                request_digest,
                run_id,
                join_proof,
                source_manifest,
                ..
            } => {
                validate_idempotency(client_operation_id, request_digest)?;
                join_proof.validate()?;
                if join_proof.run_id() != run_id
                    || join_proof.source_id() != source_manifest.source_id()
                {
                    return Err(ContractError::InvalidField {
                        field: "join_proof",
                        reason: "must be scoped to the requested run and source",
                    });
                }
                source_manifest.validate()
            }
        }
    }
}

impl<'de> Deserialize<'de> for OpenRunRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Create {
                schema_version: SchemaVersion,
                client_operation_id: String,
                request_digest: String,
                client_run_key: String,
                environment: EnvironmentKind,
                authority: AuthorityRef,
                principal: PrincipalRef,
                objective_ref: String,
                privacy_profile_ref: String,
                retention_profile_ref: String,
                expected_source_kinds: Vec<SourceKind>,
                source_manifest: SourceManifest,
            },
            Join {
                schema_version: SchemaVersion,
                client_operation_id: String,
                request_digest: String,
                run_id: RunId,
                join_proof: JoinProof,
                source_manifest: SourceManifest,
            },
        }

        let value = match Wire::deserialize(deserializer)? {
            Wire::Create {
                schema_version,
                client_operation_id,
                request_digest,
                client_run_key,
                environment,
                authority,
                principal,
                objective_ref,
                privacy_profile_ref,
                retention_profile_ref,
                expected_source_kinds,
                source_manifest,
            } => Self::Create {
                schema_version,
                client_operation_id,
                request_digest,
                client_run_key,
                environment,
                authority,
                principal,
                objective_ref,
                privacy_profile_ref,
                retention_profile_ref,
                expected_source_kinds,
                source_manifest,
            },
            Wire::Join {
                schema_version,
                client_operation_id,
                request_digest,
                run_id,
                join_proof,
                source_manifest,
            } => Self::Join {
                schema_version,
                client_operation_id,
                request_digest,
                run_id,
                join_proof,
                source_manifest,
            },
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Server-verifiable join authorization representation.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinProofKind {
    /// A time-bounded grant minted for one run and source.
    Grant,
    /// A registered policy authorizing this source to join the run.
    RegistrationPolicy,
}

/// Join proof whose wire-visible scope cannot silently target another source.
#[derive(schemars::JsonSchema, Clone, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct JoinProof {
    kind: JoinProofKind,
    #[schemars(length(min = 1, max = 512))]
    proof_ref: String,
    run_id: RunId,
    source_id: SourceId,
    #[schemars(range(min = 1))]
    expires_at_unix_ms: u64,
}

impl fmt::Debug for JoinProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinProof")
            .field("kind", &self.kind)
            .field("proof_ref", &"[REDACTED]")
            .field("run_id", &self.run_id)
            .field("source_id", &self.source_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

impl JoinProof {
    /// Return the proof representation selected by the source.
    pub fn kind(&self) -> JoinProofKind {
        self.kind
    }

    /// Return the opaque server-verifiable proof reference.
    pub fn proof_ref(&self) -> &str {
        &self.proof_ref
    }

    /// Return the run scope asserted by the proof.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the joining source scope asserted by the proof.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Return the asserted proof expiry.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_reference(&self.proof_ref, "join_proof.proof_ref")?;
        if self.expires_at_unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "join_proof.expires_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for JoinProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: JoinProofKind,
            proof_ref: String,
            run_id: RunId,
            source_id: SourceId,
            expires_at_unix_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            kind: wire.kind,
            proof_ref: wire.proof_ref,
            run_id: wire.run_id,
            source_id: wire.source_id,
            expires_at_unix_ms: wire.expires_at_unix_ms,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Operations granted by a source-scoped run lease.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GatewayOperation {
    /// Attach an execution identity.
    BindRuntime,
    /// Submit evidence envelopes.
    Ingest,
    /// Request bounded run finalization.
    FinishRun,
}

/// Bearer lease identity with a redacted `Debug` representation.
#[derive(schemars::JsonSchema, Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct RunLeaseId(String);

impl RunLeaseId {
    fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_contract_identifier(&value, "lease_id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunLeaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunLeaseId([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for RunLeaseId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A time-bounded, source-stream-scoped capability returned by `open_run`.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RunLease {
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    lease_id: RunLeaseId,
    #[schemars(range(min = 1))]
    expires_at_unix_ms: u64,
    #[schemars(length(min = 1))]
    allowed_operations: Vec<GatewayOperation>,
}

impl RunLease {
    /// Issue a validated source-stream-scoped run lease.
    pub fn new(
        lease_id: impl Into<String>,
        expires_at_unix_ms: u64,
        allowed_operations: Vec<GatewayOperation>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            lease_id: RunLeaseId::new(lease_id)?,
            expires_at_unix_ms,
            allowed_operations,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the opaque lease identity.
    pub fn lease_id(&self) -> &str {
        self.lease_id.as_str()
    }

    /// Return the server-controlled lease expiry.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Return the granted Gateway operations.
    pub fn allowed_operations(&self) -> &[GatewayOperation] {
        &self.allowed_operations
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.expires_at_unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "expires_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        if self.allowed_operations.is_empty() {
            return Err(ContractError::InvalidField {
                field: "allowed_operations",
                reason: "must grant at least one operation",
            });
        }
        let mut operations = BTreeSet::new();
        for operation in &self.allowed_operations {
            if !operations.insert(operation) {
                return Err(ContractError::DuplicateValue {
                    field: "allowed_operations",
                });
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RunLease {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            lease_id: String,
            expires_at_unix_ms: u64,
            allowed_operations: Vec<GatewayOperation>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            lease_id: RunLeaseId::new(wire.lease_id).map_err(de::Error::custom)?,
            expires_at_unix_ms: wire.expires_at_unix_ms,
            allowed_operations: wire.allowed_operations,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Result classification for an `open_run` request.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenRunOutcome {
    /// A new run was created.
    Created,
    /// A new source joined an existing run.
    Joined,
    /// The original result was returned for an exact retry.
    IdempotentRetry,
}

/// Lease and canonical identities returned after opening a source stream.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct OpenRunResponse {
    schema_version: SchemaVersion,
    run_id: RunId,
    source_id: SourceId,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    source_stream_id: String,
    outcome: OpenRunOutcome,
    lease: RunLease,
}

impl OpenRunResponse {
    /// Construct a validated response after a run source stream is committed.
    pub fn new(
        run_id: RunId,
        source_id: SourceId,
        source_stream_id: impl Into<String>,
        outcome: OpenRunOutcome,
        lease: RunLease,
    ) -> Result<Self, ContractError> {
        let value = Self {
            schema_version: SchemaVersion::V0_1,
            run_id,
            source_id,
            source_stream_id: source_stream_id.into(),
            outcome,
            lease,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the canonical run identity.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the registered source identity.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Return the distinct source stream created by this operation.
    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    /// Return whether the stream was created, joined, or replayed.
    pub fn outcome(&self) -> OpenRunOutcome {
        self.outcome
    }

    /// Return the source-stream-scoped lease.
    pub fn lease(&self) -> &RunLease {
        &self.lease
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.source_stream_id, "source_stream_id")?;
        self.lease.validate()
    }
}

impl<'de> Deserialize<'de> for OpenRunResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            run_id: RunId,
            source_id: SourceId,
            source_stream_id: String,
            outcome: OpenRunOutcome,
            lease: RunLease,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            source_id: wire.source_id,
            source_stream_id: wire.source_stream_id,
            outcome: wire.outcome,
            lease: wire.lease,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Runtime identity categories supported by the v0.1 binding contract.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeIdentityKind {
    /// Operating-system process identity.
    Process,
    /// Linux cgroup identity.
    Cgroup,
    /// Container-runtime identity.
    Container,
    /// Kubernetes Pod identity.
    Pod,
    /// Virtual-machine identity.
    Vm,
    /// CI or development runner identity.
    Runner,
    /// Provider-managed workload identity.
    ProviderWorkload,
}

/// Explicit quality of a run-to-runtime correlation.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttribution {
    /// An explicitly propagated identity was independently validated.
    Exact,
    /// A non-unique heuristic selected one most likely runtime.
    Inferred,
    /// Multiple plausible runtime identities remain.
    Ambiguous,
    /// No qualifying runtime identity could be assigned.
    Unattributed,
}

/// Evidence method used to establish a runtime correlation.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBindingBasis {
    /// A propagated runtime identifier was checked at an independent boundary.
    PropagatedAndValidated,
    /// A provider asserted the runtime relation inside its own boundary.
    ProviderAttestation,
    /// PID, time, path, argument, name, or comparable heuristic matching.
    HeuristicMatch,
    /// No qualifying basis was available.
    Unavailable,
}

/// One scored alternative retained for an ambiguous runtime relation.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RuntimeBindingCandidate {
    #[schemars(length(min = 1, max = 512))]
    identity_ref: String,
    #[schemars(length(min = 1))]
    reason_codes: Vec<String>,
    #[schemars(range(max = 10000))]
    confidence_bps: u16,
    #[schemars(length(min = 1))]
    evidence_basis_refs: Vec<String>,
}

impl RuntimeBindingCandidate {
    /// Return the candidate runtime identity reference.
    pub fn identity_ref(&self) -> &str {
        &self.identity_ref
    }

    /// Return the evidence-backed reasons supporting this candidate.
    pub fn reason_codes(&self) -> &[String] {
        &self.reason_codes
    }

    /// Return the candidate's bounded projector score in basis points.
    pub fn confidence_bps(&self) -> u16 {
        self.confidence_bps
    }

    /// Return the evidence references supporting this candidate.
    pub fn evidence_basis_refs(&self) -> &[String] {
        &self.evidence_basis_refs
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_reference(&self.identity_ref, "binding.candidate.identity_ref")?;
        validate_reason_codes(&self.reason_codes, "binding.candidate.reason_codes")?;
        if self.confidence_bps > 10_000 {
            return Err(ContractError::InvalidField {
                field: "binding.candidate.confidence_bps",
                reason: "must be between 0 and 10000",
            });
        }
        if self.evidence_basis_refs.is_empty() {
            return Err(ContractError::InvalidField {
                field: "binding.candidate.evidence_basis_refs",
                reason: "must not be empty",
            });
        }
        for reference in &self.evidence_basis_refs {
            validate_reference(reference, "binding.candidate.evidence_basis_refs")?;
        }
        reject_duplicate_refs(
            self.evidence_basis_refs.iter().map(String::as_str),
            "binding.candidate.evidence_basis_refs",
        )
    }
}

impl<'de> Deserialize<'de> for RuntimeBindingCandidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            identity_ref: String,
            reason_codes: Vec<String>,
            confidence_bps: u16,
            evidence_basis_refs: Vec<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            identity_ref: wire.identity_ref,
            reason_codes: wire.reason_codes,
            confidence_bps: wire.confidence_bps,
            evidence_basis_refs: wire.evidence_basis_refs,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// A versioned, evidence-backed relation between a run and runtime identity.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RuntimeBinding {
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    binding_id: String,
    asserting_source_id: SourceId,
    identity_kind: RuntimeIdentityKind,
    #[schemars(length(min = 1, max = 512))]
    identity_ref: String,
    #[schemars(range(min = 1))]
    valid_from_unix_ms: u64,
    valid_until_unix_ms: Option<u64>,
    evidence_basis: RuntimeBindingBasis,
    #[schemars(length(min = 1, max = 512))]
    evidence_basis_ref: String,
    attribution: RuntimeAttribution,
    reason_codes: Vec<String>,
    #[schemars(range(max = 10000))]
    confidence_bps: Option<u16>,
    alternative_runtime_candidates: Vec<RuntimeBindingCandidate>,
}

impl RuntimeBinding {
    /// Return the idempotent binding identity.
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Return the registered Evidence Source asserting this relation.
    pub fn asserting_source_id(&self) -> &SourceId {
        &self.asserting_source_id
    }

    /// Return the runtime identity category.
    pub fn identity_kind(&self) -> RuntimeIdentityKind {
        self.identity_kind
    }

    /// Return the runtime identity reference asserted by this binding.
    pub fn identity_ref(&self) -> &str {
        &self.identity_ref
    }

    /// Return the beginning of the asserted validity window.
    pub fn valid_from_unix_ms(&self) -> u64 {
        self.valid_from_unix_ms
    }

    /// Return the end of the asserted validity window, when bounded.
    pub fn valid_until_unix_ms(&self) -> Option<u64> {
        self.valid_until_unix_ms
    }

    /// Return the method used to establish this binding.
    pub fn evidence_basis(&self) -> RuntimeBindingBasis {
        self.evidence_basis
    }

    /// Return the evidence reference establishing this binding.
    pub fn evidence_basis_ref(&self) -> &str {
        &self.evidence_basis_ref
    }

    /// Return the selected or first retained candidate score, when non-exact.
    pub fn confidence_bps(&self) -> Option<u16> {
        self.confidence_bps
    }

    /// Return the explicit correlation quality.
    pub fn attribution(&self) -> RuntimeAttribution {
        self.attribution
    }

    /// Return the reasons supporting a non-exact attribution.
    pub fn reason_codes(&self) -> &[String] {
        &self.reason_codes
    }

    /// Return every scored alternative retained for an ambiguous binding.
    pub fn alternative_runtime_candidates(&self) -> &[RuntimeBindingCandidate] {
        &self.alternative_runtime_candidates
    }

    /// Validate binding evidence without consulting run or lease state.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.binding_id, "binding.binding_id")?;
        validate_reference(&self.identity_ref, "binding.identity_ref")?;
        validate_reference(&self.evidence_basis_ref, "binding.evidence_basis_ref")?;
        if self.valid_from_unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "binding.valid_from_unix_ms",
                reason: "must be greater than zero",
            });
        }
        if self
            .valid_until_unix_ms
            .is_some_and(|until| until <= self.valid_from_unix_ms)
        {
            return Err(ContractError::InvalidField {
                field: "binding.valid_until_unix_ms",
                reason: "must be greater than valid_from_unix_ms",
            });
        }
        for candidate in &self.alternative_runtime_candidates {
            candidate.validate()?;
        }
        reject_duplicate_refs(
            self.alternative_runtime_candidates
                .iter()
                .map(|candidate| candidate.identity_ref.as_str()),
            "binding.alternative_runtime_candidates",
        )?;

        match self.attribution {
            RuntimeAttribution::Exact => {
                if self.evidence_basis != RuntimeBindingBasis::PropagatedAndValidated
                    || !self.reason_codes.is_empty()
                    || self.confidence_bps.is_some()
                    || !self.alternative_runtime_candidates.is_empty()
                {
                    return Err(ContractError::InvalidField {
                        field: "binding.attribution",
                        reason: "exact requires propagated validation without heuristic scoring",
                    });
                }
            }
            RuntimeAttribution::Inferred => {
                validate_reason_codes(&self.reason_codes, "binding.reason_codes")?;
                if self.confidence_bps.is_none_or(|value| value > 10_000)
                    || !self.alternative_runtime_candidates.is_empty()
                {
                    return Err(ContractError::InvalidField {
                        field: "binding.confidence_bps",
                        reason: "inferred requires one bounded score and no alternatives",
                    });
                }
            }
            RuntimeAttribution::Ambiguous => {
                validate_reason_codes(&self.reason_codes, "binding.reason_codes")?;
                if self.confidence_bps.is_none_or(|value| value > 10_000)
                    || self.alternative_runtime_candidates.is_empty()
                {
                    return Err(ContractError::InvalidField {
                        field: "binding.alternative_runtime_candidates",
                        reason:
                            "ambiguous requires scores and evidence for every retained candidate",
                    });
                }
            }
            RuntimeAttribution::Unattributed => {
                validate_reason_codes(&self.reason_codes, "binding.reason_codes")?;
                if self.confidence_bps.is_some() || !self.alternative_runtime_candidates.is_empty()
                {
                    return Err(ContractError::InvalidField {
                        field: "binding.attribution",
                        reason: "unattributed cannot carry scores or candidates",
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_reason_codes(
    reason_codes: &[String],
    field: &'static str,
) -> Result<(), ContractError> {
    if reason_codes.is_empty() {
        return Err(ContractError::InvalidField {
            field,
            reason: "must not be empty",
        });
    }
    for reason in reason_codes {
        validate_contract_identifier(reason, field)?;
    }
    reject_duplicate_refs(reason_codes.iter().map(String::as_str), field)
}

impl<'de> Deserialize<'de> for RuntimeBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            binding_id: String,
            asserting_source_id: SourceId,
            identity_kind: RuntimeIdentityKind,
            identity_ref: String,
            valid_from_unix_ms: u64,
            valid_until_unix_ms: Option<u64>,
            evidence_basis: RuntimeBindingBasis,
            evidence_basis_ref: String,
            attribution: RuntimeAttribution,
            reason_codes: Vec<String>,
            confidence_bps: Option<u16>,
            alternative_runtime_candidates: Vec<RuntimeBindingCandidate>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            binding_id: wire.binding_id,
            asserting_source_id: wire.asserting_source_id,
            identity_kind: wire.identity_kind,
            identity_ref: wire.identity_ref,
            valid_from_unix_ms: wire.valid_from_unix_ms,
            valid_until_unix_ms: wire.valid_until_unix_ms,
            evidence_basis: wire.evidence_basis,
            evidence_basis_ref: wire.evidence_basis_ref,
            attribution: wire.attribution,
            reason_codes: wire.reason_codes,
            confidence_bps: wire.confidence_bps,
            alternative_runtime_candidates: wire.alternative_runtime_candidates,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Runtime binding after server-side source and policy acceptance.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct AcceptedRuntimeBinding {
    source_registration_id: String,
    source_stream_id: String,
    #[schemars(range(min = 1))]
    registration_policy_revision: u64,
    effective_trust_profile: TrustProfile,
    manifest_version: SchemaVersion,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    manifest_digest: String,
    binding: RuntimeBinding,
}

impl AcceptedRuntimeBinding {
    /// Construct a runtime binding with immutable server acceptance facts.
    pub fn new(
        source_registration_id: impl Into<String>,
        source_stream_id: impl Into<String>,
        registration_policy_revision: u64,
        effective_trust_profile: TrustProfile,
        manifest_version: SchemaVersion,
        manifest_digest: impl Into<String>,
        binding: RuntimeBinding,
    ) -> Result<Self, ContractError> {
        let value = Self {
            source_registration_id: source_registration_id.into(),
            source_stream_id: source_stream_id.into(),
            registration_policy_revision,
            effective_trust_profile,
            manifest_version,
            manifest_digest: manifest_digest.into(),
            binding,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn source_registration_id(&self) -> &str {
        &self.source_registration_id
    }

    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    pub fn registration_policy_revision(&self) -> u64 {
        self.registration_policy_revision
    }

    pub fn effective_trust_profile(&self) -> TrustProfile {
        self.effective_trust_profile
    }

    pub fn manifest_version(&self) -> SchemaVersion {
        self.manifest_version
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn binding(&self) -> &RuntimeBinding {
        &self.binding
    }

    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.source_registration_id, "source_registration_id")?;
        validate_contract_identifier(&self.source_stream_id, "source_stream_id")?;
        if self.registration_policy_revision == 0 {
            return Err(ContractError::InvalidField {
                field: "registration_policy_revision",
                reason: "must be greater than zero",
            });
        }
        validate_sha256_digest(&self.manifest_digest, "manifest_digest")?;
        self.binding.validate()
    }
}

impl<'de> Deserialize<'de> for AcceptedRuntimeBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            source_registration_id: String,
            source_stream_id: String,
            registration_policy_revision: u64,
            effective_trust_profile: TrustProfile,
            manifest_version: SchemaVersion,
            manifest_digest: String,
            binding: RuntimeBinding,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.source_registration_id,
            wire.source_stream_id,
            wire.registration_policy_revision,
            wire.effective_trust_profile,
            wire.manifest_version,
            wire.manifest_digest,
            wire.binding,
        )
        .map_err(de::Error::custom)
    }
}

/// Idempotent request to bind a runtime identity under a run lease.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct BindRuntimeRequest {
    schema_version: SchemaVersion,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    client_operation_id: String,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    request_digest: String,
    run_id: RunId,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    lease_id: RunLeaseId,
    binding: RuntimeBinding,
}

impl BindRuntimeRequest {
    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the client-scoped idempotency identity.
    pub fn client_operation_id(&self) -> &str {
        &self.client_operation_id
    }

    /// Return the client-supplied canonical request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Return the asserted run scope.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the required lease assertion.
    pub fn lease_id(&self) -> &str {
        self.lease_id.as_str()
    }

    /// Return the versioned runtime relation asserted by this request.
    pub fn binding(&self) -> &RuntimeBinding {
        &self.binding
    }

    /// Revalidate invariants at a trusted service boundary.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_idempotency(&self.client_operation_id, &self.request_digest)?;
        validate_contract_identifier(self.lease_id.as_str(), "lease_id")?;
        self.binding.validate()
    }
}

impl<'de> Deserialize<'de> for BindRuntimeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            client_operation_id: String,
            request_digest: String,
            run_id: RunId,
            lease_id: String,
            binding: RuntimeBinding,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            client_operation_id: wire.client_operation_id,
            request_digest: wire.request_digest,
            run_id: wire.run_id,
            lease_id: RunLeaseId::new(wire.lease_id).map_err(de::Error::custom)?,
            binding: wire.binding,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Acknowledgement of a runtime binding operation.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct BindRuntimeResponse {
    schema_version: SchemaVersion,
    run_id: RunId,
    binding_id: String,
    accepted: bool,
    idempotent_replay: bool,
}

impl BindRuntimeResponse {
    /// Construct a validated runtime-binding acknowledgement.
    pub fn new(
        run_id: RunId,
        binding_id: impl Into<String>,
        accepted: bool,
        idempotent_replay: bool,
    ) -> Result<Self, ContractError> {
        let value = Self {
            schema_version: SchemaVersion::V0_1,
            run_id,
            binding_id: binding_id.into(),
            accepted,
            idempotent_replay,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the acknowledged run identity.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the idempotent binding identity.
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Return whether the binding was accepted.
    pub fn accepted(&self) -> bool {
        self.accepted
    }

    /// Return whether this is the original response to an exact retry.
    pub fn idempotent_replay(&self) -> bool {
        self.idempotent_replay
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.binding_id, "binding_id")
    }
}

impl<'de> Deserialize<'de> for BindRuntimeResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            run_id: RunId,
            binding_id: String,
            accepted: bool,
            idempotent_replay: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            binding_id: wire.binding_id,
            accepted: wire.accepted,
            idempotent_replay: wire.idempotent_replay,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Bounded, atomic evidence-ingest request under a source-stream lease.
#[derive(schemars::JsonSchema, Clone, Debug, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct IngestRequest {
    schema_version: SchemaVersion,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    client_operation_id: String,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    request_digest: String,
    run_id: RunId,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    lease_id: RunLeaseId,
    #[schemars(length(min = 1, max = 256))]
    envelopes: Vec<SourceEnvelope>,
}

impl IngestRequest {
    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the client-scoped idempotency identity.
    pub fn client_operation_id(&self) -> &str {
        &self.client_operation_id
    }

    /// Return the client-supplied canonical request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Return the asserted run scope.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the required lease assertion.
    pub fn lease_id(&self) -> &str {
        self.lease_id.as_str()
    }

    /// Return the bounded evidence batch.
    pub fn envelopes(&self) -> &[SourceEnvelope] {
        &self.envelopes
    }

    /// Revalidate invariants at a trusted service boundary.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_idempotency(&self.client_operation_id, &self.request_digest)?;
        validate_contract_identifier(self.lease_id.as_str(), "lease_id")?;
        if self.envelopes.is_empty() {
            return Err(ContractError::InvalidField {
                field: "envelopes",
                reason: "batch must contain at least one envelope",
            });
        }
        if self.envelopes.len() > MAX_INGEST_BATCH_ITEMS {
            return Err(ContractError::InvalidField {
                field: "envelopes",
                reason: "batch must contain at most 256 envelopes",
            });
        }
        for envelope in &self.envelopes {
            envelope.validate()?;
            if envelope.run_id() != &self.run_id {
                return Err(ContractError::InvalidField {
                    field: "envelopes.run_id",
                    reason: "must match the request run_id",
                });
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for IngestRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            client_operation_id: String,
            request_digest: String,
            run_id: RunId,
            lease_id: String,
            envelopes: Vec<SourceEnvelope>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            client_operation_id: wire.client_operation_id,
            request_digest: wire.request_digest,
            run_id: wire.run_id,
            lease_id: RunLeaseId::new(wire.lease_id).map_err(de::Error::custom)?,
            envelopes: wire.envelopes,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Per-envelope durable ingest disposition.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestDisposition {
    /// Newly committed to durable storage.
    Committed,
    /// Exact prior event and digest returned its original acknowledgement.
    Duplicate,
}

/// Per-envelope acknowledgement in an ingest result.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct EnvelopeAck {
    source_event_id: String,
    disposition: IngestDisposition,
    ingest_sequence: Option<u64>,
}

impl EnvelopeAck {
    /// Construct a validated durable per-envelope acknowledgement.
    pub fn new(
        source_event_id: impl Into<String>,
        disposition: IngestDisposition,
        ingest_sequence: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            source_event_id: source_event_id.into(),
            disposition,
            ingest_sequence: Some(ingest_sequence),
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the acknowledged source event identity.
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    /// Return whether this event was newly committed or an exact duplicate.
    pub fn disposition(&self) -> IngestDisposition {
        self.disposition
    }

    /// Return the immutable durable ingest position.
    pub fn ingest_sequence(&self) -> Option<u64> {
        self.ingest_sequence
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.source_event_id, "source_event_id")?;
        match (self.disposition, self.ingest_sequence) {
            (IngestDisposition::Committed | IngestDisposition::Duplicate, Some(sequence))
                if sequence > 0 =>
            {
                Ok(())
            }
            _ => Err(ContractError::InvalidField {
                field: "acknowledgements.ingest_sequence",
                reason: "must be present only for committed or duplicate envelopes",
            }),
        }
    }
}

impl<'de> Deserialize<'de> for EnvelopeAck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            source_event_id: String,
            disposition: IngestDisposition,
            ingest_sequence: Option<u64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            source_event_id: wire.source_event_id,
            disposition: wire.disposition,
            ingest_sequence: wire.ingest_sequence,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Inclusive missing source-sequence range known at acknowledgement time.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct SequenceGap {
    #[schemars(range(min = 1))]
    first_missing_sequence: u64,
    #[schemars(range(min = 1))]
    last_missing_sequence: u64,
}

impl SequenceGap {
    /// Construct a validated inclusive source-sequence gap.
    pub fn new(
        first_missing_sequence: u64,
        last_missing_sequence: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            first_missing_sequence,
            last_missing_sequence,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the first missing source-local sequence.
    pub fn first_missing_sequence(&self) -> u64 {
        self.first_missing_sequence
    }

    /// Return the last missing source-local sequence.
    pub fn last_missing_sequence(&self) -> u64 {
        self.last_missing_sequence
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.first_missing_sequence == 0
            || self.last_missing_sequence < self.first_missing_sequence
        {
            return Err(ContractError::InvalidField {
                field: "known_gaps",
                reason: "gap bounds must be a non-zero inclusive range",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for SequenceGap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            first_missing_sequence: u64,
            last_missing_sequence: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            first_missing_sequence: wire.first_missing_sequence,
            last_missing_sequence: wire.last_missing_sequence,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Durable batch acknowledgement with replay counts and sequence-gap state.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct IngestAck {
    schema_version: SchemaVersion,
    run_id: RunId,
    acknowledgements: Vec<EnvelopeAck>,
    committed_count: u32,
    duplicate_count: u32,
    durable_ingest_watermark: u64,
    source_watermark: u64,
    known_gaps: Vec<SequenceGap>,
}

impl IngestAck {
    /// Construct a validated durable ingest acknowledgement.
    pub fn new(
        run_id: RunId,
        acknowledgements: Vec<EnvelopeAck>,
        durable_ingest_watermark: u64,
        source_watermark: u64,
        known_gaps: Vec<SequenceGap>,
    ) -> Result<Self, ContractError> {
        let committed_count = acknowledgements
            .iter()
            .filter(|ack| ack.disposition == IngestDisposition::Committed)
            .count() as u32;
        let duplicate_count = acknowledgements
            .iter()
            .filter(|ack| ack.disposition == IngestDisposition::Duplicate)
            .count() as u32;
        let value = Self {
            schema_version: SchemaVersion::V0_1,
            run_id,
            acknowledgements,
            committed_count,
            duplicate_count,
            durable_ingest_watermark,
            source_watermark,
            known_gaps,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the acknowledged run identity.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the input-ordered per-envelope acknowledgements.
    pub fn acknowledgements(&self) -> &[EnvelopeAck] {
        &self.acknowledgements
    }

    /// Return the number of newly committed envelopes.
    pub fn committed_count(&self) -> u32 {
        self.committed_count
    }

    /// Return the number of exact replay acknowledgements.
    pub fn duplicate_count(&self) -> u32 {
        self.duplicate_count
    }

    /// Return the highest durable server ingest sequence reflected here.
    pub fn durable_ingest_watermark(&self) -> u64 {
        self.durable_ingest_watermark
    }

    /// Return the highest durable source-local sequence observed by the stream.
    pub fn source_watermark(&self) -> u64 {
        self.source_watermark
    }

    /// Return currently known source-local gaps without fabricating events.
    pub fn known_gaps(&self) -> &[SequenceGap] {
        &self.known_gaps
    }

    fn validate(&self) -> Result<(), ContractError> {
        let mut event_ids = BTreeSet::new();
        let mut committed = 0u32;
        let mut duplicates = 0u32;
        let mut max_ingest_sequence = 0u64;
        for acknowledgement in &self.acknowledgements {
            acknowledgement.validate()?;
            if !event_ids.insert(acknowledgement.source_event_id.as_str()) {
                return Err(ContractError::DuplicateValue {
                    field: "acknowledgements.source_event_id",
                });
            }
            match acknowledgement.disposition {
                IngestDisposition::Committed => committed += 1,
                IngestDisposition::Duplicate => duplicates += 1,
            }
            max_ingest_sequence =
                max_ingest_sequence.max(acknowledgement.ingest_sequence.unwrap_or_default());
        }
        if committed != self.committed_count || duplicates != self.duplicate_count {
            return Err(ContractError::InvalidField {
                field: "committed_count/duplicate_count",
                reason: "must match per-envelope dispositions",
            });
        }
        if max_ingest_sequence > self.durable_ingest_watermark {
            return Err(ContractError::InvalidField {
                field: "durable_ingest_watermark",
                reason: "must include every acknowledged ingest sequence",
            });
        }
        let mut previous_last = 0u64;
        for gap in &self.known_gaps {
            gap.validate()?;
            if gap.last_missing_sequence > self.source_watermark {
                return Err(ContractError::InvalidField {
                    field: "known_gaps",
                    reason: "must not extend beyond source_watermark",
                });
            }
            if gap.first_missing_sequence <= previous_last {
                return Err(ContractError::InvalidField {
                    field: "known_gaps",
                    reason: "must be ordered, unique, and non-overlapping",
                });
            }
            previous_last = gap.last_missing_sequence;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for IngestAck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            run_id: RunId,
            acknowledgements: Vec<EnvelopeAck>,
            committed_count: u32,
            duplicate_count: u32,
            durable_ingest_watermark: u64,
            source_watermark: u64,
            known_gaps: Vec<SequenceGap>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            acknowledgements: wire.acknowledgements,
            committed_count: wire.committed_count,
            duplicate_count: wire.duplicate_count,
            durable_ingest_watermark: wire.durable_ingest_watermark,
            source_watermark: wire.source_watermark,
            known_gaps: wire.known_gaps,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Final declared position for one expected source stream.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct TerminalSourcePosition {
    source_id: SourceId,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    source_stream_id: String,
    #[schemars(range(min = 1))]
    final_source_sequence: u64,
}

impl TerminalSourcePosition {
    /// Construct a validated terminal position for one source stream.
    pub fn new(
        source_id: SourceId,
        source_stream_id: impl Into<String>,
        final_source_sequence: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            source_id,
            source_stream_id: source_stream_id.into(),
            final_source_sequence,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the source identity owning this terminal stream.
    pub fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Return the terminal source stream.
    pub fn source_stream_id(&self) -> &str {
        &self.source_stream_id
    }

    /// Return the declared final source-local position.
    pub fn final_source_sequence(&self) -> u64 {
        self.final_source_sequence
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.source_stream_id, "source_stream_id")?;
        if self.final_source_sequence == 0 {
            return Err(ContractError::InvalidField {
                field: "final_source_sequence",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TerminalSourcePosition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            source_id: SourceId,
            source_stream_id: String,
            final_source_sequence: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            source_id: wire.source_id,
            source_stream_id: wire.source_stream_id,
            final_source_sequence: wire.final_source_sequence,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Idempotent declaration that a run should enter bounded finalization.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct FinishRunRequest {
    schema_version: SchemaVersion,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    client_operation_id: String,
    #[schemars(length(equal = 64), regex(pattern = r"^[0-9a-f]{64}$"))]
    request_digest: String,
    run_id: RunId,
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
    )]
    lease_id: RunLeaseId,
    #[schemars(length(min = 1, max = 256))]
    terminal_positions: Vec<TerminalSourcePosition>,
    #[schemars(length(max = 64))]
    outcome_claim_refs: Vec<String>,
    requested_finalization_deadline_unix_ms: Option<u64>,
}

impl FinishRunRequest {
    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the client-scoped idempotency identity.
    pub fn client_operation_id(&self) -> &str {
        &self.client_operation_id
    }

    /// Return the client-supplied canonical request digest.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    /// Return the asserted run scope.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the required lease assertion.
    pub fn lease_id(&self) -> &str {
        self.lease_id.as_str()
    }

    /// Return expected terminal source positions.
    pub fn terminal_positions(&self) -> &[TerminalSourcePosition] {
        &self.terminal_positions
    }

    /// Return content-free terminal outcome claim references.
    pub fn outcome_claim_refs(&self) -> &[String] {
        &self.outcome_claim_refs
    }

    /// Return the client-requested finalization deadline, when supplied.
    pub fn requested_finalization_deadline_unix_ms(&self) -> Option<u64> {
        self.requested_finalization_deadline_unix_ms
    }

    /// Revalidate invariants at a trusted service boundary.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_idempotency(&self.client_operation_id, &self.request_digest)?;
        validate_contract_identifier(self.lease_id.as_str(), "lease_id")?;
        validate_finalization_inputs(&self.terminal_positions, &self.outcome_claim_refs)?;
        if self
            .requested_finalization_deadline_unix_ms
            .is_some_and(|deadline| deadline == 0)
        {
            return Err(ContractError::InvalidField {
                field: "requested_finalization_deadline_unix_ms",
                reason: "must be greater than zero when present",
            });
        }
        Ok(())
    }
}

fn validate_finalization_inputs(
    terminal_positions: &[TerminalSourcePosition],
    outcome_claim_refs: &[String],
) -> Result<(), ContractError> {
    if terminal_positions.is_empty() || terminal_positions.len() > MAX_TERMINAL_POSITIONS {
        return Err(ContractError::InvalidField {
            field: "terminal_positions",
            reason: "must contain between 1 and 256 source positions",
        });
    }
    let mut streams = BTreeSet::new();
    for position in terminal_positions {
        position.validate()?;
        if !streams.insert(position.source_stream_id.as_str()) {
            return Err(ContractError::DuplicateValue {
                field: "terminal_positions.source_stream_id",
            });
        }
    }
    if outcome_claim_refs.len() > MAX_OUTCOME_CLAIMS {
        return Err(ContractError::InvalidField {
            field: "outcome_claim_refs",
            reason: "must contain at most 64 references",
        });
    }
    for reference in outcome_claim_refs {
        validate_reference(reference, "outcome_claim_refs")?;
    }
    reject_duplicate_refs(
        outcome_claim_refs.iter().map(String::as_str),
        "outcome_claim_refs",
    )
}

impl<'de> Deserialize<'de> for FinishRunRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            client_operation_id: String,
            request_digest: String,
            run_id: RunId,
            lease_id: String,
            terminal_positions: Vec<TerminalSourcePosition>,
            outcome_claim_refs: Vec<String>,
            requested_finalization_deadline_unix_ms: Option<u64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            client_operation_id: wire.client_operation_id,
            request_digest: wire.request_digest,
            run_id: wire.run_id,
            lease_id: RunLeaseId::new(wire.lease_id).map_err(de::Error::custom)?,
            terminal_positions: wire.terminal_positions,
            outcome_claim_refs: wire.outcome_claim_refs,
            requested_finalization_deadline_unix_ms: wire.requested_finalization_deadline_unix_ms,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Server-accepted cumulative declaration used to rebuild finalization.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct AcceptedRunFinalization {
    declared_by_source_registration_id: String,
    declared_by_source_stream_id: String,
    declared_by_principal: PrincipalRef,
    #[schemars(range(min = 1))]
    registration_policy_revision: u64,
    #[schemars(length(min = 1, max = 256))]
    terminal_positions: Vec<TerminalSourcePosition>,
    #[schemars(length(max = 64))]
    outcome_claim_refs: Vec<String>,
    #[schemars(range(min = 1))]
    accepted_deadline_unix_ms: u64,
}

impl AcceptedRunFinalization {
    /// Construct a server-owned cumulative finalization declaration.
    pub fn new(
        declared_by_source_registration_id: impl Into<String>,
        declared_by_source_stream_id: impl Into<String>,
        declared_by_principal: PrincipalRef,
        registration_policy_revision: u64,
        terminal_positions: Vec<TerminalSourcePosition>,
        outcome_claim_refs: Vec<String>,
        accepted_deadline_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            declared_by_source_registration_id: declared_by_source_registration_id.into(),
            declared_by_source_stream_id: declared_by_source_stream_id.into(),
            declared_by_principal,
            registration_policy_revision,
            terminal_positions,
            outcome_claim_refs,
            accepted_deadline_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the authenticated source registration that declared finalization.
    pub fn declared_by_source_registration_id(&self) -> &str {
        &self.declared_by_source_registration_id
    }

    /// Return the lease-bound source stream that declared finalization.
    pub fn declared_by_source_stream_id(&self) -> &str {
        &self.declared_by_source_stream_id
    }

    /// Return the authenticated principal that declared finalization.
    pub fn declared_by_principal(&self) -> &PrincipalRef {
        &self.declared_by_principal
    }

    /// Return the control-plane policy revision used for the declaration.
    pub fn registration_policy_revision(&self) -> u64 {
        self.registration_policy_revision
    }

    /// Return the complete cumulative terminal stream declaration.
    pub fn terminal_positions(&self) -> &[TerminalSourcePosition] {
        &self.terminal_positions
    }

    /// Return the complete cumulative set of claimed outcome references.
    pub fn outcome_claim_refs(&self) -> &[String] {
        &self.outcome_claim_refs
    }

    /// Return the immutable server-bounded deadline accepted for this run.
    pub fn accepted_deadline_unix_ms(&self) -> u64 {
        self.accepted_deadline_unix_ms
    }

    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(
            &self.declared_by_source_registration_id,
            "declared_by_source_registration_id",
        )?;
        validate_contract_identifier(
            &self.declared_by_source_stream_id,
            "declared_by_source_stream_id",
        )?;
        self.declared_by_principal.validate()?;
        if self.registration_policy_revision == 0 || self.accepted_deadline_unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "registration_policy_revision/accepted_deadline_unix_ms",
                reason: "must be greater than zero",
            });
        }
        validate_finalization_inputs(&self.terminal_positions, &self.outcome_claim_refs)
    }
}

impl<'de> Deserialize<'de> for AcceptedRunFinalization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            declared_by_source_registration_id: String,
            declared_by_source_stream_id: String,
            declared_by_principal: PrincipalRef,
            registration_policy_revision: u64,
            terminal_positions: Vec<TerminalSourcePosition>,
            outcome_claim_refs: Vec<String>,
            accepted_deadline_unix_ms: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.declared_by_source_registration_id,
            wire.declared_by_source_stream_id,
            wire.declared_by_principal,
            wire.registration_policy_revision,
            wire.terminal_positions,
            wire.outcome_claim_refs,
            wire.accepted_deadline_unix_ms,
        )
        .map_err(de::Error::custom)
    }
}

/// Gateway-assigned finalization state and deadline.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct FinishRunResponse {
    schema_version: SchemaVersion,
    run_id: RunId,
    state: RunState,
    finalization_deadline_unix_ms: Option<u64>,
    idempotent_replay: bool,
}

impl FinishRunResponse {
    /// Construct a validated finalization response.
    pub fn new(
        run_id: RunId,
        state: RunState,
        finalization_deadline_unix_ms: Option<u64>,
        idempotent_replay: bool,
    ) -> Result<Self, ContractError> {
        let value = Self {
            schema_version: SchemaVersion::V0_1,
            run_id,
            state,
            finalization_deadline_unix_ms,
            idempotent_replay,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the finalized run identity.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the accepted finalization lifecycle state.
    pub fn state(&self) -> RunState {
        self.state
    }

    /// Return the server-assigned finalization deadline while finishing.
    pub fn finalization_deadline_unix_ms(&self) -> Option<u64> {
        self.finalization_deadline_unix_ms
    }

    /// Return whether this is the original response to an exact retry.
    pub fn idempotent_replay(&self) -> bool {
        self.idempotent_replay
    }

    fn validate(&self) -> Result<(), ContractError> {
        match (self.state, self.finalization_deadline_unix_ms) {
            (RunState::Finishing, Some(deadline)) if deadline > 0 => Ok(()),
            (RunState::Finished | RunState::Incomplete, None) => Ok(()),
            _ => Err(ContractError::InvalidField {
                field: "state/finalization_deadline_unix_ms",
                reason: "finishing requires a deadline; sealed states must omit it",
            }),
        }
    }
}

impl<'de> Deserialize<'de> for FinishRunResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            run_id: RunId,
            state: RunState,
            finalization_deadline_unix_ms: Option<u64>,
            idempotent_replay: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            run_id: wire.run_id,
            state: wire.state,
            finalization_deadline_unix_ms: wire.finalization_deadline_unix_ms,
            idempotent_replay: wire.idempotent_replay,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Closed v0.1 wire error vocabulary for all Gateway operations.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractErrorCode {
    /// No acceptable transport identity was supplied.
    Unauthenticated,
    /// The authenticated principal lacks this operation.
    Forbidden,
    /// Enumeration-safe missing or cross-organization resource result.
    NotFound,
    /// Request schema version is not supported.
    UnsupportedContractVersion,
    /// Source payload version is not supported.
    UnsupportedSourceVersion,
    /// Request violates the selected wire contract.
    InvalidContract,
    /// Operation is not legal in the current run state.
    InvalidLifecycleTransition,
    /// Lease passed its server-controlled expiry.
    LeaseExpired,
    /// Lease was explicitly revoked.
    LeaseRevoked,
    /// Lease is not scoped to this run, source, stream, or operation.
    LeaseScopeMismatch,
    /// Operation identity was reused with different content.
    IdempotencyConflict,
    /// Source event identity was reused with different content.
    SourceEventConflict,
    /// A source sequence contradicts durable stream state.
    SequenceConflict,
    /// Source registration does not permit this evidence capability.
    CapabilityMismatch,
    /// Required edge or Gateway redaction was not applied.
    RedactionRequired,
    /// Content capture exceeds the authorized privacy ceiling.
    ContentNotAuthorized,
    /// Requested retention exceeds the organization ceiling.
    RetentionNotAuthorized,
    /// Request exceeds the bounded batch limit.
    BatchTooLarge,
    /// Capacity is temporarily unavailable and nothing novel committed.
    Backpressure,
    /// Principal or organization rate limit was reached.
    RateLimited,
    /// Query cursor signature, shape, or scope is invalid.
    CursorInvalid,
    /// Query cursor is valid but no longer retained.
    CursorExpired,
    /// Required projection is unavailable; durable ingest may still exist.
    ProjectionUnavailable,
}

/// Safe, enumeration-resistant Gateway error body.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct GatewayErrorResponse {
    schema_version: SchemaVersion,
    code: ContractErrorCode,
    message: String,
    retryable: bool,
    retry_after_ms: Option<u64>,
}

impl GatewayErrorResponse {
    /// Construct a validated, enumeration-safe Gateway error body.
    pub fn new(
        code: ContractErrorCode,
        message: impl Into<String>,
        retryable: bool,
        retry_after_ms: Option<u64>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            schema_version: SchemaVersion::V0_1,
            code,
            message: message.into(),
            retryable,
            retry_after_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the wire schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the stable machine error code.
    pub fn code(&self) -> ContractErrorCode {
        self.code
    }

    /// Return safe text suitable for the authenticated caller.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return whether an exact request may be retried.
    pub fn retryable(&self) -> bool {
        self.retryable
    }

    /// Return a bounded server retry hint when supplied.
    pub fn retry_after_ms(&self) -> Option<u64> {
        self.retry_after_ms
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_reference(&self.message, "message")?;
        if self.retry_after_ms.is_some() && !self.retryable {
            return Err(ContractError::InvalidField {
                field: "retry_after_ms",
                reason: "must be absent for a non-retryable error",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GatewayErrorResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            code: ContractErrorCode,
            message: String,
            retryable: bool,
            retry_after_ms: Option<u64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            code: wire.code,
            message: wire.message,
            retryable: wire.retryable,
            retry_after_ms: wire.retry_after_ms,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

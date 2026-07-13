// SPDX-License-Identifier: Apache-2.0

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    id::{validate_contract_identifier, validate_reference},
    ContractError, OrganizationId, RunId, SchemaVersion,
};

/// The supported environment profiles for an Agent Run.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentKind {
    /// Local CLI or IDE integration.
    LocalCliOrIde,
    /// CI runner or remote development workspace.
    CiRunnerOrRemoteWorkspace,
    /// Vendor-hosted coding-agent sandbox.
    VendorHostedCodingSandbox,
    /// Customer-built agent service.
    CustomerBuiltAgentService,
    /// Fully managed agent runtime.
    FullyManagedAgentRuntime,
}

/// The kind of boundary that authorized a run.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    /// A human-controlled authorization boundary.
    Human,
    /// A service-controlled authorization boundary.
    Service,
    /// A policy-controlled authorization boundary.
    Policy,
}

/// A content-free reference to the Authority that permits a run.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct AuthorityRef {
    kind: AuthorityKind,
    id: String,
}

impl AuthorityRef {
    /// Create a validated Authority reference.
    pub fn new(kind: AuthorityKind, id: impl Into<String>) -> Result<Self, ContractError> {
        let value = Self {
            kind,
            id: id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the Authority boundary kind.
    pub fn kind(&self) -> AuthorityKind {
        self.kind
    }

    /// Borrow the opaque Authority reference.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.id, "authority.id")
    }
}

impl<'de> Deserialize<'de> for AuthorityRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: AuthorityKind,
            id: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.kind, wire.id).map_err(de::Error::custom)
    }
}

/// The kind of authenticated identity acting within an Authority.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// An authenticated human identity.
    Human,
    /// An authenticated workload identity.
    Workload,
}

/// A content-free reference to the Principal acting in a run.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct PrincipalRef {
    kind: PrincipalKind,
    id: String,
}

impl PrincipalRef {
    /// Create a validated Principal reference.
    pub fn new(kind: PrincipalKind, id: impl Into<String>) -> Result<Self, ContractError> {
        let value = Self {
            kind,
            id: id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the Principal identity kind.
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Borrow the opaque Principal reference.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_contract_identifier(&self.id, "principal.id")
    }
}

impl<'de> Deserialize<'de> for PrincipalRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: PrincipalKind,
            id: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.kind, wire.id).map_err(de::Error::custom)
    }
}

/// Lifecycle states for an Agent Run.
#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Identity and source policy are being validated.
    Opening,
    /// Registered sources may contribute evidence.
    Active,
    /// Terminal declarations and gaps are being reconciled.
    Finishing,
    /// The run is sealed without an unresolved required-source gap.
    Finished,
    /// The run is sealed with at least one terminal or evidence gap.
    Incomplete,
}

impl RunState {
    /// Return whether v0.1 permits a transition from this state to `next`.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Opening, Self::Active | Self::Incomplete)
                | (Self::Active, Self::Finishing | Self::Incomplete)
                | (Self::Finishing, Self::Finished | Self::Incomplete)
        )
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Finishing => "finishing",
            Self::Finished => "finished",
            Self::Incomplete => "incomplete",
        }
    }
}

/// The immutable opening descriptor and current state for an Agent Run.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RunDescriptor {
    schema_version: SchemaVersion,
    organization_id: OrganizationId,
    run_id: RunId,
    authority: AuthorityRef,
    principal: PrincipalRef,
    objective_ref: String,
    environment: EnvironmentKind,
    state: RunState,
}

impl RunDescriptor {
    /// Create a run descriptor in the mandatory `opening` state.
    pub fn new(
        organization_id: impl AsRef<str>,
        run_id: impl AsRef<str>,
        authority: AuthorityRef,
        principal: PrincipalRef,
        objective_ref: impl Into<String>,
        environment: EnvironmentKind,
    ) -> Result<Self, ContractError> {
        let value = Self {
            schema_version: SchemaVersion::V0_1,
            organization_id: OrganizationId::try_from(organization_id.as_ref())?,
            run_id: RunId::try_from(run_id.as_ref())?,
            authority,
            principal,
            objective_ref: objective_ref.into(),
            environment,
            state: RunState::Opening,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the v0.1 schema marker.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Return the organization scope.
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Return the canonical Agent Run identifier.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Return the current lifecycle state.
    pub fn state(&self) -> RunState {
        self.state
    }

    /// Move the descriptor through one legal v0.1 lifecycle transition.
    pub fn transition_to(&mut self, next: RunState) -> Result<(), ContractError> {
        if !self.state.can_transition_to(next) {
            return Err(ContractError::InvalidTransition {
                from: self.state.as_str(),
                to: next.as_str(),
            });
        }
        self.state = next;
        Ok(())
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.authority.validate()?;
        self.principal.validate()?;
        validate_reference(&self.objective_ref, "objective_ref")
    }
}

impl<'de> Deserialize<'de> for RunDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: SchemaVersion,
            organization_id: OrganizationId,
            run_id: RunId,
            authority: AuthorityRef,
            principal: PrincipalRef,
            objective_ref: String,
            environment: EnvironmentKind,
            state: RunState,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            organization_id: wire.organization_id,
            run_id: wire.run_id,
            authority: wire.authority,
            principal: wire.principal,
            objective_ref: wire.objective_ref,
            environment: wire.environment,
            state: wire.state,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// An append-only lifecycle fact retained in an Agent Execution Record.
#[derive(schemars::JsonSchema, Clone, Debug, Eq, PartialEq, Serialize)]
#[schemars(deny_unknown_fields)]
pub struct RunStateTransition {
    /// State before the transition.
    from: RunState,
    /// State after the transition.
    to: RunState,
    /// Server-recorded transition time.
    #[schemars(range(min = 1))]
    recorded_at_unix_ms: u64,
}

impl<'de> Deserialize<'de> for RunStateTransition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(schemars::JsonSchema, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            from: RunState,
            to: RunState,
            recorded_at_unix_ms: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            from: wire.from,
            to: wire.to,
            recorded_at_unix_ms: wire.recorded_at_unix_ms,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl RunStateTransition {
    /// Create and validate one append-only lifecycle fact.
    pub fn new(
        from: RunState,
        to: RunState,
        recorded_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            from,
            to,
            recorded_at_unix_ms,
        };
        value.validate()?;
        Ok(value)
    }

    /// Return the state before the transition.
    pub fn from(&self) -> RunState {
        self.from
    }

    /// Return the state after the transition.
    pub fn to(&self) -> RunState {
        self.to
    }

    /// Validate this fact against the v0.1 lifecycle.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !self.from.can_transition_to(self.to) {
            return Err(ContractError::InvalidTransition {
                from: self.from.as_str(),
                to: self.to.as_str(),
            });
        }
        if self.recorded_at_unix_ms == 0 {
            return Err(ContractError::InvalidField {
                field: "recorded_at_unix_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

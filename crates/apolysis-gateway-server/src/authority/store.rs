// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, OrganizationId, PrincipalRef,
    SourceRegistrationPolicy,
};
use sqlx::{postgres::PgPoolOptions, Connection, PgConnection, PgPool, Postgres, Row, Transaction};

use super::{
    certificate::{credential_id, mtls_leaf_fingerprint, ClientCertificate},
    input::{
        checked_database_integer, current_unix_ms, validate_contract_identifier,
        MAX_CERTIFICATE_PEM_BYTES, MAX_DATABASE_URL_BYTES,
    },
    policy::{
        parse_principal_kind, policy_allows_operation, principal_kind_as_str,
        validate_registration_update, RegistrationDocument, StoredPolicy,
    },
};
use crate::GatewayServerError;

/// PostgreSQL-backed current authority for direct-mTLS Gateway requests.
///
/// The store deliberately retains only a connection pool. Every resolution
/// re-reads credential, organization, registration, policy revision, epoch,
/// validity, and revocation state in one database transaction.
#[derive(Clone)]
pub struct AuthorityStore {
    pool: PgPool,
}

async fn qualify_served_connection(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    let has_origin_replication_role: bool =
        sqlx::query_scalar("SELECT current_setting('session_replication_role', false) = 'origin'")
            .fetch_one(connection)
            .await?;
    if !has_origin_replication_role {
        return Err(sqlx::Error::Protocol(
            "served PostgreSQL session failed qualification".to_string(),
        ));
    }
    Ok(())
}

impl AuthorityStore {
    /// Connect to an already-migrated Gateway database.
    ///
    /// Request-serving and authority-administration runtimes use this path so
    /// their database roles do not require schema-owner privileges. Every
    /// physical connection is qualified for normal trigger execution before
    /// pool use.
    pub async fn connect(database_url: &str) -> Result<Self, GatewayServerError> {
        if database_url.is_empty() || database_url.len() > MAX_DATABASE_URL_BYTES {
            return Err(GatewayServerError::configuration(
                "Gateway database URL is invalid",
            ));
        }

        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(10))
            .after_connect(|connection, _metadata| {
                Box::pin(async move { qualify_served_connection(connection).await })
            })
            .connect(database_url)
            .await
            .map_err(GatewayServerError::database)?;

        Ok(Self { pool })
    }

    /// Apply the ledger and current-authority migrations in reviewed order.
    ///
    /// This is reserved for the explicit `migrate` administration command.
    pub async fn migrate(database_url: &str) -> Result<(), GatewayServerError> {
        if database_url.is_empty() || database_url.len() > MAX_DATABASE_URL_BYTES {
            return Err(GatewayServerError::configuration(
                "Gateway database URL is invalid",
            ));
        }

        // Migration role changes must never escape into a serving pool. A
        // dedicated connection is dropped on both success and failure.
        let mut connection = PgConnection::connect(database_url)
            .await
            .map_err(GatewayServerError::database)?;
        sqlx::query("SET ROLE apolysis_schema_owner")
            .execute(&mut connection)
            .await
            .map_err(GatewayServerError::database)?;
        // sqlx deliberately keeps its migration history in public. Pin that
        // one explicit schema after role elevation: PostgreSQL searches the
        // omitted pg_catalog first, and this fresh connection cannot contain
        // caller-created temporary objects.
        sqlx::query("SET search_path = public")
            .execute(&mut connection)
            .await
            .map_err(GatewayServerError::database)?;
        apolysis_gateway_postgres::MIGRATOR
            .run(&mut connection)
            .await
            .map_err(migration_error)
    }

    /// Resolve the peer leaf certificate against current PostgreSQL authority.
    ///
    /// `leaf_der` is never persisted. Its domain-separated SHA-256 digest is
    /// used as the lookup key and as the only certificate-derived audit value.
    /// The transport caller supplies a leaf already authenticated by mTLS, one
    /// of the fixed Gateway route operations, and its trusted system-clock
    /// reading. Violations of those caller preconditions fail before an
    /// authority decision; every valid admission attempt is resolved and
    /// audited in PostgreSQL.
    pub async fn resolve_mtls(
        &self,
        leaf_der: &[u8],
        operation: &str,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedSourceContext, GatewayServerError> {
        validate_resolution_input(leaf_der, operation, now_unix_ms)?;
        let fingerprint = mtls_leaf_fingerprint(leaf_der);
        let now = checked_database_integer(now_unix_ms, "Gateway clock is invalid")?;

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GatewayServerError::database)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_gateway_authority_by_fingerprint($1)",
        )
        .bind(fingerprint.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;
        let row = sqlx::query(
            "SELECT credential.credential_id, credential.organization_id, \
                    credential.source_registration_id, \
                    credential.credential_epoch AS transport_credential_epoch, \
                    credential.effective_at_unix_ms AS credential_effective_at_unix_ms, \
                    credential.expires_at_unix_ms AS credential_expires_at_unix_ms, \
                    credential.revoked_at_unix_ms, \
                    organization.organization_state, \
                    registration.source_id, registration.principal_kind, \
                    registration.principal_id, registration.registration_state, \
                    registration.policy_revision, \
                    registration.credential_epoch AS registration_credential_epoch, \
                    registration.effective_at_unix_ms AS registration_effective_at_unix_ms, \
                    registration.expires_at_unix_ms AS registration_expires_at_unix_ms, \
                    registration.policy_document \
             FROM apolysis_gateway.transport_credentials AS credential \
             JOIN apolysis_gateway.organizations AS organization \
               ON organization.organization_id=credential.organization_id \
             JOIN apolysis_gateway.source_registrations AS registration \
               ON registration.organization_id=credential.organization_id \
              AND registration.source_registration_id=credential.source_registration_id \
             WHERE credential.certificate_fingerprint=$1",
        )
        .bind(fingerprint.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        let Some(row) = row else {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                AuditIdentity::default(),
                "unknown_credential",
                false,
            )
            .await;
        };
        let authority = match AuthorityRow::decode(&row) {
            Ok(authority) => authority,
            Err(_) => {
                return finish_denial(
                    transaction,
                    &fingerprint,
                    operation,
                    now,
                    AuditIdentity::default(),
                    "authority_state_inconsistent",
                    false,
                )
                .await;
            }
        };
        let audit_identity = authority.audit_identity();

        if authority.organization_state != "active" {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "organization_inactive",
                false,
            )
            .await;
        }
        if authority.revoked_at_unix_ms.is_some() {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "credential_revoked",
                false,
            )
            .await;
        }
        if now < authority.credential_effective_at_unix_ms {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "credential_not_yet_effective",
                false,
            )
            .await;
        }
        if now >= authority.credential_expires_at_unix_ms {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "credential_expired",
                false,
            )
            .await;
        }
        if authority.registration_state != "active" {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "registration_inactive",
                false,
            )
            .await;
        }
        if now < authority.registration_effective_at_unix_ms {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "registration_not_yet_effective",
                false,
            )
            .await;
        }
        if now >= authority.registration_expires_at_unix_ms {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "registration_expired",
                false,
            )
            .await;
        }
        if authority.transport_credential_epoch != authority.registration_credential_epoch {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "credential_epoch_mismatch",
                false,
            )
            .await;
        }

        let stored_policy =
            match serde_json::from_value::<StoredPolicy>(authority.policy_document.clone()) {
                Ok(policy) => policy,
                Err(_) => {
                    return finish_denial(
                        transaction,
                        &fingerprint,
                        operation,
                        now,
                        audit_identity,
                        "invalid_policy",
                        false,
                    )
                    .await;
                }
            };
        if stored_policy.source_id.as_str() != authority.source_id {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "authority_state_inconsistent",
                false,
            )
            .await;
        }
        let registration_policy = match stored_policy.build_policy() {
            Ok(policy) => policy,
            Err(_) => {
                return finish_denial(
                    transaction,
                    &fingerprint,
                    operation,
                    now,
                    audit_identity,
                    "invalid_policy",
                    false,
                )
                .await;
            }
        };
        if !policy_allows_operation(&registration_policy, operation) {
            return finish_denial(
                transaction,
                &fingerprint,
                operation,
                now,
                audit_identity,
                "operation_forbidden",
                true,
            )
            .await;
        }

        let context = match authority.authenticated_context(registration_policy, now_unix_ms) {
            Ok(context) => context,
            Err(()) => {
                return finish_denial(
                    transaction,
                    &fingerprint,
                    operation,
                    now,
                    audit_identity,
                    "authority_state_inconsistent",
                    false,
                )
                .await;
            }
        };

        record_gateway_audit(
            &mut transaction,
            &fingerprint,
            operation,
            now,
            "authorized",
            "current_authority",
            audit_identity,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(GatewayServerError::database)?;
        Ok(context)
    }

    pub(super) async fn register_source(
        &self,
        registration: RegistrationDocument,
        certificate: ClientCertificate,
    ) -> Result<(), GatewayServerError> {
        let now_unix_ms = current_unix_ms()?;
        registration.validate(now_unix_ms, &certificate)?;
        let stored_policy = registration.stored_policy();
        stored_policy
            .build_policy()
            .map_err(|_| GatewayServerError::configuration("Source policy is invalid"))?;
        let policy_document = serde_json::to_value(&stored_policy)
            .map_err(|_| GatewayServerError::configuration("Source policy serialization failed"))?;
        let now = checked_database_integer(now_unix_ms, "Gateway clock is invalid")?;
        let policy_revision = checked_database_integer(
            registration.policy_revision,
            "Source policy revision is invalid",
        )?;
        let credential_epoch = checked_database_integer(
            registration.credential_epoch,
            "Transport credential epoch is invalid",
        )?;
        let effective_at_unix_ms = checked_database_integer(
            registration.effective_at_unix_ms,
            "Source registration validity is invalid",
        )?;
        let expires_at_unix_ms = checked_database_integer(
            registration.expires_at_unix_ms,
            "Source registration validity is invalid",
        )?;
        let credential_id = credential_id(&certificate.fingerprint);

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GatewayServerError::database)?;

        // Missing rows cannot be locked. Transaction-scoped advisory locks
        // serialize first registration, re-registration, and rotation for an
        // organization and registration before any current-state read. The
        // fixed domain seed keeps this lock namespace separate from callers
        // that may also use hashtextextended-backed locks.
        for authority_key in [
            format!("organization:{}", registration.organization_id.as_str()),
            format!("registration:{}", registration.source_registration_id),
        ] {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4715382012602313075))")
                .bind(authority_key)
                .execute(&mut *transaction)
                .await
                .map_err(GatewayServerError::database)?;
        }

        // Every authority path that spans these rows takes locks in the same
        // hierarchy. In particular, evidence admission resolves organization
        // then registration then credential, so control-plane writes must not
        // acquire a credential while they can still wait on either ancestor.
        sqlx::query(
            "SELECT organization_id \
             FROM apolysis_gateway.organizations \
             WHERE organization_id=$1 \
             FOR UPDATE",
        )
        .bind(registration.organization_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        if let Some(existing) = sqlx::query(
            "SELECT organization_id \
             FROM apolysis_gateway.source_registrations \
             WHERE source_registration_id=$1 \
             FOR UPDATE",
        )
        .bind(&registration.source_registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        {
            let existing_organization: String = existing
                .try_get("organization_id")
                .map_err(GatewayServerError::database)?;
            if existing_organization != registration.organization_id.as_str() {
                return Err(GatewayServerError::configuration(
                    "Source registration identity is immutable",
                ));
            }
        }

        if let Some(existing) = sqlx::query(
            "SELECT organization_id, source_registration_id, revoked_at_unix_ms \
             FROM apolysis_gateway.transport_credentials \
             WHERE certificate_fingerprint=$1 \
             FOR UPDATE",
        )
        .bind(certificate.fingerprint.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        {
            let existing_organization: String = existing
                .try_get("organization_id")
                .map_err(GatewayServerError::database)?;
            let existing_registration: String = existing
                .try_get("source_registration_id")
                .map_err(GatewayServerError::database)?;
            let existing_revocation: Option<i64> = existing
                .try_get("revoked_at_unix_ms")
                .map_err(GatewayServerError::database)?;
            if existing_organization != registration.organization_id.as_str()
                || existing_registration != registration.source_registration_id
            {
                return Err(GatewayServerError::configuration(
                    "Client certificate is already bound to another source",
                ));
            }
            if existing_revocation.is_some() {
                return Err(GatewayServerError::configuration(
                    "A revoked client certificate cannot be registered again",
                ));
            }
        }

        if let Some(existing) = sqlx::query(
            "SELECT registration.organization_id, registration.source_id, \
                    registration.principal_kind, registration.principal_id, \
                    registration.registration_state, registration.policy_revision, \
                    registration.credential_epoch, registration.effective_at_unix_ms, \
                    registration.expires_at_unix_ms, registration.policy_document, \
                    organization.organization_state \
             FROM apolysis_gateway.source_registrations AS registration \
             JOIN apolysis_gateway.organizations AS organization \
               ON organization.organization_id=registration.organization_id \
             WHERE registration.source_registration_id=$1",
        )
        .bind(&registration.source_registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        {
            validate_registration_update(&existing, &registration, &policy_document)?;

            let credentials = sqlx::query(
                "SELECT certificate_fingerprint, revoked_at_unix_ms \
                 FROM apolysis_gateway.transport_credentials \
                 WHERE source_registration_id=$1 \
                 ORDER BY certificate_fingerprint \
                 FOR UPDATE",
            )
            .bind(&registration.source_registration_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(GatewayServerError::database)?;
            let mut matching_current_credential = false;
            let mut other_current_credential = false;
            for current_credential in credentials {
                let existing_fingerprint: Vec<u8> = current_credential
                    .try_get("certificate_fingerprint")
                    .map_err(GatewayServerError::database)?;
                let revoked: Option<i64> = current_credential
                    .try_get("revoked_at_unix_ms")
                    .map_err(GatewayServerError::database)?;
                if revoked.is_none() {
                    if existing_fingerprint == certificate.fingerprint {
                        matching_current_credential = true;
                    } else {
                        other_current_credential = true;
                    }
                }
            }
            if !matching_current_credential || other_current_credential {
                return Err(GatewayServerError::configuration(
                    "Source authority updates require the credential rotation gate",
                ));
            }
        }

        sqlx::query(
            "INSERT INTO apolysis_gateway.organizations ( \
                 organization_id, organization_state, created_at_unix_ms, updated_at_unix_ms \
             ) VALUES ($1, $2, $3, $3) \
             ON CONFLICT (organization_id) DO UPDATE SET \
                 organization_state=EXCLUDED.organization_state, \
                 updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
        )
        .bind(registration.organization_id.as_str())
        .bind(registration.organization_state.as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        sqlx::query(
            "INSERT INTO apolysis_gateway.source_registrations ( \
                 source_registration_id, organization_id, source_id, principal_kind, \
                 principal_id, registration_state, policy_revision, credential_epoch, \
                 effective_at_unix_ms, expires_at_unix_ms, policy_document, \
                 created_at_unix_ms, updated_at_unix_ms \
             ) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11, $11) \
             ON CONFLICT (source_registration_id) DO UPDATE SET \
                 organization_id=EXCLUDED.organization_id, \
                 source_id=EXCLUDED.source_id, \
                 principal_kind=EXCLUDED.principal_kind, \
                 principal_id=EXCLUDED.principal_id, \
                 registration_state='active', \
                 policy_revision=EXCLUDED.policy_revision, \
                 credential_epoch=EXCLUDED.credential_epoch, \
                 effective_at_unix_ms=EXCLUDED.effective_at_unix_ms, \
                 expires_at_unix_ms=EXCLUDED.expires_at_unix_ms, \
                 policy_document=EXCLUDED.policy_document, \
                 updated_at_unix_ms=EXCLUDED.updated_at_unix_ms",
        )
        .bind(&registration.source_registration_id)
        .bind(registration.organization_id.as_str())
        .bind(registration.source_id.as_str())
        .bind(principal_kind_as_str(registration.principal.kind()))
        .bind(registration.principal.id())
        .bind(policy_revision)
        .bind(credential_epoch)
        .bind(effective_at_unix_ms)
        .bind(expires_at_unix_ms)
        .bind(&policy_document)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        let credential_update = sqlx::query(
            "INSERT INTO apolysis_gateway.transport_credentials ( \
                 credential_id, certificate_fingerprint, organization_id, \
                 source_registration_id, credential_epoch, effective_at_unix_ms, \
                 expires_at_unix_ms, revoked_at_unix_ms, revocation_reason, \
                 created_at_unix_ms, updated_at_unix_ms \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, $8, $8) \
             ON CONFLICT (credential_id) DO UPDATE SET \
                 credential_epoch=EXCLUDED.credential_epoch, \
                 effective_at_unix_ms=EXCLUDED.effective_at_unix_ms, \
                 expires_at_unix_ms=EXCLUDED.expires_at_unix_ms, \
                 updated_at_unix_ms=EXCLUDED.updated_at_unix_ms \
             WHERE apolysis_gateway.transport_credentials.organization_id=EXCLUDED.organization_id \
               AND apolysis_gateway.transport_credentials.source_registration_id=EXCLUDED.source_registration_id \
               AND apolysis_gateway.transport_credentials.certificate_fingerprint=EXCLUDED.certificate_fingerprint",
        )
        .bind(&credential_id)
        .bind(certificate.fingerprint.as_slice())
        .bind(registration.organization_id.as_str())
        .bind(&registration.source_registration_id)
        .bind(credential_epoch)
        .bind(effective_at_unix_ms)
        .bind(expires_at_unix_ms)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;
        if credential_update.rows_affected() != 1 {
            return Err(GatewayServerError::configuration(
                "Client certificate binding conflicts with current authority",
            ));
        }

        record_source_authority_revision(
            &mut transaction,
            AuthorityRevisionRecord {
                organization_id: registration.organization_id.as_str(),
                source_registration_id: &registration.source_registration_id,
                credential_id: &credential_id,
                credential_epoch,
                policy_revision,
                policy_document: &policy_document,
                effective_at_unix_ms,
                expires_at_unix_ms,
                recorded_at_unix_ms: now,
            },
        )
        .await?;

        sqlx::query(
            "INSERT INTO apolysis_gateway.authority_change_audit ( \
                 occurred_at_unix_ms, action, reason_code, organization_id, \
                 source_registration_id, credential_id, policy_revision, credential_epoch \
             ) VALUES ($1, 'register_source', 'source_registered', $2, $3, $4, $5, $6)",
        )
        .bind(now)
        .bind(registration.organization_id.as_str())
        .bind(&registration.source_registration_id)
        .bind(&credential_id)
        .bind(policy_revision)
        .bind(credential_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        transaction
            .commit()
            .await
            .map_err(GatewayServerError::database)?;
        Ok(())
    }

    pub(super) async fn rotate_policy(
        &self,
        registration: RegistrationDocument,
        current_certificate: ClientCertificate,
        reason: &str,
    ) -> Result<(), GatewayServerError> {
        let current_fingerprint = current_certificate.fingerprint;
        let mut prepared =
            PreparedAuthorityUpdate::new(registration, &current_certificate, reason)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GatewayServerError::database)?;
        let current = lock_rotation_authority(
            &mut transaction,
            &prepared.registration,
            &current_fingerprint,
        )
        .await?;
        prepared.refresh_cutover_time(&current_certificate)?;

        let expected_policy_revision = current.policy_revision.checked_add(1).ok_or_else(|| {
            GatewayServerError::configuration("Policy rotation sequence is invalid")
        })?;
        if prepared.policy_revision != expected_policy_revision
            || prepared.credential_epoch != current.credential_epoch
        {
            return Err(GatewayServerError::configuration(
                "Policy rotation sequence is invalid",
            ));
        }

        let registration_update = sqlx::query(
            "UPDATE apolysis_gateway.source_registrations \
             SET policy_revision=$1, effective_at_unix_ms=$2, expires_at_unix_ms=$3, \
                 policy_document=$4, updated_at_unix_ms=$5 \
             WHERE organization_id=$6 AND source_registration_id=$7 \
               AND policy_revision=$8 AND credential_epoch=$9 \
               AND registration_state='active'",
        )
        .bind(prepared.policy_revision)
        .bind(prepared.effective_at_unix_ms)
        .bind(prepared.expires_at_unix_ms)
        .bind(&prepared.policy_document)
        .bind(prepared.now)
        .bind(prepared.registration.organization_id.as_str())
        .bind(&prepared.registration.source_registration_id)
        .bind(current.policy_revision)
        .bind(current.credential_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;
        if registration_update.rows_affected() != 1 {
            return Err(GatewayServerError::configuration(
                "Source authority updates require the credential rotation gate",
            ));
        }

        let credential_update = sqlx::query(
            "UPDATE apolysis_gateway.transport_credentials \
             SET effective_at_unix_ms=$1, expires_at_unix_ms=$2, \
                 updated_at_unix_ms=$3 \
             WHERE credential_id=$4 AND organization_id=$5 \
               AND source_registration_id=$6 AND credential_epoch=$7 \
               AND revoked_at_unix_ms IS NULL",
        )
        .bind(prepared.effective_at_unix_ms)
        .bind(prepared.expires_at_unix_ms)
        .bind(prepared.now)
        .bind(&current.credential_id)
        .bind(prepared.registration.organization_id.as_str())
        .bind(&prepared.registration.source_registration_id)
        .bind(current.credential_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;
        if credential_update.rows_affected() != 1 {
            return Err(GatewayServerError::configuration(
                "Source authority updates require the credential rotation gate",
            ));
        }

        record_source_authority_revision(
            &mut transaction,
            AuthorityRevisionRecord::from_prepared(&current.credential_id, &prepared),
        )
        .await?;
        invalidate_rotated_authority(
            &mut transaction,
            prepared.registration.organization_id.as_str(),
            &prepared.registration.source_registration_id,
            prepared.now,
        )
        .await?;
        record_authority_change(
            &mut transaction,
            "rotate_policy",
            reason,
            &current.credential_id,
            &prepared,
        )
        .await?;

        transaction
            .commit()
            .await
            .map_err(GatewayServerError::database)
    }

    pub(super) async fn rotate_credential(
        &self,
        registration: RegistrationDocument,
        current_certificate: ClientCertificate,
        replacement_certificate: ClientCertificate,
        reason: &str,
    ) -> Result<(), GatewayServerError> {
        if current_certificate.fingerprint == replacement_certificate.fingerprint {
            return Err(GatewayServerError::configuration(
                "Client certificate binding conflicts with current authority",
            ));
        }
        let current_fingerprint = current_certificate.fingerprint;
        let replacement_credential_id = credential_id(&replacement_certificate.fingerprint);
        let replacement_fingerprint = replacement_certificate.fingerprint;
        let mut prepared =
            PreparedAuthorityUpdate::new(registration, &replacement_certificate, reason)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GatewayServerError::database)?;
        let current = lock_rotation_authority(
            &mut transaction,
            &prepared.registration,
            &current_fingerprint,
        )
        .await?;
        prepared.refresh_cutover_time(&replacement_certificate)?;

        let expected_credential_epoch =
            current.credential_epoch.checked_add(1).ok_or_else(|| {
                GatewayServerError::configuration("Credential rotation sequence is invalid")
            })?;
        let next_policy_revision = current.policy_revision.checked_add(1).ok_or_else(|| {
            GatewayServerError::configuration("Credential rotation sequence is invalid")
        })?;
        let policy_is_unchanged = prepared.policy_revision == current.policy_revision
            && prepared.policy_document == current.policy_document;
        let policy_advances_once = prepared.policy_revision == next_policy_revision;
        if prepared.credential_epoch != expected_credential_epoch
            || !(policy_is_unchanged || policy_advances_once)
        {
            return Err(GatewayServerError::configuration(
                "Credential rotation sequence is invalid",
            ));
        }

        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM apolysis_gateway.transport_credentials \
                 WHERE certificate_fingerprint=$1 OR credential_id=$2 \
             )",
        )
        .bind(replacement_fingerprint.as_slice())
        .bind(&replacement_credential_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        {
            return Err(GatewayServerError::configuration(
                "Client certificate binding conflicts with current authority",
            ));
        }

        let revoked = sqlx::query(
            "UPDATE apolysis_gateway.transport_credentials \
             SET revoked_at_unix_ms=$1, revocation_reason=$2, updated_at_unix_ms=$1 \
             WHERE credential_id=$3 AND organization_id=$4 \
               AND source_registration_id=$5 AND credential_epoch=$6 \
               AND revoked_at_unix_ms IS NULL",
        )
        .bind(prepared.now)
        .bind(reason)
        .bind(&current.credential_id)
        .bind(prepared.registration.organization_id.as_str())
        .bind(&prepared.registration.source_registration_id)
        .bind(current.credential_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;
        if revoked.rows_affected() != 1 {
            return Err(GatewayServerError::configuration(
                "Source authority updates require the credential rotation gate",
            ));
        }

        sqlx::query(
            "INSERT INTO apolysis_gateway.transport_credentials ( \
                 credential_id, certificate_fingerprint, organization_id, \
                 source_registration_id, credential_epoch, effective_at_unix_ms, \
                 expires_at_unix_ms, revoked_at_unix_ms, revocation_reason, \
                 created_at_unix_ms, updated_at_unix_ms \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, $8, $8)",
        )
        .bind(&replacement_credential_id)
        .bind(replacement_fingerprint.as_slice())
        .bind(prepared.registration.organization_id.as_str())
        .bind(&prepared.registration.source_registration_id)
        .bind(prepared.credential_epoch)
        .bind(prepared.effective_at_unix_ms)
        .bind(prepared.expires_at_unix_ms)
        .bind(prepared.now)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        let registration_update = sqlx::query(
            "UPDATE apolysis_gateway.source_registrations \
             SET policy_revision=$1, credential_epoch=$2, effective_at_unix_ms=$3, \
                 expires_at_unix_ms=$4, policy_document=$5, updated_at_unix_ms=$6 \
             WHERE organization_id=$7 AND source_registration_id=$8 \
               AND policy_revision=$9 AND credential_epoch=$10 \
               AND registration_state='active'",
        )
        .bind(prepared.policy_revision)
        .bind(prepared.credential_epoch)
        .bind(prepared.effective_at_unix_ms)
        .bind(prepared.expires_at_unix_ms)
        .bind(&prepared.policy_document)
        .bind(prepared.now)
        .bind(prepared.registration.organization_id.as_str())
        .bind(&prepared.registration.source_registration_id)
        .bind(current.policy_revision)
        .bind(current.credential_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;
        if registration_update.rows_affected() != 1 {
            return Err(GatewayServerError::configuration(
                "Source authority updates require the credential rotation gate",
            ));
        }

        record_source_authority_revision(
            &mut transaction,
            AuthorityRevisionRecord::from_prepared(&replacement_credential_id, &prepared),
        )
        .await?;
        invalidate_rotated_authority(
            &mut transaction,
            prepared.registration.organization_id.as_str(),
            &prepared.registration.source_registration_id,
            prepared.now,
        )
        .await?;
        record_authority_change(
            &mut transaction,
            "rotate_credential",
            reason,
            &replacement_credential_id,
            &prepared,
        )
        .await?;

        transaction
            .commit()
            .await
            .map_err(GatewayServerError::database)
    }

    pub(super) async fn revoke_credential(
        &self,
        fingerprint: [u8; 32],
        reason: &str,
    ) -> Result<(), GatewayServerError> {
        validate_contract_identifier(reason, "Revocation reason is invalid")?;
        let now = checked_database_integer(current_unix_ms()?, "Gateway clock is invalid")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GatewayServerError::database)?;
        let credential_scope = sqlx::query(
            "SELECT organization_id, source_registration_id \
             FROM apolysis_gateway.transport_credentials \
             WHERE certificate_fingerprint=$1",
        )
        .bind(fingerprint.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        .ok_or_else(|| {
            GatewayServerError::configuration("Transport credential is not registered")
        })?;
        let organization_id: String = credential_scope
            .try_get("organization_id")
            .map_err(GatewayServerError::database)?;
        let source_registration_id: String = credential_scope
            .try_get("source_registration_id")
            .map_err(GatewayServerError::database)?;
        lock_authority_advisory_scope(&mut transaction, &organization_id, &source_registration_id)
            .await?;
        sqlx::query_scalar::<_, String>(
            "SELECT organization_id \
             FROM apolysis_gateway.organizations \
             WHERE organization_id=$1 \
             FOR UPDATE",
        )
        .bind(&organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        .ok_or_else(|| {
            GatewayServerError::configuration("Transport credential is not registered")
        })?;
        let registration_credential_epoch = sqlx::query_scalar::<_, i64>(
            "SELECT credential_epoch \
             FROM apolysis_gateway.source_registrations \
             WHERE organization_id=$1 AND source_registration_id=$2 \
             FOR UPDATE",
        )
        .bind(&organization_id)
        .bind(&source_registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        .ok_or_else(|| {
            GatewayServerError::configuration("Transport credential is not registered")
        })?;
        let credential = sqlx::query(
            "SELECT credential_id, credential_epoch, revoked_at_unix_ms \
             FROM apolysis_gateway.transport_credentials \
             WHERE certificate_fingerprint=$1 AND organization_id=$2 \
               AND source_registration_id=$3 \
             FOR UPDATE",
        )
        .bind(fingerprint.as_slice())
        .bind(&organization_id)
        .bind(&source_registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        .ok_or_else(|| {
            GatewayServerError::configuration("Transport credential is not registered")
        })?;
        let credential_id: String = credential
            .try_get("credential_id")
            .map_err(GatewayServerError::database)?;
        let credential_epoch: i64 = credential
            .try_get("credential_epoch")
            .map_err(GatewayServerError::database)?;
        let revoked_at_unix_ms: Option<i64> = credential
            .try_get("revoked_at_unix_ms")
            .map_err(GatewayServerError::database)?;

        let revoked_current = if revoked_at_unix_ms.is_none() {
            let revoked = sqlx::query(
                "UPDATE apolysis_gateway.transport_credentials \
                 SET revoked_at_unix_ms=$1, revocation_reason=$2, updated_at_unix_ms=$1 \
                 WHERE credential_id=$3 AND organization_id=$4 \
                   AND source_registration_id=$5 AND credential_epoch=$6 \
                   AND revoked_at_unix_ms IS NULL",
            )
            .bind(now)
            .bind(reason)
            .bind(&credential_id)
            .bind(&organization_id)
            .bind(&source_registration_id)
            .bind(credential_epoch)
            .execute(&mut *transaction)
            .await
            .map_err(GatewayServerError::database)?;
            if revoked.rows_affected() != 1 {
                return Err(GatewayServerError::configuration(
                    "Transport credential is not registered",
                ));
            }
            registration_credential_epoch == credential_epoch
        } else {
            false
        };
        if revoked_current {
            invalidate_revoked_credential(
                &mut transaction,
                &organization_id,
                &source_registration_id,
                &credential_id,
                credential_epoch,
                now,
            )
            .await?;
        }

        sqlx::query(
            "INSERT INTO apolysis_gateway.authority_change_audit ( \
                 occurred_at_unix_ms, action, reason_code, organization_id, \
                 source_registration_id, credential_id, credential_epoch \
             ) VALUES ($1, 'revoke_credential', $2, $3, $4, $5, $6)",
        )
        .bind(now)
        .bind(reason)
        .bind(&organization_id)
        .bind(&source_registration_id)
        .bind(&credential_id)
        .bind(credential_epoch)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        transaction
            .commit()
            .await
            .map_err(GatewayServerError::database)?;
        Ok(())
    }
}

struct PreparedAuthorityUpdate {
    registration: RegistrationDocument,
    policy_document: serde_json::Value,
    now: i64,
    policy_revision: i64,
    credential_epoch: i64,
    effective_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

impl PreparedAuthorityUpdate {
    fn new(
        registration: RegistrationDocument,
        certificate: &ClientCertificate,
        reason: &str,
    ) -> Result<Self, GatewayServerError> {
        validate_contract_identifier(reason, "Authority change reason is invalid")?;
        let now_unix_ms = current_unix_ms()?;
        registration.validate(now_unix_ms, certificate)?;
        let stored_policy = registration.stored_policy();
        stored_policy
            .build_policy()
            .map_err(|_| GatewayServerError::configuration("Source policy is invalid"))?;
        let policy_document = serde_json::to_value(stored_policy)
            .map_err(|_| GatewayServerError::configuration("Source policy serialization failed"))?;
        Ok(Self {
            policy_revision: checked_database_integer(
                registration.policy_revision,
                "Source policy revision is invalid",
            )?,
            credential_epoch: checked_database_integer(
                registration.credential_epoch,
                "Transport credential epoch is invalid",
            )?,
            effective_at_unix_ms: checked_database_integer(
                registration.effective_at_unix_ms,
                "Source registration validity is invalid",
            )?,
            expires_at_unix_ms: checked_database_integer(
                registration.expires_at_unix_ms,
                "Source registration validity is invalid",
            )?,
            now: checked_database_integer(now_unix_ms, "Gateway clock is invalid")?,
            registration,
            policy_document,
        })
    }

    fn refresh_cutover_time(
        &mut self,
        certificate: &ClientCertificate,
    ) -> Result<(), GatewayServerError> {
        let now_unix_ms = current_unix_ms()?;
        self.registration.validate(now_unix_ms, certificate)?;
        self.now = checked_database_integer(now_unix_ms, "Gateway clock is invalid")?;
        Ok(())
    }
}

struct LockedRotationAuthority {
    credential_id: String,
    credential_epoch: i64,
    policy_revision: i64,
    policy_document: serde_json::Value,
}

struct AuthorityRevisionRecord<'a> {
    organization_id: &'a str,
    source_registration_id: &'a str,
    credential_id: &'a str,
    credential_epoch: i64,
    policy_revision: i64,
    policy_document: &'a serde_json::Value,
    effective_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    recorded_at_unix_ms: i64,
}

impl<'a> AuthorityRevisionRecord<'a> {
    fn from_prepared(credential_id: &'a str, prepared: &'a PreparedAuthorityUpdate) -> Self {
        Self {
            organization_id: prepared.registration.organization_id.as_str(),
            source_registration_id: &prepared.registration.source_registration_id,
            credential_id,
            credential_epoch: prepared.credential_epoch,
            policy_revision: prepared.policy_revision,
            policy_document: &prepared.policy_document,
            effective_at_unix_ms: prepared.effective_at_unix_ms,
            expires_at_unix_ms: prepared.expires_at_unix_ms,
            recorded_at_unix_ms: prepared.now,
        }
    }
}

async fn lock_rotation_authority(
    transaction: &mut Transaction<'_, Postgres>,
    registration: &RegistrationDocument,
    current_fingerprint: &[u8; 32],
) -> Result<LockedRotationAuthority, GatewayServerError> {
    lock_authority_advisory_scope(
        transaction,
        registration.organization_id.as_str(),
        &registration.source_registration_id,
    )
    .await?;

    let organization_state = sqlx::query_scalar::<_, String>(
        "SELECT organization_state \
         FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 \
         FOR UPDATE",
    )
    .bind(registration.organization_id.as_str())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?
    .ok_or_else(|| {
        GatewayServerError::configuration(
            "Source authority updates require the credential rotation gate",
        )
    })?;

    let current_registration = sqlx::query(
        "SELECT source_id, principal_kind, principal_id, registration_state, \
                policy_revision, credential_epoch, policy_document \
         FROM apolysis_gateway.source_registrations \
         WHERE organization_id=$1 AND source_registration_id=$2 \
         FOR UPDATE",
    )
    .bind(registration.organization_id.as_str())
    .bind(&registration.source_registration_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?
    .ok_or_else(|| {
        GatewayServerError::configuration(
            "Source authority updates require the credential rotation gate",
        )
    })?;
    let current_source_id: String = current_registration
        .try_get("source_id")
        .map_err(GatewayServerError::database)?;
    let current_principal_kind: String = current_registration
        .try_get("principal_kind")
        .map_err(GatewayServerError::database)?;
    let current_principal_id: String = current_registration
        .try_get("principal_id")
        .map_err(GatewayServerError::database)?;
    let current_registration_state: String = current_registration
        .try_get("registration_state")
        .map_err(GatewayServerError::database)?;
    let policy_revision: i64 = current_registration
        .try_get("policy_revision")
        .map_err(GatewayServerError::database)?;
    let registration_credential_epoch: i64 = current_registration
        .try_get("credential_epoch")
        .map_err(GatewayServerError::database)?;
    let policy_document: serde_json::Value = current_registration
        .try_get("policy_document")
        .map_err(GatewayServerError::database)?;
    if organization_state != registration.organization_state.as_str()
        || current_registration_state != "active"
        || current_source_id != registration.source_id.as_str()
        || current_principal_kind != principal_kind_as_str(registration.principal.kind())
        || current_principal_id != registration.principal.id()
    {
        return Err(GatewayServerError::configuration(
            "Source registration identity is immutable",
        ));
    }

    let current_credential = sqlx::query(
        "SELECT credential_id, certificate_fingerprint, credential_epoch \
         FROM apolysis_gateway.transport_credentials \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND revoked_at_unix_ms IS NULL \
         ORDER BY credential_id \
         FOR UPDATE",
    )
    .bind(registration.organization_id.as_str())
    .bind(&registration.source_registration_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?
    .ok_or_else(|| GatewayServerError::configuration("Transport credential is not registered"))?;
    let credential_id: String = current_credential
        .try_get("credential_id")
        .map_err(GatewayServerError::database)?;
    let fingerprint: Vec<u8> = current_credential
        .try_get("certificate_fingerprint")
        .map_err(GatewayServerError::database)?;
    let credential_epoch: i64 = current_credential
        .try_get("credential_epoch")
        .map_err(GatewayServerError::database)?;
    if fingerprint.as_slice() != current_fingerprint
        || credential_epoch != registration_credential_epoch
    {
        return Err(GatewayServerError::configuration(
            "Transport credential is not registered",
        ));
    }

    Ok(LockedRotationAuthority {
        credential_id,
        credential_epoch,
        policy_revision,
        policy_document,
    })
}

async fn lock_authority_advisory_scope(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    source_registration_id: &str,
) -> Result<(), GatewayServerError> {
    for authority_key in [
        format!("organization:{organization_id}"),
        format!("registration:{source_registration_id}"),
    ] {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4715382012602313075))")
            .bind(authority_key)
            .execute(&mut **transaction)
            .await
            .map_err(GatewayServerError::database)?;
    }
    Ok(())
}

async fn record_source_authority_revision(
    transaction: &mut Transaction<'_, Postgres>,
    revision: AuthorityRevisionRecord<'_>,
) -> Result<(), GatewayServerError> {
    let inserted = sqlx::query(
        "INSERT INTO apolysis_gateway.source_authority_revisions ( \
             organization_id, source_registration_id, credential_id, credential_epoch, \
             registration_policy_revision, policy_document, effective_at_unix_ms, \
             expires_at_unix_ms, recorded_at_unix_ms \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (organization_id, source_registration_id, credential_id, \
                      credential_epoch, registration_policy_revision) DO NOTHING",
    )
    .bind(revision.organization_id)
    .bind(revision.source_registration_id)
    .bind(revision.credential_id)
    .bind(revision.credential_epoch)
    .bind(revision.policy_revision)
    .bind(revision.policy_document)
    .bind(revision.effective_at_unix_ms)
    .bind(revision.expires_at_unix_ms)
    .bind(revision.recorded_at_unix_ms)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;
    if inserted.rows_affected() == 0 {
        let identical = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM apolysis_gateway.source_authority_revisions \
                 WHERE organization_id=$1 AND source_registration_id=$2 \
                   AND credential_id=$3 AND credential_epoch=$4 \
                   AND registration_policy_revision=$5 AND policy_document=$6 \
                   AND effective_at_unix_ms=$7 AND expires_at_unix_ms=$8 \
             )",
        )
        .bind(revision.organization_id)
        .bind(revision.source_registration_id)
        .bind(revision.credential_id)
        .bind(revision.credential_epoch)
        .bind(revision.policy_revision)
        .bind(revision.policy_document)
        .bind(revision.effective_at_unix_ms)
        .bind(revision.expires_at_unix_ms)
        .fetch_one(&mut **transaction)
        .await
        .map_err(GatewayServerError::database)?;
        if !identical {
            return Err(GatewayServerError::configuration(
                "Source authority updates require the credential rotation gate",
            ));
        }
    }
    Ok(())
}

async fn invalidate_rotated_authority(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    source_registration_id: &str,
    cutover_at_unix_ms: i64,
) -> Result<(), GatewayServerError> {
    sqlx::query(
        "UPDATE apolysis_gateway.leases \
         SET revoked_at_unix_ms=greatest(issued_at_unix_ms, $1) \
         WHERE organization_id=$2 AND source_registration_id=$3 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(cutover_at_unix_ms)
    .bind(organization_id)
    .bind(source_registration_id)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;

    sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET authorization_state='revoked', \
             revoked_at_unix_ms=greatest(issued_at_unix_ms, $1) \
         WHERE organization_id=$2 AND authorization_state='pending' \
           AND (source_registration_id=$3 OR issued_by_source_registration_id=$3)",
    )
    .bind(cutover_at_unix_ms)
    .bind(organization_id)
    .bind(source_registration_id)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;
    Ok(())
}

async fn invalidate_revoked_credential(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    source_registration_id: &str,
    credential_id: &str,
    credential_epoch: i64,
    revoked_at_unix_ms: i64,
) -> Result<(), GatewayServerError> {
    sqlx::query(
        "UPDATE apolysis_gateway.leases \
         SET revoked_at_unix_ms=greatest(issued_at_unix_ms, $1) \
         WHERE organization_id=$2 AND source_registration_id=$3 \
           AND credential_id=$4 AND credential_epoch=$5 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(revoked_at_unix_ms)
    .bind(organization_id)
    .bind(source_registration_id)
    .bind(credential_id)
    .bind(credential_epoch)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;

    sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET authorization_state='revoked', \
             revoked_at_unix_ms=greatest(issued_at_unix_ms, $1) \
         WHERE organization_id=$2 AND authorization_state='pending' \
           AND ( \
               (source_registration_id=$3 AND credential_id=$4 \
                AND credential_epoch=$5) \
               OR \
               (issued_by_source_registration_id=$3 AND issued_by_credential_id=$4 \
                AND issued_by_credential_epoch=$5) \
           )",
    )
    .bind(revoked_at_unix_ms)
    .bind(organization_id)
    .bind(source_registration_id)
    .bind(credential_id)
    .bind(credential_epoch)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;
    Ok(())
}

async fn record_authority_change(
    transaction: &mut Transaction<'_, Postgres>,
    action: &str,
    reason: &str,
    credential_id: &str,
    prepared: &PreparedAuthorityUpdate,
) -> Result<(), GatewayServerError> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.authority_change_audit ( \
             occurred_at_unix_ms, action, reason_code, organization_id, \
             source_registration_id, credential_id, policy_revision, credential_epoch \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(prepared.now)
    .bind(action)
    .bind(reason)
    .bind(prepared.registration.organization_id.as_str())
    .bind(&prepared.registration.source_registration_id)
    .bind(credential_id)
    .bind(prepared.policy_revision)
    .bind(prepared.credential_epoch)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;
    Ok(())
}

struct AuthorityRow {
    credential_id: String,
    organization_id: String,
    source_registration_id: String,
    transport_credential_epoch: i64,
    credential_effective_at_unix_ms: i64,
    credential_expires_at_unix_ms: i64,
    revoked_at_unix_ms: Option<i64>,
    organization_state: String,
    source_id: String,
    principal_kind: String,
    principal_id: String,
    registration_state: String,
    policy_revision: i64,
    registration_credential_epoch: i64,
    registration_effective_at_unix_ms: i64,
    registration_expires_at_unix_ms: i64,
    policy_document: serde_json::Value,
}

impl AuthorityRow {
    fn decode(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            credential_id: row.try_get("credential_id")?,
            organization_id: row.try_get("organization_id")?,
            source_registration_id: row.try_get("source_registration_id")?,
            transport_credential_epoch: row.try_get("transport_credential_epoch")?,
            credential_effective_at_unix_ms: row.try_get("credential_effective_at_unix_ms")?,
            credential_expires_at_unix_ms: row.try_get("credential_expires_at_unix_ms")?,
            revoked_at_unix_ms: row.try_get("revoked_at_unix_ms")?,
            organization_state: row.try_get("organization_state")?,
            source_id: row.try_get("source_id")?,
            principal_kind: row.try_get("principal_kind")?,
            principal_id: row.try_get("principal_id")?,
            registration_state: row.try_get("registration_state")?,
            policy_revision: row.try_get("policy_revision")?,
            registration_credential_epoch: row.try_get("registration_credential_epoch")?,
            registration_effective_at_unix_ms: row.try_get("registration_effective_at_unix_ms")?,
            registration_expires_at_unix_ms: row.try_get("registration_expires_at_unix_ms")?,
            policy_document: row.try_get("policy_document")?,
        })
    }

    fn audit_identity(&self) -> AuditIdentity<'_> {
        AuditIdentity {
            organization_id: Some(&self.organization_id),
            source_registration_id: Some(&self.source_registration_id),
            credential_id: Some(&self.credential_id),
            policy_revision: Some(self.policy_revision),
            credential_epoch: Some(self.transport_credential_epoch),
        }
    }

    fn authenticated_context(
        &self,
        registration_policy: SourceRegistrationPolicy,
        now_unix_ms: u64,
    ) -> Result<AuthenticatedSourceContext, ()> {
        let organization_id =
            OrganizationId::try_from(self.organization_id.clone()).map_err(drop)?;
        let principal_kind = parse_principal_kind(&self.principal_kind).ok_or(())?;
        let principal =
            PrincipalRef::new(principal_kind, self.principal_id.clone()).map_err(drop)?;
        let policy_revision = u64::try_from(self.policy_revision).map_err(drop)?;
        let credential_epoch = u64::try_from(self.transport_credential_epoch).map_err(drop)?;
        let expires_at_unix_ms = u64::try_from(
            self.credential_expires_at_unix_ms
                .min(self.registration_expires_at_unix_ms),
        )
        .map_err(drop)?;
        let authentication = AuthenticationSnapshot::new(
            self.credential_id.clone(),
            credential_epoch,
            policy_revision,
            now_unix_ms,
            expires_at_unix_ms,
        )
        .map_err(drop)?;
        AuthenticatedSourceContext::new(
            organization_id,
            principal,
            self.source_registration_id.clone(),
            authentication,
            registration_policy,
        )
        .map_err(drop)
    }
}

#[derive(Clone, Copy, Default)]
struct AuditIdentity<'a> {
    organization_id: Option<&'a str>,
    source_registration_id: Option<&'a str>,
    credential_id: Option<&'a str>,
    policy_revision: Option<i64>,
    credential_epoch: Option<i64>,
}

async fn finish_denial(
    mut transaction: Transaction<'_, Postgres>,
    fingerprint: &[u8; 32],
    operation: &str,
    now: i64,
    identity: AuditIdentity<'_>,
    reason: &'static str,
    forbidden: bool,
) -> Result<AuthenticatedSourceContext, GatewayServerError> {
    let decision = if forbidden {
        "forbidden"
    } else {
        "unauthenticated"
    };
    record_gateway_audit(
        &mut transaction,
        fingerprint,
        operation,
        now,
        decision,
        reason,
        identity,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(GatewayServerError::database)?;
    if forbidden {
        Err(GatewayServerError::forbidden(reason))
    } else {
        Err(GatewayServerError::unauthenticated(reason))
    }
}

async fn record_gateway_audit(
    transaction: &mut Transaction<'_, Postgres>,
    fingerprint: &[u8; 32],
    operation: &str,
    now: i64,
    decision: &str,
    reason: &str,
    identity: AuditIdentity<'_>,
) -> Result<(), GatewayServerError> {
    sqlx::query(
        "INSERT INTO apolysis_gateway.gateway_authority_audit ( \
             requested_at_unix_ms, operation, decision, reason_code, \
             certificate_fingerprint, organization_id, source_registration_id, \
             credential_id, policy_revision, credential_epoch \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(now)
    .bind(operation)
    .bind(decision)
    .bind(reason)
    .bind(fingerprint.as_slice())
    .bind(identity.organization_id)
    .bind(identity.source_registration_id)
    .bind(identity.credential_id)
    .bind(identity.policy_revision)
    .bind(identity.credential_epoch)
    .execute(&mut **transaction)
    .await
    .map_err(GatewayServerError::database)?;
    Ok(())
}

fn validate_resolution_input(
    leaf_der: &[u8],
    operation: &str,
    now_unix_ms: u64,
) -> Result<(), GatewayServerError> {
    if leaf_der.is_empty() || leaf_der.len() > MAX_CERTIFICATE_PEM_BYTES {
        return Err(GatewayServerError::unauthenticated(
            "Client certificate is invalid",
        ));
    }
    if !matches!(
        operation,
        "open_run" | "bind_runtime" | "ingest" | "finish_run"
    ) {
        return Err(GatewayServerError::configuration(
            "Gateway authority operation is invalid",
        ));
    }
    checked_database_integer(now_unix_ms, "Gateway clock is invalid")?;
    Ok(())
}

fn migration_error(error: sqlx::migrate::MigrateError) -> GatewayServerError {
    GatewayServerError::database(sqlx::Error::Migrate(Box::new(error)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn prepared_rotation_reports_an_authority_change_reason_error() {
        let registration: RegistrationDocument = serde_json::from_value(json!({
            "organization_id": "org_rotation_reason",
            "organization_state": "active",
            "source_registration_id": "registration_rotation_reason",
            "source_id": "source_rotation_reason",
            "principal": {"kind": "workload", "id": "principal_rotation_reason"},
            "policy_revision": 1,
            "credential_epoch": 1,
            "effective_at_unix_ms": 1,
            "expires_at_unix_ms": 2,
            "allowed_source_kinds": ["semantic_hook"],
            "allowed_environments": ["ci_runner_or_remote_workspace"],
            "allowed_operations": ["ingest"],
            "effective_trust_profile": "harness_observed",
            "allowed_capabilities": ["tool_calls"],
            "allowed_privacy_capabilities": ["structure_only"],
            "allowed_redaction_profile_refs": ["redaction_rotation_reason"],
            "allowed_run_authorities": [],
            "allowed_run_privacy_profile_refs": [],
            "allowed_run_retention_profile_refs": [],
            "required_run_source_kinds": [],
            "may_create_runs": false,
            "may_join_runs": false,
            "may_finalize_runs": false
        }))
        .expect("registration fixture");
        let certificate = ClientCertificate {
            fingerprint: [0x11; 32],
            not_before_unix_ms: 1,
            not_after_unix_ms: 2,
        };

        let error = match PreparedAuthorityUpdate::new(
            registration,
            &certificate,
            "not a contract identifier",
        ) {
            Ok(_) => panic!("invalid rotation reason was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "Authority change reason is invalid");
    }

    #[tokio::test]
    async fn revoke_credential_retains_its_revocation_reason_error() {
        let store = AuthorityStore {
            pool: PgPoolOptions::new()
                .connect_lazy("postgresql://localhost/apolysis")
                .expect("syntactically valid lazy pool"),
        };

        let error = match store
            .revoke_credential([0x22; 32], "not a contract identifier")
            .await
        {
            Ok(()) => panic!("invalid revocation reason was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.to_string(), "Revocation reason is invalid");
    }
}

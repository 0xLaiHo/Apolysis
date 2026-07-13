// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Cursor,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityRef, EnvironmentKind,
    GatewayOperation, OrganizationId, PrincipalKind, PrincipalRef, PrivacyCapability,
    SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy, TrustProfile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use x509_parser::prelude::parse_x509_certificate;
use zeroize::Zeroizing;

use crate::{file_input::read_bounded_file, GatewayServerError};

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_DATABASE_URL_BYTES: usize = 8 * 1024;
const MAX_REGISTRATION_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_PEM_BYTES: usize = 128 * 1024;
const MTLS_FINGERPRINT_DOMAIN: &[u8] = b"apolysis.gateway.mtls-leaf/v1\0";

/// PostgreSQL-backed current authority for direct-mTLS Gateway requests.
///
/// The store deliberately retains only a connection pool. Every resolution
/// re-reads credential, organization, registration, policy revision, epoch,
/// validity, and revocation state in one database transaction.
#[derive(Clone)]
pub struct AuthorityStore {
    pool: PgPool,
}

impl AuthorityStore {
    /// Connect to the real Gateway database and apply the ledger and current-
    /// authority migrations in their reviewed order.
    pub async fn connect_and_migrate(database_url: &str) -> Result<Self, GatewayServerError> {
        if database_url.is_empty() || database_url.len() > MAX_DATABASE_URL_BYTES {
            return Err(GatewayServerError::configuration(
                "Gateway database URL is invalid",
            ));
        }

        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await
            .map_err(GatewayServerError::database)?;

        apolysis_gateway_postgres::MIGRATOR
            .run(&pool)
            .await
            .map_err(migration_error)?;
        Ok(Self { pool })
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
             WHERE credential.certificate_fingerprint=$1 \
             FOR SHARE OF credential, organization, registration",
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

    async fn register_source(
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
            "SELECT organization_id, source_id, principal_kind, principal_id, \
                    policy_revision, credential_epoch, effective_at_unix_ms, \
                    expires_at_unix_ms, policy_document \
             FROM apolysis_gateway.source_registrations \
             WHERE source_registration_id=$1 \
             FOR UPDATE",
        )
        .bind(&registration.source_registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        {
            validate_registration_update(&existing, &registration, &policy_document)?;

            let old_epoch: i64 = existing
                .try_get("credential_epoch")
                .map_err(GatewayServerError::database)?;
            if let Some(current_credential) = sqlx::query(
                "SELECT certificate_fingerprint, revoked_at_unix_ms \
                 FROM apolysis_gateway.transport_credentials \
                 WHERE source_registration_id=$1 AND credential_epoch=$2 \
                 ORDER BY created_at_unix_ms DESC, credential_id DESC \
                 LIMIT 1 \
                 FOR UPDATE",
            )
            .bind(&registration.source_registration_id)
            .bind(old_epoch)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(GatewayServerError::database)?
            {
                let old_fingerprint: Vec<u8> = current_credential
                    .try_get("certificate_fingerprint")
                    .map_err(GatewayServerError::database)?;
                let revoked: Option<i64> = current_credential
                    .try_get("revoked_at_unix_ms")
                    .map_err(GatewayServerError::database)?;
                if (old_fingerprint != certificate.fingerprint || revoked.is_some())
                    && credential_epoch <= old_epoch
                {
                    return Err(GatewayServerError::configuration(
                        "Credential rotation must advance the credential epoch",
                    ));
                }
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
        .bind(policy_document)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?;

        sqlx::query(
            "UPDATE apolysis_gateway.transport_credentials \
             SET revoked_at_unix_ms=$1, \
                 revocation_reason='superseded_by_new_epoch', \
                 updated_at_unix_ms=$1 \
             WHERE source_registration_id=$2 \
               AND certificate_fingerprint<>$3 \
               AND revoked_at_unix_ms IS NULL",
        )
        .bind(now)
        .bind(&registration.source_registration_id)
        .bind(certificate.fingerprint.as_slice())
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

    async fn revoke_credential(
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
        let credential = sqlx::query(
            "SELECT credential_id, organization_id, source_registration_id, \
                    credential_epoch, revoked_at_unix_ms \
             FROM apolysis_gateway.transport_credentials \
             WHERE certificate_fingerprint=$1 \
             FOR UPDATE",
        )
        .bind(fingerprint.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(GatewayServerError::database)?
        .ok_or_else(|| {
            GatewayServerError::configuration("Transport credential is not registered")
        })?;

        let credential_id: String = credential
            .try_get("credential_id")
            .map_err(GatewayServerError::database)?;
        let organization_id: String = credential
            .try_get("organization_id")
            .map_err(GatewayServerError::database)?;
        let source_registration_id: String = credential
            .try_get("source_registration_id")
            .map_err(GatewayServerError::database)?;
        let credential_epoch: i64 = credential
            .try_get("credential_epoch")
            .map_err(GatewayServerError::database)?;
        let revoked_at_unix_ms: Option<i64> = credential
            .try_get("revoked_at_unix_ms")
            .map_err(GatewayServerError::database)?;

        if revoked_at_unix_ms.is_none() {
            sqlx::query(
                "UPDATE apolysis_gateway.transport_credentials \
                 SET revoked_at_unix_ms=$1, revocation_reason=$2, updated_at_unix_ms=$1 \
                 WHERE credential_id=$3 AND revoked_at_unix_ms IS NULL",
            )
            .bind(now)
            .bind(reason)
            .bind(&credential_id)
            .execute(&mut *transaction)
            .await
            .map_err(GatewayServerError::database)?;
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

/// Parse and execute the intentionally narrow authority-administration CLI.
pub async fn run_authority_command() -> Result<(), GatewayServerError> {
    match AuthorityCommand::from_args(std::env::args_os())? {
        AuthorityCommand::Migrate { database_url_file } => {
            let database_url = read_database_url(&database_url_file)?;
            let _store = AuthorityStore::connect_and_migrate(&database_url).await?;
            Ok(())
        }
        AuthorityCommand::RegisterSource {
            database_url_file,
            registration,
            client_certificate,
        } => {
            let database_url = read_database_url(&database_url_file)?;
            let document = read_registration(&registration)?;
            let certificate = read_client_certificate(&client_certificate)?;
            let store = AuthorityStore::connect_and_migrate(&database_url).await?;
            store.register_source(document, certificate).await
        }
        AuthorityCommand::RevokeCredential {
            database_url_file,
            client_certificate,
            reason,
        } => {
            let database_url = read_database_url(&database_url_file)?;
            let certificate = read_client_certificate(&client_certificate)?;
            let store = AuthorityStore::connect_and_migrate(&database_url).await?;
            store
                .revoke_credential(certificate.fingerprint, &reason)
                .await
        }
    }
}

#[derive(Debug)]
enum AuthorityCommand {
    Migrate {
        database_url_file: PathBuf,
    },
    RegisterSource {
        database_url_file: PathBuf,
        registration: PathBuf,
        client_certificate: PathBuf,
    },
    RevokeCredential {
        database_url_file: PathBuf,
        client_certificate: PathBuf,
        reason: String,
    },
}

impl AuthorityCommand {
    fn from_args(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, GatewayServerError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let command = arguments
            .next()
            .ok_or_else(|| GatewayServerError::configuration("Authority command is required"))?
            .into_string()
            .map_err(|_| {
                GatewayServerError::configuration("Authority command names must be UTF-8")
            })?;
        let mut options = BTreeMap::new();
        while let Some(option) = arguments.next() {
            let option = option.into_string().map_err(|_| {
                GatewayServerError::configuration("Authority option names must be UTF-8")
            })?;
            let value = arguments.next().ok_or_else(|| {
                GatewayServerError::configuration("Authority option is missing its value")
            })?;
            if options.insert(option, value).is_some() {
                return Err(GatewayServerError::configuration(
                    "Authority option was supplied more than once",
                ));
            }
        }

        match command.as_str() {
            "migrate" => {
                require_only_options(&options, &["--database-url-file"])?;
                Ok(Self::Migrate {
                    database_url_file: required_path(&mut options, "--database-url-file")?,
                })
            }
            "register-source" => {
                require_only_options(
                    &options,
                    &[
                        "--database-url-file",
                        "--registration",
                        "--client-certificate",
                    ],
                )?;
                Ok(Self::RegisterSource {
                    database_url_file: required_path(&mut options, "--database-url-file")?,
                    registration: required_path(&mut options, "--registration")?,
                    client_certificate: required_path(&mut options, "--client-certificate")?,
                })
            }
            "revoke-credential" => {
                require_only_options(
                    &options,
                    &["--database-url-file", "--client-certificate", "--reason"],
                )?;
                let database_url_file = required_path(&mut options, "--database-url-file")?;
                let client_certificate = required_path(&mut options, "--client-certificate")?;
                let reason = required_string(&mut options, "--reason")?;
                validate_contract_identifier(&reason, "Revocation reason is invalid")?;
                Ok(Self::RevokeCredential {
                    database_url_file,
                    client_certificate,
                    reason,
                })
            }
            _ => Err(GatewayServerError::configuration(
                "Authority command is unsupported",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum OrganizationState {
    Active,
    Suspended,
}

impl OrganizationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationDocument {
    organization_id: OrganizationId,
    organization_state: OrganizationState,
    source_registration_id: String,
    source_id: SourceId,
    principal: PrincipalRef,
    policy_revision: u64,
    credential_epoch: u64,
    effective_at_unix_ms: u64,
    expires_at_unix_ms: u64,
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
    fn validate(
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

    fn stored_policy(&self) -> StoredPolicy {
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
struct StoredPolicy {
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

impl StoredPolicy {
    fn build_policy(&self) -> Result<SourceRegistrationPolicy, apolysis_contracts::ContractError> {
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

struct ClientCertificate {
    fingerprint: [u8; 32],
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
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
        let expires_at_unix_ms = u64::try_from(
            self.credential_expires_at_unix_ms
                .min(self.registration_expires_at_unix_ms),
        )
        .map_err(drop)?;
        let authentication = AuthenticationSnapshot::new(
            self.credential_id.clone(),
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

fn validate_registration_update(
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
    if new_revision < existing_revision || new_epoch < existing_epoch {
        return Err(GatewayServerError::configuration(
            "Source authority revisions must not move backwards",
        ));
    }
    if new_revision == existing_revision {
        let existing_policy: serde_json::Value = existing
            .try_get("policy_document")
            .map_err(GatewayServerError::database)?;
        let existing_effective: i64 = existing
            .try_get("effective_at_unix_ms")
            .map_err(GatewayServerError::database)?;
        let existing_expires: i64 = existing
            .try_get("expires_at_unix_ms")
            .map_err(GatewayServerError::database)?;
        if existing_policy != *policy_document
            || existing_effective
                != i64::try_from(registration.effective_at_unix_ms).unwrap_or(i64::MAX)
            || existing_expires
                != i64::try_from(registration.expires_at_unix_ms).unwrap_or(i64::MAX)
        {
            return Err(GatewayServerError::configuration(
                "Source policy changes must advance the policy revision",
            ));
        }
    }
    Ok(())
}

fn policy_allows_operation(policy: &SourceRegistrationPolicy, operation: &str) -> bool {
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

fn parse_principal_kind(value: &str) -> Option<PrincipalKind> {
    match value {
        "human" => Some(PrincipalKind::Human),
        "workload" => Some(PrincipalKind::Workload),
        _ => None,
    }
}

fn principal_kind_as_str(value: PrincipalKind) -> &'static str {
    match value {
        PrincipalKind::Human => "human",
        PrincipalKind::Workload => "workload",
    }
}

fn mtls_leaf_fingerprint(leaf_der: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(MTLS_FINGERPRINT_DOMAIN);
    digest.update(leaf_der);
    digest.finalize().into()
}

fn credential_id(fingerprint: &[u8; 32]) -> String {
    let mut value = String::with_capacity(5 + fingerprint.len() * 2);
    value.push_str("mtls_");
    for byte in fingerprint {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn read_database_url(path: &Path) -> Result<Zeroizing<String>, GatewayServerError> {
    require_absolute_path(path)?;
    let bytes = Zeroizing::new(read_bounded_file(
        path,
        MAX_DATABASE_URL_BYTES as u64,
        true,
    )?);
    if bytes.is_empty() || bytes.len() > MAX_DATABASE_URL_BYTES {
        return Err(GatewayServerError::configuration(
            "Gateway database URL file is invalid",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        GatewayServerError::configuration("Gateway database URL file must be UTF-8")
    })?;
    let value = text.trim();
    if value.is_empty()
        || value.chars().any(char::is_control)
        || !(value.starts_with("postgres://") || value.starts_with("postgresql://"))
    {
        return Err(GatewayServerError::configuration(
            "Gateway database URL file is invalid",
        ));
    }
    Ok(Zeroizing::new(value.to_string()))
}

fn read_registration(path: &Path) -> Result<RegistrationDocument, GatewayServerError> {
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

fn read_client_certificate(path: &Path) -> Result<ClientCertificate, GatewayServerError> {
    require_absolute_path(path)?;
    let pem = read_bounded_file(path, MAX_CERTIFICATE_PEM_BYTES as u64, false)?;
    if pem.is_empty() || pem.len() > MAX_CERTIFICATE_PEM_BYTES {
        return Err(GatewayServerError::configuration(
            "Client certificate file is invalid",
        ));
    }
    let mut cursor = Cursor::new(pem.as_slice());
    let certificates = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayServerError::configuration("Client certificate PEM is invalid"))?;
    let leaf = certificates.first().ok_or_else(|| {
        GatewayServerError::configuration("Client certificate PEM contains no certificate")
    })?;
    let leaf_der = leaf.as_ref();
    let (remaining, certificate) = parse_x509_certificate(leaf_der)
        .map_err(|_| GatewayServerError::configuration("Client certificate DER is invalid"))?;
    if !remaining.is_empty() || certificate.is_ca() {
        return Err(GatewayServerError::configuration(
            "Client certificate must be a leaf certificate",
        ));
    }
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| GatewayServerError::configuration("Client certificate usage is invalid"))?
        .ok_or_else(|| {
            GatewayServerError::configuration("Client certificate must declare clientAuth")
        })?;
    if !extended_key_usage.value.client_auth && !extended_key_usage.value.any {
        return Err(GatewayServerError::configuration(
            "Client certificate must declare clientAuth",
        ));
    }
    let not_before_unix_ms =
        certificate_time_millis(certificate.validity().not_before.timestamp())?;
    let not_after_unix_ms = certificate_time_millis(certificate.validity().not_after.timestamp())?;
    Ok(ClientCertificate {
        fingerprint: mtls_leaf_fingerprint(leaf_der),
        not_before_unix_ms,
        not_after_unix_ms,
    })
}

fn certificate_time_millis(timestamp_seconds: i64) -> Result<u64, GatewayServerError> {
    let timestamp_seconds = u64::try_from(timestamp_seconds)
        .map_err(|_| GatewayServerError::configuration("Client certificate validity is invalid"))?;
    timestamp_seconds
        .checked_mul(1_000)
        .filter(|value| *value <= MAX_IJSON_INTEGER)
        .ok_or_else(|| GatewayServerError::configuration("Client certificate validity is invalid"))
}

fn current_unix_ms() -> Result<u64, GatewayServerError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayServerError::configuration("Gateway clock is invalid"))?
        .as_millis();
    u64::try_from(milliseconds)
        .ok()
        .filter(|value| *value > 0 && *value <= MAX_IJSON_INTEGER)
        .ok_or_else(|| GatewayServerError::configuration("Gateway clock is invalid"))
}

fn checked_database_integer(value: u64, message: &'static str) -> Result<i64, GatewayServerError> {
    if value == 0 || value > MAX_IJSON_INTEGER {
        return Err(GatewayServerError::configuration(message));
    }
    i64::try_from(value).map_err(|_| GatewayServerError::configuration(message))
}

fn validate_contract_identifier(
    value: &str,
    message: &'static str,
) -> Result<(), GatewayServerError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .next_back()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(message))
    }
}

fn require_only_options(
    options: &BTreeMap<String, OsString>,
    allowed: &[&str],
) -> Result<(), GatewayServerError> {
    if options
        .keys()
        .all(|option| allowed.contains(&option.as_str()))
    {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(
            "Authority received an unsupported option",
        ))
    }
}

fn required_path(
    options: &mut BTreeMap<String, OsString>,
    option: &'static str,
) -> Result<PathBuf, GatewayServerError> {
    let path = PathBuf::from(options.remove(option).ok_or_else(|| {
        GatewayServerError::configuration("Authority is missing a required option")
    })?);
    require_absolute_path(&path)?;
    Ok(path)
}

fn required_string(
    options: &mut BTreeMap<String, OsString>,
    option: &'static str,
) -> Result<String, GatewayServerError> {
    options
        .remove(option)
        .ok_or_else(|| GatewayServerError::configuration("Authority is missing a required option"))?
        .into_string()
        .map_err(|_| GatewayServerError::configuration("Authority option values must be UTF-8"))
}

fn require_absolute_path(path: &Path) -> Result<(), GatewayServerError> {
    if !path.as_os_str().is_empty() && path.is_absolute() {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(
            "Authority file paths must be absolute",
        ))
    }
}

fn migration_error(error: sqlx::migrate::MigrateError) -> GatewayServerError {
    GatewayServerError::database(sqlx::Error::Migrate(Box::new(error)))
}

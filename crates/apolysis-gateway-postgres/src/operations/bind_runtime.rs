// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    AcceptedRuntimeBinding, AgentExecutionRecordFact, AuthenticatedSourceContext,
    BindRuntimeRequest, BindRuntimeResponse, ContractErrorCode, GatewayOperation, RunState,
    RuntimeAttribution, RuntimeIdentityKind, SourceCapability, SourceManifest, TrustProfile,
};
use apolysis_gateway::{canonical_runtime_binding_digest, lease_id_digest, LedgerOutcome};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    error::{lease_failure, policy_failure, repository_failure},
    model::{encode_digest, enum_name, hex_digest, principal_kind_name, sql_i64, sql_u64},
    repository::{
        decode_json, hash_runtime_identity, operation_identity, PostgresGatewayRepository,
        TxFailure, TxResult,
    },
};

impl PostgresGatewayRepository {
    pub(crate) async fn execute_bind_runtime(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        request: &BindRuntimeRequest,
        now_unix_ms: u64,
    ) -> TxResult<LedgerOutcome> {
        let identity = operation_identity(context, "bind_runtime", request.client_operation_id())
            .map_err(TxFailure::rollback)?;
        if let Some(outcome) = self
            .lock_and_replay_operation(
                transaction,
                &identity,
                request.request_digest(),
                now_unix_ms,
            )
            .await?
        {
            return Ok(outcome);
        }
        let run = self
            .load_run_for_update(
                transaction,
                context.organization_id().as_str(),
                request.run_id(),
            )
            .await?;
        let lease = load_lease(transaction, context, request).await?;
        validate_lease(context, request, &lease)?;
        let requested_lease_expired = now_unix_ms >= lease.expires_at_unix_ms;
        if self
            .reconcile_expired_run(transaction, context, request.run_id(), &run, now_unix_ms)
            .await?
        {
            return Err(TxFailure::commit(if requested_lease_expired {
                lease_failure(ContractErrorCode::LeaseExpired)
            } else {
                policy_failure(ContractErrorCode::InvalidLifecycleTransition)
            }));
        }
        if requested_lease_expired {
            return Err(TxFailure::rollback(lease_failure(
                ContractErrorCode::LeaseExpired,
            )));
        }
        if run.state != RunState::Active {
            return Err(TxFailure::rollback(policy_failure(
                ContractErrorCode::InvalidLifecycleTransition,
            )));
        }
        let stream = load_stream(transaction, context, request, &lease).await?;
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
            return Err(TxFailure::rollback(policy_failure(
                ContractErrorCode::CapabilityMismatch,
            )));
        }
        let binding_digest = canonical_runtime_binding_digest(request.binding())
            .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let binding_digest_bytes = hex_digest(&binding_digest).map_err(TxFailure::rollback)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT apolysis_gateway.lock_gateway_runtime_binding($1,$2,$3)",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(request.binding().binding_id())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_lock_binding", error))?;
        if let Some(existing) = sqlx::query(
            "SELECT binding_digest, source_registration_id, source_stream_id, \
                    registration_policy_revision, effective_trust_profile, manifest_version, \
                    manifest_digest \
             FROM apolysis_gateway.runtime_bindings \
             WHERE organization_id=$1 AND run_id=$2 AND binding_id=$3",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(request.binding().binding_id())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_load_binding", error))?
        {
            let same_frozen_provenance = existing
                .try_get::<String, _>("source_registration_id")
                .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_binding", error))?
                == context.source_registration_id()
                && existing
                    .try_get::<String, _>("source_stream_id")
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("bind_runtime_decode_binding", error)
                    })?
                    == lease.source_stream_id
                && existing
                    .try_get::<i64, _>("registration_policy_revision")
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("bind_runtime_decode_binding", error)
                    })?
                    == sql_i64(stream.registration_policy_revision).map_err(TxFailure::rollback)?
                && existing
                    .try_get::<String, _>("effective_trust_profile")
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("bind_runtime_decode_binding", error)
                    })?
                    == enum_name(&stream.effective_trust_profile).map_err(TxFailure::rollback)?
                && existing
                    .try_get::<String, _>("manifest_version")
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("bind_runtime_decode_binding", error)
                    })?
                    == enum_name(&stream.manifest.schema_version()).map_err(TxFailure::rollback)?
                && existing
                    .try_get::<Vec<u8>, _>("manifest_digest")
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("bind_runtime_decode_binding", error)
                    })?
                    == hex_digest(&stream.manifest_digest).map_err(TxFailure::rollback)?;
            if !same_frozen_provenance {
                return Err(TxFailure::rollback(lease_failure(
                    ContractErrorCode::LeaseScopeMismatch,
                )));
            }
            if existing
                .try_get::<Vec<u8>, _>("binding_digest")
                .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_binding", error))?
                != binding_digest_bytes
            {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::IdempotencyConflict,
                )));
            }
            let response = BindRuntimeResponse::new(
                request.run_id().clone(),
                request.binding().binding_id(),
                true,
                true,
            )
            .map_err(|_| TxFailure::rollback(repository_failure()))?;
            let outcome = LedgerOutcome::BindRuntime(response);
            self.store_operation(
                transaction,
                &identity,
                request.request_digest(),
                request.run_id(),
                now_unix_ms,
                &outcome,
            )
            .await?;
            return Ok(outcome);
        }

        let identity_kind =
            enum_name(&request.binding().identity_kind()).map_err(TxFailure::rollback)?;
        let identity_digest = hash_runtime_identity(request.binding().identity_ref());
        let mut exact_identity_already_bound_to_run = false;
        if request.binding().attribution() == RuntimeAttribution::Exact {
            if let Some(bound_run) = sqlx::query_scalar::<_, String>(
                "SELECT run_id FROM apolysis_gateway.active_runtime_identities \
                 WHERE organization_id=$1 AND identity_kind=$2 AND identity_digest=$3 FOR UPDATE",
            )
            .bind(context.organization_id().as_str())
            .bind(&identity_kind)
            .bind(&identity_digest)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| {
                TxFailure::from_sqlx_at("bind_runtime_load_active_runtime_identity", error)
            })? {
                if bound_run != request.run_id().as_str() {
                    return Err(TxFailure::rollback(policy_failure(
                        ContractErrorCode::InvalidContract,
                    )));
                }
                exact_identity_already_bound_to_run = true;
            }
        }

        let accepted_binding = AcceptedRuntimeBinding::new(
            context.source_registration_id(),
            &lease.source_stream_id,
            stream.registration_policy_revision,
            stream.effective_trust_profile,
            stream.manifest.schema_version(),
            stream.manifest_digest.clone(),
            request.binding().clone(),
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let ingest_sequence = self
            .append_fact(
                transaction,
                context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RuntimeBound(Box::new(accepted_binding.clone())),
            )
            .await?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.runtime_bindings (\
                organization_id, run_id, binding_id, source_registration_id, source_stream_id, \
                asserting_source_id, registration_policy_revision, effective_trust_profile, \
                manifest_version, manifest_digest, binding_digest, identity_kind, identity_ref, \
                identity_digest, attribution, valid_from_unix_ms, valid_until_unix_ms, \
                ledger_ingest_sequence, accepted_binding_json\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(request.binding().binding_id())
        .bind(context.source_registration_id())
        .bind(&lease.source_stream_id)
        .bind(request.binding().asserting_source_id().as_str())
        .bind(sql_i64(stream.registration_policy_revision).map_err(TxFailure::rollback)?)
        .bind(enum_name(&stream.effective_trust_profile).map_err(TxFailure::rollback)?)
        .bind(enum_name(&stream.manifest.schema_version()).map_err(TxFailure::rollback)?)
        .bind(hex_digest(&stream.manifest_digest).map_err(TxFailure::rollback)?)
        .bind(&binding_digest_bytes)
        .bind(&identity_kind)
        .bind(request.binding().identity_ref())
        .bind(&identity_digest)
        .bind(enum_name(&request.binding().attribution()).map_err(TxFailure::rollback)?)
        .bind(sql_i64(request.binding().valid_from_unix_ms()).map_err(TxFailure::rollback)?)
        .bind(
            request
                .binding()
                .valid_until_unix_ms()
                .map(sql_i64)
                .transpose()
                .map_err(TxFailure::rollback)?,
        )
        .bind(sql_i64(ingest_sequence).map_err(TxFailure::rollback)?)
        .bind(
            serde_json::to_value(&accepted_binding)
                .map_err(|_| TxFailure::rollback(repository_failure()))?,
        )
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_insert_runtime_binding", error))?;
        if request.binding().attribution() == RuntimeAttribution::Exact {
            let result = if exact_identity_already_bound_to_run {
                sqlx::query(
                    "UPDATE apolysis_gateway.active_runtime_identities \
                     SET binding_id=$4, activated_at_unix_ms=$5 \
                     WHERE organization_id=$1 AND identity_kind=$2 AND identity_digest=$3 \
                       AND run_id=$6",
                )
                .bind(context.organization_id().as_str())
                .bind(&identity_kind)
                .bind(&identity_digest)
                .bind(request.binding().binding_id())
                .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
                .bind(request.run_id().as_str())
                .execute(&mut **transaction)
                .await
                .map_err(|error| {
                    TxFailure::from_sqlx_at("bind_runtime_update_active_runtime_identity", error)
                })?
            } else {
                sqlx::query(
                    "INSERT INTO apolysis_gateway.active_runtime_identities (\
                        organization_id, identity_kind, identity_digest, run_id, binding_id, \
                        activated_at_unix_ms\
                     ) VALUES ($1,$2,$3,$4,$5,$6) \
                     ON CONFLICT (organization_id, identity_kind, identity_digest) DO NOTHING",
                )
                .bind(context.organization_id().as_str())
                .bind(&identity_kind)
                .bind(&identity_digest)
                .bind(request.run_id().as_str())
                .bind(request.binding().binding_id())
                .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
                .execute(&mut **transaction)
                .await
                .map_err(|error| {
                    TxFailure::from_sqlx_at("bind_runtime_insert_active_runtime_identity", error)
                })?
            };
            if result.rows_affected() != 1 {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::InvalidContract,
                )));
            }
        }
        let response = BindRuntimeResponse::new(
            request.run_id().clone(),
            request.binding().binding_id(),
            true,
            false,
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let outcome = LedgerOutcome::BindRuntime(response);
        self.store_operation(
            transaction,
            &identity,
            request.request_digest(),
            request.run_id(),
            now_unix_ms,
            &outcome,
        )
        .await?;
        Ok(outcome)
    }
}

struct LeaseRow {
    run_id: String,
    source_registration_id: String,
    source_stream_id: String,
    source_id: String,
    principal_kind: String,
    principal_id: String,
    registration_policy_revision: u64,
    expires_at_unix_ms: u64,
    revoked: bool,
    allowed_operations: Vec<String>,
}

struct StreamRow {
    manifest: SourceManifest,
    manifest_digest: String,
    registration_policy_revision: u64,
    effective_trust_profile: TrustProfile,
}

async fn load_lease(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
    request: &BindRuntimeRequest,
) -> TxResult<LeaseRow> {
    let lease_digest =
        hex_digest(&lease_id_digest(request.lease_id())).map_err(TxFailure::rollback)?;
    sqlx::query_scalar::<_, bool>("SELECT apolysis_gateway.lock_gateway_lease($1,$2)")
        .bind(context.organization_id().as_str())
        .bind(&lease_digest)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_lock_lease", error))?;
    let row = sqlx::query(
        "SELECT run_id, source_registration_id, source_stream_id, source_id, principal_kind, \
                principal_id, registration_policy_revision, expires_at_unix_ms, revoked_at_unix_ms \
         FROM apolysis_gateway.leases \
         WHERE organization_id=$1 AND lease_digest=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(&lease_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_load_lease", error))?
    .ok_or_else(|| TxFailure::rollback(lease_failure(ContractErrorCode::LeaseScopeMismatch)))?;
    let allowed_operations = sqlx::query_scalar::<_, String>(
        "SELECT operation_kind FROM apolysis_gateway.lease_operations \
         WHERE organization_id=$1 AND lease_digest=$2 ORDER BY operation_kind",
    )
    .bind(context.organization_id().as_str())
    .bind(&lease_digest)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_load_lease_operations", error))?;
    Ok(LeaseRow {
        run_id: row
            .try_get("run_id")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        source_registration_id: row
            .try_get("source_registration_id")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        source_stream_id: row
            .try_get("source_stream_id")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        source_id: row
            .try_get("source_id")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        principal_kind: row
            .try_get("principal_kind")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        principal_id: row
            .try_get("principal_id")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        registration_policy_revision: sql_u64(
            row.try_get("registration_policy_revision")
                .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        )
        .map_err(TxFailure::rollback)?,
        expires_at_unix_ms: sql_u64(
            row.try_get("expires_at_unix_ms")
                .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?,
        )
        .map_err(TxFailure::rollback)?,
        revoked: row
            .try_get::<Option<i64>, _>("revoked_at_unix_ms")
            .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_lease", error))?
            .is_some(),
        allowed_operations,
    })
}

fn validate_lease(
    context: &AuthenticatedSourceContext,
    request: &BindRuntimeRequest,
    lease: &LeaseRow,
) -> TxResult<()> {
    if lease.revoked
        || lease.registration_policy_revision != context.authentication().policy_revision()
    {
        return Err(TxFailure::rollback(lease_failure(
            ContractErrorCode::LeaseRevoked,
        )));
    }
    if lease.run_id != request.run_id().as_str()
        || lease.source_registration_id != context.source_registration_id()
        || lease.principal_kind
            != principal_kind_name(context.principal().kind()).map_err(TxFailure::rollback)?
        || lease.principal_id != context.principal().id()
        || lease.source_id != request.binding().asserting_source_id().as_str()
        || !lease
            .allowed_operations
            .contains(&enum_name(&GatewayOperation::BindRuntime).map_err(TxFailure::rollback)?)
    {
        return Err(TxFailure::rollback(lease_failure(
            ContractErrorCode::LeaseScopeMismatch,
        )));
    }
    Ok(())
}

async fn load_stream(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
    request: &BindRuntimeRequest,
    lease: &LeaseRow,
) -> TxResult<StreamRow> {
    let row = sqlx::query(
        "SELECT manifest_json, manifest_digest, registration_policy_revision, effective_trust_profile, source_id \
         FROM apolysis_gateway.source_streams \
         WHERE organization_id=$1 AND run_id=$2 AND source_registration_id=$3 AND source_stream_id=$4",
    )
    .bind(context.organization_id().as_str())
    .bind(request.run_id().as_str())
    .bind(context.source_registration_id())
    .bind(&lease.source_stream_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_load_source_stream", error))?
    .ok_or_else(|| TxFailure::rollback(lease_failure(ContractErrorCode::LeaseScopeMismatch)))?;
    if row
        .try_get::<String, _>("source_id")
        .map_err(|error| TxFailure::from_sqlx_at("bind_runtime_decode_source_stream", error))?
        != lease.source_id
    {
        return Err(TxFailure::rollback(lease_failure(
            ContractErrorCode::LeaseScopeMismatch,
        )));
    }
    Ok(StreamRow {
        manifest: decode_json(row.try_get("manifest_json").map_err(|error| {
            TxFailure::from_sqlx_at("bind_runtime_decode_source_stream", error)
        })?)
        .map_err(TxFailure::rollback)?,
        manifest_digest: encode_digest(&row.try_get::<Vec<u8>, _>("manifest_digest").map_err(
            |error| TxFailure::from_sqlx_at("bind_runtime_decode_source_stream", error),
        )?)
        .map_err(TxFailure::rollback)?,
        registration_policy_revision: sql_u64(
            row.try_get("registration_policy_revision")
                .map_err(|error| {
                    TxFailure::from_sqlx_at("bind_runtime_decode_source_stream", error)
                })?,
        )
        .map_err(TxFailure::rollback)?,
        effective_trust_profile: serde_json::from_value(serde_json::Value::String(
            row.try_get("effective_trust_profile").map_err(|error| {
                TxFailure::from_sqlx_at("bind_runtime_decode_source_stream", error)
            })?,
        ))
        .map_err(|_| TxFailure::rollback(repository_failure()))?,
    })
}

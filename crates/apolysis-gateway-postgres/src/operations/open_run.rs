// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::{
    AgentExecutionRecordFact, AuthenticatedSourceContext, GatewayOperation, OpenRunOutcome,
    OpenRunRequest, OpenRunResponse, RegisteredSource, RunDescriptor, RunId, RunLease,
    RunPolicySelection, RunState, RunStateTransition, SourceManifest,
};
use apolysis_gateway::{
    canonical_source_manifest_digest, lease_id_digest, AuditReason, GatewayFailure,
    GatewayIdGenerator, LedgerOutcome, MAX_SOURCE_STREAMS_PER_RUN,
};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    error::{idempotency_conflict, policy_failure, repository_failure},
    model::{enum_name, join_proof_digest, principal_kind_name, sql_i64},
    repository::{
        digest_bytes, next_id, operation_identity, PostgresGatewayRepository, TxFailure, TxResult,
    },
};

impl PostgresGatewayRepository {
    pub(crate) async fn execute_open_run(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        request: &OpenRunRequest,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
        ids: &dyn GatewayIdGenerator,
    ) -> TxResult<LedgerOutcome> {
        let identity = operation_identity(context, "open_run", request.client_operation_id())
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
        self.ensure_organization(transaction, context.organization_id().as_str(), now_unix_ms)
            .await?;

        let prepared = match request {
            OpenRunRequest::Create {
                client_run_key,
                environment,
                authority,
                principal,
                objective_ref,
                privacy_profile_ref,
                retention_profile_ref,
                expected_source_kinds,
                source_manifest,
                ..
            } => {
                let principal_kind =
                    principal_kind_name(context.principal().kind()).map_err(TxFailure::rollback)?;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 573274118))")
                    .bind(client_run_advisory_lock_key(
                        context.organization_id().as_str(),
                        &principal_kind,
                        context.principal().id(),
                        client_run_key,
                    ))
                    .execute(&mut **transaction)
                    .await
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("open_run_lock_client_run_key", error)
                    })?;
                sqlx::query_scalar::<_, bool>(
                    "SELECT apolysis_gateway.lock_gateway_client_run($1,$2,$3,$4)",
                )
                .bind(context.organization_id().as_str())
                .bind(&principal_kind)
                .bind(context.principal().id())
                .bind(client_run_key)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| TxFailure::from_sqlx_at("open_run_lock_client_run_row", error))?;
                let existing: Option<i32> = sqlx::query_scalar(
                    "SELECT 1 FROM apolysis_gateway.client_runs \
                     WHERE organization_id=$1 AND principal_kind=$2 AND principal_id=$3 \
                       AND client_run_key=$4",
                )
                .bind(context.organization_id().as_str())
                .bind(&principal_kind)
                .bind(context.principal().id())
                .bind(client_run_key)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|error| TxFailure::from_sqlx_at("open_run_load_client_run_key", error))?;
                if existing.is_some() {
                    return Err(TxFailure::rollback(idempotency_conflict()));
                }
                let run_id = RunId::try_from(next_id(ids, "run").map_err(TxFailure::rollback)?)
                    .map_err(|_| TxFailure::rollback(repository_failure()))?;
                let source_stream_id = next_id(ids, "stream").map_err(TxFailure::rollback)?;
                let now = sql_i64(now_unix_ms).map_err(TxFailure::rollback)?;
                sqlx::query(
                    "INSERT INTO apolysis_gateway.runs (\
                        organization_id, run_id, state, environment, authority_kind, authority_id, \
                        principal_kind, principal_id, objective_ref, privacy_profile_ref, \
                        retention_profile_ref, initiating_source_registration_id, \
                        initiating_principal_kind, initiating_principal_id, opened_at_unix_ms, \
                        state_changed_at_unix_ms\
                     ) VALUES ($1,$2,'active',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)",
                )
                .bind(context.organization_id().as_str())
                .bind(run_id.as_str())
                .bind(enum_name(environment).map_err(TxFailure::rollback)?)
                .bind(enum_name(&authority.kind()).map_err(TxFailure::rollback)?)
                .bind(authority.id())
                .bind(principal_kind_name(principal.kind()).map_err(TxFailure::rollback)?)
                .bind(principal.id())
                .bind(objective_ref)
                .bind(privacy_profile_ref)
                .bind(retention_profile_ref)
                .bind(context.source_registration_id())
                .bind(principal_kind_name(context.principal().kind()).map_err(TxFailure::rollback)?)
                .bind(context.principal().id())
                .bind(now)
                .execute(&mut **transaction)
                .await
                .map_err(|error| TxFailure::from_sqlx_at("open_run_insert_run", error))?;
                for source_kind in expected_source_kinds {
                    sqlx::query(
                        "INSERT INTO apolysis_gateway.run_expected_source_kinds (\
                            organization_id, run_id, source_kind\
                         ) VALUES ($1,$2,$3)",
                    )
                    .bind(context.organization_id().as_str())
                    .bind(run_id.as_str())
                    .bind(enum_name(source_kind).map_err(TxFailure::rollback)?)
                    .execute(&mut **transaction)
                    .await
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("open_run_insert_expected_source_kind", error)
                    })?;
                }
                sqlx::query(
                    "INSERT INTO apolysis_gateway.client_runs (\
                        organization_id, principal_kind, principal_id, client_run_key, run_id, \
                        created_at_unix_ms\
                     ) VALUES ($1,$2,$3,$4,$5,$6)",
                )
                .bind(context.organization_id().as_str())
                .bind(&principal_kind)
                .bind(context.principal().id())
                .bind(client_run_key)
                .bind(run_id.as_str())
                .bind(now)
                .execute(&mut **transaction)
                .await
                .map_err(|error| TxFailure::from_sqlx_at("open_run_insert_client_run", error))?;

                let policy = RunPolicySelection::new(
                    privacy_profile_ref,
                    retention_profile_ref,
                    expected_source_kinds.clone(),
                )
                .map_err(|_| TxFailure::rollback(repository_failure()))?;
                let descriptor = RunDescriptor::new(
                    context.organization_id().as_str(),
                    run_id.as_str(),
                    authority.clone(),
                    principal.clone(),
                    objective_ref,
                    *environment,
                    policy,
                )
                .map_err(|_| TxFailure::rollback(repository_failure()))?;
                self.append_fact(
                    transaction,
                    context,
                    &run_id,
                    now_unix_ms,
                    AgentExecutionRecordFact::RunOpened(Box::new(descriptor)),
                )
                .await?;
                self.append_fact(
                    transaction,
                    context,
                    &run_id,
                    now_unix_ms,
                    AgentExecutionRecordFact::RunStateChanged(
                        RunStateTransition::new(RunState::Opening, RunState::Active, now_unix_ms)
                            .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    ),
                )
                .await?;
                PreparedOpen {
                    run_id,
                    source_stream_id,
                    source_manifest,
                    outcome: OpenRunOutcome::Created,
                    allowed_operations: context.registration_policy().allowed_operations().to_vec(),
                    lease_expires_at_unix_ms,
                    consumed_grant_digest: None,
                }
            }
            OpenRunRequest::Join {
                run_id,
                join_proof,
                source_manifest,
                ..
            } => {
                let run = self
                    .load_run_for_update(transaction, context.organization_id().as_str(), run_id)
                    .await?;
                let proof_digest = join_proof_digest(join_proof.proof_ref());
                let grant = sqlx::query(
                    "SELECT authorization_kind, authorization_state, run_id, source_id, \
                            source_kind, environment, source_registration_id, principal_kind, \
                            principal_id, registration_policy_revision, expires_at_unix_ms \
                     FROM apolysis_gateway.join_authorizations \
                     WHERE organization_id=$1 AND proof_digest=$2 FOR UPDATE",
                )
                .bind(context.organization_id().as_str())
                .bind(&proof_digest)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|error| {
                    TxFailure::from_sqlx_at("open_run_load_join_authorization", error)
                })?
                .ok_or_else(|| {
                    TxFailure::rollback(policy_failure(
                        apolysis_contracts::ContractErrorCode::NotFound,
                    ))
                })?;
                let grant_kind: String = grant.try_get("authorization_kind").map_err(|error| {
                    TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                })?;
                let grant_expires: i64 = grant.try_get("expires_at_unix_ms").map_err(|error| {
                    TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                })?;
                let authorized = grant_kind
                    == enum_name(&join_proof.kind()).map_err(TxFailure::rollback)?
                    && grant
                        .try_get::<String, _>("authorization_state")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                        })?
                        == "pending"
                    && grant.try_get::<String, _>("run_id").map_err(|error| {
                        TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                    })? == run_id.as_str()
                    && grant.try_get::<String, _>("source_id").map_err(|error| {
                        TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                    })? == source_manifest.source_id().as_str()
                    && grant.try_get::<String, _>("source_kind").map_err(|error| {
                        TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                    })? == enum_name(&source_manifest.source_kind())
                        .map_err(TxFailure::rollback)?
                    && grant.try_get::<String, _>("environment").map_err(|error| {
                        TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                    })? == enum_name(&source_manifest.environment())
                        .map_err(TxFailure::rollback)?
                    && grant
                        .try_get::<String, _>("source_registration_id")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                        })?
                        == context.source_registration_id()
                    && grant
                        .try_get::<String, _>("principal_kind")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                        })?
                        == principal_kind_name(context.principal().kind())
                            .map_err(TxFailure::rollback)?
                    && grant
                        .try_get::<String, _>("principal_id")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                        })?
                        == context.principal().id()
                    && grant
                        .try_get::<i64, _>("registration_policy_revision")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("open_run_decode_join_authorization", error)
                        })?
                        == sql_i64(context.authentication().policy_revision())
                            .map_err(TxFailure::rollback)?
                    && grant_expires
                        == sql_i64(join_proof.expires_at_unix_ms()).map_err(TxFailure::rollback)?
                    && sql_i64(now_unix_ms).map_err(TxFailure::rollback)? < grant_expires;
                if !authorized {
                    return Err(TxFailure::rollback(policy_failure(
                        apolysis_contracts::ContractErrorCode::NotFound,
                    )));
                }
                if self
                    .reconcile_expired_run(transaction, context, run_id, &run, now_unix_ms)
                    .await?
                {
                    return Err(TxFailure::commit(policy_failure(
                        apolysis_contracts::ContractErrorCode::InvalidLifecycleTransition,
                    )));
                }
                if matches!(run.state, RunState::Finished | RunState::Incomplete) {
                    return Err(TxFailure::rollback(policy_failure(
                        apolysis_contracts::ContractErrorCode::InvalidLifecycleTransition,
                    )));
                }
                let stream_count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM apolysis_gateway.source_streams \
                     WHERE organization_id=$1 AND run_id=$2",
                )
                .bind(context.organization_id().as_str())
                .bind(run_id.as_str())
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| TxFailure::from_sqlx_at("open_run_count_source_streams", error))?;
                if stream_count
                    >= i64::try_from(MAX_SOURCE_STREAMS_PER_RUN)
                        .map_err(|_| TxFailure::rollback(repository_failure()))?
                {
                    return Err(TxFailure::rollback(GatewayFailure::admission_limit(
                        AuditReason::AdmissionLimit,
                    )));
                }
                let lease_expiry = if run.state == RunState::Finishing {
                    let deadline = run
                        .finalization_deadline_unix_ms
                        .ok_or_else(|| TxFailure::rollback(repository_failure()))?;
                    if now_unix_ms >= deadline {
                        return Err(TxFailure::rollback(policy_failure(
                            apolysis_contracts::ContractErrorCode::InvalidLifecycleTransition,
                        )));
                    }
                    lease_expires_at_unix_ms.min(deadline)
                } else {
                    lease_expires_at_unix_ms
                };
                let source_stream_id = next_id(ids, "stream").map_err(TxFailure::rollback)?;
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
                PreparedOpen {
                    run_id: run_id.clone(),
                    source_stream_id,
                    source_manifest,
                    outcome: OpenRunOutcome::Joined,
                    allowed_operations,
                    lease_expires_at_unix_ms: lease_expiry,
                    consumed_grant_digest: (grant_kind == "grant").then_some(proof_digest),
                }
            }
        };

        let lease_id = next_id(ids, "lease").map_err(TxFailure::rollback)?;
        let lease = RunLease::new(
            lease_id.clone(),
            prepared.lease_expires_at_unix_ms,
            prepared.allowed_operations.clone(),
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let response = OpenRunResponse::new(
            prepared.run_id.clone(),
            context.registration_policy().source_id().clone(),
            prepared.source_stream_id.clone(),
            prepared.outcome,
            lease,
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let registered = RegisteredSource::new(
            context.source_registration_id(),
            &prepared.source_stream_id,
            context.authentication().policy_revision(),
            context.principal().clone(),
            prepared.source_manifest.clone(),
            context.registration_policy().effective_trust_profile(),
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let registered_ingest_sequence = self
            .append_fact(
                transaction,
                context,
                &prepared.run_id,
                now_unix_ms,
                AgentExecutionRecordFact::SourceRegistered(Box::new(registered)),
            )
            .await?;
        self.insert_source_stream_and_lease(
            transaction,
            context,
            &prepared,
            &lease_id,
            registered_ingest_sequence,
            now_unix_ms,
        )
        .await?;
        if let Some(proof_digest) = prepared.consumed_grant_digest {
            let updated = sqlx::query(
                "UPDATE apolysis_gateway.join_authorizations \
                 SET authorization_state='consumed', consumed_at_unix_ms=$3 \
                 WHERE organization_id=$1 AND proof_digest=$2 \
                   AND authorization_kind='grant' AND authorization_state='pending'",
            )
            .bind(context.organization_id().as_str())
            .bind(proof_digest)
            .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                TxFailure::from_sqlx_at("open_run_consume_join_authorization", error)
            })?;
            if updated.rows_affected() != 1 {
                return Err(TxFailure::rollback(idempotency_conflict()));
            }
        }
        let outcome = LedgerOutcome::OpenRun(response);
        self.store_operation(
            transaction,
            &identity,
            request.request_digest(),
            &prepared.run_id,
            now_unix_ms,
            &outcome,
        )
        .await?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_source_stream_and_lease(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        prepared: &PreparedOpen<'_>,
        lease_id: &str,
        registered_ingest_sequence: u64,
        now_unix_ms: u64,
    ) -> TxResult<()> {
        let manifest_digest = canonical_source_manifest_digest(prepared.source_manifest)
            .map_err(|_| TxFailure::rollback(repository_failure()))?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.source_streams (\
                organization_id, run_id, source_registration_id, source_stream_id, source_id, \
                source_kind, environment, registration_principal_kind, registration_principal_id, \
                registration_policy_revision, effective_trust_profile, manifest_version, \
                manifest_digest, manifest_json, registered_ingest_sequence, registered_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(context.organization_id().as_str())
        .bind(prepared.run_id.as_str())
        .bind(context.source_registration_id())
        .bind(&prepared.source_stream_id)
        .bind(prepared.source_manifest.source_id().as_str())
        .bind(enum_name(&prepared.source_manifest.source_kind()).map_err(TxFailure::rollback)?)
        .bind(enum_name(&prepared.source_manifest.environment()).map_err(TxFailure::rollback)?)
        .bind(principal_kind_name(context.principal().kind()).map_err(TxFailure::rollback)?)
        .bind(context.principal().id())
        .bind(sql_i64(context.authentication().policy_revision()).map_err(TxFailure::rollback)?)
        .bind(
            enum_name(&context.registration_policy().effective_trust_profile())
                .map_err(TxFailure::rollback)?,
        )
        .bind(enum_name(&prepared.source_manifest.schema_version()).map_err(TxFailure::rollback)?)
        .bind(digest_bytes(&manifest_digest).map_err(TxFailure::rollback)?)
        .bind(
            serde_json::to_value(prepared.source_manifest)
                .map_err(|_| TxFailure::rollback(repository_failure()))?,
        )
        .bind(sql_i64(registered_ingest_sequence).map_err(TxFailure::rollback)?)
        .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("open_run_insert_source_stream", error))?;
        for capability in prepared.source_manifest.capabilities() {
            sqlx::query(
                "INSERT INTO apolysis_gateway.source_stream_capabilities (\
                    organization_id, run_id, source_registration_id, source_stream_id, capability\
                 ) VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(context.organization_id().as_str())
            .bind(prepared.run_id.as_str())
            .bind(context.source_registration_id())
            .bind(&prepared.source_stream_id)
            .bind(enum_name(capability).map_err(TxFailure::rollback)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                TxFailure::from_sqlx_at("open_run_insert_source_stream_capability", error)
            })?;
        }
        let lease_digest = digest_bytes(&lease_id_digest(lease_id)).map_err(TxFailure::rollback)?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.leases (\
                organization_id, lease_digest, run_id, source_registration_id, source_stream_id, \
                source_id, principal_kind, principal_id, registration_policy_revision, \
                issued_at_unix_ms, expires_at_unix_ms\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(context.organization_id().as_str())
        .bind(&lease_digest)
        .bind(prepared.run_id.as_str())
        .bind(context.source_registration_id())
        .bind(&prepared.source_stream_id)
        .bind(prepared.source_manifest.source_id().as_str())
        .bind(principal_kind_name(context.principal().kind()).map_err(TxFailure::rollback)?)
        .bind(context.principal().id())
        .bind(sql_i64(context.authentication().policy_revision()).map_err(TxFailure::rollback)?)
        .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
        .bind(sql_i64(prepared.lease_expires_at_unix_ms).map_err(TxFailure::rollback)?)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("open_run_insert_lease", error))?;
        for operation in &prepared.allowed_operations {
            sqlx::query(
                "INSERT INTO apolysis_gateway.lease_operations (\
                    organization_id, lease_digest, operation_kind\
                 ) VALUES ($1,$2,$3)",
            )
            .bind(context.organization_id().as_str())
            .bind(&lease_digest)
            .bind(enum_name(operation).map_err(TxFailure::rollback)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("open_run_insert_lease_operation", error))?;
        }
        Ok(())
    }
}

fn client_run_advisory_lock_key(
    organization_id: &str,
    principal_kind: &str,
    principal_id: &str,
    client_run_key: &str,
) -> String {
    let mut value = String::new();
    for component in [
        organization_id,
        principal_kind,
        principal_id,
        client_run_key,
    ] {
        value.push_str(&component.len().to_string());
        value.push(':');
        value.push_str(component);
    }
    value
}

struct PreparedOpen<'a> {
    run_id: RunId,
    source_stream_id: String,
    source_manifest: &'a SourceManifest,
    outcome: OpenRunOutcome,
    allowed_operations: Vec<GatewayOperation>,
    lease_expires_at_unix_ms: u64,
    consumed_grant_digest: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_run_lock_key_is_text_safe_and_boundary_unambiguous() {
        let first = client_run_advisory_lock_key("ab", "c", "principal", "run-key");
        let different_boundary = client_run_advisory_lock_key("a", "bc", "principal", "run-key");
        assert!(!first.contains('\0'));
        assert_ne!(first, different_boundary);
    }
}

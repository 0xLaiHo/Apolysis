// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use apolysis_contracts::{
    AcceptedRunFinalization, AgentExecutionRecordFact, AuthenticatedSourceContext,
    ContractErrorCode, FinishRunRequest, FinishRunResponse, GatewayOperation, RunState,
    RunStateTransition, SourceId, TerminalSourcePosition,
};
use apolysis_gateway::{lease_id_digest, LedgerOutcome};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    error::{lease_failure, policy_failure, repository_failure},
    model::{enum_name, hex_digest, principal_kind_name, sql_i64, sql_u64},
    repository::{operation_identity, PostgresGatewayRepository, TxFailure, TxResult},
};

impl PostgresGatewayRepository {
    pub(crate) async fn execute_finish_run(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        request: &FinishRunRequest,
        now_unix_ms: u64,
        finalization_deadline_unix_ms: u64,
    ) -> TxResult<LedgerOutcome> {
        let identity = operation_identity(context, "finish_run", request.client_operation_id())
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
        if run.initiating_source_registration_id != context.source_registration_id()
            && !context.registration_policy().may_finalize_runs()
        {
            return Err(TxFailure::rollback(policy_failure(
                ContractErrorCode::Forbidden,
            )));
        }
        if self
            .reconcile_expired_run(transaction, context, request.run_id(), &run, now_unix_ms)
            .await?
        {
            let response =
                FinishRunResponse::new(request.run_id().clone(), RunState::Incomplete, None, false)
                    .map_err(|_| TxFailure::rollback(repository_failure()))?;
            let outcome = LedgerOutcome::FinishRun(response);
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
        if matches!(run.state, RunState::Finished | RunState::Incomplete) {
            return Err(TxFailure::rollback(policy_failure(
                ContractErrorCode::InvalidLifecycleTransition,
            )));
        }
        if run.state == RunState::Active && finalization_deadline_unix_ms <= now_unix_ms {
            return Err(TxFailure::rollback(policy_failure(
                ContractErrorCode::InvalidContract,
            )));
        }
        if now_unix_ms >= lease.expires_at_unix_ms {
            return Err(TxFailure::rollback(lease_failure(
                ContractErrorCode::LeaseExpired,
            )));
        }

        let stream_rows = sqlx::query(
            "SELECT stream.source_stream_id, stream.source_id, stream.source_kind, \
                    count(event.source_sequence) AS event_count, min(event.source_sequence) AS min_sequence, \
                    max(event.source_sequence) AS max_sequence \
             FROM apolysis_gateway.source_streams AS stream \
             LEFT JOIN apolysis_gateway.evidence_events AS event \
               ON event.organization_id=stream.organization_id AND event.run_id=stream.run_id \
              AND event.source_registration_id=stream.source_registration_id \
              AND event.source_stream_id=stream.source_stream_id \
             WHERE stream.organization_id=$1 AND stream.run_id=$2 \
             GROUP BY stream.source_stream_id, stream.source_id, stream.source_kind \
             ORDER BY stream.source_stream_id",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("finish_run_load_stream_states", error))?;
        let mut streams = BTreeMap::new();
        for row in stream_rows {
            let stream_id: String = row.try_get("source_stream_id").map_err(|error| {
                TxFailure::from_sqlx_at("finish_run_decode_stream_state", error)
            })?;
            streams.insert(
                stream_id,
                StreamState {
                    source_id: SourceId::try_from(row.try_get::<String, _>("source_id").map_err(
                        |error| TxFailure::from_sqlx_at("finish_run_decode_stream_state", error),
                    )?)
                    .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    source_kind: row.try_get("source_kind").map_err(|error| {
                        TxFailure::from_sqlx_at("finish_run_decode_stream_state", error)
                    })?,
                    event_count: sql_u64(row.try_get("event_count").map_err(|error| {
                        TxFailure::from_sqlx_at("finish_run_decode_stream_state", error)
                    })?)
                    .map_err(TxFailure::rollback)?,
                    min_sequence: row
                        .try_get::<Option<i64>, _>("min_sequence")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("finish_run_decode_stream_state", error)
                        })?
                        .map(sql_u64)
                        .transpose()
                        .map_err(TxFailure::rollback)?,
                    max_sequence: row
                        .try_get::<Option<i64>, _>("max_sequence")
                        .map_err(|error| {
                            TxFailure::from_sqlx_at("finish_run_decode_stream_state", error)
                        })?
                        .map(sql_u64)
                        .transpose()
                        .map_err(TxFailure::rollback)?,
                },
            );
        }
        let prior_position_rows = sqlx::query(
            "SELECT DISTINCT ON (source_stream_id) source_stream_id, source_id, final_source_sequence \
             FROM apolysis_gateway.finalization_terminal_positions \
             WHERE organization_id=$1 AND run_id=$2 \
             ORDER BY source_stream_id, declaration_revision DESC",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| {
            TxFailure::from_sqlx_at("finish_run_load_terminal_positions", error)
        })?;
        let mut declared_positions = BTreeMap::new();
        for row in prior_position_rows {
            declared_positions.insert(
                row.try_get::<String, _>("source_stream_id")
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("finish_run_decode_terminal_position", error)
                    })?,
                DeclaredPosition {
                    source_id: SourceId::try_from(row.try_get::<String, _>("source_id").map_err(
                        |error| {
                            TxFailure::from_sqlx_at("finish_run_decode_terminal_position", error)
                        },
                    )?)
                    .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    final_source_sequence: sql_u64(row.try_get("final_source_sequence").map_err(
                        |error| {
                            TxFailure::from_sqlx_at("finish_run_decode_terminal_position", error)
                        },
                    )?)
                    .map_err(TxFailure::rollback)?,
                },
            );
        }
        for position in request.terminal_positions() {
            let stream = streams.get(position.source_stream_id()).ok_or_else(|| {
                TxFailure::rollback(policy_failure(ContractErrorCode::InvalidContract))
            })?;
            if stream.source_id != *position.source_id()
                || position.final_source_sequence() < stream.max_sequence.unwrap_or_default()
                || declared_positions
                    .get(position.source_stream_id())
                    .is_some_and(|prior| {
                        prior.source_id != *position.source_id()
                            || prior.final_source_sequence != position.final_source_sequence()
                    })
            {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::InvalidContract,
                )));
            }
            declared_positions.insert(
                position.source_stream_id().to_string(),
                DeclaredPosition {
                    source_id: position.source_id().clone(),
                    final_source_sequence: position.final_source_sequence(),
                },
            );
        }
        let prior_outcomes = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT outcome_claim_ref \
             FROM apolysis_gateway.finalization_outcome_claims \
             WHERE organization_id=$1 AND run_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("finish_run_load_outcome_claims", error))?;
        let mut outcome_claim_refs = prior_outcomes.into_iter().collect::<BTreeSet<_>>();
        outcome_claim_refs.extend(request.outcome_claim_refs().iter().cloned());
        let expected_source_kinds = sqlx::query_scalar::<_, String>(
            "SELECT source_kind FROM apolysis_gateway.run_expected_source_kinds \
             WHERE organization_id=$1 AND run_id=$2 ORDER BY source_kind",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("finish_run_load_expected_source_kinds", error))?;
        let all_expected_sources_registered = expected_source_kinds.iter().all(|expected| {
            streams
                .values()
                .any(|stream| &stream.source_kind == expected)
        });
        let all_required_streams_declared = streams.iter().all(|(stream_id, stream)| {
            !expected_source_kinds.contains(&stream.source_kind)
                || declared_positions.contains_key(stream_id)
        });
        let all_declared_positions_reconciled =
            declared_positions.iter().all(|(stream_id, position)| {
                streams.get(stream_id).is_some_and(|stream| {
                    stream.source_id == position.source_id
                        && stream.min_sequence == Some(1)
                        && stream.max_sequence == Some(position.final_source_sequence)
                        && stream.event_count == position.final_source_sequence
                })
            });
        let next_state = if all_expected_sources_registered
            && all_required_streams_declared
            && all_declared_positions_reconciled
        {
            RunState::Finished
        } else {
            RunState::Finishing
        };
        let accepted_deadline = run
            .finalization_deadline_unix_ms
            .unwrap_or_else(|| finalization_deadline_unix_ms.min(lease.expires_at_unix_ms));
        let response_deadline = (next_state != RunState::Finished).then_some(accepted_deadline);
        let response = FinishRunResponse::new(
            request.run_id().clone(),
            next_state,
            response_deadline,
            false,
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let accepted_positions = declared_positions
            .iter()
            .map(|(stream_id, position)| {
                TerminalSourcePosition::new(
                    position.source_id.clone(),
                    stream_id,
                    position.final_source_sequence,
                )
                .map_err(|_| TxFailure::rollback(repository_failure()))
            })
            .collect::<TxResult<Vec<_>>>()?;
        let accepted_finalization = AcceptedRunFinalization::new(
            context.source_registration_id(),
            &lease.source_stream_id,
            context.principal().clone(),
            lease.registration_policy_revision,
            accepted_positions,
            outcome_claim_refs.iter().cloned().collect(),
            accepted_deadline,
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let ingest_sequence = self
            .append_fact(
                transaction,
                context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunFinalizationDeclared(Box::new(accepted_finalization)),
            )
            .await?;
        if run.state == RunState::Active && next_state == RunState::Finished {
            self.append_fact(
                transaction,
                context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(RunState::Active, RunState::Finishing, now_unix_ms)
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                ),
            )
            .await?;
            self.append_fact(
                transaction,
                context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(RunState::Finishing, RunState::Finished, now_unix_ms)
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                ),
            )
            .await?;
        } else if next_state != run.state {
            self.append_fact(
                transaction,
                context,
                request.run_id(),
                now_unix_ms,
                AgentExecutionRecordFact::RunStateChanged(
                    RunStateTransition::new(run.state, next_state, now_unix_ms)
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                ),
            )
            .await?;
        }
        let declaration_revision: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max(declaration_revision),0)+1 \
             FROM apolysis_gateway.finalization_declarations \
             WHERE organization_id=$1 AND run_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| {
            TxFailure::from_sqlx_at("finish_run_load_next_declaration_revision", error)
        })?;
        sqlx::query(
            "INSERT INTO apolysis_gateway.finalization_declarations (\
                organization_id, run_id, declaration_revision, declared_by_source_registration_id, \
                declared_by_source_stream_id, declared_by_source_id, declared_by_principal_kind, \
                declared_by_principal_id, registration_policy_revision, accepted_deadline_unix_ms, \
                resulting_run_state, declared_at_unix_ms, ledger_ingest_sequence\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(declaration_revision)
        .bind(context.source_registration_id())
        .bind(&lease.source_stream_id)
        .bind(&lease.source_id)
        .bind(principal_kind_name(context.principal().kind()).map_err(TxFailure::rollback)?)
        .bind(context.principal().id())
        .bind(sql_i64(lease.registration_policy_revision).map_err(TxFailure::rollback)?)
        .bind(sql_i64(accepted_deadline).map_err(TxFailure::rollback)?)
        .bind(enum_name(&next_state).map_err(TxFailure::rollback)?)
        .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
        .bind(sql_i64(ingest_sequence).map_err(TxFailure::rollback)?)
        .execute(&mut **transaction)
        .await
        .map_err(|error| {
            TxFailure::from_sqlx_at("finish_run_insert_finalization_declaration", error)
        })?;
        for (stream_id, position) in &declared_positions {
            sqlx::query(
                "INSERT INTO apolysis_gateway.finalization_terminal_positions (\
                    organization_id, run_id, declaration_revision, source_stream_id, source_id, \
                    final_source_sequence\
                 ) VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(context.organization_id().as_str())
            .bind(request.run_id().as_str())
            .bind(declaration_revision)
            .bind(stream_id)
            .bind(position.source_id.as_str())
            .bind(sql_i64(position.final_source_sequence).map_err(TxFailure::rollback)?)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                TxFailure::from_sqlx_at("finish_run_insert_terminal_position", error)
            })?;
        }
        for outcome_claim_ref in &outcome_claim_refs {
            sqlx::query(
                "INSERT INTO apolysis_gateway.finalization_outcome_claims (\
                    organization_id, run_id, declaration_revision, outcome_claim_ref\
                 ) VALUES ($1,$2,$3,$4)",
            )
            .bind(context.organization_id().as_str())
            .bind(request.run_id().as_str())
            .bind(declaration_revision)
            .bind(outcome_claim_ref)
            .execute(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_insert_outcome_claim", error))?;
        }
        sqlx::query(
            "UPDATE apolysis_gateway.runs \
             SET state=$3, finalization_deadline_unix_ms=$4, state_changed_at_unix_ms=$5, \
                 lock_version=lock_version+1 \
             WHERE organization_id=$1 AND run_id=$2",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(enum_name(&next_state).map_err(TxFailure::rollback)?)
        .bind(
            response_deadline
                .map(sql_i64)
                .transpose()
                .map_err(TxFailure::rollback)?,
        )
        .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
        .execute(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("finish_run_update_run_state", error))?;
        if next_state == RunState::Finished {
            sqlx::query(
                "DELETE FROM apolysis_gateway.active_runtime_identities \
                 WHERE organization_id=$1 AND run_id=$2",
            )
            .bind(context.organization_id().as_str())
            .bind(request.run_id().as_str())
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                TxFailure::from_sqlx_at("finish_run_delete_active_runtime_identities", error)
            })?;
        }
        let outcome = LedgerOutcome::FinishRun(response);
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

struct StreamState {
    source_id: SourceId,
    source_kind: String,
    event_count: u64,
    min_sequence: Option<u64>,
    max_sequence: Option<u64>,
}

struct DeclaredPosition {
    source_id: SourceId,
    final_source_sequence: u64,
}

async fn load_lease(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
    request: &FinishRunRequest,
) -> TxResult<LeaseRow> {
    let lease_digest =
        hex_digest(&lease_id_digest(request.lease_id())).map_err(TxFailure::rollback)?;
    let row = sqlx::query(
        "SELECT run_id, source_registration_id, source_stream_id, source_id, principal_kind, \
                principal_id, registration_policy_revision, expires_at_unix_ms, revoked_at_unix_ms \
         FROM apolysis_gateway.leases WHERE organization_id=$1 AND lease_digest=$2 FOR UPDATE",
    )
    .bind(context.organization_id().as_str())
    .bind(&lease_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("finish_run_load_lease", error))?
    .ok_or_else(|| TxFailure::rollback(lease_failure(ContractErrorCode::LeaseScopeMismatch)))?;
    let allowed_operations = sqlx::query_scalar::<_, String>(
        "SELECT operation_kind FROM apolysis_gateway.lease_operations \
         WHERE organization_id=$1 AND lease_digest=$2 ORDER BY operation_kind",
    )
    .bind(context.organization_id().as_str())
    .bind(&lease_digest)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("finish_run_load_lease_operations", error))?;
    Ok(LeaseRow {
        run_id: row
            .try_get("run_id")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        source_registration_id: row
            .try_get("source_registration_id")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        source_stream_id: row
            .try_get("source_stream_id")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        source_id: row
            .try_get("source_id")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        principal_kind: row
            .try_get("principal_kind")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        principal_id: row
            .try_get("principal_id")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        registration_policy_revision: sql_u64(
            row.try_get("registration_policy_revision")
                .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        )
        .map_err(TxFailure::rollback)?,
        expires_at_unix_ms: sql_u64(
            row.try_get("expires_at_unix_ms")
                .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?,
        )
        .map_err(TxFailure::rollback)?,
        revoked: row
            .try_get::<Option<i64>, _>("revoked_at_unix_ms")
            .map_err(|error| TxFailure::from_sqlx_at("finish_run_decode_lease", error))?
            .is_some(),
        allowed_operations,
    })
}

fn validate_lease(
    context: &AuthenticatedSourceContext,
    request: &FinishRunRequest,
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
        || !lease
            .allowed_operations
            .contains(&enum_name(&GatewayOperation::FinishRun).map_err(TxFailure::rollback)?)
    {
        return Err(TxFailure::rollback(lease_failure(
            ContractErrorCode::LeaseScopeMismatch,
        )));
    }
    Ok(())
}

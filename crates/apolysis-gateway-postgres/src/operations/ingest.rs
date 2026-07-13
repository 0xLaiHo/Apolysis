// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use apolysis_contracts::{
    AcceptedSourceEnvelope, AgentExecutionRecordFact, AuthenticatedSourceContext,
    ContractErrorCode, EnvelopeAck, GatewayOperation, IngestAck, IngestDisposition, IngestRequest,
    RunState, SequenceGap, SourceManifest, TrustProfile,
};
use apolysis_gateway::{canonical_source_envelope_digest, lease_id_digest, LedgerOutcome};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    error::{lease_failure, policy_failure, repository_failure},
    model::{encode_digest, enum_name, hex_digest, principal_kind_name, sql_i64, sql_u64},
    repository::{decode_json, operation_identity, PostgresGatewayRepository, TxFailure, TxResult},
};

impl PostgresGatewayRepository {
    pub(crate) async fn execute_ingest(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: &AuthenticatedSourceContext,
        request: &IngestRequest,
        now_unix_ms: u64,
    ) -> TxResult<LedgerOutcome> {
        let identity = operation_identity(context, "ingest", request.client_operation_id())
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
        let stream = load_stream(transaction, context, request, &lease).await?;
        let terminal_position = if run.state == RunState::Finishing {
            sqlx::query_scalar::<_, i64>(
                "SELECT position.final_source_sequence \
                 FROM apolysis_gateway.finalization_terminal_positions AS position \
                 WHERE position.organization_id=$1 AND position.run_id=$2 \
                   AND position.source_stream_id=$3 \
                 ORDER BY position.declaration_revision DESC LIMIT 1",
            )
            .bind(context.organization_id().as_str())
            .bind(request.run_id().as_str())
            .bind(&lease.source_stream_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("ingest_load_terminal_position", error))?
            .map(sql_u64)
            .transpose()
            .map_err(TxFailure::rollback)?
        } else {
            None
        };

        let event_ids = request
            .envelopes()
            .iter()
            .map(|envelope| envelope.source_event_id().to_string())
            .collect::<Vec<_>>();
        let source_sequences = request
            .envelopes()
            .iter()
            .map(|envelope| sql_i64(envelope.source_sequence()).map_err(TxFailure::rollback))
            .collect::<Result<Vec<_>, _>>()?;
        let existing_rows = sqlx::query(
            "SELECT source_event_id, source_sequence, envelope_digest, ledger_ingest_sequence \
             FROM apolysis_gateway.evidence_events \
             WHERE organization_id=$1 AND run_id=$2 AND source_registration_id=$3 \
               AND source_stream_id=$4 \
               AND (source_event_id=ANY($5::text[]) OR source_sequence=ANY($6::bigint[]))",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(context.source_registration_id())
        .bind(&lease.source_stream_id)
        .bind(&event_ids)
        .bind(&source_sequences)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("ingest_load_existing_events", error))?;
        let mut existing_by_id = HashMap::new();
        let mut existing_by_sequence = HashMap::new();
        for row in existing_rows {
            let event_id: String = row
                .try_get("source_event_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_existing_event", error))?;
            let sequence =
                sql_u64(row.try_get("source_sequence").map_err(|error| {
                    TxFailure::from_sqlx_at("ingest_decode_existing_event", error)
                })?)
                .map_err(TxFailure::rollback)?;
            let stored = ExistingEvent {
                source_sequence: sequence,
                digest: row.try_get("envelope_digest").map_err(|error| {
                    TxFailure::from_sqlx_at("ingest_decode_existing_event", error)
                })?,
                ingest_sequence: sql_u64(row.try_get("ledger_ingest_sequence").map_err(
                    |error| TxFailure::from_sqlx_at("ingest_decode_existing_event", error),
                )?)
                .map_err(TxFailure::rollback)?,
            };
            existing_by_sequence.insert(sequence, event_id.clone());
            existing_by_id.insert(event_id, stored);
        }

        let mut batch_sequences = BTreeMap::new();
        let mut batch_events = HashMap::new();
        let mut classified = Vec::with_capacity(request.envelopes().len());
        for envelope in request.envelopes() {
            if envelope.run_id() != request.run_id()
                || envelope.source_id().as_str() != lease.source_id
                || envelope.source_stream_id() != lease.source_stream_id
            {
                return Err(TxFailure::rollback(lease_failure(
                    ContractErrorCode::LeaseScopeMismatch,
                )));
            }
            if terminal_position.is_some_and(|position| envelope.source_sequence() > position) {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::InvalidLifecycleTransition,
                )));
            }
            let required_capability = envelope
                .inline_payload()
                .map(|payload| payload.required_source_capability())
                .ok_or_else(|| {
                    TxFailure::rollback(policy_failure(ContractErrorCode::ContentNotAuthorized))
                })?;
            if !stream
                .manifest
                .capabilities()
                .contains(&required_capability)
            {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::CapabilityMismatch,
                )));
            }
            let digest = canonical_source_envelope_digest(envelope)
                .map_err(|_| TxFailure::rollback(repository_failure()))?;
            let digest_bytes = hex_digest(&digest).map_err(TxFailure::rollback)?;
            if let Some((prior_sequence, prior_digest)) =
                batch_events.get(envelope.source_event_id())
            {
                if *prior_sequence != envelope.source_sequence() || prior_digest != &digest_bytes {
                    return Err(TxFailure::rollback(policy_failure(
                        ContractErrorCode::SourceEventConflict,
                    )));
                }
                continue;
            }
            batch_events.insert(
                envelope.source_event_id().to_string(),
                (envelope.source_sequence(), digest_bytes.clone()),
            );
            if let Some(existing) = existing_by_id.get(envelope.source_event_id()) {
                if existing.digest != digest_bytes
                    || existing.source_sequence != envelope.source_sequence()
                {
                    return Err(TxFailure::rollback(policy_failure(
                        ContractErrorCode::SourceEventConflict,
                    )));
                }
                classified.push((
                    ClassifiedEvent::Duplicate(existing.ingest_sequence),
                    envelope.clone(),
                ));
                continue;
            }
            if existing_by_sequence
                .get(&envelope.source_sequence())
                .or_else(|| batch_sequences.get(&envelope.source_sequence()))
                .is_some_and(|event_id| event_id != envelope.source_event_id())
            {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::SequenceConflict,
                )));
            }
            batch_sequences.insert(
                envelope.source_sequence(),
                envelope.source_event_id().to_string(),
            );
            classified.push((ClassifiedEvent::Novel(digest_bytes), envelope.clone()));
        }
        if matches!(run.state, RunState::Finished | RunState::Incomplete)
            && classified
                .iter()
                .any(|(event, _)| matches!(event, ClassifiedEvent::Novel(_)))
        {
            return Err(TxFailure::rollback(policy_failure(
                ContractErrorCode::InvalidLifecycleTransition,
            )));
        }

        let mut acknowledgements = Vec::with_capacity(classified.len());
        for (classification, envelope) in classified {
            match classification {
                ClassifiedEvent::Duplicate(ingest_sequence) => {
                    acknowledgements.push(
                        EnvelopeAck::new(
                            envelope.source_event_id(),
                            IngestDisposition::Duplicate,
                            ingest_sequence,
                        )
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    );
                }
                ClassifiedEvent::Novel(envelope_digest) => {
                    let accepted = AcceptedSourceEnvelope::new(
                        context.source_registration_id(),
                        &lease.source_stream_id,
                        stream.registration_policy_revision,
                        stream.effective_trust_profile,
                        stream.manifest.schema_version(),
                        stream.manifest_digest.clone(),
                        envelope.clone(),
                    )
                    .map_err(|_| TxFailure::rollback(repository_failure()))?;
                    let ingest_sequence = self
                        .append_fact(
                            transaction,
                            context,
                            request.run_id(),
                            now_unix_ms,
                            AgentExecutionRecordFact::EvidenceAccepted(Box::new(accepted.clone())),
                        )
                        .await?;
                    sqlx::query(
                        "INSERT INTO apolysis_gateway.evidence_events (\
                            organization_id, run_id, source_registration_id, source_stream_id, \
                            source_id, source_event_id, source_sequence, envelope_digest, \
                            ledger_ingest_sequence, accepted_at_unix_ms, payload_type, \
                            accepted_envelope_json\
                         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                    )
                    .bind(context.organization_id().as_str())
                    .bind(request.run_id().as_str())
                    .bind(context.source_registration_id())
                    .bind(&lease.source_stream_id)
                    .bind(&lease.source_id)
                    .bind(envelope.source_event_id())
                    .bind(sql_i64(envelope.source_sequence()).map_err(TxFailure::rollback)?)
                    .bind(envelope_digest)
                    .bind(sql_i64(ingest_sequence).map_err(TxFailure::rollback)?)
                    .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
                    .bind(envelope.payload_type())
                    .bind(
                        serde_json::to_value(&accepted)
                            .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    )
                    .execute(&mut **transaction)
                    .await
                    .map_err(|error| {
                        TxFailure::from_sqlx_at("ingest_insert_evidence_event", error)
                    })?;
                    acknowledgements.push(
                        EnvelopeAck::new(
                            envelope.source_event_id(),
                            IngestDisposition::Committed,
                            ingest_sequence,
                        )
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    );
                }
            }
        }
        let source_watermark = sql_u64(
            sqlx::query_scalar::<_, Option<i64>>(
                "SELECT max(source_sequence) FROM apolysis_gateway.evidence_events \
                 WHERE organization_id=$1 AND run_id=$2 AND source_registration_id=$3 \
                   AND source_stream_id=$4",
            )
            .bind(context.organization_id().as_str())
            .bind(request.run_id().as_str())
            .bind(context.source_registration_id())
            .bind(&lease.source_stream_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("ingest_load_source_watermark", error))?
            .unwrap_or_default(),
        )
        .map_err(TxFailure::rollback)?;
        let gap_rows = sqlx::query(
            "WITH ordered AS (\
                SELECT source_sequence, lag(source_sequence,1,0) OVER (ORDER BY source_sequence) AS previous \
                FROM apolysis_gateway.evidence_events \
                WHERE organization_id=$1 AND run_id=$2 AND source_registration_id=$3 \
                  AND source_stream_id=$4\
             ) SELECT previous+1 AS first_missing, source_sequence-1 AS last_missing \
               FROM ordered WHERE source_sequence>previous+1 \
               ORDER BY first_missing LIMIT 257",
        )
        .bind(context.organization_id().as_str())
        .bind(request.run_id().as_str())
        .bind(context.source_registration_id())
        .bind(&lease.source_stream_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("ingest_load_source_gaps", error))?;
        if gap_rows.len() > 256 {
            return Err(TxFailure::rollback(repository_failure()));
        }
        let known_gaps = gap_rows
            .into_iter()
            .map(|row| {
                let first =
                    sql_u64(row.try_get("first_missing").map_err(|error| {
                        TxFailure::from_sqlx_at("ingest_decode_source_gap", error)
                    })?)
                    .map_err(TxFailure::rollback)?;
                let last =
                    sql_u64(row.try_get("last_missing").map_err(|error| {
                        TxFailure::from_sqlx_at("ingest_decode_source_gap", error)
                    })?)
                    .map_err(TxFailure::rollback)?;
                SequenceGap::new(first, last).map_err(|_| TxFailure::rollback(repository_failure()))
            })
            .collect::<TxResult<Vec<_>>>()?;
        let durable_ingest_watermark = sql_u64(
            sqlx::query_scalar::<_, i64>(
                "SELECT next_ingest_sequence-1 FROM apolysis_gateway.organization_sequences \
                 WHERE organization_id=$1",
            )
            .bind(context.organization_id().as_str())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| {
                TxFailure::from_sqlx_at("ingest_load_durable_ingest_watermark", error)
            })?,
        )
        .map_err(TxFailure::rollback)?;
        let acknowledgement = IngestAck::new(
            request.run_id().clone(),
            acknowledgements,
            durable_ingest_watermark,
            source_watermark,
            known_gaps,
        )
        .map_err(|_| TxFailure::rollback(repository_failure()))?;
        let outcome = LedgerOutcome::Ingest(acknowledgement);
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

struct ExistingEvent {
    source_sequence: u64,
    digest: Vec<u8>,
    ingest_sequence: u64,
}

enum ClassifiedEvent {
    Duplicate(u64),
    Novel(Vec<u8>),
}

async fn load_lease(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
    request: &IngestRequest,
) -> TxResult<LeaseRow> {
    let lease_digest =
        hex_digest(&lease_id_digest(request.lease_id())).map_err(TxFailure::rollback)?;
    let row = sqlx::query(
        "SELECT run_id, source_registration_id, source_stream_id, source_id, principal_kind, \
                principal_id, registration_policy_revision, expires_at_unix_ms, revoked_at_unix_ms \
         FROM apolysis_gateway.leases \
         WHERE organization_id=$1 AND lease_digest=$2 FOR UPDATE",
    )
    .bind(context.organization_id().as_str())
    .bind(&lease_digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_load_lease", error))?
    .ok_or_else(|| TxFailure::rollback(lease_failure(ContractErrorCode::LeaseScopeMismatch)))?;
    let operation_rows = sqlx::query_scalar::<_, String>(
        "SELECT operation_kind FROM apolysis_gateway.lease_operations \
         WHERE organization_id=$1 AND lease_digest=$2 ORDER BY operation_kind",
    )
    .bind(context.organization_id().as_str())
    .bind(&lease_digest)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_load_lease_operations", error))?;
    Ok(LeaseRow {
        run_id: row
            .try_get("run_id")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        source_registration_id: row
            .try_get("source_registration_id")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        source_stream_id: row
            .try_get("source_stream_id")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        source_id: row
            .try_get("source_id")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        principal_kind: row
            .try_get("principal_kind")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        principal_id: row
            .try_get("principal_id")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        registration_policy_revision: sql_u64(
            row.try_get("registration_policy_revision")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        )
        .map_err(TxFailure::rollback)?,
        expires_at_unix_ms: sql_u64(
            row.try_get("expires_at_unix_ms")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?,
        )
        .map_err(TxFailure::rollback)?,
        revoked: row
            .try_get::<Option<i64>, _>("revoked_at_unix_ms")
            .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_lease", error))?
            .is_some(),
        allowed_operations: operation_rows,
    })
}

fn validate_lease(
    context: &AuthenticatedSourceContext,
    request: &IngestRequest,
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
            .contains(&enum_name(&GatewayOperation::Ingest).map_err(TxFailure::rollback)?)
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
    request: &IngestRequest,
    lease: &LeaseRow,
) -> TxResult<StreamRow> {
    let row = sqlx::query(
        "SELECT manifest_json, manifest_digest, registration_policy_revision, \
                effective_trust_profile, source_id \
         FROM apolysis_gateway.source_streams \
         WHERE organization_id=$1 AND run_id=$2 AND source_registration_id=$3 \
           AND source_stream_id=$4",
    )
    .bind(context.organization_id().as_str())
    .bind(request.run_id().as_str())
    .bind(context.source_registration_id())
    .bind(&lease.source_stream_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_load_source_stream", error))?
    .ok_or_else(|| TxFailure::rollback(lease_failure(ContractErrorCode::LeaseScopeMismatch)))?;
    if row
        .try_get::<String, _>("source_id")
        .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_source_stream", error))?
        != lease.source_id
    {
        return Err(TxFailure::rollback(lease_failure(
            ContractErrorCode::LeaseScopeMismatch,
        )));
    }
    Ok(StreamRow {
        manifest: decode_json(
            row.try_get::<serde_json::Value, _>("manifest_json")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_source_stream", error))?,
        )
        .map_err(TxFailure::rollback)?,
        manifest_digest: encode_digest(
            &row.try_get::<Vec<u8>, _>("manifest_digest")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_source_stream", error))?,
        )
        .map_err(TxFailure::rollback)?,
        registration_policy_revision: sql_u64(
            row.try_get("registration_policy_revision")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_source_stream", error))?,
        )
        .map_err(TxFailure::rollback)?,
        effective_trust_profile: serde_json::from_value(serde_json::Value::String(
            row.try_get("effective_trust_profile")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_source_stream", error))?,
        ))
        .map_err(|_| TxFailure::rollback(repository_failure()))?,
    })
}

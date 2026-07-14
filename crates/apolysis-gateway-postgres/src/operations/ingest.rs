// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use apolysis_contracts::{
    AcceptedSourceEnvelope, AgentExecutionRecordFact, AuthenticatedSourceContext,
    ContractErrorCode, EnvelopeAck, GatewayOperation, IngestAck, IngestDisposition, IngestRequest,
    PrivacyCapability, RunState, SequenceGap, SourceManifest, TrustProfile,
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
        process_now_unix_ms: u64,
    ) -> TxResult<LedgerOutcome> {
        // PostgreSQL is authoritative whenever an ingest can bind external
        // evidence. A skewed process clock must never seal that run early or
        // admit an already-expired object. Content-off ingest retains the
        // injected clock seam used by the existing deterministic contract.
        let includes_object_reference = request
            .envelopes()
            .iter()
            .any(|envelope| envelope.object_ref().is_some());
        let now_unix_ms = if includes_object_reference {
            sql_u64(
                sqlx::query_scalar::<_, i64>(
                    "SELECT apolysis_gateway.evidence_object_db_now_unix_ms()",
                )
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| TxFailure::from_sqlx_at("ingest_read_database_time", error))?,
            )
            .map_err(TxFailure::rollback)?
        } else {
            process_now_unix_ms
        };
        // Establish the shared ancestor lock before operation, run, lease,
        // policy, and object locks when this transaction can bind an object.
        // The object-link trigger revalidates this authority later; prelocking
        // here preserves the lifecycle-wide order against concurrent
        // control-plane policy rotation. Content-off ledger ingest has no
        // dependency on transport-authority rows and retains that separation.
        if includes_object_reference {
            sqlx::query_scalar::<_, bool>(
                "SELECT apolysis_gateway.lock_evidence_object_organization_shared($1)",
            )
            .bind(context.organization_id().as_str())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| TxFailure::from_sqlx_at("ingest_lock_organization", error))?
            .then_some(())
            .ok_or_else(|| TxFailure::rollback(repository_failure()))?;
        }
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
            match (envelope.inline_payload(), envelope.object_ref()) {
                (Some(payload), None) => {
                    if !stream
                        .manifest
                        .capabilities()
                        .contains(&payload.required_source_capability())
                    {
                        return Err(TxFailure::rollback(policy_failure(
                            ContractErrorCode::CapabilityMismatch,
                        )));
                    }
                }
                (None, Some(_)) => {
                    if !stream
                        .manifest
                        .privacy_capabilities()
                        .contains(&PrivacyCapability::AuthorizedContentReference)
                    {
                        return Err(TxFailure::rollback(policy_failure(
                            ContractErrorCode::ContentNotAuthorized,
                        )));
                    }
                }
                _ => {
                    return Err(TxFailure::rollback(policy_failure(
                        ContractErrorCode::ContentNotAuthorized,
                    )));
                }
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

        // Durable duplicates replay their original acceptance without reopening
        // object availability. Only novel events participate in object admission.
        let mut novel_object_bindings = BTreeMap::new();
        for (classification, envelope) in &classified {
            if !matches!(classification, ClassifiedEvent::Novel(_)) {
                continue;
            }
            let Some(object_ref) = envelope.object_ref() else {
                continue;
            };
            let binding = NovelObjectBinding {
                object_id: object_ref.object_id().to_string(),
                payload_type: envelope.payload_type().to_string(),
                payload_version: envelope.payload_version().to_string(),
                content_digest: hex_digest(object_ref.sha256()).map_err(TxFailure::rollback)?,
                content_size_bytes: object_ref.size_bytes(),
            };
            if novel_object_bindings
                .insert(binding.object_id.clone(), binding)
                .is_some()
            {
                return Err(TxFailure::rollback(policy_failure(
                    ContractErrorCode::ContentNotAuthorized,
                )));
            }
        }
        let authorized_object_capabilities = validate_novel_object_bindings(
            transaction,
            context,
            request,
            &lease,
            &stream.manifest,
            &novel_object_bindings,
            now_unix_ms,
        )
        .await?;

        let mut prepared = Vec::with_capacity(classified.len());
        let mut facts = Vec::new();
        for (classification, envelope) in classified {
            match classification {
                ClassifiedEvent::Duplicate(ingest_sequence) => {
                    prepared.push((PreparedEvent::Duplicate(ingest_sequence), envelope));
                }
                ClassifiedEvent::Novel(envelope_digest) => {
                    let accepted = Box::new(
                        AcceptedSourceEnvelope::new(
                            context.source_registration_id(),
                            &lease.source_stream_id,
                            stream.registration_policy_revision,
                            stream.effective_trust_profile,
                            stream.manifest.schema_version(),
                            stream.manifest_digest.clone(),
                            envelope.clone(),
                        )
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    );
                    facts.push(AgentExecutionRecordFact::EvidenceAccepted(accepted.clone()));
                    prepared.push((
                        PreparedEvent::Novel {
                            envelope_digest,
                            accepted,
                        },
                        envelope,
                    ));
                }
            }
        }
        let mut reserved_sequences = self
            .append_facts(transaction, context, request.run_id(), now_unix_ms, facts)
            .await?
            .into_iter();
        let mut acknowledgements = Vec::with_capacity(prepared.len());
        for (classification, envelope) in prepared {
            match classification {
                PreparedEvent::Duplicate(ingest_sequence) => {
                    acknowledgements.push(
                        EnvelopeAck::new(
                            envelope.source_event_id(),
                            IngestDisposition::Duplicate,
                            ingest_sequence,
                        )
                        .map_err(|_| TxFailure::rollback(repository_failure()))?,
                    );
                }
                PreparedEvent::Novel {
                    envelope_digest,
                    accepted,
                } => {
                    let ingest_sequence = reserved_sequences
                        .next()
                        .ok_or_else(|| TxFailure::rollback(repository_failure()))?;
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
                    if let Some(object_ref) = envelope.object_ref() {
                        let required_capability = authorized_object_capabilities
                            .get(object_ref.object_id())
                            .ok_or_else(object_binding_denied)?;
                        sqlx::query(
                            "INSERT INTO apolysis_gateway.evidence_event_objects (\
                                organization_id, run_id, source_registration_id, \
                                source_stream_id, source_id, lease_digest, source_event_id, object_id, \
                                required_source_capability, payload_type, payload_version, \
                                content_digest, content_size_bytes, bound_at_unix_ms\
                             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
                        )
                        .bind(context.organization_id().as_str())
                        .bind(request.run_id().as_str())
                        .bind(context.source_registration_id())
                        .bind(&lease.source_stream_id)
                        .bind(&lease.source_id)
                        .bind(&lease.lease_digest)
                        .bind(envelope.source_event_id())
                        .bind(object_ref.object_id())
                        .bind(required_capability)
                        .bind(envelope.payload_type())
                        .bind(envelope.payload_version())
                        .bind(hex_digest(object_ref.sha256()).map_err(TxFailure::rollback)?)
                        .bind(sql_i64(object_ref.size_bytes()).map_err(TxFailure::rollback)?)
                        .bind(sql_i64(now_unix_ms).map_err(TxFailure::rollback)?)
                        .execute(&mut **transaction)
                        .await
                        .map_err(object_binding_insert_failure)?;
                    }
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
        if reserved_sequences.next().is_some() {
            return Err(TxFailure::rollback(repository_failure()));
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
    lease_digest: Vec<u8>,
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

enum PreparedEvent {
    Duplicate(u64),
    Novel {
        envelope_digest: Vec<u8>,
        accepted: Box<AcceptedSourceEnvelope>,
    },
}

#[derive(Clone)]
struct NovelObjectBinding {
    object_id: String,
    payload_type: String,
    payload_version: String,
    content_digest: Vec<u8>,
    content_size_bytes: u64,
}

#[derive(Clone)]
struct LockedEvidenceObject {
    organization_id: String,
    object_id: String,
    run_id: String,
    source_registration_id: String,
    source_stream_id: String,
    source_id: String,
    lease_digest: Vec<u8>,
    payload_type: String,
    payload_version: String,
    required_source_capability: String,
    content_digest: Vec<u8>,
    content_size_bytes: u64,
    object_state: String,
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    requested_retention_ms: u64,
}

struct ObjectIngestScope<'a> {
    organization_id: &'a str,
    run_id: &'a str,
    source_registration_id: &'a str,
    source_stream_id: &'a str,
    source_id: &'a str,
    lease_digest: &'a [u8],
    max_object_size_bytes: u64,
    retention_ms: u64,
    now_unix_ms: u64,
}

impl LockedEvidenceObject {
    fn admits(&self, binding: &NovelObjectBinding, scope: &ObjectIngestScope<'_>) -> bool {
        self.organization_id == scope.organization_id
            && self.object_id == binding.object_id
            && self.run_id == scope.run_id
            && self.source_registration_id == scope.source_registration_id
            && self.source_stream_id == scope.source_stream_id
            && self.source_id == scope.source_id
            && self.lease_digest == scope.lease_digest
            && self.payload_type == binding.payload_type
            && self.payload_version == binding.payload_version
            && self.content_digest == binding.content_digest
            && self.content_size_bytes == binding.content_size_bytes
            && self.content_size_bytes <= scope.max_object_size_bytes
            && self.requested_retention_ms <= scope.retention_ms
            && self.object_state == "available"
            && self.expires_at_unix_ms > scope.now_unix_ms
            && self
                .created_at_unix_ms
                .checked_add(scope.retention_ms)
                .is_some_and(|expires_at| expires_at > scope.now_unix_ms)
    }
}

async fn validate_novel_object_bindings(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
    request: &IngestRequest,
    lease: &LeaseRow,
    manifest: &SourceManifest,
    bindings: &BTreeMap<String, NovelObjectBinding>,
    object_now_unix_ms: u64,
) -> TxResult<BTreeMap<String, String>> {
    if bindings.is_empty() {
        return Ok(BTreeMap::new());
    }
    // Every ingest transaction takes object locks in database order so
    // overlapping batches cannot deadlock by presenting different input order.
    let policy = sqlx::query(
        "SELECT policy.max_object_size_bytes, policy.retention_ms \
         FROM apolysis_gateway.runs AS run \
         JOIN apolysis_gateway.evidence_object_policy_revisions AS policy \
           ON policy.organization_id=run.organization_id \
          AND policy.privacy_profile_ref=run.privacy_profile_ref \
          AND policy.retention_profile_ref=run.retention_profile_ref \
         WHERE run.organization_id=$1 AND run.run_id=$2 \
           AND policy.policy_state='active' AND policy.effective_at_unix_ms<=$3",
    )
    .bind(context.organization_id().as_str())
    .bind(request.run_id().as_str())
    .bind(sql_i64(object_now_unix_ms).map_err(TxFailure::rollback)?)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_lock_evidence_object_policy", error))?
    .ok_or_else(object_binding_denied)?;
    let max_object_size_bytes =
        sql_u64(policy.try_get("max_object_size_bytes").map_err(|error| {
            TxFailure::from_sqlx_at("ingest_decode_evidence_object_policy", error)
        })?)
        .map_err(TxFailure::rollback)?;
    let retention_ms =
        sql_u64(policy.try_get("retention_ms").map_err(|error| {
            TxFailure::from_sqlx_at("ingest_decode_evidence_object_policy", error)
        })?)
        .map_err(TxFailure::rollback)?;
    let object_ids = bindings.keys().cloned().collect::<Vec<_>>();
    let locked_object_count = sqlx::query_scalar::<_, i64>(
        "SELECT apolysis_gateway.lock_evidence_objects_for_ingest($1,$2)",
    )
    .bind(context.organization_id().as_str())
    .bind(&object_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_lock_evidence_objects", error))?;
    if usize::try_from(locked_object_count).ok() != Some(bindings.len()) {
        return Err(object_binding_denied());
    }
    let rows = sqlx::query(
        "SELECT stored_object.organization_id, stored_object.object_id, stored_object.run_id, \
                stored_object.source_registration_id, stored_object.source_stream_id, \
                stored_object.source_id, stored_object.lease_digest, stored_object.payload_type, \
                stored_object.payload_version, \
                stored_object.required_source_capability, \
                stored_object.content_digest, stored_object.content_size_bytes, \
                stored_object.object_state, stored_object.created_at_unix_ms, \
                stored_object.expires_at_unix_ms, stored_object.requested_retention_ms \
         FROM apolysis_gateway.evidence_objects AS stored_object \
         WHERE stored_object.organization_id=$1 \
           AND stored_object.object_id=ANY($2::text[]) \
         ORDER BY stored_object.object_id",
    )
    .bind(context.organization_id().as_str())
    .bind(&object_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_lock_evidence_objects", error))?;
    if rows.len() != bindings.len() {
        return Err(object_binding_denied());
    }
    let scope = ObjectIngestScope {
        organization_id: context.organization_id().as_str(),
        run_id: request.run_id().as_str(),
        source_registration_id: context.source_registration_id(),
        source_stream_id: &lease.source_stream_id,
        source_id: &lease.source_id,
        lease_digest: &lease.lease_digest,
        max_object_size_bytes,
        retention_ms,
        now_unix_ms: object_now_unix_ms,
    };
    let allowed_capabilities = manifest
        .capabilities()
        .iter()
        .map(enum_name)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(TxFailure::rollback)?;
    let mut authorized_capabilities = BTreeMap::new();
    for row in rows {
        let stored = LockedEvidenceObject {
            organization_id: row
                .try_get("organization_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            object_id: row
                .try_get("object_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            run_id: row
                .try_get("run_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            source_registration_id: row
                .try_get("source_registration_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            source_stream_id: row
                .try_get("source_stream_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            source_id: row
                .try_get("source_id")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            lease_digest: row
                .try_get("lease_digest")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            payload_type: row
                .try_get("payload_type")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            payload_version: row
                .try_get("payload_version")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            required_source_capability: row
                .try_get("required_source_capability")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            content_digest: row
                .try_get("content_digest")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            content_size_bytes: sql_u64(row.try_get("content_size_bytes").map_err(|error| {
                TxFailure::from_sqlx_at("ingest_decode_evidence_object", error)
            })?)
            .map_err(TxFailure::rollback)?,
            object_state: row
                .try_get("object_state")
                .map_err(|error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error))?,
            created_at_unix_ms: sql_u64(row.try_get("created_at_unix_ms").map_err(|error| {
                TxFailure::from_sqlx_at("ingest_decode_evidence_object", error)
            })?)
            .map_err(TxFailure::rollback)?,
            expires_at_unix_ms: sql_u64(row.try_get("expires_at_unix_ms").map_err(|error| {
                TxFailure::from_sqlx_at("ingest_decode_evidence_object", error)
            })?)
            .map_err(TxFailure::rollback)?,
            requested_retention_ms: sql_u64(row.try_get("requested_retention_ms").map_err(
                |error| TxFailure::from_sqlx_at("ingest_decode_evidence_object", error),
            )?)
            .map_err(TxFailure::rollback)?,
        };
        let Some(binding) = bindings.get(&stored.object_id) else {
            return Err(object_binding_denied());
        };
        if !stored.admits(binding, &scope)
            || !allowed_capabilities.contains(&stored.required_source_capability)
        {
            return Err(object_binding_denied());
        }
        authorized_capabilities.insert(
            stored.object_id.clone(),
            stored.required_source_capability.clone(),
        );
    }
    // This second statement runs after all object locks are held, so it sees a
    // prior contender's committed link before this transaction appends facts.
    let object_already_bound = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (\
            SELECT 1 FROM apolysis_gateway.evidence_event_objects AS event_object \
            WHERE event_object.organization_id=$1 \
              AND event_object.object_id=ANY($2::text[])\
         )",
    )
    .bind(context.organization_id().as_str())
    .bind(&object_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| TxFailure::from_sqlx_at("ingest_check_object_reuse", error))?;
    if object_already_bound {
        return Err(object_binding_denied());
    }
    Ok(authorized_capabilities)
}

fn object_binding_denied() -> TxFailure {
    TxFailure::rollback(policy_failure(ContractErrorCode::ContentNotAuthorized))
}

fn object_binding_insert_failure(error: sqlx::Error) -> TxFailure {
    let is_object_denied = error.as_database_error().is_some_and(|database_error| {
        let constraint = database_error.constraint();
        (database_error.code().as_deref() == Some("23505")
            && constraint == Some("evidence_event_objects_organization_id_object_id_key"))
            || (database_error.code().as_deref() == Some("23514")
                && matches!(
                    constraint,
                    Some(
                        "evidence_event_object_exact_binding_ck"
                            | "evidence_event_object_current_authority_ck"
                            | "evidence_object_current_lease_ck"
                    )
                ))
    });
    if is_object_denied {
        object_binding_denied()
    } else {
        TxFailure::from_sqlx_at("ingest_insert_evidence_event_object", error)
    }
}

async fn load_lease(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AuthenticatedSourceContext,
    request: &IngestRequest,
) -> TxResult<LeaseRow> {
    let lease_digest =
        hex_digest(&lease_id_digest(request.lease_id())).map_err(TxFailure::rollback)?;
    sqlx::query_scalar::<_, bool>("SELECT apolysis_gateway.lock_gateway_lease($1,$2)")
        .bind(context.organization_id().as_str())
        .bind(&lease_digest)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| TxFailure::from_sqlx_at("ingest_lock_lease", error))?;
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
        lease_digest,
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_UNIX_MS: u64 = 1_000;

    fn binding() -> NovelObjectBinding {
        NovelObjectBinding {
            object_id: "object-1".to_string(),
            payload_type: "protocol_interaction".to_string(),
            payload_version: "0.1".to_string(),
            content_digest: vec![0x5a; 32],
            content_size_bytes: 4_096,
        }
    }

    fn stored_object() -> LockedEvidenceObject {
        LockedEvidenceObject {
            organization_id: "org-1".to_string(),
            object_id: "object-1".to_string(),
            run_id: "run-1".to_string(),
            source_registration_id: "registration-1".to_string(),
            source_stream_id: "stream-1".to_string(),
            source_id: "source-1".to_string(),
            lease_digest: vec![0x7b; 32],
            payload_type: "protocol_interaction".to_string(),
            payload_version: "0.1".to_string(),
            required_source_capability: "mcp".to_string(),
            content_digest: vec![0x5a; 32],
            content_size_bytes: 4_096,
            object_state: "available".to_string(),
            created_at_unix_ms: NOW_UNIX_MS - 1,
            expires_at_unix_ms: NOW_UNIX_MS + 1,
            requested_retention_ms: 10_000,
        }
    }

    fn admits(stored: &LockedEvidenceObject) -> bool {
        stored.admits(
            &binding(),
            &ObjectIngestScope {
                organization_id: "org-1",
                run_id: "run-1",
                source_registration_id: "registration-1",
                source_stream_id: "stream-1",
                source_id: "source-1",
                lease_digest: &[0x7b; 32],
                max_object_size_bytes: 8_192,
                retention_ms: 10_000,
                now_unix_ms: NOW_UNIX_MS,
            },
        )
    }

    fn assert_rejected(mutator: impl FnOnce(&mut LockedEvidenceObject)) {
        let mut stored = stored_object();
        mutator(&mut stored);
        assert!(!admits(&stored));
    }

    #[test]
    fn exact_available_unexpired_object_is_admissible() {
        assert!(admits(&stored_object()));
    }

    #[test]
    fn unavailable_or_expired_object_is_denied() {
        assert_rejected(|stored| stored.object_state = "uploading".to_string());
        assert_rejected(|stored| stored.object_state = "delete_pending".to_string());
        assert_rejected(|stored| stored.object_state = "deleted".to_string());
        assert_rejected(|stored| stored.expires_at_unix_ms = NOW_UNIX_MS);
        assert_rejected(|stored| stored.expires_at_unix_ms = NOW_UNIX_MS - 1);
    }

    #[test]
    fn object_scope_and_integrity_must_match_exactly() {
        assert_rejected(|stored| stored.organization_id = "org-2".to_string());
        assert_rejected(|stored| stored.object_id = "object-2".to_string());
        assert_rejected(|stored| stored.run_id = "run-2".to_string());
        assert_rejected(|stored| {
            stored.source_registration_id = "registration-2".to_string();
        });
        assert_rejected(|stored| stored.source_stream_id = "stream-2".to_string());
        assert_rejected(|stored| stored.source_id = "source-2".to_string());
        assert_rejected(|stored| stored.lease_digest = vec![0x6a; 32]);
        assert_rejected(|stored| stored.payload_type = "tool_interaction".to_string());
        assert_rejected(|stored| stored.payload_version = "0.2".to_string());
        assert_rejected(|stored| stored.content_digest = vec![0xa5; 32]);
        assert_rejected(|stored| stored.content_size_bytes += 1);
        assert_rejected(|stored| stored.requested_retention_ms += 1);
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    sync::{Arc, OnceLock},
};

use apolysis_contracts::{AuthenticatedSourceContext, RunId, SourceKind, TrustProfile};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use apolysis_gateway_testkit::{
    gateway_repository_conformance_tests, GatewayConformanceCounts, GatewayConformanceHarness,
    GatewayConformanceSnapshot, HarnessAdminFuture, HarnessFuture,
};
use sqlx::Row;

static DATABASE_TEST_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

struct PostgresGatewayHarness {
    repository: PostgresGatewayRepository,
    inspection_pool: sqlx::PgPool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl GatewayConformanceHarness for PostgresGatewayHarness {
    type Repository = PostgresGatewayRepository;

    fn start() -> HarnessFuture<'static, Self> {
        Box::pin(async {
            let guard = DATABASE_TEST_LOCK
                .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
                .lock_owned()
                .await;
            let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL").map_err(|_| {
                "APOLYSIS_TEST_DATABASE_URL is required by the explicit PostgreSQL harness"
            })?;
            let protector = Arc::new(Aes256GcmReplayProtector::new(
                "integration-test-key",
                [("integration-test-key".to_string(), [41_u8; 32])],
            )?);
            let inspection_pool = sqlx::PgPool::connect(&database_url).await?;
            MIGRATOR.run(&inspection_pool).await?;
            let repository = PostgresGatewayRepository::connect(
                &database_url,
                protector,
                PostgresGatewayConfig::default(),
            )
            .await?;
            sqlx::query("TRUNCATE TABLE apolysis_gateway.organization_sequences CASCADE")
                .execute(&inspection_pool)
                .await?;
            Ok(Self {
                repository,
                inspection_pool,
                _guard: guard,
            })
        })
    }

    fn repository(&self) -> Self::Repository {
        self.repository.clone()
    }

    fn snapshot(&self) -> HarnessFuture<'_, GatewayConformanceSnapshot> {
        Box::pin(async move {
            let counts = sqlx::query(
                "SELECT \
                    (SELECT count(*) FROM apolysis_gateway.record_items) AS records, \
                    (SELECT count(*) FROM apolysis_gateway.projection_outbox) AS outbox, \
                    (SELECT count(*) FROM apolysis_gateway.record_items \
                       WHERE fact_kind='run_state_changed' \
                         AND fact_json #>> '{fact,fact,to}'='incomplete') AS incomplete_records, \
                    (SELECT count(*) FROM apolysis_gateway.projection_outbox AS incomplete_outbox \
                       JOIN apolysis_gateway.record_items AS incomplete_record \
                         ON incomplete_record.organization_id=incomplete_outbox.organization_id \
                        AND incomplete_record.ingest_sequence=incomplete_outbox.ingest_sequence \
                       WHERE incomplete_record.fact_kind='run_state_changed' \
                         AND incomplete_record.fact_json #>> '{fact,fact,to}'='incomplete') \
                      AS incomplete_outbox, \
                    (SELECT count(*) FROM apolysis_gateway.evidence_events) AS events, \
                    (SELECT count(*) FROM apolysis_gateway.gateway_operations) AS operations, \
                    (SELECT count(*) FROM apolysis_gateway.operation_replays) AS replays, \
                    (SELECT count(*) FROM apolysis_gateway.finalization_declarations) AS finalizations",
            )
            .fetch_one(&self.inspection_pool)
            .await?;
            let trust_rows = sqlx::query(
                "SELECT effective_trust_profile \
                 FROM apolysis_gateway.evidence_events AS event \
                 JOIN apolysis_gateway.source_streams AS stream \
                   ON stream.organization_id=event.organization_id \
                  AND stream.run_id=event.run_id \
                  AND stream.source_registration_id=event.source_registration_id \
                  AND stream.source_stream_id=event.source_stream_id \
                 ORDER BY event.organization_id, event.ledger_ingest_sequence",
            )
            .fetch_all(&self.inspection_pool)
            .await?;
            let accepted_trust = trust_rows
                .into_iter()
                .map(|row| {
                    serde_json::from_value::<TrustProfile>(serde_json::Value::String(
                        row.try_get::<String, _>("effective_trust_profile")?,
                    ))
                    .map_err(Into::into)
                })
                .collect::<Result<Vec<_>, Box<dyn Error + Send + Sync>>>()?;
            Ok(GatewayConformanceSnapshot::new(
                GatewayConformanceCounts {
                    record_item_count: usize::try_from(counts.try_get::<i64, _>("records")?)?,
                    projection_outbox_count: usize::try_from(counts.try_get::<i64, _>("outbox")?)?,
                    incomplete_record_item_count: usize::try_from(
                        counts.try_get::<i64, _>("incomplete_records")?,
                    )?,
                    incomplete_projection_outbox_count: usize::try_from(
                        counts.try_get::<i64, _>("incomplete_outbox")?,
                    )?,
                    evidence_event_count: usize::try_from(counts.try_get::<i64, _>("events")?)?,
                    operation_count: usize::try_from(counts.try_get::<i64, _>("operations")?)?,
                    replay_count: usize::try_from(counts.try_get::<i64, _>("replays")?)?,
                    finalization_declaration_count: usize::try_from(
                        counts.try_get::<i64, _>("finalizations")?,
                    )?,
                },
                accepted_trust,
            ))
        })
    }

    fn register_join_grant<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            self.repository
                .register_join_grant(
                    issuer,
                    joining_source,
                    run_id,
                    source_kind,
                    proof_ref,
                    expires_at_unix_ms,
                )
                .await
        })
    }

    fn register_join_policy<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            self.repository
                .register_join_policy(
                    issuer,
                    joining_source,
                    run_id,
                    source_kind,
                    proof_ref,
                    expires_at_unix_ms,
                )
                .await
        })
    }
}

gateway_repository_conformance_tests!(
    #[ignore = "requires the explicit PostgreSQL integration harness"]
    PostgresGatewayHarness
);

// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    io,
    sync::{Arc, Mutex, OnceLock},
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    EnvironmentKind, GatewayOperation, OpenRunRequest, PrincipalKind, PrincipalRef,
    PrivacyCapability, SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy,
    TrustProfile,
};
use apolysis_gateway::{canonical_request_digest, GatewayClock, GatewayIdGenerator};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use sqlx::{postgres::PgPoolOptions, PgPool};

pub const NOW_UNIX_MS: u64 = 1_783_891_200_000;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

static DATABASE_TEST_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

pub struct TestDatabase {
    database_url: String,
    pool: PgPool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl TestDatabase {
    pub async fn start() -> TestResult<Self> {
        let guard = DATABASE_TEST_LOCK
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL").map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "APOLYSIS_TEST_DATABASE_URL is required by the ignored PostgreSQL durability tests",
            )
        })?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .map_err(|_| io::Error::other("failed to connect to the PostgreSQL test database"))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|_| io::Error::other("failed to migrate the PostgreSQL test database"))?;
        sqlx::query(
            "TRUNCATE TABLE apolysis_gateway.organization_sequences RESTART IDENTITY CASCADE",
        )
        .execute(&pool)
        .await
        .map_err(|_| io::Error::other("failed to isolate the PostgreSQL durability test"))?;
        Ok(Self {
            database_url,
            pool,
            _guard: guard,
        })
    }

    pub async fn repository(&self) -> TestResult<PostgresGatewayRepository> {
        self.repository_with_config(PostgresGatewayConfig::default())
            .await
    }

    pub async fn repository_with_config(
        &self,
        config: PostgresGatewayConfig,
    ) -> TestResult<PostgresGatewayRepository> {
        PostgresGatewayRepository::connect_and_migrate(
            &self.database_url,
            replay_protector()?,
            config,
        )
        .await
        .map_err(|_| {
            io::Error::other("failed to construct the PostgreSQL Gateway repository").into()
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn replay_protector() -> TestResult<Arc<Aes256GcmReplayProtector>> {
    Ok(Arc::new(Aes256GcmReplayProtector::new(
        "durability-test-key",
        [("durability-test-key".to_string(), [73_u8; 32])],
    )?))
}

#[derive(Clone, Copy)]
pub struct FixedClock(pub u64);

impl GatewayClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

pub struct FixedIds {
    values: Mutex<Vec<String>>,
}

impl FixedIds {
    pub fn new(values: &[&str]) -> Self {
        Self {
            values: Mutex::new(
                values
                    .iter()
                    .rev()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
        }
    }
}

impl GatewayIdGenerator for FixedIds {
    fn next_id(&self, _kind: &'static str) -> Result<String, String> {
        self.values
            .lock()
            .map_err(|_| "deterministic ID source is unavailable".to_string())?
            .pop()
            .ok_or_else(|| "no deterministic ID should be needed".to_string())
    }
}

pub fn source_context() -> AuthenticatedSourceContext {
    let principal =
        PrincipalRef::new(PrincipalKind::Workload, "principal_runner").expect("principal fixture");
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from("source_codex").expect("source fixture"),
        vec![SourceKind::SemanticHook],
        vec![EnvironmentKind::CiRunnerOrRemoteWorkspace],
        vec![
            GatewayOperation::BindRuntime,
            GatewayOperation::Ingest,
            GatewayOperation::FinishRun,
        ],
        true,
        false,
    )
    .expect("registration policy fixture")
    .with_run_authorities(vec![AuthorityRef::new(
        AuthorityKind::Service,
        "authority_ci",
    )
    .expect("authority fixture")])
    .expect("authority policy fixture")
    .with_run_profiles(
        vec!["privacy_structure_only_v1".to_string()],
        vec!["retention_30d_v1".to_string()],
        vec![SourceKind::SemanticHook],
    )
    .expect("run profile fixture")
    .with_evidence_policy(
        TrustProfile::HarnessObserved,
        vec![
            SourceCapability::SemanticLifecycle,
            SourceCapability::ToolCalls,
            SourceCapability::ClaimedOutcome,
        ],
        vec![PrivacyCapability::StructureOnly],
        vec!["redaction_structure_only_v1".to_string()],
    )
    .expect("evidence policy fixture");
    AuthenticatedSourceContext::new(
        "org_durability".try_into().expect("organization fixture"),
        principal,
        "registration_codex",
        AuthenticationSnapshot::new(
            "credential_ci_runner",
            7,
            1_783_891_100_000,
            1_783_894_800_000,
        )
        .expect("authentication fixture"),
        policy,
    )
    .expect("source context fixture")
}

pub fn create_request(client_operation_id: &str, client_run_key: &str) -> OpenRunRequest {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/open_run_create_request.json"
    );
    let mut wire: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).expect("read the checked-in open_run fixture"),
    )
    .expect("decode the checked-in open_run fixture");
    wire["client_operation_id"] = serde_json::Value::String(client_operation_id.to_string());
    wire["client_run_key"] = serde_json::Value::String(client_run_key.to_string());
    wire["expected_source_kinds"] = serde_json::json!(["semantic_hook"]);
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: OpenRunRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid open_run fixture");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("open_run", &unsigned).expect("canonical open_run digest"),
    );
    serde_json::from_value(wire).expect("digest-valid open_run fixture")
}

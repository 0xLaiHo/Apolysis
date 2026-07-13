// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    error::Error,
    fs,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    EnvironmentKind, FinishRunRequest, GatewayOperation, IngestRequest, OpenRunRequest,
    OpenRunResponse, PrincipalKind, PrincipalRef, PrivacyCapability, SourceCapability, SourceId,
    SourceKind, SourceRegistrationPolicy, TrustProfile, TypedEvidencePayload,
};
use apolysis_gateway::{
    canonical_inline_payload_digest, canonical_request_digest, ExecutionEvidenceGateway,
    GatewayClock, OsRandomIdGenerator, SystemClock,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use apolysis_projection_postgres::{
    migrate_projection_schema, GenerationKey, PostgresRunProjection, ProjectionBatchOutcome,
    ProjectionCommit, ProjectionError,
};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Postgres, Transaction,
};

pub const NOW_UNIX_MS: u64 = 1_783_891_200_000;

pub type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

static DATABASE_TEST_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

/// One process-local, destructive test lease over an explicitly supplied real database.
pub struct TestDatabase {
    database_url: String,
    connect_options: PgConnectOptions,
    pool: PgPool,
    _database_guard: Transaction<'static, Postgres>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl TestDatabase {
    pub async fn start() -> TestResult<Self> {
        let guard = DATABASE_TEST_LOCK
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
            .lock_owned()
            .await;
        let (database_url, connect_options) = read_gate_owned_database_url()?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(connect_options.clone())
            .await
            .map_err(|_| io::Error::other("failed to connect to the PostgreSQL test database"))?;
        let gate_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM public.apolysis_projection_test_ownership \
                 WHERE singleton AND gate_version='v1' \
                   AND database_name=current_database() \
                   AND database_user=current_user\
             )",
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| {
            io::Error::other("the PostgreSQL database is not owned by the projection test gate")
        })?;
        if !gate_owned {
            return Err(io::Error::other(
                "the PostgreSQL database is not owned by the projection test gate",
            )
            .into());
        }
        let mut database_guard = pool
            .begin()
            .await
            .map_err(|_| io::Error::other("failed to begin the PostgreSQL test lease"))?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(\
                 hashtextextended('apolysis_projection.real_postgres_tests/v1', 0))",
        )
        .execute(&mut *database_guard)
        .await
        .map_err(|_| io::Error::other("failed to acquire the PostgreSQL test lease"))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|_| io::Error::other("failed to migrate the Gateway test schema"))?;
        migrate_projection_schema(&pool)
            .await
            .map_err(|_| io::Error::other("failed to migrate the projection test schema"))?;
        sqlx::query(
            "TRUNCATE TABLE apolysis_gateway.organization_sequences, \
                 apolysis_projection.generations RESTART IDENTITY CASCADE",
        )
        .execute(&pool)
        .await
        .map_err(|_| io::Error::other("failed to isolate the PostgreSQL projection test"))?;
        Ok(Self {
            database_url,
            connect_options,
            pool,
            _database_guard: database_guard,
            _guard: guard,
        })
    }

    pub async fn repository(&self) -> TestResult<PostgresGatewayRepository> {
        PostgresGatewayRepository::connect_and_migrate(
            &self.database_url,
            replay_protector()?,
            PostgresGatewayConfig::default(),
        )
        .await
        .map_err(|_| io::Error::other("failed to construct a PostgreSQL Gateway repository").into())
    }

    pub async fn independent_pool(&self) -> TestResult<PgPool> {
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&self.database_url)
            .await
            .map_err(|_| {
                io::Error::other("failed to construct an independent PostgreSQL pool").into()
            })
    }

    pub fn connect_options(&self) -> PgConnectOptions {
        self.connect_options.clone()
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn read_gate_owned_database_url() -> TestResult<(String, PgConnectOptions)> {
    const MAX_DATABASE_URL_BYTES: u64 = 4_096;

    let path = env::var_os("APOLYSIS_TEST_DATABASE_URL_FILE").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the explicit gate-owned disposable database URL file is required",
        )
    })?;
    if path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the gate-owned database URL file path is empty",
        )
        .into());
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| io::Error::other("failed to inspect the gate-owned database URL file"))?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_DATABASE_URL_BYTES
    {
        return Err(
            io::Error::other("the gate-owned database URL file has unsafe metadata").into(),
        );
    }
    let mut file = fs::File::open(&path)
        .map_err(|_| io::Error::other("failed to open the gate-owned database URL file"))?;
    let opened = file
        .metadata()
        .map_err(|_| io::Error::other("failed to inspect the opened database URL file"))?;
    if !opened.file_type().is_file()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(io::Error::other("the gate-owned database URL file was replaced").into());
    }
    let mut encoded = Vec::with_capacity(
        usize::try_from(opened.len())
            .map_err(|_| io::Error::other("the gate-owned database URL is too large"))?,
    );
    (&mut file)
        .take(MAX_DATABASE_URL_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| io::Error::other("failed to read the gate-owned database URL file"))?;
    if u64::try_from(encoded.len()).ok() != Some(opened.len()) {
        return Err(io::Error::other("the gate-owned database URL file changed while read").into());
    }
    let text = String::from_utf8(encoded)
        .map_err(|_| io::Error::other("the gate-owned database URL is not UTF-8"))?;
    let database_url = text.strip_suffix('\n').unwrap_or(&text);
    if database_url.is_empty()
        || database_url.contains(['\r', '\n', '\0'])
        || !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"))
    {
        return Err(io::Error::other("the gate-owned database URL has an unsafe format").into());
    }
    let connect_options = PgConnectOptions::from_str(database_url)
        .map_err(|_| io::Error::other("failed to parse the gate-owned database URL"))?;
    let database_name = connect_options
        .get_database()
        .ok_or_else(|| io::Error::other("the gate-owned database URL has no database name"))?;
    if connect_options.get_host() != "127.0.0.1"
        || !connect_options
            .get_username()
            .starts_with("apolysis_primary_")
        || !database_name.starts_with("apolysis_primary_")
        || connect_options.get_username() != database_name
    {
        return Err(io::Error::other(
            "the database URL does not identify the gate-owned loopback database",
        )
        .into());
    }
    Ok((database_url.to_string(), connect_options))
}

fn replay_protector() -> TestResult<Arc<Aes256GcmReplayProtector>> {
    Ok(Arc::new(Aes256GcmReplayProtector::new(
        "projection-test-key",
        [("projection-test-key".to_string(), [113_u8; 32])],
    )?))
}

pub fn source_context(organization_id: &str) -> AuthenticatedSourceContext {
    let now_unix_ms = SystemClock.now_unix_ms();
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
        organization_id.try_into().expect("organization fixture"),
        principal,
        "registration_codex",
        AuthenticationSnapshot::new(
            "credential_ci_runner",
            7,
            now_unix_ms.saturating_sub(60_000),
            now_unix_ms.saturating_add(86_400_000),
        )
        .expect("authentication fixture"),
        policy,
    )
    .expect("source context fixture")
}

pub fn create_request(
    client_operation_id: &str,
    client_run_key: &str,
    objective_ref: &str,
) -> OpenRunRequest {
    let mut wire = request_fixture("open_run_create_request.json");
    wire["client_operation_id"] = serde_json::Value::String(client_operation_id.to_string());
    wire["client_run_key"] = serde_json::Value::String(client_run_key.to_string());
    wire["objective_ref"] = serde_json::Value::String(objective_ref.to_string());
    wire["expected_source_kinds"] = serde_json::json!(["semantic_hook"]);
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: OpenRunRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid open_run fixture");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("open_run", &unsigned).expect("canonical open_run digest"),
    );
    serde_json::from_value(wire).expect("digest-valid open_run fixture")
}

pub fn ingest_request(run_id: &str, lease_id: &str, source_stream_id: &str) -> IngestRequest {
    let mut wire = request_fixture("ingest_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    for envelope in wire["envelopes"].as_array_mut().expect("envelope array") {
        envelope["run_id"] = serde_json::Value::String(run_id.to_string());
        envelope["source_stream_id"] = serde_json::Value::String(source_stream_id.to_string());
    }
    finalize_ingest_wire(wire)
}

pub fn gap_fill_request(run_id: &str, lease_id: &str, source_stream_id: &str) -> IngestRequest {
    let mut wire = request_fixture("ingest_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    wire["client_operation_id"] = serde_json::json!("operation_projection_gap_fill_01");
    let mut envelope = wire["envelopes"][0].clone();
    envelope["run_id"] = serde_json::Value::String(run_id.to_string());
    envelope["source_stream_id"] = serde_json::Value::String(source_stream_id.to_string());
    envelope["source_event_id"] = serde_json::json!("event_projection_gap_fill_02");
    envelope["source_sequence"] = serde_json::json!(2);
    envelope["correlation"]["tool_ref"] = serde_json::json!("tool_call_02");
    envelope["inline_payload"]["body"]["interaction_ref"] = serde_json::json!("tool_call_02");
    envelope["inline_payload"]["body"]["request_ref"] = serde_json::json!("request_digest_02");
    wire["envelopes"] = serde_json::Value::Array(vec![envelope]);
    finalize_ingest_wire(wire)
}

pub fn finish_run_request(
    run_id: &str,
    lease_id: &str,
    source_stream_id: &str,
) -> FinishRunRequest {
    let mut wire = request_fixture("finish_run_request.json");
    wire["run_id"] = serde_json::Value::String(run_id.to_string());
    wire["lease_id"] = serde_json::Value::String(lease_id.to_string());
    wire["client_operation_id"] = serde_json::json!("operation_projection_finish_01");
    wire["terminal_positions"] = serde_json::json!([{
        "source_id": "source_codex",
        "source_stream_id": source_stream_id,
        "final_source_sequence": 3
    }]);
    wire["requested_finalization_deadline_unix_ms"] =
        serde_json::json!(SystemClock.now_unix_ms().saturating_add(600_000));
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: FinishRunRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid finish_run fixture");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("finish_run", &unsigned).expect("canonical finish_run digest"),
    );
    serde_json::from_value(wire).expect("digest-valid finish_run fixture")
}

fn finalize_ingest_wire(mut wire: serde_json::Value) -> IngestRequest {
    for envelope in wire["envelopes"].as_array_mut().expect("envelope array") {
        let payload: TypedEvidencePayload =
            serde_json::from_value(envelope["inline_payload"].clone())
                .expect("typed evidence payload fixture");
        envelope["payload_digest"] = serde_json::Value::String(
            canonical_inline_payload_digest(&payload).expect("canonical inline payload digest"),
        );
    }
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: IngestRequest =
        serde_json::from_value(wire.clone()).expect("shape-valid ingest fixture");
    wire["request_digest"] = serde_json::Value::String(
        canonical_request_digest("ingest", &unsigned).expect("canonical ingest digest"),
    );
    serde_json::from_value(wire).expect("digest-valid ingest fixture")
}

fn request_fixture(file_name: &str) -> serde_json::Value {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../apolysis-contracts/tests/fixtures/gateway/positive/"
    );
    let path = format!("{root}{file_name}");
    serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {file_name}: {error}")),
    )
    .expect("decode the checked-in Gateway fixture")
}

pub async fn open_run(
    repository: PostgresGatewayRepository,
    context: &AuthenticatedSourceContext,
    request: OpenRunRequest,
) -> TestResult<OpenRunResponse> {
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let response = gateway.open_run(context, request).await?;
    record_test_bearer_pattern(response.lease().lease_id())?;
    Ok(response)
}

fn record_test_bearer_pattern(pattern: &str) -> TestResult<()> {
    const MAX_BEARER_PATTERN_BYTES: u64 = 65_536;

    let suffix = pattern.strip_prefix("lease_").ok_or_else(|| {
        io::Error::other("the generated lease did not use the production bearer format")
    })?;
    if suffix.len() != 64
        || !suffix
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(io::Error::other(
            "the generated lease did not use the production bearer format",
        )
        .into());
    }
    let path = PathBuf::from(env::var_os("APOLYSIS_TEST_BEARER_PATTERN_FILE").ok_or_else(
        || {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the projection gate bearer inventory file is required",
            )
        },
    )?);
    let before = fs::symlink_metadata(&path)
        .map_err(|_| io::Error::other("invalid projection gate bearer inventory file"))?;
    if !before.file_type().is_file()
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() > MAX_BEARER_PATTERN_BYTES
    {
        return Err(io::Error::other("invalid projection gate bearer inventory file").into());
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|_| io::Error::other("failed to open the gate bearer inventory"))?;
    let opened = file
        .metadata()
        .map_err(|_| io::Error::other("failed to inspect the gate bearer inventory"))?;
    if !opened.file_type().is_file()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Err(io::Error::other("the gate bearer inventory was replaced").into());
    }
    writeln!(file, "{pattern}")
        .map_err(|_| io::Error::other("failed to update the gate bearer inventory"))?;
    file.sync_data()
        .map_err(|_| io::Error::other("failed to persist the gate bearer inventory"))?;
    let after = fs::symlink_metadata(&path)
        .map_err(|_| io::Error::other("invalid projection gate bearer inventory file"))?;
    if !after.file_type().is_file()
        || after.mode() & 0o777 != 0o600
        || after.nlink() != 1
        || after.dev() != opened.dev()
        || after.ino() != opened.ino()
        || after.len() > MAX_BEARER_PATTERN_BYTES
    {
        return Err(io::Error::other("the gate bearer inventory was replaced").into());
    }
    Ok(())
}

pub async fn project_until_caught_up(
    projection: &PostgresRunProjection,
    key: &GenerationKey,
    first_now_unix_ms: u64,
) -> Result<Vec<ProjectionCommit>, ProjectionError> {
    let mut commits = Vec::new();
    for offset in 0..10_000_u64 {
        match projection
            .project_next(key, first_now_unix_ms + offset)
            .await?
        {
            ProjectionBatchOutcome::Applied(commit) => commits.push(commit),
            ProjectionBatchOutcome::CaughtUp(_) => return Ok(commits),
        }
    }
    panic!("projection did not reach its bounded caught-up state");
}

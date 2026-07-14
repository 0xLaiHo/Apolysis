// SPDX-License-Identifier: Apache-2.0

//! Process-level real PostgreSQL projection crash/restart gate driver.
//!
//! The driver deliberately accepts the database URL only through a private
//! file and reports stage names rather than propagating dependency errors. Its
//! persisted state contains identifiers and aggregate counts only.

use std::{
    env,
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::{self, Read, Write},
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    EnvironmentKind, GatewayOperation, OpenRunRequest, OrganizationId, PrincipalKind, PrincipalRef,
    PrivacyCapability, SourceCapability, SourceId, SourceKind, SourceRegistrationPolicy,
    TrustProfile,
};
use apolysis_gateway::{
    canonical_request_digest, ExecutionEvidenceGateway, GatewayClock, OsRandomIdGenerator,
    SystemClock,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository, MIGRATOR,
};
use apolysis_projection_postgres::{
    ComputationVersion, GenerationId, GenerationKey, PostgresRunProjection, ProjectionBatchOutcome,
    ProjectionConfig,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};

const STATE_SCHEMA_VERSION: &str = "apolysis-projection-crash-state/v1";
const ORGANIZATION_ID: &str = "org_projection_crash_gate";
const COMPUTATION_VERSION: &str = "run-lifecycle-crash-gate-v1";
const NOW_UNIX_MS: u64 = 1_783_891_200_000;
const SEED_RUN_COUNT: u64 = 2;
const FACTS_PER_OPEN_RUN: u64 = 3;
const MAX_DATABASE_URL_BYTES: u64 = 4_096;
const MAX_BEARER_PATTERN_BYTES: u64 = 65_536;
const MAX_PROJECTION_STEPS: u64 = 1_000_000;

type DriverResult<T> = Result<T, DriverError>;

#[derive(Clone, Copy)]
struct DriverError {
    stage: &'static str,
}

impl DriverError {
    const fn at(stage: &'static str) -> Self {
        Self { stage }
    }
}

impl fmt::Debug for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DriverError")
            .field("stage", &self.stage)
            .finish()
    }
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "stage={}", self.stage)
    }
}

impl Error for DriverError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DriverState {
    schema_version: String,
    organization_id: String,
    generation_id: i64,
    seeded_run_count: u64,
    expected_watermark: u64,
}

impl DriverState {
    fn seed(generation_id: GenerationId) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION.to_string(),
            organization_id: ORGANIZATION_ID.to_string(),
            generation_id: generation_id.get(),
            seeded_run_count: SEED_RUN_COUNT,
            expected_watermark: SEED_RUN_COUNT * FACTS_PER_OPEN_RUN,
        }
    }

    fn validate(&self) -> DriverResult<()> {
        let expected = self
            .seeded_run_count
            .checked_mul(FACTS_PER_OPEN_RUN)
            .ok_or_else(|| DriverError::at("state_count_overflow"))?;
        if self.schema_version != STATE_SCHEMA_VERSION
            || self.organization_id != ORGANIZATION_ID
            || self.generation_id <= 0
            || self.seeded_run_count < SEED_RUN_COUNT
            || self.expected_watermark != expected
            || self.expected_watermark > MAX_PROJECTION_STEPS
        {
            return Err(DriverError::at("state_validation"));
        }
        Ok(())
    }

    fn generation_key(&self) -> DriverResult<GenerationKey> {
        let organization_id = OrganizationId::try_from(self.organization_id.as_str())
            .map_err(|_| DriverError::at("state_organization"))?;
        let generation_id = GenerationId::try_from(self.generation_id)
            .map_err(|_| DriverError::at("state_generation"))?;
        Ok(GenerationKey::new(organization_id, generation_id))
    }

    fn after_append(&self) -> DriverResult<Self> {
        let seeded_run_count = self
            .seeded_run_count
            .checked_add(1)
            .ok_or_else(|| DriverError::at("append_count_overflow"))?;
        let expected_watermark = self
            .expected_watermark
            .checked_add(FACTS_PER_OPEN_RUN)
            .ok_or_else(|| DriverError::at("append_watermark_overflow"))?;
        let next = Self {
            schema_version: self.schema_version.clone(),
            organization_id: self.organization_id.clone(),
            generation_id: self.generation_id,
            seeded_run_count,
            expected_watermark,
        };
        next.validate()?;
        Ok(next)
    }
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("stage=runtime_initialization");
            std::process::exit(1);
        }
    };
    if let Err(error) = runtime.block_on(run()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> DriverResult<()> {
    let mode = parse_mode()?;
    let database_url = read_database_url()?;
    let state_path = required_path("APOLYSIS_PROJECTION_STATE_FILE", "state_path")?;
    let bearer_pattern_path =
        required_path("APOLYSIS_TEST_BEARER_PATTERN_FILE", "bearer_pattern_path")?;
    validate_bearer_pattern_file(&bearer_pattern_path)?;

    match mode.as_str() {
        "seed" => seed(&database_url, &state_path, &bearer_pattern_path).await,
        "project-one" => project_one(&database_url, &state_path).await,
        "verify-zero" => verify_zero_mode(&database_url, &state_path).await,
        "project-until-idle" => project_until_idle_mode(&database_url, &state_path).await,
        "verify-complete" => verify_complete_mode(&database_url, &state_path).await,
        "append-and-project" => {
            append_and_project(&database_url, &state_path, &bearer_pattern_path).await
        }
        _ => Err(DriverError::at("mode_invalid")),
    }
}

fn parse_mode() -> DriverResult<String> {
    let mut arguments = env::args();
    let _program = arguments.next();
    let mode = arguments
        .next()
        .ok_or_else(|| DriverError::at("mode_missing"))?;
    if arguments.next().is_some() {
        return Err(DriverError::at("mode_argument_count"));
    }
    Ok(mode)
}

fn required_path(variable: &'static str, stage: &'static str) -> DriverResult<PathBuf> {
    let value = env::var_os(variable).ok_or_else(|| DriverError::at(stage))?;
    if value.is_empty() {
        return Err(DriverError::at(stage));
    }
    Ok(PathBuf::from(value))
}

fn read_database_url() -> DriverResult<String> {
    let path = required_path("APOLYSIS_TEST_DATABASE_URL_FILE", "database_url_path")?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| DriverError::at("database_url_metadata"))?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_DATABASE_URL_BYTES
    {
        return Err(DriverError::at("database_url_permissions"));
    }
    let mut file = fs::File::open(&path).map_err(|_| DriverError::at("database_url_open"))?;
    let opened = file
        .metadata()
        .map_err(|_| DriverError::at("database_url_open_metadata"))?;
    if !opened.file_type().is_file()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
    {
        return Err(DriverError::at("database_url_replaced"));
    }
    let mut encoded = Vec::with_capacity(
        usize::try_from(opened.len()).map_err(|_| DriverError::at("database_url_size"))?,
    );
    (&mut file)
        .take(MAX_DATABASE_URL_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| DriverError::at("database_url_read"))?;
    if u64::try_from(encoded.len()).ok() != Some(opened.len()) {
        return Err(DriverError::at("database_url_changed"));
    }
    let text = String::from_utf8(encoded).map_err(|_| DriverError::at("database_url_encoding"))?;
    let database_url = text.trim_end_matches(['\r', '\n']);
    if database_url.is_empty()
        || database_url.contains(['\r', '\n', '\0'])
        || !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"))
    {
        return Err(DriverError::at("database_url_format"));
    }
    Ok(database_url.to_string())
}

fn projection_config() -> DriverResult<ProjectionConfig> {
    ProjectionConfig::new(1, 8, 5_000, 30_000).map_err(|_| DriverError::at("projection_config"))
}

fn replay_protector() -> DriverResult<Arc<Aes256GcmReplayProtector>> {
    Aes256GcmReplayProtector::new(
        "projection-crash-gate-v1",
        [("projection-crash-gate-v1".to_string(), [137_u8; 32])],
    )
    .map(Arc::new)
    .map_err(|_| DriverError::at("replay_protector"))
}

async fn gateway_repository(database_url: &str) -> DriverResult<PostgresGatewayRepository> {
    PostgresGatewayRepository::connect(
        database_url,
        replay_protector()?,
        PostgresGatewayConfig::default(),
    )
    .await
    .map_err(|_| DriverError::at("gateway_connect_migrate"))
}

async fn projection_repository(database_url: &str) -> DriverResult<PostgresRunProjection> {
    PostgresRunProjection::connect_and_migrate(database_url, projection_config()?)
        .await
        .map_err(|_| DriverError::at("projection_connect_migrate"))
}

async fn database_pool(database_url: &str) -> DriverResult<PgPool> {
    PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await
        .map_err(|_| DriverError::at("verification_database_connect"))
}

async fn seed(
    database_url: &str,
    state_path: &Path,
    bearer_pattern_path: &Path,
) -> DriverResult<()> {
    if fs::symlink_metadata(state_path).is_ok() {
        return Err(DriverError::at("seed_state_exists"));
    }
    let pool = database_pool(database_url).await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|_| DriverError::at("gateway_migrate"))?;
    let gateway = gateway_repository(database_url).await?;
    let projection = projection_repository(database_url).await?;
    verify_seed_scope_empty(&pool).await?;

    for ordinal in 1..=SEED_RUN_COUNT {
        open_genuine_run(gateway.clone(), ordinal, "seed", bearer_pattern_path).await?;
    }

    let organization_id = OrganizationId::try_from(ORGANIZATION_ID)
        .map_err(|_| DriverError::at("seed_organization"))?;
    let computation_version = ComputationVersion::try_from(COMPUTATION_VERSION)
        .map_err(|_| DriverError::at("seed_computation_version"))?;
    let generation = projection
        .initialize_current(&organization_id, computation_version, NOW_UNIX_MS + 100)
        .await
        .map_err(|_| DriverError::at("seed_initialize_generation"))?;
    let state = DriverState::seed(generation.key().generation_id());
    verify_zero(&pool, &projection, &state).await?;
    write_state_atomic(state_path, &state)
}

async fn verify_seed_scope_empty(pool: &PgPool) -> DriverResult<()> {
    let gateway_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.organization_sequences WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("seed_scope_gateway_query"))?;
    let projection_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_projection.generations WHERE organization_id=$1",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("seed_scope_projection_query"))?;
    if gateway_count != 0 || projection_count != 0 {
        return Err(DriverError::at("seed_scope_not_empty"));
    }
    Ok(())
}

async fn project_one(database_url: &str, state_path: &Path) -> DriverResult<()> {
    let state = read_state(state_path)?;
    let projection = projection_repository(database_url).await?;
    let key = state.generation_key()?;
    let outcome = projection
        .project_next(&key, NOW_UNIX_MS + 200)
        .await
        .map_err(|_| DriverError::at("project_one_commit"))?;
    match outcome {
        ProjectionBatchOutcome::Applied(commit)
            if commit.record_count() == 1
                && commit.through_input_watermark()
                    == commit.from_input_watermark().saturating_add(1) => {}
        ProjectionBatchOutcome::Applied(_) => {
            return Err(DriverError::at("project_one_batch_shape"));
        }
        ProjectionBatchOutcome::CaughtUp(_) => {
            return Err(DriverError::at("project_one_unexpected_idle"));
        }
    }

    let marker_path = env::var_os("APOLYSIS_TEST_POST_COMMIT_MARKER")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(path) = marker_path.as_deref() {
        write_marker(path)?;
    }
    if env::var_os("APOLYSIS_TEST_HOLD_AFTER_COMMIT").as_deref() == Some("1".as_ref()) {
        if marker_path.is_none() {
            return Err(DriverError::at("project_one_hold_without_marker"));
        }
        std::future::pending::<()>().await;
    }
    Ok(())
}

async fn verify_zero_mode(database_url: &str, state_path: &Path) -> DriverResult<()> {
    let state = read_state(state_path)?;
    let projection = projection_repository(database_url).await?;
    let pool = database_pool(database_url).await?;
    verify_zero(&pool, &projection, &state).await
}

async fn project_until_idle_mode(database_url: &str, state_path: &Path) -> DriverResult<()> {
    let state = read_state(state_path)?;
    let projection = projection_repository(database_url).await?;
    project_until_idle(&projection, &state).await
}

async fn verify_complete_mode(database_url: &str, state_path: &Path) -> DriverResult<()> {
    let state = read_state(state_path)?;
    let projection = projection_repository(database_url).await?;
    let pool = database_pool(database_url).await?;
    verify_complete(&pool, &projection, &state).await
}

async fn append_and_project(
    database_url: &str,
    state_path: &Path,
    bearer_pattern_path: &Path,
) -> DriverResult<()> {
    let state = read_state(state_path)?;
    let ordinal = env::var("APOLYSIS_TEST_APPEND_ORDINAL")
        .map_err(|_| DriverError::at("append_ordinal_missing"))?
        .parse::<u64>()
        .map_err(|_| DriverError::at("append_ordinal_format"))?;
    if ordinal <= SEED_RUN_COUNT || ordinal > 999_999 {
        return Err(DriverError::at("append_ordinal_range"));
    }

    let gateway = gateway_repository(database_url).await?;
    open_genuine_run(gateway, ordinal, "append", bearer_pattern_path).await?;
    let next_state = state.after_append()?;
    let projection = projection_repository(database_url).await?;
    project_until_idle(&projection, &next_state).await?;
    let pool = database_pool(database_url).await?;
    verify_complete(&pool, &projection, &next_state).await?;
    write_state_atomic(state_path, &next_state)
}

async fn project_until_idle(
    projection: &PostgresRunProjection,
    state: &DriverState,
) -> DriverResult<()> {
    let key = state.generation_key()?;
    for offset in 0..=state.expected_watermark {
        let now_unix_ms = NOW_UNIX_MS
            .checked_add(300)
            .and_then(|value| value.checked_add(offset))
            .ok_or_else(|| DriverError::at("projection_clock_overflow"))?;
        match projection
            .project_next(&key, now_unix_ms)
            .await
            .map_err(|_| DriverError::at("projection_drain_batch"))?
        {
            ProjectionBatchOutcome::Applied(commit) if commit.record_count() == 1 => {}
            ProjectionBatchOutcome::Applied(_) => {
                return Err(DriverError::at("projection_drain_batch_shape"));
            }
            ProjectionBatchOutcome::CaughtUp(checkpoint) => {
                if checkpoint.input_watermark() != state.expected_watermark {
                    return Err(DriverError::at("projection_drain_watermark"));
                }
                return Ok(());
            }
        }
    }
    Err(DriverError::at("projection_drain_bound"))
}

async fn verify_zero(
    pool: &PgPool,
    projection: &PostgresRunProjection,
    state: &DriverState,
) -> DriverResult<()> {
    state.validate()?;
    let key = state.generation_key()?;
    let status = projection
        .generation_status(&key, NOW_UNIX_MS + 400)
        .await
        .map_err(|_| DriverError::at("verify_zero_status"))?;
    if status.generation().key() != &key
        || status.checkpoint().input_watermark() != 0
        || status.checkpoint().last_commit_revision().is_some()
        || status.checkpoint().failure().is_some()
        || status.durable_input_watermark() != state.expected_watermark
        || status.query_visible_watermark() != 0
    {
        return Err(DriverError::at("verify_zero_checkpoint"));
    }

    let (record_count, run_count): (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM apolysis_gateway.record_items WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.runs WHERE organization_id=$1)",
    )
    .bind(&state.organization_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("verify_zero_gateway_counts"))?;
    if !equals_u64(record_count, state.expected_watermark)
        || !equals_u64(run_count, state.seeded_run_count)
    {
        return Err(DriverError::at("verify_zero_gateway_shape"));
    }

    let (commit_count, lifecycle_count): (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM apolysis_projection.commits \
              WHERE organization_id=$1 AND generation_id=$2), \
           (SELECT count(*) FROM apolysis_projection.run_lifecycle \
              WHERE organization_id=$1 AND generation_id=$2)",
    )
    .bind(&state.organization_id)
    .bind(state.generation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("verify_zero_projection_counts"))?;
    if commit_count != 0 || lifecycle_count != 0 {
        return Err(DriverError::at("verify_zero_projection_shape"));
    }

    let (outbox_count, pending_count, published_count, attempt_count): (i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT count(*), \
                    count(*) FILTER (WHERE delivery_state='pending' \
                        AND published_at_unix_ms IS NULL \
                        AND claimed_by IS NULL AND claimed_at_unix_ms IS NULL \
                        AND last_error_code IS NULL), \
                    count(*) FILTER (WHERE delivery_state='published'), \
                    COALESCE(sum(attempt_count), 0)::bigint \
             FROM apolysis_gateway.projection_outbox WHERE organization_id=$1",
        )
        .bind(&state.organization_id)
        .fetch_one(pool)
        .await
        .map_err(|_| DriverError::at("verify_zero_outbox"))?;
    if !equals_u64(outbox_count, state.expected_watermark)
        || !equals_u64(pending_count, state.expected_watermark)
        || published_count != 0
        || attempt_count != 0
    {
        return Err(DriverError::at("verify_zero_outbox_shape"));
    }
    Ok(())
}

async fn verify_complete(
    pool: &PgPool,
    projection: &PostgresRunProjection,
    state: &DriverState,
) -> DriverResult<()> {
    state.validate()?;
    let key = state.generation_key()?;
    let status = projection
        .generation_status(&key, NOW_UNIX_MS + 500)
        .await
        .map_err(|_| DriverError::at("verify_complete_status"))?;
    if status.generation().key() != &key
        || status.checkpoint().input_watermark() != state.expected_watermark
        || status.checkpoint().last_commit_revision() != Some(state.expected_watermark)
        || status.checkpoint().failure().is_some()
        || status.durable_input_watermark() != state.expected_watermark
        || status.query_visible_watermark() != state.expected_watermark
        || !status.is_current()
    {
        return Err(DriverError::at("verify_complete_checkpoint"));
    }

    let (record_count, run_count): (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM apolysis_gateway.record_items WHERE organization_id=$1), \
           (SELECT count(*) FROM apolysis_gateway.runs WHERE organization_id=$1)",
    )
    .bind(&state.organization_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("verify_complete_gateway_counts"))?;
    if !equals_u64(record_count, state.expected_watermark)
        || !equals_u64(run_count, state.seeded_run_count)
    {
        return Err(DriverError::at("verify_complete_gateway_shape"));
    }

    let (commit_count, record_sum, first_revision, last_revision): (
        i64,
        i64,
        Option<i64>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT count(*), COALESCE(sum(record_count), 0)::bigint, \
                min(commit_revision), max(commit_revision) \
         FROM apolysis_projection.commits \
         WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(&state.organization_id)
    .bind(state.generation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("verify_complete_commits"))?;
    let expected_revision = i64::try_from(state.expected_watermark)
        .map_err(|_| DriverError::at("verify_complete_revision_range"))?;
    if commit_count != expected_revision
        || record_sum != expected_revision
        || first_revision != Some(1)
        || last_revision != Some(expected_revision)
    {
        return Err(DriverError::at("verify_complete_commit_shape"));
    }

    let (lifecycle_count, active_count): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE run_state='active') \
         FROM apolysis_projection.run_lifecycle \
         WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(&state.organization_id)
    .bind(state.generation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("verify_complete_lifecycle"))?;
    if !equals_u64(lifecycle_count, state.seeded_run_count)
        || !equals_u64(active_count, state.seeded_run_count)
    {
        return Err(DriverError::at("verify_complete_lifecycle_shape"));
    }

    let (outbox_count, published_count, attempt_count): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE delivery_state='published' \
                    AND published_at_unix_ms IS NOT NULL \
                    AND claimed_by IS NULL AND claimed_at_unix_ms IS NULL \
                    AND last_error_code IS NULL AND attempt_count=1), \
                COALESCE(sum(attempt_count), 0)::bigint \
         FROM apolysis_gateway.projection_outbox WHERE organization_id=$1",
    )
    .bind(&state.organization_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError::at("verify_complete_outbox"))?;
    if !equals_u64(outbox_count, state.expected_watermark)
        || !equals_u64(published_count, state.expected_watermark)
        || !equals_u64(attempt_count, state.expected_watermark)
    {
        return Err(DriverError::at("verify_complete_outbox_shape"));
    }
    Ok(())
}

fn equals_u64(actual: i64, expected: u64) -> bool {
    u64::try_from(actual).ok() == Some(expected)
}

async fn open_genuine_run(
    repository: PostgresGatewayRepository,
    ordinal: u64,
    purpose: &str,
    bearer_pattern_path: &Path,
) -> DriverResult<()> {
    let context = source_context()?;
    let request = create_request(ordinal, purpose)?;
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let opened = gateway
        .open_run(&context, request)
        .await
        .map_err(|_| DriverError::at("gateway_open_run"))?;
    record_bearer_pattern(bearer_pattern_path, opened.lease().lease_id())
}

fn source_context() -> DriverResult<AuthenticatedSourceContext> {
    let now_unix_ms = SystemClock.now_unix_ms();
    let principal = PrincipalRef::new(PrincipalKind::Workload, "principal_projection_gate")
        .map_err(|_| DriverError::at("source_principal"))?;
    let authority = AuthorityRef::new(AuthorityKind::Service, "authority_projection_gate")
        .map_err(|_| DriverError::at("source_authority"))?;
    let policy = SourceRegistrationPolicy::new(
        SourceId::try_from("source_projection_gate")
            .map_err(|_| DriverError::at("source_identifier"))?,
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
    .map_err(|_| DriverError::at("source_policy"))?
    .with_run_authorities(vec![authority])
    .map_err(|_| DriverError::at("source_authority_policy"))?
    .with_run_profiles(
        vec!["privacy_structure_only_v1".to_string()],
        vec!["retention_30d_v1".to_string()],
        vec![SourceKind::SemanticHook],
    )
    .map_err(|_| DriverError::at("source_profile_policy"))?
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
    .map_err(|_| DriverError::at("source_evidence_policy"))?;
    AuthenticatedSourceContext::new(
        OrganizationId::try_from(ORGANIZATION_ID)
            .map_err(|_| DriverError::at("source_organization"))?,
        principal,
        "registration_projection_gate",
        AuthenticationSnapshot::new(
            "credential_projection_gate",
            1,
            now_unix_ms.saturating_sub(60_000),
            now_unix_ms.saturating_add(86_400_000),
        )
        .map_err(|_| DriverError::at("source_authentication"))?,
        policy,
    )
    .map_err(|_| DriverError::at("source_context"))
}

fn validate_bearer_pattern_file(path: &Path) -> DriverResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DriverError::at("bearer_pattern_metadata"))?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_BEARER_PATTERN_BYTES
    {
        return Err(DriverError::at("bearer_pattern_permissions"));
    }
    Ok(())
}

fn record_bearer_pattern(path: &Path, pattern: &str) -> DriverResult<()> {
    if pattern.is_empty() || pattern.contains(['\r', '\n', '\0']) {
        return Err(DriverError::at("bearer_pattern_format"));
    }
    let before =
        fs::symlink_metadata(path).map_err(|_| DriverError::at("bearer_pattern_metadata"))?;
    validate_bearer_pattern_file(path)?;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|_| DriverError::at("bearer_pattern_open"))?;
    let opened = file
        .metadata()
        .map_err(|_| DriverError::at("bearer_pattern_open_metadata"))?;
    if !opened.file_type().is_file()
        || opened.mode() & 0o777 != 0o600
        || opened.nlink() != 1
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
    {
        return Err(DriverError::at("bearer_pattern_replaced"));
    }
    writeln!(file, "{pattern}").map_err(|_| DriverError::at("bearer_pattern_write"))?;
    file.sync_data()
        .map_err(|_| DriverError::at("bearer_pattern_sync"))?;
    validate_bearer_pattern_file(path)
}

fn create_request(ordinal: u64, purpose: &str) -> DriverResult<OpenRunRequest> {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(
        "../../apolysis-contracts/tests/fixtures/gateway/positive/open_run_create_request.json"
    ))
    .map_err(|_| DriverError::at("open_request_fixture"))?;
    wire["client_operation_id"] =
        serde_json::Value::String(format!("operation_projection_{purpose}_{ordinal:06}"));
    wire["client_run_key"] =
        serde_json::Value::String(format!("client_projection_{purpose}_{ordinal:06}"));
    wire["objective_ref"] =
        serde_json::Value::String(format!("objective_projection_{purpose}_{ordinal:06}"));
    wire["authority"] = serde_json::json!({
        "kind": "service",
        "id": "authority_projection_gate"
    });
    wire["principal"] = serde_json::json!({
        "kind": "workload",
        "id": "principal_projection_gate"
    });
    wire["source_manifest"]["source_id"] =
        serde_json::Value::String("source_projection_gate".to_string());
    wire["expected_source_kinds"] = serde_json::json!(["semantic_hook"]);
    wire["request_digest"] = serde_json::Value::String("0".repeat(64));
    let unsigned: OpenRunRequest =
        serde_json::from_value(wire.clone()).map_err(|_| DriverError::at("open_request_shape"))?;
    let digest = canonical_request_digest("open_run", &unsigned)
        .map_err(|_| DriverError::at("open_request_digest"))?;
    wire["request_digest"] = serde_json::Value::String(digest);
    serde_json::from_value(wire).map_err(|_| DriverError::at("open_request_finalize"))
}

fn read_state(path: &Path) -> DriverResult<DriverState> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DriverError::at("state_metadata"))?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 4_096
    {
        return Err(DriverError::at("state_permissions"));
    }
    let state: DriverState =
        serde_json::from_slice(&fs::read(path).map_err(|_| DriverError::at("state_read"))?)
            .map_err(|_| DriverError::at("state_decode"))?;
    state.validate()?;
    Ok(state)
}

fn write_state_atomic(path: &Path, state: &DriverState) -> DriverResult<()> {
    state.validate()?;
    let parent = normalized_parent(path);
    let file_name = path
        .file_name()
        .ok_or_else(|| DriverError::at("state_file_name"))?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".tmp.{}", std::process::id()));
    let temporary_path = parent.join(temporary_name);
    let result = write_state_file(&temporary_path, path, state);
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn write_state_file(temporary_path: &Path, path: &Path, state: &DriverState) -> DriverResult<()> {
    let mut encoded = serde_json::to_vec(state).map_err(|_| DriverError::at("state_encode"))?;
    encoded.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary_path)
        .map_err(|_| DriverError::at("state_temporary_create"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| DriverError::at("state_temporary_permissions"))?;
    file.write_all(&encoded)
        .map_err(|_| DriverError::at("state_temporary_write"))?;
    file.sync_all()
        .map_err(|_| DriverError::at("state_temporary_sync"))?;
    fs::rename(temporary_path, path).map_err(|_| DriverError::at("state_rename"))?;
    sync_parent(path, "state_parent_sync")
}

fn write_marker(path: &Path) -> DriverResult<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| DriverError::at("post_commit_marker_create"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| DriverError::at("post_commit_marker_permissions"))?;
    file.write_all(b"committed\n")
        .map_err(|_| DriverError::at("post_commit_marker_write"))?;
    file.sync_all()
        .map_err(|_| DriverError::at("post_commit_marker_sync"))?;
    sync_parent(path, "post_commit_marker_parent_sync")
}

fn normalized_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn sync_parent(path: &Path, stage: &'static str) -> DriverResult<()> {
    fs::File::open(normalized_parent(path))
        .and_then(|directory| directory.sync_all())
        .map_err(|_: io::Error| DriverError::at(stage))
}

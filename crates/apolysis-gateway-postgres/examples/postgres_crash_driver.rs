// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use apolysis_contracts::{
    AuthenticatedSourceContext, AuthenticationSnapshot, AuthorityKind, AuthorityRef,
    EnvironmentKind, GatewayOperation, OpenRunOutcome, OpenRunRequest, OpenRunResponse,
    OrganizationId, PrincipalKind, PrincipalRef, PrivacyCapability, RunId, SchemaVersion,
    SourceCapability, SourceId, SourceKind, SourceManifest, SourceRegistrationPolicy, TrustProfile,
};
use apolysis_gateway::{
    canonical_request_digest, lease_id_digest, ExecutionEvidenceGateway, GatewayClock,
    OsRandomIdGenerator, SystemClock,
};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use zeroize::{Zeroize, Zeroizing};

const MAX_CONTROL_FILE_BYTES: u64 = 16 * 1024;
const REPLAY_KEY_ID: &str = "postgres-crash-recovery-v1";

type DriverResult<T> = Result<T, DriverError>;
type CrashRecoveryGateway =
    ExecutionEvidenceGateway<PostgresGatewayRepository, SystemClock, OsRandomIdGenerator>;

#[derive(Clone, Copy)]
struct DriverError(&'static str);

impl DriverError {
    fn report(self) {
        eprintln!(
            "error: PostgreSQL crash recovery driver failed during {}",
            self.0
        );
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Open,
    VerifyReplay,
    VerifyRollbackAndRetry,
    OpenAndHoldBeforeClientAck,
    ReplayAndHoldBeforeClientAck,
}

impl Mode {
    fn parse(value: &str) -> DriverResult<Self> {
        match value {
            "open" => Ok(Self::Open),
            "verify-replay" => Ok(Self::VerifyReplay),
            "verify-rollback-and-retry" => Ok(Self::VerifyRollbackAndRetry),
            "open-and-hold-before-client-ack" => Ok(Self::OpenAndHoldBeforeClientAck),
            "replay-and-hold-before-client-ack" => Ok(Self::ReplayAndHoldBeforeClientAck),
            _ => Err(DriverError("argument validation")),
        }
    }
}

struct Arguments {
    mode: Mode,
    database_url_file: PathBuf,
    replay_key_file: PathBuf,
    scenario: String,
    state_file: PathBuf,
    ready_file: Option<PathBuf>,
    release_file: Option<PathBuf>,
    ack_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableState {
    scenario: String,
    run_id: RunId,
    source_stream_id: String,
    lease_digest: String,
    response_identity_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScenarioCounts {
    runs: i64,
    operations: i64,
    replays: i64,
    leases: i64,
    records: i64,
    outbox: i64,
}

impl ScenarioCounts {
    const COMMITTED_OPEN: Self = Self {
        runs: 1,
        operations: 1,
        replays: 1,
        leases: 1,
        records: 3,
        outbox: 3,
    };

    const ZERO: Self = Self {
        runs: 0,
        operations: 0,
        replays: 0,
        leases: 0,
        records: 0,
        outbox: 0,
    };
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        error.report();
        std::process::exit(1);
    }
}

async fn run() -> DriverResult<()> {
    let arguments = parse_arguments()?;
    validate_absolute_path(&arguments.database_url_file)?;
    validate_absolute_path(&arguments.replay_key_file)?;
    validate_absolute_path(&arguments.state_file)?;
    let mut output_paths = vec![&arguments.state_file];
    for path in [
        arguments.ready_file.as_ref(),
        arguments.release_file.as_ref(),
        arguments.ack_file.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_absolute_path(path)?;
        if output_paths.contains(&path) {
            return Err(DriverError("argument validation"));
        }
        output_paths.push(path);
    }

    let expected_state = if matches!(
        arguments.mode,
        Mode::VerifyReplay | Mode::ReplayAndHoldBeforeClientAck
    ) {
        Some(read_state(&arguments.state_file, &arguments.scenario)?)
    } else {
        ensure_output_absent(&arguments.state_file)?;
        None
    };
    for path in [
        arguments.ready_file.as_ref(),
        arguments.release_file.as_ref(),
        arguments.ack_file.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        ensure_output_absent(path)?;
    }

    let database_url = read_database_url(&arguments.database_url_file)?;
    let replay_key = read_replay_key(&arguments.replay_key_file)?;
    let (gateway, pool) = production_gateway(&database_url, replay_key).await?;
    let (context, request) = build_operation(&arguments.scenario)?;

    match arguments.mode {
        Mode::Open => {
            let response = gateway
                .open_run(&context, request)
                .await
                .map_err(|_| DriverError("Gateway open"))?;
            require_outcome(&response, OpenRunOutcome::Created)?;
            let state =
                verify_committed_result(&pool, &context, &arguments.scenario, &response, None)
                    .await?;
            write_state(&arguments.state_file, &state)?;
        }
        Mode::VerifyReplay => {
            let expected_state = expected_state.ok_or(DriverError("state validation"))?;
            let response = gateway
                .open_run(&context, request)
                .await
                .map_err(|_| DriverError("Gateway replay"))?;
            require_outcome(&response, OpenRunOutcome::IdempotentRetry)?;
            verify_committed_result(
                &pool,
                &context,
                &arguments.scenario,
                &response,
                Some(&expected_state),
            )
            .await?;
        }
        Mode::VerifyRollbackAndRetry => {
            verify_counts(
                &pool,
                context.organization_id().as_str(),
                ScenarioCounts::ZERO,
            )
            .await?;
            let response = gateway
                .open_run(&context, request)
                .await
                .map_err(|_| DriverError("Gateway rollback retry"))?;
            require_outcome(&response, OpenRunOutcome::Created)?;
            let state =
                verify_committed_result(&pool, &context, &arguments.scenario, &response, None)
                    .await?;
            write_state(&arguments.state_file, &state)?;
        }
        Mode::OpenAndHoldBeforeClientAck => {
            let state = {
                let response = gateway
                    .open_run(&context, request)
                    .await
                    .map_err(|_| DriverError("Gateway held open"))?;
                require_outcome(&response, OpenRunOutcome::Created)?;
                verify_committed_result(&pool, &context, &arguments.scenario, &response, None)
                    .await?
            };
            write_state(&arguments.state_file, &state)?;
            hold_before_client_ack(&arguments, b"committed\n").await?;
        }
        Mode::ReplayAndHoldBeforeClientAck => {
            let expected_state = expected_state.ok_or(DriverError("state validation"))?;
            let response = gateway
                .open_run(&context, request)
                .await
                .map_err(|_| DriverError("Gateway held replay"))?;
            require_outcome(&response, OpenRunOutcome::IdempotentRetry)?;
            verify_committed_result(
                &pool,
                &context,
                &arguments.scenario,
                &response,
                Some(&expected_state),
            )
            .await?;
            hold_before_client_ack(&arguments, b"replayed\n").await?;
        }
    }

    Ok(())
}

async fn hold_before_client_ack(arguments: &Arguments, ready_contents: &[u8]) -> DriverResult<()> {
    let ready_file = arguments
        .ready_file
        .as_deref()
        .ok_or(DriverError("argument validation"))?;
    let release_file = arguments
        .release_file
        .as_deref()
        .ok_or(DriverError("argument validation"))?;
    let ack_file = arguments
        .ack_file
        .as_deref()
        .ok_or(DriverError("argument validation"))?;

    // The ready marker is fault-injector instrumentation, not the client
    // response. Only the separately released acknowledgement file represents
    // delivery to the external caller. The crash gate kills this process while
    // the acknowledgement path is still absent.
    write_private_file(ready_file, ready_contents, "ready marker")?;
    loop {
        match fs::symlink_metadata(release_file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => return Err(DriverError("acknowledgement release")),
            Ok(_) => {
                let release = read_private_file(release_file, "acknowledgement release")?;
                if release.as_slice() != b"release\n" {
                    return Err(DriverError("acknowledgement release"));
                }
                break;
            }
        }
    }
    write_private_file(ack_file, b"acknowledged\n", "client acknowledgement")
}

fn parse_arguments() -> DriverResult<Arguments> {
    let mut arguments = env::args_os().skip(1);
    let mode = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(DriverError("argument validation"))?;
    let mode = Mode::parse(&mode)?;

    let mut database_url_file = None;
    let mut replay_key_file = None;
    let mut scenario = None;
    let mut state_file = None;
    let mut ready_file = None;
    let mut release_file = None;
    let mut ack_file = None;

    while let Some(flag) = arguments.next() {
        let flag = flag.to_str().ok_or(DriverError("argument validation"))?;
        let value = arguments.next().ok_or(DriverError("argument validation"))?;
        match flag {
            "--database-url-file" => set_once(&mut database_url_file, PathBuf::from(value))?,
            "--replay-key-file" => set_once(&mut replay_key_file, PathBuf::from(value))?,
            "--scenario" => {
                let value = value
                    .into_string()
                    .map_err(|_| DriverError("argument validation"))?;
                validate_scenario(&value)?;
                set_once(&mut scenario, value)?;
            }
            "--state-file" => set_once(&mut state_file, PathBuf::from(value))?,
            "--ready-file" => set_once(&mut ready_file, PathBuf::from(value))?,
            "--release-file" => set_once(&mut release_file, PathBuf::from(value))?,
            "--ack-file" => set_once(&mut ack_file, PathBuf::from(value))?,
            _ => return Err(DriverError("argument validation")),
        }
    }

    let holds_before_client_ack = matches!(
        mode,
        Mode::OpenAndHoldBeforeClientAck | Mode::ReplayAndHoldBeforeClientAck
    );
    let has_all_ack_paths = ready_file.is_some() && release_file.is_some() && ack_file.is_some();
    let has_any_ack_path = ready_file.is_some() || release_file.is_some() || ack_file.is_some();
    if (holds_before_client_ack && !has_all_ack_paths)
        || (!holds_before_client_ack && has_any_ack_path)
    {
        return Err(DriverError("argument validation"));
    }

    Ok(Arguments {
        mode,
        database_url_file: database_url_file.ok_or(DriverError("argument validation"))?,
        replay_key_file: replay_key_file.ok_or(DriverError("argument validation"))?,
        scenario: scenario.ok_or(DriverError("argument validation"))?,
        state_file: state_file.ok_or(DriverError("argument validation"))?,
        ready_file,
        release_file,
        ack_file,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> DriverResult<()> {
    if slot.replace(value).is_some() {
        return Err(DriverError("argument validation"));
    }
    Ok(())
}

fn validate_scenario(scenario: &str) -> DriverResult<()> {
    if scenario.is_empty()
        || scenario.len() > 64
        || !scenario
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || !scenario
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !scenario
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(DriverError("scenario validation"));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> DriverResult<()> {
    if !path.is_absolute() {
        return Err(DriverError("path validation"));
    }
    Ok(())
}

fn ensure_output_absent(path: &Path) -> DriverResult<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(DriverError("output preflight")),
    }
}

fn read_private_file(path: &Path, stage: &'static str) -> DriverResult<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DriverError(stage))?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_CONTROL_FILE_BYTES
    {
        return Err(DriverError(stage));
    }
    fs::read(path)
        .map(Zeroizing::new)
        .map_err(|_| DriverError(stage))
}

fn read_database_url(path: &Path) -> DriverResult<Zeroizing<String>> {
    let bytes = read_private_file(path, "database URL loading")?;
    let value =
        String::from_utf8(bytes.to_vec()).map_err(|_| DriverError("database URL loading"))?;
    let value = value.trim_end_matches(&['\r', '\n'][..]);
    if value.is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err(DriverError("database URL loading"));
    }
    Ok(Zeroizing::new(value.to_string()))
}

fn read_replay_key(path: &Path) -> DriverResult<[u8; 32]> {
    let bytes = read_private_file(path, "replay key loading")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| DriverError("replay key loading"))
}

fn read_state(path: &Path, scenario: &str) -> DriverResult<DurableState> {
    let bytes = read_private_file(path, "state loading")?;
    let state: DurableState =
        serde_json::from_slice(&bytes).map_err(|_| DriverError("state loading"))?;
    validate_scenario(&state.scenario)?;
    if state.scenario != scenario
        || validate_stream_id(&state.source_stream_id).is_err()
        || !is_sha256_hex(&state.lease_digest)
        || !is_sha256_hex(&state.response_identity_digest)
    {
        return Err(DriverError("state validation"));
    }
    Ok(state)
}

fn validate_stream_id(value: &str) -> DriverResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(DriverError("state validation"));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn response_identity_digest(
    response: &OpenRunResponse,
    lease_digest: &str,
) -> DriverResult<String> {
    // Replay deliberately changes only `outcome` from created to
    // idempotent_retry. Hash every other response field, substituting the
    // one-way lease digest so the crash-control state never holds a bearer.
    let identity = serde_json::json!({
        "schema_version": response.schema_version(),
        "run_id": response.run_id(),
        "source_id": response.source_id(),
        "source_stream_id": response.source_stream_id(),
        "lease": {
            "lease_digest": lease_digest,
            "expires_at_unix_ms": response.lease().expires_at_unix_ms(),
            "allowed_operations": response.lease().allowed_operations(),
        },
    });
    let canonical = serde_json_canonicalizer::to_vec(&identity)
        .map_err(|_| DriverError("response identity digest"))?;
    let digest = Sha256::digest(canonical);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(encoded)
}

async fn production_gateway(
    database_url: &str,
    mut replay_key: [u8; 32],
) -> DriverResult<(CrashRecoveryGateway, PgPool)> {
    // The pre-commit crash scenario deliberately waits on a database lock.
    // Keep the production adapter's timeouts bounded, but comfortably above
    // the harness's 30-second observation window so CI scheduling cannot turn
    // the intended process kill into an ordinary lock-timeout rollback.
    let config = PostgresGatewayConfig::default()
        .with_database_timeouts(60_000, 90_000)
        .map_err(|_| DriverError("database timeout configuration"))?;
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections())
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
        .map_err(|_| DriverError("database connection"))?;
    let protector =
        Aes256GcmReplayProtector::new(REPLAY_KEY_ID, [(REPLAY_KEY_ID.to_string(), replay_key)]);
    replay_key.zeroize();
    let protector = protector.map_err(|_| DriverError("replay protector construction"))?;
    let repository =
        PostgresGatewayRepository::from_pool(pool.clone(), Arc::new(protector), config);
    repository
        .migrate()
        .await
        .map_err(|_| DriverError("database migration"))?;
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    Ok((gateway, pool))
}

fn build_operation(scenario: &str) -> DriverResult<(AuthenticatedSourceContext, OpenRunRequest)> {
    let organization_id = OrganizationId::try_from(format!("org_{scenario}"))
        .map_err(|_| DriverError("operation construction"))?;
    let source_id = SourceId::try_from(format!("source_{scenario}"))
        .map_err(|_| DriverError("operation construction"))?;
    let principal = PrincipalRef::new(PrincipalKind::Workload, format!("principal_{scenario}"))
        .map_err(|_| DriverError("operation construction"))?;
    let authority = AuthorityRef::new(AuthorityKind::Service, format!("authority_{scenario}"))
        .map_err(|_| DriverError("operation construction"))?;
    let source_manifest: SourceManifest = serde_json::from_value(serde_json::json!({
        "schema_version": "0.1",
        "source_id": source_id.as_str(),
        "source_kind": "semantic_hook",
        "declared_boundary": "agent_harness",
        "adapter_name": "postgres_crash_driver",
        "adapter_version": "1.0.0",
        "environment": "ci_runner_or_remote_workspace",
        "capabilities": ["semantic_lifecycle", "tool_calls", "claimed_outcome"],
        "expected_lifecycle": ["started", "finished"],
        "ordering": "strict_per_stream",
        "samples": false,
        "redaction_profile_ref": "redaction_structure_only_v1",
        "redacted_fields": ["payload.command"],
        "privacy_capabilities": ["structure_only"]
    }))
    .map_err(|_| DriverError("operation construction"))?;

    let policy = SourceRegistrationPolicy::new(
        source_id,
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
    .map_err(|_| DriverError("operation construction"))?
    .with_run_authorities(vec![authority.clone()])
    .map_err(|_| DriverError("operation construction"))?
    .with_run_profiles(
        vec!["privacy_structure_only_v1".to_string()],
        vec!["retention_30d_v1".to_string()],
        vec![SourceKind::SemanticHook],
    )
    .map_err(|_| DriverError("operation construction"))?
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
    .map_err(|_| DriverError("operation construction"))?;

    let now_unix_ms = SystemClock.now_unix_ms();
    let authentication = AuthenticationSnapshot::new(
        format!("credential_{scenario}"),
        1,
        now_unix_ms.saturating_sub(60_000).max(1),
        now_unix_ms
            .checked_add(60 * 60 * 1_000)
            .ok_or(DriverError("operation construction"))?,
    )
    .map_err(|_| DriverError("operation construction"))?;
    let context = AuthenticatedSourceContext::new(
        organization_id,
        principal.clone(),
        format!("registration_{scenario}"),
        authentication,
        policy,
    )
    .map_err(|_| DriverError("operation construction"))?;

    let mut request = OpenRunRequest::Create {
        schema_version: SchemaVersion::V0_1,
        client_operation_id: format!("operation_{scenario}"),
        request_digest: "0".repeat(64),
        client_run_key: format!("client_{scenario}"),
        environment: EnvironmentKind::CiRunnerOrRemoteWorkspace,
        authority,
        principal,
        objective_ref: format!("objective:{scenario}"),
        privacy_profile_ref: "privacy_structure_only_v1".to_string(),
        retention_profile_ref: "retention_30d_v1".to_string(),
        expected_source_kinds: vec![SourceKind::SemanticHook],
        source_manifest,
    };
    let request_digest = canonical_request_digest("open_run", &request)
        .map_err(|_| DriverError("operation construction"))?;
    match &mut request {
        OpenRunRequest::Create {
            request_digest: claimed_digest,
            ..
        } => *claimed_digest = request_digest,
        OpenRunRequest::Join { .. } => return Err(DriverError("operation construction")),
    }
    Ok((context, request))
}

fn require_outcome(response: &OpenRunResponse, expected: OpenRunOutcome) -> DriverResult<()> {
    if response.outcome() != expected {
        return Err(DriverError("Gateway outcome validation"));
    }
    Ok(())
}

async fn verify_committed_result(
    pool: &PgPool,
    context: &AuthenticatedSourceContext,
    scenario: &str,
    response: &OpenRunResponse,
    expected: Option<&DurableState>,
) -> DriverResult<DurableState> {
    let lease_digest = lease_id_digest(response.lease().lease_id());
    let state = DurableState {
        scenario: scenario.to_string(),
        run_id: response.run_id().clone(),
        source_stream_id: response.source_stream_id().to_string(),
        response_identity_digest: response_identity_digest(response, &lease_digest)?,
        lease_digest,
    };
    if expected.is_some_and(|expected| expected != &state) {
        return Err(DriverError("replayed result validation"));
    }

    let organization_id = context.organization_id().as_str();
    verify_counts(pool, organization_id, ScenarioCounts::COMMITTED_OPEN).await?;
    verify_database_identity(pool, organization_id, &state).await?;
    verify_plaintext_lease_absent(pool, response.lease().lease_id()).await?;
    Ok(state)
}

async fn load_counts(pool: &PgPool, organization_id: &str) -> DriverResult<ScenarioCounts> {
    let row = sqlx::query(
        "SELECT \
           (SELECT count(*) FROM apolysis_gateway.runs WHERE organization_id=$1) AS runs, \
           (SELECT count(*) FROM apolysis_gateway.gateway_operations \
             WHERE organization_id=$1) AS operations, \
           (SELECT count(*) FROM apolysis_gateway.operation_replays \
             WHERE organization_id=$1) AS replays, \
           (SELECT count(*) FROM apolysis_gateway.leases WHERE organization_id=$1) AS leases, \
           (SELECT count(*) FROM apolysis_gateway.record_items \
             WHERE organization_id=$1) AS records, \
           (SELECT count(*) FROM apolysis_gateway.projection_outbox \
             WHERE organization_id=$1) AS outbox",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError("scenario count query"))?;
    Ok(ScenarioCounts {
        runs: row
            .try_get("runs")
            .map_err(|_| DriverError("scenario count decoding"))?,
        operations: row
            .try_get("operations")
            .map_err(|_| DriverError("scenario count decoding"))?,
        replays: row
            .try_get("replays")
            .map_err(|_| DriverError("scenario count decoding"))?,
        leases: row
            .try_get("leases")
            .map_err(|_| DriverError("scenario count decoding"))?,
        records: row
            .try_get("records")
            .map_err(|_| DriverError("scenario count decoding"))?,
        outbox: row
            .try_get("outbox")
            .map_err(|_| DriverError("scenario count decoding"))?,
    })
}

async fn verify_counts(
    pool: &PgPool,
    organization_id: &str,
    expected: ScenarioCounts,
) -> DriverResult<()> {
    if load_counts(pool, organization_id).await? != expected {
        return Err(DriverError("scenario count validation"));
    }
    Ok(())
}

async fn verify_database_identity(
    pool: &PgPool,
    organization_id: &str,
    state: &DurableState,
) -> DriverResult<()> {
    let matching: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.leases \
         WHERE organization_id=$1 AND run_id=$2 AND source_stream_id=$3 \
           AND encode(lease_digest, 'hex')=$4",
    )
    .bind(organization_id)
    .bind(state.run_id.as_str())
    .bind(&state.source_stream_id)
    .bind(&state.lease_digest)
    .fetch_one(pool)
    .await
    .map_err(|_| DriverError("database identity query"))?;
    if matching != 1 {
        return Err(DriverError("database identity validation"));
    }
    Ok(())
}

async fn verify_plaintext_lease_absent(pool: &PgPool, lease_id: &str) -> DriverResult<()> {
    let columns = sqlx::query(
        "SELECT relation.relname AS table_name, attribute.attname AS column_name, \
                base_type.typname AS storage_type \
         FROM pg_catalog.pg_attribute AS attribute \
         JOIN pg_catalog.pg_class AS relation ON relation.oid=attribute.attrelid \
         JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace \
         JOIN pg_catalog.pg_type AS declared_type ON declared_type.oid=attribute.atttypid \
         JOIN pg_catalog.pg_type AS base_type \
           ON base_type.oid=CASE WHEN declared_type.typtype='d' \
                                 THEN declared_type.typbasetype ELSE declared_type.oid END \
         WHERE namespace.nspname='apolysis_gateway' \
           AND relation.relkind IN ('r','p') \
           AND attribute.attnum>0 AND NOT attribute.attisdropped \
           AND base_type.typname IN ('text','varchar','bpchar','json','jsonb','bytea') \
         ORDER BY relation.relname, attribute.attnum",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| DriverError("plaintext column enumeration"))?;

    for column in columns {
        let table_name: String = column
            .try_get("table_name")
            .map_err(|_| DriverError("plaintext column decoding"))?;
        let column_name: String = column
            .try_get("column_name")
            .map_err(|_| DriverError("plaintext column decoding"))?;
        let storage_type: String = column
            .try_get("storage_type")
            .map_err(|_| DriverError("plaintext column decoding"))?;
        let table_name = quote_identifier(&table_name);
        let column_name = quote_identifier(&column_name);
        let statement = if storage_type == "bytea" {
            format!(
                "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.{table_name} \
                 WHERE position($1::bytea in {column_name})>0)"
            )
        } else {
            format!(
                "SELECT EXISTS (SELECT 1 FROM apolysis_gateway.{table_name} \
                 WHERE position($1::text in {column_name}::text)>0)"
            )
        };
        let found: bool = if storage_type == "bytea" {
            sqlx::query_scalar(&statement)
                .bind(lease_id.as_bytes())
                .fetch_one(pool)
                .await
                .map_err(|_| DriverError("plaintext byte scan"))?
        } else {
            sqlx::query_scalar(&statement)
                .bind(lease_id)
                .fetch_one(pool)
                .await
                .map_err(|_| DriverError("plaintext text scan"))?
        };
        if found {
            return Err(DriverError("plaintext lease validation"));
        }
    }
    Ok(())
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn write_state(path: &Path, state: &DurableState) -> DriverResult<()> {
    let mut bytes = serde_json::to_vec(state).map_err(|_| DriverError("state serialization"))?;
    bytes.push(b'\n');
    write_private_file(path, &bytes, "state writing")
}

fn write_private_file(path: &Path, contents: &[u8], stage: &'static str) -> DriverResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| DriverError(stage))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| DriverError(stage))?;
    file.write_all(contents).map_err(|_| DriverError(stage))?;
    file.sync_all().map_err(|_| DriverError(stage))?;
    verify_private_output(&file, stage)
}

fn verify_private_output(file: &File, stage: &'static str) -> DriverResult<()> {
    let metadata = file.metadata().map_err(|_| DriverError(stage))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(DriverError(stage));
    }
    Ok(())
}

// SPDX-License-Identifier: Apache-2.0

use std::{
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::support::{
    self, create_request, open_run, source_context, TestDatabase, TestResult, NOW_UNIX_MS,
};
use apolysis_contracts::AuthenticatedSourceContext;
use apolysis_projection_postgres::{
    ComputationVersion, GenerationKey, GenerationState, PostgresRunProjection, ProjectionConfig,
    ProjectionErrorCode,
};
use sqlx::postgres::{PgPoolOptions, PgSslMode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};

const MAX_PROTOCOL_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn an_unknown_commit_outcome_never_retries_into_a_second_batch() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_commit_unknown");
    let repository = database
        .repository()
        .await
        .expect("construct the genuine Gateway repository");
    open_run(
        repository,
        &context,
        create_request(
            "operation_commit_unknown_0000",
            "client_commit_unknown_0000",
            "objective_commit_unknown_0000",
        ),
    )
    .await
    .expect("commit genuine Gateway input spanning more than one projection batch");

    let config = ProjectionConfig::new(1, 4, 5_000, 30_000).expect("bounded retry config");
    let direct_projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the direct projection pool"),
        config.clone(),
    );
    let generation = direct_projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-commit-unknown-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the active generation");

    let direct_options = database.connect_options();
    let proxy = CommitResponseDropProxy::start(
        direct_options.get_host().to_string(),
        direct_options.get_port(),
    )
    .await
    .expect("start the bounded PostgreSQL transport fault proxy");
    let proxy_options = direct_options
        .host("127.0.0.1")
        .port(proxy.port())
        .ssl_mode(PgSslMode::Disable);
    let proxy_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_with(proxy_options)
        .await
        .expect("connect one genuine PostgreSQL pool through the fault proxy");
    let faulted_projection = PostgresRunProjection::from_pool(proxy_pool, config);

    let result = faulted_projection
        .project_next(generation.key(), NOW_UNIX_MS + 2)
        .await;
    let status = direct_projection
        .generation_status(generation.key(), NOW_UNIX_MS + 3)
        .await
        .expect("reconcile the durable checkpoint after the suppressed commit response");

    assert_eq!(
        proxy.suppressed_commit_count(),
        1,
        "the proxy must suppress exactly one response after PostgreSQL completed COMMIT"
    );
    assert!(
        matches!(
            result,
            Err(ref error)
                if error.code() == ProjectionErrorCode::CommitOutcomeUnknown
                    && !error.is_retryable()
                    && error.retry_after_ms().is_none()
        ),
        "the call must require reconciliation instead of returning another batch"
    );
    assert_eq!(
        status.checkpoint().input_watermark(),
        1,
        "one invocation must not blindly retry and advance a second batch"
    );
    assert_eq!(status.checkpoint().last_commit_revision(), Some(1));
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn a_definitive_batch_commit_rejection_rolls_back_without_retry() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let context = source_context("org_projection_batch_commit_rejected");
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            "operation_batch_commit_rejected_0000",
            "client_batch_commit_rejected_0000",
            "objective_batch_commit_rejected_0000",
        ),
    )
    .await
    .expect("commit genuine Gateway input spanning more than one projection batch");

    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the direct projection pool"),
        ProjectionConfig::new(1, 4, 5_000, 30_000).expect("bounded retry config"),
    );
    let generation = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from("run-lifecycle-batch-commit-rejected-v1")
                .expect("computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the active generation");
    sqlx::raw_sql(
        "CREATE SEQUENCE apolysis_projection.test_reject_batch_commit_count_seq; \
         CREATE FUNCTION apolysis_projection.reject_test_batch_commit() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             PERFORM nextval(\
               'apolysis_projection.test_reject_batch_commit_count_seq'::regclass\
             ); \
             RAISE EXCEPTION 'forced test rollback'; \
           END \
         $function$; \
         CREATE CONSTRAINT TRIGGER reject_test_batch_commit \
           AFTER INSERT ON apolysis_projection.commits \
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW \
           EXECUTE FUNCTION apolysis_projection.reject_test_batch_commit();",
    )
    .execute(database.pool())
    .await
    .expect("install a counted real deferred batch commit rejection");

    let error = projection
        .project_next(generation.key(), NOW_UNIX_MS + 2)
        .await
        .expect_err("the deferred trigger must reject batch COMMIT");
    let trigger_count: (i64, bool) = sqlx::query_as(
        "SELECT last_value, is_called \
         FROM apolysis_projection.test_reject_batch_commit_count_seq",
    )
    .fetch_one(database.pool())
    .await
    .expect("load the nontransactional trigger count");
    sqlx::raw_sql(
        "DROP TRIGGER reject_test_batch_commit ON apolysis_projection.commits; \
         DROP FUNCTION apolysis_projection.reject_test_batch_commit(); \
         DROP SEQUENCE apolysis_projection.test_reject_batch_commit_count_seq;",
    )
    .execute(database.pool())
    .await
    .expect("remove the deferred batch commit rejection");

    let checkpoint: (i64, Option<i64>) = sqlx::query_as(
        "SELECT input_watermark, last_commit_revision \
         FROM apolysis_projection.checkpoints \
         WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .fetch_one(database.pool())
    .await
    .expect("load the rolled-back checkpoint");
    let commit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_projection.commits \
         WHERE organization_id=$1 AND generation_id=$2",
    )
    .bind(context.organization_id().as_str())
    .bind(generation.key().generation_id().get())
    .fetch_one(database.pool())
    .await
    .expect("count rolled-back projection commits");
    let outbox: (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE delivery_state='pending'), \
                coalesce(sum(attempt_count),0) \
         FROM apolysis_gateway.projection_outbox WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("load the rolled-back outbox state");

    assert_eq!(error.code(), ProjectionErrorCode::RepositoryInvariant);
    assert!(!error.is_retryable());
    assert_eq!(error.retry_after_ms(), None);
    assert_eq!(trigger_count, (1, true), "the batch must not be retried");
    assert_eq!(checkpoint, (0, None));
    assert_eq!(commit_count, 0);
    assert_eq!(outbox, (3, 0));
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn an_unknown_cutover_commit_outcome_is_reconciled_from_the_durable_head() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let (context, direct_projection, current, rebuilding) = prepare_caught_up_rebuild(
        &database,
        "org_projection_cutover_commit_unknown",
        "unknown",
    )
    .await;

    let direct_options = database.connect_options();
    let proxy = CommitResponseDropProxy::start(
        direct_options.get_host().to_string(),
        direct_options.get_port(),
    )
    .await
    .expect("start the bounded PostgreSQL transport fault proxy");
    let proxy_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_with(
            direct_options
                .host("127.0.0.1")
                .port(proxy.port())
                .ssl_mode(PgSslMode::Disable),
        )
        .await
        .expect("connect one genuine PostgreSQL pool through the fault proxy");
    let faulted_projection =
        PostgresRunProjection::from_pool(proxy_pool, ProjectionConfig::default());

    let result = faulted_projection
        .cut_over(&rebuilding, NOW_UNIX_MS + 20)
        .await;
    let active = direct_projection
        .active_status(context.organization_id(), NOW_UNIX_MS + 21)
        .await
        .expect("reconcile the durable active generation");
    let retired = direct_projection
        .generation_status(&current, NOW_UNIX_MS + 21)
        .await
        .expect("reconcile the previous generation");
    let cutover_revision: i64 = sqlx::query_scalar(
        "SELECT cutover_revision FROM apolysis_projection.organization_heads \
         WHERE organization_id=$1",
    )
    .bind(context.organization_id().as_str())
    .fetch_one(database.pool())
    .await
    .expect("load the durable cutover revision");

    assert_eq!(proxy.suppressed_commit_count(), 1);
    assert!(matches!(
        result,
        Err(ref error)
            if error.code() == ProjectionErrorCode::CommitOutcomeUnknown
                && !error.is_retryable()
    ));
    assert_eq!(active.generation().key(), &rebuilding);
    assert_eq!(active.generation().state(), GenerationState::Active);
    assert_eq!(cutover_revision, 2);
    assert_eq!(retired.generation().state(), GenerationState::Retired);
}

#[tokio::test]
#[ignore = "requires the explicit gate-owned disposable PostgreSQL database"]
async fn a_definitive_cutover_commit_rejection_is_not_reported_as_unknown() {
    let database = TestDatabase::start()
        .await
        .expect("start the isolated real PostgreSQL test");
    let (context, projection, current, rebuilding) = prepare_caught_up_rebuild(
        &database,
        "org_projection_cutover_commit_rejected",
        "rejected",
    )
    .await;
    sqlx::raw_sql(
        "CREATE FUNCTION apolysis_projection.reject_test_cutover_commit() \
           RETURNS trigger LANGUAGE plpgsql AS $function$ \
           BEGIN \
             RAISE EXCEPTION 'forced test rollback'; \
           END \
         $function$; \
         CREATE CONSTRAINT TRIGGER reject_test_cutover_commit \
           AFTER UPDATE ON apolysis_projection.organization_heads \
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW \
           EXECUTE FUNCTION apolysis_projection.reject_test_cutover_commit();",
    )
    .execute(database.pool())
    .await
    .expect("install a real deferred commit rejection");

    let error = projection
        .cut_over(&rebuilding, NOW_UNIX_MS + 20)
        .await
        .expect_err("the deferred trigger must reject COMMIT");
    let active = projection
        .active_status(context.organization_id(), NOW_UNIX_MS + 21)
        .await
        .expect("load the unchanged durable head");
    sqlx::raw_sql(
        "DROP TRIGGER reject_test_cutover_commit \
           ON apolysis_projection.organization_heads; \
         DROP FUNCTION apolysis_projection.reject_test_cutover_commit();",
    )
    .execute(database.pool())
    .await
    .expect("remove the deferred commit rejection");

    assert_eq!(error.code(), ProjectionErrorCode::RepositoryInvariant);
    assert!(!error.is_retryable());
    assert_eq!(active.generation().key(), &current);
    assert_eq!(active.generation().state(), GenerationState::Active);
}

async fn prepare_caught_up_rebuild(
    database: &TestDatabase,
    organization_id: &str,
    suffix: &str,
) -> (
    AuthenticatedSourceContext,
    PostgresRunProjection,
    GenerationKey,
    GenerationKey,
) {
    let context = source_context(organization_id);
    open_run(
        database
            .repository()
            .await
            .expect("construct the genuine Gateway repository"),
        &context,
        create_request(
            &format!("operation_cutover_commit_{suffix}"),
            &format!("client_cutover_commit_{suffix}"),
            &format!("objective_cutover_commit_{suffix}"),
        ),
    )
    .await
    .expect("commit genuine Gateway input for cutover");
    let projection = PostgresRunProjection::from_pool(
        database
            .independent_pool()
            .await
            .expect("construct the direct projection pool"),
        ProjectionConfig::default(),
    );
    let current = projection
        .initialize_current(
            context.organization_id(),
            ComputationVersion::try_from(format!("run-lifecycle-cutover-{suffix}-v1"))
                .expect("current computation version"),
            NOW_UNIX_MS + 1,
        )
        .await
        .expect("initialize the active generation");
    support::project_until_caught_up(&projection, current.key(), NOW_UNIX_MS + 2)
        .await
        .expect("catch up the active generation");
    let rebuilding = projection
        .start_rebuild(
            context.organization_id(),
            ComputationVersion::try_from(format!("run-lifecycle-cutover-{suffix}-v2"))
                .expect("rebuild computation version"),
            NOW_UNIX_MS + 10,
        )
        .await
        .expect("start the rebuild generation");
    support::project_until_caught_up(&projection, rebuilding.key(), NOW_UNIX_MS + 11)
        .await
        .expect("catch up the rebuild generation");
    (
        context,
        projection,
        current.key().clone(),
        rebuilding.key().clone(),
    )
}

struct CommitResponseDropProxy {
    port: u16,
    suppressed_commit_count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl CommitResponseDropProxy {
    async fn start(target_host: String, target_port: u16) -> TestResult<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let suppressed_commit_count = Arc::new(AtomicUsize::new(0));
        let counter = suppressed_commit_count.clone();
        let task = tokio::spawn(async move {
            let mut fault_first_connection = true;
            while let Ok((client, _)) = listener.accept().await {
                let target_host = target_host.clone();
                let counter = counter.clone();
                let fault_this_connection = fault_first_connection;
                fault_first_connection = false;
                tokio::spawn(async move {
                    let Ok(server) = TcpStream::connect((target_host.as_str(), target_port)).await
                    else {
                        return;
                    };
                    if fault_this_connection {
                        let _ = suppress_first_commit_response(client, server, counter).await;
                    } else {
                        let mut client = client;
                        let mut server = server;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        Ok(Self {
            port,
            suppressed_commit_count,
            task,
        })
    }

    const fn port(&self) -> u16 {
        self.port
    }

    fn suppressed_commit_count(&self) -> usize {
        self.suppressed_commit_count.load(Ordering::SeqCst)
    }
}

impl Drop for CommitResponseDropProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn suppress_first_commit_response(
    mut client: TcpStream,
    mut server: TcpStream,
    suppressed_commit_count: Arc<AtomicUsize>,
) -> io::Result<()> {
    forward_startup_message(&mut client, &mut server).await?;
    let (mut client_read, mut client_write) = client.split();
    let (mut server_read, mut server_write) = server.split();
    let (commit_forwarded_tx, commit_forwarded_rx) = watch::channel(false);
    let (commit_completed_tx, mut commit_completed_rx) = watch::channel(false);

    let client_to_server = async {
        loop {
            let (kind, payload) = read_typed_frame(&mut client_read).await?;
            let is_commit = kind == b'Q' && payload.as_slice() == b"COMMIT\0";
            if is_commit {
                commit_forwarded_tx
                    .send(true)
                    .map_err(|_| io::Error::other("commit-forward signal closed"))?;
            }
            write_typed_frame(&mut server_write, kind, &payload).await?;
            if is_commit {
                while !*commit_completed_rx.borrow() {
                    commit_completed_rx
                        .changed()
                        .await
                        .map_err(|_| io::Error::other("commit-complete signal closed"))?;
                }
                return Ok::<(), io::Error>(());
            }
        }
    };

    let server_to_client = async {
        loop {
            let (kind, payload) = read_typed_frame(&mut server_read).await?;
            if *commit_forwarded_rx.borrow() {
                if kind == b'Z' {
                    suppressed_commit_count.fetch_add(1, Ordering::SeqCst);
                    commit_completed_tx
                        .send(true)
                        .map_err(|_| io::Error::other("commit-complete receiver closed"))?;
                    return Ok::<(), io::Error>(());
                }
            } else {
                write_typed_frame(&mut client_write, kind, &payload).await?;
            }
        }
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

async fn forward_startup_message(client: &mut TcpStream, server: &mut TcpStream) -> io::Result<()> {
    let length = client.read_u32().await?;
    let payload_length = checked_payload_length(length, 4)?;
    let mut payload = vec![0_u8; payload_length];
    client.read_exact(&mut payload).await?;
    server.write_u32(length).await?;
    server.write_all(&payload).await
}

async fn read_typed_frame<R>(reader: &mut R) -> io::Result<(u8, Vec<u8>)>
where
    R: AsyncReadExt + Unpin,
{
    let kind = reader.read_u8().await?;
    let length = reader.read_u32().await?;
    let payload_length = checked_payload_length(length, 4)?;
    let mut payload = vec![0_u8; payload_length];
    reader.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

async fn write_typed_frame<W>(writer: &mut W, kind: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let length = u32::try_from(payload.len())
        .ok()
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "protocol frame overflow"))?;
    writer.write_u8(kind).await?;
    writer.write_u32(length).await?;
    writer.write_all(payload).await
}

fn checked_payload_length(length: u32, header_bytes: u32) -> io::Result<usize> {
    let payload_length = length
        .checked_sub(header_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid protocol frame"))?;
    if payload_length > MAX_PROTOCOL_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol frame exceeds test bound",
        ));
    }
    Ok(payload_length)
}

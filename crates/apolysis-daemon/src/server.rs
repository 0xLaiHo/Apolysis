// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use apolysis_accountability::{
    decode_intent_frame, AdapterKind, ComponentState, HealthSnapshot, IntentError, IntentRequest,
    RetentionTier, SessionState, MAX_INTENT_FRAME_BYTES,
};
use apolysis_observer::{DaemonObserver, DaemonObserverConfig};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;

use crate::{
    render_prometheus_metrics, run_observer_runtime, run_runtime_adapter, scope_channel,
    ContainerdCriRuntimeAdapter, CriRuntimeClient, DaemonConfig, DaemonState, DockerEngineClient,
    DockerEnginePollingRuntimeAdapter, KubernetesCliClient, KubernetesCliRuntimeAdapter,
    RuntimeAdapterSummary,
};

pub const DAEMON_SCHEMA_V1: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    Ack {
        schema_version: u32,
        operation: String,
        session_id: Option<String>,
    },
    Health {
        schema_version: u32,
        liveness: bool,
        readiness: bool,
        health: HealthSnapshot,
    },
    Session {
        schema_version: u32,
        session: Option<SessionState>,
    },
    SessionList {
        schema_version: u32,
        tenant_id: String,
        retention_tier: Option<RetentionTier>,
        sessions: Vec<SessionState>,
    },
    Error {
        schema_version: u32,
        code: String,
        message: String,
    },
}

pub async fn serve(
    config: DaemonConfig,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), String> {
    prepare_socket(&config)?;
    let listener = UnixListener::bind(&config.socket_path)
        .map_err(|error| format!("failed to bind daemon socket: {error}"))?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o660))
        .map_err(|error| format!("failed to set daemon socket permissions: {error}"))?;
    let observer_setup = config.bpf_object.as_ref().and_then(|object_path| {
        match DaemonObserver::load(DaemonObserverConfig::new(object_path)) {
            Ok(observer) => {
                let (scope, receiver) = scope_channel(config.scope_command_capacity);
                Some((observer, scope, receiver))
            }
            Err(error) => {
                eprintln!("apolysisd: observer unavailable: {error}");
                None
            }
        }
    });
    let scope = observer_setup.as_ref().map(|(_, scope, _)| scope.clone());
    let state = match DaemonState::new_with_scope(&config, scope) {
        Ok(state) => Arc::new(state),
        Err(error) => {
            drop(listener);
            remove_socket_if_socket(&config.socket_path)?;
            return Err(error);
        }
    };
    let (metrics_shutdown, mut metrics_task) =
        match start_metrics_listener(config.metrics_listen, Arc::clone(&state)).await {
            Ok(metrics) => metrics,
            Err(error) => {
                drop(listener);
                remove_socket_if_socket(&config.socket_path)?;
                return Err(error);
            }
        };
    let (writer_shutdown, writer_shutdown_receiver) = oneshot::channel();
    let mut writer_task = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_shutdown_receiver).await })
    };
    let (runtime_adapter_shutdowns, runtime_adapter_tasks) =
        start_runtime_adapters(&config, Arc::clone(&state));
    let (observer_shutdown, mut observer_task) =
        if let Some((observer, _, receiver)) = observer_setup {
            let (sender, shutdown_receiver) = oneshot::channel();
            let initial_cgroups = state.tracked_cgroups().await;
            let state = Arc::clone(&state);
            let task = tokio::spawn(async move {
                run_observer_runtime(
                    observer,
                    initial_cgroups,
                    receiver,
                    state,
                    shutdown_receiver,
                )
                .await
            });
            (Some(sender), Some(task))
        } else {
            (None, None)
        };
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut handlers = JoinSet::new();
    let mut accept_error = None;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            result = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(result) = result {
                    log_connection_result(result);
                }
            }
            accepted = listener.accept() => {
                let (mut stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        accept_error = Some(format!("failed to accept daemon connection: {error}"));
                        break;
                    }
                };
                match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => {
                        let state = Arc::clone(&state);
                        let request_timeout = config.request_timeout;
                        handlers.spawn(async move {
                            let _permit = permit;
                            match tokio::time::timeout(
                                request_timeout,
                                handle_connection(stream, state),
                            )
                            .await
                            {
                                Ok(result) => result,
                                Err(_) => Ok(()),
                            }
                        });
                    }
                    Err(_) => {
                        let _ = tokio::time::timeout(
                            config.request_timeout,
                            write_response(
                                &mut stream,
                                &error_response(
                                    "server_busy",
                                    "daemon connection limit reached",
                                ),
                            ),
                        )
                        .await;
                    }
                }
            }
        }
    }

    drop(listener);
    while let Some(result) = handlers.join_next().await {
        log_connection_result(result);
    }

    if let Some(observer_shutdown) = observer_shutdown {
        let _ = observer_shutdown.send(());
    }
    if let Some(metrics_shutdown) = metrics_shutdown {
        let _ = metrics_shutdown.send(());
    }
    if let Some(task) = metrics_task.as_mut() {
        match tokio::time::timeout(config.shutdown_drain_timeout, &mut *task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                eprintln!("apolysisd: metrics listener stopped with error: {error}");
            }
            Ok(Err(error)) => {
                eprintln!("apolysisd: metrics listener task failed: {error}");
            }
            Err(_) => {
                task.abort();
                eprintln!("apolysisd: metrics listener shutdown deadline exceeded");
            }
        }
    }
    if let Some(task) = observer_task.as_mut() {
        match tokio::time::timeout(config.shutdown_drain_timeout, &mut *task).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(error))) => {
                eprintln!("apolysisd: observer stopped with error: {error}");
            }
            Ok(Err(error)) => {
                eprintln!("apolysisd: observer task failed: {error}");
            }
            Err(_) => {
                task.abort();
                eprintln!("apolysisd: observer shutdown deadline exceeded");
            }
        }
    }
    for shutdown in runtime_adapter_shutdowns {
        let _ = shutdown.send(());
    }
    for mut task in runtime_adapter_tasks {
        match tokio::time::timeout(config.shutdown_drain_timeout, &mut task).await {
            Ok(Ok(_summary)) => {}
            Ok(Err(error)) => {
                eprintln!("apolysisd: runtime adapter task failed: {error}");
            }
            Err(_) => {
                task.abort();
                eprintln!("apolysisd: runtime adapter shutdown deadline exceeded");
            }
        }
    }

    let _ = writer_shutdown.send(());
    match tokio::time::timeout(config.shutdown_drain_timeout, &mut writer_task).await {
        Ok(Ok(Ok(_))) => {}
        Ok(Ok(Err(error))) => {
            remove_socket_if_socket(&config.socket_path)?;
            return Err(format!("daemon writer stopped with error: {error}"));
        }
        Ok(Err(error)) => {
            remove_socket_if_socket(&config.socket_path)?;
            return Err(format!("daemon writer task failed: {error}"));
        }
        Err(_) => {
            writer_task.abort();
            remove_socket_if_socket(&config.socket_path)?;
            return Err("daemon writer shutdown deadline exceeded".to_string());
        }
    }
    remove_socket_if_socket(&config.socket_path)?;
    match accept_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn start_metrics_listener(
    metrics_listen: Option<SocketAddr>,
    state: Arc<DaemonState>,
) -> Result<
    (
        Option<oneshot::Sender<()>>,
        Option<tokio::task::JoinHandle<Result<(), String>>>,
    ),
    String,
> {
    let Some(addr) = metrics_listen else {
        return Ok((None, None));
    };
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| format!("failed to bind metrics listener {addr}: {error}"))?;
    let (shutdown, receiver) = oneshot::channel();
    let task = tokio::spawn(run_metrics_listener(listener, state, receiver));
    Ok((Some(shutdown), Some(task)))
}

async fn run_metrics_listener(
    listener: TcpListener,
    state: Arc<DaemonState>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), String> {
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| format!("failed to accept metrics connection: {error}"))?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(error) = handle_metrics_connection(stream, state).await {
                        eprintln!("apolysisd: metrics request failed: {error}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_metrics_connection(
    mut stream: TcpStream,
    state: Arc<DaemonState>,
) -> Result<(), String> {
    let request = read_http_request(&mut stream).await?;
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    if path != "/metrics" {
        return write_http_response(
            &mut stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n",
        )
        .await;
    }

    let health = state.health().await;
    let metrics = render_prometheus_metrics(&health);
    write_http_response(
        &mut stream,
        "200 OK",
        "text/plain; version=0.0.4; charset=utf-8",
        &metrics,
    )
    .await
}

async fn read_http_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| format!("failed to read metrics HTTP request: {error}"))?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
        if request.len() > 8 * 1024 {
            return Err("metrics HTTP request exceeded 8 KiB".to_string());
        }
    }
    String::from_utf8(request)
        .map_err(|error| format!("metrics HTTP request was not UTF-8: {error}"))
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| format!("failed to write metrics HTTP response: {error}"))
}

fn start_runtime_adapters(
    config: &DaemonConfig,
    state: Arc<DaemonState>,
) -> (
    Vec<oneshot::Sender<()>>,
    Vec<tokio::task::JoinHandle<RuntimeAdapterSummary>>,
) {
    let mut shutdowns = Vec::new();
    let mut tasks = Vec::new();

    if let Some(socket_path) = config.docker_socket.clone() {
        let (shutdown, receiver) = oneshot::channel();
        shutdowns.push(shutdown);
        let proc_root = config.proc_root.clone();
        let cgroup_root = config.cgroup_root.clone();
        let scan_interval = config.runtime_adapter_scan_interval;
        let seen_capacity = config.runtime_adapter_seen_capacity;
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let client = DockerEngineClient::new(socket_path);
            let adapter = DockerEnginePollingRuntimeAdapter::new(
                client,
                proc_root,
                cgroup_root,
                scan_interval,
                seen_capacity,
            );
            run_runtime_adapter(adapter, state, receiver).await
        }));
    }

    if let Some(socket_path) = config.containerd_socket.clone() {
        let (shutdown, receiver) = oneshot::channel();
        shutdowns.push(shutdown);
        let proc_root = config.proc_root.clone();
        let cgroup_root = config.cgroup_root.clone();
        let scan_interval = config.runtime_adapter_scan_interval;
        let seen_capacity = config.runtime_adapter_seen_capacity;
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let client = CriRuntimeClient::new(socket_path);
            match ContainerdCriRuntimeAdapter::new(
                AdapterKind::Containerd,
                client,
                proc_root,
                cgroup_root,
                scan_interval,
                seen_capacity,
            ) {
                Ok(adapter) => run_runtime_adapter(adapter, state, receiver).await,
                Err(error) => degraded_summary(state, AdapterKind::Containerd, error).await,
            }
        }));
    }

    if let Some(socket_path) = config.k3s_containerd_socket.clone() {
        let (shutdown, receiver) = oneshot::channel();
        shutdowns.push(shutdown);
        let proc_root = config.proc_root.clone();
        let cgroup_root = config.cgroup_root.clone();
        let scan_interval = config.runtime_adapter_scan_interval;
        let seen_capacity = config.runtime_adapter_seen_capacity;
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let client = CriRuntimeClient::new(socket_path).with_image_endpoint(None);
            match ContainerdCriRuntimeAdapter::new(
                AdapterKind::K3sContainerd,
                client,
                proc_root,
                cgroup_root,
                scan_interval,
                seen_capacity,
            ) {
                Ok(adapter) => run_runtime_adapter(adapter, state, receiver).await,
                Err(error) => degraded_summary(state, AdapterKind::K3sContainerd, error).await,
            }
        }));
    }

    if let Some(kubectl_path) = config.kubernetes_kubectl.clone() {
        let (shutdown, receiver) = oneshot::channel();
        shutdowns.push(shutdown);
        let proc_root = config.proc_root.clone();
        let cgroup_root = config.cgroup_root.clone();
        let scan_interval = config.runtime_adapter_scan_interval;
        let seen_capacity = config.runtime_adapter_seen_capacity;
        let cri_socket = config
            .kubernetes_cri_socket
            .clone()
            .or_else(|| config.k3s_containerd_socket.clone())
            .unwrap_or_else(|| "/run/k3s/containerd/containerd.sock".into());
        let state = Arc::clone(&state);
        tasks.push(tokio::spawn(async move {
            let kubernetes = KubernetesCliClient::new(kubectl_path);
            let cri = CriRuntimeClient::new(cri_socket).with_image_endpoint(None);
            let adapter = KubernetesCliRuntimeAdapter::new(
                kubernetes,
                cri,
                proc_root,
                cgroup_root,
                scan_interval,
                seen_capacity,
            );
            run_runtime_adapter(adapter, state, receiver).await
        }));
    }

    (shutdowns, tasks)
}

async fn degraded_summary(
    state: Arc<DaemonState>,
    adapter: AdapterKind,
    error: String,
) -> RuntimeAdapterSummary {
    eprintln!("apolysisd: runtime adapter unavailable: {error}");
    state.set_adapter(adapter, ComponentState::Degraded).await;
    RuntimeAdapterSummary {
        adapter,
        discovered: 0,
        missing_intent: 0,
        backend_errors: 1,
        backend_recoveries: 0,
        ingest_errors: 0,
    }
}

async fn handle_connection(mut stream: UnixStream, state: Arc<DaemonState>) -> Result<(), String> {
    let length = stream
        .read_u32()
        .await
        .map_err(|error| format!("failed to read request length: {error}"))?
        as usize;
    if length > MAX_INTENT_FRAME_BYTES {
        return write_response(
            &mut stream,
            &error_response(
                "frame_too_large",
                format!("request frame is too large: {length}"),
            ),
        )
        .await;
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|error| format!("failed to read request body: {error}"))?;
    let now_unix_ms = current_unix_ms()?;
    let response = match decode_intent_frame(&frame, now_unix_ms) {
        Ok(request) => dispatch(request, &state, now_unix_ms).await,
        Err(error) => error_response(intent_error_code(&error), error.to_string()),
    };
    write_response(&mut stream, &response).await
}

async fn dispatch(request: IntentRequest, state: &DaemonState, now_unix_ms: u64) -> DaemonResponse {
    match request {
        IntentRequest::Register { intent } => {
            let session_id = intent.session_id.clone();
            match state.register(intent, now_unix_ms).await {
                Ok(_) => ack("register", Some(session_id)),
                Err(error) => error_response("state_error", error),
            }
        }
        IntentRequest::Renew {
            session_id,
            expires_at_unix_ms,
        } => match state
            .renew(&session_id, expires_at_unix_ms, now_unix_ms)
            .await
        {
            Ok(()) => ack("renew", Some(session_id)),
            Err(error) => error_response("state_error", error),
        },
        IntentRequest::Close { session_id } => match state.close(&session_id).await {
            Ok(()) => ack("close", Some(session_id)),
            Err(error) => error_response("state_error", error),
        },
        IntentRequest::Query {
            tenant_id,
            session_id,
        } => DaemonResponse::Session {
            schema_version: DAEMON_SCHEMA_V1,
            session: state.query_for_tenant(&session_id, &tenant_id).await,
        },
        IntentRequest::ListSessions {
            tenant_id,
            retention_tier,
        } => DaemonResponse::SessionList {
            schema_version: DAEMON_SCHEMA_V1,
            sessions: state.list_for_tenant(&tenant_id, retention_tier).await,
            tenant_id,
            retention_tier,
        },
        IntentRequest::Health => {
            let health = state.health().await;
            DaemonResponse::Health {
                schema_version: DAEMON_SCHEMA_V1,
                liveness: health.liveness(),
                readiness: health.readiness(),
                health,
            }
        }
    }
}

async fn write_response(stream: &mut UnixStream, response: &DaemonResponse) -> Result<(), String> {
    let bytes = serde_json::to_vec(response)
        .map_err(|error| format!("failed to serialize daemon response: {error}"))?;
    let length =
        u32::try_from(bytes.len()).map_err(|_| "daemon response is too large".to_string())?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| format!("failed to write response length: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("failed to write response body: {error}"))
}

fn ack(operation: &str, session_id: Option<String>) -> DaemonResponse {
    DaemonResponse::Ack {
        schema_version: DAEMON_SCHEMA_V1,
        operation: operation.to_string(),
        session_id,
    }
}

fn error_response(code: &str, message: impl Into<String>) -> DaemonResponse {
    DaemonResponse::Error {
        schema_version: DAEMON_SCHEMA_V1,
        code: code.to_string(),
        message: message.into(),
    }
}

fn log_connection_result(result: Result<Result<(), String>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("apolysisd: connection failed: {error}"),
        Err(error) => eprintln!("apolysisd: connection task failed: {error}"),
    }
}

fn intent_error_code(error: &IntentError) -> &'static str {
    match error {
        IntentError::FrameTooLarge(_) => "frame_too_large",
        _ => "invalid_request",
    }
}

fn prepare_socket(config: &DaemonConfig) -> Result<(), String> {
    let parent = config
        .socket_path
        .parent()
        .ok_or_else(|| "daemon socket path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create daemon socket directory: {error}"))?;
    remove_socket_if_socket(&config.socket_path)
}

fn remove_socket_if_socket(path: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)
            .map_err(|error| format!("failed to remove stale daemon socket: {error}")),
        Ok(_) => Err(format!(
            "refusing to replace daemon path that is not a Unix socket: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("failed to inspect daemon socket path: {error}")),
    }
}

fn current_unix_ms() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "current Unix timestamp exceeds u64".to_string())
}

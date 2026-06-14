// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use apolysis_accountability::{
    decode_intent_frame, HealthSnapshot, IntentError, IntentRequest, SessionState,
    MAX_INTENT_FRAME_BYTES,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;

use crate::{DaemonConfig, DaemonState};

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
    let state = Arc::new(DaemonState::new(&config)?);
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut handlers = JoinSet::new();

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (mut stream, _) =
                    accepted.map_err(|error| format!("failed to accept daemon connection: {error}"))?;
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
                        handlers.spawn(async move {
                            write_response(
                                &mut stream,
                                &error_response(
                                    "server_busy",
                                    "daemon connection limit reached",
                                ),
                            )
                            .await
                        });
                    }
                }
            }
        }
    }

    drop(listener);
    while let Some(result) = handlers.join_next().await {
        result
            .map_err(|error| format!("daemon connection task failed: {error}"))??;
    }
    remove_socket_if_socket(&config.socket_path)?;
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    state: Arc<DaemonState>,
) -> Result<(), String> {
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

async fn dispatch(
    request: IntentRequest,
    state: &DaemonState,
    now_unix_ms: u64,
) -> DaemonResponse {
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
        IntentRequest::Query { session_id } => DaemonResponse::Session {
            schema_version: DAEMON_SCHEMA_V1,
            session: state.query(&session_id).await,
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

async fn write_response(
    stream: &mut UnixStream,
    response: &DaemonResponse,
) -> Result<(), String> {
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

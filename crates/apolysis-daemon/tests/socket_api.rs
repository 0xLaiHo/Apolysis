// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use apolysis_daemon::{serve, DaemonConfig, DaemonResponse, DAEMON_SCHEMA_V1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn health_request_reports_liveness_and_secure_socket_mode() {
    let server = TestServer::start("health").await;
    let response = request(&server.config.socket_path, br#"{"type":"health"}"#).await;

    let DaemonResponse::Health {
        schema_version,
        liveness,
        readiness,
        ..
    } = response
    else {
        panic!("expected health response");
    };
    assert_eq!(schema_version, DAEMON_SCHEMA_V1);
    assert!(liveness);
    assert!(!readiness, "eBPF is not loaded by the foundation server");
    let mode = std::fs::metadata(&server.config.socket_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o660);

    server.stop().await;
}

#[tokio::test]
async fn register_renew_query_and_close_update_session_state() {
    let server = TestServer::start("lifecycle").await;
    let register = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-f2",
            "expires_at_unix_ms":4102444800000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "policy_ref":"policy.yaml",
            "workload_selectors":[]
        }
    }"#;
    assert!(matches!(
        request(&server.config.socket_path, register).await,
        DaemonResponse::Ack {
            operation,
            session_id: Some(session_id),
            ..
        } if operation == "register" && session_id == "session-f2"
    ));

    let renew = br#"{"type":"renew","session_id":"session-f2","expires_at_unix_ms":4102444801000}"#;
    assert!(matches!(
        request(&server.config.socket_path, renew).await,
        DaemonResponse::Ack { operation, .. } if operation == "renew"
    ));

    let query = br#"{"type":"query","session_id":"session-f2"}"#;
    let DaemonResponse::Session {
        session: Some(session),
        ..
    } = request(&server.config.socket_path, query).await
    else {
        panic!("expected session response");
    };
    assert_eq!(session.expires_at_unix_ms, 4_102_444_801_000);

    let close = br#"{"type":"close","session_id":"session-f2"}"#;
    assert!(matches!(
        request(&server.config.socket_path, close).await,
        DaemonResponse::Ack { operation, .. } if operation == "close"
    ));

    server.stop().await;
}

#[tokio::test]
async fn malformed_and_oversized_frames_return_errors_without_stopping_server() {
    let server = TestServer::start("invalid").await;
    assert!(matches!(
        request(&server.config.socket_path, b"{not-json").await,
        DaemonResponse::Error { code, .. } if code == "invalid_request"
    ));

    let oversized = request_with_declared_length(
        &server.config.socket_path,
        (apolysis_accountability::MAX_INTENT_FRAME_BYTES + 1) as u32,
    )
    .await;
    assert!(matches!(
        oversized,
        DaemonResponse::Error { code, .. } if code == "frame_too_large"
    ));

    assert!(matches!(
        request(&server.config.socket_path, br#"{"type":"health"}"#).await,
        DaemonResponse::Health { liveness: true, .. }
    ));
    server.stop().await;
}

#[tokio::test]
async fn serves_multiple_clients_with_a_fixed_connection_limit() {
    let server = TestServer::start_with_connections("concurrent", 8).await;
    let mut requests = Vec::new();
    for _ in 0..8 {
        let socket = server.config.socket_path.clone();
        requests.push(tokio::spawn(async move {
            request(&socket, br#"{"type":"health"}"#).await
        }));
    }
    for request in requests {
        assert!(matches!(
            request.await.unwrap(),
            DaemonResponse::Health { liveness: true, .. }
        ));
    }
    server.stop().await;
}

#[tokio::test]
async fn slow_client_cannot_block_connection_rejection_or_shutdown() {
    let server = TestServer::start_with_connections("slow-client", 1).await;
    let _slow = UnixStream::connect(&server.config.socket_path)
        .await
        .expect("slow client");
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert!(matches!(
        request(&server.config.socket_path, br#"{"type":"health"}"#).await,
        DaemonResponse::Error { code, .. } if code == "server_busy"
    ));
    tokio::time::timeout(Duration::from_secs(1), server.stop())
        .await
        .expect("shutdown must not wait indefinitely");
}

#[tokio::test]
async fn refuses_to_replace_a_non_socket_path() {
    let config = config("regular-file", 2);
    std::fs::create_dir_all(config.socket_path.parent().unwrap()).unwrap();
    std::fs::write(&config.socket_path, "do not remove").unwrap();
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();

    let error = serve(config.clone(), shutdown_rx)
        .await
        .expect_err("regular file must be preserved");
    assert!(error.contains("not a Unix socket"));
    assert_eq!(
        std::fs::read_to_string(&config.socket_path).unwrap(),
        "do not remove"
    );
    cleanup(&config);
}

#[tokio::test]
async fn clean_shutdown_removes_the_socket_file() {
    let server = TestServer::start("shutdown").await;
    let socket = server.config.socket_path.clone();
    server.stop().await;
    assert!(!socket.exists());
}

#[tokio::test]
async fn restart_restores_active_session_and_continues_hash_chain() {
    let server = TestServer::start("restart").await;
    let config = server.config.clone();
    let register = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-restart",
            "expires_at_unix_ms":4102444800000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "policy_ref":"policy.yaml",
            "workload_selectors":[]
        }
    }"#;
    assert!(matches!(
        request(&config.socket_path, register).await,
        DaemonResponse::Ack { .. }
    ));
    server.stop_preserving().await;

    let restarted = TestServer::start_config(config.clone()).await;
    let query = br#"{"type":"query","session_id":"session-restart"}"#;
    assert!(matches!(
        request(&config.socket_path, query).await,
        DaemonResponse::Session {
            session: Some(_),
            ..
        }
    ));
    let renew =
        br#"{"type":"renew","session_id":"session-restart","expires_at_unix_ms":4102444801000}"#;
    assert!(matches!(
        request(&config.socket_path, renew).await,
        DaemonResponse::Ack { .. }
    ));
    restarted.stop_preserving().await;

    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/session-restart/timeline.jsonl"),
    )
    .expect("session timeline");
    assert_eq!(timeline.lines().count(), 2);
    assert!(timeline.lines().nth(1).unwrap().contains(r#""sequence":2"#));
    cleanup(&config);
}

#[tokio::test]
async fn failed_persistence_does_not_publish_session_state() {
    let config = config("storage-failure", 16);
    let blocked_timeline = config
        .state_dir
        .join("sessions/session-storage-failure/timeline.jsonl");
    std::fs::create_dir_all(&blocked_timeline).unwrap();
    let server = TestServer::start_config(config.clone()).await;
    let register = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-storage-failure",
            "expires_at_unix_ms":4102444800000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "policy_ref":"policy.yaml",
            "workload_selectors":[]
        }
    }"#;

    assert!(matches!(
        request(&config.socket_path, register).await,
        DaemonResponse::Error { code, .. } if code == "state_error"
    ));
    assert!(matches!(
        request(
            &config.socket_path,
            br#"{"type":"query","session_id":"session-storage-failure"}"#,
        )
        .await,
        DaemonResponse::Session { session: None, .. }
    ));
    let DaemonResponse::Health { health, .. } =
        request(&config.socket_path, br#"{"type":"health"}"#).await
    else {
        panic!("expected health response");
    };
    assert_eq!(
        health.storage(),
        apolysis_accountability::ComponentState::Unavailable
    );

    server.stop().await;
}

struct TestServer {
    config: DaemonConfig,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl TestServer {
    async fn start(name: &str) -> Self {
        Self::start_with_connections(name, 16).await
    }

    async fn start_with_connections(name: &str, max_connections: usize) -> Self {
        let config = config(name, max_connections);
        Self::start_config(config).await
    }

    async fn start_config(config: DaemonConfig) -> Self {
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(serve(config.clone(), receiver));
        for _ in 0..100 {
            if config.socket_path.exists() {
                return Self {
                    config,
                    shutdown,
                    task,
                };
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("daemon socket was not created");
    }

    async fn stop(self) {
        let config = self.config.clone();
        self.stop_preserving().await;
        cleanup(&config);
    }

    async fn stop_preserving(self) {
        let _ = self.shutdown.send(());
        self.task.await.unwrap().expect("clean server shutdown");
    }
}

async fn request(path: &std::path::Path, payload: &[u8]) -> DaemonResponse {
    let mut stream = UnixStream::connect(path).await.expect("connect daemon");
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(payload).await.unwrap();
    read_response(&mut stream).await
}

async fn request_with_declared_length(path: &std::path::Path, length: u32) -> DaemonResponse {
    let mut stream = UnixStream::connect(path).await.expect("connect daemon");
    stream.write_all(&length.to_be_bytes()).await.unwrap();
    read_response(&mut stream).await
}

async fn read_response(stream: &mut UnixStream) -> DaemonResponse {
    let length = stream.read_u32().await.expect("response length") as usize;
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .await
        .expect("response body");
    serde_json::from_slice(&response).expect("valid response")
}

fn config(name: &str, max_connections: usize) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("apolysisd-test-{name}-{}-{id}", std::process::id()));
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        max_sessions: 32,
        max_pending: 32,
        max_connections,
        request_timeout: Duration::from_millis(100),
    }
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_daemon::{serve, DaemonConfig, DaemonResponse, DAEMON_SCHEMA_V1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
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
        health,
    } = response
    else {
        panic!("expected health response");
    };
    assert_eq!(schema_version, DAEMON_SCHEMA_V1);
    assert!(liveness);
    assert!(!readiness, "eBPF is not loaded by the foundation server");
    assert_eq!(health.queue.capacity, server.config.queue_capacity);
    assert_eq!(
        health.ebpf(),
        apolysis_accountability::ComponentState::Unavailable
    );
    let mode = std::fs::metadata(&server.config.socket_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o660);

    server.stop().await;
}

#[tokio::test]
async fn metrics_endpoint_exports_prometheus_health_snapshot() {
    let mut config = config("metrics", 16);
    config.metrics_listen = Some(unused_loopback_addr());
    let metrics_addr = config.metrics_listen.unwrap();
    let server = TestServer::start_config(config).await;

    let response = http_get(metrics_addr, "/metrics").await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("Content-Type: text/plain; version=0.0.4"));
    assert!(response.contains("apolysis_component_state{component=\"ebpf\"} 0"));
    assert!(response.contains("apolysis_component_state{component=\"storage\"} 1"));
    assert!(response.contains("apolysis_queue_capacity 16384"));
    assert!(!response.contains("session_id"));
    assert!(!response.contains("workload_id"));

    let not_found = http_get(metrics_addr, "/not-found").await;
    assert!(
        not_found.starts_with("HTTP/1.1 404 Not Found"),
        "{not_found}"
    );

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
async fn client_disconnect_does_not_prevent_clean_shutdown() {
    let server = TestServer::start("disconnect").await;
    let stream = UnixStream::connect(&server.config.socket_path)
        .await
        .expect("connect client");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(10)).await;

    server.stop().await;
}

#[tokio::test]
async fn startup_docker_adapter_ingests_marked_running_container() {
    let mut config = config("docker-adapter-startup", 16);
    let root = config
        .socket_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let docker_socket = root.join("run/docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let cgroup = cgroup_root.join("system.slice/docker-container-abc.scope");
    std::fs::create_dir_all(&cgroup).expect("create fake cgroup");
    std::fs::create_dir_all(proc_root.join("1234")).expect("create fake proc pid");
    std::fs::write(
        proc_root.join("1234/cgroup"),
        "0::/system.slice/docker-container-abc.scope\n",
    )
    .expect("write fake proc cgroup");
    config.docker_socket = Some(docker_socket.clone());
    config.proc_root = proc_root;
    config.cgroup_root = cgroup_root;

    let docker = fake_docker_engine(
        &docker_socket,
        vec![
            (
                "GET /containers/json HTTP/1.1\r\n",
                r#"[{"Id":"container-abc","Labels":{"apolysis.session_id":"session-docker"}}]"#,
            ),
            (
                "GET /containers/container-abc/json HTTP/1.1\r\n",
                r#"{
                    "Id":"container-abc",
                    "State":{"Pid":1234},
                    "Config":{
                        "Image":"alpine:3.20",
                        "Labels":{"apolysis.session_id":"session-docker"}
                    },
                    "HostConfig":{"Runtime":"runsc"}
                }"#,
            ),
        ],
    );

    let server = TestServer::start_config(config.clone()).await;
    let timeline_path = config
        .state_dir
        .join("sessions/session-docker/timeline.jsonl");
    let timeline = wait_for_file_contains(&timeline_path, "runtime_workload_discovered").await;
    assert!(timeline.contains(r#""adapter":"docker""#));
    assert!(timeline.contains(r#""workload_id":"container-abc""#));
    assert!(timeline.contains(&format!(
        r#""cgroup_id":{}"#,
        std::fs::metadata(&cgroup).unwrap().ino()
    )));

    server.stop().await;
    docker.await.expect("fake docker engine");
}

#[tokio::test]
async fn state_initialization_failure_removes_the_bound_socket() {
    let config = config("state-init-failure", 2);
    std::fs::create_dir_all(&config.state_dir).unwrap();
    std::fs::write(config.state_dir.join("sessions"), "not a directory").unwrap();
    let socket = config.socket_path.clone();
    let (_shutdown_tx, shutdown_rx) = oneshot::channel();

    let error = serve(config.clone(), shutdown_rx)
        .await
        .expect_err("invalid state directory must fail startup");

    assert!(error.contains("state directory"), "{error}");
    assert!(!socket.exists(), "failed startup must remove bound socket");
    cleanup(&config);
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
async fn restart_quarantines_corrupt_tail_and_keeps_valid_session_recoverable() {
    let server = TestServer::start("restart-corrupt-tail").await;
    let config = server.config.clone();
    let register = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-corrupt-tail",
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

    let timeline_path = config
        .state_dir
        .join("sessions/session-corrupt-tail/timeline.jsonl");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&timeline_path)
        .expect("open timeline for corrupt tail")
        .write_all(br#"{"schema_version":1"#)
        .expect("write corrupt tail");

    let restarted = TestServer::start_config(config.clone()).await;
    let query = br#"{"type":"query","session_id":"session-corrupt-tail"}"#;
    assert!(matches!(
        request(&config.socket_path, query).await,
        DaemonResponse::Session {
            session: Some(_),
            ..
        }
    ));
    let DaemonResponse::Health { health, .. } =
        request(&config.socket_path, br#"{"type":"health"}"#).await
    else {
        panic!("expected health response");
    };
    assert_eq!(
        health.storage(),
        apolysis_accountability::ComponentState::Degraded
    );
    restarted.stop_preserving().await;

    let timeline = std::fs::read_to_string(&timeline_path).expect("session timeline");
    assert!(timeline.contains(r#""record_type":"intent_registered""#));
    assert!(timeline.contains(r#""record_type":"integrity_finding""#));
    assert!(timeline.contains(r#""reason":"hash_chain_tail_quarantined""#));

    let quarantine = quarantine_files(timeline_path.parent().unwrap());
    assert_eq!(quarantine.len(), 1);
    assert_eq!(
        std::fs::read_to_string(&quarantine[0]).expect("quarantine contents"),
        r#"{"schema_version":1"#
    );
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
            if task.is_finished() {
                let result = task.await.expect("daemon task join");
                panic!("daemon failed before creating socket: {result:?}");
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

async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut last_error = None;
    for _ in 0..100 {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                stream
                    .write_all(
                        format!(
                            "GET {path} HTTP/1.1\r\nHost: apolysisd\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("write HTTP request");
                let mut response = Vec::new();
                stream
                    .read_to_end(&mut response)
                    .await
                    .expect("read HTTP response");
                return String::from_utf8(response).expect("UTF-8 HTTP response");
            }
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
    panic!("metrics endpoint {addr} did not accept connections: {last_error:?}");
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

fn fake_docker_engine(
    socket_path: &std::path::Path,
    responses: Vec<(&'static str, &'static str)>,
) -> tokio::task::JoinHandle<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("create docker socket directory");
    }
    let listener = UnixListener::bind(socket_path).expect("bind fake docker socket");
    tokio::spawn(async move {
        for (expected_prefix, body) in responses {
            let (mut stream, _) = listener.accept().await.expect("accept docker client");
            let request = read_http_request(&mut stream).await;
            assert!(
                request.starts_with(expected_prefix),
                "unexpected Docker request: {request:?}"
            );
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .expect("write Docker response");
        }
    })
}

async fn read_http_request(stream: &mut UnixStream) -> String {
    let mut request = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .expect("read HTTP request");
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(request).expect("UTF-8 request")
}

async fn wait_for_file_contains(path: &std::path::Path, needle: &str) -> String {
    for _ in 0..100 {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if contents.contains(needle) {
                return contents;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{} did not contain {needle}", path.display());
}

fn config(name: &str, max_connections: usize) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "apolysisd-test-{name}-{}-{id}-{nonce}",
        std::process::id()
    ));
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        max_sessions: 32,
        max_pending: 32,
        max_connections,
        request_timeout: Duration::from_millis(100),
        ..DaemonConfig::default()
    }
}

fn unused_loopback_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind unused loopback port");
    listener.local_addr().expect("local addr")
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}

fn quarantine_files(session_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(session_dir)
        .expect("read session dir")
        .map(|entry| entry.expect("session dir entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("timeline.jsonl.quarantine-"))
        })
        .collect();
    paths.sort();
    paths
}

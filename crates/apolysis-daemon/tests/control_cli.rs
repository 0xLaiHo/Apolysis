// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const DIFFERENT_UID_SERVER_SOCKET: &str = "APOLYSIS_TEST_DIFFERENT_UID_SERVER_SOCKET";

#[test]
fn control_cli_forwards_a_typed_request_and_prints_a_canonical_response() {
    let root = temp_root("success");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let request = read_frame(&mut stream);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request).expect("parse request"),
            serde_json::json!({
                "type": "query",
                "tenant_id": "default",
                "session_id": "session-k1"
            })
        );
        write_frame(
            &mut stream,
            br#" { "session_id": "session-k1", "operation": "query", "schema_version": 1, "type": "ack" } "#,
        );
    });

    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &[],
    );

    server.join().expect("fake daemon completed");
    assert!(
        output.status.success(),
        "control CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}
"#
    );
    assert!(output.stderr.is_empty());

    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_rejects_an_insecure_daemon_socket_before_forwarding() {
    let root = temp_root("insecure-mode");
    let socket = root.join("apolysisd.sock");
    let listener = UnixListener::bind(&socket).expect("bind fake daemon socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
        .expect("set insecure mode");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_frame(&mut stream);
                    write_frame(
                        &mut stream,
                        br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}"#,
                    );
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept control client: {error}"),
            }
        }
    });

    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &[],
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !server.join().expect("fake daemon completed"),
        "an insecure socket received the request"
    );

    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_accepts_an_explicit_nonzero_overall_deadline() {
    let root = temp_root("explicit-timeout");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_frame(&mut stream);
                    write_frame(
                        &mut stream,
                        br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}"#,
                    );
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept control client: {error}"),
            }
        }
    });

    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &["--timeout-ms", "1000"],
    );

    assert!(
        output.status.success(),
        "control CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(server.join().expect("fake daemon completed"));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_applies_one_deadline_to_the_complete_daemon_exchange() {
    let root = temp_root("overall-timeout");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let _ = read_frame(&mut stream);
        let body =
            br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}"#;
        thread::sleep(Duration::from_millis(40));
        if stream.write_all(&(body.len() as u32).to_be_bytes()).is_ok() {
            thread::sleep(Duration::from_millis(40));
            let _ = stream.write_all(body);
        }
    });

    let started = Instant::now();
    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &["--timeout-ms", "60"],
    );
    let elapsed = started.elapsed();

    server.join().expect("fake daemon completed");
    assert!(!output.status.success(), "split response bypassed deadline");
    assert!(output.stdout.is_empty());
    assert!(
        elapsed < Duration::from_millis(200),
        "deadline was not enforced promptly: {elapsed:?}"
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_returns_nonzero_without_echoing_a_daemon_error_or_request() {
    let root = temp_root("daemon-error");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let _ = read_frame(&mut stream);
        write_frame(
            &mut stream,
            br#"{"type":"error","schema_version":1,"code":"state_error","message":"secret-request-marker"}"#,
        );
    });
    let request = br#"{"type":"query","tenant_id":"default","session_id":"secret-request-marker"}"#;

    let output = run_control(&socket, request, &[]);

    server.join().expect("fake daemon completed");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!contains(&output.stderr, b"secret-request-marker"));
    assert!(!contains(&output.stderr, request));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_accepts_a_bounded_response_larger_than_the_request_limit() {
    let root = temp_root("large-response");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let _ = read_frame(&mut stream);
        let mut response =
            br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}"#
                .to_vec();
        response.resize(apolysis_accountability::MAX_INTENT_FRAME_BYTES + 1024, b' ');
        write_frame(&mut stream, &response);
    });

    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &[],
    );

    server.join().expect("fake daemon completed");
    assert!(
        output.status.success(),
        "control CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}
"#
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_forwards_a_typed_kubernetes_claim_registration() {
    let root = temp_root("kubernetes-claim");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let request: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut stream)).expect("parse request");
        assert_eq!(request["type"], "register");
        assert_eq!(
            request["intent"]["kubernetes_claims"][0]["pod_uid"],
            "22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            request["intent"]["kubernetes_claims"][0]["container_ref"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        write_frame(
            &mut stream,
            br#"{"type":"ack","schema_version":1,"operation":"register","session_id":"session-k1-claim"}"#,
        );
    });
    let request = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "tenant_id":"default",
            "session_id":"session-k1-claim",
            "expires_at_unix_ms":4102444800000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "workload_selectors":[],
            "kubernetes_claims":[{
                "schema_version":1,
                "claim_revision":1,
                "cluster_id":"11111111-1111-1111-1111-111111111111",
                "namespace_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pod_uid":"22222222-2222-2222-2222-222222222222",
                "container_kind":"application",
                "container_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }]
        }
    }"#;

    let output = run_control(&socket, request, &[]);

    server.join().expect("fake daemon completed");
    assert!(
        output.status.success(),
        "control CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_forwards_every_non_registration_intent_operation() {
    for (name, request, expected_type) in [
        (
            "renew",
            br#"{"type":"renew","session_id":"session-k1","expires_at_unix_ms":4102444800000}"#
                .as_slice(),
            "renew",
        ),
        (
            "close",
            br#"{"type":"close","session_id":"session-k1"}"#.as_slice(),
            "close",
        ),
        (
            "query-all",
            br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#.as_slice(),
            "query",
        ),
        (
            "list",
            br#"{"type":"list_sessions","tenant_id":"default","retention_tier":"standard"}"#
                .as_slice(),
            "list_sessions",
        ),
        (
            "purge-preview",
            br#"{"type":"apply_retention","tenant_id":"default","dry_run":true}"#.as_slice(),
            "apply_retention",
        ),
    ] {
        assert_forwarded_type(name, request, expected_type);
    }
}

#[test]
fn control_cli_rejects_an_invalid_kubernetes_claim_without_forwarding_or_echoing_it() {
    let root = temp_root("invalid-kubernetes-claim");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let request = br#"{
        "type":"register",
        "intent":{
            "schema_version":1,
            "session_id":"session-secret-claim-marker",
            "expires_at_unix_ms":4102444800000,
            "declared_actions":["test"],
            "allowed_resources":[],
            "workload_selectors":[],
            "kubernetes_claims":[{
                "schema_version":1,
                "claim_revision":1,
                "cluster_id":"11111111-1111-1111-1111-111111111111",
                "namespace_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pod_uid":"secret-claim-marker",
                "container_kind":"application",
                "container_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }]
        }
    }"#;

    let output = run_control(&socket, request, &[]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!contains(&output.stderr, b"secret-claim-marker"));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_rejects_symlink_and_non_socket_endpoints() {
    let request = br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#;

    let symlink_root = temp_root("socket-symlink");
    let target = symlink_root.join("target.sock");
    let listener = secure_listener(&target);
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let socket_link = symlink_root.join("apolysisd.sock");
    std::os::unix::fs::symlink(&target, &socket_link).expect("create socket symlink");
    let output = run_control(&socket_link, request, &[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    std::fs::remove_dir_all(symlink_root).expect("remove symlink fixture");

    let file_root = temp_root("regular-file");
    let regular_file = file_root.join("apolysisd.sock");
    std::fs::write(&regular_file, b"not a socket").expect("write endpoint fixture");
    std::fs::set_permissions(&regular_file, std::fs::Permissions::from_mode(0o660))
        .expect("set endpoint fixture mode");
    let output = run_control(&regular_file, request, &[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    std::fs::remove_dir_all(file_root).expect("remove file fixture");
}

#[test]
fn control_cli_accepts_an_input_at_the_limit_and_rejects_one_byte_more() {
    let root = temp_root("request-bound");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let request: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut stream)).expect("parse request");
        assert_eq!(request["type"], "query");
        write_frame(
            &mut stream,
            br#"{"type":"ack","schema_version":1,"operation":"query","session_id":"session-k1"}"#,
        );
    });
    let mut exact = br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#.to_vec();
    exact.resize(apolysis_accountability::MAX_INTENT_FRAME_BYTES, b' ');
    let output = run_control(&socket, &exact, &[]);
    server.join().expect("fake daemon completed");
    assert!(output.status.success());
    std::fs::remove_dir_all(root).expect("remove exact-bound fixture");

    let oversized = vec![b'x'; apolysis_accountability::MAX_INTENT_FRAME_BYTES + 1];
    let output = run_control(
        std::path::Path::new("/endpoint-must-not-be-opened"),
        &oversized,
        &[],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn control_cli_rejects_a_response_above_its_four_mib_bound() {
    let root = temp_root("oversized-response");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let _ = read_frame(&mut stream);
        stream
            .write_all(&((4 * 1024 * 1024 + 1) as u32).to_be_bytes())
            .expect("write oversized response length");
    });

    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &[],
    );

    server.join().expect("fake daemon completed");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_deadline_also_bounds_waiting_for_stdin_eof() {
    let root = temp_root("stdin-timeout");
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let binary = std::env::var("CARGO_BIN_EXE_apolysisd-control")
        .expect("apolysisd-control test binary path");
    let mut child = Command::new(binary)
        .arg("--socket")
        .arg(&socket)
        .arg("--timeout-ms")
        .arg("50")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run apolysisd-control");
    let mut stdin = child.stdin.take().expect("control stdin");
    stdin
        .write_all(br#"{"type":"query""#)
        .expect("write incomplete request");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll control CLI") {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "control CLI did not apply its stdin deadline"
        );
        thread::sleep(Duration::from_millis(5));
    };
    drop(stdin);
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("control stdout")
        .read_to_end(&mut stdout)
        .expect("read control stdout");

    assert!(!status.success());
    assert!(stdout.is_empty());
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn control_cli_rejects_a_daemon_peer_with_a_different_uid_when_root_can_exercise_it() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: different-peer-UID exercise requires root to drop the server UID");
        return;
    }
    let root = temp_root("peer-uid");
    let socket = root.join("apolysisd.sock");
    let current_test_binary = std::env::current_exe().expect("current test binary");
    let server = Command::new(current_test_binary)
        .arg("--exact")
        .arg("different_uid_server_helper")
        .env(DIFFERENT_UID_SERVER_SOCKET, &socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn different-uid server");
    let ready_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(metadata) = std::fs::symlink_metadata(&socket) {
            if metadata.file_type().is_socket() && metadata.permissions().mode() & 0o7777 == 0o660 {
                break;
            }
        }
        assert!(
            Instant::now() < ready_deadline,
            "different-uid server did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let output = run_control(
        &socket,
        br#"{"type":"query","tenant_id":"default","session_id":"session-k1"}"#,
        &[],
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let server_output = server
        .wait_with_output()
        .expect("wait for different-uid server");
    assert!(
        server_output.status.success(),
        "different-uid server failed: {}",
        String::from_utf8_lossy(&server_output.stderr)
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn different_uid_server_helper() {
    let Some(socket) = std::env::var_os(DIFFERENT_UID_SERVER_SOCKET) else {
        return;
    };
    let listener = UnixListener::bind(&socket).expect("bind different-uid server");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
        .expect("secure different-uid socket");
    assert_eq!(unsafe { libc::setgid(65_534) }, 0, "drop server gid");
    assert_eq!(unsafe { libc::setuid(65_534) }, 0, "drop server uid");
    let (mut stream, _) = listener.accept().expect("accept control client");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set peer test timeout");
    let mut byte = [0_u8; 1];
    assert_eq!(stream.read(&mut byte).expect("read rejected client"), 0);
}

fn run_control(
    socket: &std::path::Path,
    request: &[u8],
    extra_args: &[&str],
) -> std::process::Output {
    let binary = std::env::var("CARGO_BIN_EXE_apolysisd-control")
        .expect("apolysisd-control test binary path");
    let mut command = Command::new(binary);
    command
        .arg("--socket")
        .arg(socket)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("run apolysisd-control");
    child
        .stdin
        .take()
        .expect("control stdin")
        .write_all(request)
        .expect("write control request");
    child.wait_with_output().expect("wait for control CLI")
}

fn assert_forwarded_type(name: &str, request: &[u8], expected_type: &str) {
    let root = temp_root(name);
    let socket = root.join("apolysisd.sock");
    let listener = secure_listener(&socket);
    let expected_type = expected_type.to_string();
    let response_operation = expected_type.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept control client");
        let request: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut stream)).expect("parse request");
        assert_eq!(request["type"], expected_type);
        let response = serde_json::json!({
            "type": "ack",
            "schema_version": 1,
            "operation": response_operation,
            "session_id": null
        })
        .to_string();
        write_frame(&mut stream, response.as_bytes());
    });

    let output = run_control(&socket, request, &[]);

    server.join().expect("fake daemon completed");
    assert!(
        output.status.success(),
        "control CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(root).expect("remove fixture");
}

fn secure_listener(path: &std::path::Path) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind fake daemon socket");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .expect("secure fake daemon socket");
    listener
}

fn read_frame(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).expect("read request length");
    let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).expect("read request body");
    body
}

fn write_frame(stream: &mut std::os::unix::net::UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .expect("write response length");
    stream.write_all(body).expect("write response body");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn temp_root(name: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-control-cli-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create fixture root");
    root
}

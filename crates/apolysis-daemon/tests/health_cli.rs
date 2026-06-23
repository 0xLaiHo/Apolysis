// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn apolysisd_health_cli_prints_health_response_from_unix_socket() {
    let root = temp_root("health-cli");
    let socket = root.join("apolysisd.sock");
    let listener = UnixListener::bind(&socket).expect("bind fake daemon socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept health client");
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).expect("read request length");
        let length = u32::from_be_bytes(length) as usize;
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).expect("read request body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request).expect("parse request"),
            serde_json::json!({"type": "health"})
        );
        let response = serde_json::json!({
            "type": "health",
            "schema_version": 1,
            "liveness": true,
            "readiness": false,
            "health": {
                "event_loop_running": true,
                "ebpf": "unavailable",
                "storage": "ready",
                "adapters": {},
                "queue": {
                    "accepted": 0,
                    "dropped": 0,
                    "ordinary_depth": 0,
                    "protected_depth": 0,
                    "capacity": 16384
                }
            }
        })
        .to_string()
        .into_bytes();
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .expect("write response length");
        stream.write_all(&response).expect("write response body");
    });

    let binary =
        std::env::var("CARGO_BIN_EXE_apolysisd-health").expect("apolysisd-health test binary path");
    let output = std::process::Command::new(binary)
        .arg("--socket")
        .arg(&socket)
        .output()
        .expect("run apolysisd-health");

    server.join().expect("fake daemon completed");
    assert!(
        output.status.success(),
        "apolysisd-health failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("health CLI output is JSON");
    assert_eq!(response["type"], "health");
    assert_eq!(response["liveness"], true);
    assert_eq!(response["readiness"], false);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn apolysisd_health_cli_fails_when_required_readiness_is_false() {
    let root = temp_root("health-cli-readiness");
    let socket = root.join("apolysisd.sock");
    let listener = UnixListener::bind(&socket).expect("bind fake daemon socket");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept health client: {error}"),
            }
        };
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).expect("read request length");
        let length = u32::from_be_bytes(length) as usize;
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).expect("read request body");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request).expect("parse request"),
            serde_json::json!({"type": "health"})
        );
        let response = serde_json::json!({
            "type": "health",
            "schema_version": 1,
            "liveness": true,
            "readiness": false,
            "health": {
                "event_loop_running": true,
                "ebpf": "unavailable",
                "storage": "ready",
                "adapters": {},
                "queue": {
                    "accepted": 0,
                    "dropped": 0,
                    "ordinary_depth": 0,
                    "protected_depth": 0,
                    "capacity": 16384
                }
            }
        })
        .to_string()
        .into_bytes();
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .expect("write response length");
        stream.write_all(&response).expect("write response body");
        true
    });

    let binary =
        std::env::var("CARGO_BIN_EXE_apolysisd-health").expect("apolysisd-health test binary path");
    let output = std::process::Command::new(binary)
        .arg("--socket")
        .arg(&socket)
        .arg("--require-readiness")
        .output()
        .expect("run apolysisd-health");

    assert!(
        server.join().expect("fake daemon completed"),
        "health CLI did not connect to the daemon socket"
    );
    assert!(
        !output.status.success(),
        "apolysisd-health unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("readiness requirement failed"),
        "unexpected stderr: {stderr}"
    );

    let _ = std::fs::remove_dir_all(root);
}

fn temp_root(name: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-daemon-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

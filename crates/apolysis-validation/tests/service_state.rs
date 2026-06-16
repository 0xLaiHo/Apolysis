// SPDX-License-Identifier: Apache-2.0

use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_validation::{capture_service_state, RuntimeSocketState, ServiceCaptureRequest};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn parses_systemd_service_state_and_drop_ins() {
    let root = temp_root("service");
    let socket_path = root.join("run/docker.sock");
    std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
    let _listener = UnixListener::bind(&socket_path).unwrap();

    let state = capture_service_state(ServiceCaptureRequest {
        service_name: "docker.service".to_string(),
        systemctl_show: "\
Id=docker.service
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
FragmentPath=/usr/lib/systemd/system/docker.service
DropInPaths=/etc/systemd/system/docker.service.d/http-proxy.conf /etc/systemd/system/docker.service.d/override.conf
",
        runtime_sockets: vec![socket_path.clone(), root.join("run/missing.sock")],
    })
    .expect("capture service state");

    assert_eq!(state.service_name, "docker.service");
    assert_eq!(state.load_state, "loaded");
    assert_eq!(state.active_state, "inactive");
    assert_eq!(state.unit_file_state, "disabled");
    assert_eq!(
        state.fragment_path.as_deref(),
        Some(std::path::Path::new(
            "/usr/lib/systemd/system/docker.service"
        ))
    );
    assert_eq!(
        state.drop_in_paths,
        vec![
            std::path::PathBuf::from("/etc/systemd/system/docker.service.d/http-proxy.conf"),
            std::path::PathBuf::from("/etc/systemd/system/docker.service.d/override.conf")
        ]
    );
    assert_eq!(
        state.runtime_sockets,
        vec![
            RuntimeSocketState {
                path: socket_path,
                present: true,
            },
            RuntimeSocketState {
                path: root.join("run/missing.sock"),
                present: false,
            }
        ]
    );
    cleanup(&root);
}

#[test]
fn missing_systemd_fields_fail_closed() {
    let error = capture_service_state(ServiceCaptureRequest {
        service_name: "containerd.service".to_string(),
        systemctl_show: "Id=containerd.service\nActiveState=active\n",
        runtime_sockets: Vec::new(),
    })
    .expect_err("missing service fields must fail");

    assert!(error.contains("LoadState"), "{error}");
}

fn temp_root(name: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-validation-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn cleanup(root: &std::path::Path) {
    let _ = std::fs::remove_dir_all(root);
}

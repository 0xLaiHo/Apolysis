// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_validation::{
    capture_backup_manifest, capture_service_state, plan_restore, BackupCaptureRequest,
    BackupSource, ManagedServiceInputs, RestoreAction, RestorePlanRequest, ServiceCaptureRequest,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn plans_file_restore_validation_cleanup_and_service_state_restore() {
    let root = temp_root("restore-plan");
    let source = root.join("etc/docker/daemon.json");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"{\"default-runtime\":\"runc\"}").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
    let backup_root = root.join("backup");
    let manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: backup_root.clone(),
        sources: vec![BackupSource::new("docker_daemon", &source)],
    })
    .expect("capture manifest");
    let service = capture_service_state(ServiceCaptureRequest {
        service_name: "docker.service".to_string(),
        systemctl_show: "\
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
FragmentPath=/usr/lib/systemd/system/docker.service
DropInPaths=
",
        runtime_sockets: vec![root.join("run/docker.sock")],
    })
    .expect("capture service");

    let plan = plan_restore(RestorePlanRequest {
        backup_root,
        manifest,
        services: vec![service],
        managed_service_inputs: vec![ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec!["docker_daemon".to_string()],
        }],
        validation_owned_paths: vec![root.join("run/apolysis-validation.sock")],
    })
    .expect("plan restore");

    assert_eq!(plan.actions.len(), 3);
    assert!(matches!(
        &plan.actions[0],
        RestoreAction::RestoreRegularFile {
            id,
            from_backup,
            to_path,
            mode: Some(0o644),
            ..
        } if id == "docker_daemon"
            && from_backup == &std::path::PathBuf::from("files/docker_daemon")
            && to_path == &source
    ));
    assert_eq!(
        plan.actions[1],
        RestoreAction::RemoveValidationPath {
            path: root.join("run/apolysis-validation.sock")
        }
    );
    assert_eq!(
        plan.actions[2],
        RestoreAction::RestoreServiceState {
            service_name: "docker.service".to_string(),
            active_state: "inactive".to_string(),
            unit_file_state: "disabled".to_string(),
        }
    );
    cleanup(&root);
}

#[test]
fn missing_or_corrupt_backup_bytes_fail_closed() {
    let root = temp_root("restore-corrupt");
    let source = root.join("etc/containerd/config.toml");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"version = 3\n").unwrap();
    let backup_root = root.join("backup");
    let manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: backup_root.clone(),
        sources: vec![BackupSource::new("containerd_config", &source)],
    })
    .expect("capture manifest");
    let backup_relative = manifest.entries[0]
        .backup_relative_path
        .as_ref()
        .expect("backup path")
        .clone();
    std::fs::write(backup_root.join(backup_relative), b"tampered").unwrap();

    let error = plan_restore(RestorePlanRequest {
        backup_root,
        manifest,
        services: Vec::new(),
        managed_service_inputs: Vec::new(),
        validation_owned_paths: Vec::new(),
    })
    .expect_err("corrupt backup must fail");

    assert!(error.contains("checksum"), "{error}");
    cleanup(&root);
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

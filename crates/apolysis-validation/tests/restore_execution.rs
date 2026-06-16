// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_validation::{
    capture_backup_manifest, capture_service_state, execute_restore_plan, plan_restore,
    BackupCaptureRequest, BackupSource, ManagedServiceInputs, RestoreExecutionRequest,
    RestorePlanRequest, ServiceCaptureRequest, ServiceController,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn executes_restore_plan_after_rechecking_backup_integrity() {
    let root = temp_root("restore-execute");
    let source = root.join("etc/docker/daemon.json");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"{\"default-runtime\":\"runc\"}\n").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
    let validation_path = root.join("run/apolysis-validation/socket");
    std::fs::create_dir_all(validation_path.parent().unwrap()).unwrap();
    std::fs::write(&validation_path, b"temporary validation state").unwrap();

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
        backup_root: backup_root.clone(),
        manifest: manifest.clone(),
        services: vec![service.clone()],
        managed_service_inputs: vec![ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec!["docker_daemon".to_string()],
        }],
        validation_owned_paths: vec![validation_path.clone()],
    })
    .expect("plan restore");

    std::fs::write(&source, b"{\"runtimes\":{\"runsc\":{}}}\n").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut controller = RecordingServiceController::default();

    let report = execute_restore_plan(
        RestoreExecutionRequest {
            backup_root,
            manifest,
            services: vec![service],
            plan,
        },
        &mut controller,
    )
    .expect("execute restore plan");

    assert_eq!(
        std::fs::read(&source).unwrap(),
        b"{\"default-runtime\":\"runc\"}\n"
    );
    assert_eq!(
        std::fs::metadata(&source).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert!(!validation_path.exists());
    assert_eq!(report.actions_applied, 3);
    assert_eq!(
        controller.operations,
        vec![
            "unit docker.service disabled".to_string(),
            "active docker.service inactive".to_string(),
        ]
    );
    cleanup(&root);
}

#[test]
fn refuses_to_restore_when_backup_copy_changed_after_planning() {
    let root = temp_root("restore-execute-corrupt");
    let source = root.join("etc/containerd/config.toml");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"version = 3\n").unwrap();
    let backup_root = root.join("backup");
    let manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: backup_root.clone(),
        sources: vec![BackupSource::new("containerd_config", &source)],
    })
    .expect("capture manifest");
    let plan = plan_restore(RestorePlanRequest {
        backup_root: backup_root.clone(),
        manifest: manifest.clone(),
        services: Vec::new(),
        managed_service_inputs: Vec::new(),
        validation_owned_paths: Vec::new(),
    })
    .expect("plan restore");
    let backup_relative = manifest.entries[0]
        .backup_relative_path
        .as_ref()
        .expect("backup path")
        .clone();
    std::fs::write(backup_root.join(backup_relative), b"tampered").unwrap();
    std::fs::write(&source, b"changed = true\n").unwrap();

    let mut controller = RecordingServiceController::default();
    let error = execute_restore_plan(
        RestoreExecutionRequest {
            backup_root,
            manifest,
            services: Vec::new(),
            plan,
        },
        &mut controller,
    )
    .expect_err("corrupt backup must fail before mutation");

    assert!(error.contains("checksum"), "{error}");
    assert_eq!(std::fs::read(&source).unwrap(), b"changed = true\n");
    assert!(controller.operations.is_empty());
    cleanup(&root);
}

#[test]
fn refuses_to_restore_when_service_state_action_was_tampered() {
    let root = temp_root("restore-execute-service-tamper");
    let source = root.join("etc/docker/daemon.json");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"{\"default-runtime\":\"runc\"}\n").unwrap();
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
ActiveState=active
UnitFileState=disabled
FragmentPath=/usr/lib/systemd/system/docker.service
DropInPaths=
",
        runtime_sockets: Vec::new(),
    })
    .expect("capture service");
    let mut plan = plan_restore(RestorePlanRequest {
        backup_root: backup_root.clone(),
        manifest: manifest.clone(),
        services: vec![service.clone()],
        managed_service_inputs: vec![ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec!["docker_daemon".to_string()],
        }],
        validation_owned_paths: Vec::new(),
    })
    .expect("plan restore");
    for action in &mut plan.actions {
        if let apolysis_validation::RestoreAction::RestoreServiceState { active_state, .. } = action
        {
            *active_state = "inactive".to_string();
        }
    }
    std::fs::write(&source, b"{\"runtimes\":{\"runsc\":{}}}\n").unwrap();
    let mut controller = RecordingServiceController::default();

    let error = execute_restore_plan(
        RestoreExecutionRequest {
            backup_root,
            manifest,
            services: vec![service],
            plan,
        },
        &mut controller,
    )
    .expect_err("tampered service action must fail before mutation");

    assert!(
        error.contains("active state does not match capture"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&source).unwrap(),
        b"{\"runtimes\":{\"runsc\":{}}}\n"
    );
    assert!(controller.operations.is_empty());
    cleanup(&root);
}

#[derive(Default)]
struct RecordingServiceController {
    operations: Vec<String>,
}

impl ServiceController for RecordingServiceController {
    fn restore_unit_file_state(
        &mut self,
        service_name: &str,
        unit_file_state: &str,
    ) -> Result<(), String> {
        self.operations
            .push(format!("unit {service_name} {unit_file_state}"));
        Ok(())
    }

    fn restore_active_state(
        &mut self,
        service_name: &str,
        active_state: &str,
    ) -> Result<(), String> {
        self.operations
            .push(format!("active {service_name} {active_state}"));
        Ok(())
    }
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

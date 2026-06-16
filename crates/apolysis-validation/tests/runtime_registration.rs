// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_validation::{
    apply_runtime_registration_plan, plan_runtime_registration, restore_validation_from_output,
    RuntimeRegistrationPlanRequest, ServiceController,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn plans_and_applies_runtime_registration_files() {
    let root = temp_root("runtime-registration");
    let docker_path = root.join("etc/docker/daemon.json");
    let containerd_path = root.join("etc/containerd/config.toml");
    let k3s_dropin_path = root.join(
        "var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml",
    );
    std::fs::create_dir_all(docker_path.parent().unwrap()).unwrap();
    std::fs::write(
        &docker_path,
        r#"{"runtimes":{"nvidia":{"path":"nvidia-container-runtime","args":[]}}}"#,
    )
    .unwrap();

    let plan = plan_runtime_registration(RuntimeRegistrationPlanRequest {
        docker_daemon_path: docker_path.clone(),
        docker_daemon_json: std::fs::read_to_string(&docker_path).unwrap(),
        containerd_config_path: containerd_path.clone(),
        containerd_config_toml: None,
        k3s_runtime_dropin_path: k3s_dropin_path.clone(),
    })
    .expect("plan runtime registration");

    assert_eq!(
        plan.file_writes
            .iter()
            .map(|write| write.id.as_str())
            .collect::<Vec<_>>(),
        vec!["docker_daemon", "containerd_config", "k3s_runtime_dropin"]
    );

    let report = apply_runtime_registration_plan(&plan).expect("apply runtime registration");

    assert_eq!(report.files_written, 3);
    let docker_json = std::fs::read_to_string(&docker_path).unwrap();
    assert!(docker_json.contains("\"runsc\""));
    assert!(docker_json.contains("nvidia-container-runtime"));
    let containerd_toml = std::fs::read_to_string(&containerd_path).unwrap();
    assert!(containerd_toml.contains("io.containerd.runc.v2"));
    assert!(containerd_toml.contains("io.containerd.runsc.v1"));
    assert!(containerd_toml.contains("io.containerd.kata.v2"));
    let k3s_dropin = std::fs::read_to_string(&k3s_dropin_path).unwrap();
    assert!(k3s_dropin.contains("io.containerd.runsc.v1"));
    assert!(k3s_dropin.contains("io.containerd.kata.v2"));
    assert_eq!(
        std::fs::metadata(&containerd_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    cleanup(&root);
}

#[test]
fn restores_from_written_validation_artifacts_with_service_controller() {
    let root = temp_root("runtime-registration-restore");
    let source = root.join("etc/docker/daemon.json");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"{\"default-runtime\":\"runc\"}\n").unwrap();
    let output = root.join("validation");
    let manifest =
        apolysis_validation::capture_backup_manifest(apolysis_validation::BackupCaptureRequest {
            output_dir: output.clone(),
            sources: vec![apolysis_validation::BackupSource::new(
                "docker_daemon",
                &source,
            )],
        })
        .expect("capture manifest");
    let service =
        apolysis_validation::capture_service_state(apolysis_validation::ServiceCaptureRequest {
            service_name: "docker.service".to_string(),
            systemctl_show: "\
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
FragmentPath=/usr/lib/systemd/system/docker.service
DropInPaths=
",
            runtime_sockets: Vec::new(),
        })
        .expect("capture service");
    let restore_plan = apolysis_validation::plan_restore(apolysis_validation::RestorePlanRequest {
        backup_root: output.clone(),
        manifest: manifest.clone(),
        services: vec![service.clone()],
        managed_service_inputs: vec![apolysis_validation::ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec!["docker_daemon".to_string()],
        }],
        validation_owned_paths: Vec::new(),
    })
    .expect("plan restore");
    std::fs::write(
        output.join("backup-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        output.join("service-state.json"),
        serde_json::to_vec_pretty(&vec![service]).unwrap(),
    )
    .unwrap();
    std::fs::write(
        output.join("restore-plan.json"),
        serde_json::to_vec_pretty(&restore_plan).unwrap(),
    )
    .unwrap();
    std::fs::write(&source, b"{\"runtimes\":{\"runsc\":{}}}\n").unwrap();
    let mut controller = RecordingServiceController::default();

    let report = restore_validation_from_output(&output, &mut controller).expect("restore output");

    assert_eq!(report.actions_applied, 2);
    assert_eq!(
        std::fs::read(&source).unwrap(),
        b"{\"default-runtime\":\"runc\"}\n"
    );
    assert_eq!(
        controller.operations,
        vec![
            "unit docker.service disabled".to_string(),
            "active docker.service inactive".to_string(),
        ]
    );
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

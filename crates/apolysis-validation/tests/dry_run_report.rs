// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_validation::{
    build_validation_report, BackupSource, KubernetesCaptureRequest, ManagedServiceInputs,
    ServiceCaptureRequest, ValidationReportRequest,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn writes_dry_run_report_artifacts_without_sensitive_kubernetes_fields() {
    let root = temp_root("report");
    let source = root.join("etc/docker/daemon.json");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, b"{\"default-runtime\":\"runc\"}").unwrap();
    let output = root.join("out");

    let report = build_validation_report(ValidationReportRequest {
        output_dir: output.clone(),
        backup_sources: vec![BackupSource::new("docker_daemon", &source)],
        service_requests: vec![ServiceCaptureRequest {
            service_name: "docker.service".to_string(),
            systemctl_show: "\
LoadState=loaded
ActiveState=inactive
UnitFileState=disabled
FragmentPath=/usr/lib/systemd/system/docker.service
DropInPaths=
",
            runtime_sockets: vec![root.join("run/docker.sock")],
        }],
        kubernetes: KubernetesCaptureRequest {
            runtimeclasses_json: r#"{"items":[]}"#,
            nodes_json: r#"{"items":[]}"#,
            pods_json: r#"{"items":[{"metadata":{"namespace":"default","name":"pod","annotations":{"token":"secret"}},"spec":{"containers":[{"env":[{"value":"do-not-store"}]}]}}]}"#,
            validation_label_key: "apolysis.dev/validation",
        },
        managed_service_inputs: vec![ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec!["docker_daemon".to_string()],
        }],
        validation_owned_paths: vec![root.join("run/apolysis-validation.sock")],
    })
    .expect("build dry-run report");

    assert_eq!(report.backup_manifest.entries.len(), 1);
    assert_eq!(report.services.len(), 1);
    assert_eq!(report.kubernetes.workloads.len(), 1);
    assert_eq!(report.restore_plan.actions.len(), 3);
    for name in [
        "backup-manifest.json",
        "service-state.json",
        "kubernetes-context.json",
        "restore-plan.json",
    ] {
        assert!(output.join(name).is_file(), "{name} missing");
    }
    let combined = std::fs::read_to_string(output.join("kubernetes-context.json")).unwrap();
    assert!(!combined.contains("secret"));
    assert!(!combined.contains("do-not-store"));
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

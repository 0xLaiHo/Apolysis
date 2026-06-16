// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_validation::{
    capture_backup_manifest, BackupCaptureRequest, BackupEntryKind, BackupSource,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn captures_regular_file_bytes_checksum_and_metadata() {
    let root = temp_root("regular-file");
    let source = root.join("etc/docker/daemon.json");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, br#"{"runtimes":{}}"#).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o640)).unwrap();
    let output = root.join("backup");

    let manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: output.clone(),
        sources: vec![BackupSource::new("docker_daemon", &source)],
    })
    .expect("capture backup manifest");

    assert_eq!(manifest.entries.len(), 1);
    let entry = &manifest.entries[0];
    assert_eq!(entry.id, "docker_daemon");
    assert_eq!(entry.original_path, source);
    assert_eq!(entry.kind, BackupEntryKind::RegularFile);
    assert_eq!(entry.mode, Some(0o640));
    assert_eq!(entry.uid, Some(std::fs::metadata(&source).unwrap().uid()));
    assert_eq!(entry.gid, Some(std::fs::metadata(&source).unwrap().gid()));
    assert_eq!(
        entry.sha256_hex.as_deref(),
        Some("0f195c922de093a70dcf621709c824b81acee822126f2c36390ade08dac1e2e7")
    );
    assert_eq!(
        std::fs::read(output.join(entry.backup_relative_path.as_ref().unwrap())).unwrap(),
        br#"{"runtimes":{}}"#
    );
    cleanup(&root);
}

#[test]
fn captures_missing_files_and_symlinks_without_following_targets() {
    let root = temp_root("missing-symlink");
    let missing = root.join("etc/containerd/config.toml");
    let target = root.join("real-template.toml");
    let link = root.join("etc/rancher/k3s/agent/etc/containerd/config.toml.tmpl");
    std::fs::write(&target, b"version = 3\n").unwrap();
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    symlink(&target, &link).unwrap();
    let output = root.join("backup");

    let manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: output,
        sources: vec![
            BackupSource::new("containerd_config", &missing),
            BackupSource::new("k3s_template", &link),
        ],
    })
    .expect("capture backup manifest");

    assert_eq!(manifest.entries.len(), 2);
    assert_eq!(manifest.entries[0].kind, BackupEntryKind::Missing);
    assert!(manifest.entries[0].backup_relative_path.is_none());
    assert_eq!(manifest.entries[1].kind, BackupEntryKind::Symlink);
    assert_eq!(
        manifest.entries[1].symlink_target.as_deref(),
        Some(target.as_path())
    );
    assert!(manifest.entries[1].backup_relative_path.is_none());
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

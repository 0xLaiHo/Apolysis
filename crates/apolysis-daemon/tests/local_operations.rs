// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_daemon::{
    LocalDaemonChange, LocalDaemonErrorCode, LocalDaemonOperationKind, LocalDaemonOperations,
};
use serde_json::json;
use sha2::{Digest, Sha256};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

const ARTIFACTS: [(&str, &str, &str, u32); 5] = [
    (
        "bin/apolysis",
        "cli_binary",
        "usr/local/bin/apolysis",
        0o755,
    ),
    (
        "bin/apolysisd",
        "daemon_binary",
        "usr/local/bin/apolysisd",
        0o755,
    ),
    (
        "bin/apolysisd-health",
        "health_binary",
        "usr/local/bin/apolysisd-health",
        0o755,
    ),
    (
        "ebpf/apolysis_observer.bpf.o",
        "core_bpf_object",
        "usr/local/lib/apolysis/apolysis_observer.bpf.o",
        0o644,
    ),
    (
        "systemd/apolysisd.service",
        "systemd_unit",
        "etc/systemd/system/apolysisd.service",
        0o644,
    ),
];

#[test]
fn staged_install_then_default_uninstall_is_bounded_and_preserves_agent_runs() {
    let fixture = Fixture::new("install-uninstall");
    let bundle = fixture.bundle("v0.4.0");
    let canary = fixture.root.join("usr/local/bin/unrelated-canary");
    write_file(&canary, b"operator-owned\n", 0o755);
    let timeline = fixture
        .root
        .join("var/lib/apolysis/sessions/run-keep/timeline.jsonl");
    write_file(&timeline, b"private-agent-run\n", 0o640);

    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle.clone(),
        })
        .expect("plan staged install");
    let report = operations.apply(plan).expect("apply staged install");
    assert_eq!(report.operation(), LocalDaemonOperationKind::Install);
    assert_eq!(report.changed_files(), ARTIFACTS.len() + 1);

    for (bundle_path, _, target_path, mode) in ARTIFACTS {
        assert_eq!(
            std::fs::read(fixture.root.join(target_path)).expect("read installed artifact"),
            std::fs::read(bundle.join(bundle_path)).expect("read bundle artifact")
        );
        assert_eq!(
            std::fs::metadata(fixture.root.join(target_path))
                .expect("installed artifact metadata")
                .permissions()
                .mode()
                & 0o777,
            mode
        );
    }
    assert!(fixture
        .root
        .join("usr/local/lib/apolysis/install-receipt-v1.json")
        .is_file());

    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect("plan idempotent staged install");
    let report = operations.apply(plan).expect("repeat staged install");
    assert_eq!(report.changed_files(), 0);

    let plan = operations
        .plan(LocalDaemonChange::UninstallPreserveState)
        .expect("plan bounded uninstall");
    let report = operations.apply(plan).expect("apply bounded uninstall");
    assert_eq!(report.operation(), LocalDaemonOperationKind::Uninstall);
    assert!(report.preserved_agent_run_state());

    for (_, _, target_path, _) in ARTIFACTS {
        assert!(!fixture.root.join(target_path).exists());
    }
    assert!(!fixture
        .root
        .join("usr/local/lib/apolysis/install-receipt-v1.json")
        .exists());
    assert_eq!(
        std::fs::read(canary).expect("read canary"),
        b"operator-owned\n"
    );
    assert_eq!(
        std::fs::read(timeline).expect("read preserved Agent Run"),
        b"private-agent-run\n"
    );
}

#[test]
fn staged_install_rejects_an_unmanaged_target_before_any_mutation() {
    let fixture = Fixture::new("unmanaged-conflict");
    let bundle = fixture.bundle("v0.4.0");
    let conflict = fixture.root.join("usr/local/bin/apolysisd");
    write_file(&conflict, b"operator-owned\n", 0o755);

    let operations = LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let error = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect_err("unmanaged target must fail closed");
    assert_eq!(error.code(), LocalDaemonErrorCode::UnmanagedTarget);
    assert_eq!(
        std::fs::read(conflict).expect("read unmanaged conflict"),
        b"operator-owned\n"
    );
    for (_, _, target_path, _) in ARTIFACTS {
        if target_path != "usr/local/bin/apolysisd" {
            assert!(!fixture.root.join(target_path).exists());
        }
    }
}

#[test]
fn staged_install_never_follows_a_target_symlink() {
    let fixture = Fixture::new("target-symlink");
    let bundle = fixture.bundle("v0.4.0");
    let external = fixture.workspace.join("outside-canary");
    write_file(&external, b"outside\n", 0o600);
    let target = fixture.root.join("usr/local/bin/apolysis");
    std::fs::create_dir_all(target.parent().expect("target parent")).expect("create target parent");
    symlink(&external, &target).expect("create hostile target symlink");
    let before = std::fs::metadata(&external).expect("external metadata");

    let operations = LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let error = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect_err("symlink target must fail closed");
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTarget);
    let after = std::fs::metadata(&external).expect("external metadata after refusal");
    assert_eq!(
        std::fs::read(&external).expect("read external"),
        b"outside\n"
    );
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
}

#[test]
fn opening_staged_root_never_follows_a_root_symlink() {
    let fixture = Fixture::new("root-symlink");
    let external = fixture.workspace.join("external-root");
    std::fs::create_dir(&external).expect("create external root");
    let external_canary = external.join("canary");
    write_file(&external_canary, b"external-root\n", 0o600);
    let linked_root = fixture.workspace.join("linked-root");
    symlink(&external, &linked_root).expect("link staged root to external root");
    let before = std::fs::metadata(&external_canary).expect("external canary metadata");

    let error = match LocalDaemonOperations::open_staged(&linked_root) {
        Err(error) => error,
        Ok(_) => panic!("staged root symlink must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeRoot);
    let after = std::fs::metadata(&external_canary).expect("external metadata after refusal");
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(
        std::fs::read(&external_canary).expect("read external canary"),
        b"external-root\n"
    );
}

#[test]
fn opening_staged_root_never_follows_a_symlink_ancestor() {
    let fixture = Fixture::new("root-symlink-ancestor");
    let external_parent = fixture.workspace.join("external-parent");
    let external_root = external_parent.join("root");
    std::fs::create_dir_all(&external_root).expect("create external staged root");
    let external_canary = external_root.join("canary");
    write_file(&external_canary, b"external-root\n", 0o600);
    let linked_parent = fixture.workspace.join("linked-parent");
    symlink(&external_parent, &linked_parent).expect("link staged root ancestor");
    let supplied_root = linked_parent.join("root");
    let root_before = std::fs::metadata(&external_root).expect("external root metadata");
    let canary_before = std::fs::metadata(&external_canary).expect("external canary metadata");

    let error = match LocalDaemonOperations::open_staged(&supplied_root) {
        Err(error) => error,
        Ok(_) => panic!("staged root symlink ancestor must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeRoot);

    let root_after =
        std::fs::metadata(&external_root).expect("external root metadata after refusal");
    let canary_after =
        std::fs::metadata(&external_canary).expect("external canary metadata after refusal");
    assert_eq!(
        (root_before.dev(), root_before.ino()),
        (root_after.dev(), root_after.ino())
    );
    assert_eq!(
        (canary_before.dev(), canary_before.ino()),
        (canary_after.dev(), canary_after.ino())
    );
    assert_eq!(
        std::fs::read(&external_canary).expect("read external canary"),
        b"external-root\n"
    );
}

#[test]
fn opening_staged_root_rejects_parent_components_without_mutation() {
    let fixture = Fixture::new("root-parent-component");
    let detour = fixture.workspace.join("detour");
    std::fs::create_dir(&detour).expect("create detour directory");
    let supplied_root = detour.join("..").join("root");
    let canary = fixture.root.join("canary");
    write_file(&canary, b"staged-root\n", 0o600);
    let root_before = std::fs::metadata(&fixture.root).expect("staged root metadata");
    let canary_before = std::fs::metadata(&canary).expect("staged root canary metadata");

    let error = match LocalDaemonOperations::open_staged(&supplied_root) {
        Err(error) => error,
        Ok(_) => panic!("parent path component must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeRoot);

    let root_after = std::fs::metadata(&fixture.root).expect("staged root metadata after refusal");
    let canary_after = std::fs::metadata(&canary).expect("staged root canary after refusal");
    assert_eq!(
        (root_before.dev(), root_before.ino()),
        (root_after.dev(), root_after.ino())
    );
    assert_eq!(
        (canary_before.dev(), canary_before.ino()),
        (canary_after.dev(), canary_after.ino())
    );
    assert_eq!(
        std::fs::read(&canary).expect("read staged root canary"),
        b"staged-root\n"
    );
}

#[test]
fn staged_install_never_follows_a_bundle_root_symlink_ancestor() {
    let fixture = Fixture::new("bundle-root-symlink-ancestor");
    let bundle = fixture.bundle("v0.4.0");
    let external_parent = fixture.workspace.join("external-bundle-parent");
    std::fs::create_dir(&external_parent).expect("create external bundle parent");
    let external_bundle = external_parent.join("bundle");
    std::fs::rename(&bundle, &external_bundle).expect("move bundle under external parent");
    let external_canary = external_parent.join("canary");
    write_file(&external_canary, b"external-bundle\n", 0o600);
    let linked_parent = fixture.workspace.join("linked-bundle-parent");
    symlink(&external_parent, &linked_parent).expect("link bundle root ancestor");
    let supplied_bundle = linked_parent.join("bundle");
    let bundle_before = std::fs::metadata(&external_bundle).expect("external bundle metadata");
    let canary_before = std::fs::metadata(&external_canary).expect("external canary metadata");

    let operations = LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let error = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: supplied_bundle,
        })
        .expect_err("bundle root symlink ancestor must fail closed");
    assert_eq!(error.code(), LocalDaemonErrorCode::InvalidBundle);

    let bundle_after =
        std::fs::metadata(&external_bundle).expect("external bundle metadata after refusal");
    let canary_after =
        std::fs::metadata(&external_canary).expect("external canary metadata after refusal");
    assert_eq!(
        (bundle_before.dev(), bundle_before.ino()),
        (bundle_after.dev(), bundle_after.ino())
    );
    assert_eq!(
        (canary_before.dev(), canary_before.ino()),
        (canary_after.dev(), canary_after.ino())
    );
    assert_eq!(
        std::fs::read(&external_canary).expect("read external canary"),
        b"external-bundle\n"
    );
    for (_, _, target_path, _) in ARTIFACTS {
        assert!(
            !fixture.root.join(target_path).exists(),
            "refused bundle must not publish {target_path}"
        );
    }
}

#[test]
fn staged_install_never_follows_an_artifact_parent_symlink() {
    let fixture = Fixture::new("artifact-parent-symlink");
    let bundle = fixture.bundle("v0.4.0");
    let external_bin = fixture.workspace.join("external-bin");
    std::fs::rename(bundle.join("bin"), &external_bin).expect("move bundle binaries outside");
    let external_canary = external_bin.join("canary");
    write_file(&external_canary, b"external-artifact-parent\n", 0o600);
    symlink(&external_bin, bundle.join("bin")).expect("link artifact parent");
    let directory_before = std::fs::metadata(&external_bin).expect("external bin metadata");
    let canary_before = std::fs::metadata(&external_canary).expect("external canary metadata");

    let operations = LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let error = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect_err("artifact parent symlink must fail closed");
    assert_eq!(error.code(), LocalDaemonErrorCode::InvalidBundle);

    let directory_after =
        std::fs::metadata(&external_bin).expect("external bin metadata after refusal");
    let canary_after =
        std::fs::metadata(&external_canary).expect("external canary metadata after refusal");
    assert_eq!(
        (directory_before.dev(), directory_before.ino()),
        (directory_after.dev(), directory_after.ino())
    );
    assert_eq!(
        (canary_before.dev(), canary_before.ino()),
        (canary_after.dev(), canary_after.ino())
    );
    assert_eq!(
        std::fs::read(&external_canary).expect("read external canary"),
        b"external-artifact-parent\n"
    );
    for (_, _, target_path, _) in ARTIFACTS {
        assert!(
            !fixture.root.join(target_path).exists(),
            "refused artifact parent must not publish {target_path}"
        );
    }
}

#[test]
fn staged_install_never_follows_a_managed_parent_symlink() {
    let fixture = Fixture::new("managed-parent-symlink");
    let bundle = fixture.bundle("v0.4.0");
    let external_bin = fixture.workspace.join("external-target-bin");
    std::fs::create_dir(&external_bin).expect("create external target parent");
    let external_canary = external_bin.join("canary");
    write_file(&external_canary, b"external-target-parent\n", 0o600);
    let managed_local = fixture.root.join("usr/local");
    std::fs::create_dir_all(&managed_local).expect("create managed ancestor");
    symlink(&external_bin, managed_local.join("bin")).expect("link managed target parent");
    let directory_before = std::fs::metadata(&external_bin).expect("external bin metadata");
    let canary_before = std::fs::metadata(&external_canary).expect("external canary metadata");

    let error = match LocalDaemonOperations::open_staged(&fixture.root) {
        Err(error) => error,
        Ok(_) => panic!("managed parent symlink must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTarget);
    assert!(
        bundle.is_dir(),
        "refusal must not mutate the release bundle"
    );

    let directory_after =
        std::fs::metadata(&external_bin).expect("external bin metadata after refusal");
    let canary_after =
        std::fs::metadata(&external_canary).expect("external canary metadata after refusal");
    assert_eq!(
        (directory_before.dev(), directory_before.ino()),
        (directory_after.dev(), directory_after.ino())
    );
    assert_eq!(
        (canary_before.dev(), canary_before.ino()),
        (canary_after.dev(), canary_after.ino())
    );
    assert_eq!(
        std::fs::read(&external_canary).expect("read external canary"),
        b"external-target-parent\n"
    );
    for (_, _, target_path, _) in ARTIFACTS {
        assert!(
            !fixture.root.join(target_path).is_file(),
            "refused managed parent must not publish {target_path}"
        );
    }
}

#[test]
fn staged_operations_reject_a_world_writable_receipt() {
    let fixture = Fixture::new("writable-receipt");
    let bundle = fixture.bundle("v0.4.0");
    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect("plan staged install");
    operations.apply(plan).expect("apply staged install");

    let receipt = fixture
        .root
        .join("usr/local/lib/apolysis/install-receipt-v1.json");
    std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o666))
        .expect("make receipt unsafe");

    let error = operations
        .inspect()
        .expect_err("writable receipt must not prove managed ownership");
    assert_eq!(error.code(), LocalDaemonErrorCode::InvalidReceipt);
    for (_, _, target_path, _) in ARTIFACTS {
        assert!(
            fixture.root.join(target_path).is_file(),
            "refusing the receipt must not remove {target_path}"
        );
    }
}

#[test]
fn staged_operations_reject_setuid_bits_on_the_cli_target() {
    let fixture = Fixture::new("setuid-cli-target");
    let bundle = fixture.bundle("v0.4.0");
    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect("plan staged install");
    operations.apply(plan).expect("apply staged install");

    let cli = fixture.root.join("usr/local/bin/apolysis");
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o4755))
        .expect("set hostile setuid bit");

    let error = operations
        .inspect()
        .expect_err("setuid CLI must not match the installation receipt");
    assert_eq!(error.code(), LocalDaemonErrorCode::ManagedTargetChanged);
}

#[test]
fn equal_content_new_inode_target_is_not_receipt_owned() {
    let fixture = Fixture::new("equal-content-new-inode");
    let bundle = fixture.bundle("v0.4.0");
    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let install = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect("plan staged install");
    operations.apply(install).expect("apply staged install");

    let target = fixture.root.join("usr/local/bin/apolysis");
    let original = std::fs::metadata(&target).expect("original target metadata");
    let bytes = std::fs::read(&target).expect("read original target");
    let replacement = fixture.root.join("usr/local/bin/.operator-replacement");
    write_file(&replacement, &bytes, 0o755);
    let replacement_metadata =
        std::fs::metadata(&replacement).expect("replacement target metadata");
    assert_ne!(original.ino(), replacement_metadata.ino());
    std::fs::rename(&replacement, &target).expect("atomically replace managed target");

    let inspect_error = operations
        .inspect()
        .expect_err("same content on another inode must not remain receipt-owned");
    assert_eq!(
        inspect_error.code(),
        LocalDaemonErrorCode::ManagedTargetChanged
    );
    let uninstall_error = operations
        .plan(LocalDaemonChange::UninstallPreserveState)
        .expect_err("uninstall must refuse a replacement inode");
    assert_eq!(
        uninstall_error.code(),
        LocalDaemonErrorCode::ManagedTargetChanged
    );
    let after = std::fs::metadata(&target).expect("preserved replacement metadata");
    assert_eq!(
        (replacement_metadata.dev(), replacement_metadata.ino()),
        (after.dev(), after.ino())
    );
    assert_eq!(
        std::fs::read(&target).expect("read preserved target"),
        bytes
    );
}

#[test]
fn staged_operations_reject_setuid_bits_on_the_receipt() {
    let fixture = Fixture::new("setuid-receipt");
    let bundle = fixture.bundle("v0.4.0");
    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect("plan staged install");
    operations.apply(plan).expect("apply staged install");

    let receipt = fixture
        .root
        .join("usr/local/lib/apolysis/install-receipt-v1.json");
    std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o4644))
        .expect("set hostile setuid bit");

    let error = operations
        .inspect()
        .expect_err("setuid receipt must not prove managed ownership");
    assert_eq!(error.code(), LocalDaemonErrorCode::InvalidReceipt);
}

#[test]
fn staged_install_rejects_a_foreign_manifest_target_before_mutation() {
    let fixture = Fixture::new("foreign-target");
    let bundle = fixture.bundle("v0.4.0");
    let manifest_path = bundle.join("apolysis-release-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("read release manifest"))
            .expect("decode release manifest");
    let foreign_target = if std::env::consts::ARCH == "aarch64" {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-unknown-linux-gnu"
    };
    manifest["target"] = json!(foreign_target);
    write_file(
        &manifest_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).expect("encode foreign manifest")
        )
        .as_bytes(),
        0o644,
    );

    let operations = LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let error = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect_err("foreign target must fail before mutation");
    assert_eq!(error.code(), LocalDaemonErrorCode::InvalidBundle);
    for (_, _, target_path, _) in ARTIFACTS {
        assert!(!fixture.root.join(target_path).exists());
    }
}

#[test]
fn staged_operations_reject_a_receipt_claiming_another_installer_owner() {
    let fixture = Fixture::new("foreign-receipt-owner");
    let bundle = fixture.bundle("v0.4.0");
    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle,
        })
        .expect("plan staged install");
    operations.apply(plan).expect("apply staged install");

    let receipt_path = fixture
        .root
        .join("usr/local/lib/apolysis/install-receipt-v1.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("read receipt"))
            .expect("decode receipt");
    let claimed_uid = receipt["installer_uid"]
        .as_u64()
        .expect("receipt installer uid")
        .wrapping_add(1);
    receipt["installer_uid"] = json!(claimed_uid);
    write_file(
        &receipt_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&receipt).expect("encode altered receipt")
        )
        .as_bytes(),
        0o644,
    );

    let error = operations
        .inspect()
        .expect_err("foreign installer identity must not prove ownership");
    assert_eq!(error.code(), LocalDaemonErrorCode::InvalidReceipt);
}

#[test]
fn opening_staged_root_refuses_an_unknown_transaction_sibling() {
    let fixture = Fixture::new("unknown-transaction-sibling");
    let sibling = fixture
        .root
        .join("usr/local/bin/.apolysis-install-foreign-apolysis");
    write_file(&sibling, b"operator-canary\n", 0o600);

    let error = match LocalDaemonOperations::open_staged(&fixture.root) {
        Err(error) => error,
        Ok(_) => panic!("unknown transaction sibling must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
    assert_eq!(
        std::fs::read(&sibling).expect("read unknown transaction sibling"),
        b"operator-canary\n"
    );
}

#[test]
fn opening_staged_root_refuses_a_changed_journal_without_mutation() {
    let fixture = Fixture::new("changed-transaction-journal");
    let journal = fixture
        .root
        .join("usr/local/lib/apolysis/.local-operation-transaction-v1.json");
    let canary = fixture.root.join("usr/local/bin/operator-canary");
    write_file(&journal, b"{\"phase\":\"tampered\"}\n", 0o600);
    write_file(&canary, b"operator-canary\n", 0o755);
    let before = std::fs::metadata(&canary).expect("canary metadata");

    let error = match LocalDaemonOperations::open_staged(&fixture.root) {
        Err(error) => error,
        Ok(_) => panic!("changed transaction journal must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
    let after = std::fs::metadata(&canary).expect("canary metadata after refusal");
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(
        std::fs::read(&journal).expect("read changed journal"),
        b"{\"phase\":\"tampered\"}\n"
    );
    assert_eq!(
        std::fs::read(&canary).expect("read canary"),
        b"operator-canary\n"
    );
}

#[test]
fn durable_precommit_rejects_a_null_new_identity_without_deleting_a_canary() {
    let fixture = Fixture::new("null-new-identity-journal");
    let canary = fixture.root.join("usr/local/bin/apolysis");
    let canary_bytes = b"equal-content-operator-canary\n";
    write_file(&canary, canary_bytes, 0o755);
    let canary_before = std::fs::metadata(&canary).expect("canary metadata");
    let root_metadata = std::fs::metadata(&fixture.root).expect("root metadata");
    let operation_id = "999-1";
    let journal_value = json!({
        "schema_version": 1,
        "phase": "precommit",
        "operation": "install",
        "operation_id": operation_id,
        "root_identity": {
            "device": root_metadata.dev(),
            "inode": root_metadata.ino(),
        },
        "installer_uid": root_metadata.uid(),
        "installer_gid": root_metadata.gid(),
        "entries": [{
            "logical_name": "cli_binary",
            "target_path": "usr/local/bin/apolysis",
            "temporary_name": format!(".apolysis-install-{operation_id}-apolysis"),
            "old": null,
            "new": {
                "identity": null,
                "len": canary_bytes.len(),
                "mode": 0o755,
                "uid": canary_before.uid(),
                "gid": canary_before.gid(),
                "sha256": hex_sha256(canary_bytes),
            },
        }],
    });
    let journal = fixture
        .root
        .join("usr/local/lib/apolysis/.local-operation-transaction-v1.json");
    write_file(
        &journal,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&journal_value).expect("serialize forged journal")
        )
        .as_bytes(),
        0o600,
    );

    let error = match LocalDaemonOperations::open_staged(&fixture.root) {
        Err(error) => error,
        Ok(_) => panic!("durable null identity must fail closed"),
    };
    assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
    let canary_after = std::fs::metadata(&canary).expect("preserved canary metadata");
    assert_eq!(
        (canary_before.dev(), canary_before.ino()),
        (canary_after.dev(), canary_after.ino())
    );
    assert_eq!(
        std::fs::read(&canary).expect("read preserved canary"),
        canary_bytes
    );
    assert!(
        journal.is_file(),
        "unsafe journal evidence must be retained"
    );
}

#[test]
fn staged_install_rejects_a_source_snapshot_replaced_after_planning() {
    let fixture = Fixture::new("stale-source");
    let bundle = fixture.bundle("v0.4.0");
    let mut operations =
        LocalDaemonOperations::open_staged(&fixture.root).expect("open staged root");
    let plan = operations
        .plan(LocalDaemonChange::Install {
            bundle_root: bundle.clone(),
        })
        .expect("plan staged install");

    let source = bundle.join("bin/apolysisd");
    let replacement = bundle.join("bin/.replacement-apolysisd");
    let bytes = std::fs::read(&source).expect("read planned source");
    write_file(&replacement, &bytes, 0o755);
    std::fs::rename(&replacement, &source).expect("replace source with equal bytes");

    let error = operations
        .apply(plan)
        .expect_err("source identity change must stale the plan");
    assert_eq!(error.code(), LocalDaemonErrorCode::StalePlan);
    for (_, _, target_path, _) in ARTIFACTS {
        assert!(
            !fixture.root.join(target_path).exists(),
            "stale plan must not publish {target_path}"
        );
    }
}

struct Fixture {
    workspace: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let workspace = std::env::temp_dir().join(format!(
            "apolysis-local-operations-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let root = workspace.join("root");
        std::fs::create_dir_all(&root).expect("create staged root");
        Self { workspace, root }
    }

    fn bundle(&self, release_version: &str) -> PathBuf {
        let bundle = self.workspace.join("bundle");
        let mut artifacts = Vec::new();
        for (path, kind, _, mode) in ARTIFACTS {
            let bytes = format!("fixture:{kind}\n").into_bytes();
            let artifact = bundle.join(path);
            write_file(&artifact, &bytes, mode);
            artifacts.push(json!({
                "path": path,
                "kind": kind,
                "sha256": hex_sha256(&bytes),
                "size_bytes": bytes.len(),
                "mode": format!("{mode:04o}"),
            }));
        }
        let manifest = json!({
            "schema_version": 2,
            "release_version": release_version,
            "target": format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
            "artifacts": artifacts,
        });
        write_file(
            &bundle.join("apolysis-release-manifest.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&manifest).expect("serialize manifest")
            )
            .as_bytes(),
            0o644,
        );
        bundle
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.workspace);
    }
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::create_dir_all(path.parent().expect("file parent")).expect("create file parent");
    std::fs::write(path, bytes).expect("write fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set fixture mode");
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

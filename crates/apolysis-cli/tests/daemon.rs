// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;
use sha2::{Digest, Sha256};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

const ARTIFACTS: [(&str, &str, u32); 5] = [
    ("bin/apolysis", "cli_binary", 0o755),
    ("bin/apolysisd", "daemon_binary", 0o755),
    ("bin/apolysisd-health", "health_binary", 0o755),
    ("ebpf/apolysis_observer.bpf.o", "core_bpf_object", 0o644),
    ("systemd/apolysisd.service", "systemd_unit", 0o644),
];

#[test]
fn daemon_commands_install_inspect_and_uninstall_an_alternate_root() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let timeline = fixture
        .root
        .join("var/lib/apolysis/sessions/run-keep/timeline.jsonl");
    write_file(&timeline, b"retained\n", 0o640);

    let install = apolysis(&[
        "daemon",
        "install",
        "--bundle",
        bundle.to_str().expect("bundle path"),
        "--root",
        fixture.root.to_str().expect("root path"),
    ]);
    assert_success(&install, "daemon install");
    let install: serde_json::Value = serde_json::from_slice(&install.stdout).expect("install JSON");
    assert_eq!(install["operation"], "install");
    assert_eq!(install["installed"], true);
    assert_eq!(install["recovered_interrupted_operation"], false);
    assert_eq!(install["systemd_activated"], false);

    let inspect = apolysis(&[
        "daemon",
        "inspect",
        "--root",
        fixture.root.to_str().expect("root path"),
    ]);
    assert_success(&inspect, "daemon inspect");
    let inspect: serde_json::Value = serde_json::from_slice(&inspect.stdout).expect("inspect JSON");
    assert_eq!(inspect["operation"], "inspect");
    assert_eq!(inspect["installed"], true);
    assert_eq!(inspect["release_version"], "v0.4.0-test");
    assert_eq!(inspect["recovered_interrupted_operation"], false);

    let uninstall = apolysis(&[
        "daemon",
        "uninstall",
        "--root",
        fixture.root.to_str().expect("root path"),
    ]);
    assert_success(&uninstall, "daemon uninstall");
    let uninstall: serde_json::Value =
        serde_json::from_slice(&uninstall.stdout).expect("uninstall JSON");
    assert_eq!(uninstall["operation"], "uninstall");
    assert_eq!(uninstall["agent_run_state_preserved"], true);
    assert_eq!(uninstall["recovered_interrupted_operation"], false);
    assert_eq!(
        std::fs::read(timeline).expect("retained Agent Run"),
        b"retained\n"
    );
}

fn apolysis(args: &[&str]) -> std::process::Output {
    let binary = std::env::var("CARGO_BIN_EXE_apolysis").expect("apolysis test binary path");
    std::process::Command::new(binary)
        .args(args)
        .output()
        .expect("run apolysis")
}

fn assert_success(output: &std::process::Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Fixture {
    workspace: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let workspace =
            std::env::temp_dir().join(format!("apolysis-cli-daemon-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&workspace);
        let root = workspace.join("root");
        std::fs::create_dir_all(&root).expect("create alternate root");
        Self { workspace, root }
    }

    fn bundle(&self) -> PathBuf {
        let bundle = self.workspace.join("bundle");
        let mut artifacts = Vec::new();
        for (path, kind, mode) in ARTIFACTS {
            let bytes = format!("fixture:{kind}\n").into_bytes();
            write_file(&bundle.join(path), &bytes, mode);
            artifacts.push(json!({
                "path": path,
                "kind": kind,
                "sha256": sha256_hex(&bytes),
                "size_bytes": bytes.len(),
                "mode": format!("{mode:04o}"),
            }));
        }
        let manifest = json!({
            "schema_version": 2,
            "release_version": "v0.4.0-test",
            "target": "x86_64-unknown-linux-gnu",
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

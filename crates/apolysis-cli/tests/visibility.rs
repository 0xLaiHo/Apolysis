// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn visibility_command_records_kata_guest_collector_decision() {
    let output = temp_jsonl("apolysis-visibility-kata");
    let _ = std::fs::remove_file(&output);

    let status = apolysis_command()
        .args([
            "visibility",
            "--scenario",
            "kubernetes-kata",
            "--input",
            "tests/fixtures/visibility/kubernetes-kata-host-events.txt",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--kubernetes-metadata",
            "tests/fixtures/kubernetes/agent-sandbox-kata-pod.yaml",
        ])
        .status()
        .expect("run apolysis visibility");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read visibility output");
    assert!(timeline.contains(r#""record_type":"visibility_assessment""#));
    assert!(timeline.contains(r#""runtime_profile":"kubernetes-kata""#));
    assert!(timeline.contains(r#""host_visibility_scope":"boundary_only""#));
    assert!(timeline.contains(r#""host_semantics_collapsed":true"#));
    assert!(timeline.contains(r#""guest_collector_required":true"#));
    assert!(timeline.contains(r#""runtime_metadata_required":true"#));
    assert!(timeline.contains(r#""pod_name":"kata-session-9""#));
    assert!(timeline.contains(r#""namespace":"agents""#));
    assert!(timeline.contains(r#""runtime_class_name":"kata-qemu""#));

    let _ = std::fs::remove_file(&output);
}

fn apolysis_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
    command.current_dir(workspace_root());
    command
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn temp_jsonl(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}.jsonl", std::process::id()))
}

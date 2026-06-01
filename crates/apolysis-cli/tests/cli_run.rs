// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn run_command_writes_a_jsonl_timeline() {
    let output =
        std::env::temp_dir().join(format!("apolysis-cli-run-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&output);

    let status = Command::new(env!("CARGO_BIN_EXE_apolysis"))
        .args([
            "run",
            "--policy",
            "policies/local-dev.yaml",
            "--output",
            output.to_str().expect("utf-8 output path"),
            "--",
            "echo",
            "hello",
        ])
        .status()
        .expect("run apolysis CLI");

    assert!(status.success());
    let timeline = std::fs::read_to_string(&output).expect("read timeline");
    assert!(timeline.contains(r#""event_type":"session_started""#));
    assert!(timeline.contains(r#""event_type":"exec""#));
    assert!(timeline.contains(r#""event_type":"process_exit""#));
    assert!(timeline.contains(r#""actor":"echo hello""#));

    let _ = std::fs::remove_file(&output);
}

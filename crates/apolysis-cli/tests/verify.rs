// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::process::Command;

use apolysis_store::HashChainStore;

#[test]
fn verify_hash_chain_command_reports_valid_timeline() {
    let timeline = temp_jsonl("apolysis-verify-hash-chain-valid");
    let report_path = temp_jsonl("apolysis-verify-hash-chain-valid-report");
    let _ = std::fs::remove_file(&timeline);
    let _ = std::fs::remove_file(&report_path);
    {
        let mut store = HashChainStore::create_or_recover(&timeline)
            .expect("create hash chain")
            .store;
        store
            .append_json(1, r#"{"record_type":"event","session_id":"verify-valid"}"#)
            .expect("append first record");
        store
            .append_json(
                1,
                r#"{"record_type":"event","session_id":"verify-valid","index":2}"#,
            )
            .expect("append second record");
        store.flush().expect("flush hash chain");
    }

    let status = apolysis_command()
        .args([
            "verify",
            "hash-chain",
            "--input",
            timeline.to_str().expect("utf-8 timeline path"),
            "--output",
            report_path.to_str().expect("utf-8 report path"),
        ])
        .status()
        .expect("run apolysis verify hash-chain");

    assert!(status.success());
    let report = read_report(&report_path);
    assert_eq!(report["passed"], true);
    assert_eq!(report["record_count"], 2);
    assert_eq!(report["last_sequence"], 2);
    assert!(report["failure"].is_null());

    let _ = std::fs::remove_file(&timeline);
    let _ = std::fs::remove_file(&report_path);
}

#[test]
fn verify_hash_chain_command_reports_invalid_tail_without_mutating_timeline() {
    let timeline = temp_jsonl("apolysis-verify-hash-chain-invalid");
    let report_path = temp_jsonl("apolysis-verify-hash-chain-invalid-report");
    let _ = std::fs::remove_file(&timeline);
    let _ = std::fs::remove_file(&report_path);
    {
        let mut store = HashChainStore::create_or_recover(&timeline)
            .expect("create hash chain")
            .store;
        store
            .append_json(
                1,
                r#"{"record_type":"event","session_id":"verify-invalid"}"#,
            )
            .expect("append record");
        store.flush().expect("flush hash chain");
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&timeline)
        .expect("open timeline")
        .write_all(br#"{"schema_version":1"#)
        .expect("append invalid tail");
    let before = std::fs::read_to_string(&timeline).expect("read before verify");

    let output = apolysis_command()
        .args([
            "verify",
            "hash-chain",
            "--input",
            timeline.to_str().expect("utf-8 timeline path"),
            "--output",
            report_path.to_str().expect("utf-8 report path"),
        ])
        .output()
        .expect("run apolysis verify hash-chain");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        std::fs::read_to_string(&timeline).expect("read after verify"),
        before
    );
    let report = read_report(&report_path);
    assert_eq!(report["passed"], false);
    assert_eq!(report["record_count"], 1);
    assert_eq!(report["last_sequence"], 1);
    assert!(
        report["failure"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid or truncated tail"),
        "{report}"
    );
    let quarantine_matches = std::fs::read_dir(timeline.parent().unwrap())
        .expect("read temp dir")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("apolysis-verify-hash-chain-invalid")
                && entry.file_name().to_string_lossy().contains(".quarantine-")
        })
        .count();
    assert_eq!(quarantine_matches, 0, "verify must be read-only");

    let _ = std::fs::remove_file(&timeline);
    let _ = std::fs::remove_file(&report_path);
}

fn read_report(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read report"))
        .expect("parse report")
}

fn apolysis_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apolysis"));
    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command
}

fn temp_jsonl(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{name}-{}.jsonl", std::process::id()))
}

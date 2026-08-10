// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_store::{
    read_agent_run_records, HashChainStore, LocalRecordFormat, LocalRecordReadError,
    MAX_SAVED_RUN_BYTES, MAX_SAVED_RUN_LINE_BYTES,
};
use serde_json::json;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn plain_rotated_run_reads_oldest_archive_before_the_active_file() {
    let root = temp_root("plain-rotation");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let active = root.join("timeline.jsonl");
    std::fs::write(
        root.join("timeline.jsonl.2"),
        "{\"record_type\":\"event\",\"ordinal\":1}\n",
    )
    .expect("write oldest archive");
    std::fs::write(
        root.join("timeline.jsonl.1"),
        "{\"record_type\":\"event\",\"ordinal\":2}\n",
    )
    .expect("write newest archive");
    std::fs::write(&active, "{\"record_type\":\"event\",\"ordinal\":3}\n")
        .expect("write active file");

    let batch = read_agent_run_records(&active).expect("read rotated run");
    assert_eq!(
        json!({
            "format": format!("{:?}", batch.format),
            "source_files": batch.source_files,
            "source_bytes": batch.source_bytes,
            "ordinals": batch
                .records
                .iter()
                .map(|record| record["ordinal"].clone())
                .collect::<Vec<_>>()
        }),
        json!({
            "format": format!("{:?}", LocalRecordFormat::PlainJsonl),
            "source_files": 3,
            "source_bytes": 108,
            "ordinals": [1, 2, 3]
        })
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn valid_hash_chain_is_verified_before_payloads_are_exposed() {
    let root = temp_root("valid-hash-chain");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let path = root.join("timeline.jsonl");
    let mut store = HashChainStore::create_or_recover(&path)
        .expect("create chain")
        .store;
    store
        .append_json(1, r#"{"record_type":"event","ordinal":1}"#)
        .expect("append first payload");
    store
        .append_json(1, r#"{"record_type":"event","ordinal":2}"#)
        .expect("append second payload");
    store.flush().expect("flush chain");
    drop(store);

    let batch = read_agent_run_records(&path).expect("read verified hash chain");
    assert_eq!(
        json!({
            "format": format!("{:?}", batch.format),
            "source_files": batch.source_files,
            "ordinals": batch
                .records
                .iter()
                .map(|record| record["ordinal"].clone())
                .collect::<Vec<_>>()
        }),
        json!({
            "format": format!("{:?}", LocalRecordFormat::VerifiedHashChain),
            "source_files": 1,
            "ordinals": [1, 2]
        })
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn tampered_hash_chain_exposes_no_payloads() {
    let root = temp_root("tampered-hash-chain");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let path = root.join("timeline.jsonl");
    let mut store = HashChainStore::create_or_recover(&path)
        .expect("create chain")
        .store;
    store
        .append_json(1, r#"{"record_type":"event","ordinal":1}"#)
        .expect("append first payload");
    store
        .append_json(1, r#"{"record_type":"event","ordinal":2}"#)
        .expect("append second payload");
    store.flush().expect("flush chain");
    drop(store);
    let original = std::fs::read_to_string(&path).expect("read chain");
    std::fs::write(
        &path,
        original.replacen("\"ordinal\":2", "\"ordinal\":9", 1),
    )
    .expect("tamper payload");

    assert_eq!(
        read_agent_run_records(&path).expect_err("tampered chain must fail closed"),
        LocalRecordReadError::HashChainIntegrity { sequence: Some(2) }
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn truncated_plain_jsonl_tail_fails_closed() {
    let root = temp_root("truncated-plain");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let path = root.join("timeline.jsonl");
    std::fs::write(
        &path,
        br#"{"record_type":"event","private":"APOLYSIS_STORE_SECRET"}"#,
    )
    .expect("write truncated input");

    let error = read_agent_run_records(&path).expect_err("truncated input must fail closed");
    assert_eq!(
        error,
        LocalRecordReadError::TruncatedJsonlTail { segment: 0 }
    );
    assert!(!error.to_string().contains("APOLYSIS_STORE_SECRET"));

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[cfg(unix)]
#[test]
fn symlink_input_is_refused() {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let target = root.join("target.jsonl");
    let path = root.join("timeline.jsonl");
    std::fs::write(&target, "{\"record_type\":\"event\"}\n").expect("write target");
    symlink(&target, &path).expect("create symlink");

    assert_eq!(
        read_agent_run_records(&path).expect_err("symlink input must fail closed"),
        LocalRecordReadError::SymlinkRefused { segment: 0 }
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn missing_rotation_index_is_refused() {
    let root = temp_root("missing-rotation");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let path = root.join("timeline.jsonl");
    std::fs::write(
        root.join("timeline.jsonl.2"),
        "{\"record_type\":\"event\"}\n",
    )
    .expect("write non-contiguous archive");
    std::fs::write(&path, "{\"record_type\":\"event\"}\n").expect("write active file");

    assert_eq!(
        read_agent_run_records(&path).expect_err("rotation gap must fail closed"),
        LocalRecordReadError::RotationSetInvalid
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn oversized_sparse_input_is_rejected_before_materializing_it() {
    let root = temp_root("oversized-total");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let path = root.join("timeline.jsonl");
    let file = std::fs::File::create(&path).expect("create sparse input");
    file.set_len(MAX_SAVED_RUN_BYTES + 1)
        .expect("extend sparse input");

    assert_eq!(
        read_agent_run_records(&path).expect_err("oversized input must fail closed"),
        LocalRecordReadError::InputLimitExceeded {
            limit: "the total byte limit"
        }
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

#[test]
fn every_hash_chain_envelope_obeys_the_line_limit() {
    let root = temp_root("hash-chain-line-limit");
    std::fs::create_dir_all(&root).expect("create fixture root");
    let path = root.join("timeline.jsonl");
    let mut store = HashChainStore::create_or_recover(&path)
        .expect("create chain")
        .store;
    store
        .append_json(1, r#"{"record_type":"event","ordinal":1}"#)
        .expect("append first payload");
    let oversized_payload = format!(
        "{{\"record_type\":\"event\",\"padding\":\"{}\"}}",
        "x".repeat(MAX_SAVED_RUN_LINE_BYTES)
    );
    store
        .append_json(1, &oversized_payload)
        .expect("append oversized second payload");
    store.flush().expect("flush chain");
    drop(store);

    assert_eq!(
        read_agent_run_records(&path).expect_err("oversized envelope must fail closed"),
        LocalRecordReadError::InputLimitExceeded {
            limit: "the line byte limit"
        }
    );

    std::fs::remove_dir_all(root).expect("remove fixture root");
}

fn temp_root(name: &str) -> std::path::PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "apolysis-saved-run-input-{name}-{}-{id}",
        std::process::id()
    ))
}

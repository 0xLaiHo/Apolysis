// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_store::{HashChainStore, StoreError, ZERO_HASH};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn hashes_are_deterministic_and_sequences_are_chained() {
    let path_a = temp_path("deterministic-a");
    let path_b = temp_path("deterministic-b");
    let mut a = HashChainStore::create_or_recover(&path_a)
        .expect("create a")
        .store;
    let mut b = HashChainStore::create_or_recover(&path_b)
        .expect("create b")
        .store;

    let first_a = a.append_json(1, r#"{"type":"finding","id":1}"#).unwrap();
    let first_b = b.append_json(1, r#"{"type":"finding","id":1}"#).unwrap();
    let second = a.append_json(1, r#"{"type":"finding","id":2}"#).unwrap();
    a.flush().unwrap();
    b.flush().unwrap();

    assert_eq!(first_a.record_hash, first_b.record_hash);
    assert_eq!(first_a.sequence, 1);
    assert_eq!(first_a.previous_hash, ZERO_HASH);
    assert_eq!(second.sequence, 2);
    assert_eq!(second.previous_hash, first_a.record_hash);

    cleanup(&[path_a, path_b]);
}

#[test]
fn restart_continues_from_the_last_valid_record() {
    let path = temp_path("restart");
    let previous_hash = {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        let record = store.append_json(1, r#"{"type":"event"}"#).unwrap();
        store.flush().unwrap();
        record.record_hash
    };

    let recovery = HashChainStore::create_or_recover(&path).expect("recover");
    assert_eq!(recovery.next_sequence, 2);
    assert_eq!(recovery.previous_hash, previous_hash);
    assert!(recovery.quarantined_path.is_none());

    cleanup(&[path]);
}

#[test]
fn truncated_tail_is_quarantined_and_valid_prefix_is_preserved() {
    let path = temp_path("truncated");
    {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        store.append_json(1, r#"{"type":"event"}"#).unwrap();
        store.flush().unwrap();
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1"#)
        .unwrap();

    let recovery = HashChainStore::create_or_recover(&path).expect("recover tail");
    let quarantine = recovery
        .quarantined_path
        .clone()
        .expect("quarantine path");
    assert_eq!(recovery.next_sequence, 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    assert_eq!(
        std::fs::read_to_string(&quarantine).unwrap(),
        r#"{"schema_version":1"#
    );

    cleanup(&[path, quarantine]);
}

#[test]
fn corrupt_final_record_is_quarantined() {
    let path = temp_path("corrupt-tail");
    {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        store.append_json(1, r#"{"type":"first"}"#).unwrap();
        store.append_json(1, r#"{"type":"second"}"#).unwrap();
        store.flush().unwrap();
    }
    corrupt_record_hash(&path, 1);

    let recovery = HashChainStore::create_or_recover(&path).expect("recover final record");
    assert_eq!(recovery.next_sequence, 2);
    assert!(recovery.quarantined_path.is_some());
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);

    let quarantine = recovery.quarantined_path.unwrap();
    cleanup(&[path, quarantine]);
}

#[test]
fn corruption_before_a_later_record_fails_closed() {
    let path = temp_path("corrupt-middle");
    {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        store.append_json(1, r#"{"type":"first"}"#).unwrap();
        store.append_json(1, r#"{"type":"second"}"#).unwrap();
        store.append_json(1, r#"{"type":"third"}"#).unwrap();
        store.flush().unwrap();
    }
    corrupt_record_hash(&path, 1);

    let error = HashChainStore::create_or_recover(&path)
        .expect_err("middle corruption must fail closed");
    assert!(matches!(
        error,
        StoreError::Integrity {
            sequence: Some(2),
            ..
        }
    ));

    cleanup(&[path]);
}

fn corrupt_record_hash(path: &std::path::Path, line_index: usize) {
    let input = std::fs::read_to_string(path).unwrap();
    let mut lines: Vec<String> = input.lines().map(ToString::to_string).collect();
    let marker = r#""record_hash":""#;
    let start = lines[line_index].find(marker).unwrap() + marker.len();
    let replacement = if &lines[line_index][start..start + 1] == "f" {
        "e"
    } else {
        "f"
    };
    lines[line_index].replace_range(start..start + 1, replacement);
    std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "apolysis-hash-chain-{name}-{}-{}.jsonl",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn cleanup(paths: &[std::path::PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

use std::io::Write;

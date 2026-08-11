// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_store::{HashChainStore, StoreError, ZERO_HASH};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[test]
fn recovery_refuses_a_timeline_symlink_without_touching_its_target() {
    let external = temp_path("symlink-external");
    let timeline = temp_path("symlink-timeline");
    {
        let mut store = HashChainStore::create_or_recover(&external)
            .expect("create external fixture")
            .store;
        store
            .append_json(1, r#"{"type":"external"}"#)
            .expect("append external fixture");
        store.flush().expect("flush external fixture");
    }
    let before = std::fs::read(&external).expect("read external before refusal");
    symlink(&external, &timeline).expect("create timeline symlink");

    let error = HashChainStore::create_or_recover(&timeline)
        .expect_err("recovery must not follow a timeline symlink");

    assert!(matches!(error, StoreError::Io(_)));
    assert_eq!(
        std::fs::read(&external).expect("read external after refusal"),
        before
    );
    assert!(std::fs::symlink_metadata(&timeline)
        .expect("timeline symlink remains")
        .file_type()
        .is_symlink());

    cleanup(&[timeline, external]);
}

#[test]
fn recovery_refuses_a_multiply_linked_timeline_without_unlinking_external_data() {
    let external = temp_path("hardlink-external");
    let timeline = temp_path("hardlink-timeline");
    {
        let mut store = HashChainStore::create_or_recover(&external)
            .expect("create external fixture")
            .store;
        store
            .append_json(1, r#"{"type":"external"}"#)
            .expect("append external fixture");
        store.flush().expect("flush external fixture");
    }
    std::fs::hard_link(&external, &timeline).expect("create timeline hard link");
    let before = std::fs::metadata(&external).expect("external metadata before refusal");
    let bytes = std::fs::read(&external).expect("external bytes before refusal");

    let error = HashChainStore::create_or_recover(&timeline)
        .expect_err("recovery must not adopt a multiply linked timeline");

    assert!(matches!(error, StoreError::Io(_)));
    let after = std::fs::metadata(&external).expect("external metadata after refusal");
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.nlink(), 2);
    assert_eq!(std::fs::read(&external).expect("external bytes"), bytes);

    cleanup(&[timeline, external]);
}

#[test]
fn a_new_timeline_is_not_group_writable_or_world_readable() {
    let timeline = temp_path("private-mode");

    drop(
        HashChainStore::create_or_recover(&timeline)
            .expect("create private timeline")
            .store,
    );

    let mode = std::fs::metadata(&timeline)
        .expect("timeline metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640);

    cleanup(&[timeline]);
}

#[test]
fn a_new_timeline_parent_is_private() {
    let root = temp_path("private-parent-root");
    let timeline = root.join("agent-run/timeline.jsonl");

    drop(
        HashChainStore::create_or_recover(&timeline)
            .expect("create timeline and parent")
            .store,
    );

    let mode = std::fs::metadata(timeline.parent().expect("timeline parent"))
        .expect("timeline parent metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o750);

    std::fs::remove_dir_all(root).expect("remove private parent fixture");
}

#[test]
fn an_open_store_refuses_to_write_after_its_timeline_path_is_replaced() {
    let timeline = temp_path("replaced-open-timeline");
    let retired = temp_path("replaced-open-retired");
    let mut store = HashChainStore::create_or_recover(&timeline)
        .expect("create timeline")
        .store;
    store
        .append_json(1, r#"{"type":"before"}"#)
        .expect("append before replacement");
    store.flush().expect("flush before replacement");
    std::fs::rename(&timeline, &retired).expect("retire open timeline path");
    std::fs::write(&timeline, b"operator-owned replacement\n").expect("write replacement");

    let error = store
        .append_json(1, r#"{"type":"after"}"#)
        .expect_err("open store must reject a replacement path");

    assert!(matches!(error, StoreError::Io(_)));
    assert_eq!(
        std::fs::read(&timeline).expect("read replacement"),
        b"operator-owned replacement\n"
    );
    drop(store);
    cleanup(&[timeline, retired]);
}

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
    let quarantine = recovery.quarantined_path.clone().expect("quarantine path");
    assert_eq!(recovery.next_sequence, 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    assert_eq!(
        std::fs::read_to_string(&quarantine).unwrap(),
        r#"{"schema_version":1"#
    );
    let quarantine_metadata = std::fs::metadata(&quarantine).expect("quarantine metadata");
    assert_eq!(quarantine_metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(quarantine_metadata.nlink(), 1);

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

    let error =
        HashChainStore::create_or_recover(&path).expect_err("middle corruption must fail closed");
    assert!(matches!(
        error,
        StoreError::Integrity {
            sequence: Some(2),
            ..
        }
    ));

    cleanup(&[path]);
}

#[test]
fn offline_verification_reports_valid_hash_chain_without_mutating_file() {
    let path = temp_path("verify-valid");
    let original = {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        store.append_json(1, r#"{"type":"first"}"#).unwrap();
        let last = store.append_json(1, r#"{"type":"second"}"#).unwrap();
        store.flush().unwrap();
        assert_ne!(last.record_hash, ZERO_HASH);
        std::fs::read_to_string(&path).expect("read original")
    };

    let report = HashChainStore::verify(&path).expect("verify valid chain");
    assert!(report.passed, "{report:?}");
    assert_eq!(report.record_count, 2);
    assert_eq!(report.last_sequence, 2);
    assert_ne!(report.last_record_hash, ZERO_HASH);
    assert_eq!(report.valid_bytes, report.total_bytes);
    assert!(report.failure.is_none());
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after verification"),
        original
    );

    cleanup(&[path]);
}

#[test]
fn offline_verification_reports_truncated_tail_without_quarantine_mutation() {
    let path = temp_path("verify-truncated");
    let original_prefix = {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        store.append_json(1, r#"{"type":"first"}"#).unwrap();
        store.flush().unwrap();
        std::fs::read_to_string(&path).expect("read original prefix")
    };
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1"#)
        .unwrap();
    let with_tail = std::fs::read_to_string(&path).expect("read appended tail");

    let report = HashChainStore::verify(&path).expect("verify truncated chain");
    assert!(!report.passed, "{report:?}");
    assert_eq!(report.record_count, 1);
    assert_eq!(report.last_sequence, 1);
    assert!(report.valid_bytes < report.total_bytes);
    assert!(
        report
            .failure
            .as_deref()
            .unwrap_or_default()
            .contains("invalid or truncated tail"),
        "{report:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after verification"),
        with_tail
    );
    assert_eq!(
        std::fs::read_to_string(&path)
            .expect("read after verification")
            .trim_end_matches(r#"{"schema_version":1"#),
        original_prefix
    );
    let quarantine_matches = std::fs::read_dir(path.parent().unwrap())
        .expect("read temp dir")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("verify-truncated")
                && entry.file_name().to_string_lossy().contains(".quarantine-")
        })
        .count();
    assert_eq!(quarantine_matches, 0, "verify must be read-only");

    cleanup(&[path]);
}

#[test]
fn offline_verification_reports_valid_prefix_before_middle_corruption() {
    let path = temp_path("verify-middle-corruption");
    {
        let mut store = HashChainStore::create_or_recover(&path)
            .expect("create")
            .store;
        store.append_json(1, r#"{"type":"first"}"#).unwrap();
        store.append_json(1, r#"{"type":"second"}"#).unwrap();
        store.append_json(1, r#"{"type":"third"}"#).unwrap();
        store.flush().unwrap();
    }
    let first_line_bytes = std::fs::read_to_string(&path)
        .expect("read original")
        .lines()
        .next()
        .expect("first line")
        .len()
        + 1;
    corrupt_record_hash(&path, 1);
    let before = std::fs::read_to_string(&path).expect("read before verification");

    let report = HashChainStore::verify(&path).expect("verify corrupted chain");
    assert!(!report.passed, "{report:?}");
    assert_eq!(report.record_count, 1);
    assert_eq!(report.last_sequence, 1);
    assert_eq!(report.valid_bytes, first_line_bytes as u64);
    assert!(report.total_bytes > report.valid_bytes);
    assert!(
        report
            .failure
            .as_deref()
            .unwrap_or_default()
            .contains("hash-chain integrity failure"),
        "{report:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after verification"),
        before
    );

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

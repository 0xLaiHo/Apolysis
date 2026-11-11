// SPDX-License-Identifier: Apache-2.0

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use apolysis_core::SessionIntentReasonRecord;
use apolysis_store::{append_intent_reason, parse_intent_reason, IntentAppendOutcome};

fn record(reason_id: &str) -> SessionIntentReasonRecord {
    SessionIntentReasonRecord {
        timestamp_unix_ms: 42,
        session_id: "capture".into(),
        intent_id: "0123456789abcdef0123456789abcdef".into(),
        intent_source: "codex".into(),
        harness_session_id: "native".into(),
        source_event_id: "call-1".into(),
        reason_id: reason_id.into(),
        reason_code: "inspect_context".into(),
        reason_source: "agent_declared".into(),
        reason_summary: None,
        task_ref: None,
        supersedes_reason_id: None,
    }
}

struct EvidenceFile(PathBuf);

impl EvidenceFile {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "apolysis-reason-{label}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }
}

impl Drop for EvidenceFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn records(path: &Path) -> Vec<SessionIntentReasonRecord> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| parse_intent_reason(line).unwrap())
        .collect()
}

fn assert_rejected_without_changes(path: &Path, record: &SessionIntentReasonRecord) {
    let before = std::fs::read(path).unwrap();
    assert_eq!(
        append_intent_reason(path, record).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn retries_ignore_only_ingestion_time_and_independent_reasons_remain_visible() {
    let file = EvidenceFile::new("retry");
    let first = record("first");
    assert_eq!(
        append_intent_reason(&file.0, &first).unwrap(),
        IntentAppendOutcome::Appended
    );
    let mut retry = first.clone();
    retry.timestamp_unix_ms = u128::MAX;
    assert_eq!(
        append_intent_reason(&file.0, &retry).unwrap(),
        IntentAppendOutcome::AlreadyRecorded
    );
    let mut conflict = retry;
    conflict.reason_code = "verify_change".into();
    assert_rejected_without_changes(&file.0, &conflict);
    append_intent_reason(&file.0, &record("independent")).unwrap();
    let mut another_session = first.clone();
    another_session.session_id = "another-capture".into();
    append_intent_reason(&file.0, &another_session).unwrap();
    let saved = records(&file.0);
    assert_eq!(saved.len(), 3);
    assert_eq!(saved[0], first);
}

#[test]
fn corrections_form_an_append_only_chain_and_retry_old_versions() {
    let file = EvidenceFile::new("correction");
    let first = record("first");
    append_intent_reason(&file.0, &first).unwrap();
    let mut second = record("second");
    second.supersedes_reason_id = Some("first".into());
    second.reason_code = "reproduce_issue".into();
    append_intent_reason(&file.0, &second).unwrap();
    let mut third = record("third");
    third.supersedes_reason_id = Some("second".into());
    third.reason_code = "diagnose_failure".into();
    append_intent_reason(&file.0, &third).unwrap();
    assert_eq!(
        append_intent_reason(&file.0, &first).unwrap(),
        IntentAppendOutcome::AlreadyRecorded
    );
    assert_eq!(
        append_intent_reason(&file.0, &second).unwrap(),
        IntentAppendOutcome::AlreadyRecorded
    );
    let mut branch = record("branch");
    branch.supersedes_reason_id = Some("first".into());
    assert_rejected_without_changes(&file.0, &branch);
    let mut cycle = first.clone();
    cycle.supersedes_reason_id = Some("third".into());
    assert_rejected_without_changes(&file.0, &cycle);
    let mut missing = record("missing");
    missing.supersedes_reason_id = Some("not-stored".into());
    assert_rejected_without_changes(&file.0, &missing);
    assert_eq!(records(&file.0), vec![first, second, third]);
}

#[test]
fn corrections_must_preserve_the_full_call_identity() {
    let file = EvidenceFile::new("identity");
    append_intent_reason(&file.0, &record("parent")).unwrap();
    for index in 0..5 {
        let mut correction = record("correction");
        correction.supersedes_reason_id = Some("parent".into());
        match index {
            0 => correction.session_id = "other".into(),
            1 => correction.intent_id = "f".repeat(32),
            2 => correction.intent_source = "pi".into(),
            3 => correction.harness_session_id = "other".into(),
            _ => correction.source_event_id = "other".into(),
        }
        assert_rejected_without_changes(&file.0, &correction);
    }
}

#[test]
fn parser_rejects_private_extra_fields_duplicate_fields_and_invalid_shapes() {
    let mut original = record("first");
    original.timestamp_unix_ms = u128::MAX;
    original.reason_summary = Some("Inspect \"quoted\" names \\ safely".into());
    original.task_ref = Some("opaque-task".into());
    let line = original.to_json_line();
    for ending in ["", "\n", "\r\n"] {
        assert_eq!(
            parse_intent_reason(&format!("{line}{ending}")).unwrap(),
            original
        );
    }
    for malformed in [
        format!(
            "{},\"prompt\":\"SYNTHETIC_PRIVATE_INPUT\"}}",
            line.trim_end_matches('}')
        ),
        format!(
            "{},\"reason_id\":\"SYNTHETIC_PRIVATE_INPUT\"}}",
            line.trim_end_matches('}')
        ),
        line.replace("\"intent_reason\"", "\"intent\""),
        line.replace("\"source_event_id\":\"call-1\",", ""),
        line.replace(
            "\"reason_code\":\"inspect_context\"",
            "\"reason_code\":false",
        ),
        format!("{line}\n{line}"),
    ] {
        let error = parse_intent_reason(&malformed).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(!error.to_string().contains("SYNTHETIC_PRIVATE_INPUT"));
    }
}

#[test]
fn all_history_is_checked_before_retries_or_appends_and_errors_preserve_evidence() {
    let file = EvidenceFile::new("invalid-history");
    let first = record("first");
    let line = first.to_json_line();
    let mut conflict = first.clone();
    conflict.reason_code = "verify_change".into();
    let mut missing = record("missing");
    missing.supersedes_reason_id = Some("absent".into());
    let mut branch = record("branch");
    branch.supersedes_reason_id = Some("first".into());
    let mut other_branch = branch.clone();
    other_branch.reason_id = "other-branch".into();
    for body in [
        line.clone(),
        format!("{line}\n{{\"record_type\":\"intent\"}}\n"),
        format!("{line}\nnot-json\n"),
        format!("{line}\n{}\n", conflict.to_json_line()),
        format!("{line}\n{}\n", missing.to_json_line()),
        format!(
            "{line}\n{}\n{}\n",
            branch.to_json_line(),
            other_branch.to_json_line()
        ),
        format!("{line}\n\n"),
    ] {
        std::fs::write(&file.0, body).unwrap();
        assert_rejected_without_changes(&file.0, &first);
        assert_rejected_without_changes(&file.0, &record("fresh"));
    }
}

#[test]
fn invalid_incoming_record_does_not_create_a_file() {
    let file = EvidenceFile::new("invalid-new");
    let mut invalid = record("first");
    invalid.reason_summary = Some("invalid\nsummary".into());
    assert!(append_intent_reason(&file.0, &invalid).is_err());
    assert!(!file.0.exists());
}

#[cfg(unix)]
#[test]
fn newly_created_reason_file_is_private_and_default_has_no_summary() {
    use std::os::unix::fs::PermissionsExt;
    let file = EvidenceFile::new("private");
    append_intent_reason(&file.0, &record("first")).unwrap();
    assert_eq!(
        std::fs::metadata(&file.0).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved = records(&file.0);
    assert_eq!(saved[0].reason_summary, None);
    assert_eq!(saved[0].task_ref, None);
}

// Executed in separate processes to exercise the file lock rather than a mutex.
#[test]
fn reason_append_worker() {
    let Ok(path) = std::env::var("APOLYSIS_REASON_TEST_PATH") else {
        return;
    };
    let worker = std::env::var("APOLYSIS_REASON_TEST_WORKER").unwrap();
    let mode = std::env::var("APOLYSIS_REASON_TEST_MODE").unwrap();
    match mode.as_str() {
        "retry" => {
            let mut shared = record("shared");
            shared.timestamp_unix_ms = worker.parse().unwrap();
            append_intent_reason(&path, &shared).unwrap();
            append_intent_reason(&path, &record(&format!("independent-{worker}"))).unwrap();
            assert_eq!(
                append_intent_reason(&path, &shared).unwrap(),
                IntentAppendOutcome::AlreadyRecorded
            );
        }
        "conflict" => {
            let mut competing = record("shared");
            if worker.parse::<usize>().unwrap() % 2 == 0 {
                competing.reason_code = "verify_change".into();
            }
            if let Err(error) = append_intent_reason(&path, &competing) {
                assert_eq!(error.kind(), ErrorKind::InvalidData);
                assert!(error.to_string().contains("conflicting record"));
            }
        }
        "correction" => {
            let mut competing = record(&format!("correction-{worker}"));
            competing.supersedes_reason_id = Some("parent".into());
            if let Err(error) = append_intent_reason(&path, &competing) {
                assert_eq!(error.kind(), ErrorKind::InvalidData);
                assert!(error.to_string().contains("branching corrections"));
            }
        }
        _ => panic!("unknown worker mode"),
    }
}

fn concurrent_workers(path: &Path, mode: &str) {
    let executable = std::env::current_exe().unwrap();
    let mut children: Vec<_> = (0..8)
        .map(|worker| {
            Command::new(&executable)
                .args(["--exact", "reason_append_worker"])
                .env("APOLYSIS_REASON_TEST_PATH", path)
                .env("APOLYSIS_REASON_TEST_WORKER", worker.to_string())
                .env("APOLYSIS_REASON_TEST_MODE", mode)
                .stdout(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
}

#[test]
fn concurrent_processes_deduplicate_retries_without_losing_independent_reasons() {
    let file = EvidenceFile::new("concurrent-retry");
    concurrent_workers(&file.0, "retry");
    let saved = records(&file.0);
    assert_eq!(saved.len(), 9);
    assert_eq!(
        saved
            .iter()
            .filter(|record| record.reason_id == "shared")
            .count(),
        1
    );
}

#[test]
fn concurrent_conflicting_writers_commit_only_one_version() {
    let file = EvidenceFile::new("concurrent-conflict");
    concurrent_workers(&file.0, "conflict");
    assert_eq!(records(&file.0).len(), 1);
}

#[test]
fn concurrent_corrections_cannot_branch_history() {
    let file = EvidenceFile::new("concurrent-correction");
    append_intent_reason(&file.0, &record("parent")).unwrap();
    concurrent_workers(&file.0, "correction");
    let saved = records(&file.0);
    assert_eq!(saved.len(), 2);
    assert_eq!(saved[1].supersedes_reason_id.as_deref(), Some("parent"));
}

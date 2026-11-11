// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use apolysis_core::{records, SessionIntentReasonRecord};
use serde::Deserialize;

use crate::IntentAppendOutcome;

/// Append one reason under an exclusive local-file lock, retaining corrections.
///
/// The lock covers validation of all existing records, deduplication, writing the
/// complete line, and syncing data. All writers must use this API; external file
/// rotation and network filesystem lock semantics are outside this contract.
/// New Unix files are private (mode 0600, further restricted by the umask).
pub fn append_intent_reason(
    path: impl AsRef<Path>,
    record: &SessionIntentReasonRecord,
) -> io::Result<IntentAppendOutcome> {
    record.validate().map_err(invalid_data)?;
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.lock()?;
    // Dropping the file releases the lock on every error path.
    let mut history = ReasonHistory::default();
    let mut reader = BufReader::new(&file);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if !line.ends_with('\n') {
            return Err(invalid_data(
                "intent reason file has an incomplete trailing line",
            ));
        }
        history.insert(parse_intent_reason(&line)?)?;
    }
    let outcome = history.insert(record.clone())?;
    if outcome == IntentAppendOutcome::Appended {
        let mut line = record.to_json_line();
        line.push('\n');
        file.write_all(line.as_bytes())?;
    }
    file.sync_data()?;
    Ok(outcome)
}

/// Parse one reason JSONL record, validating its schema and individual fields.
/// Cross-record identity conflicts and correction graphs are left to callers.
/// Errors deliberately omit input values, which may contain private content.
pub fn parse_intent_reason(line: &str) -> io::Result<SessionIntentReasonRecord> {
    let line = line
        .strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line);
    if line.contains(['\r', '\n']) {
        return Err(invalid_data(
            "intent reason record must occupy one JSONL line",
        ));
    }
    let wire: StoredReasonRecord = serde_json::from_str(line)
        .map_err(|_| invalid_data("intent reason file contains an invalid record"))?;
    if wire.record_type != records::INTENT_REASON {
        return Err(invalid_data(
            "intent reason file contains a non-reason record",
        ));
    }
    let record = wire.into_record();
    record.validate().map_err(invalid_data)?;
    Ok(record)
}

#[derive(Default)]
struct ReasonHistory {
    records: HashMap<(String, String), SessionIntentReasonRecord>,
    superseded: HashSet<(String, String)>,
}

impl ReasonHistory {
    fn insert(&mut self, mut record: SessionIntentReasonRecord) -> io::Result<IntentAppendOutcome> {
        // Timestamp describes ingestion, so otherwise identical retries are equal.
        record.timestamp_unix_ms = 0;
        let key = (record.session_id.clone(), record.reason_id.clone());
        if let Some(existing) = self.records.get(&key) {
            if existing == &record {
                return Ok(IntentAppendOutcome::AlreadyRecorded);
            }
            return Err(invalid_data(
                "conflicting record for an existing reason identity",
            ));
        }
        if let Some(parent_id) = &record.supersedes_reason_id {
            let parent_key = (record.session_id.clone(), parent_id.clone());
            let parent = self.records.get(&parent_key).ok_or_else(|| {
                invalid_data("superseded reason must already exist in the same session")
            })?;
            if parent.intent_id != record.intent_id
                || parent.intent_source != record.intent_source
                || parent.harness_session_id != record.harness_session_id
                || parent.source_event_id != record.source_event_id
            {
                return Err(invalid_data(
                    "superseded reason belongs to another call identity",
                ));
            }
            if !self.superseded.insert(parent_key) {
                return Err(invalid_data(
                    "an intent reason cannot have branching corrections",
                ));
            }
        }
        // Only new IDs can reference previously inserted IDs; self-reference is
        // rejected by field validation, so correction cycles cannot be created.
        self.records.insert(key, record);
        Ok(IntentAppendOutcome::Appended)
    }
}

/// A strict on-disk envelope rejects mixed record types, unknown payload fields,
/// duplicate JSON fields, and missing or wrongly typed required identities.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReasonRecord {
    record_type: String,
    timestamp_unix_ms: u128,
    session_id: String,
    intent_id: String,
    intent_source: String,
    harness_session_id: String,
    source_event_id: String,
    reason_id: String,
    reason_code: String,
    reason_source: String,
    reason_summary: Option<String>,
    task_ref: Option<String>,
    supersedes_reason_id: Option<String>,
}

impl StoredReasonRecord {
    fn into_record(self) -> SessionIntentReasonRecord {
        SessionIntentReasonRecord {
            timestamp_unix_ms: self.timestamp_unix_ms,
            session_id: self.session_id,
            intent_id: self.intent_id,
            intent_source: self.intent_source,
            harness_session_id: self.harness_session_id,
            source_event_id: self.source_event_id,
            reason_id: self.reason_id,
            reason_code: self.reason_code,
            reason_source: self.reason_source,
            reason_summary: self.reason_summary,
            task_ref: self.task_ref,
            supersedes_reason_id: self.supersedes_reason_id,
        }
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

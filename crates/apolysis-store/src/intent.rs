// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use apolysis_core::SessionIntentRecord;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentAppendOutcome {
    Appended,
    AlreadyRecorded,
}

/// Serialize independent hook processes on a local append-only intent file.
///
/// The lock covers deduplication, the complete line, and sync_data. Existing
/// create/truncate stores intentionally retain their original semantics.
/// All writers to this file must use this interface; network filesystem lock
/// semantics and external file rotation are outside this local hook contract.
pub fn append_intent(
    path: impl AsRef<Path>,
    record: &SessionIntentRecord,
) -> io::Result<IntentAppendOutcome> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;
    file.lock()?;
    // Dropping the file also releases its lock on every error path.
    let mut incoming: Value = serde_json::from_str(&record.to_json_line())
        .map_err(|_| invalid_data("invalid serialized intent record"))?;
    strip_ingestion_timestamp(&mut incoming);
    let mut reader = BufReader::new(&file);
    let mut line = String::new();
    let mut duplicate = false;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        // Never concatenate onto a partial write, even if its JSON happens to
        // be valid. Recovery must be explicit and preserve the original file.
        if !line.ends_with('\n') {
            return Err(invalid_data("intent file has an incomplete trailing line"));
        }
        let mut existing: Value = serde_json::from_str(&line)
            .map_err(|_| invalid_data("intent file contains an invalid JSONL record"))?;
        if existing.get("record_type").and_then(Value::as_str) != Some("intent") {
            return Err(invalid_data("intent file contains a non-intent record"));
        }
        let same_session = existing.get("session_id") == incoming.get("session_id");
        let same_id = existing.get("intent_id") == incoming.get("intent_id");
        let same_call = existing.get("intent_source") == incoming.get("intent_source")
            && existing.get("harness_session_id") == incoming.get("harness_session_id")
            && incoming
                .get("source_event_id")
                .and_then(Value::as_str)
                .is_some()
            && existing.get("source_event_id") == incoming.get("source_event_id");
        if same_session && (same_id || same_call) {
            strip_ingestion_timestamp(&mut existing);
            if existing != incoming {
                return Err(invalid_data(
                    "conflicting record for an existing intent identity",
                ));
            }
            duplicate = true;
        }
    }
    if duplicate {
        file.sync_data()?;
        return Ok(IntentAppendOutcome::AlreadyRecorded);
    }
    let mut line = record.to_json_line();
    line.push('\n');
    file.write_all(line.as_bytes())?;
    file.sync_data()?;
    Ok(IntentAppendOutcome::Appended)
}

fn strip_ingestion_timestamp(value: &mut Value) {
    if let Some(record) = value.as_object_mut() {
        record.remove("timestamp_unix_ms");
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChainRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_hash: String,
    pub record_hash: String,
    pub payload: Value,
}

#[derive(Debug)]
pub struct HashChainStore {
    writer: BufWriter<File>,
    path: PathBuf,
    sequence: u64,
    previous_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashChainVerificationReport {
    pub path: PathBuf,
    pub passed: bool,
    pub record_count: usize,
    pub last_sequence: u64,
    pub last_record_hash: String,
    pub valid_bytes: u64,
    pub total_bytes: u64,
    pub failure: Option<String>,
}

#[derive(Debug)]
pub struct Recovery {
    pub store: HashChainStore,
    pub next_sequence: u64,
    pub previous_hash: String,
    pub quarantined_path: Option<PathBuf>,
    pub records: Vec<ChainRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError {
    Io(String),
    InvalidPayload(String),
    Integrity {
        sequence: Option<u64>,
        detail: String,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "hash-chain I/O failure: {error}"),
            Self::InvalidPayload(error) => write!(formatter, "invalid JSON payload: {error}"),
            Self::Integrity { sequence, detail } => {
                write!(
                    formatter,
                    "hash-chain integrity failure at {sequence:?}: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl HashChainStore {
    pub fn verify(path: impl AsRef<Path>) -> Result<HashChainVerificationReport, StoreError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path).map_err(io_error)?;
        let total_bytes = bytes.len() as u64;
        let validation = verify_existing(&bytes);
        let valid_bytes = validation.valid_len as u64;
        let failure = validation.failure.or_else(|| {
            (valid_bytes != total_bytes).then(|| {
                format!(
                    "invalid or truncated tail after valid prefix at byte {}",
                    validation.valid_len
                )
            })
        });
        Ok(HashChainVerificationReport {
            path,
            passed: failure.is_none(),
            record_count: validation.records.len(),
            last_sequence: validation.sequence,
            last_record_hash: validation.previous_hash,
            valid_bytes,
            total_bytes,
            failure,
        })
    }

    pub fn create_or_recover(path: impl AsRef<Path>) -> Result<Recovery, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(io_error)?;
            }
        }

        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(io_error(error)),
        };
        let validation = validate_existing(&bytes)?;
        let quarantined_path = if validation.valid_len < bytes.len() {
            let quarantine = quarantine_path(&path);
            std::fs::write(&quarantine, &bytes[validation.valid_len..]).map_err(io_error)?;
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)
                .map_err(io_error)?;
            file.set_len(validation.valid_len as u64)
                .map_err(io_error)?;
            Some(quarantine)
        } else {
            None
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(io_error)?;
        let next_sequence = validation.sequence.saturating_add(1);
        let previous_hash = validation.previous_hash.clone();
        let records = validation.records;
        Ok(Recovery {
            store: Self {
                writer: BufWriter::new(file),
                path,
                sequence: validation.sequence,
                previous_hash: validation.previous_hash,
            },
            next_sequence,
            previous_hash,
            quarantined_path,
            records,
        })
    }

    pub fn append_json(
        &mut self,
        schema_version: u32,
        payload: &str,
    ) -> Result<ChainRecord, StoreError> {
        let payload: Value = serde_json::from_str(payload)
            .map_err(|error| StoreError::InvalidPayload(error.to_string()))?;
        let canonical_payload = serde_json::to_string(&payload)
            .map_err(|error| StoreError::InvalidPayload(error.to_string()))?;
        let sequence = self.sequence.saturating_add(1);
        let record_hash = calculate_hash(
            schema_version,
            sequence,
            &self.previous_hash,
            &canonical_payload,
        );
        let record = ChainRecord {
            schema_version,
            sequence,
            previous_hash: self.previous_hash.clone(),
            record_hash,
            payload,
        };
        let line = serde_json::to_string(&record)
            .map_err(|error| StoreError::InvalidPayload(error.to_string()))?;
        self.writer.write_all(line.as_bytes()).map_err(io_error)?;
        self.writer.write_all(b"\n").map_err(io_error)?;
        self.sequence = sequence;
        self.previous_hash = record.record_hash.clone();
        Ok(record)
    }

    pub fn flush(&mut self) -> Result<(), StoreError> {
        self.writer.flush().map_err(io_error)?;
        self.writer.get_ref().sync_data().map_err(io_error)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

struct Validation {
    sequence: u64,
    previous_hash: String,
    valid_len: usize,
    records: Vec<ChainRecord>,
}

struct ReadonlyValidation {
    sequence: u64,
    previous_hash: String,
    valid_len: usize,
    records: Vec<ChainRecord>,
    failure: Option<String>,
}

fn verify_existing(bytes: &[u8]) -> ReadonlyValidation {
    let mut sequence = 0_u64;
    let mut previous_hash = ZERO_HASH.to_string();
    let mut valid_len = 0_usize;
    let mut records = Vec::new();
    let newline_positions: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        .collect();
    let mut start = 0_usize;

    for newline in newline_positions {
        let line = &bytes[start..newline];
        let expected_sequence = sequence.saturating_add(1);
        match validate_line(line, expected_sequence, &previous_hash) {
            Ok(record) => {
                sequence = record.sequence;
                previous_hash = record.record_hash.clone();
                records.push(record);
                valid_len = newline + 1;
                start = newline + 1;
            }
            Err(detail) => {
                return ReadonlyValidation {
                    sequence,
                    previous_hash,
                    valid_len,
                    records,
                    failure: Some(format!(
                        "hash-chain integrity failure at {:?}: {}",
                        Some(expected_sequence),
                        detail
                    )),
                };
            }
        }
    }

    ReadonlyValidation {
        sequence,
        previous_hash,
        valid_len,
        records,
        failure: None,
    }
}

fn validate_existing(bytes: &[u8]) -> Result<Validation, StoreError> {
    let mut sequence = 0_u64;
    let mut previous_hash = ZERO_HASH.to_string();
    let mut valid_len = 0_usize;
    let mut records = Vec::new();
    let newline_positions: Vec<usize> = bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        .collect();
    let trailing_bytes = newline_positions
        .last()
        .map(|position| position + 1 < bytes.len())
        .unwrap_or(!bytes.is_empty());
    let mut start = 0_usize;

    for (line_index, newline) in newline_positions.iter().copied().enumerate() {
        let line = &bytes[start..newline];
        let expected_sequence = sequence.saturating_add(1);
        let result = validate_line(line, expected_sequence, &previous_hash);
        match result {
            Ok(record) => {
                sequence = record.sequence;
                previous_hash = record.record_hash.clone();
                records.push(record);
                valid_len = newline + 1;
                start = newline + 1;
            }
            Err(detail) => {
                let has_later_complete_line = line_index + 1 < newline_positions.len();
                if has_later_complete_line || trailing_bytes {
                    return Err(StoreError::Integrity {
                        sequence: Some(expected_sequence),
                        detail,
                    });
                }
                return Ok(Validation {
                    sequence,
                    previous_hash,
                    valid_len: start,
                    records,
                });
            }
        }
    }

    Ok(Validation {
        sequence,
        previous_hash,
        valid_len,
        records,
    })
}

fn validate_line(
    line: &[u8],
    expected_sequence: u64,
    expected_previous_hash: &str,
) -> Result<ChainRecord, String> {
    let record: ChainRecord =
        serde_json::from_slice(line).map_err(|error| format!("invalid record JSON: {error}"))?;
    if record.sequence != expected_sequence {
        return Err(format!(
            "expected sequence {expected_sequence}, got {}",
            record.sequence
        ));
    }
    if record.previous_hash != expected_previous_hash {
        return Err("previous hash does not match valid prefix".to_string());
    }
    let canonical_payload =
        serde_json::to_string(&record.payload).map_err(|error| error.to_string())?;
    let expected_hash = calculate_hash(
        record.schema_version,
        record.sequence,
        &record.previous_hash,
        &canonical_payload,
    );
    if record.record_hash != expected_hash {
        return Err("record hash does not match payload".to_string());
    }
    Ok(record)
}

fn calculate_hash(
    schema_version: u32,
    sequence: u64,
    previous_hash: &str,
    payload: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(schema_version.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(payload.as_bytes());
    encode_hex(&hasher.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn quarantine_path(path: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("timeline.jsonl");
    path.with_file_name(format!("{file_name}.quarantine-{timestamp}"))
}

fn io_error(error: std::io::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

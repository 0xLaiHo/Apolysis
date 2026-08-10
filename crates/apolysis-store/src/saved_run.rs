// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash_chain::decode_verified_chain;
use crate::StoreError;

pub const MAX_SAVED_RUN_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_SAVED_RUN_LINE_BYTES: usize = 1024 * 1024;
pub const MAX_SAVED_RUN_RECORDS: usize = 1_000_000;
const MAX_ROTATED_FILES: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalRecordFormat {
    PlainJsonl,
    VerifiedHashChain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalRecordBatch {
    pub format: LocalRecordFormat,
    pub source_files: usize,
    pub source_bytes: u64,
    pub records: Vec<Value>,
    #[serde(skip)]
    source_paths: Vec<PathBuf>,
}

impl LocalRecordBatch {
    pub fn source_paths(&self) -> &[PathBuf] {
        &self.source_paths
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalRecordReadError {
    InvalidPath,
    Io { operation: &'static str },
    SymlinkRefused { segment: usize },
    NonRegularFile { segment: usize },
    RotationSetInvalid,
    SourceChangedDuringRead { segment: usize },
    InputLimitExceeded { limit: &'static str },
    TruncatedJsonlTail { segment: usize },
    MalformedJson { segment: usize, line: u64 },
    MixedFormats { segment: usize, line: u64 },
    HashChainIntegrity { sequence: Option<u64> },
}

impl std::fmt::Display for LocalRecordReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => write!(formatter, "saved-run input path is invalid"),
            Self::Io { operation } => write!(formatter, "saved-run {operation} failed"),
            Self::SymlinkRefused { segment } => {
                write!(formatter, "saved-run segment {segment} is a symlink")
            }
            Self::NonRegularFile { segment } => {
                write!(
                    formatter,
                    "saved-run segment {segment} is not a regular file"
                )
            }
            Self::RotationSetInvalid => write!(formatter, "saved-run rotation set is invalid"),
            Self::SourceChangedDuringRead { segment } => {
                write!(
                    formatter,
                    "saved-run segment {segment} changed while reading"
                )
            }
            Self::InputLimitExceeded { limit } => {
                write!(formatter, "saved-run input exceeded {limit}")
            }
            Self::TruncatedJsonlTail { segment } => {
                write!(
                    formatter,
                    "saved-run segment {segment} has a truncated JSONL tail"
                )
            }
            Self::MalformedJson { segment, line } => {
                write!(
                    formatter,
                    "saved-run segment {segment} line {line} is malformed"
                )
            }
            Self::MixedFormats { segment, line } => write!(
                formatter,
                "saved-run segment {segment} line {line} mixes envelope formats"
            ),
            Self::HashChainIntegrity { sequence } => write!(
                formatter,
                "saved-run hash-chain integrity failed at sequence {sequence:?}"
            ),
        }
    }
}

impl std::error::Error for LocalRecordReadError {}

pub fn read_agent_run_records(
    active_path: impl AsRef<Path>,
) -> Result<LocalRecordBatch, LocalRecordReadError> {
    let active_path = active_path.as_ref();
    let segment_paths = discover_segments(active_path)?;
    let mut segments = open_segments(&segment_paths)?;
    let segment_count = segments.len();
    validate_path_snapshot(active_path, &segment_paths, &segments)?;
    let mut records = Vec::new();
    let mut total_bytes = 0_u64;
    let mut total_records = 0_usize;
    let mut format = None;

    for (segment, opened) in segments.iter_mut().enumerate() {
        let remaining_bytes = MAX_SAVED_RUN_BYTES.saturating_sub(total_bytes);
        let bytes = read_stable_regular_file(opened, segment, remaining_bytes)?;
        total_bytes = total_bytes.checked_add(bytes.len() as u64).ok_or(
            LocalRecordReadError::InputLimitExceeded {
                limit: "the total byte limit",
            },
        )?;
        if total_bytes > MAX_SAVED_RUN_BYTES {
            return Err(LocalRecordReadError::InputLimitExceeded {
                limit: "the total byte limit",
            });
        }
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(LocalRecordReadError::TruncatedJsonlTail { segment });
        }
        let content = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        if content.is_empty() {
            continue;
        }
        let mut segment_format = None;
        for (line_index, line) in content.split(|byte| *byte == b'\n').enumerate() {
            let line_number = u64::try_from(line_index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(LocalRecordReadError::InputLimitExceeded {
                    limit: "the record limit",
                })?;
            if line.is_empty() || line.len() > MAX_SAVED_RUN_LINE_BYTES {
                return Err(LocalRecordReadError::InputLimitExceeded {
                    limit: "the line byte limit",
                });
            }
            if total_records >= MAX_SAVED_RUN_RECORDS {
                return Err(LocalRecordReadError::InputLimitExceeded {
                    limit: "the record limit",
                });
            }
            total_records =
                total_records
                    .checked_add(1)
                    .ok_or(LocalRecordReadError::InputLimitExceeded {
                        limit: "the record limit",
                    })?;
            let value: Value =
                serde_json::from_slice(line).map_err(|_| LocalRecordReadError::MalformedJson {
                    segment,
                    line: line_number,
                })?;
            if !value.is_object() {
                return Err(LocalRecordReadError::MalformedJson {
                    segment,
                    line: line_number,
                });
            }
            let current_format =
                detect_format(&value).ok_or(LocalRecordReadError::MalformedJson {
                    segment,
                    line: line_number,
                })?;
            if let Some(expected) = segment_format {
                if expected != current_format {
                    return Err(LocalRecordReadError::MixedFormats {
                        segment,
                        line: line_number,
                    });
                }
            } else {
                segment_format = Some(current_format);
            }
            if let Some(expected) = format {
                if expected != current_format {
                    return Err(LocalRecordReadError::MixedFormats {
                        segment,
                        line: line_number,
                    });
                }
            } else {
                format = Some(current_format);
            }
            match current_format {
                LocalRecordFormat::PlainJsonl => records.push(value),
                LocalRecordFormat::VerifiedHashChain => {}
            }
        }

        if segment_format == Some(LocalRecordFormat::VerifiedHashChain) {
            if segment_count != 1 {
                return Err(LocalRecordReadError::RotationSetInvalid);
            }
            let chain = decode_verified_chain(&bytes).map_err(|error| match error {
                StoreError::Integrity { sequence, .. } => {
                    LocalRecordReadError::HashChainIntegrity { sequence }
                }
                StoreError::Io(_) | StoreError::InvalidPayload(_) => {
                    LocalRecordReadError::HashChainIntegrity { sequence: None }
                }
            })?;
            if chain.len() != total_records
                || chain.iter().any(|record| !record.payload.is_object())
            {
                return Err(LocalRecordReadError::HashChainIntegrity { sequence: None });
            }
            records.extend(chain.into_iter().map(|record| record.payload));
        }
    }

    validate_path_snapshot(active_path, &segment_paths, &segments)?;
    Ok(LocalRecordBatch {
        format: format.unwrap_or(LocalRecordFormat::PlainJsonl),
        source_files: segment_paths.len(),
        source_bytes: total_bytes,
        records,
        source_paths: segment_paths,
    })
}

fn discover_segments(active_path: &Path) -> Result<Vec<PathBuf>, LocalRecordReadError> {
    let file_name = active_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(LocalRecordReadError::InvalidPath)?;
    let parent = active_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = format!("{file_name}.");
    let mut archives = Vec::new();
    let entries = std::fs::read_dir(parent).map_err(|_| LocalRecordReadError::Io {
        operation: "directory read",
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| LocalRecordReadError::Io {
            operation: "directory entry read",
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let index = suffix
            .parse::<usize>()
            .map_err(|_| LocalRecordReadError::RotationSetInvalid)?;
        if index == 0 || index > MAX_ROTATED_FILES {
            return Err(LocalRecordReadError::RotationSetInvalid);
        }
        archives.push((index, entry.path()));
    }
    archives.sort_by_key(|(index, _)| std::cmp::Reverse(*index));
    if let Some((oldest, _)) = archives.first() {
        let expected = (1..=*oldest).rev().collect::<Vec<_>>();
        let actual = archives.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        if actual != expected {
            return Err(LocalRecordReadError::RotationSetInvalid);
        }
    }
    let mut segments = archives
        .into_iter()
        .map(|(_, path)| path)
        .collect::<Vec<_>>();
    segments.push(active_path.to_path_buf());
    Ok(segments)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct OpenedSegment {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
}

fn open_segments(paths: &[PathBuf]) -> Result<Vec<OpenedSegment>, LocalRecordReadError> {
    let mut opened = Vec::with_capacity(paths.len());
    for (segment, path) in paths.iter().enumerate() {
        let link_metadata =
            std::fs::symlink_metadata(path).map_err(|_| LocalRecordReadError::Io {
                operation: "metadata read",
            })?;
        if link_metadata.file_type().is_symlink() {
            return Err(LocalRecordReadError::SymlinkRefused { segment });
        }
        if !link_metadata.is_file() {
            return Err(LocalRecordReadError::NonRegularFile { segment });
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    LocalRecordReadError::SymlinkRefused { segment }
                } else {
                    LocalRecordReadError::Io {
                        operation: "file open",
                    }
                }
            })?;
        let metadata = file.metadata().map_err(|_| LocalRecordReadError::Io {
            operation: "metadata read",
        })?;
        if !metadata.is_file() {
            return Err(LocalRecordReadError::NonRegularFile { segment });
        }
        let identity = file_identity(&metadata);
        if identity.device != link_metadata.dev() || identity.inode != link_metadata.ino() {
            return Err(LocalRecordReadError::SourceChangedDuringRead { segment });
        }
        opened.push(OpenedSegment {
            path: path.clone(),
            file,
            identity,
        });
    }
    Ok(opened)
}

fn read_stable_regular_file(
    opened: &mut OpenedSegment,
    segment: usize,
    remaining_bytes: u64,
) -> Result<Vec<u8>, LocalRecordReadError> {
    if opened.identity.len > remaining_bytes {
        return Err(LocalRecordReadError::InputLimitExceeded {
            limit: "the total byte limit",
        });
    }
    let mut bytes = Vec::new();
    opened
        .file
        .by_ref()
        .take(remaining_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| LocalRecordReadError::Io {
            operation: "file read",
        })?;
    if bytes.len() as u64 > remaining_bytes {
        return Err(LocalRecordReadError::InputLimitExceeded {
            limit: "the total byte limit",
        });
    }
    let after = opened
        .file
        .metadata()
        .map_err(|_| LocalRecordReadError::Io {
            operation: "metadata read",
        })?;
    if opened.identity != file_identity(&after) || after.len() != bytes.len() as u64 {
        return Err(LocalRecordReadError::SourceChangedDuringRead { segment });
    }
    Ok(bytes)
}

fn validate_path_snapshot(
    active_path: &Path,
    expected_paths: &[PathBuf],
    opened: &[OpenedSegment],
) -> Result<(), LocalRecordReadError> {
    if discover_segments(active_path).ok().as_deref() != Some(expected_paths) {
        return Err(LocalRecordReadError::SourceChangedDuringRead { segment: 0 });
    }
    for (segment, opened) in opened.iter().enumerate() {
        let metadata = std::fs::symlink_metadata(&opened.path)
            .map_err(|_| LocalRecordReadError::SourceChangedDuringRead { segment })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || file_identity(&metadata) != opened.identity
        {
            return Err(LocalRecordReadError::SourceChangedDuringRead { segment });
        }
    }
    Ok(())
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn detect_format(value: &Value) -> Option<LocalRecordFormat> {
    if value.get("record_type").and_then(Value::as_str).is_some() {
        Some(LocalRecordFormat::PlainJsonl)
    } else if value.get("schema_version").is_some()
        && value.get("sequence").is_some()
        && value.get("previous_hash").is_some()
        && value.get("record_hash").is_some()
        && value.get("payload").is_some_and(Value::is_object)
    {
        Some(LocalRecordFormat::VerifiedHashChain)
    } else {
        None
    }
}

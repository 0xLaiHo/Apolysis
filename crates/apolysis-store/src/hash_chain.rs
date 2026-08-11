// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

static NEXT_QUARANTINE_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
type QuarantineTestHook = (PathBuf, Box<dyn FnOnce() + Send>);

#[cfg(test)]
fn quarantine_test_hook() -> &'static Mutex<Vec<QuarantineTestHook>> {
    static HOOK: OnceLock<Mutex<Vec<QuarantineTestHook>>> = OnceLock::new();
    HOOK.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(test)]
fn install_quarantine_test_hook(path: PathBuf, hook: impl FnOnce() + Send + 'static) {
    let mut slot = quarantine_test_hook()
        .lock()
        .expect("lock quarantine test hook");
    assert!(
        !slot.iter().any(|(expected, _)| expected == &path),
        "quarantine test hook already installed for path"
    );
    slot.push((path, Box::new(hook)));
}

#[cfg(test)]
fn run_quarantine_test_hook(path: &Path) {
    let hook = {
        let mut slot = quarantine_test_hook()
            .lock()
            .expect("lock quarantine test hook");
        slot.iter()
            .position(|(expected, _)| expected == path)
            .map(|index| slot.remove(index).1)
    };
    if let Some(hook) = hook {
        hook();
    }
}

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

/// Stable filesystem identity of the descriptor backing a hash-chain store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreFileIdentity {
    pub device: u64,
    pub inode: u64,
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
        let validation = scan_existing(&bytes);
        let valid_bytes = validation.valid_len as u64;
        let failure = validation
            .failure
            .as_ref()
            .map(|failure| {
                format!(
                    "hash-chain integrity failure at {:?}: {}",
                    Some(failure.sequence),
                    failure.detail
                )
            })
            .or_else(|| {
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
                let parent_existed = parent.exists();
                std::fs::create_dir_all(parent).map_err(io_error)?;
                let metadata = std::fs::symlink_metadata(parent).map_err(io_error)?;
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(StoreError::Io(
                        "refusing a linked or non-directory timeline parent".to_string(),
                    ));
                }
                if !parent_existed {
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))
                        .map_err(io_error)?;
                }
            }
        }
        let (parent_directory, parent_path, timeline_name) = open_timeline_parent(&path)?;
        let mut file = open_or_create_timeline_at(&parent_directory, &timeline_name)?;
        let opened_metadata = validate_open_timeline(&path, &file)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .map_err(io_error)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io_error)?;
        ensure_path_matches_open_file(&path, &opened_metadata)?;
        let validation = validate_existing(&bytes)?;
        let quarantined_path = if validation.valid_len < bytes.len() {
            #[cfg(test)]
            run_quarantine_test_hook(&path);
            ensure_parent_path_matches_open_directory(&parent_path, &parent_directory)?;
            let quarantine = write_private_quarantine(
                &parent_directory,
                &path,
                &timeline_name,
                &bytes[validation.valid_len..],
            )?;
            ensure_parent_path_matches_open_directory(&parent_path, &parent_directory)?;
            ensure_path_matches_open_file(&path, &opened_metadata)?;
            file.set_len(validation.valid_len as u64)
                .map_err(io_error)?;
            file.sync_data().map_err(io_error)?;
            ensure_parent_path_matches_open_directory(&parent_path, &parent_directory)?;
            ensure_path_matches_open_file(&path, &opened_metadata)?;
            Some(quarantine)
        } else {
            None
        };
        file.seek(SeekFrom::End(0)).map_err(io_error)?;
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
        self.ensure_path_identity()?;
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
        self.ensure_path_identity()?;
        self.writer.flush().map_err(io_error)?;
        self.writer.get_ref().sync_data().map_err(io_error)?;
        self.ensure_path_identity()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the identity of the already-open timeline without reopening its path.
    pub fn file_identity(&self) -> Result<StoreFileIdentity, StoreError> {
        let metadata = self.writer.get_ref().metadata().map_err(io_error)?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(StoreError::Io(
                "timeline descriptor is linked or non-regular".to_string(),
            ));
        }
        Ok(StoreFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn ensure_path_identity(&self) -> Result<(), StoreError> {
        let metadata = self.writer.get_ref().metadata().map_err(io_error)?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(StoreError::Io(
                "timeline descriptor is linked or non-regular".to_string(),
            ));
        }
        ensure_path_matches_open_file(&self.path, &metadata)
    }
}

fn validate_open_timeline(path: &Path, file: &File) -> Result<std::fs::Metadata, StoreError> {
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(StoreError::Io(
            "refusing to recover a linked or non-regular timeline".to_string(),
        ));
    }
    ensure_path_matches_open_file(path, &metadata)?;
    Ok(metadata)
}

fn ensure_path_matches_open_file(
    path: &Path,
    opened_metadata: &std::fs::Metadata,
) -> Result<(), StoreError> {
    let current = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !current.file_type().is_file()
        || current.file_type().is_symlink()
        || current.nlink() != 1
        || current.dev() != opened_metadata.dev()
        || current.ino() != opened_metadata.ino()
    {
        return Err(StoreError::Io(
            "timeline path changed while it was being opened".to_string(),
        ));
    }
    Ok(())
}

struct ChainScan {
    sequence: u64,
    previous_hash: String,
    valid_len: usize,
    records: Vec<ChainRecord>,
    failure: Option<ChainScanFailure>,
}

struct ChainScanFailure {
    sequence: u64,
    detail: String,
}

fn scan_existing(bytes: &[u8]) -> ChainScan {
    let mut sequence = 0_u64;
    let mut previous_hash = ZERO_HASH.to_string();
    let mut valid_len = 0_usize;
    let mut records = Vec::new();

    for chunk in bytes.split_inclusive(|byte| *byte == b'\n') {
        if !chunk.ends_with(b"\n") {
            break;
        }
        let line = &chunk[..chunk.len() - 1];
        let expected_sequence = sequence.saturating_add(1);
        match validate_line(line, expected_sequence, &previous_hash) {
            Ok(record) => {
                sequence = record.sequence;
                previous_hash = record.record_hash.clone();
                records.push(record);
                valid_len = valid_len.saturating_add(chunk.len());
            }
            Err(detail) => {
                return ChainScan {
                    sequence,
                    previous_hash,
                    valid_len,
                    records,
                    failure: Some(ChainScanFailure {
                        sequence: expected_sequence,
                        detail,
                    }),
                };
            }
        }
    }

    ChainScan {
        sequence,
        previous_hash,
        valid_len,
        records,
        failure: None,
    }
}

pub(crate) fn decode_verified_chain(bytes: &[u8]) -> Result<Vec<ChainRecord>, StoreError> {
    let validation = scan_existing(bytes);
    if let Some(failure) = validation.failure {
        return Err(StoreError::Integrity {
            sequence: Some(failure.sequence),
            detail: failure.detail,
        });
    }
    if validation.valid_len != bytes.len() {
        return Err(StoreError::Integrity {
            sequence: validation.sequence.checked_add(1),
            detail: "invalid or truncated hash-chain tail".to_string(),
        });
    }
    Ok(validation.records)
}

fn validate_existing(bytes: &[u8]) -> Result<ChainScan, StoreError> {
    let mut validation = scan_existing(bytes);
    let trailing_bytes = !bytes.is_empty() && !bytes.ends_with(b"\n");
    if let Some(failure) = validation.failure.take() {
        let invalid_and_remainder = &bytes[validation.valid_len..];
        let invalid_line_end = invalid_and_remainder
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| StoreError::Integrity {
                sequence: Some(failure.sequence),
                detail: failure.detail.clone(),
            })?;
        let remainder = &invalid_and_remainder[invalid_line_end + 1..];
        if remainder.contains(&b'\n') || trailing_bytes {
            return Err(StoreError::Integrity {
                sequence: Some(failure.sequence),
                detail: failure.detail,
            });
        }
    }
    Ok(validation)
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

fn open_timeline_parent(path: &Path) -> Result<(File, PathBuf, OsString), StoreError> {
    let timeline_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| StoreError::Io("timeline path has no file name".to_string()))?
        .to_os_string();
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&parent_path)
        .map_err(io_error)?;
    ensure_parent_path_matches_open_directory(&parent_path, &parent)?;
    Ok((parent, parent_path, timeline_name))
}

fn ensure_parent_path_matches_open_directory(path: &Path, parent: &File) -> Result<(), StoreError> {
    let opened = parent.metadata().map_err(io_error)?;
    let current = std::fs::symlink_metadata(path).map_err(io_error)?;
    if !opened.file_type().is_dir()
        || !current.file_type().is_dir()
        || current.file_type().is_symlink()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(StoreError::Io(
            "timeline parent changed while it was being opened".to_string(),
        ));
    }
    Ok(())
}

fn open_or_create_timeline_at(parent: &File, name: &OsStr) -> Result<File, StoreError> {
    let name = c_string(name)?;
    // SAFETY: parent is an open directory, name is one NUL-terminated path
    // component, and O_NOFOLLOW prevents final-component traversal.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o640 as libc::mode_t,
        )
    };
    file_from_descriptor(descriptor)
}

fn write_private_quarantine(
    parent: &File,
    path: &Path,
    timeline_name: &OsStr,
    bytes: &[u8],
) -> Result<PathBuf, StoreError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    for _ in 0..32 {
        let id = NEXT_QUARANTINE_ID.fetch_add(1, Ordering::Relaxed);
        let mut quarantine_name = timeline_name.as_bytes().to_vec();
        quarantine_name.extend_from_slice(
            format!(".quarantine-{timestamp}-{}-{id}", std::process::id()).as_bytes(),
        );
        let quarantine_name = OsString::from_vec(quarantine_name);
        let mut file = match create_private_file_at(parent, &quarantine_name) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(error)),
        };
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        parent.sync_all().map_err(io_error)?;
        return Ok(path.with_file_name(quarantine_name));
    }
    Err(StoreError::Io(
        "failed to allocate a private quarantine file".to_string(),
    ))
}

fn create_private_file_at(parent: &File, name: &OsStr) -> std::io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: parent is an open directory, name is a NUL-terminated single
    // component, and O_EXCL plus O_NOFOLLOW refuses existing or linked names.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative descriptor returned by openat is uniquely owned
    // here and is transferred into File exactly once.
    let file = unsafe { File::from_raw_fd(descriptor) };
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn file_from_descriptor(descriptor: libc::c_int) -> Result<File, StoreError> {
    if descriptor < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: a non-negative descriptor returned by openat is uniquely owned
    // here and is transferred into File exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn c_string(name: &OsStr) -> Result<CString, StoreError> {
    CString::new(name.as_bytes())
        .map_err(|_| StoreError::Io("filesystem name contains NUL".to_string()))
}

fn io_error(error: std::io::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{install_quarantine_test_hook, HashChainStore, StoreError};
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn quarantine_never_uses_a_replaced_parent_path() {
        let root = std::env::temp_dir().join(format!(
            "apolysis-quarantine-parent-race-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("agent-run");
        let detached_parent = root.join("detached-agent-run");
        let timeline = corrupt_timeline_fixture(&parent);

        let raced_parent = parent.clone();
        let raced_detached_parent = detached_parent.clone();
        install_quarantine_test_hook(timeline.clone(), move || {
            std::fs::rename(&raced_parent, &raced_detached_parent).expect("detach opened parent");
            std::fs::create_dir(&raced_parent).expect("create replacement parent");
            std::fs::write(raced_parent.join("operator-canary"), b"operator-owned\n")
                .expect("write replacement canary");
        });

        let error = HashChainStore::create_or_recover(&timeline)
            .expect_err("parent replacement must fail recovery");

        assert!(matches!(error, StoreError::Io(_)));
        let replacement_names = std::fs::read_dir(&parent)
            .expect("read replacement parent")
            .map(|entry| entry.expect("read replacement entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(replacement_names, vec!["operator-canary"]);
        assert_eq!(
            std::fs::read(parent.join("operator-canary")).expect("read replacement canary"),
            b"operator-owned\n"
        );

        std::fs::remove_dir_all(root).expect("remove parent-race fixture");
    }

    #[test]
    fn quarantine_refuses_a_replaced_parent_even_when_the_timeline_inode_returns() {
        let root = std::env::temp_dir().join(format!(
            "apolysis-quarantine-parent-return-race-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("agent-run");
        let detached_parent = root.join("detached-agent-run");
        let timeline = corrupt_timeline_fixture(&parent);
        let original_bytes = std::fs::read(&timeline).expect("read corrupt timeline fixture");

        let raced_parent = parent.clone();
        let raced_detached_parent = detached_parent.clone();
        install_quarantine_test_hook(timeline.clone(), move || {
            std::fs::rename(&raced_parent, &raced_detached_parent).expect("detach opened parent");
            std::fs::create_dir(&raced_parent).expect("create replacement parent");
            std::fs::rename(
                raced_detached_parent.join("timeline.jsonl"),
                raced_parent.join("timeline.jsonl"),
            )
            .expect("return the opened timeline inode through the replacement parent");
            std::fs::write(raced_parent.join("operator-canary"), b"operator-owned\n")
                .expect("write replacement canary");
        });

        let error = HashChainStore::create_or_recover(&timeline)
            .expect_err("parent identity replacement must fail recovery");

        assert!(matches!(error, StoreError::Io(_)));
        assert_eq!(
            std::fs::read(&timeline).expect("read preserved corrupt timeline"),
            original_bytes,
            "failed recovery must not truncate the returned timeline inode"
        );
        let replacement_names = std::fs::read_dir(&parent)
            .expect("read replacement parent")
            .map(|entry| entry.expect("read replacement entry").file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            replacement_names,
            BTreeSet::from(["operator-canary".into(), "timeline.jsonl".into()])
        );
        assert_eq!(
            std::fs::read_dir(&detached_parent)
                .expect("read detached parent")
                .count(),
            0,
            "refused recovery must not strand quarantine data in the detached parent"
        );

        std::fs::remove_dir_all(root).expect("remove returned-parent-race fixture");
    }

    fn corrupt_timeline_fixture(parent: &Path) -> PathBuf {
        let timeline = parent.join("timeline.jsonl");
        std::fs::create_dir_all(parent).expect("create agent-run fixture");
        {
            let mut store = HashChainStore::create_or_recover(&timeline)
                .expect("create timeline fixture")
                .store;
            store
                .append_json(1, r#"{"type":"event"}"#)
                .expect("append timeline fixture");
            store.flush().expect("flush timeline fixture");
        }
        std::fs::OpenOptions::new()
            .append(true)
            .open(&timeline)
            .expect("open timeline tail")
            .write_all(br#"{"schema_version":1"#)
            .expect("append corrupt tail");
        timeline
    }
}

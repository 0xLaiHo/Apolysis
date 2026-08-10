// SPDX-License-Identifier: Apache-2.0

//! JSONL storage primitives for Apolysis.
//!
//! TimelineStore stores timeline data in append-only JSONL because it is transparent,
//! shell-friendly, and easy to preserve as evidence during early eBPF work.

use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use apolysis_core::JsonLine;
use tokio::fs as async_fs;
use tokio::io::{AsyncWriteExt, BufWriter as AsyncBufWriter};

mod hash_chain;
mod saved_run;

pub use hash_chain::{
    ChainRecord, HashChainStore, HashChainVerificationReport, Recovery, StoreError, ZERO_HASH,
};
pub use saved_run::{
    read_agent_run_records, LocalRecordBatch, LocalRecordFormat, LocalRecordReadError,
    MAX_SAVED_RUN_BYTES, MAX_SAVED_RUN_LINE_BYTES, MAX_SAVED_RUN_RECORDS,
};

pub struct JsonlStore {
    writer: BufWriter<File>,
    path: PathBuf,
    current_bytes: u64,
    rotation: Option<JsonlRotationPolicy>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonlRotationPolicy {
    pub max_file_bytes: u64,
    pub max_archived_files: usize,
}

impl JsonlStore {
    /// Create or truncate a JSONL timeline file.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::create_with_rotation_policy(path, None)
    }

    /// Create or truncate a JSONL timeline file with bounded local rotation.
    ///
    /// Rotation never splits a JSONL record.  If a single record is larger than
    /// the active-file budget, it is written as one oversized line and the next
    /// append rotates before writing again.
    pub fn create_with_rotation(
        path: impl AsRef<Path>,
        rotation: JsonlRotationPolicy,
    ) -> io::Result<Self> {
        Self::create_with_rotation_policy(path, Some(rotation))
    }

    pub fn create_with_rotation_policy(
        path: impl AsRef<Path>,
        rotation: Option<JsonlRotationPolicy>,
    ) -> io::Result<Self> {
        if let Some(rotation) = rotation {
            validate_rotation_policy(rotation)?;
        }
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let file = File::create(&path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            path,
            current_bytes: 0,
            rotation,
        })
    }

    /// Append one schema object as exactly one JSONL line.
    pub fn append<T: JsonLine>(&mut self, record: &T) -> io::Result<()> {
        let line = record.to_json_line();
        let line_len = u64::try_from(line.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "JSONL record too large"))?
            .saturating_add(1);
        if self.should_rotate_before(line_len) {
            self.rotate()?;
        }
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.current_bytes = self.current_bytes.saturating_add(line_len);
        Ok(())
    }

    /// Append heterogeneous records as one durable boundary.
    ///
    /// Rotation is decided once for the complete batch, so the boundary is
    /// never split merely because its individual records exceed the active
    /// file budget. If writing or synchronization fails, the active file is
    /// truncated back to its pre-batch length before the error is returned.
    pub fn append_batch_and_sync(&mut self, records: &[&dyn JsonLine]) -> io::Result<()> {
        if records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "JSONL durable batch must not be empty",
            ));
        }

        let mut batch = Vec::new();
        let mut batch_len = 0_u64;
        for record in records {
            let line = record.to_json_line();
            let line_len = u64::try_from(line.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "JSONL record too large"))?
                .checked_add(1)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "JSONL batch is too large")
                })?;
            batch_len = batch_len.checked_add(line_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "JSONL batch is too large")
            })?;
            batch.extend_from_slice(line.as_bytes());
            batch.push(b'\n');
        }

        if self.should_rotate_before(batch_len) {
            self.rotate()?;
        }
        self.writer.flush()?;
        let starting_bytes = self.current_bytes;
        let result = (|| {
            self.writer.get_mut().write_all(&batch)?;
            self.writer.get_mut().sync_all()?;
            self.sync_parent()
        })();
        if let Err(error) = result {
            let rollback = self.rollback_active_write(starting_bytes);
            let message = match rollback {
                Ok(()) => format!("{error}; durable batch rolled back"),
                Err(rollback_error) => {
                    format!("{error}; durable batch rollback failed: {rollback_error}")
                }
            };
            return Err(io::Error::new(error.kind(), message));
        }
        self.current_bytes = self.current_bytes.saturating_add(batch_len);
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Flush userspace buffers and synchronize the file and parent directory.
    pub fn flush_and_sync(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        self.sync_parent()
    }

    fn sync_parent(&self) -> io::Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()
    }

    fn rollback_active_write(&mut self, starting_bytes: u64) -> io::Result<()> {
        let file = self.writer.get_mut();
        file.set_len(starting_bytes)?;
        file.seek(SeekFrom::Start(starting_bytes))?;
        file.sync_all()?;
        self.sync_parent()
    }

    fn should_rotate_before(&self, next_line_bytes: u64) -> bool {
        self.rotation
            .map(|rotation| {
                self.current_bytes > 0
                    && self.current_bytes.saturating_add(next_line_bytes) > rotation.max_file_bytes
            })
            .unwrap_or(false)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let rotation = self
            .rotation
            .expect("rotation is configured before rotate is called");
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        let oldest = archive_path(&self.path, rotation.max_archived_files);
        match std::fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        for index in (1..rotation.max_archived_files).rev() {
            let source = archive_path(&self.path, index);
            let target = archive_path(&self.path, index + 1);
            if source.exists() {
                std::fs::rename(source, target)?;
            }
        }
        if self.path.exists() {
            std::fs::rename(&self.path, archive_path(&self.path, 1))?;
        }
        self.writer = BufWriter::new(File::create(&self.path)?);
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        self.current_bytes = 0;
        Ok(())
    }
}

fn archive_path(path: &Path, index: usize) -> PathBuf {
    let mut archive = path.as_os_str().to_os_string();
    archive.push(format!(".{index}"));
    PathBuf::from(archive)
}

fn validate_rotation_policy(rotation: JsonlRotationPolicy) -> io::Result<()> {
    if rotation.max_file_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_file_bytes must be greater than zero",
        ));
    }
    if rotation.max_archived_files == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_archived_files must be greater than zero",
        ));
    }
    Ok(())
}

/// Async JSONL writer for command paths that already run on Tokio.
///
/// The synchronous `JsonlStore` stays available for process supervision code
/// that needs simple blocking semantics.  This async variant gives future
/// observer backends and CLI commands a non-blocking write path without changing
/// the JSONL schema or the append-one-record contract.
pub struct AsyncJsonlStore {
    writer: AsyncBufWriter<async_fs::File>,
}

impl AsyncJsonlStore {
    /// Create or truncate a JSONL timeline file using Tokio file APIs.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                async_fs::create_dir_all(parent).await?;
            }
        }

        let file = async_fs::File::create(path).await?;
        Ok(Self {
            writer: AsyncBufWriter::new(file),
        })
    }

    /// Append one schema object as exactly one JSONL line.
    pub async fn append<T: JsonLine>(&mut self, record: &T) -> io::Result<()> {
        self.writer
            .write_all(record.to_json_line().as_bytes())
            .await?;
        self.writer.write_all(b"\n").await?;
        Ok(())
    }

    /// Flush buffered records to the underlying file handle.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().await
    }
}

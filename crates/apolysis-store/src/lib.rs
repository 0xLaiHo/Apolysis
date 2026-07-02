// SPDX-License-Identifier: Apache-2.0

//! JSONL storage primitives for Apolysis.
//!
//! TimelineStore stores timeline data in append-only JSONL because it is transparent,
//! shell-friendly, and easy to preserve as evidence during early eBPF work.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use apolysis_core::JsonLine;
use tokio::fs as async_fs;
use tokio::io::{AsyncWriteExt, BufWriter as AsyncBufWriter};

mod hash_chain;

pub use hash_chain::{ChainRecord, HashChainStore, Recovery, StoreError, ZERO_HASH};

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

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
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

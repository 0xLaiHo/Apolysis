// SPDX-License-Identifier: Apache-2.0

//! JSONL storage primitives for Apolysis.
//!
//! M1 stores timeline data in append-only JSONL because it is transparent,
//! shell-friendly, and easy to preserve as evidence during early eBPF work.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use apolysis_core::JsonLine;
use tokio::fs as async_fs;
use tokio::io::{AsyncWriteExt, BufWriter as AsyncBufWriter};

pub struct JsonlStore {
    writer: BufWriter<File>,
}

impl JsonlStore {
    /// Create or truncate a JSONL timeline file.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let file = File::create(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    /// Append one schema object as exactly one JSONL line.
    pub fn append<T: JsonLine>(&mut self, record: &T) -> io::Result<()> {
        self.writer.write_all(record.to_json_line().as_bytes())?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
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

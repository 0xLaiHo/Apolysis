// SPDX-License-Identifier: Apache-2.0

//! JSONL storage primitives for Apolysis.
//!
//! M1 stores timeline data in append-only JSONL because it is transparent,
//! shell-friendly, and easy to preserve as evidence during early eBPF work.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use apolysis_core::JsonLine;

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

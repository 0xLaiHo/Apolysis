// SPDX-License-Identifier: Apache-2.0

//! Agent-facing violation feedback files.
//!
//! The feedback file is intentionally simple text: agent harness hooks can read
//! it without linking against Apolysis, while the final `APOLYSIS_VIOLATION`
//! line keeps a compact machine-readable payload for future Claude/Codex hooks.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use apolysis_core::{feedback, json_string, PolicyViolation};

static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackWriter {
    directory: PathBuf,
}

impl FeedbackWriter {
    /// Create a writer rooted at an agent-visible feedback directory.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Persist the latest violation in both human and machine-readable forms.
    pub fn write_last_violation(&self, violation: &PolicyViolation) -> Result<(), String> {
        fs::create_dir_all(&self.directory)
            .map_err(|error| format!("failed to create feedback directory: {error}"))?;
        atomic_write(
            &self.path(),
            render_violation_feedback(violation).as_bytes(),
        )?;
        atomic_write(
            &self.json_path(),
            format!("{}\n", render_machine_tag(violation)).as_bytes(),
        )
    }

    /// Return the concrete feedback file path used by this writer.
    pub fn path(&self) -> PathBuf {
        last_violation_path(&self.directory)
    }

    /// Return the machine-readable feedback file path used by this writer.
    pub fn json_path(&self) -> PathBuf {
        last_violation_json_path(&self.directory)
    }
}

/// Render a violation feedback file for agent harness hooks.
pub fn render_violation_feedback(violation: &PolicyViolation) -> String {
    format!(
        "Apolysis policy violation\nsession_id: {}\nrule_id: {}\ndecision: {}\ntarget: {}\npid: {}\nbackend: {}\nreason: {}\n{} {}\n",
        violation.session_id,
        violation.rule_id,
        violation.decision.as_str(),
        violation.target,
        violation.pid,
        violation.enforcement_backend.as_str(),
        violation.reason,
        feedback::VIOLATION_TAG,
        render_machine_tag(violation)
    )
}

fn render_machine_tag(violation: &PolicyViolation) -> String {
    format!(
        "{{\"session_id\":{},\"rule_id\":{},\"decision\":{},\"target\":{},\"pid\":{},\"enforcement_backend\":{},\"reason\":{}}}",
        json_string(&violation.session_id),
        json_string(&violation.rule_id),
        json_string(violation.decision.as_str()),
        json_string(&violation.target),
        violation.pid,
        json_string(violation.enforcement_backend.as_str()),
        json_string(&violation.reason)
    )
}

/// Return the conventional feedback file path for a directory.
pub fn last_violation_path(directory: impl AsRef<Path>) -> PathBuf {
    directory.as_ref().join(feedback::LAST_VIOLATION_FILE)
}

/// Return the conventional machine-readable feedback path for a directory.
pub fn last_violation_json_path(directory: impl AsRef<Path>) -> PathBuf {
    directory
        .as_ref()
        .join(feedback::LAST_VIOLATION_JSON_FILE)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("feedback path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("feedback path is not valid UTF-8: {}", path.display()))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed)
    ));

    let result = (|| -> Result<(), String> {
        let mut file = fs::File::create(&temporary)
            .map_err(|error| format!("failed to create feedback temporary file: {error}"))?;
        file.write_all(contents)
            .map_err(|error| format!("failed to write feedback temporary file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync feedback temporary file: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("failed to replace feedback file: {error}"))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync feedback directory: {error}"))
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

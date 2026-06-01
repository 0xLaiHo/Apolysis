// SPDX-License-Identifier: Apache-2.0

//! Agent-facing violation feedback files.
//!
//! The feedback file is intentionally simple text: agent harness hooks can read
//! it without linking against Apolysis, while the final `APOLYSIS_VIOLATION`
//! line keeps a compact machine-readable payload for future Claude/Codex hooks.

use std::fs;
use std::path::{Path, PathBuf};

use apolysis_core::{json_string, PolicyViolation};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedbackWriter {
    directory: PathBuf,
}

impl FeedbackWriter {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn write_last_violation(&self, violation: &PolicyViolation) -> Result<(), String> {
        fs::create_dir_all(&self.directory)
            .map_err(|error| format!("failed to create feedback directory: {error}"))?;
        fs::write(self.path(), render_violation_feedback(violation))
            .map_err(|error| format!("failed to write violation feedback: {error}"))
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join("last-violation.txt")
    }
}

pub fn render_violation_feedback(violation: &PolicyViolation) -> String {
    format!(
        "Apolysis policy violation\nsession_id: {}\nrule_id: {}\ndecision: {}\ntarget: {}\npid: {}\nbackend: {}\nreason: {}\nAPOLYSIS_VIOLATION {}\n",
        violation.session_id,
        violation.rule_id,
        violation.decision.as_str(),
        violation.target,
        violation.pid,
        violation.enforcement_backend.as_str(),
        violation.reason,
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

pub fn last_violation_path(directory: impl AsRef<Path>) -> PathBuf {
    directory.as_ref().join("last-violation.txt")
}

// SPDX-License-Identifier: Apache-2.0

use crate::{json_string, optional_json_string, records, JsonLine};

/// An explicitly supplied reason, stored separately from execution declarations.
///
/// A reason is an annotation, not proof of causality or authorization. Producers
/// must opt in to retaining a summary; prompts and tool arguments are not fields
/// in this record. Corrections append a new record rather than replacing history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIntentReasonRecord {
    pub timestamp_unix_ms: u128,
    pub session_id: String,
    pub intent_id: String,
    pub intent_source: String,
    pub harness_session_id: String,
    pub source_event_id: String,
    pub reason_id: String,
    pub reason_code: String,
    pub reason_source: String,
    pub reason_summary: Option<String>,
    pub task_ref: Option<String>,
    pub supersedes_reason_id: Option<String>,
}

impl SessionIntentReasonRecord {
    /// Validate field constraints. Cross-record correction checks belong to the
    /// append store, which can inspect the complete history while holding a lock.
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            &self.session_id,
            &self.intent_source,
            &self.harness_session_id,
            &self.source_event_id,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err("intent reason requires a complete nonempty call identity");
        }
        if self.intent_id.len() != 32
            || !self
                .intent_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("intent reason requires a 32-character lowercase hexadecimal intent ID");
        }
        if !opaque_reference(&self.reason_id)
            || self
                .task_ref
                .as_deref()
                .is_some_and(|value| !opaque_reference(value))
            || self
                .supersedes_reason_id
                .as_deref()
                .is_some_and(|value| !opaque_reference(value))
        {
            return Err("reason references must contain 1 to 64 ASCII letters, digits, underscores or hyphens");
        }
        if self.supersedes_reason_id.as_deref() == Some(self.reason_id.as_str()) {
            return Err("an intent reason cannot supersede itself");
        }
        if !matches!(
            self.reason_code.as_str(),
            "unknown"
                | "inspect_context"
                | "verify_change"
                | "reproduce_issue"
                | "implement_change"
                | "diagnose_failure"
                | "gather_evidence"
        ) {
            return Err("unsupported intent reason code");
        }
        if !matches!(
            self.reason_source.as_str(),
            "agent_declared" | "tool_description" | "operator_annotation"
        ) {
            return Err("unsupported intent reason source");
        }
        if self.reason_source == "tool_description" && self.reason_code != "unknown" {
            return Err("a tool description must use the unknown reason code");
        }
        if let Some(summary) = &self.reason_summary {
            if summary.chars().count() > 240
                || summary.chars().any(|character| {
                    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
                })
            {
                return Err("intent reason summary must be one line of at most 240 characters without control characters");
            }
        }
        Ok(())
    }

    pub fn to_json_line(&self) -> String {
        <Self as JsonLine>::to_json_line(self)
    }
}

fn opaque_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

impl JsonLine for SessionIntentReasonRecord {
    fn to_json_line(&self) -> String {
        format!(
            "{{\"record_type\":{},\"timestamp_unix_ms\":{},\"session_id\":{},\"intent_id\":{},\"intent_source\":{},\"harness_session_id\":{},\"source_event_id\":{},\"reason_id\":{},\"reason_code\":{},\"reason_source\":{},\"reason_summary\":{},\"task_ref\":{},\"supersedes_reason_id\":{}}}",
            json_string(records::INTENT_REASON),
            self.timestamp_unix_ms,
            json_string(&self.session_id),
            json_string(&self.intent_id),
            json_string(&self.intent_source),
            json_string(&self.harness_session_id),
            json_string(&self.source_event_id),
            json_string(&self.reason_id),
            json_string(&self.reason_code),
            json_string(&self.reason_source),
            optional_json_string(self.reason_summary.as_deref()),
            optional_json_string(self.task_ref.as_deref()),
            optional_json_string(self.supersedes_reason_id.as_deref()),
        )
    }
}

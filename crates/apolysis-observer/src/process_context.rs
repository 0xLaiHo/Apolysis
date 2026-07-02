// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use apolysis_core::{CanonicalEvent, EventType, RawKernelEvent};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessContext {
    command: String,
    executable: String,
    started_at_unix_ms: u128,
}

#[derive(Default)]
pub(crate) struct ProcessContextTable {
    by_pid: HashMap<u32, ProcessContext>,
}

impl ProcessContextTable {
    pub(crate) fn observe(
        &mut self,
        raw: &RawKernelEvent,
        canonical: CanonicalEvent,
    ) -> CanonicalEvent {
        if canonical.event_type == EventType::Exec {
            let context = ProcessContext {
                command: exec_command(raw).unwrap_or_else(|| raw.resource.clone()),
                executable: raw.resource.clone(),
                started_at_unix_ms: raw.timestamp_unix_ms,
            };
            self.by_pid.insert(raw.pid, context);
        }

        let enriched = if should_enrich(&canonical.event_type) {
            if let Some(context) = self.by_pid.get(&raw.pid) {
                canonical.with_process_context(
                    context.command.clone(),
                    context.executable.clone(),
                    context.started_at_unix_ms,
                )
            } else {
                canonical
            }
        } else {
            canonical
        };

        if enriched.event_type == EventType::ProcessExit {
            self.by_pid.remove(&raw.pid);
        }

        enriched
    }
}

fn should_enrich(event_type: &EventType) -> bool {
    matches!(
        event_type,
        EventType::Exec
            | EventType::FileOpen
            | EventType::FileCreate
            | EventType::FileTruncate
            | EventType::FileUnlink
            | EventType::FileRename
            | EventType::CredentialRead
            | EventType::NetworkConnect
            | EventType::ProcessExit
    )
}

fn exec_command(raw: &RawKernelEvent) -> Option<String> {
    let command = raw
        .raw_payload
        .strip_prefix("argv:")
        .or_else(|| raw.raw_payload.strip_prefix("argv="))?;
    let command = strip_exec_payload_marker(command, "payload_truncated:true");
    let command = strip_exec_payload_marker(command, "argv_truncated:true");
    let command = strip_exec_payload_marker(command, "resource_truncated:true");
    let command = command.trim();
    if command.is_empty() {
        None
    } else {
        Some(command.to_string())
    }
}

fn strip_exec_payload_marker<'a>(value: &'a str, marker: &str) -> &'a str {
    value
        .strip_suffix(marker)
        .and_then(|value| value.strip_suffix(','))
        .unwrap_or(value)
}

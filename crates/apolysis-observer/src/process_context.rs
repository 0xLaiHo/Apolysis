// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use apolysis_core::{CanonicalEvent, EventType, RawKernelEvent};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessContext {
    command: String,
    executable: String,
    started_at_unix_ms: u128,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ProcessContextKey {
    Stable {
        host_boot_id: String,
        process_generation: u64,
        exec_generation: u32,
    },
    LegacyPid(u32),
}

impl ProcessContextKey {
    fn from_raw(raw: &RawKernelEvent) -> Self {
        match (
            raw.host_boot_id.as_deref(),
            raw.process_generation,
            raw.exec_generation,
        ) {
            (Some(host_boot_id), Some(process_generation), Some(exec_generation)) => Self::Stable {
                host_boot_id: host_boot_id.to_string(),
                process_generation,
                exec_generation,
            },
            _ => Self::LegacyPid(raw.pid),
        }
    }

    fn belongs_to_process(&self, host_boot_id: &str, process_generation: u64) -> bool {
        matches!(
            self,
            Self::Stable {
                host_boot_id: candidate_boot_id,
                process_generation: candidate_generation,
                ..
            } if candidate_boot_id == host_boot_id && *candidate_generation == process_generation
        )
    }
}

#[derive(Default)]
pub(crate) struct ProcessContextTable {
    by_identity: HashMap<ProcessContextKey, ProcessContext>,
}

impl ProcessContextTable {
    pub(crate) fn observe(
        &mut self,
        raw: &RawKernelEvent,
        canonical: CanonicalEvent,
    ) -> CanonicalEvent {
        let key = ProcessContextKey::from_raw(raw);
        if canonical.event_type == EventType::Exec {
            if let ProcessContextKey::Stable {
                host_boot_id,
                process_generation,
                ..
            } = &key
            {
                self.by_identity.retain(|candidate, _| {
                    !candidate.belongs_to_process(host_boot_id, *process_generation)
                });
            }
            let context = ProcessContext {
                command: exec_command(raw).unwrap_or_else(|| raw.resource.clone()),
                executable: raw.resource.clone(),
                started_at_unix_ms: raw.timestamp_unix_ms,
            };
            self.by_identity.insert(key.clone(), context);
        }

        let enriched = if should_enrich(&canonical.event_type) {
            if let Some(context) = self.by_identity.get(&key) {
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
            self.by_identity.remove(&key);
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

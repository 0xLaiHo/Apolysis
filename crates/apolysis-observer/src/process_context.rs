// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use apolysis_core::{CanonicalEvent, EventType, RawKernelEvent};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessContext {
    command: String,
    executable: String,
    started_at_unix_ms: u128,
    intent_id: Option<String>,
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
            let command = exec_command(raw).unwrap_or_else(|| raw.resource.clone());
            let own = intent_id_from_command(&command);
            let inherited = self
                .by_pid
                .get(&raw.ppid)
                .and_then(|parent| parent.intent_id.clone());
            let context = ProcessContext {
                command,
                executable: raw.resource.clone(),
                started_at_unix_ms: raw.timestamp_unix_ms,
                intent_id: own.or(inherited),
            };
            self.by_pid.insert(raw.pid, context);
        }

        let enriched = if should_enrich(&canonical.event_type) {
            if let Some(context) = self.by_pid.get(&raw.pid) {
                let intent_id = context.intent_id.clone();
                let mut event = canonical.with_process_context(
                    context.command.clone(),
                    context.executable.clone(),
                    context.started_at_unix_ms,
                );
                if let Some(intent_id) = intent_id {
                    event = event.with_intent_id(intent_id);
                }
                event
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

fn valid_intent_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '-' | '.'))
}

fn intent_id_from_command(command: &str) -> Option<String> {
    let prefix = format!("{}=", apolysis_core::env::INTENT_ID);
    command.split_whitespace().find_map(|token| {
        let value = token.strip_prefix(&prefix)?;
        valid_intent_id(value).then(|| value.to_string())
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use apolysis_core::{EventSource, EventType, RawKernelEvent};

    fn exec(pid: u32, ppid: u32, argv: &str) -> RawKernelEvent {
        RawKernelEvent::new(
            1_780_328_000_000,
            "session-intent",
            EventSource::KernelTracepoint,
            "sched_process_exec",
            pid,
            ppid,
            1000,
            1000,
            "bash",
            "/bin/bash",
            "exec",
            None,
            None,
            argv,
        )
    }

    #[test]
    fn shell_token_is_kept_and_inherited_by_the_child_exec() {
        let mut table = ProcessContextTable::default();
        let shell = table.observe(
            &exec(
                40,
                1,
                "argv:/bin/bash -lc APOLYSIS_INTENT_ID=claude:toolu_1 cargo test",
            ),
            CanonicalEvent::new(
                "session-intent",
                EventSource::KernelTracepoint,
                EventType::Exec,
                40,
                1,
                "bash",
                "/bin/bash",
                "exec",
            ),
        );
        assert_eq!(shell.intent_id.as_deref(), Some("claude:toolu_1"));

        let child = table.observe(
            &exec(41, 40, "argv:/usr/bin/cargo test"),
            CanonicalEvent::new(
                "session-intent",
                EventSource::KernelTracepoint,
                EventType::Exec,
                41,
                40,
                "cargo",
                "/usr/bin/cargo",
                "exec",
            ),
        );
        assert_eq!(child.intent_id.as_deref(), Some("claude:toolu_1"));
    }

    #[test]
    fn malformed_intent_token_is_ignored() {
        let mut table = ProcessContextTable::default();
        let event = table.observe(
            &exec(
                7,
                1,
                "argv:/bin/bash -lc APOLYSIS_INTENT_ID=bad=id cargo test",
            ),
            CanonicalEvent::new(
                "session-intent",
                EventSource::KernelTracepoint,
                EventType::Exec,
                7,
                1,
                "bash",
                "/bin/bash",
                "exec",
            ),
        );
        assert_eq!(event.intent_id, None);
    }
}

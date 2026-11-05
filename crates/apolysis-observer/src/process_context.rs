// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use apolysis_core::{CanonicalEvent, EventType, RawKernelEvent};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessContext {
    command: String,
    executable: String,
    started_at_unix_ms: u128,
    intent_id: Option<String>,
    generation: Option<u64>,
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
        let own = raw
            .intent_id
            .as_ref()
            .filter(|id| valid_intent_id(id))
            .cloned();
        // Live events carry authoritative kernel attribution, including absence.
        // Fixtures without kernel identity can exercise lifecycle inheritance.
        let live_identity = raw.process_start_time_ns.is_some();
        let previous = self
            .by_pid
            .get(&raw.pid)
            .filter(|context| context.generation == raw.process_start_time_ns)
            .cloned();
        let parent = self
            .by_pid
            .get(&raw.ppid)
            .filter(|context| context.generation == raw.parent_start_time_ns)
            .cloned();
        let is_fork = raw.event_name == "sched_process_fork";
        let older_generation = self.by_pid.get(&raw.pid).is_some_and(|context| {
            matches!((context.generation, raw.process_start_time_ns),
                (Some(current), Some(incoming)) if incoming < current)
        });

        if (canonical.event_type == EventType::Exec || is_fork) && !older_generation {
            let inherited = if is_fork {
                parent.as_ref()
            } else {
                previous.as_ref().or(parent.as_ref())
            };
            let intent_id = if live_identity {
                own.clone()
            } else {
                own.clone()
                    .or_else(|| inherited.and_then(|context| context.intent_id.clone()))
            };
            let (command, executable) = if is_fork {
                parent
                    .as_ref()
                    .map(|context| (context.command.clone(), context.executable.clone()))
                    .unwrap_or_else(|| (raw.comm.clone(), raw.resource.clone()))
            } else {
                (
                    exec_command(raw).unwrap_or_else(|| raw.resource.clone()),
                    raw.resource.clone(),
                )
            };
            let context = ProcessContext {
                command,
                executable,
                started_at_unix_ms: raw.timestamp_unix_ms,
                intent_id,
                generation: raw.process_start_time_ns,
            };
            self.by_pid.insert(raw.pid, context);
        }

        let mut enriched = canonical;
        if should_enrich(&enriched.event_type) || is_fork {
            if let Some(context) = self
                .by_pid
                .get(&raw.pid)
                .filter(|context| context.generation == raw.process_start_time_ns)
            {
                enriched = enriched.with_process_context(
                    context.command.clone(),
                    context.executable.clone(),
                    context.started_at_unix_ms,
                );
                if !live_identity {
                    enriched.intent_id = own.clone().or_else(|| context.intent_id.clone());
                }
            }
            if live_identity || own.is_some() {
                // No userspace fallback: a map-pressure loss or an unobserved
                // new exec must never resurrect the previous tool's token.
                enriched.intent_id = own;
            }
        }

        if enriched.event_type == EventType::ProcessExit
            && self
                .by_pid
                .get(&raw.pid)
                .is_some_and(|context| context.generation == raw.process_start_time_ns)
        {
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
    value.len() == crate::abi::INTENT_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exec_command(raw: &RawKernelEvent) -> Option<String> {
    let command = raw
        .raw_payload
        .strip_prefix("argv:")
        .or_else(|| raw.raw_payload.strip_prefix("argv="))?;
    let command = strip_exec_payload_marker(command, "intent_capture_incomplete:true");
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
    use apolysis_core::EventSource;

    const FIRST: &str = "0123456789abcdef0123456789abcdef";
    const SECOND: &str = "abcdef0123456789abcdef0123456789";

    fn raw(pid: u32, ppid: u32, event: &str) -> RawKernelEvent {
        RawKernelEvent::new(
            100,
            "session",
            EventSource::KernelTracepoint,
            event,
            pid,
            ppid,
            1000,
            1000,
            "bash",
            "/bin/bash",
            "action",
            None,
            None,
            "",
        )
    }

    fn observe(table: &mut ProcessContextTable, raw: RawKernelEvent) -> CanonicalEvent {
        let event_type = match raw.event_name.as_str() {
            "exec" => EventType::Exec,
            "exit" => EventType::ProcessExit,
            "open" => EventType::FileOpen,
            _ => EventType::RuntimeMetadata,
        };
        let canonical = CanonicalEvent::new(
            &raw.session_id,
            EventSource::KernelTracepoint,
            event_type,
            raw.pid,
            raw.ppid,
            &raw.comm,
            &raw.resource,
            &raw.action,
        );
        table.observe(&raw, canonical)
    }

    #[test]
    fn same_pid_exec_preserves_fixture_token_and_new_token_overrides_it() {
        let mut table = ProcessContextTable::default();
        observe(&mut table, raw(40, 1, "exec").with_intent_id(FIRST));
        let exec = observe(&mut table, raw(40, 1, "exec"));
        assert_eq!(exec.intent_id.as_deref(), Some(FIRST));
        let exec = observe(&mut table, raw(40, 1, "exec").with_intent_id(SECOND));
        assert_eq!(exec.intent_id.as_deref(), Some(SECOND));
        assert_eq!(
            observe(&mut table, raw(40, 1, "open")).intent_id.as_deref(),
            Some(SECOND)
        );
    }

    #[test]
    fn fork_only_child_keeps_context_after_parent_exit() {
        let mut table = ProcessContextTable::default();
        observe(&mut table, raw(40, 1, "exec").with_intent_id(FIRST));
        observe(&mut table, raw(41, 40, "sched_process_fork"));
        observe(&mut table, raw(40, 1, "exit"));
        assert_eq!(
            observe(&mut table, raw(41, 1, "open")).intent_id.as_deref(),
            Some(FIRST)
        );
        assert_eq!(
            observe(&mut table, raw(41, 1, "exec")).intent_id.as_deref(),
            Some(FIRST)
        );
    }

    #[test]
    fn kernel_attribution_survives_missing_lifecycle_events() {
        let mut table = ProcessContextTable::default();
        let event = observe(
            &mut table,
            raw(41, 40, "open")
                .with_process_identity(1000, Some(500))
                .with_intent_id(FIRST),
        );
        assert_eq!(event.intent_id.as_deref(), Some(FIRST));
        assert_eq!(event.process_executable, None);
    }

    #[test]
    fn missing_live_token_never_resurrects_stale_userspace_attribution() {
        let mut table = ProcessContextTable::default();
        observe(
            &mut table,
            raw(40, 1, "exec")
                .with_process_identity(1000, None)
                .with_intent_id(FIRST),
        );
        let missing = observe(
            &mut table,
            raw(40, 1, "open").with_process_identity(1000, None),
        );
        assert_eq!(missing.intent_id, None);
        let changed = observe(
            &mut table,
            raw(40, 1, "open")
                .with_process_identity(1000, None)
                .with_intent_id(SECOND),
        );
        assert_eq!(changed.intent_id.as_deref(), Some(SECOND));
    }

    #[test]
    fn reused_pid_and_delayed_exit_do_not_transfer_or_delete_new_context() {
        let mut table = ProcessContextTable::default();
        observe(
            &mut table,
            raw(40, 1, "exec")
                .with_process_identity(1000, None)
                .with_intent_id(FIRST),
        );
        let reused = observe(
            &mut table,
            raw(40, 1, "open").with_process_identity(2000, None),
        );
        assert_eq!(reused.intent_id, None);
        assert_eq!(reused.process_executable, None);
        observe(
            &mut table,
            raw(40, 1, "exec")
                .with_process_identity(2000, None)
                .with_intent_id(SECOND),
        );
        observe(
            &mut table,
            raw(40, 1, "exit").with_process_identity(1000, None),
        );
        let current = observe(
            &mut table,
            raw(40, 1, "open")
                .with_process_identity(2000, None)
                .with_intent_id(SECOND),
        );
        assert_eq!(current.intent_id.as_deref(), Some(SECOND));
        assert_eq!(current.process_executable.as_deref(), Some("/bin/bash"));
    }

    #[test]
    fn diagnostic_argv_never_imparts_attribution() {
        for command in [
            format!("argv:/bin/echo APOLYSIS_INTENT_ID={FIRST}"),
            format!("argv:/bin/bash -c # APOLYSIS_INTENT_ID={FIRST}\ntrue"),
            "argv:/bin/bash -c # APOLYSIS_INTENT_ID=012345,argv_truncated:true".to_string(),
        ] {
            let mut table = ProcessContextTable::default();
            let mut input = raw(40, 1, "exec");
            input.raw_payload = command;
            assert_eq!(observe(&mut table, input).intent_id, None);
        }
    }

    #[test]
    fn malformed_transport_tokens_are_ignored() {
        for token in [
            "",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdef0",
        ] {
            let mut table = ProcessContextTable::default();
            assert_eq!(
                observe(&mut table, raw(40, 1, "exec").with_intent_id(token)).intent_id,
                None
            );
        }
    }
}

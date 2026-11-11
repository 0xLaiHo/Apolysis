// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use apolysis_core::{CanonicalEvent, EventType, RawKernelEvent};

const MAX_PROCESS_CONTEXTS: usize = 16_384;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessContext {
    command: String,
    executable: String,
    started_at_unix_ms: u128,
    intent_id: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum ProcessContextKey {
    Stable {
        host_boot_id: String,
        pid: u32,
        process_generation: u64,
        exec_generation: u32,
    },
    LegacyPid(u32),
}

impl ProcessContextKey {
    fn from_raw(raw: &RawKernelEvent) -> Option<Self> {
        match (
            raw.host_boot_id.as_deref(),
            raw.process_generation,
            raw.exec_generation,
        ) {
            (Some(host_boot_id), Some(process_generation), Some(exec_generation)) => {
                Some(Self::Stable {
                    host_boot_id: host_boot_id.to_string(),
                    pid: raw.pid,
                    process_generation,
                    exec_generation,
                })
            }
            (None, None, None)
                if raw.scope_generation.is_none()
                    && raw.process_start_time_ns.is_none()
                    && raw.parent_process_generation.is_none()
                    && raw.parent_exec_generation.is_none() =>
            {
                Some(Self::LegacyPid(raw.pid))
            }
            _ => None,
        }
    }

    fn belongs_to_process(&self, host_boot_id: &str, pid: u32, process_generation: u64) -> bool {
        matches!(
            self,
            Self::Stable {
                host_boot_id: candidate_boot_id,
                pid: candidate_pid,
                process_generation: candidate_generation,
                ..
            } if candidate_boot_id == host_boot_id
                && *candidate_pid == pid
                && *candidate_generation == process_generation
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
        mut canonical: CanonicalEvent,
    ) -> Result<CanonicalEvent, String> {
        let key = ProcessContextKey::from_raw(raw);
        let own = raw
            .intent_id
            .as_ref()
            .filter(|id| valid_intent_id(id))
            .cloned();
        // Only identity-free fixtures inherit in userspace; live absence is authoritative.
        let legacy = matches!(key, Some(ProcessContextKey::LegacyPid(_)));
        let is_fork = raw.event_name == "sched_process_fork";
        let parent_key = match key.as_ref() {
            Some(ProcessContextKey::Stable { host_boot_id, .. }) => raw
                .parent_process_generation
                .zip(raw.parent_exec_generation)
                .map(
                    |(process_generation, exec_generation)| ProcessContextKey::Stable {
                        host_boot_id: host_boot_id.clone(),
                        pid: raw.ppid,
                        process_generation,
                        exec_generation,
                    },
                ),
            Some(ProcessContextKey::LegacyPid(_)) => Some(ProcessContextKey::LegacyPid(raw.ppid)),
            None => None,
        };
        let parent = parent_key
            .as_ref()
            .and_then(|key| self.by_identity.get(key))
            .cloned();
        let previous = key
            .as_ref()
            .and_then(|key| self.by_identity.get(key))
            .cloned();
        if canonical.event_type == EventType::Exec || is_fork {
            if let Some(ProcessContextKey::Stable {
                host_boot_id,
                pid,
                process_generation,
                ..
            }) = key.as_ref()
            {
                self.by_identity.retain(|candidate, _| {
                    !candidate.belongs_to_process(host_boot_id, *pid, *process_generation)
                });
            }
            if let Some(key) = key.as_ref() {
                if !self.by_identity.contains_key(key)
                    && self.by_identity.len() >= MAX_PROCESS_CONTEXTS
                {
                    return Err(format!(
                        "process context capacity {MAX_PROCESS_CONTEXTS} exceeded"
                    ));
                }
                self.by_identity.insert(
                    key.clone(),
                    ProcessContext {
                        command: if is_fork {
                            parent
                                .as_ref()
                                .map(|context| context.command.clone())
                                .unwrap_or_else(|| raw.comm.clone())
                        } else {
                            exec_command(raw).unwrap_or_else(|| raw.resource.clone())
                        },
                        executable: if is_fork {
                            parent
                                .as_ref()
                                .map(|context| context.executable.clone())
                                .unwrap_or_else(|| raw.resource.clone())
                        } else {
                            raw.resource.clone()
                        },
                        started_at_unix_ms: raw.timestamp_unix_ms,
                        intent_id: own.clone().or_else(|| {
                            if legacy {
                                (if is_fork {
                                    parent.as_ref()
                                } else {
                                    previous.as_ref().or(parent.as_ref())
                                })
                                .and_then(|context| context.intent_id.clone())
                            } else {
                                None
                            }
                        }),
                    },
                );
            }
        }

        canonical.intent_id = own;
        let enriched = if should_enrich(&canonical.event_type) || is_fork {
            if let Some(context) = key.as_ref().and_then(|key| self.by_identity.get(key)) {
                if legacy && canonical.intent_id.is_none() {
                    canonical.intent_id = context.intent_id.clone();
                }
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
            if let Some(key) = key.as_ref() {
                self.by_identity.remove(key);
            }
        }

        Ok(enriched)
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

fn valid_intent_id(value: &str) -> bool {
    value.len() == crate::abi::INTENT_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    use apolysis_core::{EventSource, RuntimeRelation};

    const FIRST: &str = "0123456789abcdef0123456789abcdef";
    const SECOND: &str = "abcdef0123456789abcdef0123456789";

    fn fixture(pid: u32, ppid: u32, event: &str) -> RawKernelEvent {
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
        table
            .observe(&raw, canonical_event(event_type, raw.pid))
            .unwrap()
    }

    #[test]
    fn fixtures_inherit_across_exec_and_fork_but_new_tokens_override() {
        let mut table = ProcessContextTable::default();
        observe(&mut table, fixture(40, 1, "exec").with_intent_id(FIRST));
        assert_eq!(
            observe(&mut table, fixture(40, 1, "exec"))
                .intent_id
                .as_deref(),
            Some(FIRST)
        );
        observe(&mut table, fixture(41, 40, "sched_process_fork"));
        observe(&mut table, fixture(40, 1, "exit"));
        assert_eq!(
            observe(&mut table, fixture(41, 1, "open"))
                .intent_id
                .as_deref(),
            Some(FIRST)
        );
        assert_eq!(
            observe(&mut table, fixture(41, 1, "exec"))
                .intent_id
                .as_deref(),
            Some(FIRST)
        );
        observe(&mut table, fixture(41, 1, "exec").with_intent_id(SECOND));
        assert_eq!(
            observe(&mut table, fixture(41, 1, "open"))
                .intent_id
                .as_deref(),
            Some(SECOND)
        );
    }

    fn live(pid: u32, event: &str, generation: u64) -> RawKernelEvent {
        fixture(pid, 1, event).with_process_identity(
            Some("boot-test".into()),
            Some(1),
            Some(generation),
            Some(generation),
            Some(1),
            None,
            None,
        )
    }

    #[test]
    fn kernel_tokens_are_authoritative_even_without_lifecycle_events() {
        let mut table = ProcessContextTable::default();
        let event = observe(&mut table, live(41, "open", 1000).with_intent_id(FIRST));
        assert_eq!(event.intent_id.as_deref(), Some(FIRST));
        assert_eq!(event.process_executable, None);
        observe(&mut table, live(40, "exec", 1000).with_intent_id(FIRST));
        assert_eq!(observe(&mut table, live(40, "open", 1000)).intent_id, None);
        assert_eq!(
            observe(&mut table, live(40, "open", 1000).with_intent_id(SECOND))
                .intent_id
                .as_deref(),
            Some(SECOND)
        );
    }

    #[test]
    fn reused_pid_and_delayed_exit_do_not_transfer_or_delete_new_context() {
        let mut table = ProcessContextTable::default();
        observe(&mut table, live(40, "exec", 1000).with_intent_id(FIRST));
        let reused = observe(&mut table, live(40, "open", 2000));
        assert_eq!(reused.intent_id, None);
        assert_eq!(reused.process_executable, None);
        observe(&mut table, live(40, "exec", 2000).with_intent_id(SECOND));
        observe(&mut table, live(40, "exit", 1000));
        let current = observe(&mut table, live(40, "open", 2000).with_intent_id(SECOND));
        assert_eq!(current.intent_id.as_deref(), Some(SECOND));
        assert_eq!(current.process_executable.as_deref(), Some("/bin/bash"));
    }

    #[test]
    fn diagnostic_argv_and_malformed_tokens_never_impart_attribution() {
        for token in [
            "",
            "0123456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdef0",
        ] {
            let mut table = ProcessContextTable::default();
            let mut raw = fixture(40, 1, "exec").with_intent_id(token);
            raw.raw_payload = format!("argv:/bin/bash -c # APOLYSIS_INTENT_ID={FIRST}\ntrue");
            assert_eq!(observe(&mut table, raw).intent_id, None);
        }
    }

    #[test]
    fn partial_live_identity_never_falls_back_to_pid_context() {
        let mut contexts = ProcessContextTable::default();
        let exec = raw_event("sched_process_exec", 44, None, Some(1));
        assert_eq!(exec.relation_status, RuntimeRelation::Inferred);

        let exec_event = contexts
            .observe(&exec, canonical_event(EventType::Exec, 44))
            .expect("observe partial exec identity");
        assert_eq!(exec_event.process_executable, None);

        let file = raw_event("openat", 44, None, Some(1));
        let file_event = contexts
            .observe(&file, canonical_event(EventType::FileOpen, 44))
            .expect("observe partial file identity");
        assert_eq!(file_event.process_executable, None);
    }

    #[test]
    fn process_context_capacity_fails_loud() {
        let mut contexts = ProcessContextTable::default();
        for pid in 1..=MAX_PROCESS_CONTEXTS as u32 {
            let raw = raw_event("sched_process_exec", pid, Some(u64::from(pid)), Some(1));
            contexts
                .observe(&raw, canonical_event(EventType::Exec, pid))
                .expect("context within capacity");
        }

        let overflow_pid = MAX_PROCESS_CONTEXTS as u32 + 1;
        let overflow = raw_event(
            "sched_process_exec",
            overflow_pid,
            Some(u64::from(overflow_pid)),
            Some(1),
        );
        let error = contexts
            .observe(&overflow, canonical_event(EventType::Exec, overflow_pid))
            .expect_err("context table pressure must fail loud");

        assert!(error.contains("process context capacity"));
    }

    fn raw_event(
        event_name: &str,
        pid: u32,
        process_generation: Option<u64>,
        exec_generation: Option<u32>,
    ) -> RawKernelEvent {
        RawKernelEvent::new(
            u128::from(pid),
            "session-context",
            EventSource::KernelTracepoint,
            event_name,
            pid,
            1,
            1000,
            1000,
            "tool",
            "/usr/bin/tool",
            "exec",
            None,
            Some("42".to_string()),
            "argv:/usr/bin/tool",
        )
        .with_process_identity(
            Some("11111111-2222-3333-4444-555555555555".to_string()),
            Some(1),
            process_generation,
            Some(u64::from(pid)),
            exec_generation,
            None,
            None,
        )
    }

    fn canonical_event(event_type: EventType, pid: u32) -> CanonicalEvent {
        CanonicalEvent::new(
            "session-context",
            EventSource::KernelTracepoint,
            event_type,
            pid,
            1,
            "tool",
            "/usr/bin/tool",
            "observe",
        )
    }
}

// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use apolysis_core::{CanonicalEvent, EventType, RawKernelEvent};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedValue {
    pub value: String,
    pub redacted: bool,
}

#[derive(Clone, Debug)]
pub struct Redactor {
    session_id: String,
    workspace_root: PathBuf,
}

impl Redactor {
    pub fn new(session_id: impl Into<String>, workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            session_id: session_id.into(),
            workspace_root: workspace_root.into(),
        }
    }

    pub fn redact_resource(&self, event_type: EventType, resource: &str) -> RedactedValue {
        match event_type {
            EventType::Exec => executable_reference(resource),
            EventType::CredentialRead => self.token("path", resource),
            EventType::FileOpen
            | EventType::FileCreate
            | EventType::FileTruncate
            | EventType::FileUnlink
            | EventType::FileRename => {
                if self.is_workspace_path(resource) {
                    RedactedValue {
                        value: resource.to_string(),
                        redacted: false,
                    }
                } else {
                    self.token("path", resource)
                }
            }
            EventType::NetworkConnect => {
                let port = socket_port(resource).unwrap_or("unknown");
                let token = self.token_value("address", resource);
                RedactedValue {
                    value: format!("address_token:{token}:port:{port}"),
                    redacted: true,
                }
            }
            _ => RedactedValue {
                value: resource.to_string(),
                redacted: false,
            },
        }
    }

    fn token(&self, kind: &str, value: &str) -> RedactedValue {
        RedactedValue {
            value: format!("{kind}_token:{}", self.token_value(kind, value)),
            redacted: true,
        }
    }

    fn token_value(&self, kind: &str, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_bytes());
        hasher.update([0]);
        hasher.update(kind.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        let digest = hasher.finalize();
        let mut token = String::with_capacity(24);
        for byte in &digest[..12] {
            use std::fmt::Write as _;
            write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
        }
        token
    }

    fn is_workspace_path(&self, resource: &str) -> bool {
        let path = Path::new(resource);
        if path.is_absolute() {
            return path.starts_with(&self.workspace_root);
        }
        relative_path_stays_in_workspace(path)
    }
}

fn relative_path_stays_in_workspace(path: &Path) -> bool {
    let mut depth = 0_u32;
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(_) => {
                depth = depth.saturating_add(1);
            }
            std::path::Component::ParentDir => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            std::path::Component::Prefix(_) | std::path::Component::RootDir => return false,
        }
    }
    true
}

fn redact_raw_event_for_persistence(
    raw: &RawKernelEvent,
    redactor: &Redactor,
    credential_read: bool,
) -> RawKernelEvent {
    let mut persisted = raw.clone();
    let event_type = match raw.event_name.as_str() {
        "exec" | "execve" | "execveat" | "sched_process_exec" => EventType::Exec,
        "open" | "openat" | "openat2" if credential_read => EventType::CredentialRead,
        "open" | "openat" | "openat2" => EventType::FileOpen,
        "creat" => EventType::FileCreate,
        "truncate" | "ftruncate" => EventType::FileTruncate,
        "unlink" | "unlinkat" => EventType::FileUnlink,
        "rename" | "renameat" | "renameat2" => EventType::FileRename,
        "connect" => EventType::NetworkConnect,
        _ => return persisted,
    };
    match event_type {
        EventType::Exec => {
            persisted.raw_payload = content_off_exec_payload(&raw.raw_payload);
            append_marker(&mut persisted.raw_payload, "redacted:payload");
        }
        EventType::FileRename if !raw.raw_payload.is_empty() => {
            let payload = redactor.redact_resource(EventType::FileRename, &raw.raw_payload);
            persisted.raw_payload = payload.value;
            if payload.redacted {
                append_marker(&mut persisted.raw_payload, "redacted:payload");
            }
        }
        _ => {}
    }
    let resource = redactor.redact_resource(event_type.clone(), &raw.resource);
    persisted.resource = resource.value;
    if resource.redacted {
        append_marker(&mut persisted.raw_payload, "redacted:resource");
    }
    persisted
}

/// The only persistence policy entry point for kernel-derived runtime events.
///
/// Kernel capture may transiently contain argv so process context can be
/// resolved, but persisted records keep only structure and truncation markers.
/// Raw argv and reconstructed process commands never cross this seam.
pub struct RuntimeEvidencePersistence<'a> {
    redactor: &'a Redactor,
}

impl<'a> RuntimeEvidencePersistence<'a> {
    /// Bind persistence policy to one session-scoped redactor.
    pub fn new(redactor: &'a Redactor) -> Self {
        Self { redactor }
    }

    /// Apply content-off policy to a raw event when no canonical event exists.
    pub fn persist_raw(&self, raw: &RawKernelEvent, credential_read: bool) -> RawKernelEvent {
        redact_raw_event_for_persistence(raw, self.redactor, credential_read)
    }

    /// Apply content-off policy to a joined raw and canonical event pair.
    pub fn persist_event(
        &self,
        raw: &RawKernelEvent,
        canonical: &CanonicalEvent,
        credential_read: bool,
    ) -> (RawKernelEvent, CanonicalEvent) {
        let persisted_raw = self.persist_raw(raw, credential_read);
        let mut persisted_canonical = canonical.clone();
        persisted_canonical.resource = self
            .redactor
            .redact_resource(canonical.event_type.clone(), &canonical.resource)
            .value;
        persisted_canonical.process_command = None;
        persisted_canonical.process_executable = canonical
            .process_executable
            .as_deref()
            .map(|value| executable_reference(value).value);
        (persisted_raw, persisted_canonical)
    }
}

pub fn redact_command_text_for_persistence(
    session_id: &str,
    workspace_root: &Path,
    command: &str,
) -> RedactedValue {
    let redactor = Redactor::new(session_id, workspace_root);
    let executable = command
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .map(|value| redactor.redact_resource(EventType::Exec, value).value)
        .unwrap_or_else(|| "executable:unavailable".to_string());
    RedactedValue {
        value: format!("{executable} argv_redacted:true"),
        redacted: true,
    }
}

fn content_off_exec_payload(payload: &str) -> String {
    let mut markers = vec!["argv_redacted:true"];
    for marker in [
        "resource_truncated:true",
        "argv_truncated:true",
        "payload_truncated:true",
    ] {
        if payload.split(',').any(|part| part == marker) {
            markers.push(marker);
        }
    }
    markers.join(",")
}

fn executable_reference(resource: &str) -> RedactedValue {
    let name = Path::new(resource)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-')
                })
        })
        .unwrap_or("unknown");
    RedactedValue {
        value: format!("executable_ref:{name}"),
        redacted: true,
    }
}

fn append_marker(payload: &mut String, marker: &str) {
    if !payload.is_empty() {
        payload.push(',');
    }
    payload.push_str(marker);
}

fn socket_port(resource: &str) -> Option<&str> {
    resource
        .rsplit_once(':')
        .map(|(_, port)| port)
        .filter(|port| port.parse::<u16>().is_ok())
}

// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use apolysis_core::{EventType, RawKernelEvent};
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

pub fn redact_raw_event_for_persistence(
    raw: &RawKernelEvent,
    redactor: &Redactor,
    credential_read: bool,
) -> RawKernelEvent {
    let mut persisted = raw.clone();
    let event_type = match raw.event_name.as_str() {
        "open" | "openat" | "openat2" if credential_read => EventType::CredentialRead,
        "open" | "openat" | "openat2" => EventType::FileOpen,
        "creat" => EventType::FileCreate,
        "truncate" | "ftruncate" => EventType::FileTruncate,
        "unlink" | "unlinkat" => EventType::FileUnlink,
        "rename" | "renameat" | "renameat2" => EventType::FileRename,
        "connect" => EventType::NetworkConnect,
        _ => return persisted,
    };
    let resource = redactor.redact_resource(event_type.clone(), &raw.resource);
    persisted.resource = resource.value;
    if resource.redacted {
        append_marker(&mut persisted.raw_payload, "redacted:resource");
    }
    if event_type == EventType::FileRename && !raw.raw_payload.is_empty() {
        let payload = redactor.redact_resource(EventType::FileRename, &raw.raw_payload);
        persisted.raw_payload = payload.value;
        if payload.redacted {
            append_marker(&mut persisted.raw_payload, "redacted:payload");
        }
    }
    persisted
}

pub fn redact_command_text_for_persistence(
    session_id: &str,
    workspace_root: &Path,
    command: &str,
) -> RedactedValue {
    let redactor = Redactor::new(session_id, workspace_root);
    let mut redacted = false;
    let mut redact_next = false;
    let mut args = Vec::new();
    for arg in command.split_whitespace() {
        if redact_next {
            args.push("<redacted>".to_string());
            redacted = true;
            redact_next = false;
            continue;
        }

        if secret_flag(arg) {
            args.push(arg.to_string());
            redact_next = true;
            continue;
        }

        if authorization_marker(arg) {
            args.push(arg.to_string());
            redact_next = true;
            continue;
        }

        if let Some((key, value)) = arg.split_once('=') {
            if secret_word(key) {
                args.push(format!("{key}=<redacted>"));
                redacted = true;
                continue;
            }
            let value = redact_command_argument_resource(&redactor, value);
            if value.redacted {
                redacted = true;
                args.push(format!("{key}={}", value.value));
                continue;
            }
        }

        if looks_like_secret_value(arg) {
            args.push("<redacted>".to_string());
            redacted = true;
            continue;
        }

        let value = redact_command_argument_resource(&redactor, arg);
        redacted |= value.redacted;
        args.push(value.value);
    }

    RedactedValue {
        value: args.join(" "),
        redacted,
    }
}

fn redact_command_argument_resource(redactor: &Redactor, value: &str) -> RedactedValue {
    if !looks_like_path_argument(value) {
        return RedactedValue {
            value: value.to_string(),
            redacted: false,
        };
    }
    let event_type = if looks_like_credential_path(value) {
        EventType::CredentialRead
    } else {
        EventType::FileOpen
    };
    redactor.redact_resource(event_type, value)
}

fn secret_flag(value: &str) -> bool {
    value.starts_with("--") && secret_word(value.trim_start_matches('-'))
}

fn secret_word(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "api-key",
        "apikey",
        "authorization",
    ]
    .iter()
    .any(|word| normalized.contains(word))
}

fn looks_like_secret_value(value: &str) -> bool {
    let normalized = value.trim_matches(|ch| matches!(ch, '\'' | '"' | ',' | ';'));
    normalized.starts_with("sk-")
        || normalized.starts_with("ghp_")
        || normalized.starts_with("github_pat_")
        || normalized.starts_with("Bearer ")
}

fn authorization_marker(value: &str) -> bool {
    let normalized = value
        .trim_matches(|ch| matches!(ch, '\'' | '"' | ',' | ';'))
        .trim_end_matches(':')
        .to_ascii_lowercase();
    normalized == "authorization" || normalized == "bearer"
}

fn looks_like_path_argument(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
}

fn looks_like_credential_path(value: &str) -> bool {
    value.ends_with("/.env")
        || value.contains("/.env.")
        || value.contains("/.ssh/")
        || value.contains("/.aws/")
        || value.contains("/var/run/secrets/")
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

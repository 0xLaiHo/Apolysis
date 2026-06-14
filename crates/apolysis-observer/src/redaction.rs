// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use apolysis_core::EventType;
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
                if Path::new(resource).starts_with(&self.workspace_root) {
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
}

fn socket_port(resource: &str) -> Option<&str> {
    resource
        .rsplit_once(':')
        .map(|(_, port)| port)
        .filter(|port| port.parse::<u16>().is_ok())
}

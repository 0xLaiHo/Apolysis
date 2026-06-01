// SPDX-License-Identifier: Apache-2.0

//! Policy parsing and audit-only decision logic for Apolysis.
//!
//! The M1 policy reader supports the small YAML subset used by
//! `policies/local-dev.yaml`.  This avoids pulling a YAML dependency before the
//! v1 schema is stable, while still giving tests and examples a real policy path.

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    pub credentials: CredentialPolicy,
    pub runtime: RuntimePolicy,
    pub workspace: WorkspacePolicy,
    pub commands: CommandPolicy,
    pub network: NetworkPolicy,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialPolicy {
    pub deny_read: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub max_seconds: Option<u64>,
    pub max_processes: Option<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkspacePolicy {
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandPolicy {
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkPolicy {
    pub allow_egress: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Notify { rule_id: String, reason: String },
}

impl Policy {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut policy = Self::default();
        let mut section = "";
        let mut list = "";

        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line == "---" {
                continue;
            }

            if !raw_line.starts_with(' ') && line.ends_with(':') {
                section = line.trim_end_matches(':');
                list = "";
                continue;
            }

            if line.ends_with(':') {
                list = line.trim_end_matches(':');
                continue;
            }

            if let Some(value) = line.strip_prefix("- ") {
                push_list_value(&mut policy, section, list, value.trim());
                continue;
            }

            if let Some(value) = line.strip_prefix("max_seconds:") {
                policy.runtime.max_seconds = Some(parse_u64("max_seconds", value)?);
                continue;
            }

            if let Some(value) = line.strip_prefix("max_processes:") {
                policy.runtime.max_processes = Some(parse_u64("max_processes", value)?);
            }
        }

        Ok(policy)
    }

    pub fn denies_credential_path(&self, path: &str) -> bool {
        self.credentials
            .deny_read
            .iter()
            .any(|pattern| path_matches(pattern, path))
    }

    pub fn evaluate_file_read(&self, path: &str) -> PolicyDecision {
        if self.denies_credential_path(path) {
            return PolicyDecision::Notify {
                rule_id: "credentials.deny_read".to_string(),
                reason: "file path matches credential deny list".to_string(),
            };
        }

        PolicyDecision::Allow
    }
}

fn push_list_value(policy: &mut Policy, section: &str, list: &str, value: &str) {
    match (section, list) {
        ("credentials", "deny_read") => policy.credentials.deny_read.push(value.to_string()),
        ("workspace", "allow_read") => policy.workspace.allow_read.push(value.to_string()),
        ("workspace", "allow_write") => policy.workspace.allow_write.push(value.to_string()),
        ("commands", "deny") => policy.commands.deny.push(value.to_string()),
        ("network", "allow_egress") => policy.network.allow_egress.push(value.to_string()),
        _ => {}
    }
}

fn parse_u64(field: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("invalid {field}: {error}"))
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if path == pattern || path.starts_with(&format!("{pattern}/")) {
        return true;
    }

    if let Some(home_relative) = pattern.strip_prefix("~/") {
        let suffix = format!("/{home_relative}");
        return path.ends_with(&suffix) || path.contains(&format!("{suffix}/"));
    }

    if !pattern.starts_with('/') {
        let suffix = format!("/{pattern}");
        return path.ends_with(&suffix) || path.contains(&format!("{suffix}/"));
    }

    false
}

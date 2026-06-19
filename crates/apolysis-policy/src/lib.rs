// SPDX-License-Identifier: Apache-2.0

//! Policy parsing and decision logic for Apolysis.
//!
//! The M5 reader supports the small YAML/JSON policy subset used by the
//! repository fixtures.  The engine keeps `Block` distinct from `Kill` and only
//! maps `Block` to a BPF-LSM backend when capability detection says that backend
//! is actually available.

use std::fs;

use apolysis_core::{
    env, scalars::clean_scalar, CanonicalEvent, EnforcementBackend, EventType,
    PolicyDecision as CorePolicyDecision,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    pub credentials: CredentialPolicy,
    pub runtime: RuntimePolicy,
    pub workspace: WorkspacePolicy,
    pub commands: CommandPolicy,
    pub network: NetworkPolicy,
    pub enforcement: EnforcementPolicy,
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
pub struct EnforcementPolicy {
    pub requested: DecisionKind,
    pub fallback: DecisionKind,
}

impl Default for EnforcementPolicy {
    fn default() -> Self {
        Self {
            requested: DecisionKind::Notify,
            fallback: DecisionKind::Notify,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionKind {
    Allow,
    Notify,
    Block,
    Kill,
    Review,
}

impl DecisionKind {
    /// Return the stable policy decision string used in policy files.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Notify => "notify",
            Self::Block => "block",
            Self::Kill => "kill",
            Self::Review => "review",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EnforcementRuntime {
    #[default]
    Local,
    Docker,
    Containerd,
    Kubernetes,
    Gvisor,
    Kata,
    Firecracker,
    Unknown,
}

impl EnforcementRuntime {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Docker => "docker",
            Self::Containerd => "containerd",
            Self::Kubernetes => "kubernetes",
            Self::Gvisor => "gvisor",
            Self::Kata => "kata",
            Self::Firecracker => "firecracker",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementAction {
    Exec,
    FileRead,
    FileWrite,
    NetworkConnect,
    CredentialRead,
    Other,
}

impl EnforcementAction {
    pub fn from_event_type(event_type: &EventType) -> Self {
        match event_type {
            EventType::Exec => Self::Exec,
            EventType::FileOpen => Self::FileRead,
            EventType::CredentialRead => Self::CredentialRead,
            EventType::FileCreate
            | EventType::FileTruncate
            | EventType::FileUnlink
            | EventType::FileRename => Self::FileWrite,
            EventType::NetworkConnect => Self::NetworkConnect,
            EventType::SessionStarted | EventType::RuntimeMetadata | EventType::ProcessExit => {
                Self::Other
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::NetworkConnect => "network_connect",
            Self::CredentialRead => "credential_read",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PreoperationBlockSupport {
    pub exec: bool,
    pub file_read: bool,
    pub file_write: bool,
    pub network_connect: bool,
    pub credential_read: bool,
}

impl PreoperationBlockSupport {
    fn any(self) -> bool {
        self.exec
            || self.file_read
            || self.file_write
            || self.network_connect
            || self.credential_read
    }

    fn supports(self, action: EnforcementAction) -> bool {
        match action {
            EnforcementAction::Exec => self.exec,
            EnforcementAction::FileRead => self.file_read,
            EnforcementAction::FileWrite => self.file_write,
            EnforcementAction::NetworkConnect => self.network_connect,
            EnforcementAction::CredentialRead => self.credential_read,
            EnforcementAction::Other => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementTiming {
    AuditOnly,
    PostEventFeedback,
    PostEventContainment,
    PreOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementCapability {
    pub requested: DecisionKind,
    pub effective: DecisionKind,
    pub action: EnforcementAction,
    pub runtime: EnforcementRuntime,
    pub requested_supported: bool,
    pub enforcement_backend: EnforcementBackend,
    pub timing: EnforcementTiming,
    pub preoperation_prevention: bool,
    pub downgrade: Option<DecisionDowngrade>,
}

pub struct EnforcementCapabilityMatrix<'a> {
    capabilities: &'a PolicyRuntimeCapabilities,
}

impl<'a> EnforcementCapabilityMatrix<'a> {
    pub fn new(capabilities: &'a PolicyRuntimeCapabilities) -> Self {
        Self { capabilities }
    }

    pub fn resolve(
        &self,
        requested: DecisionKind,
        fallback: DecisionKind,
        runtime: EnforcementRuntime,
        event_type: EventType,
    ) -> EnforcementCapability {
        let action = EnforcementAction::from_event_type(&event_type);

        match requested {
            DecisionKind::Allow => EnforcementCapability {
                requested,
                effective: DecisionKind::Allow,
                action,
                runtime,
                requested_supported: true,
                enforcement_backend: EnforcementBackend::AuditOnly,
                timing: EnforcementTiming::AuditOnly,
                preoperation_prevention: false,
                downgrade: None,
            },
            DecisionKind::Notify => EnforcementCapability {
                requested,
                effective: DecisionKind::Notify,
                action,
                runtime,
                requested_supported: true,
                enforcement_backend: EnforcementBackend::TracepointNotify,
                timing: EnforcementTiming::PostEventFeedback,
                preoperation_prevention: false,
                downgrade: None,
            },
            DecisionKind::Review => EnforcementCapability {
                requested,
                effective: DecisionKind::Review,
                action,
                runtime,
                requested_supported: true,
                enforcement_backend: EnforcementBackend::TracepointNotify,
                timing: EnforcementTiming::PostEventFeedback,
                preoperation_prevention: false,
                downgrade: None,
            },
            DecisionKind::Kill => EnforcementCapability {
                requested,
                effective: DecisionKind::Kill,
                action,
                runtime,
                requested_supported: true,
                enforcement_backend: EnforcementBackend::SignalKill,
                timing: EnforcementTiming::PostEventContainment,
                preoperation_prevention: false,
                downgrade: None,
            },
            DecisionKind::Block => self.resolve_block(fallback, runtime, action),
        }
    }

    fn resolve_block(
        &self,
        fallback: DecisionKind,
        runtime: EnforcementRuntime,
        action: EnforcementAction,
    ) -> EnforcementCapability {
        if self.capabilities.can_preoperation_block(runtime, action) {
            return EnforcementCapability {
                requested: DecisionKind::Block,
                effective: DecisionKind::Block,
                action,
                runtime,
                requested_supported: true,
                enforcement_backend: EnforcementBackend::BpfLsmBlock,
                timing: EnforcementTiming::PreOperation,
                preoperation_prevention: true,
                downgrade: None,
            };
        }

        let fallback = safe_non_block_fallback(&fallback);
        let reason = self
            .capabilities
            .block_downgrade_reason(runtime, action, fallback);
        EnforcementCapability {
            requested: DecisionKind::Block,
            effective: fallback,
            action,
            runtime,
            requested_supported: false,
            enforcement_backend: backend_for_fallback(&fallback),
            timing: timing_for_fallback(fallback),
            preoperation_prevention: false,
            downgrade: Some(DecisionDowngrade {
                from: DecisionKind::Block,
                to: fallback,
                reason,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Notify { rule_id: String, reason: String },
    Block { rule_id: String, reason: String },
    Kill { rule_id: String, reason: String },
    Review { rule_id: String, reason: String },
}

impl PolicyDecision {
    /// Return whether this evaluation allows the event without operator action.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Convert the policy crate decision into the shared timeline schema enum.
    pub fn core_decision(&self) -> CorePolicyDecision {
        match self {
            Self::Allow => CorePolicyDecision::Allow,
            Self::Notify { .. } => CorePolicyDecision::Notify,
            Self::Block { .. } => CorePolicyDecision::Block,
            Self::Kill { .. } => CorePolicyDecision::Kill,
            Self::Review { .. } => CorePolicyDecision::Review,
        }
    }

    /// Return the matched rule id when the decision is not `Allow`.
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Notify { rule_id, .. }
            | Self::Block { rule_id, .. }
            | Self::Kill { rule_id, .. }
            | Self::Review { rule_id, .. } => Some(rule_id),
        }
    }

    /// Return the human-readable reason when the decision is not `Allow`.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Notify { reason, .. }
            | Self::Block { reason, .. }
            | Self::Kill { reason, .. }
            | Self::Review { reason, .. } => Some(reason),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRuntimeCapabilities {
    pub kernel_release: Option<String>,
    pub bpf_lsm_available: bool,
    pub seccomp_available: bool,
    pub runtime: EnforcementRuntime,
    pub preoperation_block: PreoperationBlockSupport,
}

impl Default for PolicyRuntimeCapabilities {
    fn default() -> Self {
        Self {
            kernel_release: None,
            bpf_lsm_available: false,
            seccomp_available: false,
            runtime: EnforcementRuntime::Local,
            preoperation_block: PreoperationBlockSupport::default(),
        }
    }
}

impl PolicyRuntimeCapabilities {
    /// Detect runtime enforcement capabilities from overrides or kernel state.
    pub fn detect() -> Self {
        if let Ok(value) = std::env::var(env::BPF_LSM_AVAILABLE) {
            return Self {
                kernel_release: kernel_release(),
                bpf_lsm_available: matches!(value.as_str(), "1" | "true" | "yes" | "on"),
                seccomp_available: seccomp_available(),
                ..Self::default()
            };
        }

        Self {
            kernel_release: kernel_release(),
            bpf_lsm_available: fs::read_to_string("/sys/kernel/security/lsm")
                .map(|lsm| lsm.split(',').any(|name| name.trim() == "bpf"))
                .unwrap_or(false),
            seccomp_available: seccomp_available(),
            ..Self::default()
        }
    }

    pub fn can_preoperation_block(
        &self,
        runtime: EnforcementRuntime,
        action: EnforcementAction,
    ) -> bool {
        self.bpf_lsm_available
            && runtime_supports_host_bpf_lsm(runtime)
            && self.preoperation_block.supports(action)
    }

    fn any_preoperation_block_available(&self) -> bool {
        self.bpf_lsm_available
            && runtime_supports_host_bpf_lsm(self.runtime)
            && self.preoperation_block.any()
    }

    fn block_downgrade_reason(
        &self,
        runtime: EnforcementRuntime,
        action: EnforcementAction,
        fallback: DecisionKind,
    ) -> String {
        if !self.bpf_lsm_available {
            return format!(
                "BPF-LSM is not available; requested block for {}/{} downgraded to {}",
                runtime.as_str(),
                action.as_str(),
                fallback.as_str()
            );
        }

        if !runtime_supports_host_bpf_lsm(runtime) {
            return format!(
                "pre-operation block is unsupported for {}/{}; requested block downgraded to {}",
                runtime.as_str(),
                action.as_str(),
                fallback.as_str()
            );
        }

        format!(
            "pre-operation block prototype is not enabled for {}/{}; requested block downgraded to {}",
            runtime.as_str(),
            action.as_str(),
            fallback.as_str()
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionDowngrade {
    pub from: DecisionKind,
    pub to: DecisionKind,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub enforcement_backend: EnforcementBackend,
    pub downgrade: Option<DecisionDowngrade>,
}

impl PolicyEvaluation {
    /// Build an allow evaluation using the audit-only backend.
    pub fn allow() -> Self {
        Self {
            decision: PolicyDecision::Allow,
            enforcement_backend: EnforcementBackend::AuditOnly,
            downgrade: None,
        }
    }
}

impl Policy {
    /// Parse the repository's YAML-like or JSON policy subset.
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.trim_start().starts_with('{') {
            return parse_json_policy(input);
        }

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
                push_list_value(&mut policy, section, list, clean_scalar(value.trim()));
                continue;
            }

            if let Some(value) = line.strip_prefix("max_seconds:") {
                policy.runtime.max_seconds = Some(parse_u64("max_seconds", value)?);
                continue;
            }

            if let Some(value) = line.strip_prefix("max_processes:") {
                policy.runtime.max_processes = Some(parse_u64("max_processes", value)?);
                continue;
            }

            if let Some(value) = line.strip_prefix("requested:") {
                if section == "enforcement" {
                    policy.enforcement.requested = parse_decision_kind(clean_scalar(value.trim()))?;
                }
                continue;
            }

            if let Some(value) = line.strip_prefix("fallback:") {
                if section == "enforcement" {
                    policy.enforcement.fallback = parse_decision_kind(clean_scalar(value.trim()))?;
                }
            }
        }

        Ok(policy)
    }

    /// Return whether a path matches the credential deny list.
    pub fn denies_credential_path(&self, path: &str) -> bool {
        self.credentials
            .deny_read
            .iter()
            .any(|pattern| path_matches(pattern, path))
    }

    /// Evaluate a direct file read against credential rules.
    pub fn evaluate_file_read(&self, path: &str) -> PolicyDecision {
        if self.denies_credential_path(path) {
            return PolicyDecision::Notify {
                rule_id: "credentials.deny_read".to_string(),
                reason: "file path matches credential deny list".to_string(),
            };
        }

        PolicyDecision::Allow
    }

    /// Report startup downgrade metadata when requested enforcement is unsafe.
    pub fn startup_downgrade(
        &self,
        capabilities: &PolicyRuntimeCapabilities,
    ) -> Option<DecisionDowngrade> {
        if self.enforcement.requested == DecisionKind::Block
            && !capabilities.any_preoperation_block_available()
        {
            let fallback = safe_non_block_fallback(&self.enforcement.fallback);
            return Some(DecisionDowngrade {
                from: DecisionKind::Block,
                to: fallback,
                reason: format!(
                    "pre-operation block is not available for runtime {}; requested block downgraded to {}",
                    capabilities.runtime.as_str(),
                    fallback.as_str()
                ),
            });
        }

        None
    }

    /// Evaluate one canonical event and select the effective enforcement backend.
    pub fn evaluate_event(
        &self,
        event: &CanonicalEvent,
        capabilities: &PolicyRuntimeCapabilities,
    ) -> PolicyEvaluation {
        let Some((rule_id, reason)) = self.match_event_rule(event) else {
            return PolicyEvaluation::allow();
        };

        let capability = self.effective_decision(capabilities, event.event_type.clone());
        PolicyEvaluation {
            decision: decision_for_kind(capability.effective, rule_id, reason),
            enforcement_backend: capability.enforcement_backend,
            downgrade: capability.downgrade,
        }
    }

    fn match_event_rule(&self, event: &CanonicalEvent) -> Option<(String, String)> {
        match event.event_type {
            EventType::CredentialRead => Some((
                "credentials.deny_read".to_string(),
                "file path matches credential deny list".to_string(),
            )),
            EventType::FileOpen => {
                if !self.workspace.allow_read.is_empty()
                    && !path_matches_any(&self.workspace.allow_read, &event.resource)
                {
                    return Some((
                        "workspace.allow_read".to_string(),
                        "file read is outside workspace read allow list".to_string(),
                    ));
                }
                None
            }
            EventType::FileCreate
            | EventType::FileTruncate
            | EventType::FileUnlink
            | EventType::FileRename => {
                if !self.workspace.allow_write.is_empty()
                    && !path_matches_any(&self.workspace.allow_write, &event.resource)
                {
                    return Some((
                        "workspace.allow_write".to_string(),
                        "file write is outside workspace write allow list".to_string(),
                    ));
                }
                None
            }
            EventType::NetworkConnect => {
                if !self.network.allow_egress.is_empty()
                    && !endpoint_matches_any(&self.network.allow_egress, &event.resource)
                {
                    return Some((
                        "network.allow_egress".to_string(),
                        "network endpoint is outside egress allow list".to_string(),
                    ));
                }
                None
            }
            EventType::Exec => {
                if self.commands.deny.iter().any(|pattern| {
                    event.actor.contains(pattern) || event.resource.contains(pattern)
                }) {
                    return Some((
                        "commands.deny".to_string(),
                        "command matches deny list".to_string(),
                    ));
                }
                None
            }
            _ => None,
        }
    }

    fn effective_decision(
        &self,
        capabilities: &PolicyRuntimeCapabilities,
        event_type: EventType,
    ) -> EnforcementCapability {
        EnforcementCapabilityMatrix::new(capabilities).resolve(
            self.enforcement.requested,
            self.enforcement.fallback,
            capabilities.runtime,
            event_type,
        )
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

fn parse_json_policy(input: &str) -> Result<Policy, String> {
    let mut policy = Policy::default();

    if let Some(section) = json_object_section(input, "credentials")? {
        policy.credentials.deny_read = json_string_array(section, "deny_read")?;
    }
    if let Some(section) = json_object_section(input, "workspace")? {
        policy.workspace.allow_read = json_string_array(section, "allow_read")?;
        policy.workspace.allow_write = json_string_array(section, "allow_write")?;
    }
    if let Some(section) = json_object_section(input, "commands")? {
        policy.commands.deny = json_string_array(section, "deny")?;
    }
    if let Some(section) = json_object_section(input, "network")? {
        policy.network.allow_egress = json_string_array(section, "allow_egress")?;
    }
    if let Some(section) = json_object_section(input, "runtime")? {
        policy.runtime.max_seconds = json_u64(section, "max_seconds")?;
        policy.runtime.max_processes = json_u64(section, "max_processes")?;
    }
    if let Some(section) = json_object_section(input, "enforcement")? {
        if let Some(requested) = json_string_field(section, "requested")? {
            policy.enforcement.requested = parse_decision_kind(&requested)?;
        }
        if let Some(fallback) = json_string_field(section, "fallback")? {
            policy.enforcement.fallback = parse_decision_kind(&fallback)?;
        }
    }

    Ok(policy)
}

fn json_object_section<'a>(input: &'a str, key: &str) -> Result<Option<&'a str>, String> {
    let Some(value_start) = json_value_start(input, key) else {
        return Ok(None);
    };
    let bytes = input.as_bytes();
    if bytes.get(value_start) != Some(&b'{') {
        return Err(format!("json field {key} must be an object"));
    }

    let end = matching_delimiter(input, value_start, b'{', b'}')
        .ok_or_else(|| format!("json object {key} is not closed"))?;
    Ok(Some(&input[value_start + 1..end]))
}

fn json_string_array(input: &str, key: &str) -> Result<Vec<String>, String> {
    let Some(value_start) = json_value_start(input, key) else {
        return Ok(Vec::new());
    };
    let bytes = input.as_bytes();
    if bytes.get(value_start) != Some(&b'[') {
        return Err(format!("json field {key} must be an array"));
    }

    let end = matching_delimiter(input, value_start, b'[', b']')
        .ok_or_else(|| format!("json array {key} is not closed"))?;
    parse_json_string_array_items(&input[value_start + 1..end])
}

fn json_string_field(input: &str, key: &str) -> Result<Option<String>, String> {
    let Some(value_start) = json_value_start(input, key) else {
        return Ok(None);
    };

    parse_json_string_at(input, value_start).map(Some)
}

fn json_u64(input: &str, key: &str) -> Result<Option<u64>, String> {
    let Some(value_start) = json_value_start(input, key) else {
        return Ok(None);
    };
    let number_end = input[value_start..]
        .find(|ch: char| !ch.is_ascii_digit())
        .map(|offset| value_start + offset)
        .unwrap_or(input.len());
    if number_end == value_start {
        return Err(format!("json field {key} must be a number"));
    }
    input[value_start..number_end]
        .parse::<u64>()
        .map(Some)
        .map_err(|error| format!("invalid json number {key}: {error}"))
}

fn json_value_start(input: &str, key: &str) -> Option<usize> {
    let pattern = format!("\"{key}\"");
    let key_start = input.find(&pattern)?;
    let after_key = key_start + pattern.len();
    let colon = input[after_key..].find(':')? + after_key;
    Some(skip_json_whitespace(input, colon + 1))
}

fn skip_json_whitespace(input: &str, mut index: usize) -> usize {
    while input
        .as_bytes()
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }
    index
}

fn matching_delimiter(input: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, byte) in bytes[start..].iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }

        if *byte == b'"' {
            in_string = true;
        } else if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(start + offset);
            }
        }
    }

    None
}

fn parse_json_string_array_items(input: &str) -> Result<Vec<String>, String> {
    let mut items = Vec::new();
    let mut index = skip_json_whitespace(input, 0);

    while index < input.len() {
        if input.as_bytes().get(index) == Some(&b',') {
            index = skip_json_whitespace(input, index + 1);
            continue;
        }
        let value = parse_json_string_at(input, index)?;
        index += consumed_json_string_len(&input[index..])?;
        items.push(value);
        index = skip_json_whitespace(input, index);
        if input.as_bytes().get(index) == Some(&b',') {
            index = skip_json_whitespace(input, index + 1);
        } else if index < input.len() {
            return Err("expected comma between json string array items".to_string());
        }
    }

    Ok(items)
}

fn parse_json_string_at(input: &str, start: usize) -> Result<String, String> {
    if input.as_bytes().get(start) != Some(&b'"') {
        return Err("expected json string".to_string());
    }

    let mut out = String::new();
    let mut escaped = false;
    for ch in input[start + 1..].chars() {
        if escaped {
            match ch {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => return Err(format!("unsupported json escape: \\{other}")),
            }
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '"' => return Ok(out),
            other => out.push(other),
        }
    }

    Err("json string is not closed".to_string())
}

fn consumed_json_string_len(input: &str) -> Result<usize, String> {
    if input.as_bytes().first() != Some(&b'"') {
        return Err("expected json string".to_string());
    }

    let mut escaped = false;
    for (offset, byte) in input.as_bytes()[1..].iter().enumerate() {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Ok(offset + 2);
        }
    }

    Err("json string is not closed".to_string())
}

fn parse_u64(field: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("invalid {field}: {error}"))
}

fn parse_decision_kind(value: &str) -> Result<DecisionKind, String> {
    match value {
        "allow" => Ok(DecisionKind::Allow),
        "notify" => Ok(DecisionKind::Notify),
        "block" => Ok(DecisionKind::Block),
        "kill" => Ok(DecisionKind::Kill),
        "review" => Ok(DecisionKind::Review),
        unknown => Err(format!("unknown policy decision: {unknown}")),
    }
}

fn decision_for_kind(kind: DecisionKind, rule_id: String, reason: String) -> PolicyDecision {
    match kind {
        DecisionKind::Allow => PolicyDecision::Allow,
        DecisionKind::Notify => PolicyDecision::Notify { rule_id, reason },
        DecisionKind::Block => PolicyDecision::Block { rule_id, reason },
        DecisionKind::Kill => PolicyDecision::Kill { rule_id, reason },
        DecisionKind::Review => PolicyDecision::Review { rule_id, reason },
    }
}

fn backend_for_fallback(kind: &DecisionKind) -> EnforcementBackend {
    match kind {
        DecisionKind::Allow => EnforcementBackend::AuditOnly,
        DecisionKind::Notify | DecisionKind::Review | DecisionKind::Block => {
            EnforcementBackend::TracepointNotify
        }
        DecisionKind::Kill => EnforcementBackend::SignalKill,
    }
}

fn timing_for_fallback(kind: DecisionKind) -> EnforcementTiming {
    match kind {
        DecisionKind::Allow => EnforcementTiming::AuditOnly,
        DecisionKind::Notify | DecisionKind::Review | DecisionKind::Block => {
            EnforcementTiming::PostEventFeedback
        }
        DecisionKind::Kill => EnforcementTiming::PostEventContainment,
    }
}

fn safe_non_block_fallback(kind: &DecisionKind) -> DecisionKind {
    match kind {
        DecisionKind::Block => DecisionKind::Notify,
        other => *other,
    }
}

fn runtime_supports_host_bpf_lsm(runtime: EnforcementRuntime) -> bool {
    matches!(
        runtime,
        EnforcementRuntime::Local
            | EnforcementRuntime::Docker
            | EnforcementRuntime::Containerd
            | EnforcementRuntime::Kubernetes
    )
}

fn kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn seccomp_available() -> bool {
    fs::metadata("/proc/sys/kernel/seccomp/actions_avail").is_ok()
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let path = path.strip_prefix("./").unwrap_or(path);

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

fn path_matches_any(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pattern| path_matches(pattern, path))
}

fn endpoint_matches_any(patterns: &[String], endpoint: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| endpoint_matches(pattern, endpoint))
}

fn endpoint_matches(pattern: &str, endpoint: &str) -> bool {
    if pattern == endpoint {
        return true;
    }

    let Some((pattern_host, pattern_port)) = pattern.rsplit_once(':') else {
        return endpoint.starts_with(pattern);
    };
    let Some((endpoint_host, _endpoint_port)) = endpoint.rsplit_once(':') else {
        return false;
    };

    pattern_host == endpoint_host && pattern_port == "0"
}

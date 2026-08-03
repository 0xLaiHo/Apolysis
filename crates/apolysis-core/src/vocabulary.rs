// SPDX-License-Identifier: Apache-2.0

//! Shared string vocabulary for observation timeline records and integrations.
//!
//! Apolysis writes JSONL records that are consumed by tests, analysis tools,
//! and runtime metadata adapters. Keeping public strings in one place avoids
//! drift when a new observer or metadata adapter emits the
//! same schema concepts.

/// JSONL record type names used by every storage backend.
pub mod records {
    /// A normalized event emitted by a runtime, observer, or metadata adapter.
    pub const EVENT: &str = "event";
    /// A raw kernel-side event preserved before canonicalization.
    pub const RAW_KERNEL_EVENT: &str = "raw_kernel_event";
    /// A declared harness or tool-call intent tied to a session.
    pub const INTENT: &str = "intent";
    /// Observer loss, truncation, lifecycle, or summary evidence.
    pub const OBSERVER_DIAGNOSTIC: &str = "observer_diagnostic";
    /// A runtime visibility assessment for strong-isolation backends.
    pub const VISIBILITY_ASSESSMENT: &str = "visibility_assessment";
}

/// Stable actor names for canonical timeline events.
pub mod actors {
    /// Host process-tree attribution.
    pub const PROCESS_TREE: &str = "process_tree";
    /// Kernel observer metadata or event producers.
    pub const OBSERVER: &str = "observer";
    /// Kubernetes metadata adapter.
    pub const KUBERNETES: &str = "kubernetes";
}

/// Resource names used in canonical events.
pub mod resources {
    /// A local operating system process.
    pub const PROCESS: &str = "process";
    /// A runtime container.
    pub const CONTAINER: &str = "container";
    /// Local process-tree attribution metadata.
    pub const LOCAL_ATTRIBUTION: &str = "local-attribution";
    /// Observer operating mode metadata.
    pub const OBSERVER_MODE: &str = "observer-mode";
    /// Observer backend metadata.
    pub const OBSERVER_BACKEND: &str = "observer-backend";
    /// Observer runner plan metadata.
    pub const OBSERVER_RUNNERS: &str = "observer-runners";
    /// Live observer session scope metadata.
    pub const OBSERVER_SCOPE: &str = "observer-scope";
    /// Observer local JSONL output rotation metadata.
    pub const OBSERVER_OUTPUT_ROTATION: &str = "observer-output-rotation";
    /// Managed agent supervisor mode metadata.
    pub const AGENT_SUPERVISOR_MODE: &str = "agent-supervisor-mode";
    /// Managed agent kind metadata.
    pub const AGENT_KIND: &str = "agent-kind";
    /// Managed agent root PID metadata.
    pub const AGENT_ROOT_PID: &str = "agent-root-pid";
    /// Managed agent command metadata.
    pub const AGENT_COMMAND: &str = "agent-command";
    /// Managed or registered agent command fingerprint metadata.
    pub const AGENT_COMMAND_FINGERPRINT: &str = "agent-command-fingerprint";
    /// Managed agent executable metadata.
    pub const AGENT_EXECUTABLE: &str = "agent-executable";
    /// Managed agent workspace root metadata.
    pub const AGENT_WORKSPACE_ROOT: &str = "agent-workspace-root";
    /// Managed agent kernel start time metadata.
    pub const AGENT_START_TIME: &str = "agent-start-time";
    /// Managed agent exit status metadata.
    pub const AGENT_EXIT_STATUS: &str = "agent-exit-status";
    /// Kubernetes pod name metadata.
    pub const KUBERNETES_POD: &str = "kubernetes-pod";
    /// Kubernetes namespace metadata.
    pub const KUBERNETES_NAMESPACE: &str = "kubernetes-namespace";
    /// Kubernetes runtime isolation profile metadata.
    pub const KUBERNETES_RUNTIME_PROFILE: &str = "kubernetes-runtime-profile";
    /// Kubernetes pod UID metadata.
    pub const KUBERNETES_POD_UID: &str = "kubernetes-pod-uid";
    /// Kubernetes service account metadata.
    pub const KUBERNETES_SERVICE_ACCOUNT: &str = "kubernetes-service-account";
    /// Kubernetes RuntimeClass metadata.
    pub const KUBERNETES_RUNTIME_CLASS: &str = "kubernetes-runtime-class";
    /// Kubernetes node metadata.
    pub const KUBERNETES_NODE: &str = "kubernetes-node";
    /// Agent Sandbox metadata label.
    pub const AGENT_SANDBOX: &str = "agent-sandbox";
    /// Kubernetes service account token metadata.
    pub const KUBERNETES_SERVICE_ACCOUNT_TOKEN: &str = "kubernetes-service-account-token";
}

/// Action strings and prefixes used in canonical timeline events.
pub mod actions {
    /// The prefix used for process exit metadata.
    pub const EXIT_PREFIX: &str = "exit:";
    /// The prefix used for Kubernetes pod metadata.
    pub const NAME_PREFIX: &str = "name:";
    /// The prefix used for Kubernetes namespace metadata.
    pub const NAMESPACE_PREFIX: &str = "namespace:";
    /// The prefix used for runtime isolation metadata.
    pub const ISOLATION_PREFIX: &str = "isolation:";
    /// The prefix used for Kubernetes UID metadata.
    pub const UID_PREFIX: &str = "uid:";
    /// The prefix used for Kubernetes service account metadata.
    pub const SERVICE_ACCOUNT_PREFIX: &str = "serviceAccount:";
    /// The prefix used for Kubernetes RuntimeClass metadata.
    pub const RUNTIME_CLASS_PREFIX: &str = "runtimeClass:";
    /// The prefix used for Kubernetes node metadata.
    pub const NODE_PREFIX: &str = "node:";
    /// The prefix used for Agent Sandbox metadata.
    pub const SANDBOX_PREFIX: &str = "sandbox:";
    /// The prefix used for Kubernetes token automount metadata.
    pub const AUTOMOUNT_PREFIX: &str = "automount:";
}

// SPDX-License-Identifier: Apache-2.0

//! Shared string vocabulary for timeline records and runtime integrations.
//!
//! Apolysis writes JSONL records that are consumed by tests, analysis tools,
//! and future runtime adapters.  Keeping public strings in one place avoids
//! drift when a new observer, runtime backend, or feedback channel emits the
//! same schema concepts.

/// JSONL record type names used by every storage backend.
pub mod records {
    /// A sandbox session identity and configuration snapshot.
    pub const SESSION: &str = "session";
    /// A normalized event emitted by a runtime, observer, or metadata adapter.
    pub const EVENT: &str = "event";
    /// A raw kernel-side event preserved before canonicalization.
    pub const RAW_KERNEL_EVENT: &str = "raw_kernel_event";
    /// A declared harness or tool-call intent tied to a session.
    pub const INTENT: &str = "intent";
    /// A policy decision that should be visible to operators or agent hooks.
    pub const POLICY_VIOLATION: &str = "policy_violation";
    /// Capability and timing metadata for a policy enforcement decision.
    pub const ENFORCEMENT_METADATA: &str = "enforcement_metadata";
    /// Observer loss, truncation, lifecycle, or summary evidence.
    pub const OBSERVER_DIAGNOSTIC: &str = "observer_diagnostic";
    /// A runtime visibility assessment for strong-isolation backends.
    pub const VISIBILITY_ASSESSMENT: &str = "visibility_assessment";
}

/// Stable actor names for canonical timeline events.
pub mod actors {
    /// The Apolysis CLI/runtime itself.
    pub const APOLYSIS: &str = "apolysis";
    /// Docker CLI or daemon metadata.
    pub const DOCKER: &str = "docker";
    /// Host process-tree attribution.
    pub const PROCESS_TREE: &str = "process_tree";
    /// Kernel observer metadata or event producers.
    pub const OBSERVER: &str = "observer";
    /// Policy engine metadata.
    pub const POLICY: &str = "policy";
    /// Kubernetes metadata adapter.
    pub const KUBERNETES: &str = "kubernetes";
}

/// Runtime names used in sessions, CLI selections, and metadata labels.
pub mod runtimes {
    /// Local host process-tree runtime.
    pub const LOCAL: &str = "local";
    /// Docker runtime adapter.
    pub const DOCKER: &str = "docker";
    /// Kubernetes runtime metadata adapter.
    pub const KUBERNETES: &str = "kubernetes";
    /// Firecracker microVM prototype runtime.
    pub const FIRECRACKER: &str = "firecracker";
}

/// Resource names used in canonical events.
pub mod resources {
    /// A local operating system process.
    pub const PROCESS: &str = "process";
    /// A runtime container.
    pub const CONTAINER: &str = "container";
    /// Local runtime session metadata.
    pub const LOCAL_SESSION: &str = "local-session";
    /// Docker runtime session metadata.
    pub const DOCKER_SESSION: &str = "docker-session";
    /// Local process-tree attribution metadata.
    pub const LOCAL_ATTRIBUTION: &str = "local-attribution";
    /// Docker container image metadata.
    pub const CONTAINER_IMAGE: &str = "container-image";
    /// Docker container identifier metadata.
    pub const CONTAINER_ID: &str = "container-id";
    /// Docker cgroup path metadata.
    pub const CGROUP_PATH: &str = "cgroup-path";
    /// Docker network mode metadata.
    pub const NETWORK_MODE: &str = "network-mode";
    /// Docker OCI runtime metadata.
    pub const DOCKER_RUNTIME: &str = "docker-runtime";
    /// Docker mount metadata.
    pub const MOUNTS: &str = "mounts";
    /// Docker label metadata.
    pub const CONTAINER_LABELS: &str = "container-labels";
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
    /// BPF-LSM capability metadata.
    pub const BPF_LSM: &str = "bpf-lsm";
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
    /// A session or runtime component started.
    pub const START: &str = "start";
    /// A process execution event.
    pub const EXEC: &str = "exec";
    /// The prefix used for runtime mode metadata.
    pub const MODE_PREFIX: &str = "mode:";
    /// The prefix used for process exit metadata.
    pub const EXIT_PREFIX: &str = "exit:";
    /// The prefix used for killed process metadata.
    pub const KILLED_PREFIX: &str = "killed:";
    /// The prefix used for Docker image metadata.
    pub const IMAGE_PREFIX: &str = "image:";
    /// The prefix used for network mode metadata.
    pub const NETWORK_PREFIX: &str = "network:";
    /// The prefix used for OCI runtime metadata.
    pub const OCI_RUNTIME_PREFIX: &str = "oci-runtime:";
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

/// Environment variables shared between the CLI, runtimes, and policies.
pub mod env {
    /// Session identifier exported into a supervised process or container.
    pub const SESSION_ID: &str = "APOLYSIS_SESSION_ID";
    /// Runtime type exported into a supervised container.
    pub const RUNTIME: &str = "APOLYSIS_RUNTIME";
    /// Test/operator override for BPF-LSM capability detection.
    pub const BPF_LSM_AVAILABLE: &str = "APOLYSIS_BPF_LSM_AVAILABLE";
    /// Docker binary override for tests and non-standard installations.
    pub const DOCKER_BIN: &str = "APOLYSIS_DOCKER_BIN";
}

/// Agent feedback file vocabulary.
pub mod feedback {
    /// Machine-readable line prefix consumed by agent harness integrations.
    pub const VIOLATION_TAG: &str = "APOLYSIS_VIOLATION";
    /// Default file name that stores the latest violation.
    pub const LAST_VIOLATION_FILE: &str = "last-violation.txt";
    /// Machine-readable file name that stores the latest violation.
    pub const LAST_VIOLATION_JSON_FILE: &str = "last-violation.json";
    /// Default file name that stores the latest accountability finding.
    pub const LAST_ACCOUNTABILITY_FINDING_FILE: &str = "last-accountability-finding.txt";
    /// Machine-readable file name that stores the latest accountability finding.
    pub const LAST_ACCOUNTABILITY_FINDING_JSON_FILE: &str = "last-accountability-finding.json";
}

// SPDX-License-Identifier: Apache-2.0

//! CLI vocabulary shared by command parsers.
//!
//! The binary intentionally keeps argument parsing lightweight for M1-M7, but
//! command names and flags still form a public interface.  Centralizing them
//! makes new subcommands less error-prone and keeps usage text in sync with
//! parser logic.

/// Top-level command names.
pub(crate) mod commands {
    /// Execute a command under a selected runtime adapter.
    pub(crate) const RUN: &str = "run";
    /// Convert observer input into a canonical timeline.
    pub(crate) const OBSERVE: &str = "observe";
    /// Assess host-side visibility for an isolation profile.
    pub(crate) const VISIBILITY: &str = "visibility";
}

/// Runtime and backend selection values.
pub(crate) mod values {
    /// Local process-tree runtime adapter.
    pub(crate) const LOCAL: &str = apolysis_core::runtimes::LOCAL;
    /// Docker runtime adapter.
    pub(crate) const DOCKER: &str = apolysis_core::runtimes::DOCKER;
    /// Fixture-backed observer input.
    pub(crate) const FIXTURE: &str = "fixture";
    /// Live Aya ring-buffer observer.
    pub(crate) const LIVE: &str = "live";
}

/// Shared CLI option names.
pub(crate) mod options {
    /// Runtime selector for `apolysis run`.
    pub(crate) const RUNTIME: &str = "--runtime";
    /// Docker image selector for `apolysis run --runtime docker`.
    pub(crate) const IMAGE: &str = "--image";
    /// Docker OCI runtime selector for gVisor/runsc or compatible shims.
    pub(crate) const DOCKER_RUNTIME: &str = "--docker-runtime";
    /// Policy file path.
    pub(crate) const POLICY: &str = "--policy";
    /// JSONL output path.
    pub(crate) const OUTPUT: &str = "--output";
    /// Command separator before child process arguments.
    pub(crate) const COMMAND_SEPARATOR: &str = "--";
    /// Observer backend selector.
    pub(crate) const BACKEND: &str = "--backend";
    /// Input file path.
    pub(crate) const INPUT: &str = "--input";
    /// Session id selector.
    pub(crate) const SESSION: &str = "--session";
    /// Agent feedback directory path.
    pub(crate) const FEEDBACK_DIR: &str = "--feedback-dir";
    /// Kubernetes metadata fixture or snapshot path.
    pub(crate) const KUBERNETES_METADATA: &str = "--kubernetes-metadata";
    /// CO-RE eBPF object path for the live observer.
    pub(crate) const BPF_OBJECT: &str = "--bpf-object";
    /// Cgroup v2 id used for kernel-side live event filtering.
    pub(crate) const SCOPE_CGROUP: &str = "--scope-cgroup";
    /// Root pid used for process-tree live event filtering.
    pub(crate) const SCOPE_PID: &str = "--scope-pid";
    /// Optional deterministic observer runtime.
    pub(crate) const DURATION_SECONDS: &str = "--duration-seconds";
    /// Workspace root whose file paths may be persisted without tokenization.
    pub(crate) const WORKSPACE_ROOT: &str = "--workspace-root";
    /// Visibility validation scenario selector.
    pub(crate) const SCENARIO: &str = "--scenario";
}

/// Default JSONL timeline path used by `apolysis run`.
pub(crate) const DEFAULT_TIMELINE_PATH: &str = ".apolysis/timeline.jsonl";

/// Render the public usage text.
pub(crate) fn usage() -> String {
    format!(
        "usage: apolysis {run} [{runtime} {local}|{docker}] [{image} <image>] [{docker_runtime} <oci-runtime>] {policy} <path> [{output} <path>] {separator} <command> [args...]\n       apolysis {observe} {backend} {fixture} {input} <path> {session} <id> {policy} <path> {output} <path> [{feedback_dir} <path>] [{kubernetes_metadata} <path>]\n       apolysis {observe} {backend} {live} {session} <id> {policy} <path> {output} <path> {bpf_object} <path> ({scope_cgroup} <id>|{scope_pid} <pid>) [{workspace_root} <path>] [{duration_seconds} <n>] [{feedback_dir} <path>]\n       apolysis {visibility} {scenario} docker-default|docker-gvisor|kubernetes-gvisor|kubernetes-kata|firecracker-prototype {input} <path> {output} <path> [{session} <id>] [{kubernetes_metadata} <path>]",
        run = commands::RUN,
        observe = commands::OBSERVE,
        visibility = commands::VISIBILITY,
        runtime = options::RUNTIME,
        local = values::LOCAL,
        docker = values::DOCKER,
        image = options::IMAGE,
        docker_runtime = options::DOCKER_RUNTIME,
        policy = options::POLICY,
        output = options::OUTPUT,
        separator = options::COMMAND_SEPARATOR,
        backend = options::BACKEND,
        fixture = values::FIXTURE,
        live = values::LIVE,
        input = options::INPUT,
        session = options::SESSION,
        feedback_dir = options::FEEDBACK_DIR,
        kubernetes_metadata = options::KUBERNETES_METADATA,
        bpf_object = options::BPF_OBJECT,
        scope_cgroup = options::SCOPE_CGROUP,
        scope_pid = options::SCOPE_PID,
        duration_seconds = options::DURATION_SECONDS,
        workspace_root = options::WORKSPACE_ROOT,
        scenario = options::SCENARIO,
    )
}

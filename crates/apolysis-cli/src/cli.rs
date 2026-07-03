// SPDX-License-Identifier: Apache-2.0

//! CLI vocabulary shared by command parsers.
//!
//! The binary intentionally keeps argument parsing lightweight for TimelineStore-VisibilityValidation, but
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
    /// Ingest external harness intent logs into timeline records.
    pub(crate) const INTENT: &str = "intent";
    /// Verify persisted evidence artifacts without mutating them.
    pub(crate) const VERIFY: &str = "verify";
    /// Ingest intent records from a supported harness log.
    pub(crate) const INGEST: &str = "ingest";
    /// Correlate intent records with observed host-side timeline events.
    pub(crate) const CORRELATE: &str = "correlate";
    /// Verify a hash-chain timeline file.
    pub(crate) const HASH_CHAIN: &str = "hash-chain";
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
    /// Codex JSONL response-item log adapter.
    pub(crate) const CODEX_JSONL: &str = "codex-jsonl";
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
    /// Maximum bytes for one active JSONL output file before rotation.
    pub(crate) const OUTPUT_MAX_BYTES: &str = "--output-max-bytes";
    /// Number of rotated JSONL output files to retain locally.
    pub(crate) const OUTPUT_MAX_FILES: &str = "--output-max-files";
    /// Command separator before child process arguments.
    pub(crate) const COMMAND_SEPARATOR: &str = "--";
    /// Observer backend selector.
    pub(crate) const BACKEND: &str = "--backend";
    /// Input file path.
    pub(crate) const INPUT: &str = "--input";
    /// Intent harness adapter selector.
    pub(crate) const ADAPTER: &str = "--adapter";
    /// Intent JSONL input path.
    pub(crate) const INTENT_INPUT: &str = "--intent-input";
    /// Observed timeline JSONL input path.
    pub(crate) const TIMELINE_INPUT: &str = "--timeline-input";
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
    /// Agent kind label for Apolysis-managed live observer launch.
    pub(crate) const AGENT_KIND: &str = "--agent-kind";
    /// Start an agent command under Apolysis-managed live observation.
    pub(crate) const AGENT_RUN: &str = "--agent-run";
    /// Attach to an already-running agent from an explicit registration file.
    pub(crate) const AGENT_REGISTRATION: &str = "--agent-registration";
    /// Diagnostic-only discovery fallback for already-running local agents.
    pub(crate) const AGENT_DISCOVER: &str = "--agent-discover";
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
        "usage: apolysis {run} [{runtime} {local}|{docker}] [{image} <image>] [{docker_runtime} <oci-runtime>] {policy} <path> [{output} <path>] {separator} <command> [args...]\n       apolysis {observe} {backend} {fixture} {input} <path> {session} <id> {policy} <path> {output} <path> [{output_max_bytes} <bytes> {output_max_files} <n>] [{feedback_dir} <path>] [{kubernetes_metadata} <path>]\n       apolysis {observe} {backend} {live} {session} <id> {policy} <path> {output} <path> {bpf_object} <path> ({scope_cgroup} <id>|{scope_pid} <pid>|{agent_kind} <kind> {agent_run} {separator} <command> [args...]|{agent_registration} <path>|{agent_kind} <kind> {agent_discover}) [{workspace_root} <path>] [{duration_seconds} <n>] [{output_max_bytes} <bytes> {output_max_files} <n>] [{feedback_dir} <path>]\n       apolysis {intent} {ingest} {adapter} {codex_jsonl} {input} <path> {session} <id> {output} <path> [{workspace_root} <path>]\n       apolysis {intent} {correlate} {intent_input} <path> {timeline_input} <path> {output} <path>\n       apolysis {visibility} {scenario} docker-default|docker-gvisor|kubernetes-gvisor|kubernetes-kata|firecracker-prototype {input} <path> {output} <path> [{session} <id>] [{kubernetes_metadata} <path>]\n       apolysis {verify} {hash_chain} {input} <path> {output} <path>",
        run = commands::RUN,
        observe = commands::OBSERVE,
        intent = commands::INTENT,
        verify = commands::VERIFY,
        ingest = commands::INGEST,
        correlate = commands::CORRELATE,
        hash_chain = commands::HASH_CHAIN,
        visibility = commands::VISIBILITY,
        runtime = options::RUNTIME,
        local = values::LOCAL,
        docker = values::DOCKER,
        image = options::IMAGE,
        docker_runtime = options::DOCKER_RUNTIME,
        policy = options::POLICY,
        output = options::OUTPUT,
        output_max_bytes = options::OUTPUT_MAX_BYTES,
        output_max_files = options::OUTPUT_MAX_FILES,
        separator = options::COMMAND_SEPARATOR,
        backend = options::BACKEND,
        adapter = options::ADAPTER,
        intent_input = options::INTENT_INPUT,
        timeline_input = options::TIMELINE_INPUT,
        codex_jsonl = values::CODEX_JSONL,
        fixture = values::FIXTURE,
        live = values::LIVE,
        input = options::INPUT,
        session = options::SESSION,
        feedback_dir = options::FEEDBACK_DIR,
        kubernetes_metadata = options::KUBERNETES_METADATA,
        bpf_object = options::BPF_OBJECT,
        scope_cgroup = options::SCOPE_CGROUP,
        scope_pid = options::SCOPE_PID,
        agent_kind = options::AGENT_KIND,
        agent_run = options::AGENT_RUN,
        agent_registration = options::AGENT_REGISTRATION,
        agent_discover = options::AGENT_DISCOVER,
        duration_seconds = options::DURATION_SECONDS,
        workspace_root = options::WORKSPACE_ROOT,
        scenario = options::SCENARIO,
    )
}

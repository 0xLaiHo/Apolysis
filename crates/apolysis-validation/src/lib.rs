// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use apolysis_core::EventType;
use apolysis_policy::{
    BlockPrototypeBackend, BlockPrototypeEvidence, BlockPrototypeEvidenceSource,
    EnforcementRuntime, PolicyRuntimeCapabilities,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toml_edit::{value as toml_value, DocumentMut, Item, Table};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCaptureRequest {
    pub output_dir: PathBuf,
    pub sources: Vec<BackupSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceCaptureRequest<'a> {
    pub service_name: String,
    pub systemctl_show: &'a str,
    pub runtime_sockets: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesCaptureRequest<'a> {
    pub runtimeclasses_json: &'a str,
    pub nodes_json: &'a str,
    pub pods_json: &'a str,
    pub validation_label_key: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePlanRequest {
    pub backup_root: PathBuf,
    pub manifest: BackupManifest,
    pub services: Vec<ServiceState>,
    pub managed_service_inputs: Vec<ManagedServiceInputs>,
    pub validation_owned_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreExecutionRequest {
    pub backup_root: PathBuf,
    pub manifest: BackupManifest,
    pub services: Vec<ServiceState>,
    pub plan: RestorePlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RestoreExecutionReport {
    pub actions_applied: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRegistrationPlanRequest {
    pub docker_daemon_path: PathBuf,
    pub docker_daemon_json: String,
    pub containerd_config_path: PathBuf,
    pub containerd_config_toml: Option<String>,
    pub k3s_runtime_dropin_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeRegistrationPlan {
    pub file_writes: Vec<RuntimeConfigFileWrite>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeConfigFileWrite {
    pub id: String,
    pub path: PathBuf,
    pub contents: String,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeRegistrationReport {
    pub files_written: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRuntimeRegistrationReport {
    pub validation: HostValidationReport,
    pub registration: RuntimeRegistrationReport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReportRequest<'a> {
    pub output_dir: PathBuf,
    pub backup_sources: Vec<BackupSource>,
    pub service_requests: Vec<ServiceCaptureRequest<'a>>,
    pub kubernetes: KubernetesCaptureRequest<'a>,
    pub managed_service_inputs: Vec<ManagedServiceInputs>,
    pub validation_owned_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServiceInputs {
    pub service_name: String,
    pub entry_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceSpec {
    pub service_name: String,
    pub runtime_sockets: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceLoad {
    Idle,
    #[serde(rename = "steady_10000")]
    Steady10000,
    #[serde(rename = "burst_50000")]
    Burst50000,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerformanceBudget {
    pub load: PerformanceLoad,
    pub min_events_per_second: u64,
    pub max_milli_cpu: Option<u64>,
    pub max_rss_mib: u64,
    pub require_worker_pool_bounded: bool,
    pub require_loss_accounted: bool,
    pub require_queue_bounded: bool,
    pub require_adapter_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerformanceSample {
    pub load: PerformanceLoad,
    pub events_per_second: u64,
    pub milli_cpu: u64,
    pub rss_mib: u64,
    pub submitted_events: u64,
    pub accepted_events: u64,
    pub written_events: u64,
    pub dropped_events: u64,
    pub worker_pool_bounded: bool,
    pub loss_accounted: bool,
    pub queue_bounded: bool,
    pub adapter_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerformanceGateFailure {
    pub load: PerformanceLoad,
    pub metric: String,
    pub message: String,
    pub actual: String,
    pub budget: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerformanceGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub budgets: Vec<PerformanceBudget>,
    pub samples: Vec<PerformanceSample>,
    pub failures: Vec<PerformanceGateFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityTarget {
    Local,
    DockerRunc,
    DockerGvisor,
    ContainerdRunc,
    ContainerdGvisor,
    ContainerdKata,
    K3sRunc,
    K3sGvisor,
    K3sKata,
}

impl VisibilityTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::DockerRunc => "docker_runc",
            Self::DockerGvisor => "docker_gvisor",
            Self::ContainerdRunc => "containerd_runc",
            Self::ContainerdGvisor => "containerd_gvisor",
            Self::ContainerdKata => "containerd_kata",
            Self::K3sRunc => "k3s_runc",
            Self::K3sGvisor => "k3s_gvisor",
            Self::K3sKata => "k3s_kata",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VisibilityReport {
    pub target: VisibilityTarget,
    pub live_validated: bool,
    pub evidence_source: String,
    pub host_visibility_scope: String,
    pub guest_semantics_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VisibilityReportGateFailure {
    pub target: Option<VisibilityTarget>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VisibilityReportGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub reports: Vec<VisibilityReport>,
    pub failures: Vec<VisibilityReportGateFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F3BlockValidationSource {
    Fixture,
    LiveHost,
}

impl F3BlockValidationSource {
    fn policy_source(self) -> BlockPrototypeEvidenceSource {
        match self {
            Self::Fixture => BlockPrototypeEvidenceSource::Fixture,
            Self::LiveHost => BlockPrototypeEvidenceSource::LiveHost,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F3BlockValidationRuntime {
    Local,
    Docker,
    Containerd,
    Kubernetes,
    Gvisor,
    Kata,
    Firecracker,
    Unknown,
}

impl F3BlockValidationRuntime {
    fn policy_runtime(self) -> EnforcementRuntime {
        match self {
            Self::Local => EnforcementRuntime::Local,
            Self::Docker => EnforcementRuntime::Docker,
            Self::Containerd => EnforcementRuntime::Containerd,
            Self::Kubernetes => EnforcementRuntime::Kubernetes,
            Self::Gvisor => EnforcementRuntime::Gvisor,
            Self::Kata => EnforcementRuntime::Kata,
            Self::Firecracker => EnforcementRuntime::Firecracker,
            Self::Unknown => EnforcementRuntime::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F3BlockValidationAction {
    Exec,
    FileRead,
    FileWrite,
    NetworkConnect,
    CredentialRead,
}

impl F3BlockValidationAction {
    fn policy_event_type(self) -> EventType {
        match self {
            Self::Exec => EventType::Exec,
            Self::FileRead => EventType::FileOpen,
            Self::FileWrite => EventType::FileCreate,
            Self::NetworkConnect => EventType::NetworkConnect,
            Self::CredentialRead => EventType::CredentialRead,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockValidationReport {
    pub evidence_id: String,
    pub source: F3BlockValidationSource,
    pub runtime: F3BlockValidationRuntime,
    pub action: F3BlockValidationAction,
    pub backend: String,
    pub host_bpf_lsm_available: bool,
    pub seccomp_available: bool,
    pub preoperation_prevention: bool,
    pub decision_latency_ms: Option<u128>,
    pub side_effect_race_window_ms: Option<u128>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockValidationEnablement {
    pub evidence_id: String,
    pub runtime: F3BlockValidationRuntime,
    pub action: F3BlockValidationAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockValidationGateFailure {
    pub evidence_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockValidationGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub reports: Vec<F3BlockValidationReport>,
    pub validated_blocks: Vec<F3BlockValidationEnablement>,
    pub failures: Vec<F3BlockValidationGateFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockRollbackPlan {
    pub plan_id: String,
    pub disable_command: String,
    pub validation_command: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockEnablementRequest {
    pub request_id: String,
    pub evidence_id: String,
    pub backend: String,
    pub runtime: F3BlockValidationRuntime,
    pub action: F3BlockValidationAction,
    pub operator_approved: bool,
    pub default_enabled: bool,
    pub rollback: Option<F3BlockRollbackPlan>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockApprovedEnablement {
    pub request_id: String,
    pub evidence_id: String,
    pub backend: String,
    pub runtime: F3BlockValidationRuntime,
    pub action: F3BlockValidationAction,
    pub default_enabled: bool,
    pub rollback_plan_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockEnablementFailure {
    pub request_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockEnablementPolicyReport {
    pub schema_version: u32,
    pub passed: bool,
    pub approved_enablements: Vec<F3BlockApprovedEnablement>,
    pub failures: Vec<F3BlockEnablementFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F3BlockOperatorAuditOperation {
    Approve,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BlockOperatorAuditRecord {
    pub record_type: String,
    pub operation: F3BlockOperatorAuditOperation,
    pub request_id: String,
    pub evidence_id: String,
    pub backend: String,
    pub runtime: F3BlockValidationRuntime,
    pub action: F3BlockValidationAction,
    pub default_enabled: bool,
    pub rollback_plan_id: String,
    pub operator: String,
    pub timestamp_unix_ms: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3LocalSeccompExecutionRequest {
    pub evidence_id: String,
    pub backend: String,
    pub runtime: F3BlockValidationRuntime,
    pub action: F3BlockValidationAction,
    pub target_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3LocalSeccompExecutionFailure {
    pub evidence_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3LocalSeccompExecutionReport {
    pub schema_version: u32,
    pub passed: bool,
    pub evidence_id: String,
    pub target_path: String,
    pub applied_enablement_id: Option<String>,
    pub enforcement_backend: Option<String>,
    pub blocked_errno: Option<i32>,
    pub blocked_message: Option<String>,
    pub failures: Vec<F3LocalSeccompExecutionFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BpfLsmPrototypeEnvironment {
    pub linux: bool,
    pub btf_available: bool,
    pub bpf_lsm_configured: bool,
    pub bpf_lsm_active: bool,
    pub prototype_object_available: bool,
    pub privileged_for_bpf: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BpfLsmPrototypePrerequisiteFailure {
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F3BpfLsmPrototypePrerequisiteReport {
    pub schema_version: u32,
    pub passed: bool,
    pub environment: F3BpfLsmPrototypeEnvironment,
    pub failures: Vec<F3BpfLsmPrototypePrerequisiteFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F4RuntimeGuardrailTarget {
    Local,
    Docker,
    Containerd,
    Kubernetes,
    Gvisor,
    Kata,
    Firecracker,
}

impl F4RuntimeGuardrailTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Docker => "docker",
            Self::Containerd => "containerd",
            Self::Kubernetes => "kubernetes",
            Self::Gvisor => "gvisor",
            Self::Kata => "kata",
            Self::Firecracker => "firecracker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F4GuardrailSupportStatus {
    Supported,
    PrototypeValidated,
    RequiresRuntimeEvidence,
    MetadataOnly,
    BoundaryOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4GuardrailSupportEntry {
    pub status: F4GuardrailSupportStatus,
    pub evidence_ids: Vec<String>,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4RuntimeGuardrailSupport {
    pub runtime: F4RuntimeGuardrailTarget,
    pub notify: F4GuardrailSupportEntry,
    pub review: F4GuardrailSupportEntry,
    pub kill: F4GuardrailSupportEntry,
    pub seccomp_block: F4GuardrailSupportEntry,
    pub bpf_lsm_block: F4GuardrailSupportEntry,
    pub requires_guest_collector: bool,
    pub no_go_claims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4RuntimeGuardrailMatrixReport {
    pub schema_version: u32,
    pub production_facing_kernel_blocking_supported: bool,
    pub runtimes: Vec<F4RuntimeGuardrailSupport>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4LiveRuntimeEvidenceBundleRequest {
    pub artifact_dir: PathBuf,
    pub visibility_reports: Vec<VisibilityReport>,
    pub block_validation_reports: Vec<F3BlockValidationReport>,
    pub runtime_adapter_evidence_reports: Vec<F4RuntimeAdapterEvidenceReport>,
    pub gvisor_metadata_evidence_reports: Vec<F4GvisorMetadataEvidenceReport>,
    pub kubernetes_agent_sandbox_evidence_reports: Vec<F4KubernetesAgentSandboxEvidenceReport>,
    pub kata_boundary_evidence_reports: Vec<F4KataBoundaryEvidenceReport>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4LiveRuntimeEvidenceBundleFailure {
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4LiveRuntimeEvidenceBundleReport {
    pub schema_version: u32,
    pub passed: bool,
    pub artifact_dir: PathBuf,
    pub visibility_gate: VisibilityReportGateReport,
    pub matrix: Option<F4RuntimeGuardrailMatrixReport>,
    pub failures: Vec<F4LiveRuntimeEvidenceBundleFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F5ReleasePromotionChannel {
    Staging,
    Production,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5ReleasePromotionRequest {
    pub promotion_id: String,
    pub channel: F5ReleasePromotionChannel,
    pub source_tag: String,
    pub target_tag: String,
    pub image_digest: String,
    pub sbom_attachment_digest: String,
    pub release_manifest_sha256: String,
    pub retention_days: u32,
    pub requested_at_unix_ms: u64,
    pub retain_until_unix_ms: u64,
    pub promotion_approved: bool,
    pub require_digest_pulls: bool,
    pub allow_anonymous_pull: bool,
    pub allowed_pull_principals: Vec<String>,
    pub allowed_push_principals: Vec<String>,
    pub rollback_tag: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct F5ReleasePromotionPolicyEvidence {
    pub release_manifest_sha256: String,
    pub registry_attachment_sha256: String,
    pub release_manifest: serde_json::Value,
    pub registry_attachment: serde_json::Value,
    pub archive_manifest: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5ReleasePromotionApproval {
    pub promotion_id: String,
    pub channel: F5ReleasePromotionChannel,
    pub source_tag: String,
    pub target_tag: String,
    pub image_digest: String,
    pub release_manifest_sha256: String,
    pub sbom_attachment_digest: String,
    pub retention_days: u32,
    pub retain_until_unix_ms: u64,
    pub allowed_pull_principals: Vec<String>,
    pub allowed_push_principals: Vec<String>,
    pub rollback_tag: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5ReleasePromotionPolicyFailure {
    pub field: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5ReleasePromotionPolicyReport {
    pub schema_version: u32,
    pub passed: bool,
    pub approval: Option<F5ReleasePromotionApproval>,
    pub failures: Vec<F5ReleasePromotionPolicyFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F5SigningKeyProvider {
    EphemeralLocalValidation,
    LocalFile,
    Kms,
    Hsm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F5SigningReleaseChannel {
    Staging,
    Production,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5SigningProfile {
    pub profile_id: String,
    pub provider: F5SigningKeyProvider,
    pub key_uri: String,
    pub public_key_ref: String,
    pub certificate_chain_ref: String,
    pub attestation_ref: String,
    pub non_exportable: bool,
    pub hardware_or_service_backed: bool,
    pub operator_approved: bool,
    pub rotation_period_days: u32,
    pub allowed_release_channels: Vec<F5SigningReleaseChannel>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5SigningProfileApproval {
    pub profile_id: String,
    pub provider: F5SigningKeyProvider,
    pub key_uri: String,
    pub public_key_ref: String,
    pub certificate_chain_ref: String,
    pub attestation_ref: String,
    pub max_rotation_period_days: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5SigningProfileFailure {
    pub field: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5SigningProfileReport {
    pub schema_version: u32,
    pub passed: bool,
    pub approval: Option<F5SigningProfileApproval>,
    pub failures: Vec<F5SigningProfileFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F5WormProvider {
    LocalFilesystem,
    S3ObjectLock,
    GcsBucketLock,
    AzureImmutableBlob,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F5WormRetentionMode {
    Governance,
    Compliance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5WormArchivePolicy {
    pub policy_id: String,
    pub provider: F5WormProvider,
    pub bucket_uri: String,
    pub object_prefix: String,
    pub release_manifest_sha256: String,
    pub requested_at_unix_ms: u64,
    pub retention_days: u32,
    pub retain_until_unix_ms: u64,
    pub retention_mode: F5WormRetentionMode,
    pub object_lock_enabled: bool,
    pub versioning_enabled: bool,
    pub legal_hold_supported: bool,
    pub delete_protection_enabled: bool,
    pub audit_log_ref: String,
    pub operator_approved: bool,
    pub allowed_writer_principals: Vec<String>,
    pub allowed_reader_principals: Vec<String>,
    pub deny_delete_principals: Vec<String>,
    pub replication_target_uri: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5WormArchiveApproval {
    pub policy_id: String,
    pub provider: F5WormProvider,
    pub bucket_uri: String,
    pub object_prefix: String,
    pub release_manifest_sha256: String,
    pub retention_days: u32,
    pub retain_until_unix_ms: u64,
    pub replication_target_uri: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5WormArchivePolicyFailure {
    pub field: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F5WormArchivePolicyReport {
    pub schema_version: u32,
    pub passed: bool,
    pub approval: Option<F5WormArchiveApproval>,
    pub failures: Vec<F5WormArchivePolicyFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F4RuntimeAdapterEvidenceSource {
    Fixture,
    LiveHost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4RuntimeAdapterEvidenceReport {
    pub evidence_id: String,
    pub source: F4RuntimeAdapterEvidenceSource,
    pub runtime: F4RuntimeGuardrailTarget,
    pub adapter: String,
    pub session_id: String,
    pub workload_id: String,
    pub cgroup_id: u64,
    pub runtime_handler: Option<String>,
    pub metadata_correlation: bool,
    pub cgroup_correlation: bool,
    pub host_boundary_visibility: bool,
    pub guest_semantics_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4RuntimeAdapterEvidenceGateFailure {
    pub evidence_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4RuntimeAdapterEvidenceGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub reports: Vec<F4RuntimeAdapterEvidenceReport>,
    pub validated_evidence: Vec<F4RuntimeAdapterEvidenceReport>,
    pub failures: Vec<F4RuntimeAdapterEvidenceGateFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4GvisorMetadataEvidenceReport {
    pub evidence_id: String,
    pub source: F4RuntimeAdapterEvidenceSource,
    pub runtime_adapter_evidence_id: String,
    pub session_id: String,
    pub runtime_handler: Option<String>,
    pub host_event_subjects: Vec<String>,
    pub runsc_observed: bool,
    pub sentry_observed: bool,
    pub gofer_observed: bool,
    pub host_semantics_collapsed: bool,
    pub guest_semantics_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4GvisorMetadataEvidenceGateFailure {
    pub evidence_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4GvisorMetadataEvidenceGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub reports: Vec<F4GvisorMetadataEvidenceReport>,
    pub validated_evidence: Vec<F4GvisorMetadataEvidenceReport>,
    pub failures: Vec<F4GvisorMetadataEvidenceGateFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4KubernetesAgentSandboxEvidenceReport {
    pub evidence_id: String,
    pub source: F4RuntimeAdapterEvidenceSource,
    pub runtime_adapter_evidence_id: String,
    pub session_id: String,
    pub pod_name: String,
    pub namespace: String,
    pub service_account: Option<String>,
    pub runtime_class_name: Option<String>,
    pub sandbox_name: Option<String>,
    pub node_name: Option<String>,
    pub pod_uid: Option<String>,
    pub host_boundary_visibility: bool,
    pub guest_semantics_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4KubernetesAgentSandboxEvidenceGateFailure {
    pub evidence_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4KubernetesAgentSandboxEvidenceGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub reports: Vec<F4KubernetesAgentSandboxEvidenceReport>,
    pub validated_evidence: Vec<F4KubernetesAgentSandboxEvidenceReport>,
    pub failures: Vec<F4KubernetesAgentSandboxEvidenceGateFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4KataBoundaryEvidenceReport {
    pub evidence_id: String,
    pub source: F4RuntimeAdapterEvidenceSource,
    pub runtime_adapter_evidence_id: String,
    pub session_id: String,
    pub runtime_handler: Option<String>,
    pub host_event_subjects: Vec<String>,
    pub shim_observed: bool,
    pub vmm_observed: bool,
    pub host_boundary_visibility: bool,
    pub guest_collector_required: bool,
    pub guest_semantics_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4KataBoundaryEvidenceGateFailure {
    pub evidence_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct F4KataBoundaryEvidenceGateReport {
    pub schema_version: u32,
    pub passed: bool,
    pub reports: Vec<F4KataBoundaryEvidenceReport>,
    pub validated_evidence: Vec<F4KataBoundaryEvidenceReport>,
    pub failures: Vec<F4KataBoundaryEvidenceGateFailure>,
}

impl F3BlockOperatorAuditRecord {
    pub fn to_json_line(&self) -> Result<String, String> {
        serde_json::to_string(self)
            .map_err(|error| format!("failed to serialize F3 block operator audit record: {error}"))
    }
}

pub trait ServiceController {
    fn restore_unit_file_state(
        &mut self,
        service_name: &str,
        unit_file_state: &str,
    ) -> Result<(), String>;

    fn restore_active_state(
        &mut self,
        service_name: &str,
        active_state: &str,
    ) -> Result<(), String>;
}

pub struct SystemctlServiceController;

impl ServiceController for SystemctlServiceController {
    fn restore_unit_file_state(
        &mut self,
        service_name: &str,
        unit_file_state: &str,
    ) -> Result<(), String> {
        match unit_file_state {
            "enabled" => systemctl_action("enable", service_name),
            "disabled" => systemctl_action("disable", service_name),
            "masked" => systemctl_action("mask", service_name),
            "static" | "generated" | "indirect" | "alias" | "linked" | "linked-runtime"
            | "transient" => Ok(()),
            state => Err(format!(
                "unsupported unit file state for {service_name}: {state}"
            )),
        }
    }

    fn restore_active_state(
        &mut self,
        service_name: &str,
        active_state: &str,
    ) -> Result<(), String> {
        match active_state {
            "active" | "reloading" => systemctl_action("restart", service_name),
            "activating" => systemctl_action("start", service_name),
            "inactive" | "deactivating" => systemctl_action("stop", service_name),
            "failed" => {
                systemctl_action("stop", service_name)?;
                systemctl_action("reset-failed", service_name)
            }
            state => Err(format!(
                "unsupported active state for {service_name}: {state}"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidateHostArgs {
    pub mode: ValidateHostMode,
    pub output_dir: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidateHostMode {
    DryRun,
    ApplyRuntimeRegistration,
    Restore,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSource {
    pub id: String,
    pub path: PathBuf,
}

impl BackupSource {
    pub fn new(id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            path: path.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub entries: Vec<BackupEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceState {
    pub service_name: String,
    pub load_state: String,
    pub active_state: String,
    pub unit_file_state: String,
    pub fragment_path: Option<PathBuf>,
    pub drop_in_paths: Vec<PathBuf>,
    pub runtime_sockets: Vec<RuntimeSocketState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSocketState {
    pub path: PathBuf,
    pub present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KubernetesRestoreContext {
    pub runtime_classes: Vec<RuntimeClassSnapshot>,
    pub nodes: Vec<NodeSnapshot>,
    pub workloads: Vec<KubernetesWorkloadSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeClassSnapshot {
    pub name: String,
    pub handler: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeSnapshot {
    pub name: String,
    pub ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KubernetesWorkloadSnapshot {
    pub namespace: String,
    pub name: String,
    pub service_account_name: Option<String>,
    pub runtime_class_name: Option<String>,
    pub node_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RestorePlan {
    pub schema_version: u32,
    pub actions: Vec<RestoreAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostValidationReport {
    pub schema_version: u32,
    pub backup_manifest: BackupManifest,
    pub services: Vec<ServiceState>,
    pub kubernetes: KubernetesRestoreContext,
    pub restore_plan: RestorePlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RestoreAction {
    RestoreRegularFile {
        id: String,
        from_backup: PathBuf,
        to_path: PathBuf,
        uid: Option<u32>,
        gid: Option<u32>,
        mode: Option<u32>,
    },
    RestoreSymlink {
        id: String,
        target: PathBuf,
        link_path: PathBuf,
        uid: Option<u32>,
        gid: Option<u32>,
    },
    EnsureMissing {
        id: String,
        path: PathBuf,
    },
    RemoveValidationPath {
        path: PathBuf,
    },
    RestoreServiceState {
        service_name: String,
        active_state: String,
        unit_file_state: String,
    },
}

pub fn default_host_backup_sources() -> Vec<BackupSource> {
    vec![
        BackupSource::new("docker_daemon", "/etc/docker/daemon.json"),
        BackupSource::new("containerd_config", "/etc/containerd/config.toml"),
        BackupSource::new(
            "k3s_generated_containerd_config",
            "/var/lib/rancher/k3s/agent/etc/containerd/config.toml",
        ),
        BackupSource::new(
            "k3s_containerd_v3_template",
            "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl",
        ),
        BackupSource::new(
            "k3s_runtime_dropin",
            "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml",
        ),
        BackupSource::new(
            "docker_http_proxy_dropin",
            "/etc/systemd/system/docker.service.d/http-proxy.conf",
        ),
        BackupSource::new(
            "k3s_http_proxy_dropin",
            "/etc/systemd/system/k3s.service.d/http-proxy.conf",
        ),
    ]
}

pub fn default_f2_performance_budgets() -> Vec<PerformanceBudget> {
    vec![
        PerformanceBudget {
            load: PerformanceLoad::Idle,
            min_events_per_second: 0,
            max_milli_cpu: Some(10),
            max_rss_mib: 128,
            require_worker_pool_bounded: true,
            require_loss_accounted: true,
            require_queue_bounded: true,
            require_adapter_connected: true,
        },
        PerformanceBudget {
            load: PerformanceLoad::Steady10000,
            min_events_per_second: 10_000,
            max_milli_cpu: Some(1000),
            max_rss_mib: 256,
            require_worker_pool_bounded: true,
            require_loss_accounted: true,
            require_queue_bounded: true,
            require_adapter_connected: true,
        },
        PerformanceBudget {
            load: PerformanceLoad::Burst50000,
            min_events_per_second: 50_000,
            max_milli_cpu: None,
            max_rss_mib: 256,
            require_worker_pool_bounded: true,
            require_loss_accounted: true,
            require_queue_bounded: true,
            require_adapter_connected: true,
        },
    ]
}

pub fn evaluate_performance_gate(
    budgets: Vec<PerformanceBudget>,
    samples: Vec<PerformanceSample>,
) -> PerformanceGateReport {
    let samples_by_load: BTreeMap<PerformanceLoad, &PerformanceSample> =
        samples.iter().map(|sample| (sample.load, sample)).collect();
    let mut failures = Vec::new();

    for budget in &budgets {
        let Some(sample) = samples_by_load.get(&budget.load) else {
            failures.push(performance_failure(
                budget.load,
                "sample",
                "required load sample missing",
                "missing",
                "present",
            ));
            continue;
        };

        if sample.events_per_second < budget.min_events_per_second {
            failures.push(performance_failure(
                budget.load,
                "events_per_second",
                &format!("{} event rate below required load", load_name(budget.load)),
                sample.events_per_second.to_string(),
                budget.min_events_per_second.to_string(),
            ));
        }

        if let Some(max_milli_cpu) = budget.max_milli_cpu {
            if sample.milli_cpu > max_milli_cpu {
                failures.push(performance_failure(
                    budget.load,
                    "milli_cpu",
                    &format!("{} cpu budget exceeded", load_name(budget.load)),
                    sample.milli_cpu.to_string(),
                    max_milli_cpu.to_string(),
                ));
            }
        }

        if sample.rss_mib > budget.max_rss_mib {
            failures.push(performance_failure(
                budget.load,
                "rss_mib",
                &format!("{} rss budget exceeded", load_name(budget.load)),
                sample.rss_mib.to_string(),
                budget.max_rss_mib.to_string(),
            ));
        }

        if budget.require_worker_pool_bounded && !sample.worker_pool_bounded {
            failures.push(performance_failure(
                budget.load,
                "worker_pool_bounded",
                &format!("{} worker pool was not bounded", load_name(budget.load)),
                "false",
                "true",
            ));
        }

        if budget.require_loss_accounted && !sample.loss_accounted {
            failures.push(performance_failure(
                budget.load,
                "loss_accounted",
                &format!("{} loss was not accounted", load_name(budget.load)),
                "false",
                "true",
            ));
        }

        if budget.require_queue_bounded && !sample.queue_bounded {
            failures.push(performance_failure(
                budget.load,
                "queue_bounded",
                &format!("{} queue was not bounded", load_name(budget.load)),
                "false",
                "true",
            ));
        }

        if budget.require_adapter_connected && !sample.adapter_connected {
            failures.push(performance_failure(
                budget.load,
                "adapter_connected",
                &format!("{} adapters not connected", load_name(budget.load)),
                "false",
                "true",
            ));
        }

        let accounted_events = sample
            .written_events
            .saturating_add(sample.dropped_events)
            .max(sample.accepted_events.saturating_add(sample.dropped_events));
        if accounted_events < sample.submitted_events {
            failures.push(performance_failure(
                budget.load,
                "event_accounting",
                &format!(
                    "{} submitted events were not fully accounted",
                    load_name(budget.load)
                ),
                accounted_events.to_string(),
                sample.submitted_events.to_string(),
            ));
        }
    }

    PerformanceGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        budgets,
        samples,
        failures,
    }
}

pub fn required_f2_visibility_targets() -> Vec<VisibilityTarget> {
    vec![
        VisibilityTarget::Local,
        VisibilityTarget::DockerRunc,
        VisibilityTarget::DockerGvisor,
        VisibilityTarget::ContainerdRunc,
        VisibilityTarget::ContainerdGvisor,
        VisibilityTarget::ContainerdKata,
        VisibilityTarget::K3sRunc,
        VisibilityTarget::K3sGvisor,
        VisibilityTarget::K3sKata,
    ]
}

pub fn evaluate_f5_release_promotion_policy(
    request: F5ReleasePromotionRequest,
    evidence: F5ReleasePromotionPolicyEvidence,
) -> F5ReleasePromotionPolicyReport {
    const MIN_PRODUCTION_RETENTION_DAYS: u32 = 90;
    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

    let mut failures = Vec::new();

    if request.promotion_id.trim().is_empty() {
        f5_push_failure(&mut failures, "promotion_id", "promotion id is required");
    }
    if !f5_is_sha256_digest(&request.image_digest) {
        f5_push_failure(
            &mut failures,
            "image_digest",
            "image digest must be a sha256 digest",
        );
    }
    if !f5_is_sha256_digest(&request.sbom_attachment_digest) {
        f5_push_failure(
            &mut failures,
            "sbom_attachment_digest",
            "SBOM attachment digest must be a sha256 digest",
        );
    }
    if !f5_is_sha256_hex(&request.release_manifest_sha256) {
        f5_push_failure(
            &mut failures,
            "release_manifest_sha256",
            "release manifest sha256 must be 64 hex characters",
        );
    }
    if request.release_manifest_sha256 != evidence.release_manifest_sha256 {
        f5_push_failure(
            &mut failures,
            "release_manifest_sha256",
            "request release manifest digest does not match evidence",
        );
    }
    if !f5_is_sha256_hex(&evidence.registry_attachment_sha256) {
        f5_push_failure(
            &mut failures,
            "registry_attachment_sha256",
            "registry attachment sha256 must be 64 hex characters",
        );
    }

    f5_validate_release_manifest(&evidence, &mut failures);
    f5_validate_registry_attachment(&request, &evidence, &mut failures);
    f5_validate_archive_manifest(&request, &evidence, &mut failures);

    if request.target_tag == "latest" || !request.target_tag.starts_with("prod-") {
        f5_push_failure(
            &mut failures,
            "target_tag",
            "target tag must be immutable and start with prod-",
        );
    }
    if request.source_tag.trim().is_empty() {
        f5_push_failure(&mut failures, "source_tag", "source tag is required");
    }
    if request.retention_days < MIN_PRODUCTION_RETENTION_DAYS {
        f5_push_failure(
            &mut failures,
            "retention_days",
            "minimum production retention is 90 days",
        );
    }
    let required_retain_until = request
        .requested_at_unix_ms
        .saturating_add(u64::from(request.retention_days).saturating_mul(DAY_MS));
    if request.retain_until_unix_ms < required_retain_until {
        f5_push_failure(
            &mut failures,
            "retain_until_unix_ms",
            "retain-until timestamp must cover the requested retention window",
        );
    }
    if !request.promotion_approved {
        f5_push_failure(
            &mut failures,
            "promotion_approved",
            "operator approval is required",
        );
    }
    if !request.require_digest_pulls {
        f5_push_failure(
            &mut failures,
            "require_digest_pulls",
            "digest-only pulls are required",
        );
    }
    if request.allow_anonymous_pull {
        f5_push_failure(
            &mut failures,
            "allow_anonymous_pull",
            "anonymous registry pull access is forbidden",
        );
    }
    if request.allowed_pull_principals.is_empty() {
        f5_push_failure(
            &mut failures,
            "allowed_pull_principals",
            "at least one pull principal is required",
        );
    }
    if request.allowed_push_principals.is_empty() {
        f5_push_failure(
            &mut failures,
            "allowed_push_principals",
            "at least one push principal is required",
        );
    }
    for principal in &request.allowed_pull_principals {
        if principal == "*" {
            f5_push_failure(
                &mut failures,
                "allowed_pull_principals",
                "wildcard pull principals are forbidden",
            );
        }
        if f5_is_anonymous_principal(principal) {
            f5_push_failure(
                &mut failures,
                "allowed_pull_principals",
                "anonymous pull principals are forbidden",
            );
        }
    }
    for principal in &request.allowed_push_principals {
        if principal == "*" {
            f5_push_failure(
                &mut failures,
                "allowed_push_principals",
                "wildcard push principals are forbidden",
            );
        }
        if f5_is_anonymous_principal(principal) {
            f5_push_failure(
                &mut failures,
                "allowed_push_principals",
                "anonymous push principals are forbidden",
            );
        }
    }
    if request.rollback_tag.trim().is_empty() {
        f5_push_failure(&mut failures, "rollback_tag", "rollback tag is required");
    }

    let approval = if failures.is_empty() {
        Some(F5ReleasePromotionApproval {
            promotion_id: request.promotion_id,
            channel: request.channel,
            source_tag: request.source_tag,
            target_tag: request.target_tag,
            image_digest: request.image_digest,
            release_manifest_sha256: request.release_manifest_sha256,
            sbom_attachment_digest: request.sbom_attachment_digest,
            retention_days: request.retention_days,
            retain_until_unix_ms: request.retain_until_unix_ms,
            allowed_pull_principals: request.allowed_pull_principals,
            allowed_push_principals: request.allowed_push_principals,
            rollback_tag: request.rollback_tag,
        })
    } else {
        None
    };

    F5ReleasePromotionPolicyReport {
        schema_version: 1,
        passed: approval.is_some(),
        approval,
        failures,
    }
}

pub fn evaluate_f5_signing_profile(profile: F5SigningProfile) -> F5SigningProfileReport {
    const MAX_ROTATION_DAYS: u32 = 180;
    let mut failures = Vec::new();

    if profile.profile_id.trim().is_empty() {
        f5_signing_failure(&mut failures, "profile_id", "profile id is required");
    }
    if !matches!(
        profile.provider,
        F5SigningKeyProvider::Kms | F5SigningKeyProvider::Hsm
    ) {
        f5_signing_failure(
            &mut failures,
            "provider",
            "production release signing requires KMS or HSM provider",
        );
    }
    if !profile.non_exportable {
        f5_signing_failure(
            &mut failures,
            "non_exportable",
            "production signing key must be non-exportable",
        );
    }
    if !profile.hardware_or_service_backed {
        f5_signing_failure(
            &mut failures,
            "hardware_or_service_backed",
            "production signing key must be hardware-backed or managed by a KMS service",
        );
    }
    if !profile.operator_approved {
        f5_signing_failure(
            &mut failures,
            "operator_approved",
            "operator approval is required",
        );
    }
    if profile.public_key_ref.trim().is_empty() {
        f5_signing_failure(
            &mut failures,
            "public_key_ref",
            "public key reference is required",
        );
    }
    if profile.certificate_chain_ref.trim().is_empty() {
        f5_signing_failure(
            &mut failures,
            "certificate_chain_ref",
            "certificate chain or verification bundle reference is required",
        );
    }
    if profile.attestation_ref.trim().is_empty() {
        f5_signing_failure(
            &mut failures,
            "attestation_ref",
            "attestation or key policy evidence is required",
        );
    }
    if profile.rotation_period_days == 0 || profile.rotation_period_days > MAX_ROTATION_DAYS {
        f5_signing_failure(
            &mut failures,
            "rotation_period_days",
            "rotation period must be 180 days or less",
        );
    }
    if !profile
        .allowed_release_channels
        .contains(&F5SigningReleaseChannel::Production)
    {
        f5_signing_failure(
            &mut failures,
            "allowed_release_channels",
            "production release channel must be allowed",
        );
    }
    if f5_is_file_key_uri(&profile.key_uri) {
        f5_signing_failure(
            &mut failures,
            "key_uri",
            "file paths are not valid production signing key URIs",
        );
    } else if !f5_signing_uri_matches_provider(profile.provider, &profile.key_uri) {
        f5_signing_failure(
            &mut failures,
            "key_uri",
            "signing key URI must match the selected KMS or HSM provider",
        );
    }

    let approval = if failures.is_empty() {
        Some(F5SigningProfileApproval {
            profile_id: profile.profile_id,
            provider: profile.provider,
            key_uri: profile.key_uri,
            public_key_ref: profile.public_key_ref,
            certificate_chain_ref: profile.certificate_chain_ref,
            attestation_ref: profile.attestation_ref,
            max_rotation_period_days: profile.rotation_period_days,
        })
    } else {
        None
    };

    F5SigningProfileReport {
        schema_version: 1,
        passed: approval.is_some(),
        approval,
        failures,
    }
}

pub fn evaluate_f5_worm_archive_policy(policy: F5WormArchivePolicy) -> F5WormArchivePolicyReport {
    const MIN_WORM_RETENTION_DAYS: u32 = 180;
    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
    let mut failures = Vec::new();

    if policy.policy_id.trim().is_empty() {
        f5_worm_failure(&mut failures, "policy_id", "policy id is required");
    }
    if !matches!(
        policy.provider,
        F5WormProvider::S3ObjectLock
            | F5WormProvider::GcsBucketLock
            | F5WormProvider::AzureImmutableBlob
    ) {
        f5_worm_failure(
            &mut failures,
            "provider",
            "external WORM archive requires S3 Object Lock, GCS Bucket Lock, or Azure Immutable Blob",
        );
    }
    if !f5_worm_uri_matches_provider(policy.provider, &policy.bucket_uri) {
        f5_worm_failure(
            &mut failures,
            "bucket_uri",
            "production archive URI must be provider-backed object storage",
        );
    }
    if policy.object_prefix.trim().is_empty()
        || policy.object_prefix.starts_with('/')
        || policy.object_prefix.contains("..")
    {
        f5_worm_failure(
            &mut failures,
            "object_prefix",
            "object prefix must be a bounded relative object prefix",
        );
    }
    if !f5_is_sha256_hex(&policy.release_manifest_sha256) {
        f5_worm_failure(
            &mut failures,
            "release_manifest_sha256",
            "release manifest sha256 must be 64 hex characters",
        );
    }
    if !policy.object_lock_enabled {
        f5_worm_failure(
            &mut failures,
            "object_lock_enabled",
            "object lock must be enabled",
        );
    }
    if !policy.versioning_enabled {
        f5_worm_failure(
            &mut failures,
            "versioning_enabled",
            "object versioning must be enabled",
        );
    }
    if policy.retention_mode != F5WormRetentionMode::Compliance {
        f5_worm_failure(
            &mut failures,
            "retention_mode",
            "retention mode must be compliance",
        );
    }
    if policy.retention_days < MIN_WORM_RETENTION_DAYS {
        f5_worm_failure(
            &mut failures,
            "retention_days",
            "minimum WORM retention is 180 days",
        );
    }
    let required_retain_until = policy
        .requested_at_unix_ms
        .saturating_add(u64::from(policy.retention_days).saturating_mul(DAY_MS));
    if policy.retain_until_unix_ms < required_retain_until {
        f5_worm_failure(
            &mut failures,
            "retain_until_unix_ms",
            "retain-until timestamp must cover the WORM retention window",
        );
    }
    if !policy.legal_hold_supported {
        f5_worm_failure(
            &mut failures,
            "legal_hold_supported",
            "legal hold support is required",
        );
    }
    if !policy.delete_protection_enabled {
        f5_worm_failure(
            &mut failures,
            "delete_protection_enabled",
            "delete protection must be enabled",
        );
    }
    if policy.audit_log_ref.trim().is_empty() {
        f5_worm_failure(
            &mut failures,
            "audit_log_ref",
            "audit log reference is required",
        );
    }
    if !policy.operator_approved {
        f5_worm_failure(
            &mut failures,
            "operator_approved",
            "operator approval is required",
        );
    }
    if policy.allowed_writer_principals.is_empty() {
        f5_worm_failure(
            &mut failures,
            "allowed_writer_principals",
            "writer principals are required",
        );
    }
    if policy.allowed_reader_principals.is_empty() {
        f5_worm_failure(
            &mut failures,
            "allowed_reader_principals",
            "reader principals are required",
        );
    }
    for principal in &policy.allowed_writer_principals {
        if principal == "*" {
            f5_worm_failure(
                &mut failures,
                "allowed_writer_principals",
                "wildcard writer principals are forbidden",
            );
        }
        if f5_is_anonymous_principal(principal) {
            f5_worm_failure(
                &mut failures,
                "allowed_writer_principals",
                "anonymous writer principals are forbidden",
            );
        }
    }
    for principal in &policy.allowed_reader_principals {
        if principal == "*" {
            f5_worm_failure(
                &mut failures,
                "allowed_reader_principals",
                "wildcard reader principals are forbidden",
            );
        }
        if f5_is_anonymous_principal(principal) {
            f5_worm_failure(
                &mut failures,
                "allowed_reader_principals",
                "anonymous reader principals are forbidden",
            );
        }
    }
    if policy.deny_delete_principals.is_empty() {
        f5_worm_failure(
            &mut failures,
            "deny_delete_principals",
            "delete-deny principals are required",
        );
    }
    if policy.replication_target_uri.trim().is_empty() {
        f5_worm_failure(
            &mut failures,
            "replication_target_uri",
            "replication target URI is required",
        );
    } else if !f5_worm_uri_matches_provider(policy.provider, &policy.replication_target_uri) {
        f5_worm_failure(
            &mut failures,
            "replication_target_uri",
            "replication target URI must use the same provider-backed storage type",
        );
    } else if policy.replication_target_uri == policy.bucket_uri {
        f5_worm_failure(
            &mut failures,
            "replication_target_uri",
            "replication target URI must differ from the primary archive URI",
        );
    }

    let approval = if failures.is_empty() {
        Some(F5WormArchiveApproval {
            policy_id: policy.policy_id,
            provider: policy.provider,
            bucket_uri: policy.bucket_uri,
            object_prefix: policy.object_prefix,
            release_manifest_sha256: policy.release_manifest_sha256,
            retention_days: policy.retention_days,
            retain_until_unix_ms: policy.retain_until_unix_ms,
            replication_target_uri: policy.replication_target_uri,
        })
    } else {
        None
    };

    F5WormArchivePolicyReport {
        schema_version: 1,
        passed: approval.is_some(),
        approval,
        failures,
    }
}

pub fn evaluate_visibility_report_gate(
    reports: Vec<VisibilityReport>,
) -> VisibilityReportGateReport {
    let reports_by_target: BTreeMap<VisibilityTarget, &VisibilityReport> = reports
        .iter()
        .map(|report| (report.target, report))
        .collect();
    let mut failures = Vec::new();

    for target in required_f2_visibility_targets() {
        let Some(report) = reports_by_target.get(&target) else {
            failures.push(visibility_failure(
                Some(target),
                format!("missing visibility report for {}", target.as_str()),
            ));
            continue;
        };

        if !report.live_validated {
            failures.push(visibility_failure(
                Some(target),
                "visibility report is not live validated",
            ));
        }
        if report.evidence_source.trim().is_empty() {
            failures.push(visibility_failure(
                Some(target),
                "visibility report is missing evidence source",
            ));
        }
        if report.host_visibility_scope.trim().is_empty() {
            failures.push(visibility_failure(
                Some(target),
                "visibility report is missing host visibility scope",
            ));
        }
        if report.guest_semantics_claimed
            && matches!(
                target,
                VisibilityTarget::ContainerdKata | VisibilityTarget::K3sKata
            )
        {
            failures.push(visibility_failure(
                Some(target),
                "Kata host-boundary report must not claim full guest semantics",
            ));
        }
    }

    VisibilityReportGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        reports,
        failures,
    }
}

pub fn evaluate_f4_live_runtime_evidence_bundle(
    request: F4LiveRuntimeEvidenceBundleRequest,
) -> F4LiveRuntimeEvidenceBundleReport {
    let mut failures = Vec::new();

    for artifact in required_f4_live_runtime_artifacts() {
        let path = request.artifact_dir.join(artifact);
        if !path.is_file() {
            failures.push(f4_live_runtime_evidence_failure(format!(
                "runtime adapter matrix artifact missing required file: {}",
                path.display()
            )));
        }
    }

    let artifact_marker = request.artifact_dir.display().to_string();
    let visibility_gate = evaluate_visibility_report_gate(request.visibility_reports);
    if !visibility_gate.passed {
        failures.push(f4_live_runtime_evidence_failure(
            "F4 live runtime evidence requires a passed F2 visibility report gate",
        ));
    }
    for report in &visibility_gate.reports {
        if !report.evidence_source.contains(&artifact_marker) {
            failures.push(f4_live_runtime_evidence_failure(format!(
                "visibility evidence source for {} must reference runtime adapter matrix artifact {}",
                report.target.as_str(),
                artifact_marker
            )));
        }
    }

    let adapter_gate =
        evaluate_f4_runtime_adapter_evidence_gate(request.runtime_adapter_evidence_reports);
    if !adapter_gate.passed {
        failures.push(f4_live_runtime_evidence_failure(
            "F4 live runtime evidence requires a passed runtime adapter evidence gate",
        ));
    }
    let gvisor_gate = if request.gvisor_metadata_evidence_reports.is_empty() {
        F4GvisorMetadataEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        }
    } else {
        let gate =
            evaluate_f4_gvisor_metadata_evidence_gate(request.gvisor_metadata_evidence_reports);
        if !gate.passed {
            failures.push(f4_live_runtime_evidence_failure(
                "F4 live runtime evidence requires a passed gVisor metadata evidence gate",
            ));
        }
        gate
    };
    let kubernetes_gate = if request.kubernetes_agent_sandbox_evidence_reports.is_empty() {
        F4KubernetesAgentSandboxEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        }
    } else {
        let gate = evaluate_f4_kubernetes_agent_sandbox_evidence_gate(
            request.kubernetes_agent_sandbox_evidence_reports,
        );
        if !gate.passed {
            failures.push(f4_live_runtime_evidence_failure(
                "F4 live runtime evidence requires a passed Kubernetes Agent Sandbox evidence gate",
            ));
        }
        gate
    };
    let kata_gate = if request.kata_boundary_evidence_reports.is_empty() {
        F4KataBoundaryEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        }
    } else {
        let gate = evaluate_f4_kata_boundary_evidence_gate(request.kata_boundary_evidence_reports);
        if !gate.passed {
            failures.push(f4_live_runtime_evidence_failure(
                "F4 live runtime evidence requires a passed Kata boundary evidence gate",
            ));
        }
        gate
    };

    let matrix = if failures.is_empty() {
        Some(evaluate_f4_runtime_guardrail_matrix_with_runtime_metadata(
            request.block_validation_reports,
            adapter_gate,
            gvisor_gate,
            kubernetes_gate,
            kata_gate,
        ))
    } else {
        None
    };

    F4LiveRuntimeEvidenceBundleReport {
        schema_version: 1,
        passed: failures.is_empty(),
        artifact_dir: request.artifact_dir,
        visibility_gate,
        matrix,
        failures,
    }
}

pub fn evaluate_f3_block_validation_gate(
    reports: Vec<F3BlockValidationReport>,
) -> F3BlockValidationGateReport {
    let mut failures = Vec::new();
    let mut validated_blocks = Vec::new();

    if reports.is_empty() {
        failures.push(f3_block_failure(
            None,
            "at least one F3 block validation report is required",
        ));
    }

    for report in &reports {
        let mut report_failures = Vec::new();
        let evidence_id = if report.evidence_id.trim().is_empty() {
            None
        } else {
            Some(report.evidence_id.clone())
        };
        let backend = match report.backend.as_str() {
            "bpf_lsm_block" => Some(BlockPrototypeBackend::BpfLsm),
            "seccomp_block" => Some(BlockPrototypeBackend::Seccomp),
            _ => None,
        };

        if report.evidence_id.trim().is_empty() {
            report_failures.push(f3_block_failure(
                None,
                "block validation report is missing evidence id",
            ));
        }
        if backend.is_none() {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "F3 block validation report must target bpf_lsm_block or seccomp_block backend",
            ));
        }
        if report.source != F3BlockValidationSource::LiveHost {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "pre-operation block requires live-host validation evidence",
            ));
        }
        if backend == Some(BlockPrototypeBackend::BpfLsm) && !report.host_bpf_lsm_available {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "BPF-LSM must be available before enabling block prototype",
            ));
        }
        if backend == Some(BlockPrototypeBackend::Seccomp) && !report.seccomp_available {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "seccomp must be available before enabling block prototype",
            ));
        }
        if !report.preoperation_prevention {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "block prototype evidence must prove pre-operation prevention",
            ));
        }
        if report.decision_latency_ms.is_none() {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "block prototype evidence must include decision latency",
            ));
        }
        if report.side_effect_race_window_ms != Some(0) {
            report_failures.push(f3_block_failure(
                evidence_id.clone(),
                "block prototype evidence must prove a zero side-effect race window",
            ));
        }

        if report_failures.is_empty() {
            let capabilities = PolicyRuntimeCapabilities {
                bpf_lsm_available: report.host_bpf_lsm_available,
                seccomp_available: report.seccomp_available,
                runtime: report.runtime.policy_runtime(),
                ..PolicyRuntimeCapabilities::default()
            };
            let evidence = BlockPrototypeEvidence {
                backend: backend.expect("backend was validated"),
                source: report.source.policy_source(),
                runtime: report.runtime.policy_runtime(),
                action: report.action.policy_event_type(),
                preoperation_prevention: report.preoperation_prevention,
                decision_latency_ms: report.decision_latency_ms,
                side_effect_race_window_ms: report.side_effect_race_window_ms,
            };

            match capabilities.with_validated_block_prototype(evidence) {
                Ok(validated_capabilities) => {
                    if validated_capabilities.can_preoperation_block(
                        report.runtime.policy_runtime(),
                        report.action.policy_event_type(),
                    ) {
                        validated_blocks.push(F3BlockValidationEnablement {
                            evidence_id: report.evidence_id.clone(),
                            runtime: report.runtime,
                            action: report.action,
                        });
                    } else {
                        report_failures.push(f3_block_failure(
                            evidence_id.clone(),
                            "validated block prototype did not enable the requested action",
                        ));
                    }
                }
                Err(error) => report_failures.push(f3_block_failure(evidence_id.clone(), error)),
            }
        }

        failures.extend(report_failures);
    }

    F3BlockValidationGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        reports,
        validated_blocks: if failures.is_empty() {
            validated_blocks
        } else {
            Vec::new()
        },
        failures,
    }
}

pub fn evaluate_f4_runtime_guardrail_matrix(
    reports: Vec<F3BlockValidationReport>,
) -> F4RuntimeGuardrailMatrixReport {
    evaluate_f4_runtime_guardrail_matrix_with_adapter_evidence(
        reports,
        F4RuntimeAdapterEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
    )
}

pub fn evaluate_f4_runtime_guardrail_matrix_with_adapter_evidence(
    reports: Vec<F3BlockValidationReport>,
    adapter_evidence: F4RuntimeAdapterEvidenceGateReport,
) -> F4RuntimeGuardrailMatrixReport {
    evaluate_f4_runtime_guardrail_matrix_with_gvisor_metadata(
        reports,
        adapter_evidence,
        F4GvisorMetadataEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
    )
}

pub fn evaluate_f4_runtime_guardrail_matrix_with_gvisor_metadata(
    reports: Vec<F3BlockValidationReport>,
    adapter_evidence: F4RuntimeAdapterEvidenceGateReport,
    gvisor_metadata: F4GvisorMetadataEvidenceGateReport,
) -> F4RuntimeGuardrailMatrixReport {
    evaluate_f4_runtime_guardrail_matrix_with_runtime_metadata(
        reports,
        adapter_evidence,
        gvisor_metadata,
        F4KubernetesAgentSandboxEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
        F4KataBoundaryEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
    )
}

pub fn evaluate_f4_runtime_guardrail_matrix_with_kubernetes_agent_sandbox(
    reports: Vec<F3BlockValidationReport>,
    adapter_evidence: F4RuntimeAdapterEvidenceGateReport,
    kubernetes_agent_sandbox: F4KubernetesAgentSandboxEvidenceGateReport,
) -> F4RuntimeGuardrailMatrixReport {
    evaluate_f4_runtime_guardrail_matrix_with_runtime_metadata(
        reports,
        adapter_evidence,
        F4GvisorMetadataEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
        kubernetes_agent_sandbox,
        F4KataBoundaryEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
    )
}

pub fn evaluate_f4_runtime_guardrail_matrix_with_kata_boundary(
    reports: Vec<F3BlockValidationReport>,
    adapter_evidence: F4RuntimeAdapterEvidenceGateReport,
    kata_boundary: F4KataBoundaryEvidenceGateReport,
) -> F4RuntimeGuardrailMatrixReport {
    evaluate_f4_runtime_guardrail_matrix_with_runtime_metadata(
        reports,
        adapter_evidence,
        F4GvisorMetadataEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
        F4KubernetesAgentSandboxEvidenceGateReport {
            schema_version: 1,
            passed: true,
            reports: Vec::new(),
            validated_evidence: Vec::new(),
            failures: Vec::new(),
        },
        kata_boundary,
    )
}

pub fn evaluate_f4_runtime_guardrail_matrix_with_runtime_metadata(
    reports: Vec<F3BlockValidationReport>,
    adapter_evidence: F4RuntimeAdapterEvidenceGateReport,
    gvisor_metadata: F4GvisorMetadataEvidenceGateReport,
    kubernetes_agent_sandbox: F4KubernetesAgentSandboxEvidenceGateReport,
    kata_boundary: F4KataBoundaryEvidenceGateReport,
) -> F4RuntimeGuardrailMatrixReport {
    let local_seccomp_evidence = f4_validated_local_block_evidence(&reports, "seccomp_block");
    let local_bpf_lsm_evidence = f4_validated_local_block_evidence(&reports, "bpf_lsm_block");
    let adapter_evidence_ids = f4_adapter_evidence_ids_by_runtime(&adapter_evidence);
    let gvisor_evidence_ids = f4_gvisor_metadata_evidence_ids(&gvisor_metadata);
    let gvisor_combined_evidence_ids = f4_merge_evidence_ids(
        f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Gvisor),
        gvisor_evidence_ids,
    );
    let kubernetes_evidence_ids =
        f4_kubernetes_agent_sandbox_evidence_ids(&kubernetes_agent_sandbox);
    let kubernetes_combined_evidence_ids = f4_merge_evidence_ids(
        f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Kubernetes),
        kubernetes_evidence_ids,
    );
    let kata_evidence_ids = f4_kata_boundary_evidence_ids(&kata_boundary);
    let kata_combined_evidence_ids = f4_merge_evidence_ids(
        f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Kata),
        kata_evidence_ids,
    );

    F4RuntimeGuardrailMatrixReport {
        schema_version: 1,
        production_facing_kernel_blocking_supported: false,
        runtimes: vec![
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Local,
                notify: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    Vec::new(),
                    "audit timeline can emit notify findings for local process sessions",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    Vec::new(),
                    "review findings can be attached to local session evidence",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    Vec::new(),
                    "post-event kill containment is available for local process sessions",
                ),
                seccomp_block: f4_local_block_entry(local_seccomp_evidence, "seccomp_block"),
                bpf_lsm_block: f4_local_block_entry(local_bpf_lsm_evidence, "bpf_lsm_block"),
                requires_guest_collector: false,
                no_go_claims: vec![
                    "local block prototypes are not production-facing kernel blocking".to_string(),
                    "block remains opt-in and must keep validation, approval, rollback, and audit evidence".to_string(),
                ],
            },
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Docker,
                notify: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Docker),
                    "Docker metadata correlation supports accountable notify findings",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Docker),
                    "Docker workload identity can be attached to review findings",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Docker),
                    "Docker workload metadata supports post-event kill containment decisions",
                ),
                seccomp_block: f4_runtime_evidence_required("Docker seccomp block"),
                bpf_lsm_block: f4_runtime_evidence_required("Docker BPF-LSM block"),
                requires_guest_collector: false,
                no_go_claims: vec![
                    "Docker block support must not inherit local-only F3 evidence".to_string(),
                    "runtime-specific live evidence is required before any Docker block enablement".to_string(),
                ],
            },
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Containerd,
                notify: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Containerd),
                    "containerd task metadata supports accountable notify findings",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Containerd),
                    "containerd workload identity can be attached to review findings",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Containerd),
                    "containerd task metadata supports post-event kill containment decisions",
                ),
                seccomp_block: f4_runtime_evidence_required("containerd seccomp block"),
                bpf_lsm_block: f4_runtime_evidence_required("containerd BPF-LSM block"),
                requires_guest_collector: false,
                no_go_claims: vec![
                    "containerd block support must not inherit local-only F3 evidence".to_string(),
                    "runtime-specific live evidence is required before any containerd block enablement".to_string(),
                ],
            },
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Kubernetes,
                notify: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    kubernetes_combined_evidence_ids.clone(),
                    "Pod, namespace, service account, and RuntimeClass metadata support notify findings",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    kubernetes_combined_evidence_ids.clone(),
                    "Kubernetes identity can be attached to review findings",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    kubernetes_combined_evidence_ids,
                    "Kubernetes workload identity supports post-event containment decisions",
                ),
                seccomp_block: f4_runtime_evidence_required("Kubernetes seccomp block"),
                bpf_lsm_block: f4_runtime_evidence_required("Kubernetes BPF-LSM block"),
                requires_guest_collector: false,
                no_go_claims: vec![
                    "Kubernetes block support must not inherit local-only F3 evidence".to_string(),
                    "RuntimeClass-specific live evidence is required before any Kubernetes block enablement".to_string(),
                ],
            },
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Gvisor,
                notify: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    gvisor_combined_evidence_ids.clone(),
                    "runsc, sentry, and gofer metadata can identify the sandbox boundary",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::Supported,
                    gvisor_combined_evidence_ids.clone(),
                    "gVisor metadata can support review findings without claiming guest syscall semantics",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::RequiresRuntimeEvidence,
                    gvisor_combined_evidence_ids.clone(),
                    "kill containment needs runtime-specific evidence for runsc/sentry/gofer behavior",
                ),
                seccomp_block: f4_metadata_only_block(
                    "gVisor seccomp block",
                    gvisor_combined_evidence_ids.clone(),
                ),
                bpf_lsm_block: f4_metadata_only_block(
                    "gVisor BPF-LSM block",
                    gvisor_combined_evidence_ids,
                ),
                requires_guest_collector: false,
                no_go_claims: vec![
                    "host-side evidence must not claim gVisor guest syscall semantics".to_string(),
                    "block support is metadata-only until runtime-specific prevention is proven".to_string(),
                ],
            },
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Kata,
                notify: f4_entry(
                    F4GuardrailSupportStatus::BoundaryOnly,
                    kata_combined_evidence_ids.clone(),
                    "host visibility can identify the Kata VM boundary",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::BoundaryOnly,
                    kata_combined_evidence_ids.clone(),
                    "review findings must be scoped to host-boundary evidence unless a guest collector exists",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::BoundaryOnly,
                    kata_combined_evidence_ids.clone(),
                    "kill containment is limited to boundary-level actions without guest evidence",
                ),
                seccomp_block: f4_boundary_only_block(
                    "Kata seccomp block",
                    kata_combined_evidence_ids.clone(),
                ),
                bpf_lsm_block: f4_boundary_only_block(
                    "Kata BPF-LSM block",
                    kata_combined_evidence_ids,
                ),
                requires_guest_collector: true,
                no_go_claims: vec![
                    "host-side kernel block must not claim Kata guest-semantic prevention".to_string(),
                    "guest collector evidence is required for guest-semantic guardrail claims".to_string(),
                ],
            },
            F4RuntimeGuardrailSupport {
                runtime: F4RuntimeGuardrailTarget::Firecracker,
                notify: f4_entry(
                    F4GuardrailSupportStatus::BoundaryOnly,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Firecracker),
                    "Firecracker support remains a host-boundary research prototype",
                ),
                review: f4_entry(
                    F4GuardrailSupportStatus::BoundaryOnly,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Firecracker),
                    "review findings must be scoped to the VM boundary in the research prototype",
                ),
                kill: f4_entry(
                    F4GuardrailSupportStatus::BoundaryOnly,
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Firecracker),
                    "kill containment is limited to boundary-level research behavior",
                ),
                seccomp_block: f4_boundary_only_block(
                    "Firecracker seccomp block",
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Firecracker),
                ),
                bpf_lsm_block: f4_boundary_only_block(
                    "Firecracker BPF-LSM block",
                    f4_adapter_ids(&adapter_evidence_ids, F4RuntimeGuardrailTarget::Firecracker),
                ),
                requires_guest_collector: true,
                no_go_claims: vec![
                    "Firecracker is not a production runtime lifecycle manager in F4".to_string(),
                    "host-side kernel block must not claim Firecracker guest-semantic prevention".to_string(),
                ],
            },
        ],
    }
}

pub fn evaluate_f4_gvisor_metadata_evidence_gate(
    reports: Vec<F4GvisorMetadataEvidenceReport>,
) -> F4GvisorMetadataEvidenceGateReport {
    let mut failures = Vec::new();
    let mut validated_evidence = Vec::new();

    if reports.is_empty() {
        failures.push(f4_gvisor_failure(
            None,
            "at least one F4 gVisor metadata evidence report is required",
        ));
    }

    for report in &reports {
        let evidence_id = if report.evidence_id.trim().is_empty() {
            None
        } else {
            Some(report.evidence_id.clone())
        };
        let mut report_failures = Vec::new();

        if report.evidence_id.trim().is_empty() {
            report_failures.push(f4_gvisor_failure(
                None,
                "gVisor metadata evidence is missing evidence id",
            ));
        }
        if report.source != F4RuntimeAdapterEvidenceSource::LiveHost {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence requires live-host evidence",
            ));
        }
        if report.runtime_adapter_evidence_id.trim().is_empty() {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence is missing runtime adapter evidence id",
            ));
        }
        if report.session_id.trim().is_empty() {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence is missing session id",
            ));
        }
        if !report
            .runtime_handler
            .as_deref()
            .map(f4_is_gvisor_handler)
            .unwrap_or(false)
        {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence requires a runsc or gvisor runtime handler",
            ));
        }
        if report.host_event_subjects.is_empty() {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence must include host event subjects",
            ));
        }
        if !report.runsc_observed || !report.sentry_observed || !report.gofer_observed {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence must observe runsc, sentry, and gofer",
            ));
        }
        if !f4_subject_observed(&report.host_event_subjects, "runsc")
            || !f4_subject_observed(&report.host_event_subjects, "sentry")
            || !f4_subject_observed(&report.host_event_subjects, "gofer")
        {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor host event subjects must include runsc, sentry, and gofer",
            ));
        }
        if !report.host_semantics_collapsed {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence must prove host semantics are collapsed to the runtime boundary",
            ));
        }
        if report.guest_semantics_claimed {
            report_failures.push(f4_gvisor_failure(
                evidence_id.clone(),
                "gVisor metadata evidence must not claim guest semantics",
            ));
        }

        if report_failures.is_empty() {
            validated_evidence.push(report.clone());
        }
        failures.extend(report_failures);
    }

    F4GvisorMetadataEvidenceGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        reports,
        validated_evidence: if failures.is_empty() {
            validated_evidence
        } else {
            Vec::new()
        },
        failures,
    }
}

pub fn evaluate_f4_kubernetes_agent_sandbox_evidence_gate(
    reports: Vec<F4KubernetesAgentSandboxEvidenceReport>,
) -> F4KubernetesAgentSandboxEvidenceGateReport {
    let mut failures = Vec::new();
    let mut validated_evidence = Vec::new();

    if reports.is_empty() {
        failures.push(f4_kubernetes_agent_sandbox_failure(
            None,
            "at least one F4 Kubernetes Agent Sandbox evidence report is required",
        ));
    }

    for report in &reports {
        let evidence_id = if report.evidence_id.trim().is_empty() {
            None
        } else {
            Some(report.evidence_id.clone())
        };
        let mut report_failures = Vec::new();

        if report.evidence_id.trim().is_empty() {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                None,
                "Kubernetes Agent Sandbox evidence is missing evidence id",
            ));
        }
        if report.source != F4RuntimeAdapterEvidenceSource::LiveHost {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence requires live-host evidence",
            ));
        }
        if report.runtime_adapter_evidence_id.trim().is_empty() {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing runtime adapter evidence id",
            ));
        }
        if report.session_id.trim().is_empty() {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing session id",
            ));
        }
        if report.pod_name.trim().is_empty() {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing pod name",
            ));
        }
        if report.namespace.trim().is_empty() {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing namespace",
            ));
        }
        if !f4_optional_nonempty(&report.service_account) {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing service account",
            ));
        }
        if !f4_optional_nonempty(&report.runtime_class_name) {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing RuntimeClass",
            ));
        }
        if !f4_optional_nonempty(&report.sandbox_name) {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence is missing sandbox name",
            ));
        }
        if !report.host_boundary_visibility {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence must prove host-boundary visibility",
            ));
        }
        if report.guest_semantics_claimed {
            report_failures.push(f4_kubernetes_agent_sandbox_failure(
                evidence_id.clone(),
                "Kubernetes Agent Sandbox evidence must not claim guest semantics",
            ));
        }

        if report_failures.is_empty() {
            validated_evidence.push(report.clone());
        }
        failures.extend(report_failures);
    }

    F4KubernetesAgentSandboxEvidenceGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        reports,
        validated_evidence: if failures.is_empty() {
            validated_evidence
        } else {
            Vec::new()
        },
        failures,
    }
}

pub fn evaluate_f4_kata_boundary_evidence_gate(
    reports: Vec<F4KataBoundaryEvidenceReport>,
) -> F4KataBoundaryEvidenceGateReport {
    let mut failures = Vec::new();
    let mut validated_evidence = Vec::new();

    if reports.is_empty() {
        failures.push(f4_kata_boundary_failure(
            None,
            "at least one F4 Kata boundary evidence report is required",
        ));
    }

    for report in &reports {
        let evidence_id = if report.evidence_id.trim().is_empty() {
            None
        } else {
            Some(report.evidence_id.clone())
        };
        let mut report_failures = Vec::new();

        if report.evidence_id.trim().is_empty() {
            report_failures.push(f4_kata_boundary_failure(
                None,
                "Kata boundary evidence is missing evidence id",
            ));
        }
        if report.source != F4RuntimeAdapterEvidenceSource::LiveHost {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence requires live-host evidence",
            ));
        }
        if report.runtime_adapter_evidence_id.trim().is_empty() {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence is missing runtime adapter evidence id",
            ));
        }
        if report.session_id.trim().is_empty() {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence is missing session id",
            ));
        }
        if !report
            .runtime_handler
            .as_deref()
            .map(f4_is_kata_handler)
            .unwrap_or(false)
        {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence requires a Kata runtime handler",
            ));
        }
        if report.host_event_subjects.is_empty() {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence must include host event subjects",
            ));
        }
        if !report.shim_observed {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence must observe the containerd shim",
            ));
        }
        if !report.vmm_observed {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence must observe the VMM",
            ));
        }
        if !f4_subject_observed(&report.host_event_subjects, "shim")
            || !f4_subject_observed(&report.host_event_subjects, "kata")
        {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata host event subjects must include the Kata shim",
            ));
        }
        if !f4_subject_observed(&report.host_event_subjects, "qemu")
            && !f4_subject_observed(&report.host_event_subjects, "vmm")
        {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata host event subjects must include a VMM",
            ));
        }
        if !report.host_boundary_visibility {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence must prove host-boundary visibility",
            ));
        }
        if !report.guest_collector_required {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence must require a guest collector for guest semantics",
            ));
        }
        if report.guest_semantics_claimed {
            report_failures.push(f4_kata_boundary_failure(
                evidence_id.clone(),
                "Kata boundary evidence must not claim guest semantics",
            ));
        }

        if report_failures.is_empty() {
            validated_evidence.push(report.clone());
        }
        failures.extend(report_failures);
    }

    F4KataBoundaryEvidenceGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        reports,
        validated_evidence: if failures.is_empty() {
            validated_evidence
        } else {
            Vec::new()
        },
        failures,
    }
}

pub fn evaluate_f4_runtime_adapter_evidence_gate(
    reports: Vec<F4RuntimeAdapterEvidenceReport>,
) -> F4RuntimeAdapterEvidenceGateReport {
    let mut failures = Vec::new();
    let mut validated_evidence = Vec::new();

    if reports.is_empty() {
        failures.push(f4_adapter_failure(
            None,
            "at least one F4 runtime adapter evidence report is required",
        ));
    }

    for report in &reports {
        let evidence_id = if report.evidence_id.trim().is_empty() {
            None
        } else {
            Some(report.evidence_id.clone())
        };
        let mut report_failures = Vec::new();

        if report.evidence_id.trim().is_empty() {
            report_failures.push(f4_adapter_failure(
                None,
                "runtime adapter evidence is missing evidence id",
            ));
        }
        if report.source != F4RuntimeAdapterEvidenceSource::LiveHost {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "F4 runtime guardrail support requires live runtime adapter evidence",
            ));
        }
        if report.adapter.trim().is_empty() {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence is missing adapter name",
            ));
        }
        if report.session_id.trim().is_empty() {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence is missing session id",
            ));
        }
        if report.workload_id.trim().is_empty() {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence is missing workload id",
            ));
        }
        if report.cgroup_id == 0 {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence must include a non-zero cgroup id",
            ));
        }
        if !report.metadata_correlation {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence must prove metadata correlation",
            ));
        }
        if !report.cgroup_correlation {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence must prove cgroup correlation",
            ));
        }
        if !report.host_boundary_visibility {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "runtime adapter evidence must prove host-boundary visibility",
            ));
        }
        if report.guest_semantics_claimed
            && matches!(
                report.runtime,
                F4RuntimeGuardrailTarget::Gvisor
                    | F4RuntimeGuardrailTarget::Kata
                    | F4RuntimeGuardrailTarget::Firecracker
            )
        {
            report_failures.push(f4_adapter_failure(
                evidence_id.clone(),
                "strong-isolation runtime adapter evidence must not claim guest semantics",
            ));
        }

        if report_failures.is_empty() {
            validated_evidence.push(report.clone());
        }
        failures.extend(report_failures);
    }

    F4RuntimeAdapterEvidenceGateReport {
        schema_version: 1,
        passed: failures.is_empty(),
        reports,
        validated_evidence: if failures.is_empty() {
            validated_evidence
        } else {
            Vec::new()
        },
        failures,
    }
}

pub fn evaluate_f3_block_enablement_policy(
    validation: F3BlockValidationGateReport,
    requests: Vec<F3BlockEnablementRequest>,
) -> F3BlockEnablementPolicyReport {
    let mut failures = Vec::new();
    let mut approved_enablements = Vec::new();
    let reports_by_evidence: BTreeMap<&str, &F3BlockValidationReport> = validation
        .reports
        .iter()
        .map(|report| (report.evidence_id.as_str(), report))
        .collect();
    let validated_by_evidence: BTreeSet<&str> = validation
        .validated_blocks
        .iter()
        .map(|enablement| enablement.evidence_id.as_str())
        .collect();

    if !validation.passed {
        failures.push(f3_enablement_failure(
            None,
            "block validation gate must pass before enablement can be approved",
        ));
    }
    if requests.is_empty() {
        failures.push(f3_enablement_failure(
            None,
            "at least one block enablement request is required",
        ));
    }

    for request in &requests {
        let mut request_failures = Vec::new();
        let request_id = if request.request_id.trim().is_empty() {
            None
        } else {
            Some(request.request_id.clone())
        };

        if request.request_id.trim().is_empty() {
            request_failures.push(f3_enablement_failure(
                None,
                "block enablement request is missing request id",
            ));
        }
        if request.evidence_id.trim().is_empty() {
            request_failures.push(f3_enablement_failure(
                request_id.clone(),
                "block enablement request is missing evidence id",
            ));
        }
        if !request.operator_approved {
            request_failures.push(f3_enablement_failure(
                request_id.clone(),
                "operator approval is required",
            ));
        }
        if request.default_enabled {
            request_failures.push(f3_enablement_failure(
                request_id.clone(),
                "production-facing block must remain opt-in",
            ));
        }

        match &request.rollback {
            Some(rollback) => {
                if rollback.plan_id.trim().is_empty() {
                    request_failures.push(f3_enablement_failure(
                        request_id.clone(),
                        "rollback plan is missing plan id",
                    ));
                }
                if rollback.disable_command.trim().is_empty() {
                    request_failures.push(f3_enablement_failure(
                        request_id.clone(),
                        "rollback plan is missing disable command",
                    ));
                }
                if rollback.validation_command.trim().is_empty() {
                    request_failures.push(f3_enablement_failure(
                        request_id.clone(),
                        "rollback plan is missing validation command",
                    ));
                }
            }
            None => request_failures.push(f3_enablement_failure(
                request_id.clone(),
                "rollback plan is required",
            )),
        }

        let validated_report = reports_by_evidence.get(request.evidence_id.as_str());
        if !validated_by_evidence.contains(request.evidence_id.as_str()) {
            request_failures.push(f3_enablement_failure(
                request_id.clone(),
                "no matching validated block evidence",
            ));
        }
        if let Some(report) = validated_report {
            if report.backend != request.backend
                || report.runtime != request.runtime
                || report.action != request.action
            {
                request_failures.push(f3_enablement_failure(
                    request_id.clone(),
                    "enablement request does not match validated runtime/action/backend",
                ));
            }
        }

        if request_failures.is_empty() {
            let rollback = request.rollback.as_ref().expect("rollback was validated");
            approved_enablements.push(F3BlockApprovedEnablement {
                request_id: request.request_id.clone(),
                evidence_id: request.evidence_id.clone(),
                backend: request.backend.clone(),
                runtime: request.runtime,
                action: request.action,
                default_enabled: request.default_enabled,
                rollback_plan_id: rollback.plan_id.clone(),
            });
        }

        failures.extend(request_failures);
    }

    F3BlockEnablementPolicyReport {
        schema_version: 1,
        passed: failures.is_empty(),
        approved_enablements: if failures.is_empty() {
            approved_enablements
        } else {
            Vec::new()
        },
        failures,
    }
}

pub fn f3_block_operator_audit_records(
    report: &F3BlockEnablementPolicyReport,
    operation: F3BlockOperatorAuditOperation,
    operator: &str,
    timestamp_unix_ms: u128,
) -> Result<Vec<F3BlockOperatorAuditRecord>, String> {
    let operator = operator.trim();
    if operator.is_empty() {
        return Err("operator is required for F3 block operator audit".to_string());
    }
    if !report.passed {
        return Err(
            "F3 block operator audit requires a passed enablement policy report".to_string(),
        );
    }

    Ok(report
        .approved_enablements
        .iter()
        .map(|enablement| F3BlockOperatorAuditRecord {
            record_type: "f3_block_operator_audit".to_string(),
            operation,
            request_id: enablement.request_id.clone(),
            evidence_id: enablement.evidence_id.clone(),
            backend: enablement.backend.clone(),
            runtime: enablement.runtime,
            action: enablement.action,
            default_enabled: enablement.default_enabled,
            rollback_plan_id: enablement.rollback_plan_id.clone(),
            operator: operator.to_string(),
            timestamp_unix_ms,
        })
        .collect())
}

pub fn evaluate_f3_local_seccomp_execution_gate(
    report: &F3BlockEnablementPolicyReport,
    request: F3LocalSeccompExecutionRequest,
) -> F3LocalSeccompExecutionReport {
    let evidence_id = request.evidence_id.trim().to_string();
    let target_path = request.target_path.trim().to_string();
    let mut failures = Vec::new();

    if !report.passed {
        failures.push(f3_local_seccomp_execution_failure(
            None,
            "local seccomp execution requires a passed enablement policy report",
        ));
    }
    if evidence_id.is_empty() {
        failures.push(f3_local_seccomp_execution_failure(
            None,
            "evidence id is required",
        ));
    }
    if target_path.is_empty() {
        failures.push(f3_local_seccomp_execution_failure(
            evidence_id_opt(&evidence_id),
            "target path is required",
        ));
    }
    if request.backend != "seccomp_block" {
        failures.push(f3_local_seccomp_execution_failure(
            evidence_id_opt(&evidence_id),
            "local seccomp execution only supports backend seccomp_block",
        ));
    }
    if request.runtime != F3BlockValidationRuntime::Local {
        failures.push(f3_local_seccomp_execution_failure(
            evidence_id_opt(&evidence_id),
            "local seccomp execution only supports local runtime",
        ));
    }
    if request.action != F3BlockValidationAction::FileRead {
        failures.push(f3_local_seccomp_execution_failure(
            evidence_id_opt(&evidence_id),
            "local seccomp execution only supports file_read action",
        ));
    }

    let matching_enablement = report.approved_enablements.iter().find(|enablement| {
        enablement.evidence_id == evidence_id
            && enablement.backend == request.backend
            && enablement.runtime == request.runtime
            && enablement.action == request.action
            && !enablement.default_enabled
    });
    if matching_enablement.is_none() {
        failures.push(f3_local_seccomp_execution_failure(
            evidence_id_opt(&evidence_id),
            "no matching approved local seccomp file-read enablement",
        ));
    }

    F3LocalSeccompExecutionReport {
        schema_version: 1,
        passed: failures.is_empty(),
        evidence_id,
        target_path,
        applied_enablement_id: if failures.is_empty() {
            matching_enablement.map(|enablement| enablement.request_id.clone())
        } else {
            None
        },
        enforcement_backend: if failures.is_empty() {
            Some("seccomp_block".to_string())
        } else {
            None
        },
        blocked_errno: None,
        blocked_message: None,
        failures,
    }
}

pub fn evaluate_f3_bpf_lsm_prototype_prerequisites(
    environment: F3BpfLsmPrototypeEnvironment,
) -> F3BpfLsmPrototypePrerequisiteReport {
    let mut failures = Vec::new();

    if !environment.linux {
        failures.push(f3_bpf_lsm_prerequisite_failure(
            "BPF-LSM prototype requires Linux",
        ));
    }
    if !environment.btf_available {
        failures.push(f3_bpf_lsm_prerequisite_failure(
            "readable kernel BTF is required",
        ));
    }
    if !environment.bpf_lsm_configured {
        failures.push(f3_bpf_lsm_prerequisite_failure(
            "kernel must be configured with CONFIG_BPF_LSM",
        ));
    }
    if !environment.bpf_lsm_active {
        failures.push(f3_bpf_lsm_prerequisite_failure(
            "active LSM list must include bpf",
        ));
    }
    if !environment.prototype_object_available {
        failures.push(f3_bpf_lsm_prerequisite_failure(
            "BPF-LSM prototype object is required",
        ));
    }
    if !environment.privileged_for_bpf {
        failures.push(f3_bpf_lsm_prerequisite_failure(
            "CAP_BPF and CAP_PERFMON or CAP_SYS_ADMIN are required",
        ));
    }

    F3BpfLsmPrototypePrerequisiteReport {
        schema_version: 1,
        passed: failures.is_empty(),
        environment,
        failures,
    }
}

pub fn default_service_specs() -> Vec<ServiceSpec> {
    vec![
        ServiceSpec {
            service_name: "containerd.service".to_string(),
            runtime_sockets: vec![PathBuf::from("/run/containerd/containerd.sock")],
        },
        ServiceSpec {
            service_name: "docker.service".to_string(),
            runtime_sockets: vec![PathBuf::from("/run/docker.sock")],
        },
        ServiceSpec {
            service_name: "k3s.service".to_string(),
            runtime_sockets: vec![PathBuf::from("/run/k3s/containerd/containerd.sock")],
        },
    ]
}

pub fn parse_validate_host_args(
    args: impl IntoIterator<Item = String>,
) -> Result<ValidateHostArgs, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut mode = None;
    let mut output_dir = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dry-run" => set_validate_mode(&mut mode, ValidateHostMode::DryRun)?,
            "--apply-runtime-registration" => {
                set_validate_mode(&mut mode, ValidateHostMode::ApplyRuntimeRegistration)?
            }
            "--restore" => set_validate_mode(&mut mode, ValidateHostMode::Restore)?,
            "--output" => {
                index += 1;
                output_dir = args.get(index).map(PathBuf::from);
            }
            unknown => {
                return Err(format!(
                    "unknown argument: {unknown}\n{}",
                    validate_host_usage()
                ))
            }
        }
        index += 1;
    }
    let mode = mode.ok_or_else(|| format!("missing mode\n{}", validate_host_usage()))?;
    let output_dir =
        output_dir.ok_or_else(|| format!("missing --output\n{}", validate_host_usage()))?;
    Ok(ValidateHostArgs { mode, output_dir })
}

fn set_validate_mode(
    mode: &mut Option<ValidateHostMode>,
    next_mode: ValidateHostMode,
) -> Result<(), String> {
    if mode.is_some() {
        return Err(format!(
            "expected exactly one mode\n{}",
            validate_host_usage()
        ));
    }
    *mode = Some(next_mode);
    Ok(())
}

pub fn render_docker_runtime_config(input: &str) -> Result<String, String> {
    let mut document = if input.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(input)
            .map_err(|error| format!("failed to parse Docker daemon JSON: {error}"))?
    };
    let root = document
        .as_object_mut()
        .ok_or_else(|| "Docker daemon config must be a JSON object".to_string())?;
    let runtimes = root
        .entry("runtimes")
        .or_insert_with(|| serde_json::json!({}));
    let runtimes = runtimes
        .as_object_mut()
        .ok_or_else(|| "Docker daemon runtimes must be a JSON object".to_string())?;
    runtimes.insert(
        "runsc".to_string(),
        serde_json::json!({
            "path": "/usr/local/bin/runsc"
        }),
    );
    serde_json::to_string_pretty(&document)
        .map(|json| format!("{json}\n"))
        .map_err(|error| format!("failed to serialize Docker daemon JSON: {error}"))
}

pub fn render_containerd_runtime_config(input: &str) -> Result<String, String> {
    let mut document = parse_containerd_config(input)?;
    document["version"] = toml_value(3);
    upsert_containerd_runtime(&mut document, "runc", "io.containerd.runc.v2");
    document["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]["runtimes"]["runc"]
        ["options"]["SystemdCgroup"] = toml_value(false);
    upsert_containerd_runtime(&mut document, "runsc", "io.containerd.runsc.v1");
    upsert_containerd_runtime(&mut document, "kata", "io.containerd.kata.v2");
    Ok(ensure_trailing_newline(document.to_string()))
}

pub fn render_k3s_runtime_dropin_config() -> String {
    let mut document = DocumentMut::new();
    upsert_containerd_runtime(&mut document, "runsc", "io.containerd.runsc.v1");
    upsert_containerd_runtime(&mut document, "kata", "io.containerd.kata.v2");
    ensure_trailing_newline(document.to_string())
}

pub fn plan_runtime_registration(
    request: RuntimeRegistrationPlanRequest,
) -> Result<RuntimeRegistrationPlan, String> {
    require_absolute_path(&request.docker_daemon_path)?;
    require_absolute_path(&request.containerd_config_path)?;
    require_absolute_path(&request.k3s_runtime_dropin_path)?;

    Ok(RuntimeRegistrationPlan {
        file_writes: vec![
            RuntimeConfigFileWrite {
                id: "docker_daemon".to_string(),
                path: request.docker_daemon_path,
                contents: render_docker_runtime_config(&request.docker_daemon_json)?,
                mode: 0o644,
            },
            RuntimeConfigFileWrite {
                id: "containerd_config".to_string(),
                path: request.containerd_config_path,
                contents: render_containerd_runtime_config(
                    request.containerd_config_toml.as_deref().unwrap_or(""),
                )?,
                mode: 0o644,
            },
            RuntimeConfigFileWrite {
                id: "k3s_runtime_dropin".to_string(),
                path: request.k3s_runtime_dropin_path,
                contents: render_k3s_runtime_dropin_config(),
                mode: 0o644,
            },
        ],
    })
}

pub fn apply_runtime_registration_plan(
    plan: &RuntimeRegistrationPlan,
) -> Result<RuntimeRegistrationReport, String> {
    let mut paths = BTreeSet::new();
    for write in &plan.file_writes {
        require_absolute_path(&write.path)?;
        if !paths.insert(write.path.clone()) {
            return Err(format!(
                "runtime registration contains duplicate path: {}",
                write.path.display()
            ));
        }
    }

    let mut files_written = 0;
    for write in &plan.file_writes {
        write_config_file(&write.path, write.contents.as_bytes(), write.mode)?;
        files_written += 1;
    }
    Ok(RuntimeRegistrationReport { files_written })
}

pub fn collect_and_apply_host_runtime_registration(
    output_dir: PathBuf,
) -> Result<HostRuntimeRegistrationReport, String> {
    let validation = collect_host_validation_report(output_dir.clone())?;
    let docker_daemon_path = PathBuf::from("/etc/docker/daemon.json");
    let containerd_config_path = PathBuf::from("/etc/containerd/config.toml");
    let k3s_runtime_dropin_path = PathBuf::from(
        "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml",
    );
    let plan = plan_runtime_registration(RuntimeRegistrationPlanRequest {
        docker_daemon_path: docker_daemon_path.clone(),
        docker_daemon_json: read_optional_string(&docker_daemon_path)?
            .unwrap_or_else(|| "{}".to_string()),
        containerd_config_path: containerd_config_path.clone(),
        containerd_config_toml: read_optional_string(&containerd_config_path)?,
        k3s_runtime_dropin_path,
    })?;
    write_json(&output_dir.join("runtime-registration-plan.json"), &plan)?;
    let registration = apply_runtime_registration_plan(&plan)?;
    write_json(
        &output_dir.join("runtime-registration-report.json"),
        &registration,
    )?;
    Ok(HostRuntimeRegistrationReport {
        validation,
        registration,
    })
}

pub fn restore_validation_from_output<C: ServiceController>(
    output_dir: &Path,
    service_controller: &mut C,
) -> Result<RestoreExecutionReport, String> {
    let manifest = read_json::<BackupManifest>(&output_dir.join("backup-manifest.json"))?;
    let services = read_json::<Vec<ServiceState>>(&output_dir.join("service-state.json"))?;
    let plan = read_json::<RestorePlan>(&output_dir.join("restore-plan.json"))?;
    let report = execute_restore_plan(
        RestoreExecutionRequest {
            backup_root: output_dir.to_path_buf(),
            manifest,
            services,
            plan,
        },
        service_controller,
    )?;
    write_json(&output_dir.join("restore-execution-report.json"), &report)?;
    Ok(report)
}

pub fn validate_host_usage() -> &'static str {
    "usage: apolysis-validate-host (--dry-run | --apply-runtime-registration | --restore) --output <dir>"
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub kind: BackupEntryKind,
    pub backup_relative_path: Option<PathBuf>,
    pub sha256_hex: Option<String>,
    pub symlink_target: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupEntryKind {
    RegularFile,
    Symlink,
    Missing,
}

pub fn capture_backup_manifest(request: BackupCaptureRequest) -> Result<BackupManifest, String> {
    std::fs::create_dir_all(request.output_dir.join("files"))
        .map_err(|error| format!("failed to create backup output directory: {error}"))?;
    let mut entries = Vec::with_capacity(request.sources.len());

    for source in request.sources {
        entries.push(capture_source(&request.output_dir, source)?);
    }

    Ok(BackupManifest {
        schema_version: 1,
        entries,
    })
}

pub fn capture_service_state(request: ServiceCaptureRequest<'_>) -> Result<ServiceState, String> {
    let load_state = required_systemctl_value(request.systemctl_show, "LoadState")?;
    let active_state = required_systemctl_value(request.systemctl_show, "ActiveState")?;
    let unit_file_state = required_systemctl_value(request.systemctl_show, "UnitFileState")?;
    let fragment_path = optional_path(systemctl_value(request.systemctl_show, "FragmentPath"));
    let drop_in_paths = systemctl_value(request.systemctl_show, "DropInPaths")
        .map(split_paths)
        .unwrap_or_default();
    let runtime_sockets = request
        .runtime_sockets
        .into_iter()
        .map(|path| RuntimeSocketState {
            present: std::fs::symlink_metadata(&path).is_ok(),
            path,
        })
        .collect();

    Ok(ServiceState {
        service_name: request.service_name,
        load_state,
        active_state,
        unit_file_state,
        fragment_path,
        drop_in_paths,
        runtime_sockets,
    })
}

pub fn capture_kubernetes_restore_context(
    request: KubernetesCaptureRequest<'_>,
) -> Result<KubernetesRestoreContext, String> {
    let runtimeclasses = parse_json(request.runtimeclasses_json, "runtimeclasses")?;
    let nodes = parse_json(request.nodes_json, "nodes")?;
    let pods = parse_json(request.pods_json, "pods")?;

    let mut runtime_classes = items(&runtimeclasses)
        .iter()
        .filter_map(runtime_class_snapshot)
        .collect::<Vec<_>>();
    runtime_classes.sort_by(|left, right| left.name.cmp(&right.name));

    let mut node_snapshots = items(&nodes)
        .iter()
        .filter_map(node_snapshot)
        .collect::<Vec<_>>();
    node_snapshots.sort_by(|left, right| left.name.cmp(&right.name));

    let mut workloads = items(&pods)
        .iter()
        .filter(|pod| !has_label(pod, request.validation_label_key))
        .filter_map(workload_snapshot)
        .collect::<Vec<_>>();
    workloads.sort_by(|left, right| {
        left.namespace
            .cmp(&right.namespace)
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(KubernetesRestoreContext {
        runtime_classes,
        nodes: node_snapshots,
        workloads,
    })
}

pub fn plan_restore(request: RestorePlanRequest) -> Result<RestorePlan, String> {
    let mut actions = Vec::new();
    let mut known_entry_ids = BTreeSet::new();

    for entry in &request.manifest.entries {
        known_entry_ids.insert(entry.id.clone());
        match entry.kind {
            BackupEntryKind::RegularFile => {
                let backup_relative_path =
                    entry.backup_relative_path.as_ref().ok_or_else(|| {
                        format!(
                            "regular file backup entry {} is missing backup path",
                            entry.id
                        )
                    })?;
                verify_backup_copy(&request.backup_root, entry, backup_relative_path)?;
                actions.push(RestoreAction::RestoreRegularFile {
                    id: entry.id.clone(),
                    from_backup: backup_relative_path.clone(),
                    to_path: entry.original_path.clone(),
                    uid: entry.uid,
                    gid: entry.gid,
                    mode: entry.mode,
                });
            }
            BackupEntryKind::Symlink => {
                let target = entry.symlink_target.clone().ok_or_else(|| {
                    format!("symlink backup entry {} is missing target", entry.id)
                })?;
                actions.push(RestoreAction::RestoreSymlink {
                    id: entry.id.clone(),
                    target,
                    link_path: entry.original_path.clone(),
                    uid: entry.uid,
                    gid: entry.gid,
                });
            }
            BackupEntryKind::Missing => {
                actions.push(RestoreAction::EnsureMissing {
                    id: entry.id.clone(),
                    path: entry.original_path.clone(),
                });
            }
        }
    }

    let mut validation_owned_paths = request.validation_owned_paths;
    validation_owned_paths.sort();
    validation_owned_paths.dedup();
    actions.extend(
        validation_owned_paths
            .into_iter()
            .map(|path| RestoreAction::RemoveValidationPath { path }),
    );

    let services = request
        .services
        .into_iter()
        .map(|service| (service.service_name.clone(), service))
        .collect::<BTreeMap<_, _>>();
    let mut managed_inputs = request.managed_service_inputs;
    managed_inputs.sort_by(|left, right| left.service_name.cmp(&right.service_name));
    for managed in managed_inputs {
        for entry_id in &managed.entry_ids {
            if !known_entry_ids.contains(entry_id) {
                return Err(format!(
                    "managed service {} references unknown backup entry {entry_id}",
                    managed.service_name
                ));
            }
        }
        let service = services.get(&managed.service_name).ok_or_else(|| {
            format!(
                "managed service {} is missing captured service state",
                managed.service_name
            )
        })?;
        actions.push(RestoreAction::RestoreServiceState {
            service_name: service.service_name.clone(),
            active_state: service.active_state.clone(),
            unit_file_state: service.unit_file_state.clone(),
        });
    }

    Ok(RestorePlan {
        schema_version: 1,
        actions,
    })
}

pub fn execute_restore_plan<C: ServiceController>(
    request: RestoreExecutionRequest,
    service_controller: &mut C,
) -> Result<RestoreExecutionReport, String> {
    verify_restore_execution_inputs(&request)?;
    let mut actions_applied = 0;

    for action in request.plan.actions {
        match action {
            RestoreAction::RestoreRegularFile {
                from_backup,
                to_path,
                uid,
                gid,
                mode,
                ..
            } => {
                restore_regular_file(&request.backup_root, &from_backup, &to_path, uid, gid, mode)?;
            }
            RestoreAction::RestoreSymlink {
                target,
                link_path,
                uid,
                gid,
                ..
            } => restore_symlink(&target, &link_path, uid, gid)?,
            RestoreAction::EnsureMissing { path, .. }
            | RestoreAction::RemoveValidationPath { path } => remove_path_if_present(&path)?,
            RestoreAction::RestoreServiceState {
                service_name,
                active_state,
                unit_file_state,
            } => {
                service_controller.restore_unit_file_state(&service_name, &unit_file_state)?;
                service_controller.restore_active_state(&service_name, &active_state)?;
            }
        }
        actions_applied += 1;
    }

    Ok(RestoreExecutionReport { actions_applied })
}

pub fn build_validation_report(
    request: ValidationReportRequest<'_>,
) -> Result<HostValidationReport, String> {
    std::fs::create_dir_all(&request.output_dir)
        .map_err(|error| format!("failed to create validation output directory: {error}"))?;
    let backup_manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: request.output_dir.clone(),
        sources: request.backup_sources,
    })?;
    let services = request
        .service_requests
        .into_iter()
        .map(capture_service_state)
        .collect::<Result<Vec<_>, _>>()?;
    let kubernetes = capture_kubernetes_restore_context(request.kubernetes)?;
    let restore_plan = plan_restore(RestorePlanRequest {
        backup_root: request.output_dir.clone(),
        manifest: backup_manifest.clone(),
        services: services.clone(),
        managed_service_inputs: request.managed_service_inputs,
        validation_owned_paths: request.validation_owned_paths,
    })?;
    let report = HostValidationReport {
        schema_version: 1,
        backup_manifest,
        services,
        kubernetes,
        restore_plan,
    };
    write_json(
        &request.output_dir.join("backup-manifest.json"),
        &report.backup_manifest,
    )?;
    write_json(
        &request.output_dir.join("service-state.json"),
        &report.services,
    )?;
    write_json(
        &request.output_dir.join("kubernetes-context.json"),
        &report.kubernetes,
    )?;
    write_json(
        &request.output_dir.join("restore-plan.json"),
        &report.restore_plan,
    )?;
    Ok(report)
}

pub fn collect_host_validation_report(output_dir: PathBuf) -> Result<HostValidationReport, String> {
    let service_outputs = default_service_specs()
        .into_iter()
        .map(|spec| {
            let output = systemctl_show(&spec.service_name)?;
            Ok((spec, output))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let service_requests = service_outputs
        .iter()
        .map(|(spec, output)| ServiceCaptureRequest {
            service_name: spec.service_name.clone(),
            systemctl_show: output.as_str(),
            runtime_sockets: spec.runtime_sockets.clone(),
        })
        .collect::<Vec<_>>();
    let runtimeclasses_json = kubectl_json(&["get", "runtimeclasses", "-o", "json"])?;
    let nodes_json = kubectl_json(&["get", "nodes", "-o", "json"])?;
    let pods_json = kubectl_json(&["get", "pods", "-A", "-o", "json"])?;

    build_validation_report(ValidationReportRequest {
        output_dir,
        backup_sources: default_host_backup_sources(),
        service_requests,
        kubernetes: KubernetesCaptureRequest {
            runtimeclasses_json: &runtimeclasses_json,
            nodes_json: &nodes_json,
            pods_json: &pods_json,
            validation_label_key: "apolysis.dev/validation",
        },
        managed_service_inputs: default_managed_service_inputs(),
        validation_owned_paths: default_validation_owned_paths(),
    })
}

fn capture_source(
    output_dir: &std::path::Path,
    source: BackupSource,
) -> Result<BackupEntry, String> {
    let metadata = match std::fs::symlink_metadata(&source.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BackupEntry {
                id: source.id,
                original_path: source.path,
                kind: BackupEntryKind::Missing,
                backup_relative_path: None,
                sha256_hex: None,
                symlink_target: None,
                uid: None,
                gid: None,
                mode: None,
            })
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect backup source {}: {error}",
                source.path.display()
            ))
        }
    };

    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(&source.path).map_err(|error| {
            format!("failed to read symlink {}: {error}", source.path.display())
        })?;
        return Ok(BackupEntry {
            id: source.id,
            original_path: source.path,
            kind: BackupEntryKind::Symlink,
            backup_relative_path: None,
            sha256_hex: None,
            symlink_target: Some(target),
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            mode: Some(metadata.permissions().mode() & 0o7777),
        });
    }

    if !metadata.file_type().is_file() {
        return Err(format!(
            "backup source is not a regular file or symlink: {}",
            source.path.display()
        ));
    }

    let backup_relative_path = PathBuf::from("files").join(safe_backup_name(&source.id));
    let backup_path = output_dir.join(&backup_relative_path);
    let bytes = std::fs::read(&source.path).map_err(|error| {
        format!(
            "failed to read backup source {}: {error}",
            source.path.display()
        )
    })?;
    std::fs::write(&backup_path, &bytes).map_err(|error| {
        format!(
            "failed to write backup copy {}: {error}",
            backup_path.display()
        )
    })?;

    Ok(BackupEntry {
        id: source.id,
        original_path: source.path,
        kind: BackupEntryKind::RegularFile,
        backup_relative_path: Some(backup_relative_path),
        sha256_hex: Some(sha256_hex(&bytes)),
        symlink_target: None,
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        mode: Some(metadata.permissions().mode() & 0o7777),
    })
}

fn safe_backup_name(id: &str) -> String {
    id.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn required_systemctl_value(input: &str, key: &str) -> Result<String, String> {
    systemctl_value(input, key)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("systemd service state is missing {key}"))
}

fn systemctl_value<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    input
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
}

fn optional_path(value: Option<&str>) -> Option<PathBuf> {
    value.filter(|path| !path.is_empty()).map(PathBuf::from)
}

fn split_paths(value: &str) -> Vec<PathBuf> {
    value
        .split_whitespace()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_containerd_config(input: &str) -> Result<DocumentMut, String> {
    if input.trim().is_empty() {
        Ok(DocumentMut::new())
    } else {
        input
            .parse::<DocumentMut>()
            .map_err(|error| format!("failed to parse containerd TOML: {error}"))
    }
}

fn upsert_containerd_runtime(document: &mut DocumentMut, runtime_name: &str, runtime_type: &str) {
    ensure_toml_table(&mut document["plugins"]);
    ensure_toml_table(&mut document["plugins"]["io.containerd.cri.v1.runtime"]);
    ensure_toml_table(&mut document["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]);
    ensure_toml_table(
        &mut document["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]["runtimes"],
    );
    let runtime = &mut document["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]
        ["runtimes"][runtime_name];
    ensure_toml_table(runtime);
    runtime["runtime_type"] = toml_value(runtime_type);
}

fn ensure_toml_table(item: &mut Item) {
    if !item.is_table() {
        *item = Item::Table(Table::new());
    }
}

fn ensure_trailing_newline(mut output: String) -> String {
    if !output.ends_with('\n') {
        output.push('\n');
    }
    output
}

fn parse_json(input: &str, name: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(input).map_err(|error| format!("failed to parse {name} JSON: {error}"))
}

fn verify_backup_copy(
    backup_root: &std::path::Path,
    entry: &BackupEntry,
    backup_relative_path: &std::path::Path,
) -> Result<(), String> {
    let path = backup_root.join(backup_relative_path);
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("backup copy is missing for {}: {error}", entry.id))?;
    let checksum = sha256_hex(&bytes);
    if entry.sha256_hex.as_deref() != Some(checksum.as_str()) {
        return Err(format!("backup checksum mismatch for {}", entry.id));
    }
    Ok(())
}

fn verify_restore_execution_inputs(request: &RestoreExecutionRequest) -> Result<(), String> {
    if request.plan.schema_version != 1 {
        return Err(format!(
            "unsupported restore plan schema version {}",
            request.plan.schema_version
        ));
    }
    if request.manifest.schema_version != 1 {
        return Err(format!(
            "unsupported backup manifest schema version {}",
            request.manifest.schema_version
        ));
    }
    let entries = request
        .manifest
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let services = request
        .services
        .iter()
        .map(|service| (service.service_name.as_str(), service))
        .collect::<BTreeMap<_, _>>();

    for action in &request.plan.actions {
        match action {
            RestoreAction::RestoreRegularFile {
                id,
                from_backup,
                to_path,
                ..
            } => {
                require_absolute_path(to_path)?;
                let entry = entries.get(id.as_str()).ok_or_else(|| {
                    format!("restore action references unknown backup entry {id}")
                })?;
                if entry.kind != BackupEntryKind::RegularFile {
                    return Err(format!("restore action {id} does not match manifest kind"));
                }
                if entry.original_path != *to_path {
                    return Err(format!(
                        "restore action {id} target does not match manifest"
                    ));
                }
                let manifest_backup = entry.backup_relative_path.as_ref().ok_or_else(|| {
                    format!("regular file backup entry {id} is missing backup path")
                })?;
                if manifest_backup != from_backup {
                    return Err(format!(
                        "restore action {id} backup path does not match manifest"
                    ));
                }
                verify_backup_copy(&request.backup_root, entry, from_backup)?;
            }
            RestoreAction::RestoreSymlink {
                id,
                target,
                link_path,
                ..
            } => {
                require_absolute_path(link_path)?;
                let entry = entries.get(id.as_str()).ok_or_else(|| {
                    format!("restore action references unknown backup entry {id}")
                })?;
                if entry.kind != BackupEntryKind::Symlink {
                    return Err(format!("restore action {id} does not match manifest kind"));
                }
                if entry.original_path != *link_path {
                    return Err(format!(
                        "restore action {id} link path does not match manifest"
                    ));
                }
                if entry.symlink_target.as_ref() != Some(target) {
                    return Err(format!(
                        "restore action {id} target does not match manifest"
                    ));
                }
            }
            RestoreAction::EnsureMissing { id, path } => {
                require_absolute_path(path)?;
                let entry = entries.get(id.as_str()).ok_or_else(|| {
                    format!("restore action references unknown backup entry {id}")
                })?;
                if entry.kind != BackupEntryKind::Missing {
                    return Err(format!("restore action {id} does not match manifest kind"));
                }
                if entry.original_path != *path {
                    return Err(format!("restore action {id} path does not match manifest"));
                }
            }
            RestoreAction::RemoveValidationPath { path } => require_absolute_path(path)?,
            RestoreAction::RestoreServiceState {
                service_name,
                active_state,
                unit_file_state,
            } => {
                let service = services.get(service_name.as_str()).ok_or_else(|| {
                    format!("restore action references uncaptured service {service_name}")
                })?;
                if service.active_state != *active_state {
                    return Err(format!(
                        "restore action for {service_name} active state does not match capture"
                    ));
                }
                if service.unit_file_state != *unit_file_state {
                    return Err(format!(
                        "restore action for {service_name} unit file state does not match capture"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn restore_regular_file(
    backup_root: &Path,
    from_backup: &Path,
    to_path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
) -> Result<(), String> {
    require_absolute_path(to_path)?;
    let parent = to_path
        .parent()
        .ok_or_else(|| format!("restore target has no parent: {}", to_path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    if let Ok(metadata) = std::fs::symlink_metadata(to_path) {
        if metadata.file_type().is_dir() {
            return Err(format!(
                "refusing to replace directory with restored file: {}",
                to_path.display()
            ));
        }
    }

    let temp_path = restore_temp_path(parent, to_path)?;
    let backup_path = backup_root.join(from_backup);
    std::fs::copy(&backup_path, &temp_path).map_err(|error| {
        format!(
            "failed to copy backup {} to {}: {error}",
            backup_path.display(),
            temp_path.display()
        )
    })?;
    if let Some(mode) = mode {
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("failed to set mode on {}: {error}", temp_path.display()))?;
    }
    std::fs::rename(&temp_path, to_path).map_err(|error| {
        let _ = std::fs::remove_file(&temp_path);
        format!(
            "failed to move restored file {} to {}: {error}",
            temp_path.display(),
            to_path.display()
        )
    })?;
    if let Some(mode) = mode {
        std::fs::set_permissions(to_path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| format!("failed to set mode on {}: {error}", to_path.display()))?;
    }
    set_owner_if_needed(to_path, uid, gid, true)
}

fn write_config_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    require_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("config target has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_dir() {
            return Err(format!(
                "refusing to replace directory with config file: {}",
                path.display()
            ));
        }
    }

    let temp_path = restore_temp_path(parent, path)?;
    std::fs::write(&temp_path, contents)
        .map_err(|error| format!("failed to write {}: {error}", temp_path.display()))?;
    std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("failed to set mode on {}: {error}", temp_path.display()))?;
    std::fs::rename(&temp_path, path).map_err(|error| {
        let _ = std::fs::remove_file(&temp_path);
        format!(
            "failed to move config file {} to {}: {error}",
            temp_path.display(),
            path.display()
        )
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("failed to set mode on {}: {error}", path.display()))
}

fn restore_symlink(
    target: &Path,
    link_path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    require_absolute_path(link_path)?;
    let parent = link_path
        .parent()
        .ok_or_else(|| format!("restore link has no parent: {}", link_path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    remove_path_if_present(link_path)?;
    std::os::unix::fs::symlink(target, link_path).map_err(|error| {
        format!(
            "failed to restore symlink {} -> {}: {error}",
            link_path.display(),
            target.display()
        )
    })?;
    set_owner_if_needed(link_path, uid, gid, false)
}

fn remove_path_if_present(path: &Path) -> Result<(), String> {
    require_absolute_path(path)?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("failed to inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_dir() {
        std::fs::remove_dir_all(path)
            .map_err(|error| format!("failed to remove directory {}: {error}", path.display()))
    } else {
        std::fs::remove_file(path)
            .map_err(|error| format!("failed to remove file {}: {error}", path.display()))
    }
}

fn require_absolute_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(format!(
            "restore path must be an absolute non-root path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn restore_temp_path(parent: &Path, to_path: &Path) -> Result<PathBuf, String> {
    let file_name = to_path
        .file_name()
        .ok_or_else(|| format!("restore target has no file name: {}", to_path.display()))?;
    Ok(parent.join(format!(
        ".{}.apolysis-restore.{}",
        file_name.to_string_lossy(),
        std::process::id()
    )))
}

fn set_owner_if_needed(
    path: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
    follow_symlink: bool,
) -> Result<(), String> {
    let Some(uid) = uid else {
        return Ok(());
    };
    let Some(gid) = gid else {
        return Ok(());
    };
    let metadata = if follow_symlink {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    }
    .map_err(|error| {
        format!(
            "failed to inspect restored owner {}: {error}",
            path.display()
        )
    })?;
    if metadata.uid() == uid && metadata.gid() == gid {
        return Ok(());
    }
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("restore path contains a NUL byte: {}", path.display()))?;
    let result = if follow_symlink {
        unsafe { libc::chown(path_c.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) }
    } else {
        unsafe { libc::lchown(path_c.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to restore owner on {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    }
}

fn write_json(path: &std::path::Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))?;
    std::fs::write(path, bytes)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

fn read_optional_string(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("failed to read {}: {error}", path.display())),
    }
}

fn default_managed_service_inputs() -> Vec<ManagedServiceInputs> {
    vec![
        ManagedServiceInputs {
            service_name: "containerd.service".to_string(),
            entry_ids: vec!["containerd_config".to_string()],
        },
        ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec![
                "docker_daemon".to_string(),
                "docker_http_proxy_dropin".to_string(),
            ],
        },
        ManagedServiceInputs {
            service_name: "k3s.service".to_string(),
            entry_ids: vec![
                "k3s_generated_containerd_config".to_string(),
                "k3s_containerd_v3_template".to_string(),
                "k3s_runtime_dropin".to_string(),
                "k3s_http_proxy_dropin".to_string(),
            ],
        },
    ]
}

fn default_validation_owned_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/run/apolysis-validation"),
        PathBuf::from("/var/lib/apolysis-validation"),
    ]
}

fn systemctl_show(service_name: &str) -> Result<String, String> {
    command_output(
        "systemctl",
        &[
            "show",
            service_name,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            "--property=FragmentPath",
            "--property=DropInPaths",
            "--no-page",
        ],
    )
}

fn systemctl_action(action: &str, service_name: &str) -> Result<(), String> {
    command_output("systemctl", &[action, service_name]).map(|_| ())
}

fn kubectl_json(args: &[&str]) -> Result<String, String> {
    command_output("k3s", &[&["kubectl"], args].concat())
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed with status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("{program} output is not UTF-8: {error}"))
}

fn performance_failure(
    load: PerformanceLoad,
    metric: &str,
    message: &str,
    actual: impl ToString,
    budget: impl ToString,
) -> PerformanceGateFailure {
    PerformanceGateFailure {
        load,
        metric: metric.to_string(),
        message: message.to_string(),
        actual: actual.to_string(),
        budget: budget.to_string(),
    }
}

fn load_name(load: PerformanceLoad) -> &'static str {
    match load {
        PerformanceLoad::Idle => "idle",
        PerformanceLoad::Steady10000 => "steady_10000",
        PerformanceLoad::Burst50000 => "burst_50000",
    }
}

fn visibility_failure(
    target: Option<VisibilityTarget>,
    message: impl Into<String>,
) -> VisibilityReportGateFailure {
    VisibilityReportGateFailure {
        target,
        message: message.into(),
    }
}

fn f3_block_failure(
    evidence_id: Option<String>,
    message: impl Into<String>,
) -> F3BlockValidationGateFailure {
    F3BlockValidationGateFailure {
        evidence_id,
        message: message.into(),
    }
}

fn f3_enablement_failure(
    request_id: Option<String>,
    message: impl Into<String>,
) -> F3BlockEnablementFailure {
    F3BlockEnablementFailure {
        request_id,
        message: message.into(),
    }
}

fn required_f4_live_runtime_artifacts() -> [&'static str; 6] {
    [
        "backup-manifest.json",
        "service-state.json",
        "kubernetes-context.json",
        "restore-plan.json",
        "runtime-registration-report.json",
        "restore-execution-report.json",
    ]
}

fn f4_live_runtime_evidence_failure(
    message: impl Into<String>,
) -> F4LiveRuntimeEvidenceBundleFailure {
    F4LiveRuntimeEvidenceBundleFailure {
        message: message.into(),
    }
}

fn f4_validated_local_block_evidence(
    reports: &[F3BlockValidationReport],
    backend: &str,
) -> Vec<String> {
    reports
        .iter()
        .filter(|report| {
            report.source == F3BlockValidationSource::LiveHost
                && report.runtime == F3BlockValidationRuntime::Local
                && report.action == F3BlockValidationAction::FileRead
                && report.backend == backend
                && report.preoperation_prevention
                && report.decision_latency_ms.is_some()
                && report.side_effect_race_window_ms == Some(0)
                && match backend {
                    "seccomp_block" => report.seccomp_available,
                    "bpf_lsm_block" => report.host_bpf_lsm_available,
                    _ => false,
                }
        })
        .map(|report| report.evidence_id.clone())
        .collect()
}

fn f4_entry(
    status: F4GuardrailSupportStatus,
    evidence_ids: Vec<String>,
    note: impl Into<String>,
) -> F4GuardrailSupportEntry {
    F4GuardrailSupportEntry {
        status,
        evidence_ids,
        note: note.into(),
    }
}

fn f4_local_block_entry(
    evidence_ids: Vec<String>,
    backend_label: &'static str,
) -> F4GuardrailSupportEntry {
    if evidence_ids.is_empty() {
        f4_entry(
            F4GuardrailSupportStatus::RequiresRuntimeEvidence,
            evidence_ids,
            format!("{backend_label} requires live local F3 validation evidence"),
        )
    } else {
        f4_entry(
            F4GuardrailSupportStatus::PrototypeValidated,
            evidence_ids,
            format!("{backend_label} has narrow live local file-read prototype evidence only"),
        )
    }
}

fn f4_runtime_evidence_required(capability: &'static str) -> F4GuardrailSupportEntry {
    f4_entry(
        F4GuardrailSupportStatus::RequiresRuntimeEvidence,
        Vec::new(),
        format!("{capability} requires runtime-specific live prevention evidence"),
    )
}

fn f4_metadata_only_block(
    capability: &'static str,
    evidence_ids: Vec<String>,
) -> F4GuardrailSupportEntry {
    f4_entry(
        F4GuardrailSupportStatus::MetadataOnly,
        evidence_ids,
        format!(
            "{capability} is metadata-only until guest/runtime prevention semantics are proven"
        ),
    )
}

fn f4_boundary_only_block(
    capability: &'static str,
    evidence_ids: Vec<String>,
) -> F4GuardrailSupportEntry {
    f4_entry(
        F4GuardrailSupportStatus::BoundaryOnly,
        evidence_ids,
        format!("{capability} is boundary-only without guest collector evidence"),
    )
}

fn f4_adapter_evidence_ids_by_runtime(
    gate: &F4RuntimeAdapterEvidenceGateReport,
) -> BTreeMap<F4RuntimeGuardrailTarget, Vec<String>> {
    let mut by_runtime: BTreeMap<F4RuntimeGuardrailTarget, Vec<String>> = BTreeMap::new();
    if !gate.passed {
        return by_runtime;
    }
    for report in &gate.validated_evidence {
        by_runtime
            .entry(report.runtime)
            .or_default()
            .push(report.evidence_id.clone());
    }
    by_runtime
}

fn f4_adapter_ids(
    by_runtime: &BTreeMap<F4RuntimeGuardrailTarget, Vec<String>>,
    runtime: F4RuntimeGuardrailTarget,
) -> Vec<String> {
    by_runtime.get(&runtime).cloned().unwrap_or_default()
}

fn f4_adapter_failure(
    evidence_id: Option<String>,
    message: impl Into<String>,
) -> F4RuntimeAdapterEvidenceGateFailure {
    F4RuntimeAdapterEvidenceGateFailure {
        evidence_id,
        message: message.into(),
    }
}

fn f4_gvisor_metadata_evidence_ids(gate: &F4GvisorMetadataEvidenceGateReport) -> Vec<String> {
    if !gate.passed {
        return Vec::new();
    }
    gate.validated_evidence
        .iter()
        .map(|report| report.evidence_id.clone())
        .collect()
}

fn f4_kubernetes_agent_sandbox_evidence_ids(
    gate: &F4KubernetesAgentSandboxEvidenceGateReport,
) -> Vec<String> {
    if !gate.passed {
        return Vec::new();
    }
    gate.validated_evidence
        .iter()
        .map(|report| report.evidence_id.clone())
        .collect()
}

fn f4_kata_boundary_evidence_ids(gate: &F4KataBoundaryEvidenceGateReport) -> Vec<String> {
    if !gate.passed {
        return Vec::new();
    }
    gate.validated_evidence
        .iter()
        .map(|report| report.evidence_id.clone())
        .collect()
}

fn f5_validate_release_manifest(
    evidence: &F5ReleasePromotionPolicyEvidence,
    failures: &mut Vec<F5ReleasePromotionPolicyFailure>,
) {
    let manifest = &evidence.release_manifest;
    f5_expect_json_string(
        failures,
        manifest,
        "/schema",
        "apolysis.dev/f5-release-manifest/v1",
        "release manifest schema must be F5 release manifest v1",
    );
    f5_expect_json_string(
        failures,
        manifest,
        "/phase",
        "F5.6",
        "release manifest phase must be F5.6",
    );
    let key_mode = f5_json_str(manifest, "/signing/keyMode").unwrap_or_default();
    if !f5_is_production_signing_mode(key_mode) {
        f5_push_failure(
            failures,
            "release_manifest.signing.keyMode",
            "external or KMS/HSM-backed signing is required",
        );
    }
    for (pointer, message) in [
        (
            "/signing/publicKey",
            "release signing public key evidence is required",
        ),
        (
            "/signing/manifestBundle",
            "release manifest signature bundle is required",
        ),
        (
            "/signing/provenanceBundle",
            "release provenance signature bundle is required",
        ),
    ] {
        if f5_json_str(manifest, pointer)
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
        {
            f5_push_failure(failures, pointer, message);
        }
    }
    for artifact in [
        "apolysis-f5-release-payload.tar.gz",
        "apolysis-f5-apolysisd-image.tar",
        "apolysis-f5-sbom.cdx.json",
        "apolysis-f5-provenance.intoto.json",
    ] {
        if !f5_json_array_contains_path(manifest, "/files", artifact) {
            f5_push_failure(
                failures,
                "release_manifest.files",
                format!("release manifest must include {artifact}"),
            );
        }
    }
}

fn f5_validate_registry_attachment(
    request: &F5ReleasePromotionRequest,
    evidence: &F5ReleasePromotionPolicyEvidence,
    failures: &mut Vec<F5ReleasePromotionPolicyFailure>,
) {
    let attachment = &evidence.registry_attachment;
    f5_expect_json_string(
        failures,
        attachment,
        "/schema",
        "apolysis.dev/f5-registry-attachment/v1",
        "registry attachment schema must be F5 registry attachment v1",
    );
    f5_expect_json_string(
        failures,
        attachment,
        "/phase",
        "F5.8",
        "registry attachment phase must be F5.8",
    );
    if f5_json_str(attachment, "/registry/imageDigest") != Some(request.image_digest.as_str()) {
        f5_push_failure(
            failures,
            "registry.imageDigest",
            "image digest does not match registry attachment",
        );
    }
    if f5_json_str(attachment, "/registry/sbomAttachmentDigest")
        != Some(request.sbom_attachment_digest.as_str())
    {
        f5_push_failure(
            failures,
            "registry.sbomAttachmentDigest",
            "SBOM attachment digest does not match registry attachment",
        );
    }
    if f5_json_str(attachment, "/registry/tag") != Some(request.source_tag.as_str()) {
        f5_push_failure(
            failures,
            "registry.tag",
            "source tag does not match registry attachment",
        );
    }
    if f5_json_str(attachment, "/releaseArtifacts/manifest/sha256")
        != Some(evidence.release_manifest_sha256.as_str())
    {
        f5_push_failure(
            failures,
            "registry.releaseArtifacts.manifest.sha256",
            "registry attachment release manifest digest does not match evidence",
        );
    }
    if !f5_json_array_contains_string(
        attachment,
        "/registryObservedState/tagsAfterSbom/tags",
        &request.source_tag,
    ) {
        f5_push_failure(
            failures,
            "registryObservedState.tagsAfterSbom",
            "registry observed tags must include the source image tag",
        );
    }
    if let Some(sbom_tag) = f5_json_str(attachment, "/registry/sbomAttachmentTag") {
        if !f5_json_array_contains_string(
            attachment,
            "/registryObservedState/tagsAfterSbom/tags",
            sbom_tag,
        ) {
            f5_push_failure(
                failures,
                "registryObservedState.tagsAfterSbom",
                "registry observed tags must include the SBOM attachment tag",
            );
        }
    }
}

fn f5_validate_archive_manifest(
    request: &F5ReleasePromotionRequest,
    evidence: &F5ReleasePromotionPolicyEvidence,
    failures: &mut Vec<F5ReleasePromotionPolicyFailure>,
) {
    let archive = &evidence.archive_manifest;
    f5_expect_json_string(
        failures,
        archive,
        "/schema",
        "apolysis.dev/f5-immutable-archive-manifest/v1",
        "archive manifest schema must be F5 immutable archive manifest v1",
    );
    f5_expect_json_string(
        failures,
        archive,
        "/phase",
        "F5.8",
        "archive manifest phase must be F5.8",
    );
    if f5_json_str(archive, "/archive/releaseManifestSha256")
        != Some(request.release_manifest_sha256.as_str())
    {
        f5_push_failure(
            failures,
            "archive.releaseManifestSha256",
            "archive release manifest digest does not match request",
        );
    }
    if f5_json_str(archive, "/archive/registryAttachmentSha256")
        != Some(evidence.registry_attachment_sha256.as_str())
    {
        f5_push_failure(
            failures,
            "archive.registryAttachmentSha256",
            "archive registry attachment digest does not match evidence",
        );
    }
    f5_expect_json_string(
        failures,
        archive,
        "/immutability/directoryMode",
        "0555",
        "archive directory mode must be read-only",
    );
    f5_expect_json_string(
        failures,
        archive,
        "/immutability/fileMode",
        "0444",
        "archive file mode must be read-only",
    );
    if f5_json_str(archive, "/immutability/mutationProbe") != Some("denied") {
        f5_push_failure(
            failures,
            "archive.immutability.mutationProbe",
            "archive mutation probe must be denied",
        );
    }
    for artifact in [
        "apolysis-f5-release-manifest.json",
        "apolysis-f5-registry-attachment.json",
        "apolysis-f5-apolysisd-image.tar",
    ] {
        if !f5_json_array_contains_path(archive, "/artifacts", artifact) {
            f5_push_failure(
                failures,
                "archive.artifacts",
                format!("archive manifest must include {artifact}"),
            );
        }
    }
    if let Some(artifacts) = archive
        .pointer("/artifacts")
        .and_then(serde_json::Value::as_array)
    {
        for artifact in artifacts {
            if artifact.get("mode").and_then(serde_json::Value::as_str) != Some("0444") {
                let path = artifact
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<unknown>");
                f5_push_failure(
                    failures,
                    "archive.artifacts.mode",
                    format!("archive artifact {path} must be read-only"),
                );
            }
        }
    }
}

fn f5_expect_json_string(
    failures: &mut Vec<F5ReleasePromotionPolicyFailure>,
    value: &serde_json::Value,
    pointer: &str,
    expected: &str,
    message: impl Into<String>,
) {
    if f5_json_str(value, pointer) != Some(expected) {
        f5_push_failure(failures, pointer, message);
    }
}

fn f5_json_str<'a>(value: &'a serde_json::Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer)?.as_str()
}

fn f5_json_array_contains_path(value: &serde_json::Value, pointer: &str, path: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(|candidate| candidate == path || candidate.ends_with(&format!("/{path}")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn f5_json_array_contains_string(value: &serde_json::Value, pointer: &str, expected: &str) -> bool {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_array)
        .map(|entries| entries.iter().any(|entry| entry.as_str() == Some(expected)))
        .unwrap_or(false)
}

fn f5_push_failure(
    failures: &mut Vec<F5ReleasePromotionPolicyFailure>,
    field: impl Into<String>,
    message: impl Into<String>,
) {
    failures.push(F5ReleasePromotionPolicyFailure {
        field: field.into(),
        message: message.into(),
    });
}

fn f5_is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .map(f5_is_sha256_hex)
        .unwrap_or(false)
}

fn f5_is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn f5_is_production_signing_mode(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized == "external" || normalized.contains("kms") || normalized.contains("hsm")
}

fn f5_is_anonymous_principal(value: &str) -> bool {
    matches!(value, "anonymous" | "system:anonymous")
}

fn f5_signing_failure(
    failures: &mut Vec<F5SigningProfileFailure>,
    field: impl Into<String>,
    message: impl Into<String>,
) {
    failures.push(F5SigningProfileFailure {
        field: field.into(),
        message: message.into(),
    });
}

fn f5_is_file_key_uri(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("file:")
}

fn f5_signing_uri_matches_provider(provider: F5SigningKeyProvider, value: &str) -> bool {
    match provider {
        F5SigningKeyProvider::Kms => {
            value.starts_with("awskms://")
                || value.starts_with("azurekms://")
                || value.starts_with("gcpkms://")
                || value.starts_with("hashivault://")
                || value.starts_with("kms://")
        }
        F5SigningKeyProvider::Hsm => value.starts_with("pkcs11:") || value.starts_with("pkcs11://"),
        F5SigningKeyProvider::EphemeralLocalValidation | F5SigningKeyProvider::LocalFile => false,
    }
}

fn f5_worm_failure(
    failures: &mut Vec<F5WormArchivePolicyFailure>,
    field: impl Into<String>,
    message: impl Into<String>,
) {
    failures.push(F5WormArchivePolicyFailure {
        field: field.into(),
        message: message.into(),
    });
}

fn f5_worm_uri_matches_provider(provider: F5WormProvider, value: &str) -> bool {
    match provider {
        F5WormProvider::S3ObjectLock => value.starts_with("s3://"),
        F5WormProvider::GcsBucketLock => value.starts_with("gs://"),
        F5WormProvider::AzureImmutableBlob => value.starts_with("azblob://"),
        F5WormProvider::LocalFilesystem => false,
    }
}

fn f4_merge_evidence_ids(left: Vec<String>, right: Vec<String>) -> Vec<String> {
    let mut merged = BTreeSet::new();
    merged.extend(left);
    merged.extend(right);
    merged.into_iter().collect()
}

fn f4_gvisor_failure(
    evidence_id: Option<String>,
    message: impl Into<String>,
) -> F4GvisorMetadataEvidenceGateFailure {
    F4GvisorMetadataEvidenceGateFailure {
        evidence_id,
        message: message.into(),
    }
}

fn f4_kubernetes_agent_sandbox_failure(
    evidence_id: Option<String>,
    message: impl Into<String>,
) -> F4KubernetesAgentSandboxEvidenceGateFailure {
    F4KubernetesAgentSandboxEvidenceGateFailure {
        evidence_id,
        message: message.into(),
    }
}

fn f4_kata_boundary_failure(
    evidence_id: Option<String>,
    message: impl Into<String>,
) -> F4KataBoundaryEvidenceGateFailure {
    F4KataBoundaryEvidenceGateFailure {
        evidence_id,
        message: message.into(),
    }
}

fn f4_is_gvisor_handler(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("runsc") || normalized.contains("gvisor")
}

fn f4_is_kata_handler(value: &str) -> bool {
    value.to_ascii_lowercase().contains("kata")
}

fn f4_optional_nonempty(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(|text| !text.trim().is_empty())
        .unwrap_or(false)
}

fn f4_subject_observed(subjects: &[String], needle: &str) -> bool {
    subjects
        .iter()
        .any(|subject| subject.to_ascii_lowercase().contains(needle))
}

fn f3_local_seccomp_execution_failure(
    evidence_id: Option<String>,
    message: impl Into<String>,
) -> F3LocalSeccompExecutionFailure {
    F3LocalSeccompExecutionFailure {
        evidence_id,
        message: message.into(),
    }
}

fn evidence_id_opt(evidence_id: &str) -> Option<String> {
    if evidence_id.is_empty() {
        None
    } else {
        Some(evidence_id.to_string())
    }
}

fn f3_bpf_lsm_prerequisite_failure(
    message: impl Into<String>,
) -> F3BpfLsmPrototypePrerequisiteFailure {
    F3BpfLsmPrototypePrerequisiteFailure {
        message: message.into(),
    }
}

fn items(value: &serde_json::Value) -> &[serde_json::Value] {
    value
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn runtime_class_snapshot(value: &serde_json::Value) -> Option<RuntimeClassSnapshot> {
    Some(RuntimeClassSnapshot {
        name: metadata_string(value, "name")?,
        handler: value.get("handler")?.as_str()?.to_string(),
    })
}

fn node_snapshot(value: &serde_json::Value) -> Option<NodeSnapshot> {
    Some(NodeSnapshot {
        name: metadata_string(value, "name")?,
        ready: value
            .pointer("/status/conditions")
            .and_then(serde_json::Value::as_array)
            .map(|conditions| {
                conditions.iter().any(|condition| {
                    condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(serde_json::Value::as_str)
                            == Some("True")
                })
            })
            .unwrap_or(false),
    })
}

fn workload_snapshot(value: &serde_json::Value) -> Option<KubernetesWorkloadSnapshot> {
    Some(KubernetesWorkloadSnapshot {
        namespace: metadata_string(value, "namespace").unwrap_or_else(|| "default".to_string()),
        name: metadata_string(value, "name")?,
        service_account_name: spec_string(value, "serviceAccountName"),
        runtime_class_name: spec_string(value, "runtimeClassName"),
        node_name: spec_string(value, "nodeName"),
    })
}

fn metadata_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get("metadata")?
        .get(key)?
        .as_str()
        .map(ToOwned::to_owned)
}

fn spec_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get("spec")?.get(key)?.as_str().map(ToOwned::to_owned)
}

fn has_label(value: &serde_json::Value, key: &str) -> bool {
    value
        .pointer("/metadata/labels")
        .and_then(|labels| labels.get(key))
        .is_some()
}

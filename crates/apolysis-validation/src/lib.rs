// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
